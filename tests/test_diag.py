import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

SCRIPT = Path(__file__).resolve().parent.parent / 'ansible/roles/diag/files/diag.py'
spec = importlib.util.spec_from_file_location('diag', SCRIPT)
diag = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diag)


class PathRules(unittest.TestCase):
    def test_allowed(self):
        for app, path in [('sonarr', '/api/v3/health'), ('qbit', '/api/v2/torrents/info'), ('qui', '/api/instances'), ('jellyfin', '/System/Info')]:
            self.assertIsNone(diag.check_path(app, path), (app, path))

    def test_unknown_and_prefix(self):
        self.assertEqual(diag.check_path('proxmox', '/api2/json'), 'unknown-app')
        for app, path in [('sonarr', '/login'), ('jellyfin', '/Videos/1/stream'), ('jellyfin', '/ItemsExtra')]:
            self.assertEqual(diag.check_path(app, path), 'prefix')

    def test_denylist_ignores_case(self):
        for path in ['/api/v3/config/host', '/API/V3/Config/Host', '/api/v3/config/host/', '/api/v3/Config/Host/x']:
            self.assertTrue(diag.check_path('sonarr', path).startswith('deny:'), path)

    def test_traversal_rejected(self):
        for path in ['/api/v3/../config/host', '/api/v3//health', '/api/v3/%2e%2e/x', '/api/v3/a%2fb', '/api/v3\\x']:
            self.assertIsNotNone(diag.check_path('sonarr', path), path)

    def test_searches_and_files_denied(self):
        for app, path in [('sonarr', '/api/v3/release'), ('radarr', '/api/v3/release'), ('prowlarr', '/api/v1/search'), ('prowlarr', '/api/v1/indexer/test'), ('sonarr', '/api/v3/filesystem'), ('sonarr', '/api/v3/mediacover/1/poster.jpg'), ('sonarr', '/api/v3/system/backup'), ('sonarr', '/api/v3/log/file'), ('qbit', '/api/v2/torrents/export'), ('qbit', '/api/v2/app/shutdown'), ('qbit', '/api/v2/log/main'), ('qui', '/api/instances/1/torrents/x/export'), ('jellyfin', '/Items/1/Download'), ('jellyfin', '/Items/1/File')]:
            self.assertIsNotNone(diag.check_path(app, path), (app, path))

    def test_prowlarr_newznab_and_download_routes_denied(self):
        for path in ['/api/v1/indexer/1/newznab', '/API/V1/Indexer/2/Newznab/',
                     '/api/v1/indexer/1/download', '/api/v1/indexer/-1/download/x']:
            rule = diag.check_path('prowlarr', path)
            self.assertIsNotNone(rule, path)
            self.assertTrue(rule.startswith('deny:'), path)
        self.assertIsNone(diag.check_path('prowlarr', '/api/v1/indexer/1'))

    def test_qui_client_settings_is_an_exact_read_route(self):
        self.assertIsNone(diag.check_path('qui', '/api/client-settings'))
        for path in ['/api/client-settings/other', '/api/client-settings-extra']:
            self.assertEqual(diag.check_path('qui', path), 'prefix')


class Redaction(unittest.TestCase):
    def setUp(self):
        self.s = diag.Secrets()
        self.key = 'cAnArY' + 'x' * 13  # built at runtime so gitleaks sees no key literal
        self.s.add(self.key, 'prowlarr')

    def test_exact_value_in_free_text(self):
        out, counts = diag.redact({'comment': f'see https://t.example/a?pk={self.key} ok', 'msg': f'bad key {self.key}'}, self.s)
        self.assertNotIn(self.key, json.dumps(out))
        self.assertGreaterEqual(counts['exact'] + counts['url'], 2)

    def test_encoded_forms(self):
        for form in [quote(self.key + '/'), base64.b64encode(self.key.encode()).decode(), self.key.encode().hex()]:
            out, _ = diag.redact({'x': f'pre {form} post'}, self.s)
            self.assertNotIn(form, json.dumps(out))

    def test_encoded_slash_and_json_key(self):
        value = 'secret/value+12345'
        secrets = diag.Secrets()
        secrets.add(value, 'test')
        for form in [quote(value, safe=''), value.encode().hex(), base64.b64encode(value.encode()).decode()]:
            out, _ = diag.redact({form: 'ok'}, secrets)
            self.assertNotIn(form, json.dumps(out))

    def test_short_values_skipped(self):
        s = diag.Secrets()
        s.add('abc', 'x')
        self.assertEqual(s.scrub('abc abc')[0], 'abc abc')

    def test_field_names(self):
        out, _ = diag.redact({'apiKey': 'zzz', 'Password': 'zzz', 'rss_key': 'zzz', 'nested': [{'Cookie': 'zzz'}]}, diag.Secrets())
        self.assertNotIn('zzz', json.dumps(out))

    def test_name_value_pair_masked(self):
        out, _ = diag.redact({'fields': [{'name': 'cookie', 'value': 'zzz'}, {'name': 'baseUrl', 'value': 'keep'}]}, diag.Secrets())
        self.assertNotIn('zzz', json.dumps(out))
        self.assertIn('keep', json.dumps(out))

    def test_announce_url_cleaned(self):
        self.assertEqual(diag.clean_url('https://tracker.example:443/announce/abcdef1234567890'), 'https://tracker.example:443/[path removed]')
        self.assertEqual(diag.clean_url('https://u:p@h.example/'), 'https://h.example/[path removed]')
        self.assertEqual(diag.clean_url('not a url'), 'not a url')

    def test_tripwire(self):
        self.assertEqual(diag.tripwire('x ghp_' + 'a' * 36), 'github')
        self.assertIsNone(diag.tripwire('{"title": "Some Show S01E01"}'))
        self.assertIsNone(diag.tripwire('"hash": "' + 'a' * 40 + '"'))


class Harvest(unittest.TestCase):
    def test_provider_fields(self):
        items = [{'fields': [{'name': 'apiKey', 'value': 'k' * 20, 'privacy': 'apiKey'}, {'name': 'cookie', 'value': 'c' * 20}, {'name': 'baseUrl', 'value': 'https://x.example'}, {'name': 'minimumSeeders', 'value': 1}]}]
        self.assertEqual(sorted(diag.harvest_provider_fields(items)), ['c' * 20, 'k' * 20])

    def test_tracker_urls(self):
        fake = 'F' * 16  # built at runtime so gitleaks sees no key literal
        got = diag.harvest_tracker_urls(['https://t.example/announce.php?passkey=' + fake, 'udp://open.example:1337/announce'])
        self.assertEqual(got, [fake])

    def test_cache_resumes(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 't.jsonl'
            cache = diag.HarvestCache(path)
            cache.add('h1', ['v' * 16])
            resumed = diag.HarvestCache(path)
            self.assertEqual(resumed.done_hashes(), {'h1'})
            self.assertEqual(resumed.values(), ['v' * 16])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


class HarvestReadiness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cache = diag.HarvestCache(Path(self.tmp.name) / 'cache.jsonl')
        self.secrets = diag.Secrets()
        self.state = diag.HarvestState()
        self.canary = 'provider-canary-' + 'Z' * 16
        self.hash = 'a' * 40
        self.cfg = {'apps': {'sonarr': {}, 'qbit': {}}}

    def fetch(self, app, path, cfg):
        if path.endswith('/torrents/info'):
            data = [{'hash': self.hash}]
        elif '/torrents/trackers?' in path:
            data = [{'url': 'https://t.example/' + self.canary}]
        else:
            data = [{'fields': [{'name': 'apiKey', 'value': self.canary}]}]
        return 200, 'application/json', json.dumps(data).encode()

    def test_complete_snapshot_redacts_free_text(self):
        self.assertIsNone(self.state.ticket())
        with patch.object(diag, 'fetch', side_effect=self.fetch):
            self.assertTrue(diag.harvest_cycle(self.cfg, self.secrets, self.cache, self.state))
        self.assertIsNotNone(self.state.ticket())
        status, body = diag.shape('sonarr', '/api/v3/health', 200, 'application/json',
                                  json.dumps({'message': self.canary}).encode(), self.secrets)
        self.assertEqual(status, 200)
        self.assertNotIn(self.canary, json.dumps(body))
        # Persisted tracker progress is not proof of provider readiness after a restart.
        self.assertIsNone(diag.HarvestState().ticket())

    def test_partial_failure_and_malformed_sources_fail_closed(self):
        for index, (bad_path, reply) in enumerate([
            ('/api/v3/notification', (502, 'application/json', b'{}')),
            ('/api/v3/indexer', (200, 'application/json', b'{}')),
            ('/api/v3/indexer', (200, 'application/json', b'[{"fields":null}]')),
            ('/api/v2/torrents/info', (200, 'application/json', b'[{"hash":"bad"}]')),
            ('/api/v2/torrents/trackers?hash=' + 'a' * 40, (502, 'application/json', b'{}')),
            ('/api/v2/torrents/trackers?hash=' + 'a' * 40, (200, 'application/json', b'[{}]')),
        ]):
            with self.subTest(path=bad_path, reply=reply):
                cache = diag.HarvestCache(Path(self.tmp.name) / f'case-{index}.jsonl')
                def fetch(app, path, cfg):
                    return reply if path == bad_path else self.fetch(app, path, cfg)
                self.state.finish(self.state.begin(), True)
                with patch.object(diag, 'fetch', side_effect=fetch):
                    self.assertFalse(diag.harvest_cycle(self.cfg, self.secrets, cache, self.state))
                self.assertIsNone(self.state.ticket())

    def test_failure_recovers_and_stale_snapshot_expires(self):
        with patch.object(diag, 'fetch', side_effect=OSError('do not log details')):
            self.assertFalse(diag.harvest_cycle(self.cfg, self.secrets, self.cache, self.state))
        with patch.object(diag, 'fetch', side_effect=self.fetch):
            self.assertTrue(diag.harvest_cycle(self.cfg, self.secrets, self.cache, self.state))
        self.assertIsNotNone(self.state.ticket())
        with patch.object(diag.time, 'monotonic', return_value=diag.time.monotonic() + 1801):
            self.assertIsNone(self.state.ticket())


class Shape(unittest.TestCase):
    def test_non_json_withheld(self):
        status, body = diag.shape('jellyfin', '/x', 200, 'video/mp4', b'\x00\x01', diag.Secrets())
        self.assertEqual(status, 415)
        self.assertNotIn('untrusted_data', body)

    def test_wrapped(self):
        status, body = diag.shape('sonarr', '/api/v3/health', 200, 'application/json', b'[{"type":"warning"}]', diag.Secrets())
        self.assertEqual(status, 200)
        self.assertEqual(body['untrusted_data'], [{'type': 'warning'}])

    def test_shape_truncates_large_array(self):
        big = json.dumps([{'name': 'x' * 200, 'hash': str(i)} for i in range(5000)]).encode()
        status, body = diag.shape('qbit', '/api/v2/torrents/info', 200, 'application/json', big, diag.Secrets())
        self.assertEqual(status, 200)
        self.assertTrue(body['truncated'])
        self.assertEqual(body['total_items'], 5000)
        self.assertLessEqual(len(json.dumps(body).encode()), 262144)
        self.assertIn('limit', body['narrow_with'])

    def test_tripwire_blocks(self):
        status, body = diag.shape('sonarr', '/x', 200, 'application/json', json.dumps({'m': 'ghp_' + 'a' * 36}).encode(), diag.Secrets())
        self.assertEqual((status, body['rule']), (502, 'github'))

    def test_jellyfin_identifiers_do_not_trip_hex_detector(self):
        guid = 'a' * 32
        item = {'Id': guid, 'ServerId': guid, 'Name': 'ordinary item',
                'SeriesId': guid, 'ImageTags': {'Primary': guid},
                'BackdropImageTags': [guid], 'Studios': [{'Id': guid, 'Name': 'Studio'}],
                'DisplayPreferencesId': guid, 'ParentPrimaryImageTag': guid,
                'People': [{'Id': guid, 'PrimaryImageTag': guid}], 'UserData': {'ItemId': guid},
                'ImageBlurHashes': {'Primary': {guid: 'blurhash'}}, 'MediaSources': [{'Id': guid}]}
        for path, data in [
            ('/Items', {'Items': [item], 'TotalRecordCount': 1}),
            ('/Users/' + guid + '/Items/' + guid, item),
            ('/System/Info', {'Id': guid, 'ServerName': 'Media'}),
            ('/System/Info/Public', {'Id': guid}),
            ('/Sessions', [{'Id': guid, 'UserId': guid, 'NowPlayingItem': item, 'NowPlayingQueue': [{'Id': guid}]}]),
            ('/ScheduledTasks', [{'Id': guid, 'Name': 'Task', 'LastExecutionResult': {'Id': guid}}]),
            ('/Library/VirtualFolders', [{'ItemId': guid, 'Name': 'Library'}]),
            ('/Plugins', [{'Id': guid, 'Name': 'Plugin'}]),
        ]:
            with self.subTest(path=path):
                status, body = diag.shape('jellyfin', path, 200, 'application/json', json.dumps(data).encode(), diag.Secrets())
                self.assertEqual(status, 200, body)
                self.assertEqual(body['untrusted_data'], data)
                self.assertEqual(body['path'], path)

    def test_jellyfin_hex_exceptions_never_override_known_secrets(self):
        canary = 'b' * 32
        secrets = diag.Secrets()
        secrets.add(canary, 'sonarr')
        data = {'Items': [{'Id': canary, 'ImageTags': {'Primary': canary}}]}
        status, body = diag.shape('jellyfin', '/Items/' + canary, 200, 'application/json', json.dumps(data).encode(), secrets)
        self.assertEqual(status, 200)
        self.assertNotIn(canary, json.dumps(body))
        self.assertIn('[REDACTED:sonarr]', json.dumps(body))

    def test_jellyfin_unexpected_hex_values_still_block(self):
        unknown = 'c' * 32
        for app, path, data, upstream_status in [
            ('jellyfin', '/Items', {'Items': [{'Id': unknown, 'Overview': unknown}]}, 200),
            ('jellyfin', '/Items', {'Items': [{'Metadata': {'Id': unknown}}]}, 200),
            ('jellyfin', '/Items', {'Id': unknown}, 200),
            ('jellyfin', '/Items', {'Items': [{'ImageTags': {'Custom': unknown}}]}, 200),
            ('jellyfin', '/Items', {'Items': [{'Studios': [{'PrimaryImageTag': unknown}]}]}, 200),
            ('jellyfin', '/Items/Filters', {'Id': unknown}, 200),
            ('jellyfin', '/Devices', {'Items': [{'Id': unknown}]}, 200),
            ('jellyfin', '/System/Info', {'Id': unknown}, 500),
            ('sonarr', '/api/v3/series', [{'Id': unknown}], 200),
        ]:
            with self.subTest(app=app, path=path, data=data):
                status, body = diag.shape(app, path, upstream_status, 'application/json', json.dumps(data).encode(), diag.Secrets())
                self.assertEqual((status, body.get('rule')), (502, 'hex-key'))

    def test_jellyfin_non_hex_tripwires_remain_active(self):
        data = {'Items': [{'Id': 'a' * 32, 'Name': 'ghp_' + 'z' * 36}]}
        status, body = diag.shape('jellyfin', '/Items', 200, 'application/json', json.dumps(data).encode(), diag.Secrets())
        self.assertEqual((status, body.get('rule')), (502, 'github'))

    def test_upstream_error_has_no_secret(self):
        cfg = {'apps': {'sonarr': {'base': 'http://127.0.0.1:9', 'headers': {'X-Api-Key': 's3cr3tvalue123'}}}}
        status, _, body = diag.fetch('sonarr', '/api/v3/health', cfg)
        self.assertEqual(status, 502)
        self.assertNotIn(b's3cr3t', body)

    def test_oversized_object_and_invalid_json(self):
        self.assertEqual(diag.shape('sonarr', '/x', 200, 'application/json', json.dumps({'x': 'a' * 270000}).encode(), diag.Secrets())[0], 413)
        self.assertEqual(diag.shape('sonarr', '/x', 200, 'application/json', b'{bad', diag.Secrets())[0], 415)
        self.assertEqual(diag.shape('sonarr', '/x', 200, 'application/json', b'{"x":NaN}', diag.Secrets())[0], 415)
        self.assertEqual(diag.shape('sonarr', '/x', 200, 'text/notjson', b'{}', diag.Secrets())[0], 415)

    def test_redirect_not_followed(self):
        class Redirect(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header('Location', 'http://127.0.0.1:9/escape')
                self.end_headers()
            def log_message(self, *args):
                pass
        upstream = ThreadingHTTPServer(('127.0.0.1', 0), Redirect)
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        try:
            cfg = {'apps': {'sonarr': {'base': f'http://127.0.0.1:{upstream.server_port}', 'headers': {'X-Api-Key': 'fake-api-key-value'}}}}
            status, _, _ = diag.fetch('sonarr', '/api/v3/health', cfg)
            self.assertEqual(status, 302)
        finally:
            upstream.shutdown()
            upstream.server_close()


class Handler(unittest.TestCase):
    def start_server(self, cfg, state=None):
        cfg = dict(cfg, bind='127.0.0.1', port=0, allow_client='127.0.0.1')
        server = diag.create_server(cfg, diag.Secrets(), state)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f'http://127.0.0.1:{server.server_port}'

    def test_unready_inventory_never_fetches(self):
        base = self.start_server({'apps': {'sonarr': {}}})
        with patch.object(diag, 'fetch') as fetch:
            with self.assertRaises(HTTPError) as cm:
                urlopen(base + '/diag/sonarr/api/v3/health', timeout=5)
            self.assertEqual(cm.exception.code, 503)
            cm.exception.close()
            fetch.assert_not_called()
            with urlopen(base + '/diag/', timeout=5) as response:
                self.assertFalse(json.load(response)['redaction_ready'])

    def test_refresh_invalidates_inflight_response(self):
        state = diag.HarvestState()
        state.finish(state.begin(), True)
        base = self.start_server({'apps': {'sonarr': {}}}, state)
        def refresh_during_fetch(*args):
            state.finish(state.begin(), True)
            return 200, 'application/json', b'{"message":"withhold stale response"}'
        with patch.object(diag, 'fetch', side_effect=refresh_during_fetch):
            with self.assertRaises(HTTPError) as cm:
                urlopen(base + '/diag/sonarr/api/v3/health', timeout=5)
            self.assertEqual(cm.exception.code, 503)
            self.assertNotIn(b'withhold stale response', cm.exception.read())
            cm.exception.close()

    def test_prowlarr_search_and_download_never_reach_upstream(self):
        state = diag.HarvestState()
        state.finish(state.begin(), True)
        base = self.start_server({'apps': {'prowlarr': {}}}, state)
        with patch.object(diag, 'fetch') as fetch:
            for path in ['/api/v1/indexer/1/newznab?t=search&q=test',
                         '/API/V1/Indexer/1/Newznab/?t=tvsearch',
                         '/api/v1/indexer/1/download?link=test&file=test']:
                with self.assertRaises(HTTPError) as cm:
                    urlopen(base + '/diag/prowlarr' + path, timeout=5)
                self.assertEqual(cm.exception.code, 403)
                self.assertTrue(json.load(cm.exception)['rule'].startswith('deny:'))
                cm.exception.close()
            fetch.assert_not_called()

    def test_qui_incognito_setting_is_readable_but_not_writable(self):
        state = diag.HarvestState()
        state.finish(state.begin(), True)
        base = self.start_server({'apps': {'qui': {}}}, state)
        payload = json.dumps({'qui-incognito-mode': 'true', 'apiKey': 'withhold-me'}).encode()
        with patch.object(diag, 'fetch', return_value=(200, 'application/json', payload)) as fetch:
            with urlopen(base + '/diag/qui/api/client-settings', timeout=5) as response:
                data = json.load(response)['untrusted_data']
                self.assertEqual(data['qui-incognito-mode'], 'true')
                self.assertEqual(data['apiKey'], '[REDACTED]')
            with self.assertRaises(HTTPError) as cm:
                urlopen(Request(base + '/diag/qui/api/client-settings', method='PUT'), timeout=5)
            self.assertEqual(cm.exception.code, 405)
            cm.exception.close()
            fetch.assert_called_once()
            self.assertEqual(fetch.call_args.args[:2], ('qui', '/api/client-settings'))

    def test_methods_paths_and_redaction(self):
        class Upstream(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'[{"apiKey":"zzz"}]')
            def log_message(self, *args):
                pass
        upstream = ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
        thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        thread.start()
        cfg = {'bind': '127.0.0.1', 'port': 0, 'allow_client': '127.0.0.1', 'apps': {'sonarr': {'base': f'http://127.0.0.1:{upstream.server_port}', 'headers': {}}}}
        state = diag.HarvestState()
        state.finish(state.begin(), True)
        server = diag.create_server(cfg, diag.Secrets(), state)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f'http://127.0.0.1:{server.server_port}'
        try:
            for method, path, expected in [('POST', '/diag/sonarr/api/v3/health', 405), ('TRACE', '/diag/sonarr/api/v3/health', 405), ('GET', '/diag/sonarr/api/v3/config/host', 403)]:
                with self.assertRaises(HTTPError) as cm:
                    urlopen(Request(base + path, method=method), timeout=5)
                self.assertEqual(cm.exception.code, expected)
                cm.exception.close()
            with urlopen(base + '/diag/sonarr/api/v3/health', timeout=5) as response:
                self.assertEqual(response.status, 200)
                self.assertNotIn(b'zzz', response.read())
        finally:
            server.shutdown()
            server.server_close()
            upstream.shutdown()
            upstream.server_close()


class Selftest(unittest.TestCase):
    def test_selftest(self):
        result = subprocess.run([sys.executable, str(SCRIPT), 'selftest'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
