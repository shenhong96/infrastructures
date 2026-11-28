import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
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


class HeaderSecrets(unittest.TestCase):
    def test_jellyfin_key_unwrapped(self):
        key = 'k' * 16 + '1' * 16
        values = diag.header_secrets({'Authorization': f'MediaBrowser Token="{key}"'})
        self.assertIn(key, values)
        secrets = diag.Secrets()
        for value in values:
            secrets.add(value, 'jellyfin')
        self.assertNotIn(key, secrets.scrub(f'{{"Key": "{key}"}}')[0])

    def test_plain_header_kept(self):
        key = 'x' * 16
        self.assertEqual(diag.header_secrets({'X-Api-Key': key}), [key])


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
        for app, path in [('sonarr', '/api/v3/release'), ('radarr', '/api/v3/release'), ('prowlarr', '/api/v1/search'), ('prowlarr', '/api/v1/indexer/test'), ('sonarr', '/api/v3/filesystem'), ('sonarr', '/api/v3/mediacover/1/poster.jpg'), ('sonarr', '/api/v3/system/backup'), ('sonarr', '/api/v3/log/file'), ('qbit', '/api/v2/torrents/export'), ('qbit', '/api/v2/app/shutdown'), ('qbit', '/api/v2/log/main'), ('qui', '/api/instances/1/torrents/x/export'), ('qui', '/api/instances/1/torrents/x/files/0/download'), ('jellyfin', '/Items/1/Download'), ('jellyfin', '/Items/1/File'),
                          ('qbit', '/api/v2/app/cookies'), ('qbit', '/api/v2/app/getDirectoryContent'), ('qbit', '/api/v2/search/downloadTorrent'),
                          ('qbit', '/api/v2/search/results'), ('qbit', '/api/v2/torrentcreator/torrentFile'), ('qbit-ubits', '/api/v2/torrents/SSLParameters'),
                          ('jellyfin', '/Items/1/RemoteImages'), ('jellyfin', '/Items/1/RemoteSearch/Subtitles/eng'),
                          ('qui', '/api/instances/1/getDirectoryContent'), ('qui', '/api/instances/1/free-space'),
                          ('qui', '/api/instances/1/mediainfo'), ('qui', '/api/instances/1/torrents/x/files/0/mediainfo'),
                          ('sonarr', '/api/v3/manualimport'), ('radarr', '/api/v3/ManualImport'), ('jellyfin', '/Packages')]:
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
        out, _ = diag.redact({'apiKey': 'zzz', 'Password': 'zzz', 'rss_key': 'zzz', 'nested': [{'Cookie': 'zzz'}],
                              'Items': [{'AccessToken': 'zzz'}]}, diag.Secrets())  # Jellyfin /Devices
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


def random_token(seed, n=24):
    # Built at runtime: a key-shaped literal trips gitleaks.
    import random, string
    return ''.join(random.Random(seed).choices(string.ascii_letters + string.digits, k=n))


class EntropyLayer(unittest.TestCase):
    def test_unknown_credential_in_free_text_is_masked(self):
        # Servarr masks its own provider credentials, so diag never learns them.
        token = random_token(1)
        out, counts = diag.redact({'message': f'Indexer auth failed for key {token}'}, diag.Secrets(), 'sonarr')
        self.assertNotIn(token, json.dumps(out))
        self.assertEqual(counts['entropy'], 1)

    def test_magnet_tracker_passkey_is_masked(self):
        token = random_token(2, 32)
        out, _ = diag.redact({'magnet_uri': 'magnet:?xt=urn:btih:' + 'a' * 40 + '&tr=https%3A%2F%2Ft.example%2Fannounce%2F' + token}, diag.Secrets(), 'qbit')
        self.assertNotIn(token, json.dumps(out))
        self.assertIn('a' * 40, json.dumps(out))

    def test_ordinary_values_survive(self):
        keep = {'name': 'Show.Name.S01E01.1080p.WEB-DL.DDP5.1.H.264-GROUP', 'save_path': '/mnt/data/torrents/tv/2024',
                'hash': '0123456789abcdef' * 2 + '01234567', 'downloadId': ('0123456789ABCDEF' * 4),
                'added': '2026-11-26T01:14:46Z', 'size': 123456789012345,
                'message': 'Indexer UBits is unavailable due to failures for more than 6 hours',
                'exception': 'NzbDrone.Core.Indexers.Exceptions.IndexerException'}
        out, counts = diag.redact(keep, diag.Secrets(), 'sonarr')
        self.assertEqual(out, keep)
        self.assertEqual(counts['entropy'], 0)

    def test_jellyfin_ids_kept_only_for_jellyfin(self):
        import random
        jid = '%032x' % random.Random(5).getrandbits(128)  # realistic Jellyfin ID / Servarr key shape
        self.assertEqual(diag.redact({'Id': jid}, diag.Secrets(), 'jellyfin')[0], {'Id': jid})
        self.assertNotIn(jid, json.dumps(diag.redact({'x': jid}, diag.Secrets(), 'sonarr')[0]))

    def test_tracker_url_keys_are_cleaned(self):
        token = random_token(3, 20)
        maindata = {'trackers': {'https://t.example/announce/' + token: ['h1'],
                                 'https://t.example/announce/' + random_token(4, 20): ['h2']}}
        out, counts = diag.redact(maindata, diag.Secrets(), 'qbit')
        self.assertNotIn(token, json.dumps(out))
        self.assertEqual(len(out['trackers']), 2)  # colliding cleaned keys both kept
        self.assertGreaterEqual(counts['url'], 2)


class Harvest(unittest.TestCase):
    def test_masked_placeholders_are_not_secrets(self):
        items = [{'fields': [{'name': 'apiKey', 'value': '********', 'privacy': 'apiKey'}]}]
        self.assertEqual(diag.harvest_provider_fields(items), [])

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


def all_ready():
    ready = diag.Readiness()
    for app in diag.APPS:
        ready.mark(app)
    return ready


class HarvestReadiness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cache = diag.HarvestCache(Path(self.tmp.name) / 'cache.jsonl')
        self.secrets = diag.Secrets()
        self.ready = diag.Readiness()
        self.canary = 'provider-canary-' + 'Z' * 16
        self.hash = 'a' * 40
        self.cfg = {'apps': {'sonarr': {}, 'qbit': {}, 'qui': {}, 'jellyfin': {}}}

    def fetch(self, app, path, cfg):
        if path.endswith('/torrents/info'):
            data = [{'hash': self.hash}]
        elif '/torrents/trackers?' in path:
            data = [{'url': 'https://t.example/' + self.canary}]
        else:
            data = [{'fields': [{'name': 'apiKey', 'value': self.canary}]}]
        return 200, 'application/json', json.dumps(data).encode()

    def harvest(self, fetch, cache=None):
        with patch.object(diag, 'fetch', side_effect=fetch):
            return diag.harvest_once(self.cfg, self.secrets, cache or self.cache, self.ready)

    def test_complete_harvest_marks_apps_and_redacts(self):
        self.assertFalse(self.ready.ready('sonarr'))
        self.assertTrue(self.harvest(self.fetch))
        for app in ('sonarr', 'qbit', 'qui', 'jellyfin', 'qbit-ubits'):
            self.assertTrue(self.ready.ready(app), app)
        status, body = diag.shape('sonarr', '/api/v3/health', 200, 'application/json',
                                  json.dumps({'message': self.canary}).encode(), self.secrets)
        self.assertEqual(status, 200)
        self.assertNotIn(self.canary, json.dumps(body))
        # Persisted tracker progress is not proof of provider readiness after a restart.
        self.assertFalse(diag.Readiness().ready('sonarr'))

    def test_failure_blocks_only_the_failing_app(self):
        provider = {'sonarr'}
        tracker = {'qbit', 'qui'}
        for index, (bad_path, reply, blocked) in enumerate([
            ('/api/v3/notification', (502, 'application/json', b'{}'), provider),
            ('/api/v3/indexer', (200, 'application/json', b'{}'), provider),
            ('/api/v3/indexer', (200, 'application/json', b'[{"fields":null}]'), provider),
            ('/api/v2/torrents/info', (200, 'application/json', b'[{"hash":"bad"}]'), tracker),
            ('/api/v2/torrents/trackers?hash=' + 'a' * 40, (502, 'application/json', b'{}'), tracker),
            ('/api/v2/torrents/trackers?hash=' + 'a' * 40, (200, 'application/json', b'[{}]'), tracker),
        ]):
            with self.subTest(path=bad_path, reply=reply):
                self.ready = diag.Readiness()
                cache = diag.HarvestCache(Path(self.tmp.name) / f'case-{index}.jsonl')
                def fetch(app, path, cfg):
                    return reply if path == bad_path else self.fetch(app, path, cfg)
                self.assertFalse(self.harvest(fetch, cache))
                for app in ('sonarr', 'qbit', 'qui', 'jellyfin'):
                    self.assertEqual(self.ready.ready(app), app not in blocked, app)

    def test_removed_torrent_is_skipped(self):
        def fetch(app, path, cfg):
            if '/torrents/trackers?' in path:
                return 404, 'text/plain', b'Torrent hash was not found'
            return self.fetch(app, path, cfg)
        self.assertTrue(self.harvest(fetch))
        self.assertTrue(self.ready.ready('qbit'))

    def test_readiness_survives_failed_refresh(self):
        self.assertTrue(self.harvest(self.fetch))
        self.assertFalse(self.harvest(lambda *args: (502, 'application/json', b'{}')))
        self.assertTrue(self.ready.ready('sonarr'))
        self.assertTrue(self.ready.ready('qbit'))

    def test_stale_cache_refresh_does_not_gate_readiness(self):
        path = Path(self.tmp.name) / 'stale.jsonl'
        path.write_text(json.dumps({'hash': 'qbit:' + self.hash, 'values': ['v' * 16], 'saved_at': 0}) + '\n')
        def fetch(app, p, cfg):
            if '/torrents/trackers?' in p:
                return 502, 'application/json', b'{}'
            return self.fetch(app, p, cfg)
        self.assertFalse(self.harvest(fetch, diag.HarvestCache(path)))
        self.assertTrue(self.ready.ready('qbit'))

    def test_wait_returns_after_first_cycle(self):
        threading.Timer(0.1, self.ready.cycle_done).start()
        start = time.monotonic()
        self.assertFalse(self.ready.wait('sonarr', 5))
        self.assertLess(time.monotonic() - start, 2)


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
        for path, data in [
            ('/Items', {'Items': [{'Id': guid, 'Etag': guid, 'ImageTags': {'Primary': guid},
                                   'MediaSources': [{'Id': guid, 'ETag': guid}], 'Trickplay': {guid: {}}}]}),
            ('/Sessions', [{'Id': guid, 'PlayState': {'MediaSourceId': guid}}]),
            ('/System/Info', {'Id': guid}),
        ]:
            with self.subTest(path=path):
                status, body = diag.shape('jellyfin', path, 200, 'application/json', json.dumps(data).encode(), diag.Secrets())
                self.assertEqual(status, 200, body)
                self.assertEqual(body['untrusted_data'], data)

    def test_known_secret_redacted_in_jellyfin_id_slot(self):
        canary = 'b' * 32
        secrets = diag.Secrets()
        secrets.add(canary, 'sonarr')
        data = {'Items': [{'Id': canary, 'ImageTags': {'Primary': canary}}]}
        status, body = diag.shape('jellyfin', '/Items/' + canary, 200, 'application/json', json.dumps(data).encode(), secrets)
        self.assertEqual(status, 200)
        self.assertNotIn(canary, json.dumps(body))
        self.assertIn('[REDACTED:sonarr]', json.dumps(body))

    def test_hex_key_still_blocks_other_apps(self):
        status, body = diag.shape('sonarr', '/api/v3/series', 200, 'application/json', json.dumps([{'Id': 'c' * 32}]).encode(), diag.Secrets())
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
        ready = diag.Readiness()
        ready.cycle_done()  # first harvest finished without sonarr
        base = self.start_server({'apps': {'sonarr': {}}}, ready)
        with patch.object(diag, 'fetch') as fetch:
            with self.assertRaises(HTTPError) as cm:
                urlopen(base + '/diag/sonarr/api/v3/health', timeout=5)
            self.assertEqual(cm.exception.code, 503)
            cm.exception.close()
            fetch.assert_not_called()
            with urlopen(base + '/diag/', timeout=5) as response:
                self.assertEqual(json.load(response)['ready'], [])

    def test_first_read_waits_for_harvest(self):
        ready = diag.Readiness()
        base = self.start_server({'apps': {'sonarr': {}}}, ready)
        threading.Timer(0.2, ready.mark, args=('sonarr',)).start()
        with patch.object(diag, 'fetch', return_value=(200, 'application/json', b'{"ok":true}')):
            with urlopen(base + '/diag/sonarr/api/v3/health', timeout=5) as response:
                self.assertEqual(response.status, 200)

    def test_prowlarr_search_and_download_never_reach_upstream(self):
        state = all_ready()
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
        state = all_ready()
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
        state = all_ready()
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


class FetchDeadline(unittest.TestCase):
    def start_upstream(self, handler):
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return {'apps': {'sonarr': {'base': f'http://127.0.0.1:{server.server_port}', 'headers': {}}}}

    def test_header_body_and_chunk_trickles_share_one_deadline(self):
        stop = threading.Event()
        class Slow(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                body = b'{"ok":true}'
                headers = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
                if self.path == '/chunked':
                    headers += b'Transfer-Encoding: chunked\r\n\r\n'
                    chunks = [headers] + [b'1\r\n' + bytes([ch]) + b'\r\n' for ch in body] + [b'0\r\n\r\n']
                else:
                    headers += b'Content-Length: ' + str(len(body)).encode() + b'\r\n\r\n'
                    chunks = [bytes([ch]) for ch in headers] + [body] if self.path == '/headers' else [headers] + [bytes([ch]) for ch in body]
                if self.path == '/combined':
                    stop.wait(0.08)
                try:
                    for chunk in chunks:
                        if stop.is_set():
                            return
                        self.wfile.write(chunk)
                        self.wfile.flush()
                        stop.wait(0.025)
                except OSError:
                    pass  # the deadline intentionally closes the socket mid-stream
        cfg = self.start_upstream(Slow)
        self.addCleanup(stop.set)
        for path in ['/headers', '/body', '/chunked', '/combined']:
            with self.subTest(path=path), patch.object(diag, 'TIMEOUT', 0.15):
                start = time.monotonic()
                status, _, body = diag.fetch('sonarr', path, cfg)
                elapsed = time.monotonic() - start
                self.assertEqual(status, 502)
                self.assertEqual(json.loads(body), {'error': 'upstream unreachable'})
                self.assertLess(elapsed, 0.6)

    def test_fast_response_and_upstream_size_cap(self):
        seen = []
        class Fast(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                seen.append((self.command, self.headers.get('X-Api-Key')))
                body = b'{"ok":true}' if self.path == '/small' else b'[' + b'0,' * 100 + b'0]'
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        cfg = self.start_upstream(Fast)
        cfg['apps']['sonarr']['headers']['X-Api-Key'] = 'fake-header-' + 'Z' * 16
        with patch.object(diag, 'TIMEOUT', 0.3), patch.object(diag, 'MAX_UPSTREAM', 64), \
                patch.dict(diag.os.environ, {'http_proxy': 'http://127.0.0.1:9', 'HTTP_PROXY': 'http://127.0.0.1:9', 'no_proxy': '', 'NO_PROXY': ''}):
            status, _, body = diag.fetch('sonarr', '/small', cfg)
            self.assertEqual((status, json.loads(body)), (200, {'ok': True}))
            self.assertEqual(diag.fetch('sonarr', '/large', cfg)[0], 413)
        self.assertEqual(seen, [('GET', cfg['apps']['sonarr']['headers']['X-Api-Key'])] * 2)

    def test_invalid_bases_never_open_a_connection(self):
        with patch.object(diag, 'DeadlineConnection') as connection:
            for base in ['http://example.com', 'https://127.0.0.1', 'http://127.0.0.1/api',
                         'http://u:***@127.0.0.1', 'http://127.0.0.1?x=y', 'http://192.168.9.156:8989']:
                cfg = {'apps': {'sonarr': {'base': base}}}
                self.assertEqual(diag.fetch('sonarr', '/api/v3/health', cfg)[0], 502)
            connection.assert_not_called()


class Selftest(unittest.TestCase):
    def test_selftest(self):
        result = subprocess.run([sys.executable, str(SCRIPT), 'selftest'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
