import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
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


class Redaction(unittest.TestCase):
    def setUp(self):
        self.s = diag.Secrets()
        self.key = 'cAnArYpAsSkEy123456'
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
        got = diag.harvest_tracker_urls(['https://t.example/announce.php?passkey=ABCDEF0123456789', 'udp://open.example:1337/announce'])
        self.assertEqual(got, ['ABCDEF0123456789'])

    def test_cache_resumes(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 't.jsonl'
            cache = diag.HarvestCache(path)
            cache.add('h1', ['v' * 16])
            resumed = diag.HarvestCache(path)
            self.assertEqual(resumed.done_hashes(), {'h1'})
            self.assertEqual(resumed.values(), ['v' * 16])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


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
        server = diag.create_server(cfg, diag.Secrets())
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
