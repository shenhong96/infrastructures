#!/usr/bin/env python3
"""Read-only, redacting gateway for selected home-lab application APIs."""
import argparse
import base64
from contextlib import contextmanager
import json
import logging
import os
from pathlib import Path
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.parse import parse_qs, quote, unquote, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

CONFIG = Path('/etc/diag/config.json')
STATE = Path('/var/lib/diag/trackers.jsonl')
MAX_RESPONSE = 262144
MAX_UPSTREAM = 16 * 1024 * 1024
TIMEOUT = 20
HARVEST_INTERVAL = 1800
HARVEST_RETRY = 60
FIELD_RE = re.compile(r'pass(word|key)?|secret|token|api_?key|rss_?key|auth|cookie|session|credential|private', re.I)
SERVARR_DENY = ('release', 'search', 'indexer/test', 'filesystem', 'mediacover',
                'system/backup', 'log', 'config/host', 'command', 'update', 'apikey')
APPS = {
    'qbit': {'prefixes': ['/api/v2/'], 'deny': ['/api/v2/torrents/export', '/api/v2/torrents/downloadfile', '/api/v2/log', '/api/v2/app/shutdown', '/api/v2/auth']},
    'qbit-ubits': {'prefixes': ['/api/v2/'], 'deny': ['/api/v2/torrents/export', '/api/v2/torrents/downloadfile', '/api/v2/log', '/api/v2/app/shutdown', '/api/v2/auth']},
    'qui': {'prefixes': ['/api/instances', '/api/health', '/api/version'], 'exact': ['/api/client-settings'], 'deny_contains': ['export', 'backup', 'api-keys', 'apikeys', 'auth', 'logs']},
    'sonarr': {'prefixes': ['/api/v3/'], 'deny': ['/api/v3/' + p for p in SERVARR_DENY]},
    'radarr': {'prefixes': ['/api/v3/'], 'deny': ['/api/v3/' + p for p in SERVARR_DENY]},
    # Prowlarr 2.7 NewznabController performs searches/downloads on these GETs.
    # Withholding its XML/torrent response afterwards cannot undo the action.
    'prowlarr': {'prefixes': ['/api/v1/'], 'deny': ['/api/v1/' + p for p in SERVARR_DENY], 'deny_regex': [r'^/api/v1/indexer/[^/]+/(newznab|download)(/|$)']},
    'jellyfin': {'prefixes': ['/system/info', '/sessions', '/scheduledtasks', '/library/virtualfolders', '/items', '/users/*/items', '/devices', '/plugins', '/packages', '/health'], 'deny': ['/environment'], 'deny_regex': [r'^/items/[^/]+/(download|file|images)(/|$)', r'^/users/[^/]+/items/[^/]+/(download|file|images)(/|$)', r'^/plugins/[^/]+/configuration(/|$)']},
}
PAGING = {'qbit': 'limit, offset, filter, category', 'qbit-ubits': 'limit, offset, filter, category', 'qui': 'limit, offset', 'sonarr': 'pageSize, page', 'radarr': 'pageSize, page', 'prowlarr': 'pageSize, page', 'jellyfin': 'Limit, StartIndex'}
PROVIDER_PATHS = {
    app: [f'/api/{version}/{name}' for name in names]
    for app, version, names in (
        ('sonarr', 'v3', ('indexer', 'downloadclient', 'notification', 'importlist')),
        ('radarr', 'v3', ('indexer', 'downloadclient', 'notification', 'importlist')),
        ('prowlarr', 'v1', ('indexer', 'downloadclient', 'notification', 'applications', 'indexerproxy')),
    )
}
TRIPWIRES = [(name, re.compile(pattern)) for name, pattern in (
    ('github', r'gh[pousr]_[A-Za-z0-9]{36}|github_pat_\w{22,}'),
    ('telegram', r'\b\d{8,10}:[A-Za-z0-9_-]{35}\b'),
    ('jwt', r'eyJ[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]{10,}'),
    ('private-key', r'-----BEGIN [A-Z ]*PRIVATE KEY-----'),
    ('aws', r'AKIA[0-9A-Z]{16}'),
    ('slack', r'xox[baprs]-[A-Za-z0-9-]{10,}'),
    ('hex-key', r'\b[a-f0-9]{32}\b'),
)]


def _matches(path, prefix):
    return path == prefix.rstrip('/') or path.startswith(prefix.rstrip('/') + '/')


def check_path(app, path):
    if app not in APPS:
        return 'unknown-app'
    if not isinstance(path, str) or not path.startswith('/'):
        return 'bad-chars'
    if '%' in path or '\\' in path or not re.fullmatch(r'[A-Za-z0-9/_.,:=-]*', path):
        return 'bad-chars'
    if '..' in path or '//' in path:
        return 'traversal'
    path = path.lower()
    rules = APPS[app]
    for denied in rules.get('deny', []):
        if _matches(path, denied):
            return 'deny:' + denied
    for denied in rules.get('deny_contains', []):
        if denied in path:
            return 'deny:' + denied
    for pattern in rules.get('deny_regex', []):
        if re.match(pattern, path):
            return 'deny:' + pattern
    if path in rules.get('exact', []):
        return None
    prefixes = rules['prefixes']
    if not any((re.match(r'^/users/[^/]+/items(?:/|$)', path) if p == '/users/*/items' else _matches(path, p)) for p in prefixes):
        return 'prefix'
    return None


class Secrets:
    def __init__(self):
        self._forms = {}
        self._lock = threading.Lock()
        self._regex = None
        self._snapshot = {}

    def add(self, value, source):
        if not isinstance(value, str) or len(value) < 8:
            return
        raw = value.encode('utf-8')
        forms = {value, quote(value, safe=''), quote(value, safe='/'), base64.b64encode(raw).decode(), raw.hex(), json.dumps(value, ensure_ascii=True)[1:-1], json.dumps(value, ensure_ascii=False)[1:-1]}
        with self._lock:
            for form in forms:
                self._forms[form] = source
            self._regex = None

    def scrub(self, text):
        with self._lock:
            if not self._forms:
                return text, 0
            if self._regex is None:
                forms = sorted(self._forms, key=len, reverse=True)
                self._regex = re.compile('|'.join(re.escape(form) for form in forms))
                self._snapshot = self._forms.copy()
            regex, sources = self._regex, self._snapshot
        return regex.subn(lambda match: '[REDACTED:' + sources[match.group()] + ']', text)


def clean_url(s):
    try:
        url = urlsplit(s)
        if url.scheme.lower() not in ('http', 'https', 'udp') or not url.hostname:
            return s
        port = url.port
        if url.path not in ('', '/') or url.query or url.fragment or url.username is not None or url.password is not None:
            host = url.hostname
            if ':' in host:
                host = '[' + host + ']'
            return url.scheme + '://' + host + (':' + str(port) if port is not None else '') + '/[path removed]'
    except ValueError:
        pass
    return s


def redact(obj, secrets):
    counts = {'exact': 0, 'field': 0, 'url': 0}
    def walk(value):
        if isinstance(value, dict):
            named = isinstance(value.get('name'), str) and FIELD_RE.search(value['name'])
            out = {}
            for key, item in value.items():
                safe_key, n = secrets.scrub(key)
                counts['exact'] += n
                if FIELD_RE.search(key) or (key == 'value' and named):
                    out[safe_key] = '[REDACTED]'
                    counts['field'] += 1
                else:
                    out[safe_key] = walk(item)
            return out
        if isinstance(value, list):
            return [walk(item) for item in value]
        if isinstance(value, str):
            cleaned = clean_url(value)
            counts['url'] += cleaned != value
            cleaned, n = secrets.scrub(cleaned)
            counts['exact'] += n
            return cleaned
        return value
    return walk(obj), counts


def tripwire(text):
    for name, regex in TRIPWIRES:
        if regex.search(text):
            return name
    return None


def harvest_provider_fields(items):
    if not isinstance(items, list):
        raise ValueError('invalid provider inventory')
    found = []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get('fields'), list):
            raise ValueError('invalid provider fields')
        for field in item['fields']:
            if not isinstance(field, dict) or not isinstance(field.get('name'), str):
                raise ValueError('invalid provider field')
            value, name = field.get('value'), field.get('name')
            if isinstance(value, str) and value and (field.get('privacy') in ('apiKey', 'password', 'userName') or (isinstance(name, str) and FIELD_RE.search(name))):
                found.append(value)
    return found


def harvest_tracker_urls(urls):
    found = []
    for url in urls:
        try:
            parsed = urlsplit(url)
            found.extend(unquote(part) for part in parsed.path.split('/') if len(unquote(part)) > 12)
            found.extend(value for values in parse_qs(parsed.query).values() for value in values if len(value) > 12)
        except (TypeError, ValueError):
            continue
    return found


class HarvestCache:
    def __init__(self, path):
        self.path = Path(path)
        self._entries = {}
        if self.path.exists():
            with self.path.open(encoding='utf-8') as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        self._entries[entry['hash']] = (entry['values'], entry.get('saved_at', 0))
                    except (ValueError, KeyError, TypeError):
                        continue

    def done_hashes(self):
        cutoff = time.time() - 1800
        return {key for key, (_, saved_at) in self._entries.items() if saved_at > cutoff}

    def values(self):
        return [value for values, _ in self._entries.values() for value in values]

    def add(self, hash, values):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.fchmod(fd, 0o600)
        saved_at = time.time()
        with os.fdopen(fd, 'a', encoding='utf-8') as f:
            f.write(json.dumps({'hash': hash, 'values': values, 'saved_at': saved_at}) + '\n')
            f.flush()
            os.fsync(f.fileno())
        self._entries[hash] = (values, saved_at)


def shape(app, path, status, content_type, body, secrets, stats=None):
    mime = content_type.split(';', 1)[0].strip().lower()
    if mime != 'application/json' and not mime.endswith('+json'):
        return 415, {'error': 'non-JSON response withheld', 'content_type': 'non-JSON'}
    try:
        def reject_constant(value):
            raise ValueError('invalid JSON constant')
        data = json.loads(body, parse_constant=reject_constant)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return 415, {'error': 'invalid JSON response withheld'}
    try:
        data, counts = redact(data, secrets)
        if stats is not None:
            stats.update(counts)
        safe_path, _ = secrets.scrub(path)
        result = {'app': app, 'path': safe_path, 'untrusted_data': data}
        def encoded():
            return json.dumps(result, ensure_ascii=True, allow_nan=False).encode('utf-8')
        if len(encoded()) > MAX_RESPONSE:
            if not isinstance(data, list):
                return 413, {'error': 'response too large'}
            result.update(truncated=True, total_items=len(data), narrow_with=PAGING.get(app, 'filter'))
            low, high = 0, len(data)
            while low < high:
                mid = (low + high + 1) // 2
                result['untrusted_data'] = data[:mid]
                if len(encoded()) <= MAX_RESPONSE:
                    low = mid
                else:
                    high = mid - 1
            result['untrusted_data'] = data[:low]
            if len(encoded()) > MAX_RESPONSE:
                return 413, {'error': 'response too large'}
        rule = tripwire(encoded().decode('utf-8'))
        if rule:
            if stats is not None:
                stats['tripwire'] = rule
            return 502, {'error': 'tripwire', 'rule': rule}
        return status, result
    except (RecursionError, TypeError, ValueError):
        return 502, {'error': 'response withheld'}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(app, path_qs, cfg):
    try:
        config = cfg['apps'][app]
        request = Request(config['base'].rstrip('/') + path_qs, headers=config.get('headers', {}), method='GET')
        opener = build_opener(ProxyHandler({}), NoRedirect())
        try:
            response = opener.open(request, timeout=TIMEOUT)
        except HTTPError as err:
            response = err
        with response:
            body = response.read(MAX_UPSTREAM + 1)
            if len(body) > MAX_UPSTREAM:
                return 413, 'application/json', b'{"error":"upstream response too large"}'
            return response.status, response.headers.get('Content-Type', ''), body
    except Exception:
        logging.warning('upstream request failed app=%s', app)
        return 502, 'application/json', b'{"error":"upstream unreachable"}'


class HarvestState:
    """Authorize responses only within a completed, fresh harvest generation."""
    def __init__(self):
        self._lock = threading.Lock()
        self._generation = 0
        self._expires = 0

    def begin(self):
        with self._lock:
            self._generation += 1
            self._expires = 0
            return self._generation

    def finish(self, generation, success):
        with self._lock:
            if generation == self._generation:
                self._expires = time.monotonic() + HARVEST_INTERVAL if success else 0

    def ticket(self):
        with self._lock:
            return self._generation if time.monotonic() < self._expires else None

    @contextmanager
    def response_guard(self, ticket):
        # Keep refresh from invalidating the inventory between redaction and send.
        with self._lock:
            yield ticket is not None and ticket == self._generation and time.monotonic() < self._expires


def harvest_once(cfg, secrets, cache):
    complete = True
    for value in cache.values():
        secrets.add(value, 'tracker')
    for app, paths in PROVIDER_PATHS.items():
        if app not in cfg['apps']:
            continue
        for path in paths:
            status, _, body = fetch(app, path, cfg)
            if status != 200:
                complete = False
                continue
            try:
                for value in harvest_provider_fields(json.loads(body)):
                    secrets.add(value, app)
            except (ValueError, TypeError):
                complete = False
                logging.warning('harvest failed app=%s', app)
    for app in ('qbit', 'qbit-ubits'):
        if app not in cfg['apps']:
            continue
        done = cache.done_hashes()
        status, _, body = fetch(app, '/api/v2/torrents/info', cfg)
        if status != 200:
            complete = False
            continue
        try:
            torrents = json.loads(body)
            if not isinstance(torrents, list):
                raise ValueError('invalid torrent inventory')
            for torrent in torrents:
                torrent_hash = torrent.get('hash', '')
                cache_key = app + ':' + torrent_hash
                if not re.fullmatch(r'(?:[a-fA-F0-9]{40}|[a-fA-F0-9]{64})', torrent_hash):
                    raise ValueError('invalid torrent hash')
                if cache_key in done:
                    continue
                status, _, body = fetch(app, '/api/v2/torrents/trackers?hash=' + torrent_hash, cfg)
                if status != 200:
                    complete = False
                    continue
                trackers = json.loads(body)
                if not isinstance(trackers, list) or any(not isinstance(t, dict) or not isinstance(t.get('url'), str) for t in trackers):
                    raise ValueError('invalid tracker inventory')
                values = harvest_tracker_urls([t['url'] for t in trackers])
                for value in values:
                    secrets.add(value, app)
                cache.add(cache_key, values)
        except (ValueError, TypeError, AttributeError):
            complete = False
            logging.warning('tracker harvest failed app=%s', app)
    return complete


def harvest_cycle(cfg, secrets, cache, state):
    generation = state.begin()
    success = False
    try:
        success = harvest_once(cfg, secrets, cache)
    except Exception:
        logging.error('harvest failed')
    finally:
        state.finish(generation, success)
    return success


def harvest_loop(cfg, secrets, cache, state):
    while True:
        success = harvest_cycle(cfg, secrets, cache, state)
        time.sleep(HARVEST_INTERVAL if success else HARVEST_RETRY)


class DiagHandler(BaseHTTPRequestHandler):
    def __getattr__(self, name):
        if name.startswith('do_'):
            return self.do_POST
        raise AttributeError(name)

    def log_message(self, format, *args):
        pass

    def respond(self, status, obj):
        raw = json.dumps(obj, ensure_ascii=True).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
        stats = getattr(self, 'stats', {})
        logging.info('app=%s status=%d bytes=%d exact=%d field=%d url=%d tripwire=%s',
                     getattr(self, 'app', '-'), status, len(raw), stats.get('exact', 0),
                     stats.get('field', 0), stats.get('url', 0), stats.get('tripwire', '-'))

    def do_GET(self):
        if self.client_address[0] != self.server.cfg['allow_client']:
            return self.respond(403, {'error': 'client forbidden'})
        parts = urlsplit(self.path)
        if parts.path == '/diag/':
            return self.respond(200, {'apps': sorted(self.server.cfg['apps']),
                                      'redaction_ready': self.server.harvest.ticket() is not None})
        match = re.fullmatch(r'/diag/([^/]+)(/.*)', parts.path)
        if not match:
            return self.respond(404, {'error': 'not found'})
        app, path = match.groups()
        self.app = app if app in APPS else '-'
        rule = check_path(app, path)
        if rule:
            return self.respond(403, {'error': 'blocked', 'rule': rule})
        if app not in self.server.cfg['apps']:
            return self.respond(403, {'error': 'blocked', 'rule': 'unknown-app'})
        ticket = self.server.harvest.ticket()
        if ticket is None:
            return self.respond(503, {'error': 'secret inventory unavailable', 'retry_after': HARVEST_RETRY})
        status, content_type, body = fetch(app, path + ('?' + parts.query if parts.query else ''), self.server.cfg)
        if status == 502 and body == b'{"error":"upstream unreachable"}':
            return self.respond(502, {'error': 'upstream unreachable', 'app': app})
        with self.server.harvest.response_guard(ticket) as ready:
            if not ready:
                return self.respond(503, {'error': 'secret inventory unavailable', 'retry_after': HARVEST_RETRY})
            self.stats = {}
            status, result = shape(app, path, status, content_type, body, self.server.secrets, self.stats)
            return self.respond(status, result)

    def do_POST(self):
        self.respond(405, {'error': 'method not allowed'})
    do_PUT = do_PATCH = do_DELETE = do_POST
    do_HEAD = do_OPTIONS = do_POST


def create_server(cfg, secrets, harvest=None):
    server = ThreadingHTTPServer((cfg.get('bind', '0.0.0.0'), cfg.get('port', 8796)), DiagHandler)
    server.cfg, server.secrets = cfg, secrets
    server.harvest = harvest if harvest is not None else HarvestState()
    return server


def selftest():
    secrets = Secrets()
    secrets.add('fake-canary-123456', 'test')
    result, _ = redact({'message': 'fake-canary-123456', 'apiKey': 'x'}, secrets)
    assert 'fake-canary-123456' not in json.dumps(result)
    assert check_path('sonarr', '/api/v3/config/host') is not None
    assert check_path('sonarr', '/api/v3/health') is None
    assert tripwire('ghp_' + 'a' * 36) == 'github'
    print('diag selftest: PASS')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['serve', 'selftest'])
    args = parser.parse_args()
    if args.command == 'selftest':
        selftest()
        return
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    with CONFIG.open(encoding='utf-8') as f:
        cfg = json.load(f)
    secrets = Secrets()
    for app, config in cfg['apps'].items():
        for value in config.get('headers', {}).values():
            secrets.add(value, app)
    cache = HarvestCache(STATE)
    for value in cache.values():
        secrets.add(value, 'tracker')
    harvest = HarvestState()
    threading.Thread(target=harvest_loop, args=(cfg, secrets, cache, harvest), daemon=True).start()
    create_server(cfg, secrets, harvest).serve_forever()


if __name__ == '__main__':
    main()
