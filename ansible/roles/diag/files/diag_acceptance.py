#!/usr/bin/env python3
"""Live acceptance for the diag door (plan Task 8, spec section 8).

Runs as root on the Proxmox host against /run/diag-wake/diag.sock.
  init     write 3 random canaries to /root/diag-canaries.json (0600); never prints them
  check    GET a fixed endpoint list; assert no canary and no real app key leaks; PASS/FAIL only
  cleanup  delete the canary file
  selftest offline check of the leak detector

The owner plants the canaries (values read from the file in their own shell):
  A: paused qBittorrent (home) torrent named diag-canary, tracker
     http://canary.invalid/announce?passkey=<A>
  B: disabled Prowlarr indexer whose cookie field = <B>
  C: disabled Sonarr notification whose token field = <C>
Output never contains a canary or key value, only check names and counts.
"""
import base64
import http.client
import json
import os
import secrets
import socket
import string
import subprocess
import sys
import time
from urllib.parse import quote

SOCK = '/run/diag-wake/diag.sock'
CANARY_FILE = '/root/diag-canaries.json'


class UnixConn(http.client.HTTPConnection):
    def __init__(self):
        super().__init__('localhost', timeout=90)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(90)
        self.sock.connect(SOCK)


def get(path):
    conn = UnixConn()
    try:
        conn.request('GET', path)
        resp = conn.getresponse()
        return resp.status, resp.read().decode('utf-8', 'replace')
    finally:
        conn.close()


def forms(value):
    """The encodings a leaked value could hide in. Base64 at all 3 alignments."""
    out = {value, quote(value, safe=''), value.encode().hex(), json.dumps(value)[1:-1]}
    raw = value.encode()
    for shift in range(3):
        enc = base64.b64encode(b'\0' * shift + raw).decode()
        out.add(enc[4 if shift else 0:-4])  # drop chars mixed with prefix or padding
    return {f for f in out if len(f) >= 8}


def leaks(body, value):
    low = body.lower()
    return any(f.lower() in low for f in forms(value))


def partial(body, value, n=8):
    return any(value[i:i + n] in body for i in range(len(value) - n + 1))


def real_keys():
    raw = subprocess.run(['pct', 'exec', '121', '--', 'cat', '/etc/diag/config.json'],
                         capture_output=True, check=True).stdout
    out = []
    for app in json.loads(raw)['apps'].values():
        for v in app.get('headers', {}).values():
            out.append(v.split('Token="')[1].rstrip('"') if 'Token="' in v else v)
    return [k for k in out if len(k) >= 12]


def wrap(status, body):
    try:
        return status, json.loads(body)
    except ValueError:
        return status, None


DENIED = [('sonarr', '/api/v3/config/host'), ('sonarr', '/api/v3/release'), ('radarr', '/api/v3/release'),
          ('prowlarr', '/api/v1/search'), ('prowlarr', '/api/v1/indexer/test'), ('prowlarr', '/api/v1/indexer/1/newznab'),
          ('prowlarr', '/api/v1/indexer/1/download'), ('sonarr', '/api/v3/filesystem'), ('sonarr', '/api/v3/system/backup'),
          ('sonarr', '/api/v3/log/file'), ('sonarr', '/api/v3/manualimport'), ('qbit', '/api/v2/torrents/export'),
          ('qbit', '/api/v2/app/shutdown'), ('qbit', '/api/v2/log/main'), ('qbit', '/api/v2/app/cookies'),
          ('qbit', '/api/v2/app/getDirectoryContent'), ('qbit', '/api/v2/search/results'),
          ('qbit-ubits', '/api/v2/torrents/SSLParameters'), ('qui', '/api/instances/1/torrents/x/export'),
          ('qui', '/api/instances/1/getDirectoryContent'), ('jellyfin', '/Items/1/Download'), ('jellyfin', '/Packages'),
          ('sonarr', '/api/v3/../config/host'), ('sonarr', '/api/v3/%2e%2e/x')]


def check():
    with open(CANARY_FILE) as f:
        canaries = json.load(f)
    get('/diag/')  # wakes CT 121 (idle-stopped) so pct exec can read its config
    keys = real_keys()
    secret_list = [('canary ' + k, v) for k, v in canaries.items()] + [('app key %d' % i, v) for i, v in enumerate(keys)]
    results = []

    def record(name, ok, warn=False):
        results.append((name, ok or warn))
        print(('PASS ' if ok else ('WARN ' if warn else 'FAIL ')) + name)

    for _ in range(24):  # cold start: each app is ready after its first harvest (up to ~2 min)
        status, idx = wrap(*get('/diag/'))
        if status == 200 and idx and set(idx['ready']) == set(idx['apps']):
            break
        time.sleep(5)
    record('door answers /diag/ (all apps ready)', status == 200 and idx and set(idx['ready']) == set(idx['apps']))

    _, hist = wrap(*get('/diag/prowlarr/api/v1/history?pageSize=1'))
    before = (hist or {}).get('untrusted_data', {}).get('totalRecords')

    _, info = wrap(*get('/diag/qbit/api/v2/torrents/info?limit=500'))
    torrents = (info or {}).get('untrusted_data') or []
    test = [t.get('hash') for t in torrents if isinstance(t, dict) and 'diag-canary' in str(t.get('name', ''))]
    record('test torrent diag-canary found in home qBittorrent', len(test) == 1)
    h = test[0] if test else 'missing'

    reads = [('qbit', '/api/v2/torrents/info?limit=500'), ('qbit', '/api/v2/torrents/trackers?hash=' + h),
             ('qbit', '/api/v2/torrents/properties?hash=' + h), ('prowlarr', '/api/v1/indexer'),
             ('sonarr', '/api/v3/notification'), ('sonarr', '/api/v3/downloadclient'), ('sonarr', '/api/v3/health'),
             ('qui', '/api/instances'), ('jellyfin', '/System/Info')]
    for app, path in reads:
        status, body = get('/diag/%s%s' % (app, path))
        name = '%s %s' % (app, path.split('?')[0])
        record('%s answered (%d)' % (name, status), status in (200, 502))
        for label, value in secret_list:
            if leaks(body, value):
                record('%s leaks %s' % (name, label), False)
            elif label.startswith('canary') and partial(body, value):
                record('%s holds an 8+ char piece of %s' % (name, label), False, warn=True)
    record('no full secret leaked in %d reads' % len(reads), not any(not ok and 'leaks' in n for n, ok in results))

    for app, path in DENIED:
        status, _ = get('/diag/%s%s' % (app, path))
        record('%s %s blocked (%d)' % (app, path, status), status == 403)
    for app, path in [('jellyfin', '/Items/x/File'), ('qui', '/api/instances/1/torrents/x/export')]:
        status, _ = get('/diag/%s%s' % (app, path))
        record('%s %s withheld (%d)' % (app, path, status), status in (403, 415))

    _, hist = wrap(*get('/diag/prowlarr/api/v1/history?pageSize=1'))
    after = (hist or {}).get('untrusted_data', {}).get('totalRecords')
    record('prowlarr history unchanged by the run', before is not None and before == after)

    fails = sum(1 for _, ok in results if not ok)
    print('\n%d checks, %d not passed' % (len(results), fails))
    return 1 if fails else 0


def selftest():
    v = 'Ab3' + 'x' * 21
    for enc in [v, quote(v), v.encode().hex(), base64.b64encode(b'pre' + v.encode()).decode(),
                base64.b64encode(b'p' + v.encode()).decode(), base64.b64encode(b'pr' + v.encode()).decode()]:
        assert leaks('{"x": "%s"}' % enc, v), enc
    assert not leaks('{"x": "nothing here at all"}', v)
    assert partial('..Ab3xxxxx..', v) and not partial('..Ab3xxxx..', v)
    print('selftest PASS')


def main(cmd):
    if cmd == 'init':
        if os.path.exists(CANARY_FILE):
            sys.exit('canary file exists; run cleanup first')
        alphabet = string.ascii_letters + string.digits
        data = {k: ''.join(secrets.choice(alphabet) for _ in range(24)) for k in 'ABC'}
        fd = os.open(CANARY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f)
        print('wrote %s (0600). Plant A, B, C as the docstring says.' % CANARY_FILE)
    elif cmd == 'check':
        sys.exit(check())
    elif cmd == 'cleanup':
        os.remove(CANARY_FILE)
        print('removed %s' % CANARY_FILE)
    elif cmd == 'selftest':
        selftest()
    else:
        sys.exit(__doc__)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '')
