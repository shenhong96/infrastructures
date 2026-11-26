#!/usr/bin/env python3
"""Plant or remove the Task 8 canaries. Runs INSIDE CT 121 (it holds the app keys and
may reach the app ports); canary values arrive on stdin, are never printed.
  pct push 121 diag_canary_plant.py /tmp/p.py
  pct exec 121 -- python3 /tmp/p.py plant  < /root/diag-canaries.json
  pct exec 121 -- python3 /tmp/p.py remove < /root/diag-canaries.json
A: paused home-qBittorrent torrent 'diag-canary', tracker passkey=A
B: disabled Prowlarr indexer 'diag-canary', cookie field = B
C: disabled Sonarr Gotify notification 'diag-canary', app token = C
"""
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request

NAME = 'diag-canary'
CANARIES = json.load(sys.stdin)
CFG = json.load(open('/etc/diag/config.json'))['apps']


def scrub(text):
    for v in CANARIES.values():
        text = text.replace(v, '[canary]')
    return text


def call(app, path, data=None, method=None, ctype='application/json'):
    a = CFG[app]
    req = urllib.request.Request(a['base'] + path, data=data, method=method, headers=dict(a['headers']))
    if data is not None:
        req.add_header('Content-Type', ctype)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')


def report(what, status, body=''):
    ok = 200 <= status < 300
    print('%s %s (%d)%s' % ('OK  ' if ok else 'FAIL', what, status, '' if ok else ': ' + scrub(body)[:300]))


def bencode(x):
    if isinstance(x, int):
        return b'i%de' % x
    if isinstance(x, str):
        x = x.encode()
    if isinstance(x, bytes):
        return b'%d:%s' % (len(x), x)
    if isinstance(x, dict):
        return b'd' + b''.join(bencode(k) + bencode(x[k]) for k in sorted(x)) + b'e'
    raise TypeError(x)


def torrent():
    info = {'name': NAME, 'length': 1, 'piece length': 16384, 'pieces': hashlib.sha1(b'\0').digest(), 'private': 1}
    meta = bencode({'announce': 'http://canary.invalid/announce?passkey=' + CANARIES['A'], 'info': info})
    return meta, hashlib.sha1(bencode(info)).hexdigest()


def qbit_plant():
    meta, h = torrent()
    b = 'diagcanaryboundary'
    parts = [('stopped', 'true'), ('paused', 'true'), ('skip_checking', 'true')]
    body = b''.join(b'--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n' % (b.encode(), k.encode(), v.encode()) for k, v in parts)
    body += b'--%s\r\nContent-Disposition: form-data; name="torrents"; filename="%s.torrent"\r\nContent-Type: application/x-bittorrent\r\n\r\n' % (b.encode(), NAME.encode()) + meta + b'\r\n--%s--\r\n' % b.encode()
    report('qbit add torrent', *call('qbit', '/api/v2/torrents/add', body, 'POST', 'multipart/form-data; boundary=' + b))
    for _ in range(10):  # add is async: the torrent appears a moment later
        _, info = call('qbit', '/api/v2/torrents/info?hashes=' + h)
        if h in info:
            break
        time.sleep(1)
    print('OK   qbit torrent present' if h in info else 'FAIL qbit torrent not found after add')


def qbit_remove():
    _, h = torrent()
    report('qbit delete torrent', *call('qbit', '/api/v2/torrents/delete', ('hashes=%s&deleteFiles=true' % h).encode(), 'POST', 'application/x-www-form-urlencoded'))


def find(app, path):
    _, body = call(app, path)
    return [x for x in json.loads(body) if x.get('name') == NAME]


def prowlarr_plant():
    if find('prowlarr', '/api/v1/indexer'):
        return print('OK   prowlarr indexer already there')
    schemas = json.loads(call('prowlarr', '/api/v1/indexer/schema')[1])
    pick = next(s for s in schemas if s.get('implementation') == 'Cardigann' and s.get('privacy') == 'private'
                and any(f['name'] == 'cookie' for f in s['fields']))
    _, profiles = call('prowlarr', '/api/v1/appprofile')
    pick.update(name=NAME, enable=False, appProfileId=json.loads(profiles)[0]['id'], tags=[])
    for f in pick['fields']:
        if f['name'] == 'cookie':
            f['value'] = CANARIES['B']
    report('prowlarr add indexer (%s)' % pick.get('definitionName'),
           *call('prowlarr', '/api/v1/indexer?forceSave=true', json.dumps(pick).encode(), 'POST'))


def sonarr_plant():
    if find('sonarr', '/api/v3/notification'):
        return print('OK   sonarr notification already there')
    schemas = json.loads(call('sonarr', '/api/v3/notification/schema')[1])
    pick = next(s for s in schemas if s.get('implementation') == 'Gotify')
    pick.update(name=NAME, tags=[], **{k: False for k in pick if k.startswith('on') and isinstance(pick[k], bool)})
    for f in pick['fields']:
        if f['name'] == 'server':
            f['value'] = 'http://canary.invalid'
        if f['name'] == 'appToken':
            f['value'] = CANARIES['C']
    report('sonarr add notification', *call('sonarr', '/api/v3/notification?forceSave=true', json.dumps(pick).encode(), 'POST'))


def remove(app, path):
    for x in find(app, path):
        report('%s delete %s' % (app, path.rsplit('/', 1)[1]), *call(app, '%s/%d' % (path, x['id']), method='DELETE'))


if sys.argv[1:] == ['plant']:
    qbit_plant(); prowlarr_plant(); sonarr_plant()
elif sys.argv[1:] == ['remove']:
    qbit_remove(); remove('prowlarr', '/api/v1/indexer'); remove('sonarr', '/api/v3/notification')
else:
    sys.exit(__doc__)
