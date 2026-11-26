"""Real stunnel/diag transport integration tests; all state stays in tempdirs."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

try:
    import yaml
    from jinja2 import Environment
except ImportError:  # match the repository's declared test dependencies
    yaml = None
    Environment = None

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / 'ansible/roles/diag_transport'
DIAG_PATH = ROOT / 'ansible/roles/diag/files/diag.py'
PKI_PATH = ROOT / 'tools/diag-pki.py'
STUNNEL = shutil.which('stunnel4') or shutil.which('stunnel')


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


diag = load_module('diag_transport_test_diag', DIAG_PATH)


def run(*args, check=True):
    return subprocess.run([str(x) for x in args], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=check, text=True)


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def wait_port(port, process, timeout=4):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if process.poll() is not None:
            raise AssertionError(f'stunnel exited early ({process.returncode})')
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                return
        except OSError:
            time.sleep(.025)
    raise AssertionError(f'stunnel did not listen on loopback port {port}')


@unittest.skipUnless(STUNNEL, 'stunnel4/stunnel binary is not installed')
@unittest.skipUnless(yaml and Environment, 'PyYAML and Jinja2 are required')
class StunnelTransport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = (ROLE / 'templates/stunnel.conf.j2').read_text()
        cls.defaults = yaml.safe_load((ROLE / 'defaults/main.yml').read_text())

    def backend_handler(self):
        owner = self
        class Backend(BaseHTTPRequestHandler):
            def do_GET(self):
                owner.seen_headers.append(self.headers.get('X-Api-Key'))
                body = json.dumps({'message': 'upstream', 'apiKey': 'dont-leak-this'}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            def log_message(self, *args):
                pass
        self.seen_headers = []
        return Backend

    def cert(self, name, ip='127.0.0.1', days=2, ca_key=None, ca=None):
        key, csr, cert, ext = (self.dir / f'{name}.{suffix}' for suffix in ('key', 'csr', 'pem', 'ext'))
        run('openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', key)
        run('openssl', 'req', '-new', '-key', key, '-subj', f'/CN={name}', '-out', csr)
        ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                       'extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=IP:' + ip + '\n')
        run('openssl', 'x509', '-req', '-in', csr, '-CA', ca or self.ca, '-CAkey', ca_key or self.ca_key,
            '-CAcreateserial', '-days', str(days), '-extfile', ext, '-out', cert)
        return cert, key

    def render(self, client, accept, connect, peer_ip='127.0.0.1', identity=None, peer_cert=None,
               peer_ca=None, name='integration'):
        identity = identity or self.client_identity
        peer_cert = peer_cert or self.server_identity[0]
        peer_ca = peer_ca or self.ca
        bundle = self.dir / f'{name}-peer.pem'
        bundle.write_bytes(Path(peer_ca).read_bytes() + Path(peer_cert).read_bytes())
        vars = {
            'inventory_hostname': 'diag',
            'diag_transport_services': {'diag': [{'name': name, 'client': client,
                'accept': accept, 'connect': connect, 'peer': 'peer'}]},
            'diag_transport_nodes': {'peer': {'ip': peer_ip}},
        }
        rendered = Environment().from_string(self.template).render(**vars)
        rendered = rendered.replace('/etc/diag-tls/identity.pem', str(identity[0]))
        rendered = rendered.replace('/etc/diag-tls/identity.key', str(identity[1]))
        rendered = rendered.replace(f'/etc/diag-tls/peers/peer.pem', str(bundle))
        conf = self.dir / f'{name}.conf'
        conf.write_text(rendered)
        return conf

    def start(self, conf):
        log = open(self.dir / (conf.stem + '.log'), 'w')
        self.addCleanup(log.close)
        proc = subprocess.Popen([STUNNEL, str(conf)], stdout=log, stderr=log)
        self.addCleanup(self.stop, proc)
        return proc

    @staticmethod
    def stop(proc):
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)

    def tunnel_pair(self, server_identity=None, server_peer=None, server_peer_ip='127.0.0.1',
                    client_identity=None, client_peer=None, client_peer_ip='127.0.0.1', tag='pair'):
        server_identity = server_identity or self.server_identity
        client_identity = client_identity or self.client_identity
        tls_port, local_port = free_port(), free_port()
        server_conf = self.render(False, f'127.0.0.1:{tls_port}', f'127.0.0.1:{self.backend.server_port}',
            server_peer_ip, server_identity, server_peer or client_identity[0], self.ca, tag + '-server')
        client_conf = self.render(True, f'127.0.0.1:{local_port}', f'127.0.0.1:{tls_port}',
            client_peer_ip, client_identity, client_peer or server_identity[0], self.ca, tag + '-client')
        sp = self.start(server_conf)
        wait_port(tls_port, sp)
        cp = self.start(client_conf)
        wait_port(local_port, cp)
        return local_port, cp, sp

    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory(prefix='diag-transport-')
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.ca_key, self.ca = self.dir / 'ca.key', self.dir / 'ca.pem'
        run('openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', self.ca_key)
        run('openssl', 'req', '-new', '-x509', '-key', self.ca_key, '-days', '3', '-subj', '/CN=test CA',
            '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-out', self.ca)
        self.backend = ThreadingHTTPServer(('127.0.0.1', 0), self.backend_handler())
        threading.Thread(target=self.backend.serve_forever, daemon=True).start()
        self.addCleanup(self.backend.server_close)
        self.addCleanup(self.backend.shutdown)
        self.client_identity = self.cert('client')
        self.server_identity = self.cert('server')

    def test_template_maps_all_seven_services_and_forbids_non_loopback_diag(self):
        clients = [s for host in self.defaults['diag_transport_services'].values() for s in host if s['client']]
        servers = [s for host in self.defaults['diag_transport_services'].values() for s in host if not s['client']]
        self.assertEqual(len(clients), 8)  # seven diag upstreams plus proxmox->diag
        diag_clients = {s['name']: s for s in self.defaults['diag_transport_services']['diag'] if s['client']}
        self.assertEqual(set(diag_clients), {'qbit', 'qbit-ubits', 'qui', 'sonarr', 'radarr', 'prowlarr', 'jellyfin'})
        self.assertEqual(len(servers), 8)
        server_listeners = {s['accept'] for s in servers}
        for service in clients:
            self.assertIn(service['connect'], server_listeners, service['name'])
        for host, services in self.defaults['diag_transport_services'].items():
            for service in services:
                if service['client']:
                    self.assertEqual(service['accept'].split(':')[0], '127.0.0.1', service['name'])
                else:
                    self.assertEqual(service['connect'].split(':')[0], '127.0.0.1', service['name'])
        cfg = {'bind': '0.0.0.0', 'allow_client': '127.0.0.1', 'apps': {}}
        with self.assertRaises(ValueError):
            diag.create_server(cfg, diag.Secrets())

    def test_diag_fetch_redacts_through_two_real_stunnel_processes(self):
        local, _, _ = self.tunnel_pair()
        key = 'test-api-key-' + 'Z' * 18
        cfg = {'apps': {'sonarr': {'base': f'http://127.0.0.1:{local}', 'headers': {'X-Api-Key': key}}}}
        status, mime, body = diag.fetch('sonarr', '/api/v3/health', cfg)
        self.assertEqual((status, mime), (200, 'application/json'))
        # The same header secret is loaded by serve() before fetch.
        secrets = diag.Secrets()
        for item in diag.header_secrets(cfg['apps']['sonarr']['headers']):
            secrets.add(item, 'sonarr')
        shaped_status, shaped = diag.shape('sonarr', '/api/v3/health', status, mime, body, secrets)
        self.assertEqual(shaped_status, 200)
        self.assertNotIn('dont-leak-this', json.dumps(shaped))
        self.assertEqual(self.seen_headers, [key])

    def test_peer_verification_rejects_untrusted_wrong_ip_and_unpinned_leaf(self):
        other_ca_key = self.dir / 'other-ca.key'
        other_ca = self.dir / 'other-ca.pem'
        run('openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', other_ca_key)
        run('openssl', 'req', '-new', '-x509', '-key', other_ca_key, '-days', '2', '-subj', '/CN=untrusted CA',
            '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-out', other_ca)
        untrusted_server = self.cert('untrusted-server', ca_key=other_ca_key, ca=other_ca)
        local, _, _ = self.tunnel_pair(server_identity=untrusted_server, tag='untrusted')
        cfg = {'apps': {'sonarr': {'base': f'http://127.0.0.1:{local}', 'headers': {'X-Api-Key': 'must-not-fallback'}}}}
        self.assertEqual(diag.fetch('sonarr', '/api/v3/health', cfg)[0], 502)
        self.assertEqual(self.seen_headers, [], 'plaintext request reached backend despite untrusted TLS peer')
        # Trusted chain, but server cert SAN does not match the configured checkIP.
        wrong_server = self.cert('wrong-server', ip='192.0.2.44')
        local, _, _ = self.tunnel_pair(server_identity=wrong_server, tag='wrong-ip')
        cfg['apps']['sonarr']['base'] = f'http://127.0.0.1:{local}'
        self.assertEqual(diag.fetch('sonarr', '/api/v3/health', cfg)[0], 502)
        # Same CA and valid identity, but server's exact leaf pin names another client.
        allowed, _ = self.cert('allowed-client')
        alternate = self.cert('alternate-client')
        local, _, _ = self.tunnel_pair(client_identity=alternate,
                                       server_peer=allowed, tag='wrong-pin')
        cfg['apps']['sonarr']['base'] = f'http://127.0.0.1:{local}'
        self.assertEqual(diag.fetch('sonarr', '/api/v3/health', cfg)[0], 502)

    def test_unpinned_and_expired_server_never_receives_credentials(self):
        alternate_server = self.cert('alternate-server')
        local, _, _ = self.tunnel_pair(server_identity=alternate_server,
                                       client_peer=self.server_identity[0], tag='wrong-server-pin')
        cfg = {'apps': {'sonarr': {'base': f'http://127.0.0.1:{local}', 'headers': {'X-Api-Key': 'not-forwarded'}}}}
        self.assertEqual(diag.fetch('sonarr', '/api/v3/health', cfg)[0], 502)
        expired_server = self.cert('expired-server', days=0)
        local, _, _ = self.tunnel_pair(server_identity=expired_server, tag='expired-server')
        cfg['apps']['sonarr']['base'] = f'http://127.0.0.1:{local}'
        self.assertEqual(diag.fetch('sonarr', '/api/v3/health', cfg)[0], 502)
        self.assertEqual(self.seen_headers, [])

    def test_expired_and_missing_client_credentials_are_rejected(self):
        expired = self.cert('expired-client', days=0)
        local, _, _ = self.tunnel_pair(client_identity=expired, tag='expired')
        cfg = {'apps': {'sonarr': {'base': f'http://127.0.0.1:{local}', 'headers': {}}}}
        self.assertEqual(diag.fetch('sonarr', '/api/v3/health', cfg)[0], 502)
        # Connect without presenting any client identity; the rendered server
        # must abort the TLS handshake before its plaintext backend is touched.
        tls_port = free_port()
        server_conf = self.render(False, f'127.0.0.1:{tls_port}', f'127.0.0.1:{self.backend.server_port}', name='missing-client-server')
        server_proc = self.start(server_conf)
        wait_port(tls_port, server_proc)
        result = run('openssl', 's_client', '-connect', f'127.0.0.1:{tls_port}', '-CAfile', self.ca,
                     '-verify_ip', '127.0.0.1', '-quiet', check=False)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.seen_headers, [])

    def test_handshake_stall_and_trickle_body_obey_diag_absolute_deadline(self):
        # The remote port accepts TCP but never starts TLS; fetch's deadline must
        # bound the request even though stunnel's own connect timeout is longer.
        stalled = socket.socket()
        stalled.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        stalled.bind(('127.0.0.1', 0))
        stalled.listen()
        stopped = threading.Event()
        def hold_connection():
            try:
                stalled.settimeout(2)
                conn, _ = stalled.accept()
                with conn:
                    stopped.wait(2)
            except OSError:
                pass
        thread = threading.Thread(target=hold_connection, daemon=True)
        thread.start()
        self.addCleanup(stopped.set)
        self.addCleanup(stalled.close)
        local = free_port()
        conf = self.render(True, f'127.0.0.1:{local}', f'127.0.0.1:{stalled.getsockname()[1]}', name='stalled-client')
        proc = self.start(conf)
        wait_port(local, proc)
        cfg = {'apps': {'sonarr': {'base': f'http://127.0.0.1:{local}', 'headers': {'X-Api-Key': 'not-sent'}}}}
        with patch.object(diag, 'TIMEOUT', .2):
            start = time.monotonic()
            self.assertEqual(diag.fetch('sonarr', '/api/v3/health', cfg)[0], 502)
            self.assertLess(time.monotonic() - start, .8)

        # A valid TLS path with a response body that trickles beyond the same
        # absolute budget must fail rather than reset its timeout per read.
        owner = self
        class Trickle(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'{"message":"slow"}'
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                try:
                    for byte in body:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        time.sleep(.06)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            def log_message(self, *args):
                pass
        slow = ThreadingHTTPServer(('127.0.0.1', 0), Trickle)
        threading.Thread(target=slow.serve_forever, daemon=True).start()
        self.addCleanup(slow.server_close)
        self.addCleanup(slow.shutdown)
        tls_port, local = free_port(), free_port()
        server_conf = self.render(False, f'127.0.0.1:{tls_port}', f'127.0.0.1:{slow.server_port}', name='trickle-server')
        client_conf = self.render(True, f'127.0.0.1:{local}', f'127.0.0.1:{tls_port}', name='trickle-client')
        server_proc = self.start(server_conf)
        wait_port(tls_port, server_proc)
        client_proc = self.start(client_conf)
        wait_port(local, client_proc)
        cfg['apps']['sonarr']['base'] = f'http://127.0.0.1:{local}'
        with patch.object(diag, 'TIMEOUT', .25):
            start = time.monotonic()
            status, _, response = diag.fetch('sonarr', '/api/v3/health', cfg)
            self.assertEqual(status, 502)
            self.assertNotIn(b'slow', response)
            self.assertLess(time.monotonic() - start, .9)

    def test_invalid_client_certificate_is_rejected(self):
        other_key, other_ca = self.dir / 'other-client-ca.key', self.dir / 'other-client-ca.pem'
        run('openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', other_key)
        run('openssl', 'req', '-new', '-x509', '-key', other_key, '-days', '2', '-subj', '/CN=invalid client CA',
            '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-out', other_ca)
        invalid = self.cert('invalid-client', ca_key=other_key, ca=other_ca)
        local, _, _ = self.tunnel_pair(client_identity=invalid, tag='bad-client-cert')
        cfg = {'apps': {'sonarr': {'base': f'http://127.0.0.1:{local}', 'headers': {}}}}
        self.assertEqual(diag.fetch('sonarr', '/api/v3/health', cfg)[0], 502)
        self.assertEqual(self.seen_headers, [])


@unittest.skipUnless(shutil.which('openssl'), 'openssl is required')
class PKIGenerator(unittest.TestCase):
    def test_generator_checker_permissions_expiry_and_tampering(self):
        with tempfile.TemporaryDirectory(prefix='diag-pki-test-') as parent:
            directory = Path(parent) / 'pki'
            created = run(sys.executable, PKI_PATH, 'init', directory, check=False)
            self.assertEqual(created.returncode, 0, created.stdout + created.stderr)
            self.assertEqual((directory.stat().st_mode & 0o777), 0o700)
            checked = run(sys.executable, PKI_PATH, 'check', directory, check=False)
            self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
            key = directory / 'diag/key.pem'
            key.chmod(0o644)
            self.assertNotEqual(run(sys.executable, PKI_PATH, 'check', directory, check=False).returncode, 0)
            key.chmod(0o600)
            # Replace the first certificate with a validly parseable but untrusted leaf.
            cert = directory / 'diag/cert.pem'
            original = cert.read_bytes()
            cert.write_bytes(original.replace(b'BEGIN CERTIFICATE', b'BEGIN XERTIFICATE', 1))
            self.assertNotEqual(run(sys.executable, PKI_PATH, 'check', directory, check=False).returncode, 0)

    def test_checker_rejects_expired_certificate(self):
        with tempfile.TemporaryDirectory(prefix='diag-pki-expired-') as parent:
            directory = Path(parent) / 'pki'
            created = run(sys.executable, PKI_PATH, 'init', directory, check=False)
            self.assertEqual(created.returncode, 0, created.stdout + created.stderr)
            cert = directory / 'diag/cert.pem'
            key = directory / 'diag/key.pem'
            ca, ca_key = directory / 'ca.pem', directory / 'ca.key'
            csr = Path(parent) / 'expired.csr'
            ext = Path(parent) / 'expired.ext'
            ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                           'extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=IP:192.168.9.158\n')
            run('openssl', 'req', '-new', '-key', key, '-subj', '/CN=diag-expired', '-out', csr)
            run('openssl', 'x509', '-req', '-in', csr, '-CA', ca, '-CAkey', ca_key, '-CAcreateserial',
                '-days', '0', '-extfile', ext, '-out', cert)
            self.assertNotEqual(run(sys.executable, PKI_PATH, 'check', directory, check=False).returncode, 0)


if __name__ == '__main__':
    unittest.main()
