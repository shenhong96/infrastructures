#!/usr/bin/env python3
"""Offline, owner-run PKI for diag's pinned mutual TLS. Never prints key material.

init DIRECTORY creates a NEW 0700 directory outside git (fails if it exists).
check DIRECTORY validates identities, private permissions and 30 days' validity.
Only each node's own key/cert and named public peer bundles are deployed. The CA
private key stays on the laptop/offline backup, never any server or container.
"""
import argparse
from ipaddress import IPv4Address
import os
from pathlib import Path
import stat
import subprocess
import sys

NODES = {'proxmox': '192.168.9.152', 'diag': '192.168.9.158',
         'vpn': '192.168.9.156', 'media': '192.168.9.154'}


def openssl(*args):
    result = subprocess.run(['openssl', *map(str, args)], capture_output=True, check=False)
    if result.returncode:
        # OpenSSL diagnostics may contain input data. Report the operation, not its stderr.
        raise ValueError('OpenSSL operation failed: ' + str(args[0]))
    return result.stdout


def init(directory):
    directory = Path(directory).resolve()
    # Do not place a private CA in any checkout, even if it is gitignored.
    if any((p / '.git').exists() for p in (directory, *directory.parents)):
        raise ValueError('PKI must be outside a git checkout')
    os.umask(0o077)
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    openssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256',
            '-out', directory / 'ca.key')
    openssl('req', '-new', '-x509', '-key', directory / 'ca.key', '-days', '3650',
            '-subj', '/CN=diag transport offline CA', '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-out', directory / 'ca.pem')
    (directory / 'peers').mkdir(mode=0o700)
    for name, ip in NODES.items():
        node = directory / name
        node.mkdir(mode=0o700)
        openssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', node / 'key.pem')
        openssl('req', '-new', '-key', node / 'key.pem', '-subj', '/CN=diag-' + name, '-out', node / 'request.pem')
        ext = node / 'extensions.cnf'
        ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                       'extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=IP:' + ip + '\n')
        openssl('x509', '-req', '-in', node / 'request.pem', '-CA', directory / 'ca.pem',
                '-CAkey', directory / 'ca.key', '-CAcreateserial', '-days', '365',
                '-extfile', ext, '-out', node / 'cert.pem')
        (directory / 'peers' / (name + '.pem')).write_bytes(
            (directory / 'ca.pem').read_bytes() + (node / 'cert.pem').read_bytes())
    check(directory)


def private(path):
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError('private key must be a regular owner-only file')


def check(directory):
    directory = Path(directory).resolve()
    if not directory.is_dir() or stat.S_IMODE(directory.stat().st_mode) & 0o077:
        raise ValueError('PKI directory must be owner-only')
    for name, ip in NODES.items():
        IPv4Address(ip)
        cert, key = directory / name / 'cert.pem', directory / name / 'key.pem'
        private(key)
        openssl('verify', '-CAfile', directory / 'ca.pem', '-purpose', 'sslserver', '-verify_ip', ip, cert)
        openssl('verify', '-CAfile', directory / 'ca.pem', '-purpose', 'sslclient', cert)
        openssl('x509', '-in', cert, '-noout', '-checkend', str(30 * 86400))
        public = openssl('x509', '-in', cert, '-pubkey', '-noout')
        if public != openssl('pkey', '-in', key, '-pubout'):
            raise ValueError('certificate/key mismatch')
        expected = (directory / 'ca.pem').read_bytes() + cert.read_bytes()
        if (directory / 'peers' / (name + '.pem')).read_bytes() != expected:
            raise ValueError('peer bundle does not exactly match CA and expected leaf')
    print('PKI validation PASS (4 identities, chain/IP/EKU/key match, >=30 days)')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['init', 'check'])
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    try:
        globals()[args.action](args.directory)
    except (ValueError, OSError):
        sys.exit('PKI operation failed; check directory, permissions, certificate validity and OpenSSL installation. No key values logged.')


if __name__ == '__main__':
    main()
