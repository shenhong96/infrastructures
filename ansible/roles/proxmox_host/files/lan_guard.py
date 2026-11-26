#!/usr/bin/env python3
"""Reviewed, fail-closed PVE guest source enforcement. No automatic guest restart.

inspect is read-only and needs no manifest. check plans enrollment; apply writes
NIC flags/guest policies only; enable separately compiles the installed backend
with ebtables proposed ON before writing that option. rollback restores a named
backup only if every target still equals what this tool wrote.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

ROOT = Path('/etc/pve')
BACKUPS = Path('/var/lib/proxmox-lan-guard/backups')
MAC = re.compile(r'(?i)^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$')
MODELS = ('virtio', 'e1000', 'e1000e', 'rtl8139', 'vmxnet3', 'ne2k_pci', 'i82551', 'i82557b', 'i82559er')


class GuardError(RuntimeError):
    pass


def run(argv):
    try:
        return subprocess.run(argv, text=True, capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GuardError('command failed: ' + argv[0] + ' (diagnostics withheld)') from exc


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest() if text is not None else None


def configs():
    ids = {}
    for family, directory in [('ct', ROOT / 'lxc'), ('vm', ROOT / 'qemu-server')]:
        for path in directory.glob('*.conf'):
            if path.stem.isdigit():
                ids[path.stem] = family
    return ids


def parse_config(text):
    return dict(line.split(': ', 1) for line in text.splitlines() if ': ' in line)


def current_config(vmid, family):
    return parse_config(run(['pct' if family == 'ct' else 'qm', 'config', vmid]))


def config_nics(config):
    return {k: v for k, v in config.items() if re.fullmatch(r'net\d+', k)}


def nic_fields(value):
    parts = value.split(',')
    if any('=' not in p for p in parts):
        raise GuardError('NIC has an unrecognized field')
    fields = dict(p.split('=', 1) for p in parts)
    if len(fields) != len(parts):
        raise GuardError('NIC has duplicate fields')
    return fields


def with_flag(value):
    if re.search(r'(^|,)firewall=', value):
        return re.sub(r'(^|,)firewall=[^,]*', r'\1firewall=1', value)
    return value + ',firewall=1'


def mac_of(fields, family):
    return fields.get('hwaddr', '') if family == 'ct' else next((fields[m] for m in MODELS if m in fields), '')


def inspect():
    guests = []
    for vmid, family in sorted(configs().items()):
        fw = ROOT / 'firewall' / (vmid + '.fw')
        text = fw.read_text() if fw.exists() else None
        guests.append({'vmid': vmid, 'kind': family, 'action': 'REVIEW',
                       'existing_firewall_sha256': digest(text),
                       'nics': {name: {'config': value, 'mac': mac_of(nic_fields(value), family),
                                       'ipv4': [], 'ipv6': [], 'dhcp': False,
                                       'ipv6_reviewed': False, 'egress_sources_reviewed': False}
                                for name, value in config_nics(current_config(vmid, family)).items()}})
    return {'pve_firewall_version': run(['dpkg-query', '-W', '-f=${Version}', 'pve-firewall']).strip(),
            'compiled_rules_verified': False, 'guests': guests}


def validate(manifest, live_ids):
    entries = manifest.get('guests')
    if not isinstance(entries, list) or not entries:
        raise GuardError('manifest guests must be a non-empty owner-reviewed list')
    declared = {}
    for ent in entries:
        vmid = str(ent.get('vmid', ''))
        if not re.fullmatch(r'[1-9][0-9]+', vmid) or vmid in declared or ent.get('kind') not in ('ct', 'vm'):
            raise GuardError('invalid or duplicate guest entry')
        declared[vmid] = ent
    if declared.keys() != live_ids.keys():
        raise GuardError('manifest/live inventory mismatch')
    claimed = {}
    for vmid, ent in declared.items():
        if ent['kind'] != live_ids[vmid] or ent.get('action') != 'enroll':
            raise GuardError(vmid + ': every guest, including stopped QEMU guests, must be explicitly enrolled')
        if 'existing_firewall_sha256' not in ent:
            raise GuardError(vmid + ': existing firewall hash/null must be explicitly reviewed')
        if not isinstance(ent.get('nics'), dict) or not ent['nics']:
            raise GuardError(vmid + ': explicit NIC policy required')
        for name, spec in ent['nics'].items():
            if not re.fullmatch(r'net\d+', name) or not isinstance(spec, dict) or not MAC.fullmatch(spec.get('mac', '')):
                raise GuardError(vmid + ': invalid NIC/MAC policy')
            if not isinstance(spec.get('config'), str) or spec.get('ipv6_reviewed') is not True or spec.get('egress_sources_reviewed') is not True:
                raise GuardError(vmid + '/' + name + ': full NIC, IPv6 and namespace/Docker source review required')
            if not isinstance(spec.get('dhcp'), bool):
                raise GuardError(vmid + '/' + name + ': DHCP must be explicitly boolean')
            if not isinstance(spec.get('ipv4'), list) or not spec['ipv4'] or not isinstance(spec.get('ipv6'), list):
                raise GuardError(vmid + '/' + name + ': explicit IPv4/IPv6 host lists required')
            for version, key in [(4, 'ipv4'), (6, 'ipv6')]:
                for address in spec[key]:
                    ip = ipaddress.ip_interface(address)
                    if ip.version != version or ip.network.prefixlen != (32 if version == 4 else 128) or ip.ip.is_unspecified or ip.ip.is_multicast:
                        raise GuardError(vmid + '/' + name + ': allow only unicast host addresses (/32 or /128), never 0.0.0.0')
                    if ip.ip.is_loopback or str(ip.ip) in ('192.168.9.152', '192.168.9.2'):
                        raise GuardError('guest source policy must not permit the host, gateway or loopback identity')
                    owner = claimed.setdefault(str(ip.ip), (vmid, name))
                    if owner != (vmid, name):
                        raise GuardError('duplicate permitted address across NICs')
            if spec['dhcp'] and (spec.get('dhcp_lease_reviewed') is not True or spec.get('arp_probe_reviewed') is not True):
                raise GuardError(vmid + '/' + name + ': fixed DHCP reservation/lease and ARP probing must be reviewed')
            if spec.get('allow_arp_probe') and (not spec['dhcp'] or spec.get('arp_probe_reviewed') is not True):
                raise GuardError('zero-source ARP exception requires explicit reviewed DHCP probing')
    return declared


def preflight(manifest):
    if manifest.get('pve_firewall_version') != run(['dpkg-query', '-W', '-f=${Version}', 'pve-firewall']).strip():
        raise GuardError('installed pve-firewall version does not match reviewed manifest')
    host = ROOT / 'nodes/proxmox/host.fw'
    if not host.exists() or not re.search(r'(?m)^enable:\s*0\s*$', host.read_text()) or re.search(r'(?m)^nftables:\s*1', host.read_text()):
        raise GuardError('expected disabled host firewall and legacy iptables backend')
    cluster = (ROOT / 'firewall/cluster.fw').read_text()
    if not re.search(r'(?m)^enable:\s*1\s*$', cluster) or len(re.findall(r'(?m)^ebtables:\s*[01]\s*$', cluster)) != 1:
        raise GuardError('cluster must already be enabled with an explicit ebtables option')
    if not run(['iptables', '-S', 'FORWARD']).startswith('-P FORWARD ACCEPT'):
        raise GuardError('Docker bridge safeguard requires FORWARD ACCEPT')
    run(['pve-firewall', 'compile'])


def desired_fw(vmid, nics):
    dhcp = any(s['dhcp'] for s in nics.values())
    lines = ['# managed by proxmox lan_guard', '[OPTIONS]', 'enable: 1', 'policy_in: ACCEPT',
             'policy_out: ACCEPT', 'macfilter: 1', 'ipfilter: 1', 'dhcp: ' + str(int(dhcp)), '']
    for nic, spec in sorted(nics.items()):
        # Explicit probe exception only for reviewed DHCP behavior. It does not
        # authorize any other IPv4 address; required later live renew/reboot tests.
        addresses = spec['ipv4'] + spec['ipv6'] + (['0.0.0.0/32'] if spec.get('allow_arp_probe') is True else [])
        lines += [f'[IPSET ipfilter-{nic}]', *sorted(addresses), '']
    return '\n'.join(lines)


def plan(manifest, declared):
    changes = []
    for vmid, ent in declared.items():
        family = ent['kind']
        cfg = current_config(vmid, family)
        if set(config_nics(cfg)) != set(ent['nics']):
            raise GuardError(vmid + ': live NIC set differs from reviewed manifest')
        for nic, spec in ent['nics'].items():
            original = cfg[nic]
            fields = nic_fields(original)
            expected = nic_fields(spec['config'])
            # Idempotent after the sole permitted NIC change; every other field stays exact.
            fields.pop('firewall', None)
            expected.pop('firewall', None)
            if fields != expected or mac_of(fields, family).lower() != spec['mac'].lower():
                raise GuardError(vmid + '/' + nic + ': live NIC/MAC differs from reviewed manifest')
            if family == 'ct':
                ipval = fields.get('ip', '')
                if ipval == 'dhcp':
                    if not spec['dhcp']:
                        raise GuardError(vmid + ': live DHCP was not reviewed')
                elif str(ipaddress.ip_interface(ipval).ip) not in [str(ipaddress.ip_interface(x).ip) for x in spec['ipv4']]:
                    raise GuardError(vmid + ': implicit configured CT IPv4 is not in policy')
                ip6 = fields.get('ip6', '')
                if ip6 in ('auto', 'dhcp'):
                    raise GuardError(vmid + ': dynamic IPv6 needs stable source policy before enrollment')
                if ip6 and str(ipaddress.ip_interface(ip6).ip) not in [str(ipaddress.ip_interface(x).ip) for x in spec['ipv6']]:
                    raise GuardError(vmid + ': implicit configured CT IPv6 is not in policy')
            if with_flag(original) != original:
                if run(['pct' if family == 'ct' else 'qm', 'status', vmid]).strip() != 'status: stopped':
                    raise GuardError(vmid + ': stop guest in the maintenance window before changing NIC flag')
                changes.append({'kind': family, 'vmid': vmid, 'nic': nic, 'before': original, 'after': with_flag(original)})
        fw = ROOT / 'firewall' / (vmid + '.fw')
        existing = fw.read_text() if fw.exists() else None
        if vmid == '121':
            if ent.get('preserve_firewall') is not True or digest(existing) != ent['existing_firewall_sha256'] or existing is None:
                raise GuardError('121: preserve and hash the existing restrictive secure-transport firewall')
            if not all(re.search(r'(?m)^' + option + r':\s*1\s*$', existing) for option in ['enable', 'macfilter', 'ipfilter']):
                raise GuardError('121: mandatory filters are missing')
            if not all(re.search(r'(?m)^policy_' + direction + r':\s*DROP\s*$', existing) for direction in ['in', 'out']):
                raise GuardError('121: never replace its default DROP with open guest policies')
            continue
        if ent.get('preserve_firewall'):
            raise GuardError('preserve_firewall is only valid for 121; other guests need enforced generated policy')
        want = desired_fw(vmid, ent['nics'])
        if existing != want:
            if digest(existing) != ent['existing_firewall_sha256']:
                raise GuardError(vmid + ': existing firewall changed or was not reviewed')
            changes.append({'firewall': str(fw), 'before': existing, 'after': want})
    return changes


def compile_proposed(declared):
    # Installed compiler, in-memory override ONLY. Never writes /etc/pve or invokes apply.
    perl = ('PVE::Firewall::set_verbose(0); my $c=PVE::Firewall::load_clusterfw_conf(); '
            '$c->{options}->{ebtables}=1; my ($v4,$sets,$v6,$eb)=PVE::Firewall::compile($c,undef,undef); '
            'for my $r ($v4->{filter},$v6->{filter},$eb) { '
            'for my $k (sort keys %$r) { print "CHAIN $k\\n"; print "$_\\n" for @{$r->{$k}}; }}')
    output = run(['perl', '-MPVE::Firewall', '-e', perl])
    for vmid, ent in declared.items():
        for nic, spec in ent['nics'].items():
            index = nic[3:]
            iface = ('veth' if ent['kind'] == 'ct' else 'tap') + vmid + 'i' + index
            chain = iface + '-OUT-ARP'
            required = [f'CHAIN {chain}', f'-A {chain} -j DROP']
            ip_lines = '\n'.join(line for line in output.splitlines() if line.startswith('-A ' + iface + '-OUT '))
            mac_rule = '-m mac ! --mac-source ' + spec['mac'].lower() + ' -j DROP'
            for version in (4, 6):
                source_rule = f'-m set ! --match-set PVEFW-{vmid}-ipfilter-{nic}-v{version} src -j DROP'
                if source_rule.lower() not in ip_lines.lower():
                    raise GuardError(vmid + '/' + nic + ': installed compiler lacks interface IP source filtering')
            if mac_rule.lower() not in ip_lines.lower():
                raise GuardError(vmid + '/' + nic + ': installed compiler lacks interface MAC filtering')
            # Inspect per-chain rather than allowing another guest's address to satisfy a test.
            arp = '\n'.join(line for line in output.splitlines() if line.startswith('-A ' + chain + ' '))
            for address in spec['ipv4']:
                ip = str(ipaddress.ip_interface(address).ip)
                if not re.search(r'--arp-ip-src ' + re.escape(ip) + r'(?:/32)? -j RETURN', arp):
                    raise GuardError(vmid + '/' + nic + ': installed compiler did not produce expected ARP allow')
            for needle in required:
                if needle.lower() not in output.lower():
                    raise GuardError(vmid + '/' + nic + ': installed compiler output lacks expected MAC/IP/ARP enforcement')
    return output


def backup(changes):
    BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
    if BACKUPS.is_symlink():
        raise GuardError('backup folder must not be a symlink')
    BACKUPS.chmod(0o700)
    target = BACKUPS / (uuid.uuid4().hex + '.json')
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(changes, handle)
        handle.flush()
        os.fsync(handle.fileno())
    return target


def write_changes(changes):
    # pmxcfs disallows chmod/rename/temp-file writes. Direct write matches the
    # existing role's tee pattern; full preflight and backups precede every write.
    for ch in changes:
        if 'nic' in ch:
            run(['pct' if ch['kind'] == 'ct' else 'qm', 'set', ch['vmid'], '--' + ch['nic'], ch['after']])
        else:
            path = Path(ch['firewall'])
            if ch['after'] is None:
                path.unlink()
            else:
                path.write_text(ch['after'])


def rollback(path):
    path = Path(path).resolve()
    if path.parent != BACKUPS.resolve() or path.is_symlink():
        raise GuardError('rollback requires a named backup in the protected backup directory')
    changes = json.loads(path.read_text())
    reverse = []
    for ch in changes:
        if 'nic' in ch:
            if run(['pct' if ch['kind'] == 'ct' else 'qm', 'status', ch['vmid']]).strip() != 'status: stopped':
                raise GuardError('stop the guest before restoring a NIC flag')
            current = current_config(ch['vmid'], ch['kind'])[ch['nic']]
        else:
            target = Path(ch['firewall'])
            if target.parent != ROOT / 'firewall' or not re.fullmatch(r'(?:[1-9][0-9]+|cluster)\.fw', target.name):
                raise GuardError('invalid backup firewall target')
            current = target.read_text() if target.exists() else None
        if current not in (ch['after'], ch['before']):
            raise GuardError('rollback target changed since apply; refusing to overwrite it')
        if current != ch['before']:
            reverse.append(dict(ch, before=ch['after'], after=ch['before']))
    write_changes(list(reversed(reverse)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['inspect', 'check', 'apply', 'enable', 'rollback'])
    parser.add_argument('--manifest')
    parser.add_argument('--backup')
    args = parser.parse_args()
    try:
        if args.mode == 'inspect':
            print(json.dumps(inspect(), indent=2))
            return 0
        if args.mode == 'rollback':
            if not args.backup:
                raise GuardError('rollback needs --backup')
            rollback(args.backup)
            print('rollback complete')
            return 0
        if not args.manifest:
            raise GuardError('reviewed manifest required')
        manifest = json.loads(sys.stdin.read() if args.manifest == '-' else Path(args.manifest).read_text())
        declared = validate(manifest, configs())
        preflight(manifest)
        changes = plan(manifest, declared)
        print(json.dumps({'guests': len(declared), 'pending_changes': len(changes)}))
        if args.mode == 'check':
            return 0
        if args.mode == 'enable':
            if changes:
                raise GuardError('apply guest enrollment first, then inspect installed compiler output before enabling ebtables')
            if manifest.get('compiled_rules_verified') is not True:
                raise GuardError('explicit installed-version compiled-rule review is required')
            compile_proposed(declared)
            cluster = ROOT / 'firewall/cluster.fw'
            before = cluster.read_text()
            after = re.sub(r'(?m)^ebtables:\s*0\s*$', 'ebtables: 1', before)
            changes = [] if before == after else [{'firewall': str(cluster), 'before': before, 'after': after}]
        elif validate(manifest, configs()) != declared or plan(manifest, declared) != changes:
            raise GuardError('configuration changed during preflight')
        if changes:
            print('backup: ' + str(backup(changes)))
            write_changes(changes)
        print('apply complete; verify live rule attachment, counters and DHCP/IPv6 before claiming protection')
    except (GuardError, OSError, ValueError, KeyError, TypeError) as exc:
        print('lan_guard: REFUSED: ' + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
