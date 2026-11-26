import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).parents[1] / 'ansible/roles/proxmox_host/files/lan_guard.py'
spec = importlib.util.spec_from_file_location('lan_guard', SCRIPT)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'pve'
        (self.root / 'firewall').mkdir(parents=True)
        self.root_patch = patch.object(guard, 'ROOT', self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.backup_patch = patch.object(guard, 'BACKUPS', Path(self.tmp.name) / 'backups')
        self.backup_patch.start()
        self.addCleanup(self.backup_patch.stop)
        self.nic = 'name=eth0,bridge=vmbr0,firewall=1,gw=192.168.9.2,hwaddr=12:91:CA:F3:B7:84,ip=192.168.9.153/24,type=veth'
        self.policy = {'config': self.nic, 'mac': '12:91:CA:F3:B7:84', 'ipv4': ['192.168.9.153/32'],
                       'ipv6': [], 'dhcp': False, 'ipv6_reviewed': True, 'egress_sources_reviewed': True}
        self.guest = {'vmid': '101', 'kind': 'ct', 'action': 'enroll', 'existing_firewall_sha256': None,
                      'nics': {'net0': self.policy}}

    def validate(self, entries=None, live=None):
        return guard.validate({'guests': entries or [self.guest]}, live or {'101': 'ct'})

    def test_exact_inventory_and_stopped_guests_are_mandatory(self):
        with self.assertRaisesRegex(guard.GuardError, 'inventory mismatch'):
            self.validate(live={'101': 'ct', '401': 'vm'})
        other = {'vmid': 107, 'kind': 'vm', 'action': 'exclude', 'reason': 'DHCP'}
        with self.assertRaisesRegex(guard.GuardError, 'every guest'):
            self.validate([self.guest, other], {'101': 'ct', '107': 'vm'})

    def test_unknown_sources_ipv6_and_nic_are_refused(self):
        for key in ['config', 'ipv6_reviewed', 'egress_sources_reviewed', 'dhcp']:
            ent = copy.deepcopy(self.guest)
            ent['nics']['net0'].pop(key)
            with self.subTest(key=key), self.assertRaises(guard.GuardError):
                self.validate([ent])

    def test_no_subnet_or_zero_or_multicast_allowances(self):
        for ip in ['192.168.9.0/24', '0.0.0.0/32', '224.0.0.1/32']:
            ent = copy.deepcopy(self.guest)
            ent['nics']['net0']['ipv4'] = [ip]
            with self.subTest(ip=ip), self.assertRaisesRegex(guard.GuardError, 'unicast host'):
                self.validate([ent])

    def test_duplicate_source_addresses_refused(self):
        ent = copy.deepcopy(self.guest)
        ent['vmid'] = '102'
        with self.assertRaisesRegex(guard.GuardError, 'duplicate permitted'):
            self.validate([self.guest, ent], {'101': 'ct', '102': 'ct'})

    def test_host_and_gateway_identity_can_never_be_assigned_to_a_guest(self):
        for address in ['192.168.9.152/32', '192.168.9.2/32', '127.0.0.1/32']:
            ent = copy.deepcopy(self.guest)
            ent['nics']['net0']['ipv4'].append(address)
            with self.assertRaisesRegex(guard.GuardError, 'host, gateway or loopback'):
                self.validate([ent])

    def test_qemu_fixed_dhcp_is_explicit_not_guessed(self):
        ent = copy.deepcopy(self.guest)
        ent.update(vmid='107', kind='vm')
        nic = ent['nics']['net0']
        nic.update(config='virtio=12:91:CA:F3:B7:84,bridge=vmbr0', dhcp=True)
        with self.assertRaisesRegex(guard.GuardError, 'DHCP reservation'):
            self.validate([ent], {'107': 'vm'})
        nic.update(dhcp_lease_reviewed=True, arp_probe_reviewed=True, allow_arp_probe=True)
        self.validate([ent], {'107': 'vm'})
        fw = guard.desired_fw('107', ent['nics'])
        self.assertIn('dhcp: 1', fw)
        self.assertIn('0.0.0.0/32', fw)
        with patch.object(guard, 'current_config', return_value={'net0': nic['config']}), patch.object(guard, 'run', return_value='status: stopped'):
            changes = guard.plan({}, {'107': ent})
        self.assertEqual(changes[0]['after'], nic['config'] + ',firewall=1')
        self.assertEqual(changes[0]['kind'], 'vm')

    def test_zero_probe_exception_requires_reviewed_dhcp(self):
        self.policy['allow_arp_probe'] = True
        with self.assertRaisesRegex(guard.GuardError, 'zero-source'):
            self.validate()

    def test_full_nic_is_preserved_and_running_guest_not_reconfigured(self):
        original = self.nic.replace('firewall=1', 'firewall=0') + ',tag=30'
        self.policy['config'] = original
        with patch.object(guard, 'current_config', return_value={'net0': original}), patch.object(guard, 'run', return_value='status: running'):
            with self.assertRaisesRegex(guard.GuardError, 'stop guest'):
                guard.plan({}, {'101': self.guest})
        with patch.object(guard, 'current_config', return_value={'net0': original}), patch.object(guard, 'run', return_value='status: stopped'):
            change = guard.plan({}, {'101': self.guest})[0]
        self.assertEqual(change['after'], original.replace('firewall=0', 'firewall=1'))

    def test_unknown_firewall_not_overwritten_and_hash_adoption_idempotent(self):
        target = self.root / 'firewall/101.fw'
        previous = '[OPTIONS]\nenable: 0\n# owner rules\n'
        target.write_text(previous)
        with patch.object(guard, 'current_config', return_value={'net0': self.nic}):
            with self.assertRaisesRegex(guard.GuardError, 'not reviewed'):
                guard.plan({}, {'101': self.guest})
            self.guest['existing_firewall_sha256'] = guard.digest(previous)
            changes = guard.plan({}, {'101': self.guest})
            handle = guard.backup(changes)
            guard.write_changes(changes)
            self.assertEqual(guard.plan({}, {'101': self.guest}), [])
            guard.rollback(handle)
            self.assertEqual(target.read_text(), previous)
            self.assertEqual(handle.stat().st_mode & 0o777, 0o600)

    def test_partial_apply_rollback_and_drift_refusal(self):
        target = self.root / 'firewall/101.fw'
        changes = [{'firewall': str(target), 'before': None, 'after': 'new\n'}]
        handle = guard.backup(changes)
        guard.rollback(handle)  # write never happened; safe no-op
        guard.write_changes(changes)
        target.write_text('owner changed it\n')
        with self.assertRaisesRegex(guard.GuardError, 'target changed'):
            guard.rollback(handle)
        target.write_text('new\n')
        guard.rollback(handle)
        self.assertFalse(target.exists())

    def test_extra_nic_and_implicit_ct_address_are_refused(self):
        for cfg in [{'net0': self.nic, 'net1': self.nic}, {'net0': self.nic.replace('.153/24', '.154/24')}]:
            with patch.object(guard, 'current_config', return_value=cfg), self.assertRaises(guard.GuardError):
                guard.plan({}, {'101': self.guest})

    def test_installed_version_guard_and_forward_policy(self):
        host = self.root / 'nodes/proxmox'
        host.mkdir(parents=True)
        (host / 'host.fw').write_text('[OPTIONS]\nenable: 0\n')
        (self.root / 'firewall/cluster.fw').write_text('[OPTIONS]\nenable: 1\nebtables: 0\n')
        def run(argv):
            return '6.0.4' if argv[0] == 'dpkg-query' else '-P FORWARD ACCEPT\n'
        with patch.object(guard, 'run', side_effect=run):
            guard.preflight({'pve_firewall_version': '6.0.4'})
            with self.assertRaisesRegex(guard.GuardError, 'version'):
                guard.preflight({'pve_firewall_version': 'unknown'})

    def test_121_never_becomes_open_policy(self):
        ent = copy.deepcopy(self.guest)
        ent['vmid'] = '121'
        with patch.object(guard, 'current_config', return_value={'net0': self.nic}):
            with self.assertRaisesRegex(guard.GuardError, 'preserve'):
                guard.plan({}, {'121': ent})

    def test_installed_compiler_checks_each_guest_arp_chain(self):
        good = ('CHAIN veth101i0-OUT-ARP\n-A veth101i0-OUT-ARP -p ARP --arp-ip-src 192.168.9.153 -j RETURN\n'
                '-A veth101i0-OUT-ARP -j DROP\n'
                '-A veth101i0-OUT -m mac ! --mac-source 12:91:CA:F3:B7:84 -j DROP\n'
                '-A veth101i0-OUT -m set ! --match-set PVEFW-101-ipfilter-net0-v4 src -j DROP\n'
                '-A veth101i0-OUT -m set ! --match-set PVEFW-101-ipfilter-net0-v6 src -j DROP\n')
        with patch.object(guard, 'run', return_value=good):
            self.assertEqual(guard.compile_proposed({'101': self.guest}), good)
        with patch.object(guard, 'run', return_value=good.replace('veth101', 'veth999')):
            with self.assertRaises(guard.GuardError):
                guard.compile_proposed({'101': self.guest})


if __name__ == '__main__':
    unittest.main()
