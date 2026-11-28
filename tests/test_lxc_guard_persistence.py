"""The inventory, not a firewall-file marker, owns an enrolled CT's NIC firewall flag."""
import contextlib
import io
import json
from pathlib import Path
import runpy
import unittest
from unittest.mock import patch

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / 'ansible/roles/lxc/files/pct_diff.py'
GUARD_TASKS = ROOT / 'ansible/roles/proxmox_host/tasks/lan_guard.yml'


class EnrollmentPersistence(unittest.TestCase):
    def compare(self, wanted, live):
        files = {'/etc/pve/lxc/110.conf': live,
                 # A GUI edit may drop any marker; it must not change adoption results.
                 '/etc/pve/firewall/110.fw': '# managed by proxmox lan_guard\n'}
        def fake_open(path, *args, **kwargs):
            return io.StringIO(files[str(path)])
        out = io.StringIO()
        with patch('sys.argv', [str(SCRIPT), '110']), patch('sys.stdin', io.StringIO(json.dumps(wanted))), \
                patch('builtins.open', side_effect=fake_open), patch('os.path.exists', side_effect=lambda p: str(p) in files), \
                contextlib.redirect_stdout(out):
            runpy.run_path(str(SCRIPT), run_name='__main__')
        return json.loads(out.getvalue())

    def test_adoption_follows_inventory_regardless_of_firewall_file(self):
        result = self.compare({'net0': 'name=eth0,bridge=vmbr0'}, 'net0: name=eth0,bridge=vmbr0,firewall=1\n')
        self.assertEqual(result['args'], ['--net0', 'name=eth0,bridge=vmbr0'])

    def test_inventory_flag_keeps_enrollment(self):
        base = 'name=eth0,bridge=vmbr0,firewall=1'
        result = self.compare({'net0': base}, 'net0: ' + base + '\n')
        self.assertEqual(result['args'], [])

    def test_enrollment_requires_inventory_flag(self):
        text = GUARD_TASKS.read_text()
        guard = text.index('Every enrolled inventory-managed CT NIC already carries firewall=1')
        # The inventory check runs before the enrollment command, for every writing stage.
        self.assertLess(guard, text.index('Inspect, validate, enroll'))
        self.assertIn("when: proxmox_host_lan_guard_mode in ['check', 'apply', 'enable']", text[guard:])

    def test_already_enrolled_diag_and_media_apps_carry_the_flag(self):
        inventory = (ROOT / 'ansible/inventory.yml').read_text()
        for ip in ('192.168.9.156', '192.168.9.158'):
            line = next(l for l in inventory.splitlines() if 'ip=' + ip + '/' in l)
            self.assertRegex(line, r'(^|,)firewall=1(,|$)')


if __name__ == '__main__':
    unittest.main()
