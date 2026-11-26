"""An ordinary lxc adoption must not undo the separate source-enforcement stage."""
import contextlib
import io
import json
from pathlib import Path
import runpy
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).parents[1] / 'ansible/roles/lxc/files/pct_diff.py'


class EnrollmentPersistence(unittest.TestCase):
    def compare(self, wanted, live, marker):
        files = {'/etc/pve/lxc/110.conf': live,
                 '/etc/pve/firewall/110.fw': '# managed by proxmox lan_guard\n' if marker else '[OPTIONS]\nenable: 0\n'}
        def fake_open(path, *args, **kwargs):
            return io.StringIO(files[str(path)])
        out = io.StringIO()
        with patch('sys.argv', [str(SCRIPT), '110']), patch('sys.stdin', io.StringIO(json.dumps(wanted))), \
                patch('builtins.open', side_effect=fake_open), patch('os.path.exists', side_effect=lambda p: str(p) in files), \
                contextlib.redirect_stdout(out):
            runpy.run_path(str(SCRIPT), run_name='__main__')
        return json.loads(out.getvalue())

    def test_omitted_and_zero_flags_cannot_undo_enrollment(self):
        base = 'name=eth0,bridge=vmbr0,hwaddr=C2:C9:24:A1:03:2B,ip=192.168.9.154/24,type=veth'
        for wanted in [base, base + ',firewall=0']:
            result = self.compare({'net0': wanted}, 'net0: ' + base + ',firewall=1\n', True)
            self.assertEqual(result['differs'], {})
            self.assertEqual(result['args'], [])

    def test_other_requested_nic_changes_still_keep_the_security_flag(self):
        base = 'name=eth0,bridge=vmbr0,tag=30'
        result = self.compare({'net0': base}, 'net0: name=eth0,bridge=vmbr0,firewall=1\n', True)
        self.assertEqual(result['args'], ['--net0', base + ',firewall=1'])

    def test_unenrolled_guest_retains_existing_inventory_behavior(self):
        result = self.compare({'net0': 'name=eth0,bridge=vmbr0'}, 'net0: name=eth0,bridge=vmbr0,firewall=1\n', False)
        self.assertEqual(result['args'], ['--net0', 'name=eth0,bridge=vmbr0'])


if __name__ == '__main__':
    unittest.main()
