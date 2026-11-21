import subprocess, sys, unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "ansible/roles/vpn/files/coverage/coverage.py"


class CoverageSelftest(unittest.TestCase):
    def test_selftest(self):
        r = subprocess.run([sys.executable, str(SCRIPT), "selftest"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
