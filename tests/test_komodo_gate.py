"""Part of the recovery gate: Komodo's sync files can only carry what the sync that reads
them may apply. The rules are policy/gate.py's (the `gate` check runs them on every PR);
this runs them on the repo as it is. Run from the repo root: python3 -m unittest discover tests"""
import sys
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "policy"))
import gate  # noqa: E402


class KomodoGate(unittest.TestCase):
    def test_sync_files_pass_the_gate(self):
        exceptions = tomllib.loads((ROOT / "policy/exceptions.toml").read_text())
        self.assertEqual(gate.komodo_findings(ROOT, exceptions), [])

    def test_procedures_are_scheduled_after_adoption(self):
        # Phase 3 step 7 turned the job on.
        for proc in tomllib.loads((ROOT / "komodo/procedures.toml").read_text())["procedure"]:
            with self.subTest(proc["name"]):
                self.assertTrue(proc["config"]["schedule_enabled"])


if __name__ == "__main__":
    unittest.main()
