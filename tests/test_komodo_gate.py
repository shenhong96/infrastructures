"""Part of the recovery gate: Komodo's sync files can only carry what the sync that reads
them may apply. Run from the repo root: python3 -m unittest discover tests"""
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Top-level tables each file may hold. Procedures and actions (the only things that can be
# scheduled) live in komodo/procedures.toml, which only the automation sync reads. The syncs
# themselves are defined in Ansible, never in git.
ALLOWED = {
    "komodo/servers.toml": {"server"},
    "komodo/procedures.toml": {"procedure"},
}
STACK_TABLES = {"stack"}


class KomodoGate(unittest.TestCase):
    def tomls(self):
        for folder in ("komodo", "stacks"):
            yield from sorted((ROOT / folder).rglob("*.toml"))

    def test_only_expected_tables(self):
        for path in self.tomls():
            rel = path.relative_to(ROOT).as_posix()
            with self.subTest(rel):
                self.assertTrue(rel in ALLOWED or rel.startswith("stacks/"), f"{rel} is not a known sync file")
                tables = set(tomllib.loads(path.read_text()))
                self.assertLessEqual(tables, ALLOWED.get(rel, STACK_TABLES))

    def test_no_sync_definition_in_git(self):
        self.assertFalse((ROOT / "komodo/sync.toml").exists())

    def test_servers_never_rotate_keys_by_themselves(self):
        servers = tomllib.loads((ROOT / "komodo/servers.toml").read_text())["server"]
        for server in servers:
            with self.subTest(server["name"]):
                self.assertFalse(server["config"]["auto_rotate_keys"])
                self.assertEqual(server["config"]["address"], "")

    def test_procedures_stay_unscheduled_until_the_end_of_adoption(self):
        # Flip this test, in the same commit, when Phase 3 step 7 turns the job on.
        for proc in tomllib.loads((ROOT / "komodo/procedures.toml").read_text())["procedure"]:
            with self.subTest(proc["name"]):
                self.assertFalse(proc["config"]["schedule_enabled"])


if __name__ == "__main__":
    unittest.main()
