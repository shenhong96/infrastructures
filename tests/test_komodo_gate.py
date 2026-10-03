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

    def test_stacks_only_record_never_deploy(self):
        # A sync must create or update a stack record and nothing else: no deploy flag, no
        # automatic pull, update or webhook, and a project name that matches today's one.
        seen = set()
        for path in sorted((ROOT / "stacks").rglob("komodo.toml")):
            for stack in tomllib.loads(path.read_text())["stack"]:
                with self.subTest(stack["name"]):
                    self.assertNotIn(stack["name"], seen)
                    seen.add(stack["name"])
                    self.assertNotIn("deploy", stack)
                    config = stack["config"]
                    for flag in ("auto_pull", "poll_for_updates", "auto_update", "webhook_enabled"):
                        self.assertIs(config[flag], False, flag)
                    self.assertTrue(config["project_name"])
                    self.assertTrue(config["server"])
                    if config.get("files_on_host"):
                        # The compose file stays on the machine and is not in git (vpn): the
                        # folder holds only komodo.toml, and Komodo never writes an env file there.
                        self.assertEqual([p.name for p in path.parent.iterdir()], ["komodo.toml"])
                        self.assertTrue(config["run_directory"].startswith("/"))
                        self.assertTrue(config["env_file_path"] not in (".env", ""), "Komodo must not use .env")
                        continue
                    compose = ROOT / config["run_directory"] / config["file_paths"][0]
                    self.assertTrue(compose.is_file(), f"{compose} is missing")

    def test_procedures_are_scheduled_after_adoption(self):
        # Phase 3 step 7 turned the job on.
        for proc in tomllib.loads((ROOT / "komodo/procedures.toml").read_text())["procedure"]:
            with self.subTest(proc["name"]):
                self.assertTrue(proc["config"]["schedule_enabled"])


if __name__ == "__main__":
    unittest.main()
