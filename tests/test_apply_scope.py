"""What a merge applies (Semaphore's apply template, ansible/roles/semaphore) and what only the
laptop runs (policy/gate.py's LAPTOP_TAGS) cover every play in ansible/site.yml, and never
overlap: a new role in site.yml has to pick a side. Run from the repo root:
python3 -m unittest discover tests"""
import sys
import unittest
from pathlib import Path

try:
    import yaml
except ImportError:  # ci always has it
    yaml = None

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "policy"))
import gate  # noqa: E402


@unittest.skipIf(yaml is None, "needs PyYAML")
class ApplyScope(unittest.TestCase):
    def test_every_play_is_applied_by_a_merge_or_by_the_laptop(self):
        defaults = yaml.safe_load((ROOT / "ansible/roles/semaphore/defaults/main.yml").read_text())
        applied = set(defaults["semaphore_apply_tags"])
        tags = set()
        for play in yaml.safe_load((ROOT / "ansible/site.yml").read_text()):
            tags |= {play["tags"]} if isinstance(play["tags"], str) else set(play["tags"])
        self.assertEqual(applied | gate.LAPTOP_TAGS, tags - {"never"})
        self.assertEqual(applied & gate.LAPTOP_TAGS, set())


    def test_merge_limit_skips_hosts_whose_secrets_ops_cannot_read(self):
        """The SOPS vars plugin decrypts host_vars for every host in the limit, so an admin-only
        secrets file on an included host aborts the whole merge run before any play."""
        rules = yaml.safe_load((ROOT / ".sops.yaml").read_text())["creation_rules"]
        ops = next(r for r in rules if "group_vars/all" in r.get("path_regex", ""))["age"].split(",")[1].strip()
        limit = yaml.safe_load((ROOT / "ansible/roles/semaphore/defaults/main.yml").read_text())["semaphore_apply_limit"]
        excluded = {part[1:] for part in limit.split(":") if part.startswith("!")}
        files = sorted((ROOT / "ansible/host_vars").glob("*/secrets.sops.yml"))
        self.assertTrue(files)
        for f in files:
            recipients = {r["recipient"] for r in yaml.safe_load(f.read_text())["sops"]["age"]}
            if ops not in recipients:
                self.assertIn(f.parent.name, excluded, f"{f.relative_to(ROOT)} is admin-only")

if __name__ == "__main__":
    unittest.main()
