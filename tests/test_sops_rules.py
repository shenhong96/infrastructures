"""Who can open which secret file: the first matching rule in .sops.yaml, as sops picks it. The
ops key (control's runner) opens exactly the five files a merge's Ansible needs, and every
encrypted file carries the keys its rule names (a missed `sops updatekeys` fails here).
Run from the repo root: python3 -m unittest discover tests"""
import re
import subprocess
import unittest
from pathlib import Path

try:
    import yaml
except ImportError:  # ci always has it
    yaml = None

ROOT = Path(__file__).resolve().parent.parent
OPS_FILES = {"ansible/group_vars/all/secrets.sops.yml"} | {
    f"ansible/host_vars/{h}/secrets.sops.yml" for h in ("fileserver", "gitlab", "proxy", "vpn")}


def recipients(rules, path):
    rule = next(r for r in rules if re.search(r.get("path_regex", ""), path))
    return set(rule["age"].split(","))


@unittest.skipIf(yaml is None, "needs PyYAML")
class SopsRules(unittest.TestCase):
    def setUp(self):
        self.rules = yaml.safe_load((ROOT / ".sops.yaml").read_text())["creation_rules"]
        self.files = subprocess.run(["git", "ls-files", "*.sops.*"], cwd=ROOT, check=True,
                                    capture_output=True, text=True).stdout.split()
        self.files.remove(".sops.yaml")  # the glob matches the rules file too
        admin = recipients(self.rules, "no/rule/matches/this")  # the catch-all
        self.ops = recipients(self.rules, "ansible/group_vars/all/secrets.sops.yml") - admin

    def test_ops_opens_exactly_the_five_files(self):
        self.assertEqual(len(self.ops), 1)
        self.assertEqual({f for f in self.files if self.ops <= recipients(self.rules, f)}, OPS_FILES)

    def test_every_file_carries_its_rules_keys(self):
        for f in self.files:
            with self.subTest(f):
                have = set(re.findall(r"age1[0-9a-z]{58}", (ROOT / f).read_text()))
                self.assertEqual(have, recipients(self.rules, f))


if __name__ == "__main__":
    unittest.main()
