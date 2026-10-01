"""Phase 3 step 3 and 5: how a stack gets its secrets, and that a captured compose file carries
none. Run from the repo root: python3 -m unittest discover tests"""
import re
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STACKS = ROOT / "stacks"
DECRYPT = "/usr/local/sbin/komodo-decrypt-env"
REDACT = "/usr/local/sbin/komodo-redact-config"
LAB = re.search(r"age: age1\w+,(age1\w+)", (ROOT / ".sops.yaml").read_text()).group(1)
# Stacks that stay out of this contract: Komodo's own (Ansible deploys it, admin-only secrets).
NOT_KOMODO_STACKS = {"komodo"}
# Keys whose value is not a secret even though the name says so (a path to a secret file, a flag).
NOT_SECRET = {"FILE__PASSWORD", "MYSQL_RANDOM_ROOT_PASSWORD", "OAUTHLIB_RELAX_TOKEN_SCOPE", "ALLOW_USER_SIGNUPS", "GF_AUTH_ANONYMOUS_ORG_ROLE"}
SECRETISH = re.compile(r"(pass|secret|token|key|hash|auth|cookie|dsn|salt|webhook|credential|pwd|license|email)", re.I)
HARMLESS = re.compile(r"^(|\$\{[A-Z0-9_]+\}|true|false|yes|no|\d+|/\S*|https?://[^@\s]*|[a-z0-9.-]+\.[a-z]{2,}|\w+@example\.com)$", re.I)


def stacks():
    for toml in sorted(STACKS.glob("*/komodo.toml")):
        for stack in tomllib.loads(toml.read_text())["stack"]:
            yield toml.parent, stack["name"], stack["config"]


class StackSecrets(unittest.TestCase):
    def test_no_decrypted_file_in_the_repo(self):
        for path in STACKS.rglob("*.env"):
            self.assertTrue(path.name.endswith(".sops.env"), f"{path} is a plaintext env file")

    def test_every_secret_file_is_decrypted_before_deploy_and_tracked(self):
        for folder, name, config in stacks():
            sops = sorted(p.name for p in folder.glob("*.sops.env"))
            with self.subTest(name):
                if not sops:
                    self.assertNotIn("pre_deploy", config)
                    continue
                self.assertEqual(sorted(config["pre_deploy"]["command"].split()[1:]), sops)
                self.assertTrue(config["pre_deploy"]["command"].startswith(DECRYPT + " "))
                self.assertEqual(sorted(f["path"] for f in config["config_files"]), sops)
                for f in config["config_files"]:
                    self.assertEqual(f["requires"], "Redeploy")  # a secret-only edit is a changed stack
                # the plaintext is never tracked: Komodo would otherwise store it in Core
                for env in config.get("additional_env_files", []):
                    self.assertIs(env["track"], False)
                    self.assertEqual(env["path"], "secrets.env")
                plain = [s.replace(".sops.env", ".env") for s in sops]
                self.assertEqual(sorted(config["compose_cmd_wrapper"].split()[6:]), sorted(plain))
                self.assertTrue(config["compose_cmd_wrapper"].startswith(f"set -o pipefail; [[COMPOSE_COMMAND]] | {REDACT} "))
                self.assertEqual(config["compose_cmd_wrapper_include"], ["config"])

    def test_secret_files_are_encrypted_for_the_lab_key(self):
        # The agent opens them with the lab key. The one stack that must fail closed is the exception.
        for sops in sorted(STACKS.glob("*/*.sops.env")):
            if sops.parent.name == NOT_KOMODO_STACKS.copy().pop():
                continue
            text = sops.read_text()
            with self.subTest(sops.relative_to(ROOT).as_posix()):
                if sops.parent.name == "canary-secret-bad":
                    self.assertNotIn(LAB, text)
                else:
                    self.assertIn(LAB, text)

    def test_komodo_never_owns_dot_env(self):
        for folder, name, config in stacks():
            with self.subTest(name):
                self.assertNotEqual(config.get("env_file_path", "komodo.env"), ".env")
                compose = folder / "compose.yaml"
                if compose.exists():
                    for line in compose.read_text().splitlines():
                        self.assertNotRegex(line, r"^\s*(env_file:\s*|-\s*)\.env\s*$")

    def test_captured_compose_files_are_absolute_and_carry_no_secret(self):
        for folder, name, config in stacks():
            compose = folder / "compose.yaml"
            if not compose.exists() or folder.name.startswith("canary") or folder.name.startswith("monitoring"):
                continue
            with self.subTest(name):
                section = None
                for line in compose.read_text().splitlines():
                    head = re.match(r"^    (\w+):", line)
                    if head:
                        section = head.group(1)
                    if section == "volumes":
                        self.assertNotRegex(line, r'^\s+- ["\']?\.', f"relative bind in {line.strip()}")
                    self.assertNotRegex(line, r"^\s+context: (?!\.\s*$|/)", "build context must be . or absolute")
                    self.assertNotRegex(line, r"portainer", "Portainer is retired")
                    if section in ("environment", "labels"):
                        m = re.match(r'^\s+(?:- )?["\']?([A-Za-z0-9_.-]+)["\']?[=:]\s*(.*?)["\']?\s*$', line)
                        if m and m.group(1) not in NOT_SECRET:
                            key, value = m.group(1), m.group(2).strip("\"'")
                            if SECRETISH.search(key) or "@" in value:
                                self.assertRegex(value, HARMLESS, f"{name}: inline secret in {key}")

    def test_interpolating_stacks_pass_the_decrypted_file(self):
        for folder, name, config in stacks():
            compose = folder / "compose.yaml"
            if not compose.exists() or folder.name.startswith("canary-secret-"):
                continue
            uses_vars = re.search(r"\$\{[A-Z_]+", compose.read_text()) is not None
            envs = [e["path"] for e in config.get("additional_env_files", [])]
            with self.subTest(name):
                if uses_vars and name not in ("immich",) and (folder / "secrets.sops.env").exists():
                    self.assertEqual(envs, ["secrets.env"])

    def test_vpn_compose_never_enters_git(self):
        # Low profile: that stack is files-on-server mode, so the repo holds its komodo.toml only.
        self.assertEqual([p.name for p in (STACKS / "vpn").iterdir()], ["komodo.toml"])
        self.assertFalse(list(STACKS.rglob("docker-compose*.y*ml")))


class ProxyOwnership(unittest.TestCase):
    def test_ansible_does_not_place_komodos_files(self):
        # Komodo owns stacks/proxy/compose.yaml and Dockerfile; Ansible keeps .env, conf/Caddyfile, private.caddy.
        tasks = (ROOT / "ansible/roles/proxy/tasks/main.yml").read_text()
        self.assertNotRegex(tasks, r"loop:\s*\[compose\.yaml")
        self.assertNotIn("stacks/proxy/{{ item }}", tasks)
        handler = (ROOT / "ansible/roles/proxy/handlers/main.yml").read_text()
        self.assertNotIn("docker compose", handler.replace("# ", "").split("- name:")[1])


if __name__ == "__main__":
    unittest.main()
