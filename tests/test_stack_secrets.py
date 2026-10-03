"""Phase 3 step 3 and 5: how a stack gets its secrets, and that a captured compose file carries
none. Run from the repo root: python3 -m unittest discover tests"""
import re
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STACKS = ROOT / "stacks"
DECRYPT = "/usr/local/sbin/komodo-decrypt-env"
DECRYPT_FILES = "/usr/local/sbin/komodo-decrypt-files"
REDACT = "/usr/local/sbin/komodo-redact-config"
LAB = re.search(r"age: age1\w+,(age1\w+)", (ROOT / ".sops.yaml").read_text()).group(1)
# Stacks that stay out of this contract: Komodo's own (Ansible deploys it, admin-only secrets).
NOT_KOMODO_STACKS = {"komodo"}
# Keys whose value is not a secret even though the name says so (a path to a secret file, a flag).
NOT_SECRET = {"FILE__PASSWORD", "MYSQL_RANDOM_ROOT_PASSWORD", "OAUTHLIB_RELAX_TOKEN_SCOPE", "ALLOW_USER_SIGNUPS", "GF_AUTH_ANONYMOUS_ORG_ROLE"}
SECRETISH = re.compile(r"(pass|secret|token|key|hash|auth|cookie|dsn|salt|webhook|credential|pwd|license|email)", re.I)
HARMLESS = re.compile(r"^(|\$\{[A-Z0-9_]+\}|true|false|yes|no|\d+|/\S*|https?://[^@\s]*|[a-z0-9.-]+\.[a-z]{2,}|\w+@example\.com)$", re.I)


# Config that names things or holds keys: committed only as an opaque *.sops.yaml blob (same rule as .githooks/pre-commit).
PLAINTEXT_CONFIG = re.compile(r"(^|/)(\.decrypted/|homepage/(bookmarks|docker|proxmox|services|settings|widgets)\.ya?ml(\..*)?$|homepage/[^/]*\.bak|smokeping/(Targets|ssmtp\.conf)$)")


def komodo_command(command):
    """Komodo's multiline command: comments dropped, `\\` joins lines, the remaining lines chained with &&."""
    lines = [l.strip() for l in command.split("\n")]
    joined = "\n".join(l.split(" #")[0] for l in lines if l and not l.startswith("#"))
    flat = "".join(" " + part.strip() for part in joined.split(" \\"))
    return [l.strip() for l in flat.split("\n") if l.strip()]


def is_blob(path):
    """An opaque blob is one encrypted value (`data: ENC[..]`), not a SOPS tree whose key names stay readable."""
    return path.read_text().startswith("data: ENC[")


def blobs_of(folder):
    return sorted(p.relative_to(folder).as_posix() for p in folder.rglob("*.sops.yaml") if is_blob(p))


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
            blobs = blobs_of(folder)
            with self.subTest(name):
                if not sops and not blobs:
                    self.assertNotIn("pre_deploy", config)
                    continue
                cmds = komodo_command(config["pre_deploy"]["command"])
                self.assertEqual(len(cmds), bool(sops) + bool(blobs))
                if sops:
                    self.assertTrue(cmds[0].startswith(DECRYPT + " "))
                    self.assertEqual(sorted(cmds[0].split()[1:]), sops)
                if blobs:
                    self.assertTrue(cmds[-1].startswith(DECRYPT_FILES + " -m 0644 "), "the container's user must be able to read its own file")
                    self.assertEqual(sorted(cmds[-1].split()[3:]), blobs)  # every blob of the stack, in one call
                tracked = {f["path"]: f for f in config["config_files"]}
                for path in sops + blobs:
                    self.assertEqual(tracked[path]["requires"], "Redeploy")  # a secret-only edit is a changed stack
                for path in blobs:
                    self.assertTrue(tracked[path]["services"], "a blob redeploys only the service that mounts it")
                # the plaintext is never tracked: Komodo would otherwise store it in Core
                for env in config.get("additional_env_files", []):
                    self.assertIs(env["track"], False)
                    self.assertIn(env["path"], ("secrets.env", "files.env"))
                if blobs:
                    self.assertIn({"path": "files.env", "track": False}, config["additional_env_files"])
                if sops:
                    plain = [s.replace(".sops.env", ".env") for s in sops]
                    self.assertEqual(sorted(config["compose_cmd_wrapper"].split()[6:]), sorted(plain))
                    self.assertTrue(config["compose_cmd_wrapper"].startswith(f"set -o pipefail; [[COMPOSE_COMMAND]] | {REDACT} "))
                    self.assertEqual(config["compose_cmd_wrapper_include"], ["config"])

    def test_every_file_mounted_from_the_clone_is_tracked(self):
        # A bind of ./file only works if a change to it is noticed: it must be a config_files entry that
        # restarts (plain file) or redeploys (blob, through its .sops.yaml) just the services that mount it.
        for folder, name, config in stacks():
            compose = folder / "compose.yaml"
            if not compose.exists():
                continue
            tracked = {f["path"]: f for f in config.get("config_files", [])}
            text = compose.read_text()
            with self.subTest(name):
                for m in re.finditer(r"^\s+- [\"']?\./([^:\"']+):(/[^:\"'\s]*)", text, re.M):
                    rel = m.group(1)
                    self.assertNotIn("..", rel)
                    if rel.startswith(".decrypted/"):
                        blob = rel[len(".decrypted/"):].removesuffix(".yaml") + ".sops.yaml"
                        self.assertIn(blob, tracked, f"{rel}: its blob is not in config_files")
                        self.assertTrue((folder / blob).is_file())
                        continue
                    target = folder / rel
                    files = [target] if target.is_file() else sorted(p for p in target.rglob("*") if p.is_file())
                    self.assertTrue(files, f"{rel} does not exist in the repo")
                    for f in files:
                        path = f.relative_to(folder).as_posix()
                        self.assertIn(path, tracked, f"{path} is mounted but not in config_files")
                        self.assertEqual(tracked[path]["requires"], "Restart")
                        self.assertTrue(tracked[path]["services"])
                for path in tracked:
                    self.assertTrue((folder / path).is_file(), f"config_files names a missing file: {path}")
                if "build:" in text:
                    for ctx in re.findall(r"^\s+context: (\./\S+)\s*$", text, re.M):
                        self.assertTrue((folder / ctx).is_dir())

    def test_blobs_are_opaque_and_stamp_their_container(self):
        for folder, name, config in stacks():
            blobs = blobs_of(folder)
            if not blobs:
                continue
            compose = (folder / "compose.yaml").read_text()
            with self.subTest(name):
                for blob in blobs:
                    lines = [l for l in (folder / blob).read_text().splitlines() if l.strip()]
                    self.assertRegex(lines[0], r"^data: ENC\[AES256_GCM,", f"{blob} is not a single encrypted value")
                    tops = [l.split(":")[0] for l in lines if not l.startswith((" ", "-", "#"))]
                    self.assertEqual(tops, ["data", "sops"], f"{blob} shows more than the encrypted value")
                    self.assertIn(LAB, (folder / blob).read_text(), f"{blob} is not encrypted for the lab key")
                    top = blob.split("/")[0].upper()
                    self.assertIn("${BLOBS_%s_SHA}" % top, compose, f"nothing recreates {top} when its blob changes")

    def test_no_plaintext_of_blob_config_in_the_repo(self):
        for path in STACKS.rglob("*"):
            rel = path.relative_to(ROOT).as_posix()
            if path.is_file() and not rel.endswith(".sops.yaml"):
                self.assertIsNone(PLAINTEXT_CONFIG.search(rel), f"{rel}: this config must only be committed as an encrypted blob")
        for path in STACKS.rglob("*.sops.yaml"):
            if path.parent.name in ("homepage", "smokeping"):
                self.assertTrue(is_blob(path), f"{path.relative_to(ROOT)}: a SOPS tree would show the key names; make it a blob (tools/sops-blob)")
        self.assertFalse(list(STACKS.rglob(".decrypted")), "a decrypted folder in the repo")
        self.assertFalse(list(STACKS.rglob("*.bak*")))

    def test_secret_files_are_encrypted_for_the_lab_key(self):
        # The agent opens them with the lab key.
        for sops in sorted(STACKS.glob("*/*.sops.env")):
            if sops.parent.name == NOT_KOMODO_STACKS.copy().pop():
                continue
            text = sops.read_text()
            with self.subTest(sops.relative_to(ROOT).as_posix()):
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
                        self.assertNotRegex(line, r'^\s+- ["\']?(\.\.|\.[^/])', f"relative bind outside this folder in {line.strip()}")
                    self.assertNotRegex(line, r"^\s+context: (?!\.\s*$|\./|/)", "build context must be ., ./dir or absolute")
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
                    self.assertEqual(envs, ["secrets.env"] + (["files.env"] if blobs_of(folder) else []))

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
