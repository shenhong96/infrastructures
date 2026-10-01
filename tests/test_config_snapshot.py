"""config-snapshot: pure-function, backend and full-run tests. Run from the repo root:
python3 -m unittest discover tests

Fake secrets are built at runtime (secrets.token_hex / ssh-keygen into a tempdir), never
written as literal strings, so the committed test source cannot trip the repo's gitleaks
pre-commit hook. Every scenario that produces persisted output asserts the fake value is
absent from stage files, git objects, captured stdout/stderr and notification payloads.
"""
import http.server
import importlib.util
import json
import secrets
import shutil
import socketserver
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "ansible/roles/proxmox_host/files/config-snapshot.py"

import sys as _sys

_spec = importlib.util.spec_from_file_location("config_snapshot", SCRIPT)
cs = importlib.util.module_from_spec(_spec)
_sys.modules["config_snapshot"] = cs
_spec.loader.exec_module(cs)

GITLEAKS_BIN = "/opt/homebrew/bin/gitleaks"
HAS_GITLEAKS = Path(GITLEAKS_BIN).exists()


def fake_secret(nbytes: int = 16) -> str:
    return secrets.token_hex(nbytes)


def fake_pem() -> str:
    # Not a real key: random hex wrapped in PEM armor, enough to trip our PEM_RE and any
    # gitleaks private-key rule, but never a usable credential.
    body = "\n".join(secrets.token_hex(32) for _ in range(4))
    return f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----\n"


def write(root: Path, rel: str, content: str) -> Path:
    dest = root / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content, encoding="utf-8")
    return dest


def make_bare_repo(tmp_path: Path, name: str = "origin") -> tuple[Path, str]:
    bare = tmp_path / f"{name}.git"
    subprocess.run(["git", "init", "--quiet", "--bare", str(bare)], check=True)
    return bare, f"file://{bare}"


def git_cat_all_blob_contents(repo_dir: Path) -> str:
    """Every object's content, concatenated, for a leak-free assertion over full history."""
    res = subprocess.run(
        ["git", "-C", str(repo_dir), "cat-file", "--batch-all-objects", "--batch=%(objectname) %(objecttype)"],
        capture_output=True,
    )
    lines = res.stdout.decode("utf-8", errors="replace").splitlines()
    out = []
    for line in lines:
        parts = line.split(" ")
        if len(parts) != 2:
            continue
        sha, kind = parts
        if kind != "blob":
            continue
        blob = subprocess.run(["git", "-C", str(repo_dir), "cat-file", "-p", sha], capture_output=True)
        out.append(blob.stdout.decode("utf-8", errors="replace"))
    return "\n".join(out)


def base_config(repo_url: str, machines: list, **overrides) -> dict:
    config = {
        "repo_url": repo_url,
        "commit_url_base": "https://example.invalid/commit/",
        "branch": "main",
        "git_author": "config-snapshot <config-snapshot@proxmox.invalid>",
        "deploy_key": None,
        "known_hosts": None,
        "gotify_url": "http://127.0.0.1:0",
        "gotify_token_file": "/nonexistent",
        "gitleaks": GITLEAKS_BIN,
        "limits": {"file_bytes": 1048576, "total_bytes": 52428800},
        "redact_pve_description": True,
        "machines": machines,
    }
    config.update(overrides)
    return config


class RecordingNotifier:
    """An injected callable standing in for Gotify: records calls, can be made to fail."""

    def __init__(self, fail_times: int = 0):
        self.calls: list[tuple[str, str, int]] = []
        self.fail_times = fail_times

    def __call__(self, title: str, message: str, priority: int = 5) -> None:
        if self.fail_times > 0:
            self.fail_times -= 1
            raise cs.NotifyError("injected failure")
        self.calls.append((title, message, priority))


def make_runner(tmp_path, config, backends, notify_fn=None, lock_timeout=5.0):
    paths = cs.RunPaths(
        repo_dir=tmp_path / "repo",
        stage_dir=tmp_path / "stage",
        run_dir=tmp_path / "run",
        pending_dir=tmp_path / "pending",
        lock_file=tmp_path / "lock" / "config-snapshot.lock",
        lock_timeout=lock_timeout,
    )
    return cs.Runner(config, backends, paths, notify_fn=notify_fn), paths


# ----------------------------------------------------------------------------------
# Pure functions: redaction per format
# ----------------------------------------------------------------------------------


class RedactionFormats(unittest.TestCase):
    def test_json_redacts_sensitive_values_and_keeps_order(self):
        secret = fake_secret()
        raw = json.dumps({"name": "svc", "db_password": secret, "nested": {"api_token": secret}})
        out = cs.redact_json(raw)
        self.assertNotIn(secret, out)
        data = json.loads(out)
        self.assertEqual(list(data.keys()), ["name", "db_password", "nested"])
        self.assertEqual(data["db_password"], "<redacted>")
        self.assertEqual(data["nested"]["api_token"], "<redacted>")

    def test_json_malformed_is_an_error(self):
        with self.assertRaises(cs.CollectionError):
            cs.redact_json("{not: valid json,}")

    def test_yaml_simple_key_value(self):
        secret = fake_secret()
        out = cs.redact_yaml(f"name: svc\ndb_password: {secret}\n")
        self.assertNotIn(secret, out)
        self.assertIn("db_password: <redacted>", out)
        self.assertIn("name: svc", out)

    def test_yaml_block_scalar_under_sensitive_key(self):
        secret1, secret2 = fake_secret(), fake_secret()
        text = f"ssh_private_key: |\n  {secret1}\n  {secret2}\nnext_setting: visible\n"
        out = cs.redact_yaml(text)
        self.assertNotIn(secret1, out)
        self.assertNotIn(secret2, out)
        self.assertIn("ssh_private_key: |", out)
        self.assertIn("next_setting: visible", out)
        self.assertEqual(out.count("<redacted>"), 1)

    def test_yaml_compose_env_list(self):
        secret = fake_secret()
        text = f'environment:\n  - DATABASE_PASSWORD={secret}\n  - "API_TOKEN={secret}"\n  - DEBUG=true\n'
        out = cs.redact_yaml(text)
        self.assertNotIn(secret, out)
        self.assertIn("- DATABASE_PASSWORD=<redacted>", out)
        self.assertIn('- "API_TOKEN=<redacted>"', out)
        self.assertIn("- DEBUG=true", out)

    def test_yaml_flow_mapping(self):
        secret = fake_secret()
        out = cs.redact_yaml(f"opts: {{password: {secret}, timeout: 5}}\n")
        self.assertNotIn(secret, out)
        self.assertIn("password: <redacted>", out)
        self.assertIn("timeout: 5", out)

    def test_kv_toml_ini_conf(self):
        secret = fake_secret()
        out = cs.redact_kv(f"[server]\nname = demo\ntoken = {secret}\n")
        self.assertNotIn(secret, out)
        self.assertIn("token = <redacted>", out)
        self.assertIn("name = demo", out)

    def test_kv_toml_multiline_string(self):
        secret1, secret2 = fake_secret(), fake_secret()
        text = f'secret_blob = """\n{secret1}\n{secret2}\n"""\nafter = "kept"\n'
        out = cs.redact_kv(text)
        self.assertNotIn(secret1, out)
        self.assertNotIn(secret2, out)
        self.assertIn("after = \"kept\"", out)

    def test_kv_smb_conf_style(self):
        secret = fake_secret()
        out = cs.redact_kv(f"[global]\nworkgroup = LAB\npassdb backend = tdbsam\nldap admin dn password = {secret}\n")
        self.assertNotIn(secret, out)

    def test_shell_env_assignments(self):
        secret = fake_secret()
        text = f"export API_TOKEN={secret}\nPLAIN=ok\nAPI_TOKEN=\"{secret}\"\n"
        out = cs.redact_shell(text)
        self.assertNotIn(secret, out)
        self.assertIn("PLAIN=ok", out)
        self.assertIn("export API_TOKEN=<redacted>", out)

    def test_systemd_environment_line(self):
        secret = fake_secret()
        out = cs.redact_shell(f'Environment="DB_PASSWORD={secret}"\nEnvironmentFile=/etc/foo.env\n')
        self.assertNotIn(secret, out)
        self.assertIn("EnvironmentFile=/etc/foo.env", out)

    def test_gitlab_rb_single_line(self):
        secret = fake_secret()
        out = cs.redact_gitlab_rb(f"gitlab_rails['smtp_password'] = '{secret}'\n")
        self.assertNotIn(secret, out)
        self.assertIn("gitlab_rails['smtp_password'] = <redacted>", out)

    def test_gitlab_rb_multiline_statement(self):
        # A sensitive key whose value is a literal multi-line string (Ruby allows a raw
        # newline inside a double-quoted string): the whole statement must be redacted,
        # not just its first line.
        secret1, secret2 = fake_secret(), fake_secret()
        text = f"gitlab_rails['smtp_password'] = \"{secret1}\n{secret2}\"\nafter_field = 'kept'\n"
        out = cs.redact_gitlab_rb(text)
        self.assertNotIn(secret1, out)
        self.assertNotIn(secret2, out)
        self.assertIn("gitlab_rails['smtp_password'] = <redacted>", out)
        self.assertIn("after_field = 'kept'", out)

    def test_xml_element_and_attribute(self):
        secret = fake_secret()
        out = cs.redact_xml(f'<Config password="{secret}"><ApiToken>{secret}</ApiToken></Config>')
        self.assertNotIn(secret, out)
        self.assertIn('password="<redacted>"', out)
        self.assertIn("<ApiToken><redacted></ApiToken>", out)

    def test_generic_url_userinfo(self):
        secret = fake_secret()
        out = cs.redact_urls_and_hashes(f"remote = https://user:{secret}@example.invalid/repo.git\n")
        self.assertNotIn(secret, out)
        self.assertIn("https://<redacted>@example.invalid", out)

    def test_generic_ping_url_token(self):
        token = fake_secret(16)
        out = cs.redact_urls_and_hashes(f"url = https://hc-ping.com/{token}/snapraid\n")
        self.assertNotIn(token, out)

    def test_generic_bcrypt_hash(self):
        out = cs.redact_urls_and_hashes("hash = $2b$12$" + secrets.token_hex(22) + "\n")
        self.assertIn("<redacted>", out)
        self.assertNotIn("$2b$12$", out)

    def test_generic_pem_block_is_error(self):
        with self.assertRaises(cs.CollectionError):
            cs.redact_urls_and_hashes(fake_pem())

    def test_sanitize_text_pem_in_config_is_error_even_under_sensitive_key(self):
        text = f"ssh_private_key: |\n  {fake_pem()}\n"
        with self.assertRaises(cs.CollectionError):
            cs.sanitize_text("app.yaml", text.encode())

    def test_sanitize_text_unknown_format_with_credential_blocks(self):
        secret = fake_secret(20)
        text = f"notes\nconnect with password={secret}\n"
        with self.assertRaises(cs.CollectionError):
            cs.sanitize_text("README.weird", text.encode())

    def test_sanitize_text_unknown_format_without_credential_passes(self):
        out = cs.sanitize_text("README.weird", b"just some plain notes, nothing sensitive here\n")
        self.assertIn(b"plain notes", out)

    def test_sanitize_text_binary_is_error(self):
        with self.assertRaises(cs.CollectionError):
            cs.sanitize_text("blob.bin", b"\x00\x01\x02binary")

    def test_pve_description_redaction(self):
        text = "#comment line one\n#comment line two\narch: amd64\ndescription: hello world\n"
        out = cs.redact_pve_conf(text)
        self.assertNotIn("comment line one", out)
        self.assertIn("description: <redacted>", out)
        self.assertIn("arch: amd64", out)


# ----------------------------------------------------------------------------------
# Pure functions: exclusion
# ----------------------------------------------------------------------------------


class Exclusion(unittest.TestCase):
    def test_private_key_names_excluded(self):
        for name in ("/home/u/.ssh/id_rsa", "/opt/app/server.key", "/opt/app/cert.pem", "/opt/app/bundle.p12"):
            with self.subTest(name):
                self.assertIsNotNone(cs.exclusion_reason(name))

    def test_env_files_excluded(self):
        for name in ("/opt/app/.env", "/opt/app/secrets.env", "/opt/app/prod.env"):
            with self.subTest(name):
                self.assertIsNotNone(cs.exclusion_reason(name))

    def test_sops_files_excluded(self):
        self.assertIsNotNone(cs.exclusion_reason("/opt/app/vars.sops.yaml"))

    def test_path_segment_exclusions(self):
        for name in ("/opt/app/.decrypted/data.yml", "/opt/app/.git/config", "/root/.ssh/config", "/root/.gnupg/pubring"):
            with self.subTest(name):
                self.assertIsNotNone(cs.exclusion_reason(name))

    def test_self_exclusion(self):
        self.assertEqual(cs.exclusion_reason("/etc/config-snapshot/config.json"), "self-exclusion")
        self.assertEqual(cs.exclusion_reason("/var/lib/config-snapshot/repo/x"), "self-exclusion")

    def test_shadow_excluded(self):
        self.assertIsNotNone(cs.exclusion_reason("/etc/shadow"))
        self.assertIsNotNone(cs.exclusion_reason("/etc/gshadow-"))

    def test_ordinary_file_not_excluded(self):
        self.assertIsNone(cs.exclusion_reason("/opt/adguard/confdir/AdGuardHome.yaml"))

    def test_crypttab_keyfile_excluded(self):
        crypttab = "data /dev/sdb1 /etc/luks/disk.key luks\nswap /dev/sdc1 none swap\n"
        keyfiles = cs.parse_crypttab_keyfiles(crypttab)
        self.assertEqual(keyfiles, frozenset({"/etc/luks/disk.key"}))
        self.assertEqual(cs.exclusion_reason("/etc/luks/disk.key", keyfiles), "disk-key-file")

    def test_sensitive_key_allowlist_for_path_like_names(self):
        self.assertFalse(cs.is_sensitive_key("token_file"))
        self.assertFalse(cs.is_sensitive_key("ssh_private_key_path"))
        self.assertTrue(cs.is_sensitive_key("token"))
        self.assertTrue(cs.is_sensitive_key("db_password"))


# ----------------------------------------------------------------------------------
# Pure functions: canonical listings
# ----------------------------------------------------------------------------------


class Listings(unittest.TestCase):
    def test_packages_filters_installed_only(self):
        raw = (
            "bash\t5.2\tamd64\tinstall ok installed\n"
            "oldpkg\t1.0\tamd64\tdeinstall ok config-files\n"
            "zsh\t5.9\tamd64\tinstall ok installed\n"
        )
        out = cs.format_packages(raw)
        self.assertEqual(out, "bash\t5.2\tamd64\nzsh\t5.9\tamd64\n")

    def test_systemd_units_takes_first_two_columns(self):
        raw = "ssh.service enabled vendor-preset\ncron.service static -\n"
        out = cs.format_systemd_units(raw)
        self.assertEqual(out, "cron.service\tstatic\nssh.service\tenabled\n")

    def test_docker_projects_running_and_exited(self):
        raw = json.dumps(
            [
                {"Name": "b", "Status": "exited(1)", "ConfigFiles": "/opt/b/compose.yml"},
                {"Name": "a", "Status": "running(2)", "ConfigFiles": "/opt/a/compose.yml"},
            ]
        )
        out = cs.format_docker_projects(raw)
        self.assertEqual(
            out,
            "a\trunning\t/opt/a/compose.yml\nb\texited\t/opt/b/compose.yml\n",
        )

    def test_docker_running_projects_filter(self):
        raw = json.dumps(
            [
                {"Name": "a", "Status": "running(1)", "ConfigFiles": "/opt/a/compose.yml"},
                {"Name": "b", "Status": "exited(1)", "ConfigFiles": "/opt/b/compose.yml"},
            ]
        )
        running = cs.docker_running_projects(raw)
        self.assertEqual([p["Name"] for p in running], ["a"])

    def test_docker_projects_malformed_json_is_error(self):
        with self.assertRaises(cs.CollectionError):
            cs.format_docker_projects("{not json")

    def test_docker_images_listing(self):
        raw = "/web\tnginx:1.27\tsha256:abc\n/db\tpostgres:16\tsha256:def\n"
        out = cs.format_docker_images(raw)
        self.assertEqual(out, "db\tpostgres:16\tsha256:def\nweb\tnginx:1.27\tsha256:abc\n")

    def test_missing_optional_listing(self):
        self.assertIsNone(cs.format_missing_optional([]))
        self.assertEqual(cs.format_missing_optional(["/b", "/a", "/a"]), "/a\n/b\n")

    def test_compose_output_name_collision(self):
        seen = {}
        n1 = cs.compose_output_name("proj", seen, "/opt/a/.env.d/x.yml")
        n2 = cs.compose_output_name("proj", seen, "/opt/b/.env.d/x.yml")
        self.assertEqual(n1, "x.yml")
        self.assertNotEqual(n2, "x.yml")


# ----------------------------------------------------------------------------------
# Backends
# ----------------------------------------------------------------------------------


class FixtureBackendTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-fixture-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_read_file_and_glob(self):
        write(self.tmp, "etc/cron.d/job1", "* * * * * root true\n")
        write(self.tmp, "etc/cron.d/job2", "* * * * * root true\n")
        backend = cs.FixtureBackend(self.tmp, "host")
        self.assertEqual(backend.read_file("/etc/cron.d/job1"), b"* * * * * root true\n")
        self.assertEqual(backend.list_glob("/etc/cron.d/*"), ["/etc/cron.d/job1", "/etc/cron.d/job2"])

    def test_realpath_symlink_escape_into_excluded_path(self):
        write(self.tmp, "etc/shadow", "root:!:0:0:::\n")
        link = self.tmp / "opt/app/secret"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(self.tmp / "etc/shadow")
        backend = cs.FixtureBackend(self.tmp, "host")
        resolved = backend.realpath("/opt/app/secret")
        self.assertEqual(resolved, "/etc/shadow")
        self.assertEqual(cs.exclusion_reason(resolved), "shadow-file")

    def test_run_uses_canned_commands(self):
        backend = cs.FixtureBackend(self.tmp, "host", commands={("echo", "hi"): b"hi\n"})
        res = backend.run(["echo", "hi"])
        self.assertEqual(res.stdout, b"hi\n")

    def test_status_default_running(self):
        backend = cs.FixtureBackend(self.tmp, "ct")
        self.assertEqual(backend.status(), "running")


# ----------------------------------------------------------------------------------
# collect_machine / collect_all (no git)
# ----------------------------------------------------------------------------------


def minimal_host_backend(tmp, extra_files=None, commands=None, status_value="running"):
    write(tmp, "etc/hosts", "127.0.0.1 localhost\n")
    write(tmp, "etc/hostname", "proxmox\n")
    write(tmp, "etc/fstab", "/dev/sda1 / ext4 defaults 0 1\n")
    for rel, content in (extra_files or {}).items():
        write(tmp, rel, content)
    cmds = {
        tuple(cs.PACKAGES_CMD): b"",
        tuple(cs.UNIT_FILES_CMD): b"",
        tuple(cs.COMPOSE_LS_CMD): b"[]",
        tuple(cs.PS_AQ_CMD): b"",
    }
    cmds.update(commands or {})
    return cs.FixtureBackend(tmp, "proxmox", commands=cmds, status_value=status_value)


class CollectMachine(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-collect-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.out = self.tmp / "out"

    def _run_collect(self, machine_cfg, backend, limits=None):
        limits = limits or {"file_bytes": 1048576, "total_bytes": 52428800}
        stats = cs.CollectStats()
        budget = cs.RunBudget(limits["total_bytes"])
        out_root = self.tmp / "machine_root"
        cs.collect_machine(backend, machine_cfg, limits, True, out_root, stats, budget)
        return out_root / machine_cfg["name"], stats

    def test_required_missing_aborts(self):
        backend = minimal_host_backend(self.tmp / "fs")
        machine_cfg = {"name": "proxmox", "vmid": None, "docker": False, "paths": [{"path": "/opt/missing.txt", "optional": False}]}
        with self.assertRaises(cs.CollectionError):
            self._run_collect(machine_cfg, backend)

    def test_optional_missing_is_listed_not_an_error(self):
        backend = minimal_host_backend(self.tmp / "fs")
        machine_cfg = {"name": "proxmox", "vmid": None, "docker": False, "paths": [{"path": "/opt/missing.txt", "optional": True}]}
        root, stats = self._run_collect(machine_cfg, backend)
        self.assertIn("/opt/missing.txt", stats.missing_optional)

    def test_container_stopped_aborts(self):
        backend = cs.FixtureBackend(
            self.tmp / "ctfs",
            "apps",
            commands={tuple(cs.PACKAGES_CMD): b"", tuple(cs.UNIT_FILES_CMD): b"", tuple(cs.COMPOSE_LS_CMD): b"[]", tuple(cs.PS_AQ_CMD): b""},
            status_value="stopped",
        )
        machine_cfg = {"name": "apps", "vmid": 111, "docker": False, "paths": []}
        with self.assertRaises(cs.CollectionError):
            self._run_collect(machine_cfg, backend)

    def test_command_failure_aborts(self):
        fs = self.tmp / "fs"
        write(fs, "etc/hosts", "x\n")
        write(fs, "etc/hostname", "x\n")
        write(fs, "etc/fstab", "x\n")

        def handler(cmd):
            if list(cmd) == cs.PACKAGES_CMD:
                raise cs.CollectionError("dpkg-query failed")
            return None

        backend = cs.FixtureBackend(
            fs,
            "proxmox",
            commands={tuple(cs.UNIT_FILES_CMD): b"", tuple(cs.COMPOSE_LS_CMD): b"[]", tuple(cs.PS_AQ_CMD): b""},
            run_handler=handler,
        )
        machine_cfg = {"name": "proxmox", "vmid": None, "docker": False, "paths": []}
        with self.assertRaises(cs.CollectionError):
            self._run_collect(machine_cfg, backend)

    def test_oversize_file_aborts(self):
        backend = minimal_host_backend(self.tmp / "fs", extra_files={"opt/big.txt": "x" * 100})
        machine_cfg = {"name": "proxmox", "vmid": None, "docker": False, "paths": [{"path": "/opt/big.txt", "optional": False}]}
        with self.assertRaises(cs.CollectionError):
            self._run_collect(machine_cfg, backend, limits={"file_bytes": 10, "total_bytes": 52428800})

    def test_identical_fixtures_yield_identical_trees(self):
        backend = minimal_host_backend(self.tmp / "fs", extra_files={"opt/app/config.yml": "name: svc\n"})
        machine_cfg = {"name": "proxmox", "vmid": None, "docker": False, "paths": [{"path": "/opt/app/config.yml", "optional": False}]}
        root1, _ = self._run_collect(machine_cfg, backend)
        hash1 = cs.hash_tree(root1)
        stats2 = cs.CollectStats()
        limits2 = {"file_bytes": 1048576, "total_bytes": 52428800}
        budget2 = cs.RunBudget(limits2["total_bytes"])
        out_root2 = self.tmp / "machine_root2"
        cs.collect_machine(backend, machine_cfg, limits2, True, out_root2, stats2, budget2)
        hash2 = cs.hash_tree(out_root2 / "proxmox")
        self.assertEqual(hash1, hash2)

    def test_add_edit_delete_produces_expected_diff(self):
        old = {"a/files/opt/one.txt": "h1", "a/files/opt/two.txt": "h2"}
        new = {"a/files/opt/one.txt": "h1-changed", "a/files/opt/three.txt": "h3"}
        changes = cs.diff_trees(old, new)
        # diff_trees sorts by path (deterministic ordering, not grouped by status).
        self.assertEqual(
            changes,
            [("M", "a/files/opt/one.txt"), ("A", "a/files/opt/three.txt"), ("D", "a/files/opt/two.txt")],
        )

    def test_declared_path_excluded_is_config_error(self):
        backend = minimal_host_backend(self.tmp / "fs", extra_files={"opt/app/id_rsa": "fake"})
        machine_cfg = {"name": "proxmox", "vmid": None, "docker": False, "paths": [{"path": "/opt/app/id_rsa", "optional": False}]}
        with self.assertRaises(cs.ConfigError):
            self._run_collect(machine_cfg, backend)

    def test_globbed_private_key_is_skipped_silently(self):
        backend = minimal_host_backend(
            self.tmp / "fs", extra_files={"etc/cron.d/job": "* * * * * root true\n", "etc/cron.d/id_rsa": "fakekey"}
        )
        machine_cfg = {"name": "proxmox", "vmid": None, "docker": False, "paths": []}
        root, stats = self._run_collect(machine_cfg, backend)
        self.assertTrue((root / "files/etc/cron.d/job").exists())
        self.assertFalse((root / "files/etc/cron.d/id_rsa").exists())

    def test_pem_inside_declared_config_aborts(self):
        backend = minimal_host_backend(self.tmp / "fs", extra_files={"opt/app/config.yml": f"key: |\n  {fake_pem()}\n"})
        machine_cfg = {"name": "proxmox", "vmid": None, "docker": False, "paths": [{"path": "/opt/app/config.yml", "optional": False}]}
        with self.assertRaises(cs.CollectionError):
            self._run_collect(machine_cfg, backend)

    def test_symlink_escaping_into_excluded_path_is_error(self):
        fs = self.tmp / "fs"
        write(fs, "etc/hosts", "x\n")
        write(fs, "etc/hostname", "x\n")
        write(fs, "etc/fstab", "x\n")
        write(fs, "etc/shadow", "root:!:::\n")
        link = fs / "opt/app/config.yml"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(fs / "etc/shadow")
        cmds = {tuple(cs.PACKAGES_CMD): b"", tuple(cs.UNIT_FILES_CMD): b"", tuple(cs.COMPOSE_LS_CMD): b"[]", tuple(cs.PS_AQ_CMD): b""}
        backend = cs.FixtureBackend(fs, "proxmox", commands=cmds)
        machine_cfg = {"name": "proxmox", "vmid": None, "docker": False, "paths": [{"path": "/opt/app/config.yml", "optional": False}]}
        with self.assertRaises(cs.ConfigError):
            self._run_collect(machine_cfg, backend)

    def test_nested_secret_files_in_compose_dir_skipped(self):
        fs = self.tmp / "fs"
        write(fs, "etc/hosts", "x\n")
        write(fs, "etc/hostname", "x\n")
        write(fs, "etc/fstab", "x\n")
        write(fs, "opt/stack/compose.yml", "services: {}\n")
        write(fs, "opt/stack/secrets.env", "SECRET=should-not-appear\n")
        write(fs, "opt/stack/.decrypted/data.yml", "x\n")
        write(fs, "opt/stack/vars.sops.yaml", "x\n")
        compose_ls = json.dumps([{"Name": "stack", "Status": "running(1)", "ConfigFiles": "/opt/stack/compose.yml"}])
        cmds = {
            tuple(cs.PACKAGES_CMD): b"",
            tuple(cs.UNIT_FILES_CMD): b"",
            tuple(cs.COMPOSE_LS_CMD): compose_ls.encode(),
            tuple(cs.PS_AQ_CMD): b"",
        }
        backend = cs.FixtureBackend(fs, "proxmox", commands=cmds)
        machine_cfg = {"name": "proxmox", "vmid": None, "docker": True, "paths": []}
        root, _ = self._run_collect(machine_cfg, backend)
        self.assertTrue((root / "docker/compose/stack/compose.yml").exists())
        self.assertFalse((root / "docker/compose/stack/secrets.env").exists())

    def test_crontab_with_env_lines_only_redacts_env_assignment(self):
        fs = self.tmp / "fs"
        secret = fake_secret()
        write(fs, "etc/hosts", "x\n")
        write(fs, "etc/hostname", "x\n")
        write(fs, "etc/fstab", "x\n")
        write(fs, "etc/crontab", f"MAILTO=root\nAPI_TOKEN={secret}\n0 1 * * * root /bin/true\n")
        cmds = {tuple(cs.PACKAGES_CMD): b"", tuple(cs.UNIT_FILES_CMD): b"", tuple(cs.COMPOSE_LS_CMD): b"[]", tuple(cs.PS_AQ_CMD): b""}
        backend = cs.FixtureBackend(fs, "proxmox", commands=cmds)
        machine_cfg = {"name": "proxmox", "vmid": None, "docker": False, "paths": []}
        root, _ = self._run_collect(machine_cfg, backend)
        content = (root / "files/etc/crontab").read_text()
        self.assertNotIn(secret, content)
        self.assertIn("0 1 * * * root /bin/true", content)


# ----------------------------------------------------------------------------------
# gitleaks gate
# ----------------------------------------------------------------------------------


@unittest.skipUnless(HAS_GITLEAKS, "gitleaks not installed at /opt/homebrew/bin/gitleaks")
class GitleaksGate(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-gitleaks-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_clean_stage_passes(self):
        stage = self.tmp / "stage"
        write(stage, "a/README.md", "nothing interesting here\n")
        cs.run_gitleaks(GITLEAKS_BIN, stage, self.tmp / "run")

    def test_finding_reports_only_path_and_rule(self):
        stage = self.tmp / "stage"
        token = "ghp_" + secrets.token_hex(18)
        write(stage, "a/notes.txt", f"contact support with code {token}\n")
        with self.assertRaises(cs.GitleaksFinding) as ctx:
            cs.run_gitleaks(GITLEAKS_BIN, stage, self.tmp / "run")
        self.assertNotIn(token, str(ctx.exception.findings))
        rels = [rel for rel, _rule in ctx.exception.findings]
        self.assertIn("a/notes.txt", rels)

    def test_redactor_misses_but_gitleaks_catches_free_text_token(self):
        """A ghp_-style token embedded in a free-text comment (not key:value, not a URL) slips
        past our own redactor but must still be caught by the gitleaks gate before any commit."""
        stage = self.tmp / "stage"
        token = "ghp_" + secrets.token_hex(18)
        raw = f"# support ticket reference {token}\n0 1 * * * root /bin/true\n"
        sanitized = cs.sanitize_text("/etc/crontab", raw.encode())
        self.assertIn(token.encode(), sanitized)  # confirms our redactor indeed misses it
        write(stage, "proxmox/files/etc/crontab", "placeholder")
        (stage / "proxmox/files/etc/crontab").write_bytes(sanitized)
        with self.assertRaises(cs.GitleaksFinding):
            cs.run_gitleaks(GITLEAKS_BIN, stage, self.tmp / "run")


# ----------------------------------------------------------------------------------
# Full run(): git, lock, notifications
# ----------------------------------------------------------------------------------


def host_machine_cfg(paths=None):
    return {"name": "proxmox", "vmid": None, "docker": False, "paths": paths or []}


def host_backend(fs_root, extra_files=None):
    return minimal_host_backend(fs_root, extra_files=extra_files)


class FullRun(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-run-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.bare, self.repo_url = make_bare_repo(self.tmp)

    def _config(self, **overrides):
        return base_config(self.repo_url, [host_machine_cfg()], **overrides)

    def test_first_run_commits_and_pushes(self):
        backend = host_backend(self.tmp / "fs")
        config = self._config()
        notifier = RecordingNotifier()
        runner, paths = make_runner(self.tmp, config, {"proxmox": backend}, notify_fn=notifier)
        code = runner.run()
        self.assertEqual(code, 0)
        self.assertTrue((paths.repo_dir / "README.md").exists())
        self.assertEqual(len(notifier.calls), 1)
        self.assertIn("Config drift", notifier.calls[0][0])

    def test_identical_second_run_makes_no_new_commit(self):
        backend = host_backend(self.tmp / "fs")
        config = self._config()
        runner, paths = make_runner(self.tmp, config, {"proxmox": backend}, notify_fn=RecordingNotifier())
        self.assertEqual(runner.run(), 0)
        log1 = subprocess.run(["git", "-C", str(paths.repo_dir), "log", "--oneline"], capture_output=True).stdout
        self.assertEqual(runner.run(), 0)
        log2 = subprocess.run(["git", "-C", str(paths.repo_dir), "log", "--oneline"], capture_output=True).stdout
        self.assertEqual(log1, log2)

    def test_add_edit_delete_produces_expected_commit(self):
        fs = self.tmp / "fs"
        write(fs, "opt/app/a.txt", "one\n")
        write(fs, "opt/app/b.txt", "two\n")
        backend = host_backend(fs)
        config = self._config()
        machine_cfg = host_machine_cfg(
            paths=[{"path": "/opt/app/a.txt", "optional": False}, {"path": "/opt/app/b.txt", "optional": False}]
        )
        config["machines"] = [machine_cfg]
        runner, paths = make_runner(self.tmp, config, {"proxmox": backend}, notify_fn=RecordingNotifier())
        self.assertEqual(runner.run(), 0)

        (fs / "opt/app/a.txt").write_text("one-changed\n")
        (fs / "opt/app/b.txt").unlink()
        write(fs, "opt/app/c.txt", "three\n")
        machine_cfg2 = host_machine_cfg(
            paths=[
                {"path": "/opt/app/a.txt", "optional": False},
                {"path": "/opt/app/b.txt", "optional": True},
                {"path": "/opt/app/c.txt", "optional": False},
            ]
        )
        config2 = self._config()
        config2["machines"] = [machine_cfg2]
        backend2 = host_backend(fs)
        runner2, _ = make_runner(self.tmp, config2, {"proxmox": backend2}, notify_fn=RecordingNotifier())
        self.assertEqual(runner2.run(), 0)
        log = subprocess.run(
            ["git", "-C", str(paths.repo_dir), "log", "-1", "--name-status", "--pretty=%B"], capture_output=True
        ).stdout.decode()
        self.assertIn("proxmox/files/opt/app/a.txt", log)
        self.assertIn("proxmox/files/opt/app/c.txt", log)

    def test_required_missing_leaves_tree_untouched_no_commit(self):
        backend = host_backend(self.tmp / "fs")
        config = self._config()
        runner, paths = make_runner(self.tmp, config, {"proxmox": backend}, notify_fn=RecordingNotifier())
        self.assertEqual(runner.run(), 0)
        before = cs.hash_tree_excluding_git(paths.repo_dir)
        log_before = subprocess.run(["git", "-C", str(paths.repo_dir), "rev-parse", "HEAD"], capture_output=True).stdout

        config2 = self._config()
        config2["machines"] = [host_machine_cfg(paths=[{"path": "/opt/missing.txt", "optional": False}])]
        backend2 = host_backend(self.tmp / "fs")
        runner2, _ = make_runner(self.tmp, config2, {"proxmox": backend2}, notify_fn=RecordingNotifier())
        self.assertEqual(runner2.run(), 1)
        after = cs.hash_tree_excluding_git(paths.repo_dir)
        log_after = subprocess.run(["git", "-C", str(paths.repo_dir), "rev-parse", "HEAD"], capture_output=True).stdout
        self.assertEqual(before, after)
        self.assertEqual(log_before, log_after)

    def test_oversize_aborts_no_commit(self):
        fs = self.tmp / "fs"
        write(fs, "opt/app/big.txt", "x" * 2048)
        backend = host_backend(fs)
        config = self._config(limits={"file_bytes": 100, "total_bytes": 52428800})
        config["machines"] = [host_machine_cfg(paths=[{"path": "/opt/app/big.txt", "optional": False}])]
        runner, paths = make_runner(self.tmp, config, {"proxmox": backend}, notify_fn=RecordingNotifier())
        self.assertEqual(runner.run(), 1)
        self.assertFalse((paths.repo_dir / "proxmox").exists())

    @unittest.skipUnless(HAS_GITLEAKS, "gitleaks not installed")
    def test_gitleaks_finding_blocks_commit_and_reports_only_path_and_rule(self):
        fs = self.tmp / "fs"
        token = "ghp_" + secrets.token_hex(18)
        write(fs, "opt/app/notes.txt", f"# ref {token}\nkey: value\n")
        backend = host_backend(fs)
        config = self._config()
        config["machines"] = [host_machine_cfg(paths=[{"path": "/opt/app/notes.txt", "optional": False}])]
        runner, paths = make_runner(self.tmp, config, {"proxmox": backend}, notify_fn=RecordingNotifier())
        import io
        import contextlib

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = runner.run()
        self.assertEqual(code, 1)
        self.assertNotIn(token, err.getvalue())
        self.assertIn("notes.txt", err.getvalue())
        self.assertFalse((paths.repo_dir / "proxmox").exists())
        self.assertEqual(
            subprocess.run(["git", f"--git-dir={self.bare}", "log", "--oneline", "--all"], capture_output=True).stdout, b""
        )

    def test_dirty_workspace_recovered(self):
        backend = host_backend(self.tmp / "fs")
        config = self._config()
        runner, paths = make_runner(self.tmp, config, {"proxmox": backend}, notify_fn=RecordingNotifier())
        self.assertEqual(runner.run(), 0)
        stray = paths.repo_dir / "half-copied-garbage.txt"
        stray.write_text("leftover from an interrupted run\n")
        backend2 = host_backend(self.tmp / "fs")
        runner2, _ = make_runner(self.tmp, config, {"proxmox": backend2}, notify_fn=RecordingNotifier())
        self.assertEqual(runner2.run(), 0)
        self.assertFalse(stray.exists())

    def test_unpushed_commit_is_pushed_on_next_unchanged_run(self):
        backend = host_backend(self.tmp / "fs")
        config = self._config()
        runner, paths = make_runner(self.tmp, config, {"proxmox": backend}, notify_fn=RecordingNotifier())
        self.assertEqual(runner.run(), 0)

        # Simulate a prior run whose commit succeeded but whose push failed: add a local
        # commit directly, break the remote, confirm push() fails and the commit is retained.
        write(paths.repo_dir, "proxmox/files/opt/extra.txt", "extra\n")
        subprocess.run(["git", "-C", str(paths.repo_dir), "add", "-A"], check=True)
        subprocess.run(
            ["git", "-C", str(paths.repo_dir), "-c", "user.email=a@b.invalid", "-c", "user.name=a", "commit", "-q", "-m", "stranded"],
            check=True,
        )
        broken_url = str(self.tmp / "does-not-exist.git")
        subprocess.run(["git", "-C", str(paths.repo_dir), "remote", "set-url", "origin", broken_url], check=True)
        with self.assertRaises(cs.GitError):
            cs.push(paths.repo_dir, "main", {})
        subprocess.run(["git", "-C", str(paths.repo_dir), "remote", "set-url", "origin", self.repo_url], check=True)
        cs.push(paths.repo_dir, "main", {})
        local_head = subprocess.run(["git", "-C", str(paths.repo_dir), "rev-parse", "HEAD"], capture_output=True).stdout
        remote_head = subprocess.run(["git", f"--git-dir={self.bare}", "rev-parse", "main"], capture_output=True).stdout
        self.assertEqual(local_head, remote_head)

    def test_remote_diverged_blocks_push_without_force(self):
        backend = host_backend(self.tmp / "fs")
        config = self._config()
        runner, paths = make_runner(self.tmp, config, {"proxmox": backend}, notify_fn=RecordingNotifier())
        self.assertEqual(runner.run(), 0)
        original_remote_head = subprocess.run(
            ["git", f"--git-dir={self.bare}", "rev-parse", "main"], capture_output=True
        ).stdout

        other_clone = self.tmp / "other-clone"
        subprocess.run(["git", "clone", "-q", self.repo_url, str(other_clone)], check=True)
        write(other_clone, "intruder.txt", "divergent history\n")
        subprocess.run(["git", "-C", str(other_clone), "add", "-A"], check=True)
        subprocess.run(
            ["git", "-C", str(other_clone), "-c", "user.email=a@b.invalid", "-c", "user.name=a", "commit", "-q", "-m", "divergent"],
            check=True,
        )
        subprocess.run(["git", "-C", str(other_clone), "push", "-q", "origin", "HEAD:main"], check=True)

        write(paths.repo_dir, "proxmox/files/opt/mine.txt", "mine\n")
        subprocess.run(["git", "-C", str(paths.repo_dir), "add", "-A"], check=True)
        subprocess.run(
            ["git", "-C", str(paths.repo_dir), "-c", "user.email=a@b.invalid", "-c", "user.name=a", "commit", "-q", "-m", "local-only"],
            check=True,
        )
        with self.assertRaises(cs.DivergedError):
            cs.push(paths.repo_dir, "main", {})
        remote_head_after = subprocess.run(["git", f"--git-dir={self.bare}", "rev-parse", "main"], capture_output=True).stdout
        self.assertNotEqual(remote_head_after, original_remote_head)  # the intruder's push landed
        self.assertEqual(remote_head_after, subprocess.run(["git", "-C", str(other_clone), "rev-parse", "HEAD"], capture_output=True).stdout)

    def test_notification_failure_retained_and_retried_on_next_noop_run(self):
        backend = host_backend(self.tmp / "fs")
        config = self._config()
        notifier = RecordingNotifier(fail_times=1)
        runner, paths = make_runner(self.tmp, config, {"proxmox": backend}, notify_fn=notifier)
        self.assertEqual(runner.run(), 1)
        pending_files = list(paths.pending_dir.glob("*.json"))
        self.assertEqual(len(pending_files), 1)

        backend2 = host_backend(self.tmp / "fs")
        runner2, _ = make_runner(self.tmp, config, {"proxmox": backend2}, notify_fn=notifier)
        self.assertEqual(runner2.run(), 0)
        self.assertEqual(len(notifier.calls), 1)
        self.assertEqual(list(paths.pending_dir.glob("*.json")), [])

    def test_concurrent_run_blocked_by_lock(self):
        backend = host_backend(self.tmp / "fs")
        config = self._config()
        runner, paths = make_runner(self.tmp, config, {"proxmox": backend}, notify_fn=RecordingNotifier(), lock_timeout=0.3)
        paths.lock_file.parent.mkdir(parents=True, exist_ok=True)
        held = open(paths.lock_file, "a+")
        import fcntl as _fcntl

        _fcntl.flock(held.fileno(), _fcntl.LOCK_EX)
        try:
            start = time.monotonic()
            code = runner.run()
            elapsed = time.monotonic() - start
        finally:
            _fcntl.flock(held.fileno(), _fcntl.LOCK_UN)
            held.close()
        self.assertEqual(code, 75)
        self.assertLess(elapsed, 2.0)

    def test_no_secret_leakage_into_repo_stdout_or_notifications(self):
        secret = fake_secret()
        fs = self.tmp / "fs"
        write(fs, "opt/app/config.json", json.dumps({"db_password": secret}))
        backend = host_backend(fs)
        config = self._config()
        config["machines"] = [host_machine_cfg(paths=[{"path": "/opt/app/config.json", "optional": False}])]
        notifier = RecordingNotifier()
        runner, paths = make_runner(self.tmp, config, {"proxmox": backend}, notify_fn=notifier)
        import io
        import contextlib

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = runner.run()
        self.assertEqual(code, 0)
        self.assertNotIn(secret, out.getvalue())
        self.assertNotIn(secret, err.getvalue())
        for title, message, _priority in notifier.calls:
            self.assertNotIn(secret, title)
            self.assertNotIn(secret, message)
        tree_text = (paths.repo_dir / "proxmox/files/opt/app/config.json").read_text()
        self.assertNotIn(secret, tree_text)
        self.assertNotIn(secret, git_cat_all_blob_contents(paths.repo_dir))


# ----------------------------------------------------------------------------------
# config.json validation + self-exclusion
# ----------------------------------------------------------------------------------


class ConfigValidation(unittest.TestCase):
    def test_valid_config_passes(self):
        cs.validate_config(base_config("file:///tmp/x.git", [host_machine_cfg()]))

    def test_unknown_key_rejected(self):
        config = base_config("file:///tmp/x.git", [host_machine_cfg()])
        config["unexpected"] = True
        with self.assertRaises(cs.ConfigError):
            cs.validate_config(config)

    def test_ssh_url_requires_deploy_key(self):
        config = base_config("git@github.com:org/repo.git", [host_machine_cfg()])
        config["deploy_key"] = None
        config["known_hosts"] = None
        with self.assertRaises(cs.ConfigError):
            cs.validate_config(config)

    def test_declared_path_under_own_storage_rejected(self):
        config = base_config(
            "file:///tmp/x.git", [host_machine_cfg(paths=[{"path": "/var/lib/config-snapshot/repo/x", "optional": False}])]
        )
        with self.assertRaises(cs.ConfigError):
            cs.validate_config(config)


# ----------------------------------------------------------------------------------
# Opus review fixes (2026-10-02): one test per numbered item.
# ----------------------------------------------------------------------------------


class OpusReviewFixes(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-opus-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    # 1. every backend.run() result must be returncode-checked; a failed listing command
    # must never look like "nothing here".
    def test_1_run_checked_raises_on_nonzero_and_is_used_for_every_listing_command(self):
        backend = cs.FixtureBackend(self.tmp, "host", commands={("whoami",): (1, b"")})
        with self.assertRaises(cs.CollectionError) as ctx:
            cs._run_checked(backend, ["whoami"], "whoami")
        self.assertIn("whoami failed (exit 1)", str(ctx.exception))

        # Integration: a failing dpkg-query must abort collect_machine, not emit an empty
        # packages.txt that looks like every package vanished.
        fs = self.tmp / "fs"
        write(fs, "etc/hosts", "x\n")
        write(fs, "etc/hostname", "x\n")
        write(fs, "etc/fstab", "x\n")
        cmds = {
            tuple(cs.PACKAGES_CMD): (1, b""),
            tuple(cs.UNIT_FILES_CMD): b"",
            tuple(cs.COMPOSE_LS_CMD): b"[]",
            tuple(cs.PS_AQ_CMD): b"",
        }
        backend2 = cs.FixtureBackend(fs, "proxmox", commands=cmds)
        machine_cfg = {"name": "proxmox", "vmid": None, "docker": False, "paths": []}
        stats = cs.CollectStats()
        budget = cs.RunBudget(52428800)
        with self.assertRaises(cs.CollectionError) as ctx2:
            cs.collect_machine(backend2, machine_cfg, {"file_bytes": 1048576, "total_bytes": 52428800}, True, self.tmp / "out", stats, budget)
        self.assertIn("dpkg-query failed (exit 1)", str(ctx2.exception))

    # 2. PctBackend must never silently degrade a real pct/container failure into "missing"
    # or "empty" — it must raise CollectionError for info()/realpath()/list_glob().
    def test_2_pct_backend_raises_on_unreachable_container_instead_of_degrading(self):
        bindir = self.tmp / "bin"
        bindir.mkdir()
        fake_pct = bindir / "pct"
        fake_pct.write_text("#!/bin/sh\nexit 7\n")
        fake_pct.chmod(0o755)
        old_path = __import__("os").environ["PATH"]
        __import__("os").environ["PATH"] = str(bindir) + ":" + old_path
        self.addCleanup(lambda: __import__("os").environ.__setitem__("PATH", old_path))

        backend = cs.PctBackend(999, "apps")
        with self.assertRaises(cs.CollectionError):
            backend.info("/etc/hosts")
        with self.assertRaises(cs.CollectionError):
            backend.realpath("/etc/hosts")
        with self.assertRaises(cs.CollectionError):
            backend.list_glob("/etc/cron.d/*")
        with self.assertRaises(cs.CollectionError):
            backend.list_glob("/etc/systemd/system/**")
        with self.assertRaises(cs.CollectionError):
            backend.read_file("/etc/hosts")

    # 3. "/**" recursion must behave identically across backends: files + symlinks (to a
    # file or a directory) are leaves; a symlinked directory is never descended into. Check
    # the generated pct script shape, and that running it for real agrees with
    # walk_files_and_symlinks (used by Local/FixtureBackend) on an actual directory tree.
    def test_3_recursive_glob_argv_shape_and_pct_script_agrees_with_backend_walk(self):
        argv_plain = cs.PctBackend._list_glob_argv("/etc/cron.d/*")
        self.assertIn("for f in", argv_plain[2])
        self.assertIn("exit 0", argv_plain[2])

        base = self.tmp / "systemd" / "system"
        wants = base / "multi-user.target.wants"
        wants.mkdir(parents=True)
        (wants / "foo.service").write_text("x")
        (base / "a.service").write_text("x")
        real_target_dir = self.tmp / "real-target-dir"
        real_target_dir.mkdir()
        (real_target_dir / "inside.txt").write_text("should not appear: dir symlink is a leaf")
        (base / "dir-link").symlink_to(real_target_dir)
        (base / "file-link").symlink_to(base / "a.service")

        argv_recursive = cs.PctBackend._list_glob_argv(str(base) + "/**")
        self.assertIn("find", argv_recursive[2])
        self.assertIn("-type f", argv_recursive[2])
        self.assertIn("-type l", argv_recursive[2])
        res = subprocess.run(argv_recursive, capture_output=True)
        self.assertEqual(res.returncode, 0)
        pct_paths = sorted(p for p in res.stdout.decode().split("\n") if p)

        walked = sorted(str(p) for p in cs.walk_files_and_symlinks(base))
        self.assertEqual(pct_paths, walked)
        # the symlinked directory itself is a leaf; nothing inside it was walked into.
        self.assertFalse(any("inside.txt" in p for p in walked))
        self.assertIn(str(base / "dir-link"), walked)
        self.assertIn(str(base / "file-link"), walked)

        # a missing base directory is empty, not an error (exit 0, no output).
        missing_argv = cs.PctBackend._list_glob_argv(str(self.tmp / "does-not-exist") + "/**")
        res2 = subprocess.run(missing_argv, capture_output=True)
        self.assertEqual(res2.returncode, 0)
        self.assertEqual(res2.stdout, b"")

    # 4. oversize must be rejected from the stat-reported size, before ever reading the file.
    def test_4_oversize_checked_from_stat_before_read_is_attempted(self):
        fs = self.tmp / "fs"
        big = write(fs, "opt/big.txt", "x" * 2048)
        backend = cs.FixtureBackend(fs, "proxmox")
        read_calls = []
        real_read = backend.read_file

        def spy_read(path):
            read_calls.append(path)
            return real_read(path)

        backend.read_file = spy_read
        info = backend.info("/opt/big.txt")
        self.assertGreater(info.size, 100)
        budget = cs.RunBudget(52428800)
        with self.assertRaises(cs.CollectionError):
            cs._check_and_sanitize(
                backend, "/opt/big.txt", {"file_bytes": 100, "total_bytes": 52428800}, budget, False, info, follow_symlink=True
            )
        self.assertEqual(read_calls, [], "read_file must not be called once the stat size already exceeds the limit")

    # 5. a declared path (snapshot_paths) that is a symlink to a regular file must collect
    # the resolved file's sanitized content; a glob-discovered symlink stays "-> target".
    def test_5_declared_symlink_to_file_collects_content_glob_symlink_keeps_arrow(self):
        fs = self.tmp / "fs"
        write(fs, "etc/hosts", "x\n")
        write(fs, "etc/hostname", "x\n")
        write(fs, "etc/fstab", "x\n")
        secret = fake_secret()
        write(fs, "opt/real/config.yml", f"db_password: {secret}\nname: svc\n")
        link = fs / "opt/app/config.yml"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(fs / "opt/real/config.yml")
        glob_target = write(fs, "etc/cron.d/real-job", "* * * * * root true\n")
        glob_link = fs / "etc/cron.d/job-link"
        glob_link.symlink_to(glob_target)

        cmds = {tuple(cs.PACKAGES_CMD): b"", tuple(cs.UNIT_FILES_CMD): b"", tuple(cs.COMPOSE_LS_CMD): b"[]", tuple(cs.PS_AQ_CMD): b""}
        backend = cs.FixtureBackend(fs, "proxmox", commands=cmds)
        machine_cfg = {"name": "proxmox", "vmid": None, "docker": False, "paths": [{"path": "/opt/app/config.yml", "optional": False}]}
        stats = cs.CollectStats()
        budget = cs.RunBudget(52428800)
        out_root = self.tmp / "out"
        cs.collect_machine(backend, machine_cfg, {"file_bytes": 1048576, "total_bytes": 52428800}, True, out_root, stats, budget)

        declared_content = (out_root / "proxmox/files/opt/app/config.yml").read_text()
        self.assertNotIn(secret, declared_content)
        self.assertIn("db_password: <redacted>", declared_content)
        self.assertIn("name: svc", declared_content)

        glob_content = (out_root / "proxmox/files/etc/cron.d/job-link").read_text()
        self.assertTrue(glob_content.startswith("-> "))
        self.assertIn("real-job", glob_content)

    # 6. total_bytes is a per-run budget shared across machines, not reset per machine.
    def test_6_total_bytes_enforced_across_the_whole_run_not_per_machine(self):
        fs1 = self.tmp / "fs1"
        fs2 = self.tmp / "fs2"
        write(fs1, "etc/hosts", "x\n")
        write(fs1, "etc/hostname", "x\n")
        write(fs1, "etc/fstab", "x\n")
        write(fs1, "opt/a.txt", "a" * 600)
        write(fs2, "etc/hosts", "x\n")
        write(fs2, "etc/hostname", "x\n")
        write(fs2, "etc/fstab", "x\n")
        write(fs2, "opt/b.txt", "b" * 600)
        cmds = {tuple(cs.PACKAGES_CMD): b"", tuple(cs.UNIT_FILES_CMD): b"", tuple(cs.COMPOSE_LS_CMD): b"[]", tuple(cs.PS_AQ_CMD): b""}
        backend1 = cs.FixtureBackend(fs1, "m1", commands=cmds)
        backend2 = cs.FixtureBackend(fs2, "m2", commands=cmds)
        config = {
            "limits": {"file_bytes": 1048576, "total_bytes": 1000},  # each file alone fits; both together don't
            "redact_pve_description": True,
            "machines": [
                {"name": "m1", "vmid": None, "docker": False, "paths": [{"path": "/opt/a.txt", "optional": False}]},
                {"name": "m2", "vmid": None, "docker": False, "paths": [{"path": "/opt/b.txt", "optional": False}]},
            ],
        }
        with self.assertRaises(cs.CollectionError) as ctx:
            cs.collect_all(config, {"m1": backend1, "m2": backend2}, self.tmp / "out")
        self.assertIn("total_bytes", str(ctx.exception))

    # 7. names ending in key/keys are sensitive (subject to the path allowlist).
    def test_7_names_ending_in_key_are_sensitive(self):
        for name in ("APP_KEY", "MASTER_KEY", "B2_ACCOUNT_KEY", "PresharedKey", "PrivateKey", "api_keys"):
            with self.subTest(name):
                self.assertTrue(cs.is_sensitive_key(name))
        # Path-like allowlisted names stay visible even though they end in "key"/"file".
        self.assertFalse(cs.is_sensitive_key("keyfile"))
        self.assertFalse(cs.is_sensitive_key("token_file"))

    # 8. gitleaks: stale/old report deleted before running and after parsing; any exit code
    # other than 0/1 is a scanner error even if a report file happens to exist.
    def test_8_gitleaks_report_cleanup_and_non_01_exit_is_scanner_error(self):
        run_dir = self.tmp / "run"
        run_dir.mkdir()
        report_path = run_dir / "gitleaks-report.json"
        report_path.write_text('[{"File": "stale", "RuleID": "stale-rule"}]')

        bindir = self.tmp / "bin"
        bindir.mkdir()
        fake_gitleaks = bindir / "gitleaks"
        # exit 2 is not 0 (clean) or 1 (findings): must be treated as a scanner error and must
        # not read whatever (possibly stale) report file exists.
        fake_gitleaks.write_text("#!/bin/sh\nexit 2\n")
        fake_gitleaks.chmod(0o755)

        stage = self.tmp / "stage"
        write(stage, "a.txt", "nothing\n")
        with self.assertRaises(cs.GitleaksFinding) as ctx:
            cs.run_gitleaks(str(fake_gitleaks), stage, run_dir)
        self.assertIn("scanner-error", str(ctx.exception.findings))
        self.assertNotIn("stale-rule", str(ctx.exception.findings))
        self.assertFalse(report_path.exists(), "report file must be deleted after the run, success or failure")

    # 9. the Gotify token is loaded lazily (only when something is deliverable); a missing
    # token file prints a safe message and keeps the pending record, no traceback.
    def test_9_notifier_loaded_lazily_missing_token_file_is_safe_and_keeps_pending(self):
        bare, repo_url = make_bare_repo(self.tmp)
        fs = self.tmp / "fs"
        backend = host_backend(fs)
        config = base_config(repo_url, [host_machine_cfg()])
        config["gotify_token_file"] = str(self.tmp / "no-such-token-file")
        runner, paths = make_runner(self.tmp, config, {"proxmox": backend}, notify_fn=None)
        import contextlib
        import io

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = runner.run()
        self.assertEqual(code, 1)
        self.assertNotIn("Traceback", err.getvalue())
        self.assertIn("notification skipped", err.getvalue())
        self.assertEqual(len(list(paths.pending_dir.glob("*.json"))), 1)

    # 10. main() never lets an unexpected exception's traceback reach stderr; it prints a
    # safe "internal error: <ClassName>" and exits 1. CONFIG_SNAPSHOT_DEBUG=1 re-raises.
    def test_10_main_catch_all_hides_traceback_debug_env_reraises(self):
        config_path = self.tmp / "config.json"
        config = base_config("file:///nonexistent.git", [host_machine_cfg()])
        config_path.write_text(json.dumps(config))

        original = cs.build_backends
        cs.build_backends = lambda cfg: (_ for _ in ()).throw(RuntimeError("boom"))
        self.addCleanup(lambda: setattr(cs, "build_backends", original))

        import contextlib
        import io

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = cs.main(["--config", str(config_path), "run"])
        self.assertEqual(code, 1)
        self.assertEqual(err.getvalue().strip(), "internal error: RuntimeError")
        self.assertNotIn("Traceback", err.getvalue())

        old_env = __import__("os").environ.get("CONFIG_SNAPSHOT_DEBUG")
        __import__("os").environ["CONFIG_SNAPSHOT_DEBUG"] = "1"
        try:
            with self.assertRaises(RuntimeError):
                cs.main(["--config", str(config_path), "run"])
        finally:
            if old_env is None:
                __import__("os").environ.pop("CONFIG_SNAPSHOT_DEBUG", None)
            else:
                __import__("os").environ["CONFIG_SNAPSHOT_DEBUG"] = old_env

    # 11. a running compose project's missing or excluded ConfigFiles entry is recorded,
    # not silently dropped.
    def test_11_compose_files_skipped_are_recorded_with_reason(self):
        fs = self.tmp / "fs"
        write(fs, "etc/hosts", "x\n")
        write(fs, "etc/hostname", "x\n")
        write(fs, "etc/fstab", "x\n")
        write(fs, "opt/stack/compose.yml", "services: {}\n")
        # secrets.env exists but is excluded by name; present.yml simply doesn't exist on disk.
        write(fs, "opt/stack/secrets.env", "SECRET=x\n")
        compose_ls = json.dumps(
            [
                {
                    "Name": "stack",
                    "Status": "running(1)",
                    "ConfigFiles": "/opt/stack/compose.yml,/opt/stack/secrets.env,/opt/stack/absent.yml",
                }
            ]
        )
        cmds = {
            tuple(cs.PACKAGES_CMD): b"",
            tuple(cs.UNIT_FILES_CMD): b"",
            tuple(cs.COMPOSE_LS_CMD): compose_ls.encode(),
            tuple(cs.PS_AQ_CMD): b"",
        }
        backend = cs.FixtureBackend(fs, "proxmox", commands=cmds)
        machine_cfg = {"name": "proxmox", "vmid": None, "docker": True, "paths": []}
        stats = cs.CollectStats()
        budget = cs.RunBudget(52428800)
        out_root = self.tmp / "out"
        cs.collect_machine(backend, machine_cfg, {"file_bytes": 1048576, "total_bytes": 52428800}, True, out_root, stats, budget)

        skipped_text = (out_root / "proxmox/_meta/compose-files-skipped.txt").read_text()
        self.assertIn("stack\t/opt/stack/secrets.env\texcluded:secret-pattern", skipped_text)
        self.assertIn("stack\t/opt/stack/absent.yml\tmissing", skipped_text)
        self.assertTrue((out_root / "proxmox/docker/compose/stack/compose.yml").exists())


if __name__ == "__main__":
    unittest.main()
