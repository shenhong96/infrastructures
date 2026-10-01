"""The opaque-blob tooling: komodo-decrypt-files (the pre-deploy helper) and the pre-commit hook that keeps the
plaintext twin out of the public repo. Needs sops, age-keygen (helper) and gitleaks (hook); a test skips without its tool.
Run from the repo root: python3 -m unittest discover tests"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / "ansible/roles/periphery/files/komodo-decrypt-files"
HOOK = ROOT / ".githooks/pre-commit"
SOPS_BLOB = ROOT / "tools/sops-blob"


def run(cmd, cwd, env=None, **kw):
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, **kw)


@unittest.skipUnless(shutil.which("sops") and shutil.which("age-keygen"), "sops and age-keygen are needed")
class DecryptFiles(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        key = self.tmp / "key.txt"
        run(["age-keygen", "-o", str(key)], self.tmp)
        pub = re.search(r"age1\w+", key.read_text()).group(0)
        self.run_dir = self.tmp / "run"
        (self.run_dir / "homepage").mkdir(parents=True)
        (self.run_dir / "smokeping").mkdir()
        self.env = {**os.environ, "SOPS_AGE_KEY_FILE": str(key)}
        # the helper pins PATH for the machines; here sops lives elsewhere, so use a copy that keeps ours
        self.helper = self.tmp / "helper.sh"
        self.helper.write_text(re.sub(r"^export PATH=.*$", 'export PATH="$PATH"', HELPER.read_text(), flags=re.M))
        self.plain = {"homepage/services.sops.yaml": "name: SECRET-NAME\nkey: SECRET-KEY\n", "smokeping/Targets.sops.yaml": "host = SECRET-HOST\n"}
        for rel, text in self.plain.items():
            src = self.tmp / "plain"
            src.write_text(text)
            out = run(["sops", "-e", "--age", pub, "--input-type", "binary", "--output-type", "yaml", str(src)], self.tmp, self.env)
            self.assertEqual(out.returncode, 0, out.stderr)
            (self.run_dir / rel).write_text(out.stdout)

    def helper_run(self, *args):
        return run(["bash", str(self.helper), *args], self.run_dir, self.env)

    def test_decrypts_each_blob_root_only_and_stamps_each_folder(self):
        out = self.helper_run("-m", "0644", *self.plain)
        self.assertEqual((out.returncode, out.stdout.strip(), out.stderr), (0, "decrypted 2 file(s)", ""))
        self.assertEqual((self.run_dir / ".decrypted/homepage/services.yaml").read_text(), self.plain["homepage/services.sops.yaml"])
        self.assertEqual((self.run_dir / ".decrypted/smokeping/Targets.yaml").read_text(), self.plain["smokeping/Targets.sops.yaml"])
        self.assertEqual(oct((self.run_dir / ".decrypted").stat().st_mode & 0o777), "0o700")
        self.assertEqual(oct((self.run_dir / ".decrypted/homepage/services.yaml").stat().st_mode & 0o777), "0o644")
        stamp = dict(l.split("=") for l in (self.run_dir / "files.env").read_text().split())
        self.assertEqual(sorted(stamp), ["BLOBS_HOMEPAGE_SHA", "BLOBS_SMOKEPING_SHA"])
        self.assertNotIn("SECRET", out.stdout + out.stderr + (self.run_dir / "files.env").read_text())
        before = dict(stamp)
        self.helper_run("-m", "0644", *self.plain)
        self.assertEqual(dict(l.split("=") for l in (self.run_dir / "files.env").read_text().split()), before)  # stable
        self.assertEqual([p.name for p in self.run_dir.iterdir() if p.name.startswith(".decrypt.")], [])  # no temp left

    def test_default_mode_is_root_only(self):
        self.helper_run(*self.plain)
        self.assertEqual(oct((self.run_dir / ".decrypted/homepage/services.yaml").stat().st_mode & 0o777), "0o600")

    def test_fails_closed_and_leaves_no_plaintext(self):
        self.assertEqual(self.helper_run("-m", "0644", *self.plain).returncode, 0)
        tampered = self.run_dir / "smokeping/Targets.sops.yaml"
        tampered.write_text(tampered.read_text() + "x")
        out = self.helper_run("-m", "0644", *self.plain)
        self.assertEqual(out.returncode, 1)
        self.assertNotIn("SECRET", out.stdout + out.stderr)
        self.assertFalse((self.run_dir / ".decrypted").exists(), "an older plaintext must not stay")
        self.assertFalse((self.run_dir / "files.env").exists())
        self.assertEqual([p.name for p in self.run_dir.iterdir() if p.name.startswith(".decrypt")], [])

    def test_rejects_bad_arguments(self):
        for args in (["../x.sops.yaml"], ["/abs.sops.yaml"], [".hid/x.sops.yaml"], ["a.env"], ["a b.sops.yaml"], [],
                     ["-m", "0666", "homepage/services.sops.yaml"], ["homepage/services.sops.yaml"] * 2, ["missing.sops.yaml"]):
            with self.subTest(args=args):
                out = self.helper_run(*args)
                self.assertEqual(out.returncode, 1)
                self.assertFalse((self.run_dir / ".decrypted").exists())

    def test_sops_blob_edit_keeps_it_a_blob(self):
        (self.tmp / ".sops.yaml").write_text("creation_rules:\n  - age: %s\n" % re.search(r"age1\w+", (self.tmp / "key.txt").read_text()).group(0))
        editor = self.tmp / "ed.sh"
        editor.write_text('#!/bin/sh\necho "more" >> "$1"\n')
        editor.chmod(0o755)
        target = self.tmp / "f.sops.yaml"
        self.assertEqual(run(["bash", str(SOPS_BLOB), "new", str(target)], self.tmp, self.env, input="a: 1\n").returncode, 0)
        self.assertEqual(run(["bash", str(SOPS_BLOB), "edit", str(target)], self.tmp, {**self.env, "EDITOR": str(editor)}).returncode, 0)
        self.assertTrue(target.read_text().startswith("data: ENC["))
        dec = run(["sops", "-d", "--input-type", "yaml", "--output-type", "binary", str(target)], self.tmp, self.env)
        self.assertEqual(dec.stdout, "a: 1\nmore\n")


@unittest.skipUnless(shutil.which("gitleaks") and shutil.which("git"), "gitleaks is needed")
class PreCommitHook(unittest.TestCase):
    def setUp(self):
        self.repo = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        run(["git", "init", "-q"], self.repo)
        (self.repo / ".githooks").mkdir()
        shutil.copy(HOOK, self.repo / ".githooks/pre-commit")
        shutil.copy(ROOT / ".sops.yaml", self.repo)

    def staged(self, files):
        for rel, text in files.items():
            path = self.repo / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        run(["git", "add", "-f", "-A"], self.repo)
        return run(["bash", ".githooks/pre-commit"], self.repo)

    def test_real_blobs_pass(self):
        files = {p.relative_to(ROOT).as_posix(): p.read_text() for p in (ROOT / "stacks").rglob("*.sops.yaml") if p.parent.name in ("homepage", "smokeping")}
        self.assertTrue(files)
        out = self.staged(files)
        self.assertEqual((out.returncode, out.stderr), (0, ""))

    def test_plaintext_twins_are_refused(self):
        names = ["stacks/aio/homepage/services.yaml", "stacks/aio/homepage/settings.yml", "stacks/aio/homepage/services.yaml.bak-1",
                 "stacks/aio/smokeping/Targets", "stacks/aio/smokeping/ssmtp.conf", "stacks/aio/.decrypted/homepage/docker.yaml"]
        out = self.staged({n: "x: 1\n" for n in names})
        self.assertEqual(out.returncode, 1)
        for n in names:
            self.assertIn(n, out.stderr)

    def test_a_blob_with_a_plaintext_value_is_refused(self):
        good = next(p for p in (ROOT / "stacks").rglob("*.sops.yaml") if p.parent.name == "homepage").read_text()
        bad = good.replace("data: ENC[", "data: hello ENC[", 1)
        out = self.staged({"stacks/aio/homepage/services.sops.yaml": bad})
        self.assertEqual(out.returncode, 1)


if __name__ == "__main__":
    unittest.main()
