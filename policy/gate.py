#!/usr/bin/env python3
"""The `gate` check: main's security policy, run on a pull request's files as data.

The gate workflow checks out main (this code) and the PR head (with main in its history)
side by side, then runs

    python3 main/policy/gate.py --pr pr --head-sha SHA --out out [--ack]

Nothing from the PR is ever run. It writes out/check.json (the body of the `gate` check
run) and out/comment.md (the summary comment). --ack means you labelled the PR gate-change
since its last push. A crash exits non-zero and posts nothing, so the PR stays blocked.
Tests: python3 -m unittest discover tests
"""
import argparse
import fnmatch
import json
import os
import posixpath
import re
import subprocess
import tomllib
from pathlib import Path

POLICY = Path(__file__).resolve().parent
HOOK = POLICY.parent / ".githooks" / "pre-commit"
ALLOW = "gitleaks:" + "allow"  # the marker that hides a line from gitleaks (split, or it would hide this one)

# Files that decide what runs, or what this gate checks: they pass only with your ack.
GATE_FILES = (
    ".github/*", "policy/*", ".githooks/*", ".sops.yaml", ".gitleaks.toml", ".gitleaksignore",
    "komodo/*", "ansible/requirements.yml", "ansible/inventory.yml", "ansible/known_hosts",
    "ansible/collections/*",
)
CODE_DIRS = ("library", "module_utils")  # and any *_plugins folder: code Ansible loads

# Host paths a container must not see: the host's own system, or Docker's socket.
SYSTEM_PATHS = ("/etc", "/proc", "/sys", "/dev", "/run", "/var/run", "/root", "/boot", "/usr",
                "/lib", "/bin", "/sbin", "/var/lib/docker")
HARMLESS = {"/etc/localtime", "/etc/timezone"}
HOST_NAMESPACES = ("network_mode", "pid", "ipc", "uts", "userns_mode", "cgroup")

# Komodo: the only stack settings in use today. Anything else (post_deploy, extra_args, ...)
# needs a policy change first.
STACK_KEYS = {
    "additional_env_files", "auto_pull", "auto_update", "branch", "compose_cmd_wrapper",
    "compose_cmd_wrapper_include", "config_files", "env_file_path", "file_paths", "files_on_host",
    "git_provider", "poll_for_updates", "pre_deploy", "project_name", "repo", "run_directory",
    "server", "webhook_enabled",
}
KOMODO_FILES = {"komodo/servers.toml": {"server"}, "komodo/procedures.toml": {"procedure"}}
REPO = {"repo": "shenhong96/infrastructures", "branch": "main", "git_provider": "github.com"}
# pre_deploy runs on the machine as root: only the decrypt helpers, with plain arguments.
HELPER = re.compile(r"/usr/local/sbin/komodo-decrypt-(env|files)( [\w.-][\w./-]*)+")
# compose_cmd_wrapper: only the redaction pipe, over plain env file names.
WRAPPER = re.compile(r"set -o pipefail; \[\[COMPOSE_COMMAND\]\] \| /usr/local/sbin/komodo-redact-config( [\w.-]+)+")

LAPTOP_TAGS = {"host", "lxc", "komodo", "periphery", "tailscale", "control", "github"}
RISKY_TASK = re.compile(r"^\s*(?:-\s+)?(?:ansible\.(?:builtin|legacy)\.)?(shell|command|raw|script|get_url)\s*:")
ON_CONTROL = re.compile(r"\b(delegate_to|local_action)\b|connection\s*:\s*local|\b(lookup|query)\(")


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout


def stage_on_merge_base(pr, base_ref):
    """Leaves the PR's changes staged on its merge base with main (HEAD is the base, the work
    tree and the index are the PR) and returns {path: A|M|D}. A rename is a D and an A."""
    base = git(pr, "merge-base", "HEAD", base_ref).strip()
    git(pr, "reset", "-q", "--soft", base)
    out = git(pr, "diff", "--cached", "--name-status", "--no-renames", "-z").split("\0")
    return dict(zip(out[1::2], out[0::2]))


def base_text(pr, path):
    r = subprocess.run(["git", "-C", str(pr), "show", f"HEAD:{path}"], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else None


def head_text(pr, path):
    p = Path(pr) / path
    return p.read_text() if p.is_file() else None


def added_lines(pr, *paths):
    """(file, line) for every line the PR adds, under paths."""
    out, f = [], None
    diff = git(pr, "diff", "--cached", "-U0", "--no-color", "--no-ext-diff", "--no-textconv", "--", *paths)
    for line in diff.splitlines():
        if line.startswith("+++ "):
            f = line[6:] if line.startswith("+++ b/") else None
        elif line.startswith("+") and f:
            out.append((f, line[1:]))
    return out


def is_gate_file(path):
    parts = path.split("/")
    return (any(fnmatch.fnmatchcase(path, g) for g in GATE_FILES)
            or parts[-1] == "ansible.cfg"
            or any(p.endswith("_plugins") or p in CODE_DIRS for p in parts[:-1]))


def secret_findings(pr):
    """Main's pre-commit hook on the PR's staged changes, with main's gitleaks config: a PR
    can't loosen either."""
    env = {**os.environ, "GITLEAKS_CONFIG": str(POLICY / "gitleaks.toml")}
    r = subprocess.run(["bash", str(HOOK)], cwd=pr, env=env, capture_output=True, text=True)
    found = [l.removeprefix("pre-commit: ") for l in r.stderr.splitlines() if l.startswith("pre-commit: ")]
    found += [f"{f}: adds an inline {ALLOW} comment" for f, l in added_lines(pr) if ALLOW in l]
    return found or ([] if r.returncode == 0 else [f"the secret checks failed (exit {r.returncode})"])


def load_yaml(text):
    """safe_load, refusing duplicate keys: Compose refuses them, and the gate must read the
    same value Compose would."""
    import yaml

    class Strict(yaml.SafeLoader):
        pass

    def mapping(loader, node):
        keys = [k.value for k, _ in node.value if isinstance(k, yaml.ScalarNode) and k.value != "<<"]
        if len(keys) != len(set(keys)):
            raise yaml.constructor.ConstructorError(None, None, "duplicate key", node.start_mark)
        return loader.construct_mapping(node)

    Strict.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    return yaml.load(text, Strict)


def mount_finding(src):
    """The finding for a host path a container gets, or None when it is harmless."""
    src = str(src)
    if "$" in src or src.startswith("~"):  # can't tell where it points
        return f"mount: {src}"
    if not src.startswith("/"):  # relative to the stack's folder
        path = posixpath.normpath(src)
        return f"mount: {src}" if path == ".." or path.startswith("../") else None
    path = "/" + posixpath.normpath(src).lstrip("/")  # normpath keeps a leading //
    if path in HARMLESS:
        return None
    if path == "/" or path.endswith("docker.sock") or any(path == p or path.startswith(p + "/") for p in SYSTEM_PATHS):
        return f"mount: {path}"
    return None


def volume_source(v):
    if isinstance(v, dict):
        return v.get("source") if v.get("type") == "bind" else None
    parts = str(v).split(":")
    return parts[0] if len(parts) > 1 and parts[0].startswith((".", "/", "~", "$")) else None


def listed(value):
    return [value] if isinstance(value, (str, dict)) else list(value or [])


def service_findings(svc):
    out = []
    if svc.get("privileged"):
        out.append("privileged")
    out += [f"{key}: {v}" for key in ("cap_add", "devices", "device_cgroup_rules") for v in listed(svc.get(key))]
    out += ["extends"] if svc.get("extends") else []
    out += [f"{key}: host" for key in HOST_NAMESPACES if str(svc.get(key, "")) == "host"]
    out += [f"security_opt: {o}" for o in listed(svc.get("security_opt")) if re.search(r"unconfined|label[:=]disable", str(o))]
    build = svc.get("build")
    if isinstance(build, dict) and (build.get("privileged") or build.get("entitlements") or str(build.get("network", "")) == "host"):
        out.append("build: privileged, entitlements or host network")
    sources = [volume_source(v) for v in listed(svc.get("volumes"))]
    sources += [e.get("path") if isinstance(e, dict) else e for e in listed(svc.get("env_file"))]
    out += [f for f in map(mount_finding, filter(None, sources)) if f]
    return out


def top_findings(doc):
    out = ["include"] if doc.get("include") else []
    for vol in (doc.get("volumes") or {}).values():
        device = ((vol or {}).get("driver_opts") or {}).get("device")
        if device and (f := mount_finding(device)):
            out.append(f)
    for kind in ("secrets", "configs"):
        for item in (doc.get(kind) or {}).values():
            if (item or {}).get("file") and (f := mount_finding(item["file"])):
                out.append(f)
    return out


def compose_findings(pr, exceptions):
    """Every compose file under stacks/ against the compose rules, less policy exceptions."""
    import yaml

    out = []
    for rel in sorted(filter(None, git(pr, "ls-files", "-z", "--", "stacks").split("\0"))):
        if not re.search(r"\.ya?ml$", rel) or ".sops." in rel:
            continue
        try:
            doc = load_yaml((Path(pr) / rel).read_text())
        except (yaml.YAMLError, UnicodeDecodeError) as e:
            out.append(f"{rel}: can't be read as YAML ({type(e).__name__})")
            continue
        if not isinstance(doc, dict) or "services" not in doc:
            continue
        allowed = exceptions.get(rel, {})
        services = doc["services"] if isinstance(doc["services"], dict) else {"(services)": {"extends": True}}
        for name, svc in services.items():
            out += [f"{rel}: {name}: {f}" for f in service_findings(svc if isinstance(svc, dict) else {})
                    if f not in allowed.get(name, [])]
        out += [f"{rel}: (top level): {f}" for f in top_findings(doc) if f not in allowed.get("(top level)", [])]
    return out


def stack_findings(stack, rel, root, exceptions):
    name, c = stack.get("name"), stack.get("config", {})
    out = [f"{k} is not allowed" for k in sorted(set(stack) - {"name", "config"})]
    out += [f"{k} is not allowed" for k in sorted(set(c) - STACK_KEYS)]
    out += [f"{flag} must be false" for flag in ("auto_pull", "poll_for_updates", "auto_update", "webhook_enabled")
            if c.get(flag) is not False]
    if not c.get("project_name"):
        out.append("project_name is empty")
    if not c.get("server"):
        out.append("server is empty")
    if c.get("server") == "proxmox" and name not in exceptions["proxmox_stacks"]:
        out.append("a new stack on proxmox")
    paths = [c.get("env_file_path"), *c.get("file_paths", []),
             *(f.get("path") for f in c.get("config_files", []) + c.get("additional_env_files", []))]
    out += [f"{p} leaves the stack's folder" for p in filter(None, paths) if p.startswith("/") or ".." in p.split("/")]
    pre = c.get("pre_deploy", {})
    if set(pre) - {"command"}:
        out.append("pre_deploy may only hold a command")
    for line in pre.get("command", "").replace("\\\n", " ").splitlines():
        line = " ".join(line.split())
        if line and (not HELPER.fullmatch(line) or ".." in line):
            out.append(f"pre_deploy runs more than the decrypt helpers: {line[:60]}")
    wrapper = c.get("compose_cmd_wrapper")
    if (wrapper is not None and not WRAPPER.fullmatch(wrapper)) or c.get("compose_cmd_wrapper_include", ["config"]) != ["config"]:
        out.append("compose_cmd_wrapper is not the redaction wrapper")
    if c.get("files_on_host"):
        # The compose file stays on the machine and is not in git (vpn): the folder holds only
        # komodo.toml, and Komodo never writes an env file there.
        if name not in exceptions["files_on_host_stacks"]:
            out.append("files_on_host: its compose file would not be in git")
        if [p.name for p in (root / rel).parent.iterdir()] != ["komodo.toml"]:
            out.append("a files_on_host folder holds only komodo.toml")
        if not str(c.get("run_directory", "")).startswith("/") or c.get("env_file_path") in (".env", "", None):
            out.append("files_on_host needs an absolute run_directory and an env_file_path other than .env")
        return out
    want = {**REPO, "run_directory": posixpath.dirname(rel)}
    out += [f"{k} must be {v}" for k, v in want.items() if c.get(k) != v]
    files = c.get("file_paths") or []
    if not files or not all(re.search(r"\.ya?ml$", f) for f in files):
        out.append("file_paths must name YAML compose files")
    elif not (root / want["run_directory"] / files[0]).is_file():
        out.append(f"{files[0]} is missing")
    return out


def komodo_findings(root, exceptions):
    """Komodo's sync files can only carry what the sync that reads them may apply: servers
    that never rotate keys, and stack records that never deploy by themselves, from this repo's
    main, with nothing but the decrypt helpers run on the machine."""
    root, out, seen = Path(root), [], set()
    if (root / "komodo/sync.toml").exists():
        out.append("komodo/sync.toml: syncs are defined in Ansible, never in git")
    for path in [p for folder in ("komodo", "stacks") for p in sorted((root / folder).rglob("*.toml"))]:
        rel = path.relative_to(root).as_posix()
        try:
            doc = tomllib.loads(path.read_text())
        except (tomllib.TOMLDecodeError, UnicodeDecodeError):
            out.append(f"{rel}: not valid TOML")
            continue
        if rel not in KOMODO_FILES and not rel.startswith("stacks/"):
            out.append(f"{rel}: not a known sync file")
        if extra := set(doc) - KOMODO_FILES.get(rel, {"stack"}):
            out.append(f"{rel}: unexpected tables {sorted(extra)}")
        for server in doc.get("server", []) if rel == "komodo/servers.toml" else []:
            config = server.get("config", {})
            if config.get("auto_rotate_keys") is not False or config.get("address") != "":
                out.append(f"{rel}: {server.get('name')}: rotates keys or sets an address")
        for stack in doc.get("stack", []) if rel.startswith("stacks/") else []:
            if stack.get("name") in seen:
                out.append(f"{rel}: {stack.get('name')}: duplicate name")
            seen.add(stack.get("name"))
            out += [f"{rel}: {stack.get('name')}: {f}" for f in stack_findings(stack, rel, root, exceptions)]
    return out


def services_images(text):
    try:
        doc = load_yaml(text or "") or {}
        return {k: (v or {}).get("image") for k, v in doc.get("services", {}).items()}
    except Exception:  # a broken file is reported by compose_findings
        return {}


def image_changes(pr, changed):
    out = []
    for rel in sorted(changed):
        if rel.startswith("stacks/") and re.search(r"\.ya?ml$", rel) and ".sops." not in rel:
            old, new = services_images(base_text(pr, rel)), services_images(head_text(pr, rel))
            for svc in sorted(set(old) | set(new)):
                if old.get(svc) != new.get(svc):
                    image = new.get(svc)
                    pin = "" if not image else " (pinned by digest)" if "@sha256:" in image else " (not pinned by digest)"
                    out.append(f"{rel}: {svc}: {old.get(svc) or '(none)'} → {image or '(none)'}{pin}")
    return out


def stacks_touched(pr, changed):
    out = []
    for folder in sorted({"/".join(p.split("/")[:2]) for p in changed if p.startswith("stacks/") and p.count("/") >= 2}):
        try:
            stacks = tomllib.loads((Path(pr) / folder / "komodo.toml").read_text()).get("stack", [])
        except (OSError, tomllib.TOMLDecodeError):
            stacks = []
        names = [f"{s.get('name')} on {s.get('config', {}).get('server')}" for s in stacks]
        out.append(f"{folder}: {', '.join(names) or 'no Komodo stack'}")
    return out


def roles_touched(changed):
    return sorted({p.split("/")[2] for p in changed if p.startswith("ansible/roles/") and p.count("/") >= 3})


def laptop_runs(pr, changed):
    """What merging won't apply: roles under laptop-only tags, base on proxmox, and the
    host_vars of machines Semaphore never touches."""
    try:
        plays = load_yaml(head_text(pr, "ansible/site.yml") or "") or []
    except Exception:
        plays = []
    tags_of = {}
    for play in plays if isinstance(plays, list) else []:
        tags = listed(play.get("tags"))
        for role in listed(play.get("roles")):
            role = role if isinstance(role, str) else role.get("role") or role.get("name")
            tags_of.setdefault(role, set()).update(tags)
    out = []
    for role in roles_touched(changed):
        if laptop := sorted(tags_of.get(role, set()) & LAPTOP_TAGS):
            out.append(f"role {role} (tag {', '.join(laptop)})")
        if role == "base":
            out.append("role base on proxmox (a merge applies it to the containers only)")
    out += [f"host_vars/{h}" for h in ("proxmox", "control") if any(p.startswith(f"ansible/host_vars/{h}/") for p in changed)]
    return out


def check(pr, base_ref="origin/main", ack=False):
    """(blocks, flags) for the PR checked out at pr."""
    pr = Path(pr)
    changed = stage_on_merge_base(pr, base_ref)
    exceptions = tomllib.loads((POLICY / "exceptions.toml").read_text())
    blocks = secret_findings(pr) + compose_findings(pr, exceptions["compose"]) + komodo_findings(pr, exceptions)
    gate = sorted(p for p in changed if is_gate_file(p))
    if gate and not ack:
        blocks.append("gate files changed without your gate-change label: " + ", ".join(gate))
    added = added_lines(pr, "ansible")
    flags = [
        ("Stacks", stacks_touched(pr, changed)),
        ("Images", image_changes(pr, changed)),
        ("Secret files (names only)", sorted(p for p in changed if ".sops." in p)),
        ("Ansible roles", roles_touched(changed)),
        ("New tasks check mode can't preview", [f"{f}: {l.strip()}" for f, l in added if RISKY_TASK.search(l)]),
        ("Tasks and lookups that run on control", [f"{f}: {l.strip()}" for f, l in added if ON_CONTROL.search(l)]),
        ("ansible/site.yml changed", ["a role may have moved to another tag or hosts"] if "ansible/site.yml" in changed else []),
        ("Needs a laptop run: merging won't apply it", laptop_runs(pr, changed)),
        ("Gate files", gate),
    ]
    return blocks, flags


def esc(text, limit=160):
    """PR-controlled text, safe inside a Markdown list item."""
    text = re.sub(r"[\x00-\x1f]", "?", str(text))[:limit]
    return re.sub(r"([\\`*_\[\]<>#|~@!])", r"\\\1", text)


def render(blocks, flags):
    lines = ["<!-- gate -->", f"### gate: {'blocked' if blocks else 'passes'}", ""]
    if blocks:
        lines += ["**Blocks**", *[f"- {esc(b)}" for b in blocks], ""]
    for title, items in flags:
        if items:
            lines += [f"**{title}**", *[f"- {esc(i)}" for i in items[:50]], ""]
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(description="Run the gate on a PR checkout.")
    p.add_argument("--pr", type=Path, required=True, help="the PR head, checked out with main in its history")
    p.add_argument("--base-ref", default="origin/main")
    p.add_argument("--head-sha", required=True)
    p.add_argument("--ack", action="store_true", help="you labelled the PR gate-change since its last push")
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args(argv)
    blocks, flags = check(args.pr, args.base_ref, args.ack)
    summary = render(blocks, flags)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "comment.md").write_text(summary)
    (args.out / "check.json").write_text(json.dumps({
        "name": "gate", "head_sha": args.head_sha, "status": "completed",
        "conclusion": "failure" if blocks else "success",
        "output": {"title": f"{len(blocks)} blocking" if blocks else "Nothing blocks", "summary": summary[:60000]},
    }))


if __name__ == "__main__":
    main()
