#!/usr/bin/env python3
"""config-snapshot: sanitized, deterministic drift snapshot of the lab's config into a private
git repo, with a gitleaks gate before every commit and a Gotify notification after every push.

Design: pure functions (classification, redaction, exclusion, listings, tree diff, notification
queue) are separate from I/O. Machine access goes through a Backend (LocalBackend for the host,
PctBackend for containers via `pct exec`, FixtureBackend in tests). See
tests/test_config_snapshot.py and the Phase 4 build contract for the full behavioural spec.

Never print file contents, redacted values, tokens, or URLs containing tokens. Only safe paths,
machine names, rule IDs and error categories reach stdout/stderr. For the same reason, main()
never lets an unexpected exception's traceback (which can echo source lines/values) reach
stderr: it prints `internal error: <ExceptionClassName>` and exits 1. Set
CONFIG_SNAPSHOT_DEBUG=1 to re-raise instead, for local debugging.
"""
from __future__ import annotations

import argparse
import dataclasses
import fcntl
import fnmatch
import glob as glob_mod
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional, Sequence

# --------------------------------------------------------------------------------------
# Errors. Messages on these must stay safe to print (paths/rule-ids/categories only).
# --------------------------------------------------------------------------------------


class SnapshotError(Exception):
    """Base for every error this tool raises deliberately."""


class ConfigError(SnapshotError):
    """Bad config.json, or a declared path that must never be collected."""


class LockBusyError(SnapshotError):
    """Another run holds the lock."""


class CollectionError(SnapshotError):
    """Collection/sanitization failed: required file missing, CT stopped, oversize, bad format."""


class GitleaksFinding(SnapshotError):
    """gitleaks found something, or failed to run."""

    def __init__(self, findings: list[tuple[str, str]]):
        super().__init__("gitleaks findings")
        self.findings = findings  # list of (relative_path, rule_id)


class GitError(SnapshotError):
    pass


class DivergedError(GitError):
    pass


class NotifyError(SnapshotError):
    pass


# --------------------------------------------------------------------------------------
# Defaults (production paths; all overridable so tests run unprivileged in temp dirs).
# --------------------------------------------------------------------------------------

DEFAULT_CONFIG_PATH = "/etc/config-snapshot/config.json"
DEFAULT_REPO_DIR = "/var/lib/config-snapshot/repo"
DEFAULT_PENDING_DIR = "/var/lib/config-snapshot/pending"
DEFAULT_STAGE_DIR = "/var/lib/config-snapshot/stage"
DEFAULT_RUN_DIR = "/run/config-snapshot"
DEFAULT_LOCK_FILE = "/run/lock/config-snapshot.lock"
DEFAULT_LOCK_TIMEOUT = 1800.0  # 30 minutes
SELF_EXCLUDE_PREFIXES = ("/etc/config-snapshot", "/var/lib/config-snapshot", "/etc/job-heartbeat")

README_CONTENT = """# Config snapshot

This repository is a sanitized, deterministic mirror of selected configuration from the lab,
written by `config-snapshot` (ansible/roles/proxmox_host/files/config-snapshot.py). Every secret
value is redacted before anything reaches this tree or git history; nothing here should ever
need redaction again by a human.

Layout, per machine (the inventory name):

    <machine>/files/<absolute path without leading slash>   collected, sanitized files
    <machine>/packages.txt                                   installed package versions
    <machine>/systemd-units.txt                               unit name + state
    <machine>/docker/projects.txt                             compose project + status + files
    <machine>/docker/compose/<project>/...                    sanitized compose config files
    <machine>/docker/images.txt                               container + image ref + image id
    <machine>/_meta/missing-optional.txt                       optional paths absent this run

This repo is private and read by nobody except the drift-alert pipeline. Treat it as sanitized,
not secret: a redaction bug would still be a disclosure, so report any suspicious value you see.
"""

# --------------------------------------------------------------------------------------
# config.json schema
# --------------------------------------------------------------------------------------

_CONFIG_KEYS = {
    "repo_url",
    "commit_url_base",
    "branch",
    "git_author",
    "deploy_key",
    "known_hosts",
    "gotify_url",
    "gotify_token_file",
    "gitleaks",
    "limits",
    "redact_pve_description",
    "machines",
}
_LIMIT_KEYS = {"file_bytes", "total_bytes"}
_MACHINE_KEYS = {"name", "vmid", "docker", "paths"}
_PATH_ITEM_KEYS = {"path", "optional"}


def _is_ssh_url(url: str) -> bool:
    return url.startswith("ssh://") or (":" in url and "@" in url.split(":", 1)[0] and "://" not in url)


def validate_config(config: dict) -> None:
    """Raise ConfigError on anything wrong. Never touches a backend."""
    if not isinstance(config, dict):
        raise ConfigError("config.json must be a JSON object")
    unknown = set(config) - _CONFIG_KEYS
    if unknown:
        raise ConfigError(f"unknown config keys: {', '.join(sorted(unknown))}")
    missing = _CONFIG_KEYS - {"deploy_key", "known_hosts"} - set(config)
    if missing:
        raise ConfigError(f"missing config keys: {', '.join(sorted(missing))}")
    repo_url = config["repo_url"]
    if not isinstance(repo_url, str) or not repo_url:
        raise ConfigError("repo_url must be a non-empty string")
    if _is_ssh_url(repo_url):
        for key in ("deploy_key", "known_hosts"):
            if not config.get(key):
                raise ConfigError(f"{key} is required for an ssh repo_url")
    limits = config.get("limits")
    if not isinstance(limits, dict) or set(limits) != _LIMIT_KEYS:
        raise ConfigError("limits must have exactly file_bytes and total_bytes")
    for key in _LIMIT_KEYS:
        if not isinstance(limits[key], int) or limits[key] <= 0:
            raise ConfigError(f"limits.{key} must be a positive integer")
    machines = config.get("machines")
    if not isinstance(machines, list) or not machines:
        raise ConfigError("machines must be a non-empty list")
    names = set()
    for m in machines:
        if not isinstance(m, dict) or set(m) - _MACHINE_KEYS:
            raise ConfigError("machine entries must only have name/vmid/docker/paths")
        if "name" not in m or not isinstance(m["name"], str) or not m["name"]:
            raise ConfigError("every machine needs a non-empty name")
        if m["name"] in names:
            raise ConfigError(f"duplicate machine name: {m['name']}")
        names.add(m["name"])
        if "vmid" in m and m["vmid"] is not None and not isinstance(m["vmid"], int):
            raise ConfigError(f"{m['name']}: vmid must be null or an integer")
        if "docker" in m and not isinstance(m["docker"], bool):
            raise ConfigError(f"{m['name']}: docker must be a boolean")
        for item in m.get("paths", []):
            path = _path_item_path(item, m["name"])
            for prefix in SELF_EXCLUDE_PREFIXES:
                if path == prefix or path.startswith(prefix.rstrip("/") + "/"):
                    raise ConfigError(
                        f"{m['name']}: declared path {path} is under the snapshot's own "
                        "private storage (self-exclusion)"
                    )


def _path_item_path(item, machine_name: str) -> str:
    if isinstance(item, str):
        return item
    if isinstance(item, dict) and set(item) <= _PATH_ITEM_KEYS and "path" in item:
        return item["path"]
    raise ConfigError(f"{machine_name}: bad paths entry {item!r}")


def _path_item_optional(item) -> bool:
    if isinstance(item, dict):
        return bool(item.get("optional", False))
    return False


def load_config(path: str) -> dict:
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config at {path}: {exc.__class__.__name__}") from exc
    try:
        config = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"config at {path} is not valid JSON: {exc.msg}") from exc
    validate_config(config)
    return config


# --------------------------------------------------------------------------------------
# Sensitive-key classification (pure)
# --------------------------------------------------------------------------------------

SENSITIVE_KEY_RE = re.compile(
    # NOTE: the bare "auth" alternative over-matches ("author", "authorized_keys",
    # "authentication"...). That's deliberate: over-redaction (a false-positive <redacted>)
    # is a non-event; a missed credential is a disclosure. Keep it.
    r"pass(word|wd|phrase)?|secret|token|api[_-]?key|apikey|private[_-]?key|access[_-]?key|"
    r"client[_-]?secret|auth|credential|cookie|session[_-]?key|salt|signing|encryption[_-]?key|"
    r"webhook|dsn|bearer|otp|psk|smtp_password|license",
    re.IGNORECASE,
)
# Catches the many *_KEY/*_KEYS names the alternation above doesn't spell out verbatim
# (APP_KEY, MASTER_KEY, B2_ACCOUNT_KEY, WireGuard PresharedKey/PrivateKey, ...). Still
# subject to PATH_ALLOWLIST_RE below, so e.g. "keyfile" (a path, not a key) stays visible.
ENDS_WITH_KEY_RE = re.compile(r"keys?$", re.IGNORECASE)
# Allowlist: a key whose *name* trips the regexes above but whose *value* is a path to a
# secret, not the secret itself (e.g. "token_file", "ssh_private_key_path", "keyfile").
# Keeping these un-redacted preserves useful diffs (a path change is real drift) without
# ever exposing a value.
PATH_ALLOWLIST_RE = re.compile(r"(_file|_path|file)$", re.IGNORECASE)


def is_sensitive_key(raw_key: str) -> bool:
    key = raw_key.strip().strip("'\"[]")
    if not (SENSITIVE_KEY_RE.search(key) or ENDS_WITH_KEY_RE.search(key)):
        return False
    if PATH_ALLOWLIST_RE.search(key):
        return False
    return True


REDACTED = "<redacted>"

PEM_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
HASH_RE = re.compile(r"\$(2[aby]|argon2[a-z]*|6|y)\$[A-Za-z0-9./$+=_-]+")
USERINFO_URL_RE = re.compile(r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://)(?P<userinfo>[^@/\s:]+:[^@/\s]+)@")
# A URL-ish token in a path/query segment: a UUID, or >=20 chars of mixed-class [A-Za-z0-9_-].
TOKEN_SEGMENT_RE = re.compile(
    r"(?P<prefix>[/?&=])(?P<token>"
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"|[A-Za-z0-9_-]{20,})"
)


def _looks_like_mixed_token(candidate: str) -> bool:
    has_alpha = any(c.isalpha() for c in candidate)
    has_digit = any(c.isdigit() for c in candidate)
    return has_alpha and has_digit


def redact_urls_and_hashes(text: str) -> str:
    """Generic rules applied to every text format after per-format redaction."""

    def _token_sub(m: re.Match) -> str:
        token = m.group("token")
        if "-" in token and len(token) == 36:  # UUID shape already checked by regex
            return m.group("prefix") + REDACTED
        if _looks_like_mixed_token(token):
            return m.group("prefix") + REDACTED
        return m.group(0)

    text = USERINFO_URL_RE.sub(lambda m: m.group("scheme") + REDACTED + "@", text)
    text = TOKEN_SEGMENT_RE.sub(_token_sub, text)
    text = HASH_RE.sub(REDACTED, text)
    if PEM_RE.search(text):
        raise CollectionError("private key material found in a config file (PEM block)")
    return text


CREDENTIAL_INDICATOR_RE = re.compile(
    r"-----BEGIN|"
    r"(?P<key>[\w.\[\]'\"-]+)\s*[:=]\s*\S|"
    r"://[^/\s]+:[^/\s]+@",
)
HIGH_ENTROPY_RE = re.compile(r"[A-Za-z0-9_-]{32,}")


def looks_like_credential(text: str) -> bool:
    """Used only for unknown/binary-classified text: block the run if it smells like a secret."""
    if PEM_RE.search(text):
        return True
    if USERINFO_URL_RE.search(text):
        return True
    for line in text.splitlines():
        m = re.match(r"\s*([\w.\[\]'\"-]+)\s*[:=]\s*(\S.*)$", line)
        if m and is_sensitive_key(m.group(1)):
            return True
    for token in HIGH_ENTROPY_RE.findall(text):
        if _looks_like_mixed_token(token):
            return True
    return False


# --------------------------------------------------------------------------------------
# Per-format redaction (pure, text in -> text out, or raise CollectionError)
# --------------------------------------------------------------------------------------


def classify_format(path: str) -> str:
    name = os.path.basename(path).lower()
    if name == "gitlab.rb":
        return "gitlab_rb"
    if name.endswith(".json"):
        return "json"
    if name.endswith((".yml", ".yaml")):
        return "yaml"
    if name.endswith(".xml"):
        return "xml"
    if name.endswith((".toml", ".ini", ".conf", ".cfg")) or name == "smb.conf":
        return "kv"
    if name.endswith(".sh") or name in (
        "crontab",
        "environment",
    ) or "cron" in os.path.dirname(path).lower().split("/")[-1:]:
        return "shell"
    if name in ("caddyfile", "fstab", "crypttab", "interfaces", "snapraid.conf", "sanoid.conf"):
        return "kv"
    if os.path.dirname(path).endswith(("/cron.d", "/crontabs")) or name == "crontab":
        return "shell"
    if name.startswith(("service", "timer", "socket")) or name.endswith((".service", ".timer", ".socket")):
        return "shell"
    return "unknown"


def redact_json(text: str) -> str:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CollectionError(f"invalid JSON: {exc.msg}") from exc

    def walk(node):
        if isinstance(node, dict):
            out = {}
            for k, v in node.items():
                if is_sensitive_key(k):
                    out[k] = REDACTED
                else:
                    out[k] = walk(v)
            return out
        if isinstance(node, list):
            return [walk(v) for v in node]
        return node

    return json.dumps(walk(data), indent=2) + "\n"


_YAML_KV_RE = re.compile(r"^(?P<indent>\s*)(?P<dash>- )?(?P<key>[^\s:#][^:]*?):(\s+(?P<value>.*)|\s*)$")
_YAML_LIST_ITEM_RE = re.compile(r'^(?P<indent>\s*)-\s+(?P<quote>["\']?)(?P<key>[A-Za-z0-9_.-]+)=(?P<rest>.*)$')
_YAML_FLOW_MAP_RE = re.compile(r"\{([^{}]*)\}")


def _redact_flow_mapping(match: re.Match) -> str:
    body = match.group(1)
    parts = []
    for piece in body.split(","):
        if ":" in piece:
            k, _, v = piece.partition(":")
            if is_sensitive_key(k):
                parts.append(f"{k}: {REDACTED}")
                continue
        parts.append(piece)
    return "{" + ",".join(parts) + "}"


def redact_yaml(text: str) -> str:
    lines = text.split("\n")
    out = []
    i = 0
    while i < len(lines):
        line = lines[i]
        list_m = _YAML_LIST_ITEM_RE.match(line)
        kv_m = _YAML_KV_RE.match(line)
        if list_m and is_sensitive_key(list_m.group("key")):
            q = list_m.group("quote")
            out.append(f"{list_m.group('indent')}- {q}{list_m.group('key')}={REDACTED}{q}")
            i += 1
            continue
        if kv_m and kv_m.group("key") and is_sensitive_key(kv_m.group("key")):
            value = (kv_m.group("value") or "").strip()
            indent = kv_m.group("indent")
            dash = kv_m.group("dash") or ""
            if value in ("|", ">") or value.startswith(("|", ">")):
                out.append(line)
                base_indent = len(indent) + len(dash)
                j = i + 1
                block_indent = None
                while j < len(lines):
                    nxt = lines[j]
                    if nxt.strip() == "":
                        j += 1
                        continue
                    nxt_indent = len(nxt) - len(nxt.lstrip(" "))
                    if nxt_indent <= base_indent:
                        break
                    if block_indent is None:
                        block_indent = nxt_indent
                        out.append(" " * block_indent + REDACTED)
                    j += 1
                i = j
                continue
            out.append(f"{indent}{dash}{kv_m.group('key')}: {REDACTED}")
            i += 1
            continue
        out.append(_YAML_FLOW_MAP_RE.sub(_redact_flow_mapping, line))
        i += 1
    return "\n".join(out)


_KV_LINE_RE = re.compile(r"^(?P<indent>\s*)(?P<key>[A-Za-z0-9_.\[\]'\" -]+?)\s*(?P<sep>[:=])\s*(?P<value>.*)$")


def redact_kv(text: str) -> str:
    lines = text.split("\n")
    out = []
    i = 0
    in_multiline_toml = False
    delim = None
    while i < len(lines):
        line = lines[i]
        if in_multiline_toml:
            if delim in line:
                in_multiline_toml = False
            i += 1
            continue
        m = _KV_LINE_RE.match(line)
        if m and not line.strip().startswith(("#", ";", "[")):
            key = m.group("key")
            value = m.group("value")
            if is_sensitive_key(key):
                for triple in ('"""', "'''"):
                    if value.startswith(triple) and value.count(triple) < 2:
                        delim = triple
                        in_multiline_toml = True
                        out.append(f"{m.group('indent')}{key} = {REDACTED}")
                        i += 1
                        break
                else:
                    out.append(f"{m.group('indent')}{key} {m.group('sep')} {REDACTED}")
                    i += 1
                continue
        out.append(line)
        i += 1
    return "\n".join(out)


_SHELL_KV_RE = re.compile(
    r"^(?P<prefix>\s*(export\s+)?)(?P<key>[A-Za-z_][A-Za-z0-9_]*)=(?P<quote>[\"']?)(?P<value>.*)$"
)
_ENVIRON_RE = re.compile(r"^(?P<prefix>\s*Environment\s*=\s*)(?P<quote>[\"']?)(?P<key>[A-Za-z_][A-Za-z0-9_]*)=(?P<rest>.*)$")


def redact_shell(text: str) -> str:
    out = []
    for line in text.split("\n"):
        m = _ENVIRON_RE.match(line)
        if m and is_sensitive_key(m.group("key")):
            q = m.group("quote")
            out.append(f"{m.group('prefix')}{q}{m.group('key')}={REDACTED}{q.rstrip() if False else q}")
            continue
        m = _SHELL_KV_RE.match(line)
        if m and is_sensitive_key(m.group("key")):
            q = m.group("quote")
            out.append(f"{m.group('prefix')}{m.group('key')}={q}{REDACTED}{q}")
            continue
        out.append(line)
    return "\n".join(out)


_GITLAB_RB_RE = re.compile(r"^(?P<prefix>\s*[\w.]+\[(['\"])(?P<key>[\w-]+)\2\]\s*=\s*)(?P<value>.*)$")


def _balanced(s: str) -> bool:
    depth = 0
    in_quote = None
    i = 0
    while i < len(s):
        c = s[i]
        if in_quote:
            if c == "\\":
                i += 2
                continue
            if c == in_quote:
                in_quote = None
        elif c in "'\"":
            in_quote = c
        elif c in "[{(":
            depth += 1
        elif c in "]})":
            depth -= 1
        i += 1
    return depth == 0 and in_quote is None


def redact_gitlab_rb(text: str) -> str:
    lines = text.split("\n")
    out = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _GITLAB_RB_RE.match(line)
        if m and is_sensitive_key(m.group("key")):
            value = m.group("value")
            j = i
            acc = value
            while not _balanced(acc) and j + 1 < len(lines):
                j += 1
                acc += "\n" + lines[j]
            out.append(f"{m.group('prefix')}{REDACTED}")
            i = j + 1
            continue
        out.append(line)
        i += 1
    return "\n".join(out)


_XML_TAG_RE = re.compile(r"<(?P<tag>[A-Za-z0-9_:.-]+)(?P<attrs>[^>]*)>(?P<body>.*?)</(?P=tag)>", re.DOTALL)
_XML_ATTR_RE = re.compile(r'(?P<name>[A-Za-z0-9_:.-]+)="(?P<value>[^"]*)"')


def _xml_attrs_sub(m: re.Match) -> str:
    if is_sensitive_key(m.group("name")):
        return f'{m.group("name")}="{REDACTED}"'
    return m.group(0)


def redact_xml(text: str) -> str:
    def tag_sub(m: re.Match) -> str:
        attrs = _XML_ATTR_RE.sub(_xml_attrs_sub, m.group("attrs"))
        body = m.group("body")
        if "<" in body:
            # nested elements: recurse so an inner sensitive tag still gets redacted even
            # though this (outer, possibly non-sensitive) tag's body isn't a plain value.
            body = redact_xml(body)
        elif is_sensitive_key(m.group("tag")):
            body = REDACTED
        return f"<{m.group('tag')}{attrs}>{body}</{m.group('tag')}>"

    return _XML_TAG_RE.sub(tag_sub, text)


FORMAT_REDACTORS: dict[str, Callable[[str], str]] = {
    "json": redact_json,
    "yaml": redact_yaml,
    "kv": redact_kv,
    "shell": redact_shell,
    "gitlab_rb": redact_gitlab_rb,
    "xml": redact_xml,
}


def sanitize_text(path: str, raw: bytes) -> bytes:
    """Classify, redact, apply generic rules. Raises CollectionError for anything unsafe."""
    if b"\x00" in raw:
        if looks_like_credential(raw.decode("utf-8", errors="replace")):
            raise CollectionError(f"{path}: binary file with a credential indicator")
        raise CollectionError(f"{path}: binary file cannot be sanitized")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            preview = raw.decode("latin-1")
        except Exception:
            preview = ""
        if looks_like_credential(preview):
            raise CollectionError(f"{path}: non-utf8 file with a credential indicator")
        raise CollectionError(f"{path}: non-utf8 file cannot be sanitized")

    fmt = classify_format(path)
    if PEM_RE.search(text):
        # PEM material must never be silently redacted away, even if it happens to live
        # inside a sensitive-key block that the per-format redactor would otherwise handle:
        # a private key reaching a collected file is always a configuration error.
        raise CollectionError(f"{path}: private key material found (PEM block)")
    if fmt == "unknown":
        if looks_like_credential(text):
            raise CollectionError(f"{path}: unrecognized format contains a possible credential")
        return text.encode("utf-8")
    redactor = FORMAT_REDACTORS[fmt]
    redacted = redactor(text)
    redacted = redact_urls_and_hashes(redacted)
    return redacted.encode("utf-8")


def redact_pve_conf(text: str) -> str:
    """PVE guest .conf: `description:` line value, and leading '#' comment lines (PVE's own
    description storage at the top of the file / each snapshot section) -> <redacted>."""
    out = []
    for line in text.split("\n"):
        if line.startswith("#"):
            out.append("#" + REDACTED)
        elif line.lower().startswith("description:"):
            out.append("description: " + REDACTED)
        else:
            out.append(line)
    return "\n".join(out)


# --------------------------------------------------------------------------------------
# Exclusion (pure)
# --------------------------------------------------------------------------------------

BASENAME_EXCLUDE_GLOBS = (
    ".env",
    "secrets.env",
    "*.env",
    "*.sops.*",
    "*.key",
    "*.pem",
    "*.p12",
    "*.pfx",
    "id_*",
    "*.age",
    "keys.txt",
    "*credentials*",
    "*.kdbx",
    ".git-credentials",
    ".netrc",
    ".pgpass",
    ".my.cnf",
    "authkey*",
    "pve-root-ca*",
    "pve-www*",
    ".version",
    ".members",
    ".vmlist",
    ".clusterlog",
)
EXCLUDED_PATH_SEGMENTS = {".decrypted", ".git", "priv", ".ssh", ".gnupg"}
EXCLUDED_PREFIXES = SELF_EXCLUDE_PREFIXES + ("/etc/ssl/private",)


def exclusion_reason(resolved_path: str, crypttab_keyfiles: frozenset[str] = frozenset()) -> Optional[str]:
    """Return a safe reason string if resolved_path must never be collected, else None."""
    norm = resolved_path.rstrip("/") or "/"
    for prefix in EXCLUDED_PREFIXES:
        if norm == prefix or norm.startswith(prefix + "/"):
            return "self-exclusion"
    if norm.startswith("/etc/shadow") or norm.startswith("/etc/gshadow"):
        return "shadow-file"
    if norm in crypttab_keyfiles:
        return "disk-key-file"
    parts = norm.split("/")
    basename = parts[-1] if parts else norm
    if basename in EXCLUDED_PATH_SEGMENTS or any(p in EXCLUDED_PATH_SEGMENTS for p in parts[:-1]):
        return "excluded-path-segment"
    for pat in BASENAME_EXCLUDE_GLOBS:
        if fnmatch.fnmatchcase(basename, pat):
            return "secret-pattern"
    return None


def parse_crypttab_keyfiles(text: str) -> frozenset[str]:
    keyfiles = set()
    for line in text.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) >= 3:
            keyfile = fields[2]
            if keyfile not in ("none", "-") and keyfile.startswith("/"):
                keyfiles.add(keyfile.rstrip("/"))
    return frozenset(keyfiles)


# --------------------------------------------------------------------------------------
# Canonical listings (pure: command stdout text in -> listing text out)
# --------------------------------------------------------------------------------------


def format_packages(dpkg_output: str) -> str:
    lines = []
    for line in dpkg_output.split("\n"):
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        name, version, arch, status = parts[0], parts[1], parts[2], parts[3]
        if status.strip() != "install ok installed":
            continue
        lines.append(f"{name}\t{version}\t{arch}")
    return "\n".join(sorted(lines)) + ("\n" if lines else "")


def format_systemd_units(systemctl_output: str) -> str:
    lines = []
    for line in systemctl_output.split("\n"):
        if not line.strip():
            continue
        cols = line.split()
        if len(cols) < 2:
            continue
        lines.append(f"{cols[0]}\t{cols[1]}")
    return "\n".join(sorted(lines)) + ("\n" if lines else "")


def format_docker_projects(compose_ls_json: str) -> str:
    try:
        projects = json.loads(compose_ls_json) if compose_ls_json.strip() else []
    except json.JSONDecodeError as exc:
        raise CollectionError(f"docker compose ls: invalid JSON: {exc.msg}") from exc
    lines = []
    for p in projects:
        name = p.get("Name", "")
        status = p.get("Status", "")
        words = sorted(set(re.findall(r"[a-zA-Z]+", status)))
        config_files = p.get("ConfigFiles", "")
        lines.append(f"{name}\t{','.join(words)}\t{config_files}")
    return "\n".join(sorted(lines)) + ("\n" if lines else "")


def docker_running_projects(compose_ls_json: str) -> list[dict]:
    try:
        projects = json.loads(compose_ls_json) if compose_ls_json.strip() else []
    except json.JSONDecodeError as exc:
        raise CollectionError(f"docker compose ls: invalid JSON: {exc.msg}") from exc
    return [p for p in projects if "running" in p.get("Status", "").lower()]


def format_docker_images(inspect_output: str) -> str:
    lines = []
    for line in inspect_output.split("\n"):
        if not line.strip():
            continue
        cols = line.split("\t")
        if len(cols) < 3:
            continue
        name = cols[0].lstrip("/")
        lines.append(f"{name}\t{cols[1]}\t{cols[2]}")
    return "\n".join(sorted(lines)) + ("\n" if lines else "")


def format_missing_optional(paths: Iterable[str]) -> Optional[str]:
    paths = sorted(set(paths))
    if not paths:
        return None
    return "\n".join(paths) + "\n"


def compose_output_name(project: str, seen_basenames: dict[str, set[str]], file_path: str) -> str:
    """basename, falling back to a sanitized relative path on collision within the project."""
    base = os.path.basename(file_path)
    used = seen_basenames.setdefault(project, set())
    if base not in used:
        used.add(base)
        return base
    rel = file_path.lstrip("/").replace("/", "__")
    used.add(rel)
    return rel


# --------------------------------------------------------------------------------------
# Backend interface
# --------------------------------------------------------------------------------------


@dataclass
class PathInfo:
    exists: bool
    is_dir: bool = False
    is_symlink: bool = False
    is_file: bool = False
    size: int = 0
    link_target: Optional[str] = None


class Backend:
    name: str

    def info(self, path: str) -> PathInfo:
        raise NotImplementedError

    def read_file(self, path: str) -> bytes:
        raise NotImplementedError

    def list_glob(self, pattern: str) -> list[str]:
        raise NotImplementedError

    def realpath(self, path: str) -> str:
        raise NotImplementedError

    def run(self, cmd: Sequence[str]) -> subprocess.CompletedProcess:
        raise NotImplementedError

    def status(self) -> str:
        """'running' for the host or a reachable container, something else otherwise."""
        raise NotImplementedError


def _run_checked(backend: "Backend", cmd: Sequence[str], what: str) -> subprocess.CompletedProcess:
    """Run a listing command and insist on exit 0. A failed listing command must never be
    mistaken for "nothing here": that would make real content look like mass deletion."""
    res = backend.run(cmd)
    if res.returncode != 0:
        raise CollectionError(f"{backend.name}: {what} failed (exit {res.returncode})")
    return res


def walk_files_and_symlinks(root: Path) -> list[Path]:
    """Recursive walk matching `find <root> -mindepth 1 \\( -type f -o -type l \\) -print`:
    regular files and symlinks (to a file OR a directory) are leaves; a symlinked directory
    is never descended into. Shared by LocalBackend and FixtureBackend so their "/**" glob
    semantics are identical to PctBackend's `find`-based one (see PctBackend._list_glob_argv)."""
    out: list[Path] = []
    if not root.is_dir():
        return out
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                out.append(entry)
            elif entry.is_dir():
                stack.append(entry)
            elif entry.is_file():
                out.append(entry)
    return sorted(out)


class LocalBackend(Backend):
    """The Proxmox host itself: direct filesystem + subprocess access."""

    def __init__(self, name: str = "proxmox"):
        self.name = name

    def info(self, path: str) -> PathInfo:
        try:
            st = os.lstat(path)
        except OSError:
            return PathInfo(exists=False)
        is_link = stat.S_ISLNK(st.st_mode)
        target = os.readlink(path) if is_link else None
        if is_link:
            try:
                real_st = os.stat(path)
                is_dir = stat.S_ISDIR(real_st.st_mode)
                is_file = stat.S_ISREG(real_st.st_mode)
                size = real_st.st_size
            except OSError:
                is_dir = is_file = False
                size = 0
        else:
            is_dir = stat.S_ISDIR(st.st_mode)
            is_file = stat.S_ISREG(st.st_mode)
            size = st.st_size
        return PathInfo(exists=True, is_dir=is_dir, is_symlink=is_link, is_file=is_file, size=size, link_target=target)

    def read_file(self, path: str) -> bytes:
        try:
            return Path(path).read_bytes()
        except OSError as exc:
            raise CollectionError(f"{self.name}: cannot read {path} ({exc.__class__.__name__})") from exc

    def list_glob(self, pattern: str) -> list[str]:
        if pattern.endswith("/**"):
            base = pattern[:-3] or "/"
            return sorted(str(p) for p in walk_files_and_symlinks(Path(base)))
        return sorted(glob_mod.glob(pattern, recursive=True))

    def realpath(self, path: str) -> str:
        return os.path.realpath(path)

    def run(self, cmd: Sequence[str]) -> subprocess.CompletedProcess:
        return subprocess.run(list(cmd), capture_output=True)

    def status(self) -> str:
        return "running"


class PctBackend(Backend):
    """An LXC container, reached only via `pct exec <vmid> -- ...` on the host (never SSH)."""

    # Each helper script ends in an explicit `exit 0`/`exit $?` so a real pct/shell failure
    # (nonzero) is always distinguishable from "nothing found"/"path missing" (which print an
    # explicit marker instead of relying on a silent empty/zero exit code).
    _INFO_SCRIPT = (
        'if out=$(stat -c "%F|%s" -- "$1" 2>/dev/null); then '
        'printf "OK|%s\\n" "$out"; '
        'if [ -L "$1" ]; then readlink -- "$1"; fi; '
        "else printf 'MISSING\\n'; fi; exit 0"
    )

    def __init__(self, vmid: int, name: str):
        self.vmid = vmid
        self.name = name

    def _pct_exec(self, argv: Sequence[str]) -> subprocess.CompletedProcess:
        return subprocess.run(["pct", "exec", str(self.vmid), "--"] + list(argv), capture_output=True)

    def info(self, path: str) -> PathInfo:
        res = self._pct_exec(["sh", "-c", self._INFO_SCRIPT, "sh", path])
        if res.returncode != 0:
            raise CollectionError(f"{self.name}: info failed for {path} (exit {res.returncode})")
        lines = res.stdout.decode("utf-8", errors="replace").split("\n")
        first = lines[0] if lines else ""
        if first == "MISSING":
            return PathInfo(exists=False)
        if not first.startswith("OK|"):
            raise CollectionError(f"{self.name}: info returned unexpected output for {path}")
        kind_size = first[len("OK|"):].split("|")
        kind = kind_size[0]
        if len(kind_size) < 2 or not kind_size[1].isdigit():
            raise CollectionError(f"{self.name}: info returned unparsable size for {path}")
        size = int(kind_size[1])
        is_link = "symbolic link" in kind
        target = lines[1] if is_link and len(lines) > 1 and lines[1] else None
        return PathInfo(
            exists=True,
            is_dir="directory" in kind,
            is_symlink=is_link,
            is_file="regular" in kind,
            size=size,
            link_target=target,
        )

    def read_file(self, path: str) -> bytes:
        res = self._pct_exec(["cat", "--", path])
        if res.returncode != 0:
            raise CollectionError(f"{self.name}: cat failed for {path} (exit {res.returncode})")
        return res.stdout

    @staticmethod
    def _list_glob_argv(pattern: str) -> list[str]:
        """The exact argv `_pct_exec` runs for a glob pattern (exposed so tests can check the
        generated script shape, and that it agrees with Local/FixtureBackend's semantics, without
        needing a real `pct` binary)."""
        if pattern.endswith("/**"):
            base = pattern[:-3] or "/"
            script = 'if [ -d "$1" ]; then find "$1" -mindepth 1 \\( -type f -o -type l \\) -print; exit $?; else exit 0; fi'
            return ["sh", "-c", script, "sh", base]
        script = "for f in " + pattern + '; do [ -e "$f" ] || [ -L "$f" ] && printf "%s\\n" "$f"; done; exit 0'
        return ["sh", "-c", script]

    def list_glob(self, pattern: str) -> list[str]:
        res = self._pct_exec(self._list_glob_argv(pattern))
        if res.returncode != 0:
            raise CollectionError(f"{self.name}: list_glob failed for {pattern} (exit {res.returncode})")
        return sorted(p for p in res.stdout.decode("utf-8", errors="replace").split("\n") if p)

    def realpath(self, path: str) -> str:
        res = self._pct_exec(["realpath", "-m", "--", path])
        if res.returncode != 0:
            raise CollectionError(f"{self.name}: realpath failed for {path} (exit {res.returncode})")
        return res.stdout.decode("utf-8", errors="replace").strip() or path

    def run(self, cmd: Sequence[str]) -> subprocess.CompletedProcess:
        return self._pct_exec(cmd)

    def status(self) -> str:
        res = subprocess.run(["pct", "status", str(self.vmid)], capture_output=True)
        out = res.stdout.decode("utf-8", errors="replace")
        return "running" if "status: running" in out else out.strip() or "unknown"


class FixtureBackend(Backend):
    """Tests: a temp dir stands in for the machine's filesystem root; commands are canned."""

    def __init__(
        self,
        root: Path,
        name: str = "fixture",
        commands: Optional[dict[tuple, bytes]] = None,
        status_value: str = "running",
        run_handler: Optional[Callable[[Sequence[str]], Optional[subprocess.CompletedProcess]]] = None,
    ):
        # realpath so a /tmp-under-symlink (e.g. macOS /var -> /private/var) root still
        # compares equal to itself after resolving symlinks inside it.
        self.root = Path(os.path.realpath(root))
        self.name = name
        self.commands = commands or {}
        self._status = status_value
        self.run_handler = run_handler

    def _host_path(self, path: str) -> Path:
        rel = path.lstrip("/")
        return (self.root / rel) if rel else self.root

    def info(self, path: str) -> PathInfo:
        hp = self._host_path(path)
        try:
            st = hp.lstat()
        except OSError:
            return PathInfo(exists=False)
        is_link = stat.S_ISLNK(st.st_mode)
        target = os.readlink(hp) if is_link else None
        if is_link:
            try:
                real_st = hp.stat()
                is_dir = stat.S_ISDIR(real_st.st_mode)
                is_file = stat.S_ISREG(real_st.st_mode)
                size = real_st.st_size
            except OSError:
                is_dir = is_file = False
                size = 0
        else:
            is_dir = stat.S_ISDIR(st.st_mode)
            is_file = stat.S_ISREG(st.st_mode)
            size = st.st_size
        return PathInfo(exists=True, is_dir=is_dir, is_symlink=is_link, is_file=is_file, size=size, link_target=target)

    def read_file(self, path: str) -> bytes:
        try:
            return self._host_path(path).read_bytes()
        except OSError as exc:
            raise CollectionError(f"{self.name}: cannot read {path} ({exc.__class__.__name__})") from exc

    def list_glob(self, pattern: str) -> list[str]:
        if pattern.endswith("/**"):
            base = pattern[:-3] or "/"
            files = walk_files_and_symlinks(self._host_path(base))
            return sorted("/" + f.relative_to(self.root).as_posix() for f in files)
        rel_pattern = pattern.lstrip("/")
        matches = sorted(self.root.glob(rel_pattern))
        out = []
        for m in matches:
            rel = m.relative_to(self.root).as_posix()
            out.append("/" + rel)
        return out

    def realpath(self, path: str) -> str:
        hp = self._host_path(path)
        resolved = Path(os.path.realpath(hp))
        try:
            rel = resolved.relative_to(self.root)
        except ValueError:
            raise CollectionError(f"{path}: symlink escapes the fixture root")
        relp = rel.as_posix()
        return "/" + relp if relp != "." else "/"

    def run(self, cmd: Sequence[str]) -> subprocess.CompletedProcess:
        key = tuple(cmd)
        if self.run_handler is not None:
            res = self.run_handler(cmd)
            if res is not None:
                return res
        if key in self.commands:
            value = self.commands[key]
            if isinstance(value, subprocess.CompletedProcess):
                return value
            if isinstance(value, tuple):
                # (returncode, stdout) — lets tests simulate a failing listing command.
                returncode, out = value
                return subprocess.CompletedProcess(list(cmd), returncode, out, b"")
            return subprocess.CompletedProcess(list(cmd), 0, value, b"")
        raise CollectionError(f"{self.name}: no fixture registered for command {cmd[0] if cmd else ''}")

    def status(self) -> str:
        return self._status


# --------------------------------------------------------------------------------------
# Collection items + per-machine collection
# --------------------------------------------------------------------------------------

PVE_ALLOWLIST_FILES = (
    "storage.cfg",
    "datacenter.cfg",
    "user.cfg",
    "jobs.cfg",
    "vzdump.cron",
    "notifications.cfg",
    "replication.cfg",
)
PVE_OPTIONAL_DIRS = ("firewall", "ha", "sdn", "mapping")

PACKAGES_CMD = ["dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Architecture}\t${Status}\n"]
UNIT_FILES_CMD = ["systemctl", "list-unit-files", "--no-legend", "--no-pager"]
COMPOSE_LS_CMD = ["docker", "compose", "ls", "-a", "--format", "json"]
PS_AQ_CMD = ["docker", "ps", "-aq"]


def inspect_cmd(ids: Sequence[str]) -> list[str]:
    return ["docker", "inspect", "--format", "{{.Name}}\t{{.Config.Image}}\t{{.Image}}", *ids]


@dataclass
class CollectItem:
    kind: str  # "file" | "glob" | "pve_desc_glob"
    path: str = ""
    optional: bool = False


def _common_fixed_items() -> list[CollectItem]:
    return [
        CollectItem("file", "/etc/crontab", optional=True),
        CollectItem("glob", "/etc/cron.d/*"),
        CollectItem("glob", "/var/spool/cron/crontabs/*"),
        CollectItem("glob", "/etc/systemd/system/**"),
    ]


def host_fixed_items(redact_pve_description: bool) -> list[CollectItem]:
    items = [CollectItem("file", f"/etc/pve/{n}", optional=True) for n in PVE_ALLOWLIST_FILES]
    for d in PVE_OPTIONAL_DIRS:
        items.append(CollectItem("glob", f"/etc/pve/{d}/**"))
    items.append(CollectItem("pve_desc_glob" if redact_pve_description else "glob", "/etc/pve/nodes/*/lxc/*.conf"))
    items.append(
        CollectItem("pve_desc_glob" if redact_pve_description else "glob", "/etc/pve/nodes/*/qemu-server/*.conf")
    )
    items.append(CollectItem("glob", "/etc/pve/nodes/*/host.fw"))
    items += [
        CollectItem("glob", "/etc/network/interfaces.d/*"),
        CollectItem("file", "/etc/network/interfaces", optional=True),
        CollectItem("glob", "/etc/systemd/network/*"),
        CollectItem("file", "/etc/hosts"),
        CollectItem("file", "/etc/hostname"),
        CollectItem("file", "/etc/fstab"),
        CollectItem("file", "/etc/crypttab", optional=True),
        CollectItem("file", "/etc/snapraid.conf", optional=True),
        CollectItem("file", "/etc/sanoid/sanoid.conf", optional=True),
    ]
    items += _common_fixed_items()
    return items


def container_fixed_items() -> list[CollectItem]:
    return list(_common_fixed_items())


def resolve_declared_paths(item_paths: list, machine_name: str) -> list[CollectItem]:
    out = []
    for raw in item_paths:
        path = _path_item_path(raw, machine_name)
        out.append(CollectItem("file", path, optional=_path_item_optional(raw)))
    return out


@dataclass
class CollectStats:
    """Per-machine: only things that vary by machine. total_bytes is a per-run budget,
    tracked separately by RunBudget, so one machine's data can't silently starve the limit
    check for the next (see RunBudget below)."""

    missing_optional: list[str] = field(default_factory=list)


class RunBudget:
    """Shared total_bytes accounting across every machine in a single run."""

    def __init__(self, limit: int):
        self.limit = limit
        self.used = 0

    def add(self, nbytes: int) -> None:
        self.used += nbytes
        if self.used > self.limit:
            raise CollectionError("total_bytes limit exceeded")


def _write_sanitized(out_root: Path, rel: str, data: bytes) -> None:
    dest = out_root / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)


def _check_and_sanitize(
    backend: Backend,
    declared_path: str,
    limits: dict,
    budget: RunBudget,
    pve_desc: bool,
    info: PathInfo,
    follow_symlink: bool,
) -> bytes:
    if info.is_symlink and not (follow_symlink and info.is_file):
        # Glob-discovered symlinks (and declared symlinks pointing at a directory, or
        # dangling) are recorded as a link, never dereferenced: only a declared path
        # (snapshot_paths) that resolves to a regular file gets its content collected.
        data = f"-> {info.link_target}\n".encode("utf-8")
    else:
        # Check the cheap stat-reported size before reading, so an oversized file is
        # rejected without ever buffering it; re-check the real byte count afterwards
        # in case the backend's reported size was stale or wrong.
        if info.size > limits["file_bytes"]:
            raise CollectionError(f"{declared_path}: exceeds file_bytes limit")
        raw = backend.read_file(declared_path)
        if len(raw) > limits["file_bytes"]:
            raise CollectionError(f"{declared_path}: exceeds file_bytes limit")
        data = sanitize_text(declared_path, raw)
        if pve_desc:
            data = redact_pve_conf(data.decode("utf-8")).encode("utf-8")
    budget.add(len(data))
    return data


def collect_machine(
    backend: Backend,
    machine_cfg: dict,
    limits: dict,
    redact_pve_description: bool,
    out_root: Path,
    stats: CollectStats,
    budget: RunBudget,
) -> None:
    name = machine_cfg["name"]
    is_host = machine_cfg.get("vmid") is None
    if not is_host:
        st = backend.status()
        if st != "running":
            raise CollectionError(f"{name}: container not running ({st})")

    crypttab_keyfiles: frozenset[str] = frozenset()
    info = backend.info("/etc/crypttab")
    if info.exists and info.is_file:
        try:
            crypttab_keyfiles = parse_crypttab_keyfiles(backend.read_file("/etc/crypttab").decode("utf-8"))
        except UnicodeDecodeError:
            pass

    items = host_fixed_items(redact_pve_description) if is_host else container_fixed_items()
    items += resolve_declared_paths(machine_cfg.get("paths", []), name)

    machine_root = out_root / name
    for item in items:
        if item.kind == "file":
            _collect_declared(backend, item, crypttab_keyfiles, limits, budget, machine_root, pve_desc=False, stats=stats)
        else:
            pve_desc = item.kind == "pve_desc_glob"
            for match in backend.list_glob(item.path):
                _collect_globbed(backend, match, crypttab_keyfiles, limits, budget, machine_root, pve_desc=pve_desc)

    packages_out = _run_checked(backend, PACKAGES_CMD, "dpkg-query").stdout.decode("utf-8", "replace")
    _write_sanitized(machine_root, "packages.txt", format_packages(packages_out).encode())
    units_out = _run_checked(backend, UNIT_FILES_CMD, "systemctl list-unit-files").stdout.decode("utf-8", "replace")
    _write_sanitized(machine_root, "systemd-units.txt", format_systemd_units(units_out).encode())

    if machine_cfg.get("docker"):
        _collect_docker(backend, machine_root, limits, budget)


def _collect_declared(backend, item, crypttab_keyfiles, limits, budget, machine_root, pve_desc, stats) -> None:
    declared = item.path
    resolved = backend.realpath(declared)
    reason = exclusion_reason(resolved, crypttab_keyfiles)
    if reason:
        raise ConfigError(f"{declared}: declared path is excluded ({reason})")
    info = backend.info(declared)
    if not info.exists:
        if item.optional:
            stats.missing_optional.append(declared)
            return
        raise CollectionError(f"{declared}: required path is missing")
    data = _check_and_sanitize(backend, declared, limits, budget, pve_desc, info, follow_symlink=True)
    _write_sanitized(machine_root, "files/" + declared.lstrip("/"), data)


def _collect_globbed(backend, match, crypttab_keyfiles, limits, budget, machine_root, pve_desc) -> None:
    info = backend.info(match)
    if info.is_dir:
        return
    resolved = backend.realpath(match)
    reason = exclusion_reason(resolved, crypttab_keyfiles)
    if reason:
        return  # glob matches are skipped silently when excluded
    data = _check_and_sanitize(backend, match, limits, budget, pve_desc, info, follow_symlink=False)
    _write_sanitized(machine_root, "files/" + match.lstrip("/"), data)


def _collect_docker(backend: Backend, machine_root: Path, limits: dict, budget: RunBudget) -> None:
    compose_json = _run_checked(backend, COMPOSE_LS_CMD, "docker compose ls").stdout.decode("utf-8", "replace")
    _write_sanitized(machine_root, "docker/projects.txt", format_docker_projects(compose_json).encode())

    running = docker_running_projects(compose_json)
    seen_basenames: dict[str, set[str]] = {}
    skipped: list[tuple[str, str, str]] = []
    for project in running:
        pname = project.get("Name", "")
        config_files = project.get("ConfigFiles", "")
        for file_path in [f for f in config_files.split(",") if f]:
            resolved = backend.realpath(file_path)
            reason = exclusion_reason(resolved, frozenset())
            if reason:
                skipped.append((pname, file_path, f"excluded:{reason}"))
                continue
            info = backend.info(file_path)
            if not info.exists:
                skipped.append((pname, file_path, "missing"))
                continue
            data = _check_and_sanitize(backend, file_path, limits, budget, pve_desc=False, info=info, follow_symlink=True)
            out_name = compose_output_name(pname, seen_basenames, file_path)
            _write_sanitized(machine_root, f"docker/compose/{pname}/{out_name}", data)
    if skipped:
        lines = sorted(f"{p}\t{f}\t{r}" for p, f, r in skipped)
        _write_sanitized(machine_root, "_meta/compose-files-skipped.txt", ("\n".join(lines) + "\n").encode())

    ids_out = _run_checked(backend, PS_AQ_CMD, "docker ps").stdout.decode("utf-8", "replace")
    ids = [i for i in ids_out.split("\n") if i.strip()]
    images_text = ""
    if ids:
        images_text = _run_checked(backend, inspect_cmd(ids), "docker inspect").stdout.decode("utf-8", "replace")
    _write_sanitized(machine_root, "docker/images.txt", format_docker_images(images_text).encode())


def collect_all(
    config: dict,
    backends: dict[str, Backend],
    out_dir: Path,
) -> None:
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    limits = config["limits"]
    redact_pve_description = bool(config.get("redact_pve_description", True))
    budget = RunBudget(limits["total_bytes"])  # shared across every machine in this run
    for machine_cfg in config["machines"]:
        name = machine_cfg["name"]
        backend = backends[name]
        stats = CollectStats()
        collect_machine(backend, machine_cfg, limits, redact_pve_description, out_dir, stats, budget)
        missing_text = format_missing_optional(stats.missing_optional)
        if missing_text:
            _write_sanitized(out_dir / name, "_meta/missing-optional.txt", missing_text.encode())
    (out_dir / "README.md").write_text(README_CONTENT, encoding="utf-8")


# --------------------------------------------------------------------------------------
# gitleaks gate
# --------------------------------------------------------------------------------------


def run_gitleaks(gitleaks_bin: str, stage_dir: Path, run_dir: Path) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    report_path = run_dir / "gitleaks-report.json"
    report_path.unlink(missing_ok=True)  # never trust a leftover report from a previous run
    cmd = [
        gitleaks_bin,
        "dir",
        str(stage_dir),
        "--redact",
        "--no-banner",
        "--exit-code",
        "1",
        "--report-format",
        "json",
        "--report-path",
        str(report_path),
    ]
    try:
        try:
            res = subprocess.run(cmd, capture_output=True)
        except OSError as exc:
            raise GitleaksFinding([("", f"scanner-error:{exc.__class__.__name__}")]) from exc
        if res.returncode == 0:
            return
        if res.returncode != 1:
            # Anything other than the documented 0 (clean)/1 (findings) is a scanner
            # failure: don't trust whatever (possibly partial) report file might exist.
            raise GitleaksFinding([("", f"scanner-error:exit-{res.returncode}")])
        findings = []
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            report = []
        for f in report:
            file_path = f.get("File", "")
            try:
                rel = str(Path(file_path).resolve().relative_to(stage_dir.resolve()))
            except ValueError:
                rel = os.path.basename(file_path)
            findings.append((rel, f.get("RuleID", "unknown-rule")))
        if not findings:
            findings.append(("", "scanner-error"))
        raise GitleaksFinding(findings)
    finally:
        report_path.unlink(missing_ok=True)


# --------------------------------------------------------------------------------------
# Tree diff / replace (pure-ish: hashing is I/O-light but no git)
# --------------------------------------------------------------------------------------


def hash_tree(root: Path) -> dict[str, str]:
    out = {}
    if not root.exists():
        return out
    for p in sorted(root.rglob("*")):
        if p.is_file():
            rel = p.relative_to(root).as_posix()
            out[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def diff_trees(old: dict[str, str], new: dict[str, str]) -> list[tuple[str, str]]:
    changes = []
    for path in sorted(set(old) | set(new)):
        if path not in old:
            changes.append(("A", path))
        elif path not in new:
            changes.append(("D", path))
        elif old[path] != new[path]:
            changes.append(("M", path))
    return changes


def replace_tree(repo_dir: Path, stage_dir: Path) -> None:
    repo_dir.mkdir(parents=True, exist_ok=True)
    for entry in repo_dir.iterdir():
        if entry.name == ".git":
            continue
        if entry.is_dir():
            shutil.rmtree(entry)
        else:
            entry.unlink()
    for entry in stage_dir.iterdir():
        dest = repo_dir / entry.name
        if entry.is_dir():
            shutil.copytree(entry, dest)
        else:
            shutil.copy2(entry, dest)


# --------------------------------------------------------------------------------------
# Git layer
# --------------------------------------------------------------------------------------


def _git_env(deploy_key: Optional[str], known_hosts: Optional[str]) -> dict:
    env = dict(os.environ)
    if deploy_key and known_hosts:
        env["GIT_SSH_COMMAND"] = (
            f"ssh -i {deploy_key} -o IdentitiesOnly=yes -o UserKnownHostsFile={known_hosts} "
            "-o StrictHostKeyChecking=yes"
        )
    return env


def _git(repo_dir: Path, args: list[str], env: dict, check: bool = True) -> subprocess.CompletedProcess:
    res = subprocess.run(["git", "-C", str(repo_dir)] + args, capture_output=True, env=env)
    if check and res.returncode != 0:
        raise GitError(f"git {' '.join(args[:2])} failed (exit {res.returncode})")
    return res


def ensure_repo(repo_dir: Path, repo_url: str, branch: str, deploy_key: Optional[str], known_hosts: Optional[str]) -> None:
    env = _git_env(deploy_key, known_hosts)
    if not (repo_dir / ".git").exists():
        repo_dir.mkdir(parents=True, exist_ok=True)
        res = subprocess.run(["git", "clone", repo_url, str(repo_dir)], capture_output=True, env=env)
        if res.returncode != 0:
            raise GitError("git clone failed")
        if _git(repo_dir, ["rev-parse", "--verify", branch], env, check=False).returncode != 0:
            if _git(repo_dir, ["rev-parse", "--verify", f"origin/{branch}"], env, check=False).returncode == 0:
                _git(repo_dir, ["checkout", "-b", branch, f"origin/{branch}"], env)
            else:
                _git(repo_dir, ["checkout", "-b", branch], env)
        else:
            _git(repo_dir, ["checkout", branch], env)
    else:
        _git(repo_dir, ["fetch", "origin"], env)
        has_head = _git(repo_dir, ["rev-parse", "--verify", "HEAD"], env, check=False).returncode == 0
        if has_head:
            _git(repo_dir, ["reset", "--hard", "HEAD"], env)
        _git(repo_dir, ["clean", "-fdx"], env)


def commit_if_changed(repo_dir: Path, changes: list[tuple[str, str]], author: str, env: dict) -> Optional[str]:
    if not changes:
        return None
    _git(repo_dir, ["add", "-A"], env)
    diff = _git(repo_dir, ["diff", "--cached", "--quiet"], env, check=False)
    if diff.returncode == 0:
        return None
    name, _, email = author.rpartition(" <")
    email = email.rstrip(">")
    date = time.strftime("%Y-%m-%d", time.gmtime())
    body = "\n".join(f"{status} {path}" for status, path in changes)
    message = f"Snapshot {date}\n\n{body}\n"
    res = subprocess.run(
        ["git", "-C", str(repo_dir), "commit", "-q", "-m", message, f"--author={author}"],
        capture_output=True,
        env={**env, "GIT_AUTHOR_NAME": name or author, "GIT_AUTHOR_EMAIL": email or "config-snapshot@proxmox.invalid",
             "GIT_COMMITTER_NAME": name or author, "GIT_COMMITTER_EMAIL": email or "config-snapshot@proxmox.invalid"},
    )
    if res.returncode != 0:
        raise GitError("git commit failed")
    return _git(repo_dir, ["rev-parse", "HEAD"], env).stdout.decode().strip()


def push(repo_dir: Path, branch: str, env: dict) -> None:
    _git(repo_dir, ["fetch", "origin"], env)
    remote_ref = f"origin/{branch}"
    remote_exists = _git(repo_dir, ["rev-parse", "--verify", remote_ref], env, check=False).returncode == 0
    if remote_exists:
        ancestor = _git(repo_dir, ["merge-base", "--is-ancestor", remote_ref, "HEAD"], env, check=False)
        if ancestor.returncode != 0:
            raise DivergedError("remote has diverged; refusing to force-push")
        remote_sha = _git(repo_dir, ["rev-parse", remote_ref], env).stdout.decode().strip()
        head_sha = _git(repo_dir, ["rev-parse", "HEAD"], env).stdout.decode().strip()
        if remote_sha == head_sha:
            return
    res = subprocess.run(
        ["git", "-C", str(repo_dir), "push", "origin", f"HEAD:{branch}"], capture_output=True, env=env
    )
    if res.returncode != 0:
        raise GitError("git push failed")


def is_ancestor(repo_dir: Path, sha: str, ref: str, env: dict) -> bool:
    return _git(repo_dir, ["merge-base", "--is-ancestor", sha, ref], env, check=False).returncode == 0


# --------------------------------------------------------------------------------------
# Notification queue (pure parts: schema + message text; I/O: enqueue/dequeue/send)
# --------------------------------------------------------------------------------------


def build_pending_record(sha: str, changes: list[tuple[str, str]], commit_url_base: str, commit_time: str) -> dict:
    files = [f"{status} {path}" for status, path in changes]
    return {"sha": sha, "files": sorted(files), "url": commit_url_base.rstrip("/") + "/" + sha, "commit_time": commit_time}


def enqueue_pending(pending_dir: Path, record: dict) -> Path:
    pending_dir.mkdir(parents=True, exist_ok=True)
    dest = pending_dir / f"{record['sha']}.json"
    dest.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return dest


def list_pending(pending_dir: Path) -> list[tuple[Path, dict]]:
    if not pending_dir.exists():
        return []
    items = []
    for p in sorted(pending_dir.glob("*.json")):
        try:
            items.append((p, json.loads(p.read_text(encoding="utf-8"))))
        except (OSError, json.JSONDecodeError):
            continue
    items.sort(key=lambda t: t[1].get("commit_time", ""))
    return items


def build_notification_message(record: dict) -> tuple[str, str]:
    files = record["files"]
    shown = files[:50]
    more = len(files) - len(shown)
    body_lines = list(shown)
    if more > 0:
        body_lines.append(f"\u2026 and {more} more")
    body_lines.append("")
    body_lines.append(record["url"])
    title = f"Config drift: {len(files)} files"
    return title, "\n".join(body_lines)


class GotifySender:
    def __init__(self, gotify_url: str, token: str, timeout: float = 10.0):
        self.gotify_url = gotify_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def __call__(self, title: str, message: str, priority: int = 5) -> None:
        data = urllib.parse.urlencode({"title": title, "message": message, "priority": str(priority)}).encode("utf-8")
        req = urllib.request.Request(
            self.gotify_url + "/message", data=data, method="POST", headers={"X-Gotify-Key": self.token}
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status >= 300:
                    raise NotifyError(f"gotify responded with status {resp.status}")
        except urllib.error.URLError as exc:
            raise NotifyError(f"gotify request failed: {exc.__class__.__name__}") from exc


def load_gotify_token(token_file: str) -> str:
    return Path(token_file).read_text(encoding="utf-8").strip()


# --------------------------------------------------------------------------------------
# Lock
# --------------------------------------------------------------------------------------


class FileLock:
    def __init__(self, path: Path, timeout: float = DEFAULT_LOCK_TIMEOUT, poll_interval: float = 0.05):
        self.path = path
        self.timeout = timeout
        self.poll_interval = poll_interval
        self._fh = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "a+")
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError:
                if time.monotonic() >= deadline:
                    self._fh.close()
                    raise LockBusyError("another config-snapshot run holds the lock")
                time.sleep(self.poll_interval)

    def __exit__(self, exc_type, exc, tb):
        if self._fh is not None:
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            self._fh.close()


# --------------------------------------------------------------------------------------
# Runner: orchestrates the full run() algorithm
# --------------------------------------------------------------------------------------


@dataclass
class RunPaths:
    repo_dir: Path
    stage_dir: Path
    run_dir: Path
    pending_dir: Path
    lock_file: Path
    lock_timeout: float = DEFAULT_LOCK_TIMEOUT


class Runner:
    def __init__(
        self,
        config: dict,
        backends: dict[str, Backend],
        paths: RunPaths,
        notify_fn: Optional[Callable[[str, str], None]] = None,
        gitleaks_bin: Optional[str] = None,
    ):
        self.config = config
        self.backends = backends
        self.paths = paths
        self._notify_fn = notify_fn
        self.gitleaks_bin = gitleaks_bin or config.get("gitleaks", "gitleaks")

    def _notifier(self) -> Callable[[str, str], None]:
        if self._notify_fn is not None:
            return self._notify_fn
        try:
            token = load_gotify_token(self.config["gotify_token_file"])
        except OSError as exc:
            raise NotifyError(f"cannot read gotify token file: {exc.__class__.__name__}") from exc
        return GotifySender(self.config["gotify_url"], token)

    def check_config(self) -> None:
        validate_config(self.config)

    def collect(self, out_dir: Path) -> None:
        collect_all(self.config, self.backends, out_dir)
        run_gitleaks(self.gitleaks_bin, out_dir, self.paths.run_dir)

    def run(self) -> int:
        try:
            validate_config(self.config)
        except ConfigError as exc:
            print(f"config error: {exc}", file=sys.stderr)
            return 2
        try:
            with FileLock(self.paths.lock_file, timeout=self.paths.lock_timeout):
                return self._run_locked()
        except LockBusyError as exc:
            print(f"busy: {exc}", file=sys.stderr)
            return 75

    def _run_locked(self) -> int:
        cfg = self.config
        env = _git_env(cfg.get("deploy_key"), cfg.get("known_hosts"))
        try:
            ensure_repo(self.paths.repo_dir, cfg["repo_url"], cfg["branch"], cfg.get("deploy_key"), cfg.get("known_hosts"))
        except GitError as exc:
            print(f"git error: {exc}", file=sys.stderr)
            return 1

        try:
            collect_all(cfg, self.backends, self.paths.stage_dir)
        except (CollectionError, ConfigError) as exc:
            print(f"collection failed: {exc}", file=sys.stderr)
            shutil.rmtree(self.paths.stage_dir, ignore_errors=True)
            return 1

        try:
            run_gitleaks(self.gitleaks_bin, self.paths.stage_dir, self.paths.run_dir)
        except GitleaksFinding as exc:
            for rel, rule in exc.findings:
                print(f"gitleaks finding: {rel} ({rule})", file=sys.stderr)
            shutil.rmtree(self.paths.stage_dir, ignore_errors=True)
            return 1

        old_hashes = hash_tree_excluding_git(self.paths.repo_dir)
        new_hashes = hash_tree(self.paths.stage_dir)
        changes = diff_trees(old_hashes, new_hashes)

        try:
            replace_tree(self.paths.repo_dir, self.paths.stage_dir)
        except OSError as exc:
            print(f"tree replace failed: {exc.__class__.__name__}", file=sys.stderr)
            return 1
        finally:
            shutil.rmtree(self.paths.stage_dir, ignore_errors=True)

        try:
            sha = commit_if_changed(self.paths.repo_dir, changes, cfg["git_author"], env)
            if sha:
                commit_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                record = build_pending_record(sha, changes, cfg["commit_url_base"], commit_time)
                enqueue_pending(self.paths.pending_dir, record)
        except GitError as exc:
            print(f"commit failed: {exc}", file=sys.stderr)
            return 1

        try:
            push(self.paths.repo_dir, cfg["branch"], env)
        except DivergedError as exc:
            print(f"push blocked: {exc}", file=sys.stderr)
            return 1
        except GitError as exc:
            print(f"push failed: {exc}", file=sys.stderr)
            return 1

        deliverable = [
            (path, record)
            for path, record in list_pending(self.paths.pending_dir)
            if is_ancestor(self.paths.repo_dir, record["sha"], f"origin/{cfg['branch']}", env)
        ]
        if not deliverable:
            return 0

        try:
            notifier = self._notifier()
        except NotifyError as exc:
            # No traceback: a token-file problem must not look like a crash, and the
            # pending records stay queued for the next run to retry.
            print(f"notification skipped: {exc}", file=sys.stderr)
            return 1

        notify_ok = True
        for path, record in deliverable:
            title, message = build_notification_message(record)
            try:
                notifier(title, message, 5)
            except Exception as exc:  # noqa: BLE001 - any notifier failure must not crash the run
                print(f"notification failed for {record['sha'][:12]}: {exc.__class__.__name__}", file=sys.stderr)
                notify_ok = False
                continue
            path.unlink(missing_ok=True)

        return 0 if notify_ok else 1


def hash_tree_excluding_git(root: Path) -> dict[str, str]:
    out = {}
    if not root.exists():
        return out
    for p in sorted(root.rglob("*")):
        if ".git" in p.relative_to(root).parts:
            continue
        if p.is_file():
            rel = p.relative_to(root).as_posix()
            out[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


# --------------------------------------------------------------------------------------
# Backend construction from config + CLI
# --------------------------------------------------------------------------------------


def build_backends(config: dict) -> dict[str, Backend]:
    backends: dict[str, Backend] = {}
    for m in config["machines"]:
        if m.get("vmid") is None:
            backends[m["name"]] = LocalBackend(m["name"])
        else:
            backends[m["name"]] = PctBackend(m["vmid"], m["name"])
    return backends


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="config-snapshot")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--repo-dir", default=DEFAULT_REPO_DIR)
    parser.add_argument("--stage-dir", default=DEFAULT_STAGE_DIR)
    parser.add_argument("--pending-dir", default=DEFAULT_PENDING_DIR)
    parser.add_argument("--run-dir", default=DEFAULT_RUN_DIR)
    parser.add_argument("--lock-file", default=DEFAULT_LOCK_FILE)
    parser.add_argument("--lock-timeout", type=float, default=DEFAULT_LOCK_TIMEOUT)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run")
    sub.add_parser("check-config")
    collect_parser = sub.add_parser("collect")
    collect_parser.add_argument("--out", required=True)

    # argparse itself calls sys.exit on bad args: let that SystemExit propagate normally,
    # only guard the command logic below.
    args = parser.parse_args(argv)

    debug = os.environ.get("CONFIG_SNAPSHOT_DEBUG") == "1"
    try:
        return _main_dispatch(args)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - last-resort guard: never leak a traceback
        if debug:
            raise
        print(f"internal error: {exc.__class__.__name__}", file=sys.stderr)
        return 1


def _main_dispatch(args: argparse.Namespace) -> int:
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    if args.command == "check-config":
        print("config ok")
        return 0

    backends = build_backends(config)
    paths = RunPaths(
        repo_dir=Path(args.repo_dir),
        stage_dir=Path(args.stage_dir),
        run_dir=Path(args.run_dir),
        pending_dir=Path(args.pending_dir),
        lock_file=Path(args.lock_file),
        lock_timeout=args.lock_timeout,
    )
    runner = Runner(config, backends, paths)

    if args.command == "collect":
        try:
            runner.collect(Path(args.out))
        except (CollectionError, ConfigError) as exc:
            print(f"collection failed: {exc}", file=sys.stderr)
            return 1
        except GitleaksFinding as exc:
            for rel, rule in exc.findings:
                print(f"gitleaks finding: {rel} ({rule})", file=sys.stderr)
            return 1
        print("collection ok")
        return 0

    return runner.run()


if __name__ == "__main__":
    sys.exit(main())
