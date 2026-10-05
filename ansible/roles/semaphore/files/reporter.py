#!/usr/bin/env python3
"""The deploy reporter (deploy-from-anywhere plan 3), on control, every minute (reporter.timer).

Reads main's recent commits and the deploy/* statuses on them, Semaphore's `apply` tasks and
Komodo's stacks, and posts deploy/ansible and deploy/stacks on each commit. On failure or error
it also pushes to Gotify. GitHub's statuses are its only memory: a restart or a missed minute
just catches up.

Nothing from a log or an error message leaves the lab. A description is one of PHRASES, or a
stack name and what went wrong; a link points at Semaphore or Komodo on the LAN, or is dropped.

Installed by ansible/roles/semaphore (laptop only): a merge never changes it.
  reporter            post and push
  reporter --dry-run  print what it would post and push; send nothing
"""
import json
import re
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path

CONFIG = Path("/etc/reporter.json")
HOME = Path("/home/reporter")
CONTEXTS = ("deploy/ansible", "deploy/stacks")
WAIT = 15 * 60  # pending this long with nothing run: error
GRACE = 5 * 60  # a deployed stack's time to turn healthy
SKEW = 120  # Komodo's clock against GitHub's: deploys this much before a merge still count
MAX_AGE = 24 * 3600  # older commits are left alone
FINAL = {"success", "failure"}  # error isn't: the next run covers the commit
RUNNING = {"waiting", "starting", "running", "stopping", "waiting_confirmation", "confirmed"}

STACK = r"[a-z0-9][a-z0-9-]{0,39}"
PHRASES = (
    "waiting for Semaphore", "ansible running", "ansible run succeeded", "ansible run failed",
    "ansible run stopped", "nothing ran: no checkout", "nothing ran in 15 min",
    "waiting for Komodo", "stacks starting", "stacks deployed", "no stacks changed", "reconcile failed",
)
ALLOWED = re.compile(r"(in [0-9a-f]{7}'s run: )?(%s|%s: (deploy failed|unhealthy|not running)( \+\d+ more)?)"
                     % ("|".join(map(re.escape, PHRASES)), STACK))


def decide(facts, cfg):
    """What to post. facts (gather() reads them):
      now       epoch seconds
      commits   [{sha, time}], main's newest first, none older than MAX_AGE
      statuses  {sha: {context: {state, description, url, created}}}, the newest of each context
      tasks     [{id, status, commit, created}] of the apply template, or None (Semaphore unreadable)
      komodo    {procedure, runs: [{id, start, done, success}], stacks: [{id, name, latest, deployed,
                pending, deploys: [{id, start, end, success}], services: [{state, status}] or None}]},
                or None (Komodo unreadable). latest and deployed are Komodo's short hashes.
    Returns [{sha, context, state, description, url, push}] for the statuses that change; push is
    True when one turns failure or error."""
    out = []
    for c in facts["commits"]:
        have = facts["statuses"].get(c["sha"], {})
        for context, source, judge in (("deploy/ansible", "tasks", _ansible),):
            cur = have.get(context)
            if facts[source] is None or (cur and cur["state"] in FINAL):
                continue  # never decide from missing data; a result stays
            new = judge(c, cur, facts, cfg)
            if new is None:
                continue
            state, description, url = new
            description, url = clean(description, url, cfg)
            if description is None or (cur and (cur["state"], cur["description"], cur["url"]) == (state, description, url)):
                continue
            out.append({"sha": c["sha"], "context": context, "state": state, "description": description, "url": url,
                        "push": state in ("failure", "error") and (cur is None or cur["state"] != state)})
    return out


def _ansible(c, cur, facts, cfg):
    """deploy/ansible: the first apply task whose checkout includes c and that finished decides it;
    a stopped one doesn't, so a later run can still cover c."""
    sem, project = cfg["semaphore"], cfg["project"]
    order = {x["sha"]: i for i, x in enumerate(facts["commits"])}  # 0 is the newest
    covering = sorted((t for t in facts["tasks"] if t["commit"] in order and order[t["commit"]] <= order[c["sha"]]),
                      key=lambda t: t["id"])
    stopped = None
    for t in covering:
        link = f"{sem}/project/{project}/history?t={t['id']}"
        if t["status"] in RUNNING:
            return "pending", "ansible running", link
        if t["status"] == "success":
            return "success", _in_run(c, t["commit"]) + "ansible run succeeded", link
        if t["status"] == "error":
            return "failure", _in_run(c, t["commit"]) + "ansible run failed", link
        stopped = stopped or (t, link)  # stopped or rejected: it may have applied part of c
    if stopped:
        t, link = stopped
        return "error", _in_run(c, t["commit"]) + "ansible run stopped", link
    # No checkout yet: a task still starting, or one that failed before it (no runner, a clone error).
    unchecked = sorted((t for t in facts["tasks"] if not t["commit"] and t["created"] >= c["time"]), key=lambda t: t["id"])
    if unchecked:
        t = unchecked[-1]
        link = f"{sem}/project/{project}/history?t={t['id']}"
        return ("pending", "ansible running", link) if t["status"] in RUNNING else ("error", "nothing ran: no checkout", link)
    return _waiting(c, cur, facts["now"], "waiting for Semaphore", f"{sem}/project/{project}/templates/{cfg['template']}")


def _waiting(c, cur, now, phrase, url):
    """Nothing has run on c yet: pending, then error once it has waited WAIT."""
    if cur is None:
        return "pending", phrase, url
    if cur["state"] == "pending" and now - cur["created"] >= WAIT:
        return "error", "nothing ran in 15 min", url
    return None


def _in_run(c, sha):
    """Runs coalesce: an earlier commit names the run that covered it."""
    return "" if sha == c["sha"] else f"in {sha[:7]}'s run: "


def clean(description, url, cfg):
    """The only text and links that may leave the lab: (None, None) drops the status."""
    if len(description) > 140 or not ALLOWED.fullmatch(description):
        return None, None
    if url and not url.startswith((cfg["semaphore"] + "/", cfg["komodo"] + "/")):
        url = None
    return description, url


def safe(name):
    """A stack name as it may appear in a description (only there: stacks are matched by id)."""
    return name if re.fullmatch(STACK, name) else "stack"


def ts(text):
    """Epoch seconds from an RFC 3339 time (Semaphore's has nanoseconds; Python reads 6 digits)."""
    return datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", text.replace("Z", "+00:00"))).timestamp()
