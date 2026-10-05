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
HOLD = 20 * 60  # a failing push holds its status back at most this long after the status it replaces
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
    Returns [{sha, context, state, description, url, push, since}] for the statuses that change; push
    is True when one turns failure or error; since is when the status it replaces was posted (or the
    commit's time)."""
    out = []
    for c in facts["commits"]:
        have = facts["statuses"].get(c["sha"], {})
        for context, source, judge in (("deploy/ansible", "tasks", _ansible), ("deploy/stacks", "komodo", _stacks)):
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
                        "push": state in ("failure", "error") and (cur is None or cur["state"] != state),
                        "since": cur["created"] if cur else c["time"]})
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


def _stacks(c, cur, facts, cfg):
    """deploy/stacks: once Komodo has pulled c for every stack, no stack may still wait for a deploy,
    and every stack deployed at c or later must be up and healthy. Commits are matched by Komodo's
    own hashes, never by time."""
    k, base, now, commits = facts["komodo"], cfg["komodo"], facts["now"], facts["commits"]
    proc = f"{base}/procedures/{k['procedure']}" if k["procedure"] else None
    stacks = [s for s in k["stacks"] if s["latest"]]  # Komodo couldn't read the others' files at all
    if not stacks or not all(_at_or_after(s["latest"], c, commits) for s in stacks):
        return _waiting(c, cur, now, "waiting for Komodo", proc)
    pulled = min((_resolve(s["latest"], commits) for s in stacks), key=[x["sha"] for x in commits].index)
    prefix = _in_run(c, pulled)
    bad, undeployed, starting, deployed = [], False, False, False
    for s in stacks:
        failed = [d for d in s["deploys"] if not d["success"] and d["start"] >= c["time"] - SKEW]
        if s["pending"]:
            if failed:
                bad.append((safe(s["name"]), "deploy failed", f"{base}/updates/{max(failed, key=lambda d: d['start'])['id']}"))
            else:
                undeployed = True
            continue
        since = [d for d in s["deploys"] if d["success"] and d["start"] >= c["time"] - SKEW]
        if not (_at_or_after(s["deployed"], c, commits) or since):
            continue  # last deployed or restarted before c: not this merge's (a restart keeps deployed_hash)
        deployed = True
        state = health(s["services"])
        if state == "ok":
            continue
        ends = [d["end"] for d in s["deploys"] if d["success"] and d["end"]]
        if ends and now < max(ends) + GRACE:
            starting = True
        else:
            bad.append((safe(s["name"]), "not running" if state == "down" else "unhealthy", f"{base}/stacks/{s['id']}"))
    if bad:
        name, what, url = bad[0]
        more = f" +{len(bad) - 1} more" if len(bad) > 1 else ""
        return "failure", f"{prefix}{name}: {what}{more}", url
    runs = sorted((r for r in k["runs"] if r["done"] and r["start"] >= c["time"] - SKEW), key=lambda r: r["start"])
    if undeployed:
        if runs and not runs[-1]["success"]:  # not the change's fault for sure: error, not failure
            return "error", "reconcile failed", f"{base}/updates/{runs[-1]['id']}"
        return _waiting(c, cur, now, "waiting for Komodo", proc)
    if starting:
        return "pending", "stacks starting", proc
    return "success", prefix + ("stacks deployed" if deployed else "no stacks changed"), \
        f"{base}/updates/{runs[-1]['id']}" if runs else proc


def health(services):
    """A deployed stack's containers: down (none, or one not running), unhealthy, starting or ok.
    Docker's status text carries a health check's result: 'Up 3 minutes (healthy)',
    'Up 9 seconds (health: starting)', 'Up 2 minutes (unhealthy)'; no check, no suffix."""
    if not services:
        return "down"
    worst = "ok"
    for s in services:
        if s["state"] != "running":
            return "down"
        text = s["status"] or ""
        if "(unhealthy)" in text:
            worst = "unhealthy"
        elif "(health: starting)" in text and worst == "ok":
            worst = "starting"
    return worst


def pending(info):
    """Komodo still has a change to deploy or restart for a stack, by DeployStackIfChanged's own test
    (resolve_deploy_if_changed_action): never deployed, a new file, or a changed one whose requires
    isn't None. A changed file with requires None, or one only in what was deployed, never deploys."""
    deployed, remote = info.get("deployed_contents"), info.get("remote_contents")
    if deployed is None:
        return True
    was = {f["path"]: f["contents"] for f in deployed}
    return any(f["path"] not in was or (f["contents"] != was[f["path"]] and f.get("requires", "None") != "None")
               for f in remote or [])


def _resolve(short, commits):
    """The full SHA on main for one of Komodo's short hashes, or None: older than the list, or
    ambiguous."""
    found = [x["sha"] for x in commits if short and x["sha"].startswith(short)]
    return found[0] if len(found) == 1 else None


def _at_or_after(short, c, commits):
    """Komodo's short hash names c or a later commit."""
    order = [x["sha"] for x in commits]  # newest first
    sha = _resolve(short, commits)
    return sha is not None and order.index(sha) <= order.index(c["sha"])


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


# Everything below talks to the APIs. Each source is read inside its own boundary in gather():
# whatever goes wrong there (unreachable, or an answer of the wrong shape) skips that source's
# context for this minute and is logged to the journal on control.
UNREADABLE = (OSError, ValueError, KeyError, TypeError, AttributeError)


def gather(cfg, now):
    """The facts decide() needs (see there). Semaphore and Komodo are read only while a commit
    still waits for a result."""
    repo = cfg["repo"]
    commits = [{"sha": x["sha"], "time": ts(x["commit"]["committer"]["date"])}
               for x in github(f"/repos/{repo}/commits?sha={cfg['branch']}&per_page=20")]
    commits = [c for c in commits if now - c["time"] < MAX_AGE]
    statuses = {c["sha"]: newest(github(f"/repos/{repo}/commits/{c['sha']}/statuses?per_page=100")) for c in commits}
    times = [c["time"] for c in commits
             if any(statuses[c["sha"]].get(k, {}).get("state") not in FINAL for k in CONTEXTS)]
    facts = {"now": now, "commits": commits, "statuses": statuses, "tasks": None, "komodo": None}
    if not times:
        return facts  # every commit has its results
    for name, read in (("tasks", lambda: semaphore_tasks(cfg)), ("komodo", lambda: komodo_state(cfg, min(times)))):
        try:
            facts[name] = read()
        except UNREADABLE as e:
            print(f"{name}: skipped this minute: {e!r}", file=sys.stderr)
    return facts


def newest(rows):
    """Our two contexts' newest statuses on a commit (GitHub lists the newest first)."""
    mine = {}
    for s in rows:
        if s["context"] in CONTEXTS and s["context"] not in mine:
            mine[s["context"]] = {"state": s["state"], "description": s["description"] or "",
                                  "url": s["target_url"] or None, "created": ts(s["created_at"])}
    return mine


def semaphore_tasks(cfg):
    """The apply template's last 100 tasks. commit_hash is set at the checkout, so a task without
    one never got that far."""
    token = (HOME / "semaphore-token").read_text().strip()
    rows = call(f"{cfg['semaphore']}/api/project/{cfg['project']}/tasks?count=100", None,
                {"Authorization": f"Bearer {token}"})
    return [{"id": int(t["id"]), "status": str(t["status"]), "commit": t.get("commit_hash") or None,
             "created": ts(t["created"])}
            for t in rows if int(t["template_id"]) == int(cfg["template"])]


def komodo_state(cfg, since):
    """Every stack (its hashes, whether a change waits, its deploys since the oldest commit still
    waiting, and its containers if it deployed), and the reconcile runs since then."""
    key = json.loads((HOME / "komodo-key.json").read_text())
    auth = {"x-api-key": key["key"], "x-api-secret": key["secret"]}

    def read(request, body=None):
        return call(f"{cfg['komodo']}/read/{request}", body or {}, auth)

    def end(u):  # ListUpdates leaves end_ts out
        e = read("GetUpdate", {"id": u["id"]})["end_ts"]
        return e / 1000 if e else None

    procedure = next((p["id"] for p in read("ListProcedures") if p["name"] == cfg["procedure"]), None)
    query = {"start_ts": {"$gte": int((since - SKEW) * 1000)},
             "operation": {"$in": ["RunProcedure", "DeployStack", "RestartStack"]}}
    updates, page = [], 0
    while page is not None:
        answer = read("ListUpdates", {"query": query, "page": page})
        updates += answer["updates"]
        page = answer.get("next_page")
    deploys = {}  # a restart (for a requires = "Restart" file) counts as a deploy
    for u in updates:
        if u["operation"] in ("DeployStack", "RestartStack") and u["target"]["type"] == "Stack":
            done = u["status"] == "Complete"
            deploys.setdefault(u["target"]["id"], []).append(
                {"id": u["id"], "start": u["start_ts"] / 1000, "end": end(u) if done and u["success"] else None,
                 "success": bool(u["success"]) if done else True})  # one still running hasn't failed
    stacks = []
    for s in read("ListFullStacks"):
        sid = s["_id"]["$oid"] if isinstance(s["_id"], dict) else s["_id"]  # a whole Stack: Mongo's id
        mine = deploys.get(sid, [])
        services = None
        if any(d["success"] for d in mine):
            services = [{"state": (x.get("container") or {}).get("state"), "status": (x.get("container") or {}).get("status")}
                        for x in read("ListStackServices", {"stack": sid})]
        stacks.append({"id": sid, "name": s["name"], "latest": s["info"].get("latest_hash"),
                       "deployed": s["info"].get("deployed_hash"), "pending": pending(s["info"]),
                       "deploys": mine, "services": services})
    runs = [{"id": u["id"], "start": u["start_ts"] / 1000, "done": u["status"] == "Complete", "success": bool(u["success"])}
            for u in updates if u["operation"] == "RunProcedure" and u["target"] == {"type": "Procedure", "id": procedure}]
    return {"procedure": procedure, "runs": runs, "stacks": stacks}


def call(url, body=None, headers=None):
    """One JSON request: GET, or POST when there is a body."""
    request = urllib.request.Request(
        url, data=None if body is None else json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "homelab-deploy-reporter", **(headers or {})})
    with urllib.request.urlopen(request, timeout=15) as answer:
        raw = answer.read()
    return json.loads(raw) if raw else None


def github(path, body=None):
    token = (HOME / "github-token").read_text().strip()
    return call("https://api.github.com" + path, body, {
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"})


def push(cfg, s):
    """A Gotify push with the status's description and link: tapping it opens the log."""
    token = (HOME / "gotify-token").read_text().strip()
    extras = {"client::display": {"contentType": "text/markdown"}}
    message = s["description"]
    if s["url"]:
        extras["client::notification"] = {"click": {"url": s["url"]}}
        message += f"\n\n[Open the log]({s['url']})"
    call(f"{cfg['gotify']}/message", {"title": f"{s['context']} {s['state']} · {s['sha'][:7]}",
                                      "message": message, "priority": 8, "extras": extras},
         {"X-Gotify-Key": token})


def main(argv):
    """Post each change. Delivery is at least once: a push goes before its status, so a failed push
    holds that status back to try both again next minute; a GitHub failure right after a push
    means that push comes twice. One status's failure never holds back another's. Gotify runs in
    aio, so a push still failing HOLD after the status it replaces lets the status through alone:
    a merge that breaks aio must still show on GitHub."""
    dry = "--dry-run" in argv
    cfg = json.loads(CONFIG.read_text())
    now = time.time()
    for s in decide(gather(cfg, now), cfg):
        print(f"{'would post' if dry else 'post'} {s['sha'][:7]} {s['context']} {s['state']}: "
              f"{s['description']} {s['url'] or ''}{' (push)' if s['push'] else ''}")
        if dry:
            continue
        body = {"state": s["state"], "description": s["description"], "context": s["context"]}
        if s["url"]:
            body["target_url"] = s["url"]
        try:
            if s["push"]:
                try:
                    push(cfg, s)
                except (OSError, ValueError) as e:
                    if now - s["since"] < HOLD:
                        raise
                    print(f"{s['sha'][:7]} {s['context']}: push failed for too long, posting without it: {e!r}",
                          file=sys.stderr)
            github(f"/repos/{cfg['repo']}/statuses/{s['sha']}", body)
        except (OSError, ValueError) as e:
            print(f"{s['sha'][:7]} {s['context']}: not sent, next minute again: {e!r}", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1:])
