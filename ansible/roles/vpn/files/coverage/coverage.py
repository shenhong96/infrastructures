#!/usr/bin/env python3
"""Episode coverage: which Prowlarr site has which episodes of watched shows.

Runs on the vpn host. Talks to prowlarr/sonarr/qbittorrent via `docker exec <ctr> curl`
on localhost; API keys are read from each app's config at run time and never stored.
`query` / `seeding` never touch a site; only `refresh` searches, slowly.
"""
import argparse, fcntl, hashlib, json, random, re, secrets, sqlite3, subprocess, sys, time, unicodedata, urllib.parse, urllib.request
from collections import defaultdict
from contextlib import closing
from datetime import datetime, timezone
from itertools import groupby
from pathlib import Path

DB = Path(__file__).with_name("coverage.db")
MIN_AGE = 12 * 3600          # a (show, site) pair is searched at most every 12 h
ENDED_AGE = 7 * 86400        # ended + backfilled shows: weekly
GAP = (10, 15)               # seconds between requests (one at a time, never parallel)
PAGE = 100                   # Prowlarr page size
BACKFILL_PAGES = 5           # per (show, site, term) per run
RUN_CAP = 60                 # total search requests per run
BACKOFF0, BACKOFF_MAX = 86400, 7 * 86400
CONFIG = "/root/coverage/config.json"   # private: default sites, API bind/port/allow (Ansible writes it)

def config():
    try:
        with open(CONFIG) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

# ---------- app access ----------
_keys = {}
def _key(ctr):
    if ctr not in _keys:
        _keys[ctr] = subprocess.check_output(
            ["docker", "exec", ctr, "sh", "-c",
             "grep -o '<ApiKey>[^<]*' /config/config.xml | cut -d'>' -f2"], text=True).strip()
    return _keys[ctr]

def api(ctr, port, path, auth=True, timeout=150):
    """GET localhost:<port><path> inside <ctr>. Returns parsed JSON; raises on HTTP >= 400."""
    cmd = ["docker", "exec", ctr, "curl", "-s", "-m", str(timeout), "-w", "\n%{http_code}"]
    if auth:
        cmd += ["-H", "X-Api-Key: " + _key(ctr)]
    out = subprocess.run(cmd + [f"localhost:{port}{path}"], capture_output=True, text=True,
                         timeout=timeout + 30).stdout
    body, _, code = out.rpartition("\n")
    if not code.isdigit() or int(code) >= 400:
        raise RuntimeError(f"{ctr} {path.split('?')[0]} -> HTTP {code or 'none'}")
    return json.loads(body) if body.strip() else None

sonarr = lambda p: api("sonarr", 8989, "/api/v3" + p)
prowlarr = lambda p, **kw: api("prowlarr", 9696, "/api/v1" + p, **kw)

# ---------- db ----------
def db(ro=False):
    if ro:
        c = sqlite3.connect(f"file:{DB}?mode=ro", uri=True, timeout=30)
        c.row_factory = sqlite3.Row
        return c
    c = sqlite3.connect(DB, timeout=30)
    c.row_factory = sqlite3.Row
    c.executescript("""
    create table if not exists shows(id integer primary key, title text, terms text, added real);
    create table if not exists sites(id integer primary key, name text, backoff_until real default 0,
        fails integer default 0);
    create table if not exists releases(guid text, site_id integer, show_id integer, title text,
        size integer, seeders integer, flags text, published text, info_url text, download_url text,
        first_seen real, last_seen real, primary key(guid, site_id));
    create table if not exists actions(ts real, kind text, detail text);
    create table if not exists fetches(show_id integer, site_id integer, term text,
        next_offset integer default 0, backfilled integer default 0, last_ok real default 0,
        last_result text, primary key(show_id, site_id, term));
    create table if not exists grabs(
        id text primary key, show_id integer, site_id integer, guid text, pick text,
        eps text, n_eps integer, size integer, status text,
        created real, decided real, msg_id integer, note text);
    create index if not exists grabs_created on grabs(created);
    create table if not exists kv(k text primary key, v text);
    """)
    return c

# ---------- episode layout & title parsing ----------
CN = {c: i + 1 for i, c in enumerate("一二三四五六七八九十")}
ROMAN = {c: i + 1 for i, c in enumerate("ⅠⅡⅢⅣⅤⅥⅦⅧⅨⅩ")}

def layout(series_id):
    """Regular (season >= 1) episodes in air order -> list of dicts; index+1 = absolute number."""
    eps = [e for e in sonarr(f"/episode?seriesId={series_id}") if e["seasonNumber"] > 0]
    return sorted(eps, key=lambda e: (e["seasonNumber"], e["episodeNumber"]))

def season_lengths(eps):
    n = defaultdict(int)
    for e in eps:
        n[e["seasonNumber"]] += 1
    return dict(n)

def _season(t):
    for rx in (r"\bS(\d{1,2})(?=E|\b)", r"Season\s*(\d{1,2})", r"第\s*(\d{1,2})\s*季"):
        m = re.search(rx, t, re.I)
        if m:
            return int(m[1])
    m = re.search(r"第([一二三四五六七八九十])季", t)
    if m:
        return CN[m[1]]
    m = re.search(r"[ⅠⅡⅢⅣⅤⅥⅦⅧⅨⅩ]", t)
    if m:
        return ROMAN[m[0]]
    m = re.search(r"\b(II|III|IV)\b", t)
    return {"II": 2, "III": 3, "IV": 4}[m[1]] if m else None

def _episodes(t):
    """(first, last) episode numbers in the title, or None."""
    for rx in (r"\bS\d{1,2}E(\d{1,4})(?:-?E?(\d{1,4}))?\b",
               r"第\s*(\d{1,4})\s*(?:-\s*(\d{1,4})\s*)?[集话話]",
               r"\bEP?(\d{1,4})(?:-(\d{1,4}))?\b",
               r"\s-\s(\d{1,4})(?:-(\d{1,4}))?(?=\s|\[|\(|$)",
               r"\[(\d{1,4})(?:-(\d{1,4}))?(?:v\d)?(?:\s*END)?\]",
               r"【(\d{1,4})(?:-(\d{1,4}))?】"):
        for m in re.finditer(rx, t, re.I):
            a, b = int(m[1]), int(m[2] or m[1])
            if a >= 1900 or b < a:              # a year or a resolution, not an episode
                continue
            return a, b
    return None

SPECIAL = re.compile(r"\bS00|\b(?:SP|OVA|OAD)\d*\b|番外|特别篇|特別篇|剧场版|劇場版", re.I)

def strip_key(url):
    """Prowlarr download links embed its API key; never store it."""
    return re.sub(r"apikey=[^&]*&?", "", url or "")

def parse(title, lengths):
    """Title -> set of absolute episode numbers (may exceed the layout), or None if unclear.

    S1 numbers and numbers with no season marker are absolute. In season s > 1 a number
    that fits inside the season is season-relative, a bigger one is absolute.
    A season marker with no episode number is a whole-season pack.
    ponytail: "S02E30" where 30 fits season 2 is read as season-relative; a site that
    numbers absolutely *and* writes S02 would be misread. Fix per site if one shows up.
    """
    if SPECIAL.search(title):
        return None
    s, ep = _season(title), _episodes(title)
    start = lambda season: sum(n for k, n in lengths.items() if k < season)
    m = re.search(r"\bS(\d{1,2})\s*-\s*S(\d{1,2})\b", title, re.I)
    if m and not ep:                                    # multi-season pack
        got = set()
        for k in range(int(m[1]), int(m[2]) + 1):
            got |= set(range(start(k) + 1, start(k) + lengths.get(k, 0) + 1))
        return got or None
    if ep:
        a, b = ep
        if s and s > 1 and b <= lengths.get(s, 0):
            a, b = a + start(s), b + start(s)
        return set(range(a, b + 1))
    if s and s in lengths:
        return set(range(start(s) + 1, start(s) + lengths[s] + 1))
    return None

def relevant(title, terms):
    """Title contains a term, not as the start of a longer name ('Example Show's Romance')."""
    t = title.lower().replace("’", "'")
    rx = lambda x: r"[\s._]*".join(map(re.escape, x.lower().split())) + r"(?!'s|[a-z])"
    return any(re.search(rx(x), t) for x in terms)

# ---------- commands: watch / sites ----------
def find_series(name):
    allser = sonarr("/series")
    hits = [s for s in allser if str(s["id"]) == name or s["title"].lower() == name.lower()] or \
           [s for s in allser if name.lower() in s["title"].lower()]
    if len(hits) != 1:
        sys.exit(f"'{name}' matches {len(hits)} Sonarr series: " + ", ".join(s["title"] for s in hits[:8]))
    return hits[0]

def show_row(c, name, exact=False):
    allrows = list(c.execute("select * from shows"))
    rows = [r for r in allrows if str(r["id"]) == name or r["title"].lower() == name.lower()]
    if not rows and not exact:
        rows = [r for r in allrows if name.lower() in r["title"].lower()]
    if len(rows) != 1:
        sys.exit(f"'{name}' matches {len(rows)} watched shows (see: watch list)")
    return rows[0]

def site_row(c, name):
    rows = [r for r in c.execute("select * from sites") if name.lower() in r["name"].lower()]
    exact = [r for r in rows if r["name"].lower() == name.lower()]
    rows = exact or rows
    if len(rows) != 1:
        sys.exit(f"'{name}' matches {len(rows)} sites (see: sites list)")
    return rows[0]

def cmd_watch(a, c):
    if a.action == "add":
        s = find_series(a.show)
        terms = a.term or [s["title"]]
        c.execute("insert or replace into shows values(?,?,?,?)", (s["id"], s["title"], json.dumps(terms, ensure_ascii=False), time.time()))
        print(f"watching {s['title']} (sonarr {s['id']}) terms={terms}")
    elif a.action == "remove":
        r = show_row(c, a.show)
        for t in ("shows where id", "releases where show_id", "fetches where show_id"):
            c.execute(f"delete from {t}=?", (r["id"],))
        print("removed", r["title"])
    else:
        for r in c.execute("select * from shows order by title"):
            print(r["id"], r["title"], json.loads(r["terms"]))
    c.commit()

def cmd_sites(a, c):
    if a.action == "list":
        now = time.time()
        for r in c.execute("select * from sites order by name"):
            bo = f" backoff until {datetime.fromtimestamp(r['backoff_until']):%m-%d %H:%M}" if r["backoff_until"] > now else ""
            print(r["id"], r["name"] + bo)
        return
    idx = prowlarr("/indexer")
    names = a.names or (config().get("sites", []) if a.action == "add" else [])
    for n in names:
        if a.action == "remove":
            r = site_row(c, n)
            c.execute("delete from sites where id=?", (r["id"],))
            print("removed", r["name"])
            continue
        hit = [i for i in idx if i["name"].lower() == n.lower()] or \
              [i for i in idx if n.lower() in i["name"].lower()]
        if len(hit) != 1:
            print(f"skip '{n}': matches {len(hit)} Prowlarr indexers")
            continue
        c.execute("insert or ignore into sites(id,name) values(?,?)", (hit[0]["id"], hit[0]["name"]))
        print("site", hit[0]["id"], hit[0]["name"])
    c.commit()

# ---------- refresh ----------
def unhealthy():
    """Indexer ids Prowlarr has disabled after failures. A failed search still returns
    HTTP 200 with an empty list, so this is the only way to tell 'nothing' from 'broken'."""
    now = datetime.now(timezone.utc).isoformat()
    return {x["indexerId"] for x in prowlarr("/indexerstatus") or [] if (x.get("disabledTill") or "") > now}

def add_narrowed(c, sh):
    """For a site that only returns its newest PAGE results, add narrower searches
    '<term> S01E0' .. 'S01E9' (per season tag the site uses), so older episodes become
    reachable. They are extra fetch rows, refreshed weekly (new episodes show up in the
    plain search anyway). ponytail: assumes SxxEyy naming; sites without it stay capped."""
    terms = json.loads(sh["terms"])
    for f in c.execute("select site_id, term from fetches where show_id=? and last_result like 'capped%'", (sh["id"],)).fetchall():
        if f["term"] not in terms:
            continue                                    # a narrowed search that is itself capped
        key = lambda s: re.sub(r"\s+", "", s).lower()
        titles = [r[0] for r in c.execute("select title from releases where show_id=? and site_id=?", (sh["id"], f["site_id"]))
                  if re.search(r"\bS\d{2}E\d", r[0], re.I) and key(f["term"]) in key(r[0])]
        if not titles:
            continue                                    # this term isn't how the site names SxxEyy releases
        for tag in sorted({m for t in titles for m in re.findall(r"\bS(\d{2})E\d", t, re.I)}):
            for d in range(10):
                c.execute("insert or ignore into fetches(show_id, site_id, term) values(?,?,?)",
                          (sh["id"], f["site_id"], f"{f['term']} S{tag}E{d}"))
    c.commit()

def show_terms(c, sh, site_id):
    base = json.loads(sh["terms"])
    extra = [r[0] for r in c.execute("select term from fetches where show_id=? and site_id=?", (sh["id"], site_id))
             if r[0] not in base]
    return base + sorted(extra)

def cmd_refresh(a, c):
    lock = open(DB.with_suffix(".lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)   # two runs would double the request rate
    except OSError:
        sys.exit("another refresh is running")
    now, budget, fails, tries = time.time(), RUN_CAP, 0, 0
    shows = [show_row(c, a.show)] if a.show else list(c.execute("select * from shows"))
    sites = list(c.execute("select * from sites where backoff_until < ?", (now,)))
    status = {s["id"]: s["status"] for s in sonarr("/series")}
    dead = unhealthy()
    for st in sites:
        if st["id"] in dead:
            print(f"  {st['name']}: Prowlarr has it disabled after failures; skipped this run")
    first = True
    for sh in shows:
        add_narrowed(c, sh)
        for st in sites:
            if st["id"] in dead:
                continue
            for term in show_terms(c, sh, st["id"]):
                f = c.execute("select * from fetches where show_id=? and site_id=? and term=?",
                              (sh["id"], st["id"], term)).fetchone()
                f = dict(f) if f else {"next_offset": 0, "backfilled": 0, "last_ok": 0}
                narrowed = term not in json.loads(sh["terms"])
                age = ENDED_AGE if f["backfilled"] and (narrowed or status.get(sh["id"]) == "ended") else MIN_AGE
                if not a.force and now - f["last_ok"] < age:
                    continue
                offset = f["next_offset"] if not f["backfilled"] else 0
                pages, new_total, result, prev = 0, 0, "ok", set()
                while True:
                    if budget <= 0:
                        result = "run cap reached"
                        break
                    if not first:
                        time.sleep(random.uniform(*GAP))
                    first = False
                    budget -= 1; tries += 1; pages += 1
                    q = urllib.parse.urlencode({"query": term, "indexerIds": st["id"], "type": "search",
                                                "limit": PAGE, "offset": offset})
                    try:
                        res = prowlarr("/search?" + q) or []
                        if not res and st["id"] in unhealthy():
                            raise RuntimeError("Prowlarr reports the indexer failing")
                    except Exception as e:  # site/indexer failure -> back off this site
                        fails += 1
                        bo = min(BACKOFF0 * 2 ** st["fails"], BACKOFF_MAX)
                        c.execute("update sites set fails=fails+1, backoff_until=? where id=?", (now + bo, st["id"]))
                        c.commit()
                        dead.add(st["id"])
                        print(f"  {st['name']}: {e}; backing off {bo // 3600} h")
                        result = f"error: {e}"
                        break
                    c.execute("update sites set fails=0 where id=?", (st["id"],))
                    new = 0
                    for r in res:
                        if not relevant(r["title"], json.loads(sh["terms"])):
                            continue
                        cur = c.execute("update releases set seeders=?, flags=?, last_seen=? where guid=? and site_id=?",
                                        (r.get("seeders"), json.dumps(r.get("indexerFlags") or []), now, r["guid"], st["id"]))
                        if cur.rowcount == 0:
                            new += 1
                            c.execute("insert into releases values(?,?,?,?,?,?,?,?,?,?,?,?)",
                                      (r["guid"], st["id"], sh["id"], r["title"], r.get("size"), r.get("seeders"),
                                       json.dumps(r.get("indexerFlags") or []), r.get("publishDate"),
                                       r.get("infoUrl"), strip_key(r.get("downloadUrl")), now, now))
                    new_total += new
                    offset += PAGE
                    guids = {r["guid"] for r in res}
                    repeat = guids <= prev              # same page again: indexer ignores offset
                    prev |= guids
                    if narrowed:                        # one page only; if the site ignores the
                        f["backfilled"] = 1             # narrowing it returns the same newest 100,
                        break                           # and paging further would just repeat that
                    if len(res) < PAGE or repeat:       # end of what the site has
                        f["backfilled"] = 1
                        if pages > 1 and (repeat or not res):   # full page 1, then nothing more
                            result = f"capped: only the newest {PAGE} results are reachable"
                        break
                    if f["backfilled"] and new == 0:    # caught up with what we already have
                        break
                    if pages >= BACKFILL_PAGES:         # backfill continues next run
                        break                           # ponytail: >500 new releases between runs would be missed
                if not result.startswith("error"):
                    c.execute("insert or replace into fetches values(?,?,?,?,?,?,?)",
                              (sh["id"], st["id"], term, 0 if f["backfilled"] else offset,
                               f["backfilled"], f["last_ok"] if result.startswith("run cap") else now, result))
                c.commit()
                print(f"{sh['title']} @ {st['name']} [{term}]: {pages} page(s), {new_total} new"
                      + ("" if f["backfilled"] else ", backfill continues next run") + (f" ({result})" if result != "ok" else ""))
                if tries >= 3 and fails == tries:
                    sys.exit("first 3 requests all failed: Prowlarr or VPN down? stopping, nothing else changed")
                if result.startswith("error") or budget <= 0:
                    break
            if budget <= 0:
                print(f"run cap of {RUN_CAP} requests reached; the rest waits for the next run")
                return

# ---------- query ----------
def rng(nums):
    out = []
    for _, g in groupby(enumerate(sorted(nums)), lambda p: p[1] - p[0]):
        g = [x for _, x in g]
        out.append(str(g[0]) if len(g) == 1 else f"{g[0]}-{g[-1]}")
    return ",".join(out) or "none"

def coverage(c, sh):
    eps = layout(sh["id"])
    lengths = season_lengths(eps)
    now = datetime.now(timezone.utc).isoformat()
    aired = {i + 1 for i, e in enumerate(eps) if e.get("airDateUtc") and e["airDateUtc"] <= now}
    have = {i + 1 for i, e in enumerate(eps) if e["hasFile"]}
    cov, unclear = defaultdict(lambda: defaultdict(list)), defaultdict(list)
    for r in c.execute("select r.*, s.name site from releases r join sites s on s.id=r.site_id where show_id=?", (sh["id"],)):
        n = parse(r["title"], lengths)
        if n is None:
            unclear[r["site"]].append(dict(r))
            continue
        for e in n:
            cov[r["site"]][e].append(dict(r))
    return eps, aired, have, cov, unclear

def se(eps, n):
    if n > len(eps):
        return f"abs {n} (beyond Sonarr)"
    e = eps[n - 1]
    return f"S{e['seasonNumber']:02}E{e['episodeNumber']:02}"

# ponytail: title tags only; WEB-DL titles often carry none -> "?". Upgrade: scrape info_url 副标题/MediaInfo.
SUB_TAGS = [("hard", r"内嵌|硬字幕|\bHardsub"), ("soft", r"内封|外挂|\bSoftsub")]
SUB_LANG = [("chs+cht", r"简繁|CHS.?CHT|GB.?BIG5"), ("chs", r"\[(GB|CHS|简体?(中文)?)\]|简中|\bCHS\b"),
            ("cht", r"\[(BIG5|CHT|繁体?(中文)?)\]|繁中|\bCHT\b")]

def subs(title):
    """'hard-chs' / 'soft-cht' / 'chs' (kind unknown) / '?' (no tag) from the release title."""
    kind = next((k for k, rx in SUB_TAGS if re.search(rx, title, re.I)), "")
    lang = next((k for k, rx in SUB_LANG if re.search(rx, title, re.I)), "")
    if not kind and re.search(r"\[Baha\]", title):  # ANi Baha rips are hardsubbed CHT
        kind, lang = "hard", lang or "cht"
    if not kind and not lang:  # release groups with a known house style; private, so from config
        m = re.search(r"-([A-Za-z0-9]+)(\.\w{2,4})?$", title.strip())
        known = config().get("sub_groups", {}) if m else {}
        return known.get(m.group(1), "?") if m else "?"
    return "-".join(x for x in (kind, lang) if x) or "?"

# ---------- grab: Hermes asks, the owner approves in Telegram ----------
GRAB_DEFAULTS = {"grab_enabled": False, "grab_category": "tv-sonarr",
                 "grab_max_eps_day": 30, "grab_max_bytes_day": 200 * 10**9}

def grab_cfg():
    return {**GRAB_DEFAULTS, **config()}

def pick_id(r):
    """10 hex chars over the fields a grab depends on: changes if the daily refresh rewrites the row."""
    raw = "\x1f".join(str(r[k] or "") for k in ("site_id", "guid", "title", "download_url"))
    return hashlib.sha256(raw.encode()).hexdigest()[:10]

def fmt_rel(r, dl):
    flags = ",".join(json.loads(r["flags"] or "[]"))
    days = int((time.time() - r["last_seen"]) / 86400)   # old pages aren't re-read, so seeders/flags age
    old = f" (as of {days}d ago)" if days >= 2 else ""
    line = f"{r['site']}: {r['title']} | subs {subs(r['title'])} | {(r['size'] or 0) / 2**30:.1f}G seed {r['seeders']}{' ' + flags if flags else ''} | pick {pick_id(r)}{old}\n      {r['info_url']}"
    return line + (f"\n      {r['download_url']}&apikey={_key('prowlarr')}" if dl and r["download_url"] else "")

def best_releases(cov, sites, want, dl, top=8):
    """Releases that cover the most of `want`, best first."""
    seen = {}
    for s in sites:
        for e in want:
            for r in cov.get(s, {}).get(e, []):
                k = (s, r["guid"])
                seen.setdefault(k, (r, set()))[1].add(e)
    ranked = sorted(seen.values(), key=lambda v: (-len(v[1]), -(v[0]["seeders"] or 0)))
    for r, got in ranked[:top]:
        print(f"  [{len(got)} eps: {rng(got)}] {fmt_rel(r, dl)}")
    if len(ranked) > top:
        print(f"  ... {len(ranked) - top} more releases")

def cmd_query(a, c):
    sh = show_row(c, a.show)
    eps, aired, have, cov, unclear = coverage(c, sh)
    sites = [r["name"] for r in c.execute("select name from sites order by name")]
    stale = c.execute("select count(*) from fetches where show_id=? and backfilled=0", (sh["id"],)).fetchone()[0]
    if stale:
        print(f"note: backfill still in progress for {stale} site/term pair(s); answers may be incomplete")
    base = json.loads(sh["terms"])
    for site, in c.execute("select distinct s.name from fetches f join sites s on s.id=f.site_id "
                           "where show_id=? and last_result like 'capped%'", (sh["id"],)).fetchall():
        rows = [r for r in c.execute("select f.term, f.last_ok from fetches f join sites s on s.id=f.site_id "
                                     "where show_id=? and s.name=?", (sh["id"], site)) if r[0] not in base]
        done = sum(1 for r in rows if r[1])
        if not rows or done < len(rows):
            print(f"note: {site} only returns its newest {PAGE} results per search; "
                  + (f"narrower searches {done}/{len(rows)} done" if rows else "no narrower searches possible")
                  + ", so older episodes there may be missing from this answer")
    missing = aired - have
    if a.what == "missing":
        print(f"{sh['title']}: {len(aired)} aired, have {len(have & aired)}, missing {len(missing)}: {rng(missing)}")
        if not missing:
            return
        rows = sorted(((len(missing & set(cov.get(s, {}))), s) for s in sites), reverse=True)
        full = [s for n, s in rows if n == len(missing)]
        print("has ALL missing episodes:", ", ".join(full) or "no single site")
        for n, s in rows:
            if n:
                print(f"  {s}: {n}/{len(missing)}" + (f", lacks {rng(missing - set(cov[s]))}" if n < len(missing) else ""))
        print("best releases for the missing episodes:")
        best_releases(cov, sites, missing, a.download_links)
    elif a.what in ("site", "gaps"):
        site = site_row(c, a.site)["name"]
        got = set(cov.get(site, {}))
        lack = aired - got
        extra = {n for n in got if n > len(eps)}
        print(f"{sh['title']} @ {site}: has {len(got & aired)}/{len(aired)} aired episodes; lacks {rng(lack)}")
        if extra:
            print(f"  also has abs {rng(extra)} which Sonarr doesn't list yet (TVDB behind, or different numbering)")
        if a.what == "gaps" and lack:
            others = [s for s in sites if s != site]
            nobody = lack - {e for s in others for e in cov.get(s, {})}
            print("who fills the gap:")
            best_releases(cov, others, lack, a.download_links)
            if nobody:
                print(f"  nobody has: {rng(nobody)}")
    elif a.what == "unclear":
        for s, rs in sorted(unclear.items()):
            for r in rs:
                print(f"{s}: {r['title']}")
        if not unclear:
            print("none")

# ---------- seeding ----------
def cmd_seeding(a, c):
    port = subprocess.check_output(["docker", "exec", "qbittorrent", "sh", "-c", "echo ${WEBUI_PORT:-8080}"], text=True).strip()
    ts = api("qbittorrent", port, "/api/v2/torrents/info", auth=False)
    by = defaultdict(lambda: [0, 0])
    for t in ts:
        host = urllib.parse.urlparse(t.get("tracker") or "").hostname or "(no working tracker)"
        by[host][0] += 1
        by[host][1] += t.get("size") or 0
    for h, (n, sz) in sorted(by.items(), key=lambda kv: -kv[1][0]):
        print(f"{n:5}  {sz / 2**40:6.2f} TiB  {h}")

# ---------- grab: request side (HTTP API and CLI) ----------
GRAB_TTL, GRAB_PENDING_MAX, GRAB_REQ_DAY = 1800, 5, 20
GRAB_LIVE = "('pending','approved','queued','sent')"    # states that hold part of the daily caps
PICK_RX = re.compile(r"^[0-9a-f]{10}$")

def grab_expire(c):
    now = time.time()
    c.execute("update grabs set status='expired', decided=? where status='pending' and created<?", (now, now - GRAB_TTL))
    c.commit()

def grab_usage(c, ignore_id=None):
    """(episodes, bytes) held by requests in the last 24 h; ignore_id is the row being approved."""
    return tuple(c.execute(f"select coalesce(sum(n_eps),0), coalesce(sum(size),0) from grabs "
                           f"where status in {GRAB_LIVE} and created>? and id is not ?",
                           (time.time() - 86400, ignore_id)).fetchone())

def grab_check(c, show, pick, ignore_id=None):
    """Everything that must hold at request time AND again at approval time.
    Returns (show_row, release_dict, missing_eps) or raises Refused."""
    cfg = grab_cfg()
    if not cfg["grab_enabled"]:
        raise Refused("grab is disabled")
    if not isinstance(pick, str) or not PICK_RX.match(pick):
        raise Refused("'pick' must be the 10-character id printed on a release line")
    try:
        sh = show_row(c, str(show), exact=True)
    except SystemExit as e:
        raise Refused(str(e.code))
    _, aired, have, cov, _ = coverage(c, sh)
    found = {}
    for by_ep in cov.values():
        for ep, rels in by_ep.items():
            for r in rels:
                if pick_id(r) == pick:
                    found.setdefault((r["site_id"], r["guid"]), (r, set()))[1].add(ep)
    if not found:
        raise Refused("stale pick: that release is gone or changed; run missing again")
    rel, got = next(iter(found.values()))
    fills = sorted(got & (aired - have))
    if not fills:
        raise Refused("nothing missing in this release")
    if c.execute("select count(*) from grabs where site_id=? and guid=? and status not in ('denied','expired','failed') "
                 "and id is not ?", (rel["site_id"], rel["guid"], ignore_id)).fetchone()[0]:
        raise Refused("this release was already requested")
    eps_used, bytes_used = grab_usage(c, ignore_id)
    size = rel["size"] or 0
    if size <= 0:
        raise Refused("the listed size is unknown, so it can't be held to the daily size cap")
    if eps_used + len(fills) > grab_cfg()["grab_max_eps_day"]:
        raise Refused(f"daily episode cap: {eps_used} used + {len(fills)} would pass {grab_cfg()['grab_max_eps_day']}")
    if bytes_used + size > grab_cfg()["grab_max_bytes_day"]:
        raise Refused(f"daily size cap: {bytes_used / 1e9:.0f} GB used + {size / 1e9:.1f} GB would pass "
                      f"{grab_cfg()['grab_max_bytes_day'] / 1e9:.0f} GB")
    return sh, rel, fills

def grab_request(c, show, pick):
    """Hermes (or the owner CLI) asks; the owner approves in Telegram. Nothing is fetched here."""
    cfg = grab_cfg()
    if not cfg["grab_enabled"]:
        raise Refused("grab is disabled")
    grab_expire(c)
    if c.execute("select count(*) from grabs where status='pending'").fetchone()[0] >= GRAB_PENDING_MAX:
        raise Refused(f"{GRAB_PENDING_MAX} requests are already waiting for the owner")
    _budget(c, "grab_req", GRAB_REQ_DAY)
    sh, rel, fills = grab_check(c, show, pick)
    gid = secrets.token_urlsafe(12)
    c.execute("insert into grabs values(?,?,?,?,?,?,?,?,?,?,?,?,?)",
              (gid, sh["id"], rel["site_id"], rel["guid"], pick, json.dumps(fills), len(fills),
               rel["size"] or 0, "pending", time.time(), None, None, ""))
    c.execute("insert into actions values(?,?,?)", (time.time(), "grab_req", f"{sh['id']} {rel['site_id']}:{rel['guid']} {rng(fills)}"))
    c.commit()
    return (f"request {gid[:6]} for {sh['title']} episodes {rng(fills)} is waiting for the owner to approve "
            f"in Telegram (30 min); no need to poll, check GET /coverage/grabs once later if asked")

def grab_list(c):
    now = time.time()
    rows = c.execute("select g.*, s.title as show from grabs g left join shows s on s.id=g.show_id "
                     "where g.created>? order by g.created", (now - 86400,)).fetchall()
    eps, size = grab_usage(c)
    cfg = grab_cfg()
    out = [f"today: {eps}/{cfg['grab_max_eps_day']} eps \u00b7 {size / 1e9:.1f}/{cfg['grab_max_bytes_day'] / 1e9:.0f} GB"]
    for r in rows:
        st = "expired" if r["status"] == "pending" and r["created"] < now - GRAB_TTL else r["status"]
        out.append(f"{r['id'][:6]}  {st:9} {r['show'] or r['show_id']}  eps {rng(json.loads(r['eps']))}  "
                   f"{(r['size'] or 0) / 1e9:.1f} GB  {r['note'] or ''}".rstrip())
    return "\n".join(out)

# ---------- grab: dispatch (only the bot calls this, after the owner's tap) ----------
DL_PATH_RX = re.compile(r"^/\d+/download$")
MAGNET_RX = re.compile(r"^magnet:\?xt=urn:bt[im]h:[0-9A-Za-z]{32,40}(&[^\s]{0,1500})?$")
CATEGORY_RX = re.compile(r"^[\w.-]{1,40}$")

def check_download_url(url):
    """Only the internal Prowlarr gateway, never a URL we did not build."""
    u = urllib.parse.urlsplit(url or "")
    if len(url or "") > 2048 or u.scheme != "http" or u.netloc != "localhost:9696" or not DL_PATH_RX.match(u.path):
        raise Refused("download link is not an internal gateway link")
    return url

def _bdecode(b, i=0, depth=0):
    """Minimal bencode reader -> (value, next index). Raises ValueError on anything odd."""
    if depth > 20:
        raise ValueError("too deep")
    c = b[i:i + 1]
    if c == b"i":
        j = b.index(b"e", i)
        return int(b[i + 1:j]), j + 1
    if c in (b"l", b"d"):
        out, i = ([], i + 1) if c == b"l" else ({}, i + 1)
        while b[i:i + 1] != b"e":
            v, i = _bdecode(b, i, depth + 1)
            if c == b"l":
                out.append(v)
            else:
                k = v
                v, i = _bdecode(b, i, depth + 1)
                out[k] = v
        return out, i + 1
    j = b.index(b":", i)
    n = int(b[i:j])
    if n < 0 or j + 1 + n > len(b):
        raise ValueError("bad string")
    return b[j + 1:j + 1 + n], j + 1 + n

def torrent_bytes(body):
    """Total payload size a .torrent declares (single file or the sum of its files)."""
    info = _bdecode(body)[0][b"info"]
    return info[b"length"] if b"length" in info else sum(f[b"length"] for f in info[b"files"])

def docker_curl(ctr, args, stdin=None, timeout=90):
    """The only place a write goes through: `docker exec [-i] <ctr> curl <args>`. Returns (returncode, stdout)."""
    cmd = ["docker", "exec"] + (["-i"] if stdin is not None else []) + [ctr, "curl"] + list(args)
    try:
        r = subprocess.run(cmd, input=stdin, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, b""
    return r.returncode, r.stdout

def qb_port():
    return subprocess.check_output(["docker", "exec", "qbittorrent", "sh", "-c", "echo ${WEBUI_PORT:-8080}"], text=True).strip()

def dispatch(c, g):
    """Fetch the release through Prowlarr, hand the file (or magnet) to qBittorrent. -> (status, note).
    Never retried by the caller: a failure here may still have added the item."""
    rel = c.execute("select * from releases where site_id=? and guid=?", (g["site_id"], g["guid"])).fetchone()
    if not rel:
        return "failed", "release row is gone"
    cat = grab_cfg()["grab_category"]
    if not CATEGORY_RX.match(str(cat)):
        return "failed", "bad grab_category in config"
    try:
        url = check_download_url(rel["download_url"])
    except Refused as e:
        return "failed", str(e)
    key = _key("prowlarr")
    rc, out = docker_curl("prowlarr", ["-s", "-m", "60", "--max-redirs", "0", "--max-filesize", "5M", "-o", "-",
                                       "-w", "\n%{http_code} %{redirect_url}",
                                       url + ("&" if "?" in url else "?") + "apikey=" + key], timeout=90)
    body, _, tail = out.rpartition(b"\n")
    code, _, loc = tail.decode(errors="replace").partition(" ")
    if rc != 0:
        return "failed", "could not fetch the link from Prowlarr"
    port = qb_port()
    base = ["-s", "-m", "30", "-w", "\n%{http_code}", "--form-string", "category=" + cat]
    if code == "200" and body.startswith(b"d") and b"4:info" in body:
        try:
            total = torrent_bytes(body)
        except Exception:
            return "failed", "the file is not a valid torrent"
        listed = rel["size"] or 0
        if not isinstance(total, int) or total <= 0 or total > grab_cfg()["grab_max_bytes_day"] or total > listed * 1.25 + 50 * 2**20:
            return "failed", f"the file declares {total / 1e9:.1f} GB, bigger than the listing ({listed / 1e9:.1f} GB) or the daily cap" \
                if isinstance(total, int) and total > 0 else "the file declares no size"
        rc, res = docker_curl("qbittorrent", base + ["-F", "torrents=@-;filename=x.torrent", f"localhost:{port}/api/v2/torrents/add"],
                              stdin=body, timeout=60)
    elif code in ("301", "302", "303", "307", "308") and MAGNET_RX.match(loc.strip()):
        rc, res = docker_curl("qbittorrent", base + ["--form-string", "urls=" + loc.strip(), f"localhost:{port}/api/v2/torrents/add"],
                              timeout=60)
    else:
        return "failed", f"link returned HTTP {code or 'none'}, not a torrent file or magnet"
    if rc != 0 or not res.startswith(b"Ok"):
        return "failed", "qBittorrent did not accept it"
    try:
        qs = urllib.parse.urlencode({"category": cat, "sort": "added_on", "reverse": "true", "limit": 5})
        for t in api("qbittorrent", port, "/api/v2/torrents/info?" + qs, auth=False) or []:
            if t.get("added_on", 0) > time.time() - 60:
                return "queued", "queued: " + re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", str(t.get("name")))[:80]
    except Exception:
        pass
    return "sent", "sent to qBittorrent; not visible there yet"

# ---------- grab: Telegram bot (the only holder of the bot token) ----------
def clean(text, n=200):
    """Untrusted release text -> one short plain line: control, format (bidi, zero-width) and
    line/paragraph-separator characters become spaces."""
    return "".join(" " if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp") else ch
                   for ch in str(text or "")).strip()[:n]

def tg(method, **params):
    """Telegram Bot API call. Errors never carry the URL, so the token cannot reach a log."""
    token = config().get("grab_bot_token")
    if not token:
        raise RuntimeError(f"{method}: no bot token configured")
    req = urllib.request.Request(f"https://api.telegram.org/bot{token}/{method}", json.dumps(params).encode(),
                                 {"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=params.get("timeout", 0) + 30) as r:
            res = json.load(r)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{method} failed: HTTP {e.code}") from None
    except Exception as e:
        raise RuntimeError(f"{method} failed: {type(e).__name__}") from None
    if not res.get("ok"):
        raise RuntimeError(f"{method} failed: {clean(res.get('description'), 80)}")
    return res.get("result")

def grab_message(c, g):
    rel = c.execute("select r.*, s.name site from releases r join sites s on s.id=r.site_id where r.site_id=? and r.guid=?",
                    (g["site_id"], g["guid"])).fetchone()
    show = c.execute("select title from shows where id=?", (g["show_id"],)).fetchone()
    eps, size = grab_usage(c)
    cfg = grab_cfg()
    lines = ["Grab request from Hermes",
             f"{clean((show or {'title': g['show_id']})['title'], 80)} \u2014 fills {rng(json.loads(g['eps']))} ({g['n_eps']} eps)"]
    if rel:
        lines += [f"{clean(rel['site'], 40)}: {clean(rel['title'])}",
                  f"{(rel['size'] or 0) / 1e9:.1f} GB \u00b7 seeders {rel['seeders']} \u00b7 subs {subs(clean(rel['title'], 300))}"]
    lines.append(f"Today incl. this: {eps}/{cfg['grab_max_eps_day']} eps \u00b7 {size / 1e9:.1f}/{cfg['grab_max_bytes_day'] / 1e9:.0f} GB")
    return "\n".join(lines)

def _grab_done(c, gid, status, note, decision):
    c.execute("update grabs set status=?, note=?, decided=? where id=?", (status, note, time.time(), gid))
    c.execute("insert into actions values(?,?,?)", (time.time(), "grab", f"{gid[:6]} {decision} -> {status}"))
    c.commit()
    print(f"grab {gid[:6]} {decision} -> {status}", file=sys.stderr, flush=True)

def _edit(c, g, tail):
    """Replace the approval message with its outcome (and drop the buttons). Best effort."""
    if not g["msg_id"]:
        return
    try:
        tg("editMessageText", chat_id=grab_cfg().get("owner_chat_id"), message_id=g["msg_id"],
           text=grab_message(c, g) + "\n\n" + tail, reply_markup={"inline_keyboard": []})
    except Exception as e:
        print("grab edit failed:", e, file=sys.stderr, flush=True)

def announce(c):
    for g in c.execute("select * from grabs where status='pending' and msg_id is null").fetchall():
        kb = {"inline_keyboard": [[{"text": "\u2705 Approve", "callback_data": "a:" + g["id"]},
                                    {"text": "\u274c Deny", "callback_data": "d:" + g["id"]}]]}
        m = tg("sendMessage", chat_id=grab_cfg().get("owner_chat_id"), text=grab_message(c, g), reply_markup=kb)
        c.execute("update grabs set msg_id=? where id=?", (m["message_id"], g["id"]))
        c.commit()

def expire(c):
    grab_expire(c)
    for g in c.execute("select * from grabs where status='expired' and msg_id is not null and coalesce(note,'')=''").fetchall():
        _edit(c, g, "Expired: no answer in 30 minutes.")
        c.execute("update grabs set note='expired' where id=?", (g["id"],))
        c.commit()

def handle_callback(c, cb):
    cfg = grab_cfg()
    owner = cfg.get("owner_user_id")
    if owner in (None, "") or str((cb.get("from") or {}).get("id")) != str(owner):
        return                                  # not the owner: say nothing at all
    def answer(text):
        try:
            tg("answerCallbackQuery", callback_query_id=cb.get("id"), text=text)
        except Exception:
            pass
    m = re.fullmatch(r"([ad]):([\w-]{1,40})", str(cb.get("data") or ""))
    g = c.execute("select * from grabs where id=?", (m.group(2),)).fetchone() if m else None
    if not g or g["status"] != "pending":
        return answer("already handled")
    if g["created"] < time.time() - GRAB_TTL:
        grab_expire(c)
        return answer("expired")
    if m.group(1) == "d":
        _grab_done(c, g["id"], "denied", "denied", "deny")
        _edit(c, g, "Denied.")
        return answer("denied")
    # approve: claim the row first so a second tap or a crash can never dispatch twice
    if c.execute("update grabs set status='approved', decided=? where id=? and status='pending'",
                 (time.time(), g["id"])).rowcount != 1:
        return answer("already handled")
    c.commit()
    try:
        grab_check(c, g["show_id"], g["pick"], ignore_id=g["id"])
    except Refused as e:
        _grab_done(c, g["id"], "failed", str(e), "approve")
        _edit(c, g, f"Not fetched: {e}")
        return answer("not fetched")
    except Exception as e:
        _grab_done(c, g["id"], "failed", f"check failed: {type(e).__name__}", "approve")
        _edit(c, g, f"Not fetched: check failed ({type(e).__name__}).")
        return answer("not fetched")
    try:
        status, note = dispatch(c, g)
    except Exception as e:                      # may or may not have been added: stay 'approved', never retry
        c.execute("update grabs set note=? where id=?", (f"approved, result unknown ({type(e).__name__})", g["id"]))
        c.commit()
        print(f"grab {g['id'][:6]} dispatch error {type(e).__name__}", file=sys.stderr, flush=True)
        _edit(c, g, f"Approved, but the result is unknown ({type(e).__name__}). Check qBittorrent before asking again.")
        return answer("result unknown")
    _grab_done(c, g["id"], status, note, "approve")
    _edit(c, g, ("Done: " if status != "failed" else "Not fetched: ") + note)
    answer(status)

def cmd_bot(a, _c):
    backoff = 5
    while True:
        try:
            if not grab_cfg()["grab_enabled"]:
                time.sleep(30)
                continue
            with closing(db()) as c:
                expire(c)
                announce(c)
                off = int((c.execute("select v from kv where k='tg_offset'").fetchone() or ["0"])[0])
                for u in tg("getUpdates", offset=off, timeout=15, allowed_updates=["callback_query"]) or []:
                    try:
                        if u.get("callback_query"):
                            handle_callback(c, u["callback_query"])
                    except Exception as e:
                        print("callback error", type(e).__name__, file=sys.stderr, flush=True)
                    c.execute("insert or replace into kv values('tg_offset', ?)", (str(u["update_id"] + 1),))
                    c.commit()
            backoff = 5
        except Exception as e:
            print("bot error", type(e).__name__, str(e)[:200], file=sys.stderr, flush=True)
            time.sleep(backoff)
            backoff = min(backoff * 2, 300)

# ---------- serve: HTTP API for Hermes (via the read-only proxy) ----------
# Limits are enforced here, on the home side; they are the only fence (owner chose no approval).
MAX_SHOWS, MAX_CHANGES_DAY, MAX_REFRESH_DAY, MAX_TERMS, MAX_BODY = 10, 20, 6, 3, 4096
TERM_RX = re.compile(r"^[\w\s\-'’:.!·,&()]{1,40}$")

class Refused(Exception):
    pass

def _capture(fn, a, c):
    """Run a CLI command, return its text output. sys.exit(msg) from it becomes Refused."""
    import contextlib, io
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            fn(a, c)
    except SystemExit as e:
        raise Refused(str(e.code) if e.code not in (None, 0) else buf.getvalue().strip())
    return buf.getvalue()

def _budget(c, kind, limit):
    n = c.execute("select count(*) from actions where kind=? and ts>?", (kind, time.time() - 86400)).fetchone()[0]
    if n >= limit:
        raise Refused(f"daily limit reached: {limit} {kind} per 24 h")

def api_read(path, q):
    ns = argparse.Namespace
    with closing(db(ro=True)) as c:
        if path == "/coverage/shows":
            return _capture(lambda a, c: cmd_watch(a, c), ns(action="list"), c)
        if path == "/coverage/sites":
            return _capture(cmd_sites, ns(action="list", names=[]), c)
        if path == "/coverage/seeding":
            return _capture(cmd_seeding, ns(), c)
        if path == "/coverage/grabs":
            return grab_list(c)
        what = path.rsplit("/", 1)[-1]
        if what in ("missing", "site", "gaps", "unclear"):
            if not q.get("show") or (what in ("site", "gaps") and not q.get("site")):
                raise Refused("need ?show=" + ("&site=" if what in ("site", "gaps") else ""))
            return _capture(cmd_query, ns(what=what, show=q["show"], site=q.get("site"), download_links=False), c)
        raise Refused("unknown path")

def api_write(path, body):
    show = str(body.get("show") or "").strip()
    if not show or len(show) > 80:
        raise Refused("need a 'show' (Sonarr title or id)")
    with closing(db()) as c:
        if path == "/coverage/watch":
            terms = body.get("terms") or []
            if not isinstance(terms, list) or len(terms) > MAX_TERMS or not all(isinstance(t, str) and TERM_RX.match(t) for t in terms):
                raise Refused(f"'terms' must be a list of up to {MAX_TERMS} plain strings, each 1-40 chars")
            _budget(c, "changes", MAX_CHANGES_DAY)
            s = find_series(show)
            known = c.execute("select terms from shows where id=?", (s["id"],)).fetchone()
            terms = terms or (json.loads(known["terms"]) if known else [])   # re-watch keeps old terms
            if not known and c.execute("select count(*) from shows").fetchone()[0] >= MAX_SHOWS:
                raise Refused(f"already watching {MAX_SHOWS} shows; unwatch one first")
            out = _capture(cmd_watch, argparse.Namespace(action="add", show=str(s["id"]), term=terms or None), c)
            kind = "changes"
        elif path == "/coverage/unwatch":
            _budget(c, "changes", MAX_CHANGES_DAY)
            r = show_row(c, show, exact=True)
            out = _capture(cmd_watch, argparse.Namespace(action="remove", show=str(r["id"])), c)
            kind = "changes"
        elif path == "/coverage/refresh":
            _budget(c, "refresh", MAX_REFRESH_DAY)
            show_row(c, show, exact=True)       # must be watched
            r = subprocess.run(["systemctl", "start", "--no-block", "episode-coverage.service"], capture_output=True, text=True)
            if r.returncode:
                raise Refused("could not start refresh")
            out = ("refresh started for all watched shows; it keeps the usual pacing (12 h per show and site, "
                   "60 searches per run), so new data arrives over the next minutes")
            kind = "refresh"
        elif path == "/coverage/grab":
            if set(body) != {"show", "pick"}:
                raise Refused("body must be exactly {\"show\": ..., \"pick\": ...}")
            return grab_request(c, show, body["pick"])      # writes its own actions row
        else:
            raise Refused("unknown path")
        c.execute("insert into actions values(?,?,?)", (time.time(), kind, f"{path} {show}"))
        c.commit()
        return out

def cmd_serve(a, _c):
    from http.server import BaseHTTPRequestHandler, HTTPServer
    allow = set(a.allow)

    class H(BaseHTTPRequestHandler):
        timeout = 30            # one thread: a stalled client must not block the API
        def _send(self, code, text):
            body = json.dumps({"ok": code == 200, "text": text}, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _handle(self, write):
            if self.client_address[0] not in allow:
                return self._send(403, "forbidden")
            u = urllib.parse.urlsplit(self.path)
            try:
                if write:
                    n = int(self.headers.get("Content-Length") or 0)
                    if not 0 <= n <= MAX_BODY:
                        raise Refused("body too large")
                    body = json.loads(self.rfile.read(n) or b"{}")
                    if not isinstance(body, dict):
                        raise Refused("body must be a JSON object")
                    out = api_write(u.path, body)
                else:
                    q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
                    out = api_read(u.path, q)
                self._send(200, out)
                code = 200
            except (Refused, json.JSONDecodeError, ValueError) as e:
                self._send(400, str(e)); code = 400
            except SystemExit as e:  # find_series/show_row refuse with sys.exit(msg)
                self._send(400, str(e.code)); code = 400
            except Exception as e:  # don't leak internals; details go to the journal
                print("error", u.path, repr(e), file=sys.stderr); self._send(500, "internal error"); code = 500
            if write:
                print(f"write {u.path} -> {code}", file=sys.stderr, flush=True)

        def do_GET(self):
            self._handle(False)

        def do_POST(self):
            self._handle(True)

        def log_message(self, fmt, *args):
            pass

    HTTPServer((a.bind, a.port), H).serve_forever()

# ---------- selftest ----------
def _selftest_limits():
    """API limits against a temp DB, with Sonarr and systemctl faked."""
    import tempfile
    g = globals()
    saved = {k: g[k] for k in ("DB", "find_series")}
    real_run = subprocess.run
    try:
        g["DB"] = Path(tempfile.mkdtemp()) / "t.db"
        db().close()
        g["find_series"] = lambda name: {"id": int(name) if name.isdigit() else abs(hash(name)) % 10**6, "title": name}
        subprocess.run = lambda *a, **k: argparse.Namespace(returncode=0)
        def refused(path, body):
            try:
                api_write(path, body)
            except Refused:
                return True
            return False
        assert refused("/coverage/watch", {"show": "x", "terms": ["ok", "bad;rm -rf"]})       # term charset
        assert refused("/coverage/watch", {"show": "x", "terms": ["a", "b", "c", "d"]})       # too many terms
        assert refused("/coverage/watch", {"show": ""})                                        # no show
        assert refused("/coverage/nope", {"show": "x"})
        for i in range(MAX_SHOWS):
            api_write("/coverage/watch", {"show": str(i + 1), "terms": ["示例剧 第二季"]})
        assert refused("/coverage/watch", {"show": "999"})                                     # 11th show
        api_write("/coverage/watch", {"show": "1"})                                            # re-watch is fine
        assert json.loads(db().execute("select terms from shows where id=1").fetchone()[0]) == ["示例剧 第二季"]
        for _ in range(MAX_REFRESH_DAY):
            api_write("/coverage/refresh", {"show": "1"})
        assert refused("/coverage/refresh", {"show": "1"})                                     # 7th refresh
        n = MAX_CHANGES_DAY - MAX_SHOWS - 1
        for _ in range(n):
            api_write("/coverage/watch", {"show": "1"})
        assert refused("/coverage/unwatch", {"show": "1"})                                     # 21st change
        # exact match required for API writes: partial title must not unwatch or refresh
        g["DB"] = Path(tempfile.mkdtemp()) / "exact.db"
        db().close()
        ri = {"id": 42, "title": "Sample Immortal"}
        g["find_series"] = lambda name: ri if name in (ri["title"], str(ri["id"])) else sys.exit(f"unknown {name}")
        api_write("/coverage/watch", {"show": "Sample Immortal"})
        def write_refused(path, body):
            try:
                api_write(path, body)
            except (Refused, SystemExit):
                return True
            return False
        assert write_refused("/coverage/unwatch", {"show": "Sample"})
        assert write_refused("/coverage/refresh", {"show": "Sample"})
        with closing(db()) as c:
            assert [r["title"] for r in c.execute("select title from shows")] == ["Sample Immortal"]
        assert "removed Sample Immortal" in api_write("/coverage/unwatch", {"show": "Sample Immortal"})
        with closing(db()) as c:
            assert c.execute("select count(*) from shows").fetchone()[0] == 0
    finally:
        g.update(saved)
        subprocess.run = real_run

def _selftest_grab_basics():
    """pick ids, grab config defaults and the grabs/kv tables."""
    import tempfile
    g = globals()
    saved = {k: g[k] for k in ("DB", "config")}
    try:
        g["DB"] = Path(tempfile.mkdtemp()) / "g.db"
        g["config"] = lambda: {}
        r = {"site_id": 1, "guid": "g1", "title": "Example Show S01E05 1080p", "download_url": "http://localhost:9696/1/download?link=a",
             "site": "SiteA", "size": 2**30, "seeders": 5, "flags": "[]", "info_url": "http://x", "last_seen": time.time()}
        pid = pick_id(r)
        assert re.fullmatch(r"[0-9a-f]{10}", pid) and pick_id(dict(r)) == pid
        assert pick_id({**r, "title": "changed"}) != pid and pick_id({**r, "download_url": "http://localhost:9696/2/download"}) != pid
        assert f"pick {pid}" in fmt_rel(r, False)
        cfg = grab_cfg()
        assert cfg["grab_enabled"] is False and cfg["grab_category"] == "tv-sonarr"
        assert cfg["grab_max_eps_day"] == 30 and cfg["grab_max_bytes_day"] == 200_000_000_000
        g["config"] = lambda: {"grab_enabled": True, "grab_max_eps_day": 5}
        assert grab_cfg()["grab_enabled"] is True and grab_cfg()["grab_max_eps_day"] == 5 and grab_cfg()["grab_max_bytes_day"] == 200_000_000_000
        with closing(db()) as c:
            names = {x[0] for x in c.execute("select name from sqlite_master where type='table'")}
            assert {"grabs", "kv"} <= names
    finally:
        g.update(saved)

def _selftest_grab_request():
    """grab request API: eligibility, caps, limits. Sonarr layout faked, no network."""
    import tempfile
    g = globals()
    saved = {k: g[k] for k in ("DB", "config", "layout")}
    try:
        cfgd = {"grab_enabled": True}
        g["config"] = lambda: cfgd
        past = "2020-01-01T00:00:00Z"
        g["layout"] = lambda sid: [{"seasonNumber": 1, "episodeNumber": i, "airDateUtc": past, "hasFile": i <= 4}
                                   for i in range(1, 11)]
        now = time.time()
        def fresh():
            g["DB"] = Path(tempfile.mkdtemp()) / "r.db"
            with closing(db()) as c:
                c.execute("insert into sites(id, name) values(1, 'SiteA')")
                c.execute("insert into shows values(7, 'Example Show', '[\"Example Show\"]', ?)", (now,))
                c.commit()
        def seed(guid, title, size=10**9):
            with closing(db()) as c:
                c.execute("insert into releases values(?,?,?,?,?,?,?,?,?,?,?,?)",
                          (guid, 1, 7, title, size, 5, "[]", "", "http://x",
                           "http://localhost:9696/1/download?link=" + guid, now, now))
                c.commit()
        def pk(guid):
            with closing(db()) as c:
                return pick_id(c.execute("select * from releases where guid=?", (guid,)).fetchone())
        def filler(i, n, size, status, created=None):
            with closing(db()) as c:
                c.execute("insert into grabs values(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                          (i, 7, 9, "f" + i, "0" * 10, "[]", n, size, status, created or now, None, None, ""))
                c.commit()
        def refused(body):
            try:
                api_write("/coverage/grab", body)
            except Refused:
                return True
            return False
        def req(guid, show="7"):
            return api_write("/coverage/grab", {"show": show, "pick": pk(guid)})
        def status_of(i):
            with closing(db()) as c:
                return c.execute("select status from grabs where id=?", (i,)).fetchone()[0]

        fresh()
        seed("A", "[GrpB][动画][示例剧][Example Show][2023][03-06][GB][1080P]")   # covers 3-6; 3,4 owned -> fills 5,6
        seed("B", "Example Show S01E02 1080p")                                     # only an owned episode
        seed("C", "Example Show S01E07 1080p")
        seed("D", "Example Show S01E08 1080p")
        cfgd["grab_enabled"] = False
        assert refused({"show": "7", "pick": pk("A")})                              # disabled
        cfgd["grab_enabled"] = True
        assert refused({"show": "999", "pick": pk("A")})                            # not watched
        assert refused({"show": "7", "pick": "ZZ"}) and refused({"show": "7"})      # bad / missing pick
        assert refused({"show": "7", "pick": pk("A"), "url": "http://evil"})        # smuggled key
        old = pk("A")
        with closing(db()) as c:
            c.execute("update releases set title=title||' x' where guid='A'"); c.commit()
        assert refused({"show": "7", "pick": old})                                  # stale pick
        with closing(db()) as c:
            c.execute("update releases set title=substr(title,1,length(title)-2) where guid='A'"); c.commit()
        assert pk("A") == old
        assert refused({"show": "7", "pick": pk("B")})                              # nothing missing
        out = req("A")
        assert "Telegram" in out and "http" not in out
        with closing(db()) as c:
            row = c.execute("select * from grabs").fetchone()
            assert row["status"] == "pending" and row["n_eps"] == 2 and json.loads(row["eps"]) == [5, 6]
            assert c.execute("select count(*) from actions where kind='grab_req'").fetchone()[0] == 1
        assert refused({"show": "7", "pick": pk("A")})                              # same release twice
        with closing(db()) as c:
            c.execute("update grabs set status='denied'"); c.commit()
        req("A")                                                                    # denied -> may ask again
        shown = api_read("/coverage/grabs", {})
        assert "2/30 eps" in shown and "http" not in shown and "Example Show" in shown

        seed("Z0", "Example Show S01E10 1080p", 0)
        assert refused({"show": "7", "pick": pk("Z0")})                             # unknown size can't be capped
        with closing(db()) as c:
            c.execute("update releases set size=NULL where guid='Z0'"); c.commit()
        assert refused({"show": "7", "pick": pk("Z0")})
        # a failed request may be asked for again (transient failure), a pending/queued one may not
        with closing(db()) as c:
            c.execute("update grabs set status='failed'"); c.commit()
        req("A")
        with closing(db()) as c:
            c.execute("delete from grabs where status='failed'"); c.commit()
        # episode cap: 2 pending + filler 27 = 29 -> one more episode fits, two don't
        filler("f1", 27, 0, "pending")
        req("C")                                                                    # 30 of 30
        assert refused({"show": "7", "pick": pk("D")})                              # 31st episode
        with closing(db()) as c:
            c.execute("update grabs set status='denied' where id='f1'"); c.commit()
        req("D")                                                                    # freed share

        # byte cap
        fresh()
        seed("E", "Example Show S01E09 1080p", 2 * 10**9)
        seed("F", "Example Show S01E10 1080p", 10**9)
        filler("f2", 0, 199 * 10**9, "queued")
        assert refused({"show": "7", "pick": pk("E")})                              # 201 GB
        req("F")                                                                    # 200 GB exactly
        # rows older than 24 h fall out of the window
        fresh()
        seed("E", "Example Show S01E09 1080p", 2 * 10**9)
        filler("f3", 0, 199 * 10**9, "sent", created=now - 90000)
        req("E")

        # pending cap and request budget
        fresh()
        for i in range(5):
            filler(f"p{i}", 0, 0, "pending")
        seed("G", "Example Show S01E09 1080p")
        assert refused({"show": "7", "pick": pk("G")})                              # 6th pending
        with closing(db()) as c:
            c.execute("update grabs set status='expired' where id='p0'")
            c.commit()
        req("G")                                                                    # slot freed
        fresh()
        seed("G", "Example Show S01E09 1080p")
        with closing(db()) as c:
            for _ in range(20):
                c.execute("insert into actions values(?,?,?)", (now, "grab_req", "x"))
            c.commit()
        assert refused({"show": "7", "pick": pk("G")})                              # 21st request in 24 h

        # stale pending rows expire on the next request
        fresh()
        seed("G", "Example Show S01E09 1080p")
        filler("old", 0, 0, "pending", created=now - 2 * GRAB_TTL)
        req("G")
        assert status_of("old") == "expired"
    finally:
        g.update(saved)

def _selftest_grab_dispatch():
    """grab dispatch: URL validation, Prowlarr fetch, qBittorrent add. docker_curl/api/_key faked."""
    import tempfile
    g = globals()
    saved = {k: g[k] for k in ("DB", "config", "docker_curl", "api", "_key", "qb_port")}
    try:
        g["DB"] = Path(tempfile.mkdtemp()) / "d.db"
        g["config"] = lambda: {"grab_enabled": True, "grab_bot_token": "BOTTOKEN123"}
        g["_key"] = lambda ctr: "PROWLARRKEY"
        g["qb_port"] = lambda: "8080"
        calls, replies, listing = [], [], []
        def fake(ctr, args, stdin=None, timeout=90):
            calls.append((ctr, list(args), stdin))
            return replies.pop(0)
        g["docker_curl"] = fake
        g["api"] = lambda ctr, port, path, auth=True, timeout=150: listing
        good = "http://localhost:9696/3/download?link=abc&file=x"
        for bad in ("https://localhost:9696/3/download?link=a", "http://localhost:9697/3/download", "http://user@localhost:9696/3/download",
                    "http://localhost:9696/3/other", "http://evil.example/3/download", "http://localhost:9696/3/download?" + "a" * 2100, ""):
            try:
                check_download_url(bad)
                raise AssertionError("accepted " + bad[:40])
            except Refused:
                pass
        assert check_download_url(good) == good
        now = time.time()
        with closing(db()) as c:
            def seed(guid, url=good):
                c.execute("insert into releases values(?,?,?,?,?,?,?,?,?,?,?,?)", (guid, 1, 7, "t", 10**9, 5, "[]", "", "http://x", url, now, now))
                c.commit()
            torrent = b"d8:announce3:abc4:infod6:lengthi1eee\n\x00\xffbinary"
            magnet = "magnet:?xt=urn:btih:" + "a" * 40 + "&dn=Example"
            def run(guid, prowlarr, qb=None, url=good):
                seed(guid, url)
                calls.clear(); replies.clear()
                replies.append(prowlarr)
                if qb is not None:
                    replies.append(qb)
                return dispatch(c, {"site_id": 1, "guid": guid})
            # .torrent body -> uploaded from stdin, fixed fields, no savepath
            listing[:] = [{"name": "Example.S01E05", "added_on": now}]
            st, note = run("T1", (0, torrent + b"\n200 "), (0, b"Ok.\n200"))
            assert st == "queued" and "Example.S01E05" in note, (st, note)
            assert len(calls) == 2 and calls[0][0] == "prowlarr" and calls[1][0] == "qbittorrent"
            assert "PROWLARRKEY" in " ".join(calls[0][1]) and "--max-redirs" in calls[0][1] and "--max-filesize" in calls[0][1]
            q = calls[1][1]
            assert calls[1][2] == torrent and "torrents=@-;filename=x.torrent" in q and "category=tv-sonarr" in q
            assert not any("savepath" in a for a in q) and "PROWLARRKEY" not in " ".join(q) and "PROWLARRKEY" not in note
            # magnet redirect -> urls=, no stdin
            st, note = run("T2", (0, b"\n302 " + magnet.encode()), (0, b"Ok.\n200"))
            assert st == "queued" and calls[1][2] is None and "urls=" + magnet in calls[1][1]
            assert any(a == "--form-string" for a in calls[1][1])
            # not visible yet -> sent
            listing[:] = []
            st, _ = run("T3", (0, torrent + b"\n200 "), (0, b"Ok.\n200"))
            assert st == "sent"
            listing[:] = [{"name": "old", "added_on": now - 3600}]
            assert run("T3b", (0, torrent + b"\n200 "), (0, b"Ok.\n200"))[0] == "sent"
            # declared size in the file is checked against the listing and the daily cap
            listing[:] = [{"name": "n", "added_on": now}]
            big = b"d8:announce3:abc4:infod6:lengthi5000000000000eee"                 # 5 TB vs listed 1 GB
            st, note = run("S1", (0, big + b"\n200 "))
            assert st == "failed" and len(calls) == 1 and "bigger" in note, (st, note)
            multi = b"d4:infod5:filesld6:lengthi800000000eed6:lengthi800000000eeeee"  # 1.6 GB over two files vs listed 1 GB
            st, note = run("S2", (0, multi + b"\n200 "))
            assert st == "failed" and len(calls) == 1
            ok2 = b"d4:infod5:filesld6:lengthi300000000eed6:lengthi300000000eeeee"    # 0.6 GB: fine
            assert run("S3", (0, ok2 + b"\n200 "), (0, b"Ok.\n200"))[0] == "queued"
            st, note = run("S4", (0, b"d4:infoXe\n200 "))                            # not valid bencode
            assert st == "failed" and len(calls) == 1
            # anything else: failed, qBittorrent never called
            for i, rep in enumerate([(0, b"\n302 http://evil.example/x"), (0, b"<html>no</html>\n200 "), (0, b"\n200 "),
                                     (0, b"\n302 magnet:?xt=urn:btih:short"), (1, b""), (0, b"\n500 ")]):
                st, note = run(f"X{i}", rep)
                assert st == "failed" and len(calls) == 1 and "PROWLARRKEY" not in note, (i, st, note)
            # bad url in the DB row: no docker call at all
            st, _ = run("U1", (0, b""), url="http://evil.example/3/download")
            assert st == "failed" and calls == []
            # qBittorrent refuses
            st, note = run("Q1", (0, torrent + b"\n200 "), (0, b"Fails.\n200"))
            assert st == "failed"
            # missing row
            assert dispatch(c, {"site_id": 1, "guid": "nope"})[0] == "failed"
        assert "BOTTOKEN123" not in repr(calls)
    finally:
        g.update(saved)

def _selftest_grab_bot():
    """Telegram bot: announce, expire, taps, approval re-check. tg/dispatch faked."""
    import tempfile
    g = globals()
    saved = {k: g[k] for k in ("DB", "config", "layout", "tg", "dispatch")}
    try:
        cfgd = {"grab_enabled": True, "grab_bot_token": "BOTTOKEN123", "owner_user_id": 111, "owner_chat_id": 111}
        g["config"] = lambda: cfgd
        past = "2020-01-01T00:00:00Z"
        g["layout"] = lambda sid: [{"seasonNumber": 1, "episodeNumber": i, "airDateUtc": past, "hasFile": i <= 4} for i in range(1, 11)]
        now = time.time()
        sent = []
        def fake_tg(method, **params):
            sent.append((method, params))
            return {"message_id": 77} if method == "sendMessage" else {}
        g["tg"] = fake_tg
        dispatched = []
        def fake_dispatch(c, row):
            dispatched.append(row["guid"])
            return "queued", "queued: Example"
        g["dispatch"] = fake_dispatch
        HOSTILE = "\x1b[31m\u202e[GrpB][动画][示例剧][Example Show][2023][03-06][GB][1080P]" + " ZZZ" * 1500
        def fresh():
            g["DB"] = Path(tempfile.mkdtemp()) / "b.db"
            sent.clear(); dispatched.clear(); cfgd["grab_enabled"] = True
            with closing(db()) as c:
                c.execute("insert into sites(id, name) values(1, 'SiteA')")
                c.execute("insert into shows values(7, 'Example Show', '[\"Example Show\"]', ?)", (now,))
                c.commit()
        def seed(guid, title, size=10**9):
            with closing(db()) as c:
                c.execute("insert into releases values(?,?,?,?,?,?,?,?,?,?,?,?)",
                          (guid, 1, 7, title, size, 5, "[]", "", "http://x", "http://localhost:9696/1/download?link=" + guid, now, now))
                c.commit()
        def request(guid):
            with closing(db()) as c:
                r = c.execute("select * from releases where guid=?", (guid,)).fetchone()
                grab_request(c, "7", pick_id(r))
                return c.execute("select id from grabs order by created desc limit 1").fetchone()[0]
        def row(gid):
            with closing(db()) as c:
                return dict(c.execute("select * from grabs where id=?", (gid,)).fetchone())
        def tap(gid, act="a", user=111):
            with closing(db()) as c:
                handle_callback(c, {"id": "cb1", "from": {"id": user}, "data": f"{act}:{gid}"})
        def methods():
            return [m for m, _ in sent]

        # announce: plain text, bounded title, one keyboard, sent once
        fresh()
        seed("A", HOSTILE)
        gid = request("A")
        with closing(db()) as c:
            announce(c)
            announce(c)
        assert methods() == ["sendMessage"], methods()
        p = sent[0][1]
        assert p["chat_id"] == 111 and "parse_mode" not in p
        assert not re.search(r"[\x00-\x1f\x7f-\x9f\u202a-\u202e]", p["text"].replace("\n", " "))
        assert max(len(x) for x in p["text"].split("\n")) < 400 and "Example Show" in p["text"] and "5, 6" not in p["text"] and "5-6" in p["text"]
        btn = [b["callback_data"] for b in p["reply_markup"]["inline_keyboard"][0]]
        assert btn == [f"a:{gid}", f"d:{gid}"] and all(len(b.encode()) <= 64 for b in btn)
        assert row(gid)["msg_id"] == 77
        # expire: a 31-minute-old pending row is expired and its message edited once
        with closing(db()) as c:
            c.execute("update grabs set created=? where id=?", (now - 1860, gid)); c.commit()
            sent.clear(); expire(c); expire(c)
        assert row(gid)["status"] == "expired" and methods() == ["editMessageText"], methods()
        sent.clear(); tap(gid)                                        # tap after expiry: nothing dispatched
        assert dispatched == [] and row(gid)["status"] == "expired"

        # taps
        fresh(); seed("A", "[GrpB][动画][示例剧][Example Show][2023][03-06][GB][1080P]")
        gid = request("A")
        with closing(db()) as c:
            announce(c)
        sent.clear()
        tap(gid, user=222); tap(gid, "d", user=222)                   # someone else: ignored, silent
        assert row(gid)["status"] == "pending" and sent == [] and dispatched == []
        tap(gid); tap(gid)                                            # owner approves, second tap is a no-op
        assert dispatched == ["A"] and row(gid)["status"] == "queued" and "queued" in row(gid)["note"]
        assert "editMessageText" in methods() and "answerCallbackQuery" in methods()
        fresh(); seed("A", "[GrpB][动画][示例剧][Example Show][2023][03-06][GB][1080P]")
        gid = request("A"); tap(gid, "d")
        assert row(gid)["status"] == "denied" and dispatched == []
        tap(gid, "a"); assert dispatched == []                        # approve after deny: nothing

        # approval re-checks everything on fresh data
        for what in ("unwatched", "changed", "cap", "disabled"):
            fresh(); seed("A", "[GrpB][动画][示例剧][Example Show][2023][03-06][GB][1080P]")
            gid = request("A")
            with closing(db()) as c:
                if what == "unwatched":
                    c.execute("delete from shows")
                elif what == "changed":
                    c.execute("update releases set title=title||' v2'")
                elif what == "cap":
                    c.execute("insert into grabs values('big',7,9,'z','0000000000','[]',29,0,'queued',?,NULL,NULL,'')", (now,))
                c.commit()
            if what == "disabled":
                cfgd["grab_enabled"] = False
            tap(gid)
            assert dispatched == [] and row(gid)["status"] == "failed" and row(gid)["note"], (what, row(gid))
            cfgd["grab_enabled"] = True

        # dispatch blows up: row stays approved, loop-safe, never dispatched twice
        fresh(); seed("A", "[GrpB][动画][示例剧][Example Show][2023][03-06][GB][1080P]")
        gid = request("A")
        def boom(c, r):
            dispatched.append("boom")
            raise RuntimeError("docker died")
        g["dispatch"] = boom
        tap(gid)
        assert row(gid)["status"] == "approved" and "unknown" in row(gid)["note"] and dispatched == ["boom"]
        tap(gid)
        assert dispatched == ["boom"]
        g["dispatch"] = fake_dispatch

        # no owner configured -> every tap is ignored
        fresh(); seed("A", "[GrpB][动画][示例剧][Example Show][2023][03-06][GB][1080P]")
        gid = request("A"); cfgd["owner_user_id"] = None
        tap(gid, user=None)
        assert dispatched == [] and row(gid)["status"] == "pending"
        cfgd["owner_user_id"] = 111

        # the token never lands in the db and never in an error text
        with closing(db()) as c:
            assert "BOTTOKEN123" not in repr(c.execute("select * from grabs").fetchall()) + repr(c.execute("select * from actions").fetchall())
        import urllib.error, urllib.request
        real_open = urllib.request.urlopen
        def failing(req, timeout=None):
            raise urllib.error.URLError("boom " + req.full_url)
        urllib.request.urlopen = failing
        g["tg"] = saved["tg"]
        try:
            tg("getMe")
            raise AssertionError("tg should raise")
        except RuntimeError as e:
            assert "BOTTOKEN123" not in str(e) and "getMe" in str(e)
        finally:
            urllib.request.urlopen = real_open
        assert clean("a\x1bb\u202ec" + "x" * 500) == "a b c" + "x" * 195
        assert clean("a\u200bb\u2028c\u061cd\ufeffe\u2029f") == "a b c d e f"
    finally:
        g.update(saved)

def _selftest_grab_cli():
    """`bot` refuses to start without its keys and never echoes the token; `grab` needs show and pick."""
    import io, contextlib
    g = globals()
    saved = {k: g[k] for k in ("config", "cmd_bot")}
    argv = sys.argv
    try:
        started = []
        g["cmd_bot"] = lambda a, c: started.append(1)
        g["config"] = lambda: {"grab_enabled": True, "grab_bot_token": "BOTTOKEN123"}
        sys.argv = ["coverage.py", "bot"]
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                main()
            raise AssertionError("bot started without owner ids")
        except SystemExit as e:
            assert e.code != 0
        assert "owner_user_id" in err.getvalue() and "BOTTOKEN123" not in err.getvalue() and not started
        g["config"] = lambda: {"grab_bot_token": "BOTTOKEN123", "owner_user_id": 1, "owner_chat_id": 1}
        main()
        assert started == [1]
        sys.argv = ["coverage.py", "grab", "Example Show"]               # pick missing
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                main()
            raise AssertionError("grab ran without a pick")
        except SystemExit as e:
            assert e.code != 0
    finally:
        sys.argv = argv
        g.update(saved)

def selftest():
    L = {1: 26, 2: 36, 3: 36}
    cases = {
        "Example Show 2023 S01E103 2160p WEB-DL HQ H265 10bit AAC-GRP": {103},
        "Example Show 2023 S01E05 1080p WEB-DL H264 AAC-GRP": {5},
        "Example Show 2024 S02 2160p WEB-DL H.265 HQ 10bit DTS-HD7.1-GRP2": set(range(27, 63)),
        "Example Show S02E03 1080p": {29},
        "Example Show S02E40 1080p": {40},
        "[GrpB][动画][示例剧 第3季][Example Show Ⅲ][2026][31-34][GB][4K HEVC 10Bit]": set(range(93, 97)),
        "[GrpB][动画][示例剧][Example Show][2023][01-26][GB][1080P]": set(range(1, 27)),
        "示例剧 第57集 4K": {57},
        "示例剧 第二季 全36集": set(range(27, 63)),
        "[GrpC] Example Show - 12 (1080p)": {12},
        "Example Show EP88 2160p": {88},
        "示例剧 Example Show 2023 complete": None,
        "Example Show S01-S03 2160p WEB-DL": set(range(1, 99)),
        "Example Show II [05][1080P]": {31},
        "[示例剧][番外][01][2160]": None,
        "Example Show S00E03 1080p": None,
        "[示例剧][2160][07]": {7},
    }
    assert "apikey" not in strip_key("http://p:9696/1/download?apikey=abc&link=x") and strip_key(None) == ""
    bad = [(t, parse(t, L), want) for t, want in cases.items() if parse(t, L) != want]
    for t, got, want in bad:
        print(f"FAIL {t}\n  got  {got}\n  want {want}")
    assert relevant("示例剧 第57集", ["示例剧"]) and relevant("ExampleShow S01", ["Example Show"])
    assert not relevant("Example Saga S01", ["Example Show"])
    assert not relevant("Example Show's Romance S01 2025 2160p", ["Example Show"])
    assert relevant("示例剧.Example.Show.S01E01.2023.1080p", ["Example Show"])
    assert rng({1, 2, 3, 5, 7, 8}) == "1-3,5,7-8"
    real_config = globals()["config"]
    globals()["config"] = lambda: {"sub_groups": {"ALPHA": "hard-chs"}}   # never read the live config
    try:
        assert subs("[GrpB][动画][示例剧][Example Show][2023][12][GB][4K HEVC 10Bit]") == "chs"
        assert subs("[GrpA] Sample Blade / 示例刀 - 24 [1080P][Baha][WEB-DL][AAC AVC][CHT][MP4]") == "hard-cht"
        assert subs("[GrpD] 示例剧 [内嵌简繁][1080P]") == "hard-chs+cht"
        assert subs("Example Show 2023 S01E97 2160p WEB-DL H265 AAC-GRP") == "?"
        assert subs("Example Show S01 2023 2160p WEB-DL H265 AAC-ALPHA") == "hard-chs"
        assert subs("Show.S01E01.2160p.WEB-DL.H265-ALPHA.mkv") == "hard-chs"
        assert subs("Example Show S01 2023 2160p WEB-DL H265 AAC-GRP") == "?"
        assert subs("[GrpD] 示例剧 [内嵌简繁][1080P] -ALPHA") == "hard-chs+cht"   # title tags win
    finally:
        globals()["config"] = real_config
    _selftest_limits()
    _selftest_grab_basics()
    _selftest_grab_request()
    _selftest_grab_dispatch()
    _selftest_grab_bot()
    _selftest_grab_cli()
    sys.exit(1 if bad else print("selftest ok") or 0)

def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sp = p.add_subparsers(dest="cmd", required=True)
    w = sp.add_parser("watch"); w.add_argument("action", choices=["add", "remove", "list"])
    w.add_argument("show", nargs="?"); w.add_argument("--term", action="append", help="search term, repeatable")
    s = sp.add_parser("sites", help="'sites add' with no names adds the default shortlist")
    s.add_argument("action", choices=["add", "remove", "list"]); s.add_argument("names", nargs="*")
    r = sp.add_parser("refresh"); r.add_argument("--show"); r.add_argument("--force", action="store_true")
    q = sp.add_parser("query"); q.add_argument("what", choices=["missing", "site", "gaps", "unclear"])
    q.add_argument("show"); q.add_argument("site", nargs="?")
    q.add_argument("--download-links", action="store_true", help="also print Prowlarr download links (LAN only, embed a key)")
    sp.add_parser("seeding"); sp.add_parser("selftest")
    gr = sp.add_parser("grab", help="ask for a release to be fetched; the owner approves in Telegram")
    gr.add_argument("show"); gr.add_argument("pick")
    sp.add_parser("bot", help="Telegram approval bot for grab requests (long-running)")
    sv = sp.add_parser("serve", help="HTTP API for Hermes, behind the read-only proxy")
    sv.add_argument("--bind"); sv.add_argument("--port", type=int)
    sv.add_argument("--allow", action="append", default=[], help="client IP allowed (repeatable); default: config.json")
    a = p.parse_args()
    if a.cmd == "selftest":
        return selftest()
    if a.cmd == "watch" and a.action != "list" and not a.show:
        p.error("watch add/remove needs a show")
    if a.cmd == "query" and a.what in ("site", "gaps") and not a.site:
        p.error(f"query {a.what} needs a site")
    if a.cmd == "bot":
        cf = config()
        missing = [k for k in ("grab_bot_token", "owner_user_id", "owner_chat_id") if not cf.get(k)]
        if missing:   # fail closed; names only, never values
            p.error(f"bot needs {', '.join(missing)} in {CONFIG}")
        db().close()
        return cmd_bot(a, None)
    if a.cmd == "grab":
        try:
            with closing(db()) as c:
                print(grab_request(c, a.show, a.pick))
        except Refused as e:
            sys.exit(f"refused: {e}")
        return
    if a.cmd == "serve":
        cf = config()
        a.bind, a.port = a.bind or cf.get("bind"), a.port or cf.get("port")
        a.allow = a.allow or cf.get("allow", [])
        if not (a.bind and a.port and a.allow):   # fail closed: never listen open by accident
            p.error(f"serve needs bind, port and allow (flags or {CONFIG})")
        db().close()            # make sure the schema exists before read-only opens
        return cmd_serve(a, None)
    {"watch": cmd_watch, "sites": cmd_sites, "refresh": cmd_refresh,
     "query": cmd_query, "seeding": cmd_seeding}[a.cmd](a, db())

if __name__ == "__main__":
    main()
