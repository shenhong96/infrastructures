#!/usr/bin/env python3
"""Episode coverage: which Prowlarr site has which episodes of watched shows.

Runs on the vpn host. Talks to prowlarr/sonarr/qbittorrent via `docker exec <ctr> curl`
on localhost; API keys are read from each app's config at run time and never stored.
`query` / `seeding` never touch a site; only `refresh` searches, slowly.
"""
import argparse, fcntl, json, random, re, sqlite3, subprocess, sys, time, urllib.parse
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
    """Title contains a term, not as the start of a longer name ('The Demon Hunter's Romance')."""
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

def fmt_rel(r, dl):
    flags = ",".join(json.loads(r["flags"] or "[]"))
    days = int((time.time() - r["last_seen"]) / 86400)   # old pages aren't re-read, so seeders/flags age
    old = f" (as of {days}d ago)" if days >= 2 else ""
    line = f"{r['site']}: {r['title']} | subs {subs(r['title'])} | {(r['size'] or 0) / 2**30:.1f}G seed {r['seeders']}{' ' + flags if flags else ''}{old}\n      {r['info_url']}"
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
            api_write("/coverage/watch", {"show": str(i + 1), "terms": ["沧元图 第二季"]})
        assert refused("/coverage/watch", {"show": "999"})                                     # 11th show
        api_write("/coverage/watch", {"show": "1"})                                            # re-watch is fine
        assert json.loads(db().execute("select terms from shows where id=1").fetchone()[0]) == ["沧元图 第二季"]
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
        ri = {"id": 42, "title": "Renegade Immortal"}
        g["find_series"] = lambda name: ri if name in (ri["title"], str(ri["id"])) else sys.exit(f"unknown {name}")
        api_write("/coverage/watch", {"show": "Renegade Immortal"})
        def write_refused(path, body):
            try:
                api_write(path, body)
            except (Refused, SystemExit):
                return True
            return False
        assert write_refused("/coverage/unwatch", {"show": "Renegade"})
        assert write_refused("/coverage/refresh", {"show": "Renegade"})
        with closing(db()) as c:
            assert [r["title"] for r in c.execute("select title from shows")] == ["Renegade Immortal"]
        assert "removed Renegade Immortal" in api_write("/coverage/unwatch", {"show": "Renegade Immortal"})
        with closing(db()) as c:
            assert c.execute("select count(*) from shows").fetchone()[0] == 0
    finally:
        g.update(saved)
        subprocess.run = real_run

def selftest():
    L = {1: 26, 2: 36, 3: 36}
    cases = {
        "The Demon Hunter 2023 S01E103 2160p WEB-DL HQ H265 10bit AAC-GRP": {103},
        "The Demon Hunter 2023 S01E05 1080p WEB-DL H264 AAC-GRP": {5},
        "The Demon Hunter 2024 S02 2160p WEB-DL H.265 HQ 10bit DTS-HD7.1-AilMWe": set(range(27, 63)),
        "The Demon Hunter S02E03 1080p": {29},
        "The Demon Hunter S02E40 1080p": {40},
        "[GM-Team][国漫][沧元图 第3季][The Demon Hunter Ⅲ][2026][31-34][GB][4K HEVC 10Bit]": set(range(93, 97)),
        "[GM-Team][国漫][沧元图][The Demon Hunter][2023][01-26][GB][1080P]": set(range(1, 27)),
        "沧元图 第57集 4K": {57},
        "沧元图 第二季 全36集": set(range(27, 63)),
        "[SubsPlease] The Demon Hunter - 12 (1080p)": {12},
        "The Demon Hunter EP88 2160p": {88},
        "沧元图 The Demon Hunter 2023 complete": None,
        "The Demon Hunter S01-S03 2160p WEB-DL": set(range(1, 99)),
        "The Demon Hunter II [05][1080P]": {31},
        "[沧元图][番外][01][2160]": None,
        "The Demon Hunter S00E03 1080p": None,
        "[沧元图][2160][07]": {7},
    }
    assert "apikey" not in strip_key("http://p:9696/1/download?apikey=abc&link=x") and strip_key(None) == ""
    bad = [(t, parse(t, L), want) for t, want in cases.items() if parse(t, L) != want]
    for t, got, want in bad:
        print(f"FAIL {t}\n  got  {got}\n  want {want}")
    assert relevant("沧元图 第57集", ["沧元图"]) and relevant("The DemonHunter S01", ["The Demon Hunter"])
    assert not relevant("Demon Slayer S01", ["The Demon Hunter"])
    assert not relevant("The Demon Hunter's Romance S01 2025 2160p", ["The Demon Hunter"])
    assert relevant("沧元图.The.Demon.Hunter.S01E01.2023.1080p", ["The Demon Hunter"])
    assert rng({1, 2, 3, 5, 7, 8}) == "1-3,5,7-8"
    real_config = globals()["config"]
    globals()["config"] = lambda: {"sub_groups": {"ALPHA": "hard-chs"}}   # never read the live config
    try:
        assert subs("[GM-Team][国漫][沧元图][The Demon Hunter][2023][12][GB][4K HEVC 10Bit]") == "chs"
        assert subs("[ANi] Sword of the Demon Hunter / 鬼人幻燈抄 - 24 [1080P][Baha][WEB-DL][AAC AVC][CHT][MP4]") == "hard-cht"
        assert subs("[XK] 沧元图 [内嵌简繁][1080P]") == "hard-chs+cht"
        assert subs("The Demon Hunter 2023 S01E97 2160p WEB-DL H265 AAC-GRP") == "?"
        assert subs("The Demon Hunter S01 2023 2160p WEB-DL H265 AAC-ALPHA") == "hard-chs"
        assert subs("Show.S01E01.2160p.WEB-DL.H265-ALPHA.mkv") == "hard-chs"
        assert subs("The Demon Hunter S01 2023 2160p WEB-DL H265 AAC-GRP") == "?"
        assert subs("[XK] 沧元图 [内嵌简繁][1080P] -ALPHA") == "hard-chs+cht"   # title tags win
    finally:
        globals()["config"] = real_config
    _selftest_limits()
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
