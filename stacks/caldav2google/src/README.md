# caldav2google — Nextcloud ➜ Google Calendar (one-way)

One-way mirror of a **Nextcloud** calendar into a dedicated **Google** calendar,
running as a small scheduled container on the Portainer Docker host (CT111).
Adds/updates/deletes flow Nextcloud → Google only.

```
[Nextcloud CT112] --CalDAV/app-pw--> [Caddy CT104, valid TLS] --reverse_proxy-->
[caldav2google @ CT111, every 10 min] --HTTPS--> [Google: "Nextcloud" calendar]
```

- **Source:** [`rogsme/caldav2google`](https://github.com/rogsme/caldav2google), pinned in the `Dockerfile`.
- **Auth:** reuses **Hermes's Google OAuth client** (same GCP project) but with its
  **own** freshly-minted, calendar-scope-only token (`token.json`).
- **Why through Caddy:** the `caldav` lib verifies TLS, so we hit
  `nextcloud.ahlooii.com` (valid `*.ahlooii.com` cert) and pin it to Caddy via
  `extra_hosts` instead of the bare LXC IP.

---

## One-time setup

### 1. Get the OAuth client → `credentials.json`
Same client Hermes already uses. Easiest source is the **GCP Console**
(no need to touch the ARM): APIs & Services → Credentials → the existing
**Desktop** OAuth client → **Download JSON** → save as `credentials.json`.
> Make sure the OAuth consent screen is **"In production"** (not "Testing") so
> the token doesn't expire after 7 days. It almost certainly already is, since
> Hermes runs on this client continuously.

### 2. Create the destination Google calendar
In Google Calendar, create a calendar named **`Nextcloud`** (or whatever you set
as `GOOGLE_CALENDAR_NAME`). A dedicated calendar keeps this mirror isolated.

### 3. Create a Nextcloud app password
Nextcloud → Settings → Security → Devices & sessions → create app password.
Note the username + password.

### 4. Mint `token.json` (on your Mac — needs a browser)
```bash
cd /Users/mba-m1/homelab/caldav2google   # dir containing credentials.json
cp /path/to/downloaded/credentials.json .
python3 -m venv .venv && . .venv/bin/activate
pip install "google-auth-oauthlib>=1.2,<2"
python3 mint-token.py        # browser opens → approve the Calendar scope
```
This writes `token.json`. (Uses the same scope as the tool:
`https://www.googleapis.com/auth/calendar`.)

---

## Deploy (on CT111)

The stack lives at `/opt/caldav2google`. Put credentials + config in place:

```bash
# token.json goes in the data volume (credentials.json is NOT needed at runtime)
#   /opt/caldav2google/data/token.json
# config + secrets:
cp secrets.env.example secrets.env   # then edit: username, app password, calendar names
```

Bring it up:
```bash
cd /opt/caldav2google
docker compose up -d --build
docker compose logs -f          # watch the first sync
```

A healthy first run logs: authenticated → found Google calendar → connected to
CalDAV → "Retrieved N events" → "Adding N new events" → "sync OK".

---

## How it works
- The container loops: `python src/main.py` every `SYNC_INTERVAL` seconds
  (default 600 = 10 min), set in `docker-compose.yml`.
- State lives in `data/calendar_sync.json` (UID → Google event id), so it only
  touches events it created and detects changes/deletes incrementally.
- Token auto-refreshes and is rewritten to `data/token.json`.

## Files
| File | Purpose |
|------|---------|
| `Dockerfile` | Vendors upstream at a pinned commit + deps + the token.json patch |
| `auth_google.py` | Patched: portable `token.json` instead of `token.pickle` |
| `entrypoint.sh` | The sync loop (+ optional Uptime Kuma push) |
| `docker-compose.yml` | Service def, `extra_hosts` → Caddy, data volume |
| `secrets.env(.example)` | CalDAV URL/user/app-pw + calendar names |
| `mint-token.py` | Run on a browser machine to mint `token.json` |
| `data/` | `token.json` + auto-managed `calendar_sync.json` (gitignored) |

## Troubleshooting
- **`No calendar named 'X' found`** — `CALDAV_CALENDAR_NAME` / `GOOGLE_CALENDAR_NAME`
  must match the calendar's display name (case-insensitive). List Nextcloud
  calendar names if unsure.
- **TLS / connection errors to Nextcloud** — confirm the `extra_hosts` line and
  that `nextcloud.ahlooii.com` is served by Caddy. Test from CT111:
  `curl -so /dev/null -w '%{http_code}\n' --resolve nextcloud.ahlooii.com:443:192.168.9.155 https://nextcloud.ahlooii.com/remote.php/dav/` → expect `401`.
- **Principal discovery fails** — set `CALDAV_URL` to the explicit principal:
  `https://nextcloud.ahlooii.com/remote.php/dav/principals/users/<USERNAME>/`.
- **Browser flow triggered in container** (you'll see it hang) — means
  `token.json` is missing/invalid in `data/`. Re-mint and copy it in.

## Appendix — reuse Hermes's *exact* token instead
Because the patch uses authorized_user JSON, Hermes's own
`~/.hermes/google_token.json` is drop-in: copy it to `data/token.json`. (We chose
a separate token for independent fate, but this is the fallback.)
