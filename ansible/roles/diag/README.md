# Diag service safety contracts

This role currently contains the standalone service and local tests, not a live
installation. App route audits and live canary acceptance are required before
exposing it.

## Secret-inventory readiness

App reads are refused (503, without contacting the upstream) until that app's
own secret sources have been harvested once since the process started. Cached
tracker values are loaded at start but never make an app ready on their own;
provider inventories are re-read after every restart.

- **Per app.** Sonarr, Radarr and Prowlarr are ready when all of their provider
  endpoints were read and parsed (this collects only fields returned in clear,
  such as Cardigann cookie/passkey fields: these apps return their own
  `apiKey`/`password` fields as asterisks, so those credentials are never
  learned; the entropy layer covers them); each qBittorrent when every torrent not seen
  before has had its trackers read; qui when both qBittorrents are ready (it
  shows their tracker URLs); Jellyfin needs no harvest. One broken app does not
  block reads of the others.
- **Never withdrawn.** Learned secrets are never removed, so a running or failed
  refresh cannot weaken redaction. Refreshes run every 30 minutes, or every
  60 seconds after a failure.
- **Cold start.** The first read waits up to 30 seconds for the harvest instead
  of failing at once (30 s + the 20 s upstream budget stays under nginx's 60 s).
  It returns 503 early if the first harvest cycle finished without that app.
  Cached torrents whose 30-minute freshness expired are refreshed after the app
  is marked ready; their old values are already known. A passkey rotated while
  the CT was stopped is unknown until that refresh, but tracker URLs (values and
  `sync/maindata` keys alike) are cut to `scheme://host/` and a random-looking
  token in free text is masked by the entropy layer. Waiting for a full refresh
  instead would make most cold starts after 30 minutes idle return 503.
- A torrent removed between the torrent list and its tracker read (404) is
  skipped.

`/diag/` lists `apps` and the subset that is `ready`.

## Redaction layers

Applied to every JSON string, values and dictionary keys alike (qBittorrent's
`sync/maindata` uses tracker URLs as keys; keys that clean to the same text get
a ` (2)` suffix):

1. URL cleanup: any http/https/udp URL with a path, query or userinfo becomes
   `scheme://host[:port]/[path removed]`.
2. Exact values: every harvested or configured secret, raw and in URL-encoded,
   base64, hex and JSON-escaped forms.
3. Field names: values under keys matching `FIELD_RE` (and Servarr
   `{"name": ..., "value": ...}` pairs) become `[REDACTED]`.
4. Entropy: a token of 16+ characters from `[A-Za-z0-9+=]` that has both
   letters and digits and at least 3.3 bits of entropy per character becomes
   `[REDACTED:entropy]`. Exempt: 40/64-hex torrent hashes everywhere, 32-hex
   IDs in Jellyfin responses only. This catches credentials diag never learned
   (masked Servarr fields, a passkey rotated since the last harvest, a token in
   an error message). Cost: a long random-looking token in a release name or
   message is masked too. The log line counts each layer.

Then the tripwire scans the final text (Jellyfin skips `hex-key`, below).

Readiness means the configured sources were collected, not that arbitrary free
text is secret-free. Secrets introduced between harvests (including a passkey
rotated while the CT was stopped, until its refresh), secrets shorter than the
configured minimum, secrets absent from all configured sources, and unrecognized
encodings remain limitations of this design. Live canary tests and the
pinned-version GET route audit remain mandatory.

## GET route audit (2026-11-26, pinned versions)

Every GET under an allowed prefix was listed from source and checked for side
effects, secrets and file bodies: Sonarr 4.0.20.3014, Radarr 6.4.4.10685,
Prowlarr 2.7.0.5723, qBittorrent 5.1.4, Jellyfin 12.4, qui v1.36.1.

- **Sonarr, Radarr:** no state-changing GET outside the existing deny list.
  `series/lookup`, `movie/lookup` and Radarr `importlist/movie` call metadata
  services (Skyhook, TMDB) only; allowed.
- **Prowlarr:** only the `newznab`/`download` routes below.
- **qBittorrent:** every action outside `webapplication.h`'s POST-only list also
  answers GET. Added to the deny list: `app/cookies`, `app/getDirectoryContent`,
  `search/*` (`downloadTorrent` fetches), `torrentcreator/*`,
  `torrents/SSLParameters`.
- **Sonarr, Radarr (Codex review):** `manualimport?folder=` scans any folder
  recursively; denied.
- **Jellyfin:** added `Items/{id}/RemoteImages` and `Items/{id}/RemoteSearch`
  (outside providers, OpenSubtitles limits); `/Packages` removed from the
  allowlist (fetches repository manifests from the internet on every call). `/Devices` returns each device's
  `AccessToken`; field-name masking removes it (tested).
- **qui:** see the qui section.

Re-run when any pinned version changes.

## Prowlarr tracker side effects

Prowlarr 2.7.0.5723's `NewznabController` exposes GET
`/api/v1/indexer/{id}/newznab` and `/api/v1/indexer/{id}/download`. Both are
blocked before any upstream request, including mixed-case paths, trailing
slashes and descendants. The former can search trackers and the latter can
download reports or record redirects. The JSON-only response filter is not a
side-effect boundary. This closes those routes; it is not a claim that every
remaining GET in every upstream version has been audited.

## Qui (v1.36.1) and its API key

CT 118 runs qui v1.36.1. Since that version every API route needs a per-key
permission (`documentation/docs/api/permissions.md`, ADR 0040). **Create a new
key for diag** with exactly these permissions and no instance limit:

- `Instances: read`
- `Torrents: read` (without `Torrents: write`, qui itself hides the passkey in
  tracker URLs)
- `Settings: read` (needed for `GET /api/client-settings`)
- `System: read`

Do not reuse a key created before the upgrade: migration 111 gave every older
key every permission, including all `write` levels.

Diag allows `/api/instances`, `/api/version` and the exact
`/api/client-settings` path. `client-settings` is registered with
`settings.Read` (`internal/api/server.go:612`) and returns the stored key-value
map, including `qui-incognito-mode` (`web/src/lib/client-settings.ts`). PUT is
refused locally and by the key. Paths containing `export`, `backup`, `api-keys`,
`apikeys`, `auth`, `logs`, `download`, `getdirectorycontent`, `free-space` or
`mediainfo` are refused before qui is contacted: `download` keeps torrent
content files (allowed by `Torrents: read`) from being pulled through diag, and
the other three touch the disk at a caller-chosen path with only
`Instances: read`/`Torrents: read`.

Not verified from source: that qui hides passkeys without `Torrents: write`
comes from qui's permissions doc, not from reading the handlers. The canary test
(plan Task 8) must confirm it; the URL and entropy layers apply regardless. qui's `/health` sits outside `/api` and is not exposed;
use homelab-metrics for "is it up".

## Jellyfin and the hex-key tripwire

Jellyfin item and server IDs, Etags, image tags, media source IDs and trickplay
keys are all 32-hex strings, so the global `hex-key` tripwire would block most
Jellyfin reads (including `/Sessions` during playback). That one rule is skipped
for Jellyfin only. Diag's own Jellyfin API key is still removed by exact-value
redaction (`header_secrets()` unwraps it from the `MediaBrowser Token="…"`
header), `AccessToken` fields are masked by name, and every other tripwire
rule still applies. `hex-key` stays active for all other apps.

## Overall upstream deadline

One monotonic 20-second budget covers connection, request transmission, response
headers, chunk framing and body reading. The HTTP reader recomputes the remaining
socket timeout on each receive; a peer cannot extend the budget by trickling
bytes. Budget exhaustion returns the fixed upstream-unreachable error, and both
connection and response descriptors are closed. No global signal or background
fetch worker is left running after a timeout.

The transport now accepts **127.0.0.1 HTTP bases only**. Dedicated stunnel clients
and colocated server terminators carry all network hops using pinned mutual TLS;
HTTP never leaves the endpoint's local network namespace. See the
[maintenance runbook](../../../../docs/diag-security.md).
Hostnames, non-loopback IPv4, userinfo and base paths/queries/fragments fail
closed. Redirects are not followed and environment proxies are ignored. The
existing monotonic budget includes tunnel connection/handshake waits because
every request send/read still crosses its deadline-bounded loopback socket.
