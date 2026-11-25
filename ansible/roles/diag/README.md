# Diag service safety contracts

This role currently contains the standalone service and local tests, not a live
installation. App route audits and live canary acceptance are required before
exposing it.

## Secret-inventory readiness

The app list at `/diag/` is available during startup and includes
`redaction_ready`. All app reads return 503 without contacting an upstream until
one harvest has completed successfully for every configured provider endpoint
and every torrent not covered by a fresh tracker-cache entry. Cache entries
preserve tracker progress, but never authorize startup by themselves: provider
inventories must be read again after every process restart.

Readiness is withdrawn while refreshing, after any failed/malformed inventory,
or when the last successful snapshot expires (30 minutes). Failures retry after
60 seconds. Requests crossing a refresh generation are withheld even if the
refresh finishes before the upstream request does. Secrets already learned are
retained, including on partial failures and credential rotations.

This intentionally trades cold-start availability for fail-closed redaction.
The roughly 3-second CT boot measurement does **not** establish app-read readiness:
a first full tracker harvest may take much longer. Clients must handle 503 and
retry; a successful app-list response is not a successful app-read acceptance
check. A supported upstream version must expose every configured harvest path;
an unsupported path is a blocking configuration/audit problem, not permission to
skip that source.

Readiness establishes that the configured sources were collected, not that
arbitrary free text is secret-free. Secrets introduced between harvests, secrets
shorter than the configured minimum, secrets absent from all configured sources,
and unrecognized encodings remain limitations of this design. Live canary tests
and the pinned-version GET route audit remain mandatory.

## Prowlarr tracker side effects

Prowlarr 2.7.0.5723's `NewznabController` exposes GET
`/api/v1/indexer/{id}/newznab` and `/api/v1/indexer/{id}/download`. Both are
blocked before any upstream request, including mixed-case paths, trailing
slashes and descendants. The former can search trackers and the latter can
download reports or record redirects. The JSON-only response filter is not a
side-effect boundary. This closes those routes; it is not a claim that every
remaining GET in every upstream version has been audited.

## Qui client settings

Only the exact `/api/client-settings` path is additionally allowed for qui.
In pinned qui v1.33.1, `internal/api/server.go` registers its GET under the
authenticated group; `GetClientSettings` reads the stored key-value map without
changing it. `web/src/lib/client-settings.ts` includes `qui-incognito-mode`
among the synced settings. The existing server-side API-key credential remains
required. PUT is denied locally; this does not allow a settings subtree or
any adjacent API-key/authentication routes. The response receives the same
readiness gate, redaction, size limits and tripwire as other app responses.

## Jellyfin identity versus hex-secret detection

The design's global 32-hex tripwire also matches Jellyfin's compact GUIDs and
image cache tags. The rule is retained. For HTTP 200 Jellyfin responses only,
the scanner uses a separate inspection copy with schema-defined identity fields
replaced: item DTO identities/image tags, system-info ID, session/user/server
IDs and now-playing items, plugin/task IDs and virtual-folder item IDs. Compact
GUIDs in the corresponding item/user/task route positions are treated likewise.
The returned JSON and identifiers are unchanged.

Exact-value and sensitive-field redaction run **before** this inspection. A
known secret is never exempt, even if it occurs in a legitimate identifier field
or path. The inspection is route- and DTO-position-specific: arbitrary nested
`Id` keys, overview text, unknown routes, error responses, device IDs and other
apps receive no exception. All other tripwire rules remain in force.

This explicitly corrects the plan's context-free hex rule. It trusts Jellyfin
to populate its documented identity fields with identities, not uncollected
credentials. It cannot distinguish an unknown secret deliberately substituted
into a trusted identity slot. Unknown schemas and additional cache-key shapes
stay fail-closed until audited; extend the fixtures when upgrading Jellyfin.

## Overall upstream deadline

One monotonic 20-second budget covers connection, request transmission, response
headers, chunk framing and body reading. The HTTP reader recomputes the remaining
socket timeout on each receive; a peer cannot extend the budget by trickling
bytes. Budget exhaustion returns the fixed upstream-unreachable error, and both
connection and response descriptors are closed. No global signal or background
fetch worker is left running after a timeout.

The transport supports the design's fixed numeric IPv4 HTTP app bases only.
Hostnames, userinfo and base URL paths/queries/fragments are rejected rather
than introducing DNS or unaudited endpoint rewriting. Redirects are returned
without following them, and environment proxies are never used. Supporting
HTTPS or hostname-based apps requires an explicit transport extension and
deadline tests; none of the configured app bases needs either today.
