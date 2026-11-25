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
