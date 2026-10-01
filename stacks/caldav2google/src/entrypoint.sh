#!/usr/bin/env bash
# Run caldav2google once per $SYNC_INTERVAL. One run == one full reconcile
# (adds/updates/deletes mirrored from the Nextcloud calendar into Google).
set -euo pipefail

cd /data

if [[ ! -f /data/token.json ]]; then
  echo "[entrypoint] FATAL: /data/token.json is missing." >&2
  echo "[entrypoint] Mint it on a machine with a browser (see README -> mint-token.py)," >&2
  echo "[entrypoint] then copy token.json into this stack's data/ directory." >&2
  exit 1
fi

INTERVAL="${SYNC_INTERVAL:-600}"
echo "[entrypoint] caldav2google loop starting; interval=${INTERVAL}s; src='${CALDAV_CALENDAR_NAME:-?}' -> gcal='${GOOGLE_CALENDAR_NAME:-?}'"

while true; do
  echo "[entrypoint] $(date -Iseconds) --- sync start ---"
  if python /app/src/main.py; then
    echo "[entrypoint] $(date -Iseconds) --- sync OK ---"
    [[ -n "${KUMA_PUSH_URL:-}" ]] && curl -fsS --max-time 10 "${KUMA_PUSH_URL}?status=up&msg=ok" >/dev/null 2>&1 || true
  else
    rc=$?
    echo "[entrypoint] $(date -Iseconds) --- sync FAILED (exit ${rc}) ---" >&2
    [[ -n "${KUMA_PUSH_URL:-}" ]] && curl -fsS --max-time 10 "${KUMA_PUSH_URL}?status=down&msg=fail" >/dev/null 2>&1 || true
  fi
  sleep "${INTERVAL}"
done
