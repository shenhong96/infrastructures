#!/bin/bash
# Hands finished torrents from qbittorrent-ubits (downloads outside the tunnel) to the main
# qbittorrent (seeds through it). Both mount /mnt/data/downloads at /downloads, so nothing
# moves: the main instance adds the same .torrent at the same save path, skipping the recheck.
# Waits HANDOFF_AGE seconds after completion so Sonarr/Radarr import from the ubits client first.
# Both WebUIs let the host in without a login (172.18.0.0/16 in their auth whitelist).
set -euo pipefail

SRC=${SRC:-http://localhost:8090}
DST=${DST:-http://localhost:8080}
HANDOFF_AGE=${HANDOFF_AGE:-1800}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
now=$(date +%s)

curl -fsS "$SRC/api/v2/torrents/info?filter=completed" |
  jq -r --argjson cut $((now - HANDOFF_AGE)) \
    '.[] | select(.completion_on > 0 and .completion_on < $cut) | [.hash, .save_path, .category, .tags] | @tsv' |
  while IFS=$'\t' read -r hash path category tags; do
    if [ "$(curl -fsS "$DST/api/v2/torrents/info?hashes=$hash" | jq length)" = 0 ]; then
      curl -fsS -o "$tmp/$hash.torrent" "$SRC/api/v2/torrents/export?hash=$hash"
      curl -fsS "$DST/api/v2/torrents/add" -F "torrents=@$tmp/$hash.torrent" \
        -F "savepath=$path" -F "category=$category" -F "tags=$tags" \
        -F skip_checking=true -F paused=false >/dev/null
      sleep 2
      # ponytail: only checks the main instance knows it; a bad add shows up there as missing files.
      [ "$(curl -fsS "$DST/api/v2/torrents/info?hashes=$hash" | jq length)" = 1 ] ||
        { echo "$(date -Is) add failed: $hash" >&2; continue; }
    fi
    curl -fsS "$SRC/api/v2/torrents/delete" -d "hashes=$hash" -d deleteFiles=false
    echo "$(date -Is) handed off $hash"
  done
