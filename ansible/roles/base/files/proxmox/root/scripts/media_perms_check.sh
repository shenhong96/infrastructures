#!/usr/bin/env bash
# Report-only check that data/media and data/downloads stay group 101000 (gid 1000 in the
# unprivileged app containers), group-writable and never world-writable. Replaces the old
# `chmod 777 -R` cron: it changes nothing, logs what drifted and exits 1 so the cron's
# healthcheck ping fails. Walks the raw disks, so it also sees what mergerfs placed anywhere.
# Run: bash /root/scripts/media_perms_check.sh
set -u
log=/var/log/media-perms-check.log
out=$(find /mnt/disk[0-9]*/data/media /mnt/disk[0-9]*/data/downloads ! -type l \
  \( ! -group 101000 -o -perm -0002 -o \( -type d ! -perm -0770 \) -o \( -type f ! -perm -0660 \) \) \
  -printf '%U:%G %m %p\n' 2>/dev/null)
n=$(printf '%s' "$out" | grep -c . || true)
{ echo "$(date -Is) drift=$n"; printf '%s\n' "$out" | head -200; } >> "$log"
echo "drift=$n"
[ "$n" -eq 0 ]
