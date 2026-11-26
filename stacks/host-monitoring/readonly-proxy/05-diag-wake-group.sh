#!/bin/sh
# /diag/ reaches the host's wake socket /run/diag-wake/diag.sock (root:diag-wake 0660, gid 3121).
# nginx's worker calls initgroups("nginx"), which drops compose group_add groups, so the group
# must be in the container's /etc/group with nginx as a member. Fails loudly on any mismatch.
set -eu
line=$(grep '^diag-wake:' /etc/group || true)
if [ -z "$line" ]; then
  if grep -q '^[^:]*:[^:]*:3121:' /etc/group; then echo "gid 3121 taken by another group" >&2; exit 1; fi
  addgroup -g 3121 diag-wake
elif [ "$(echo "$line" | cut -d: -f3)" != 3121 ]; then
  echo "diag-wake exists with the wrong gid" >&2; exit 1
fi
id -nG nginx | tr ' ' '\n' | grep -qx diag-wake || addgroup nginx diag-wake
id -nG nginx | tr ' ' '\n' | grep -qx diag-wake
