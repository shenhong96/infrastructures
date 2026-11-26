#!/bin/sh
# /diag/ reaches the host's wake socket /run/diag-wake/diag.sock (root:diag-wake 0660, gid 3121).
# nginx's worker calls initgroups("nginx"), which drops compose group_add groups, so the group
# must be in the container's /etc/group with nginx as a member.
set -eu
grep -q '^diag-wake:' /etc/group || addgroup -g 3121 diag-wake
addgroup nginx diag-wake 2>/dev/null || true
