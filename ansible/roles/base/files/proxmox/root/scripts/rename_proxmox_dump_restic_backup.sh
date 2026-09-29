#!/bin/bash

# This script are used to rename the proxmox dump images into their machine-name without date & timestamp.

# Set changelog filename and location so that it gets synced by restic for future reference.
log_id="__backup.changelog"
dump_location="/mnt/storage/backups/proxmox/dump"
log="${dump_location}/${log_id}"

[[ -f "${log}" ]] || touch "${log}"

# Extract the date in the desired format
echo "$(date '+%d %b %Y')" > "${log}"
# Extract the time in the desired format
echo "$(date '+%r %z')" >> "${log}"

cd "${dump_location}"

for file in vzdump-lxc-*.log; do
  if [[ -f "$file" ]]; then
    if [[ "$file" =~ vzdump-lxc-([0-9]+)-(.*)\.log ]]; then
      id="${BASH_REMATCH[1]}"
      name=$(pct list | grep "$id" | awk '{print $3}')
      mv "$file" "$name.log"
      mv "${file%.log}.tar.zst" "$name.tar.zst"
      mv "${file%.log}.tar.zst.notes" "$name.tar.zst.notes"
      echo "LXC __ ${name} backup dump rename completed" >> "${log}"
    fi
  fi
done

for file in vzdump-qemu-*.log; do
  if [[ -f "$file" ]]; then
    if [[ "$file" =~ vzdump-qemu-([0-9]+)-.*\.log ]]; then
      id="${BASH_REMATCH[1]}"
      name=$(qm list | grep "$id" | awk '{print $2}')
      mv "$file" "$name.log"
      mv "${file%.log}.vma.zst" "$name.vma.zst"
      mv "${file%.log}.vma.zst.notes" "$name.vma.zst.notes"
      echo "QEMU __ ${name} backup dump rename completed" >> "${log}"
    fi
  fi
done