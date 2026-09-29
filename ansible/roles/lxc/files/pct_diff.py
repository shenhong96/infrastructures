# Compares one container's Proxmox config with its inventory `pct` (JSON on stdin) and
# prints, as JSON, what `pct set` or `pct create` needs to make them match. Read-only.
# Usage on the host: python3 pct_diff.py <vmid> < want.json
import json
import os
import re
import sys

vmid = sys.argv[1]
want = json.load(sys.stdin)
path = f"/etc/pve/lxc/{vmid}.conf"
binds = [v.split(",")[0] for k, v in want.items() if re.fullmatch(r"mp\d+", k) and v.startswith("/")]

if not os.path.exists(path):
    plain = {k: v for k, v in want.items() if not k.startswith("lxc.")}
    # A new root volume: "ZFS-DATA:101/vm-101-disk-1.raw,size=8G" becomes "ZFS-DATA:8".
    plain["rootfs"] = plain["rootfs"].split(":")[0] + ":" + re.search(r"size=(\d+)G", plain["rootfs"]).group(1)
    raw = [f"{k}: {v}" for k, vs in want.items() if k.startswith("lxc.") for v in (vs if isinstance(vs, list) else [vs])]
    print(json.dumps({"missing": True, "args": [a for k, v in plain.items() for a in (f"--{k}", v)], "raw": raw, "binds": binds}))
    sys.exit()

live = {}
with open(path) as f:
    for line in f:
        if line.startswith("["):  # snapshot or pending section: only the main one counts
            break
        if line.startswith("#") or ": " not in line:  # the description (unmanaged), blank lines
            continue
        k, v = line.rstrip("\n").split(": ", 1)
        live.setdefault(k, []).append(v)
live = {k: v[0] if len(v) == 1 else v for k, v in live.items()}


def norm(k, v):
    # A container recreated empty gets vm-<id>-disk-0.raw; the old one may be disk-1.
    return re.sub(r"/vm-\d+-disk-\d+\.raw", "", v) if k == "rootfs" and v else v


differs = sorted(k for k in live.keys() | want.keys() if norm(k, live.get(k)) != norm(k, want.get(k)))
settable = [k for k in differs if not k.startswith("lxc.")]  # pct can't set raw lxc.* keys
args = [a for k in settable if k in want for a in (f"--{k}", want[k])]
if [k for k in settable if k not in want]:
    args += ["--delete", ",".join(k for k in settable if k not in want)]
print(json.dumps({"missing": False, "differs": {k: {"live": live.get(k), "want": want.get(k)} for k in differs}, "args": args, "binds": binds}))
