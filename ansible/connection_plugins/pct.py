# ponytail: community.proxmox 2.0.0's proxmox_pct_remote builds
# `pct exec <vmid> -- <cmd>` with the command unquoted, so the host's shell splits it:
# in a `raw` task, everything after a `;`, `|` or `&&` runs on the Proxmox host instead
# of the container. This wraps the whole command in `sh -c '<quoted>'` so all of it runs
# inside the container. It also sets has_pipelining, which upstream leaves off although
# its exec_command already handles stdin. Delete this file once upstream fixes both.
import shlex

from ansible_collections.community.proxmox.plugins.connection.proxmox_pct_remote import (  # noqa: F401
    DOCUMENTATION,
    Connection as _Upstream,
)


class Connection(_Upstream):
    transport = "pct"
    has_pipelining = True

    def _build_pct_command(self, cmd: str) -> str:
        return super()._build_pct_command("/bin/sh -c " + shlex.quote(cmd))
