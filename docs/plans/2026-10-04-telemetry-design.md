# Telemetry for every machine: design

Status: v1 on `vpn` (CT 118). Other machines follow by adding a hosts file and a stack entry.

## Goal

One way to see, for any machine in the homelab (LXC, VM or the Proxmox host): is it healthy, what
runs on it, what is each container using, what are they logging, and is the data still arriving.
Simple to start, and built so that a new machine or a new signal is a small, obvious change.

## What was there

- Alloy on `apps` and `vpn`, Promtail on `gitlab` and `nextcloud`, nothing elsewhere. Each machine
  had its own copy of the config.
- `vpn`'s cAdvisor sent no container metrics: cAdvisor registers no Docker container without
  containerd's socket, which was never mounted.
- The `/var/log` blocks read the Alloy container's own empty `/var/log`, not the machine's.
- Prometheus scraped only itself, so nothing read the node-exporters on proxy and vpn.
- Grafana had no dashboard in git.

## Design

```
stacks/monitoring/                      every machine, one folder
  compose.yaml                          the Alloy container, pinned by digest
  config.alloy                          wiring only: modules -> Prometheus / Loki
  modules/host.alloy                    the machine, from Alloy's built-in node_exporter
  modules/docker.alloy                  each container, from cAdvisor
  modules/logs.alloy                    each container's logs
  modules/agent.alloy                   Alloy's own health
  hosts/<name>.yaml                     who the machine is (compose override)
  komodo.toml                           one [[stack]] per machine
stacks/host-monitoring/                 Prometheus, Loki, Grafana on the Proxmox host
  grafana-dashboards/*.json             built by tools/build_dashboards.py
```

**One folder, a stack per machine.** The same pattern as `stacks/canary`. A machine's identity
is a small compose override (`hosts/vpn.yaml` sets `HOST`, `HOST_KIND`, `VMID`), which Komodo adds
through `file_paths`. A plain env file would do the same, but the repo keeps no plaintext `.env`
under `stacks/`, and an override can also add host-specific settings later. The stack keeps the
old name `monitoring-vpn` and project `monitoring`: Komodo's sync never deletes, so a new name would
leave the old container running next to the new one, both trying to use port 12345.

**Modules.** Each signal is one Alloy `declare` block in `modules/`, loaded with `import.file`
as `homelab.<name>`. `config.alloy` only wires modules to the two endpoints. A new signal is a new
file and one block. A module that needs an extra mount or exception says so in its header.

**One label set.** The endpoints add `host` (the inventory and Komodo server name), `host_kind`
(`lxc`, `vm`, `proxmox`) and `vmid` to every series and every log line. Jobs follow Grafana's
`integrations/*` naming (`node_exporter`, `docker`, `alloy`), so community dashboards and mixins
also work. Container metrics and logs share `container`, `compose_project` and `compose_service`.

**Only what a panel uses.** Each module keeps its metrics by name, and the unix exporter runs
only the collectors the panels need. On vpn that comes to about 75 series for the machine, 9 per
container and about 20 for the agent. A new panel adds its metric
to the module's keep-list.

**Cadence.** Collection runs every 60s and panels draw at 5-minute steps (`interval: 5m`). A
5-minute scrape would cost the same and look the same, but Prometheus marks a series stale after
5 minutes without a sample, and `rate()` needs two samples per window. That would leave holes.

**Logs.** All containers, opt-out with the label `homelab.logs=false`, which is filtered before
tailing starts. Levels are not parsed in Alloy: Loki 3's `detected_level` finds them, so no
per-app regex is needed.

**One agent, no separate node-exporter.** Alloy has node_exporter built in
(`prometheus.exporter.unix`), with the same collectors and metric names, so the machine runs one
process, and a new machine needs no Ansible run. For the numbers to be the machine's and not the
container's, Alloy runs as the node agent: the machine's network and processes (`network_mode:
host`, `pid: host`), and its `/proc`, `/sys` and `/` read-only under `/host`. Inside an LXC the
`/proc` bind carries lxcfs, so memory and CPU are the LXC's share. The host's process view also
lets cAdvisor read each container's network. The `node_exporter` role now removes the package from
every container outside its group (vpn leaves the group in this change; proxy stays until it gets
the agent). The other way, a separate node-exporter that Alloy scrapes, needs no host mounts but
costs a second process and a laptop run per machine.

**Gate.** The agent needs the host network and PID namespaces, `/proc`, `/sys`, `/`,
`/sys/fs/cgroup`, `docker.sock` and `containerd.sock`, all read-only. These are listed in
`policy/exceptions.toml` (the owner's `gate-change` label), pinned to exactly these values;
`gate.py` itself is unchanged. docker.sock already gives root-equivalent access whatever `:ro`
says (it was already allowed on the `monitoring-*` stacks), so the rest adds no reach.

## Dashboard

`Homelab · Machines & containers`, in a `Homelab` folder, built from `tools/build_dashboards.py`.
One function per panel kind keeps every panel the same, and a test fails if the JSON is stale.

1. **Fleet:** headline tiles (machines reporting, containers, stale agents, fullest disk, OOM
   kills, error lines), a table with one row per machine and gauge cells, and CPU and memory per
   machine. Grows by itself.
2. **Machine · $host:** uptime, cores, memory, swap, OS, kernel; CPU by mode; memory;
   load against cores; network and disk I/O mirrored around zero (one axis, never two); how full
   each filesystem is; pressure stall (PSI).
3. **Containers · $host:** a table (project, image, CPU, memory, share of its limit, network,
   uptime, OOM kills) and the top 5 by CPU, memory and network. Containers that share a network
   (host, or another container's, as in a VPN setup) each show that network's total. The top 5 is chosen once for the whole time range,
   so the set doesn't change from point to point.
4. **Logs · $host:** lines by level, errors by container, and the log stream with Container and
   Search filters.
5. **Agent · $host** (collapsed): version, config loaded, last data, samples and lines sent,
   failed or dropped.

Colours: status colours (good, warning, serious, critical) only for good/bad thresholds. A
categorical palette checked for colour-blind separation on Grafana's dark surface, in fixed order,
for fixed series. `palette-classic-by-name` for hosts and containers, so a name keeps its colour
when the filter changes.

## Tested

The stack was run locally with Prometheus v3.15, Loki 3.7 and Grafana 12.0.1 at the versions
`host-monitoring` pins, Alloy v1.20.1 and a few test containers. Every dashboard query was run
through Grafana's API. That run found and fixed: the cAdvisor attribute name, the containerd
socket, the jobs the exporters set themselves, Alloy's own `host` label overriding the machine's,
and the opt-out shipping lines without labels when filtered in `relabel_rules`. Running as the node
agent was checked the same way: the machine's own interface, filesystems and OS, and per-container
network. `alloy validate` doesn't check inside `declare` blocks; only a run does.

Not tested locally: cgroup v2 (the sandbox was v1; vpn runs v2, which is cAdvisor's main path) and
the lxcfs view.

## Next

In rough order of value:

1. **The other machines:** `apps` (replaces `monitoring-apps`), `gitlab` and `nextcloud`
   (replace Promtail), then `proxy` (and the `node_exporter` role with it), `media`,
   `fileserver`, `control`. Each one needs a hosts file and a stack entry.
2. **The Proxmox host:** `host_kind: proxmox`, plus `prometheus-pve-exporter` for every guest's
   CPU, memory, disk and state as Proxmox sees them, VMs included. The Proxmox host is a gate stack
   (`proxmox_stacks`).
3. **Machine logs:** the journal, through `loki.source.journal`. Needs `/var/log/journal` and
   `/etc/machine-id` mounted (an exception).
4. **Per-container disk I/O:** needs the machine's devices (an exception).
5. **Alerts:** Grafana alerting on the same labels: an agent stale for 10 minutes, a disk over 90%,
   an OOM kill, a container restart loop.
6. **Container restarts and exited containers:** Docker's own metrics endpoint (`daemon.json`,
   Ansible).
