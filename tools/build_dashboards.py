#!/usr/bin/env python3
"""Builds the Grafana dashboards that stacks/host-monitoring provisions, from code: one function per
panel kind, so every panel looks the same and a new one is a few lines. Run from the repo root
after a change, and commit the JSON it writes (tests/test_monitoring.py fails if they differ):

    python3 tools/build_dashboards.py

The data comes from the Alloy agent in stacks/monitoring: every series and log line carries host,
host_kind and vmid, and the jobs are integrations/node_exporter, integrations/docker and
integrations/alloy. Collection is every 60s; panels draw at no finer than 5 minutes."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "stacks/host-monitoring/grafana-dashboards"

# The datasources stacks/host-monitoring/grafana-datasources/datasources.yaml provisions.
PROM = {"type": "prometheus", "uid": "ceog2753mbr40d"}
LOKI = {"type": "loki", "uid": "ceofts4g1tkw0e"}

# Colours: a categorical palette checked for colour-blind separation on Grafana's dark surface,
# used in this fixed order, and status colours kept for good/bad only. Series that are an entity
# (a host, a container) take palette-classic-by-name instead: a name keeps its colour whatever
# else is on screen.
BLUE, ORANGE, AQUA, YELLOW, MAGENTA, GREEN, VIOLET = "#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9"
GOOD, WARN, SERIOUS, CRIT, MUTED = "#0ca30c", "#fab219", "#ec835a", "#d03b3b", "#8e8e8e"
INTERVAL = "5m"  # the finest step a panel draws

# Labels every panel filters on.
H = 'host="$host"'
NODE = f'job="integrations/node_exporter", {H}'
DOCKER = f'job="integrations/docker", {H}'
ALLOY = f'job="integrations/alloy", {H}'
ERRORS = 'detected_level=~"error|fatal|critical"'


def steps(*pairs):
    """Thresholds: the base colour, then (value, colour) pairs."""
    base, *rest = pairs
    return {"mode": "absolute", "steps": [{"color": base, "value": None}] + [{"color": c, "value": v} for v, c in rest]}


USAGE = steps(GOOD, (0.7, WARN), (0.85, SERIOUS), (0.95, CRIT))  # a share of something used up
FIXED = lambda colour: {"mode": "fixed", "fixedColor": colour}  # noqa: E731
BY_NAME = {"mode": "palette-classic-by-name"}


def prom(expr, legend="", instant=False, table=False, ref="A"):
    t = {"datasource": PROM, "refId": ref, "expr": expr, "legendFormat": legend or "__auto", "editorMode": "code"}
    if instant or table:
        t |= {"instant": True, "range": False}
    if table:
        t["format"] = "table"
    return t


def loki(expr, legend="", instant=False, ref="A"):
    t = {"datasource": LOKI, "refId": ref, "expr": expr, "legendFormat": legend, "editorMode": "code", "queryType": "range"}
    if instant:
        t["queryType"] = "instant"
    return t


def override(name, **props):
    return {"matcher": {"id": "byName", "options": name}, "properties": [{"id": k.replace("__", "."), "value": v} for k, v in props.items()]}


class Layout:
    """Places panels left to right on Grafana's 24-column grid, wrapping to a new line."""

    def __init__(self):
        self.panels, self.x, self.y, self.line, self.next_id = [], 0, 0, 0, 1

    def add(self, panel, w, h):
        if self.x + w > 24:
            self.x, self.y = 0, self.y + self.line
            self.line = 0
        panel |= {"id": self.next_id, "gridPos": {"x": self.x, "y": self.y, "w": w, "h": h}}
        self.next_id += 1
        self.x += w
        self.line = max(self.line, h)
        self.panels.append(panel)
        return panel

    def row(self, title, collapsed=False, children=()):
        self.x, self.y = 0, self.y + self.line
        self.line = 0
        row = {"type": "row", "title": title, "collapsed": collapsed, "panels": []}
        self.add(row, 24, 1)
        self.x, self.y, self.line = 0, self.y + 1, 0
        if collapsed:
            # A collapsed row carries its panels inside it.
            self.panels.pop()
            start = len(self.panels)
            for build in children:
                build()
            row["panels"] = self.panels[start:]
            del self.panels[start:]
            self.panels.append(row)
            self.x, self.y, self.line = 0, row["gridPos"]["y"] + 1, 0
        return row


def stat(title, target, unit="none", colour=None, thresholds=None, desc="", text_mode="value", decimals=None, no_value="0"):
    defaults = {"unit": unit, "noValue": no_value, "color": FIXED(colour) if colour else {"mode": "thresholds"},
                "thresholds": thresholds or steps(BLUE)}
    if decimals is not None:
        defaults["decimals"] = decimals
    return {
        "type": "stat", "title": title, "description": desc, "datasource": target["datasource"], "targets": [target],
        "fieldConfig": {"defaults": defaults, "overrides": []},
        "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}, "colorMode": "value",
                    "graphMode": "none", "justifyMode": "center", "textMode": text_mode, "wideLayout": True,
                    "showPercentChange": False, "orientation": "auto"},
    }


def series(title, targets, unit="none", colour=BY_NAME, stack=False, fill=12, desc="", overrides=(), max_=None,
           bars=False, legend_calcs=("mean", "max"), min_=None, negative=()):
    """A time series: thin lines, a soft gradient, a table legend with mean and max."""
    custom = {"drawStyle": "bars" if bars else "line", "lineWidth": 2, "fillOpacity": 70 if bars else fill, "barWidthFactor": 0.6,
              "gradientMode": "none" if bars else "opacity", "showPoints": "never", "spanNulls": 360000,
              "lineInterpolation": "smooth", "axisSoftMin": 0, "axisBorderShow": False, "barAlignment": 0,
              "stacking": {"mode": "normal" if stack or bars else "none", "group": "A"},
              "axisCenteredZero": bool(negative), "thresholdsStyle": {"mode": "off"}}
    defaults = {"unit": unit, "color": colour, "custom": custom}
    if max_ is not None:
        defaults["max"] = max_
    if min_ is not None:
        defaults["min"] = min_
    ovs = list(overrides) + [override(n, custom__transform="negative-Y") for n in negative]
    return {
        "type": "timeseries", "title": title, "description": desc, "datasource": targets[0]["datasource"],
        "interval": INTERVAL, "targets": targets,
        "fieldConfig": {"defaults": defaults, "overrides": ovs},
        "options": {"legend": {"displayMode": "table", "placement": "right", "calcs": list(legend_calcs), "showLegend": True},
                    "tooltip": {"mode": "multi", "sort": "desc"}},
    }


def table(title, targets, columns, desc="", overrides=(), sort=None):
    """Instant queries joined into one row per entity. columns: query refId -> (header, unit, cell)."""
    ovs = []
    rename = {}
    for ref, (header, unit, cell, thresholds) in columns.items():
        field = f"Value #{ref}"
        rename[field] = header
        props = {"unit": unit}
        if cell == "gauge":
            props |= {"custom__cellOptions": {"type": "gauge", "mode": "basic", "valueDisplayMode": "text"},
                      "min": 0, "max": 1, "color": {"mode": "thresholds"}, "thresholds": thresholds or USAGE}
        elif cell == "status":
            props |= {"custom__cellOptions": {"type": "color-text"}, "color": {"mode": "thresholds"},
                      "thresholds": thresholds}
        elif cell == "updown":
            props |= {"custom__cellOptions": {"type": "color-text"}, "custom__width": 90, "mappings": [
                {"type": "value", "options": {"0": {"text": "Down", "color": CRIT}, "1": {"text": "Up", "color": GOOD}}}]}
        ovs.append(override(field, **props))
    return {
        "type": "table", "title": title, "description": desc, "datasource": targets[0]["datasource"], "targets": targets,
        "fieldConfig": {"defaults": {"custom": {"align": "auto", "cellOptions": {"type": "auto"}, "inspect": False},
                                     "noValue": "–"},
                        "overrides": ovs + list(overrides)},
        "options": {"showHeader": True, "cellHeight": "sm", "footer": {"show": False},
                    "sortBy": [{"displayName": sort, "desc": True}] if sort else []},
        "transformations": [
            {"id": "merge", "options": {}},
            {"id": "organize", "options": {"excludeByName": {"Time": True}, "renameByName": rename}},
        ],
    }


def topk(expr, by, k=5):
    """The k biggest over the whole time range, drawn over time: the set doesn't change from point to point."""
    return f"{expr} and on({by}) topk({k}, sum by ({by}) (avg_over_time(({expr})[$__range:{INTERVAL}] @ end())))"


def hosts_dashboard():
    L = Layout()

    # ---- Fleet: every machine at a glance; grows by itself as machines are added.
    L.row("Fleet")
    L.add(stat("Machines reporting", prom('count(up{job="integrations/node_exporter"} == 1)', instant=True),
               desc="Machines whose agent sent their metrics in the last scrape."), 4, 4)
    L.add(stat("Containers", prom("count(count by (host, container) (container_start_time_seconds))", instant=True),
               desc="Docker containers running, on every machine."), 4, 4)
    L.add(stat("Stale agents", prom("count((time() - max by (host) (max_over_time(prometheus_remote_storage_queue_highest_sent_timestamp_seconds[1d]))) > 300) or vector(0)", instant=True),
               thresholds=steps(GOOD, (1, CRIT)), desc="Alloy agents that sent nothing for 5 minutes, among those seen in the last day."), 4, 4)
    L.add(stat("Fullest disk", prom("max(1 - node_filesystem_avail_bytes / node_filesystem_size_bytes)", instant=True),
               unit="percentunit", thresholds=USAGE, decimals=0, desc="The fullest filesystem on any machine."), 4, 4)
    L.add(stat("OOM kills", prom("sum(increase(container_oom_events_total[$__range])) or vector(0)", instant=True),
               thresholds=steps(GOOD, (1, CRIT)), decimals=0, desc="Containers killed for running out of memory, in the time range."), 4, 4)
    L.add(stat("Error log lines", loki(f'sum(count_over_time({{job="integrations/docker"}} | {ERRORS} [$__range]))', instant=True),
               thresholds=steps(GOOD, (1, WARN), (100, SERIOUS)), decimals=0, desc="Lines Loki detected as error, fatal or critical, in the time range."), 4, 4)

    fleet = table("Machines", [
        prom('max by (host, host_kind, vmid) (up{job="integrations/node_exporter"})', table=True, ref="A"),
        prom('1 - avg by (host) (rate(node_cpu_seconds_total{mode="idle"}[5m]))', table=True, ref="B"),
        prom("1 - max by (host) (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)", table=True, ref="C"),
        prom('1 - max by (host) (node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"})', table=True, ref="D"),
        prom('max by (host) (node_load5) / count by (host) (node_cpu_seconds_total{mode="idle"})', table=True, ref="E"),
        prom("count by (host) (count by (host, container) (container_start_time_seconds))", table=True, ref="F"),
        prom("max by (host) (node_time_seconds - node_boot_time_seconds)", table=True, ref="G"),
        prom("time() - max by (host) (max_over_time(prometheus_remote_storage_queue_highest_sent_timestamp_seconds[1d]))", table=True, ref="H"),
    ], {
        "A": ("State", "none", "updown", None),
        "B": ("CPU", "percentunit", "gauge", None),
        "C": ("Memory", "percentunit", "gauge", None),
        "D": ("Root disk", "percentunit", "gauge", None),
        "E": ("Load / core", "none", "status", steps(GOOD, (0.8, WARN), (1.5, CRIT))),
        "F": ("Containers", "none", None, None),
        "G": ("Uptime", "s", None, None),
        "H": ("Last data", "s", "status", steps(GOOD, (180, WARN), (300, CRIT))),
    }, desc="One row per machine. Click a name to show it below.", overrides=[
        override("host", displayName="Machine", links=[{"title": "Show ${__value.raw}", "url": "/d/homelab-hosts?var-host=${__value.raw}&${__url_time_range}"}]),
        override("host_kind", displayName="Kind", custom__width=80), override("vmid", displayName="VMID", custom__width=80),
    ], sort="CPU")
    L.add(fleet, 24, 6)

    L.add(series("CPU by machine", [prom('1 - avg by (host) (rate(node_cpu_seconds_total{mode="idle"}[$__rate_interval]))', "{{host}}")],
                 unit="percentunit", max_=1), 12, 7)
    L.add(series("Memory by machine", [prom("1 - max by (host) (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)", "{{host}}")],
                 unit="percentunit", max_=1), 12, 7)

    # ---- The machine picked in $host.
    L.row("Machine · $host")
    L.add(stat("Uptime", prom(f"max(node_time_seconds{{{NODE}}} - node_boot_time_seconds{{{NODE}}})", instant=True), unit="s", colour=BLUE, no_value="–"), 4, 4)
    L.add(stat("CPU cores", prom(f'count(node_cpu_seconds_total{{{NODE}, mode="idle"}})', instant=True), colour=BLUE, no_value="–"), 4, 4)
    L.add(stat("Memory", prom(f"max(node_memory_MemTotal_bytes{{{NODE}}})", instant=True), unit="bytes", colour=BLUE, no_value="–"), 4, 4)
    L.add(stat("Swap used", prom(f"max(1 - node_memory_SwapFree_bytes{{{NODE}}} / (node_memory_SwapTotal_bytes{{{NODE}}} > 0))", instant=True),
               unit="percentunit", thresholds=USAGE, decimals=0, no_value="No swap"), 4, 4)
    L.add(stat("OS", prom(f"max by (pretty_name) (node_os_info{{{NODE}}})", "{{pretty_name}}", instant=True), colour=BLUE, text_mode="name", no_value="–"), 4, 4)
    L.add(stat("Kernel", prom(f"max by (release) (node_uname_info{{{NODE}}})", "{{release}}", instant=True), colour=BLUE, text_mode="name", no_value="–"), 4, 4)

    cpu_modes = [override(m, color=FIXED(c)) for m, c in
                 (("user", BLUE), ("system", ORANGE), ("iowait", AQUA), ("steal", YELLOW), ("softirq", MAGENTA), ("nice", GREEN), ("irq", VIOLET))]
    L.add(series("CPU by mode", [prom(f'sum by (mode) (rate(node_cpu_seconds_total{{{NODE}, mode!~"idle|guest.*"}}[$__rate_interval])) / scalar(count(node_cpu_seconds_total{{{NODE}, mode="idle"}}))', "{{mode}}")],
                 unit="percentunit", stack=True, fill=30, max_=1, overrides=cpu_modes, desc="Share of all cores, stacked."), 12, 8)
    L.add(series("Memory", [
        prom(f"max(node_memory_MemTotal_bytes{{{NODE}}} - node_memory_MemAvailable_bytes{{{NODE}}})", "Used", ref="A"),
        prom(f"max(node_memory_MemTotal_bytes{{{NODE}}})", "Total", ref="B"),
    ], unit="bytes", colour=FIXED(BLUE), overrides=[override("Total", color=FIXED(MUTED), custom__fillOpacity=0, custom__lineWidth=1)],
        desc="Used is what can't be reclaimed: total less available."), 12, 8)

    L.add(series("Load", [
        prom(f"max(node_load1{{{NODE}}})", "1m", ref="A"), prom(f"max(node_load5{{{NODE}}})", "5m", ref="B"),
        prom(f"max(node_load15{{{NODE}}})", "15m", ref="C"), prom(f'count(node_cpu_seconds_total{{{NODE}, mode="idle"}})', "Cores", ref="D"),
    ], colour=FIXED(BLUE), fill=0, overrides=[override("5m", color=FIXED(ORANGE)), override("15m", color=FIXED(AQUA)),
                                              override("Cores", color=FIXED(MUTED), custom__lineWidth=1)],
        desc="Runnable tasks against the number of cores: above the Cores line, work waits."), 8, 8)
    L.add(series("Network", [
        prom(f"sum(rate(node_network_receive_bytes_total{{{NODE}}}[$__rate_interval])) * 8", "In", ref="A"),
        prom(f"sum(rate(node_network_transmit_bytes_total{{{NODE}}}[$__rate_interval])) * 8", "Out", ref="B"),
    ], unit="bps", colour=FIXED(BLUE), overrides=[override("Out", color=FIXED(ORANGE))], negative=["Out"],
        desc="In above the line, out below."), 8, 8)
    L.add(series("Disk I/O", [
        prom(f"sum(rate(node_disk_read_bytes_total{{{NODE}}}[$__rate_interval]))", "Read", ref="A"),
        prom(f"sum(rate(node_disk_written_bytes_total{{{NODE}}}[$__rate_interval]))", "Write", ref="B"),
    ], unit="Bps", colour=FIXED(BLUE), overrides=[override("Write", color=FIXED(ORANGE))], negative=["Write"],
        desc="Read above the line, write below."), 8, 8)

    L.add({
        "type": "bargauge", "title": "Filesystems", "description": "How full each mounted filesystem is, bind mounts from the Proxmox host included.",
        "datasource": PROM, "targets": [prom(f"1 - max by (mountpoint) (node_filesystem_avail_bytes{{{NODE}}} / node_filesystem_size_bytes{{{NODE}}})", "{{mountpoint}}", instant=True)],
        "fieldConfig": {"defaults": {"unit": "percentunit", "min": 0, "max": 1, "decimals": 0, "color": {"mode": "thresholds"}, "thresholds": USAGE}, "overrides": []},
        "options": {"orientation": "horizontal", "displayMode": "basic", "valueMode": "color", "namePlacement": "left", "showUnfilled": True,
                    "sizing": "manual", "minVizHeight": 16, "maxVizHeight": 22, "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}},
    }, 12, 7)
    L.add(series("Pressure", [
        prom(f'rate(node_pressure_cpu_waiting_seconds_total{{{NODE}}}[$__rate_interval])', "CPU", ref="A"),
        prom(f'rate(node_pressure_memory_waiting_seconds_total{{{NODE}}}[$__rate_interval])', "Memory", ref="B"),
        prom(f'rate(node_pressure_io_waiting_seconds_total{{{NODE}}}[$__rate_interval])', "I/O", ref="C"),
    ], unit="percentunit", colour=FIXED(BLUE), fill=0, overrides=[override("Memory", color=FIXED(ORANGE)), override("I/O", color=FIXED(AQUA))],
        desc="Share of time some task waited for CPU, memory or I/O (Linux PSI): the clearest sign a machine is short of something."), 12, 7)

    # ---- The containers on $host.
    L.row("Containers · $host")
    by = "container"
    L.add(table("Containers", [
        prom(f"max by (container, compose_project, image) (container_start_time_seconds{{{DOCKER}}})", table=True, ref="A"),
        prom(f"sum by (container) (rate(container_cpu_usage_seconds_total{{{DOCKER}}}[5m]))", table=True, ref="B"),
        prom(f"max by (container) (container_memory_working_set_bytes{{{DOCKER}}})", table=True, ref="C"),
        prom(f"max by (container) (container_memory_working_set_bytes{{{DOCKER}}}) / max by (container) (container_spec_memory_limit_bytes{{{DOCKER}}} > 0)", table=True, ref="D"),
        prom(f"sum by (container) (rate(container_network_receive_bytes_total{{{DOCKER}}}[5m])) * 8", table=True, ref="E"),
        prom(f"sum by (container) (rate(container_network_transmit_bytes_total{{{DOCKER}}}[5m])) * 8", table=True, ref="F"),
        prom(f"time() - max by (container) (container_start_time_seconds{{{DOCKER}}})", table=True, ref="G"),
        prom(f"max by (container) (increase(container_oom_events_total{{{DOCKER}}}[$__range]))", table=True, ref="H"),
    ], {
        "A": ("Started", "dateTimeFromNow", None, None),
        "B": ("CPU", "percentunit", "status", steps(GOOD, (0.5, WARN), (1, SERIOUS))),
        "C": ("Memory", "bytes", None, None),
        "D": ("Of its limit", "percentunit", "gauge", None),
        "E": ("Net in", "bps", None, None),
        "F": ("Net out", "bps", None, None),
        "G": ("Up for", "s", None, None),
        "H": ("OOM kills", "none", "status", steps(GOOD, (1, CRIT))),
    }, desc="One row per running container. CPU is in cores (100% = one core). Containers that share a network (host, or another container's) each show that network's total. Click a name for its logs.", overrides=[
        override("container", displayName="Container", links=[{"title": "Logs of ${__value.raw}", "url": "/d/homelab-hosts?var-host=$host&var-container=${__value.raw}&${__url_time_range}"}]),
        override("compose_project", displayName="Project"),
        override("image", displayName="Image", mappings=[{"type": "regex", "options": {"pattern": "(.*)@sha256:.*", "result": {"text": "$1"}}}]),
        override("Value #A", custom__hidden=True),
    ], sort="CPU"), 24, 9)
    L.add(series("CPU · top 5", [prom(topk(f"sum by (container) (rate(container_cpu_usage_seconds_total{{{DOCKER}}}[$__rate_interval]))", by), "{{container}}")],
                 unit="percentunit", desc="The five that used the most over the time range. 100% = one core."), 12, 8)
    L.add(series("Memory · top 5", [prom(topk(f"max by (container) (container_memory_working_set_bytes{{{DOCKER}}})", by), "{{container}}")],
                 unit="bytes", desc="Working set: what the kernel can't reclaim, the number an OOM kill is judged on."), 12, 8)
    L.add(series("Network · top 5", [prom(topk(f"sum by (container) (rate(container_network_receive_bytes_total{{{DOCKER}}}[$__rate_interval]) + rate(container_network_transmit_bytes_total{{{DOCKER}}}[$__rate_interval])) * 8", by), "{{container}}")],
                 unit="bps", desc="The five busiest over the time range, in and out together. Containers that share a network each show its total."), 24, 8)

    # ---- Logs on $host.
    L.row("Logs · $host")
    levels = [override(n, color=FIXED(c)) for n, c in (("error", CRIT), ("critical", CRIT), ("fatal", CRIT), ("warn", WARN), ("info", BLUE), ("debug", MUTED), ("trace", MUTED), ("unknown", MUTED))]
    L.add(series("Log lines by level", [loki(f'sum by (detected_level) (count_over_time({{{H}, container=~"$container"}} [$__auto]))', "{{detected_level}}")],
                 bars=True, overrides=levels, legend_calcs=("sum",), desc="Loki detects each line's level by itself."), 12, 8)
    L.add(series("Errors by container", [loki(f'sum by (container) (count_over_time({{{H}, container=~"$container"}} | {ERRORS} [$__auto]))', "{{container}}")],
                 bars=True, legend_calcs=("sum",), desc="Lines detected as error, fatal or critical."), 12, 8)
    L.add({
        "type": "logs", "title": "Logs", "description": "Filter with Container and Search above.", "datasource": LOKI,
        "targets": [loki(f'{{{H}, container=~"$container"}} |~ "(?i)$search"')],
        "options": {"showTime": True, "showLabels": False, "showCommonLabels": False, "wrapLogMessage": True, "prettifyLogMessage": False,
                    "enableLogDetails": True, "enableInfiniteScrolling": True, "dedupStrategy": "none", "sortOrder": "Descending"},
    }, 24, 12)

    # ---- The agent on $host: is the data getting through. Collapsed: look here when something is missing.
    def agent():
        L.add(stat("Alloy", prom(f"max by (version) (alloy_build_info{{{ALLOY}}})", "{{version}}", instant=True), colour=BLUE, text_mode="name", no_value="Not reporting"), 6, 4)
        L.add(stat("Config loaded", prom(f"min(alloy_config_last_load_successful{{{ALLOY}}})", instant=True),
                   thresholds=steps(CRIT, (1, GOOD)), no_value="–"), 6, 4)
        L.add(stat("Last data", prom(f"time() - max(max_over_time(prometheus_remote_storage_queue_highest_sent_timestamp_seconds{{{ALLOY}}}[1d]))", instant=True),
                   unit="s", thresholds=steps(GOOD, (180, WARN), (300, CRIT)), no_value="–"), 6, 4)
        L.add(stat("Agent memory", prom(f"max(process_resident_memory_bytes{{{ALLOY}}})", instant=True), unit="bytes", colour=BLUE, no_value="–"), 6, 4)
        L.add(series("Samples to Prometheus", [
            prom(f"sum(rate(prometheus_remote_storage_samples_total{{{ALLOY}}}[$__rate_interval]))", "Sent", ref="A"),
            prom(f"sum(rate(prometheus_remote_storage_samples_failed_total{{{ALLOY}}}[$__rate_interval]))", "Failed", ref="B"),
        ], unit="cps", colour=FIXED(BLUE), overrides=[override("Failed", color=FIXED(CRIT))]), 12, 7)
        L.add(series("Log lines to Loki", [
            prom(f"sum(rate(loki_write_sent_entries_total{{{ALLOY}}}[$__rate_interval]))", "Sent", ref="A"),
            prom(f"sum(rate(loki_write_dropped_entries_total{{{ALLOY}}}[$__rate_interval]))", "Dropped", ref="B"),
        ], unit="cps", colour=FIXED(BLUE), overrides=[override("Dropped", color=FIXED(CRIT))]), 12, 7)
    L.row("Agent · $host", collapsed=True, children=[agent])

    return {
        "uid": "homelab-hosts", "title": "Homelab · Machines & containers", "tags": ["homelab"],
        "description": "Every machine with the Alloy agent (stacks/monitoring), its containers and their logs. Built by tools/build_dashboards.py.",
        "editable": False, "graphTooltip": 1, "refresh": "5m", "schemaVersion": 41, "version": 1,
        "time": {"from": "now-24h", "to": "now"}, "timepicker": {"refresh_intervals": ["5m", "15m", "1h"]},
        "fiscalYearStartMonth": 0, "liveNow": False, "weekStart": "", "timezone": "browser",
        "annotations": {"list": []}, "links": [],
        "templating": {"list": [
            {"type": "query", "name": "host", "label": "Machine", "datasource": PROM, "refresh": 2, "sort": 1,
             "query": {"query": 'label_values(up{job=~"integrations/.+"}, host)', "refId": "host"},
             "definition": 'label_values(up{job=~"integrations/.+"}, host)', "multi": False, "includeAll": False},
            {"type": "query", "name": "container", "label": "Container", "datasource": LOKI, "refresh": 2, "sort": 1,
             "query": {"type": 1, "label": "container", "stream": f"{{{H}}}", "refId": "container"},
             "definition": f"label_values({{{H}}}, container)", "multi": True, "includeAll": True, "allValue": ".+",
             "current": {"text": ["All"], "value": ["$__all"]}},
            {"type": "textbox", "name": "search", "label": "Search", "query": "", "current": {"text": "", "value": ""}},
        ]},
        "panels": L.panels,
    }


DASHBOARDS = {"homelab-hosts.json": hosts_dashboard}


def render():
    return {name: json.dumps(build(), indent=2, ensure_ascii=False) + "\n" for name, build in DASHBOARDS.items()}


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    for name, text in render().items():
        (OUT / name).write_text(text)
        print(f"wrote {(OUT / name).relative_to(ROOT)}")
