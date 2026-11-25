#!/bin/sh
# Per-guest CPU and memory, from the Proxmox host's cgroups (/sys/fs/cgroup/lxc, mounted read-only at /cgroup).
# A guest's own /proc/stat and loadavg come from lxcfs and show the host's, so the guest can't say.
# The guest's limit is set on this cgroup, so an OOM kill that limit causes is counted here and
# nowhere inside the guest (cAdvisor's container_oom_events_total misses it).
# busybox httpd runs this on every scrape: nothing is cached, nothing is written.
#   lxc_cpu_usage_seconds_total (and _user_, _system_)  CPU time the guest used
#   lxc_pressure_cpu_*_seconds_total                    time its tasks waited (some) or all stalled (full) on a CPU
#   lxc_cpu_cores                                       the cores it may use
#   lxc_memory_usage_bytes, lxc_memory_limit_bytes      memory charged to the guest (page cache included), its cap
#   lxc_memory_anon_bytes                               the part the kernel can't drop: no swap on this host
#   lxc_memory_oom_kills_total                          processes the kernel killed at the guest's cap
#   lxc_memory_major_faults_total                       pages read back from disk: climbs fast when it thrashes
#   lxc_pressure_memory_*_seconds_total, lxc_pressure_io_*  time its tasks waited (some) or all stalled (full) on memory, IO
# host is the machine's inventory name (stacks/monitoring/hosts/): add a guest there and here.
# A guest not listed here still shows up, as host="ct<vmid>".
echo "Content-Type: text/plain; version=0.0.4"
echo
cd "${CGROOT:-/cgroup}" 2>/dev/null || exit 0
ids=
for d in [0-9]*; do [ -d "$d" ] && ids="$ids $d"; done
exec awk -v ids="$ids" -v map="104=proxy 111=apps 112=nextcloud 116=gitlab 118=vpn" '
function lines(path, i, n, a) {
	n = 0
	while ((getline line < path) > 0) { n++; out[n] = line }
	close(path)
	return n
}
# "1-4,6,9" is 6 cores
function count(s, n, i, p, r) {
	n = split(s, p, ",")
	r = 0
	for (i = 1; i <= n; i++) {
		if (p[i] ~ /-/) { split(p[i], r2, "-"); r += r2[2] - r2[1] + 1 } else if (p[i] != "") r++
	}
	return r
}
BEGIN {
	n = split(map, kv, " ")
	for (i = 1; i <= n; i++) { split(kv[i], p, "="); host[p[1]] = p[2] }
	nid = split(ids, id, " ")
	for (i = 1; i <= nid; i++) {
		v = id[i]
		lab[v] = "{host=\"" ((v in host) ? host[v] : "ct" v) "\",vmid=\"" v "\"}"
		c = lines(v "/cpu.stat")
		for (j = 1; j <= c; j++) { split(out[j], a, " "); if (a[1] == "usage_usec") use[v] = a[2]; if (a[1] == "user_usec") usr[v] = a[2]; if (a[1] == "system_usec") sys[v] = a[2] }
		psi(v "/cpu.pressure", v, some, full)
		psi(v "/memory.pressure", v, msome, mfull)
		psi(v "/io.pressure", v, isome, ifull)
		if (lines(v "/memory.current") > 0) mem[v] = out[1]
		if (lines(v "/memory.max") > 0 && out[1] != "max") memmax[v] = out[1]
		anon[v] = key(v "/memory.stat", "anon")
		majflt[v] = key(v "/memory.stat", "pgmajfault")
		oomk[v] = key(v "/memory.events", "oom_kill")
		cores[v] = ""
		if (lines(v "/cpuset.cpus.effective") > 0) cores[v] = count(out[1])
		if (lines(v "/cpu.max") > 0) {
			split(out[1], q, " ")
			if (q[1] != "max" && q[2] > 0 && (cores[v] == "" || q[1] / q[2] < cores[v])) cores[v] = q[1] / q[2]
		}
	}
	us = 1000000
	emit("lxc_cpu_usage_seconds_total", "counter", "CPU time the guest used.", use, us)
	emit("lxc_cpu_user_seconds_total", "counter", "CPU time the guest spent in user mode.", usr, us)
	emit("lxc_cpu_system_seconds_total", "counter", "CPU time the guest spent in the kernel.", sys, us)
	emit("lxc_pressure_cpu_waiting_seconds_total", "counter", "Time some of the guest tasks waited for a CPU (PSI some).", some, us)
	emit("lxc_pressure_cpu_stalled_seconds_total", "counter", "Time all of the guest tasks waited for a CPU (PSI full).", full, us)
	emit("lxc_cpu_cores", "gauge", "Cores the guest may use.", cores, 1)
	emit("lxc_memory_usage_bytes", "gauge", "Memory charged to the guest, page cache included.", mem, 1)
	emit("lxc_memory_limit_bytes", "gauge", "The guest memory cap.", memmax, 1)
	emit("lxc_memory_anon_bytes", "gauge", "Anonymous memory of the guest: with no swap, the kernel cannot reclaim it.", anon, 1)
	emit("lxc_memory_oom_kills_total", "counter", "Processes the kernel OOM-killed at the guest memory cap.", oomk, 1)
	emit("lxc_memory_major_faults_total", "counter", "Major page faults in the guest.", majflt, 1)
	emit("lxc_pressure_memory_waiting_seconds_total", "counter", "Time some of the guest tasks waited for memory (PSI some).", msome, us)
	emit("lxc_pressure_memory_stalled_seconds_total", "counter", "Time all of the guest tasks waited for memory (PSI full).", mfull, us)
	emit("lxc_pressure_io_waiting_seconds_total", "counter", "Time some of the guest tasks waited for IO (PSI some).", isome, us)
	emit("lxc_pressure_io_stalled_seconds_total", "counter", "Time all of the guest tasks waited for IO (PSI full).", ifull, us)
}
# PSI file: "some ... total=<usec>" and "full ... total=<usec>" into s[v] and f[v]
function psi(path, v, s, f, c, j, t) {
	c = lines(path)
	for (j = 1; j <= c; j++) {
		if (match(out[j], /total=[0-9]+/)) { t = substr(out[j], RSTART + 6, RLENGTH - 6); if (out[j] ~ /^some/) s[v] = t; if (out[j] ~ /^full/) f[v] = t }
	}
}
# "<key> <value>" lines (memory.stat, memory.events): the value, or "" when the key is missing
function key(path, k, c, j, a) {
	c = lines(path)
	for (j = 1; j <= c; j++) { split(out[j], a, " "); if (a[1] == k) return a[2] }
	return ""
}
function emit(name, type, help, arr, div, i, v) {
	print "# HELP " name " " help
	print "# TYPE " name " " type
	for (i = 1; i <= nid; i++) {
		v = id[i]
		if (arr[v] == "") continue
		printf "%s%s %.6f\n", name, lab[v], arr[v] / div
	}
}'
