#!/bin/sh
# Per-guest CPU, from the Proxmox host's cgroups (/sys/fs/cgroup/lxc, mounted read-only at /cgroup).
# A guest's own /proc/stat and loadavg come from lxcfs and show the host's, so the guest can't say.
# busybox httpd runs this on every scrape: nothing is cached, nothing is written.
#   lxc_cpu_usage_seconds_total (and _user_, _system_)  CPU time the guest used
#   lxc_pressure_cpu_*_seconds_total                    time its tasks waited (some) or all stalled (full) on a CPU
#   lxc_cpu_cores                                       the cores it may use
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
		c = lines(v "/cpu.pressure")
		for (j = 1; j <= c; j++) {
			if (match(out[j], /total=[0-9]+/)) { t = substr(out[j], RSTART + 6, RLENGTH - 6); if (out[j] ~ /^some/) some[v] = t; if (out[j] ~ /^full/) full[v] = t }
		}
		cores[v] = ""
		if (lines(v "/cpuset.cpus.effective") > 0) cores[v] = count(out[1])
		if (lines(v "/cpu.max") > 0) {
			split(out[1], q, " ")
			if (q[1] != "max" && q[2] > 0 && (cores[v] == "" || q[1] / q[2] < cores[v])) cores[v] = q[1] / q[2]
		}
	}
	emit("lxc_cpu_usage_seconds_total", "counter", "CPU time the guest used.", use)
	emit("lxc_cpu_user_seconds_total", "counter", "CPU time the guest spent in user mode.", usr)
	emit("lxc_cpu_system_seconds_total", "counter", "CPU time the guest spent in the kernel.", sys)
	emit("lxc_pressure_cpu_waiting_seconds_total", "counter", "Time some of the guest tasks waited for a CPU (PSI some).", some)
	emit("lxc_pressure_cpu_stalled_seconds_total", "counter", "Time all of the guest tasks waited for a CPU (PSI full).", full)
	emit("lxc_cpu_cores", "gauge", "Cores the guest may use.", cores)
}
function emit(name, type, help, arr, i, v, val, div) {
	print "# HELP " name " " help
	print "# TYPE " name " " type
	div = (type == "counter") ? 1000000 : 1
	for (i = 1; i <= nid; i++) {
		v = id[i]
		if (arr[v] == "") continue
		printf "%s%s %.6f\n", name, lab[v], arr[v] / div
	}
}'
