"""The telemetry agent (stacks/monitoring) and the dashboards built for it: every machine is wired
the same way, and the committed dashboard JSON is what tools/build_dashboards.py builds.
Run from the repo root: python3 -m unittest discover tests"""
import importlib.util
import os
import re
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENT = ROOT / "stacks/monitoring"
GRAFANA = ROOT / "stacks/host-monitoring"
KINDS = {"lxc", "vm", "proxmox"}


def load_builder():
    spec = importlib.util.spec_from_file_location("build_dashboards", ROOT / "tools/build_dashboards.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def host_file(path):
    """HOST, HOST_KIND and VMID from a hosts/<name>.yaml (flat, so read without PyYAML)."""
    return dict(re.findall(r"^\s+(HOST|HOST_KIND|VMID):\s*\"?([\w.-]*)\"?\s*$", path.read_text(), re.M))


class Agent(unittest.TestCase):
    def setUp(self):
        self.stacks = tomllib.loads((AGENT / "komodo.toml").read_text())["stack"]
        self.hosts = {p.stem: host_file(p) for p in sorted((AGENT / "hosts").glob("*.yaml"))}

    def test_every_machine_has_a_hosts_file_and_a_stack(self):
        servers = {s["name"] for s in tomllib.loads((ROOT / "komodo/servers.toml").read_text())["server"]}
        self.assertEqual(sorted(s["config"]["server"] for s in self.stacks), sorted(self.hosts))
        for stack in self.stacks:
            name, c = stack["name"], stack["config"]
            with self.subTest(name):
                self.assertIn(c["server"], servers)
                self.assertEqual(name, f"monitoring-{c['server']}")
                self.assertEqual(c["project_name"], "monitoring")
                self.assertEqual(c["file_paths"], ["compose.yaml", f"hosts/{c['server']}.yaml"])

    def test_hosts_files_say_who_the_machine_is(self):
        for name, found in self.hosts.items():
            with self.subTest(name):
                self.assertEqual(found.get("HOST"), name)
                self.assertIn(found.get("HOST_KIND"), KINDS)
                self.assertIn("VMID", found)  # empty on the Proxmox host itself

    def test_every_stack_restarts_alloy_on_every_file_it_reads(self):
        want = ["config.alloy"] + sorted(p.relative_to(AGENT).as_posix() for p in (AGENT / "modules").glob("*.alloy"))
        for stack in self.stacks:
            with self.subTest(stack["name"]):
                files = stack["config"]["config_files"]
                self.assertEqual([f["path"] for f in files], want)
                self.assertTrue(all(f["services"] == ["alloy"] and f["requires"] == "Restart" for f in files))

    def test_modules_declared_are_the_modules_used(self):
        declared = {m for p in (AGENT / "modules").glob("*.alloy") for m in re.findall(r'^declare "(\w+)"', p.read_text(), re.M)}
        used = set(re.findall(r"^homelab\.(\w+) ", (AGENT / "config.alloy").read_text(), re.M))
        self.assertEqual(used, declared)


class Dashboards(unittest.TestCase):
    def setUp(self):
        self.builder = load_builder()

    def test_committed_json_is_what_the_builder_builds(self):
        for name, text in self.builder.render().items():
            with self.subTest(name):
                path = self.builder.OUT / name
                self.assertTrue(path.is_file(), f"run python3 tools/build_dashboards.py and commit {name}")
                self.assertEqual(path.read_text(), text, f"{name} is stale: run python3 tools/build_dashboards.py")
        self.assertEqual(sorted(p.name for p in self.builder.OUT.glob("*.json")), sorted(self.builder.DASHBOARDS))

    def test_dashboards_use_the_provisioned_datasources(self):
        provisioned = (GRAFANA / "grafana-datasources/datasources.yaml").read_text()
        for ds in (self.builder.PROM, self.builder.LOKI):
            self.assertIn(f"uid: {ds['uid']}", provisioned)
            self.assertRegex(provisioned, rf"uid: {ds['uid']}\n\s+type: {ds['type']}\n")


class LxcCpu(unittest.TestCase):
    def test_script_names_every_lxc_machine_and_runs_as_a_cgi(self):
        script = GRAFANA / "lxc-cpu/metrics.sh"
        self.assertTrue(os.access(script, os.X_OK), "busybox httpd only runs an executable script")
        named = dict(re.findall(r"(\d+)=([\w-]+)", re.search(r'-v map="([^"]*)"', script.read_text()).group(1)))
        want = {f["VMID"]: name for p in (AGENT / "hosts").glob("*.yaml")
                for name, f in [(p.stem, host_file(p))] if f["HOST_KIND"] == "lxc"}
        self.assertEqual(named, want)

    def test_script_reads_a_guest_cgroup(self):
        with tempfile.TemporaryDirectory() as root:
            g = Path(root, "118")
            g.mkdir()
            files = {
                "cpu.stat": "usage_usec 3000000\nuser_usec 2000000\nsystem_usec 1000000\n",
                "cpu.pressure": "some avg10=0.00 avg60=0.00 avg300=0.00 total=500000\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
                "cpuset.cpus.effective": "0-5\n",
                "cpu.max": "max 100000\n",
                "memory.current": "16738639872\n",
                "memory.max": "16777216000\n",
                "memory.stat": "anon 16358060032\nfile 210571264\npgmajfault 2401570343\n",
                "memory.events": "low 0\nhigh 0\nmax 25600906\noom 5\noom_kill 4\n",
                "memory.pressure": "some avg10=98.92 avg60=98.89 avg300=98.92 total=64337454216\nfull avg10=0 avg60=0 avg300=0 total=1\n",
                "io.pressure": "some avg10=29.29 avg60=31.56 avg300=31.33 total=32648168519\nfull avg10=0 avg60=0 avg300=0 total=2\n",
            }
            for name, text in files.items():
                (g / name).write_text(text)
            out = subprocess.run(["sh", str(GRAFANA / "lxc-cpu/metrics.sh")], env={**os.environ, "CGROOT": root},
                                 capture_output=True, text=True, check=True).stdout
        got = dict(re.findall(r'^(\w+)\{host="vpn",vmid="118"\} (\S+)$', out, re.M))
        self.assertEqual({k: float(v) for k, v in got.items()}, {
            "lxc_cpu_usage_seconds_total": 3, "lxc_cpu_user_seconds_total": 2, "lxc_cpu_system_seconds_total": 1,
            "lxc_pressure_cpu_waiting_seconds_total": 0.5, "lxc_pressure_cpu_stalled_seconds_total": 0,
            "lxc_cpu_cores": 6, "lxc_memory_usage_bytes": 16738639872, "lxc_memory_limit_bytes": 16777216000,
            "lxc_memory_anon_bytes": 16358060032, "lxc_memory_oom_kills_total": 4,
            "lxc_memory_major_faults_total": 2401570343,
            "lxc_pressure_memory_waiting_seconds_total": 64337.454216, "lxc_pressure_memory_stalled_seconds_total": 0.000001,
            "lxc_pressure_io_waiting_seconds_total": 32648.168519, "lxc_pressure_io_stalled_seconds_total": 0.000002,
        })

    def test_prometheus_scrapes_it_and_loads_the_rules(self):
        prom = (GRAFANA / "prometheus.yml").read_text()
        self.assertIn('metrics_path: /cgi-bin/metrics', prom)
        self.assertIn('lxc-cpu:9101', prom)
        self.assertIn('- "lxc-rules.yml"', prom)


class ReadOnlyProxy(unittest.TestCase):
    def test_proxy_allows_only_get_and_the_listed_paths(self):
        conf = (GRAFANA / "readonly-proxy/default.conf.template").read_text()
        self.assertIn("if ($method_ok = 0) { return 403; }", conf)
        self.assertNotRegex(conf, r"limit_except|\bPUT\b|\bDELETE\b|\bPATCH\b")
        block = re.search(r'map "\$request_method:\$uri" \$method_ok \{(.*?)\}', conf, re.S).group(1)
        allowed = re.findall(r'^\s*"([^"]+)"\s+1;', block, re.M)
        self.assertEqual(sorted(allowed), sorted(["~^GET:", "POST:/coverage/watch",
                                                  "POST:/coverage/unwatch", "POST:/coverage/refresh",
                                                  "POST:/coverage/grab"]))
        paths = re.findall(r"^\s*location\s+(?:[=~]\s+)?(\S+)", conf, re.M)
        self.assertEqual(sorted(paths), sorted(["/", "/api/v1/query", "/api/v1/query_range", "/api/v1/series",
                                                "/api/v1/labels", "/api/v1/metadata",
                                                "^/api/v1/label/[^/]+/values$", "/homepage/", "/coverage/"]))


if __name__ == "__main__":
    unittest.main()
