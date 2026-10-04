"""The telemetry agent (stacks/monitoring) and the dashboards built for it: every machine is wired
the same way, and the committed dashboard JSON is what tools/build_dashboards.py builds.
Run from the repo root: python3 -m unittest discover tests"""
import importlib.util
import json
import re
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
    """HOST, HOST_KIND, VMID and hostname from a hosts/<name>.yaml (flat, so read without PyYAML)."""
    text = path.read_text()
    found = dict(re.findall(r"^\s+(HOST|HOST_KIND|VMID|hostname):\s*\"?([\w.-]*)\"?\s*$", text, re.M))
    return found


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
                self.assertEqual(found.get("hostname"), name)
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

    def test_queries_only_name_jobs_the_agent_sends(self):
        jobs = {j for p in (AGENT / "modules").glob("*.alloy") for j in re.findall(r'"(integrations/\w+)"', p.read_text())}
        for name, build in self.builder.DASHBOARDS.items():
            text = json.dumps(build())
            with self.subTest(name):
                self.assertTrue(set(re.findall(r'integrations/\w+', text)) <= jobs)

    def test_panels_have_unique_ids_and_dont_overlap(self):
        for name, build in self.builder.DASHBOARDS.items():
            top = build()["panels"]
            panels = top + [c for p in top for c in p.get("panels", [])]
            with self.subTest(name):
                ids = [p["id"] for p in panels]
                self.assertEqual(len(ids), len(set(ids)))
                # The dashboard as it opens, then each collapsed row's panels as they show once it is opened.
                for group in [top] + [p["panels"] for p in top if p.get("panels")]:
                    cells = set()
                    for q in group:
                        g = q["gridPos"]
                        self.assertLessEqual(g["x"] + g["w"], 24, q["title"])
                        mine = {(x, y) for x in range(g["x"], g["x"] + g["w"]) for y in range(g["y"], g["y"] + g["h"])}
                        self.assertFalse(cells & mine, f"{q['title']} overlaps another panel")
                        cells |= mine

    def test_grafana_provisions_the_dashboards_folder(self):
        compose = (GRAFANA / "compose.yaml").read_text()
        provider = (GRAFANA / "grafana-dashboards-provider/homelab.yaml").read_text()
        mount = re.search(r"- \./grafana-dashboards:(\S+):ro", compose).group(1)
        self.assertIn(f"path: {mount}", provider)


if __name__ == "__main__":
    unittest.main()
