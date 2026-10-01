"""job-heartbeat: the POSIX sh wrapper that pings healthchecks.io around a scheduled job.
Uses a real local http.server on 127.0.0.1 so the real curl exercises the actual network path,
plus a fake curl on PATH for the one thing a real server can't show us (the exact argv curl
was called with, to prove the ping key never appears there).
Run from the repo root: python3 -m unittest discover tests"""
import http.server
import os
import re
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "ansible/roles/proxmox_host/files/job-heartbeat"
FAKE_KEY = "testkey123"


class Hits(http.server.BaseHTTPRequestHandler):
    """Records every request path it gets; answers 200 with an empty body unless told to fail."""

    log = []
    fail = False

    def do_GET(self):
        self.__class__.log.append(self.path)
        if self.__class__.fail:
            self.send_response(500)
        else:
            self.send_response(200)
        self.end_headers()

    def log_message(self, *a):  # quiet: unittest -v is noisy enough already
        pass


class Server:
    """A throwaway http.server.ThreadingHTTPServer bound to 127.0.0.1:0 (ephemeral port)."""

    def __init__(self):
        Hits.log = []
        Hits.fail = False
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Hits)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base(self):
        return "http://127.0.0.1:%d" % self.httpd.server_address[1]

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def run_heartbeat(slug, cmd, *, base, key_file=None, state_dir, path_prepend=None, env_extra=None):
    env = dict(os.environ)
    env["JOB_HEARTBEAT_BASE"] = base
    env["JOB_HEARTBEAT_STATE"] = str(state_dir)
    if key_file is not None:
        env["JOB_HEARTBEAT_KEY_FILE"] = str(key_file)
    else:
        # A path that cannot exist: exercises the "key file missing entirely" case.
        env["JOB_HEARTBEAT_KEY_FILE"] = str(Path(state_dir) / "no-such-key")
    if path_prepend:
        env["PATH"] = str(path_prepend) + os.pathsep + env["PATH"]
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["sh", str(SCRIPT), slug, "--", *cmd],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


class JobHeartbeat(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(self.tmp)]))
        self.state = self.tmp / "state"
        self.state.mkdir()
        self.key_file = self.tmp / "ping_key"
        self.key_file.write_text(FAKE_KEY + "\n")
        self.server = Server()
        self.addCleanup(self.server.stop)

    def marker(self, slug):
        return self.state / (slug + ".ping-failed")

    # --- real curl against the local server ---------------------------------------------

    def test_success_pings_start_then_zero(self):
        result = run_heartbeat(
            "snapraid", ["true"], base=self.server.base, key_file=self.key_file, state_dir=self.state
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(Hits.log, ["/%s/snapraid/start" % FAKE_KEY, "/%s/snapraid/0" % FAKE_KEY])
        self.assertFalse(self.marker("snapraid").exists())

    def test_failure_exit_code_pings_start_then_code_and_exits_same_code(self):
        result = run_heartbeat(
            "sanoid", ["sh", "-c", "exit 3"], base=self.server.base, key_file=self.key_file, state_dir=self.state
        )
        self.assertEqual(result.returncode, 3)
        self.assertEqual(Hits.log, ["/%s/sanoid/start" % FAKE_KEY, "/%s/sanoid/3" % FAKE_KEY])

    def test_successful_ping_removes_a_stale_marker(self):
        self.marker("snapraid").touch()
        run_heartbeat("snapraid", ["true"], base=self.server.base, key_file=self.key_file, state_dir=self.state)
        self.assertFalse(self.marker("snapraid").exists())

    def test_output_passthrough_is_byte_identical(self):
        # Mixed stdout/stderr, including a trailing-newline-less line and a NUL-free binary-ish byte.
        prog = "import sys; sys.stdout.buffer.write(b'out\\xc3\\xa9 line'); sys.stderr.write('err line\\n')"
        direct = subprocess.run([sys.executable, "-c", prog], capture_output=True)
        wrapped = run_heartbeat(
            "snapraid",
            [sys.executable, "-c", prog],
            base=self.server.base,
            key_file=self.key_file,
            state_dir=self.state,
        )
        self.assertEqual(wrapped.stdout.encode(), direct.stdout)
        self.assertIn("err line", wrapped.stderr)

    # --- server unreachable: the protected command must still run and win ------------------

    def test_server_down_command_still_runs_status_preserved_marker_set_key_not_leaked(self):
        self.server.stop()
        marker_path = self.tmp / "ran"
        result = run_heartbeat(
            "sanoid",
            ["sh", "-c", "touch %s; exit 7" % marker_path],
            base="http://127.0.0.1:1",  # nothing listens here
            key_file=self.key_file,
            state_dir=self.state,
        )
        self.assertEqual(result.returncode, 7)
        self.assertTrue(marker_path.exists(), "the protected command must run even if pinging fails")
        self.assertTrue(self.marker("sanoid").exists())
        self.assertNotIn(FAKE_KEY, result.stderr)
        self.assertNotIn(FAKE_KEY, result.stdout)

    def test_missing_key_file_entirely_command_still_runs(self):
        marker_path = self.tmp / "ran2"
        result = run_heartbeat(
            "sanoid",
            ["sh", "-c", "touch %s; exit 0" % marker_path],
            base=self.server.base,
            key_file=None,  # no JOB_HEARTBEAT_KEY_FILE path exists on disk
            state_dir=self.state,
        )
        self.assertEqual(result.returncode, 0)
        self.assertTrue(marker_path.exists())
        self.assertTrue(self.marker("sanoid").exists())
        self.assertEqual(Hits.log, [])  # never even tried to reach the server

    def test_never_retries_the_command(self):
        counter = self.tmp / "count"
        self.server.stop()
        run_heartbeat(
            "snapraid",
            ["sh", "-c", "echo x >> %s" % counter],
            base="http://127.0.0.1:1",
            key_file=self.key_file,
            state_dir=self.state,
        )
        self.assertEqual(counter.read_text().count("x"), 1)

    # --- argv: the fake curl records exactly what it was called with -----------------------

    def test_ping_key_never_appears_in_curl_argv(self):
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        argv_file = self.tmp / "argv.txt"
        fake_curl = bin_dir / "curl"
        fake_curl.write_text(
            "#!/usr/bin/env python3\n"
            "import sys, os\n"
            "sys.stdin.read()\n"  # drain the config-file pipe so the writer never sees SIGPIPE
            "with open(os.environ['ARGV_FILE'], 'w') as f:\n"
            "    f.write(repr(sys.argv))\n"
            "sys.exit(0)\n"
        )
        fake_curl.chmod(fake_curl.stat().st_mode | stat.S_IEXEC)
        result = run_heartbeat(
            "snapraid",
            ["true"],
            base=self.server.base,
            key_file=self.key_file,
            state_dir=self.state,
            path_prepend=bin_dir,
            env_extra={"ARGV_FILE": str(argv_file)},
        )
        self.assertEqual(result.returncode, 0)
        recorded = argv_file.read_text()
        self.assertNotIn(FAKE_KEY, recorded)
        self.assertNotIn(self.server.base, recorded)
        self.assertIn("--config", recorded)
        self.assertIn("-o", recorded)
        # The server never saw a real request either: the fake curl took over entirely.
        self.assertEqual(Hits.log, [])

    def test_signal_exit_status_is_128_plus_n(self):
        result = run_heartbeat(
            "snapraid",
            [sys.executable, "-c", "import os, signal; os.kill(os.getpid(), signal.SIGTERM)"],
            base=self.server.base,
            key_file=self.key_file,
            state_dir=self.state,
        )
        self.assertEqual(result.returncode, 128 + 15)

    def test_usage_error_without_separator(self):
        result = subprocess.run(
            ["sh", str(SCRIPT), "slug-only"],
            capture_output=True,
            text=True,
            env=dict(os.environ, JOB_HEARTBEAT_BASE=self.server.base),
            timeout=10,
        )
        self.assertEqual(result.returncode, 2)


class ScriptIsValidPosixSh(unittest.TestCase):
    def test_sh_n(self):
        result = subprocess.run(["sh", "-n", str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_no_bashisms_shebang(self):
        first_line = SCRIPT.read_text().splitlines()[0]
        self.assertTrue(re.match(r"^#!\s*/bin/sh\s*$", first_line), first_line)


if __name__ == "__main__":
    unittest.main()
