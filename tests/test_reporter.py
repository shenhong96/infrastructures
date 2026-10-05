"""The deploy reporter's decisions (ansible/roles/semaphore/files/reporter.py): what each commit's
deploy/ansible and deploy/stacks say, and that nothing but fixed wording and lab links goes out.
Run from the repo root: python3 -m unittest discover tests"""
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ansible/roles/semaphore/files"))
import reporter as r  # noqa: E402

SEM = "http://192.168.9.161:3000"
KOM = "http://192.168.9.151:9120"
CFG = {"repo": "o/r", "branch": "main", "semaphore": SEM, "project": 1, "template": 1,
       "komodo": KOM, "procedure": "reconcile", "gotify": "http://192.168.9.151:8087"}
A, B = "a" * 40, "b" * 40  # B is the newer
T0 = 1_000_000.0  # A merged; B a minute later


def facts(now=T0 + 120, statuses=None, tasks=(), komodo=None):
    """tasks=None: Semaphore unreadable; komodo=None: Komodo unreadable."""
    return {"now": now, "commits": [{"sha": B, "time": T0 + 60}, {"sha": A, "time": T0}],
            "statuses": statuses or {}, "tasks": None if tasks is None else list(tasks), "komodo": komodo}


def status(state, description, url=None, created=T0):
    return {"state": state, "description": description, "url": url, "created": created}


def out(f, context):
    """{sha: (state, description, url, push)} for one context."""
    return {s["sha"]: (s["state"], s["description"], s["url"], s["push"])
            for s in r.decide(f, CFG) if s["context"] == context}


class Ansible(unittest.TestCase):
    TEMPLATE = f"{SEM}/project/1/templates/1"

    def task(self, id_=7, status_="success", commit=B, created=T0 + 70):
        return {"id": id_, "status": status_, "commit": commit, "created": created}

    def test_a_new_commit_waits_for_semaphore(self):
        self.assertEqual(out(facts(), "deploy/ansible")[B], ("pending", "waiting for Semaphore", self.TEMPLATE, False))

    def test_nothing_ran_in_15_minutes_is_an_error_and_pushes(self):
        f = facts(now=T0 + 60 + r.WAIT,
                  statuses={B: {"deploy/ansible": status("pending", "waiting for Semaphore", self.TEMPLATE, T0 + 60)}})
        self.assertEqual(out(f, "deploy/ansible")[B], ("error", "nothing ran in 15 min", self.TEMPLATE, True))

    def test_a_running_task_links_to_itself(self):
        f = facts(tasks=[self.task(status_="running")])
        self.assertEqual(out(f, "deploy/ansible")[B], ("pending", "ansible running", f"{SEM}/project/1/history?t=7", False))

    def test_one_run_covers_the_earlier_commit_and_names_itself(self):
        got = out(facts(tasks=[self.task()]), "deploy/ansible")
        self.assertEqual(got[B][:2], ("success", "ansible run succeeded"))
        self.assertEqual(got[A][:2], ("success", "in bbbbbbb's run: ansible run succeeded"))

    def test_a_run_of_the_older_commit_doesnt_cover_the_newer(self):
        got = out(facts(tasks=[self.task(commit=A, created=T0 + 10)]), "deploy/ansible")
        self.assertEqual(got[A][:2], ("success", "ansible run succeeded"))
        self.assertEqual(got[B][:2], ("pending", "waiting for Semaphore"))

    def test_the_first_finished_run_after_a_commit_decides_it(self):
        f = facts(tasks=[self.task(8, "success", created=T0 + 900), self.task(7, "error")])
        self.assertEqual(out(f, "deploy/ansible")[B][:2], ("failure", "ansible run failed"))

    def test_a_failed_run_pushes_once(self):
        f = facts(tasks=[self.task(status_="error")])
        self.assertTrue(out(f, "deploy/ansible")[B][3])
        f["statuses"] = {B: {"deploy/ansible": status("failure", "ansible run failed", f"{SEM}/project/1/history?t=7")}}
        self.assertNotIn(B, out(f, "deploy/ansible"))

    def test_no_runner_is_an_error_not_a_failure(self):
        f = facts(tasks=[self.task(status_="error", commit=None)])
        self.assertEqual(out(f, "deploy/ansible")[B],
                         ("error", "nothing ran: no checkout", f"{SEM}/project/1/history?t=7", True))

    def test_a_later_run_turns_an_error_green(self):
        f = facts(tasks=[self.task(7, "error", commit=None), self.task(8, "success", created=T0 + 900)],
                  statuses={B: {"deploy/ansible": status("error", "nothing ran: no checkout")}})
        self.assertEqual(out(f, "deploy/ansible")[B][:2], ("success", "ansible run succeeded"))

    def test_a_stopped_run_is_an_error(self):
        self.assertEqual(out(facts(tasks=[self.task(status_="stopped")]), "deploy/ansible")[B][:2],
                         ("error", "ansible run stopped"))

    def test_a_later_run_replaces_a_stopped_one_on_the_same_commit(self):
        was = {B: {"deploy/ansible": status("error", "ansible run stopped")}}
        running = facts(tasks=[self.task(7, "stopped"), self.task(8, "running", created=T0 + 900)], statuses=was)
        self.assertEqual(out(running, "deploy/ansible")[B][:2], ("pending", "ansible running"))
        done = facts(tasks=[self.task(7, "stopped"), self.task(8, "success", created=T0 + 900)], statuses=was)
        self.assertEqual(out(done, "deploy/ansible")[B][:2], ("success", "ansible run succeeded"))

    def test_a_later_run_of_a_newer_commit_replaces_a_stopped_one(self):
        f = facts(tasks=[self.task(7, "stopped", commit=A, created=T0 + 10), self.task(8, "success", created=T0 + 900)],
                  statuses={A: {"deploy/ansible": status("error", "ansible run stopped")}})
        self.assertEqual(out(f, "deploy/ansible")[A][:2], ("success", "in bbbbbbb's run: ansible run succeeded"))

    def test_a_result_stays_whatever_runs_later(self):
        f = facts(tasks=[self.task(7, "error"), self.task(8, "success", created=T0 + 900)],
                  statuses={B: {"deploy/ansible": status("failure", "ansible run failed")}})
        self.assertNotIn(B, out(f, "deploy/ansible"))

    def test_semaphore_unreadable_decides_nothing(self):
        self.assertEqual(out(facts(tasks=None), "deploy/ansible"), {})

    def test_an_unchanged_status_isnt_posted_again(self):
        f = facts(statuses={B: {"deploy/ansible": status("pending", "waiting for Semaphore", self.TEMPLATE, T0 + 60)}})
        self.assertNotIn(B, out(f, "deploy/ansible"))

    def test_a_task_on_a_commit_outside_the_list_is_ignored(self):
        f = facts(tasks=[self.task(commit="c" * 40)])
        self.assertEqual(out(f, "deploy/ansible")[B][:2], ("pending", "waiting for Semaphore"))

    def test_a_change_says_since_when_its_commit_waited(self):
        f = facts(tasks=[self.task()],
                  statuses={B: {"deploy/ansible": status("pending", "waiting for Semaphore", self.TEMPLATE, T0 + 90)}})
        self.assertEqual({s["sha"]: s["since"] for s in r.decide(f, CFG) if s["context"] == "deploy/ansible"},
                         {B: T0 + 90, A: T0})


class WhatLeavesTheLab(unittest.TestCase):
    def test_only_fixed_wording(self):
        for text in ("immich: deploy failed", "in abcdef1's run: ansible run failed", "no stacks changed",
                     "immich: unhealthy +2 more"):
            self.assertEqual(r.clean(text, None, CFG)[0], text)
        for text in ("immich: Error: password=hunter2", "ansible run failed: TASK [nextcloud]",
                     "Immich: deploy failed", "x" * 141, "immich: deploy failed\nmore"):
            self.assertIsNone(r.clean(text, None, CFG)[0])

    def test_links_only_to_the_lab(self):
        for url in (f"{SEM}/project/1/history?t=7", f"{KOM}/updates/u1"):
            self.assertEqual(r.clean("stacks deployed", url, CFG)[1], url)
        for url in ("https://evil.example/x", f"{SEM}.evil.example/", f"{SEM}@evil.example/"):
            self.assertIsNone(r.clean("stacks deployed", url, CFG)[1])

    def test_every_phrase_fits_with_a_run_prefix(self):
        for phrase in r.PHRASES:
            self.assertLessEqual(len(f"in abcdef1's run: {phrase}"), 140)

    def test_odd_stack_names_become_stack(self):
        self.assertEqual(r.safe("immich"), "immich")
        self.assertEqual(r.safe("Immich Prod; rm -rf"), "stack")
        self.assertEqual(r.safe("x" * 41), "stack")

    def test_semaphore_nanoseconds(self):
        self.assertEqual(r.ts("2026-10-05T01:02:03.123456789Z"), r.ts("2026-10-05T01:02:03.123456Z"))


UP = {"state": "running", "status": "Up 3 minutes"}  # no health check


def stack(id_="s1", name="immich", latest=B[:8], deployed=B[:8], pending=False, deploys=None, services=(UP,)):
    """A stack as gather() hands it over. By default: Komodo pulled B and deployed it at B at
    T0+200 to T0+300, and it is up."""
    return {"id": id_, "name": name, "latest": latest, "deployed": deployed, "pending": pending,
            "deploys": [{"id": "d1", "start": T0 + 200, "end": T0 + 300, "success": True}] if deploys is None else deploys,
            "services": None if services is None else list(services)}


def kom(*stacks, runs=()):
    return {"procedure": "p1", "runs": list(runs), "stacks": list(stacks)}


class Stacks(unittest.TestCase):
    PROC = f"{KOM}/procedures/p1"
    RUN = f"{KOM}/updates/u1"
    OLD = "0" * 8  # a hash older than the commits the reporter looks at

    def got(self, komodo, now=T0 + 300 + r.GRACE, statuses=None):
        return out(facts(now=now, tasks=None, komodo=komodo, statuses=statuses), "deploy/stacks")

    def test_waits_until_komodo_has_pulled_the_commit(self):
        self.assertEqual(self.got(kom(stack(latest=A[:8], deployed=A[:8])))[B], ("pending", "waiting for Komodo", self.PROC, False))

    def test_a_commit_that_changed_no_stack(self):
        self.assertEqual(self.got(kom(stack(deployed=self.OLD, deploys=[], services=None)))[B][:2], ("success", "no stacks changed"))

    def test_deployed_and_up(self):
        got = self.got(kom(stack(), runs=[{"id": "u1", "start": T0 + 190, "done": True, "success": True}]))
        self.assertEqual(got[B], ("success", "stacks deployed", self.RUN, False))

    def test_the_run_that_pulled_it_counts_however_soon_after_the_merge(self):
        # Review F2: deployed by a run that started 10 s after the merge, unhealthy since; a later run changed nothing.
        k = kom(stack(deploys=[{"id": "d1", "start": T0 + 70, "end": T0 + 80, "success": True}],
                      services=[{"state": "running", "status": "Up 9 minutes (unhealthy)"}]),
                runs=[{"id": "u0", "start": T0 + 70, "done": True, "success": True},
                      {"id": "u1", "start": T0 + 400, "done": True, "success": True}])
        self.assertEqual(self.got(k, now=T0 + 800)[B], ("failure", "immich: unhealthy", f"{KOM}/stacks/s1", True))

    def test_one_pull_covers_the_earlier_commit_and_names_itself(self):
        self.assertEqual(self.got(kom(stack()))[A][:2], ("success", "in bbbbbbb's run: stacks deployed"))

    def test_a_stack_deployed_before_the_commit_isnt_its_business(self):
        k = kom(stack(), stack("s2", "canary", deployed=A[:8], deploys=[],
                                services=[{"state": "running", "status": "Up 2 days (unhealthy)"}]))
        self.assertEqual(self.got(k)[B][:2], ("success", "stacks deployed"))

    def test_a_failed_deploy_names_the_stack_and_links_its_log(self):
        k = kom(stack(deployed=A[:8], pending=True, deploys=[{"id": "d9", "start": T0 + 200, "end": None, "success": False}]))
        self.assertEqual(self.got(k)[B], ("failure", "immich: deploy failed", f"{KOM}/updates/d9", True))

    def test_a_change_komodo_hasnt_deployed_waits_then_errors(self):
        k = kom(stack(deployed=A[:8], pending=True, deploys=[]))
        self.assertEqual(self.got(k)[B][:2], ("pending", "waiting for Komodo"))
        was = {B: {"deploy/stacks": status("pending", "waiting for Komodo", self.PROC, T0 + 60)}}
        self.assertEqual(self.got(k, now=T0 + 60 + r.WAIT, statuses=was)[B], ("error", "nothing ran in 15 min", self.PROC, True))

    def test_a_failed_reconcile_with_a_change_waiting_is_an_error(self):
        k = kom(stack(deployed=A[:8], pending=True, deploys=[]), runs=[{"id": "u1", "start": T0 + 100, "done": True, "success": False}])
        self.assertEqual(self.got(k)[B], ("error", "reconcile failed", self.RUN, True))

    def test_health(self):
        cases = {  # (container status, inside the grace) -> what deploy/stacks says
            ("Up 3 minutes (healthy)", False): ("success", "stacks deployed"),
            ("Up 3 minutes", False): ("success", "stacks deployed"),  # no health check
            ("Up 9 seconds (health: starting)", True): ("pending", "stacks starting"),
            ("Up 9 minutes (health: starting)", False): ("failure", "immich: unhealthy"),
            ("Up 3 minutes (unhealthy)", True): ("pending", "stacks starting"),
            ("Up 3 minutes (unhealthy)", False): ("failure", "immich: unhealthy"),
        }
        for (text, grace), want in cases.items():
            now = T0 + 300 + (r.GRACE - 1 if grace else r.GRACE)
            got = self.got(kom(stack(services=[UP, {"state": "running", "status": text}])), now=now)[B][:2]
            self.assertEqual(got, want, text)

    def test_a_container_not_running_or_missing(self):
        for services in ([{"state": "exited", "status": "Exited (1) 2 minutes ago"}], [], [{"state": None, "status": None}]):
            self.assertEqual(self.got(kom(stack(services=services)))[B][:2], ("failure", "immich: not running"), services)

    def test_several_bad_stacks(self):
        k = kom(stack(services=[]), stack("s2", "canary", services=[]))
        self.assertEqual(self.got(k)[B][:2], ("failure", "immich: not running +1 more"))

    def test_stacks_are_matched_by_id_not_by_name(self):
        # Review F5: two names that both show as "stack", and a real stack named "stack".
        k = kom(stack("s1", "Bad Name", services=[]), stack("s2", "Other Bad"), stack("s3", "stack"))
        self.assertEqual(self.got(k)[B], ("failure", "stack: not running", f"{KOM}/stacks/s1", True))

    def test_a_short_hash_that_matches_nothing_isnt_the_commit(self):
        self.assertEqual(self.got(kom(stack(latest="c" * 8)))[B][:2], ("pending", "waiting for Komodo"))

    def test_a_restart_only_change_is_checked_too(self):
        # Final review: for a requires = "Restart" file Komodo restarts and leaves deployed_hash where it was.
        restarted = dict(deployed=A[:8], deploys=[{"id": "r1", "start": T0 + 200, "end": T0 + 300, "success": True}])
        self.assertEqual(self.got(kom(stack(**restarted)))[B][:2], ("success", "stacks deployed"))
        sick = stack(**restarted, services=[{"state": "running", "status": "Up 9 minutes (unhealthy)"}])
        self.assertEqual(self.got(kom(sick))[B][:2], ("failure", "immich: unhealthy"))

    def test_komodo_unreadable_decides_nothing(self):
        self.assertEqual(out(facts(tasks=None, komodo=None), "deploy/stacks"), {})


class Pending(unittest.TestCase):
    def test_what_komodo_would_deploy(self):
        f1, f2 = {"path": "compose.yaml", "contents": "a"}, {"path": "compose.yaml", "contents": "b", "requires": "Redeploy"}
        self.assertTrue(r.pending({"deployed_contents": None, "remote_contents": [f1]}))
        self.assertTrue(r.pending({"deployed_contents": [f1], "remote_contents": [f2]}))
        self.assertTrue(r.pending({"deployed_contents": [f1], "remote_contents": [dict(f2, requires="Restart")]}))
        self.assertTrue(r.pending({"deployed_contents": [f1], "remote_contents": [f1, dict(f2, path="app.env")]}))
        self.assertFalse(r.pending({"deployed_contents": [f1], "remote_contents": [dict(f1, services=[], requires="None")]}))
        self.assertFalse(r.pending({"deployed_contents": [f1], "remote_contents": None}))

    def test_changes_komodo_ignores(self):
        # Final review: DeployStackIfChanged skips a changed file whose requires is None (the default) and
        # never looks at a file that is only in what it deployed, so neither ever deploys.
        f1, gone = {"path": "compose.yaml", "contents": "a"}, {"path": "old.env", "contents": "x"}
        self.assertFalse(r.pending({"deployed_contents": [f1], "remote_contents": [dict(f1, contents="b", requires="None")]}))
        self.assertFalse(r.pending({"deployed_contents": [f1, gone], "remote_contents": [dict(f1, requires="Redeploy")]}))


class Newest(unittest.TestCase):
    def test_only_our_contexts_newest_first(self):
        rows = [  # GitHub lists the newest first
            {"context": "deploy/stacks", "state": "success", "description": "stacks deployed",
             "target_url": f"{KOM}/updates/u1", "created_at": "2026-10-05T01:10:00Z"},
            {"context": "gate", "state": "success", "description": "x", "target_url": None,
             "created_at": "2026-10-05T01:09:00Z"},
            {"context": "deploy/stacks", "state": "pending", "description": "waiting for Komodo",
             "target_url": None, "created_at": "2026-10-05T01:00:00Z"},
        ]
        self.assertEqual(r.newest(rows), {"deploy/stacks": {
            "state": "success", "description": "stacks deployed", "url": f"{KOM}/updates/u1",
            "created": r.ts("2026-10-05T01:10:00Z")}})


class Sources(unittest.TestCase):
    """Review F6: a source that answers in the wrong shape skips its own context only."""
    NOW = r.ts("2026-10-05T01:01:00Z")

    def setUp(self):
        home = tempfile.TemporaryDirectory()
        self.addCleanup(home.cleanup)
        for name, text in (("github-token", "g"), ("semaphore-token", "s"), ("komodo-key.json", '{"key": "k", "secret": "x"}')):
            (Path(home.name) / name).write_text(text)
        patcher = mock.patch.object(r, "HOME", Path(home.name))
        patcher.start()
        self.addCleanup(patcher.stop)

    def answers(self, semaphore, stacks, updates=()):
        def fake(url, body=None, headers=None):
            if "/commits?" in url:
                return [{"sha": B, "commit": {"committer": {"date": "2026-10-05T01:00:00Z"}}}]
            if "/statuses" in url:
                return []
            if "/api/project/" in url:
                return semaphore
            request = url.rsplit("/", 1)[1]
            return {"ListProcedures": [{"id": "p1", "name": "reconcile"}], "ListFullStacks": stacks,
                    "ListUpdates": {"updates": list(updates), "next_page": None}, "GetUpdate": {"end_ts": 2_000},
                    "ListStackServices": [{"service": "x", "container": {"state": "running", "status": "Up"}}]}[request]
        return mock.patch.object(r, "call", side_effect=fake)

    def gather(self, semaphore, stacks, updates=()):
        with self.answers(semaphore, stacks, updates), mock.patch("sys.stderr"):
            return r.gather(CFG, self.NOW)

    def test_komodo_answers_in_its_own_shape(self):
        # Final review: ListFullStacks gives whole Stacks, whose id is Mongo's {"$oid": ...} (list items
        # give a plain id), and a change to a requires = "Restart" file shows as a RestartStack update.
        oid = "6700000000000000000000a1"
        stacks = [{"_id": {"$oid": oid}, "name": "immich", "info": {
            "latest_hash": "bbbbbbbb", "deployed_hash": "aaaaaaaa", "deployed_contents": [], "remote_contents": []}}]
        restart = {"id": "u1", "operation": "RestartStack", "target": {"type": "Stack", "id": oid},
                   "start_ts": 1_000, "status": "Complete", "success": True}
        got = self.gather([], stacks, [restart])["komodo"]["stacks"][0]
        self.assertEqual((got["id"], [d["id"] for d in got["deploys"]], got["services"]),
                         (oid, ["u1"], [{"state": "running", "status": "Up"}]))

    def test_a_bad_semaphore_answer_skips_deploy_ansible_only(self):
        for bad in (None, {"tasks": []}, [None], [{"id": 1}], [{"id": 1, "status": "success", "template_id": None, "created": "x"}]):
            got = self.gather(bad, [])
            self.assertIsNone(got["tasks"], bad)
            self.assertEqual(got["komodo"], {"procedure": "p1", "runs": [], "stacks": []}, bad)

    def test_a_bad_komodo_answer_skips_deploy_stacks_only(self):
        for bad in (None, {"stacks": []}, [None], [{"id": "s1"}], [{"id": "s1", "name": "x", "info": None}]):
            got = self.gather([], bad)
            self.assertIsNone(got["komodo"], bad)
            self.assertEqual(got["tasks"], [], bad)


class Main(unittest.TestCase):
    """Review F4: one status's failure never holds back another's."""

    def posted(self, changes):
        """The statuses main() posts while Gotify is down."""
        cfg = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        cfg.write('{"repo": "o/r"}')
        cfg.close()
        self.addCleanup(Path(cfg.name).unlink)
        with mock.patch.object(r, "CONFIG", Path(cfg.name)), mock.patch.object(r, "gather"), \
                mock.patch.object(r, "decide", return_value=changes), \
                mock.patch.object(r, "push", side_effect=OSError("gotify down")), \
                mock.patch.object(r, "github") as github, mock.patch("sys.stdout"), mock.patch("sys.stderr"):
            r.main([])
        return [c.args[0] for c in github.call_args_list]

    def test_a_failed_push_holds_back_only_its_own_status(self):
        changes = [{"sha": A, "context": "deploy/stacks", "state": "failure", "description": "immich: deploy failed",
                    "url": None, "push": True, "since": time.time()},
                   {"sha": B, "context": "deploy/ansible", "state": "success", "description": "ansible run succeeded",
                    "url": None, "push": False, "since": time.time()}]
        self.assertEqual(self.posted(changes), [f"/repos/o/r/statuses/{B}"])

    def test_a_push_that_keeps_failing_lets_its_status_through(self):
        # Final review: Gotify runs in aio, so a merge that breaks aio must still show as failure.
        changes = [{"sha": A, "context": "deploy/stacks", "state": "failure", "description": "aio: unhealthy",
                    "url": None, "push": True, "since": time.time() - r.HOLD}]
        self.assertEqual(self.posted(changes), [f"/repos/o/r/statuses/{A}"])
