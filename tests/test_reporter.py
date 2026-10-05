"""The deploy reporter's decisions (ansible/roles/semaphore/files/reporter.py): what each commit's
deploy/ansible and deploy/stacks say, and that nothing but fixed wording and lab links goes out.
Run from the repo root: python3 -m unittest discover tests"""
import sys
import tempfile
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
