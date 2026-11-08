"""Ring 6 part 3 (MISSION-ROUTER-001 Amendment 018; MISSION-DISPATCH-001 §3m items 1 and 5): the router records every
write before it makes it, the decision that allows each merge before the merge, and each HITL command it acts on by
the commenter's account ID; the verifier replays the order. Vector 102 for the router; router vector 118's
prerequisite (enforcement is part 4)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from evidence import chain, producer, verify
from mission_router.github import GitHubError

from tests import test_mission_router as rt

RUN = "gh-1-1-router"


class Loop:
    """The router's own end-to-end harness, with a chain."""

    def __init__(self, test: unittest.TestCase):
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        self.store = Path(tmp.name)
        self.t = rt.RouterLoopTests("test_full_mission_fail_then_pass")
        self.t.setUp()
        self.t.router.evidence = producer.Recorder(self.store, RUN)
        self.gh = self.t.gh

    def records(self):
        path = self.store / verify.RUNS / RUN / chain.RECORDS
        return chain.read(path) if path.is_file() else []

    def actions(self):
        return [r["action"] for r in self.records()]


class RouterRecordTests(unittest.TestCase):
    def test_the_bot_s_records_carry_its_configured_account_id(self):
        loop = Loop(self)
        loop.t.router._accounts[rt.BOT.casefold()] = rt.ACCOUNTS[rt.BOT]
        loop.t.start_mission()
        ours = [r for r in loop.records() if r["actor"]["name"] == rt.BOT]
        self.assertTrue(ours)
        self.assertEqual({r["actor"]["account_id"] for r in ours}, {rt.ACCOUNTS[rt.BOT]})

    def test_a_whole_mission_is_on_record_and_replays(self):
        loop = Loop(self)
        loop.t.start_mission()
        loop.t.a2_round(1)
        loop.t.a3_round(1, "FAIL")
        loop.t.a2_round(2)
        loop.t.a3_round(2, "PASS")
        recs = loop.records()
        actions = set(loop.actions())
        for want in ("router.decision", "router.merge", "router.branch", "router.issue", "router.label",
                     "router.approval_request", "router.hitl_command", "router.comment"):
            self.assertIn(want, actions)
        merges = [r for r in recs if r["action"] == "router.merge" and r["result"] == "done"]
        self.assertEqual(len(merges), 5, "plan, A2 r1, A3 FAIL, A2 r2, A3 PASS")
        report = verify.verify_store(loop.store, {})
        self.assertTrue(report.ok, report.failure)
        for r in recs:
            self.assertNotIn("v2", str(r["reason"]), "the agent's file content is never recorded")

    def test_the_hitl_approval_is_recorded_with_the_account_id(self):
        loop = Loop(self)
        loop.t.start_mission()
        (cmd,) = [r for r in loop.records() if r["action"] == "router.hitl_command"]
        self.assertEqual(cmd["actor"], {"name": rt.HITL, "account_id": rt.ACCOUNTS[rt.HITL]})
        self.assertEqual(cmd["authority"]["kind"], "hitl_command")
        self.assertTrue(cmd["reason"].startswith("HITL command: /mission approve "))
        self.assertEqual(cmd["class"], "read")

    def test_each_merge_is_recorded_before_it_is_made(self):
        loop = Loop(self)
        seen = []
        merge = loop.gh.merge

        def watched(n, sha, title):
            last = loop.records()[-1]
            seen.append((last["action"], last["subject"]["pr"], last["subject"]["commit"]) == ("router.merge", n, sha))
            return merge(n, sha, title)
        loop.gh.merge = watched
        loop.t.start_mission()
        loop.t.a2_round(1)
        self.assertTrue(seen and all(seen), seen)

    def test_a_decision_comes_before_every_merge(self):
        loop = Loop(self)
        loop.t.start_mission()
        recs = loop.records()
        merge = next(i for i, r in enumerate(recs) if r["action"] == "router.merge")
        before = [r for r in recs[:merge] if r["action"] == "router.decision" and r["reason"].startswith("merge:")]
        self.assertTrue(before)
        self.assertEqual((before[-1]["subject"]["pr"], before[-1]["subject"]["commit"]),
                         (recs[merge]["subject"]["pr"], recs[merge]["subject"]["commit"]))

    def test_a_write_github_refuses_is_recorded_as_failed(self):
        loop = Loop(self)
        loop.gh.merge_blocked = True
        loop.gh.protected = {"main"}
        loop.t.start_mission()
        loop.t.a2_round(1)
        loop.t.a3_round(1, "PASS")
        failed = [r for r in loop.records() if r["result"] == "failed"]
        self.assertTrue(failed)
        self.assertIn("GitHub refused it (405)", failed[-1]["reason"])
        self.assertTrue(verify.verify_store(loop.store, {}).ok)

    def test_a_refusal_is_recorded(self):
        loop = Loop(self)
        loop.t.start_mission()
        loop.t.a2_round(1, files={"tools/elsewhere/app.py": "v1"})
        refusals = [r for r in loop.records() if r["action"] == "router.refusal"]
        self.assertTrue(refusals)
        self.assertEqual({r["class"] for r in refusals}, {"refuse"})

    def test_a_halt_is_recorded_with_the_command_it_acted_on(self):
        loop = Loop(self)
        loop.t.start_mission()
        issue = loop.t.issue()
        loop.gh.comment_as(issue["number"], rt.HITL, "Stopping to look at this.\n/mission halt")
        loop.t.sweep()
        recs = loop.records()
        halt_cmd = [r for r in recs if r["action"] == "router.hitl_command" and r["reason"] == "HITL command: /mission halt"]
        self.assertEqual(halt_cmd[0]["actor"]["account_id"], rt.ACCOUNTS[rt.HITL])
        self.assertIn("router.halt", [r["action"] for r in recs])
        self.assertLess(recs.index(halt_cmd[0]), [r["action"] for r in recs].index("router.halt"))

    def test_a_retry_command_is_found(self):
        loop = Loop(self)
        router = loop.t.router
        router._comments[42] = [{"id": 9, "user": rt.who(rt.HITL, "User"), "body": "/mission retry"},
                                {"id": 10, "user": rt.who("someone-else", "User"), "body": "/mission halt"}]
        self.assertEqual(router._record_commands(42, rt.MID, "AWAIT_A2"), (True, False),
                         "only HITL's commands count")
        (rec,) = loop.records()
        self.assertEqual((rec["reason"], rec["authority"]["ref"]), ("HITL command: /mission retry", "comment 9 on #42"))

    def test_a_dry_run_records_nothing(self):
        loop = Loop(self)
        loop.t.router.dry_run = True
        loop.t.sweep()
        self.assertEqual(loop.records(), [])

    def test_without_a_chain_the_router_records_nothing(self):
        t = rt.RouterLoopTests("test_full_mission_fail_then_pass")
        t.setUp()
        self.assertFalse(t.router.evidence.enabled)


class ReplayTests(unittest.TestCase):
    def store_with(self, entries):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        rec = producer.Recorder(Path(tmp.name), RUN)
        for action, reason, pr, commit in entries:
            rec.record(actor=rt.BOT, account_id=7001, action=action, result="done", reason=reason, pr=pr,
                       commit=commit, authority_kind="spec_rule", authority_ref="MISSION-ROUTER-001")
        return Path(tmp.name)

    def test_a_merge_with_no_decision_before_it_is_refused(self):
        store = self.store_with([("router.merge", "merge PR #7", 7, "a" * 40)])
        self.assertIn("router.merge of PR #7 at aaaaaaaaaaaa has no recorded decision before it",
                      verify.verify_store(store, {}).failure)

    def test_a_decision_for_another_commit_does_not_count(self):
        store = self.store_with([("router.decision", "merge: ok", 7, "b" * 40),
                                 ("router.merge", "merge PR #7", 7, "a" * 40)])
        self.assertIn("no recorded decision before it", verify.verify_store(store, {}).failure)

    def test_a_decision_after_the_merge_does_not_count(self):
        store = self.store_with([("router.landing", "merge landing PR #8", 8, "a" * 40),
                                 ("router.decision", "merge: ok", 8, "a" * 40)])
        self.assertIn("router.landing of PR #8", verify.verify_store(store, {}).failure)

    def test_decision_then_merge_replays(self):
        store = self.store_with([("router.decision", "merge: ok", 7, "a" * 40),
                                 ("router.merge", "merge PR #7", 7, "a" * 40)])
        self.assertTrue(verify.verify_store(store, {}).ok)


class WorkflowTests(unittest.TestCase):
    def test_the_router_sweep_starts_and_keeps_its_chain(self):
        root = Path(__file__).resolve().parents[3]
        live = root / ".github" / "workflows" / "mission-router.yml"
        text = (live if live.is_file() else root / "packaging" / "workflows" / "mission-router.yml").read_text()
        self.assertIn("EVIDENCE_RUN=gh-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT-router", text)
        self.assertLess(text.index("Start this sweep's evidence chain"), text.index("- name: Sweep missions"))
        keep = text.index("Keep this sweep's evidence chain")
        self.assertIn("if: always()", text[keep:keep + 200])


if __name__ == "__main__":
    unittest.main()
