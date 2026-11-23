"""MISSION-ROUTER-001 Amendment 024: `python3 -m mission_router.status`, the completion check an agent runs before it
reports work done. It replaces the deprecated mission_state.py --assert-closeout."""

from __future__ import annotations

import contextlib
import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mission_router import status  # noqa: E402
from mission_router.router import MissionRouter  # noqa: E402

from tests import test_mission_router as rt  # noqa: E402


class MissionStatusTests(unittest.TestCase):
    """Vector 142, on the router's own fake GitHub: only a landed mission is done."""

    def setUp(self):
        self.t = rt.RouterLoopTests()
        self.t.setUp()
        self.gh = self.t.gh

    def start_mission(self):
        return self.t.start_mission()

    def a2_round(self, r):
        return self.t.a2_round(r)

    def a3_round(self, r, verdict):
        return self.t.a3_round(r, verdict)

    def check(self, mid):
        router = MissionRouter(self.gh, rt.config(), rt.CLASSIFY, dry_run=True, log=lambda *_: None)
        return status.mission_status(router, mid)

    def test_v142_a_mission_is_done_only_once_its_a3_pass_is_merged(self):
        MID = rt.MID
        self.start_mission()
        done, line = self.check(MID)
        self.assertFalse(done)
        self.assertTrue(line.startswith(f"NOT DONE: {MID} is AWAIT_A2"), line)
        self.a2_round(1)
        self.assertIn("AWAIT_A3", self.check(MID)[1])
        before = dict(self.gh.branches)
        n = self.a3_round(1, "PASS")
        self.assertEqual(self.gh.prs[n]["state"], "closed")
        done, line = self.check(MID)
        self.assertTrue(done, line)
        self.assertTrue(line.startswith(f"DONE: {MID} is DONE"), line)
        self.assertIsNotNone(before)

    def test_v142_the_check_writes_nothing(self):
        MID = rt.MID
        self.start_mission()
        branches, prs = dict(self.gh.branches), {k: dict(v) for k, v in self.gh.prs.items()}
        comments = len(getattr(self.gh, "comments", []) or [])
        self.check(MID)
        self.assertEqual(self.gh.branches, branches)
        self.assertEqual({k: v["state"] for k, v in self.gh.prs.items()}, {k: v["state"] for k, v in prs.items()})
        self.assertEqual(len(getattr(self.gh, "comments", []) or []), comments)


class PrStatusTests(unittest.TestCase):
    """Vector 142: a hand-built PR is done only when merged by a HITL login."""

    def request(self, pr):
        return lambda method, path, body=None: pr

    def test_v142_merged_by_hitl_is_done_and_nothing_else_is(self):
        merged = {"merged_at": "2026-11-23T00:00:00Z", "merged_by": {"login": "Operator"}, "state": "closed"}
        self.assertEqual(status.pr_status(self.request(merged), ["operator"], 5)[0], True)
        by_bot = {**merged, "merged_by": {"login": "github-actions[bot]"}}
        done, line = status.pr_status(self.request(by_bot), ["operator"], 5)
        self.assertFalse(done)
        self.assertIn("not a HITL login", line)
        self.assertFalse(status.pr_status(self.request({"state": "open"}), ["operator"], 5)[0])
        self.assertFalse(status.pr_status(self.request({"state": "closed", "merged_at": None}), ["operator"], 5)[0])

    def test_v142_the_cli_exits_0_only_when_done_and_2_when_it_cannot_tell(self):
        def run(argv, make_router=None):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = status.main(argv, make_router=make_router)
            return code, out.getvalue().strip()

        def broken(config):
            raise RuntimeError("no GitHub")

        code, line = run(["--repo", "o/r", "--mission", "M-X-001"], make_router=broken)
        self.assertEqual(code, status.ERROR_EXIT)
        self.assertTrue(line.startswith("NOT DONE: cannot tell"), line)


if __name__ == "__main__":
    unittest.main()
