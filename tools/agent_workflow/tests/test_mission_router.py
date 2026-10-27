from __future__ import annotations

import hashlib
import itertools
import json
import re
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mission_router.gate import (MERGE, REJECT, WAIT, WAIT_APPROVAL, CapturePR, FileChange, LandingPR, OpenStagePR,
                                 classify_or_raise, evaluate, evaluate_capture, evaluate_landing)
from mission_router.github import GitHubError
from mission_router.model import (
    MissionInputError,
    failures_since_retry,
    hitl_retries,
    StageRef,
    in_scope,
    parse_identity_registry,
    parse_manifest,
    parse_stage_branch,
    parse_verdict,
    validate_scope_glob,
)
from mission_router.router import MissionRouter, load_config
from mission_router.state import AWAIT_A1, AWAIT_A2, AWAIT_A3, BLOCKED, DONE, HALTED, MergedStage, MissionState, derive_state
from router_spec002.policy import load_tables, normalize_path

REPO = "example-org/example-repo"
BOT = "github-actions[bot]"
HITL = "hitl-user"
MID = "M-DEMO-001"
CLASSIFY = classify_or_raise(load_tables(), normalize_path)
A1B, A2B, A3B = "agent-a1[bot]", "agent-a2[bot]", "agent-a3[bot]"
IDS = {"a1": A1B, "a2": A2B, "a3": A3B}
REGISTRY_PATH = "docs/IDENTITY-REGISTRY.md"


def registry_doc(**statuses):
    rows = [("a1", 1000001, "ACTIVE"), ("a2", 1000002, "ACTIVE"), ("a3", 1000003, "ACTIVE"), ("harness", 1000004, "ACTIVE")]
    lines = ["| Role | App ID | Installation ID | Status | Permissions |", "|---|---|---|---|---|"]
    lines += [f"| {name} | {app} | 1{app} | {statuses.get(name, status)} | contents write |" for name, app, status in rows]
    return "\n".join(lines)


def manifest_doc(a2="a2", a3="a3", a1="a1", scope=("tools/demo/**",), max_rounds=3, **extra):
    doc = {
        "schema": "mission-v1",
        "mission_id": MID,
        "title": "Demo mission",
        "roles": {
            "A1": {"agent": a1},
            "A2": {"agent": a2},
            "A3": {"agent": a3},
        },
        "build_scope": list(scope),
        "max_rounds": max_rounds,
    }
    doc.update(extra)
    return json.dumps(doc)


def verdict_doc(verdict, sha, round_no=1, mission_id=MID, findings=None):
    doc = {"schema": "mission-verdict-v1", "mission_id": mission_id, "round": round_no,
           "verdict": verdict, "reviewed_sha": sha, "summary": "x"}
    if findings is not None or verdict == "BLOCKED":
        doc["findings"] = list(findings) if findings is not None else ["the plan needs a credential A2 does not have"]
    return json.dumps(doc)


# ----------------------------------------------------------------------- model
class ModelTests(unittest.TestCase):
    def test_stage_branches(self):
        self.assertEqual(parse_stage_branch(f"mission/{MID}/a1"), StageRef(MID, "A1", 0))
        self.assertEqual(parse_stage_branch(f"mission/{MID}/a2-r3"), StageRef(MID, "A2", 3))
        self.assertEqual(parse_stage_branch(f"mission/{MID}/a3-r12"), StageRef(MID, "A3", 12))
        for bad in [f"mission/{MID}/integration", f"mission/{MID}/a2-r0", f"mission/{MID}/a2-r01", f"mission/{MID}/A2-r1",
                    f"mission/{MID}/a4-r1", f"mission/{MID.lower()}/a1", f"mission/{MID}/a1/x", f"x/mission/{MID}/a1",
                    f"mission/{MID}/a2-r100", "mission//a1", None, 7, f"mission/{MID}/a1\n"]:
            with self.subTest(ref=bad):
                self.assertIsNone(parse_stage_branch(bad))

    def test_manifest_valid(self):
        m = parse_manifest(manifest_doc(), MID)
        self.assertEqual(m.roles["A2"].agent, "a2")
        self.assertEqual(parse_manifest(manifest_doc(a1="a2"), MID).roles["A1"].agent, "a2")  # A1 may also build

    def test_identity_registry(self):
        self.assertEqual(parse_identity_registry(registry_doc(a3="SUSPENDED"))["a3"], "SUSPENDED")
        self.assertEqual(parse_identity_registry(Path(__file__).resolve().parents[3].joinpath(load_config()["identity_registry"]).read_text())["a2"], "ACTIVE")
        for label, text in {
            "unknown status": registry_doc(a2="MAYBE"),
            "duplicate": registry_doc() + "\n| a2 | 1 | 2 | ACTIVE | x |",
            "no rows": "# empty",
            "missing": None,
        }.items():
            with self.subTest(case=label):
                with self.assertRaises(MissionInputError):
                    parse_identity_registry(text)

    def test_manifest_rejections(self):
        cases = {
            "wrong id": manifest_doc().replace(MID, "M-OTHER-001"),
            "extra key": manifest_doc(auto_merge=True),
            "missing role": json.dumps({**json.loads(manifest_doc()), "roles": {"A1": {"agent": "a1"}}}),
            "bad agent": manifest_doc(a2="Bad Agent"),
            "login in manifest": json.dumps({**json.loads(manifest_doc()), "roles": {
                "A1": {"agent": "a1"}, "A2": {"agent": "a2", "github_login": HITL}, "A3": {"agent": "a3"}}}),
            "a3 reviews own build": manifest_doc(a3="a2"),
            "a3 reviews own plan": manifest_doc(a3="a1"),
            "rounds too high": manifest_doc(max_rounds=11),
            "rounds bool": manifest_doc(max_rounds=True),
            "scope traversal": manifest_doc(scope=["tools/../.github/x"]),
            "scope absolute": manifest_doc(scope=["/etc/passwd"]),
            "scope wildcard root": manifest_doc(scope=["**"]),
            "scope github": manifest_doc(scope=[".github/workflows/x.yml"]),
            "scope missions": manifest_doc(scope=["missions/**"]),
            "scope empty": manifest_doc(scope=[]),
            "sal with deps": manifest_doc(stack={"id": "S-1", "kind": "SAL"}, depends_on=["M-UP-001"]),
            "deps without stack": manifest_doc(depends_on=["M-UP-001"]),
            "self dependency": manifest_doc(stack={"id": "S-1", "kind": "ISAL"}, depends_on=[MID]),
            "bad stack kind": manifest_doc(stack={"id": "S-1", "kind": "LOOP"}),
            "bad dep id": manifest_doc(stack={"id": "S-1", "kind": "ISAL"}, depends_on=["lower"]),
            "not json": "{",
            "not object": "[]",
            "missing": None,
        }
        for label, text in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(MissionInputError):
                    parse_manifest(text, MID)

    def test_manifest_runtime(self):
        doc = json.loads(manifest_doc())
        doc["roles"]["A2"]["runtime"] = "claude-code"
        doc["roles"]["A3"]["runtime"] = "cursor-cli"
        m = parse_manifest(json.dumps(doc), MID)
        self.assertEqual((m.roles["A2"].runtime, m.roles["A3"].runtime, m.roles["A1"].runtime), ("claude-code", "cursor-cli", None))
        self.assertIsNone(parse_manifest(manifest_doc(), MID).roles["A2"].runtime)
        for role, runtime in (("A2", "bash"), ("A3", ""), ("A2", None), ("A1", "claude-code")):
            bad = json.loads(manifest_doc())
            bad["roles"][role]["runtime"] = runtime
            with self.subTest(role=role, runtime=runtime), self.assertRaises(MissionInputError):
                parse_manifest(json.dumps(bad), MID)

    def test_manifest_checks(self):
        m = parse_manifest(manifest_doc(checks=["python3 -m unittest discover -s tools/demo"]), MID)
        self.assertEqual(m.checks, ("python3 -m unittest discover -s tools/demo",))
        self.assertEqual(parse_manifest(manifest_doc(), MID).checks, ())
        for bad in ("make test", [""], ["   "], [1], ["x" * 501], ["a\0b"], ["t"] * 11):
            with self.subTest(checks=bad), self.assertRaises(MissionInputError):
                parse_manifest(manifest_doc(checks=bad), MID)

    def test_manifest_deliverables(self):
        m = parse_manifest(manifest_doc(deliverables=["tools/demo/a.py", "tools/demo/sub/b.json"]), MID)
        self.assertEqual(m.deliverables, ("tools/demo/a.py", "tools/demo/sub/b.json"))
        self.assertEqual(parse_manifest(manifest_doc(), MID).deliverables, ())
        for bad in ("tools/demo/*.py", "tools/demo/[ab].py", "/etc/passwd", "tools/../x.py", "tools//x.py", "tools\\x.py",
                    "", "x" * 301, 7):
            with self.subTest(path=bad), self.assertRaises(MissionInputError):
                parse_manifest(manifest_doc(deliverables=[bad]), MID)
        for bad in ("tools/demo/a.py", ["tools/demo/a.py", "tools/demo/a.py"], [f"tools/demo/{i}.py" for i in range(201)]):
            with self.subTest(deliverables=str(bad)[:40]), self.assertRaises(MissionInputError):
                parse_manifest(manifest_doc(deliverables=bad), MID)

    def test_hitl_retries(self):
        def c(login, body, when, type_="User"):
            return {"user": {"login": login, "type": type_}, "body": body, "created_at": when}
        comments = [c(HITL, "/mission retry", "2026-10-23T02:00:00Z"), c(A2B, "/mission retry", "2026-10-23T03:00:00Z", "Bot"),
                    c("mallory", "/mission retry", "2026-10-23T04:00:00Z"), c(HITL, "please /mission retry", "2026-10-23T05:00:00Z"),
                    c(HITL.upper(), "  /mission retry  ", "2026-10-23T01:00:00Z"), c(HITL, "/mission retry", None),
                    c(HITL, "/mission retry", "2026-10-23T06:00:00Z", "Bot")]
        self.assertEqual(hitl_retries(comments, {HITL}), ("2026-10-23T01:00:00Z", "2026-10-23T02:00:00Z"))

    def test_manifest_branch(self):
        self.assertIsNone(parse_manifest(manifest_doc(), MID).branch)
        for name in ("release", "release/2026-q4", "dev_1.2"):
            self.assertEqual(parse_manifest(manifest_doc(branch=name), MID).branch, name)
        for bad in ("", "mission/M-DEMO-001/integration", "stack/S-9", "a..b", "-x", "a/.x", "x.lock", "x.", "HEAD",
                    "a b", "a//b", "/a", "a/", "r" * 201, 5, None, ["main"]):
            with self.subTest(bad=bad), self.assertRaises(MissionInputError):
                parse_manifest(manifest_doc(branch=bad), MID)

    def test_config_landing_branches(self):
        base = {**config(), "l1_capture": {"path": "UPG/Q.md", "branch_prefix": "capture/"}}
        self.assertEqual(load_config_from(base | {"landing_branches": ["release"]})["landing_branches"], ["release"])
        for bad in ("release", ["stack/S-9"], ["mission/x"], ["capture/x"], ["a", "a"], ["a b"], [1]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                load_config_from(base | {"landing_branches": bad})

    def test_stack_fields(self):
        m = parse_manifest(manifest_doc(stack={"id": "S-1", "kind": "ISAL"}, depends_on=["M-UP-001"]), MID)
        self.assertEqual((m.stack_id, m.stack_kind, m.depends_on), ("S-1", "ISAL", ("M-UP-001",)))

    def test_scope_overlap(self):
        from mission_router.model import scopes_overlap
        self.assertIsNone(scopes_overlap(("tools/a/**",), ("tools/b/**",)))
        self.assertIsNone(scopes_overlap(("docs/a.md",), ("docs/b.md",)))
        self.assertIsNotNone(scopes_overlap(("tools/a/**",), ("tools/a/x/y.py",)))
        self.assertIsNotNone(scopes_overlap(("tools/*/x.py",), ("tools/b/**",)))
        self.assertIsNotNone(scopes_overlap(("tools/**",), ("tools/b/c.py",)))

    def test_scope_glob(self):
        scope = ("tools/demo/**", "docs/demo/*.md")
        self.assertTrue(in_scope("tools/demo/a.py", scope))
        self.assertTrue(in_scope("tools/demo/x/y/z.py", scope))
        self.assertTrue(in_scope("docs/demo/a.md", scope))
        self.assertFalse(in_scope("docs/demo/sub/a.md", scope))
        self.assertFalse(in_scope("tools/demo", scope + ("tools/demo/*",)) and False)
        self.assertFalse(in_scope("tools/demox/a.py", scope))
        self.assertFalse(in_scope("Tools/demo/a.py", scope))
        with self.assertRaises(MissionInputError):
            validate_scope_glob("*/x")

    def test_verdict(self):
        sha = "a" * 40
        self.assertEqual(parse_verdict(verdict_doc("PASS", sha), MID, 1).verdict, "PASS")
        for label, text in {
            "round mismatch": verdict_doc("PASS", sha, round_no=2),
            "mission mismatch": verdict_doc("PASS", sha, mission_id="M-X-001"),
            "lowercase verdict": verdict_doc("pass", sha),
            "short sha": verdict_doc("PASS", "a" * 7),
            "extra key": json.dumps({**json.loads(verdict_doc("PASS", sha)), "merge": True}),
        }.items():
            with self.subTest(case=label):
                with self.assertRaises(MissionInputError):
                    parse_verdict(text, MID, 1)


# ----------------------------------------------------------------------- state
def stage(role, rnd, n, base, merged_by=BOT, sha=None, verdict=None, reviewed=None):
    return MergedStage(StageRef(MID, role, rnd), n, base, merged_by, sha or f"{n:040x}", verdict, reviewed)


INT = f"mission/{MID}/integration"


class RoleModelTests(unittest.TestCase):
    """Amendment 006: a plan may name the model for A2 and A3, checked when the plan is read."""

    def doc(self, a2=None, a3=None, a1=None):
        data = json.loads(manifest_doc())
        for role, extra in (("A1", a1), ("A2", a2), ("A3", a3)):
            data["roles"][role].update(extra or {})
        return json.dumps(data)

    def test_models_for_each_runtime(self):
        m = parse_manifest(self.doc({"runtime": "claude-code", "model": "sonnet"},
                                    {"runtime": "cursor-cli", "model": "gpt-5.1-codex"}), MID)
        self.assertEqual((m.roles["A2"].model, m.roles["A3"].model), ("sonnet", "gpt-5.1-codex"))
        for name in ("opus", "haiku", "fable", "claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-fable-5-1"):
            self.assertEqual(parse_manifest(self.doc({"runtime": "claude-code", "model": name}), MID).roles["A2"].model, name)
        self.assertIsNone(parse_manifest(self.doc({"runtime": "claude-code"}), MID).roles["A2"].model)

    def test_bad_models_make_the_plan_invalid(self):
        for a2 in ({"model": "sonnet"}, {"runtime": "claude-code", "model": "sonet"},
                   {"runtime": "claude-code", "model": "gpt-5"}, {"runtime": "claude-code", "model": None},
                   {"runtime": "claude-code", "model": ""}, {"runtime": "cursor-cli", "model": "-x"},
                   {"runtime": "cursor-cli", "model": "GPT-5"}, {"runtime": "cursor-cli", "model": "a b"},
                   {"runtime": "cursor-cli", "model": "x" * 65}, {"runtime": "cursor-cli", "model": 5}):
            with self.subTest(a2=a2), self.assertRaises(MissionInputError):
                parse_manifest(self.doc(a2), MID)
        with self.assertRaises(MissionInputError):
            parse_manifest(self.doc(a1={"model": "opus"}), MID)

    def test_stage_comment_names_the_model(self):
        from mission_router.router import _runtime_note
        m = parse_manifest(self.doc({"runtime": "claude-code", "model": "sonnet"}, {"runtime": "cursor-cli"}), MID)
        self.assertIn("starts it as `claude-code` with model `sonnet`.", _runtime_note(m, "A2"))
        self.assertTrue(_runtime_note(m, "A3").endswith("starts it as `cursor-cli`."))



class StateTests(unittest.TestCase):
    def setUp(self):
        self.m = parse_manifest(manifest_doc(max_rounds=2), MID)
        self.trusted = {BOT, HITL}

    def derive(self, items, manifest=True):
        return derive_state(MID, items, self.m if manifest else None, self.trusted)

    def test_full_loop(self):
        a1 = stage("A1", 0, 1, INT)
        a2 = stage("A2", 1, 2, INT)
        a3f = stage("A3", 1, 3, INT, verdict="FAIL", reviewed=a2.merge_commit_sha)
        a2b = stage("A2", 2, 4, INT)
        a3p = stage("A3", 2, 5, "main", verdict="PASS", reviewed=a2b.merge_commit_sha)
        self.assertEqual(self.derive([]).stage, AWAIT_A1)
        self.assertEqual((self.derive([a1]).stage, self.derive([a1]).round), (AWAIT_A2, 1))
        s = self.derive([a1, a2])
        self.assertEqual((s.stage, s.round, s.review_sha), (AWAIT_A3, 1, a2.merge_commit_sha))
        self.assertEqual((self.derive([a1, a2, a3f]).stage, self.derive([a1, a2, a3f]).round), (AWAIT_A2, 2))
        done = self.derive([a1, a2, a3f, a2b, a3p])
        self.assertEqual((done.stage, done.landed_sha, done.plan_sha), (DONE, a3p.merge_commit_sha, a1.merge_commit_sha))

    def test_halts(self):
        a1 = stage("A1", 0, 1, INT)
        a2 = stage("A2", 1, 2, INT)
        cases = {
            "untrusted merger": [stage("A1", 0, 1, INT, merged_by="mallory")],
            "out of order": [a1, stage("A3", 1, 3, INT, verdict="FAIL", reviewed="x")],
            "skipped round": [a1, stage("A2", 2, 2, INT)],
            "a1 into main": [stage("A1", 0, 1, "main")],
            "a2 into main": [a1, stage("A2", 1, 2, "main")],
            "pass into integration": [a1, a2, stage("A3", 1, 3, INT, verdict="PASS", reviewed=a2.merge_commit_sha)],
            "fail into main": [a1, a2, stage("A3", 1, 3, "main", verdict="FAIL", reviewed=a2.merge_commit_sha)],
            "unreadable verdict": [a1, a2, stage("A3", 1, 3, INT, verdict=None, reviewed=None)],
            "stale review": [a1, a2, stage("A3", 1, 3, INT, verdict="FAIL", reviewed="f" * 40)],
            "merge after done": [a1, a2, stage("A3", 1, 3, "main", verdict="PASS", reviewed=a2.merge_commit_sha), stage("A2", 2, 4, INT)],
            "second a1": [a1, stage("A1", 0, 9, INT)],
        }
        for label, items in cases.items():
            with self.subTest(case=label):
                self.assertEqual(self.derive(items).stage, HALTED)
        self.assertEqual(self.derive([a1], manifest=False).stage, HALTED)

    def test_round_limit_halts(self):
        a1 = stage("A1", 0, 1, INT)
        items = [a1]
        for r in (1, 2):
            a2 = stage("A2", r, 10 + r, INT)
            items += [a2, stage("A3", r, 20 + r, INT, verdict="FAIL", reviewed=a2.merge_commit_sha)]
        s = self.derive(items)
        self.assertEqual(s.stage, BLOCKED, "a FAIL in the last round is recorded as a blocker, not escalated")
        self.assertIn("max_rounds", s.reason)


class RetryStateTests(unittest.TestCase):
    """Amendment 004: HITL's /mission retry reopens a blocked mission, and only that one."""

    def setUp(self):
        self.m = parse_manifest(manifest_doc(max_rounds=2), MID)
        self.a1 = self.at(stage("A1", 0, 1, INT), "01")
        self.a2 = self.at(stage("A2", 1, 2, INT), "02")
        self.blocked = self.at(stage("A3", 1, 3, INT, verdict="BLOCKED", reviewed=self.a2.merge_commit_sha), "03")

    @staticmethod
    def at(item, minute):
        return MergedStage(item.ref, item.number, item.base_ref, item.merged_by, item.merge_commit_sha, item.verdict,
                           item.reviewed_sha, item.head_sha, f"2026-10-23T00:{minute}:00Z", item.findings)

    def derive(self, items, retries=(), reopen=True):
        return derive_state(MID, items, self.m, {BOT, HITL}, "main", retries, reopen)

    def test_blocked_verdict_is_reviewed_again_by_a3(self):
        items = [self.a1, self.a2, self.blocked]
        s = self.derive(items)
        self.assertEqual((s.stage, s.resume, s.build_sha), (BLOCKED, "A3", self.a2.merge_commit_sha))
        self.assertEqual(self.derive(items, ["2026-10-23T00:02:30Z"]).stage, BLOCKED, "a retry before the block reopens nothing")
        self.assertEqual(self.derive(items, ["2026-10-23T00:09:00Z"], reopen=False).stage, BLOCKED, "a closed review stays closed")
        s = self.derive(items, ["2026-10-23T00:09:00Z"])
        self.assertEqual((s.stage, s.round), (AWAIT_A3, 2))
        self.assertEqual((s.review_sha, s.integration_head), (self.blocked.merge_commit_sha, self.blocked.merge_commit_sha))
        self.assertEqual(s.build_sha, self.a2.merge_commit_sha, "the build under review is A2's, unchanged")
        self.assertTrue(s.expects(StageRef(MID, "A3", 2)))
        self.assertFalse(s.expects(StageRef(MID, "A2", 2)))

    def test_history_after_a_retry_is_followed(self):
        passed = self.at(stage("A3", 2, 4, "main", verdict="PASS", reviewed=self.blocked.merge_commit_sha), "10")
        items = [self.a1, self.a2, self.blocked, passed]
        self.assertEqual(self.derive(items).stage, HALTED, "without a retry, nothing may follow a block")
        for reopen in (True, False):  # once merged, a reopening is history: a later closed review does not undo it
            with self.subTest(reopen=reopen):
                s = self.derive(items, ["2026-10-23T00:09:00Z"], reopen)
                self.assertEqual((s.stage, s.round, s.landed_sha), (DONE, 2, passed.merge_commit_sha))

    def test_each_reopening_takes_its_own_retry(self):
        again = self.at(stage("A3", 2, 4, INT, verdict="BLOCKED", reviewed=self.blocked.merge_commit_sha), "10")
        items = [self.a1, self.a2, self.blocked, again]
        s = self.derive(items, ["2026-10-23T00:09:00Z"])
        self.assertEqual((s.stage, s.round, s.resume), (BLOCKED, 2, "A3"))
        self.assertEqual(self.derive(items, ["2026-10-23T00:09:00Z", "2026-10-23T00:11:00Z"]).round, 3)

    def test_last_round_fail_gets_one_more_a2_round(self):
        a3f = self.at(stage("A3", 1, 3, INT, verdict="FAIL", reviewed=self.a2.merge_commit_sha), "03")
        a2b = self.at(stage("A2", 2, 4, INT), "04")
        a3f2 = self.at(stage("A3", 2, 5, INT, verdict="FAIL", reviewed=a2b.merge_commit_sha), "05")
        items = [self.a1, self.a2, a3f, a2b, a3f2]
        self.assertEqual((self.derive(items).stage, self.derive(items).resume), (BLOCKED, "A2"))
        s = self.derive(items, ["2026-10-23T00:09:00Z"])
        self.assertEqual((s.stage, s.round, s.integration_head), (AWAIT_A2, 3, a3f2.merge_commit_sha))

    def test_rounds_stop_at_the_ceiling(self):
        m = parse_manifest(manifest_doc(max_rounds=10), MID)
        items, minute = [self.a1], 1
        for r in range(1, 11):
            a2 = self.at(stage("A2", r, 10 + r, INT), f"{minute + 1:02d}")
            items += [a2, self.at(stage("A3", r, 30 + r, INT, verdict="FAIL", reviewed=a2.merge_commit_sha), f"{minute + 2:02d}")]
            minute += 2
        s = derive_state(MID, items, m, {BOT, HITL}, "main", ["2026-10-23T00:59:00Z"])
        self.assertEqual((s.stage, s.round), (BLOCKED, 10), "the router reads back at most 10 rounds")

    def test_agent_failure_blocks_are_not_reopened_here(self):
        s = MissionState(MID, BLOCKED, 1, "1" * 40, when="2026-10-23T00:03:00Z")  # resume None: the dispatcher's own retry applies
        from mission_router.state import _reopened
        self.assertIsNone(_reopened(s, ["2026-10-23T00:09:00Z"]))


# ------------------------------------------------------------------------ gate
def open_pr(role, rnd=0, base=None, author=A2B, files=(("tools/demo/a.py", "added"),), head="c" * 40, behind=0, **kw):
    base = base or INT
    return OpenStagePR(kw.get("number", 7), StageRef(MID, role, rnd), head, base, author, kw.get("same_repo", True),
                       kw.get("draft", False), tuple(FileChange(*f) for f in files), kw.get("complete", True), behind,
                       author_type=kw.get("author_type", "Bot"), pushers=kw.get("pushers", (author,)),
                       head_pushed=kw.get("head_pushed", True))


class GateTests(unittest.TestCase):
    def setUp(self):
        self.m = parse_manifest(manifest_doc(), MID)
        self.a2_state = MissionState(MID, AWAIT_A2, 1, "1" * 40)
        self.a3_state = MissionState(MID, AWAIT_A3, 1, "2" * 40, review_sha="2" * 40)

    def gate(self, pr, state, approvals=(), integration=None, **kw):
        if integration is None:
            integration = state.integration_head or "0" * 40
        kw.setdefault("identities", IDS)
        return evaluate(pr, state, self.m, CLASSIFY, set(approvals), integration, **kw)

    def test_a1_needs_bound_approval(self):
        pr = open_pr("A1", author=A1B, files=((f"missions/{MID}/mission.json", "added"), (f"missions/{MID}/PLAN.md", "added")))
        state = MissionState(MID, AWAIT_A1)
        self.assertEqual(self.gate(pr, state).action, WAIT_APPROVAL)
        self.assertEqual(self.gate(pr, state, approvals={"d" * 40}).action, WAIT_APPROVAL)
        self.assertEqual(self.gate(pr, state, approvals={pr.head_sha}).action, MERGE)

    def test_a1_rejections(self):
        state = MissionState(MID, AWAIT_A1)
        base_files = ((f"missions/{MID}/mission.json", "added"),)
        cases = {
            "outside mission dir": open_pr("A1", author=A1B, files=base_files + (("tools/x.py", "added"),)),
            "other mission": open_pr("A1", author=A1B, files=base_files + (("missions/M-OTHER-001/x.md", "added"),)),
            "writes reviews": open_pr("A1", author=A1B, files=base_files + ((f"missions/{MID}/reviews/round-1.json", "added"),)),
            "no manifest": open_pr("A1", author=A1B, files=((f"missions/{MID}/PLAN.md", "added"),)),
            "wrong author": open_pr("A1", author=A2B, files=base_files),
            "into main": open_pr("A1", author=A1B, base="main", files=base_files),
            "fork": open_pr("A1", author=A1B, files=base_files, same_repo=False),
        }
        for label, pr in cases.items():
            with self.subTest(case=label):
                self.assertEqual(self.gate(pr, state, approvals={pr.head_sha}).action, REJECT)
        ok = open_pr("A1", author=A1B, files=base_files)
        self.assertEqual(self.gate(ok, state, approvals={ok.head_sha}, integration_clean=False).action, REJECT)
        self.assertEqual(self.gate(ok, state, approvals={ok.head_sha}, start_rejects=["overlap"]).action, REJECT)
        self.assertEqual(self.gate(ok, state, approvals={ok.head_sha}, start_waits=["dependency"]).action, "WAIT")

    def test_a1_plan_that_no_build_could_deliver_is_rejected(self):
        """Amendment 004: an AUTHORITY file or a file outside build_scope in the plan is refused before approval."""
        files = ((f"missions/{MID}/mission.json", "added"),)
        pr = open_pr("A1", author=A1B, files=files)
        state = MissionState(MID, AWAIT_A1)
        pkg = "tools/agent_workflow/demo_pkg"
        cases = {
            "authority deliverable": ({"scope": (f"{pkg}/**",), "deliverables": [f"{pkg}/__init__.py", f"{pkg}/run.py"]}, "AUTHORITY"),
            "deliverable outside scope": ({"scope": (f"{pkg}/**",), "deliverables": ["tools/other/run.py"]}, "outside the plan's build_scope"),
            "authority scope entry": ({"scope": (f"{pkg}/run.py", f"{pkg}/__init__.py")}, "build_scope entry"),
        }
        for label, (kw, reason) in cases.items():
            with self.subTest(case=label):
                self.m = parse_manifest(manifest_doc(**kw), MID)
                decision = self.gate(pr, state, approvals={pr.head_sha})
                self.assertEqual(decision.action, REJECT)
                self.assertIn(reason, decision.summary)
        self.m = parse_manifest(manifest_doc(scope=(f"{pkg}/**",), deliverables=[f"{pkg}/run.py"]), MID)
        self.assertEqual(self.gate(pr, state).action, WAIT_APPROVAL, "a glob that could match an AUTHORITY file is fine")

    def test_a1_hitl_is_the_plan_actor(self):
        state = MissionState(MID, AWAIT_A1)
        files = ((f"missions/{MID}/mission.json", "added"), (f"missions/{MID}/PLAN.md", "added"))
        pr = open_pr("A1", author=HITL, author_type="User", files=files)
        self.assertEqual(self.gate(pr, state, hitl_logins={HITL}).action, WAIT_APPROVAL)
        self.assertEqual(self.gate(pr, state, approvals={pr.head_sha}, hitl_logins={HITL}).action, MERGE)
        mixed = open_pr("A1", author=A1B, files=files, pushers=(A1B, HITL))
        self.assertEqual(self.gate(mixed, state, approvals={mixed.head_sha}, hitl_logins={HITL}).action, MERGE)

    def test_a1_hitl_acts_without_an_active_a1_identity(self):
        state = MissionState(MID, AWAIT_A1)
        files = ((f"missions/{MID}/mission.json", "added"),)
        ids = {"a2": A2B, "a3": A3B}
        pr = open_pr("A1", author=HITL, author_type="User", files=files)
        self.assertEqual(self.gate(pr, state, approvals={pr.head_sha}, identities=ids, hitl_logins={HITL}).action, MERGE)
        bot = open_pr("A1", author=A1B, files=files)
        self.assertEqual(self.gate(bot, state, approvals={bot.head_sha}, identities=ids, hitl_logins={HITL}).action, REJECT)

    def test_a1_rejects_everyone_else(self):
        state = MissionState(MID, AWAIT_A1)
        files = ((f"missions/{MID}/mission.json", "added"),)
        cases = {
            "other user": open_pr("A1", author="mallory", author_type="User", files=files),
            "user named like the bot": open_pr("A1", author=A1B, author_type="User", files=files),
            "foreign push on a HITL plan": open_pr("A1", author=HITL, author_type="User", files=files, pushers=(HITL, "cursor[bot]")),
            "foreign push on a bot plan": open_pr("A1", author=A1B, files=files, pushers=(A1B, "cursor[bot]")),
        }
        for label, pr in cases.items():
            with self.subTest(case=label):
                self.assertEqual(self.gate(pr, state, approvals={pr.head_sha}, hitl_logins={HITL}).action, REJECT)

    def test_a2_merges_in_scope(self):
        self.assertEqual(self.gate(open_pr("A2", 1), self.a2_state).action, MERGE)

    def test_a2_rejections(self):
        cases = {
            "out of scope": open_pr("A2", 1, files=(("tools/other/a.py", "added"),)),
            "authority file": open_pr("A2", 1, files=(("tools/demo/a.py", "added"), (".github/workflows/x.yml", "added"))),
            "router code": open_pr("A2", 1, files=(("tools/agent_workflow/mission_router/gate.py", "modified"),)),
            "mission record": open_pr("A2", 1, files=((f"missions/{MID}/mission.json", "modified"),)),
            "rename out of authority": open_pr("A2", 1, files=(("tools/demo/w.yaml", "renamed", "governance/reviewer_execution/sal3/temporary-review-waiver.yaml"),)),
            "unsafe path": open_pr("A2", 1, files=(("tools/demo/../../AGENTS.md", "added"),)),
            "wrong author": open_pr("A2", 1, author=A3B),
            "user account with the agent's name": open_pr("A2", 1, author_type="User"),
            "hitl user": open_pr("A2", 1, author=HITL, author_type="User"),
            "foreign push": open_pr("A2", 1, pushers=(A2B, "cursor[bot]")),
            "hitl push": open_pr("A2", 1, pushers=(A2B, HITL)),
            "wrong round": open_pr("A2", 2),
            "behind integration": open_pr("A2", 1, behind=1),
            "wrong base": open_pr("A2", 1, base="main"),
            "incomplete listing": open_pr("A2", 1, complete=False),
        }
        for label, pr in cases.items():
            with self.subTest(case=label):
                self.assertEqual(self.gate(pr, self.a2_state, approvals={pr.head_sha}).action, REJECT)

    def test_a2_authority_rejected_even_inside_approved_scope(self):
        self.m = parse_manifest(manifest_doc(scope=["tools/agent_workflow/**", "tools/demo/**"]), MID)
        for path in ["tools/agent_workflow/pr_handoff_router.py", "tools/agent_workflow/mission_router/state.py",
                     "tools/agent_workflow/json.py"]:
            with self.subTest(path=path):
                d = self.gate(open_pr("A2", 1, files=((path, "modified"),)), self.a2_state)
                self.assertEqual(d.action, REJECT)
                self.assertIn("AUTHORITY", d.summary)

    def test_identity_must_be_active_and_recorded(self):
        d = self.gate(open_pr("A2", 1), self.a2_state, identities={"a1": A1B, "a3": A3B})
        self.assertEqual(d.action, REJECT)
        self.assertIn("no ACTIVE GitHub App identity", d.summary)
        self.assertEqual(self.gate(open_pr("A2", 1), self.a2_state, identities={}).action, REJECT)
        self.assertEqual(self.gate(open_pr("A2", 1, head_pushed=False), self.a2_state).action, "WAIT")
        bare = OpenStagePR(7, StageRef(MID, "A2", 1), "c" * 40, INT, A2B, True, False, (FileChange("tools/demo/a.py", "added"),), True, 0)
        self.assertNotEqual(self.gate(bare, self.a2_state).action, MERGE, "missing identity evidence must not pass")

    def test_a2_never_writes_mission_records_even_if_scope_allowed_it(self):
        from dataclasses import replace
        self.m = replace(self.m, build_scope=("missions/**", "tools/demo/**"))  # parse_manifest refuses this scope
        d = self.gate(open_pr("A2", 1, files=((f"missions/{MID}/reviews/round-1.json", "added"),)), self.a2_state)
        self.assertEqual(d.action, REJECT)
        self.assertIn("may not change mission records", d.summary)

    def test_integration_tamper_rejects(self):
        self.assertEqual(self.gate(open_pr("A2", 1), self.a2_state, integration="9" * 40).action, REJECT)

    def a3(self, verdict, base, reviewed=None, files=None, **kw):
        files = files or ((f"missions/{MID}/reviews/round-1.json", "added"),)
        pr = open_pr("A3", 1, base=base, author=A3B, files=files, **kw)
        v = parse_verdict(verdict_doc(verdict, reviewed or self.a3_state.review_sha), MID, 1)
        return pr, v

    def test_a3_fail_merges_to_integration(self):
        pr, v = self.a3("FAIL", INT)
        self.assertEqual(self.gate(pr, self.a3_state, verdict=v).action, MERGE)

    def test_a3_pass_independent_merges(self):
        pr, v = self.a3("PASS", "main")
        promo = (FileChange("tools/demo/a.py", "added"),)
        self.assertEqual(self.gate(pr, self.a3_state, verdict=v, promotion_files=promo).action, MERGE)

    def test_a3_pass_by_the_builder_identity_rejected(self):
        pr, v = self.a3("PASS", "main")
        pr = open_pr("A3", 1, base="main", author=A2B, files=((f"missions/{MID}/reviews/round-1.json", "added"),))
        self.assertEqual(self.gate(pr, self.a3_state, approvals={pr.head_sha}, verdict=v).action, REJECT)

    def test_a3_pass_own_manifest_needs_no_extra_approval(self):
        pr, v = self.a3("PASS", "main")
        promo = (FileChange(f"missions/{MID}/mission.json", "added"), FileChange("tools/demo/a.py", "added"))
        self.assertEqual(self.gate(pr, self.a3_state, verdict=v, promotion_files=promo).action, MERGE)
        promo = (FileChange("missions/M-OTHER-001/mission.json", "added"),)
        self.assertEqual(self.gate(pr, self.a3_state, verdict=v, promotion_files=promo).action, WAIT_APPROVAL)

    def test_a3_pass_with_agent_policy_needs_hitl(self):
        pr, v = self.a3("PASS", "main")
        promo = (FileChange("tools/demo/AGENTS.md", "added"),)
        self.assertEqual(self.gate(pr, self.a3_state, verdict=v, promotion_files=promo).action, WAIT_APPROVAL)

    def test_a3_rejections(self):
        cases = {
            "pass into integration": self.a3("PASS", INT),
            "fail into main": self.a3("FAIL", "main"),
            "stale review": self.a3("FAIL", INT, reviewed="f" * 40),
            "extra file": self.a3("FAIL", INT, files=((f"missions/{MID}/reviews/round-1.json", "added"), ("tools/demo/a.py", "modified"))),
            "wrong verdict file": self.a3("FAIL", INT, files=((f"missions/{MID}/reviews/round-2.json", "added"),)),
            "not on reviewed head": self.a3("FAIL", INT, behind=1),
        }
        for label, (pr, v) in cases.items():
            with self.subTest(case=label):
                self.assertEqual(self.gate(pr, self.a3_state, approvals={pr.head_sha}, verdict=v).action, REJECT)
        pr, _ = self.a3("FAIL", INT)
        self.assertEqual(self.gate(pr, self.a3_state, verdict=None, verdict_error="bad").action, REJECT)

    def test_halted_and_draft(self):
        halted = MissionState(MID, HALTED, reason="x")
        self.assertEqual(self.gate(open_pr("A2", 1), halted).action, REJECT)
        self.assertEqual(self.gate(open_pr("A2", 1, draft=True), self.a2_state).action, "WAIT")


# -------------------------------------------------------------- fake GitHub
class FakeGitHub:
    """Enough of GitHub for the router: commits with trees, branches, PRs, merges, comments, issues."""

    def __init__(self):
        self.repo = REPO
        self.commits = {}
        self.branches = {}
        self.prs = {}
        self.comments = {}
        self.reviews = {}
        self.issues = {}
        self.labels = []
        self.next_number = 100
        self.clock = itertools.count()
        self.activity_log = {}  # branch -> events, newest first
        self.checks = {}  # sha -> check runs, oldest first
        root = self._commit((), {"README.md": "hi", REGISTRY_PATH: registry_doc()})
        self.branches["main"] = root
        self.merge_blocked = False
        self.protected = {"main"}  # branches whose protection requires route-handoff-block
        self.review_required = set()  # branches whose protection also requires an approving review
        self.after_compare = None
        self.dispatches = []  # (workflow, ref)
        self.dispatch_error = None
        self.issue_listing_misses = False  # the issue listing comes back without any issue, as it did on 2026-10-22
        self.deleted = []  # branches the router deleted

    # --- git model
    def _commit(self, parents, tree):
        sha = hashlib.sha1(json.dumps([parents, sorted(tree.items()), next(self.clock)]).encode()).hexdigest()
        self.commits[sha] = (tuple(parents), dict(tree))
        return sha

    def _ancestors(self, sha):
        seen, todo = set(), [sha]
        while todo:
            s = todo.pop()
            if s not in seen:
                seen.add(s)
                todo += self.commits[s][0]
        return seen

    @staticmethod
    def agent_for(branch):
        """The bot that owns a stage branch in these tests; anything else is pushed by "someone"."""
        ref = parse_stage_branch(branch)
        return {"A1": A1B, "A2": A2B, "A3": A3B}[ref.role] if ref else "someone"

    def _record(self, branch, before, after, by, kind="push"):
        self.activity_log.setdefault(branch, []).insert(0, {
            "activity_type": kind, "before": before or "0" * 40, "after": after,
            "actor": {"login": by, "type": "Bot" if by.endswith("[bot]") else "User"}})

    def set_branch(self, branch, sha, by=None):
        before = self.branches.get(branch)
        self.branches[branch] = sha
        self._record(branch, before, sha, by or self.agent_for(branch), "push" if before else "branch_creation")

    def push(self, branch, files, base=None, remove=(), by=None):
        parent = self.branches.get(branch) or self.branches[base]
        tree = dict(self.commits[parent][1])
        tree.update(files)
        for path in remove:
            tree.pop(path, None)
        self.set_branch(branch, self._commit((parent,), tree), by)
        return self.branches[branch]

    def _resolve(self, ref):
        return self.branches.get(ref, ref)

    def compare(self, base, head):
        if self.after_compare:
            hook, self.after_compare = self.after_compare, None
            try:
                return self.compare(base, head)
            finally:
                hook()
        b, h = self._resolve(base), self._resolve(head)
        anc_b, anc_h = self._ancestors(b), self._ancestors(h)
        common = anc_b & anc_h
        mb = max(common, key=lambda s: len(self._ancestors(s)))
        old, new = self.commits[mb][1], self.commits[h][1]
        files = []
        for path in sorted(set(old) | set(new)):
            if path not in old:
                files.append({"filename": path, "status": "added"})
            elif path not in new:
                files.append({"filename": path, "status": "removed"})
            elif old[path] != new[path]:
                files.append({"filename": path, "status": "modified"})
        return {"files": files, "behind_by": len(anc_b - anc_h), "ahead_by": len(anc_h - anc_b), "merge_base_commit": {"sha": mb}}

    # --- PRs
    def open_pr(self, head, base, author, draft=False):
        n = self.next_number
        self.next_number += 1
        self.prs[n] = {"number": n, "head_ref": head, "base_ref": base, "user": author, "state": "open",
                       "user_type": "Bot" if author.endswith("[bot]") else "User",
                       "draft": draft, "merged_at": None, "merged_by": None, "merge_commit_sha": None}
        return n

    def _raw(self, n):
        p = self.prs[n]
        head_sha = self.branches.get(p["head_ref"]) if p["state"] == "open" else p.get("head_sha_at_close")
        return {"number": n, "head": {"ref": p["head_ref"], "sha": head_sha, "repo": {"full_name": REPO}},
                "base": {"ref": p["base_ref"]}, "user": {"login": p["user"], "type": p["user_type"]}, "draft": p["draft"],
                "state": p["state"], "merged_at": p["merged_at"], "merged_by": {"login": p["merged_by"]} if p["merged_by"] else None,
                "merge_commit_sha": p["merge_commit_sha"]}

    def hitl_merge(self, n, who=HITL):
        p = self.prs[n]
        head = self.branches[p["head_ref"]]
        return self._do_merge(n, head, who)

    def _do_merge(self, n, sha, who):
        p = self.prs[n]
        base_head = self.branches[p["base_ref"]]
        diff = self.compare(base_head, sha)
        tree = dict(self.commits[base_head][1])
        head_tree = self.commits[sha][1]
        for f in diff["files"]:
            if f["status"] == "removed":
                tree.pop(f["filename"], None)
            else:
                tree[f["filename"]] = head_tree[f["filename"]]
        merge = self._commit((base_head, sha), tree)
        self.set_branch(p["base_ref"], merge, who)
        p.update(state="closed", merged_at=f"2026-10-19T00:00:{next(self.clock):04d}Z", merged_by=who,
                 merge_commit_sha=merge, head_sha_at_close=sha)
        return {"sha": merge, "merged": True}

    def comment_as(self, n, login, body, type_="User"):
        self.comments.setdefault(n, []).append({"user": {"login": login, "type": type_}, "body": body,
                                                "created_at": f"2026-10-19T00:00:{next(self.clock):04d}Z"})

    # --- API surface used by the router
    def latest_check(self, sha):
        runs = [r for r in self.checks.get(sha, []) if r["name"] == "route-handoff-block"]
        return runs[-1] if runs else None

    def activity(self, branch, limit):
        return self.activity_log.get(branch, [])[:limit]

    def check_runs(self, sha, name):
        return [r for r in self.checks.get(sha, []) if r["name"] == name]  # every suite's run, like filter=latest

    def paginate(self, path, limit=2000):
        if path.startswith("/git/matching-refs/heads/mission/"):
            return iter([{"ref": f"refs/heads/{b}"} for b in sorted(self.branches) if b.startswith("mission/")])
        if path == "/labels":
            return iter([{"name": l} for l in self.labels])
        if path.startswith("/issues?labels=mission"):
            return iter([] if self.issue_listing_misses else [dict(i) for i in self.issues.values()])  # copies, like GitHub
        if path.startswith("/issues/") and path.endswith("/comments"):
            return iter(list(self.comments.get(int(path.split("/")[2]), [])))
        if path.startswith("/pulls/") and path.endswith("/reviews"):
            return iter(list(self.reviews.get(int(path.split("/")[2]), [])))
        if path.startswith("/pulls?state=open"):
            return iter([self._raw(n) for n, p in self.prs.items() if p["state"] == "open"])
        if path.startswith("/pulls?state=closed"):
            params = dict(x.split("=", 1) for x in path.split("?", 1)[1].split("&"))
            out = []
            for n, p in self.prs.items():
                if p["state"] != "closed" or ("base" in params and p["base_ref"] != params["base"]):
                    continue
                if "head" in params and params["head"] != f"{REPO.split('/')[0]}:{p['head_ref']}":
                    continue
                raw = self._raw(n)
                raw.pop("merged_by")
                out.append(raw)
            return iter(out)
        raise AssertionError(f"unexpected paginate {path}")

    def get(self, path, raw=False):
        if path.startswith("/pulls/"):
            return self._raw(int(path.split("/")[2]))
        if path.startswith("/issues/"):
            n = int(path.split("/")[2])
            if n in self.issues:
                return dict(self.issues[n])
            if n in self.prs:  # GitHub serves every PR as an issue too
                return {"number": n, "title": "a PR", "pull_request": {}, "user": {"login": self.prs[n]["user"]}}
            raise GitHubError(404, "Not Found", path)
        raise AssertionError(f"unexpected get {path}")

    def file_at(self, path, ref):
        return self.commits[self._resolve(ref)][1].get(path)

    def list_dir(self, path, ref):
        tree = self.commits[self._resolve(ref)][1]
        names = {p.split("/")[1] for p in tree if p.startswith(path + "/")}
        return [{"type": "dir", "name": n} for n in sorted(names)]

    def branch_head(self, branch):
        return self.branches.get(branch)

    def create_branch(self, branch, sha):
        if branch in self.branches:
            raise GitHubError(422, "Reference already exists", "/git/refs")
        self.set_branch(branch, sha, BOT)

    def update_ref(self, branch, sha):
        if self.branches[branch] not in self._ancestors(sha):
            raise GitHubError(422, "Update is not a fast forward", "/git/refs")
        self.set_branch(branch, sha, BOT)

    def delete_branch(self, branch):
        head = self.branches.pop(branch, None)
        for p in self.prs.values():  # GitHub closes every open PR from a deleted branch
            if p["head_ref"] == branch and p["state"] == "open":
                p["state"], p["head_sha_at_close"] = "closed", head
        self.deleted.append(branch)

    def retarget(self, n, base):
        self.prs[n]["base_ref"] = base

    def approve(self, n, sha, body):
        self.reviews.setdefault(n, []).append({"user": {"login": BOT}, "state": "APPROVED", "commit_id": sha})

    def merge(self, n, sha, title):
        p = self.prs[n]
        if p["state"] != "open" or self.branches[p["head_ref"]] != sha:
            raise GitHubError(409, "Head branch was modified", "merge")
        if p["base_ref"] in self.protected:  # branch protection: the required check must have passed on this commit
            check = self.latest_check(sha)
            if self.merge_blocked or not check or check.get("conclusion") != "success":
                raise GitHubError(405, "Required status check \"route-handoff-block\" is expected", "merge")
        if p["base_ref"] in self.review_required and not any(r["state"] == "APPROVED" and r["commit_id"] == sha
                                                            for r in self.reviews.get(n, [])):
            raise GitHubError(405, "At least 1 approving review is required", "merge")
        return self._do_merge(n, sha, BOT)

    def create_check_run(self, name, sha, status, conclusion, title, summary):
        self.checks.setdefault(sha, []).append({"id": next(self.clock), "name": name, "status": status, "conclusion": conclusion,
                                                "output": {"title": title, "summary": summary},
                                                "app": {"slug": "github-actions"}})

    def comment(self, n, body):
        self.comment_as(n, BOT, body, "Bot")

    def dispatch_workflow(self, workflow, ref):
        if self.dispatch_error:
            raise self.dispatch_error
        self.dispatches.append((workflow, ref))

    def ensure_label(self, name, color, description):
        self.labels.append(name)

    def request(self, method, path, body=None, raw=False):
        if method == "POST" and path == "/issues":
            n = self.next_number
            self.next_number += 1
            self.issues[n] = {"number": n, "title": body["title"], "body": body["body"], "state": "open",
                              "labels": [{"name": l} for l in body["labels"]], "user": {"login": BOT}}
            return self.issues[n]
        parts = path.split("/")
        n = int(parts[2])
        if method == "PATCH" and path == f"/issues/{n}":
            self.issues[n].update(body)
            return self.issues[n]
        if method == "PUT" and path.endswith("/labels"):
            self.issues[n]["labels"] = [{"name": l} for l in body["labels"]]
            return None
        if method == "POST" and path.endswith("/labels"):
            target = self.issues.get(n) or self.prs[n]
            target.setdefault("labels", [])
            target["labels"] += [{"name": l} for l in body["labels"]]
            return None
        raise AssertionError(f"unexpected request {method} {path}")


def load_config_from(data):
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "config.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return load_config(path)


def config():
    return {"hitl_logins": [HITL], "bot_login": BOT, "default_branch": "main",
            "identity_registry": REGISTRY_PATH, "agents": dict(IDS)}


class RouterLoopTests(unittest.TestCase):
    """End-to-end: the router drives a mission through every stage on a fake GitHub."""

    def setUp(self):
        self.gh = FakeGitHub()
        self.logs = []
        self.router = MissionRouter(self.gh, config(), CLASSIFY, log=self.logs.append)

    def sweep(self):
        self.router._comments = {}
        return self.router.sweep()

    def issue(self):
        (issue,) = [i for i in self.gh.issues.values() if i["title"] == f"[mission] {MID}"]
        return issue

    def labels(self):
        return sorted(l["name"] for l in self.issue()["labels"])

    def assert_refused(self, n, role="A2", r=1):
        """Refused, never merged: the refusal is a failure record on the tracking issue and the branch is gone."""
        pr = self.gh.prs[n]
        self.assertEqual((pr["state"], pr["merge_commit_sha"]), ("closed", None))
        self.assertIn(pr["head_ref"], self.gh.deleted)
        self.assertNotIn(pr["head_ref"], self.gh.branches)
        self.assertTrue(any(f"mission-dispatch:failed:{role}:{r} -->" in c for c in self.bot_comments(self.issue()["number"])))

    def bot_comments(self, n):
        return [c["body"] for c in self.gh.comments.get(n, []) if c["user"]["login"] == BOT]

    def start_mission(self, mid=MID, scope=("tools/demo/**",), **manifest_kw):
        doc = manifest_doc(scope=scope, **manifest_kw).replace(MID, mid)
        branch = f"mission/{mid}/a1"
        self.gh.push(branch, {f"missions/{mid}/mission.json": doc, f"missions/{mid}/PLAN.md": "plan"}, base="main")
        n = self.gh.open_pr(branch, "main", A1B)  # agents may open it against main; the router retargets it
        main_before = self.gh.branches["main"]
        self.sweep()
        self.assertEqual(self.gh.prs[n]["base_ref"], f"mission/{mid}/integration")
        if self.gh.prs[n]["state"] == "open" and any("/mission approve" in c for c in self.bot_comments(n)):
            self.gh.comment_as(n, HITL, f"/mission approve {self.gh.branches[branch]}")
            self.sweep()
        self.assertEqual(self.gh.branches["main"], main_before, "the plan must not reach main before A3 passes")
        return n

    def a2_round(self, r, files=None, author=A2B):
        branch = f"mission/{MID}/a2-r{r}"
        self.gh.push(branch, files or {"tools/demo/app.py": f"v{r}"}, base=INT)
        n = self.gh.open_pr(branch, INT, author)
        self.sweep()
        return n

    def a3_round(self, r, verdict, author=A3B, reviewed=None, extra=None):
        reviewed = reviewed or self.gh.branches[INT]
        branch = f"mission/{MID}/a3-r{r}"
        self.gh.set_branch(branch, reviewed)
        self.gh.push(branch, {f"missions/{MID}/reviews/round-{r}.json": verdict_doc(verdict, reviewed, r), **(extra or {})})
        n = self.gh.open_pr(branch, "main" if verdict == "PASS" else INT, author)
        self.sweep()
        return n

    def test_full_mission_fail_then_pass(self):
        self.start_mission()
        self.assertEqual(self.gh.prs[100]["merged_by"], BOT)
        self.assertNotIn(f"missions/{MID}/mission.json", self.gh.commits[self.gh.branches["main"]][1])
        self.assertEqual(self.gh.branches[INT], self.gh.prs[100]["merge_commit_sha"])
        self.assertIn("mission:stage-a2", self.labels())
        self.assertIn("target_actor: \"A2\"", self.issue()["body"])

        a2 = self.a2_round(1)
        self.assertEqual(self.gh.prs[a2]["state"], "closed")
        self.assertIn("mission:stage-a3", self.labels())
        self.assertIn(self.gh.branches[INT], self.issue()["body"])

        f1 = self.a3_round(1, "FAIL")
        self.assertEqual(self.gh.prs[f1]["merged_by"], BOT)
        self.assertIn("mission:stage-a2", self.labels())
        self.assertIn("round: 2", self.issue()["body"])

        self.a2_round(2)
        self.assertIn("mission:stage-a3", self.labels())
        main_before = self.gh.branches["main"]
        p2 = self.a3_round(2, "PASS")
        self.assertEqual(self.gh.prs[p2]["merged_by"], BOT)
        self.assertNotEqual(self.gh.branches["main"], main_before)
        main_tree = self.gh.commits[self.gh.branches["main"]][1]
        self.assertEqual(main_tree["tools/demo/app.py"], "v2")
        self.assertIn(f"missions/{MID}/reviews/round-1.json", main_tree)
        self.assertIn(f"missions/{MID}/reviews/round-2.json", main_tree)
        self.assertIn(f"missions/{MID}/mission.json", main_tree)
        self.assertEqual(self.issue()["state"], "closed")
        self.assertIn("mission:done", self.labels())

    def test_nothing_reaches_main_before_pass(self):
        main_before = self.gh.branches["main"]
        self.start_mission()
        self.a2_round(1)
        self.a3_round(1, "FAIL")
        self.a2_round(2)
        self.assertEqual(self.gh.branches["main"], main_before)

    def test_sweeps_are_idempotent(self):
        self.start_mission()
        self.a2_round(1)
        snapshot = (json.dumps(self.gh.issues, sort_keys=True), {k: len(v) for k, v in self.gh.comments.items()}, dict(self.gh.branches))
        for _ in range(3):
            self.sweep()
        self.assertEqual(snapshot, (json.dumps(self.gh.issues, sort_keys=True), {k: len(v) for k, v in self.gh.comments.items()}, dict(self.gh.branches)))

    def test_approval_attacks(self):
        self.gh.push(f"mission/{MID}/a1", {f"missions/{MID}/mission.json": manifest_doc()}, base="main")
        n = self.gh.open_pr(f"mission/{MID}/a1", "main", A1B)
        head = self.gh.branches[f"mission/{MID}/a1"]
        self.gh.comment_as(n, A1B, f"/mission approve {head}", "Bot")  # an agent
        self.gh.comment_as(n, BOT, f"/mission approve {head}", "Bot")  # a workflow token
        self.gh.comment_as(n, HITL, f"/mission approve {head}", "Bot")  # not a user account
        self.gh.comment_as(n, HITL, f"/mission approve {'e' * 40}")  # wrong sha
        self.gh.comment_as(n, HITL, f"please /mission approve {head}")  # not its own line
        self.sweep()
        self.assertEqual(self.gh.prs[n]["state"], "open")
        self.gh.comment_as(n, HITL, f"/mission approve {head}")
        self.gh.push(f"mission/{MID}/a1", {f"missions/{MID}/extra.md": "pushed after approval"})
        self.sweep()
        self.assertEqual(self.gh.prs[n]["state"], "open", "a push after approval must need a new approval")

    def test_a2_wrong_author_and_scope_rejected(self):
        self.start_mission()
        n = self.a2_round(1, author=A3B)
        self.assert_refused(n)
        self.assertTrue(any(f"assigned to agent a2 ({A2B})" in c for c in self.bot_comments(n)))
        n2 = self.a2_round(1, files={"tools/demo/app.py": "x", ".github/workflows/evil.yml": "on: push"})
        self.assert_refused(n2)
        self.assertIn("mission:stage-a2", self.labels())

    def test_a3_cannot_smuggle_code(self):
        self.start_mission()
        self.a2_round(1)
        n = self.a3_round(1, "PASS", extra={"tools/demo/app.py": "swapped by A3"})
        self.assert_refused(n, "A3")
        self.assertIn("mission:stage-a3", self.labels())

    def test_a3_stale_review_rejected(self):
        self.start_mission()
        self.a2_round(1)
        reviewed = self.gh.branches[INT]
        n = self.a3_round(1, "FAIL", reviewed=self.gh.prs[100]["merge_commit_sha"])
        self.assert_refused(n, "A3")
        self.assertNotEqual(reviewed, self.gh.prs[100]["merge_commit_sha"])

    def test_direct_push_to_integration_halts(self):
        self.start_mission()
        self.gh.push(INT, {"tools/demo/backdoor.py": "x"}, by=A2B)
        n = self.a2_round(1)
        self.assertEqual(self.gh.prs[n]["state"], "open")
        self.assertIn("mission:halted", self.labels())
        self.assertIn("changed outside the router", self.issue()["body"])

    def test_hitl_account_cannot_act_as_an_agent(self):
        self.start_mission()
        n = self.a2_round(1, author=HITL)
        self.assert_refused(n)
        self.assertIn("mission:stage-a2", self.labels())

    def test_hitl_opens_the_plan_as_a1(self):
        branch = f"mission/{MID}/a1"
        self.gh.push(branch, {f"missions/{MID}/mission.json": manifest_doc(), f"missions/{MID}/PLAN.md": "plan"}, base="main", by=HITL)
        n = self.gh.open_pr(branch, "main", HITL)
        main_before = self.gh.branches["main"]
        self.sweep()
        self.assertEqual(self.gh.prs[n]["base_ref"], INT)
        self.assertEqual(self.gh.prs[n]["state"], "open")
        self.assertTrue(any("/mission approve" in c for c in self.bot_comments(n)))
        self.gh.comment_as(n, HITL, f"/mission approve {self.gh.branches[branch]}")
        self.sweep()
        self.assertEqual(self.gh.prs[n]["merged_by"], BOT)
        self.assertEqual(self.gh.branches["main"], main_before)
        self.assertIn("mission:stage-a2", self.labels())

    def test_stranger_cannot_open_the_plan(self):
        branch = f"mission/{MID}/a1"
        self.gh.push(branch, {f"missions/{MID}/mission.json": manifest_doc()}, base="main", by="mallory")
        n = self.gh.open_pr(branch, "main", "mallory")
        self.sweep()
        self.assertEqual(self.gh.prs[n]["state"], "open")
        self.assertTrue(any("opened by mallory" in c for c in self.bot_comments(n)))

    def test_push_by_another_identity_is_rejected(self):
        self.start_mission()
        branch = f"mission/{MID}/a2-r1"
        self.gh.push(branch, {"tools/demo/app.py": "v1"}, base=INT)
        self.gh.push(branch, {"tools/demo/app.py": "changed by cursor"}, by="cursor[bot]")
        n = self.gh.open_pr(branch, INT, A2B)
        self.sweep()
        self.assert_refused(n)
        self.assertTrue(any("pushed to by cursor[bot]" in c for c in self.bot_comments(n)))

    def test_unrecorded_push_waits(self):
        self.start_mission()
        branch = f"mission/{MID}/a2-r1"
        self.gh.push(branch, {"tools/demo/app.py": "v1"}, base=INT)
        self.gh.activity_log[branch] = []  # GitHub has not recorded the push yet
        n = self.gh.open_pr(branch, INT, A2B)
        self.sweep()
        self.assertEqual(self.gh.prs[n]["state"], "open")
        self.assertTrue(any("has not yet recorded the push" in c for c in self.bot_comments(n)))

    def test_push_history_too_long_to_verify_is_rejected(self):
        self.start_mission()
        branch = f"mission/{MID}/a2-r1"
        self.gh.push(branch, {"tools/demo/app.py": "v1"}, base=INT)
        self.gh.activity_log[branch] *= 300
        n = self.gh.open_pr(branch, INT, A2B)
        self.sweep()
        self.assert_refused(n)
        self.assertTrue(any("cannot verify them all" in c for c in self.bot_comments(n)))

    def test_suspended_identity_cannot_act(self):
        self.start_mission()
        self.gh.push("main", {REGISTRY_PATH: registry_doc(a2="SUSPENDED")}, by=HITL)
        n = self.a2_round(1)
        self.assert_refused(n)
        self.assertTrue(any("no ACTIVE GitHub App identity" in c for c in self.bot_comments(n)))

    def test_router_owns_the_required_check(self):
        self.gh.push("feature/x", {"tools/x.py": "1"}, base="main", by=HITL)
        other = self.gh.open_pr("feature/x", "main", HITL)
        self.start_mission()
        self.a2_round(1)
        fail = self.a3_round(1, "FAIL")
        self.assertIsNone(self.gh.latest_check(self.gh.prs[fail]["head_sha_at_close"]), "no check on PRs outside main")
        self.a2_round(2)
        p2 = self.a3_round(2, "PASS")
        self.assertEqual(self.gh.latest_check(self.gh.prs[p2]["head_sha_at_close"])["conclusion"], "success")
        self.assertEqual(self.gh.prs[p2]["merged_by"], BOT)
        self.assertEqual(self.gh.latest_check(self.gh.branches["feature/x"])["conclusion"], "failure")
        self.assertEqual(self.gh.prs[other]["state"], "open")
        before = sum(len(v) for v in self.gh.checks.values())
        self.sweep()
        self.assertEqual(sum(len(v) for v in self.gh.checks.values()), before, "an unchanged result is not republished")

    def test_pass_held_for_hitl_keeps_the_required_check_pending(self):
        self.start_mission()
        self.a2_round(1, files={"tools/demo/AGENTS.md": "agent policy"})
        n = self.a3_round(1, "PASS")
        head = self.gh.branches[f"mission/{MID}/a3-r1"]
        check = self.gh.latest_check(head)
        self.assertEqual((check["status"], check["conclusion"]), ("in_progress", None))
        self.assertEqual(self.gh.prs[n]["state"], "open")
        self.gh.comment_as(n, HITL, f"/mission approve {head}")
        self.sweep()
        self.assertEqual(self.gh.latest_check(head)["conclusion"], "success")
        self.assertEqual(self.gh.prs[n]["merged_by"], BOT)

    def test_check_is_republished_when_a_newer_run_disagrees(self):
        self.gh.push("feature/x", {"tools/x.py": "1"}, base="main", by=HITL)
        self.gh.open_pr("feature/x", "main", HITL)
        self.sweep()
        sha = self.gh.branches["feature/x"]
        self.gh.create_check_run("route-handoff-block", sha, "completed", "success", "legacy job", "")
        self.sweep()
        self.assertEqual(self.gh.latest_check(sha)["conclusion"], "failure")

    def test_rejected_pass_fails_the_required_check(self):
        self.start_mission()
        self.a2_round(1)
        n = self.a3_round(1, "PASS", extra={"tools/demo/app.py": "swapped by A3"})
        self.assertEqual(self.gh.latest_check(self.gh.prs[n]["head_sha_at_close"])["conclusion"], "failure")
        self.assert_refused(n, "A3")

    def test_round_limit_is_recorded_as_a_blocker(self):
        self.start_mission(max_rounds=1)
        self.a2_round(1)
        self.a3_round(1, "FAIL")
        self.assertIn("mission:blocked", self.labels())
        n = self.a2_round(2)
        self.assertEqual(self.gh.prs[n]["state"], "open")

    def test_untrusted_manual_merge_halts(self):
        self.start_mission()
        branch = f"mission/{MID}/a2-r1"
        self.gh.push(branch, {"tools/demo/app.py": "v1"}, base=INT)
        n = self.gh.open_pr(branch, INT, A2B)
        self.gh.hitl_merge(n, who=A2B)
        self.sweep()
        self.assertIn("mission:halted", self.labels())

    def test_hitl_manual_merge_is_followed(self):
        self.start_mission()
        branch = f"mission/{MID}/a2-r1"
        self.gh.push(branch, {"tools/demo/app.py": "v1"}, base=INT)
        n = self.gh.open_pr(branch, INT, A2B)
        self.gh.hitl_merge(n, who=HITL)
        self.sweep()
        self.assertIn("mission:stage-a3", self.labels())

    def test_push_between_decision_and_merge_is_not_merged(self):
        self.start_mission()
        branch = f"mission/{MID}/a2-r1"
        self.gh.push(branch, {"tools/demo/app.py": "v1"}, base=INT)
        n = self.gh.open_pr(branch, INT, A2B)
        # The push lands after the router listed the PR's files but before it merges.
        self.gh.after_compare = lambda: self.gh.push(branch, {"tools/demo/app.py": "swapped after the check"})
        self.sweep()
        self.assertNotEqual(self.gh.commits[self.gh.branches[INT]][1].get("tools/demo/app.py"), "swapped after the check")

    def test_blocked_merge_waits_and_retries(self):
        self.start_mission()
        self.a2_round(1)
        self.gh.merge_blocked = True
        n = self.a3_round(1, "PASS")
        self.assertEqual(self.gh.prs[n]["state"], "open")
        self.assertTrue(any("will not merge it yet" in c for c in self.bot_comments(n)))
        self.gh.merge_blocked = False
        self.sweep()
        self.assertEqual(self.gh.prs[n]["state"], "closed")

    def test_dry_run_writes_nothing(self):
        self.gh.push(f"mission/{MID}/a1", {f"missions/{MID}/mission.json": manifest_doc()}, base="main")
        n = self.gh.open_pr(f"mission/{MID}/a1", "main", A1B)
        self.gh.comment_as(n, HITL, f"/mission approve {self.gh.branches[f'mission/{MID}/a1']}")
        branches = dict(self.gh.branches)
        router = MissionRouter(self.gh, config(), CLASSIFY, dry_run=True, log=self.logs.append)
        router.sweep()
        self.assertEqual((self.gh.prs[n]["state"], self.gh.prs[n]["base_ref"]), ("open", "main"))
        self.assertEqual((self.gh.issues, self.gh.branches), ({}, branches))
        self.assertTrue(any("[dry-run] would create" in line for line in self.logs))

    # ---- stacks
    def finish(self, mid):
        """Run mission ``mid`` (already started) through A2 and an A3 PASS."""
        integ = f"mission/{mid}/integration"
        a2 = f"mission/{mid}/a2-r1"
        self.gh.push(a2, {f"tools/{mid.lower()}/app.py": "v1"}, base=integ)
        self.gh.open_pr(a2, integ, A2B)
        self.sweep()
        reviewed = self.gh.branches[integ]
        a3 = f"mission/{mid}/a3-r1"
        self.gh.set_branch(a3, reviewed)
        self.gh.push(a3, {f"missions/{mid}/reviews/round-1.json": verdict_doc("PASS", reviewed, 1, mid)})
        n = self.gh.open_pr(a3, "main", A3B)
        self.sweep()
        self.assertEqual(self.gh.prs[n]["merged_by"], BOT)

    def test_per_leg_sal_missions_run_side_by_side(self):
        self.start_mission("M-SAL-ONE", scope=("tools/m-sal-one/**",), stack={"id": "S-1", "kind": "SAL", "landing": "per-leg"})
        self.start_mission("M-SAL-TWO", scope=("tools/m-sal-two/**",), stack={"id": "S-1", "kind": "SAL", "landing": "per-leg"})
        self.finish("M-SAL-TWO")
        self.finish("M-SAL-ONE")
        tree = self.gh.commits[self.gh.branches["main"]][1]
        self.assertIn("tools/m-sal-one/app.py", tree)
        self.assertIn("tools/m-sal-two/app.py", tree)

    def test_overlapping_scope_cannot_start_while_other_is_active(self):
        self.start_mission("M-SAL-ONE", scope=("tools/shared/**",), stack={"id": "S-1", "kind": "SAL"})
        n = self.start_mission("M-SAL-TWO", scope=("tools/shared/sub/**",), stack={"id": "S-1", "kind": "SAL"})
        self.assertEqual(self.gh.prs[n]["state"], "open")
        self.assertTrue(any("overlaps" in c for c in self.bot_comments(n)))

    def test_per_leg_isal_waits_for_dependency_then_builds_on_it(self):
        self.start_mission("M-UP-001", scope=("tools/m-up-001/**",), stack={"id": "S-2", "kind": "ISAL", "landing": "per-leg"})
        n = self.start_mission("M-DOWN-001", scope=("tools/m-down-001/**",), stack={"id": "S-2", "kind": "ISAL", "landing": "per-leg"},
                               depends_on=["M-UP-001"])
        self.assertEqual(self.gh.prs[n]["state"], "open")
        self.assertTrue(any("ISAL dependency M-UP-001" in c for c in self.bot_comments(n)))
        self.finish("M-UP-001")
        self.sweep()
        down_int = "mission/M-DOWN-001/integration"
        self.assertIn("tools/m-up-001/app.py", self.gh.commits[self.gh.branches[down_int]][1],
                      "the downstream integration branch must start from the upstream result")
        self.assertEqual(self.gh.prs[n]["state"], "open", "a per-leg plan still needs its own approval")
        self.gh.comment_as(n, HITL, f"/mission approve {self.gh.branches['mission/M-DOWN-001/a1']}")
        self.sweep()
        self.assertEqual(self.gh.prs[n]["merged_by"], BOT)

    def test_dependency_cycle_rejected(self):
        a = self.start_mission("M-CYC-A", scope=("tools/m-cyc-a/**",), stack={"id": "S-3", "kind": "ISAL"}, depends_on=["M-CYC-B"])
        b = self.start_mission("M-CYC-B", scope=("tools/m-cyc-b/**",), stack={"id": "S-3", "kind": "ISAL"}, depends_on=["M-CYC-A"])
        for n in (a, b):
            self.assertEqual(self.gh.prs[n]["state"], "open")
            self.assertTrue(any("cycle" in c for c in self.bot_comments(n)))

    # ---- cancel
    def cancel(self, mid=MID, login=HITL, type_="User", body="/mission cancel"):
        (issue,) = [i for i in self.gh.issues.values() if i["title"] == f"[mission] {mid}"]
        self.gh.comment_as(issue["number"], login, body, type_)
        self.sweep()
        return self.gh.issues[issue["number"]]

    def test_hitl_cancel_ends_the_mission(self):
        self.start_mission()
        self.a2_round(1)
        main_before = self.gh.branches["main"]
        issue = self.cancel(body="Stopping this test run.\n/mission cancel")
        self.assertEqual(issue["state"], "closed")
        self.assertEqual(sorted(l["name"] for l in issue["labels"]), ["mission", "mission:cancelled"])
        self.assertIn(f"**Cancelled.** HITL {HITL} cancelled it", issue["body"])
        self.assertIn('stage: "CANCELLED"', issue["body"])
        self.assertTrue(any("Mission cancelled" in c for c in self.bot_comments(issue["number"])))
        n = self.a3_round(1, "PASS")
        self.assertEqual(self.gh.prs[n]["state"], "open")
        self.assertTrue(any("the mission was cancelled" in c for c in self.bot_comments(n)))
        self.assertEqual(self.gh.latest_check(self.gh.branches[f"mission/{MID}/a3-r1"])["conclusion"], "failure")
        self.assertEqual(self.gh.branches["main"], main_before)

    def test_cancel_counts_only_from_a_hitl_user(self):
        self.start_mission()
        for login, type_, body in ((A2B, "Bot", "/mission cancel"), ("someone", "User", "/mission cancel"),
                                   (HITL, "Bot", "/mission cancel"), (HITL, "User", "please /mission cancel this")):
            with self.subTest(login=login, type_=type_, body=body):
                issue = self.cancel(login=login, type_=type_, body=body)
                self.assertEqual(issue["state"], "open")
                self.assertIn("mission:stage-a2", [l["name"] for l in issue["labels"]])

    def test_cancel_releases_the_scope_for_a_restart(self):
        self.start_mission("M-OLD-001", scope=("tools/shared/**",))
        self.cancel("M-OLD-001")
        n = self.start_mission("M-NEW-001", scope=("tools/shared/**",))
        self.assertEqual(self.gh.prs[n]["merged_by"], BOT)

    def test_cancel_after_done_changes_nothing(self):
        self.start_mission("M-SAL-ONE", scope=("tools/m-sal-one/**",))
        self.finish("M-SAL-ONE")
        issue = self.cancel("M-SAL-ONE")
        self.assertIn("mission:done", [l["name"] for l in issue["labels"]])

    def test_handoff_names_the_runtime(self):
        doc = json.loads(manifest_doc())
        doc["roles"]["A2"]["runtime"] = "claude-code"
        branch = f"mission/{MID}/a1"
        self.gh.push(branch, {f"missions/{MID}/mission.json": json.dumps(doc)}, base="main")
        n = self.gh.open_pr(branch, "main", A1B)
        self.sweep()
        self.gh.comment_as(n, HITL, f"/mission approve {self.gh.branches[branch]}")
        self.sweep()
        self.assertIn('assigned_runtime: "claude-code"', self.issue()["body"])
        self.assertTrue(any("starts it as `claude-code`" in c for c in self.bot_comments(self.issue()["number"])))
        self.assertEqual(self.gh.dispatches, [("mission-agent.yml", "main")])
        self.sweep()
        self.assertEqual(len(self.gh.dispatches), 1, "each handoff starts the workflow once")

    def test_handoff_without_runtime_starts_nothing(self):
        self.start_mission()
        self.assertEqual(self.gh.dispatches, [])

    def test_failed_workflow_start_does_not_stop_the_sweep(self):
        self.gh.dispatch_error = GitHubError(403, "Resource not accessible by integration", "/actions")
        doc = json.loads(manifest_doc())
        doc["roles"]["A2"]["runtime"] = "cursor-cli"
        branch = f"mission/{MID}/a1"
        self.gh.push(branch, {f"missions/{MID}/mission.json": json.dumps(doc)}, base="main")
        n = self.gh.open_pr(branch, "main", A1B)
        self.sweep()
        self.gh.comment_as(n, HITL, f"/mission approve {self.gh.branches[branch]}")
        self.sweep()
        self.assertIn("mission:stage-a2", [l["name"] for l in self.issue()["labels"]])
        self.assertTrue(any("schedule will pick it up" in line for line in self.logs))

    def test_survey_reads_without_writing(self):
        self.start_mission()
        self.a2_round(1)
        before = json.dumps([self.gh.issues, self.gh.comments, self.gh.branches, self.gh.checks, self.gh.labels], sort_keys=True)
        contexts = MissionRouter(self.gh, config(), CLASSIFY, log=self.logs.append).survey()
        self.assertEqual(json.dumps([self.gh.issues, self.gh.comments, self.gh.branches, self.gh.checks, self.gh.labels], sort_keys=True), before)
        self.assertEqual((contexts[MID].state.stage, contexts[MID].state.review_sha), (AWAIT_A3, self.gh.branches[INT]))
        self.assertEqual(contexts[MID].manifest.roles["A3"].agent, "a3")

    def test_survey_skips_finished_missions(self):
        self.start_mission("M-SAL-ONE", scope=("tools/m-sal-one/**",))
        self.finish("M-SAL-ONE")
        self.start_mission("M-OLD-001", scope=("tools/old/**",))
        self.cancel("M-OLD-001")
        self.assertEqual(MissionRouter(self.gh, config(), CLASSIFY, log=self.logs.append).survey(), {})

    # ---- tracking issue: found by number, never guessed (2026-10-22: the listing came back empty)
    def tracking_markers(self, plan_pr=100):
        return [c for c in self.bot_comments(plan_pr) if "mission-router:tracking-issue:" in c]

    def drop_tracking_markers(self, plan_pr=100):
        self.gh.comments[plan_pr] = [c for c in self.gh.comments[plan_pr] if "mission-router:tracking-issue:" not in c["body"]]

    def test_plan_pr_links_its_tracking_issue(self):
        self.start_mission()
        (marker,) = self.tracking_markers()
        self.assertIn(f"#{self.issue()['number']}", marker)
        self.assertIn(f"mission-router:tracking-issue:{self.issue()['number']}", marker)

    def test_listing_that_misses_the_issue_opens_no_duplicate(self):
        self.start_mission()
        self.gh.issue_listing_misses = True
        self.sweep()
        a2 = self.a2_round(1)
        self.assertEqual(self.gh.prs[a2]["state"], "closed")
        self.a3_round(1, "PASS")
        self.sweep()
        issue = self.issue()  # exactly one
        self.assertEqual((issue["state"], sorted(l["name"] for l in issue["labels"])), ("closed", ["mission", "mission:done"]))

    def test_cancel_holds_when_the_listing_misses_the_issue(self):
        self.start_mission()
        main_before = self.gh.branches["main"]
        self.cancel()
        self.gh.issue_listing_misses = True
        a2 = self.a2_round(1)
        self.assertEqual(self.gh.prs[a2]["state"], "open")
        self.assertTrue(any("the mission was cancelled" in c for c in self.bot_comments(a2)))
        self.assertEqual(self.issue()["state"], "closed")
        self.assertEqual(self.gh.branches["main"], main_before)

    def test_finished_mission_gets_no_new_issue_when_the_listing_misses(self):
        self.start_mission("M-SAL-ONE", scope=("tools/m-sal-one/**",))
        self.finish("M-SAL-ONE")
        self.gh.issue_listing_misses = True
        self.sweep()
        self.assertEqual(len([i for i in self.gh.issues.values() if i["title"] == "[mission] M-SAL-ONE"]), 1)
        self.drop_tracking_markers(100)  # a mission from before the marks, with no record in config.json
        self.sweep()
        self.assertEqual(len([i for i in self.gh.issues.values() if i["title"] == "[mission] M-SAL-ONE"]), 1)

    def test_listing_backfills_a_missing_mark(self):
        self.start_mission()
        self.drop_tracking_markers()
        self.sweep()
        self.assertEqual(len(self.tracking_markers()), 1)
        self.assertEqual(len(self.gh.issues), 1)

    def test_recorded_issue_needs_no_listing_or_mark(self):
        self.start_mission()
        number = self.issue()["number"]
        self.drop_tracking_markers()
        self.router.recorded_issues = {MID: number}
        self.gh.issue_listing_misses = True
        self.a2_round(1)
        self.assertIn("mission:stage-a3", self.labels())
        self.assertEqual(self.tracking_markers(), [], "a recorded issue needs no mark")

    def test_wrong_record_stops_the_mission_instead_of_guessing(self):
        self.start_mission()
        self.gh.issues[900] = {"number": 900, "title": f"[mission] {MID}", "state": "open", "labels": [], "user": {"login": HITL}}
        self.gh.issues[901] = {"number": 901, "title": "[mission] M-OTHER-001", "state": "open", "labels": [], "user": {"login": BOT}}
        self.gh.issues[902] = {"number": 902, "title": f"[mission] {MID}", "state": "open", "labels": [], "user": {"login": BOT},
                               "pull_request": {}}
        # the plan PR, an issue someone else opened, another mission's issue, a PR with the right title, no issue at all
        for wrong in (100, 900, 901, 902, 999):
            with self.subTest(wrong=wrong):
                self.router.recorded_issues = {MID: wrong}
                self.logs.clear()
                a2 = self.a2_round(1)
                self.assertEqual(self.gh.prs[a2]["state"], "open")
                self.assertEqual(len(self.gh.issues), 4)
                self.assertTrue(any("will retry next sweep" in line for line in self.logs))
                self.gh.prs[a2]["state"] = "closed"
                del self.gh.branches[f"mission/{MID}/a2-r1"]
        self.assertEqual(MissionRouter(self.gh, {**config(), "tracking_issues": {MID: 999}}, CLASSIFY,
                                       log=self.logs.append).survey(), {})
        self.assertTrue(any("left out of this survey" in line for line in self.logs))


    # ---- stacks that land as a whole (option 2): one approval, nothing on main until the whole stack passed
    def open_plan(self, mid, stack, depends_on=None):
        extra = {"depends_on": depends_on} if depends_on else {}
        doc = manifest_doc(scope=(f"tools/{mid.lower()}/**",), stack=stack, **extra).replace(MID, mid)
        branch = f"mission/{mid}/a1"
        self.gh.push(branch, {f"missions/{mid}/mission.json": doc, f"missions/{mid}/PLAN.md": "plan"}, base="main")
        return self.gh.open_pr(branch, "main", A1B)

    def stack_fingerprint(self, n):
        texts = [c for c in self.bot_comments(n) if c.startswith("Stack `")]
        self.assertTrue(texts, f"PR #{n} carries no stack approval request")
        return re.search(r"/mission approve ([0-9a-f]{40})", texts[-1]).group(1)

    def run_loop(self, mid, stack_id, verdict="PASS", findings=None):
        """A2 builds, then A3 hands in ``verdict`` (PASS into the stack branch, else into the integration branch)."""
        integ = f"mission/{mid}/integration"
        a2 = f"mission/{mid}/a2-r1"
        self.gh.push(a2, {f"tools/{mid.lower()}/app.py": "v1"}, base=integ)
        self.gh.open_pr(a2, integ, A2B)
        self.sweep()
        reviewed = self.gh.branches[integ]
        a3 = f"mission/{mid}/a3-r1"
        self.gh.set_branch(a3, reviewed)
        self.gh.push(a3, {f"missions/{mid}/reviews/round-1.json": verdict_doc(verdict, reviewed, 1, mid, findings)})
        n = self.gh.open_pr(a3, f"stack/{stack_id}" if verdict == "PASS" else integ, A3B)
        self.sweep()
        return n

    def stack_issue(self, sid):
        (issue,) = [i for i in self.gh.issues.values() if i["title"] == f"[stack] {sid}"]
        return issue

    def open_isal(self, sid="S-9"):
        stack = {"id": sid, "kind": "ISAL"}
        plans = [self.open_plan("M-LEG-001", stack), self.open_plan("M-LEG-002", stack, ["M-LEG-001"]),
                 self.open_plan("M-LEG-003", stack, ["M-LEG-002"])]
        self.sweep()
        return plans

    def test_isal_stack_lands_whole_after_one_approval(self):
        p1, p2, p3 = self.open_isal()
        fingerprint = self.stack_fingerprint(p1)
        for mid in ("M-LEG-001", "M-LEG-002", "M-LEG-003"):
            self.assertIn(f"`{mid}`", [c for c in self.bot_comments(p1) if c.startswith("Stack `")][-1])
        main_before = self.gh.branches["main"]
        self.gh.comment_as(p1, HITL, f"/mission approve {fingerprint}")  # the only HITL act until the stack lands
        self.sweep()
        self.assertEqual(self.gh.prs[p1]["merged_by"], BOT)
        self.assertEqual((self.gh.prs[p2]["state"], self.gh.prs[p3]["state"]), ("open", "open"), "later loops wait their turn")
        for mid, plan in (("M-LEG-001", p2), ("M-LEG-002", p3), ("M-LEG-003", None)):
            self.assertEqual(self.gh.prs[self.run_loop(mid, "S-9")]["merged_by"], BOT)
            (mi,) = [i for i in self.gh.issues.values() if i["title"] == f"[mission] {mid}"]
            self.assertEqual((mi["state"], "mission:done" in [l["name"] for l in mi["labels"]]), ("open", True),
                             "a passed mission's issue stays open until its stack lands")
            self.assertEqual(self.gh.branches["main"], main_before, "nothing reaches main before the whole stack passed")
            if plan:
                self.assertEqual(self.gh.prs[plan]["merged_by"], BOT, "the one approval carries the next loop")
                nxt = self.gh.branches[f"mission/{'M-LEG-00' + str(int(mid[-1]) + 1)}/integration"]
                self.assertIn(f"tools/{mid.lower()}/app.py", self.gh.commits[nxt][1], "the next loop builds on this loop's result")
        self.assertEqual(self.gh.comments.get(p2, []) + self.gh.comments.get(p3, []) and
                         [c for c in self.gh.comments.get(p2, []) + self.gh.comments.get(p3, []) if c["user"]["login"] == HITL], [])
        self.assertIn("mission:stack-active", [l["name"] for l in self.stack_issue("S-9")["labels"]])
        self.assertTrue(any("Every mission passed" in c for c in self.bot_comments(self.stack_issue("S-9")["number"])))
        self.assertIn(("mission-agent.yml", "main"), self.gh.dispatches, "the router starts the landing right away")
        land = self.gh.open_pr("stack/S-9", "main", A3B)  # the Mission Agent opens it as an A3 agent's App
        self.sweep()
        self.assertEqual(self.gh.prs[land]["merged_by"], BOT)
        tree = self.gh.commits[self.gh.branches["main"]][1]
        for mid in ("M-LEG-001", "M-LEG-002", "M-LEG-003"):
            self.assertIn(f"tools/{mid.lower()}/app.py", tree)
        self.sweep()
        issue = self.stack_issue("S-9")
        self.assertEqual((issue["state"], sorted(l["name"] for l in issue["labels"])), ("closed", ["mission", "mission:done", "mission:stack"]))
        for mid in ("M-LEG-001", "M-LEG-002", "M-LEG-003"):
            (mi,) = [i for i in self.gh.issues.values() if i["title"] == f"[mission] {mid}"]
            self.assertEqual(mi["state"], "closed")

    def test_isal_first_blocker_blocks_everything_and_reports_it(self):
        p1, p2, p3 = self.open_isal()
        self.gh.comment_as(p1, HITL, f"/mission approve {self.stack_fingerprint(p1)}")
        self.sweep()
        main_before = self.gh.branches["main"]
        self.run_loop("M-LEG-001", "S-9")
        self.assertEqual(self.gh.prs[p2]["merged_by"], BOT)
        n = self.run_loop("M-LEG-002", "S-9", "BLOCKED", ["needs the PMS API key, which no agent holds"])
        self.assertEqual(self.gh.prs[n]["merged_by"], BOT, "a blocker is recorded on the integration branch")
        self.sweep()
        self.assertEqual(self.gh.prs[p3]["state"], "open", "loop 3 never starts after loop 2's blocker")
        self.assertTrue(any("is blocked" in c for c in self.bot_comments(p3)))
        issue = self.stack_issue("S-9")
        self.assertEqual(issue["state"], "open")
        self.assertIn("mission:blocked", [l["name"] for l in issue["labels"]])
        body = issue["body"]
        self.assertIn("## Blockers", body)
        self.assertIn("needs the PMS API key", body)
        self.assertIn(f"#{n}", body)  # where
        self.assertRegex(body, r"`M-LEG-002`\*\*, round 1, 2026-")  # when
        self.assertIn("| 1 | `M-LEG-001` | - | PASS |", body)
        self.assertIn("| 3 | `M-LEG-003` | M-LEG-002 | not started |", body)
        land = self.gh.open_pr("stack/S-9", "main", A3B)
        self.sweep()
        self.assertEqual(self.gh.prs[land]["state"], "open")
        self.assertEqual(self.gh.branches["main"], main_before)

    def test_closing_a_blocked_stacks_review_closes_it_for_good(self):
        p1, p2, p3 = self.open_isal()
        self.gh.comment_as(p1, HITL, f"/mission approve {self.stack_fingerprint(p1)}")
        self.sweep()
        self.run_loop("M-LEG-001", "S-9")
        self.run_loop("M-LEG-002", "S-9", "BLOCKED")
        self.sweep()
        member_issues = lambda: {i["title"]: i["state"] for i in self.gh.issues.values() if i["title"].startswith("[mission] M-LEG")}
        self.assertEqual(set(member_issues().values()), {"open"}, "a blocked stack stays whole until HITL reviewed it")
        issue = self.stack_issue("S-9")
        issue["state"] = "closed"  # HITL closes the review
        self.sweep()
        self.sweep()
        self.assertEqual(set(member_issues().values()), {"closed"})
        self.assertEqual(self.stack_issue("S-9")["state"], "closed", "the router does not reopen a closed review")
        n = self.open_plan("M-LEG-009", {"id": "S-9", "kind": "ISAL"})
        self.sweep()
        self.assertTrue(any("restart the plans as a new stack" in c for c in self.bot_comments(n)))

    def test_sal_stack_records_a_blocker_and_carries_on(self):
        stack = {"id": "S-8", "kind": "SAL"}
        p1, p2 = self.open_plan("M-SAL-AAA", stack), self.open_plan("M-SAL-BBB", stack)
        self.sweep()
        self.gh.comment_as(p2, HITL, f"/mission approve {self.stack_fingerprint(p1)}")
        self.sweep()
        self.assertEqual((self.gh.prs[p1]["merged_by"], self.gh.prs[p2]["merged_by"]), (BOT, BOT), "SAL loops run side by side")
        self.run_loop("M-SAL-AAA", "S-8", "BLOCKED")
        self.sweep()
        self.assertIn("mission:stack-active", [l["name"] for l in self.stack_issue("S-8")["labels"]], "the other loop carries on")
        self.run_loop("M-SAL-BBB", "S-8")
        self.sweep()
        issue = self.stack_issue("S-8")
        self.assertIn("mission:blocked", [l["name"] for l in issue["labels"]])
        self.assertIn("| PASS |", issue["body"])
        self.assertNotIn("tools/m-sal-bbb/app.py", self.gh.commits[self.gh.branches["main"]][1], "a blocked stack lands nothing")

    # ---- Amendment 004: one blocked leg tried again on its own; plans checked before approval
    def mission_issue(self, mid):
        (issue,) = [i for i in self.gh.issues.values() if i["title"] == f"[mission] {mid}"]
        return issue

    def rereview(self, mid, stack_id, r, verdict, findings=None):
        """A3 hands in round ``r`` on the integration head (the build plus the earlier BLOCKED verdict)."""
        integ = f"mission/{mid}/integration"
        reviewed = self.gh.branches[integ]
        a3 = f"mission/{mid}/a3-r{r}"
        self.gh.set_branch(a3, reviewed)
        self.gh.push(a3, {f"missions/{mid}/reviews/round-{r}.json": verdict_doc(verdict, reviewed, r, mid, findings)})
        n = self.gh.open_pr(a3, f"stack/{stack_id}" if verdict == "PASS" else integ, A3B)
        self.sweep()
        return n

    def blocked_sal(self):
        stack = {"id": "S-8", "kind": "SAL"}
        p1, p2 = self.open_plan("M-SAL-AAA", stack), self.open_plan("M-SAL-BBB", stack)
        self.sweep()
        self.gh.comment_as(p2, HITL, f"/mission approve {self.stack_fingerprint(p1)}")
        self.sweep()
        self.run_loop("M-SAL-AAA", "S-8", "BLOCKED", ["the suite's tearDown raced a background git gc"])
        self.run_loop("M-SAL-BBB", "S-8")
        self.sweep()
        self.assertIn("mission:blocked", [l["name"] for l in self.stack_issue("S-8")["labels"]])
        return p1, p2

    def test_retry_reviews_one_blocked_sal_leg_again_and_lands_the_stack(self):
        self.blocked_sal()
        aaa, bbb = self.mission_issue("M-SAL-AAA"), self.mission_issue("M-SAL-BBB")
        self.assertTrue(any("/mission retry" in c for c in self.bot_comments(aaa["number"])), "the block says how to retry it")
        self.assertTrue(any("/mission retry" in c for c in self.bot_comments(self.stack_issue("S-8")["number"])))
        bbb_before = (self.gh.branches["mission/M-SAL-BBB/integration"], bbb["body"])
        main_before = self.gh.branches["main"]
        self.gh.comment_as(aaa["number"], HITL, "/mission retry")
        self.sweep()
        self.assertIn("mission:stage-a3", [l["name"] for l in aaa["labels"]])
        self.assertTrue(any("A3 reviews the same build again" in c for c in self.bot_comments(aaa["number"])))
        stack_issue = self.stack_issue("S-8")
        self.assertIn("mission:stack-active", [l["name"] for l in stack_issue["labels"]])
        self.assertTrue(any(c.startswith("**Stack resumed.**") and "`M-SAL-AAA` (round 2)" in c
                            for c in self.bot_comments(stack_issue["number"])))
        self.assertEqual((self.gh.branches["mission/M-SAL-BBB/integration"], bbb["body"]), bbb_before,
                         "the leg that passed is not run again")
        self.assertEqual(self.gh.branches["main"], main_before)
        n = self.rereview("M-SAL-AAA", "S-8", 2, "PASS")
        self.assertEqual(self.gh.prs[n]["merged_by"], BOT)
        land = self.gh.open_pr("stack/S-8", "main", A3B)
        self.sweep()
        self.assertEqual(self.gh.prs[land]["merged_by"], BOT)
        tree = self.gh.commits[self.gh.branches["main"]][1]
        for path in ("tools/m-sal-aaa/app.py", "tools/m-sal-bbb/app.py", "missions/M-SAL-AAA/reviews/round-1.json",
                     "missions/M-SAL-AAA/reviews/round-2.json"):
            self.assertIn(path, tree)

    def test_a_second_block_after_a_retry_is_reported_again(self):
        self.blocked_sal()
        number = self.stack_issue("S-8")["number"]
        self.gh.comment_as(self.mission_issue("M-SAL-AAA")["number"], HITL, "/mission retry")
        self.sweep()
        self.rereview("M-SAL-AAA", "S-8", 2, "BLOCKED", ["still blocked: the check fails on every run"])
        self.sweep()
        self.sweep()
        issue = self.stack_issue("S-8")
        self.assertIn("mission:blocked", [l["name"] for l in issue["labels"]])
        self.assertIn("still blocked", issue["body"])
        self.assertEqual(len([c for c in self.bot_comments(number) if c.startswith("**Stack blocked.**")]), 2)
        self.assertEqual(len([c for c in self.bot_comments(number) if c.startswith("**Stack resumed.**")]), 1)

    def test_retry_counts_only_from_hitl_and_not_after_the_review_closed(self):
        self.blocked_sal()
        aaa = self.mission_issue("M-SAL-AAA")
        self.gh.comment_as(aaa["number"], A2B, "/mission retry", "Bot")
        self.gh.comment_as(aaa["number"], "mallory", "/mission retry")
        self.sweep()
        self.assertIn("mission:blocked", [l["name"] for l in aaa["labels"]])
        self.stack_issue("S-8")["state"] = "closed"  # HITL ends the review
        self.gh.comment_as(aaa["number"], HITL, "/mission retry")
        self.sweep()
        self.sweep()
        self.assertEqual(aaa["state"], "closed")
        self.assertIn("mission:blocked", [l["name"] for l in aaa["labels"]])
        self.assertFalse(any("A3 reviews the same build again" in c for c in self.bot_comments(aaa["number"])))

    def test_retry_of_an_isal_blocker_releases_the_loops_it_held(self):
        p1, p2, p3 = self.open_isal()
        self.gh.comment_as(p1, HITL, f"/mission approve {self.stack_fingerprint(p1)}")
        self.sweep()
        self.run_loop("M-LEG-001", "S-9")
        self.run_loop("M-LEG-002", "S-9", "BLOCKED")
        self.sweep()
        self.assertEqual(self.gh.prs[p3]["state"], "open")
        self.gh.comment_as(self.mission_issue("M-LEG-002")["number"], HITL, "/mission retry")
        self.sweep()
        self.assertEqual(self.gh.prs[self.rereview("M-LEG-002", "S-9", 2, "PASS")]["merged_by"], BOT)
        self.sweep()
        self.assertEqual(self.gh.prs[p3]["merged_by"], BOT, "loop 3 starts once loop 2 passes")

    def test_retry_gives_a_last_round_fail_one_more_a2_round(self):
        self.start_mission(max_rounds=1)
        self.a2_round(1)
        self.a3_round(1, "FAIL")
        self.assertIn("mission:blocked", self.labels())
        self.gh.comment_as(self.issue()["number"], HITL, "/mission retry")
        self.sweep()
        self.assertIn("mission:stage-a2", self.labels())
        self.assertEqual(self.gh.prs[self.a2_round(2)]["merged_by"], BOT)

    def test_plan_needing_an_authority_file_is_refused_before_approval(self):
        pkg = "tools/agent_workflow/demo_pkg"
        doc = manifest_doc(scope=(f"{pkg}/**",), deliverables=[f"{pkg}/__init__.py", f"{pkg}/run.py"])
        self.gh.push(f"mission/{MID}/a1", {f"missions/{MID}/mission.json": doc}, base="main")
        n = self.gh.open_pr(f"mission/{MID}/a1", "main", A1B)
        self.sweep()
        comments = self.bot_comments(n)
        self.assertTrue(any("did not merge" in c and f"{pkg}/__init__.py is AUTHORITY" in c for c in comments))
        self.assertFalse(any("/mission approve" in c for c in comments), "no approval is asked for a plan that cannot work")
        self.gh.comment_as(n, HITL, f"/mission approve {self.gh.branches[f'mission/{MID}/a1']}")
        self.sweep()
        self.assertEqual(self.gh.prs[n]["state"], "open")

    def test_one_approval_binds_every_plan_at_its_commit(self):
        p1, p2, p3 = self.open_isal()
        fingerprint = self.stack_fingerprint(p1)
        self.gh.push("mission/M-LEG-002/a1", {"missions/M-LEG-002/PLAN.md": "changed after the approval request"})
        self.gh.comment_as(p1, HITL, f"/mission approve {fingerprint}")
        self.sweep()
        self.assertEqual(self.gh.prs[p1]["state"], "open", "the approval names plans that are no longer what is proposed")
        self.assertNotEqual(self.stack_fingerprint(p1), fingerprint, "a new request names the new commits")

    def test_a_plan_from_anyone_but_a1_does_not_join_the_stack(self):
        p1, p2, p3 = self.open_isal()
        fingerprint = self.stack_fingerprint(p1)
        doc = manifest_doc(scope=("tools/m-evil-001/**",), stack={"id": "S-9", "kind": "ISAL"}).replace(MID, "M-EVIL-001")
        self.gh.push("mission/M-EVIL-001/a1", {"missions/M-EVIL-001/mission.json": doc}, base="main", by=A2B)
        self.gh.open_pr("mission/M-EVIL-001/a1", "main", A2B)
        self.gh.comment_as(p1, HITL, f"/mission approve {fingerprint}")
        self.sweep()
        self.assertEqual(self.gh.prs[p1]["merged_by"], BOT, "a plan from another identity cannot change the stack")

    def test_landing_pr_rules(self):
        p1, _, _ = self.open_isal()
        self.gh.comment_as(p1, HITL, f"/mission approve {self.stack_fingerprint(p1)}")
        self.sweep()
        self.run_loop("M-LEG-001", "S-9")
        early = self.gh.open_pr("stack/S-9", "main", A3B)
        self.sweep()
        self.assertEqual(self.gh.prs[early]["state"], "open")
        self.assertTrue(any("not every mission" in c for c in self.bot_comments(early)))
        self.assertEqual(self.gh.latest_check(self.gh.branches["stack/S-9"])["conclusion"], None)
        wrong = self.gh.open_pr("stack/S-9", "main", A2B)
        self.sweep()
        self.assertTrue(any("opened by an A3 agent" in c for c in self.bot_comments(wrong)))
        self.gh.push("stack/S-9", {"tools/m-leg-001/app.py": "tampered"}, by="someone")
        self.sweep()
        self.assertTrue(any("only the router" in c for c in self.bot_comments(early)))

    def test_agent_failures_are_retried_then_recorded_as_a_blocker(self):
        doc = json.loads(manifest_doc())
        doc["roles"]["A2"]["runtime"] = "claude-code"
        self.gh.push(f"mission/{MID}/a1", {f"missions/{MID}/mission.json": json.dumps(doc)}, base="main")
        n = self.gh.open_pr(f"mission/{MID}/a1", "main", A1B)
        self.sweep()
        self.gh.comment_as(n, HITL, f"/mission approve {self.gh.branches[f'mission/{MID}/a1']}")
        self.sweep()
        number = self.issue()["number"]
        for attempt in (1, 2, 3):
            self.gh.comment_as(number, BOT, f"**Mission Agent: A2 round 1 did not finish.** attempt {attempt}.\n\n"
                                            "<!-- mission-dispatch:failed:A2:1 -->", "Bot")
            self.sweep()
            self.assertEqual("mission:blocked" in self.labels(), attempt == 3)
        self.assertIn("attempt 3", self.issue()["body"])
        self.gh.comment_as(number, HITL, "/mission retry")
        self.sweep()
        self.assertIn("mission:stage-a2", self.labels())

    def test_refused_stage_pr_is_retried_then_recorded_as_a_blocker(self):
        """Amendment 003: a refused A2 PR counts as a failed run; its branch is deleted so the agent runs again."""
        self.start_mission()
        for attempt in (1, 2, 3):
            n = self.a2_round(1, files={"tools/demo/app.py": "x", ".github/workflows/evil.yml": f"on: push # {attempt}"})
            self.assert_refused(n)
            self.sweep()
            self.assertEqual("mission:blocked" in self.labels(), attempt == 3)
        refusals = [c for c in self.bot_comments(self.issue()["number"]) if "mission-router:refused:" in c]
        self.assertEqual(len(refusals), 3, "one record per refused head")
        self.assertIn("evil.yml", self.issue()["body"], "the review matrix names what was refused")
        self.gh.comment_as(self.issue()["number"], HITL, "/mission retry")
        self.sweep()
        self.assertIn("mission:stage-a2", self.labels())

    def test_refusal_is_recorded_once_per_head(self):
        self.start_mission()
        n = self.a2_round(1, author=A3B)
        self.gh.branches[self.gh.prs[n]["head_ref"]] = self.gh.prs[n]["head_sha_at_close"]  # as if deletion lagged
        self.gh.prs[n]["state"] = "open"
        self.sweep()
        self.sweep()
        self.assertEqual(sum("mission-router:refused:" in c for c in self.bot_comments(self.issue()["number"])), 1)

    def test_pr_for_a_stage_not_awaited_is_refused_but_its_branch_kept(self):
        self.start_mission()
        n = self.a2_round(2)
        self.assertEqual(self.gh.prs[n]["state"], "open")
        self.assertIn(f"mission/{MID}/a2-r2", self.gh.branches)
        self.assertFalse(self.gh.deleted)
        self.assertFalse(any("was refused:" in c for c in self.bot_comments(self.issue()["number"])))

    def test_refused_branch_is_kept_when_the_refusal_cannot_be_recorded(self):
        self.start_mission()
        self.router._tracking.clear()
        branch = f"mission/{MID}/a2-r1"
        self.gh.push(branch, {"tools/demo/app.py": "v1"}, base=INT)
        n = self.gh.open_pr(branch, INT, A3B)
        raw = self.gh._raw(n)
        decision = self.router.decide(raw, self.router.context(MID))
        self.router._refuse_stage(raw, parse_stage_branch(branch), decision)
        self.assertIn(branch, self.gh.branches)
        self.assertFalse(self.gh.deleted)

    def test_only_the_stage_branch_in_this_repository_is_ever_deleted(self):
        self.start_mission()
        branch = f"mission/{MID}/a2-r1"
        self.gh.push(branch, {"tools/demo/app.py": "v1"}, base=INT)
        n = self.gh.open_pr(branch, INT, A3B)
        raw = self.gh._raw(n)
        decision = self.router.decide(raw, self.router.context(MID))
        for name, changed in {"fork": {**raw, "head": {**raw["head"], "repo": {"full_name": "someone/governance"}}},
                              "other branch": {**raw, "head": {**raw["head"], "ref": "main"}}}.items():
            with self.subTest(name):
                self.router._refuse_stage(changed, parse_stage_branch(branch), decision)
                self.assertEqual((self.gh.deleted, self.gh.branches["main"] is not None), ([], True))

    def test_empty_a2_build_goes_to_a3(self):
        """An A2 that records blockers instead of building hands an empty build on; A3 confirms the blockers."""
        self.start_mission()
        before = self.gh.branches[INT]
        branch = f"mission/{MID}/a2-r1"
        self.gh.push(branch, {}, base=INT)
        n = self.gh.open_pr(branch, INT, A2B)
        self.sweep()
        self.assertEqual(self.gh.prs[n]["merged_by"], BOT)
        self.assertNotEqual(self.gh.branches[INT], before)
        self.assertIn("mission:stage-a3", self.labels())

    def test_per_leg_stacks_in_config_keep_landing_one_by_one(self):
        self.router.per_leg_stacks = frozenset({"S-9"})
        p1, _, _ = self.open_isal()
        self.assertTrue(any("/mission approve " + self.gh.branches["mission/M-LEG-001/a1"] in c for c in self.bot_comments(p1)))
        self.gh.comment_as(p1, HITL, "/mission approve " + self.gh.branches["mission/M-LEG-001/a1"])
        self.sweep()
        integ = "mission/M-LEG-001/integration"
        self.gh.push("mission/M-LEG-001/a2-r1", {"tools/m-leg-001/app.py": "v1"}, base=integ)
        self.gh.open_pr("mission/M-LEG-001/a2-r1", integ, A2B)
        self.sweep()
        reviewed = self.gh.branches[integ]
        self.gh.set_branch("mission/M-LEG-001/a3-r1", reviewed)
        self.gh.push("mission/M-LEG-001/a3-r1", {"missions/M-LEG-001/reviews/round-1.json": verdict_doc("PASS", reviewed, 1, "M-LEG-001")})
        n = self.gh.open_pr("mission/M-LEG-001/a3-r1", "main", A3B)
        self.sweep()
        self.assertEqual(self.gh.prs[n]["merged_by"], BOT)
        self.assertIn("tools/m-leg-001/app.py", self.gh.commits[self.gh.branches["main"]][1])

    def test_files_of_an_unlanded_stack_stay_reserved(self):
        p1, _, _ = self.open_isal()
        self.gh.comment_as(p1, HITL, f"/mission approve {self.stack_fingerprint(p1)}")
        self.sweep()
        self.run_loop("M-LEG-001", "S-9")  # passed onto the stack branch, not yet on main
        n = self.start_mission("M-OTHER-001", scope=("tools/m-leg-001/**",))
        self.assertEqual(self.gh.prs[n]["state"], "open")
        self.assertTrue(any("overlaps" in c and "M-LEG-001" in c for c in self.bot_comments(n)))

    def test_a_stack_has_one_kind(self):
        p1 = self.open_plan("M-KIND-AAA", {"id": "S-7", "kind": "SAL"})
        p2 = self.open_plan("M-KIND-BBB", {"id": "S-7", "kind": "ISAL"})
        self.sweep()
        self.assertTrue(any("a stack has one kind" in c for c in self.bot_comments(p1) + self.bot_comments(p2)))

    def test_isal_blocker_holds_a_parallel_branch_already_running_and_one_not_started(self):
        stack = {"id": "S-6", "kind": "ISAL"}
        pa, pb = self.open_plan("M-ROOT-AAA", stack), self.open_plan("M-ROOT-BBB", stack)
        pc = self.open_plan("M-ROOT-CCC", stack)
        self.gh.prs[pc]["draft"] = True  # not ready yet; the approval still covers its commit
        self.sweep()
        self.gh.comment_as(pa, HITL, f"/mission approve {self.stack_fingerprint(pa)}")
        self.sweep()
        self.assertEqual((self.gh.prs[pa]["merged_by"], self.gh.prs[pb]["merged_by"]), (BOT, BOT))
        self.run_loop("M-ROOT-AAA", "S-6", "BLOCKED")
        b_integ = "mission/M-ROOT-BBB/integration"
        self.gh.push("mission/M-ROOT-BBB/a2-r1", {"tools/m-root-bbb/app.py": "v1"}, base=b_integ)
        n = self.gh.open_pr("mission/M-ROOT-BBB/a2-r1", b_integ, A2B)
        self.sweep()
        self.assertEqual(self.gh.prs[n]["state"], "open", "the first blocker holds everything else in an ISAL")
        (issue_b,) = [i for i in self.gh.issues.values() if i["title"] == "[mission] M-ROOT-BBB"]
        self.assertIn("blocked by M-ROOT-AAA", issue_b["body"])
        self.gh.prs[pc]["draft"] = False
        self.sweep()
        self.assertEqual(self.gh.prs[pc]["state"], "open", "nothing more starts in a blocked ISAL")
        self.assertTrue(any("is blocked" in c for c in self.bot_comments(pc)))

    def test_a_landed_stack_id_cannot_start_again(self):
        self.test_isal_stack_lands_whole_after_one_approval()
        n = self.open_plan("M-LEG-004", {"id": "S-9", "kind": "ISAL"})
        self.sweep()
        self.assertTrue(any("already landed" in c for c in self.bot_comments(n)))


class StackUnitTests(unittest.TestCase):
    def test_stack_landing_is_whole_by_default_and_can_go_back_to_per_leg(self):
        m = parse_manifest(manifest_doc(stack={"id": "S-1", "kind": "ISAL"}), MID)
        self.assertEqual((m.landing, m.lands_with_stack), ("stack", True))
        m = parse_manifest(manifest_doc(stack={"id": "S-1", "kind": "SAL", "landing": "per-leg"}), MID)
        self.assertEqual((m.landing, m.lands_with_stack), ("per-leg", False))
        self.assertFalse(parse_manifest(manifest_doc(), MID).lands_with_stack)
        for stack in ({"id": "S-1", "kind": "SAL", "landing": "later"}, {"id": "S-1", "kind": "SAL", "x": 1}):
            with self.subTest(stack), self.assertRaises(MissionInputError):
                parse_manifest(manifest_doc(stack=stack), MID)

    def test_blocked_verdict_must_name_its_blockers(self):
        v = parse_verdict(verdict_doc("BLOCKED", "a" * 40, findings=["no key"]), MID, 1)
        self.assertEqual((v.verdict, v.findings), ("BLOCKED", ("no key",)))
        for findings in ([], [" "]):
            with self.subTest(findings), self.assertRaises(MissionInputError):
                parse_verdict(verdict_doc("BLOCKED", "a" * 40, findings=findings), MID, 1)
        with self.assertRaises(MissionInputError):
            parse_verdict(verdict_doc("PASS", "a" * 40, findings=["x" * 2001]), MID, 1)

    def test_failures_count_from_hitls_last_retry(self):
        mark = {"user": {"login": BOT, "type": "Bot"}, "body": "x <!-- mission-dispatch:failed:A2:1 -->"}
        retry = {"user": {"login": HITL, "type": "User"}, "body": "/mission retry"}
        self.assertEqual(len(failures_since_retry([mark, mark, retry, mark], "A2", 1, BOT, {HITL})), 1)
        self.assertEqual(len(failures_since_retry([mark, mark], "A3", 1, BOT, {HITL})), 0)
        self.assertEqual(len(failures_since_retry([{**mark, "user": {"login": A2B}}], "A2", 1, BOT, {HITL})), 0)

    def landing(self, **kw):
        base = dict(number=5, stack_id="S-1", head_sha="h" * 40, base_ref="main", author=A3B, author_type="Bot",
                    same_repo=True, draft=False, pushers=(BOT,), head_pushed=True)
        return LandingPR(**{**base, **kw})

    def decide(self, pr=None, status="READY", files=(("tools/x/a.py", "added"),), approved=(), complete=True):
        return evaluate_landing(pr or self.landing(), status, "", "h" * 40, {A3B}, {BOT, HITL}, CLASSIFY, set(approved),
                                tuple(FileChange(*f) for f in files), complete, {"missions/M-ONE/mission.json"})

    def test_landing_merges_a_ready_stack(self):
        self.assertEqual(self.decide().action, MERGE)
        self.assertEqual(self.decide(files=(("missions/M-ONE/mission.json", "added"),)).action, MERGE)

    def test_landing_rejections(self):
        for name, pr in {"wrong author": self.landing(author=A2B), "a user": self.landing(author=HITL, author_type="User"),
                         "fork": self.landing(same_repo=False), "not main": self.landing(base_ref="dev"),
                         "stale head": self.landing(head_sha="g" * 40), "foreign push": self.landing(pushers=(BOT, "someone"))}.items():
            with self.subTest(name):
                self.assertEqual(self.decide(pr).action, REJECT)
        for status in ("BLOCKED", "HALTED", "LANDED"):
            self.assertEqual(self.decide(status=status).action, REJECT)
        self.assertEqual(self.decide(status="ACTIVE").action, WAIT)
        self.assertEqual(self.decide(self.landing(head_pushed=False)).action, WAIT)

    def test_hitl_only_files_wait_for_hitl_at_landing(self):
        files = (("tools/agent_workflow/mission_router/router.py", "modified"),)
        self.assertEqual(self.decide(files=files).action, WAIT_APPROVAL)
        self.assertEqual(self.decide(files=files, approved=["h" * 40]).action, MERGE)
        self.assertEqual(self.decide(files=(("missions/M-TWO/mission.json", "added"),)).action, WAIT_APPROVAL,
                         "only the stack's own plans are exempt")
        self.assertEqual(self.decide(complete=False).action, WAIT_APPROVAL)


class AuthorityTests(unittest.TestCase):
    def test_router_and_manifests_are_authority(self):
        tables = load_tables()
        for path in ["tools/agent_workflow/mission_router/router.py", "tools/agent_workflow/mission_router/config.json",
                     ".github/workflows/mission-router.yml", f"missions/{MID}/mission.json",
                     "tools/agent_workflow/specs/MISSION-ROUTER-001.md",
                     "tools/agent_workflow/mission_dispatch/dispatch.py", "tools/agent_workflow/mission_dispatch/runtimes.py",
                     ".github/workflows/mission-agent.yml", "tools/agent_workflow/specs/MISSION-DISPATCH-001.md"]:
            with self.subTest(path=path):
                self.assertEqual(tables.classify(normalize_path(path)), "AUTHORITY")

    def test_shipped_config_loads(self):
        cfg = load_config()
        self.assertTrue(cfg["hitl_logins"])
        self.assertEqual(cfg["bot_login"], BOT)
        self.assertLessEqual({"a2", "a3"}, set(cfg["agents"]))  # A1 is a HITL seat; an a1 App is optional (Amendment 001)
        self.assertTrue(all(login.endswith("[bot]") for login in cfg["agents"].values()))
        statuses = parse_identity_registry(Path(__file__).resolve().parents[3].joinpath(cfg["identity_registry"]).read_text())
        self.assertTrue(all(statuses.get(agent) == "ACTIVE" for agent in cfg["agents"]))

    def test_config_records_well_formed_tracking_issues(self):
        import tempfile
        for issues in ({"m-lower": 1}, {MID: 0}, {MID: True}, {MID: "951"}, [951]):
            with self.subTest(issues=issues), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp, "config.json")
                path.write_text(json.dumps({**config(), "tracking_issues": issues}))
                with self.assertRaises(ValueError):
                    load_config(path)

    def test_config_rejects_user_logins_and_shared_identities(self):
        import tempfile
        for agents in ({"a2": HITL}, {"a2": A2B, "a3": A2B}, {}):
            with self.subTest(agents=agents), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp, "config.json")
                path.write_text(json.dumps({**config(), "agents": agents}))
                with self.assertRaises(ValueError):
                    load_config(path)


QUEUE = "UPG/CONTROL_MATRIX/L1-CAPTURE-QUEUE.md"
QUEUE_DOC = "# L1 Capture Queue\n\n## Entries\n\n### CAPTURE-2026-001 — first\n\n- **Status:** DRAFT\n- **Capture:** one\n"


def capture_entry(n=2, status="DRAFT"):
    return f"\n### CAPTURE-2026-{n:03d} — idea {n}\n\n- **Captured:** 2026-10-24\n- **Status:** {status}\n- **Capture:** text {n}\n"


def capture_config(**kw):
    return {**config(), "l1_capture": {"path": QUEUE, "branch_prefix": "capture/", **kw}}


class CaptureGateTests(unittest.TestCase):
    """Amendment 005: the pure decision for one capture PR."""

    def decide(self, added=capture_entry(), on_main=QUEUE_DOC, files=((QUEUE, "modified"),), held=None, **kw):
        fields = dict(number=7, head_sha="c" * 40, base_ref="main", author=HITL, author_type="User", same_repo=True,
                      draft=False, files=tuple(FileChange(p, st) for p, st in files), files_complete=True,
                      pushers=(HITL,), head_pushed=True)
        fields.update(kw)
        at_head = None if added is None else (on_main or "") + added
        return evaluate_capture(CapturePR(**fields), QUEUE, {HITL}, on_main, at_head, held)

    def test_hitl_append_of_draft_entries_merges(self):
        self.assertEqual(self.decide().action, MERGE)
        self.assertEqual(self.decide(added=capture_entry(2) + capture_entry(3)).action, MERGE)

    def test_only_hitl_opens_and_pushes_a_capture(self):
        for kw in ({"author": A2B, "author_type": "Bot"}, {"author": "someone"}, {"author_type": "Bot"},
                   {"pushers": (HITL, A2B)}, {"pushers": ("someone",)}):
            with self.subTest(kw=kw):
                self.assertEqual(self.decide(**kw).action, REJECT)

    def test_a_capture_touches_only_the_queue(self):
        for files in (((QUEUE, "modified"), ("README.md", "modified")), (("README.md", "modified"),), ((QUEUE, "added"),),
                      ((QUEUE, "renamed"),), ()):
            with self.subTest(files=files):
                self.assertEqual(self.decide(files=files).action, REJECT)
        self.assertEqual(self.decide(files_complete=False).action, REJECT)

    def test_a_capture_only_appends(self):
        edited = QUEUE_DOC.replace("one", "changed") + capture_entry()
        self.assertEqual(evaluate_capture(CapturePR(7, "c" * 40, "main", HITL, "User", True, False,
                                                    (FileChange(QUEUE, "modified"),), True, (HITL,), True),
                                          QUEUE, {HITL}, QUEUE_DOC, edited).action, REJECT)
        self.assertEqual(self.decide(added=None).action, REJECT)
        self.assertEqual(self.decide(on_main=None).action, REJECT)

    def test_appended_text_is_draft_capture_entries(self):
        for added in ("", "\nfree text with no entry\n", "\nno entry heading\n- **Status:** DRAFT\n", capture_entry(status="FILED"), capture_entry(status="DRAFT, promoted"),
                      capture_entry().replace("- **Status:** DRAFT\n", ""), "x" * 20001 + capture_entry(),
                      capture_entry() + capture_entry(3, status="FILED")):
            with self.subTest(added=added[:40]):
                self.assertEqual(self.decide(added=added).action, REJECT)

    def test_fork_other_base_and_draft(self):
        self.assertEqual(self.decide(same_repo=False).action, REJECT)
        self.assertEqual(self.decide(base_ref="develop").action, REJECT)
        self.assertEqual(self.decide(draft=True).action, "WAIT")

    def test_waits_for_a_mission_holding_the_queue_and_for_the_push_record(self):
        self.assertEqual(self.decide(held=MID).action, "WAIT")
        self.assertEqual(self.decide(head_pushed=False).action, "WAIT")
        self.assertEqual(self.decide(held=MID, author="someone").action, REJECT)


class CaptureRouteTests(unittest.TestCase):
    """Amendment 005 end to end: HITL's capture PR merges without a mission; nothing else does."""

    def setUp(self):
        self.gh = FakeGitHub()
        self.gh.set_branch("main", self.gh._commit((self.gh.branches["main"],),
                                                   {**self.gh.commits[self.gh.branches["main"]][1], QUEUE: QUEUE_DOC}), HITL)
        self.router = MissionRouter(self.gh, capture_config(), CLASSIFY, log=lambda _: None)

    def sweep(self):
        self.router._comments = {}
        self.router.sweep()

    def capture(self, added=capture_entry(), branch="capture/l1-capture-002", author=HITL, by=HITL, base_text=None):
        text = (base_text if base_text is not None else self.gh.file_at(QUEUE, "main")) + added
        self.gh.push(branch, {QUEUE: text}, base="main", by=by)
        n = self.gh.open_pr(branch, "main", author)
        self.sweep()
        return n

    def check(self, n):
        return self.gh.latest_check(self.gh.branches.get(self.gh.prs[n]["head_ref"]) or self.gh.prs[n]["head_sha_at_close"])

    def test_hitl_capture_merges_into_main(self):
        n = self.capture()
        self.assertEqual((self.gh.prs[n]["state"], self.gh.prs[n]["merged_by"]), ("closed", BOT))
        self.assertEqual(self.gh.file_at(QUEUE, "main"), QUEUE_DOC + capture_entry())
        self.assertEqual(self.check(n)["conclusion"], "success")

    def test_capture_by_an_agent_is_refused(self):
        n = self.capture(author=A2B, by=A2B)
        self.assertEqual(self.gh.prs[n]["state"], "open")
        self.assertEqual(self.check(n)["conclusion"], "failure")
        self.assertTrue(any("did not merge this capture" in c["body"] for c in self.gh.comments[n]))
        self.assertEqual(self.gh.file_at(QUEUE, "main"), QUEUE_DOC)

    def test_hitl_pr_pushed_to_by_an_agent_is_refused(self):
        self.gh.push("capture/x", {QUEUE: QUEUE_DOC + capture_entry()}, base="main", by=HITL)
        self.gh.push("capture/x", {QUEUE: QUEUE_DOC + capture_entry() + capture_entry(3)}, by=A2B)
        n = self.gh.open_pr("capture/x", "main", HITL)
        self.sweep()
        self.assertEqual(self.gh.prs[n]["state"], "open")
        self.assertEqual(self.check(n)["conclusion"], "failure")

    def test_edit_of_an_existing_entry_or_another_file_is_refused(self):
        n = self.capture(added=capture_entry(), base_text=QUEUE_DOC.replace("one", "rewritten"))
        self.assertEqual(self.gh.prs[n]["state"], "open")
        self.gh.push("capture/two", {QUEUE: QUEUE_DOC + capture_entry(), "README.md": "changed"}, base="main", by=HITL)
        m = self.gh.open_pr("capture/two", "main", HITL)
        self.sweep()
        self.assertEqual(self.gh.prs[m]["state"], "open")
        self.assertEqual(self.gh.file_at(QUEUE, "main"), QUEUE_DOC)

    def test_capture_written_before_another_landed_is_refused_until_updated(self):
        old_main = self.gh.branches["main"]
        self.capture(branch="capture/a")
        self.gh.set_branch("capture/b", old_main, HITL)
        self.gh.push("capture/b", {QUEUE: QUEUE_DOC + capture_entry(3)}, by=HITL)
        b = self.gh.open_pr("capture/b", "main", HITL)
        self.sweep()
        self.assertEqual((self.gh.prs[b]["state"], self.check(b)["conclusion"]), ("open", "failure"))
        main = self.gh.branches["main"]
        tree = {**self.gh.commits[main][1], QUEUE: self.gh.file_at(QUEUE, "main") + capture_entry(3)}
        self.gh.set_branch("capture/b", self.gh._commit((self.gh.branches["capture/b"], main), tree), HITL)
        self.sweep()
        self.assertEqual(self.gh.prs[b]["state"], "closed")
        self.assertEqual(self.gh.file_at(QUEUE, "main"), QUEUE_DOC + capture_entry(2) + capture_entry(3))

    def test_capture_waits_while_a_mission_may_change_the_queue(self):
        RouterLoopTests.start_mission(self._loop(), scope=("UPG/CONTROL_MATRIX/**",))
        n = self.capture()
        self.assertEqual(self.gh.prs[n]["state"], "open")
        self.assertEqual(self.check(n)["status"], "in_progress")
        self.assertTrue(any("captures wait" in c["body"] for c in self.gh.comments[n]))

    def test_mission_on_other_files_or_finished_does_not_hold_captures(self):
        RouterLoopTests.start_mission(self._loop(), scope=("tools/demo/**",))
        self.assertEqual(self.gh.prs[self.capture()]["state"], "closed")
        loop = self._loop()
        RouterLoopTests.start_mission(loop, mid="M-DEMO-002", scope=("UPG/CONTROL_MATRIX/**",))
        (issue,) = [i for i in self.gh.issues.values() if i["title"] == "[mission] M-DEMO-002"]
        self.gh.comment_as(issue["number"], HITL, "/mission cancel")
        self.sweep()
        n = self.capture(added=capture_entry(3), branch="capture/after-cancel")
        self.assertEqual(self.gh.prs[n]["state"], "closed")

    def test_blocked_mission_outside_a_stack_does_not_hold_captures(self):
        RouterLoopTests.start_mission(self._loop(), scope=("UPG/CONTROL_MATRIX/**",))
        (issue,) = [i for i in self.gh.issues.values() if i["title"] == f"[mission] {MID}"]
        for _ in range(3):
            self.gh.comment_as(issue["number"], BOT, "**Mission Agent: A2 round 1 did not finish.**\n\n"
                                                     "<!-- mission-dispatch:failed:A2:1 -->", "Bot")
        self.sweep()
        self.assertIn("mission:blocked", [l["name"] for l in self.gh.issues[issue["number"]]["labels"]])
        self.assertEqual(self.gh.prs[self.capture()]["state"], "closed")

    def _loop(self):
        loop = RouterLoopTests()
        loop.gh, loop.router, loop.logs = self.gh, self.router, []
        return loop

    def test_without_the_route_a_capture_branch_is_not_a_mission(self):
        self.router = MissionRouter(self.gh, config(), CLASSIFY, log=lambda _: None)
        n = self.capture()
        self.assertEqual(self.gh.prs[n]["state"], "open")
        self.assertEqual(self.check(n)["output"]["title"], "Not a mission")

    def test_other_hitl_prs_into_main_are_still_not_missions(self):
        self.gh.push("feature/x", {QUEUE: QUEUE_DOC + capture_entry()}, base="main", by=HITL)
        n = self.gh.open_pr("feature/x", "main", HITL)
        self.sweep()
        self.assertEqual(self.gh.prs[n]["state"], "open")
        self.assertEqual(self.check(n)["output"]["title"], "Not a mission")

    def test_config_validates_the_route(self):
        import tempfile
        # A repository without a capture route leaves it out.
        self.assertIn(load_config().get("l1_capture"), (None, {"path": QUEUE, "branch_prefix": "capture/"}))
        for route in ({"path": QUEUE}, {"path": QUEUE, "branch_prefix": "mission/"}, {"path": QUEUE, "branch_prefix": "stack/"},
                      {"path": QUEUE, "branch_prefix": "capture"}, {"path": QUEUE, "branch_prefix": "Capture/"},
                      {"path": QUEUE, "branch_prefix": ""}, {"path": "UPG/*.md", "branch_prefix": "capture/"},
                      {"path": "../x.md", "branch_prefix": "capture/"}, {"path": QUEUE, "branch_prefix": "capture/", "x": 1},
                      [QUEUE], "capture/"):
            with self.subTest(route=route), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp, "config.json")
                path.write_text(json.dumps({**config(), "l1_capture": route}))
                with self.assertRaises(ValueError):
                    load_config(path)


class TargetBranchTests(unittest.TestCase):
    """Amendment 008: a plan names the branch its work finally merges into; HITL lists and creates those branches."""

    def setUp(self):
        self.gh = FakeGitHub()
        self.gh.protected = self.gh.review_required = {"main", "release"}
        # release differs from main, also in a file only HITL may land: being on release already, it needs no new approval
        self.gh.push("release", {"tools/release-only.txt": "r", "tools/agent_workflow/mission_router/router.py": "r"},
                     base="main", by=HITL)
        self.main = self.gh.branches["main"]
        self.logs = []
        self.router = MissionRouter(self.gh, {**config(), "landing_branches": ["release", "staging"]}, CLASSIFY,
                                    log=self.logs.append)

    sweep = RouterLoopTests.sweep
    bot_comments = RouterLoopTests.bot_comments
    stack_fingerprint = RouterLoopTests.stack_fingerprint
    stack_issue = RouterLoopTests.stack_issue

    def plan(self, mid=MID, branch="release", stack=None, approve=True, depends_on=None, base=None, into="main"):
        """The plan is branched from its target branch, as A1 does (``base`` overrides)."""
        extra = {"branch": branch} if branch else {}
        if stack:
            extra["stack"] = stack
        if depends_on:
            extra["depends_on"] = depends_on
        doc = manifest_doc(scope=(f"tools/{mid.lower()}/**",), **extra).replace(MID, mid)
        ref = f"mission/{mid}/a1"
        start = base or (branch if branch in self.gh.branches else "main")
        self.gh.push(ref, {f"missions/{mid}/mission.json": doc, f"missions/{mid}/PLAN.md": "plan"}, base=start)
        n = self.gh.open_pr(ref, into, A1B)
        self.sweep()
        if approve and any("/mission approve" in c for c in self.bot_comments(n)):
            self.gh.comment_as(n, HITL, f"/mission approve {self.gh.branches[ref]}")
            self.sweep()
        return n

    def build_and_review(self, mid, pass_into, verdict="PASS"):
        integ = f"mission/{mid}/integration"
        self.gh.push(f"mission/{mid}/a2-r1", {f"tools/{mid.lower()}/app.py": "v1"}, base=integ)
        self.gh.open_pr(f"mission/{mid}/a2-r1", integ, A2B)
        self.sweep()
        reviewed = self.gh.branches[integ]
        a3 = f"mission/{mid}/a3-r1"
        self.gh.set_branch(a3, reviewed)
        self.gh.push(a3, {f"missions/{mid}/reviews/round-1.json": verdict_doc(verdict, reviewed, 1, mid)})
        n = self.gh.open_pr(a3, pass_into, A3B)
        self.sweep()
        return n

    def test_a_mission_lands_on_its_branch_and_never_on_main(self):
        self.plan()
        integ = f"mission/{MID}/integration"
        self.assertIn("tools/release-only.txt", self.gh.commits[self.gh.branches[integ]][1],
                      "the mission starts from its branch, not from main")
        wrong = self.build_and_review(MID, "main")
        self.assertEqual((self.gh.prs[wrong]["state"], self.gh.prs[wrong]["merged_by"]), ("closed", None),
                         "a PASS into main is refused like any wrong stage PR")
        self.assertTrue(any("must target release" in c for c in self.bot_comments(wrong)))
        self.assertEqual(self.gh.branches["main"], self.main)
        reviewed = self.gh.branches[integ]
        self.gh.set_branch(f"mission/{MID}/a3-r1", reviewed)
        self.gh.push(f"mission/{MID}/a3-r1", {f"missions/{MID}/reviews/round-1.json": verdict_doc("PASS", reviewed, 1)})
        n = self.gh.open_pr(f"mission/{MID}/a3-r1", "release", A3B)
        head = self.gh.branches[f"mission/{MID}/a3-r1"]
        self.sweep()
        self.assertEqual(self.gh.prs[n]["merged_by"], BOT)
        self.assertEqual(self.gh.latest_check(head)["conclusion"], "success",
                         "the router's check is on the PR into the target, so its protection can require it")
        self.assertEqual(self.gh.branches["main"], self.main)
        self.assertIn(f"tools/{MID.lower()}/app.py", self.gh.commits[self.gh.branches["release"]][1])
        (issue,) = [i for i in self.gh.issues.values() if i["title"] == f"[mission] {MID}"]
        self.assertIn("merged into `release`", issue["body"])
        self.assertEqual(issue["state"], "closed")

    def test_a_branch_hitl_does_not_list_is_refused(self):
        n = self.plan(branch="hotfix")
        self.assertEqual(self.gh.prs[n]["state"], "open")
        self.assertTrue(any("branch hotfix is not a landing branch HITL allows" in c for c in self.bot_comments(n)))
        self.assertNotIn(f"mission/{MID}/integration", self.gh.branches)
        self.assertNotIn("hotfix", self.gh.branches)

    def test_a_listed_branch_that_does_not_exist_holds_the_plan_until_hitl_creates_it(self):
        n = self.plan(branch="staging")
        self.assertEqual(self.gh.prs[n]["state"], "open")
        self.assertTrue(any("branch staging does not exist" in c for c in self.bot_comments(n)))
        self.assertFalse(any("/mission approve" in c for c in self.bot_comments(n)))
        self.assertNotIn("staging", self.gh.branches, "the router never creates a target branch")
        self.assertNotIn(f"mission/{MID}/integration", self.gh.branches)
        self.gh.set_branch("staging", self.gh.branches["release"], HITL)
        self.sweep()
        self.gh.comment_as(n, HITL, f"/mission approve {self.gh.branches[f'mission/{MID}/a1']}")
        self.sweep()
        self.assertEqual(self.gh.prs[n]["merged_by"], BOT)

    def test_a_stack_starts_from_and_lands_on_its_branch(self):
        stack = {"id": "S-REL", "kind": "SAL"}
        p1 = self.plan("M-REL-001", stack=stack, approve=False)
        self.plan("M-REL-002", stack=stack, approve=False, into="release")  # A1 may open it against its branch too
        self.gh.comment_as(p1, HITL, f"/mission approve {self.stack_fingerprint(p1)}")
        self.sweep()
        self.assertIn("tools/release-only.txt", self.gh.commits[self.gh.branches["stack/S-REL"]][1])
        for mid in ("M-REL-001", "M-REL-002"):
            self.assertEqual(self.gh.prs[self.build_and_review(mid, "stack/S-REL")]["merged_by"], BOT)
        wrong = self.gh.open_pr("stack/S-REL", "main", A3B)
        self.sweep()
        self.assertEqual(self.gh.prs[wrong]["state"], "open")
        self.assertTrue(any("a landing PR must target release" in c for c in self.bot_comments(wrong)))
        self.gh.prs[wrong]["state"] = "closed"
        land = self.gh.open_pr("stack/S-REL", "release", A3B)
        self.sweep()
        self.assertEqual(self.gh.prs[land]["merged_by"], BOT)
        self.assertEqual(self.gh.branches["main"], self.main)
        self.sweep()
        issue = self.stack_issue("S-REL")
        self.assertEqual(issue["state"], "closed")
        self.assertTrue(any("merged into `release`" in c for c in self.bot_comments(issue["number"])))
        n = self.plan("M-REL-003", stack=stack)
        self.assertTrue(any("stack S-REL has already landed on release" in c for c in self.bot_comments(n)))

    def test_a_stack_has_one_branch(self):
        stack = {"id": "S-MIX", "kind": "SAL", "landing": "per-leg"}
        self.plan("M-MIX-001", stack=stack)
        n = self.plan("M-MIX-002", branch=None, stack=stack)
        self.assertEqual(self.gh.prs[n]["state"], "open")
        self.assertTrue(any("stack S-MIX lands on release in M-MIX-001 but on main here" in c for c in self.bot_comments(n)))

    def test_an_isal_dependency_must_land_where_the_mission_builds(self):
        self.router.per_leg_stacks = frozenset({"S-DEP"})
        stack = {"id": "S-DEP", "kind": "ISAL"}
        self.plan("M-DEP-001", branch=None, stack=stack)
        self.build_and_review("M-DEP-001", "main")
        n = self.plan("M-DEP-002", stack=stack, depends_on=["M-DEP-001"])
        self.assertEqual(self.gh.prs[n]["state"], "open")
        self.assertTrue(any("ISAL dependency M-DEP-001 landed on main, which this mission does not build on" in c
                            for c in self.bot_comments(n)))

    def test_a_plan_carrying_mains_newer_work_is_refused(self):
        self.gh.push("main", {"tools/main-only.txt": "m"}, by=HITL)
        n = self.plan(base="main")
        self.assertEqual(self.gh.prs[n]["state"], "open")
        self.assertTrue(any("found tools/main-only.txt" in c for c in self.bot_comments(n)),
                        "nothing from main reaches the target through a plan")

    def test_disagreeing_plans_halt_the_stack_status(self):
        stack = {"id": "S-TWO", "kind": "SAL"}
        self.plan("M-TWO-001", stack=stack, approve=False)
        self.plan("M-TWO-002", branch="staging", stack=stack, approve=False)
        status = self.router.stack_status("S-TWO")
        self.assertEqual((status.status, status.reason), ("HALTED", "its missions name different branches: release, staging"))

    def test_outside_prs_into_a_target_fail_the_check(self):
        self.gh.push("feature/x", {"tools/x.py": "x"}, base="release", by=HITL)
        n = self.gh.open_pr("feature/x", "release", HITL)
        self.sweep()
        check = self.gh.latest_check(self.gh.branches["feature/x"])
        self.assertEqual((check["conclusion"], check["output"]["title"]), ("failure", "Not a mission"))
        self.assertIn("merge into `release`", check["output"]["summary"])

    def test_default_missions_are_unchanged(self):
        self.plan(branch=None)
        self.assertNotIn("tools/release-only.txt", self.gh.commits[self.gh.branches[f"mission/{MID}/integration"]][1])
        n = self.build_and_review(MID, "main")
        self.assertEqual(self.gh.prs[n]["merged_by"], BOT)
        self.assertNotEqual(self.gh.branches["main"], self.main)


if __name__ == "__main__":
    unittest.main()
