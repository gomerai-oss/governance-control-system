"""EPAP replay (MISSION-DISPATCH-001 Amendment 062): an evidence pack rerun as an outside auditor would, from the pack
alone. A whole mission is built for real: a git repository holding the router's own config.json, the identity
registry and the pinned evidence key, a plan HITL approved, an A2 build, and an A3 PASS that landed on a main that had
moved on; every record is sealed through the real sealer and the pack is summoned by the real summon. Each tamper
vector changes one thing and checks that the replay names it as the first divergence. Placeholder repositories and
accounts only."""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from evidence import producer, replay, sealer, store, summon
from evidence.producer import text_digest

from tests.test_evidence_pack import ListingStore, key

MID = "M-DEMO-001"
REPO = "example-org/example-repo"
HITL, HITL_ID = "example-hitl", 1001
BOT = "example-router[bot]"
A2, A3 = "example-a2[bot]", "example-a3[bot]"
CHECK = "python3 check.py"
LANDING = "python3 landing.py"
REGISTRY = ("| Role | App ID | Installation ID | Status | Account ID |\n|---|---|---|---|---|\n"
            "| a1 | 1 | 11 | ACTIVE | 101 |\n| a2 | 2 | 12 | ACTIVE | 102 |\n| a3 | 3 | 13 | ACTIVE | 103 |\n")
OFFLINE = {"sandbox_mode": "offline", "probe": lambda prefix: False}  # the test's checks are its own small scripts


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def unshare_usable() -> bool:
    try:
        return subprocess.run([*replay.UNSHARE, "true"], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


class Mission:
    """M-DEMO-001 from start to landing. ``wants`` is what check.py accepts in app/x.txt; ``approver`` approves the
    plan; ``outside`` is a file A2 also changes."""

    def __init__(self, test, wants="two\n", approver=(HITL, HITL_ID), outside=None):
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.git = self.root / "repo"
        self.git.mkdir()
        self.seed, self.keys = key()
        self.keys_doc = {"schema": "evidence-keys-v1", "keys": [{"keyid": k, "public": v} for k, v in self.keys.items()]}
        self.run("init", "-q", "-b", "main")
        self.write("tools/agent_workflow/mission_router/config.json", json.dumps({
            "hitl_logins": [HITL], "hitl_account_ids": [HITL_ID], "bot_login": BOT, "bot_account_id": 9,
            "default_branch": "main", "quarantine": "enforce", "challenge": "observe",
            "identity_registry": "registry/IDENTITY-REGISTRY.md",
            "agents": {"a1": "example-a1[bot]", "a2": A2, "a3": A3}, "landing_checks": [LANDING]}, indent=2))
        self.write("tools/agent_workflow/evidence/key.json", json.dumps(self.keys_doc, indent=2))
        self.write("registry/IDENTITY-REGISTRY.md", REGISTRY)
        self.write("check.py", f"import pathlib, sys\nsys.exit(0 if pathlib.Path('app/x.txt').read_text() == {wants!r}"
                               " else 1)\n")
        self.write("landing.py", "import pathlib, sys\nsys.exit(0 if pathlib.Path('other.txt').is_file() and "
                                 "pathlib.Path('app/x.txt').read_text() == 'two\\n' else 1)\n")
        self.write("app/x.txt", "one\n")
        self.start = self.commit("start")
        self.run("branch", f"mission/{MID}/integration")
        self.run("checkout", "-q", "-b", f"mission/{MID}/a1")
        self.write(f"missions/{MID}/mission.json", json.dumps({
            "schema": "mission-v1", "mission_id": MID, "title": "Demo",
            "roles": {"A1": {"agent": "a1"}, "A2": {"agent": "a2", "runtime": "claude-code"},
                      "A3": {"agent": "a3", "runtime": "claude-code"}},
            "build_scope": ["app/**"], "max_rounds": 2, "checks": [CHECK]}, indent=2))
        self.plan = self.commit("plan")
        self.m1 = self.merge(f"mission/{MID}/integration", self.plan)
        self.run("checkout", "-q", "-b", f"mission/{MID}/a2-r1", self.m1)
        self.write("app/x.txt", "two\n")
        if outside:
            self.write(outside, "not in scope\n")
        self.h2 = self.commit(f"[{MID}] A2 round 1\n\nBuilt the demo.")
        self.m2 = self.merge(f"mission/{MID}/integration", self.h2)
        self.run("checkout", "-q", "-b", f"mission/{MID}/a3-r1", self.m2)
        self.write(f"missions/{MID}/reviews/round-1.json", json.dumps({
            "schema": "mission-verdict-v1", "mission_id": MID, "round": 1, "verdict": "PASS",
            "reviewed_sha": self.m2, "summary": "ok", "findings": []}))
        self.h3 = self.commit(f"[{MID}] A3 round 1: PASS")
        self.run("checkout", "-q", "main")
        self.write("other.txt", "main moved on\n")
        self.main2 = self.commit("other work on main")
        self.landed = self.merge("main", self.h3)
        for n, sha_ in ((5, self.plan), (7, self.h2), (9, self.h3)):
            self.run("update-ref", f"refs/remotes/pull/{n}", sha_)
        self.patch2 = self.diff(self.m1, self.h2)
        self.patch3 = self.diff(self.m2, self.h3)
        self.seal(approver)
        self.prs = {5: self.pr(5, f"mission/{MID}/a1", self.plan, f"mission/{MID}/integration", HITL, self.m1),
                    7: self.pr(7, f"mission/{MID}/a2-r1", self.h2, f"mission/{MID}/integration", A2, self.m2),
                    9: self.pr(9, f"mission/{MID}/a3-r1", self.h3, "main", A3, self.landed),
                    8: self.pr(8, "docs/by-hand", self.start, "main", HITL, None)}

    # ------------------------------------------------------------------ git
    def run(self, *args):
        return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                              cwd=self.git, check=True, capture_output=True, text=True).stdout.strip()

    def write(self, rel, text):
        path = self.git / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text if text.endswith("\n") else text + "\n")

    def commit(self, message):
        self.run("add", "-A")
        self.run("commit", "-q", "-m", message)
        return self.run("rev-parse", "HEAD")

    def merge(self, onto, head):
        self.run("checkout", "-q", onto)
        self.run("merge", "-q", "--no-ff", "-m", f"merge {head[:12]}", head)
        return self.run("rev-parse", "HEAD")

    def diff(self, base, head):
        return subprocess.run(["git", "-C", str(self.git), *summon.DIFF, base, head, "--"], capture_output=True,
                              check=True).stdout

    # ------------------------------------------------------------------ the evidence
    def seal(self, approver):
        chains = self.root / "chains"
        spec = dict(authority_kind="spec_rule", authority_ref="MISSION-ROUTER-001")

        def chain(name):
            return producer.Recorder(chains / name, name)
        r0 = chain("gh-20-1-router")
        r0.record(actor=BOT, account_id=None, action="router.branch", result="done", mission=MID, pr=5,
                  commit=self.start, reason=f"create mission/{MID}/integration at {self.start}", **spec)
        r1 = chain("gh-21-1-router")
        r1.record(actor=approver[0], account_id=approver[1], action="router.hitl_command", result="done",
                  reason=f"HITL command: /mission approve {self.plan}", mission=MID, round_n=0, pr=5,
                  commit=self.plan, authority_kind="hitl_command", authority_ref="comment 9 on #5")
        for rec in (r1,):
            rec.record(actor=BOT, account_id=None, action="router.decision", result="done", reason="merge: ok",
                       mission=MID, round_n=0, pr=5, commit=self.plan, **spec)
            rec.record(actor=BOT, account_id=None, action="router.merge", result="done", mission=MID, round_n=0, pr=5,
                       commit=self.plan, reason=f"merge PR #5 at {self.plan}", **spec)
        self.lane("A2", 30, self.m1, self.patch2, A2, 7, self.h2)
        r2 = chain("gh-31-1-router")
        r2.record(actor=BOT, account_id=None, action="router.decision", result="done", reason="merge: ok",
                  mission=MID, round_n=1, pr=7, commit=self.h2, **spec)
        r2.record(actor=BOT, account_id=None, action="router.merge", result="done", mission=MID, round_n=1, pr=7,
                  commit=self.h2, reason=f"merge PR #7 at {self.h2}", **spec)
        self.lane("A3", 40, self.m2, self.patch3, A3, 9, self.h3, checks=True)
        r3 = chain("gh-41-1-router")
        r3.record(actor=BOT, account_id=None, action="router.decision", result="done", reason="merge: ok",
                  mission=MID, round_n=1, pr=9, commit=self.h3, **spec)
        r3.record(actor=BOT, account_id=None, action="router.landing", result="done", mission=MID, round_n=1, pr=9,
                  commit=self.h3, reason=f"merge PR #9 at {self.h3}", **spec)
        # Another mission's landing in the same router chain: its attestation is not this mission's evidence.
        r3.record(actor=BOT, account_id=None, action="router.decision", result="done", reason="merge: ok",
                  mission="M-OTHER-001", round_n=1, pr=99, commit=self.main2, **spec)
        r3.record(actor=BOT, account_id=None, action="router.landing", result="done", mission="M-OTHER-001",
                  round_n=1, pr=99, commit=self.main2, reason=f"merge PR #99 at {self.main2}", **spec)
        self.listing = ListingStore()
        sealer.seal_runs(chains, self.seed, self.keys, store.Store(self.listing.request), "2026-11-27T12:00:00Z",
                         repository=REPO, merged=lambda pr, commit: True)
        self.store = self.root / "store"
        self.listing.copy_to(self.store)

    def lane(self, role, run, base, patch, actor, pr, head, checks=False):
        chains = self.root / "chains"
        lane = f"{MID}-{role}-r1"
        common = dict(mission=MID, round_n=1, authority_kind="plan", authority_ref=f"{MID} {role} round 1")
        if checks:
            c = producer.Recorder(chains / f"gh-{run}-1-checks-{lane}", f"gh-{run}-1-checks-{lane}")
            c.record(actor="mission-checks", account_id=None, action="checks.check", result="done",
                     reason="check 1: exit 0", inputs={"commit": text_digest(base)},
                     outputs={"command": text_digest(CHECK), "output": text_digest("")}, **common)
            c.record(actor="mission-checks", account_id=None, action="checks.check", result="done",
                     reason=f"landing check 1 on main at {self.main2[:12]}: exit 0",
                     inputs={"branch": text_digest("main"), "head": text_digest(self.main2)},
                     outputs={"command": text_digest(LANDING), "output": text_digest("")}, **common)
            c.record(actor="mission-checks", account_id=None, action="checks.environment", result="done",
                     reason="image ubuntu24 20261120.1; Linux X64; python 3.12.3; git 2.51.0",
                     outputs={"environment": text_digest("x")}, **common)
        a = producer.Recorder(chains / f"gh-{run}-1-agent-{lane}", f"gh-{run}-1-agent-{lane}")
        a.record(actor="mission-dispatch", account_id=None, action="dispatch.collect", result="done", commit=base,
                 outputs={"change.patch": sha(patch)}, **common)
        p = producer.Recorder(chains / f"gh-{run}-1-publish-{lane}", f"gh-{run}-1-publish-{lane}")
        p.record(actor=actor, account_id=None, action="dispatch.publish", result="done", pr=pr, commit=base,
                 outputs={"commit": text_digest(head)}, **common)

    @staticmethod
    def pr(n, ref, head, base, user, merged):
        return {"number": n, "title": f"PR {n}", "body": "quarantined text", "state": "closed",
                "merged_at": "2026-11-27T11:00:00Z" if merged else None, "merge_commit_sha": merged or "f" * 40,
                "head": {"ref": ref, "sha": head}, "base": {"ref": base, "sha": "e" * 40}, "user": {"login": user}}

    def summon(self, pr=9):
        out = self.root / f"pack-{pr}"
        summon.summon(self.store, self.git, REPO, pr, self.prs.get, out, self.keys, self.keys_doc, HITL,
                      now="2026-11-27T12:30:00Z")
        return out

    def replay(self, pack, name="work", **kw):
        return replay.replay(pack, self.root / name, now="2026-11-27T13:00:00Z", **{**OFFLINE, **kw})


def steps(report, result=None):
    return {s["step"]: s for s in report["steps"] if result is None or s["result"] == result}


def remanifest(pack, rel):
    """What a forger would do after changing a file: give it its new digest in the manifest too."""
    path = pack / "manifest.json"
    man = json.loads(path.read_text())
    man["files"][rel] = sha((pack / rel).read_bytes())
    path.write_text(json.dumps(man, indent=2, sort_keys=True) + "\n")


class ReplayTests(unittest.TestCase):
    def test_vector_281_a_genuine_pack_is_reproduced_step_by_step(self):
        m = Mission(self)
        report = m.replay(m.summon())
        self.assertEqual(report["result"], "REPRODUCED", report["first_divergence"])
        self.assertIsNone(report["first_divergence"])
        done = steps(report, replay.REPRODUCED)
        for step in ("pack files", "git", "keys", "chains", "attestations", "authority",
                     "A2 round 1 (gh-30-1)", "A2 round 1 (gh-30-1): the dispatcher's gates",
                     "A3 round 1 (gh-40-1)", "A3 round 1 (gh-40-1): the dispatcher's gates",
                     "router: PR #5 (A1)", "router: PR #7 (A2 round 1)", "router: PR #9 (A3 round 1)",
                     "router: mission state", "result", "checks: A3 round 1", "landing checks: A3 round 1"):
            with self.subTest(step):
                self.assertIn(step, done)
        self.assertIn(f"{HITL} (account {HITL_ID})", done["authority"]["detail"])
        self.assertIn("the verdict is PASS", done["A3 round 1 (gh-40-1): the dispatcher's gates"]["detail"])
        self.assertIn(f"ends DONE: landed on main as {m.landed[:12]}", done["router: mission state"]["detail"])
        self.assertIn(f"the landed commit {m.landed[:12]} on main is rebuilt tree for tree", done["result"]["detail"])
        self.assertIn("1. `python3 check.py`: exit 0, sealed 0", done["checks: A3 round 1"]["detail"])
        self.assertIn(f"merged onto main at {m.main2[:12]}", done["landing checks: A3 round 1"]["detail"],
                      "the landing check needs other.txt from main: it ran on the merged tree")
        ai = steps(report, replay.OUTPUT_VERIFIED)
        self.assertEqual(sorted(ai), ["A2 round 1: the agent's work", "A3 round 1: the agent's work"])
        self.assertEqual(report["sandbox"], "offline: this machine reaches no public address (probed), so nothing a "
                                            "check runs can either")
        work = m.root / "work"
        self.assertEqual(json.loads((work / "replay-report.json").read_text())["result"], "REPRODUCED")
        self.assertIn("**REPRODUCED**", (work / "replay-report.md").read_text())

    def test_vector_281_the_pack_holds_this_missions_attestations_only(self):
        m = Mission(self)
        pack = m.summon()
        man = json.loads((pack / "manifest.json").read_text())
        self.assertEqual(len(man["attestations"]), 1, "M-OTHER-001's landing shares the router chain; not its pack")
        self.assertIn(m.main2, man["bundle"]["commits"], "the landing head the landing checks ran on")
        self.assertIn("python3 -m evidence replay --pack", (pack / "README.md").read_text())
        report = m.replay(pack)
        self.assertIn("1 landing attestation(s) of this mission", steps(report)["attestations"]["detail"])

    def test_vector_285_a_pack_summoned_before_its_bundle_had_branches_still_replays(self):
        m = Mission(self)
        pack = m.summon()
        man = json.loads((pack / "manifest.json").read_text())
        old = [f"refs/epap-pack/{i}" for i in range(len(man["bundle"]["commits"]))]
        for ref, commit in zip(old, man["bundle"]["commits"]):
            m.run("update-ref", ref, commit)
        (pack / "repo.bundle").unlink()
        m.run("bundle", "create", str(pack / "repo.bundle"), *old)
        man["bundle"]["sha256"] = sha((pack / "repo.bundle").read_bytes())
        (pack / "manifest.json").write_text(json.dumps(man))
        remanifest(pack, "repo.bundle")
        report = m.replay(pack)
        self.assertEqual(report["result"], "REPRODUCED", report["first_divergence"])

    def test_vector_282_a_changed_change_diverges_though_the_manifest_was_rewritten(self):
        m = Mission(self)
        pack = m.summon()
        (stage,) = [s for s in json.loads((pack / "manifest.json").read_text())["stages"] if s["role"] == "A2"]
        rel = stage["change"]["path"]
        path = pack / rel
        path.write_bytes(path.read_bytes().replace(b"+two", b"+TWO"))
        remanifest(pack, rel)
        report = m.replay(pack)
        self.assertEqual(report["result"], "DIVERGED")
        self.assertEqual(steps(report)["pack files"]["result"], replay.REPRODUCED, "the manifest proves nothing")
        first = report["first_divergence"]
        self.assertEqual(first["step"], "A2 round 1 (gh-30-1)")
        self.assertIn("is not the one sealed for PR #7", first["detail"])

    def test_vector_282_a_changed_file_is_named_when_the_manifest_was_not_rewritten(self):
        m = Mission(self)
        pack = m.summon()
        (pack / "github" / "pr-9.json").write_text("{}\n")
        (pack / "extra.txt").write_text("added\n")
        outside = m.root / "outside.txt"
        outside.write_text("not the pack's\n")
        man = json.loads((pack / "manifest.json").read_text())
        man["files"]["../outside.txt"] = sha(outside.read_bytes())  # a path out of the pack is never followed
        (pack / "manifest.json").write_text(json.dumps(man))
        report = m.replay(pack)
        first = report["first_divergence"]
        self.assertEqual(first["step"], "pack files")
        self.assertIn("github/pr-9.json", first["detail"])
        self.assertIn("extra.txt", first["detail"])
        self.assertIn("../outside.txt", first["detail"])
        self.assertEqual(report["result"], "DIVERGED")

    def test_vector_282_a_changed_record_is_refused_and_none_of_its_chain_is_used(self):
        m = Mission(self)
        pack = m.summon()
        rel = "evidence/runs/gh-21-1-router/records.jsonl"
        path = pack / rel
        path.write_bytes(path.read_bytes().replace(b"comment 9", b"comment 8"))
        remanifest(pack, rel)
        report = m.replay(pack)
        self.assertEqual(report["first_divergence"]["step"], "chains")
        self.assertIn("gh-21-1-router", report["first_divergence"]["detail"])
        self.assertNotEqual(steps(report)["authority"]["result"], replay.REPRODUCED,
                            "the approval and the plan's merge were in the refused chain")

    def test_vector_282_the_packs_own_key_is_not_trusted(self):
        m = Mission(self)
        pack = m.summon()
        _, other = key()
        rel = "evidence/key.json"
        (pack / rel).write_text(json.dumps({"schema": "evidence-keys-v1", "keys": [
            {"keyid": k, "public": v} for k, v in {**m.keys, **other}.items()]}))
        remanifest(pack, rel)
        report = m.replay(pack)
        self.assertEqual(report["first_divergence"]["step"], "keys")
        self.assertIn("that the keys the repository pins", report["first_divergence"]["detail"])
        mine = m.root / "auditor-key.json"
        mine.write_text(json.dumps({"schema": "evidence-keys-v1",
                                    "keys": [{"keyid": k, "public": v} for k, v in other.items()]}))
        report = m.replay(pack, name="work-2", keys_path=mine)
        self.assertEqual(steps(report)["chains"]["result"], replay.DIVERGED,
                         "under the auditor's own pin, seals made with another key do not verify")

    def test_vector_282_a_check_sealed_as_passed_that_fails_when_rerun_diverges(self):
        m = Mission(self, wants="three\n")
        report = m.replay(m.summon())
        first = report["first_divergence"]
        self.assertEqual(first["step"], "checks: A3 round 1")
        self.assertIn("`python3 check.py`: exit 1, sealed 0", first["detail"])

    def test_vector_282_a_plan_no_hitl_account_approved_diverges(self):
        m = Mission(self, approver=("someone-else", 2002))
        report = m.replay(m.summon())
        first = report["first_divergence"]
        self.assertEqual(first["step"], "authority")
        self.assertIn("approvals by accounts that are not HITL's are not counted: someone-else", first["detail"])

    def test_vector_282_a_change_outside_the_approved_scope_diverges(self):
        m = Mission(self, outside="docs/y.txt")
        report = m.replay(m.summon())
        first = report["first_divergence"]
        self.assertEqual(first["step"], "A2 round 1 (gh-30-1): the dispatcher's gates")
        self.assertIn("docs/y.txt is outside the approved build_scope", first["detail"])
        self.assertEqual(steps(report)["router: PR #7 (A2 round 1)"]["result"], replay.DIVERGED,
                         "the router's own gate refuses it too")


class SandboxTests(unittest.TestCase):
    def test_vector_283_no_checks_run_without_a_sandbox(self):
        m = Mission(self)
        report = m.replay(m.summon(), sandbox_mode="auto", probe=lambda prefix: True)
        self.assertEqual(steps(report)["checks"]["result"], replay.NOT_REPLAYABLE)
        self.assertIn("only in a sandbox with no network", steps(report)["checks"]["detail"])
        self.assertFalse((m.root / "work" / "checks").exists(), "nothing of the repository's code ran")
        self.assertEqual(report["result"], "REPRODUCED", "every other step still ran")

    @unittest.skipUnless(unshare_usable(), "unprivileged user namespaces are not allowed on this machine")
    def test_vector_283_the_unshare_sandbox_has_no_network_and_hides_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            prefix, how = replay.sandbox("unshare", work)
            self.assertIsNotNone(prefix, how)
            self.assertTrue(how.startswith("unshare: a network namespace of its own with no network"))
            self.assertFalse(replay.network_reachable(prefix), "the probe itself, inside")
            done = subprocess.run([*prefix, "sh", "-c", 'ls -A "$HOME" | wc -l; pwd'], cwd=tmp, capture_output=True,
                                  text=True, env={"HOME": str(Path.home()), "PATH": "/usr/bin:/bin"})
            self.assertEqual(done.stdout.split()[0], "0", "the replaying account's home is hidden")
            self.assertEqual(done.stdout.split()[1], str(work.resolve()), "the work directory stays reachable")
            local = ("import socket; s = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen(1); "
                     "socket.create_connection(s.getsockname(), timeout=3).close(); print('loopback')")
            done = subprocess.run([*prefix, "python3", "-c", local], cwd=tmp, capture_output=True, text=True)
            self.assertEqual(done.stdout.strip(), "loopback", "a check's own local server works: " + done.stderr)

    @unittest.skipUnless(unshare_usable(), "unprivileged user namespaces are not allowed on this machine")
    def test_vector_283_a_whole_replay_runs_its_checks_in_the_unshare_sandbox(self):
        m = Mission(self)
        report = m.replay(m.summon(), sandbox_mode="unshare", probe=replay.network_reachable)
        self.assertEqual(report["result"], "REPRODUCED", report["first_divergence"])
        self.assertTrue(report["sandbox"].startswith("unshare: "), report["sandbox"])
        self.assertEqual(steps(report)["landing checks: A3 round 1"]["result"], replay.REPRODUCED)

    def test_vector_283_a_sandbox_that_reaches_the_network_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            prefix, how = replay.sandbox("offline", Path(tmp), probe=lambda prefix: True)
            self.assertIsNone(prefix)
            self.assertIn("docker", how.replace("container started with --network none", "docker"))
            with self.assertRaisesRegex(replay.EvidenceError, "must be one of"):
                replay.sandbox("none", Path(tmp))

    def test_vector_283_a_pr_outside_the_mission_flow_has_nothing_to_replay(self):
        m = Mission(self)
        report = m.replay(m.summon(pr=8))
        self.assertEqual(report["result"], "NOTHING TO REPLAY")
        self.assertIn("went outside the mission flow", steps(report)["mission"]["detail"])


class CliTests(unittest.TestCase):
    def test_vector_284_the_cli(self):
        from evidence import __main__ as cli
        m = Mission(self)
        pack = m.summon()
        with mock.patch.object(replay, "network_reachable", lambda prefix: False), \
                redirect_stdout(io.StringIO()) as printed:
            code = cli.main(["replay", "--pack", str(pack), "--work", str(m.root / "cli"), "--sandbox", "offline"])
        self.assertEqual(code, 0, printed.getvalue())
        self.assertIn("**REPRODUCED**", printed.getvalue())
        (pack / "github" / "pr-9.json").write_text("{}\n")
        with redirect_stdout(io.StringIO()) as printed:
            code = cli.main(["replay", "--pack", str(pack), "--work", str(m.root / "cli-2"), "--checks", "none"])
        self.assertEqual(code, 1)
        self.assertIn("First divergence: **pack files**", printed.getvalue())

    def test_vector_284_refusals(self):
        m = Mission(self)
        pack = m.summon()
        (m.root / "taken").mkdir()
        with self.assertRaisesRegex(replay.EvidenceError, "a replay works in a new directory"):
            replay.replay(pack, m.root / "taken")
        with self.assertRaisesRegex(replay.EvidenceError, "is not an evidence pack"):
            replay.replay(m.root, m.root / "fresh")
        with self.assertRaisesRegex(replay.EvidenceError, "--checks must be one of"):
            replay.replay(pack, m.root / "fresh", checks="some")


if __name__ == "__main__":
    unittest.main()
