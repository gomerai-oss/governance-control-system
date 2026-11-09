"""Ring 6 part 5 (MISSION-DISPATCH-001 §3m item 7): the checker. It verifies the whole store (chains, seals against the
pinned keys, history, record commits), records the result as one evidence.verify record, sets the evidence-verified
check, and on a refusal opens or updates the HITL issue. Placeholder repositories and accounts only."""

from __future__ import annotations

import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from epap import ed25519
from evidence import chain, checker, producer, record, seal, sealer, store, verify

from tests.test_evidence_seal import FakeStore

ROOT = Path(__file__).resolve().parents[3]


def git(*args, cwd):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args], cwd=cwd,
                          check=True, capture_output=True, text=True).stdout.strip()


class Setup:
    """A sealed store as a git clone, and a repository holding the records' commit."""

    def __init__(self, test: unittest.TestCase):
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        git("init", "-q", cwd=self.repo)
        git("commit", "-q", "--allow-empty", "-m", "c", cwd=self.repo)
        self.commit = git("rev-parse", "HEAD", cwd=self.repo)
        seed = ed25519.generate_seed()
        public = ed25519.public_key(seed)
        self.keys = {seal.keyid(public): public.hex()}
        chains = self.root / "chains"
        rec = producer.Recorder(chains, "gh-1-1-agent-M-DEMO-001-A2-r1")
        for action in ("dispatch.prepare", "dispatch.run", "dispatch.collect"):
            rec.record(actor="mission-dispatch", account_id=None, action=action, result="done", commit=self.commit,
                       authority_kind="plan", authority_ref="M-DEMO-001 A2 round 1")
        fake = FakeStore()
        sealer.seal_runs(chains, seed, self.keys, store.Store(fake.request), "2026-11-09T12:00:00Z")
        self.store = self.root / "store"
        self.store.mkdir()
        git("init", "-q", cwd=self.store)
        fake.copy_to(self.store)
        git("add", "-A", cwd=self.store)
        git("commit", "-q", "-m", "stored", cwd=self.store)
        self.chain_dir = self.root / "verify-chain"

    def recorder(self):
        return producer.Recorder(self.chain_dir, "gh-2-1-verify")

    def records(self):
        return chain.read(self.chain_dir / verify.RUNS / "gh-2-1-verify" / chain.RECORDS)


class CheckTests(unittest.TestCase):
    def test_a_good_store_is_verified_and_on_record(self):
        s = Setup(self)
        result = checker.check(s.store, s.keys, s.repo, s.recorder())
        self.assertEqual((result["ok"], result["runs"], result["records"], result["commits"], result["failures"]),
                         (True, 1, 3, 1, []))
        (rec,) = s.records()
        self.assertEqual((rec["action"], rec["class"], rec["result"], rec["actor"]["name"]),
                         ("evidence.verify", "decide", "done", "evidence-verify"))
        self.assertEqual(rec["outputs"], {"result": producer.text_digest(json.dumps(result, sort_keys=True))})

    def test_an_edited_store_is_refused_with_every_finding(self):
        s = Setup(self)
        path = next(s.store.rglob(chain.RECORDS))
        lines = path.read_bytes().split(b"\n")
        path.write_bytes(lines[0] + b"\n" + lines[2] + b"\n")
        git("commit", "-q", "-am", "edit", cwd=s.store)
        result = checker.check(s.store, s.keys, s.repo, s.recorder())
        self.assertFalse(result["ok"])
        self.assertTrue(any("a gap in the chain" in f for f in result["failures"]))
        self.assertTrue(any("was changed after it was stored" in f for f in result["failures"]))
        self.assertEqual(s.records()[0]["result"], "refused")

    def test_an_unsealed_run_is_refused(self):
        s = Setup(self)
        next(s.store.rglob("seal.json")).unlink()
        git("commit", "-q", "-am", "unseal", cwd=s.store)
        result = checker.check(s.store, s.keys, s.repo)
        self.assertFalse(result["ok"])
        self.assertTrue(any("not sealed" in f for f in result["failures"]))

    def test_a_commit_missing_from_the_repository_is_refused(self):
        s = Setup(self)
        other = s.root / "other"
        other.mkdir()
        git("init", "-q", cwd=other)
        result = checker.check(s.store, s.keys, other)
        self.assertTrue(any("is not in the repository" in f for f in result["failures"]))

    def test_a_key_not_pinned_is_refused(self):
        s = Setup(self)
        self.assertFalse(checker.check(s.store, {}, s.repo)["ok"])

    def test_the_check_is_an_action_of_the_closed_list(self):
        self.assertEqual(record.ACTIONS["evidence.verify"], "decide")


class FakeGH:
    def __init__(self, open_issue=None):
        self.checks, self.comments, self.created, self.labels = [], [], [], []
        self.open_issue = open_issue

    def create_check_run(self, *args):
        self.checks.append(args)

    def paginate(self, path, limit=50):
        return [self.open_issue] if self.open_issue else []

    def comment(self, number, body):
        self.comments.append((number, body))

    def request(self, method, path, body=None):
        if path == "/labels":
            self.labels.append(body["name"])
            return {}
        self.created.append(body)
        return {"number": 77}


class ReportTests(unittest.TestCase):
    OK = {"ok": True, "runs": 2, "records": 5, "commits": 2, "unsealed": [], "withdrawn": {}, "failures": []}
    BAD = {**OK, "ok": False, "failures": ["run r: the chain is broken at record r/2: r/1 was changed or removed",
                                           "runs/@example-user/records.jsonl was changed after it was stored"]}

    def test_a_verified_store_sets_a_passing_check_and_opens_nothing(self):
        gh = FakeGH()
        self.assertEqual(checker.report(self.OK, gh, "a" * 40, "example-org/evidence-store"), "verified")
        name, sha, status, conclusion, title, summary = gh.checks[0]
        self.assertEqual((name, sha, conclusion), ("evidence-verified", "a" * 40, "success"))
        self.assertEqual((gh.created, gh.comments), ([], []))

    def test_a_refusal_fails_the_check_and_opens_the_hitl_issue(self):
        gh = FakeGH()
        self.assertEqual(checker.report(self.BAD, gh, "a" * 40, "example-org/evidence-store", "https://run"),
                         "opened #77")
        self.assertEqual(gh.checks[0][3], "failure")
        (issue,) = gh.created
        self.assertEqual((issue["title"], issue["labels"]), (checker.ISSUE_TITLE, [checker.ISSUE_LABEL]))
        self.assertIn("r/1 was changed or removed", issue["body"])
        self.assertNotIn("@example-user", issue["body"], "store paths are data: no live mention")
        self.assertEqual(gh.labels, [checker.ISSUE_LABEL])

    def test_a_second_refusal_comments_on_the_open_issue(self):
        gh = FakeGH(open_issue={"number": 12, "title": checker.ISSUE_TITLE})
        self.assertEqual(checker.report(self.BAD, gh, "b" * 40, "example-org/evidence-store"), "commented on #12")
        self.assertEqual(gh.created, [])
        self.assertEqual(gh.comments[0][0], 12)

    def test_the_cli_check_never_fails_and_the_report_fails_on_a_refusal(self):
        from unittest import mock
        from evidence import __main__ as cli
        s = Setup(self)
        out = s.root / "result.json"
        keys = s.root / "keys.json"
        keys.write_text(json.dumps({"schema": seal.KEYS_SCHEMA, "keys": []}))
        with mock.patch.object(seal, "load_keys", return_value={}), redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["check", "--store", str(s.store), "--git", str(s.repo), "--out", str(out)]), 0)
        self.assertFalse(json.loads(out.read_text())["ok"], "no pinned key: refused, and the job still passes")
        with mock.patch("mission_router.github.GitHub", return_value=FakeGH()), \
                mock.patch.dict("os.environ", {"GITHUB_TOKEN": "ghs_placeholder_value"}), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["report", "--repo", "example-org/example-repo", "--result", str(out),
                                       "--sha", "c" * 40, "--store-repo", "example-org/evidence-store"]), 1)


class WorkflowTests(unittest.TestCase):
    def text(self, name):
        live = ROOT / ".github" / "workflows" / name
        return (live if live.is_file() else ROOT / "packaging" / "workflows" / name).read_text(encoding="utf-8")

    def test_the_reader_holds_the_key_and_the_reporter_none(self):
        text = self.text("evidence-verify.yml")
        verify_job, report_job = text[text.index("\n  verify:\n"):text.index("\n  report:\n")], \
            text[text.index("\n  report:\n"):]
        self.assertIn("environment: evidence-verify", verify_job)
        self.assertIn("secrets.EVIDENCE_READER_PRIVATE_KEY", verify_job)
        self.assertIn("permission-contents: read", verify_job)
        self.assertNotIn("permission-contents: write", text)
        self.assertNotIn("secrets.", report_job)
        self.assertNotIn("environment:", report_job)
        self.assertNotIn("EVIDENCE_SEAL_KEY", text, "the checker never holds the evidence key")
        self.assertNotIn("EVIDENCE_APP_PRIVATE_KEY", text, "nor the writer App's key")

    def test_it_runs_on_push_daily_and_by_hand_and_never_on_a_seal(self):
        text = self.text("evidence-verify.yml")
        on = text[text.index("\non:\n"):text.index("\npermissions:")]
        for trigger in ("push:", "schedule:", "workflow_dispatch:"):
            self.assertIn(trigger, on)
        self.assertNotIn("workflow_run", on, "the seal workflow seals the checker's record: no loop")
        self.assertIn("Evidence Verify", self.text("evidence-seal.yml"))


if __name__ == "__main__":
    unittest.main()
