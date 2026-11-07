"""Ring 6 part 2 (MISSION-DISPATCH-001 §3m item 1 and item 5, Amendment 020): the dispatcher's, the checks job's,
the gateway's, the egress proxy's and the credentials check's records, and the verifier's checks against files and
commits. Vector 102 (records for each action) and vector 104 (a changed file). The router's records are part 3."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from evidence import chain, producer, record, verify
from mission_dispatch import __main__ as cli
from mission_dispatch.dispatch import DispatchError, Job
from mission_dispatch.runtimes import agent_env

AW = Path(__file__).resolve().parents[1]
ROOT = AW.parents[1]
MID = "M-DEMO-001"
JOB = Job(MID, "A2", 1, "a2", "example-a2[bot]", "claude-code", "a" * 40, ("tools/demo/**",), "t")
RUN = "gh-1-1-agent-M-DEMO-001-A2-r1"


def workflow(name):
    live = ROOT / ".github" / "workflows" / name
    return (live if live.is_file() else ROOT / "packaging" / "workflows" / name).read_text(encoding="utf-8")


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.store = self.tmp / "evidence"
        self.env = {"JOB": json.dumps(JOB.to_dict()), producer.DIR_ENV: str(self.store), producer.RUN_ENV: RUN}

    def main(self, argv, patches):
        with mock.patch.dict(os.environ, self.env), mock.patch("sys.stderr"):
            with mock.patch.multiple(cli, **patches):
                return cli.main(argv)

    def records(self, run=RUN):
        return chain.read(self.store / verify.RUNS / run / chain.RECORDS)

    def verified(self, **kw):
        report = verify.verify_store(self.store, {}, **kw)
        self.assertTrue(report.ok, report.failure)
        return report


class RecorderTests(Base):
    def test_nothing_is_recorded_without_a_chain(self):
        rec = producer.Recorder.from_env({})
        self.assertFalse(rec.enabled)
        self.assertIsNone(rec.record(actor="x", account_id=None, action="dispatch.run", result="done",
                                     authority_kind="plan", authority_ref="p"))

    def test_the_chain_directory_is_private(self):
        rec = producer.Recorder.from_env(self.env)
        rec.record(actor="mission-dispatch", account_id=None, action="dispatch.run", result="done",
                   authority_kind="plan", authority_ref="p")
        self.assertEqual(stat.S_IMODE(self.store.stat().st_mode), 0o700)

    def test_a_record_that_cannot_be_written_is_a_warning(self):
        warned = []
        rec = producer.Recorder(self.store, RUN, warned.append)
        self.assertIsNone(rec.record(actor="x", account_id=None, action="not.an.action", result="done",
                                     authority_kind="plan", authority_ref="p"))
        self.assertTrue(warned and warned[0].startswith("evidence: not recorded"))

    def test_the_agent_never_sees_where_its_records_are(self):
        env = agent_env({"PATH": "/usr/bin", **self.env}, self.tmp, self.tmp, self.tmp)
        self.assertFalse([k for k in env if k.startswith("EVIDENCE_")])

    def test_a_long_log_is_bounded(self):
        log = self.tmp / "egress.jsonl"
        log.write_text("".join(json.dumps({"host": "h", "port": 443, "decision": "allowed"}) + "\n"
                               for _ in range(producer.LOG_RECORDS_MAX + 5)))
        rec = producer.Recorder.from_env(self.env)
        base = dict(authority_kind="plan", authority_ref="p")
        self.assertEqual(rec.from_log(log, "dispatch.egress", "egress-proxy", producer.egress_result, base),
                         producer.LOG_RECORDS_MAX)
        last = self.records()[-1]
        self.assertIn("5 more lines of egress.jsonl", last["reason"])
        self.assertEqual(last["outputs"], {"egress.jsonl": producer.file_digest(log)})


class DispatcherTests(Base):  # vector 102
    def test_a_refused_step_is_recorded_with_its_reason(self):
        root = self.tmp / "job"
        root.mkdir()
        code = self.main(["prepare", "--repo", "o/r", "--root", str(root)],
                         {"cmd_prepare": mock.Mock(side_effect=DispatchError("the plan's head moved"))})
        self.assertEqual(code, 1)
        (rec,) = self.records()
        self.assertEqual((rec["action"], rec["class"], rec["result"]), ("dispatch.prepare", "write", "refused"))
        self.assertEqual(rec["reason"], "prepare: the plan's head moved")
        self.assertEqual(rec["subject"], {"mission": MID, "round": 1, "run": RUN, "pr": None, "commit": "a" * 40})
        self.assertEqual(rec["authority"], {"kind": "plan", "ref": f"{MID} A2 round 1"})
        self.verified()

    def test_prepare_records_the_binding_and_provenance_by_digest(self):
        root = self.tmp / "job"
        (root / "binding").mkdir(parents=True)
        (root / "binding" / "binding.json").write_text("{}\n")
        (root / "binding" / "provenance.json").write_text("{\"landings\": []}\n")
        self.main(["prepare", "--repo", "o/r", "--root", str(root)], {"cmd_prepare": mock.Mock(return_value=0)})
        (rec,) = self.records()
        self.assertEqual(rec["result"], "done")
        self.assertEqual(rec["outputs"], {"binding.json": producer.file_digest(root / "binding" / "binding.json"),
                                          "provenance.json": producer.file_digest(root / "binding" / "provenance.json")})

    def test_collect_records_the_change_and_each_gateway_and_egress_decision(self):
        root, out = self.tmp / "job", self.tmp / "out"
        (out / "binding").mkdir(parents=True)
        root.mkdir()
        (out / "change.patch").write_text("diff\n")
        (out / "message.txt").write_text("the agent's message\n")
        (out / "boundary.json").write_text("{}\n")
        (out / "binding" / "gateway-evidence.jsonl").write_text("\n".join(json.dumps(x) for x in (
            {"entry": "decision", "tool": "search", "record": {"disposition": "ALLOW"}},
            {"entry": "decision", "tool": "write_note", "record": {"disposition": "DENY"}},
            {"entry": "refusal", "tool": "unknown_tool"},
            {"entry": "retrieval", "tool": "search"})) + "\n")
        (out / "egress.jsonl").write_text("\n".join(json.dumps(x) for x in (
            {"host": "api.example.invalid", "port": 443, "decision": "allowed"},
            {"host": "other.example.invalid", "port": 443, "decision": "refused"},
            {"route": "model", "path": "/v1/messages", "decision": "allowed"})) + "\n")
        self.main(["collect", "--root", str(root), "--out", str(out)], {"cmd_collect": mock.Mock(return_value=0)})
        recs = self.records()
        self.assertEqual([r["action"] for r in recs], ["dispatch.collect"] + ["gateway.tool"] * 3
                         + ["dispatch.egress"] * 3)
        self.assertEqual(set(recs[0]["outputs"]), {"change.patch", "message.txt", "boundary.json", "binding.json",
                                                   "gateway-evidence.jsonl", "egress.jsonl"} - {"binding.json"})
        self.assertEqual([r["result"] for r in recs[1:4]], ["done", "refused", "refused"])
        self.assertEqual([r["result"] for r in recs[4:]], ["done", "refused", "done"])
        self.assertEqual(recs[1]["actor"]["name"], "mcp-gateway")
        self.assertEqual(recs[4]["actor"]["name"], "egress-proxy")
        for r in recs:
            self.assertNotIn("the agent's message", json.dumps(r), "digests, never content")
        report = self.verified(files=out)
        self.assertEqual(report.files_checked, 5)

    def test_v104_a_changed_file_is_refused(self):
        out = self.tmp / "out"
        out.mkdir()
        (out / "change.patch").write_text("diff\n")
        self.main(["collect", "--root", str(self.tmp), "--out", str(out)], {"cmd_collect": mock.Mock(return_value=0)})
        (out / "change.patch").write_text("a different diff\n")
        report = verify.verify_store(self.store, {}, files=out)
        self.assertIn("change.patch does not match its recorded digest", report.failure)

    def test_a_file_name_found_twice_is_listed_not_checked(self):
        out = self.tmp / "out"
        (out / "a").mkdir(parents=True)
        (out / "change.patch").write_text("diff\n")
        self.main(["collect", "--root", str(self.tmp), "--out", str(out)], {"cmd_collect": mock.Mock(return_value=0)})
        (out / "a" / "change.patch").write_text("another\n")
        report = self.verified(files=out)
        self.assertEqual((report.files_checked, report.ambiguous_files), (0, ["change.patch"]))

    def test_publish_is_recorded_as_the_agent_with_its_pr(self):
        def publish(args):
            cli._NOTE.update(pr=7, commit="b" * 40)
            return 0
        self.main(["publish", "--repo", "o/r", "--root", str(self.tmp), "--artifact", str(self.tmp)],
                  {"cmd_publish": publish})
        (rec,) = self.records()
        self.assertEqual((rec["action"], rec["actor"]["name"], rec["subject"]["pr"]),
                         ("dispatch.publish", "example-a2[bot]", 7))
        self.assertEqual(rec["outputs"], {"commit": producer.text_digest("b" * 40)})

    def test_report_records_its_comment_by_digest(self):
        def report(args):
            cli._NOTE.update(comment=producer.text_digest("the comment"))
            return 0
        self.main(["report", "--repo", "o/r"], {"cmd_report": report})
        (rec,) = self.records()
        self.assertEqual((rec["action"], rec["class"]), ("dispatch.report", "send"))
        self.assertEqual(rec["outputs"], {"comment": producer.text_digest("the comment")})

    def test_the_checks_job_records_each_exit_code(self):
        out = self.tmp / "checks"
        out.mkdir()
        (out / "checks.json").write_text(json.dumps([
            {"index": 1, "command": "python3 -m unittest", "exit_code": 0, "passed": True, "output_tail": "OK"},
            {"index": 2, "command": "make lint", "exit_code": 2, "passed": False, "output_tail": "error"},
            {"index": 3, "command": "make docs", "exit_code": None, "passed": False, "output_tail": ""}]))
        self.main(["checks", "--root", str(self.tmp), "--out", str(out)], {"cmd_checks": mock.Mock(return_value=0)})
        recs = self.records()
        self.assertEqual([(r["action"], r["result"], r["reason"]) for r in recs],
                         [("checks.check", "done", "check 1: exit 0"), ("checks.check", "failed", "check 2: exit 2"),
                          ("checks.check", "failed", "check 3: exit not run")])
        self.assertEqual(recs[0]["actor"]["name"], "mission-checks")

    def test_a_registry_check_is_recorded_only_when_it_refuses(self):
        self.main(["registry-check", "--runtime", "claude-code", "--package", "p"],
                  {"cmd_registry_check": mock.Mock(return_value=0)})
        self.assertFalse((self.store / verify.RUNS / RUN / chain.RECORDS).exists())
        self.main(["registry-check", "--runtime", "claude-code", "--package", "p"],
                  {"cmd_registry_check": mock.Mock(side_effect=DispatchError("the signature does not verify"))})
        (rec,) = self.records()
        self.assertEqual((rec["action"], rec["class"]), ("dispatch.refusal", "refuse"))

    def test_steps_that_act_on_nothing_are_not_recorded(self):
        self.main(["due", "--repo", "o/r"], {"cmd_due": mock.Mock(return_value=0)})
        self.assertFalse(self.store.exists() and any(self.store.rglob(chain.RECORDS)))

    def test_one_job_s_steps_form_one_chain(self):
        root = self.tmp / "job"
        root.mkdir()
        for step, fn in (("prepare", "cmd_prepare"), ("run", "cmd_run"), ("collect", "cmd_collect")):
            argv = [step, "--root", str(root)] + (["--repo", "o/r"] if step == "prepare" else []) \
                + (["--out", str(self.tmp / "out")] if step == "collect" else [])
            self.main(argv, {fn: mock.Mock(return_value=0)})
        recs = self.records()
        self.assertEqual([r["action"] for r in recs], ["dispatch.prepare", "dispatch.run", "dispatch.collect"])
        self.assertEqual([r["seq"] for r in recs], [0, 1, 2])
        self.verified()


class CommitTests(Base):
    def git(self, *args, cwd):
        return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()

    def test_each_record_s_commit_must_be_in_the_repository(self):
        repo = self.tmp / "repo"
        repo.mkdir()
        self.git("init", "-q", cwd=repo)
        self.git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "--allow-empty",
                 "-m", "c", cwd=repo)
        head = self.git("rev-parse", "HEAD", cwd=repo)
        rec = producer.Recorder.from_env(self.env)
        rec.record(actor="mission-dispatch", account_id=None, action="dispatch.run", result="done", commit=head,
                   authority_kind="plan", authority_ref="p")
        self.assertEqual(self.verified(git=repo).commits_checked, 1)
        rec.record(actor="mission-dispatch", account_id=None, action="dispatch.run", result="done", commit="c" * 40,
                   authority_kind="plan", authority_ref="p")
        report = verify.verify_store(self.store, {}, git=repo)
        self.assertIn("commit cccccccccccc is not in the repository", report.failure)


class CredentialsCheckTests(Base):
    def test_the_default_branch_check_is_on_record(self):
        from credentials_check import __main__ as cc
        env = {producer.DIR_ENV: str(self.store), producer.RUN_ENV: "gh-1-1-credentials", "GITHUB_SHA": "d" * 40}
        with mock.patch.dict(os.environ, env), mock.patch("sys.stdout"):
            cc._record({"FINDING": ["row 3 is stale"], "PIN": []})
        recs = self.records("gh-1-1-credentials")
        self.assertEqual([r["action"] for r in recs], ["credentials.finding"] * 2)
        self.assertEqual(recs[0]["reason"], "FINDING row 3 is stale")
        self.assertEqual(recs[1]["reason"], "finding=1, pin=0")
        self.assertEqual(recs[1]["subject"]["commit"], "d" * 40)

    def test_without_a_chain_nothing_is_written(self):
        from credentials_check import __main__ as cc
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(producer.DIR_ENV, None)
            cc._record({"FINDING": ["x"]})
        self.assertFalse(self.store.exists())


class WorkflowTests(unittest.TestCase):
    def test_every_recording_job_starts_and_keeps_its_chain(self):
        text = workflow("mission-agent.yml")
        for job in ("checks", "agent", "publish", "report"):
            with self.subTest(job):
                start = text.index(f"\n  {job}:\n")
                nxt = min(i for i in (text.find(f"\n  {n}:\n", start + 1) for n in
                                      ("agent", "publish", "report", "land")) if i > start)
                block = text[start:nxt]
                self.assertIn(f"EVIDENCE_RUN=gh-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT-{job}-$LANE", block)
                self.assertIn('install -d -m 0700 "$RUNNER_TEMP/evidence"', block)
                self.assertIn(f"name: evidence-{job}-", block)
                keep = block.index("Keep this job's evidence chain")
                self.assertIn("if: always()", block[keep:keep + 200])

    def test_the_credentials_check_records_on_the_default_branch_only(self):
        text = workflow("credentials-check.yml")
        self.assertIn("EVIDENCE_RUN=gh-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT-credentials", text)
        self.assertEqual(text.count("github.event_name == 'push'"), 2)


if __name__ == "__main__":
    unittest.main()
