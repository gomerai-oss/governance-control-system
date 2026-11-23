"""Ring 6 part 4 (MISSION-DISPATCH-001 §3m items 2, 3 and 6; MISSION-ROUTER-001 Amendment 018): the seal job, the
evidence store, the evidence key, and the router's hold under enforce. Vectors 103, 105, 106 and 108; router vector
118. Placeholder repositories and accounts only."""

from __future__ import annotations

import base64
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from epap import ed25519
from evidence import EvidenceError, chain, producer, record, sealer, seal, store, verify
from mission_dispatch import permissions
from mission_router.github import GitHubError
from mission_router.router import load_config

from tests import test_mission_router as rt

AW = Path(__file__).resolve().parents[1]
ROOT = AW.parents[1]
LANE = "M-DEMO-001-A2-r1"


class FakeStore:
    """The contents API of a store: a file is added once; a PUT naming an existing file is refused."""

    def __init__(self):
        self.files = {}
        self.puts = []

    def request(self, method, path, body=None):
        name = path.split("?")[0][len("/contents/"):]
        if method == "GET":
            if name not in self.files:
                raise GitHubError(404, "Not Found", path)
            return {"content": base64.b64encode(self.files[name]).decode()}
        if method == "PUT":
            self.puts.append(body)
            if name in self.files or "sha" in body:
                raise GitHubError(422, "sha wasn't supplied", path)
            self.files[name] = base64.b64decode(body["content"])
            return {}
        raise AssertionError(method)

    def copy_to(self, root: Path):
        for name, data in self.files.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_bytes(data)


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.seed = ed25519.generate_seed()
        public = ed25519.public_key(self.seed)
        self.keys = {seal.keyid(public): public.hex()}
        self.chains = self.tmp / "chains"
        self.fake = FakeStore()

    def job(self, job, records=(("dispatch.prepare", None), ("dispatch.publish", 7))):
        run = f"gh-1-1-{job}-{LANE}"
        rec = producer.Recorder(self.chains / f"evidence-{job}-{LANE}", run)
        for action, pr in records:
            rec.record(actor="mission-dispatch", account_id=None, action=action, result="done", pr=pr,
                       commit="a" * 40, authority_kind="plan", authority_ref="M-DEMO-001 A2 round 1")
        return run

    def seal(self, seed=None):
        return sealer.seal_runs(self.chains, seed or self.seed, self.keys, store.Store(self.fake.request),
                                "2026-11-07T12:00:00Z")


class SealTests(Base):
    def test_v103_each_chain_is_sealed_and_stored_and_verifies_from_the_store_alone(self):  # vectors 103, 108
        a, p = self.job("agent", [("dispatch.prepare", None)]), self.job("publish", [("dispatch.publish", 7)])
        result = self.seal()
        self.assertEqual((sorted(result["sealed"]), result["refused"], result["prs"]),
                         (sorted([a, p]), [], [{"pr": 7, "run": p}]))
        self.assertEqual(set(self.fake.files), {f"runs/{r}/{n}" for r in (a, p) for n in ("records.jsonl", "seal.json")})
        self.assertTrue(all("sha" not in put for put in self.fake.puts), "a stored file is only ever added")
        copy = self.tmp / "store"
        self.fake.copy_to(copy)
        report = verify.verify_store(copy, self.keys, require_seal=True)
        self.assertTrue(report.ok, report.failure)
        self.assertEqual((report.runs, report.unsealed), (2, []))

    def test_an_unpinned_key_seals_nothing(self):
        self.job("agent")
        with self.assertRaisesRegex(EvidenceError, "not a pinned evidence key"):
            self.seal(seed=ed25519.generate_seed())
        self.assertEqual(self.fake.files, {})

    def test_a_broken_chain_is_not_sealed_and_marks_nothing(self):
        good = self.job("agent")
        bad = self.job("publish")
        path = self.chains / f"evidence-publish-{LANE}" / verify.RUNS / bad / chain.RECORDS
        lines = path.read_bytes().split(b"\n")
        path.write_bytes(lines[1] + b"\n")  # the first record removed
        result = self.seal()
        self.assertEqual(result["sealed"], [good])
        self.assertEqual(result["refused"][0]["run"], bad)
        self.assertNotIn(f"runs/{bad}/seal.json", self.fake.files)
        self.assertEqual(sealer.mark(result, None, "example-org/evidence-store"), [])

    def test_v239_a_refused_chain_holds_back_only_its_own_runs_prs(self):  # Amendment 047
        good = self.job("publish")  # run gh-1-1-, publishes PR 7
        other = "gh-2-1-publish-" + LANE
        rec = producer.Recorder(self.chains / f"evidence-publish-2-{LANE}", other)
        rec.record(actor="mission-dispatch", account_id=None, action="dispatch.publish", result="done", pr=8,
                   commit="a" * 40, authority_kind="plan", authority_ref="M-DEMO-002 A2 round 1")
        path = self.chains / f"evidence-publish-2-{LANE}" / verify.RUNS / other / chain.RECORDS
        path.write_bytes(path.read_bytes() + b"{}\n")  # a record that does not verify
        result = self.seal()
        self.assertEqual((result["sealed"], [r["run"] for r in result["refused"]]), ([good], [other]))
        self.assertEqual(sealer.to_mark(result), [{"pr": 7, "run": good, "chains": [good]}])

        class GH:
            def __init__(self):
                self.checks = []

            def request(self, method, path, body=None):
                return {"head": {"sha": "b" * 40}}

            def create_check_run(self, name, sha, status, conclusion, title, summary):
                self.checks.append((name, sha, conclusion, summary))

        gh = GH()
        self.assertEqual(sealer.mark(result, gh, "example-org/evidence-store"), [7])
        self.assertEqual(len(gh.checks), 1)
        self.assertIn(good, gh.checks[0][3])
        self.assertNotIn(other, gh.checks[0][3])

    def test_v239_count_prints_the_prs_to_mark(self):
        from evidence import __main__ as cli
        import contextlib
        import io
        out = self.tmp / "sealed.json"
        for result, want in (({"sealed": ["gh-5-1-publish-x"], "refused": [], "prs": [{"pr": 3, "run": "gh-5-1-publish-x"}]}, "prs=1"),
                             ({"sealed": ["gh-5-1-agent-x"], "refused": [], "prs": []}, "prs=0"),
                             ({"sealed": [], "refused": [{"run": "gh-5-1-publish-x", "reason": "r"}],
                               "prs": [{"pr": 3, "run": "gh-5-1-publish-x"}]}, "prs=0")):
            out.write_text(json.dumps(result))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(cli.main(["count", "--result", str(out)]), 0)
            self.assertEqual(buf.getvalue().strip(), want)

    def test_a_rerun_stores_nothing_new_and_never_replaces(self):
        run = self.job("agent")
        self.seal()
        before = dict(self.fake.files)
        s = store.Store(self.fake.request)
        self.assertEqual(s.add(f"runs/{run}/records.jsonl", before[f"runs/{run}/records.jsonl"], "m"), "same")
        with self.assertRaisesRegex(EvidenceError, "never replaced"):
            s.add(f"runs/{run}/records.jsonl", b"other\n", "m")
        self.assertEqual(self.fake.files, before)

    def test_a_chain_handed_over_twice_is_refused(self):
        self.job("agent")
        (self.chains / "copy").mkdir()
        src = next(self.chains.rglob(chain.RECORDS))
        dest = self.chains / "copy" / verify.RUNS / src.parent.name
        dest.mkdir(parents=True)
        (dest / chain.RECORDS).write_bytes(src.read_bytes())
        with self.assertRaisesRegex(EvidenceError, "handed over twice"):
            self.seal()

    def test_the_seal_key_must_be_hex(self):
        with self.assertRaisesRegex(EvidenceError, "lowercase hex"):
            sealer.seed_from("not a key")


class MarkTests(Base):
    class GH:
        def __init__(self):
            self.checks = []

        def request(self, method, path, body=None):
            assert (method, path) == ("GET", "/pulls/7")
            return {"head": {"sha": "b" * 40}}

        def create_check_run(self, *args):
            self.checks.append(args)

    def test_the_published_pr_gets_evidence_sealed(self):
        self.job("publish")
        result = self.seal()
        gh = self.GH()
        self.assertEqual(sealer.mark(result, gh, "example-org/evidence-store"), [7])
        name, sha, status, conclusion, title, summary = gh.checks[0]
        self.assertEqual((name, sha, status, conclusion), ("evidence-sealed", "b" * 40, "completed", "success"))
        self.assertIn("example-org/evidence-store", summary)


class KeygenTests(unittest.TestCase):
    def test_the_seed_goes_to_the_secret_only(self):
        calls = []

        def run(argv, input, text, capture_output):
            calls.append((argv, input))
            return subprocess.CompletedProcess(argv, 0, "", "")
        entry = sealer.keygen("example-org/example-repo", "evidence-seal", run=run)
        ((argv, given),) = calls
        self.assertEqual(argv, ["gh", "secret", "set", "EVIDENCE_SEAL_KEY", "--env", "evidence-seal",
                                "-R", "example-org/example-repo"])
        self.assertEqual(entry["public"], ed25519.public_key(bytes.fromhex(given)).hex())
        self.assertEqual(entry["keyid"], seal.keyid(bytes.fromhex(entry["public"])))
        self.assertNotIn(given, json.dumps(entry))

    def test_a_failed_secret_set_is_an_error(self):
        def run(argv, input, text, capture_output):
            return subprocess.CompletedProcess(argv, 1, "", "HTTP 404")
        with self.assertRaisesRegex(EvidenceError, "gh secret set failed"):
            sealer.keygen("example-org/example-repo", "evidence-seal", run=run)


class HistoryTests(unittest.TestCase):
    def git(self, *args, cwd):
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args], cwd=cwd, check=True,
                       capture_output=True)

    def test_a_stored_file_changed_later_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            self.git("init", "-q", cwd=repo)
            (repo / "runs" / "r1").mkdir(parents=True)
            (repo / "runs" / "r1" / "records.jsonl").write_text("a\n")
            self.git("add", "-A", cwd=repo)
            self.git("commit", "-q", "-m", "add", cwd=repo)
            self.assertEqual(store.history_problems(repo), [])
            (repo / "runs" / "r1" / "records.jsonl").write_text("b\n")
            self.git("commit", "-q", "-am", "edit", cwd=repo)
            (problem,) = store.history_problems(repo)
            self.assertIn("runs/r1/records.jsonl was changed after it was stored", problem)


class RouterHoldTests(unittest.TestCase):  # router vector 118 (item 6)
    def loop(self, mode):
        t = rt.RouterLoopTests("test_full_mission_fail_then_pass")
        t.setUp()
        t.router.evidence_mode = mode
        return t

    def test_v118_an_unsealed_stage_pr_is_held_under_enforce(self):
        t = self.loop("enforce")
        t.start_mission()
        n = t.a2_round(1)
        self.assertEqual(t.gh.prs[n]["state"], "open", "held, not merged")
        self.assertTrue(any("not sealed and stored yet" in c for c in t.bot_comments(n)), "the router says why")
        sha = t.gh.branches[t.gh.prs[n]["head_ref"]]
        t.gh.create_check_run("evidence-sealed", sha, "completed", "success", "Evidence sealed and stored", "s")
        t.sweep()
        self.assertEqual(t.gh.prs[n]["merged_by"], rt.BOT)

    def test_a_failed_or_foreign_seal_check_does_not_count(self):
        t = self.loop("enforce")
        t.start_mission()
        n = t.a2_round(1)
        sha = t.gh.branches[t.gh.prs[n]["head_ref"]]
        t.gh.create_check_run("evidence-sealed", sha, "completed", "failure", "x", "s")
        t.gh.checks[sha].append({"id": 999999, "name": "evidence-sealed", "status": "completed",
                                 "conclusion": "success", "app": {"slug": "some-other-app"}, "output": {}})
        t.sweep()
        self.assertEqual(t.gh.prs[n]["state"], "open")

    def test_under_observe_it_merges_and_says_so_in_the_log(self):
        t = self.loop("observe")
        t.start_mission()
        n = t.a2_round(1)
        self.assertEqual(t.gh.prs[n]["merged_by"], rt.BOT)
        self.assertTrue(any("evidence (observe)" in line for line in t.logs))

    def test_the_plan_pr_is_not_held(self):  # A1 is opened by HITL or A1, not by a dispatcher run
        t = self.loop("enforce")
        n = t.start_mission()
        self.assertEqual(t.gh.prs[n]["merged_by"], rt.BOT)


class ConfigTests(unittest.TestCase):
    def test_the_store_must_be_owner_name(self):
        config = json.loads((AW / "mission_router" / "config.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({**config, "evidence_store": "not a repository"}))
            with self.assertRaisesRegex(ValueError, "evidence_store must be owner/name"):
                load_config(path)
            path.write_text(json.dumps({**config, "evidence_store": "example-org/evidence-store"}))
            self.assertEqual(load_config(path)["evidence_store"], "example-org/evidence-store")


class PermissionTests(unittest.TestCase):
    TABLE = {"schema": permissions.GRANTS_SCHEMA, "spec": "s", "workflows": {"evidence-seal.yml": {
        "top level": {}, "jobs": {"seal": {"actions": "read"}},
        "app_tokens": {"seal": [{"contents": "write", "(repositories)": "${{ steps.store.outputs.name }}"}]}}}}
    WORKFLOW = """name: w
permissions: {}
jobs:
  seal:
    permissions:
      actions: read
    steps:
      - uses: actions/create-github-app-token@67018539274d69449ef7c02e8e71183d1719ab42 # v2.1.4
        with:
          repositories: %s
          permission-contents: write
"""

    def findings(self, named, table=None):
        return permissions.grant_findings(table or self.TABLE, {"evidence-seal.yml": self.WORKFLOW % named})

    def test_the_store_token_is_allowed_only_where_its_row_names_the_store(self):
        self.assertEqual(self.findings("${{ steps.store.outputs.name }}"), [])
        (finding,) = self.findings("${{ steps.repo.outputs.name }}")
        self.assertIn("must name repositories: ${{ steps.store.outputs.name }} (its row's)", finding)

    def test_a_row_may_name_only_a_listed_repository(self):
        bad = json.loads(json.dumps(self.TABLE))
        bad["workflows"]["evidence-seal.yml"]["app_tokens"]["seal"][0]["(repositories)"] = "${{ inputs.anything }}"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "grants.json"
            path.write_text(json.dumps(bad))
            with self.assertRaisesRegex(permissions.PermissionsError, "malformed"):
                permissions.read_grants_table(path)


class CheckoutTests(unittest.TestCase):
    """Every job that checks out this repository can read it. Ring 6's seal and mark jobs first shipped without
    ``contents: read`` and failed at checkout on every run (2026-11-09); this checks every mission workflow."""

    def test_every_job_that_checks_out_this_repository_can_read_it(self):
        import re
        for name in permissions.WORKFLOWS:
            live = ROOT / ".github" / "workflows" / name
            path = live if live.is_file() else ROOT / "packaging" / "workflows" / name
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            grants = permissions.workflow_grants(name, text)
            top = grants.get(f"{name}: top level", {})
            body = text[text.index("\njobs:\n"):]
            heads = list(re.finditer(r"(?m)^  ([A-Za-z0-9_-]+):\s*$", body))
            for i, head in enumerate(heads):
                block = body[head.start():heads[i + 1].start() if i + 1 < len(heads) else len(body)]
                steps = re.split(r"(?m)^      - ", block)
                checkouts = [st for st in steps if "uses: actions/checkout@" in st and "repository:" not in st]
                if not checkouts:
                    continue
                job = head.group(1)
                perms = grants.get(f"{name}: job {job}", top)
                with self.subTest(f"{name}: {job}"):
                    self.assertIn(perms.get("contents"), ("read", "write"),
                                  f"{name} job {job} checks out this repository without contents: read")


class SwitchOnFixTests(unittest.TestCase):
    """The three findings of AST-6.1 to 6.6, fixed with the switch-on (2026-11-09)."""

    def run_chain(self, root, run, n=3):
        rec = producer.Recorder(root, run)
        out = []
        for i in range(n):
            out.append(rec.record(actor="mission-dispatch", account_id=None, action="dispatch.run", result="done",
                                  authority_kind="plan", authority_ref="p"))
        return out

    def test_history_findings_show_even_when_a_chain_fails(self):  # AST-6.1, AST-6.2
        import io
        from contextlib import redirect_stdout
        from evidence import __main__ as cli
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            self.run_chain(repo, "run-a")
            self.run_chain(repo, "run-b")
            git = lambda *a: subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *a],
                                            cwd=repo, check=True, capture_output=True)
            git("init", "-q")
            git("add", "-A")
            git("commit", "-q", "-m", "stored")
            path = repo / "runs" / "run-a" / chain.RECORDS
            lines = path.read_bytes().split(b"\n")
            path.write_bytes(lines[0] + b"\n" + lines[2] + b"\n")  # run-a loses a record
            subprocess.run(["rm", "-r", str(repo / "runs" / "run-b")], check=True)  # run-b is deleted whole
            git("commit", "-q", "-am", "edit")
            keys = Path(tmp) / "k.json"
            keys.write_text(json.dumps({"schema": seal.KEYS_SCHEMA, "keys": []}))
            out = io.StringIO()
            with redirect_stdout(out):
                code = cli.main(["verify", "--store", str(repo), "--keys", str(keys), "--store-history"])
            text = out.getvalue()
            self.assertEqual(code, 1)
            self.assertIn("a gap in the chain", text)
            self.assertIn("runs/run-b/records.jsonl was changed after it was stored", text,
                          "the deleted run is named although another chain failed first")

    def test_a_withdrawal_in_another_run_shows_when_one_run_is_checked(self):  # AST-6.5
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = self.run_chain(root, "run-k")[1]
            rec = producer.Recorder(root, "run-w")
            rec.record(actor="hitl-example", account_id=6001, action="evidence.withdraw", result="done",
                       reason="wrong round", authority_kind="hitl_command", authority_ref="HITL direction",
                       withdraws={"id": target["id"], "digest": record.digest(target)})
            rec.record(actor="mission-dispatch", account_id=None, action="dispatch.run", result="done",
                       authority_kind="plan", authority_ref="p")  # so an edit to the withdrawal breaks a link
            report = verify.verify_store(root, {}, run="run-k")
            self.assertTrue(report.ok, report.failure)
            self.assertEqual(report.withdrawn, {"run-k/1": "run-w/0"})
            path = root / "runs" / "run-w" / chain.RECORDS
            path.write_bytes(path.read_bytes().replace(b"wrong round", b"other text!"))
            self.assertIn("run run-w", verify.verify_store(root, {}, run="run-k").failure or "",
                          "a withdrawal from a run that does not verify is refused")

    def test_a_key_change_is_a_pin_line(self):  # limit 30
        from mission_dispatch import supply_chain
        with tempfile.TemporaryDirectory() as tmp:
            base, head = Path(tmp) / "base", Path(tmp) / "head"
            for root, keys in ((base, []), (head, [{"keyid": "a" * 64, "public": "b" * 64}])):
                (root / "tools/agent_workflow/evidence").mkdir(parents=True)
                (root / "tools/agent_workflow/evidence/key.json").write_text(
                    json.dumps({"schema": seal.KEYS_SCHEMA, "keys": keys}))
            self.assertEqual(supply_chain.evidence_key_lines(base, head, "tools/agent_workflow"),
                             ["key.json adds evidence key aaaaaaaaaaaaaaaa... (a HITL hand merge; it can seal from the "
                              "merge on)"])
            self.assertEqual(supply_chain.evidence_key_lines(head, base, "tools/agent_workflow"),
                             ["key.json removes evidence key aaaaaaaaaaaaaaaa... (seals made with it no longer verify)"])
            self.assertEqual(supply_chain.evidence_key_lines(base, base, "tools/agent_workflow"), [])


class WorkflowTests(unittest.TestCase):
    def text(self):
        live = ROOT / ".github" / "workflows" / "evidence-seal.yml"
        return (live if live.is_file() else ROOT / "packaging" / "workflows" / "evidence-seal.yml").read_text()

    def test_the_seal_job_holds_the_keys_and_the_mark_job_none(self):
        text = self.text()
        seal_job, mark_job = text[text.index("\n  seal:\n"):text.index("\n  mark:\n")], text[text.index("\n  mark:\n"):]
        self.assertIn("environment: evidence-seal", seal_job)
        self.assertIn("secrets.EVIDENCE_SEAL_KEY", seal_job)
        self.assertNotIn("secrets.", mark_job)
        self.assertNotIn("environment:", mark_job)
        on = text[text.index("\non:\n"):text.index("\npermissions:")]
        self.assertIn("schedule:", on)
        self.assertNotIn("workflow_run", on, "the sweep is the only way in (Amendment 047)")
        self.assertIn("permissions: {}", text)

    def test_v240_the_mark_job_runs_only_when_a_sealed_run_published_a_pr(self):  # Amendment 047
        text = self.text()
        seal_job, mark_job = text[text.index("\n  seal:\n"):text.index("\n  mark:\n")], text[text.index("\n  mark:\n"):]
        self.assertIn("prs: ${{ steps.count.outputs.prs }}", seal_job)
        self.assertIn("python3 -B -m evidence count --result", seal_job)
        head = mark_job[:mark_job.index("\n    steps:")]
        self.assertIn("needs.seal.outputs.prs != '0'", head)
        self.assertIn("always()", head, "a refused chain fails the seal job; the other runs' PRs are still marked")
        upload = seal_job[seal_job.index("Hand the result to the mark job"):]
        self.assertIn("steps.count.outputs.prs != '0'", upload[:upload.index("uses:")])


if __name__ == "__main__":
    unittest.main()


class SweepTests(Base):
    """Amendments 022 and 047, vectors 122, 123 and 238: the scheduled sweep is the only way in. It lists the
    repository's evidence artifacts and seals every ended run of a sealed workflow whose evidence is not all sealed,
    however the run was started."""

    NOW = __import__("datetime").datetime(2026, 11, 10, 5, 0, tzinfo=__import__("datetime").timezone.utc)

    class Actions:
        """``/actions/artifacts`` (newest first, 100 a page) and ``/actions/runs/<id>``."""

        def __init__(self, runs, artifacts):
            self.runs, self.paths = {r["id"]: r for r in runs}, []
            self.artifacts = artifacts  # [(run id, name, created_at)], newest first

        def __call__(self, method, path, body=None):
            self.paths.append(path)
            if path.startswith("/actions/artifacts?"):
                page = int(path.rsplit("page=", 1)[1])
                rows = self.artifacts[(page - 1) * 100:page * 100]
                return {"artifacts": [{"name": n, "expired": False, "created_at": t, "workflow_run": {"id": r}}
                                      for r, n, t in rows]}
            return self.runs[int(path.split("/")[3])]

    class Trees:
        def __init__(self, chains, truncated=False):
            self.chains, self.truncated = chains, truncated

        def __call__(self, method, path, body=None):
            if path == "/git/trees/main":
                return {"tree": [{"path": "runs", "type": "tree", "sha": "r"}]}
            assert path == "/git/trees/r?recursive=1", path
            out = []
            for chain_name, sealed in self.chains.items():
                out.append({"path": f"{chain_name}/records.jsonl", "type": "blob"})
                if sealed:
                    out.append({"path": f"{chain_name}/seal.json", "type": "blob"})
            return {"tree": out, "truncated": self.truncated}

    def run_(self, rid, f="mission-agent.yml", attempt=1, status="completed"):
        return {"id": rid, "run_attempt": attempt, "path": f".github/workflows/{f}", "status": status}

    T = "2026-11-10T04:00:00Z"

    def test_v122_a_run_with_unsealed_evidence_is_named(self):
        from evidence import sweep
        actions = self.Actions([self.run_(11), self.run_(13)],
                               [(11, "evidence-agent-x", self.T), (11, "evidence-publish-x", self.T),
                                (11, "change-x", self.T), (13, "evidence-agent-z", self.T)])
        store_ = self.Trees({"gh-11-1-agent-x": True, "gh-11-1-publish-x": False, "gh-13-1-agent-z": True})
        self.assertEqual(sweep.unsealed_runs(actions, store_, self.NOW), [{"id": 11, "attempt": 1}])
        self.assertNotIn("/actions/runs/13", actions.paths, "a run whose evidence is all sealed is not read")

    def test_v238_any_ended_run_of_a_sealed_workflow_however_started(self):
        from evidence import sweep
        old = "2026-11-08T04:59:59Z"  # before the 2-day lookback
        actions = self.Actions(
            [self.run_(21, "mission-router.yml"), self.run_(22, "credentials-check.yml", attempt=2),
             self.run_(23, status="in_progress"), self.run_(24, "policy-ci.yml"), self.run_(25)],
            [(21, "evidence-router", self.T), (22, "evidence-credentials", self.T), (22, "evidence-credentials", self.T),
             (23, "evidence-agent-a", self.T), (24, "evidence-other", self.T), (25, "evidence-agent-b", old)])
        store_ = self.Trees({"gh-22-1-credentials": True})  # a re-run keeps attempt 1's artifact; attempt 2's is unsealed
        self.assertEqual(sweep.unsealed_runs(actions, store_, self.NOW),
                         [{"id": 21, "attempt": 1}, {"id": 22, "attempt": 2}])
        self.assertNotIn("/actions/runs/25", actions.paths, "an artifact older than the lookback is not counted")
        both = self.Trees({"gh-22-1-credentials": True, "gh-22-2-credentials": True})
        self.assertNotIn({"id": 22, "attempt": 2}, sweep.unsealed_runs(actions, both, self.NOW),
                         "once both attempts are sealed the re-run is not named again")

    def test_v238_paging_stops_after_a_page_wholly_before_the_lookback(self):
        from evidence import sweep
        old = "2026-11-01T00:00:00Z"
        rows = [(30, "sealed", self.T)] * 99 + [(31, "evidence-agent-c", old)]  # page 1: one old row, not all
        rows += [(32, "evidence-agent-d", self.T)] + [(33, "x", old)] * 99  # page 2: out of order, one new row
        rows += [(34, "evidence-agent-e", old)] * 100 + [(35, "evidence-agent-f", self.T)]  # page 3: all old
        actions = self.Actions([self.run_(32), self.run_(35)], rows)
        self.assertEqual(sweep.unsealed_runs(actions, self.Trees({}), self.NOW), [{"id": 32, "attempt": 1}])
        pages = [p for p in actions.paths if p.startswith("/actions/artifacts?")]
        self.assertEqual(len(pages), 3, "page 3 is wholly before the lookback, so page 4 is never asked for")

    def test_a_truncated_store_listing_sweeps_nothing(self):
        from evidence import sweep
        with self.assertRaisesRegex(EvidenceError, "too large"):
            sweep.unsealed_runs(self.Actions([], {}), self.Trees({}, truncated=True), self.NOW)

    def test_v123_resume_seals_the_rest_and_never_seals_twice(self):
        a = self.job("agent", [("dispatch.prepare", None)])
        p = self.job("publish", [("dispatch.publish", 7)])
        first = self.seal()
        stored_seal = self.fake.files[f"runs/{p}/seal.json"]
        del self.fake.files[f"runs/{a}/seal.json"]  # an earlier sweep stopped before sealing the agent chain
        again = sealer.seal_runs(self.chains, self.seed, self.keys, store.Store(self.fake.request),
                                 "2026-11-10T05:00:00Z", resume=True)
        self.assertEqual((sorted(again["sealed"]), again["refused"], again["prs"]),
                         (sorted(first["sealed"]), [], [{"pr": 7, "run": p}]))
        self.assertEqual(self.fake.files[f"runs/{p}/seal.json"], stored_seal, "the stored seal is kept")
        self.assertIn(f"runs/{a}/seal.json", self.fake.files, "the missing seal is made")
        copy = self.tmp / "store"
        self.fake.copy_to(copy)
        self.assertTrue(verify.verify_store(copy, self.keys, require_seal=True).ok)

    def test_without_resume_a_second_seal_is_still_refused(self):
        self.job("publish")
        self.seal()
        with self.assertRaisesRegex(EvidenceError, "never replaced"):
            sealer.seal_runs(self.chains, self.seed, self.keys, store.Store(self.fake.request), "2026-11-10T05:00:00Z")

    def test_the_sweep_covers_the_sealed_workflows(self):
        from evidence import sweep
        def workflow(name):  # live here; under packaging/workflows in a built release tree
            live = ROOT / ".github" / "workflows" / name
            return (live if live.is_file() else ROOT / "packaging" / "workflows" / name).read_text(encoding="utf-8")
        text = workflow("evidence-seal.yml")
        self.assertIn("schedule:", text)
        self.assertIn("evidence sweep --repo", text)
        self.assertIn("--resume", text[text.index("python3 -B -m evidence seal"):])
        for name, file_ in sweep.WORKFLOWS.items():
            wf = workflow(file_)
            with self.subTest(file_):
                self.assertIn(f"\nname: {name}\n", "\n" + wf)
                self.assertIn(name, text, "the seal workflow's header names every sealed workflow")
