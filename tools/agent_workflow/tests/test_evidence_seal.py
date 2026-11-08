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
from evidence import EvidenceError, chain, producer, sealer, seal, store, verify
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
        self.assertIn("types: [completed]", text)
        self.assertIn("permissions: {}", text)


if __name__ == "__main__":
    unittest.main()
