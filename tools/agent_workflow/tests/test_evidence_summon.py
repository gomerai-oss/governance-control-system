"""EPAP summon (MISSION-DISPATCH-001 Amendment 061): the evidence pack of one PR, for an outside auditor. A mission is
sealed through the real sealer into a store, its changes are real commits in a real git repository, and the pack is
checked as an auditor would: from its own files and its bundle alone. Placeholder repositories and accounts only."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from evidence import producer, sealer, store, summon

from tests.test_evidence_pack import ListingStore, key

ROOT = Path(__file__).resolve().parents[3]
MID = "M-DEMO-001"
REPO = "example-org/example-repo"
HITL, HITL_ID = "example-hitl", 1001


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Mission:
    """M-DEMO-001: a plan HITL approved, an A2 change published as PR #7 and merged, all sealed into a store."""

    def __init__(self, test, checks=True):
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.git = self.root / "repo"
        self.git.mkdir()
        self.run("init", "-q", "-b", "main")
        (self.git / "a.txt").write_text("one\n")
        self.run("add", "-A")
        self.run("commit", "-q", "-m", "plan")
        self.base = self.run("rev-parse", "HEAD")
        self.run("checkout", "-q", "-b", f"mission/{MID}/a2-r1")
        (self.git / "a.txt").write_text("one\ntwo\n")
        (self.git / "b.bin").write_bytes(bytes(range(256)))
        self.run("add", "-A")
        self.run("commit", "-q", "-m", "A2 round 1")
        self.head = self.run("rev-parse", "HEAD")
        self.run("checkout", "-q", "main")
        self.run("merge", "-q", "--no-ff", "-m", "merge A2", f"mission/{MID}/a2-r1")
        self.merge = self.run("rev-parse", "HEAD")
        self.run("update-ref", "refs/remotes/pull/7", self.head)
        self.patch = subprocess.run(["git", "-C", str(self.git), *summon.DIFF, self.base, self.head, "--"],
                                    capture_output=True, check=True).stdout
        chains = self.root / "chains"
        lane = f"{MID}-A2-r1"
        base = dict(mission=MID, round_n=1, authority_kind="plan", authority_ref=f"{MID} A2 round 1")
        agent = producer.Recorder(chains / "a", f"gh-11-1-agent-{lane}")
        agent.record(actor="mission-dispatch", account_id=None, action="dispatch.collect", result="done",
                     commit=self.base, outputs={"change.patch": sha(self.patch)}, **base)
        pub = producer.Recorder(chains / "p", f"gh-11-1-publish-{lane}")
        pub.record(actor="example-a2[bot]", account_id=None, action="dispatch.publish", result="done", pr=7,
                   commit=self.base, outputs={"commit": producer.text_digest(self.head)}, **base)
        if checks:
            chk = producer.Recorder(chains / "c", f"gh-11-1-checks-{lane}")
            chk.record(actor="mission-checks", account_id=None, action="checks.check", result="done",
                       reason="check 1: exit 0", **base)
        router = producer.Recorder(chains / "r", "gh-12-1-router")
        router.record(actor=HITL, account_id=HITL_ID, action="router.hitl_command", result="done",
                      reason=f"HITL command: /mission approve {self.base}", mission=MID, pr=5, commit=self.base,
                      authority_kind="hitl_command", authority_ref="comment 9 on #5")
        router.record(actor="example-router[bot]", account_id=None, action="router.decision", result="done",
                      reason="merge: ok", mission=MID, round_n=1, pr=7, commit=self.head,
                      authority_kind="spec_rule", authority_ref="MISSION-ROUTER-001")
        router.record(actor="example-router[bot]", account_id=None, action="router.merge", result="done",
                      reason=f"merge PR #7 at {self.head}", mission=MID, round_n=1, pr=7, commit=self.head,
                      authority_kind="spec_rule", authority_ref="MISSION-ROUTER-001")
        other = producer.Recorder(chains / "o", "gh-13-1-router")  # another mission: not in the pack
        other.record(actor="example-router[bot]", account_id=None, action="router.decision", result="done",
                     reason="merge: ok", mission="M-OTHER-001", pr=99, commit=self.head, authority_kind="spec_rule",
                     authority_ref="x")
        self.seed, self.keys = key()
        self.listing = ListingStore()
        sealer.seal_runs(chains, self.seed, self.keys, store.Store(self.listing.request), "2026-11-27T12:00:00Z")
        self.store = self.root / "store"
        self.listing.copy_to(self.store)
        self.keys_doc = {"schema": "evidence-keys-v1",
                         "keys": [{"keyid": k, "public": v} for k, v in self.keys.items()]}
        self.prs = {7: self.pr(7, f"mission/{MID}/a2-r1", self.head, merged=self.merge),
                    5: self.pr(5, f"mission/{MID}/a1", self.base, merged=None),
                    8: self.pr(8, "docs/by-hand", self.base, merged=None)}

    def run(self, *args):
        return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                              cwd=self.git, check=True, capture_output=True, text=True).stdout.strip()

    @staticmethod
    def pr(n, ref, head, merged):
        return {"number": n, "title": f"PR {n}", "body": "quarantined text", "state": "closed",
                "merged_at": "2026-11-27T11:00:00Z" if merged else None,
                "merge_commit_sha": merged or "f" * 40, "head": {"ref": ref, "sha": head},
                "base": {"ref": "main", "sha": "e" * 40}, "user": {"login": "example-a2[bot]"}}

    def summon(self, pr=7, out=None, **kw):
        out = out or self.root / f"pack-{pr}"
        return out, summon.summon(self.store, self.git, REPO, pr, self.prs.get, out, self.keys, self.keys_doc,
                                  "example-hitl", now="2026-11-27T12:30:00Z", **kw)


class PackTests(unittest.TestCase):
    def test_vector_278_a_pack_proves_each_stage_from_the_store_and_git(self):
        m = Mission(self)
        out, man = m.summon()
        self.assertEqual(man["mission"], MID)
        self.assertEqual([c["name"] for c in man["chains"]],
                         ["gh-11-1-agent-M-DEMO-001-A2-r1", "gh-11-1-checks-M-DEMO-001-A2-r1",
                          "gh-11-1-publish-M-DEMO-001-A2-r1", "gh-12-1-router"], "only this mission's chains")
        self.assertEqual({c["state"] for c in man["chains"]}, {"verified"})
        (stage,) = man["stages"]
        self.assertEqual((stage["role"], stage["round"], stage["pr"], stage["base"], stage["head"]),
                         ("A2", 1, 7, m.base, m.head))
        self.assertTrue(stage["head_bound"])
        self.assertEqual(stage["change"]["sealed_sha256"], sha(m.patch))
        self.assertTrue(stage["change"]["proven"])
        self.assertEqual((out / stage["change"]["path"]).read_bytes(), m.patch)
        self.assertEqual(stage["checks"], ["check 1: exit 0"])
        (approval,) = man["approvals"]
        self.assertEqual((approval["login"], approval["account_id"], approval["approved"]), (HITL, HITL_ID, m.base))
        self.assertEqual([(x["kind"], x["pr"], x["commit"]) for x in man["merges"]], [("merge", 7, m.head)])
        for name, digest in man["files"].items():
            with self.subTest(name):
                self.assertEqual(sha((out / name).read_bytes()), digest)
        self.assertIn("evidence/runs/gh-12-1-router/seal.json", man["files"])
        self.assertIn("PR #7", (out / "README.md").read_text())
        self.assertFalse(any("No check result" in x for x in man["limits"]))

    def test_vector_278_the_bundle_alone_rebuilds_every_change(self):
        m = Mission(self)
        out, man = m.summon()
        offline = m.root / "offline"
        subprocess.run(["git", "clone", "-q", str(out / "repo.bundle"), str(offline)], check=True, capture_output=True)
        (stage,) = man["stages"]
        again = subprocess.run(["git", "-C", str(offline), *summon.DIFF, stage["base"], stage["head"], "--"],
                               capture_output=True, check=True).stdout
        self.assertEqual(sha(again), stage["change"]["sealed_sha256"])
        self.assertIn(m.merge, man["bundle"]["commits"], "the merged PR's merge commit")
        self.assertNotIn("f" * 40, man["bundle"]["commits"] + man["bundle"]["missing"],
                         "an unmerged PR's merge_commit_sha is GitHub's test merge: not asked for")

    def test_vector_285_a_plain_clone_of_the_bundle_takes_every_commit(self):
        """A clone fetches branches and tags only; git 2.56 then keeps none of a bundle's other objects. Each commit
        must be reachable from a branch of the clone, which holds on every git version (Amendment 063)."""
        m = Mission(self)
        out, man = m.summon()
        heads = subprocess.run(["git", "bundle", "list-heads", str(out / "repo.bundle")], capture_output=True,
                               text=True, check=True).stdout.split()[1::2]
        self.assertTrue(heads and all(h.startswith(summon.BUNDLE_REFS) for h in heads), heads)
        offline = m.root / "plain-clone"
        subprocess.run(["git", "clone", "-q", "--no-checkout", str(out / "repo.bundle"), str(offline)], check=True,
                       capture_output=True)
        for commit in man["bundle"]["commits"]:
            with self.subTest(commit=commit):
                found = subprocess.run(["git", "-C", str(offline), "branch", "-r", "--contains", commit],
                                       capture_output=True, text=True).stdout.strip()
                self.assertTrue(found, f"{commit} is on no branch of a plain clone")
        self.assertEqual(m.run("for-each-ref", "--format=%(refname)", summon.BUNDLE_REFS), "",
                         "the temporary branches are removed")

    def test_vector_285_a_branch_of_the_bundles_name_is_never_overwritten(self):
        m = Mission(self)
        m.run("branch", "epap-pack/0", m.base)
        with self.assertRaisesRegex(summon.EvidenceError, "already has branches under refs/heads/epap-pack/"):
            m.summon()
        self.assertEqual(m.run("rev-parse", "epap-pack/0"), m.base, "the clone's own branch is untouched")

    def test_vector_279_a_head_that_is_not_the_published_commit_is_not_bound(self):
        m = Mission(self)
        m.run("checkout", "-q", f"mission/{MID}/a2-r1")  # a commit pushed onto the PR after it was published
        (m.git / "a.txt").write_text("one\ntwo\nthree\n")
        m.run("commit", "-q", "-am", "pushed after publish")
        m.run("update-ref", "refs/remotes/pull/7", m.run("rev-parse", "HEAD"))
        m.run("checkout", "-q", "main")
        _, man = m.summon()
        (stage,) = man["stages"]
        self.assertFalse(stage["head_bound"])
        self.assertFalse(stage["change"]["proven"])
        self.assertIn("the PR's head is not the commit the sealed dispatch.publish record names", stage["problems"])
        self.assertIn("the change regenerated from git does not match the sealed digest", stage["problems"])

    def test_vector_279_an_edited_chain_is_reported_and_the_pack_still_written(self):
        m = Mission(self)
        path = m.store / "runs" / "gh-12-1-router" / "records.jsonl"
        path.write_bytes(path.read_bytes().replace(b"comment 9", b"comment 8"))
        out, man = m.summon()
        state = {c["name"]: c["state"] for c in man["chains"]}["gh-12-1-router"]
        self.assertTrue(state.startswith("refused: "), state)
        self.assertTrue((out / "manifest.json").is_file())

    def test_vector_279_a_pr_outside_the_mission_flow_says_so(self):
        m = Mission(self)
        _, man = m.summon(pr=8)
        self.assertIsNone(man["mission"])
        self.assertEqual((man["chains"], man["stages"]), ([], []))
        self.assertTrue(man["limits"][0].startswith("PR #8 is not a mission stage PR (docs/by-hand)"))

    def test_vector_279_no_check_results_is_a_stated_limit(self):
        m = Mission(self, checks=False)
        _, man = m.summon()
        self.assertTrue(any(x.startswith("No check result of this mission is in the evidence") for x in man["limits"]))

    def test_vector_279_refusals(self):
        m = Mission(self)
        out = m.root / "exists"
        out.mkdir()
        with self.assertRaisesRegex(summon.EvidenceError, "exists"):
            m.summon(out=out)
        with self.assertRaisesRegex(summon.EvidenceError, "PR #404 is not in"):
            m.summon(pr=404)

    def test_vector_280_the_cli_records_who_summoned_which_pack(self):
        import io
        from contextlib import redirect_stdout
        from unittest import mock
        from evidence import __main__ as cli
        m = Mission(self)
        keys = m.root / "key.json"
        keys.write_text(json.dumps(m.keys_doc))
        chain_dir = m.root / "ev"
        env = {"GITHUB_TOKEN": "ghs_placeholder", "GITHUB_ACTOR": HITL, "GITHUB_ACTOR_ID": str(HITL_ID),
               "RUN_URL": "https://example.invalid/run/1", "EVIDENCE_DIR": str(chain_dir),
               "EVIDENCE_RUN": "gh-50-1-summon"}

        class GH:
            def __init__(self, token, repo):
                pass

            def request(self, method, path, body=None):
                return m.prs[int(path.rsplit("/", 1)[1])]
        out = m.root / "pack-cli"
        with mock.patch.dict("os.environ", env), mock.patch("mission_router.github.GitHub", GH), \
                redirect_stdout(io.StringIO()) as printed:
            self.assertEqual(cli.main(["summon", "--pr", "7", "--repo", REPO, "--store", str(m.store), "--git",
                                       str(m.git), "--out", str(out), "--keys", str(keys)]), 0)
        self.assertIn("1 published stages, 1 bound and proven", printed.getvalue())
        (rec,) = [json.loads(l) for l in (chain_dir / "runs" / "gh-50-1-summon" / "records.jsonl").read_text().splitlines()]
        self.assertEqual((rec["action"], rec["class"], rec["actor"]["name"], rec["actor"]["account_id"]),
                         ("evidence.summon", "read", HITL, HITL_ID))
        self.assertEqual(rec["outputs"]["manifest"], sha((out / "manifest.json").read_bytes()))


class WorkflowTests(unittest.TestCase):
    def test_vector_280_the_workflow(self):
        live = ROOT / ".github" / "workflows" / "evidence-pack.yml"
        text = (live if live.is_file() else ROOT / "packaging" / "workflows" / "evidence-pack.yml").read_text()
        on = text[text.index("\non:\n"):text.index("\npermissions:")]
        self.assertIn("workflow_dispatch:", on)
        self.assertNotIn("schedule", on)
        self.assertNotIn("pull_request", on)
        self.assertIn("environment: evidence-verify", text)
        self.assertIn("permission-contents: read", text)
        self.assertNotIn("write", text.split("steps:")[0].split("permissions:", 2)[2], "read only")
        self.assertIn("python3 -B -m mission_router.substrate", text)
        self.assertIn("case \"$PR\" in ''|*[!0-9]*)", text, "the PR must be a number")
        for line in text.splitlines():
            if "${{ inputs." in line:
                with self.subTest(line=line.strip()):
                    self.assertRegex(line.strip(), r"^PR: \$\{\{ inputs\.pr \}\}$", "the input only through the env")
        self.assertIn("name: epap-pack-pr-${{ steps.pr.outputs.number }}", text)
        self.assertIn("EVIDENCE_RUN=gh-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT-summon", text)
        from evidence import record, sweep
        self.assertEqual(sweep.WORKFLOWS.get("Evidence Pack"), "evidence-pack.yml")
        self.assertRegex("evidence-summon", sweep.CHAIN_ARTIFACT)
        self.assertIsNone(sweep.CHAIN_ARTIFACT.fullmatch("epap-pack-pr-7"), "the pack itself is not a chain")
        self.assertEqual(record.ACTIONS["evidence.summon"], "read")


if __name__ == "__main__":
    unittest.main()
