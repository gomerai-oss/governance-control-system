"""Ring 6, the landing provenance (MISSION-DISPATCH-001 §3m item 2): for each landing, the seal job writes an in-toto
Statement v1 with a SLSA Provenance v1 predicate, listing every sealed record of the mission, in a DSSE envelope
signed with the evidence key as the pipeline's attestor. The checker verifies every attestation. A whole mission is
driven through the router's own code against its fake GitHub. Placeholder repositories and accounts only."""

from __future__ import annotations

import base64
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from epap import ed25519
from evidence import chain, checker, pack, producer, record, seal, sealer, store, verify, worm

from tests import test_mission_router as rt
from tests.test_evidence_seal import FakeStore
from tests.test_evidence_worm import CONFIG, ENV, FakeCloud

REPO = "example-org/example-repo"


class ListingStore(FakeStore):
    """The store's contents API, with the git trees and blobs API the attestation lists it through."""

    truncated = False

    def request(self, method, path, body=None):
        if method == "GET" and path.startswith("/git/trees/"):
            return {"truncated": self.truncated,
                    "tree": [{"type": "blob", "path": n, "sha": f"sha-{n}"} for n in sorted(self.files)]}
        if method == "GET" and path.startswith("/git/blobs/sha-"):
            return {"content": base64.b64encode(self.files[path[len("/git/blobs/sha-"):]]).decode()}
        return super().request(method, path, body)


class Mission:
    """One mission, M-DEMO-001: its router sweeps and its dispatcher runs, sealed into a store."""

    def __init__(self, test, bucket=None, merged=None):
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.chains = self.root / "chains"
        loop = rt.RouterLoopTests("test_full_mission_fail_then_pass")
        loop.setUp()
        loop.router.evidence = producer.Recorder(self.chains / "router", "gh-9-1-router")
        loop.start_mission()
        for r in (1, 2):
            self.dispatch("A2", r, loop)
            loop.a2_round(r)
            self.dispatch("A3", r, loop)
            loop.a3_round(r, "FAIL" if r == 1 else "PASS")
        self.seed = ed25519.generate_seed()
        pub = ed25519.public_key(self.seed)
        self.keys = {seal.keyid(pub): pub.hex()}
        self.store = ListingStore()
        self.bucket = bucket
        self.asked = []
        self.result = sealer.seal_runs(self.chains, self.seed, self.keys, store.Store(self.store.request),
                                       "2026-11-10T12:00:00Z", bucket, REPO,
                                       merged=merged or (lambda pr, commit: self.asked.append((pr, commit)) or True))

    def dispatch(self, role, r, loop):
        run = f"gh-9-{r}-publish-{rt.MID}-{role}-r{r}"
        rec = producer.Recorder(self.chains / run, run)
        login = rt.A2B if role == "A2" else rt.A3B
        rec.record(actor=login, account_id=None, action="dispatch.publish", result="done", mission=rt.MID, round_n=r,
                   pr=None, authority_kind="plan", authority_ref=f"{rt.MID} {role} round {r}")

    def clone(self):
        path = self.root / "clone"
        self.store.copy_to(path)
        for args in (["init", "-q"], ["add", "-A"],
                     ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "stored"]):
            subprocess.run(["git", *args], cwd=path, check=True, capture_output=True)
        return path

    def statement(self, name=None):
        env = json.loads(self.store.files[name or self.result["packs"][0]])
        return json.loads(base64.b64decode(env["payload"]))


class AttestationTests(unittest.TestCase):
    def test_one_landing_one_attestation_that_verifies(self):
        m = Mission(self)
        self.assertEqual(len(m.result["packs"]), 1)
        name = m.result["packs"][0]
        self.assertTrue(name.startswith("packs/gh-9-1-router-") and name.endswith(".provenance.json"))
        self.assertEqual(pack.store_problems(m.clone(), m.keys), [])

    def test_the_statement_is_in_toto_with_slsa_provenance(self):
        m = Mission(self)
        st = m.statement()
        self.assertEqual((st["_type"], st["predicateType"]), (pack.STATEMENT_TYPE, pack.PREDICATE_TYPE))
        bd = st["predicate"]["buildDefinition"]
        self.assertEqual(bd["externalParameters"]["mission"], rt.MID)
        self.assertEqual(st["predicate"]["runDetails"]["builder"]["id"],
                         f"https://github.com/{REPO}/.github/workflows/evidence-seal.yml", "the signer is the pipeline")
        records = bd["internalParameters"]["records"]
        landing = next(r for r in records if r["record"] == bd["internalParameters"]["landing"])
        self.assertEqual(landing["action"], "router.landing")
        self.assertEqual(st["subject"][0]["digest"]["gitCommit"], landing["commit"])
        approvals = [r for r in records if r["record"] in bd["externalParameters"]["approvals"]]
        self.assertEqual({(a["actor"]["name"], a["actor"]["account_id"]) for a in approvals},
                         {(rt.HITL, rt.ACCOUNTS[rt.HITL])}, "the plan's approval, by HITL's account id")
        roles = {(r["role"], r["round"]) for r in records if r["action"] == "dispatch.publish"}
        self.assertEqual(roles, {("A2", 1), ("A3", 1), ("A2", 2), ("A3", 2)})
        self.assertTrue(bd["resolvedDependencies"], "the stage merges it was built from")

    def test_a_changed_attestation_is_refused(self):
        m = Mission(self)
        name = m.result["packs"][0]
        env = json.loads(m.store.files[name])
        st = json.loads(base64.b64decode(env["payload"]))
        st["predicate"]["buildDefinition"]["externalParameters"]["mission"] = "M-OTHER-001"
        env["payload"] = base64.b64encode(json.dumps(st).encode()).decode()
        m.store.files[name] = json.dumps(env).encode()
        self.assertTrue(any("does not verify" in p for p in pack.store_problems(m.clone(), m.keys)))

    def test_an_unpinned_key_is_refused(self):
        m = Mission(self)
        self.assertTrue(any("not a pinned evidence key" in p for p in pack.store_problems(m.clone(), {})))

    def test_a_cited_record_missing_from_the_store_is_refused(self):
        m = Mission(self)
        for name in [n for n in m.store.files if "-A2-r1/" in n]:
            del m.store.files[name]
        self.assertTrue(any("is not in the store as recorded" in p for p in pack.store_problems(m.clone(), m.keys)))

    def test_a_subject_that_is_not_the_landing_commit_is_refused(self):
        m = Mission(self)
        name = m.result["packs"][0]
        st = m.statement()
        st["subject"][0]["digest"]["gitCommit"] = "f" * 40
        m.store.files[name] = pack.sign(st, m.seed)
        self.assertTrue(any("its subject is not the landing's commit" in p
                            for p in pack.store_problems(m.clone(), m.keys)))

    def test_a_truncated_store_listing_is_refused_never_partial(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        listing = ListingStore()
        listing.truncated = True
        rec = producer.Recorder(Path(tmp.name) / "r", "gh-1-1-router")
        rec.record(actor="example-router[bot]", account_id=None, action="router.decision", result="done",
                   reason="merge: ok", mission="M-DEMO-001", pr=7, commit="a" * 40, authority_kind="spec_rule",
                   authority_ref="MISSION-ROUTER-001")
        rec.record(actor="example-router[bot]", account_id=None, action="router.landing", result="done",
                   mission="M-DEMO-001", pr=7, commit="a" * 40, authority_kind="spec_rule",
                   authority_ref="MISSION-ROUTER-001")
        seed = ed25519.generate_seed()
        keys = {seal.keyid(ed25519.public_key(seed)): ed25519.public_key(seed).hex()}
        result = sealer.seal_runs(Path(tmp.name), seed, keys, store.Store(listing.request), "2026-11-10T12:00:00Z",
                                  None, REPO, merged=lambda pr, commit: True)
        self.assertEqual(result["packs"], [], "never a partial attestation")
        self.assertEqual([r["run"] for r in result["refused"]], ["gh-1-1-router"])
        self.assertIn("too large", result["refused"][0]["reason"])

    def test_the_pae_is_dsse(self):
        self.assertEqual(pack.pae("t", b"ab"), b"DSSEv1 1 t 2 ab")


class WiringTests(unittest.TestCase):
    def test_the_checker_verifies_attestations_and_history_covers_them(self):
        m = Mission(self)
        clone = m.clone()
        self.assertTrue(checker.check(clone, m.keys, None)["ok"])
        path = clone / m.result["packs"][0]
        path.write_bytes(path.read_bytes().replace(b'"payloadType"', b'"payloadType" '))
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-am", "x"],
                       cwd=clone, check=True, capture_output=True)
        failures = checker.check(clone, m.keys, None)["failures"]
        self.assertTrue(any(f.startswith("packs/") and "was changed after it was stored" in f for f in failures))

    def test_the_attestation_is_copied_to_the_worm_bucket(self):
        cloud = FakeCloud()
        m = Mission(self, worm.from_config({"evidence_worm": CONFIG}, ENV, cloud))
        self.assertIn(m.result["packs"][0], cloud.objects)
        self.assertEqual(worm.check_copies(m.clone(), m.bucket, 6), [])

    def test_no_repository_no_attestation(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        chains = Path(tmp.name)
        rec = producer.Recorder(chains / "r", "gh-1-1-router")
        rec.record(actor="example-router[bot]", account_id=None, action="router.decision", result="done",
                   reason="merge: ok", mission="M-DEMO-001", pr=7, commit="a" * 40,
                   authority_kind="spec_rule", authority_ref="MISSION-ROUTER-001")
        rec.record(actor="example-router[bot]", account_id=None, action="router.landing", result="done",
                   mission="M-DEMO-001", pr=7, commit="a" * 40, authority_kind="spec_rule",
                   authority_ref="MISSION-ROUTER-001")
        seed = ed25519.generate_seed()
        keys = {seal.keyid(ed25519.public_key(seed)): ed25519.public_key(seed).hex()}
        result = sealer.seal_runs(chains, seed, keys, store.Store(ListingStore().request), "2026-11-10T12:00:00Z")
        self.assertEqual(result["packs"], [])


BOT = "example-router[bot]"
C1, C2 = "a" * 40, "b" * 40


def router_chain(chains, run, attempts, mission="M-DEMO-001", pr=7):
    """A router sweep's chain: for each ``(commit, refused)`` in ``attempts``, the decision and the landing record the
    router writes before the merge, and when GitHub refused the merge, the failed record it writes after
    (MISSION-ROUTER-001 Amendment 018)."""
    rec = producer.Recorder(Path(chains) / run, run)
    for commit, refused in attempts:
        base = dict(actor=BOT, account_id=None, mission=mission, pr=pr, commit=commit, authority_kind="spec_rule",
                    authority_ref="MISSION-ROUTER-001")
        rec.record(action="router.decision", result="done", reason="merge: ok", **base)
        rec.record(action="router.landing", result="done", reason=f"merge PR #{pr} at {commit}", **base)
        if refused:
            rec.record(action="router.landing", result="failed", reason=f"merge PR #{pr} at {commit}: GitHub refused "
                       "it (405): Required status check \"route-handoff-block\" is in progress.", **base)
    return rec


def key():
    seed = ed25519.generate_seed()
    return seed, {seal.keyid(ed25519.public_key(seed)): ed25519.public_key(seed).hex()}


class Bucket:
    """A WORM bucket that refuses the first ``refuse`` copies of an attestation."""

    def __init__(self, refuse=0):
        self.objects, self.refuse = {}, refuse

    def put(self, name, data):
        if name.startswith("packs/") and self.refuse:
            self.refuse -= 1
            raise worm.EvidenceError(f"the WORM bucket refused {name}: 503")
        if name in self.objects:
            return "present"
        self.objects[name] = data
        return "added"


class LandedOnlyTests(unittest.TestCase):
    """Amendment 055 (audit M-AUDIT-EVIDENCE-001 F3): a landing is attested only when it was one."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.chains = Path(tmp.name)
        self.seed, self.keys = key()
        self.listing = ListingStore()

    def seal(self, merged=lambda pr, commit: True, bucket=None, resume=False, time="2026-11-10T12:00:00Z"):
        return sealer.seal_runs(self.chains, self.seed, self.keys, store.Store(self.listing.request), time, bucket,
                                REPO, resume=resume, merged=merged)

    def test_vector_262_a_landing_github_refused_is_not_attested(self):
        router_chain(self.chains, "gh-1-1-router", [(C1, True)])
        asked = []
        result = self.seal(lambda pr, commit: asked.append(pr) or True)
        self.assertEqual(result["packs"], [], "GitHub refused it: never a landing, whatever GitHub says later")
        self.assertEqual(asked, [], "a refused attempt is not even asked about")
        self.assertEqual(result["sealed"], ["gh-1-1-router"], "its run is still sealed")
        self.assertEqual(result["not_landed"], [{"landing": "gh-1-1-router/1", "reason": "GitHub refused the merge"}])
        self.assertFalse([n for n in self.listing.files if n.startswith("packs/")])

    def test_vector_262_the_retry_that_landed_is_attested_once(self):
        router_chain(self.chains, "gh-1-1-router", [(C1, True)])  # Core #300, governance #1389 and #1390, #1399
        router_chain(self.chains, "gh-2-1-router", [(C1, False)])
        result = self.seal()
        self.assertEqual(result["packs"], ["packs/gh-2-1-router-1.provenance.json"])
        self.assertEqual(pack.store_problems(self.clone(), self.keys), [])

    def test_vector_262_a_landing_github_does_not_show_merged_is_not_attested(self):
        router_chain(self.chains, "gh-1-1-router", [(C1, False)])  # the router stopped before GitHub answered
        result = self.seal(lambda pr, commit: False)
        self.assertEqual(result["packs"], [])
        self.assertEqual(result["sealed"], ["gh-1-1-router"])
        self.assertIn("does not show PR #7 merged at aaaaaaaaaaaa", result["not_landed"][0]["reason"])

    def test_vector_263_github_unreadable_holds_the_run_and_the_next_sweep_attests(self):
        router_chain(self.chains, "gh-1-1-router", [(C1, False)])

        def unreadable(pr, commit):
            raise worm.EvidenceError("GitHub would not show PR #7 to confirm its landing (502)")
        first = self.seal(unreadable)
        self.assertEqual((first["sealed"], first["packs"]), ([], []))
        self.assertIn("(502)", first["refused"][0]["reason"])
        self.assertNotIn("runs/gh-1-1-router/seal.json", self.listing.files, "unsealed, so the sweep names it again")
        again = self.seal(resume=True, time="2026-11-10T12:10:00Z")
        self.assertEqual((again["sealed"], again["packs"]),
                         (["gh-1-1-router"], ["packs/gh-1-1-router-1.provenance.json"]))

    def test_vector_263_an_attestation_the_bucket_refused_is_made_on_the_next_sweep(self):
        router_chain(self.chains, "gh-1-1-router", [(C1, False)])
        bucket = Bucket(refuse=1)
        first = self.seal(bucket=bucket)
        self.assertEqual(first["sealed"], [])
        name = "packs/gh-1-1-router-1.provenance.json"
        stored = self.listing.files[name]
        self.assertNotIn("runs/gh-1-1-router/seal.json", self.listing.files)
        again = self.seal(bucket=bucket, resume=True, time="2026-11-10T12:10:00Z")
        self.assertEqual((again["sealed"], again["packs"]), (["gh-1-1-router"], [name]))
        self.assertEqual(self.listing.files[name], stored, "kept as stored, never replaced")
        self.assertEqual(bucket.objects[name], stored, "and the bucket's copy is the same bytes")

    def test_vector_263_a_repository_without_github_seals_nothing(self):
        router_chain(self.chains, "gh-1-1-router", [(C1, False)])
        with self.assertRaises(worm.EvidenceError):
            sealer.seal_runs(self.chains, self.seed, self.keys, store.Store(self.listing.request),
                             "2026-11-10T12:00:00Z", None, REPO)
        self.assertEqual(self.listing.files, {})

    def test_vector_263_github_merged_reads_the_pr(self):
        from mission_router.github import GitHubError
        answers = {1: {"merged": True, "head": {"sha": C1}}, 2: {"merged": True, "head": {"sha": C2}},
                   3: {"merged": False, "head": {"sha": C1}}}

        def request(method, path, body=None):
            n = int(path.rsplit("/", 1)[1])
            if n == 4:
                raise GitHubError(404, "Not Found", path)
            if n == 5:
                raise GitHubError(502, "Bad Gateway", path)
            return answers[n]
        merged = sealer.github_merged(request)
        self.assertEqual([merged(n, C1) for n in (1, 2, 3, 4)], [True, False, False, False])
        with self.assertRaises(worm.EvidenceError):
            merged(5, C1)

    def test_vector_263_the_seal_job_gives_the_seal_step_a_read_token(self):
        text = (Path(__file__).resolve().parents[3] / ".github" / "workflows" / "evidence-seal.yml")
        text = text.read_text() if text.is_file() else (Path(__file__).resolve().parents[3] / "packaging"
                                                         / "workflows" / "evidence-seal.yml").read_text()
        step = text[text.index("- name: Seal each chain and add it to the store"):]
        step = step[:step.index("\n      - name:", 1)] if "\n      - name:" in step[1:] else step
        self.assertIn("GITHUB_TOKEN: ${{ github.token }}", step)
        job = text[text.index("\n  seal:\n"):text.index("\n  mark:\n")]
        self.assertIn("pull-requests: read", job)
        self.assertNotIn("pull-requests: write", job)

    def clone(self):
        path = self.chains.parent / (self.chains.name + "-clone")
        self.listing.copy_to(path)
        return path


HITL, HITL_ID = "example-hitl", 1001
HITL_CONFIG = {"hitl_logins": [HITL], "hitl_account_ids": [HITL_ID], "bot_login": BOT}
DISPATCH = {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_ACTOR": HITL, "GITHUB_TRIGGERING_ACTOR": HITL,
            "GITHUB_ACTOR_ID": str(HITL_ID), "GITHUB_RUN_ID": "77"}


class StoreWithAttestations(unittest.TestCase):
    """A store holding a refused landing and the retry that landed, each attested as the seal job did before
    Amendment 055."""

    def setUp(self):
        from evidence import withdraw
        self.withdraw = withdraw
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.seed, self.keys = key()
        self.listing = ListingStore()
        router_chain(self.root / "c1", "gh-1-1-router", [(C1, True)])  # a refused landing...
        router_chain(self.root / "c1", "gh-2-1-router", [(C1, False)])  # ...and the retry that landed
        sealer.seal_runs(self.root / "c1", self.seed, self.keys, store.Store(self.listing.request),
                         "2026-11-10T12:00:00Z")
        for landing_id in ("gh-1-1-router/1", "gh-2-1-router/1"):  # attested as the old seal job did, both
            chain_name = landing_id.rsplit("/", 1)[0]
            records = [json.loads(line) for line in self.listing.files[f"runs/{chain_name}/records.jsonl"].splitlines()]
            landing = next(r for r in records if r["id"] == landing_id)
            self.listing.files[pack.name_for(landing)] = pack.sign(pack.statement(landing, records, REPO), self.seed)
        self.clone = self.copy()

    def copy(self):
        """A clone of the store: its files, as one commit (the checker reads the store's history)."""
        path = self.root / f"clone-{len(list(self.root.glob('clone-*')))}"
        self.listing.copy_to(path)
        for args in (["init", "-q"], ["add", "-A"],
                     ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "stored"]):
            subprocess.run(["git", *args], cwd=path, check=True, capture_output=True)
        return path

    def recorder(self):
        return producer.Recorder(self.root / "w", "gh-77-1-withdraw")

    def written(self):
        path = self.root / "w" / "runs" / "gh-77-1-withdraw" / "records.jsonl"
        return len(chain.read(path)) if path.is_file() else 0

    def go(self, names=("refused-landings",), env=None, confirm=True, recorder=None, clone=None, reason="false landing",
           pending=lambda: []):
        return self.withdraw.run(clone or self.clone, list(names), reason, env or DISPATCH, HITL_CONFIG,
                                 recorder or self.recorder(), confirm, pending)


class WithdrawalTests(StoreWithAttestations):
    """Amendment 055 (audit M-AUDIT-EVIDENCE-001 F5): HITL withdraws a stored record (§3m item 4)."""

    def test_vector_264_refused_landings_names_only_the_false_attestation(self):
        result = self.go(confirm=False)
        self.assertEqual([w["id"] for w in result["withdrawn"]], ["gh-1-1-router/1"])
        self.assertFalse(result["written"])
        self.assertEqual(self.written(), 0, "without confirm nothing is written")

    def test_vector_264_the_withdrawal_is_sealed_and_the_verifier_marks_the_record(self):
        result = self.go()
        self.assertTrue(result["written"])
        target = result["withdrawn"][0]
        records = chain.read(self.root / "w" / "runs" / "gh-77-1-withdraw" / "records.jsonl")
        self.assertEqual(len(records), 1)
        w = records[0]
        self.assertEqual((w["action"], w["class"], w["withdraws"]), ("evidence.withdraw", "withdraw", target))
        self.assertEqual((w["actor"]["name"], w["actor"]["account_id"]), (HITL, HITL_ID))
        self.assertEqual(w["authority"]["kind"], "hitl_command")
        self.assertIn("workflow_dispatch run 77 of evidence-verify.yml by example-hitl", w["authority"]["ref"])
        self.assertEqual((w["subject"]["pr"], w["subject"]["commit"]), (7, C1))
        sealer.seal_runs(self.root / "w", self.seed, self.keys, store.Store(self.listing.request),
                         "2026-11-10T13:00:00Z")
        report = verify.verify_store(self.copy(), self.keys, require_seal=True)
        self.assertIsNone(report.failure)
        self.assertEqual(report.withdrawn, {"gh-1-1-router/1": "gh-77-1-withdraw/0"})
        self.assertIn("packs/gh-1-1-router-1.provenance.json", self.listing.files, "nothing is deleted")
        again = self.go(clone=self.copy(), recorder=producer.Recorder(self.root / "w2", "gh-78-1-withdraw"))
        self.assertEqual((again["withdrawn"], again["skipped"], again["written"]), ([], ["gh-1-1-router/1"], False))

    def test_vector_264_the_digest_comes_from_the_store(self):
        result = self.go(names=["gh-2-1-router/0"], confirm=False)
        records = chain.read(self.clone / "runs" / "gh-2-1-router" / "records.jsonl")
        self.assertEqual(result["withdrawn"], [{"id": "gh-2-1-router/0", "digest": record.digest(records[0])}])

    def test_vector_265_only_hitl_by_hand(self):
        cases = {"a push": dict(DISPATCH, GITHUB_EVENT_NAME="push"),
                 "not a HITL login": dict(DISPATCH, GITHUB_ACTOR="someone", GITHUB_TRIGGERING_ACTOR="someone"),
                 "another account of that name": dict(DISPATCH, GITHUB_ACTOR_ID="1002"),
                 "a re-run by another": dict(DISPATCH, GITHUB_TRIGGERING_ACTOR="someone"),
                 "no account id": {k: v for k, v in DISPATCH.items() if k != "GITHUB_ACTOR_ID"}}
        for name, env in cases.items():
            with self.subTest(name), self.assertRaises(worm.EvidenceError):
                self.go(env=env)
        self.assertEqual(self.written(), 0, "nothing was written")
        with self.assertRaises(worm.EvidenceError):
            self.withdraw.run(self.clone, ["refused-landings"], "r", DISPATCH, {"hitl_logins": [HITL]},
                              self.recorder(), True)

    def test_vector_265_one_unknown_record_or_a_withdrawal_writes_nothing(self):
        with self.assertRaisesRegex(worm.EvidenceError, "not in the store: gh-9-9-router/0"):
            self.go(names=["gh-1-1-router/1", "gh-9-9-router/0"])
        self.assertEqual(self.written(), 0)
        self.go()
        sealer.seal_runs(self.root / "w", self.seed, self.keys, store.Store(self.listing.request),
                         "2026-11-10T13:00:00Z")
        with self.assertRaisesRegex(worm.EvidenceError, "is itself a withdrawal"):
            self.go(names=["gh-77-1-withdraw/0"], clone=self.copy(),
                    recorder=producer.Recorder(self.root / "w2", "gh-78-1-withdraw"))

    def test_vector_265_a_reason_and_a_chain_are_required(self):
        with self.assertRaises(worm.EvidenceError):
            self.go(reason="   ")
        with self.assertRaises(worm.EvidenceError):
            self.go(recorder=producer.Recorder(None, ""))

    def test_vector_265_the_cli_refuses_outside_hitl_dispatch(self):
        from unittest import mock
        import io
        from contextlib import redirect_stderr
        from evidence import __main__ as cli
        env = {k: v for k, v in DISPATCH.items()}
        env["GITHUB_EVENT_NAME"] = "schedule"
        err = io.StringIO()
        with mock.patch.dict("os.environ", env), redirect_stderr(err):
            code = cli.main(["withdraw", "--store", str(self.clone), "--records", "refused-landings",
                             "--reason", "x", "--confirm"])
        self.assertEqual(code, 1)
        self.assertIn("started by hand only", err.getvalue())

    def test_vector_266_the_workflow_job(self):
        root = Path(__file__).resolve().parents[3]
        live = root / ".github" / "workflows" / "evidence-verify.yml"
        text = (live if live.is_file() else root / "packaging" / "workflows" / "evidence-verify.yml").read_text()
        on = text[text.index("\non:\n"):text.index("\npermissions:")]
        for name in ("withdraw:", "reason:", "confirm:"):
            self.assertIn(name, on)
        job = text[text.index("\n  withdraw:\n"):text.index("\n  report:\n")]
        self.assertIn("if: github.event_name == 'workflow_dispatch' && (inputs.withdraw != '' || inputs.reason != '' "
                      "|| inputs.confirm)", job, "a reason or confirm with no record named is said, not skipped")
        self.assertIn("actions: read", job)
        self.assertIn("GITHUB_TOKEN: ${{ github.token }}", job)
        self.assertIn('python3 -B -m evidence withdraw "${args[@]}" 2>&1 | tee -a "$GITHUB_STEP_SUMMARY"', job)
        self.assertIn("environment: evidence-verify", job)
        self.assertIn("permission-contents: read", job)
        self.assertNotIn("write", job.split("steps:")[0], "read only")
        self.assertIn("python3 -B -m mission_router.substrate", job)
        self.assertIn('EVIDENCE_RUN=gh-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT-withdraw', job)
        self.assertIn("name: evidence-withdraw", job)
        for line in job.splitlines():
            if "${{ inputs." in line:
                with self.subTest(line):
                    self.assertRegex(line.strip(), r"^(if: |[A-Z]+: \$\{\{ inputs\.)",
                                     "inputs reach the job only in its condition and through the environment")
        from evidence import sweep
        self.assertIn("evidence-verify.yml", sweep.WORKFLOWS.values(), "Evidence Seal seals the job's chain")


class GuardTests(StoreWithAttestations):
    """Amendment 056: a confirmed withdrawal waits for an earlier one to be stored."""

    def artifacts(self, *entries):
        def request(method, path, body=None):
            assert (method, path) == ("GET", "/actions/artifacts?name=evidence-withdraw&per_page=100"), path
            return {"artifacts": [{**{"name": "evidence-withdraw", "expired": False, "created_at": "2026-11-27T01:00:00Z",
                                      "workflow_run": {"id": run}}, **extra} for run, extra in entries]}
        return request

    def test_vector_270_an_earlier_withdrawal_not_yet_stored_holds_a_confirmed_one(self):
        import datetime
        now = datetime.datetime(2026, 11, 27, 1, 10, tzinfo=datetime.timezone.utc)
        self.go()  # run 77's withdrawal, sealed into the store
        sealer.seal_runs(self.root / "w", self.seed, self.keys, store.Store(self.listing.request),
                         "2026-11-27T01:05:00Z")
        clone = self.copy()
        request = self.artifacts((77, {}), (78, {}), (79, {"expired": True}),
                                 (80, {"created_at": "2026-11-20T00:00:00Z"}), (81, {}))
        self.assertEqual(self.withdraw.unstored(request, clone, "81", now), ["78"],
                         "77 is stored; 79 expired; 80 is past the sweep's lookback; 81 is this run")
        with self.assertRaisesRegex(worm.EvidenceError, "run 78 is not in the store yet"):
            self.go(names=["gh-2-1-router/0"], clone=clone, pending=lambda: ["78"],
                    recorder=producer.Recorder(self.root / "w2", "gh-81-1-withdraw"))
        self.assertFalse((self.root / "w2" / "runs" / "gh-81-1-withdraw" / "records.jsonl").exists())
        listed = self.go(names=["gh-2-1-router/0"], clone=clone, confirm=False, pending=lambda: ["78"])
        self.assertEqual(len(listed["withdrawn"]), 1, "a dry run still lists")

    def test_vector_270_a_confirmed_withdrawal_that_cannot_ask_writes_nothing(self):
        with self.assertRaisesRegex(worm.EvidenceError, "cannot check for an earlier withdrawal"):
            self.go(pending=None)
        self.assertEqual(self.written(), 0)

    def test_vector_270_no_record_named_is_said(self):
        with self.assertRaisesRegex(worm.EvidenceError, "name the records to withdraw, or refused-landings"):
            self.go(names=[""])


class CheckerTests(StoreWithAttestations):
    """Amendment 056 (audit M-AUDIT-EVIDENCE-001 F20, F11 and F17): the checker refuses a false attestation that is
    not withdrawn."""

    def test_vector_267_a_stored_attestation_of_a_refused_landing_is_refused_until_withdrawn(self):
        result = checker.check(self.clone, self.keys, None)
        self.assertFalse(result["ok"])
        self.assertEqual([f for f in result["failures"] if f.startswith("packs/")],
                         ["packs/gh-1-1-router-1.provenance.json: attests gh-1-1-router/1, a landing GitHub refused "
                          "(gh-1-1-router/2 records the refusal); withdraw it (section 3m item 4)"])
        self.go()
        sealer.seal_runs(self.root / "w", self.seed, self.keys, store.Store(self.listing.request),
                         "2026-11-10T13:00:00Z")
        clone = self.copy()
        self.assertEqual(pack.store_problems(clone, self.keys), [], "withdrawn: kept, marked, no longer refused")
        result = checker.check(clone, self.keys, None)
        self.assertTrue(result["ok"], result["failures"])
        self.assertEqual(result["withdrawn"], {"gh-1-1-router/1": "gh-77-1-withdraw/0"})

    def test_vector_267_only_a_withdrawal_of_that_record_excuses_it(self):
        self.go(names=["gh-2-1-router/0"])  # another record withdrawn
        sealer.seal_runs(self.root / "w", self.seed, self.keys, store.Store(self.listing.request),
                         "2026-11-10T13:00:00Z")
        self.assertEqual(len(pack.store_problems(self.copy(), self.keys)), 1)

    def git_repo(self):
        repo = self.root / "repo"
        repo.mkdir()
        run = lambda *a: subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *a],  # noqa: E731
                                        cwd=repo, check=True, capture_output=True, text=True).stdout.strip()
        run("init", "-q", "-b", "main")
        run("commit", "-q", "--allow-empty", "-m", "base")
        run("checkout", "-q", "-b", "mission/M-DEMO-001/a3-r1")
        run("commit", "-q", "--allow-empty", "-m", "the A3 PASS")
        head = run("rev-parse", "HEAD")
        run("checkout", "-q", "main")
        return repo, run, head

    def landed_store(self, commit):
        listing = ListingStore()
        chains = self.root / "c2"
        router_chain(chains, "gh-5-1-router", [(commit, False)])
        sealer.seal_runs(chains, self.seed, self.keys, store.Store(listing.request), "2026-11-10T12:00:00Z", None,
                         REPO, merged=lambda pr, c: True)
        path = self.root / "c2-clone"
        listing.copy_to(path)
        for args in (["init", "-q"], ["add", "-A"],
                     ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "stored"]):
            subprocess.run(["git", *args], cwd=path, check=True, capture_output=True)
        return path

    def test_vector_268_an_attestation_of_a_commit_no_landing_branch_holds_is_refused(self):
        repo, run, head = self.git_repo()
        clone = self.landed_store(head)
        self.assertEqual(pack.store_problems(clone, self.keys), [], "without a clone, not checked")
        (problem,) = pack.store_problems(clone, self.keys, repo, ["main"])
        self.assertIn(f"attests {head[:12]}, which no landing branch (main) holds: GitHub never merged it", problem)
        run("merge", "-q", "--no-ff", "-m", "merge", "mission/M-DEMO-001/a3-r1")
        self.assertEqual(pack.store_problems(clone, self.keys, repo, ["main"]), [], "merged: its head is in main")
        (problem,) = pack.store_problems(clone, self.keys, repo, ["release"])
        self.assertIn("cannot check its landing: no landing branch (release) is in the clone", problem)
        self.assertEqual(checker.check(clone, self.keys, repo, landing_branches=["main"])["failures"], [])

    def test_vector_269_evidence_verify_of_a_whole_store_checks_the_attestations(self):
        import io
        from contextlib import redirect_stdout
        from evidence import __main__ as cli
        keys = self.root / "key.json"
        kid, public = next(iter(self.keys.items()))
        keys.write_text(json.dumps({"schema": seal.KEYS_SCHEMA, "keys": [{"keyid": kid, "public": public}]}))
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli.main(["verify", "--store", str(self.clone), "--keys", str(keys)])
        self.assertEqual(code, 1)
        self.assertIn("REFUSED: packs/gh-1-1-router-1.provenance.json: attests gh-1-1-router/1, a landing GitHub "
                      "refused", out.getvalue())
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["verify", "--store", str(self.clone), "--keys", str(keys),
                                       "--run", "gh-2-1-router"]), 0, "one run: its chain only, as before")


if __name__ == "__main__":
    unittest.main()
