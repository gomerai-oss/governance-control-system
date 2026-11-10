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
from evidence import chain, checker, pack, producer, record, seal, sealer, store, worm

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

    def __init__(self, test, bucket=None):
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
        self.result = sealer.seal_runs(self.chains, self.seed, self.keys, store.Store(self.store.request),
                                       "2026-11-10T12:00:00Z", bucket, REPO)

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
        from evidence import EvidenceError
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
        with self.assertRaisesRegex(EvidenceError, "too large"):
            sealer.seal_runs(Path(tmp.name), seed, keys, store.Store(listing.request), "2026-11-10T12:00:00Z",
                             None, REPO)

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


if __name__ == "__main__":
    unittest.main()
