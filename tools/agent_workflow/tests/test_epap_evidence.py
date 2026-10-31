from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from epap import ed25519, links, signing, verifier, writer
from epap import layout as L
from epap.registry import RegistryError, load_registry, parse_registry

REPO = Path(__file__).resolve().parents[3]
MID = "M-DEMO-EPAP-001"
APP_IDS = {"a1": "1000001", "a2": "1000002", "a3": "1000003"}
HITL_ID = "hitl:hitl-operator"
ROUTER_ID = "router:github-actions[bot]"
SIGNERS = {L.A1_SPEC: "a1", L.HITL_APPROVAL: HITL_ID, L.A2_BUILD: "a2", L.A3_REVIEW: "a3", L.HITL_MERGE: ROUTER_ID}
AUTHORITY = {"plan_approval": "/mission approve 0123456789abcdef", "approved_by": "hitl-operator", "spec": L.SPEC_ID}

REGISTRY_MD = textwrap.dedent("""\
    # Identity registry (test fixture)

    | Role | App ID | Installation ID | Status | Permissions |
    |---|---|---|---|---|
    | a1 | 1000001 | 2000001 | {a1} | contents write, PRs write |
    | a2 | {a2_app} | 2000002 | {a2} | contents write, PRs write |
    | a3 | 1000003 | 2000003 | ACTIVE | contents write, PRs write, checks write |

    **Status values:** `ACTIVE` · `SUSPENDED` · `RETIRED`.
    """)

PLAN = {f"missions/{MID}/PLAN.md": b"# plan\n", f"missions/{MID}/mission.json": b"{}\n"}
BUILD = {**PLAN, "tools/demo/feature.py": b"print('built')\n"}
REVIEWED = {**BUILD, f"missions/{MID}/reviews/round-1.json": b'{"verdict": "PASS"}\n'}
VECTORS = [links.vector("P1", "VERIFY_PASS", "VERIFY_PASS"), links.vector("P2", "INCOMPLETE", "INCOMPLETE")]

# RFC 8032 section 7.1, TEST 1
RFC_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
RFC_PUBLIC = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
RFC_SIG = ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555"
           "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")


def registry_md(a1="ACTIVE", a2="ACTIVE", a2_app=APP_IDS["a2"]):
    return REGISTRY_MD.format(a1=a1, a2=a2, a2_app=a2_app)


def link_bodies(vectors=VECTORS, verdict=None):
    d = links.digest_bytes
    return {
        L.A1_SPEC: links.make_link(L.A1_SPEC, {}, d(PLAN), ["a1", "open plan PR"]),
        L.HITL_APPROVAL: links.make_link(L.HITL_APPROVAL, d(PLAN), d(PLAN), ["/mission approve"],
                                         {"approved": "0123456789abcdef"}),
        L.A2_BUILD: links.make_link(L.A2_BUILD, d(PLAN), d(BUILD), ["a2", "build round 1"]),
        L.A3_REVIEW: links.make_link(L.A3_REVIEW, d(BUILD), d(REVIEWED), ["a3", "review round 1"],
                                     links.review_byproducts(vectors, verdict)),
        L.HITL_MERGE: links.make_link(L.HITL_MERGE, d(REVIEWED), d(REVIEWED), ["router", "merge PASS into main"]),
    }


class Fixture:
    """Throwaway keys, generated per test run; no real App key is ever used."""

    def __init__(self):
        principals = {
            "a1": L.agent_app("a1", APP_IDS["a1"]),
            "a2": L.agent_app("a2", APP_IDS["a2"]),
            "a3": L.agent_app("a3", APP_IDS["a3"]),
            HITL_ID: L.hitl("hitl-operator"),
            ROUTER_ID: L.router("github-actions[bot]"),
        }
        self.seeds = {kid: ed25519.generate_seed() for kid in principals}
        self.attacker = ed25519.generate_seed()
        self.keys = {kid: L.key_entry(p, ed25519.public_key(self.seeds[kid])) for kid, p in principals.items()}
        self.owner_hex = self.keys[HITL_ID]["public"]


class EvidenceCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = Fixture()

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.registry = self.tmp / "IDENTITY-REGISTRY.md"
        self.registry.write_text(registry_md(), encoding="utf-8")
        self._packs = 0

    def layout_doc(self, functionaries=None, seed=None):
        signed = L.make_layout(MID, self.fx.keys, HITL_ID, functionaries)
        return signing.sign_metablock(signed, HITL_ID, seed or self.fx.seeds[HITL_ID])

    def sign_link(self, body, keyid=None, seed=None):
        keyid = keyid or SIGNERS[body["name"]]
        return signing.sign_metablock(body, keyid, seed or self.fx.seeds[keyid])

    def write(self, bodies=None, docs=None, layout=None):
        bodies = bodies or link_bodies()
        docs = docs or {}
        signed = [docs[n] if n in docs else self.sign_link(bodies[n]) for n in L.STEP_NAMES]
        self._packs += 1
        return writer.write_pack(self.tmp / f"pack{self._packs}", layout or self.layout_doc(), signed, AUTHORITY)

    def verify(self, pack, **kwargs):
        return verifier.verify_pack(pack, self.registry, self.fx.owner_hex, **kwargs)

    def assertPass(self, result):
        self.assertEqual(result.status, verifier.VERIFY_PASS, result.detail)
        self.assertIsNone(result.failed_check)

    def assertFail(self, result, check):
        self.assertEqual(result.status, verifier.VERIFY_FAIL, result.detail)
        self.assertEqual(result.failed_check, check, result.detail)

    def rewrite(self, path, mutate):
        doc = json.loads(path.read_text(encoding="utf-8"))
        mutate(doc)
        path.write_bytes(signing.dump(doc))


class Ed25519Tests(unittest.TestCase):
    def test_rfc8032_test_1(self):
        seed = bytes.fromhex(RFC_SEED)
        self.assertEqual(ed25519.public_key(seed).hex(), RFC_PUBLIC)
        self.assertEqual(ed25519.sign(seed, b"").hex(), RFC_SIG)
        self.assertTrue(ed25519.verify(bytes.fromhex(RFC_PUBLIC), b"", bytes.fromhex(RFC_SIG)))

    def test_roundtrip_and_tampering(self):
        seed = ed25519.generate_seed()
        pub = ed25519.public_key(seed)
        sig = ed25519.sign(seed, b"evidence")
        self.assertTrue(ed25519.verify(pub, b"evidence", sig))
        self.assertFalse(ed25519.verify(pub, b"evidencE", sig))
        self.assertFalse(ed25519.verify(pub, b"evidence", sig[:-1] + bytes([sig[-1] ^ 1])))
        self.assertFalse(ed25519.verify(ed25519.public_key(ed25519.generate_seed()), b"evidence", sig))

    def test_malformed_inputs_never_verify(self):
        self.assertFalse(ed25519.verify(b"short", b"", bytes(64)))
        self.assertFalse(ed25519.verify(bytes.fromhex(RFC_PUBLIC), b"", b"short"))
        self.assertFalse(ed25519.verify(bytes.fromhex(RFC_PUBLIC), b"", bytes(32) + b"\xff" * 32))
        with self.assertRaises(ValueError):
            ed25519.sign(b"short", b"")


class LayoutModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = Fixture()

    def test_five_steps_in_spec_order(self):
        self.assertEqual(L.STEP_NAMES, ("A1_SPEC", "HITL_APPROVAL", "A2_BUILD", "A3_REVIEW", "HITL_MERGE"))
        self.assertEqual([s.role for s in L.STEPS], ["A1", "HITL", "A2", "A3", "HITL"])

    def test_default_functionaries_follow_the_model(self):
        funcs = L.default_functionaries(self.fx.keys)
        self.assertEqual(funcs[L.A1_SPEC], ["a1", HITL_ID])
        self.assertEqual(funcs[L.HITL_APPROVAL], [HITL_ID])
        self.assertEqual(funcs[L.A2_BUILD], ["a2"])
        self.assertEqual(funcs[L.A3_REVIEW], ["a3"])
        self.assertEqual(funcs[L.HITL_MERGE], [HITL_ID, ROUTER_ID])

    def test_layout_conforms_and_departures_are_named(self):
        self.assertIsNone(L.layout_problem(L.make_layout(MID, self.fx.keys, HITL_ID)))
        swapped = L.default_functionaries(self.fx.keys)
        swapped[L.A2_BUILD] = ["a3"]
        self.assertIn("A2_BUILD", L.layout_problem(L.make_layout(MID, self.fx.keys, HITL_ID, swapped)))
        reordered = L.make_layout(MID, self.fx.keys, HITL_ID)
        reordered["steps"].reverse()
        self.assertIsNotNone(L.layout_problem(reordered))
        renamed = dict(self.fx.keys)
        renamed["builder"] = renamed.pop("a2")
        self.assertIn("does not name its principal", L.layout_problem(L.make_layout(MID, renamed, HITL_ID)))


class RegistryTests(unittest.TestCase):
    def test_parses_roles_app_ids_and_status(self):
        reg = parse_registry(registry_md(a2="SUSPENDED"))
        self.assertEqual(set(reg), {"a1", "a2", "a3"})
        self.assertEqual(reg["a2"].app_id, APP_IDS["a2"])
        self.assertFalse(reg["a2"].active)
        self.assertTrue(reg["a3"].active)

    def test_ambiguous_registry_is_an_error(self):
        with self.assertRaises(RegistryError):
            parse_registry("no table here\n")
        doubled = registry_md().replace("| a3 |", "| a1 |")
        with self.assertRaises(RegistryError):
            parse_registry(doubled)

    @unittest.skipUnless((REPO / "registry" / "IDENTITY-REGISTRY.md").is_file(), "live registry not in checkout")
    def test_reads_the_live_registry_format(self):
        reg = load_registry(REPO / "registry" / "IDENTITY-REGISTRY.md")
        self.assertTrue({"a1", "a2", "a3"} <= set(reg))


class PredictedVectorTests(EvidenceCase):
    """Spec section 5 vectors 1-6 (plan P1-P6)."""

    def test_p1_vector_1_complete_pack_verifies_pass(self):
        pack = self.write()
        self.assertEqual(sorted(p.name for p in pack.iterdir()),
                         sorted(["layout.json", "provenance.json"] + [n + ".link" for n in L.STEP_NAMES]))
        self.assertPass(self.verify(pack))

    def test_p2_vector_2_missing_a3_link_is_incomplete(self):
        pack = self.write()
        (pack / "A3_REVIEW.link").unlink()
        result = self.verify(pack)
        self.assertFail(result, verifier.INCOMPLETE)
        self.assertIn("A3_REVIEW", result.detail)

    def test_p3_vector_3_forged_a2_signature_is_bad_signature(self):
        forged = self.sign_link(link_bodies()[L.A2_BUILD], keyid="a2", seed=self.fx.attacker)
        result = self.verify(self.write(docs={L.A2_BUILD: forged}))
        self.assertFail(result, verifier.BAD_SIGNATURE)
        self.assertIn("A2_BUILD", result.detail)

    def test_p4_vector_4_a3_materials_not_a2_products_is_chain_broken(self):
        bodies = link_bodies()
        bodies[L.A3_REVIEW]["materials"] = links.digest_bytes(PLAN)
        result = self.verify(self.write(bodies=bodies))
        self.assertFail(result, verifier.CHAIN_BROKEN)
        self.assertIn("A3_REVIEW materials differ from A2_BUILD products", result.detail)

    def test_p5_vector_5_extra_unauthorized_step_is_layout_violation(self):
        pack = self.write()
        extra = links.make_link("EXTRA_DEPLOY", links.digest_bytes(REVIEWED), links.digest_bytes(REVIEWED),
                                ["a2", "deploy"])
        (pack / "EXTRA_DEPLOY.link").write_bytes(signing.dump(self.sign_link(extra, keyid="a2")))
        result = self.verify(pack)
        self.assertFail(result, verifier.LAYOUT_VIOLATION)
        self.assertIn("EXTRA_DEPLOY", result.detail)

    def test_p6_vector_6_replay_reproduces_recorded_a3_verdict(self):
        # A3's recorded vectors are vectors 1-5 themselves; the replay re-runs the
        # verifier on each scenario pack and must reproduce what A3 recorded.
        scenarios = self.scenario_packs()
        expected = {"V1": "VERIFY_PASS", "V2": verifier.INCOMPLETE, "V3": verifier.BAD_SIGNATURE,
                    "V4": verifier.CHAIN_BROKEN, "V5": verifier.LAYOUT_VIOLATION}
        runners = {vid: self.outcome_runner(scenarios[vid]) for vid in expected}
        recorded = [links.vector(vid, expected[vid], runners[vid]()) for vid in sorted(expected)]
        self.assertTrue(all(v["result"] == "pass" for v in recorded), recorded)
        pack = self.write(bodies=link_bodies(vectors=recorded))
        self.assertPass(self.verify(pack, vector_runners=runners))
        self.assertPass(self.verify(pack))

    def outcome_runner(self, pack):
        def run():
            result = self.verify(pack)
            return result.status if result.passed else result.failed_check
        return run

    def scenario_packs(self):
        v2 = self.write()
        (v2 / "A3_REVIEW.link").unlink()
        forged = self.sign_link(link_bodies()[L.A2_BUILD], keyid="a2", seed=self.fx.attacker)
        broken = link_bodies()
        broken[L.A3_REVIEW]["materials"] = links.digest_bytes(PLAN)
        v5 = self.write()
        (v5 / "EXTRA_DEPLOY.link").write_bytes(signing.dump(self.sign_link(
            links.make_link("EXTRA_DEPLOY", {}, {}, ["deploy"]), keyid="a2")))
        return {"V1": self.write(), "V2": v2, "V3": self.write(docs={L.A2_BUILD: forged}),
                "V4": self.write(bodies=broken), "V5": v5}


class VectorReplayTests(EvidenceCase):
    def test_recorded_result_that_does_not_follow_is_a_mismatch(self):
        lying = [dict(VECTORS[0], observed="VERIFY_FAIL"), VECTORS[1]]  # still claims "pass"
        self.assertFail(self.verify(self.write(bodies=link_bodies(vectors=lying))), verifier.VECTOR_MISMATCH)

    def test_recorded_verdict_that_does_not_follow_is_a_mismatch(self):
        result = self.verify(self.write(bodies=link_bodies(verdict="FAIL")))
        self.assertFail(result, verifier.VECTOR_MISMATCH)
        self.assertIn("replay to PASS", result.detail)

    def test_replay_observing_something_else_is_a_mismatch(self):
        pack = self.write()
        result = self.verify(pack, vector_runners={"P1": lambda: "VERIFY_FAIL"})
        self.assertFail(result, verifier.VECTOR_MISMATCH)
        self.assertIn("P1", result.detail)
        self.assertFail(self.verify(pack, vector_runners={"P9": lambda: "x"}), verifier.VECTOR_MISMATCH)

        def boom():
            raise RuntimeError("cannot run")
        self.assertFail(self.verify(pack, vector_runners={"P2": boom}), verifier.VECTOR_MISMATCH)

    def test_no_recorded_vectors_is_a_mismatch(self):
        self.assertFail(self.verify(self.write(bodies=link_bodies(vectors=[], verdict="PASS"))),
                        verifier.VECTOR_MISMATCH)

    def test_merge_after_a_consistent_fail_verdict_is_a_layout_violation(self):
        failing = [VECTORS[0], links.vector("P2", "INCOMPLETE", "VERIFY_PASS")]
        result = self.verify(self.write(bodies=link_bodies(vectors=failing)))
        self.assertFail(result, verifier.LAYOUT_VIOLATION)
        self.assertIn("A3 FAIL", result.detail)


class SignatureAndIdentityTests(EvidenceCase):
    def test_untrusted_layout_owner_is_bad_signature(self):
        pack = self.write()
        other = ed25519.public_key(ed25519.generate_seed()).hex()
        self.assertFail(verifier.verify_pack(pack, self.registry, other), verifier.BAD_SIGNATURE)

    def test_layout_signed_by_someone_else_is_bad_signature(self):
        pack = self.write(layout=self.layout_doc(seed=self.fx.attacker))
        self.assertFail(self.verify(pack), verifier.BAD_SIGNATURE)

    def test_hitl_signed_layout_that_breaks_the_model_is_layout_violation(self):
        funcs = L.default_functionaries(self.fx.keys)
        funcs[L.A3_REVIEW] = ["a2"]
        result = self.verify(self.write(layout=self.layout_doc(functionaries=funcs)))
        self.assertFail(result, verifier.LAYOUT_VIOLATION)
        self.assertIn("A3_REVIEW", result.detail)

    def test_link_edited_after_signing_is_bad_signature(self):
        pack = self.write()
        self.rewrite(pack / "A2_BUILD.link", lambda doc: doc["signed"]["command"].append("--extra"))
        self.assertFail(self.verify(pack), verifier.BAD_SIGNATURE)

    def test_valid_signature_by_an_unauthorized_identity_is_bad_signature(self):
        by_a3 = self.sign_link(link_bodies()[L.A2_BUILD], keyid="a3")
        result = self.verify(self.write(docs={L.A2_BUILD: by_a3}))
        self.assertFail(result, verifier.BAD_SIGNATURE)
        self.assertIn("does not authorize", result.detail)

    def test_identity_not_active_in_registry_is_bad_signature(self):
        pack = self.write()
        self.registry.write_text(registry_md(a2="SUSPENDED"), encoding="utf-8")
        result = self.verify(pack)
        self.assertFail(result, verifier.BAD_SIGNATURE)
        self.assertIn("SUSPENDED", result.detail)

    def test_app_id_disagreeing_with_registry_is_bad_signature(self):
        pack = self.write()
        self.registry.write_text(registry_md(a2_app="9999999"), encoding="utf-8")
        self.assertFail(self.verify(pack), verifier.BAD_SIGNATURE)

    def test_identity_missing_from_registry_is_bad_signature(self):
        pack = self.write()
        self.registry.write_text(registry_md().replace("| a1 | 1000001", "| intruder | 1000001"), encoding="utf-8")
        result = self.verify(pack)
        self.assertFail(result, verifier.BAD_SIGNATURE)
        self.assertIn("not in the identity registry", result.detail)

    def test_merge_and_spec_by_hitl_in_person_verify(self):
        docs = {L.HITL_MERGE: self.sign_link(link_bodies()[L.HITL_MERGE], keyid=HITL_ID),
                L.A1_SPEC: self.sign_link(link_bodies()[L.A1_SPEC], keyid=HITL_ID)}
        self.assertPass(self.verify(self.write(docs=docs)))


class PackShapeAndProvenanceTests(EvidenceCase):
    def test_provenance_records_who_what_how_and_authority(self):
        pack = self.write()
        prov = json.loads((pack / "provenance.json").read_text(encoding="utf-8"))
        self.assertEqual(prov["_type"], "https://in-toto.io/Statement/v1")
        self.assertEqual(prov["predicateType"], "https://slsa.dev/provenance/v1")
        build = prov["predicate"]["buildDefinition"]
        self.assertEqual(build["externalParameters"]["authority"], AUTHORITY)
        self.assertEqual([s["actor"] for s in build["internalParameters"]["steps"]],
                         [SIGNERS[n] for n in L.STEP_NAMES])
        self.assertEqual({s["name"] for s in prov["subject"]}, set(REVIEWED))
        self.assertEqual(build["resolvedDependencies"], [])

    def test_tampered_provenance_is_a_mismatch(self):
        pack = self.write()

        def swap_actor(doc):
            doc["predicate"]["buildDefinition"]["internalParameters"]["steps"][2]["actor"] = "a3"
        self.rewrite(pack / "provenance.json", swap_actor)
        self.assertFail(self.verify(pack), verifier.PROVENANCE_MISMATCH)

    def test_missing_provenance_or_layout_is_incomplete(self):
        for name in ("provenance.json", "layout.json"):
            with self.subTest(name=name):
                pack = self.write()
                (pack / name).unlink()
                self.assertFail(self.verify(pack), verifier.INCOMPLETE)

    def test_stray_file_is_layout_violation(self):
        pack = self.write()
        (pack / "notes.txt").write_text("hello\n", encoding="utf-8")
        self.assertFail(self.verify(pack), verifier.LAYOUT_VIOLATION)

    def test_link_recording_another_step_is_layout_violation(self):
        pack = self.write()
        (pack / "A2_BUILD.link").write_bytes((pack / "A1_SPEC.link").read_bytes())
        self.assertFail(self.verify(pack), verifier.LAYOUT_VIOLATION)

    def test_unreadable_link_is_malformed(self):
        pack = self.write()
        (pack / "A2_BUILD.link").write_text("{not json", encoding="utf-8")
        self.assertFail(self.verify(pack), verifier.MALFORMED)
        (pack / "A2_BUILD.link").write_text('{"signed": {}, "signed": {}, "signatures": []}', encoding="utf-8")
        self.assertFail(self.verify(pack), verifier.MALFORMED)

    def test_writer_refuses_partial_packs_and_occupied_directories(self):
        docs = [self.sign_link(b) for b in link_bodies().values()]
        with self.assertRaises(writer.PackError):
            writer.write_pack(self.tmp / "partial", self.layout_doc(), docs[:-1], AUTHORITY)
        with self.assertRaises(writer.PackError):
            writer.write_pack(self.tmp / "dup", self.layout_doc(), docs + docs[:1], AUTHORITY)
        with self.assertRaises(writer.PackError):
            writer.write_pack(self.tmp / "noauth", self.layout_doc(), docs, {})
        occupied = self.tmp / "occupied"
        occupied.mkdir()
        (occupied / "x").write_text("x", encoding="utf-8")
        with self.assertRaises(writer.PackError):
            writer.write_pack(occupied, self.layout_doc(), docs, AUTHORITY)

    def test_digest_files_reads_repository_paths(self):
        root = self.tmp / "repo"
        (root / "a").mkdir(parents=True)
        (root / "a" / "f.txt").write_bytes(b"x")
        self.assertEqual(links.digest_files(root, ["a/f.txt"]), links.digest_bytes({"a/f.txt": b"x"}))
        with self.assertRaises(ValueError):
            links.digest_files(root, ["a/missing.txt"])


class CommandLineTests(EvidenceCase):
    def run_cli(self, pack):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = verifier.main([str(pack), "--owner-key", self.fx.owner_hex, "--registry", str(self.registry)])
        return code, json.loads(out.getvalue())

    def test_exit_code_and_report(self):
        pack = self.write()
        self.assertEqual(self.run_cli(pack), (0, {"status": "VERIFY_PASS", "failed_check": None,
                                                  "detail": self.verify(pack).detail}))
        (pack / "A3_REVIEW.link").unlink()
        code, report = self.run_cli(pack)
        self.assertEqual(code, 1)
        self.assertEqual((report["status"], report["failed_check"]), ("VERIFY_FAIL", "INCOMPLETE"))


if __name__ == "__main__":
    unittest.main()
