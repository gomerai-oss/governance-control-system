from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import mcp_auth.decide as D
import mcp_auth.policy as P
import mcp_auth.records as R
from epap import links, signing

PKG = Path(__file__).resolve().parents[1] / "mcp_auth"
NOW = 1_800_000_000
MISSION = "M-TEST-001"
LANE = "SPEC-TEST-LANE-001"
APPROVAL = "HITL-TEST-APPROVAL-001"
OTHER = "SPEC-OTHER-001"
RAG_READ = ["rag.retrieve", "rag.search", "rag.summarize", "rag.cite", "rag.memory_lookup", "rag.retrieve_no_write"]
EPAP_READ = ["epap.artifact_lookup", "epap.artifact_status", "epap.evidence_chain"]


def fixture_policy():
    shipped = P.load_file()
    return {
        "schema": P.SCHEMA,
        "policy_version": "test-policy-1",
        "session": {"max_ttl_seconds": 3600},
        "actions": shipped["actions"],
        "classes": shipped["classes"],
        "authority_refs": {
            LANE: {"kind": "SPEC", "source": "change-specs/SPEC-TEST-LANE-001.md", "missions": [MISSION]},
            APPROVAL: {"kind": "HITL", "source": f"missions/{MISSION}/PLAN.md", "missions": [MISSION]},
            OTHER: {"kind": "SPEC", "source": "change-specs/SPEC-OTHER-001.md", "missions": ["M-OTHER-001"]},
        },
        "roles": ["REVIEWER", "BUILDER"],
        "principals": {
            "agent:vqt-1": {"kind": "agent", "acting_identities": ["a3"], "roles": ["REVIEWER"]},
            "agent:ccp-1": {"kind": "agent", "acting_identities": ["a2"], "roles": ["BUILDER"]},
        },
        "resources": {
            "corpus:governance": {"class": "rag", "restricted": False, "credential_bearing": False},
            "corpus:secrets": {"class": "rag", "restricted": True, "credential_bearing": True},
            "corpus:outside": {"class": "rag", "restricted": False, "credential_bearing": False},
            "index:epap": {"class": "epap", "restricted": False, "credential_bearing": False},
        },
        "missions": {
            MISSION: {"authority_ref": APPROVAL,
                      "resources": ["corpus:governance", "corpus:secrets", "index:epap"],
                      "approvals": {"restricted": [], "credential": [], "runtime": []}},
            "M-OTHER-001": {"authority_ref": OTHER, "resources": ["index:epap"],
                            "approvals": {"restricted": [], "credential": [], "runtime": []}},
        },
        "grants": [
            {"id": "G-REVIEWER-RAG-READ", "effect": "allow", "role": "REVIEWER", "class": "rag",
             "resources": ["corpus:governance", "corpus:secrets"], "actions": list(RAG_READ),
             "authority_ref": LANE, "evidence": "none"},
            {"id": "G-REVIEWER-EPAP-READ", "effect": "allow", "role": "REVIEWER", "class": "epap",
             "resources": ["index:epap"], "actions": list(EPAP_READ),
             "authority_ref": LANE, "evidence": "audit_record"},
            {"id": "G-BUILDER-RAG-READ", "effect": "allow", "role": "BUILDER", "class": "rag",
             "resources": ["corpus:governance"], "actions": ["rag.retrieve"],
             "authority_ref": LANE, "evidence": "none"},
            # Scoped to another mission's SOT authority: no grant for M-TEST-001.
            {"id": "G-BUILDER-EPAP-CREATE-OTHER", "effect": "allow", "role": "BUILDER", "class": "epap",
             "resources": ["index:epap"], "actions": ["epap.artifact_create"],
             "authority_ref": OTHER, "evidence": "epap_packet"},
            {"id": "G-BUILDER-EPAP-UPDATE", "effect": "allow", "role": "BUILDER", "class": "epap",
             "resources": ["index:epap"], "actions": ["epap.artifact_update"],
             "authority_ref": LANE, "evidence": "epap_packet"},
        ],
    }


def request(**overrides):
    req = {
        "request_id": "req-0001",
        "principal": {"id": "agent:vqt-1", "kind": "agent"},
        "acting_identity": "a3",
        "session": {"id": "sess-1", "principal": "agent:vqt-1", "acting_identity": "a3", "mission": MISSION,
                    "issued_at": NOW - 60, "expires_at": NOW + 600},
        "role": "REVIEWER",
        "mission": {"id": MISSION, "authority_ref": APPROVAL},
        "resource": {"class": "rag", "id": "corpus:governance"},
        "action": "rag.retrieve",
        "connector": {"id": "mcp:rag-gateway", "capabilities": ["rag.retrieve", "rag.search"],
                      "credential_bearing": False},
        "evidence": {"can_produce": []},
        "implicates": [],
    }
    req.update(overrides)
    return req


def ccp_request(**overrides):
    base = {
        "principal": {"id": "agent:ccp-1", "kind": "agent"},
        "acting_identity": "a2",
        "session": {"id": "sess-2", "principal": "agent:ccp-1", "acting_identity": "a2", "mission": MISSION,
                    "issued_at": NOW - 60, "expires_at": NOW + 600},
        "role": "BUILDER",
        "resource": {"class": "epap", "id": "index:epap"},
        "action": "epap.artifact_update",
        "connector": {"id": "mcp:epap", "capabilities": ["epap.artifact_update"], "credential_bearing": False},
        "evidence": {"can_produce": ["epap_packet"]},
    }
    base.update(overrides)
    return request(**base)


class Base(unittest.TestCase):
    def setUp(self):
        self.policy = fixture_policy()

    def decide(self, req, policy="fixture", now=NOW):
        return D.evaluate(req, self.policy if policy == "fixture" else policy, now)

    def assertDenied(self, decision, step, stop):
        self.assertEqual(decision.disposition, D.DENY, decision.reason)
        self.assertEqual(decision.step, step, decision.reason)
        self.assertEqual(decision.stop_condition, stop, decision.reason)
        self.assertEqual(decision.record["disposition"], D.DENY)
        self.assertEqual(decision.record["failed_step"], step)
        if stop is None:
            self.assertIsNone(decision.record["stop_condition"])
        else:
            self.assertEqual(decision.record["stop_condition"],
                             {"number": stop, "text": D.STOP_CONDITIONS[stop]})
            self.assertEqual(decision.record["answers"]["stop_conditions"]["triggered"], stop)
        self.assertEqual(decision.record["answers"]["unresolved"], "FAIL_CLOSED")


class SpecVectors(Base):
    def test_vector1_resolved_in_scope_rag_read_allows(self):
        d = self.decide(request())
        self.assertEqual(d.disposition, D.ALLOW, d.reason)
        self.assertTrue(d.allowed)
        self.assertIsNone(d.step)
        self.assertIsNone(d.stop_condition)
        answers = d.record["answers"]
        self.assertEqual(answers["sot_authority"]["grant"],
                         {"id": "G-REVIEWER-RAG-READ", "ref": LANE, "kind": "SPEC",
                          "source": "change-specs/SPEC-TEST-LANE-001.md"})
        self.assertEqual(answers["sot_authority"]["mission"]["ref"], APPROVAL)
        self.assertEqual(answers["principal"], {"id": "agent:vqt-1", "kind": "agent"})
        self.assertEqual(answers["acting_identity"], "a3")
        self.assertEqual(answers["role_class"], {"role": "REVIEWER", "class": "rag"})
        self.assertEqual(answers["scope"], {"mission": MISSION, "class": "rag", "resource": "corpus:governance"})
        self.assertEqual(answers["action"], {"name": "rag.retrieve", "kind": "read"})
        self.assertEqual(answers["evidence"], "none")
        self.assertEqual(answers["stop_conditions"], {"cleared": list(range(1, 14)), "triggered": None})
        self.assertEqual(d.record["policy_version"], "test-policy-1")
        self.assertEqual(d.record["timestamp"], "2027-01-15T08:00:00Z")

    def test_vector2_unidentifiable_principal_denies_stop_2(self):
        for principal in (None, {}, {"id": "", "kind": "agent"}, {"id": "agent:ghost", "kind": "agent"},
                          {"id": "agent:vqt-1", "kind": "human"}):
            req = request(principal=principal)
            if principal is None:
                del req["principal"]
            with self.subTest(principal=principal):
                d = self.decide(req)
                self.assertDenied(d, "identity", 2)
                self.assertIsNone(d.record["answers"]["principal"])

    def test_vector3_epap_mutation_without_sot_scoped_grant_denies_stop_6(self):
        # the builder's only create grant rests on another mission's authority.
        d = self.decide(ccp_request(action="epap.artifact_create",
                                    connector={"id": "mcp:epap", "capabilities": ["epap.artifact_create"],
                                               "credential_bearing": False}))
        self.assertDenied(d, "action_grant", 6)
        self.assertIsNone(d.record["answers"]["sot_authority"]["grant"])
        # REVIEWER holds EPAP read only.
        d = self.decide(request(resource={"class": "epap", "id": "index:epap"}, action="epap.artifact_update"))
        self.assertDenied(d, "action_grant", 6)

    def test_vector4_read_to_execute_crossing_denies_stop_5_without_read_substitute(self):
        d = self.decide(request(action="tool.execute"))
        self.assertDenied(d, "action_grant", 5)
        self.assertEqual(d.record["answers"]["action"], {"name": "tool.execute", "kind": "execute"})
        self.assertIsNone(d.record["answers"]["sot_authority"]["grant"])
        self.assertIsNone(d.record["answers"]["evidence"])
        self.assertFalse(d.allowed)
        d = self.decide(request(action="rag.corpus_write"))
        self.assertDenied(d, "action_grant", 5)

    def test_vector5_conflicting_grants_deny_stop_11(self):
        self.policy["grants"].append(
            {"id": "G-REVIEWER-RAG-DENY", "effect": "deny", "role": "REVIEWER", "class": "rag",
             "resources": ["corpus:governance"], "actions": ["rag.retrieve"], "authority_ref": APPROVAL,
             "evidence": "none"})
        d = self.decide(request())
        self.assertDenied(d, "action_grant", 11)
        self.assertIn("G-REVIEWER-RAG-DENY", d.reason)
        self.assertIn("G-REVIEWER-RAG-READ", d.reason)

        self.policy = fixture_policy()
        self.policy["grants"].append(
            {"id": "G-REVIEWER-RAG-AUDITED", "effect": "allow", "role": "REVIEWER", "class": "rag",
             "resources": ["corpus:governance"], "actions": ["rag.retrieve"], "authority_ref": LANE,
             "evidence": "audit_record"})
        self.assertDenied(self.decide(request()), "action_grant", 11)

    def test_vector6_missing_or_malformed_policy_denies_stop_12(self):
        self.assertDenied(self.decide(request(), policy=None), "policy", 12)
        broken = fixture_policy()
        del broken["grants"]
        self.assertDenied(self.decide(request(), policy=broken), "policy", 12)
        broken = fixture_policy()
        broken["classes"]["rag"]["mutation"] = ["rag.corpus_write"]
        self.assertDenied(self.decide(request(), policy=broken), "policy", 12)
        broken = fixture_policy()
        broken["grants"][0]["authority_ref"] = "SPEC-NOWHERE"
        self.assertDenied(self.decide(request(), policy=broken), "policy", 12)
        self.assertDenied(self.decide(request(), policy="not a policy"), "policy", 12)

        with tempfile.TemporaryDirectory() as tmp:
            d = D.evaluate_file(request(), NOW, Path(tmp) / "absent.json")
            self.assertDenied(d, "policy", 12)
            self.assertIsNone(d.record["policy_version"])
            for name, data in (("garbage.json", b"{not json"),
                               ("dupe.json", b'{"schema": "a", "schema": "b"}'),
                               ("float.json", json.dumps({**fixture_policy(), "policy_version": 1.5}).encode())):
                path = Path(tmp) / name
                path.write_bytes(data)
                with self.subTest(name=name):
                    self.assertDenied(D.evaluate_file(request(), NOW, path), "policy", 12)
            good = Path(tmp) / "good.json"
            good.write_text(json.dumps(fixture_policy()))
            self.assertTrue(D.evaluate_file(request(), NOW, good).allowed)


class FixedOrder(Base):
    def test_session_context_failures_stop_13(self):
        session = request()["session"]
        cases = {
            "missing": None,
            "expired": {**session, "expires_at": NOW},
            "not yet issued": {**session, "issued_at": NOW + 1, "expires_at": NOW + 60},
            "too long": {**session, "issued_at": NOW - 1, "expires_at": NOW + 3600},
            "other identity": {**session, "acting_identity": "a2"},
            "other mission": {**session, "mission": "M-OTHER-001"},
            "float time": {**session, "issued_at": float(NOW - 60)},
        }
        for name, value in cases.items():
            with self.subTest(name):
                self.assertDenied(self.decide(request(session=value)), "identity", 13)

    def test_request_envelope_failures_stop_13(self):
        self.assertDenied(self.decide("not a request"), "request", 13)
        self.assertDenied(self.decide(request(extra="x")), "request", 13)
        self.assertDenied(self.decide(request(request_id="")), "request", 13)
        self.assertDenied(self.decide(request(), now=None), "request", 13)
        self.assertDenied(self.decide(request(), now=float(NOW)), "request", 13)

    def test_acting_identity_not_bound_stop_2(self):
        self.assertDenied(self.decide(request(acting_identity="a2")), "identity", 2)

    def test_role_not_held_fails_role_class(self):
        self.assertDenied(self.decide(request(role="BUILDER")), "role_class", None)
        self.assertDenied(self.decide(request(role="ROOT")), "role_class", None)
        self.assertDenied(self.decide(request(resource={"class": "memory", "id": "corpus:governance"})),
                          "role_class", None)

    def test_mission_authority_unresolved_stop_3(self):
        self.assertDenied(self.decide(request(mission={"id": MISSION, "authority_ref": LANE})), "authority", 3)
        self.policy["authority_refs"][APPROVAL]["missions"] = []
        self.assertDenied(self.decide(request()), "authority", 3)
        self.policy = fixture_policy()
        session = {**request()["session"], "mission": "M-UNKNOWN"}
        self.assertDenied(self.decide(request(mission={"id": "M-UNKNOWN", "authority_ref": APPROVAL},
                                              session=session)), "authority", 3)

    def test_resource_outside_scope_stop_4(self):
        self.assertDenied(self.decide(request(resource={"class": "rag", "id": "corpus:outside"})), "scope", 4)
        self.assertDenied(self.decide(request(resource={"class": "rag", "id": "corpus:nowhere"})), "scope", 4)
        self.assertDenied(self.decide(request(resource={"class": "rag", "id": "index:epap"})), "scope", 4)

    def test_read_without_grant_denies_at_action_grant(self):
        d = self.decide(ccp_request(resource={"class": "rag", "id": "corpus:governance"}, action="rag.search"))
        self.assertDenied(d, "action_grant", None)

    def test_unknown_action_is_ambiguous_stop_11(self):
        self.assertDenied(self.decide(request(action="rag.teleport")), "action_grant", 11)

    def test_sole_deny_grant_on_read_denies(self):
        for g in self.policy["grants"]:
            if g["id"] == "G-REVIEWER-RAG-READ":
                g["effect"] = "deny"
        self.assertDenied(self.decide(request()), "action_grant", None)

    def test_evidence_obligation_stop_10(self):
        self.assertTrue(self.decide(ccp_request()).allowed)
        self.assertDenied(self.decide(ccp_request(evidence={"can_produce": []})), "evidence", 10)
        self.assertDenied(self.decide(ccp_request(evidence=None)), "evidence", 10)
        d = self.decide(request(resource={"class": "epap", "id": "index:epap"}, action="epap.artifact_lookup",
                                connector={"id": "mcp:epap", "capabilities": ["epap.artifact_lookup"],
                                           "credential_bearing": False}))
        self.assertDenied(d, "evidence", 10)

    def test_epap_mutation_with_sot_scoped_grant_allows(self):
        d = self.decide(ccp_request())
        self.assertTrue(d.allowed, d.reason)
        self.assertEqual(d.record["answers"]["sot_authority"]["grant"]["id"], "G-BUILDER-EPAP-UPDATE")
        self.assertEqual(d.record["answers"]["evidence"], "epap_packet")


class StopConditions(Base):
    def test_connector_broader_than_authorized_stop_1(self):
        connector = {"id": "mcp:rag-gateway", "capabilities": ["rag.retrieve", "tool.execute"],
                     "credential_bearing": False}
        d = self.decide(request(connector=connector))
        self.assertDenied(d, "stop_conditions", 1)
        self.assertIn("tool.execute", d.reason)
        self.assertDenied(self.decide(request(connector=None)), "stop_conditions", 1)

    def test_restricted_corpus_stop_7(self):
        req = request(resource={"class": "rag", "id": "corpus:secrets"})
        self.assertDenied(self.decide(req), "stop_conditions", 7)
        self.policy["missions"][MISSION]["approvals"]["restricted"] = ["corpus:secrets"]
        self.assertTrue(self.decide(req).allowed)

    def test_credential_bearing_connector_stop_8(self):
        connector = {**request()["connector"], "credential_bearing": True}
        self.assertDenied(self.decide(request(connector=connector)), "stop_conditions", 8)
        self.policy["missions"][MISSION]["approvals"]["credential"] = ["mcp:rag-gateway"]
        self.assertTrue(self.decide(request(connector=connector)).allowed)

    def test_runtime_implication_stop_9(self):
        for implicates in (["production_system"], ["trading_system"], ["unknown_surface"], None):
            with self.subTest(implicates=implicates):
                self.assertDenied(self.decide(request(implicates=implicates)), "stop_conditions", 9)
        self.policy["missions"][MISSION]["approvals"]["runtime"] = ["external_exposure"]
        self.assertTrue(self.decide(request(implicates=["external_exposure"])).allowed)


class Records(Base):
    def test_deterministic(self):
        first, second = self.decide(request()), self.decide(copy.deepcopy(request()))
        self.assertEqual(first, second)
        denied = self.decide(request(action="tool.execute"))
        self.assertEqual(denied.record, self.decide(request(action="tool.execute")).record)

    def test_record_is_epap_link_material(self):
        for d in (self.decide(request()), self.decide(request(action="tool.execute")),
                  self.decide(request(), policy=None), self.decide({"bad": 1.5})):
            with self.subTest(d.reason):
                link = R.link_material(d.record)
                self.assertIsNone(links.link_problem(link))
                self.assertEqual(link["name"], R.LINK_NAME)
                self.assertEqual(link["byproducts"], d.record)
                decision_path = R.artifact_paths(d.record)["decision"]
                self.assertEqual(link["products"][decision_path], {"sha256": R.digest(d.record)})
                for path, digest in link["materials"].items():
                    self.assertEqual(link["products"][path], digest)
                signing.canonical_bytes(link)

    def test_link_names_policy_and_request(self):
        d = self.decide(request())
        link = R.link_material(d.record)
        self.assertEqual(d.record["policy_digest"], R.digest(P.validate(self.policy)))
        self.assertEqual(d.record["request_digest"], R.digest(request()))
        self.assertIn(f"mcp_auth/policy/{d.record['policy_digest']}.json", link["materials"])
        self.assertIn(f"mcp_auth/requests/{d.record['request_digest']}.json", link["materials"])
        self.assertEqual(link["command"], [R.COMMAND, "test-policy-1"])

    def test_record_answers_the_nine_questions(self):
        self.assertEqual(tuple(self.decide(request()).record["answers"]), R.QUESTIONS)
        self.assertEqual(len(R.QUESTIONS), 9)


class ShippedPolicy(unittest.TestCase):
    def test_shipped_policy_is_valid_and_binds_only_mission_seats(self):
        policy = P.load_file()
        self.assertEqual(policy["classes"]["rag"]["mutation"], [])
        self.assertEqual(sorted(policy["principals"]), ["a2", "a3"])
        self.assertEqual(policy["missions"], {})
        for grant in policy["grants"]:
            self.assertIn(grant["authority_ref"], policy["authority_refs"])
        d = D.evaluate_file(request(), NOW)
        self.assertEqual((d.disposition, d.step, d.stop_condition), (D.DENY, "identity", 2))
        self.assertEqual(d.record["policy_version"], policy["policy_version"])

    def test_engine_has_no_per_role_logic(self):
        source = (PKG / "decide.py").read_text() + (PKG / "policy.py").read_text()
        for role in P.load_file()["roles"]:
            self.assertNotIn(role, source)

    def test_namespace_package_has_no_init(self):
        self.assertFalse(any(PKG.rglob("__init__.py")))

    def test_mutation_grant_must_be_explicit(self):
        policy = fixture_policy()
        policy["grants"][4]["actions"] = ["epap.artifact_update", "epap.index_update"]
        with self.assertRaises(P.PolicyError):
            P.validate(policy)
        policy = fixture_policy()
        policy["grants"][4]["evidence"] = "none"
        with self.assertRaises(P.PolicyError):
            P.validate(policy)


if __name__ == "__main__":
    unittest.main()
