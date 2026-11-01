"""Tests for the governed-retrieval MCP gateway (MCP-GATEWAY-SPEC-001).

One named case per predicted vector (P1-P7), plus hardening cases. Every case
drives the server through its real stdio loop: ``protocol.serve`` over an
in-process pipe pair, or ``python3 -m mcp_gateway`` as a subprocess. Every case
builds its own checkout in a temporary directory and keeps the session file and
the evidence directory outside it; none reads ``governance/doctrine/`` or
``EPAP/`` from this checkout.
"""

from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mcp_auth import decide as D
from mcp_auth import policy as P
from mcp_gateway import protocol, server
from mcp_gateway import session as S
from retrieval import corpus as corpus_mod

AW = Path(__file__).resolve().parents[1]
PKG = AW / "mcp_gateway"
NOW = 1_800_000_000
MISSION = "M-TEST-GW-001"
BASE_SHA = "0123456789abcdef0123456789abcdef01234567"
ALL_RESOURCES = ("corpus:governance-doctrine", "index:epap-evidence")
ALL_TOOLS = ["artifact_status", "cite", "evidence_chain", "retrieve", "search", "trace"]
RAG_TOOLS = ["cite", "retrieve", "search"]


def doc(title, body=""):
    return "\n".join([f"# {title}", "", f"**Title:** {title}", "", body, ""])


def session_doc(seat="a2", resources=ALL_RESOURCES, now=NOW, **overrides):
    doc_ = {
        "principal": seat,
        "acting_identity": seat,
        "role": {"a2": "BUILDER", "a3": "REVIEWER"}[seat],
        "mission": {"id": MISSION, "authority_ref": "MISSION-ROUTER-001", "base_sha": BASE_SHA, "round": 1},
        "resources": list(resources),
        "issued_at": now - 60,
        "expires_at": now + 600,
    }
    doc_.update(overrides)
    return doc_


def initialize(rid=1):
    return {"jsonrpc": "2.0", "id": rid, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "test-client", "version": "0"}}}


INITIALIZED = {"jsonrpc": "2.0", "method": "notifications/initialized"}


def list_tools(rid):
    return {"jsonrpc": "2.0", "id": rid, "method": "tools/list"}


def call(rid, name, arguments):
    return {"jsonrpc": "2.0", "id": rid, "method": "tools/call", "params": {"name": name, "arguments": arguments}}


class GatewayCase(unittest.TestCase):
    def setUp(self):
        checkout = tempfile.TemporaryDirectory()
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(checkout.cleanup)
        self.addCleanup(outside.cleanup)
        self.root = Path(checkout.name)
        self.outside = Path(outside.name)
        self.evidence = self.outside / "evidence"
        self.evidence.mkdir()

    def write(self, relpath, text):
        target = self.root / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        return relpath

    def write_session(self, doc_, path=None):
        path = Path(path) if path else self.outside / "session.json"
        path.write_text(json.dumps(doc_), encoding="utf-8")
        return path

    def gateway(self, session_path, evidence=None, **kw):
        kw.setdefault("clock", lambda: NOW)
        return server.Gateway(self.root, session_path, evidence or self.evidence, **kw)

    def run_messages(self, gateway, messages):
        lines = b"".join(m if isinstance(m, bytes) else protocol.encode(m) for m in messages)
        out = io.BytesIO()
        protocol.serve(protocol.Endpoint(gateway), io.BytesIO(lines), out)
        return [json.loads(line) for line in out.getvalue().splitlines()]

    def log(self, evidence=None):
        path = (evidence or self.evidence) / server.DECISIONS_FILE
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

    def entries(self, kind, evidence=None):
        return [e for e in self.log(evidence) if e["entry"] == kind]

    def assertToolDenied(self, response, stop):
        result = response["result"]
        self.assertTrue(result["isError"], result)
        self.assertEqual(result["structuredContent"]["disposition"], "DENY")
        self.assertEqual(result["structuredContent"]["stop_condition"]["number"], stop)
        self.assertIn(f"stop condition {stop}", result["content"][0]["text"])

    def doctrine_corpus(self):
        self.write("governance/doctrine/ALPHA-001.md", doc("Alpha doctrine", "the quorum rule for reviews"))
        self.write("governance/doctrine/BETA-001.md", doc("Beta doctrine", "neutral filler text"))


class VectorTests(GatewayCase):
    def test_vector1_a2_retrieve_is_allowed_through_the_stdio_server(self):
        self.doctrine_corpus()
        now = int(time.time())
        session_path = self.write_session(session_doc("a2", now=now))
        stdin = b"".join(protocol.encode(m) for m in (
            initialize(), INITIALIZED, list_tools(2), call(3, "retrieve", {"keywords": ["quorum"]})))
        proc = subprocess.run(
            [sys.executable, "-m", "mcp_gateway", "--root", str(self.root), "--session", str(session_path),
             "--evidence-dir", str(self.evidence)],
            input=stdin, capture_output=True, timeout=120, cwd=str(self.outside),
            env=dict(os.environ, PYTHONPATH=str(AW)))
        self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", "replace"))
        responses = [json.loads(line) for line in proc.stdout.splitlines()]
        self.assertEqual([r["id"] for r in responses], [1, 2, 3])  # the notification is never answered

        init = responses[0]["result"]
        self.assertEqual(init["protocolVersion"], "2025-06-18")
        self.assertEqual(init["serverInfo"]["name"], "governed-retrieval")
        self.assertEqual(set(init["capabilities"]), {"tools"})
        self.assertEqual(sorted(t["name"] for t in responses[1]["result"]["tools"]), ALL_TOOLS)

        result = responses[2]["result"]
        self.assertFalse(result["isError"], result)
        body = result["structuredContent"]
        self.assertEqual(body["disposition"], "ALLOW")
        self.assertEqual(body["grant"], "G-MISSION-BUILDER-RAG-READ")
        self.assertEqual(body["result"]["source_id"], "ALPHA-001")
        self.assertEqual(body["result"]["stop_reason"], "RESOLVED")
        self.assertEqual([c["source_path"] for c in body["citations"]], ["governance/doctrine/ALPHA-001.md"])
        self.assertEqual(json.loads(result["content"][0]["text"]), body)

        decisions, links = self.entries("decision"), self.entries("retrieval")
        self.assertEqual(len(decisions), 1)
        self.assertEqual(len(links), 1)
        record = decisions[0]["record"]
        self.assertEqual(record["schema"], "mcp-auth-decision-v1")
        self.assertEqual(record["disposition"], "ALLOW")
        self.assertEqual(decisions[0]["mission"], {"id": MISSION, "authority_ref": "MISSION-ROUTER-001",
                                                   "base_sha": BASE_SHA, "round": 1})
        self.assertEqual(decisions[0]["link"]["name"], "MCP_AUTH_DECISION")
        self.assertEqual(links[0]["link"]["name"], "RETRIEVAL")
        self.assertEqual(links[0]["request_id"], record["request_id"])
        self.assertIn("governance/doctrine/ALPHA-001.md", links[0]["link"]["materials"])

    def test_vector1a_a3_evidence_chain_reads_only_epap_evidence_with_the_shipped_registry(self):
        self.write("EPAP/EVIDENCE/CLOSURE-001.md", doc("Closure packet", "closure evidence for the release"))
        self.write("EPAP/EVIDENCE/runs/RUN-002.md", doc("Run record", "graph run checkpoint"))
        self.write("governance/doctrine/DECOY-001.md", doc("Decoy", "closure closure closure"))
        session_path = self.write_session(session_doc("a3", resources=["index:epap-evidence"]))
        responses = self.run_messages(self.gateway(session_path), [
            initialize(), INITIALIZED, list_tools(2), call(3, "evidence_chain", {"keywords": ["closure"]})])
        self.assertEqual(sorted(t["name"] for t in responses[1]["result"]["tools"]),
                         ["artifact_status", "evidence_chain", "trace"])
        result = responses[2]["result"]
        self.assertFalse(result["isError"], result)
        body = result["structuredContent"]
        self.assertEqual(body["grant"], "G-MISSION-REVIEWER-EPAP-READ")
        self.assertEqual(body["result"]["source_id"], "CLOSURE-001")
        self.assertEqual(body["result"]["source_authority"], "evidence")
        self.assertEqual(body["result"]["provenance"]["corpus_scope"], ["corpus:epap-evidence"])
        self.assertTrue(body["citations"])
        for cite in body["citations"]:
            self.assertTrue(cite["source_path"].startswith("EPAP/EVIDENCE/"), cite)
        self.assertEqual(len(self.entries("decision")), 1)
        self.assertEqual(len(self.entries("retrieval")), 1)
        self.assertEqual(self.entries("decision")[0]["record"]["answers"]["sot_authority"]["grant"]["id"],
                         "G-MISSION-REVIEWER-EPAP-READ")

    def test_vector2_an_unbindable_session_lists_nothing_and_denies_every_call_with_stop_13(self):
        extra = session_doc("a2")
        extra["approval"] = {"restricted": ["corpus:governance-doctrine"]}
        other_ref = session_doc("a2")
        other_ref["mission"]["authority_ref"] = "SPEC-MCP-AUTHORIZATION-FABRIC-GOVERNED-RAG-EPAP-ACCESS-001"
        cases = {
            "missing": self.outside / "absent.json",
            "expired": self.write_session(session_doc("a2", issued_at=NOW - 7200, expires_at=NOW - 3600),
                                          self.outside / "expired.json"),
            "inside-checkout": self.write_session(session_doc("a2"), self.root / "session.json"),
            "extra-key": self.write_session(extra, self.outside / "extra.json"),
            "other-authority": self.write_session(other_ref, self.outside / "other.json"),
        }
        self.doctrine_corpus()
        for label, path in cases.items():
            with self.subTest(label):
                evidence = self.outside / f"evidence-{label}"
                evidence.mkdir()
                responses = self.run_messages(self.gateway(path, evidence), [
                    initialize(), list_tools(2), call(3, "retrieve", {"keywords": ["quorum"]}),
                    call(4, "evidence_chain", {"keywords": ["quorum"]})])
                self.assertEqual(responses[1]["result"]["tools"], [])
                self.assertToolDenied(responses[2], 13)
                self.assertToolDenied(responses[3], 13)
                decisions = self.entries("decision", evidence)
                self.assertEqual(len(decisions), 2)
                for entry in decisions:
                    self.assertEqual(entry["record"]["disposition"], "DENY")
                    self.assertEqual(entry["record"]["stop_condition"]["number"], 13)
                self.assertEqual(self.entries("retrieval", evidence), [])

    def test_vector3_a_catalog_naming_a_write_action_refuses_to_start(self):
        catalog = json.loads((PKG / "tools.json").read_text(encoding="utf-8"))
        catalog["tools"][3]["action"] = "epap.artifact_update"
        path = self.outside / "tools.json"
        path.write_text(json.dumps(catalog), encoding="utf-8")
        session_path = self.write_session(session_doc("a2"))
        with self.assertRaisesRegex(server.GatewayError, "read actions only"):
            self.gateway(session_path, catalog_path=path)
        catalog["tools"][3]["action"] = "tool.execute"
        path.write_text(json.dumps(catalog), encoding="utf-8")
        with self.assertRaisesRegex(server.GatewayError, "read actions only"):
            self.gateway(session_path, catalog_path=path)

    def test_vector3_a_tool_not_listed_is_a_tool_error_not_a_call(self):
        self.write("EPAP/EVIDENCE/CLOSURE-001.md", doc("Closure packet", "closure evidence"))
        session_path = self.write_session(session_doc("a2", resources=["corpus:governance-doctrine"]))
        responses = self.run_messages(self.gateway(session_path), [
            initialize(), list_tools(2), call(3, "evidence_chain", {"keywords": ["closure"]}),
            call(4, "artifact_update", {"path": "EPAP/EVIDENCE/CLOSURE-001.md"})])
        self.assertEqual(sorted(t["name"] for t in responses[1]["result"]["tools"]), RAG_TOOLS)
        self.assertToolDenied(responses[2], 4)
        self.assertTrue(responses[3]["result"]["isError"])
        self.assertEqual(responses[3]["result"]["structuredContent"]["disposition"], "REFUSED")
        self.assertEqual(self.entries("retrieval"), [])
        self.assertEqual(len(self.entries("refusal")), 1)

    def test_vector4_restricted_or_credential_bearing_resources_deny_with_stop_7(self):
        self.doctrine_corpus()
        for flag in ("restricted", "credential_bearing"):
            with self.subTest(flag):
                policy = json.loads(P.DEFAULT_PATH.read_text(encoding="utf-8"))
                policy["resources"]["corpus:governance-doctrine"][flag] = True
                policy_path = self.outside / f"policy-{flag}.json"
                policy_path.write_text(json.dumps(policy), encoding="utf-8")
                evidence = self.outside / f"evidence-{flag}"
                evidence.mkdir()
                session_path = self.write_session(session_doc("a2"))
                gateway = self.gateway(session_path, evidence, policy_path=policy_path)
                responses = self.run_messages(gateway, [
                    initialize(), list_tools(2), call(3, "retrieve", {"keywords": ["quorum"]})])
                self.assertEqual(sorted(t["name"] for t in responses[1]["result"]["tools"]),
                                 ["artifact_status", "evidence_chain", "trace"])
                self.assertToolDenied(responses[2], 7)
                self.assertEqual(self.entries("retrieval", evidence), [])
                self.assertEqual(gateway.policy["missions"][MISSION]["approvals"],
                                 {"restricted": [], "credential": [], "runtime": []})

    def test_vector5_overlay_is_valid_adds_one_mission_and_leaves_the_policy_file_unchanged(self):
        before = P.DEFAULT_PATH.read_bytes()
        shipped = P.load_file()
        session = S.parse(json.dumps(session_doc("a3")).encode("utf-8"))
        overlaid = S.overlay(shipped, session)
        self.assertEqual(P.validate(overlaid), overlaid)
        self.assertEqual(list(overlaid["missions"]), [MISSION])
        self.assertEqual(overlaid["missions"][MISSION], {
            "authority_ref": "MISSION-ROUTER-001", "resources": list(ALL_RESOURCES),
            "approvals": {"restricted": [], "credential": [], "runtime": []}})
        self.assertEqual(overlaid["authority_refs"]["MISSION-ROUTER-001"]["missions"], [MISSION])
        restored = json.loads(json.dumps(overlaid))
        restored["missions"] = {}
        restored["authority_refs"]["MISSION-ROUTER-001"]["missions"] = []
        self.assertEqual(restored, shipped)
        self.assertEqual(shipped["missions"], {})  # the input is not mutated

        self.doctrine_corpus()
        gateway = self.gateway(self.write_session(session_doc("a3")))
        self.run_messages(gateway, [initialize(), call(2, "retrieve", {"keywords": ["quorum"]})])
        record = self.entries("decision")[0]["record"]
        self.assertEqual(record["disposition"], "ALLOW")
        self.assertEqual(record["policy_digest"], D.records.digest(gateway.policy))
        self.assertEqual(P.DEFAULT_PATH.read_bytes(), before)

    def test_vector6_shipped_policy_allows_a3_search_and_denies_an_epap_mutation(self):
        self.doctrine_corpus()
        gateway = self.gateway(self.write_session(session_doc("a3")))
        responses = self.run_messages(gateway, [initialize(), call(2, "search", {"keywords": ["quorum"]})])
        result = responses[1]["result"]
        self.assertFalse(result["isError"], result)
        self.assertEqual(result["structuredContent"]["grant"], "G-MISSION-REVIEWER-RAG-READ")
        self.assertEqual(result["structuredContent"]["result"]["provenance"]["resolved_stage"], "lexical")

        for action in ("epap.artifact_update", "epap.closure_publish", "tool.execute"):
            with self.subTest(action):
                _, decision = gateway.evaluate(action, "index:epap-evidence", [action])
                self.assertEqual(decision.disposition, D.DENY, decision.reason)
                self.assertEqual(decision.step, "action_grant")
                self.assertIn(decision.stop_condition, (5, 6))
                self.assertNotEqual(decision.record["answers"]["action"]["kind"], "read")

    def test_vector7_protocol_errors_are_answered_and_the_server_keeps_serving(self):
        self.doctrine_corpus()
        gateway = self.gateway(self.write_session(session_doc("a2")))
        responses = self.run_messages(gateway, [
            b"{not json\n",
            {"jsonrpc": "2.0", "id": 2, "method": "ping"},
            {"jsonrpc": "2.0", "id": 3, "method": "resources/list"},
            {"jsonrpc": "2.0", "id": 4, "method": "ping"},
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"arguments": {}}},
            {"jsonrpc": "2.0", "id": 6, "method": "initialize", "params": ["2025-06-18"]},
            call(7, "retrieve", {"keywords": "quorum"}),
            {"jsonrpc": "1.0", "id": 8, "method": "ping"},
            [{"jsonrpc": "2.0", "id": 9, "method": "ping"}],
            {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 2}},
            call(10, "retrieve", {"keywords": ["quorum"]}),
        ])
        by_id = {r["id"]: r for r in responses if r["id"] is not None}
        anonymous = [r for r in responses if r["id"] is None]
        self.assertEqual(len(responses), 10)  # the notification is not answered
        self.assertEqual([r["error"]["code"] for r in anonymous], [-32700, -32600])
        self.assertEqual(by_id[2]["result"], {})
        self.assertEqual(by_id[3]["error"]["code"], -32601)
        self.assertEqual(by_id[4]["result"], {})
        self.assertEqual(by_id[5]["error"]["code"], -32602)
        self.assertEqual(by_id[6]["error"]["code"], -32602)
        self.assertEqual(by_id[7]["error"]["code"], -32602)
        self.assertEqual(by_id[8]["error"]["code"], -32600)
        self.assertFalse(by_id[10]["result"]["isError"])


class HardeningTests(GatewayCase):
    def test_package_holds_exactly_the_planned_files_and_no_init(self):
        names = sorted(p.name for p in PKG.iterdir() if p.name != "__pycache__")
        self.assertEqual(names, sorted(["protocol.py", "tools.json", "session.py", "server.py", "__main__.py",
                                        "IMPLEMENTATION-DECISIONS.md"]))
        self.assertFalse(any(PKG.rglob("__init__.py")))

    def test_no_release_deny_term_matches_a_delivered_file(self):
        manifests = sorted(AW.glob("*/manifest-gcs.json"))
        if not manifests:
            self.skipTest("no release manifest in this tree; the source repository runs this check")
        self.assertEqual(len(manifests), 1)
        doc = json.loads(manifests[0].read_text(encoding="utf-8"))
        terms = [re.compile(t) for t in doc["deny_terms"]]
        rules = doc.get("translate", [])
        self.assertTrue(terms)
        files = [p for p in sorted(PKG.iterdir()) if p.is_file()] + [
            P.DEFAULT_PATH, corpus_mod.default_registry_path(), Path(__file__).resolve(),
            AW / "tests" / "test_mcp_auth.py"]

        def published(path):
            text = path.read_text(encoding="utf-8")
            for rule in rules:
                text = re.sub(rule["pattern"], lambda m, replace=rule["replace"]: replace, text)
            return text

        hits = [(path.name, number, term.pattern) for path in files
                for number, line in enumerate(published(path).split("\n"), start=1)
                for term in terms if term.search(line)]
        self.assertEqual(hits, [])

    def test_shipped_catalog_maps_tools_to_read_actions_and_registered_corpora(self):
        policy = P.load_file()
        registry = corpus_mod.load_registry(corpus_mod.default_registry_path())
        tools = {t.name: t for t in server.load_catalog(server.DEFAULT_CATALOG, policy, registry)}
        self.assertEqual(sorted(tools), ALL_TOOLS)
        expected = {"retrieve": "rag.retrieve", "search": "rag.search", "cite": "rag.cite",
                    "evidence_chain": "epap.evidence_chain", "artifact_status": "epap.artifact_status"}
        for name, action in expected.items():
            tool = tools[name]
            self.assertEqual(tool.action, action)
            self.assertEqual(policy["actions"][action]["kind"], "read")
            if action.startswith("rag."):
                self.assertEqual((tool.resource, tool.corpus_scope),
                                 ("corpus:governance-doctrine", ("corpus:governance-doctrine",)))
            else:
                self.assertEqual((tool.resource, tool.corpus_scope),
                                 ("index:epap-evidence", ("corpus:epap-evidence",)))

    def test_unresolved_corpus_scope_refuses_to_start(self):
        registry = corpus_mod.parse_registry({
            "schema": "retrieval-corpus-v1", "registry_version": "test-1",
            "corpora": [{"id": "corpus:governance-doctrine", "roots": ["governance/doctrine/**/*.md"],
                         "deny_patterns": [], "authority": {}, "vocabulary": {}}]})
        with self.assertRaisesRegex(server.GatewayError, "corpus scope does not resolve"):
            self.gateway(self.write_session(session_doc("a2")), corpus_registry=registry)

    def test_evidence_dir_inside_the_checkout_refuses_to_start(self):
        inside = self.root / "evidence"
        inside.mkdir()
        with self.assertRaisesRegex(server.GatewayError, "inside the checkout"):
            self.gateway(self.write_session(session_doc("a2")), inside)

    def test_session_with_unknown_resource_or_bad_fields_is_unbindable(self):
        bad_mission = session_doc("a2")
        bad_mission["mission"]["round"] = 0
        bad_sha = session_doc("a2")
        bad_sha["mission"]["base_sha"] = BASE_SHA.upper()
        cases = {
            "unknown-resource": session_doc("a2", resources=["corpus:secrets"]),
            "empty-resources": session_doc("a2", resources=[]),
            "round-zero": bad_mission,
            "upper-sha": bad_sha,
            "float-time": session_doc("a2", expires_at=NOW + 600.5),
        }
        for label, doc_ in cases.items():
            with self.subTest(label):
                gateway = self.gateway(self.write_session(doc_, self.outside / f"{label}.json"))
                self.assertIsNone(gateway.session)
                self.assertEqual(gateway.list_tools(), [])
                _, decision = gateway.evaluate("rag.retrieve", "corpus:governance-doctrine")
                self.assertEqual((decision.disposition, decision.stop_condition), (D.DENY, 13))

    def test_an_unknown_seat_is_denied_by_the_fabric_at_identity(self):
        doc_ = session_doc("a2")
        doc_["principal"] = doc_["acting_identity"] = "a9"
        gateway = self.gateway(self.write_session(doc_))
        self.assertEqual(gateway.list_tools(), [])
        _, decision = gateway.evaluate("rag.retrieve", "corpus:governance-doctrine", ["rag.retrieve"])
        self.assertEqual((decision.step, decision.stop_condition), ("identity", 2))

    def test_connector_surface_is_stated_per_resource_and_never_broader_than_the_grants(self):
        self.doctrine_corpus()
        gateway = self.gateway(self.write_session(session_doc("a2")))
        self.run_messages(gateway, [call(1, "retrieve", {"keywords": ["quorum"]})])
        request = self.entries("decision")[0]["request"]
        self.assertEqual(request["connector"], {"id": "governed-retrieval", "credential_bearing": False,
                                                "capabilities": ["rag.cite", "rag.retrieve", "rag.search"]})
        self.assertEqual(request["implicates"], [])
        broader = ["rag.retrieve", "epap.evidence_chain"]
        _, decision = gateway.evaluate("rag.retrieve", "corpus:governance-doctrine", broader)
        self.assertEqual((decision.disposition, decision.stop_condition), (D.DENY, 1))

    def test_a_denied_acl_path_is_an_abstention_not_a_read(self):
        self.doctrine_corpus()
        self.write("governance/doctrine/api-token.md", doc("Token", "quorum"))
        gateway = self.gateway(self.write_session(session_doc("a2")))
        responses = self.run_messages(gateway, [call(1, "cite", {"path": "governance/doctrine/api-token.md"})])
        body = responses[0]["result"]["structuredContent"]
        self.assertEqual(body["result"]["stop_reason"], "ACL_SCOPE_FAILURE")
        self.assertEqual(body["citations"], [])


class SecretsBoundaryTests(GatewayCase):
    """Every tool result passes the secrets boundary's context check before the agent sees it."""

    TOKEN = "gh" + "p_" + "R" * 36

    def call_retrieve(self, query="where is the quorum rule"):
        # Results point at sources (path, span, hash) and echo the request; the echo is what can carry a secret.
        self.write("governance/doctrine/ALPHA-001.md", doc("Alpha doctrine", "the quorum rule for reviews"))
        gateway = self.gateway(self.write_session(session_doc("a2")))
        arguments = {"keywords": ["quorum"], "query": query}
        return self.run_messages(gateway, [initialize(), INITIALIZED, call(2, "retrieve", arguments)])[1]

    def test_a_secret_in_a_result_is_redacted_and_the_decision_logged(self):
        response = self.call_retrieve(f"quorum rule; deploy key {self.TOKEN}")
        result = response["result"]
        self.assertFalse(result["isError"], result)
        self.assertNotIn(self.TOKEN, json.dumps(response))
        self.assertIn("[REDACTED:github-token:", result["content"][0]["text"])
        self.assertEqual(json.loads(result["content"][0]["text"]), result["structuredContent"])
        (entry,) = self.entries("boundary")
        self.assertEqual(entry["record"]["checkpoint"], "context")
        self.assertTrue(entry["record"]["allow"])
        self.assertEqual([f["rule"] for f in entry["record"]["findings"]], ["github-token"])
        self.assertNotIn(self.TOKEN, (self.evidence / server.DECISIONS_FILE).read_text())

    def test_a_clean_result_is_unchanged_and_still_logged(self):
        response = self.call_retrieve()
        self.assertEqual(response["result"]["structuredContent"]["disposition"], "ALLOW")
        (entry,) = self.entries("boundary")
        self.assertEqual(entry["record"]["findings"], [])

    def test_a_boundary_failure_withholds_the_result(self):
        from unittest import mock
        with mock.patch.object(server.boundary.detector, "scan", side_effect=RuntimeError("down")):
            response = self.call_retrieve()
        result = response["result"]
        self.assertTrue(result["isError"], result)
        self.assertNotIn("ALLOW", json.dumps(result), "no result reaches the agent")
        self.assertEqual(self.log(), [], "the evidence log refuses unchecked entries, so the call is refused first")


class ShippedDataTests(unittest.TestCase):
    def test_policy_adds_mission_seats_and_read_only_mission_grants(self):
        policy = P.load_file()
        self.assertEqual(policy["policy_version"], "MCP-AUTH-POLICY-2026-10-28.1")
        self.assertEqual(policy["authority_refs"]["MISSION-ROUTER-001"],
                         {"kind": "HITL", "source": "tools/agent_workflow/specs/MISSION-ROUTER-001.md",
                          "missions": []})
        self.assertEqual(policy["principals"], {
            "a2": {"kind": "agent", "acting_identities": ["a2"], "roles": ["BUILDER"]},
            "a3": {"kind": "agent", "acting_identities": ["a3"], "roles": ["REVIEWER"]}})
        grants = {g["id"]: g for g in policy["grants"]}
        mission_grants = sorted(g["id"] for g in policy["grants"] if g["authority_ref"] == "MISSION-ROUTER-001")
        self.assertEqual(mission_grants, ["G-MISSION-BUILDER-EPAP-READ", "G-MISSION-BUILDER-RAG-READ",
                                          "G-MISSION-REVIEWER-EPAP-READ", "G-MISSION-REVIEWER-RAG-READ"])
        for gid in mission_grants:
            twin = grants[gid.replace("G-MISSION-", "G-")]
            mine = dict(grants[gid])
            self.assertEqual(mine.pop("authority_ref"), "MISSION-ROUTER-001")
            self.assertEqual({k: v for k, v in mine.items() if k != "id"},
                             {k: v for k, v in twin.items() if k not in ("id", "authority_ref")})
            for action in mine["actions"]:
                self.assertEqual(policy["actions"][action]["kind"], "read")
        self.assertEqual(policy["missions"], {})

    def test_registry_adds_the_epap_evidence_corpus(self):
        data = json.loads(corpus_mod.default_registry_path().read_text(encoding="utf-8"))
        self.assertEqual(data["registry_version"], "retrieval-corpus-2026-10-29.1")
        self.assertEqual([c["id"] for c in data["corpora"]], ["corpus:governance-doctrine", "corpus:epap-evidence"])
        self.assertEqual(data["corpora"][1], {
            "id": "corpus:epap-evidence",
            "roots": ["EPAP/EVIDENCE/**/*.md"],
            "deny_patterns": ["*.pem", "*.key", "*secret*", "*token*", "*credential*", "id_rsa*", ".env*"],
            "authority": {"EPAP/EVIDENCE/": "evidence"},
            "vocabulary": {}})
        self.assertEqual(data["corpora"][1]["deny_patterns"], data["corpora"][0]["deny_patterns"])


if __name__ == "__main__":
    unittest.main()


class TraceTests(GatewayCase):
    """``trace``: the evidence graph's answer for one file, through the fabric like every other tool."""

    def setUp(self):
        super().setUp()
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import test_evidence_graph as EG
        from evidence_graph import history as H

        self.EG = EG
        (self.outside / "fixture").mkdir()
        self.fx = EG.Fixture(self.outside / "fixture")
        seed = self.fx.seed()
        self.mission = self.fx.mission(seed)
        side = self.fx.commit(EG.HITL, "hand edit", self.mission["landing"], {EG.APP: "hand\n"})
        self.hand = self.fx.merge(EG.HITL, "Merge pull request #7 from hitl-user/hand-edit",
                                  self.mission["landing"], side)
        self.fx.set_main(self.hand)
        # The dispatcher's layout: the git dir lies outside the work tree, which has no .git of its own.
        self.git_dir = self.outside / "git"
        (self.fx.root / ".git").rename(self.git_dir)
        self.root = self.fx.root
        ids = H.load_identities(str(self.fx.config))
        isolated = {k: self.fx.env[k] for k in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM")}
        for patcher in (mock.patch.object(H, "load_identities", lambda path=None: ids),
                        mock.patch.dict(os.environ, isolated)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def trace(self, arguments, seat="a2", **kw):
        session_path = self.write_session(session_doc(seat))
        responses = self.run_messages(self.gateway(session_path, **kw),
                                      [initialize(), INITIALIZED, call(2, "trace", arguments)])
        return responses[1]

    def test_trace_names_every_change_to_a_file_newest_first_through_a_separate_git_dir(self):
        result = self.trace({"path": self.EG.APP}, git_dir=self.git_dir)["result"]
        self.assertFalse(result["isError"], result)
        body = result["structuredContent"]
        self.assertEqual(body["grant"], "G-MISSION-BUILDER-EPAP-READ")
        self.assertEqual(body["result"]["schema"], server.TRACE_SCHEMA)
        self.assertEqual(body["result"]["head"], self.hand)
        changes = body["result"]["changes"]
        self.assertEqual([c["kind"] for c in changes], ["hand_merge", "mission", "direct"])
        self.assertEqual(changes[0], {"kind": "hand_merge", "commit": self.hand, "pr": 7, "independent_review": "none"})
        landing = changes[1]
        self.assertEqual((landing["mission"], landing["commit"], landing["plan"]),
                         (self.EG.MID, self.mission["landing"], self.mission["plan"]))
        self.assertEqual((landing["approval"], landing["verdict"], landing["reviewed_sha"], landing["proven"]),
                         ("router", "PASS", self.mission["merges"][1], True))
        self.assertEqual(landing["specs"], ["docs/specs/DEMO-SPEC-001.md"])
        self.assertEqual(len(body["lines"]), 3)
        self.assertTrue(body["lines"][0].startswith("hand-merge #7 "), body["lines"])
        self.assertTrue(body["lines"][1].startswith(f"mission {self.EG.MID} landing "), body["lines"])
        traces = self.entries("trace")
        self.assertEqual(len(traces), 1)
        self.assertEqual((traces[0]["path"], traces[0]["head"], traces[0]["changes"]), (self.EG.APP, self.hand, 3))
        self.assertEqual(self.entries("decision")[0]["record"]["disposition"], "ALLOW")
        self.assertEqual(len(self.entries("boundary")), 1)

    def test_reviewer_seat_may_trace_too(self):
        result = self.trace({"path": self.EG.APP}, seat="a3", git_dir=self.git_dir)["result"]
        self.assertFalse(result["isError"], result)
        self.assertEqual(result["structuredContent"]["grant"], "G-MISSION-REVIEWER-EPAP-READ")

    def test_a_path_that_never_changed_has_no_changes(self):
        result = self.trace({"path": "no/such/file.py"}, git_dir=self.git_dir)["result"]
        self.assertFalse(result["isError"], result)
        self.assertEqual(result["structuredContent"]["result"]["changes"], [])

    def test_no_history_is_refused_and_logged(self):
        result = self.trace({"path": self.EG.APP})["result"]  # no git dir, and the work tree has no .git
        self.assertTrue(result["isError"], result)
        self.assertIn("trace failed (GitError)", result["content"][0]["text"])
        self.assertEqual([e["reason"] for e in self.entries("trace_error")], ["GitError"])
        self.assertEqual(self.entries("trace"), [])

    def test_trace_needs_exactly_a_path(self):
        for arguments in ({}, {"path": self.EG.APP, "keywords": ["x"]}, {"path": 7}):
            with self.subTest(arguments=arguments):
                response = self.trace(arguments, git_dir=self.git_dir)
                self.assertEqual(response["error"]["code"], -32602, response)

    def test_a_git_dir_that_is_not_a_directory_refuses_to_start(self):
        with self.assertRaises(server.GatewayError):
            self.gateway(self.write_session(session_doc("a2")), git_dir=self.outside / "missing")
