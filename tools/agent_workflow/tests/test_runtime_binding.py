"""Tests for the runtime tool binding (RUNTIME-TOOL-BINDING-SPEC-001).

One named case per predicted vector (P1-P7, with P4a and P5a), plus hardening
cases. Every case builds its own checkout and keeps the session file and the
evidence directory outside it; none reads ``governance/doctrine/`` or ``EPAP/``.
"""

from __future__ import annotations

import copy
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import tool_selection.matrix as M
import tool_selection.records as R
from epap import ed25519, links, signing
from mcp_gateway import server
from mcp_gateway import session as GS
from mission_dispatch import binding as dispatch_binding

RB = None  # tool_selection.runtime_binding, imported for this module's tests only (see setUpModule)


def setUpModule():
    # Imported here, not at module level: unittest discovery imports every test module before any test runs, and a
    # module-level import would leave tool_selection.runtime_binding loaded, so the dispatcher's "binding library
    # missing" case in test_mission_dispatch could no longer make the import fail.
    global RB
    import tool_selection.runtime_binding as RB


def tearDownModule():
    import tool_selection

    sys.modules.pop("tool_selection.runtime_binding", None)
    if hasattr(tool_selection, "runtime_binding"):
        delattr(tool_selection, "runtime_binding")


AW = Path(__file__).resolve().parents[1]
PKG = AW / "tool_selection"
NOW = 1_800_000_000
MISSION_ID = "M-TEST-BIND-001"
BASE_SHA = "0123456789abcdef0123456789abcdef01234567"
SEATS = ("A2", "A3")
GATEWAY_TOOLS = ("retrieve", "search", "cite", "evidence_chain", "artifact_status", "trace")
NEVER = ("Bash", "WebFetch", "WebSearch", "Task", "NotebookEdit")
PRINCIPAL = {"A2": "a2", "A3": "a3"}

V1_WRITER_ADMIT = ["file_edit", "branch_create", "commit", "pr_create", "local_test", "artifact_create",
                   "doctrine_draft", "architecture_map"]
V1_REVIEWER_ADMIT = ["repo_read", "diff_review", "evidence_inspect", "doctrine_lookup", "benchmark_review",
                     "disposition_draft"]
D2_WRITER = ["repo_read", "doctrine_lookup", "corpus_search", "citation_extract", "artifact_lookup"]
D2_REVIEWER = ["corpus_search", "citation_extract", "artifact_lookup"]


def mission(seat="A2", **overrides):
    doc = {"id": MISSION_ID, "round": 1, "agent": PRINCIPAL[seat], "base_sha": BASE_SHA,
           "build_scope": ["tools/demo/**"]}
    doc.update(overrides)
    return doc


class Base(unittest.TestCase):
    def setUp(self):
        checkout = tempfile.TemporaryDirectory()
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(checkout.cleanup)
        self.addCleanup(outside.cleanup)
        self.checkout = Path(checkout.name)
        self.outside = Path(outside.name)
        self.session_path = self.outside / "session.json"
        self.evidence = self.outside / "evidence"
        self.evidence.mkdir()

    def bind(self, seat="A2", runtime="claude-code", mission_doc=None, session_path=None, evidence=None, now=NOW):
        return RB.bind(seat, runtime, mission(seat) if mission_doc is None else mission_doc, self.checkout,
                       self.session_path if session_path is None else session_path,
                       self.evidence if evidence is None else evidence, AW, now)

    def all_bindings(self):
        for seat in SEATS:
            for runtime in RB.RUNTIMES:
                yield seat, runtime, self.bind(seat, runtime)

    def assertRefused(self, **kw):
        result = None
        with self.assertRaises(RB.BindingRefused):
            result = self.bind(**kw)
        self.assertIsNone(result)
        self.assertFalse(self.session_path.exists())


class SpecVectors(Base):
    def test_vector1_a2_claude_code_binds_todays_surface_and_the_gateway(self):
        b = self.bind("A2", "claude-code")
        self.assertEqual(b.tools, ("Read", "Edit", "Write", "Glob", "Grep"))
        self.assertEqual(b.allowed_rules, ["Read(**)", "Edit(**)"])
        self.assertEqual(b.denied_rules, [])
        self.assertEqual(set(b.mcp_tools), set(GATEWAY_TOOLS))
        self.assertEqual(len(b.mcp_tools), 6)
        text = json.dumps([b.tools, b.allowed_rules, b.denied_rules, b.mcp_tools, b.session, b.audit])
        for name in NEVER:
            self.assertNotIn(name, text)

    def test_vector2_a3_has_no_file_edit_and_edits_only_its_reviews(self):
        for runtime in RB.RUNTIMES:
            with self.subTest(runtime=runtime):
                b = self.bind("A3", runtime)
                record = b.audit["byproducts"]["selection"]
                self.assertNotIn("Edit", b.tools)
                self.assertEqual([r for r in b.allowed_rules if r.startswith("Edit(")],
                                 [f"Edit(missions/{MISSION_ID}/reviews/**)"])
                self.assertIn("Read(**)", b.allowed_rules)
                self.assertEqual(set(b.mcp_tools), set(GATEWAY_TOOLS))
                admitted = {c["capability"] for c in record["candidates"] if c["outcome"] == R.ADMIT}
                self.assertNotIn("file_edit", admitted)
                mutation = [c for c in record["candidates"] if c["evidence_class"] in M.MUTATION_CLASSES]
                self.assertEqual({c["tool"] for c in mutation}, {"Edit", "Write"})
                for cand in mutation:
                    self.assertEqual((cand["outcome"], cand["rule"]), (R.DENY, "WRITER_REVIEWER_SEPARATION"))
                    self.assertIn("WRITER_REVIEWER_SEPARATION", cand["reason"])

    def test_vector3_unknown_seat_runtime_or_non_admitting_selection_is_refused(self):
        for seat in ("A1", "a2", "", None, ["A2"]):
            with self.subTest(seat=seat):
                self.assertRefused(seat=seat, mission_doc=mission("A2"))
        for runtime in ("codex", "", None, "Claude-Code"):
            with self.subTest(runtime=runtime):
                self.assertRefused(runtime=runtime)

        # A registry entry whose resource cannot resolve falls back: BOUNDED_CLARIFICATION, not an admitted surface.
        doc = json.loads(RB.REGISTRY_PATH.read_text(encoding="utf-8"))
        doc["tools"][0]["resource"] = {"repo": "checkout"}
        registry = self.outside / "registry.json"
        registry.write_text(json.dumps(doc), encoding="utf-8")
        with mock.patch.object(RB, "REGISTRY_PATH", registry):
            self.assertRefused()

        # An unavailable matrix stops the selection fail-closed.
        with mock.patch.object(M, "DEFAULT_PATH", self.outside / "absent.json"):
            self.assertRefused()

        # A selection that stops is refused even when the selector is the one that stops.
        stopped = mock.Mock(disposition=R.STOP_AND_FAIL_CLOSED, reason="stopped", surface=frozenset())
        with mock.patch.object(RB.S, "select", return_value=stopped):
            self.assertRefused()

    def test_vector4_session_or_evidence_inside_the_checkout_is_refused(self):
        inside = self.checkout / "nested"
        inside.mkdir()
        for session_path in (self.checkout / "session.json", inside / "session.json", self.checkout):
            with self.subTest(session_path=session_path):
                self.assertRefused(session_path=session_path)
        for evidence in (self.checkout, inside, self.checkout / "evidence"):
            with self.subTest(evidence=evidence):
                self.assertRefused(evidence=evidence)
        # A sibling whose name only starts with the checkout's is outside it.
        sibling = self.checkout.parent / (self.checkout.name + "-binding")
        self.assertIsNotNone(self.bind(session_path=sibling / "session.json", evidence=self.evidence))

    def test_vector4a_session_is_exact_accepted_by_the_gateway_and_allows_search(self):
        for seat, runtime, b in self.all_bindings():
            with self.subTest(seat=seat, runtime=runtime):
                fabric = {"A2": "BUILDER", "A3": "REVIEWER"}[seat]
                self.assertEqual(b.session, {
                    "principal": PRINCIPAL[seat], "acting_identity": PRINCIPAL[seat], "role": fabric,
                    "mission": {"id": MISSION_ID, "authority_ref": "MISSION-ROUTER-001", "base_sha": BASE_SHA,
                                "round": 1},
                    "resources": ["corpus:governance-doctrine", "index:epap-evidence"],
                    "issued_at": NOW, "expires_at": NOW + 3600})
                self.session_path.write_text(json.dumps(b.session), encoding="utf-8")
                session = GS.load(self.session_path, self.checkout)
                self.assertTrue(session.live_at(NOW))
                self.assertFalse(session.live_at(NOW + 3600))
                gateway = server.Gateway(self.checkout, self.session_path, self.evidence, clock=lambda: NOW)
                self.assertIsNone(gateway.session_problem)
                _, decision = gateway.evaluate("rag.search", "corpus:governance-doctrine", ["rag.search"], NOW)
                self.assertTrue(decision.allowed, decision.record)
                self.session_path.unlink()

    def test_vector4a_agent_other_than_the_seat_principal_is_refused(self):
        for seat, other in (("A2", "a3"), ("A3", "a2"), ("A2", "someone")):
            with self.subTest(seat=seat, agent=other):
                self.assertRefused(seat=seat, mission_doc=mission(seat, agent=other))

    def test_vector5_bound_tools_are_a_subset_of_the_admitted_set(self):
        for seat, runtime, b in self.all_bindings():
            with self.subTest(seat=seat, runtime=runtime):
                record = b.audit["byproducts"]["selection"]
                admitted = set(record["admitted_surface"])
                self.assertEqual(R.reconstruct_surface(record), admitted)
                runtime_names = {name.split(":", 1)[0] for name in admitted}
                bound = set(b.tools) | {RB.GATEWAY_PREFIX + t for t in b.mcp_tools}
                self.assertLessEqual(bound, runtime_names)
                self.assertLessEqual(set(b.audit["byproducts"]["binding"]["tool_map"]), admitted)
                self.assertLessEqual(admitted, set(record["pre_fallback_surface"]))

    def test_vector5a_dispatcher_ceiling_accepts_every_binding(self):
        for seat, runtime, b in self.all_bindings():
            with self.subTest(seat=seat, runtime=runtime):
                tools, allowed, denied, mcp_tools = dispatch_binding.check(
                    b.tools, b.allowed_rules, b.denied_rules, b.mcp_tools)
                self.assertEqual(tools, b.tools)
                self.assertEqual(list(allowed), b.allowed_rules)
                self.assertEqual(mcp_tools, b.mcp_tools)
                for rule in b.allowed_rules:
                    self.assertFalse(rule.split("(", 1)[1].startswith(("/", "~")))
                    self.assertNotIn("..", rule)

    def test_vector6_audit_reconstructs_the_surface_and_signs_as_an_epap_link(self):
        matrix = M.load_file()
        for seat, runtime, b in self.all_bindings():
            with self.subTest(seat=seat, runtime=runtime):
                audit = json.loads(signing.canonical_bytes(b.audit))
                self.assertEqual(audit, b.audit)
                self.assertEqual(audit["name"], "RUNTIME_BINDING")
                self.assertIsNone(links.link_problem(audit))
                by = audit["byproducts"]
                row = {"A2": ("writer", "IMPLEMENT"), "A3": ("reviewer", "VERIFY")}[seat]
                self.assertEqual((by["seat"], by["runtime"], by["role"], by["mission_type"]), (seat, runtime) + row)
                self.assertEqual(by["matrix_version"], "doctrine-s4-v2")
                record = by["selection"]
                self.assertIsNone(R.record_problem(record))
                self.assertEqual(record["matrix_version"], "doctrine-s4-v2")
                self.assertEqual(record["disposition"], R.ADMITTED)
                for cand in record["candidates"]:
                    self.assertIn(cand["outcome"], (R.ADMIT, R.DENY))
                    self.assertTrue(cand["reason"])
                # The bound surface follows from the per-tool outcomes alone.
                admitted = R.reconstruct_surface(record)
                self.assertEqual({by["binding"]["tool_map"][n] for n in admitted},
                                 set(b.tools) | set(b.mcp_tools))
                self.assertEqual(by["binding"]["tools"], list(b.tools))
                self.assertEqual(by["binding"]["allowed_rules"], b.allowed_rules)
                self.assertEqual(by["binding"]["session"], b.session)
                self.assertLessEqual(set(audit["materials"]), set(audit["products"]))
                matrix_path = f"tool_selection/matrix/{R.digest(matrix)}.json"
                self.assertEqual(audit["materials"][matrix_path]["sha256"], R.digest(matrix))
                seed = bytes(range(32))
                block = signing.sign_metablock(audit, PRINCIPAL[seat], seed)
                self.assertIsNone(links.metablock_problem(block))
                self.assertIsNone(links.link_problem(block["signed"]))
                self.assertTrue(signing.signature_valid(ed25519.public_key(seed).hex(), block["signed"],
                                                        block["signatures"][0]["sig"]))

    def test_vector7_matrix_differs_from_v1_exactly_by_d2(self):
        matrix = M.load_file()
        self.assertEqual(matrix["matrix_version"], "doctrine-s4-v2")
        rows = matrix["roles"]
        self.assertEqual(rows["writer"]["admit"], V1_WRITER_ADMIT + D2_WRITER)
        self.assertEqual(rows["reviewer"]["admit"], V1_REVIEWER_ADMIT + D2_REVIEWER)
        self.assertEqual(rows["router"]["admit"], ["artifact_lookup", "doctrine_lookup", "evidence_class_routing",
                                                   "citation_extract", "corpus_search"])
        self.assertTrue(all(matrix["capabilities"][c] == "read" for c in D2_WRITER + D2_REVIEWER))
        self.assertEqual(sorted(rows["writer"]["blocked"]),
                         ["credential_access", "merge", "production_runtime", "review_disposition", "self_approval"])
        self.assertEqual(sorted(rows["reviewer"]["blocked"]),
                         ["credential_access", "epap_write", "file_edit", "implementation_repair", "merge",
                          "self_approval"])
        self.assertEqual(sorted(rows["router"]["blocked"]),
                         ["epap_write", "implementation_repair", "index_update", "review_disposition"])
        self.assertEqual({r: (rows[r]["read_only"], rows[r]["separation_rule"], rows[r]["evidence_classes"])
                          for r in rows},
                         {"writer": (False, None, ["read", "draft", "write", "execute"]),
                          "reviewer": (True, "WRITER_REVIEWER_SEPARATION", ["read", "draft"]),
                          "router": (True, "ROUTER_NO_MUTATION", ["read"])})
        self.assertEqual(len(matrix["capabilities"]), 26)
        self.assertEqual(matrix["mission_types"]["VERIFY"], ["read", "draft"])
        self.assertEqual(set(matrix["fallback_routes"].values()), {"HITL_GATE", "BOUNDED_CLARIFICATION"})


class Hardening(Base):
    def test_malformed_mission_or_clock_is_refused(self):
        cases = {
            "extra field": mission(extra=1),
            "missing field": {k: v for k, v in mission().items() if k != "build_scope"},
            "round zero": mission(round=0),
            "round bool": mission(round=True),
            "short sha": mission(base_sha="abc"),
            "upper sha": mission(base_sha=BASE_SHA.upper()),
            "id with slash": mission(id="M-1/../x"),
            "id with paren": mission(id="M-1)"),
            "scope not a list": mission(build_scope="tools/**"),
        }
        for name, doc in cases.items():
            with self.subTest(name):
                self.assertRefused(mission_doc=doc)
        for now in (True, -1, 1.5, "1800000000"):
            with self.subTest(now=now):
                self.assertRefused(now=now)

    def test_registry_offers_only_the_dispatchers_tools(self):
        doc = json.loads(RB.REGISTRY_PATH.read_text(encoding="utf-8"))
        names = {t["name"] for t in doc["tools"]}
        self.assertEqual(names, {"Read", "Glob", "Grep", "Edit", "Write", "Write:reviews"}
                         | {RB.GATEWAY_PREFIX + t for t in GATEWAY_TOOLS})
        self.assertEqual({n.split(":", 1)[0] for n in names if not n.startswith("mcp__")}, set(RB.BUILTINS))
        self.assertEqual(set(RB.BUILTINS), set(dispatch_binding.BUILTIN_CEILING))

    def test_admitted_tool_outside_the_runtime_vocabulary_is_refused(self):
        doc = json.loads(RB.REGISTRY_PATH.read_text(encoding="utf-8"))
        extra = copy.deepcopy(doc["tools"][0])
        extra["name"] = "Bash"
        doc["tools"].append(extra)
        registry = self.outside / "registry.json"
        registry.write_text(json.dumps(doc), encoding="utf-8")
        with mock.patch.object(RB, "REGISTRY_PATH", registry):
            self.assertRefused()

    def test_gateway_tool_the_gateway_does_not_serve_is_refused(self):
        root = self.outside / "tooling"
        (root / "mcp_gateway").mkdir(parents=True)
        catalog = json.loads((AW / "mcp_gateway" / "tools.json").read_text(encoding="utf-8"))
        catalog["tools"] = [t for t in catalog["tools"] if t["name"] != "cite"]
        (root / "mcp_gateway" / "tools.json").write_text(json.dumps(catalog), encoding="utf-8")
        with self.assertRaises(RB.BindingRefused):
            RB.bind("A2", "claude-code", mission(), self.checkout, self.session_path, self.evidence, root, NOW)

    def test_binding_is_deterministic(self):
        self.assertEqual(self.bind("A3", "cursor-cli"), self.bind("A3", "cursor-cli"))

    def test_package_layout_and_no_init(self):
        names = sorted(p.name for p in PKG.iterdir() if p.name != "__pycache__")
        self.assertEqual(names, sorted(["IMPLEMENTATION-DECISIONS.md", "matrix.json", "matrix.py", "records.py",
                                        "registry.py", "select.py", "seats.json", "runtime_registry.json",
                                        "runtime_binding.py"]))
        self.assertFalse(list(PKG.rglob("__init__.py")))

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
            Path(__file__).resolve(), AW / "tests" / "test_tool_selection.py"]

        def published(path):
            text = path.read_text(encoding="utf-8")
            for rule in rules:
                text = re.sub(rule["pattern"], lambda m, replace=rule["replace"]: replace, text)
            return text

        hits = [(path.name, number, term.pattern) for path in files
                for number, line in enumerate(published(path).split("\n"), start=1)
                for term in terms if term.search(line)]
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
