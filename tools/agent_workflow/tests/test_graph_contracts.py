from __future__ import annotations

import ast
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import graph_contracts.gates as G
import graph_contracts.schema as S
import graph_contracts.validate as V

PKG = Path(__file__).resolve().parents[1] / "graph_contracts"


def obj(required=None, **props):
    """An object io schema with ``props``; every property is required unless ``required`` says otherwise."""
    return {"type": "object", "properties": props, "required": list(props) if required is None else required}


STR = {"type": "string"}


def gate_io():
    return {"input_schema": obj(head=STR), "output_schema": obj(head=STR)}


def base_contract():
    """A complete, fully typed contract: plan -> build -> check (router) -> review -> approve -> publish."""
    return {
        "schema": "ge-graph-contract-v1",
        "graph_id": "GE-TEST-REVIEW-001",
        "version": "1",
        "entry": "plan",
        "nodes": [
            {"id": "plan", "kind": "DETERMINISTIC_TASK",
             "input_schema": obj(request=STR), "output_schema": obj(request=STR, plan=STR)},
            {"id": "build", "kind": "AGENT_TASK",
             "input_schema": obj(plan=STR), "output_schema": obj(head=STR, plan=STR, summary=STR)},
            {"id": "check", "kind": "ROUTER",
             "input_schema": obj(head=STR, plan=STR),
             "output_schema": obj(head=STR, plan=STR, route={"type": "string", "enum": ["PASS", "REWORK"]})},
            dict(id="review", kind="VERIFICATION_GATE", **gate_io(),
                 gate={"guards": ["build"], "satisfied_by": "INDEPENDENT_REVIEW", "exact_head": True,
                       "session_independent": True, "completion_state": "REVIEW_COMPLETED"}),
            dict(id="approve", kind="HITL_GATE", **gate_io(),
                 gate={"guards": ["build"], "satisfied_by": "HITL", "boundary": "MERGE"}),
            {"id": "publish", "kind": "SUBGRAPH",
             "input_schema": obj(head=STR), "output_schema": obj(receipt=STR),
             "subgraph": {"graph_id": "GE-TEST-PUBLISH-001", "version": "1"}},
        ],
        "edges": [
            {"kind": "static", "from": "plan", "to": "build"},
            {"kind": "static", "from": "build", "to": "check"},
            {"kind": "conditional", "from": "check", "route_key": "route",
             "routes": {"PASS": "review", "REWORK": "build"}},
            {"kind": "static", "from": "review", "to": "approve"},
            {"kind": "static", "from": "approve", "to": "publish"},
        ],
        "state": {
            "scope": "GRAPH_RUN",
            "store": "CONTROL_PLANE",
            "keys": {"head": STR, "receipt": STR},
            "transitions": [
                {"id": "t_head", "node": "build", "writes": ["head"]},
                {"id": "t_receipt", "node": "publish", "writes": ["receipt"]},
            ],
        },
        "artifacts": [
            {"id": "build_summary", "version": 1, "media_type": "text/markdown", "produced_by": "build",
             "role": "EVIDENCE"},
        ],
    }


def contract():
    return copy.deepcopy(base_contract())


def node(doc, node_id):
    return next(n for n in doc["nodes"] if n["id"] == node_id)


def edge(doc, src):
    return next(e for e in doc["edges"] if e["from"] == src)


class ContractCase(unittest.TestCase):
    def assertValid(self, doc):
        result = V.validate(doc)
        self.assertEqual(result.verdict, V.VALID, result.detail)
        self.assertIsNone(result.rule)
        self.assertTrue(result.valid)

    def assertInvalid(self, doc, rule, fragment=None):
        result = V.validate(doc)
        self.assertEqual(result.verdict, V.INVALID)
        self.assertEqual(result.rule, rule, result.detail)
        self.assertFalse(result.valid)
        if fragment is not None:
            self.assertIn(fragment, result.detail)
        return result


class SpecVectorTests(ContractCase):
    """The spec's six predicted vectors (plan P1-P6)."""

    def test_vector1_complete_typed_contract_is_valid(self):
        self.assertValid(contract())

    def test_vector2_self_satisfying_gate_edge_names_no_self_satisfied_gates(self):
        doc = contract()
        doc["edges"].append({"kind": "static", "from": "review", "to": "review"})
        self.assertInvalid(doc, "NO_SELF_SATISFIED_GATES", "into itself")

    def test_vector3_node_missing_io_schema_names_typed_io(self):
        for field in ("input_schema", "output_schema"):
            with self.subTest(field=field):
                doc = contract()
                del node(doc, "build")[field]
                self.assertInvalid(doc, "TYPED_IO", field)

    def test_vector4_route_map_naming_undeclared_node_names_dangling_route_rule(self):
        doc = contract()
        edge(doc, "check")["routes"]["REWORK"] = "ghost"
        self.assertInvalid(doc, "NO_DANGLING_ROUTES", "ghost")

    def test_vector5_artifact_as_state_store_names_artifacts_are_evidence(self):
        doc = contract()
        doc["state"]["store"] = "build_summary"
        self.assertInvalid(doc, "ARTIFACTS_ARE_EVIDENCE", "build_summary")

    def test_vector6_vendor_specific_construct_names_no_vendor_lock_in(self):
        doc = contract()
        node(doc, "build")["kind"] = "LlmAgent"
        self.assertInvalid(doc, "NO_VENDOR_LOCK_IN", "LlmAgent")


class SelfSatisfiedGateTests(ContractCase):
    def test_route_map_into_gate_from_itself(self):
        doc = contract()
        doc["nodes"].append({"id": "triage", "kind": "ROUTER", "input_schema": obj(head=STR),
                             "output_schema": obj(head=STR, route={"type": "string", "enum": ["A"]})})
        doc["edges"].append({"kind": "conditional", "from": "approve", "route_key": "route",
                             "routes": {"A": "approve"}})
        self.assertInvalid(doc, "NO_SELF_SATISFIED_GATES")

    def test_gate_guarding_itself(self):
        doc = contract()
        node(doc, "review")["gate"]["guards"].append("review")
        self.assertInvalid(doc, "NO_SELF_SATISFIED_GATES", "guards itself")

    def test_gate_satisfied_by_node_output(self):
        for gate_id, value in (("review", "build"), ("review", "SELF_CHECK"), ("approve", "build"),
                               ("approve", "ENGINE")):
            with self.subTest(gate=gate_id, satisfied_by=value):
                doc = contract()
                node(doc, gate_id)["gate"]["satisfied_by"] = value
                self.assertInvalid(doc, "NO_SELF_SATISFIED_GATES", "never by node output")

    def test_gates_satisfying_each_other(self):
        doc = contract()
        node(doc, "review")["gate"]["guards"] = ["build", "approve"]
        node(doc, "approve")["gate"]["guards"] = ["review"]
        self.assertInvalid(doc, "NO_SELF_SATISFIED_GATES", "satisfy each other")

    def test_verification_gate_must_be_exact_head_and_session_independent(self):
        for flag in ("exact_head", "session_independent"):
            with self.subTest(flag=flag):
                doc = contract()
                node(doc, "review")["gate"][flag] = False
                self.assertInvalid(doc, "SELF_CHECK_NEVER_EQUALS_INDEPENDENT_REVIEW", flag)

    def test_review_requested_never_completes_a_verification_gate(self):
        for state in G.PENDING_REVIEW_STATES:
            with self.subTest(state=state):
                doc = contract()
                node(doc, "review")["gate"]["completion_state"] = state
                self.assertInvalid(doc, "SELF_CHECK_NEVER_EQUALS_INDEPENDENT_REVIEW", state)

    def test_hitl_gate_boundary_from_gate_table(self):
        for boundary in G.CONSEQUENTIAL_BOUNDARIES:
            with self.subTest(boundary=boundary):
                doc = contract()
                node(doc, "approve")["gate"]["boundary"] = boundary
                self.assertValid(doc)
        doc = contract()
        node(doc, "approve")["gate"]["boundary"] = "WHENEVER"
        self.assertInvalid(doc, "HITL_BOUNDARY")


class TypedIoTests(ContractCase):
    def test_malformed_io_schema(self):
        cases = [
            {"type": "any"},
            {"properties": {}},
            {"type": "object"},
            {"type": "array"},
            {"type": "string", "enum": []},
            {"type": "string", "enum": [1]},
            {"type": "object", "properties": {"a": STR}, "required": ["b"]},
            {"type": "object", "properties": {}, "$ref": "#/defs/x"},
            "string",
        ]
        for bad in cases:
            with self.subTest(schema=bad):
                doc = contract()
                node(doc, "plan")["input_schema"] = bad
                self.assertInvalid(doc, "TYPED_IO")

    def test_edge_carries_value_target_does_not_accept(self):
        doc = contract()
        node(doc, "build")["input_schema"] = obj(plan=STR, budget={"type": "integer"})
        self.assertInvalid(doc, "TYPED_IO", "input_schema of build")

    def test_closed_input_rejects_open_output(self):
        doc = contract()
        node(doc, "build")["input_schema"]["additionalProperties"] = False
        self.assertInvalid(doc, "TYPED_IO")

    def test_description_is_allowed_and_never_interpreted(self):
        doc = contract()
        doc["description"] = "Uses ADK and LangGraph vocabulary as naming reference only."
        node(doc, "build")["description"] = "Builder seat; runtime is not bound (not a Gemini or GPT binding)."
        node(doc, "build")["input_schema"]["description"] = "Plan text from the planner."
        self.assertValid(doc)


class RoutingTests(ContractCase):
    def test_static_edge_to_undeclared_node(self):
        doc = contract()
        edge(doc, "approve")["to"] = "nowhere"
        self.assertInvalid(doc, "NO_DANGLING_ROUTES", "nowhere")

    def test_undeclared_entry(self):
        doc = contract()
        doc["entry"] = "start"
        self.assertInvalid(doc, "NO_DANGLING_ROUTES", "start")

    def test_route_map_must_be_total_over_route_key(self):
        doc = contract()
        del edge(doc, "check")["routes"]["REWORK"]
        self.assertInvalid(doc, "DETERMINISTIC_ROUTING", "route-map labels")

    def test_route_key_must_be_typed_router_output(self):
        doc = contract()
        edge(doc, "check")["route_key"] = "verdict"
        self.assertInvalid(doc, "DETERMINISTIC_ROUTING", "route_key")
        doc = contract()
        node(doc, "check")["output_schema"]["properties"]["route"] = STR
        self.assertInvalid(doc, "DETERMINISTIC_ROUTING", "string enum")

    def test_conditional_edge_only_from_router(self):
        doc = contract()
        doc["edges"][0] = {"kind": "conditional", "from": "plan", "route_key": "plan", "routes": {"x": "build"}}
        self.assertInvalid(doc, "DETERMINISTIC_ROUTING", "must leave a router")

    def test_router_with_static_edge(self):
        doc = contract()
        doc["edges"].append({"kind": "static", "from": "check", "to": "review"})
        self.assertInvalid(doc, "DETERMINISTIC_ROUTING")

    def test_non_router_with_two_static_successors(self):
        doc = contract()
        doc["edges"].append({"kind": "static", "from": "plan", "to": "check"})
        self.assertInvalid(doc, "DETERMINISTIC_ROUTING", "at most one")

    def test_empty_route_map(self):
        doc = contract()
        edge(doc, "check")["routes"] = {}
        self.assertInvalid(doc, "DETERMINISTIC_ROUTING")

    def test_unreachable_node(self):
        doc = contract()
        doc["nodes"].append({"id": "orphan", "kind": "DETERMINISTIC_TASK",
                             "input_schema": obj(head=STR), "output_schema": obj(head=STR)})
        self.assertInvalid(doc, "REACHABILITY", "orphan")

    def test_node_that_cannot_reach_a_terminal(self):
        doc = contract()
        doc["nodes"].append({"id": "spin", "kind": "DETERMINISTIC_TASK",
                             "input_schema": obj(head=STR), "output_schema": obj(head=STR)})
        node(doc, "check")["output_schema"]["properties"]["route"]["enum"].append("SPIN")
        edge(doc, "check")["routes"]["SPIN"] = "spin"
        doc["edges"].append({"kind": "static", "from": "spin", "to": "spin"})
        self.assertInvalid(doc, "REACHABILITY", "cannot reach a terminal")

    def test_graph_without_terminal(self):
        doc = contract()
        doc["edges"].append({"kind": "static", "from": "publish", "to": "plan"})
        self.assertInvalid(doc, "REACHABILITY", "no terminal")


class StateAndArtifactTests(ContractCase):
    def test_artifact_store_prefix(self):
        doc = contract()
        doc["state"]["store"] = "artifact:run-log"
        self.assertInvalid(doc, "ARTIFACTS_ARE_EVIDENCE")

    def test_artifact_role_must_be_evidence(self):
        doc = contract()
        doc["artifacts"][0]["role"] = "STATE"
        self.assertInvalid(doc, "ARTIFACTS_ARE_EVIDENCE", "STATE")

    def test_artifact_as_state_key_or_transition_target(self):
        doc = contract()
        doc["state"]["keys"]["build_summary"] = STR
        self.assertInvalid(doc, "ARTIFACTS_ARE_EVIDENCE")
        doc = contract()
        doc["state"]["transitions"][0]["writes"] = ["build_summary"]
        self.assertInvalid(doc, "ARTIFACTS_ARE_EVIDENCE")

    def test_state_store_must_be_control_plane(self):
        doc = contract()
        doc["state"]["store"] = "LOCAL_FILE"
        self.assertInvalid(doc, "STATE_VIA_TRANSITIONS", "CONTROL_PLANE")

    def test_state_scope(self):
        for scope in ("GRAPH_RUN", "CROSS_RUN", "TENANT"):
            with self.subTest(scope=scope):
                doc = contract()
                doc["state"]["scope"] = scope
                self.assertValid(doc)
        doc = contract()
        doc["state"]["scope"] = "GLOBAL"
        self.assertInvalid(doc, "STATE_VIA_TRANSITIONS")

    def test_transition_writes_undeclared_key(self):
        doc = contract()
        doc["state"]["transitions"][0]["writes"] = ["verdict"]
        self.assertInvalid(doc, "STATE_VIA_TRANSITIONS", "undeclared")

    def test_transition_write_must_be_typed_node_output(self):
        doc = contract()
        doc["state"]["transitions"][0]["node"] = "plan"
        self.assertInvalid(doc, "STATE_VIA_TRANSITIONS", "typed value")
        doc = contract()
        doc["state"]["keys"]["head"] = {"type": "integer"}
        self.assertInvalid(doc, "STATE_VIA_TRANSITIONS")

    def test_nodes_cannot_write_state_outside_transitions(self):
        doc = contract()
        node(doc, "build")["state_writes"] = ["head"]
        self.assertInvalid(doc, "CONTRACT_SHAPE", "state_writes")

    def test_references(self):
        doc = contract()
        doc["state"]["transitions"][0]["node"] = "ghost"
        self.assertInvalid(doc, "DECLARED_REFERENCES")
        doc = contract()
        doc["artifacts"][0]["produced_by"] = "ghost"
        self.assertInvalid(doc, "DECLARED_REFERENCES")
        doc = contract()
        node(doc, "approve")["gate"]["guards"] = ["ghost"]
        self.assertInvalid(doc, "DECLARED_REFERENCES")
        doc = contract()
        node(doc, "publish")["subgraph"]["graph_id"] = doc["graph_id"]
        self.assertInvalid(doc, "DECLARED_REFERENCES")

    def test_artifact_version(self):
        for version in (0, "1", True, None):
            with self.subTest(version=version):
                doc = contract()
                doc["artifacts"][0]["version"] = version
                self.assertInvalid(doc, "CONTRACT_SHAPE")


class VendorNeutralityTests(ContractCase):
    def test_vendor_constructs_anywhere(self):
        mutations = [
            lambda d: node(d, "build").__setitem__("adk_config", {}),
            lambda d: node(d, "build").__setitem__("kind", "SequentialAgent"),
            lambda d: node(d, "plan").__setitem__("input_schema", {"type": "pydantic.BaseModel"}),
            lambda d: node(d, "publish")["subgraph"].__setitem__("graph_id", "GE-LangGraph-Publish"),
            lambda d: d["state"].__setitem__("store", "VertexAiSessionService"),
            lambda d: d["state"].__setitem__("store", "vertex_ai_sessions"),
            lambda d: node(d, "build")["output_schema"]["properties"].__setitem__("openai_response", STR),
            lambda d: d["artifacts"][0].__setitem__("media_type", "application/x-gemini-trace"),
            lambda d: node(d, "approve").__setitem__("kind", "RequestInput"),
            lambda d: node(d, "build").__setitem__("model", "gpt-4o"),
        ]
        for i, mutate in enumerate(mutations):
            with self.subTest(case=i):
                doc = contract()
                mutate(doc)
                self.assertInvalid(doc, "NO_VENDOR_LOCK_IN")

    def test_names_spelled_description_get_no_free_text_exemption(self):
        # Round 1 finding: the scan skipped every subtree under a key named 'description', including io-schema
        # property names and state keys, so vendor constructs nested there validated as CONTRACT_VALID.
        nested = obj(openai_response=STR)
        model_enum = {"type": "string", "enum": ["gpt-4o"]}

        def add_property(sub):
            def mutate(d):
                output = node(d, "build")["output_schema"]
                output["properties"]["description"] = sub
                output["required"].append("description")
            return mutate

        def add_state_key(sub):
            return lambda d: d["state"]["keys"].__setitem__("description", sub)

        mutations = {
            "property/nested": (add_property(nested), "openai_response"),
            "property/enum": (add_property(model_enum), "gpt-4o"),
            "state_key/nested": (add_state_key(nested), "openai_response"),
            "state_key/enum": (add_state_key(model_enum), "gpt-4o"),
            "nested_io_property/enum": (
                lambda d: node(d, "build")["input_schema"]["properties"].__setitem__(
                    "plan", obj(description=model_enum, required=[])), "gpt-4o"),
            "non_string_description": (
                lambda d: node(d, "build").__setitem__("description", {"model": "gpt-4o"}), "gpt-4o"),
        }
        for name, (mutate, fragment) in mutations.items():
            with self.subTest(case=name):
                doc = contract()
                mutate(doc)
                self.assertInvalid(doc, "NO_VENDOR_LOCK_IN", fragment)

    def test_names_spelled_description_are_ordinary_names(self):
        doc = contract()
        output = node(doc, "build")["output_schema"]
        output["properties"]["description"] = {"type": "string", "description": "Not a Gemini or GPT binding."}
        output["required"].append("description")
        doc["state"]["keys"]["description"] = STR
        doc["state"]["transitions"][0]["writes"].append("description")
        self.assertValid(doc)

    def test_ordinary_words_are_not_vendor_constructs(self):
        for text in ("request_input", "agent_task", "graph", "vertex", "command", "adkins_review"):
            with self.subTest(text=text):
                self.assertIsNone(V.vendor_hit(text, S.load_file()))

    def test_package_is_standard_library_only(self):
        allowed = {"__future__", "ast", "dataclasses", "json", "pathlib", "re", "typing", "graph_contracts"}
        for path in sorted(PKG.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for stmt in ast.walk(tree):
                if isinstance(stmt, ast.Import):
                    names = [a.name for a in stmt.names]
                elif isinstance(stmt, ast.ImportFrom):
                    names = [stmt.module or ""]
                else:
                    continue
                for name in names:
                    with self.subTest(file=path.name, module=name):
                        self.assertIn(name.split(".")[0], allowed)

    def test_namespace_package_has_no_init(self):
        self.assertEqual(list(PKG.rglob("__init__.py")), [])


class ShapeTests(ContractCase):
    def test_not_an_object(self):
        for doc in (None, [], "contract", 1):
            with self.subTest(doc=doc):
                self.assertInvalid(doc, "CONTRACT_SHAPE")

    def test_envelope(self):
        doc = contract()
        doc["graph_id"] = "WF-TEST-001"
        self.assertInvalid(doc, "CONTRACT_SHAPE", "GE-")
        doc = contract()
        doc["schema"] = "graph-v0"
        self.assertInvalid(doc, "CONTRACT_SHAPE")
        doc = contract()
        doc["production_ready"] = True
        self.assertInvalid(doc, "CONTRACT_SHAPE", "production_ready")
        doc = contract()
        del doc["state"]
        self.assertInvalid(doc, "CONTRACT_SHAPE")
        doc = contract()
        doc["nodes"] = []
        self.assertInvalid(doc, "CONTRACT_SHAPE")

    def test_node_kind(self):
        for kind in ("TASK", None, "agent_task"):
            with self.subTest(kind=kind):
                doc = contract()
                node(doc, "plan")["kind"] = kind
                self.assertInvalid(doc, "NODE_KIND")

    def test_all_six_kinds_present_in_valid_fixture(self):
        self.assertEqual({n["kind"] for n in base_contract()["nodes"]}, set(S.NODE_KINDS))

    def test_duplicate_ids(self):
        doc = contract()
        doc["nodes"].append(copy.deepcopy(node(doc, "plan")))
        self.assertInvalid(doc, "UNIQUE_IDS")
        doc = contract()
        doc["state"]["transitions"].append(copy.deepcopy(doc["state"]["transitions"][0]))
        self.assertInvalid(doc, "UNIQUE_IDS")
        doc = contract()
        doc["artifacts"].append(copy.deepcopy(doc["artifacts"][0]))
        self.assertInvalid(doc, "UNIQUE_IDS")

    def test_gate_fields_are_closed(self):
        doc = contract()
        node(doc, "approve")["gate"]["auto_approve"] = True
        self.assertInvalid(doc, "CONTRACT_SHAPE", "auto_approve")
        doc = contract()
        node(doc, "build")["gate"] = {}
        self.assertInvalid(doc, "CONTRACT_SHAPE")

    def test_every_reported_rule_is_defined_and_result_disclaims_production(self):
        rules = S.load_file()["rules"]
        result = V.validate(contract())
        self.assertIn("not evidence", result.scope)
        doc = contract()
        doc["edges"].append({"kind": "static", "from": "review", "to": "review"})
        self.assertIn(V.validate(doc).rule, rules)

    def test_unexpected_values_fail_closed(self):
        doc = contract()
        node(doc, "plan")["kind"] = ["AGENT_TASK"]
        result = V.validate(doc)
        self.assertEqual(result.verdict, V.INVALID)

    def test_validate_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "contract.json"
            path.write_text(json.dumps(base_contract()), encoding="utf-8")
            self.assertTrue(V.validate_file(path).valid)
            path.write_text('{"schema": "a", "schema": "b"}', encoding="utf-8")
            result = V.validate_file(path)
            self.assertEqual((result.verdict, result.rule), (V.INVALID, "CONTRACT_SHAPE"))
            result = V.validate_file(Path(tmp) / "missing.json")
            self.assertEqual(result.verdict, V.INVALID)

    def test_validation_does_not_mutate_input(self):
        doc = contract()
        V.validate(doc)
        self.assertEqual(doc, base_contract())


class SchemaDataTests(unittest.TestCase):
    def test_shipped_schema_loads(self):
        doc = S.load_file()
        self.assertEqual(set(doc["node_kinds"]), set(S.NODE_KINDS))
        self.assertEqual(set(doc["edge_kinds"]), {"static", "conditional"})
        self.assertEqual(doc["state_store"], "CONTROL_PLANE")
        self.assertEqual(doc["artifact_role"], "EVIDENCE")
        for rule in ("NO_SELF_SATISFIED_GATES", "TYPED_IO", "NO_DANGLING_ROUTES", "ARTIFACTS_ARE_EVIDENCE",
                     "NO_VENDOR_LOCK_IN"):
            self.assertIn(rule, doc["rules"])

    def test_schema_rejects_extra_node_kind(self):
        doc = S.load_file()
        doc["node_kinds"]["LLM_CALL"] = []
        with self.assertRaises(S.SchemaError):
            S.validate(doc)

    def test_schema_rejects_gate_without_satisfied_by(self):
        doc = S.load_file()
        doc["gate_fields"]["HITL_GATE"].remove("satisfied_by")
        with self.assertRaises(S.SchemaError):
            S.validate(doc)


class GateTableTests(unittest.TestCase):
    def setUp(self):
        self.table = G.load_file()

    def test_fourteen_stages_in_order(self):
        self.assertEqual([(s["stage"], s["id"]) for s in self.table["stages"]], list(G.STAGES))
        self.assertTrue(all(s["node_output_satisfies"] is False for s in self.table["stages"]))
        self.assertTrue(all(s["control"] for s in self.table["stages"]))

    def test_independent_review_entry_is_exact_head_and_session_independent(self):
        review = G.review_criteria(self.table)
        self.assertIs(review["exact_head"], True)
        self.assertIs(review["session_independent"], True)
        self.assertIs(review["self_check_satisfies"], False)
        self.assertEqual(review["completion_state"], "REVIEW_COMPLETED")
        self.assertIn("REVIEW_REQUESTED", review["non_completion_states"])

    def test_hitl_entry_covers_consequential_boundaries(self):
        hitl = G.hitl_criteria(self.table)
        self.assertEqual(hitl["satisfied_by"], "HITL")
        for boundary in ("MERGE", "ACTIVATION", "RELIANCE"):
            self.assertIn(boundary, hitl["boundaries"])
        self.assertEqual(G.stage(self.table, "8.12")["control_kind"], "HITL")

    def test_weakened_table_is_rejected(self):
        def review(t):
            return G.stage(t, "8.5")["review"]

        def hitl(t):
            return G.stage(t, "8.6")["hitl"]

        mutations = [
            lambda t: review(t).__setitem__("exact_head", False),
            lambda t: review(t).__setitem__("session_independent", False),
            lambda t: review(t).__setitem__("self_check_satisfies", True),
            lambda t: review(t).__setitem__("completion_state", "REVIEW_REQUESTED"),
            lambda t: review(t)["non_completion_states"].remove("REVIEW_REQUESTED"),
            lambda t: hitl(t)["boundaries"].remove("MERGE"),
            lambda t: hitl(t).__setitem__("satisfied_by", "AGENT"),
            lambda t: G.stage(t, "8.4").__setitem__("node_output_satisfies", True),
            lambda t: G.stage(t, "8.12").__setitem__("control_kind", "POLICY"),
            lambda t: t["stages"].pop(),
            lambda t: t["stages"].reverse(),
        ]
        for i, mutate in enumerate(mutations):
            with self.subTest(case=i):
                table = copy.deepcopy(self.table)
                mutate(table)
                with self.assertRaises(G.GateTableError):
                    G.validate(table)
                with self.assertRaises(G.GateTableError):
                    V.validate(contract(), gates=table)

    def review_evidence(self, **overrides):
        evidence = {"state": "REVIEW_COMPLETED", "reviewed_head": "a" * 40, "head": "a" * 40,
                    "reviewer_session": "a3-session", "builder_session": "a2-session", "self_check": False}
        evidence.update(overrides)
        return evidence

    def test_review_criterion(self):
        self.assertTrue(G.review_criterion_met(self.review_evidence(), self.table)[0])
        failing = [
            {"state": "REVIEW_REQUESTED"},
            {"state": "REVIEW_QUEUED"},
            {"state": "REVIEW_COMMENT_PENDING"},
            {"self_check": True},
            {"reviewer_session": "a2-session"},
            {"reviewed_head": "b" * 40},
            {"reviewed_head": ""},
        ]
        for overrides in failing:
            with self.subTest(**overrides):
                met, reason = G.review_criterion_met(self.review_evidence(**overrides), self.table)
                self.assertFalse(met)
                self.assertTrue(reason)
        self.assertFalse(G.review_criterion_met({"state": "REVIEW_COMPLETED"}, self.table)[0])

    def test_hitl_criterion_never_met_by_node_output(self):
        good = {"boundary": "MERGE", "decided_by": "HITL", "decision": "APPROVED"}
        self.assertTrue(G.hitl_criterion_met(good, self.table)[0])
        for overrides in ({"decided_by": "build"}, {"decided_by": "ENGINE"}, {"decision": "REJECTED"},
                          {"boundary": "LUNCH"}):
            with self.subTest(**overrides):
                self.assertFalse(G.hitl_criterion_met(dict(good, **overrides), self.table)[0])


if __name__ == "__main__":
    unittest.main()
