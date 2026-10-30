"""The GE graph contract validator: accept a contract or reject it, naming the violated rule.

``validate(contract)`` returns a ``Result``: ``CONTRACT_VALID``, or ``INVALID``
with the name of the first rule the contract breaks (a key of the schema's
``rules`` table) and a detail line. Vocabulary comes from the contract schema
(``schema.json``); verification-gate and HITL-gate requirements come from the
gate-criteria table (``gates.json``, stages 8.5 and 8.6).

A ``ge-graph-contract-v1`` document::

    {"schema": "ge-graph-contract-v1", "graph_id": "GE-...", "version": "1",
     "entry": <node id>, "description": <optional prose>,
     "nodes": [{"id", "kind", "input_schema", "output_schema", "description"?,
                "gate"? (HITL_GATE / VERIFICATION_GATE), "subgraph"? (SUBGRAPH)}],
     "edges": [{"kind": "static", "from", "to"}
             | {"kind": "conditional", "from", "route_key", "routes": {label: node id}}],
     "state": {"scope", "store", "keys": {key: io schema},
               "transitions": [{"id", "node", "writes": [key]}]},
     "artifacts": [{"id", "version", "media_type", "produced_by", "role"}]}

Typed I/O schemas are a framework-neutral JSON-Schema subset: ``type`` (one of
the schema's ``io_types``) with ``properties`` / ``required`` /
``additionalProperties`` on objects, ``items`` on arrays and ``enum`` on
scalars, plus optional ``description``.

Checks run in a fixed order and the first violation is reported; the order is
recorded in ``IMPLEMENTATION-DECISIONS.md``. The vendor-neutrality scan runs
right after the top-level type check, over every key and string value except
string-valued free-text ``description`` fields of structural objects, so a
vendor construct is reported as ``NO_VENDOR_LOCK_IN`` wherever it sits. A
property name, state key or route label spelled ``description`` is a name, not
free text, and its subtree is scanned like any other.

A valid contract is a valid *contract* only. It is not evidence that any graph
runtime exists or that any workflow operates in production (directive section
8, non-equivalence rule); every ``Result`` carries that statement in ``scope``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from graph_contracts import gates as G
from graph_contracts import schema as S

VALID = "CONTRACT_VALID"
INVALID = "INVALID"
SCOPE = ("contract validity only: not evidence of a graph runtime, of execution, or of production operation "
         "(directive section 8 non-equivalence rule)")

ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]*$")
SEGMENT_RE = re.compile(r"[^A-Za-z0-9]+")
CAMEL_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")

IO_TYPE_FIELDS = {
    "object": ({"properties"}, {"required", "additionalProperties"}),
    "array": ({"items"}, set()),
    "string": (set(), {"enum"}),
    "integer": (set(), {"enum"}),
    "number": (set(), {"enum"}),
    "boolean": (set(), {"enum"}),
    "null": (set(), set()),
}

# Fields whose object value is a name map: its keys are contract-chosen names (io-schema property names,
# state keys, route labels), so a key there spelled like a free-text field is a name, never free text.
NAME_MAP_FIELDS = frozenset({"properties", "keys", "routes"})


@dataclass(frozen=True)
class Result:
    verdict: str
    rule: Optional[str]
    detail: str
    scope: str = SCOPE

    @property
    def valid(self) -> bool:
        return self.verdict == VALID


class Violation(Exception):
    def __init__(self, rule: str, detail: str):
        super().__init__(f"{rule}: {detail}")
        self.rule = rule
        self.detail = detail


def validate(contract: Any, schema: Optional[dict] = None, gates: Optional[dict] = None) -> Result:
    """Validate ``contract`` against the shipped (or given) contract schema and gate table."""
    schema = S.load_file() if schema is None else S.validate(schema)
    gates = G.load_file() if gates is None else G.validate(gates)
    checker = _Checker(schema, gates)
    try:
        checker.check(contract)
    except Violation as v:
        if v.rule not in schema["rules"]:
            raise AssertionError(f"validator reported {v.rule!r}, which the schema does not define") from None
        return Result(INVALID, v.rule, v.detail)
    except Exception as exc:  # fail closed: a contract the checks cannot evaluate is not valid
        return Result(INVALID, "CONTRACT_SHAPE", f"contract could not be evaluated ({type(exc).__name__})")
    return Result(VALID, None, "contract satisfies every rule in the contract schema")


def validate_file(path: Path, schema: Optional[dict] = None, gates: Optional[dict] = None) -> Result:
    """Validate the strict-JSON contract at ``path``; an unreadable file is ``INVALID``."""
    try:
        contract = S.read_file(path, "contract")
    except ValueError as exc:
        return Result(INVALID, "CONTRACT_SHAPE", str(exc))
    return validate(contract, schema, gates)


def vendor_hit(text: str, schema: dict) -> Optional[str]:
    """The vendor token or construct ``text`` contains, or None."""
    tokens = set(schema["vendor_tokens"])
    constructs = set(schema["vendor_constructs"])
    segments = [s for s in SEGMENT_RE.split(text) if s]
    lowered = [s.lower() for s in segments]
    for seg, low in zip(segments, lowered):
        if seg in constructs:
            return seg
        if low in tokens:
            return low
        for part in CAMEL_RE.findall(seg):
            if part.lower() in tokens:
                return part.lower()
    for a, b in zip(lowered, lowered[1:]):
        if a + b in tokens:
            return a + b
    return None


def accepts(inp: dict, out: dict) -> bool:
    """Whether every value ``out`` admits is admitted by ``inp`` (both well-formed io schemas)."""
    if inp["type"] != out["type"]:
        return False
    kind = inp["type"]
    if kind == "object":
        iprops, oprops = inp["properties"], out["properties"]
        oreq = set(out.get("required", []))
        for name in inp.get("required", []):
            if name not in oprops or name not in oreq:
                return False
        for name, ischema in iprops.items():
            if name in oprops and not accepts(ischema, oprops[name]):
                return False
        if inp.get("additionalProperties", True) is False:
            if out.get("additionalProperties", True) is not False or set(oprops) - set(iprops):
                return False
        return True
    if kind == "array":
        return accepts(inp["items"], out["items"])
    if "enum" in inp:
        return "enum" in out and all(v in inp["enum"] for v in out["enum"])
    return True


def _enum_value_ok(kind: str, value: Any) -> bool:
    if kind == "string":
        return isinstance(value, str)
    if kind == "integer":
        return type(value) is int
    if kind == "number":
        return type(value) in (int, float)
    if kind == "boolean":
        return type(value) is bool
    return False


class _Checker:
    def __init__(self, schema: dict, gates: dict):
        self.schema = schema
        # Each gate kind enforces the criteria of the section 8 stage the schema maps it to.
        self.review = G.stage(gates, schema["gate_stages"]["VERIFICATION_GATE"])["review"]
        self.hitl = G.stage(gates, schema["gate_stages"]["HITL_GATE"])["hitl"]
        self.free = set(schema["free_text_fields"])

    # -- helpers --------------------------------------------------------------------------------------------

    def _fields(self, value: Any, required, where: str, rule: str = "CONTRACT_SHAPE") -> dict:
        required = set(required)
        if not isinstance(value, dict):
            raise Violation(rule, f"{where} must be an object")
        keys = set(value) - self.free
        if keys != required:
            missing, extra = sorted(required - keys), sorted(keys - required)
            raise Violation(rule, f"{where} must have exactly the fields {sorted(required)}"
                                  f" (missing {missing}, unexpected {extra})")
        for name in self.free & set(value):
            if not isinstance(value[name], str):
                raise Violation(rule, f"{where}.{name} must be a string")
        return value

    @staticmethod
    def _id(value: Any, where: str) -> str:
        if not isinstance(value, str) or not ID_RE.match(value):
            raise Violation("CONTRACT_SHAPE", f"{where} must be an identifier matching {ID_RE.pattern}")
        return value

    def _ids(self, value: Any, where: str, allow_empty: bool = False) -> list:
        if not isinstance(value, list) or (not value and not allow_empty):
            raise Violation("CONTRACT_SHAPE", f"{where} must be a {'list' if allow_empty else 'non-empty list'}")
        for i, item in enumerate(value):
            self._id(item, f"{where}[{i}]")
        if len(set(value)) != len(value):
            raise Violation("CONTRACT_SHAPE", f"{where} has duplicate entries")
        return value

    def io_problem(self, value: Any, where: str) -> Optional[str]:
        """Why ``value`` is not a framework-neutral io schema, or None."""
        if not isinstance(value, dict) or "type" not in value:
            return f"{where} must be an object with a 'type'"
        kind = value["type"]
        if kind not in self.schema["io_types"]:
            return f"{where}.type must be one of {self.schema['io_types']}"
        needed, optional = IO_TYPE_FIELDS[kind]
        allowed = ({"type"} | needed | optional) & set(self.schema["io_fields"])
        keys = set(value) - self.free
        if not needed <= keys or not keys <= allowed:
            return f"{where}: a {kind!r} schema has {sorted({'type'} | needed)} and may have {sorted(optional)}"
        if any(not isinstance(value[f], str) for f in self.free & set(value)):
            return f"{where}: free-text fields must be strings"
        if kind == "object":
            props = value["properties"]
            if not isinstance(props, dict):
                return f"{where}.properties must be an object"
            for name, sub in props.items():
                if not isinstance(name, str) or not ID_RE.match(name):
                    return f"{where}.properties: {name!r} is not an identifier"
                problem = self.io_problem(sub, f"{where}.properties.{name}")
                if problem:
                    return problem
            req = value.get("required", [])
            if (not isinstance(req, list) or len(set(map(str, req))) != len(req)
                    or any(r not in props for r in req)):
                return f"{where}.required must list distinct declared properties"
            if "additionalProperties" in value and not isinstance(value["additionalProperties"], bool):
                return f"{where}.additionalProperties must be true or false"
        elif kind == "array":
            return self.io_problem(value["items"], f"{where}.items")
        elif "enum" in value:
            enum = value["enum"]
            if not isinstance(enum, list) or not enum or any(not _enum_value_ok(kind, v) for v in enum):
                return f"{where}.enum must be a non-empty list of {kind} values"
            if len({repr(v) for v in enum}) != len(enum):
                return f"{where}.enum has duplicate values"
        return None

    def _io(self, value: Any, where: str, rule: str = "TYPED_IO") -> dict:
        problem = self.io_problem(value, where)
        if problem:
            raise Violation(rule, problem)
        return value

    # -- the checks, in order -------------------------------------------------------------------------------

    def check(self, contract: Any) -> None:
        if not isinstance(contract, dict):
            raise Violation("CONTRACT_SHAPE", "a contract must be an object")
        self.vendor_neutral(contract, "contract")
        self.envelope(contract)
        nodes = self.nodes(contract["nodes"])
        edges = self.edges(contract["edges"])
        self.references(contract, nodes, edges)
        self.gates(nodes, edges)
        self.routing(nodes, edges)
        self.reachability(contract["entry"], nodes, edges)
        self.edge_types(nodes, edges)
        artifacts = self.artifacts(contract["artifacts"], nodes)
        self.state(contract["state"], nodes, artifacts)

    def vendor_neutral(self, value: Any, where: str, names: bool = False) -> None:
        """Scan ``value`` for vendor constructs; ``names`` marks a name map (see ``NAME_MAP_FIELDS``).

        Only a string-valued free-text field of a structural object is skipped. Every key and subtree of
        a name map is scanned, so a property or state key named ``description`` gets no exemption.
        """
        if isinstance(value, dict):
            for key, sub in value.items():
                if isinstance(key, str):
                    hit = vendor_hit(key, self.schema)
                    if hit:
                        raise Violation("NO_VENDOR_LOCK_IN", f"{where}: field {key!r} is a vendor-specific construct ({hit})")
                if not names and key in self.free and isinstance(sub, str):
                    continue
                self.vendor_neutral(sub, f"{where}.{key}", names=not names and key in NAME_MAP_FIELDS)
        elif isinstance(value, list):
            for i, sub in enumerate(value):
                self.vendor_neutral(sub, f"{where}[{i}]")
        elif isinstance(value, str):
            hit = vendor_hit(value, self.schema)
            if hit:
                raise Violation("NO_VENDOR_LOCK_IN", f"{where}: {value!r} is a vendor-specific construct ({hit})")

    def envelope(self, contract: dict) -> None:
        self._fields(contract, self.schema["contract_fields"], "contract")
        if contract["schema"] != self.schema["contract_schema"]:
            raise Violation("CONTRACT_SHAPE", f"schema must be {self.schema['contract_schema']!r}")
        graph_id = self._id(contract["graph_id"], "graph_id")
        if not graph_id.startswith(self.schema["graph_id_prefix"]):
            raise Violation("CONTRACT_SHAPE", f"graph_id must start with {self.schema['graph_id_prefix']!r}")
        if not S.is_name(contract["version"]):
            raise Violation("CONTRACT_SHAPE", "version must be a non-empty string")
        self._id(contract["entry"], "entry")
        if not isinstance(contract["nodes"], list) or not contract["nodes"]:
            raise Violation("CONTRACT_SHAPE", "nodes must be a non-empty list")
        if not isinstance(contract["edges"], list):
            raise Violation("CONTRACT_SHAPE", "edges must be a list")
        if not isinstance(contract["artifacts"], list):
            raise Violation("CONTRACT_SHAPE", "artifacts must be a list")
        if not isinstance(contract["state"], dict):
            raise Violation("CONTRACT_SHAPE", "state must be an object")
        self.graph_id = graph_id

    def nodes(self, raw: list) -> Dict[str, dict]:
        kinds = self.schema["node_kinds"]
        nodes: Dict[str, dict] = {}
        for i, node in enumerate(raw):
            where = f"nodes[{i}]"
            if not isinstance(node, dict):
                raise Violation("CONTRACT_SHAPE", f"{where} must be an object")
            if node.get("kind") not in kinds:
                raise Violation("NODE_KIND", f"{where}.kind must be one of {list(kinds)}, not {node.get('kind')!r}")
            for io in ("input_schema", "output_schema"):
                if io not in node:
                    raise Violation("TYPED_IO", f"{where} ({node.get('id')!r}) declares no {io}")
            self._fields(node, list(self.schema["node_fields"]) + kinds[node["kind"]], where)
            node_id = self._id(node["id"], f"{where}.id")
            if node_id in nodes:
                raise Violation("UNIQUE_IDS", f"node id {node_id!r} is declared twice")
            nodes[node_id] = node
        for node_id, node in nodes.items():
            for io in ("input_schema", "output_schema"):
                self._io(node[io], f"node {node_id}.{io}")
            if "gate" in node:
                gate = self._fields(node["gate"], self.schema["gate_fields"][node["kind"]], f"node {node_id}.gate")
                self._ids(gate["guards"], f"node {node_id}.gate.guards")
            if "subgraph" in node:
                ref = self._fields(node["subgraph"], self.schema["subgraph_fields"], f"node {node_id}.subgraph")
                self._id(ref["graph_id"], f"node {node_id}.subgraph.graph_id")
                if not ref["graph_id"].startswith(self.schema["graph_id_prefix"]):
                    raise Violation("CONTRACT_SHAPE", f"node {node_id}.subgraph.graph_id must be a GE graph id")
                if not S.is_name(ref["version"]):
                    raise Violation("CONTRACT_SHAPE", f"node {node_id}.subgraph.version must be a non-empty string")
        return nodes

    def edges(self, raw: list) -> List[dict]:
        kinds = self.schema["edge_kinds"]
        for i, edge in enumerate(raw):
            where = f"edges[{i}]"
            if not isinstance(edge, dict) or edge.get("kind") not in kinds:
                raise Violation("CONTRACT_SHAPE", f"{where}.kind must be one of {list(kinds)}")
            self._fields(edge, kinds[edge["kind"]], where)
            self._id(edge["from"], f"{where}.from")
            if edge["kind"] == "static":
                self._id(edge["to"], f"{where}.to")
            else:
                self._id(edge["route_key"], f"{where}.route_key")
                routes = edge["routes"]
                if not isinstance(routes, dict) or not routes:
                    raise Violation("DETERMINISTIC_ROUTING", f"{where}.routes must be a non-empty route-map")
                for label, target in routes.items():
                    if not S.is_name(label):
                        raise Violation("CONTRACT_SHAPE", f"{where}.routes: {label!r} is not a route label")
                    self._id(target, f"{where}.routes[{label}]")
        return raw

    @staticmethod
    def targets(edge: dict) -> List[str]:
        return [edge["to"]] if edge["kind"] == "static" else list(edge["routes"].values())

    def references(self, contract: dict, nodes: Dict[str, dict], edges: List[dict]) -> None:
        if contract["entry"] not in nodes:
            raise Violation("NO_DANGLING_ROUTES", f"entry {contract['entry']!r} is not a declared node")
        for i, edge in enumerate(edges):
            if edge["from"] not in nodes:
                raise Violation("NO_DANGLING_ROUTES", f"edges[{i}].from {edge['from']!r} is not a declared node")
            if edge["kind"] == "static" and edge["to"] not in nodes:
                raise Violation("NO_DANGLING_ROUTES", f"edges[{i}].to {edge['to']!r} is not a declared node")
            if edge["kind"] == "conditional":
                for label, target in edge["routes"].items():
                    if target not in nodes:
                        raise Violation("NO_DANGLING_ROUTES",
                                        f"edges[{i}] route {label!r} names undeclared node {target!r}")
        for node_id, node in nodes.items():
            for guarded in node.get("gate", {}).get("guards", []):
                if guarded not in nodes:
                    raise Violation("DECLARED_REFERENCES", f"gate {node_id} guards undeclared node {guarded!r}")
            if node.get("subgraph", {}).get("graph_id") == self.graph_id:
                raise Violation("DECLARED_REFERENCES", f"subgraph {node_id} references its own graph")

    def gates(self, nodes: Dict[str, dict], edges: List[dict]) -> None:
        gate_ids = {n for n, node in nodes.items() if "gate" in node}
        for i, edge in enumerate(edges):
            if edge["from"] in gate_ids and edge["from"] in self.targets(edge):
                raise Violation("NO_SELF_SATISFIED_GATES",
                                f"edges[{i}] routes gate {edge['from']} into itself: a gate cannot satisfy its own gate")
        principals = {"HITL_GATE": self.hitl["satisfied_by"], "VERIFICATION_GATE": self.review["satisfied_by"]}
        for gate_id in sorted(gate_ids):
            node = nodes[gate_id]
            gate = node["gate"]
            if gate_id in gate["guards"]:
                raise Violation("NO_SELF_SATISFIED_GATES", f"gate {gate_id} guards itself")
            if gate["satisfied_by"] != principals[node["kind"]]:
                raise Violation("NO_SELF_SATISFIED_GATES",
                                f"gate {gate_id} is satisfied by {gate['satisfied_by']!r}; a {node['kind']} is satisfied "
                                f"by {principals[node['kind']]!r} only, never by node output")
        # No ring of gates may satisfy each other: the guard relation among gates is acyclic.
        state: Dict[str, int] = {}

        def visit(gate_id: str, path: List[str]) -> None:
            state[gate_id] = 1
            for guarded in nodes[gate_id]["gate"]["guards"]:
                if guarded not in gate_ids:
                    continue
                if state.get(guarded) == 1:
                    ring = path[path.index(guarded):] + [guarded]
                    raise Violation("NO_SELF_SATISFIED_GATES", f"gates satisfy each other: {' -> '.join(ring)}")
                if guarded not in state:
                    visit(guarded, path + [guarded])
            state[gate_id] = 2

        for gate_id in sorted(gate_ids):
            if gate_id not in state:
                visit(gate_id, [gate_id])

        for gate_id in sorted(gate_ids):
            node, gate = nodes[gate_id], nodes[gate_id]["gate"]
            if node["kind"] == "VERIFICATION_GATE":
                for flag in ("exact_head", "session_independent"):
                    if gate[flag] is not self.review[flag]:
                        raise Violation("SELF_CHECK_NEVER_EQUALS_INDEPENDENT_REVIEW",
                                        f"verification gate {gate_id}: {flag} must be {self.review[flag]!r}")
                if gate["completion_state"] != self.review["completion_state"]:
                    raise Violation("SELF_CHECK_NEVER_EQUALS_INDEPENDENT_REVIEW",
                                    f"verification gate {gate_id} completes on {gate['completion_state']!r}; only "
                                    f"{self.review['completion_state']!r} completes independent review")
            else:
                if gate["boundary"] not in self.hitl["boundaries"]:
                    raise Violation("HITL_BOUNDARY", f"HITL gate {gate_id}: boundary must be one of {self.hitl['boundaries']}")

    def routing(self, nodes: Dict[str, dict], edges: List[dict]) -> None:
        routers = set(self.schema["router_kinds"])
        for i, edge in enumerate(edges):
            if edge["kind"] == "conditional" and nodes[edge["from"]]["kind"] not in routers:
                raise Violation("DETERMINISTIC_ROUTING",
                                f"edges[{i}]: a conditional edge must leave a router, not {edge['from']}")
        for node_id, node in nodes.items():
            out = [e for e in edges if e["from"] == node_id]
            static = [e for e in out if e["kind"] == "static"]
            conditional = [e for e in out if e["kind"] == "conditional"]
            if node["kind"] in routers:
                if len(conditional) != 1 or static:
                    raise Violation("DETERMINISTIC_ROUTING", f"router {node_id} must have exactly one route-map and no static edge")
                self.route_map(node_id, node, conditional[0])
            elif len(static) > 1:
                raise Violation("DETERMINISTIC_ROUTING", f"node {node_id} has {len(static)} static successors; at most one")

    def route_map(self, node_id: str, node: dict, edge: dict) -> None:
        output = node["output_schema"]
        key = edge["route_key"]
        if (output["type"] != "object" or key not in output["properties"]
                or key not in output.get("required", [])):
            raise Violation("DETERMINISTIC_ROUTING", f"router {node_id}: route_key {key!r} must be a required output property")
        prop = output["properties"][key]
        if prop["type"] != "string" or "enum" not in prop:
            raise Violation("DETERMINISTIC_ROUTING", f"router {node_id}: route_key {key!r} must be a string enum")
        if set(prop["enum"]) != set(edge["routes"]):
            raise Violation("DETERMINISTIC_ROUTING",
                            f"router {node_id}: route-map labels {sorted(edge['routes'])} must equal the "
                            f"route_key values {sorted(prop['enum'])}")

    def reachability(self, entry: str, nodes: Dict[str, dict], edges: List[dict]) -> None:
        succ: Dict[str, set] = {n: set() for n in nodes}
        pred: Dict[str, set] = {n: set() for n in nodes}
        for edge in edges:
            for target in self.targets(edge):
                succ[edge["from"]].add(target)
                pred[target].add(edge["from"])

        def closure(start, step):
            seen, todo = set(start), list(start)
            while todo:
                for nxt in step[todo.pop()]:
                    if nxt not in seen:
                        seen.add(nxt)
                        todo.append(nxt)
            return seen

        unreachable = sorted(set(nodes) - closure([entry], succ))
        if unreachable:
            raise Violation("REACHABILITY", f"nodes {unreachable} are not reachable from entry {entry!r}")
        terminals = [n for n in nodes if not succ[n]]
        if not terminals:
            raise Violation("REACHABILITY", "the graph has no terminal node")
        trapped = sorted(set(nodes) - closure(terminals, pred))
        if trapped:
            raise Violation("REACHABILITY", f"nodes {trapped} cannot reach a terminal node")

    def edge_types(self, nodes: Dict[str, dict], edges: List[dict]) -> None:
        for i, edge in enumerate(edges):
            out = nodes[edge["from"]]["output_schema"]
            for target in self.targets(edge):
                if not accepts(nodes[target]["input_schema"], out):
                    raise Violation("TYPED_IO", f"edges[{i}]: output of {edge['from']} does not satisfy the "
                                                f"input_schema of {target}")

    def artifacts(self, raw: list, nodes: Dict[str, dict]) -> Dict[str, dict]:
        artifacts: Dict[str, dict] = {}
        for i, artifact in enumerate(raw):
            where = f"artifacts[{i}]"
            self._fields(artifact, self.schema["artifact_fields"], where)
            artifact_id = self._id(artifact["id"], f"{where}.id")
            if artifact_id in artifacts:
                raise Violation("UNIQUE_IDS", f"artifact id {artifact_id!r} is declared twice")
            if type(artifact["version"]) is not int or artifact["version"] < 1:
                raise Violation("CONTRACT_SHAPE", f"{where}.version must be a positive integer")
            if not S.is_name(artifact["media_type"]):
                raise Violation("CONTRACT_SHAPE", f"{where}.media_type must be a non-empty string")
            if artifact["produced_by"] not in nodes:
                raise Violation("DECLARED_REFERENCES", f"{where}.produced_by {artifact['produced_by']!r} is not a declared node")
            if artifact["role"] != self.schema["artifact_role"]:
                raise Violation("ARTIFACTS_ARE_EVIDENCE",
                                f"artifact {artifact_id} has role {artifact['role']!r}; artifacts are "
                                f"{self.schema['artifact_role']!r} only")
            artifacts[artifact_id] = artifact
        return artifacts

    def state(self, state: dict, nodes: Dict[str, dict], artifacts: Dict[str, dict]) -> None:
        self._fields(state, self.schema["state_fields"], "state")
        store = state["store"]
        if store in artifacts or (isinstance(store, str) and store.lower().startswith("artifact")):
            raise Violation("ARTIFACTS_ARE_EVIDENCE",
                            f"state.store {store!r} is an artifact; artifacts are versioned evidence, never the state store")
        if store != self.schema["state_store"]:
            raise Violation("STATE_VIA_TRANSITIONS", f"state.store must be {self.schema['state_store']!r}")
        if state["scope"] not in self.schema["state_scopes"]:
            raise Violation("STATE_VIA_TRANSITIONS", f"state.scope must be one of {self.schema['state_scopes']}")
        keys = state["keys"]
        if not isinstance(keys, dict):
            raise Violation("CONTRACT_SHAPE", "state.keys must be an object")
        for key, key_schema in keys.items():
            self._id(key, f"state.keys key {key!r}")
            if key in artifacts:
                raise Violation("ARTIFACTS_ARE_EVIDENCE", f"state key {key!r} is an artifact; an artifact is not state")
            self._io(key_schema, f"state.keys.{key}")
        transitions = state["transitions"]
        if not isinstance(transitions, list):
            raise Violation("CONTRACT_SHAPE", "state.transitions must be a list")
        seen = set()
        for i, transition in enumerate(transitions):
            where = f"state.transitions[{i}]"
            self._fields(transition, self.schema["transition_fields"], where)
            transition_id = self._id(transition["id"], f"{where}.id")
            if transition_id in seen:
                raise Violation("UNIQUE_IDS", f"transition id {transition_id!r} is declared twice")
            seen.add(transition_id)
            node_id = transition["node"]
            if node_id not in nodes:
                raise Violation("DECLARED_REFERENCES", f"{where}.node {node_id!r} is not a declared node")
            output = nodes[node_id]["output_schema"]
            for key in self._ids(transition["writes"], f"{where}.writes"):
                if key in artifacts:
                    raise Violation("ARTIFACTS_ARE_EVIDENCE", f"{where} writes artifact {key!r}; artifacts are not state")
                if key not in keys:
                    raise Violation("STATE_VIA_TRANSITIONS", f"{where} writes undeclared state key {key!r}")
                if (output["type"] != "object" or key not in output["properties"]
                        or key not in output.get("required", [])
                        or not accepts(keys[key], output["properties"][key])):
                    raise Violation("STATE_VIA_TRANSITIONS",
                                    f"{where}: node {node_id} output does not carry a typed value for state key {key!r}")
