"""The GE graph contract schema (directive section 7) as data: loading and strict validation.

The schema ships as data (``schema.json`` next to this module). It is the
single source for what a ``ge-graph-contract-v1`` document may contain; the
validator (``validate.py``) holds the rules but takes every vocabulary from
here. A schema document has exactly these tables:

``schema``             ``"ge-contract-schema-v1"``
``spec``               ``"GRAPH-ENGINEERING-CONTRACT-SPEC-001"``
``contract_schema``    the ``schema`` value a contract must carry
``graph_id_prefix``    ``"GE-"`` (directive section 6: unambiguous GE naming)
``contract_fields``    required contract fields
``node_fields``        fields every node carries
``free_text_fields``   optional prose fields, never interpreted (``description``)
``node_kinds``         exactly the six section 7 kinds -> their extra fields
``gate_fields``        gate kind -> fields of its ``gate`` object
``gate_stages``        gate kind -> the section 8 stage whose criteria it enforces
``subgraph_fields``    fields of a ``subgraph`` reference
``edge_kinds``         exactly ``static`` and ``conditional`` -> their fields
``router_kinds``       node kinds that may own a conditional edge
``state_fields``       fields of the ``state`` object
``state_scopes``       admissible state scopes (graph-run, cross-run, tenant)
``state_store``        the only admissible state store (the control plane)
``transition_fields``  fields of a declared state transition
``artifact_fields``    fields of an artifact
``artifact_role``      the only admissible artifact role (evidence)
``io_types``           the framework-neutral typed-I/O primitive types
``io_fields``          the keys a typed-I/O schema may use
``vendor_tokens``      lower-case vendor, framework, provider and model names
``vendor_constructs``  vendor class names, matched case-sensitively
``rules``              every rule name the validator can report -> its statement

Any defect is a ``SchemaError``; the validator then refuses to run.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

SCHEMA = "ge-contract-schema-v1"
SPEC_ID = "GRAPH-ENGINEERING-CONTRACT-SPEC-001"
DEFAULT_PATH = Path(__file__).resolve().parent / "schema.json"

NODE_KINDS = ("AGENT_TASK", "DETERMINISTIC_TASK", "ROUTER", "HITL_GATE", "VERIFICATION_GATE", "SUBGRAPH")
GATE_KINDS = ("HITL_GATE", "VERIFICATION_GATE")
EDGE_KINDS = ("static", "conditional")

LIST_FIELDS = ("contract_fields", "node_fields", "free_text_fields", "subgraph_fields", "router_kinds",
               "state_fields", "state_scopes", "transition_fields", "artifact_fields", "io_types", "io_fields",
               "vendor_tokens", "vendor_constructs")
NAME_FIELDS = ("contract_schema", "graph_id_prefix", "state_store", "artifact_role")
TOP_FIELDS = frozenset(("schema", "spec", "node_kinds", "gate_fields", "gate_stages", "edge_kinds", "rules")
                       + LIST_FIELDS + NAME_FIELDS)


class SchemaError(ValueError):
    pass


def is_name(value: object) -> bool:
    return isinstance(value, str) and bool(value) and value == value.strip()


def _fields(value: Any, fields: Iterable[str], where: str) -> dict:
    fields = frozenset(fields)
    if not isinstance(value, dict) or set(value) != fields:
        raise SchemaError(f"{where} must have exactly the fields {sorted(fields)}")
    return value


def _names(value: Any, where: str, allow_empty: bool = False) -> list:
    if not isinstance(value, list) or (not value and not allow_empty):
        raise SchemaError(f"{where} must be a {'list' if allow_empty else 'non-empty list'}")
    for i, item in enumerate(value):
        if not is_name(item):
            raise SchemaError(f"{where}[{i}] must be a non-empty string without surrounding whitespace")
    if len(set(value)) != len(value):
        raise SchemaError(f"{where} has duplicate entries")
    return value


def validate(doc: Any) -> dict:
    """A validated copy of ``doc``; raises ``SchemaError`` naming the first defect."""
    _fields(doc, TOP_FIELDS, "schema document")
    if doc["schema"] != SCHEMA:
        raise SchemaError(f"schema must be {SCHEMA!r}")
    if doc["spec"] != SPEC_ID:
        raise SchemaError(f"spec must be {SPEC_ID!r}")
    for name in NAME_FIELDS:
        if not is_name(doc[name]):
            raise SchemaError(f"{name} must be a non-empty string")
    for name in LIST_FIELDS:
        _names(doc[name], name)

    kinds = _fields(doc["node_kinds"], NODE_KINDS, "node_kinds")
    for kind in NODE_KINDS:
        _names(kinds[kind], f"node_kinds.{kind}", allow_empty=True)
    gate_fields = _fields(doc["gate_fields"], GATE_KINDS, "gate_fields")
    for kind in GATE_KINDS:
        _names(gate_fields[kind], f"gate_fields.{kind}")
        if "gate" not in kinds[kind]:
            raise SchemaError(f"node_kinds.{kind} must carry a 'gate' field")
        if "satisfied_by" not in gate_fields[kind] or "guards" not in gate_fields[kind]:
            raise SchemaError(f"gate_fields.{kind} must include 'guards' and 'satisfied_by'")
    stages = _fields(doc["gate_stages"], GATE_KINDS, "gate_stages")
    for kind in GATE_KINDS:
        if not is_name(stages[kind]):
            raise SchemaError(f"gate_stages.{kind} must be a stage number")
    edges = _fields(doc["edge_kinds"], EDGE_KINDS, "edge_kinds")
    for kind in EDGE_KINDS:
        _names(edges[kind], f"edge_kinds.{kind}")
    unknown = sorted(set(doc["router_kinds"]) - set(NODE_KINDS))
    if unknown:
        raise SchemaError(f"router_kinds: unknown node kinds {unknown}")
    if any(token != token.lower() for token in doc["vendor_tokens"]):
        raise SchemaError("vendor_tokens must be lower-case")

    rules = doc["rules"]
    if not isinstance(rules, dict) or not rules:
        raise SchemaError("rules must be a non-empty object")
    for rule, text in rules.items():
        if not is_name(rule) or not is_name(text):
            raise SchemaError(f"rules[{rule!r}] must map a rule name to its statement")
    return json.loads(json.dumps(doc))


def _no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _no_float(text):
    raise ValueError(f"non-integer number {text}")


def parse_json(data: bytes) -> Any:
    """Strict JSON: duplicate keys, floats and NaN raise ``ValueError``."""
    return json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicates,
                      parse_float=_no_float, parse_constant=_no_float)


def read_file(path: Path, what: str) -> Any:
    """Strict JSON from ``path``; anything unreadable or malformed raises ``ValueError``."""
    path = Path(path)
    try:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"{path.name}: {what} unavailable")
        data = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"{path.name}: {what} unavailable ({exc.strerror})") from None
    try:
        return parse_json(data)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ValueError(f"{path.name}: {what} is not valid JSON: {exc}") from None


def load_file(path: Path = DEFAULT_PATH) -> dict:
    """Load and validate the contract schema at ``path`` (default: the shipped schema)."""
    try:
        doc = read_file(path, "contract schema")
    except ValueError as exc:
        raise SchemaError(str(exc)) from None
    return validate(doc)
