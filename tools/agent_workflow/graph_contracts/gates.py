"""The GE gate-criteria table (directive section 8) as data: loading, strict validation, criteria.

The table ships as data (``gates.json`` next to this module): one entry per
lifecycle stage 8.1-8.14, in order, each naming the governance control the
stage requires. A table document has exactly these fields:

``schema``  ``"ge-gate-criteria-v1"``
``spec``    ``"GRAPH-ENGINEERING-CONTRACT-SPEC-001"``
``stages``  exactly ``STAGES``, in order; each
            ``{"stage", "id", "activity", "control", "control_kind",
            "invariants", "node_output_satisfies"}``, plus ``review`` on 8.5
            and ``hitl`` on 8.6

Two entries are load-bearing and checked here when the data loads:

- 8.5 independent REVIEWER review is exact-head and session-independent, completes
  only as ``REVIEW_COMPLETED`` (``REVIEW_REQUESTED`` and the other pending
  states never complete it), and a builder's self-check never satisfies it;
- 8.6 HITL gates cover at least the merge, activation and reliance boundaries
  and are satisfied by HITL only, never by node output.

No stage may be satisfied by node output. The validator reads its
verification-gate and HITL-gate requirements from these two entries, so
weakening them in the data is a ``GateTableError``, not a quieter validator.

``review_criterion_met`` and ``hitl_criterion_met`` decide whether presented
evidence meets those two entries. They are pure predicates over the data; they
execute nothing and record nothing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Tuple

from graph_contracts import schema as S

SCHEMA = "ge-gate-criteria-v1"
DEFAULT_PATH = Path(__file__).resolve().parent / "gates.json"

STAGES = (
    ("8.1", "CONCEPTUAL_PLANNING"),
    ("8.2", "GRAPH_CONTRACT_AUTHORING"),
    ("8.3", "TRANSFER_HANDOFF"),
    ("8.4", "AUTHORIZATION_GATES"),
    ("8.5", "INDEPENDENT_REVIEW"),
    ("8.6", "HITL_GATES"),
    ("8.7", "EPAP_PROVENANCE"),
    ("8.8", "BOUNDED_RECOVERY"),
    ("8.9", "DURABLE_CONTINUATION"),
    ("8.10", "EVALUATION"),
    ("8.11", "SECURITY"),
    ("8.12", "DEPLOYMENT"),
    ("8.13", "OBSERVABILITY"),
    ("8.14", "LIVE_DASHBOARD"),
)
REVIEW_STAGE = "8.5"
HITL_STAGE = "8.6"
ACTIVATION_STAGE = "8.12"
CONTROL_KINDS = ("POLICY", "DETERMINISTIC", "VERIFICATION", "HITL")
# Directive section 9.
INVARIANTS = ("NO_VENDOR_LOCK_IN", "NO_SELF_SATISFIED_GATES", "NO_DESIGN_REFERENCE_AS_PRODUCTION_EVIDENCE",
              "NO_DUPLICATE_CANONICAL_ARCHITECTURE", "NO_DUPLICATE_DASHBOARD", "NO_SECURITY_MODEL_FORK",
              "NO_TRANSFER_BUS_BYPASS", "SELF_CHECK_NEVER_EQUALS_INDEPENDENT_REVIEW", "HITL_GATES_UNCHANGED")

REVIEW_COMPLETED = "REVIEW_COMPLETED"
PENDING_REVIEW_STATES = ("REVIEW_REQUESTED", "REVIEW_QUEUED", "REVIEW_COMMENT_PENDING")
CONSEQUENTIAL_BOUNDARIES = ("MERGE", "ACTIVATION", "RELIANCE")
HITL = "HITL"
APPROVED = "APPROVED"

TOP_FIELDS = frozenset({"schema", "spec", "stages"})
STAGE_FIELDS = frozenset({"stage", "id", "activity", "control", "control_kind", "invariants",
                          "node_output_satisfies"})
REVIEW_FIELDS = frozenset({"satisfied_by", "exact_head", "session_independent", "completion_state",
                           "non_completion_states", "self_check_satisfies"})
HITL_FIELDS = frozenset({"satisfied_by", "boundaries"})
REVIEW_EVIDENCE_FIELDS = frozenset({"state", "reviewed_head", "head", "reviewer_session", "builder_session",
                                    "self_check"})
HITL_EVIDENCE_FIELDS = frozenset({"boundary", "decided_by", "decision"})


class GateTableError(ValueError):
    pass


def _fields(value: Any, fields: frozenset, where: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise GateTableError(f"{where} must have exactly the fields {sorted(fields)}")
    return value


def _names(value: Any, where: str, allow_empty: bool = False) -> list:
    if not isinstance(value, list) or (not value and not allow_empty):
        raise GateTableError(f"{where} must be a {'list' if allow_empty else 'non-empty list'}")
    if not all(S.is_name(v) for v in value) or len(set(value)) != len(value):
        raise GateTableError(f"{where} must hold distinct non-empty strings")
    return value


def _review(value: Any, where: str) -> None:
    review = _fields(value, REVIEW_FIELDS, where)
    if review["exact_head"] is not True:
        raise GateTableError(f"{where}.exact_head must be true: independent review is exact-head")
    if review["session_independent"] is not True:
        raise GateTableError(f"{where}.session_independent must be true: independent review is session-independent")
    if review["self_check_satisfies"] is not False:
        raise GateTableError(f"{where}.self_check_satisfies must be false: a builder's self-check never satisfies it")
    if review["completion_state"] != REVIEW_COMPLETED:
        raise GateTableError(f"{where}.completion_state must be {REVIEW_COMPLETED!r}")
    pending = _names(review["non_completion_states"], f"{where}.non_completion_states")
    missing = [s for s in PENDING_REVIEW_STATES if s not in pending]
    if missing:
        raise GateTableError(f"{where}.non_completion_states must include {missing} (REVIEW_REQUESTED != REVIEW_COMPLETED)")
    if REVIEW_COMPLETED in pending:
        raise GateTableError(f"{where}.non_completion_states must not include {REVIEW_COMPLETED!r}")
    if not S.is_name(review["satisfied_by"]):
        raise GateTableError(f"{where}.satisfied_by must name the independent reviewer principal")


def _hitl(value: Any, where: str) -> None:
    hitl = _fields(value, HITL_FIELDS, where)
    if hitl["satisfied_by"] != HITL:
        raise GateTableError(f"{where}.satisfied_by must be {HITL!r}")
    boundaries = _names(hitl["boundaries"], f"{where}.boundaries")
    missing = [b for b in CONSEQUENTIAL_BOUNDARIES if b not in boundaries]
    if missing:
        raise GateTableError(f"{where}.boundaries must include {missing}: every consequential boundary carries a HITL gate")


def validate(doc: Any) -> dict:
    """A validated copy of ``doc``; raises ``GateTableError`` naming the first defect."""
    _fields(doc, TOP_FIELDS, "gate table")
    if doc["schema"] != SCHEMA:
        raise GateTableError(f"schema must be {SCHEMA!r}")
    if doc["spec"] != S.SPEC_ID:
        raise GateTableError(f"spec must be {S.SPEC_ID!r}")
    stages = doc["stages"]
    if not isinstance(stages, list) or len(stages) != len(STAGES):
        raise GateTableError(f"stages must list exactly the {len(STAGES)} section 8 stages")
    for entry, (number, stage_id) in zip(stages, STAGES):
        where = f"stages[{number}]"
        extra = set()
        if number == REVIEW_STAGE:
            extra = {"review"}
        elif number == HITL_STAGE:
            extra = {"hitl"}
        _fields(entry, STAGE_FIELDS | extra, where)
        if entry["stage"] != number or entry["id"] != stage_id:
            raise GateTableError(f"{where} must be stage {number} {stage_id}")
        for name in ("activity", "control"):
            if not S.is_name(entry[name]):
                raise GateTableError(f"{where}.{name} must be a non-empty string")
        if entry["control_kind"] not in CONTROL_KINDS:
            raise GateTableError(f"{where}.control_kind must be one of {list(CONTROL_KINDS)}")
        unknown = [i for i in _names(entry["invariants"], f"{where}.invariants", allow_empty=True)
                   if i not in INVARIANTS]
        if unknown:
            raise GateTableError(f"{where}.invariants: unknown {unknown}")
        if entry["node_output_satisfies"] is not False:
            raise GateTableError(f"{where}.node_output_satisfies must be false: no node output satisfies a stage gate")
        if number == REVIEW_STAGE:
            if entry["control_kind"] != "VERIFICATION":
                raise GateTableError(f"{where}.control_kind must be VERIFICATION")
            _review(entry["review"], f"{where}.review")
        if number in (HITL_STAGE, ACTIVATION_STAGE) and entry["control_kind"] != "HITL":
            raise GateTableError(f"{where}.control_kind must be HITL")
        if number == HITL_STAGE:
            _hitl(entry["hitl"], f"{where}.hitl")
    return json.loads(json.dumps(doc))


def load_file(path: Path = DEFAULT_PATH) -> dict:
    """Load and validate the gate table at ``path`` (default: the shipped table)."""
    try:
        doc = S.read_file(path, "gate table")
    except ValueError as exc:
        raise GateTableError(str(exc)) from None
    return validate(doc)


def stage(table: dict, number: str) -> dict:
    for entry in table["stages"]:
        if entry["stage"] == number:
            return entry
    raise KeyError(number)


def review_criteria(table: dict) -> dict:
    return stage(table, REVIEW_STAGE)["review"]


def hitl_criteria(table: dict) -> dict:
    return stage(table, HITL_STAGE)["hitl"]


def review_criterion_met(evidence: Any, table: dict) -> Tuple[bool, str]:
    """Whether ``evidence`` meets stage 8.5; ``(False, reason)`` on any doubt.

    ``evidence`` is ``{"state", "reviewed_head", "head", "reviewer_session",
    "builder_session", "self_check"}``.
    """
    criteria = review_criteria(table)
    if not isinstance(evidence, dict) or set(evidence) != REVIEW_EVIDENCE_FIELDS:
        return False, f"review evidence must have exactly the fields {sorted(REVIEW_EVIDENCE_FIELDS)}"
    if evidence["self_check"] is not False:
        return False, "a builder's self-check is never independent review"
    if evidence["state"] in criteria["non_completion_states"]:
        return False, f"{evidence['state']} != {criteria['completion_state']}"
    if evidence["state"] != criteria["completion_state"]:
        return False, f"review state must be {criteria['completion_state']}"
    if not (S.is_name(evidence["reviewed_head"]) and evidence["reviewed_head"] == evidence["head"]):
        return False, "review is not at the exact head"
    if not (S.is_name(evidence["reviewer_session"]) and S.is_name(evidence["builder_session"])
            and evidence["reviewer_session"] != evidence["builder_session"]):
        return False, "review is not session-independent of the builder"
    return True, "independent review completed at the exact head"


def hitl_criterion_met(evidence: Any, table: dict) -> Tuple[bool, str]:
    """Whether ``evidence`` meets stage 8.6; ``(False, reason)`` on any doubt.

    ``evidence`` is ``{"boundary", "decided_by", "decision"}``. Only a decision
    by ``HITL`` counts; a node id, an engine or any other source never does.
    """
    criteria = hitl_criteria(table)
    if not isinstance(evidence, dict) or set(evidence) != HITL_EVIDENCE_FIELDS:
        return False, f"HITL evidence must have exactly the fields {sorted(HITL_EVIDENCE_FIELDS)}"
    if evidence["boundary"] not in criteria["boundaries"]:
        return False, f"boundary must be one of {criteria['boundaries']}"
    if evidence["decided_by"] != criteria["satisfied_by"]:
        return False, "a HITL gate is satisfied by HITL only, never by node output"
    if evidence["decision"] != APPROVED:
        return False, f"decision must be {APPROVED}"
    return True, "HITL approved the boundary"
