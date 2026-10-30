"""Decision records and their EPAP link material.

Every evaluation, ALLOW or DENY, yields one record::

    {"schema": "mcp-auth-decision-v1",
     "request_id": ..., "request_digest": <sha256 of the canonical request> | None,
     "policy_version": ..., "policy_digest": <sha256 of the canonical policy> | None,
     "timestamp": "YYYY-MM-DDTHH:MM:SSZ" | None,
     "disposition": "ALLOW" | "DENY",
     "failed_step": None | <step>,
     "stop_condition": None | {"number": <1-13>, "text": <doctrine section 9 wording>},
     "reason": ...,
     "answers": {<the nine section 5 questions, as resolved; None where unresolved>}}

``link_material`` turns a record into the ``signed`` part of an EPAP link in
the leg-2 pack format (``epap.links``): the policy and request are its
materials, its products are those plus the record, and the record is also its
byproducts. Each artifact is named by
the SHA-256 of its canonical JSON bytes (``epap.signing.canonical_bytes``), so
the link can be signed with ``epap.signing.sign_metablock`` and the artifacts
written alongside it unchanged.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from epap import links, signing

RECORD_SCHEMA = "mcp-auth-decision-v1"
LINK_NAME = "MCP_AUTH_DECISION"
COMMAND = "mcp_auth.decide"

QUESTIONS = ("principal", "acting_identity", "role_class", "sot_authority", "scope",
             "action", "evidence", "stop_conditions", "unresolved")
FAIL_CLOSED = "FAIL_CLOSED"


def digest(value: Any) -> Optional[str]:
    """SHA-256 of ``value``'s canonical JSON, or None when it has no canonical form."""
    try:
        return signing.sha256_hex(signing.canonical_bytes(value))
    except (signing.CanonicalError, TypeError, ValueError, RecursionError):
        return None


def blank_answers() -> dict:
    answers = {q: None for q in QUESTIONS}
    answers["stop_conditions"] = {"cleared": [], "triggered": None}
    answers["unresolved"] = FAIL_CLOSED
    return answers


def make_record(*, request_id: Optional[str], request_digest: Optional[str], policy_version: Optional[str],
                policy_digest: Optional[str], timestamp: Optional[str], disposition: str,
                failed_step: Optional[str], stop_condition: Optional[Mapping], reason: str,
                answers: Mapping) -> dict:
    return {
        "schema": RECORD_SCHEMA,
        "request_id": request_id,
        "request_digest": request_digest,
        "policy_version": policy_version,
        "policy_digest": policy_digest,
        "timestamp": timestamp,
        "disposition": disposition,
        "failed_step": failed_step,
        "stop_condition": dict(stop_condition) if stop_condition else None,
        "reason": reason,
        "answers": {q: answers[q] for q in QUESTIONS},
    }


def artifact_paths(record: Mapping) -> dict:
    """Pack-relative paths of the decision's artifacts, keyed by role."""
    paths = {}
    if record.get("policy_digest"):
        paths["policy"] = f"mcp_auth/policy/{record['policy_digest']}.json"
    if record.get("request_digest"):
        paths["request"] = f"mcp_auth/requests/{record['request_digest']}.json"
    paths["decision"] = f"mcp_auth/decisions/{digest(dict(record))}.json"
    return paths


def link_material(record: Mapping) -> dict:
    """The ``signed`` part of an EPAP link recording one decision."""
    record = dict(record)
    paths = artifact_paths(record)
    materials = {}
    if "policy" in paths:
        materials[paths["policy"]] = {"sha256": record["policy_digest"]}
    if "request" in paths:
        materials[paths["request"]] = {"sha256": record["request_digest"]}
    # Leg-2 products are the whole artifact set after the step, not only what it added.
    products = {**materials, paths["decision"]: {"sha256": digest(record)}}
    command = [COMMAND, record.get("policy_version") or "policy-unavailable"]
    return links.make_link(LINK_NAME, materials, products, command, record)
