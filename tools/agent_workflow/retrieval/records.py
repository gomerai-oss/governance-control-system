"""Typed inter-stage records (doctrine section 8) and citations (section 9).

Two inter-stage records carry the request into the retriever and the result out
of it. Between them they hold exactly the section 8 field set and nothing else:

- ``retrieval-request-v1`` (what the caller declares): ``request_id``,
  ``mission_id``, ``query_intent``, ``constraints``, ``corpus_scope``,
  ``retrieval_method``.
- ``retrieval-result-v1`` (what the retriever produces): ``source_id``,
  ``source_authority``, ``source_version``, ``source_date``, ``claim_id``,
  ``claim_text``, ``evidence_span``, ``evidence_relationship``,
  ``confidence_state``, ``contradiction_state``, ``missing_evidence``,
  ``validation_state``, ``provenance``, ``stop_reason``.

``citation-v1`` (section 9) is the evidence contract for one claim: which claim,
which source, which span, how the span relates to the claim, and the validation
and contradiction state. ``source_version`` is the SHA-256 of the source file;
``evidence_span.sha256`` is the SHA-256 of the exact span bytes.

Every record is validated in both directions: a dict is checked against the
schema before it is used, and a built record is checked before it is returned.
Nothing here is phrased or typed as permission to act; retrieval is not
authority. ``confidence_state`` records only whether the request was resolved or
abstained, never that any action is allowed.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional, Sequence

REQUEST_SCHEMA = "retrieval-request-v1"
RESULT_SCHEMA = "retrieval-result-v1"
CITATION_SCHEMA = "citation-v1"

REQUEST_FIELDS = frozenset(
    {"request_id", "mission_id", "query_intent", "constraints", "corpus_scope", "retrieval_method"}
)
RESULT_FIELDS = frozenset(
    {"source_id", "source_authority", "source_version", "source_date", "claim_id", "claim_text",
     "evidence_span", "evidence_relationship", "confidence_state", "contradiction_state",
     "missing_evidence", "validation_state", "provenance", "stop_reason"}
)
CITATION_FIELDS = frozenset(
    {"claim_id", "source_id", "source_path", "source_authority", "source_version", "evidence_span",
     "evidence_relationship", "contradiction_state", "validation_state"}
)
SPAN_FIELDS = frozenset({"start_line", "end_line", "sha256"})

# Enumerations. None of these name a permission; retrieval is not authority.
EVIDENCE_RELATIONSHIPS = ("EXACT_MATCH", "LEXICAL_SUPPORT", "UNVERIFIED")
CONFIDENCE_STATES = ("RESOLVED", "ABSTAINED")
CONTRADICTION_STATES = ("NONE", "SUPERSEDED", "SUPERSEDES")
VALIDATION_STATES = ("VALIDATED", "UNVERIFIED", "FAILED", "ABSTAINED")
AUTHORITY_CLASSES = ("doctrine", "spec", "plan", "evidence", "reference")
# The seven section 2 stage names a request may pin (or null for the full hierarchy).
RETRIEVAL_METHODS = ("exact", "metadata", "structure", "vocabulary", "lexical", "semantic", "recovery")


class RecordError(ValueError):
    pass


def _is_hex64(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _str_or_none(value: object) -> bool:
    return value is None or isinstance(value, str)


def span_problem(value: object, *, allow_none: bool = True) -> Optional[str]:
    """Why an ``evidence_span`` is malformed, or None."""
    if value is None:
        return None if allow_none else "evidence_span must not be null"
    if not isinstance(value, dict) or set(value) != SPAN_FIELDS:
        return f"evidence_span must have exactly {sorted(SPAN_FIELDS)}"
    start, end = value["start_line"], value["end_line"]
    if not isinstance(start, int) or isinstance(start, bool) or start < 1:
        return "start_line must be an integer >= 1"
    if not isinstance(end, int) or isinstance(end, bool) or end < start:
        return "end_line must be an integer >= start_line"
    if not _is_hex64(value["sha256"]):
        return "span sha256 must be 64 lowercase hex characters"
    return None


def request_problem(value: object) -> Optional[str]:
    """Why a ``retrieval-request-v1`` record is malformed, or None."""
    if not isinstance(value, dict) or set(value) != REQUEST_FIELDS:
        return f"request must have exactly the fields {sorted(REQUEST_FIELDS)}"
    if not isinstance(value["request_id"], str) or not value["request_id"]:
        return "request_id must be a non-empty string"
    if not _str_or_none(value["mission_id"]):
        return "mission_id must be a string or null"
    if not isinstance(value["query_intent"], str):
        return "query_intent must be a string"
    if not isinstance(value["constraints"], dict) or not all(isinstance(k, str) for k in value["constraints"]):
        return "constraints must be an object keyed by strings"
    scope = value["corpus_scope"]
    if not isinstance(scope, list) or not all(isinstance(s, str) and s for s in scope):
        return "corpus_scope must be a list of corpus id strings"
    method = value["retrieval_method"]
    if method is not None and method not in RETRIEVAL_METHODS:
        return f"retrieval_method must be null or one of {list(RETRIEVAL_METHODS)}"
    return None


def result_problem(value: object) -> Optional[str]:
    """Why a ``retrieval-result-v1`` record is malformed, or None."""
    if not isinstance(value, dict) or set(value) != RESULT_FIELDS:
        return f"result must have exactly the fields {sorted(RESULT_FIELDS)}"
    for field in ("source_id", "source_authority", "source_version", "source_date",
                  "claim_id", "claim_text"):
        if not _str_or_none(value[field]):
            return f"{field} must be a string or null"
    if value["source_version"] is not None and not _is_hex64(value["source_version"]):
        return "source_version must be the SHA-256 hex of the source file"
    if value["source_authority"] is not None and value["source_authority"] not in AUTHORITY_CLASSES:
        return f"source_authority must be one of {list(AUTHORITY_CLASSES)}"
    problem = span_problem(value["evidence_span"])
    if problem:
        return problem
    rel = value["evidence_relationship"]
    if rel is not None and rel not in EVIDENCE_RELATIONSHIPS:
        return f"evidence_relationship must be one of {list(EVIDENCE_RELATIONSHIPS)}"
    if value["confidence_state"] not in CONFIDENCE_STATES:
        return f"confidence_state must be one of {list(CONFIDENCE_STATES)}"
    if value["contradiction_state"] not in CONTRADICTION_STATES:
        return f"contradiction_state must be one of {list(CONTRADICTION_STATES)}"
    if value["validation_state"] not in VALIDATION_STATES:
        return f"validation_state must be one of {list(VALIDATION_STATES)}"
    missing = value["missing_evidence"]
    if not isinstance(missing, list) or not all(isinstance(m, str) for m in missing):
        return "missing_evidence must be a list of strings"
    if not isinstance(value["provenance"], dict):
        return "provenance must be an object"
    if not isinstance(value["stop_reason"], str) or not value["stop_reason"]:
        return "stop_reason must be a non-empty string"
    return None


def citation_problem(value: object) -> Optional[str]:
    """Why a ``citation-v1`` record is malformed, or None."""
    if not isinstance(value, dict) or set(value) != CITATION_FIELDS:
        return f"citation must have exactly the fields {sorted(CITATION_FIELDS)}"
    if not isinstance(value["claim_id"], str) or not value["claim_id"]:
        return "claim_id must be a non-empty string"
    if not isinstance(value["source_id"], str) or not value["source_id"]:
        return "source_id must be a non-empty string"
    path = value["source_path"]
    if (not isinstance(path, str) or not path or path.startswith("/") or "\\" in path
            or any(p in ("", ".", "..") for p in path.split("/"))):
        return "source_path must be a clean relative path"
    if value["source_authority"] not in AUTHORITY_CLASSES:
        return f"source_authority must be one of {list(AUTHORITY_CLASSES)}"
    if not _is_hex64(value["source_version"]):
        return "source_version must be the SHA-256 hex of the source file"
    problem = span_problem(value["evidence_span"], allow_none=False)
    if problem:
        return problem
    if value["evidence_relationship"] not in EVIDENCE_RELATIONSHIPS:
        return f"evidence_relationship must be one of {list(EVIDENCE_RELATIONSHIPS)}"
    if value["contradiction_state"] not in CONTRADICTION_STATES:
        return f"contradiction_state must be one of {list(CONTRADICTION_STATES)}"
    if value["validation_state"] not in VALIDATION_STATES:
        return f"validation_state must be one of {list(VALIDATION_STATES)}"
    return None


def _checked(value: Any, problem) -> dict:
    reason = problem(value)
    if reason:
        raise RecordError(reason)
    return dict(value)


def validate_request(value: Mapping[str, Any]) -> dict:
    return _checked(value, request_problem)


def validate_result(value: Mapping[str, Any]) -> dict:
    return _checked(value, result_problem)


def validate_citation(value: Mapping[str, Any]) -> dict:
    return _checked(value, citation_problem)


def make_span(start_line: int, end_line: int, sha256: str) -> dict:
    span = {"start_line": start_line, "end_line": end_line, "sha256": sha256}
    reason = span_problem(span, allow_none=False)
    if reason:
        raise RecordError(reason)
    return span


def make_request(request_id: str, *, query_intent: str = "", constraints: Optional[Mapping] = None,
                 corpus_scope: Optional[Sequence[str]] = None, mission_id: Optional[str] = None,
                 retrieval_method: Optional[str] = None) -> dict:
    return validate_request({
        "request_id": request_id,
        "mission_id": mission_id,
        "query_intent": query_intent,
        "constraints": dict(constraints or {}),
        "corpus_scope": list(corpus_scope or []),
        "retrieval_method": retrieval_method,
    })


def make_citation(*, claim_id: str, source_id: str, source_path: str, source_authority: str,
                  source_version: str, evidence_span: Mapping, evidence_relationship: str,
                  contradiction_state: str = "NONE", validation_state: str = "VALIDATED") -> dict:
    return validate_citation({
        "claim_id": claim_id,
        "source_id": source_id,
        "source_path": source_path,
        "source_authority": source_authority,
        "source_version": source_version,
        "evidence_span": dict(evidence_span),
        "evidence_relationship": evidence_relationship,
        "contradiction_state": contradiction_state,
        "validation_state": validation_state,
    })
