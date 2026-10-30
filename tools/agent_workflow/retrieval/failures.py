"""The named failure classes of doctrine section 10, as data and detectors.

The doctrine lists seventeen candidate failure classes. Each is recorded here
with its detection rule (or ``NOT_DETECTABLE_IN_THIS_BUILD`` and the reason),
its severity, and the evidence retained when it occurs. No model-based judgement
is used: a class is only marked detectable when a deterministic rule decides it.

``audit_result`` runs every detectable rule over a produced result and its
corpus and returns the classes it finds, so a result can be checked for the
failures this build is responsible for not committing.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, List, Mapping, Optional

from retrieval import records

NOT_DETECTABLE = "NOT_DETECTABLE_IN_THIS_BUILD"

# severity scale, low to high consequence.
LOW, MEDIUM, HIGH, CRITICAL = "LOW", "MEDIUM", "HIGH", "CRITICAL"

FAILURE_CLASSES: dict = {
    "WRONG_SOURCE": {
        "detection": NOT_DETECTABLE,
        "reason": "deciding a different source was the right one needs the ground-truth "
                  "answer key this build does not carry.",
        "severity": HIGH,
        "evidence_retained": ["request", "cited citation", "stages run"],
    },
    "WRONG_DOCUMENT_VERSION": {
        "detection": "The primary cited source's own metadata marks it superseded, whatever the "
                     "result's contradiction_state, or the result abstained because the "
                     "Superseded-By chain leaves the corpus, cycles or names the document itself.",
        "severity": HIGH,
        "evidence_retained": ["superseded document id", "superseding document id", "stages run"],
    },
    "MISSING_REQUIRED_SOURCE": {
        "detection": "A required source is absent: the request resolved to no citation and the "
                     "result abstains with this stop_reason.",
        "severity": HIGH,
        "evidence_retained": ["request", "missing_evidence", "stages run", "recovery relaxations"],
    },
    "RETRIEVAL_INCOMPLETENESS": {
        "detection": NOT_DETECTABLE,
        "reason": "completeness is defined against an expected result set this build is not given.",
        "severity": MEDIUM,
        "evidence_retained": ["request", "stages run"],
    },
    "ENUMERATION_INCOMPLETENESS": {
        "detection": NOT_DETECTABLE,
        "reason": "there is no declared enumeration target to measure coverage against.",
        "severity": MEDIUM,
        "evidence_retained": ["request", "stages run"],
    },
    "SOURCE_AUTHORITY_FAILURE": {
        "detection": NOT_DETECTABLE,
        "reason": "the request does not declare the authority class a claim requires, so the "
                  "cited source's authority cannot be judged insufficient here.",
        "severity": HIGH,
        "evidence_retained": ["cited citation", "source_authority"],
    },
    "CITATION_ENTAILMENT_FAILURE": {
        "detection": NOT_DETECTABLE,
        "reason": "entailment is a model judgement; this build claims no model-based entailment "
                  "and records relationships only as EXACT_MATCH, LEXICAL_SUPPORT or UNVERIFIED.",
        "severity": HIGH,
        "evidence_retained": ["cited citation", "evidence_span"],
    },
    "UNSUPPORTED_ASSERTION": {
        "detection": "A citation's span no longer hashes to its recorded sha256 when re-read "
                     "from the file.",
        "severity": CRITICAL,
        "evidence_retained": ["citation", "recorded sha256", "recomputed sha256"],
    },
    "CONTRADICTION_MISSED": {
        "detection": "The cited source is superseded by an in-corpus document but the result "
                     "does not record the contradiction.",
        "severity": HIGH,
        "evidence_retained": ["cited citation", "superseding document id"],
    },
    "TEMPORAL_STALENESS": {
        "detection": NOT_DETECTABLE,
        "reason": "no freshness threshold or effective-date requirement is declared on the request.",
        "severity": MEDIUM,
        "evidence_retained": ["source_date"],
    },
    "JURISDICTION_MISMATCH": {
        "detection": NOT_DETECTABLE,
        "reason": "the corpus carries no jurisdiction field for this build to compare against.",
        "severity": HIGH,
        "evidence_retained": ["request", "cited citation"],
    },
    "ACL_SCOPE_FAILURE": {
        "detection": "A request targeted a path outside every corpus root or a deny-pattern file, "
                     "or a citation's source lies outside the corpus allow-list.",
        "severity": CRITICAL,
        "evidence_retained": ["requested path", "corpus roots", "stages run"],
    },
    "SCHEMA_FAILURE": {
        "detection": "The request or result does not validate against its typed schema.",
        "severity": CRITICAL,
        "evidence_retained": ["offending record", "schema problem"],
    },
    "OBJECTIVE_DRIFT": {
        "detection": NOT_DETECTABLE,
        "reason": "drift is measured across a loop's objective over turns; a single deterministic "
                  "retrieval has no multi-turn objective to drift from.",
        "severity": MEDIUM,
        "evidence_retained": ["request", "stages run"],
    },
    "UNSAFE_OVERCONFIDENCE": {
        "detection": NOT_DETECTABLE,
        "reason": "confidence_state is a two-valued RESOLVED/ABSTAINED fact, not a probability "
                  "this build can judge as overconfident.",
        "severity": HIGH,
        "evidence_retained": ["confidence_state", "validation_state"],
    },
    "ABSTENTION_FAILURE": {
        "detection": "The result is RESOLVED but its citation does not validate, so it asserted "
                     "where it should have abstained.",
        "severity": CRITICAL,
        "evidence_retained": ["result", "citation", "validation_state"],
    },
    "LOOP_EXHAUSTION_MISREPRESENTED": {
        "detection": "The recovery loop recorded LOOP_EXHAUSTED yet the result is RESOLVED, "
                     "representing an exhausted loop as a success.",
        "severity": CRITICAL,
        "evidence_retained": ["stages run", "recovery iterations", "confidence_state"],
    },
}

assert len(FAILURE_CLASSES) == 17


def is_detectable(name: str) -> bool:
    return FAILURE_CLASSES[name]["detection"] != NOT_DETECTABLE


def rehash_span(root: Path, source_path: str, span: Mapping[str, Any]) -> Optional[str]:
    """The SHA-256 of the span bytes as the file reads now, or None if unreadable."""
    target = Path(root) / source_path
    try:
        if target.is_symlink() or not target.is_file():
            return None
        lines = target.read_bytes().decode("utf-8", errors="replace").splitlines(keepends=True) or [""]
    except OSError:
        return None
    start, end = span["start_line"], span["end_line"]
    if start < 1 or end < start or end > len(lines):
        return "__OUT_OF_RANGE__"
    span_bytes = "".join(lines[start - 1:end]).encode("utf-8")
    return hashlib.sha256(span_bytes).hexdigest()


def _source_claims_superseded(root: Path, source_path: str) -> bool:
    """True when the source file's own metadata marks it superseded."""
    from retrieval import stages  # local import avoids any import-order coupling
    target = Path(root) / source_path
    try:
        if target.is_symlink() or not target.is_file():
            return False
        text = target.read_bytes().decode("utf-8", errors="replace")
    except OSError:
        return False
    return bool(stages.extract_metadata(source_path, text)["superseded"])


def check_citation_support(citation: Mapping[str, Any], root: Path) -> Optional[str]:
    """``UNSUPPORTED_ASSERTION`` if the span no longer hashes to its record, else None."""
    span = citation["evidence_span"]
    recomputed = rehash_span(root, citation["source_path"], span)
    if recomputed != span["sha256"]:
        return "UNSUPPORTED_ASSERTION"
    return None


def audit_result(result: Mapping[str, Any], root: Path, citations: Optional[list] = None) -> List[str]:
    """Every detectable failure class a produced result exhibits, in a stable order."""
    found: List[str] = []
    if records.result_problem(result) is not None:
        found.append("SCHEMA_FAILURE")
        return found
    cites = list(citations) if citations is not None else []
    stages = result["provenance"].get("stages", [])

    # UNSUPPORTED_ASSERTION / ABSTENTION_FAILURE.
    unsupported = any(check_citation_support(c, root) for c in cites)
    if unsupported:
        found.append("UNSUPPORTED_ASSERTION")
        if result["confidence_state"] == "RESOLVED":
            found.append("ABSTENTION_FAILURE")

    # The primary cited source, whatever citations were passed in.
    primary_path = result["provenance"].get("source_path") if result["source_id"] else None
    primary_stale = isinstance(primary_path, str) and _source_claims_superseded(root, primary_path)

    # CONTRADICTION_MISSED: a primary citation whose own source claims it is
    # superseded, yet the result records no contradiction.
    if result["contradiction_state"] == "NONE":
        stale = primary_stale or any(
            c["contradiction_state"] != "SUPERSEDED" and _source_claims_superseded(root, c["source_path"])
            for c in cites)
        if stale:
            found.append("CONTRADICTION_MISSED")

    # ACL_SCOPE_FAILURE recorded as the stop reason.
    if result["stop_reason"] == "ACL_SCOPE_FAILURE":
        found.append("ACL_SCOPE_FAILURE")

    # WRONG_DOCUMENT_VERSION: abstained on a stale document (the stop reason), or
    # the primary cited source is itself superseded, whatever contradiction_state
    # the result records (a superseded document is never the cited source).
    if result["stop_reason"] == "WRONG_DOCUMENT_VERSION" or primary_stale:
        found.append("WRONG_DOCUMENT_VERSION")

    # MISSING_REQUIRED_SOURCE recorded as the stop reason.
    if result["stop_reason"] == "MISSING_REQUIRED_SOURCE":
        found.append("MISSING_REQUIRED_SOURCE")

    # LOOP_EXHAUSTION_MISREPRESENTED: an exhausted loop reported as a success.
    for entry in stages:
        detail = entry.get("detail") or {}
        exhausted = entry.get("outcome") == "LOOP_EXHAUSTED" or (
            isinstance(detail, dict) and detail.get("outcome") == "LOOP_EXHAUSTED")
        if exhausted and result["confidence_state"] == "RESOLVED":
            found.append("LOOP_EXHAUSTION_MISREPRESENTED")
            break

    return found
