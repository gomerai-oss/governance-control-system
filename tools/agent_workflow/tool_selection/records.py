"""Selection audit records and their EPAP link material.

Every selection, whatever its disposition, yields one record::

    {"schema": "tool-selection-record-v1",
     "request_id": ... | None, "request_digest": <sha256 of the canonical request> | None,
     "role": <resolved role> | None, "mission_type": <resolved type> | None, "mission_id": ... | None,
     "matrix_version": ... | None, "matrix_digest": ... | None, "threshold": "1.0" | None,
     "registry_version": ... | None, "registry_digest": ... | None,
     "disposition": "ADMITTED" | "BOUNDED_CLARIFICATION" | "NO_TOOL_REQUIRED" | "STOP_AND_FAIL_CLOSED",
     "failed_step": None | <step>, "reason": ..., "route": None | <fallback route of a stop>,
     "needs": [...], "unmet_needs": [...],
     "candidates": [{"tool", "capability", "evidence_class", "outcome": "ADMIT" | "DENY" | "FALLBACK",
                     "step", "reason", "rule", "signals": {<five signals>}, "score": "<n>/5", "route"}],
     "pre_fallback_surface": [...], "admitted_surface": [...],
     "fallbacks": [{"tool", "route", "unresolved": [<signal>, ...]}]}

``reconstruct_surface`` recovers the admitted surface from the per-tool
outcomes alone; ``record_problem`` checks that a record is internally
consistent (its surface is exactly what its outcomes admit, and no wider than
its pre-fallback surface).

``link_material`` turns a record into the ``signed`` part of an EPAP link in
the leg-2 pack format (``epap.links``): matrix, registry and request are its
materials, its products are those plus the record, and the record is also its
byproducts. Each artifact is named by the SHA-256 of its canonical JSON bytes
(``epap.signing.canonical_bytes``).
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from epap import links, signing
from tool_selection import matrix as M

RECORD_SCHEMA = "tool-selection-record-v1"
LINK_NAME = "TOOL_SELECTION"
COMMAND = "tool_selection.select"

ADMITTED = "ADMITTED"
BOUNDED_CLARIFICATION = "BOUNDED_CLARIFICATION"
NO_TOOL_REQUIRED = "NO_TOOL_REQUIRED"
STOP_AND_FAIL_CLOSED = "STOP_AND_FAIL_CLOSED"
DISPOSITIONS = (ADMITTED, BOUNDED_CLARIFICATION, NO_TOOL_REQUIRED, STOP_AND_FAIL_CLOSED)

ADMIT = "ADMIT"
DENY = "DENY"
FALLBACK = "FALLBACK"

RECORD_FIELDS = ("schema", "request_id", "request_digest", "role", "mission_type", "mission_id",
                 "matrix_version", "matrix_digest", "threshold", "registry_version", "registry_digest",
                 "disposition", "failed_step", "reason", "route", "needs", "unmet_needs", "candidates",
                 "pre_fallback_surface", "admitted_surface", "fallbacks")


def digest(value: Any) -> Optional[str]:
    """SHA-256 of ``value``'s canonical JSON, or None when it has no canonical form."""
    try:
        return signing.sha256_hex(signing.canonical_bytes(value))
    except (signing.CanonicalError, TypeError, ValueError, RecursionError):
        return None


def make_record(**fields: Any) -> dict:
    record = {name: fields[name] for name in RECORD_FIELDS if name != "schema"}
    return {"schema": RECORD_SCHEMA, **record}


def reconstruct_surface(record: Mapping) -> frozenset:
    """The admitted surface, recomputed from the record's per-tool outcomes."""
    return frozenset(c["tool"] for c in record["candidates"] if c["outcome"] == ADMIT)


def record_problem(record: Any) -> Optional[str]:
    """Why ``record`` is not a consistent selection record, or None."""
    if not isinstance(record, dict) or set(record) != set(RECORD_FIELDS):
        return f"record must have exactly the fields {list(RECORD_FIELDS)}"
    if record["schema"] != RECORD_SCHEMA or record["disposition"] not in DISPOSITIONS:
        return "not a tool-selection record"
    surface = reconstruct_surface(record)
    if sorted(surface) != record["admitted_surface"]:
        return "admitted_surface differs from the surface the per-tool outcomes admit"
    if not surface <= set(record["pre_fallback_surface"]):
        return "admitted surface is wider than the pre-fallback surface"
    for c in record["candidates"]:
        if c["outcome"] == ADMIT and (set(c["signals"]) != set(M.SIGNALS) or not all(c["signals"].values())):
            return f"{c['tool']!r} is admitted with an unresolved signal"
    if record["disposition"] in (STOP_AND_FAIL_CLOSED, NO_TOOL_REQUIRED) and surface:
        return f"a {record['disposition']} record admits nothing"
    fallen = {f["tool"] for f in record["fallbacks"]}
    if fallen != {c["tool"] for c in record["candidates"] if c["outcome"] == FALLBACK}:
        return "fallbacks differ from the candidates routed to fallback"
    return None


def artifact_paths(record: Mapping) -> dict:
    """Pack-relative paths of the selection's artifacts, keyed by role."""
    paths = {}
    for role, folder in (("matrix", "matrix"), ("registry", "registries"), ("request", "requests")):
        if record.get(f"{role}_digest"):
            paths[role] = f"tool_selection/{folder}/{record[f'{role}_digest']}.json"
    paths["record"] = f"tool_selection/records/{digest(dict(record))}.json"
    return paths


def link_material(record: Mapping) -> dict:
    """The ``signed`` part of an EPAP link recording one selection."""
    record = dict(record)
    paths = artifact_paths(record)
    materials = {paths[role]: {"sha256": record[f"{role}_digest"]}
                 for role in ("matrix", "registry", "request") if role in paths}
    # Leg-2 products are the whole artifact set after the step, not only what it added.
    products = {**materials, paths["record"]: {"sha256": digest(record)}}
    command = [COMMAND, record.get("matrix_version") or "matrix-unavailable"]
    return links.make_link(LINK_NAME, materials, products, command, record)
