"""Decision records of the agent-pipeline boundary (schema ``secrets-boundary-decision-v1``).

A record carries the checkpoint, the decision, its reason, the caller's ``at`` and one entry per finding
(``kind``, ``rule``, ``digest``, ``location``), where ``location`` is the file path or text label for ``output``
and ``"context"`` for ``context``. It never carries input text: not the scanned values, not the redacted text.
"""

from __future__ import annotations

import json

from secrets_boundary import gate

SCHEMA = "secrets-boundary-decision-v1"
FIELDS = ("schema", "checkpoint", "allow", "reason", "at", "findings")
FINDING_FIELDS = ("kind", "rule", "digest", "location")


def _entry(finding, location: str) -> dict:
    return {"kind": finding.kind, "rule": finding.rule, "digest": finding.digest, "location": location}


def record(decision: gate.Decision, at: int) -> dict:
    """The ``secrets-boundary-decision-v1`` record of ``decision``, made at ``at``."""
    if not isinstance(decision, gate.Decision):
        raise TypeError("decision must be a gate.Decision")
    if type(at) is not int:
        raise TypeError("at must be an int")
    if decision.checkpoint == gate.CONTEXT:
        findings = [_entry(finding, gate.CONTEXT) for finding in decision.findings]
    else:
        findings = [_entry(finding, location) for location, finding in decision.findings]
    return {"schema": SCHEMA, "checkpoint": decision.checkpoint, "allow": decision.allow,
            "reason": decision.reason, "at": at, "findings": findings}


def dumps(rec: dict) -> str:
    """``rec`` as sorted-key, compact JSON."""
    return json.dumps(rec, sort_keys=True, separators=(",", ":"), allow_nan=False)
