"""The evidence record (``evidence-record-v1``, §3m item 1).

A record has a closed set of fields. Inputs and outputs are SHA-256 digests of the canonical bytes, never content:
a record never holds a secret or agent text. The reason is one line that has passed the quarantine (§3j). A record's
digest is the SHA-256 of its canonical bytes (``epap.signing.canonical_bytes``), and a run's stored line is exactly
those bytes.

The list of actions is closed and versioned: each has one class. A new action (a harness call, a memory operation) is
added here by a spec amendment, never at run time.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Mapping, Optional

from epap.signing import CanonicalError, canonical_bytes, is_hex, sha256_hex
from evidence import EvidenceError
from mission_dispatch.quarantine import inline

SCHEMA = "evidence-record-v1"
CLASSES = ("read", "write", "send", "decide", "refuse", "withdraw")
RESULTS = ("done", "refused", "failed")
AUTHORITY_KINDS = ("plan", "hitl_command", "spec_rule")
REASON_LIMIT = 300
REF_LIMIT = 200

# Every action the pipeline records today, with its class (§3m item 1). Closed: anything else is refused.
ACTIONS: Mapping[str, str] = {
    # the router (MISSION-ROUTER-001 Amendment 018)
    "router.decision": "decide",
    "router.merge": "write",
    "router.refusal": "refuse",
    "router.approval_request": "send",
    "router.landing": "write",
    "router.halt": "decide",
    "router.retry": "decide",
    "router.hitl_command": "read",
    "router.branch": "write",
    "router.comment": "send",
    "router.dispatch": "send",
    "router.issue": "write",
    "router.label": "write",
    # the dispatcher
    "dispatch.prepare": "write",
    "dispatch.run": "write",
    "dispatch.egress": "decide",
    "dispatch.collect": "read",
    "dispatch.publish": "write",
    "dispatch.report": "send",
    "dispatch.refusal": "refuse",
    # the gateway, the checks job and the credentials check
    "gateway.tool": "decide",
    "checks.check": "decide",
    "credentials.finding": "decide",
    # withdrawal (§3m item 4)
    "evidence.withdraw": "withdraw",
}

FIELDS = frozenset({"schema", "id", "seq", "time", "actor", "action", "class", "subject", "inputs", "outputs",
                    "result", "reason", "authority", "prev", "withdraws"})
SUBJECT_FIELDS = frozenset({"mission", "round", "run", "pr", "commit"})
_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_NAME = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
_RUN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_ACTOR = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.\[\]-]{0,99}")


def digest(value: Any) -> str:
    """The SHA-256 of a value's canonical bytes: a record's digest, or an input's or output's."""
    return sha256_hex(canonical_bytes(value))


def genesis(run: str) -> str:
    """The ``prev`` of a run's first record: bound to the run, so a record cannot be moved into another run."""
    return digest({"schema": SCHEMA, "run": run})


def record_id(run: str, seq: int) -> str:
    return f"{run}/{seq}"


def _int_or_none(value: object) -> bool:
    return value is None or (isinstance(value, int) and not isinstance(value, bool) and value >= 0)


def problems(rec: object) -> list:
    """What makes ``rec`` not a well-formed record; empty when it is one. The chain is checked by ``verify``."""
    if not isinstance(rec, dict):
        return ["a record must be an object"]
    out = []
    keys = set(rec)
    if keys - FIELDS:
        out.append(f"unknown fields: {', '.join(sorted(keys - FIELDS))}")
    missing = FIELDS - keys - {"withdraws"}
    if missing:
        return out + [f"missing fields: {', '.join(sorted(missing))}"]
    if rec["schema"] != SCHEMA:
        out.append(f"schema must be {SCHEMA}")
    subject = rec["subject"]
    if not (isinstance(subject, dict) and set(subject) == SUBJECT_FIELDS):
        return out + [f"subject must have exactly: {', '.join(sorted(SUBJECT_FIELDS))}"]
    run = subject["run"]
    if not (isinstance(run, str) and _RUN.fullmatch(run)):
        out.append("subject.run must be a run id")
    if not (subject["mission"] is None or isinstance(subject["mission"], str)):
        out.append("subject.mission must be a string or null")
    if not (_int_or_none(subject["round"]) and _int_or_none(subject["pr"])):
        out.append("subject.round and subject.pr must be non-negative integers or null")
    if not (subject["commit"] is None or is_hex(subject["commit"], 40)):
        out.append("subject.commit must be a 40-hex commit SHA or null")
    seq = rec["seq"]
    if not (isinstance(seq, int) and not isinstance(seq, bool) and seq >= 0):
        out.append("seq must be a non-negative integer")
    elif isinstance(run, str) and rec["id"] != record_id(run, seq):
        out.append("id must be <run>/<seq>")
    if not (isinstance(rec["time"], str) and _TIME.fullmatch(rec["time"])):
        out.append("time must be YYYY-MM-DDTHH:MM:SSZ")
    actor = rec["actor"]
    if not (isinstance(actor, dict) and set(actor) == {"name", "account_id"}
            and isinstance(actor["name"], str) and _ACTOR.fullmatch(actor["name"])
            and (actor["account_id"] is None or (_int_or_none(actor["account_id"]) and actor["account_id"] > 0))):
        out.append("actor must be {name, account_id} with a positive account id or null")
    action = rec["action"]
    if action not in ACTIONS:
        out.append(f"action {action!r} is not in the closed list")
    elif rec["class"] != ACTIONS[action]:
        out.append(f"action {action} has class {ACTIONS[action]}, not {rec['class']!r}")
    for side in ("inputs", "outputs"):
        part = rec[side]
        if not (isinstance(part, dict) and all(isinstance(k, str) and _NAME.fullmatch(k) and is_hex(v, 64)
                                               for k, v in part.items())):
            out.append(f"{side} must map names to SHA-256 digests (digests only, never content)")
    if rec["result"] not in RESULTS:
        out.append(f"result must be one of {', '.join(RESULTS)}")
    reason = rec["reason"]
    if not (isinstance(reason, str) and len(reason) <= REASON_LIMIT and reason == inline(reason, REASON_LIMIT)):
        out.append("reason must be one quarantined line of at most 300 characters")
    authority = rec["authority"]
    if not (isinstance(authority, dict) and set(authority) == {"kind", "ref"} and authority["kind"] in AUTHORITY_KINDS
            and isinstance(authority["ref"], str) and 0 < len(authority["ref"]) <= REF_LIMIT
            and authority["ref"] == inline(authority["ref"], REF_LIMIT)):
        out.append(f"authority must be {{kind, ref}} with kind one of {', '.join(AUTHORITY_KINDS)}")
    if not is_hex(rec["prev"], 64):
        out.append("prev must be a SHA-256 digest")
    withdraws = rec.get("withdraws")
    if rec["class"] == "withdraw":
        if not (isinstance(withdraws, dict) and set(withdraws) == {"id", "digest"} and isinstance(withdraws["id"], str)
                and is_hex(withdraws["digest"], 64)):
            out.append("a withdrawal must name the record it withdraws: {id, digest}")
        if isinstance(authority, dict) and authority.get("kind") != "hitl_command":
            out.append("a withdrawal is made by HITL direction only (authority kind hitl_command)")
    elif "withdraws" in rec:
        out.append("only a withdrawal names a record it withdraws")
    try:
        canonical_bytes(rec)
    except CanonicalError as exc:
        out.append(str(exc))
    return out


def make(*, run: str, seq: int, prev: str, time: str, actor: str, account_id: Optional[int], action: str,
         result: str, authority_kind: str, authority_ref: str, reason: str = "", mission: Optional[str] = None,
         round_n: Optional[int] = None, pr: Optional[int] = None, commit: Optional[str] = None,
         inputs: Optional[Mapping[str, str]] = None, outputs: Optional[Mapping[str, str]] = None,
         withdraws: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    """A record, with its class taken from the closed list and its reason and authority passed through the
    quarantine. Raises ``EvidenceError`` when the result is not a well-formed record."""
    rec: Dict[str, Any] = {
        "schema": SCHEMA, "id": record_id(run, seq), "seq": seq, "time": time,
        "actor": {"name": actor, "account_id": account_id},
        "action": action, "class": ACTIONS.get(action, ""),
        "subject": {"mission": mission, "round": round_n, "run": run, "pr": pr, "commit": commit},
        "inputs": dict(inputs or {}), "outputs": dict(outputs or {}),
        "result": result, "reason": inline(reason, REASON_LIMIT),
        "authority": {"kind": authority_kind, "ref": inline(authority_ref, REF_LIMIT)},
        "prev": prev,
    }
    if withdraws is not None:
        rec["withdraws"] = dict(withdraws)
    found = problems(rec)
    if found:
        raise EvidenceError("; ".join(found))
    return rec
