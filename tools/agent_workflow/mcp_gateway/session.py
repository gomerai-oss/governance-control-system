"""The launcher's session file and the per-session policy overlay.

The launcher (the dispatcher) writes one session file outside the agent's
checkout. It has exactly these fields, and no other key at either level::

    {"principal": <id>, "acting_identity": <id>, "role": <governed role>,
     "mission": {"id": <mission id>, "authority_ref": "MISSION-ROUTER-001",
                 "base_sha": <40 lowercase hex>, "round": <int >= 1>},
     "resources": [<policy resource id>, ...],
     "issued_at": <epoch seconds>, "expires_at": <epoch seconds>}

There is no approval field: the gateway grants nothing on a session's word
beyond the overlay below, whose approvals are always empty. The gateway never
mints identity. A session that is missing, unreadable, malformed, expired, has
an unknown key or another ``authority_ref``, or lies inside the checkout root
is invalid, and every call under it is DENY with fabric stop 13.

``overlay(policy, session)`` is the shipped policy plus exactly one
``missions[<mission id>]`` entry and that id appended to
``authority_refs["MISSION-ROUTER-001"].missions``. It is built in memory, never
written, and must pass ``mcp_auth.policy`` validation unchanged.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional, Tuple

from mcp_auth import policy as P
from mcp_auth.decide import MAX_EPOCH

AUTHORITY_REF = "MISSION-ROUTER-001"
PRINCIPAL_KIND = "agent"
SESSION_FIELDS = frozenset({"principal", "acting_identity", "role", "mission", "resources",
                            "issued_at", "expires_at"})
MISSION_FIELDS = frozenset({"id", "authority_ref", "base_sha", "round"})
MAX_BYTES = 65536
_SHA = re.compile(r"[0-9a-f]{40}")


class SessionError(ValueError):
    pass


@dataclass(frozen=True)
class Session:
    session_id: str
    principal: str
    acting_identity: str
    role: str
    mission_id: str
    authority_ref: str
    base_sha: str
    round: int
    resources: Tuple[str, ...]
    issued_at: int
    expires_at: int

    def live_at(self, now: int) -> bool:
        return self.issued_at <= now < self.expires_at

    def mission_evidence(self) -> dict:
        return {"id": self.mission_id, "authority_ref": self.authority_ref,
                "base_sha": self.base_sha, "round": self.round}


def _no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise SessionError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _no_float(text):
    raise SessionError(f"non-integer number {text}")


def parse(data: bytes) -> Session:
    """A validated session from the file's bytes; any defect is ``SessionError``."""
    try:
        doc = json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicates,
                         parse_float=_no_float, parse_constant=_no_float)
    except SessionError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise SessionError("session is not valid JSON") from None
    if not isinstance(doc, dict) or set(doc) != SESSION_FIELDS:
        raise SessionError(f"session must have exactly the fields {sorted(SESSION_FIELDS)}")
    for field in ("principal", "acting_identity", "role"):
        if not P.is_name(doc[field]):
            raise SessionError(f"session {field} must be a non-empty string")
    mission = doc["mission"]
    if not isinstance(mission, dict) or set(mission) != MISSION_FIELDS:
        raise SessionError(f"session mission must have exactly the fields {sorted(MISSION_FIELDS)}")
    if not P.is_name(mission["id"]):
        raise SessionError("session mission id must be a non-empty string")
    if mission["authority_ref"] != AUTHORITY_REF:
        raise SessionError(f"session mission authority_ref must be {AUTHORITY_REF!r}")
    if not isinstance(mission["base_sha"], str) or not _SHA.fullmatch(mission["base_sha"]):
        raise SessionError("session mission base_sha must be 40 lowercase hex characters")
    if not P.is_int(mission["round"]) or mission["round"] < 1:
        raise SessionError("session mission round must be an integer >= 1")
    resources = doc["resources"]
    if (not isinstance(resources, list) or not resources or not all(P.is_name(r) for r in resources)
            or len(set(resources)) != len(resources)):
        raise SessionError("session resources must be a non-empty list of distinct resource ids")
    issued, expires = doc["issued_at"], doc["expires_at"]
    if not (P.is_int(issued) and P.is_int(expires)) or not 0 <= issued < expires <= MAX_EPOCH:
        raise SessionError("session time bounds must be integer epoch seconds with issued_at < expires_at")
    return Session(
        session_id="session-" + hashlib.sha256(data).hexdigest()[:16],
        principal=doc["principal"], acting_identity=doc["acting_identity"], role=doc["role"],
        mission_id=mission["id"], authority_ref=mission["authority_ref"],
        base_sha=mission["base_sha"], round=mission["round"],
        resources=tuple(resources), issued_at=issued, expires_at=expires)


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def load(path: Optional[Any], root: Any) -> Session:
    """Load the session file at ``path``; it must lie outside the checkout ``root``."""
    if path is None:
        raise SessionError("no session file was given")
    path, root = Path(path), Path(root)
    try:
        candidates = (path.absolute(), path.resolve())
        roots = (root.absolute(), root.resolve())
        if any(_inside(c, r) for c in candidates for r in roots):
            raise SessionError("session file lies inside the checkout")
        if path.is_symlink() or not path.is_file():
            raise SessionError("session file is missing or not a regular file")
        data = path.read_bytes()
    except OSError as exc:
        raise SessionError(f"session file is unreadable ({exc.strerror})") from None
    if len(data) > MAX_BYTES:
        raise SessionError("session file is too large")
    return parse(data)


def overlay(policy: Mapping, session: Session) -> dict:
    """The validated shipped policy plus this session's one mission, in memory only."""
    doc = copy.deepcopy(dict(policy))
    mission_id = session.mission_id
    missions, refs = doc.get("missions"), doc.get("authority_refs")
    ref = refs.get(AUTHORITY_REF) if isinstance(refs, dict) else None
    if not isinstance(missions, dict) or not isinstance(ref, dict) or not isinstance(ref.get("missions"), list):
        raise SessionError(f"policy has no {AUTHORITY_REF!r} authority to bind the session to")
    if mission_id in missions or mission_id in ref["missions"]:
        raise SessionError(f"mission {mission_id!r} is already in the shipped policy")
    unknown = [r for r in session.resources if r not in doc.get("resources", {})]
    if unknown:
        raise SessionError(f"session names resources unknown to policy: {unknown}")
    missions[mission_id] = {
        "authority_ref": AUTHORITY_REF,
        "resources": list(session.resources),
        "approvals": {"restricted": [], "credential": [], "runtime": []},
    }
    ref["missions"] = list(ref["missions"]) + [mission_id]
    try:
        return P.validate(doc)
    except P.PolicyError as exc:
        raise SessionError(f"overlaid policy is invalid: {exc}") from None
