"""Policy data for the MCP authorization fabric: loading and strict validation.

Policy ships as data (``policy.json`` next to this module). The engine holds no
per-role logic: everything a role may do is a grant in the data, and every
grant names the SOT authority reference it rests on.

A policy document has exactly these tables:

``schema``          ``"mcp-auth-policy-v1"``
``policy_version``  non-empty string, copied into every decision record
``session``         ``{"max_ttl_seconds": <int>}``
``actions``         action name -> ``{"kind": "read" | "write" | "execute"}``
``classes``         exactly ``rag`` and ``epap``, each ``{"read": [...], "mutation": [...]}``;
                    ``rag`` has no mutation action (doctrine section 7.1)
``authority_refs``  SOT reference -> ``{"kind", "source", "missions"}``; the missions it covers
``roles``           governed role names
``principals``      principal id -> ``{"kind", "acting_identities", "roles"}``
``resources``       resource id -> ``{"class", "restricted", "credential_bearing"}``
``missions``        mission id -> ``{"authority_ref", "resources", "approvals"}``;
                    approvals are ``{"restricted", "credential", "runtime"}``
``grants``          ``[{"id", "effect", "role", "class", "resources", "actions",
                    "authority_ref", "evidence"}]``

Any defect is a ``PolicyError``, which the engine turns into stop condition 12.
There is no partial or best-effort policy.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Optional

SCHEMA = "mcp-auth-policy-v1"
DEFAULT_PATH = Path(__file__).resolve().parent / "policy.json"

CLASSES = ("rag", "epap")
ACTION_KINDS = ("read", "write", "execute")
AUTHORITY_KINDS = ("SPEC", "ABC", "HITL", "DOCTRINE", "POLICY")
PRINCIPAL_KINDS = ("human", "agent", "service")
EVIDENCE = ("none", "audit_record", "epap_packet", "pr_evidence")
IMPLICATIONS = ("runtime_bridge", "trading_system", "production_system", "external_exposure")
EFFECTS = ("allow", "deny")

TOP_FIELDS = frozenset({"schema", "policy_version", "session", "actions", "classes", "authority_refs",
                        "roles", "principals", "resources", "missions", "grants"})
GRANT_FIELDS = frozenset({"id", "effect", "role", "class", "resources", "actions", "authority_ref", "evidence"})


class PolicyError(ValueError):
    pass


def is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def is_name(value: object) -> bool:
    return isinstance(value, str) and bool(value) and value == value.strip()


def _fields(value: Any, fields: Iterable[str], where: str) -> dict:
    fields = frozenset(fields)
    if not isinstance(value, dict) or set(value) != fields:
        raise PolicyError(f"{where} must have exactly the fields {sorted(fields)}")
    return value


def _name(value: Any, where: str) -> str:
    if not is_name(value):
        raise PolicyError(f"{where} must be a non-empty string without surrounding whitespace")
    return value


def _names(value: Any, where: str, allowed: Optional[Iterable[str]] = None, nonempty: bool = False) -> list:
    if not isinstance(value, list):
        raise PolicyError(f"{where} must be a list")
    for i, item in enumerate(value):
        _name(item, f"{where}[{i}]")
    if len(set(value)) != len(value):
        raise PolicyError(f"{where} has duplicate entries")
    if nonempty and not value:
        raise PolicyError(f"{where} must not be empty")
    if allowed is not None:
        allowed = set(allowed)
        unknown = [v for v in value if v not in allowed]
        if unknown:
            raise PolicyError(f"{where}: unknown {unknown}")
    return value


def _table(value: Any, where: str, nonempty: bool = False) -> dict:
    if not isinstance(value, dict):
        raise PolicyError(f"{where} must be an object")
    if nonempty and not value:
        raise PolicyError(f"{where} must not be empty")
    for key in value:
        _name(key, f"{where} key")
    return value


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise PolicyError(f"{where} must be true or false")
    return value


def _choice(value: Any, choices: Iterable[str], where: str) -> str:
    choices = tuple(choices)
    if value not in choices or not isinstance(value, str):
        raise PolicyError(f"{where} must be one of {list(choices)}")
    return value


def validate(doc: Any) -> dict:
    """A validated copy of ``doc``; raises ``PolicyError`` naming the first defect."""
    _fields(doc, TOP_FIELDS, "policy")
    if doc["schema"] != SCHEMA:
        raise PolicyError(f"schema must be {SCHEMA!r}")
    _name(doc["policy_version"], "policy_version")
    ttl = _fields(doc["session"], {"max_ttl_seconds"}, "session")["max_ttl_seconds"]
    if not is_int(ttl) or ttl <= 0:
        raise PolicyError("session.max_ttl_seconds must be a positive integer")

    actions = _table(doc["actions"], "actions", nonempty=True)
    for name, entry in actions.items():
        _choice(_fields(entry, {"kind"}, f"actions[{name}]")["kind"], ACTION_KINDS, f"actions[{name}].kind")

    classes = _table(doc["classes"], "classes")
    if set(classes) != set(CLASSES):
        raise PolicyError(f"classes must be exactly {list(CLASSES)}")
    placed = {}
    for cls in CLASSES:
        entry = _fields(classes[cls], {"read", "mutation"}, f"classes.{cls}")
        for level, kind in (("read", "read"), ("mutation", "write")):
            names = _names(entry[level], f"classes.{cls}.{level}", actions, nonempty=(level == "read"))
            for action in names:
                if actions[action]["kind"] != kind:
                    raise PolicyError(f"classes.{cls}.{level}: {action!r} must be of kind {kind!r}")
                if action in placed:
                    raise PolicyError(f"classes.{cls}.{level}: {action!r} is already placed in {placed[action]}")
                placed[action] = f"classes.{cls}.{level}"
    if classes["rag"]["mutation"]:
        raise PolicyError("classes.rag.mutation: the rag class has no write-side action")

    roles = _names(doc["roles"], "roles", nonempty=True)
    missions = _table(doc["missions"], "missions")
    resources = _table(doc["resources"], "resources")
    for rid, entry in resources.items():
        _fields(entry, {"class", "restricted", "credential_bearing"}, f"resources[{rid}]")
        _choice(entry["class"], CLASSES, f"resources[{rid}].class")
        _bool(entry["restricted"], f"resources[{rid}].restricted")
        _bool(entry["credential_bearing"], f"resources[{rid}].credential_bearing")

    refs = _table(doc["authority_refs"], "authority_refs", nonempty=True)
    for ref, entry in refs.items():
        _fields(entry, {"kind", "source", "missions"}, f"authority_refs[{ref}]")
        _choice(entry["kind"], AUTHORITY_KINDS, f"authority_refs[{ref}].kind")
        _name(entry["source"], f"authority_refs[{ref}].source")
        _names(entry["missions"], f"authority_refs[{ref}].missions", missions)

    for pid, entry in _table(doc["principals"], "principals").items():
        _fields(entry, {"kind", "acting_identities", "roles"}, f"principals[{pid}]")
        _choice(entry["kind"], PRINCIPAL_KINDS, f"principals[{pid}].kind")
        _names(entry["acting_identities"], f"principals[{pid}].acting_identities", nonempty=True)
        _names(entry["roles"], f"principals[{pid}].roles", roles, nonempty=True)

    for mid, entry in missions.items():
        _fields(entry, {"authority_ref", "resources", "approvals"}, f"missions[{mid}]")
        _choice(entry["authority_ref"], refs, f"missions[{mid}].authority_ref")
        scoped = _names(entry["resources"], f"missions[{mid}].resources", resources)
        approvals = _fields(entry["approvals"], {"restricted", "credential", "runtime"}, f"missions[{mid}].approvals")
        _names(approvals["restricted"], f"missions[{mid}].approvals.restricted", scoped)
        _names(approvals["credential"], f"missions[{mid}].approvals.credential")
        _names(approvals["runtime"], f"missions[{mid}].approvals.runtime", IMPLICATIONS)

    grants = doc["grants"]
    if not isinstance(grants, list):
        raise PolicyError("grants must be a list")
    ids = set()
    for i, grant in enumerate(grants):
        where = f"grants[{i}]"
        _fields(grant, GRANT_FIELDS, where)
        gid = _name(grant["id"], f"{where}.id")
        if gid in ids:
            raise PolicyError(f"{where}: duplicate grant id {gid!r}")
        ids.add(gid)
        _choice(grant["effect"], EFFECTS, f"{where}.effect")
        _choice(grant["role"], roles, f"{where}.role")
        cls = _choice(grant["class"], CLASSES, f"{where}.class")
        in_class = [r for r, e in resources.items() if e["class"] == cls]
        _names(grant["resources"], f"{where}.resources", in_class, nonempty=True)
        grant_actions = _names(grant["actions"], f"{where}.actions",
                               classes[cls]["read"] + classes[cls]["mutation"], nonempty=True)
        _choice(grant["authority_ref"], refs, f"{where}.authority_ref")
        _choice(grant["evidence"], EVIDENCE, f"{where}.evidence")
        mutating = [a for a in grant_actions if a in classes[cls]["mutation"]]
        if grant["effect"] == "allow" and mutating:
            if len(grant_actions) != 1 or len(grant["resources"]) != 1:
                raise PolicyError(f"{where}: a mutation grant must name exactly one action and one resource")
            if grant["evidence"] == "none":
                raise PolicyError(f"{where}: a mutation grant must carry an evidence obligation")

    return json.loads(json.dumps(doc))


def _no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise PolicyError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _no_float(text):
    raise PolicyError(f"non-integer number {text}")


def load_bytes(data: bytes) -> dict:
    """Parse and validate policy JSON; duplicate keys, floats and NaN are malformed."""
    try:
        doc = json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicates,
                         parse_float=_no_float, parse_constant=_no_float)
    except PolicyError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise PolicyError(f"policy is not valid JSON: {exc}") from None
    return validate(doc)


def load_file(path: Path = DEFAULT_PATH) -> dict:
    """Load policy from ``path``; an unreadable file is ``PolicyError`` (data unavailable)."""
    path = Path(path)
    try:
        if path.is_symlink() or not path.is_file():
            raise PolicyError(f"{path.name}: authorization data unavailable")
        data = path.read_bytes()
    except OSError as exc:
        raise PolicyError(f"{path.name}: authorization data unavailable ({exc.strerror})") from None
    return load_bytes(data)
