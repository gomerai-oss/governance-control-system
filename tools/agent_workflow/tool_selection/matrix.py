"""The role tool-surface matrix (doctrine section 4) as policy data: loading and strict validation.

The matrix ships as data (``matrix.json`` next to this module). The pipeline
holds no per-role logic: what a role may see is its row, and writer/reviewer
separation is a property of the rows themselves, checked here when the data
loads. A matrix document has exactly these tables:

``schema``              ``"tool-selection-matrix-v1"``
``matrix_version``      non-empty string, copied into every selection record
``spec``                ``"GOVERNED-TOOL-SELECTION-SPEC-001"``
``admission_threshold`` decimal or fraction string in (0, 1]; ``"1.0"`` in the shipped data
``capabilities``        capability name -> evidence class (one of ``CLASSES``)
``roles``               exactly ``writer``, ``reviewer`` and ``router``, each
                        ``{"doctrine_row", "read_only", "separation_rule",
                        "evidence_classes", "admit", "blocked"}``
``mission_types``       exactly ``MISSION_TYPES``, each a list of admissible evidence classes
``fallback_routes``     each confidence signal -> the route an unresolved signal takes

Rules beyond shape:

- ``elevated`` (final authority, merge, credentials, production runtime) is
  admissible in no row and no mission type;
- a ``read_only`` row names a ``separation_rule`` and admits no mutation class
  (``write``, ``execute``, ``elevated``); the reviewer and router rows are read-only;
- every admitted capability's class is one of its row's evidence classes, and
  no capability is both admitted and blocked.

Any defect is a ``MatrixError``; the pipeline then stops fail-closed. There is
no partial or best-effort matrix.
"""

from __future__ import annotations

import json
from fractions import Fraction
from pathlib import Path
from typing import Any, Iterable, Optional

SCHEMA = "tool-selection-matrix-v1"
SPEC_ID = "GOVERNED-TOOL-SELECTION-SPEC-001"
DEFAULT_PATH = Path(__file__).resolve().parent / "matrix.json"

ROLES = ("writer", "reviewer", "router")
READ_ONLY_ROLES = ("reviewer", "router")
CLASSES = ("read", "draft", "write", "execute", "elevated")
MUTATION_CLASSES = ("write", "execute", "elevated")
ELEVATED = "elevated"
MISSION_TYPES = ("CAPTURE", "PLAN", "IMPLEMENT", "VERIFY", "CLOSEOUT")
# The spec's five confidence signals, in the order they are recorded.
SIGNALS = ("role_resolved", "mission_type_resolved", "resource_in_scope", "registry_entry_valid",
           "evidence_class_resolved")
ROUTES = ("BOUNDED_CLARIFICATION", "ALTERNATE_REVIEWER", "HITL_GATE")

TOP_FIELDS = frozenset({"schema", "matrix_version", "spec", "admission_threshold", "capabilities", "roles",
                        "mission_types", "fallback_routes"})
ROW_FIELDS = frozenset({"doctrine_row", "read_only", "separation_rule", "evidence_classes", "admit", "blocked"})


class MatrixError(ValueError):
    pass


def is_name(value: object) -> bool:
    return isinstance(value, str) and bool(value) and value == value.strip()


def threshold(text: Any) -> Optional[Fraction]:
    """The admission threshold ``text`` denotes, or None when it is not a string in (0, 1]."""
    if not isinstance(text, str):
        return None
    try:
        value = Fraction(text)
    except (ValueError, ZeroDivisionError):
        return None
    return value if 0 < value <= 1 else None


def _fields(value: Any, fields: Iterable[str], where: str) -> dict:
    fields = frozenset(fields)
    if not isinstance(value, dict) or set(value) != fields:
        raise MatrixError(f"{where} must have exactly the fields {sorted(fields)}")
    return value


def _name(value: Any, where: str) -> str:
    if not is_name(value):
        raise MatrixError(f"{where} must be a non-empty string without surrounding whitespace")
    return value


def _names(value: Any, where: str, allowed: Optional[Iterable[str]] = None) -> list:
    if not isinstance(value, list):
        raise MatrixError(f"{where} must be a list")
    for i, item in enumerate(value):
        _name(item, f"{where}[{i}]")
    if len(set(value)) != len(value):
        raise MatrixError(f"{where} has duplicate entries")
    if allowed is not None:
        allowed = set(allowed)
        unknown = [v for v in value if v not in allowed]
        if unknown:
            raise MatrixError(f"{where}: unknown {unknown}")
    return value


def _table(value: Any, where: str) -> dict:
    if not isinstance(value, dict) or not value:
        raise MatrixError(f"{where} must be a non-empty object")
    for key in value:
        _name(key, f"{where} key")
    return value


def validate(doc: Any) -> dict:
    """A validated copy of ``doc``; raises ``MatrixError`` naming the first defect."""
    _fields(doc, TOP_FIELDS, "matrix")
    if doc["schema"] != SCHEMA:
        raise MatrixError(f"schema must be {SCHEMA!r}")
    if doc["spec"] != SPEC_ID:
        raise MatrixError(f"spec must be {SPEC_ID!r}")
    _name(doc["matrix_version"], "matrix_version")
    if threshold(doc["admission_threshold"]) is None:
        raise MatrixError("admission_threshold must be a decimal or fraction string in (0, 1]")

    caps = _table(doc["capabilities"], "capabilities")
    for cap, cls in caps.items():
        if cls not in CLASSES:
            raise MatrixError(f"capabilities[{cap}] must be one of {list(CLASSES)}")

    roles = _fields(doc["roles"], ROLES, "roles")
    for role in ROLES:
        where = f"roles.{role}"
        row = _fields(roles[role], ROW_FIELDS, where)
        _name(row["doctrine_row"], f"{where}.doctrine_row")
        if not isinstance(row["read_only"], bool):
            raise MatrixError(f"{where}.read_only must be true or false")
        if role in READ_ONLY_ROLES and not row["read_only"]:
            raise MatrixError(f"{where} must be read-only (doctrine section 4.1)")
        if row["read_only"]:
            _name(row["separation_rule"], f"{where}.separation_rule")
        elif row["separation_rule"] is not None:
            raise MatrixError(f"{where}.separation_rule must be null on a mutation-capable row")
        classes = _names(row["evidence_classes"], f"{where}.evidence_classes", CLASSES)
        if ELEVATED in classes:
            raise MatrixError(f"{where}: the {ELEVATED!r} class is admissible in no row")
        if row["read_only"] and set(classes) & set(MUTATION_CLASSES):
            raise MatrixError(f"{where}: a read-only row admits no mutation class")
        admit = _names(row["admit"], f"{where}.admit", caps)
        for cap in admit:
            if caps[cap] not in classes:
                raise MatrixError(f"{where}.admit: {cap!r} is {caps[cap]!r}-class, outside the row's evidence classes")
        blocked = row["blocked"]
        if not isinstance(blocked, dict):
            raise MatrixError(f"{where}.blocked must be an object")
        _names(list(blocked), f"{where}.blocked", caps)
        for cap, reason in blocked.items():
            _name(reason, f"{where}.blocked[{cap}]")
        both = sorted(set(admit) & set(blocked))
        if both:
            raise MatrixError(f"{where}: {both} are both admitted and blocked")

    mission_types = _fields(doc["mission_types"], MISSION_TYPES, "mission_types")
    for mtype in MISSION_TYPES:
        classes = _names(mission_types[mtype], f"mission_types.{mtype}", CLASSES)
        if ELEVATED in classes:
            raise MatrixError(f"mission_types.{mtype}: the {ELEVATED!r} class is admissible in no mission type")

    routes = _fields(doc["fallback_routes"], SIGNALS, "fallback_routes")
    for signal in SIGNALS:
        if routes[signal] not in ROUTES:
            raise MatrixError(f"fallback_routes.{signal} must be one of {list(ROUTES)}")

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
    """Load and validate the matrix at ``path`` (default: the shipped matrix)."""
    try:
        doc = read_file(path, "matrix")
    except ValueError as exc:
        raise MatrixError(str(exc)) from None
    return validate(doc)
