"""The candidate registry: an input file, never live discovery.

A registry document has exactly these fields::

    schema            "tool-registry-v1"
    registry_version  non-empty string
    tools             [entry, ...]

A malformed document is a ``RegistryError`` and stops the selection. A
malformed *entry* does not: it is a candidate whose ``registry_entry_valid``
signal is unresolved, so it can be denied but never admitted. An entry has
exactly these fields (``description`` optional)::

    name            tool name: letters, digits and ``_ . : -``, not starting with ``#``
    capability      capability name from the matrix catalog
    evidence_class  the class the registry declares; must agree with the catalog
    resource        {"repo": <name>, "path": <clean relative path, or "." for the whole repo>}
    input_schema    {"type": "object", "properties": {...}, ["required": [...]], ["additionalProperties": bool]}
    description     string; carried, never interpreted (tool descriptions are attack surface)

A tool name that appears twice makes every entry carrying it invalid.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Mapping, Optional

from tool_selection import matrix as M

SCHEMA = "tool-registry-v1"
TOP_FIELDS = frozenset({"schema", "registry_version", "tools"})
ENTRY_FIELDS = frozenset({"name", "capability", "evidence_class", "resource", "input_schema"})
OPTIONAL_FIELDS = frozenset({"description"})
SCHEMA_FIELDS = frozenset({"type", "properties", "required", "additionalProperties"})
NAME = re.compile(r"[A-Za-z0-9_.:-]+")


class RegistryError(ValueError):
    pass


def validate(doc: Any) -> dict:
    """``doc`` itself when its envelope is well formed; raises ``RegistryError`` otherwise."""
    if not isinstance(doc, dict) or set(doc) != TOP_FIELDS:
        raise RegistryError(f"registry must have exactly the fields {sorted(TOP_FIELDS)}")
    if doc["schema"] != SCHEMA:
        raise RegistryError(f"schema must be {SCHEMA!r}")
    if not M.is_name(doc["registry_version"]):
        raise RegistryError("registry_version must be a non-empty string")
    if not isinstance(doc["tools"], list):
        raise RegistryError("tools must be a list")
    return doc


def load_file(path: Path) -> dict:
    try:
        doc = M.read_file(path, "registry")
    except ValueError as exc:
        raise RegistryError(str(exc)) from None
    return validate(doc)


def tool_name(entry: Any) -> Optional[str]:
    name = entry.get("name") if isinstance(entry, dict) else None
    if isinstance(name, str) and NAME.fullmatch(name) and not name.startswith("#"):
        return name
    return None


def duplicate_names(tools: list) -> frozenset:
    seen, dup = set(), set()
    for entry in tools:
        name = tool_name(entry)
        if name in seen:
            dup.add(name)
        seen.add(name)
    return frozenset(dup - {None})


def capability(entry: Any, catalog: Mapping[str, str]) -> Optional[str]:
    """The entry's capability when the catalog knows it, else None."""
    cap = entry.get("capability") if isinstance(entry, dict) else None
    return cap if isinstance(cap, str) and cap in catalog else None


def declared_class(entry: Any) -> Optional[str]:
    cls = entry.get("evidence_class") if isinstance(entry, dict) else None
    return cls if isinstance(cls, str) and cls in M.CLASSES else None


def clean_path(value: Any) -> bool:
    if value == ".":
        return True
    return (isinstance(value, str) and bool(value) and not value.startswith("/") and "\\" not in value
            and all(p not in ("", ".", "..") for p in value.split("/")))


def resource(entry: Any) -> Optional[dict]:
    """``{"repo", "path"}`` when the entry's resource is well formed, else None."""
    res = entry.get("resource") if isinstance(entry, dict) else None
    if isinstance(res, dict) and set(res) == {"repo", "path"} and M.is_name(res["repo"]) and clean_path(res["path"]):
        return res
    return None


def input_schema_problem(schema: Any) -> Optional[str]:
    if not isinstance(schema, dict) or not set(schema) <= SCHEMA_FIELDS or schema.get("type") != "object":
        return "input_schema must be an object schema"
    props = schema.get("properties")
    if not isinstance(props, dict) or not all(M.is_name(k) and isinstance(v, dict) for k, v in props.items()):
        return "input_schema.properties must map names to schemas"
    required = schema.get("required", [])
    if not isinstance(required, list) or len(set(map(str, required))) != len(required) \
            or not all(isinstance(r, str) and r in props for r in required):
        return "input_schema.required must list distinct declared properties"
    if not isinstance(schema.get("additionalProperties", False), bool):
        return "input_schema.additionalProperties must be true or false"
    return None


def entry_problem(entry: Any, catalog: Mapping[str, str], duplicates: frozenset) -> Optional[str]:
    """Why the entry is not a present, schema-valid registry entry, or None."""
    if not isinstance(entry, dict):
        return "registry entry is not an object"
    fields = set(entry)
    if not ENTRY_FIELDS <= fields or not fields <= ENTRY_FIELDS | OPTIONAL_FIELDS:
        return f"registry entry must have exactly {sorted(ENTRY_FIELDS)} (and optionally a description)"
    name = tool_name(entry)
    if name is None:
        return "tool name is missing or malformed"
    if name in duplicates:
        return f"tool name {name!r} is registered more than once"
    if capability(entry, catalog) is None:
        return f"capability {entry['capability']!r} is not in the matrix catalog"
    if "description" in entry and not isinstance(entry["description"], str):
        return "description must be a string"
    return input_schema_problem(entry["input_schema"])
