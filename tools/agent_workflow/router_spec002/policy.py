"""Policy tables (ROUTER-POLICY-SPEC-002 sections 3a-3d) and path classification.

All routing judgment lives in ``policy_tables.json``. This module only loads,
validates, and applies those tables; it holds no per-path or per-class logic.
"""

from __future__ import annotations

import json
import unicodedata
from fnmatch import fnmatchcase
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, FrozenSet, Mapping, Optional, Sequence, Tuple

TABLES_PATH = Path(__file__).with_name("policy_tables.json")

AUTHORITY = "AUTHORITY"
AGENT_POLICY = "AGENT_POLICY"
TOOL_CONFIG = "TOOL_CONFIG"
CODE = "CODE"
PROBE_EVIDENCE = "PROBE_EVIDENCE"
INERT = "INERT"
FAMILIES: FrozenSet[str] = frozenset(
    {AUTHORITY, AGENT_POLICY, TOOL_CONFIG, CODE, PROBE_EVIDENCE, INERT}
)

ACKNOWLEDGED = "ACKNOWLEDGED"
WAIVED = "WAIVED"
HITL_REQUIRED = "HITL_REQUIRED"
DENIED = "DENIED"
MERGEABLE_DISPOSITIONS: FrozenSet[str] = frozenset({ACKNOWLEDGED, WAIVED})
# Families a wildcard rule may feed. A glob can only make a path more restricted, never inert.
GLOB_FAMILIES: FrozenSet[str] = frozenset({AUTHORITY, AGENT_POLICY, TOOL_CONFIG})

CLASS_REQUIRED = "required"
CLASS_OPTIONAL = "optional"

_RULE_KEYS = frozenset({"exact", "prefix", "segment", "segment_path", "basename", "suffix", "glob"})
_BLOCK_KEYS = frozenset(
    {
        "pr_type",
        "pr_type_by_class",
        "class_policy",
        "implicit_class",
        "permitted_families",
        "waiver_applies",
        "mismatch_reason",
    }
)
_CLASS_KEYS = frozenset({"permitted_families", "waiver_eligible"})
_TOP_KEYS = frozenset(
    {
        "description",
        "schema_version",
        "family_precedence",
        "fallback_family",
        "families",
        "classes",
        "block_types",
        "absent_block",
        "merge_allowlist",
    }
)


class PolicyTableError(ValueError):
    """The policy tables are malformed. The router must deny, never guess."""


class PathRejected(ValueError):
    """A changed-file path cannot be classified safely."""


def match_key(text: str) -> str:
    """Comparison form for paths and table entries: NFKC-normalized, case-folded.

    Case folding makes AUTHORITY / AGENT_POLICY / TOOL_CONFIG matches wider,
    never narrower, so case-insensitive checkouts cannot alias around them.
    """
    return unicodedata.normalize("NFKC", text).casefold()


def normalize_path(raw: Any) -> str:
    """Validate a repository-relative path and return its match key.

    Anything that could make two spellings refer to one file on some checkout
    (or that is not a plain relative path) is rejected rather than interpreted.
    """
    if not isinstance(raw, str) or not raw or len(raw) > 4096:
        raise PathRejected("path must be a non-empty string")
    for ch in raw:
        if ch == "\\" or ch == ":" or unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Zl", "Zp"):
            raise PathRejected(f"disallowed character {ch!r} in path")
    if raw.startswith("/") or raw.endswith("/"):
        raise PathRejected("path must be relative and name a file")
    for segment in raw.split("/"):
        if segment in ("", ".", ".."):
            raise PathRejected("empty, '.' or '..' segment")
        if segment != segment.rstrip(". "):
            raise PathRejected("segment ends with '.' or space")
        if match_key(segment) == ".git":
            raise PathRejected("'.git' segment")
    return match_key(raw)


@dataclass(frozen=True)
class Rule:
    exact: Optional[str] = None
    prefix: Optional[str] = None
    segment: Optional[str] = None
    segment_path: Optional[Tuple[str, ...]] = None
    basename: Optional[str] = None
    suffix: Optional[Tuple[str, ...]] = None
    glob: Optional[Tuple[str, ...]] = None

    def matches(self, key: str) -> bool:
        segments = key.split("/")
        if self.glob is not None and not (
            len(segments) == len(self.glob) and all(fnmatchcase(s, g) for s, g in zip(segments, self.glob))
        ):
            return False
        if self.exact is not None and key != self.exact:
            return False
        if self.prefix is not None and not (key.startswith(self.prefix) or key == self.prefix[:-1]):
            return False
        if self.segment is not None and self.segment not in segments:
            return False
        if self.segment_path is not None and not _contains_run(segments, self.segment_path):
            return False
        if self.basename is not None and segments[-1] != self.basename:
            return False
        if self.suffix is not None and not segments[-1].endswith(self.suffix):
            return False
        return True


def _contains_run(segments: Sequence[str], run: Tuple[str, ...]) -> bool:
    width = len(run)
    return any(tuple(segments[i : i + width]) == run for i in range(len(segments) - width + 1))


@dataclass(frozen=True)
class ClassPolicy:
    permitted_families: FrozenSet[str]
    waiver_eligible: bool


@dataclass(frozen=True)
class BlockPolicy:
    pr_type: str
    pr_type_by_class: Mapping[str, str]
    class_policy: str
    implicit_class: Optional[str]
    permitted_families: Optional[FrozenSet[str]]
    waiver_applies: bool
    mismatch_reason: str

    def resolve_pr_type(self, pr_class: Any) -> str:
        if pr_class is None or pr_class == "":
            pr_class = self.implicit_class
        if isinstance(pr_class, str):
            return self.pr_type_by_class.get(pr_class, self.pr_type)
        return self.pr_type


@dataclass(frozen=True)
class PolicyTables:
    rules: Tuple[Tuple[str, Rule], ...]
    fallback_family: str
    classes: Mapping[str, ClassPolicy]
    block_types: Mapping[str, BlockPolicy]
    absent_block: BlockPolicy
    merge_allowlist: FrozenSet[Tuple[str, str]]

    def classify(self, key: str) -> str:
        """Map a normalized path to exactly one family (first match in precedence order)."""
        for family, rule in self.rules:
            if rule.matches(key):
                return family
        return self.fallback_family

    def merge_permitted(self, pr_type: str, disposition: str) -> bool:
        return (pr_type, disposition) in self.merge_allowlist


def load_tables(path: Path = TABLES_PATH) -> PolicyTables:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PolicyTableError(f"cannot read policy tables: {exc}") from exc
    return build_tables(data)


def build_tables(data: Any) -> PolicyTables:
    _require(isinstance(data, dict), "tables must be an object")
    _require(set(data) <= _TOP_KEYS, f"unknown top-level keys: {sorted(set(data) - _TOP_KEYS)}")
    _require(data.get("schema_version") == 1, "unsupported schema_version")

    _require(data.get("fallback_family") == CODE, "fallback_family must be CODE (spec 3a)")
    precedence = data.get("family_precedence")
    _require(
        isinstance(precedence, list)
        and len(precedence) == len(set(precedence))
        and set(precedence) == FAMILIES - {CODE},
        "family_precedence must list every family except CODE exactly once",
    )
    _require(precedence[0] == AUTHORITY, "AUTHORITY must take precedence over every other family")

    families = data.get("families")
    _require(isinstance(families, dict) and set(families) == set(precedence), "families must match precedence")
    rules = tuple((family, _build_rule(spec, family)) for family in precedence for spec in _list(families[family]))

    classes_raw = data.get("classes")
    _require(isinstance(classes_raw, dict) and classes_raw, "classes must be a non-empty object")
    classes = {}
    for name, spec in classes_raw.items():
        _require(isinstance(spec, dict) and set(spec) == _CLASS_KEYS, f"class {name}: bad keys")
        permitted = _family_set(spec["permitted_families"], f"class {name}")
        _require(AUTHORITY not in permitted, f"class {name} may not permit AUTHORITY (spec 3c)")
        _require(isinstance(spec["waiver_eligible"], bool), f"class {name}: waiver_eligible must be bool")
        classes[name] = ClassPolicy(permitted, spec["waiver_eligible"])

    blocks_raw = data.get("block_types")
    _require(isinstance(blocks_raw, dict), "block_types must be an object")
    block_types = {name: _build_block(spec, f"block {name}", classes) for name, spec in blocks_raw.items()}
    absent_block = _build_block(data.get("absent_block"), "absent_block", classes)

    known_pr_types = {b.pr_type for b in (*block_types.values(), absent_block)}
    known_pr_types |= {t for b in (*block_types.values(), absent_block) for t in b.pr_type_by_class.values()}
    allowlist = set()
    for entry in _list(data.get("merge_allowlist")):
        _require(isinstance(entry, dict) and set(entry) == {"pr_type", "disposition"}, "bad merge_allowlist entry")
        _require(entry["pr_type"] in known_pr_types, f"merge_allowlist names unknown pr_type {entry['pr_type']}")
        _require(entry["disposition"] in MERGEABLE_DISPOSITIONS, "merge_allowlist disposition must pass the check")
        allowlist.add((entry["pr_type"], entry["disposition"]))

    return PolicyTables(
        rules=rules,
        fallback_family=CODE,
        classes=MappingProxyType(classes),
        block_types=MappingProxyType(block_types),
        absent_block=absent_block,
        merge_allowlist=frozenset(allowlist),
    )


def _build_rule(spec: Any, family: str) -> Rule:
    _require(isinstance(spec, dict) and spec and set(spec) <= _RULE_KEYS, f"bad rule {spec!r}")
    fields = {}
    for key, value in spec.items():
        if key == "glob":
            # Per-segment wildcards: '*' never crosses '/', so a glob names a fixed depth.
            _require(family in GLOB_FAMILIES, f"glob rules may only feed {sorted(GLOB_FAMILIES)}")
            _require(isinstance(value, str) and value, "glob must be a non-empty string")
            fields[key] = tuple(normalize_path(value).split("/"))
            continue
        if key == "suffix":
            values = [value] if isinstance(value, str) else value
            _require(isinstance(values, list) and values and all(isinstance(v, str) and v for v in values), "bad suffix")
            fields[key] = tuple(match_key(v) for v in values)
            continue
        _require(isinstance(value, str) and value, f"rule field {key} must be a non-empty string")
        if key == "prefix":
            _require(value.endswith("/"), "prefix must end with '/'")
            fields[key] = match_key(value)
        elif key == "segment_path":
            fields[key] = tuple(normalize_path(value).split("/"))
        else:
            fields[key] = normalize_path(value)
            if key in ("segment", "basename"):
                _require("/" not in fields[key], f"{key} must be a single segment")
    return Rule(**fields)


def _build_block(spec: Any, label: str, classes: Mapping[str, ClassPolicy]) -> BlockPolicy:
    _require(isinstance(spec, dict) and set(spec) == _BLOCK_KEYS, f"{label}: bad keys")
    _require(isinstance(spec["pr_type"], str) and spec["pr_type"], f"{label}: pr_type")
    by_class = spec["pr_type_by_class"]
    _require(
        isinstance(by_class, dict)
        and all(k in classes and isinstance(v, str) and v for k, v in by_class.items()),
        f"{label}: pr_type_by_class must map known classes to pr_types",
    )
    _require(spec["class_policy"] in (CLASS_REQUIRED, CLASS_OPTIONAL), f"{label}: class_policy")
    implicit = spec["implicit_class"]
    if implicit is not None:
        _require(implicit in classes, f"{label}: implicit_class must be a known class")
        _require(spec["class_policy"] == CLASS_OPTIONAL, f"{label}: a required class cannot be implicit")
    permitted = spec["permitted_families"]
    if permitted is None:
        _require(spec["class_policy"] == CLASS_REQUIRED, f"{label}: null permitted_families needs a required class")
    else:
        permitted = _family_set(permitted, label)
        _require(AUTHORITY not in permitted, f"{label} may not permit AUTHORITY (spec 3c)")
    _require(isinstance(spec["waiver_applies"], bool), f"{label}: waiver_applies must be bool")
    _require(isinstance(spec["mismatch_reason"], str) and spec["mismatch_reason"], f"{label}: mismatch_reason")
    return BlockPolicy(
        pr_type=spec["pr_type"],
        pr_type_by_class=MappingProxyType(dict(by_class)),
        class_policy=spec["class_policy"],
        implicit_class=implicit,
        permitted_families=permitted,
        waiver_applies=spec["waiver_applies"],
        mismatch_reason=spec["mismatch_reason"],
    )


def _family_set(value: Any, label: str) -> FrozenSet[str]:
    _require(isinstance(value, list) and all(v in FAMILIES for v in value), f"{label}: unknown family")
    return frozenset(value)


def _list(value: Any) -> list:
    _require(isinstance(value, list), "expected a list")
    return value


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyTableError(message)
