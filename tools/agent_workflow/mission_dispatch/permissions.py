"""Ring 2, the permission matrix (MISSION-DISPATCH-001 Amendment 016, §3k): checks shared by the credentials check
(before merge) and ``prepare`` (when a seat is bound). Standard library only.

- ``mode(config)``: ``"permissions"`` in ``config.json``, ``"observe"`` when absent; any other value is an error that
  fails the job and stops the router.
- ``description_findings(catalog)``: every text the model reads about a gateway tool (its ``description`` and each
  ``description`` in its ``input_schema``) checked with the ring 3 quarantine (§3j item 1): no character the
  quarantine removes, at most ``MAX_DESCRIPTION`` characters, no line on its steering list, and no line on the
  description list below (item 1).
- ``catalog_digest(catalog)``: the SHA-256 of the catalog's canonical JSON, the value the binding pins in the gateway's
  session (item 1).
- ``grant_lines(base, head)``: one line per widening between two trees (item 3): a capability a matrix role newly
  admits or no longer blocks, a tool new to the runtime registry or the gateway catalog, a seat or a seat resource
  that is new, and a workflow or App-token permission that is new or raised. Information for HITL; never a refusal.
- ``grant_findings(table, workflows)``: every permission the mission workflows ask for, held to
  ``credentials_check/grants.json`` (item 4): a job over its row or with no row, a top level other than its row,
  ``write-all``, ``read-all`` or a computed ``permissions``, and an App-token step without the literal
  ``repositories: ${{ steps.repo.outputs.name }}`` or asking for a permission its row does not list.
"""

from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path
from typing import Dict, Iterator, List, Mapping, Optional, Sequence, Tuple

from epap import signing
from mission_dispatch import quarantine

CONFIG_KEY = "permissions"
OBSERVE, ENFORCE = "observe", "enforce"
MODES = (OBSERVE, ENFORCE)
MAX_DESCRIPTION = 500

TOOLING = "tools/agent_workflow"
CATALOG = "mcp_gateway/tools.json"  # under the tooling tree
MATRIX = "tool_selection/matrix.json"
SEATS = "tool_selection/seats.json"
REGISTRY = "tool_selection/runtime_registry.json"
WORKFLOWS = ("mission-agent.yml", "mission-router.yml", "credentials-check.yml")
APP_TOKEN_ACTION = "actions/create-github-app-token@"
GRANTS_TABLE = "credentials_check/grants.json"  # under the tooling tree (AUTHORITY with the rest of credentials_check/)
GRANTS_SCHEMA = "workflow-grants-v1"
THIS_REPOSITORY = "${{ steps.repo.outputs.name }}"  # the only repositories: an App-token step may name


class PermissionsError(ValueError):
    pass


def mode(config: Mapping[str, object]) -> str:
    value = config.get(CONFIG_KEY, OBSERVE)
    if value not in MODES:
        raise PermissionsError(f"config.json: {CONFIG_KEY} must be one of {list(MODES)}, not {value!r}")
    return str(value)


# ------------------------------------------------------------------ tool descriptions (item 1)
# A tool description says what the tool does. These are the ways one is written to steer the model that lists it
# instead, beyond the ring 3 steering list: it talks to the model, it orders when or whether to call something or
# what to keep quiet about, or it names a secret.
_DESC_FLAGS = re.I
_DESCRIPTION_PATTERNS: Sequence[Tuple[str, "re.Pattern[str]"]] = (
    ("addresses the model", re.compile(r"\b(?:you|your|yours|yourself)\b", _DESC_FLAGS)),
    ("orders the model", re.compile(
        r"(?<![\w-])(?:always|never|must|immediately|instead)(?![\w-])"
        r"|\b(?:call|use|run|read|invoke)\b[^.\n]{0,30}(?<![\w-])first(?![\w-])|(?<![\w-])first,? (?:call|use|run|read|invoke)\b"
        r"|\bbefore (?:answering|responding|replying|using|calling|you)\b"
        r"|\b(?:do not|don't|never) (?:tell|mention|reveal|show|report|log)\b"
        r"|\b(?:silently|secretly|quietly|without (?:telling|asking|mentioning))\b", _DESC_FLAGS)),
    ("names a secret", re.compile(
        r"\.env\b|\.ssh\b|\bid_(?:rsa|ed25519)\b|\.pem\b|\b(?:tokens?|secrets?|passwords?|credentials?|api[ _-]?keys?"
        r"|private[ _-]?keys?|cookies?)\b", _DESC_FLAGS)),
)


def description_kinds(text: str) -> List[str]:
    """The kinds of steering one cleaned line of a description looks like (ring 3's list, then the description list)."""
    folded = unicodedata.normalize("NFKC", text)
    return quarantine.line_kinds(text) + [kind for kind, pattern in _DESCRIPTION_PATTERNS if pattern.search(folded)]


def description_texts(catalog: Mapping) -> Iterator[Tuple[str, str, object]]:
    """(tool name, field, text) for every text the model reads about each catalog tool."""
    tools = catalog.get("tools") if isinstance(catalog, Mapping) else None
    for i, tool in enumerate(tools if isinstance(tools, list) else []):
        if not isinstance(tool, Mapping):
            continue
        name = tool.get("name") if isinstance(tool.get("name"), str) else f"tools[{i}]"
        yield name, "description", tool.get("description")
        schema = tool.get("input_schema")
        props = schema.get("properties") if isinstance(schema, Mapping) else None
        for prop, spec in (props.items() if isinstance(props, Mapping) else ()):
            if isinstance(spec, Mapping) and "description" in spec:
                yield name, f"input_schema.properties.{prop}.description", spec["description"]


def description_findings(catalog: Mapping) -> List[str]:
    """One finding per description text that fails item 1: hidden characters, length, or a steering line."""
    if not isinstance(catalog, Mapping) or not isinstance(catalog.get("tools"), list):
        return ["the gateway catalog has no tools list"]
    findings = []
    for name, field, text in description_texts(catalog):
        where = f"tool {name} {field}"
        if not isinstance(text, str):
            findings.append(f"{where}: not a string")
            continue
        cleaned, removed = quarantine.clean(text)
        if removed:
            findings.append(f"{where}: {removed} hidden character(s) the quarantine removes")
        if len(text) > MAX_DESCRIPTION:
            findings.append(f"{where}: {len(text)} characters, more than {MAX_DESCRIPTION}")
        for number, line in enumerate(cleaned.split("\n"), 1):
            kinds = description_kinds(line)
            if kinds:
                findings.append(f"{where}: line {number} ({', '.join(kinds)}): {quarantine.inline(line, 160)}")
    return findings


def catalog_digest(catalog: object) -> str:
    """SHA-256 of the catalog's canonical JSON (the form the binding's audit materials use)."""
    try:
        return signing.sha256_hex(signing.canonical_bytes(catalog))
    except (signing.CanonicalError, TypeError, ValueError, RecursionError) as exc:
        raise PermissionsError(f"the gateway catalog has no canonical form: {exc}") from None


def read_catalog(path: Path) -> dict:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise PermissionsError(f"the gateway catalog {path} cannot be read: {exc}") from None
    if not isinstance(doc, dict):
        raise PermissionsError(f"the gateway catalog {path} is not a JSON object")
    return doc


# ------------------------------------------------------------------ workflow permissions
_LEVEL = {"none": 0, "read": 1, "write": 2}
COMPUTED = "computed"
_KEY_RE = re.compile(r"^(\s*)(?:-\s+)?([A-Za-z0-9_.-]+):\s*(.*?)\s*$")


def _scalar(value: str) -> str:
    value = value.split(" #", 1)[0].strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1]
    return value


def _inline_permissions(value: str) -> Dict[str, str]:
    """``permissions: <value>`` written on one line."""
    if "${{" in value:
        return {"*": COMPUTED}
    if value in ("{}", ""):
        return {}
    if value in ("write-all", "read-all"):
        return {"*": value.split("-", 1)[0]}
    if value.startswith("{") and value.endswith("}"):
        out = {}
        for part in value[1:-1].split(","):
            if ":" in part:
                key, level = (p.strip() for p in part.split(":", 1))
                out[key] = COMPUTED if "${{" in level else _scalar(level)
        return out
    return {"*": COMPUTED}


def workflow_grants(name: str, text: str) -> Dict[str, Dict[str, str]]:
    """Every permission a workflow asks for: ``{"<file>: top level" | "<file>: job <j>" | "<file>: job <j>, App token
    <n>": {permission: level}}``. Read line by line, the way the workflows in this repository are written; anything
    computed reads as ``computed``."""
    grants: Dict[str, Dict[str, str]] = {}
    lines = text.splitlines()
    job: Optional[str] = None
    tokens = 0
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.split("#", 1)[0].rstrip() if not line.lstrip().startswith("#") else ""
        if not stripped.strip():
            i += 1
            continue
        indent = len(line) - len(line.lstrip())
        match = _KEY_RE.match(stripped)
        if indent == 0:
            job = None
        if match and indent == 2 and in_jobs(lines, i):
            job, tokens = match.group(2), 0
        if match and match.group(2) == "permissions" and (indent == 0 or (job and indent == 4)):
            key = f"{name}: top level" if indent == 0 else f"{name}: job {job}"
            value = _scalar(match.group(3))
            if value:
                grants[key] = _inline_permissions(value)
            else:
                block: Dict[str, str] = {}
                j = i + 1
                while j < len(lines):
                    inner = lines[j]
                    if inner.strip() and not inner.lstrip().startswith("#"):
                        if len(inner) - len(inner.lstrip()) <= indent:
                            break
                        m = _KEY_RE.match(inner.split(" #", 1)[0].rstrip())
                        if m:
                            level = _scalar(m.group(3))
                            block[m.group(2)] = COMPUTED if "${{" in level else level
                    j += 1
                grants[key] = block
                i = j
                continue
        if job and match and match.group(2) == "uses" and _scalar(match.group(3)).startswith(APP_TOKEN_ACTION):
            tokens += 1
            key = f"{name}: job {job}, App token {tokens}"
            step_indent = indent
            block = {}
            j = i + 1
            while j < len(lines):
                inner = lines[j]
                if inner.strip() and not inner.lstrip().startswith("#"):
                    inner_indent = len(inner) - len(inner.lstrip())
                    if inner_indent < step_indent or (inner_indent == step_indent and inner.lstrip().startswith("-")):
                        break
                    m = _KEY_RE.match(inner.split(" #", 1)[0].rstrip())
                    if m and m.group(2).startswith("permission-"):
                        level = _scalar(m.group(3))
                        block[m.group(2)[len("permission-"):]] = COMPUTED if "${{" in level else level
                    if m and m.group(2) == "repositories":
                        block["(repositories)"] = _scalar(m.group(3))
                j += 1
            grants[key] = block
        i += 1
    return grants


def in_jobs(lines: Sequence[str], index: int) -> bool:
    """Whether line ``index`` lies under the top-level ``jobs:`` key."""
    for k in range(index - 1, -1, -1):
        line = lines[k]
        if line and not line[0].isspace() and not line.startswith("#"):
            return line.startswith("jobs:")
    return False


def _rank(level: str) -> int:
    return 3 if level == COMPUTED else _LEVEL.get(level, 3)  # an unknown level counts as the widest


# ------------------------------------------------------------------ grant lines (item 3)
def _load_json(root: Path, rel: str) -> object:
    path = Path(root) / rel
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise PermissionsError(f"{rel} cannot be read: {exc}") from None


def _names(doc: object) -> List[str]:
    tools = doc.get("tools") if isinstance(doc, Mapping) else None
    return [t["name"] for t in tools if isinstance(t, Mapping) and isinstance(t.get("name"), str)] \
        if isinstance(tools, list) else []


def _grant_surface(root: Path, tooling: str, workflows: str) -> dict:
    root = Path(root)
    surface = {"matrix": _load_json(root, f"{tooling}/{MATRIX}"), "seats": _load_json(root, f"{tooling}/{SEATS}"),
               "registry": _names(_load_json(root, f"{tooling}/{REGISTRY}")),
               "catalog": _names(_load_json(root, f"{tooling}/{CATALOG}")), "workflows": {}}
    for name in WORKFLOWS:
        path = root / workflows / name
        if path.is_file():
            surface["workflows"].update(workflow_grants(name, path.read_text(encoding="utf-8")))
    return surface


def _roles(matrix: object) -> Mapping:
    roles = matrix.get("roles") if isinstance(matrix, Mapping) else None
    return roles if isinstance(roles, Mapping) else {}


def grant_lines(base: Path, head: Path, tooling: str = TOOLING, workflows: str = ".github/workflows") -> List[str]:
    """One line per widening from ``base`` to ``head`` (both repository roots)."""
    old, new = _grant_surface(base, tooling, workflows), _grant_surface(head, tooling, workflows)
    lines: List[str] = []
    old_roles, new_roles = _roles(old["matrix"]), _roles(new["matrix"])
    for role, row in new_roles.items():
        if not isinstance(row, Mapping):
            continue
        before = old_roles.get(role) if isinstance(old_roles.get(role), Mapping) else {}
        admit_before = set(before.get("admit") or []) if isinstance(before.get("admit"), list) else set()
        for cap in row.get("admit") or [] if isinstance(row.get("admit"), list) else []:
            if cap not in admit_before:
                lines.append(f"matrix role {role} admits {cap}")
        blocked_before = before.get("blocked") if isinstance(before.get("blocked"), Mapping) else {}
        blocked_now = row.get("blocked") if isinstance(row.get("blocked"), Mapping) else {}
        for cap in blocked_before:
            if cap not in blocked_now:
                lines.append(f"matrix role {role} no longer blocks {cap}")
        if before.get("read_only") is True and row.get("read_only") is not True:
            lines.append(f"matrix role {role} is no longer read-only")
    for kind, label in (("registry", "runtime registry"), ("catalog", "gateway catalog")):
        for tool in new[kind]:
            if tool not in old[kind]:
                lines.append(f"{label} adds tool {tool}")
    old_seats = old["seats"].get("seats", {}) if isinstance(old["seats"], Mapping) else {}
    new_seats = new["seats"].get("seats", {}) if isinstance(new["seats"], Mapping) else {}
    for seat, doc in (new_seats.items() if isinstance(new_seats, Mapping) else ()):
        if not isinstance(doc, Mapping):
            continue
        before = old_seats.get(seat) if isinstance(old_seats, Mapping) else None
        if not isinstance(before, Mapping):
            lines.append(f"seat {seat} is new (role {doc.get('role')!r})")
            continue
        if doc.get("role") != before.get("role"):
            lines.append(f"seat {seat} changes role from {before.get('role')!r} to {doc.get('role')!r}")
        for res in doc.get("resources") or [] if isinstance(doc.get("resources"), list) else []:
            if res not in (before.get("resources") or []):
                lines.append(f"seat {seat} adds resource {res}")
    for where, perms in new["workflows"].items():
        before = old["workflows"].get(where, {})
        if "(repositories)" in before and "(repositories)" not in perms:
            lines.append(f"{where} drops repositories: (was {before['(repositories)']!r}), so the token reaches "
                         "every repository the App is installed on")
        for perm, level in perms.items():
            if perm == "(repositories)":
                if before.get(perm) != level:
                    lines.append(f"{where} names repositories {level!r} (was {before.get(perm)!r})")
                continue
            was = before.get(perm)
            if was is None or _rank(level) > _rank(was):
                lines.append(f"{where} asks for {perm}: {level}" + (f" (was {was})" if was else ""))
    return lines


# ------------------------------------------------------------------ the GitHub permissions table (item 4)
def read_grants_table(path: Path) -> dict:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise PermissionsError(f"the permissions table {path} cannot be read: {exc}") from None
    workflows = doc.get("workflows") if isinstance(doc, dict) else None
    if not isinstance(doc, dict) or doc.get("schema") != GRANTS_SCHEMA or not isinstance(workflows, dict):
        raise PermissionsError(f"the permissions table must be {GRANTS_SCHEMA!r} with a workflows map")
    for name, row in workflows.items():
        ok = (isinstance(row, dict) and set(row) == {"top level", "jobs", "app_tokens"}
              and isinstance(row["top level"], dict) and isinstance(row["jobs"], dict)
              and all(isinstance(v, dict) for v in row["jobs"].values()) and isinstance(row["app_tokens"], dict)
              and all(isinstance(v, list) and all(isinstance(t, dict) for t in v) for v in row["app_tokens"].values()))
        levels = [lvl for block in ([row["top level"]] + list(row["jobs"].values())
                                    + [t for v in row["app_tokens"].values() for t in v]) for lvl in block.values()] \
            if ok else []
        if not ok or not all(lvl in ("read", "write") for lvl in levels):
            raise PermissionsError(f"the permissions table's row for {name} is malformed")
    return doc


def _over(asked: Mapping[str, str], row: Mapping[str, str], where: str) -> List[str]:
    findings = []
    for perm, level in asked.items():
        if perm == "(repositories)":
            continue
        if perm == "*":
            findings.append(f"{where} asks for {'every permission' if level != COMPUTED else 'computed permissions'}"
                            f" ({level}-all or an expression); name each permission")
        elif level == COMPUTED:
            findings.append(f"{where} computes {perm}; the table cannot hold an expression")
        elif perm not in row:
            findings.append(f"{where} asks for {perm}: {level}, which its row does not list")
        elif _rank(level) > _rank(row[perm]):
            findings.append(f"{where} asks for {perm}: {level}, more than its row's {row[perm]}")
    return findings


def grant_findings(table: Mapping, workflows: Mapping[str, str]) -> List[str]:
    """Every permission the mission workflows ask for that ``table`` does not allow (item 4)."""
    findings: List[str] = []
    for name, row in table["workflows"].items():
        if name not in workflows:
            continue  # a workflow that is not installed asks for nothing
        asked = workflow_grants(name, workflows[name])
        top = asked.get(f"{name}: top level")
        if top is None:
            findings.append(f"{name}: no top-level permissions, so every job not naming its own gets the "
                            "repository's default token")
        else:
            findings += _over(top, row["top level"], f"{name}: top level")
        for where, perms in asked.items():
            if where == f"{name}: top level":
                continue
            job_part = where[len(name) + 2:]  # "job <j>" or "job <j>, App token <n>"
            if ", App token " in job_part:
                job, number = job_part[4:].split(", App token ")
                rows = row["app_tokens"].get(job, [])
                index = int(number) - 1
                if index >= len(rows):
                    findings.append(f"{where} has no row in the permissions table")
                    continue
                named = perms.get("(repositories)")
                if named != THIS_REPOSITORY:
                    findings.append(f"{where} must name repositories: {THIS_REPOSITORY} (this repository only), "
                                    + (f"not {named!r}" if named is not None else "and names none"))
                findings += _over(perms, rows[index], where)
                continue
            job = job_part[4:]
            if job not in row["jobs"]:
                findings.append(f"{where} asks for permissions but has no row in the permissions table")
                continue
            findings += _over(perms, row["jobs"][job], where)
    return findings
