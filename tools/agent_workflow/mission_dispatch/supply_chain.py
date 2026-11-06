"""Supply chain and provenance (ring 4, MISSION-DISPATCH-001 §3l, Amendment 018). Standard library only.

``"supply_chain"`` in ``config.json``: ``"observe"`` (the default) or ``"enforce"``; any other value fails the job and
stops the router.

- **The pins table** (item 1), ``credentials_check/pins.json`` (SPEC-002 ``AUTHORITY``): every action the workflows
  may run, by ``owner/repo[/path]``, with its full commit SHA and the tag it was taken from; and each runtime's version,
  package SHA-256, download URL, registry key and provenance record. ``pin_findings`` lists what the workflows do that
  the table does not allow:
  - in every workflow: a ``uses:`` not pinned by a 40-hex commit SHA; an action or SHA not in the table; a
    ``docker://`` image;
  - in a mission workflow (``MISSION_WORKFLOWS``) also: a local ``./`` action; a runtime pin
    (``CLAUDE_CODE_VERSION`` ...) that differs from its row; a step that downloads with ``curl``/``wget`` and does not
    check it with ``sha256sum --check``; a step that installs with ``pip``, ``npm``, ``apt``/``apt-get`` or pipes a
    fetched script to a shell.
  - in the table: a runtime whose ``provenance.version`` is not its version.
- **Pin changes** (item 3): ``pin_lines`` lists each changed row against the PR's base, and for a runtime the
  behavioural tests the change owes. The lines never fail the check.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

OBSERVE, ENFORCE = "observe", "enforce"
MODES = (OBSERVE, ENFORCE)
CONFIG_KEY = "supply_chain"
PINS_TABLE = "credentials_check/pins.json"
PINS_SCHEMA = "workflow-pins-v1"
MISSION_WORKFLOWS = ("mission-agent.yml", "mission-router.yml", "credentials-check.yml")
RUNTIME_PINS: Mapping[str, Tuple[str, str]] = {
    "claude-code": ("CLAUDE_CODE_VERSION", "CLAUDE_CODE_SHA256"),
    "cursor-cli": ("CURSOR_CLI_VERSION", "CURSOR_CLI_SHA256"),
}
# The behavioural tests a runtime pin change owes before it is merged (§3l item 3).
TESTS_OWED: Mapping[str, Tuple[str, ...]] = {
    "claude-code": ("AST-2.4", "AST-3.4", "AST-1.6"),
    "cursor-cli": ("AST-3.3",),
}
RUNTIME_FIELDS = frozenset({"version", "sha256", "url", "registry", "attestation", "provenance"})
PROVENANCE_FIELDS = frozenset({"version", "checked", "how", "by"})

_USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(['\"]?)([^'\"\s#]+)\1")
_ACTION = re.compile(r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?)@([^@\s]+)")
_SHA = re.compile(r"[0-9a-f]{40}")
_STEP = re.compile(r"^\s*-\s+(?:name|uses|run|id|if|with|env):", re.M)
_DOWNLOAD = re.compile(r"\b(?:curl|wget)\b[^\n]*(?:\s-o\s|\s-O\s|--output\b|--output-document\b|>)")
_INSTALLS: Sequence[Tuple[str, "re.Pattern[str]"]] = (
    ("pip", re.compile(r"\bpip3?\s+install\b|\bpython3?\s+-m\s+pip\s+install\b")),
    ("npm", re.compile(r"\b(?:npm|pnpm|yarn)\s+(?:install|i|ci|add)\b|\bnpx\s")),
    ("apt", re.compile(r"\bapt(?:-get)?\s+(?:-\S+\s+)*install\b")),
    ("a fetched script piped to a shell", re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b")),
)


class SupplyChainError(ValueError):
    """The supply-chain mode is unknown, or the pins table is malformed."""


def mode(config: Mapping[str, object]) -> str:
    value = config.get(CONFIG_KEY, OBSERVE)
    if value not in MODES:
        raise SupplyChainError(f"config.json: {CONFIG_KEY} must be one of {list(MODES)}, not {value!r}")
    return str(value)


# ------------------------------------------------------------------ the table
def read_pins(path: Path) -> dict:
    """``{"schema": "workflow-pins-v1", "spec", "actions": {...}, "runtimes": {...}}``; a malformed table raises."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise SupplyChainError(f"{PINS_TABLE} is not JSON: {exc}") from None
    if not (isinstance(doc, dict) and doc.get("schema") == PINS_SCHEMA
            and set(doc) == {"schema", "spec", "actions", "runtimes"}):
        raise SupplyChainError(f"{PINS_TABLE} must be {PINS_SCHEMA} with spec, actions and runtimes")
    actions, runtimes = doc["actions"], doc["runtimes"]
    if not isinstance(actions, dict) or not all(
            isinstance(name, str) and _ACTION.fullmatch(f"{name}@x") and isinstance(row, dict)
            and set(row) == {"sha", "tag"} and isinstance(row["sha"], str) and _SHA.fullmatch(row["sha"])
            and isinstance(row["tag"], str) and row["tag"] for name, row in actions.items()):
        raise SupplyChainError(f"{PINS_TABLE}: each action is owner/repo[/path] -> {{sha (40 hex), tag}}")
    if not isinstance(runtimes, dict) or set(runtimes) != set(RUNTIME_PINS):
        raise SupplyChainError(f"{PINS_TABLE}: runtimes must be exactly {sorted(RUNTIME_PINS)}")
    for name, row in runtimes.items():
        if not (isinstance(row, dict) and set(row) == RUNTIME_FIELDS and isinstance(row["version"], str)
                and isinstance(row["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
                and isinstance(row["url"], str) and row["url"].startswith("https://")
                and isinstance(row["attestation"], str) and isinstance(row["provenance"], dict)
                and set(row["provenance"]) == PROVENANCE_FIELDS):
            raise SupplyChainError(f"{PINS_TABLE}: runtime {name!r} must have exactly {sorted(RUNTIME_FIELDS)}, "
                                   f"with provenance {sorted(PROVENANCE_FIELDS)}")
        registry = row["registry"]
        if registry is not None and not (isinstance(registry, dict) and set(registry) == {"package", "keyid", "key"}
                                         and all(isinstance(registry[k], str) and registry[k] for k in registry)):
            raise SupplyChainError(f"{PINS_TABLE}: runtime {name!r} registry must be null or {{package, keyid, key}}")
    return doc


# ------------------------------------------------------------------ findings (items 1 and 3)
def _uses(text: str) -> List[Tuple[int, str]]:
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        match = _USES.match(line)
        if match:
            found.append((number, match.group(2)))
    return found


def _steps(text: str) -> List[Tuple[int, str]]:
    """The workflow cut into steps (each from its ``- `` line to the next), with the first line's number."""
    starts = [m.start() for m in _STEP.finditer(text)]
    if not starts:
        return [(1, text)]
    chunks = []
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else len(text)
        chunks.append((text.count("\n", 0, start) + 1, text[start:end]))
    return chunks


def _env_value(text: str, name: str) -> Optional[str]:
    match = re.search(rf"^\s*{re.escape(name)}:\s*(['\"]?)([^'\"\s#]*)\1", text, re.M)
    return match.group(2) if match else None


def workflow_findings(name: str, text: str, table: Mapping) -> List[str]:
    """What ``name`` runs that the table does not allow."""
    findings: List[str] = []
    mission = name in MISSION_WORKFLOWS
    actions = table["actions"]
    for number, ref in _uses(text):
        where = f"{name}:{number}"
        if ref.startswith("docker://"):
            findings.append(f"{where} runs a container image ({ref[:80]}); no image is pinned")
            continue
        if ref.startswith("./") or ref.startswith("../"):
            if mission:
                findings.append(f"{where} runs a local action ({ref[:80]}) in a mission workflow")
            continue
        match = _ACTION.fullmatch(ref)
        if not match:
            findings.append(f"{where}: {ref[:80]} is not owner/repo@<commit SHA>")
            continue
        action, at = match.groups()
        if not _SHA.fullmatch(at):
            findings.append(f"{where}: {action}@{at[:40]} is not pinned by a full commit SHA")
            continue
        row = actions.get(action)
        if row is None:
            findings.append(f"{where}: {action} is not in the pins table")
        elif row["sha"] != at:
            findings.append(f"{where}: {action}@{at} is not the pinned SHA ({row['sha']}, {row['tag']})")
    if not mission:
        return findings
    for runtime, names in RUNTIME_PINS.items():
        row = table["runtimes"][runtime]
        for env_name, want in zip(names, (row["version"], row["sha256"])):
            got = _env_value(text, env_name)
            if got is not None and got != want:
                findings.append(f"{name}: {env_name} is {got[:80]!r}, not the pinned {want!r} ({runtime})")
    for number, step in _steps(text):
        for kind, pattern in _INSTALLS:
            if pattern.search(step):
                findings.append(f"{name}:{number}: a step installs with {kind}")
        if _DOWNLOAD.search(step) and "sha256sum --check" not in step:
            findings.append(f"{name}:{number}: a step downloads a file and does not check it with sha256sum --check")
    return findings


def table_findings(table: Mapping) -> List[str]:
    found = []
    for runtime, row in table["runtimes"].items():
        if row["provenance"].get("version") != row["version"]:
            found.append(f"pins.json: runtime {runtime} is pinned at {row['version']!r} but its provenance record is "
                         f"for {row['provenance'].get('version')!r}")
    return found


def pin_findings(table: Mapping, workflows: Mapping[str, str]) -> List[str]:
    found = table_findings(table)
    for name in sorted(workflows):
        found += workflow_findings(name, workflows[name], table)
    return found


# ------------------------------------------------------------------ pin changes (item 3)
def _read(root: Path, tooling: str) -> Optional[dict]:
    path = root / tooling / PINS_TABLE
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return None


def pin_lines(base: Path, head: Path, tooling: str, workflows_rel: str) -> List[str]:
    """One line per pin the head changes from the base: table rows, and action SHAs the workflows run."""
    lines: List[str] = []
    before, after = _read(base, tooling) or {}, _read(head, tooling) or {}
    old_actions, new_actions = before.get("actions", {}) or {}, after.get("actions", {}) or {}
    for action in sorted(set(old_actions) | set(new_actions)):
        old, new = old_actions.get(action), new_actions.get(action)
        if old == new:
            continue
        if old is None:
            lines.append(f"pins.json adds action {action}@{new.get('sha')} ({new.get('tag')})")
        elif new is None:
            lines.append(f"pins.json removes action {action}")
        else:
            lines.append(f"pins.json moves action {action} from {old.get('sha')} ({old.get('tag')}) to "
                         f"{new.get('sha')} ({new.get('tag')})")
    old_rt, new_rt = before.get("runtimes", {}) or {}, after.get("runtimes", {}) or {}
    for runtime in sorted(set(old_rt) | set(new_rt)):
        old, new = old_rt.get(runtime) or {}, new_rt.get(runtime) or {}
        changed = sorted(k for k in set(old) | set(new) if old.get(k) != new.get(k))
        if changed:
            owed = ", ".join(TESTS_OWED.get(runtime, ()))
            lines.append(f"pins.json changes runtime {runtime} ({', '.join(changed)}): "
                         f"{old.get('version')} -> {new.get('version')}; re-run before merging: {owed or 'none'}")
    old_wf = _workflow_pins(base / workflows_rel)
    for name, refs in sorted(_workflow_pins(head / workflows_rel).items()):
        for ref in sorted(refs - old_wf.get(name, set())):
            lines.append(f"{name} now runs {ref}")
    return lines


def _workflow_pins(folder: Path) -> Dict[str, set]:
    found: Dict[str, set] = {}
    if not folder.is_dir():
        return found
    for path in sorted(folder.iterdir()):
        if path.suffix in (".yml", ".yaml") and path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            found[path.name] = {ref for _, ref in _uses(text)}
            for env_names in RUNTIME_PINS.values():
                for env_name in env_names:
                    value = _env_value(text, env_name)
                    if value is not None:
                        found[path.name].add(f"{env_name}={value}")
    return found
