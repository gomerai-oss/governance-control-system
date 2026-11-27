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
- **Harnesses** (§3p, Amendment 029): each harness the app gateway may run, by name, with its app, the SHA-256 of
  its file (``mcp_gateway/harnesses/<name>.py`` in the tooling tree), the commit reviewed, who built it and the
  independent review that admits it: another seat, on another vendor's model, of that same commit. The section may be
  empty. ``pin_lines`` lists a harness pin added, removed or changed, and a harness file that no longer matches its
  pin; the app gateway refuses to run such a harness (``mcp_gateway/app_gateway.py``).
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

OBSERVE, ENFORCE = "observe", "enforce"
MODES = (OBSERVE, ENFORCE)
CONFIG_KEY = "supply_chain"
PINS_TABLE = "credentials_check/pins.json"
PINS_SCHEMA = "workflow-pins-v1"
MISSION_WORKFLOWS = ("mission-agent.yml", "mission-router.yml", "credentials-check.yml", "evidence-seal.yml",
                     "evidence-verify.yml", "mission-clock.yml")
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
TABLE_FIELDS = frozenset({"schema", "spec", "actions", "runtimes", "harnesses", "tools", "trees"})
# A harness pin (§3p, Amendment 029): the file is mcp_gateway/harnesses/<name>.py in the tooling tree.
HARNESS_DIR = "mcp_gateway/harnesses"
HARNESS_FIELDS = frozenset({"app", "sha256", "commit", "built_by", "review"})
BUILDER_FIELDS = frozenset({"seat", "vendor", "model"})
REVIEW_FIELDS = frozenset({"seat", "vendor", "model", "commit", "date", "report"})
HARNESS_TESTS_OWED = ("AST-H.6",)
_HARNESS_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}")
_APP_NAME = re.compile(r"[a-z][a-z0-9-]{0,31}")  # the app register's rule (tool_selection/apps.py)
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_HEX64 = re.compile(r"[0-9a-f]{64}")

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
    """``{"schema": "workflow-pins-v1", "spec", "actions": {...}, "runtimes": {...}, "harnesses": {...},
    "tools": {...}, "trees": {...}}``; a malformed table raises. ``tools`` and ``trees`` are checked by ``tree.py``
    (Amendment 034)."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise SupplyChainError(f"{PINS_TABLE} is not JSON: {exc}") from None
    if not (isinstance(doc, dict) and doc.get("schema") == PINS_SCHEMA
            and set(doc) == TABLE_FIELDS):
        raise SupplyChainError(f"{PINS_TABLE} must be {PINS_SCHEMA} with spec, actions, runtimes, harnesses, tools "
                               "and trees")
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
    check_harnesses(doc["harnesses"])
    from mission_dispatch import tree as tree_mod  # its own module; it imports nothing from here
    try:
        tree_mod.check_tools(doc["tools"])
        tree_mod.check_trees(doc["trees"])
    except tree_mod.TreeError as exc:
        raise SupplyChainError(f"{PINS_TABLE}: {exc}") from None
    return doc


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip()) and value.isprintable() and len(value) <= 200


def check_harnesses(harnesses: object) -> None:
    """The ``harnesses`` section: each pin well formed, at most one harness per app, and each admitted by a review
    that is independent of its builder (another seat, another vendor) and of the commit pinned."""
    if not isinstance(harnesses, dict):
        raise SupplyChainError(f"{PINS_TABLE}: harnesses must be an object (it may be empty)")
    apps: Dict[str, str] = {}
    for name, row in harnesses.items():
        where = f"{PINS_TABLE}: harness {name!r}"
        if not (isinstance(name, str) and _HARNESS_NAME.fullmatch(name)):
            raise SupplyChainError(f"{where}: a harness name is a lowercase identifier of at most 32 characters")
        if not (isinstance(row, dict) and set(row) == HARNESS_FIELDS):
            raise SupplyChainError(f"{where} must have exactly {sorted(HARNESS_FIELDS)}")
        if not (isinstance(row["app"], str) and _APP_NAME.fullmatch(row["app"])):
            raise SupplyChainError(f"{where}: app must be an app register name")
        if row["app"] in apps:
            raise SupplyChainError(f"{where}: app {row['app']!r} already has harness {apps[row['app']]!r}")
        apps[row["app"]] = name
        if not (isinstance(row["sha256"], str) and _HEX64.fullmatch(row["sha256"])):
            raise SupplyChainError(f"{where}: sha256 must be 64 lowercase hex")
        if not (isinstance(row["commit"], str) and _SHA.fullmatch(row["commit"])):
            raise SupplyChainError(f"{where}: commit must be a full commit SHA (40 hex)")
        built, review = row["built_by"], row["review"]
        if not (isinstance(built, dict) and set(built) == BUILDER_FIELDS and all(_text(built[k]) for k in built)):
            raise SupplyChainError(f"{where}: built_by must be exactly {sorted(BUILDER_FIELDS)}, each named")
        if not (isinstance(review, dict) and set(review) == REVIEW_FIELDS
                and all(_text(review[k]) for k in ("seat", "vendor", "model"))):
            raise SupplyChainError(f"{where}: review must be exactly {sorted(REVIEW_FIELDS)}, each named")
        if review["commit"] != row["commit"]:
            raise SupplyChainError(f"{where}: the review is of commit {str(review['commit'])[:40]!r}, not the one "
                                   "pinned")
        if not (isinstance(review["date"], str) and _DATE.fullmatch(review["date"])):
            raise SupplyChainError(f"{where}: review date must be YYYY-MM-DD")
        if not (_text(review["report"]) and review["report"].startswith("https://")):
            raise SupplyChainError(f"{where}: review report must be an https:// link to the review")
        if review["seat"].strip().lower() == built["seat"].strip().lower():
            raise SupplyChainError(f"{where}: reviewed by the seat that built it ({built['seat']!r})")
        if review["vendor"].strip().lower() == built["vendor"].strip().lower():
            raise SupplyChainError(f"{where}: reviewed on the builder's vendor's model ({built['vendor']!r})")


def harness_path(tooling_root: Path, name: str) -> Path:
    """Where harness ``name``'s file lies in a tooling tree."""
    return Path(tooling_root) / HARNESS_DIR / f"{name}.py"


def file_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


EVIDENCE_KEYS = "evidence/key.json"


def _evidence_keys(root: Path, tooling: str) -> Dict[str, str]:
    """The pinned evidence keys' public halves by key id; empty when the pin is absent or unreadable."""
    try:
        doc = json.loads((Path(root) / tooling / EVIDENCE_KEYS).read_text(encoding="utf-8"))
        return {str(k["keyid"]): str(k["public"]) for k in doc.get("keys", []) if isinstance(k, dict)}
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return {}


def evidence_key_lines(base: Path, head: Path, tooling: str) -> List[str]:
    """A change to the pinned evidence keys (MISSION-DISPATCH-001 §3m, limit 30) is a pin change too: one line per key
    added or removed. A removed key's seals no longer verify."""
    before, after = _evidence_keys(base, tooling), _evidence_keys(head, tooling)
    lines = [f"key.json adds evidence key {kid[:16]}... (a HITL hand merge; it can seal from the merge on)"
             for kid in sorted(set(after) - set(before))]
    lines += [f"key.json removes evidence key {kid[:16]}... (seals made with it no longer verify)"
              for kid in sorted(set(before) - set(after))]
    lines += [f"key.json changes the public half of evidence key {kid[:16]}..."
              for kid in sorted(set(before) & set(after)) if before[kid] != after[kid]]
    return lines


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
        if not old and new:  # a new row, as when the table is first written: nothing was pinned before it
            lines.append(f"pins.json adds runtime {runtime} at {new.get('version')}")
            continue
        changed = sorted(k for k in set(old) | set(new) if old.get(k) != new.get(k))
        if changed:
            owed = ", ".join(TESTS_OWED.get(runtime, ()))
            lines.append(f"pins.json changes runtime {runtime} ({', '.join(changed)}): "
                         f"{old.get('version')} -> {new.get('version')}; re-run before merging: {owed or 'none'}")
    old_wf = _workflow_pins(base / workflows_rel)
    for name, refs in sorted(_workflow_pins(head / workflows_rel).items()):
        for ref in sorted(refs - old_wf.get(name, set())):
            lines.append(f"{name} now runs {ref}")
    lines += harness_lines(base, head, tooling, before, after)
    lines += tree_lines(before, after)
    lines += evidence_key_lines(base, head, tooling)
    return lines


def tree_lines(before: Mapping, after: Mapping) -> List[str]:
    """One line per tool or tree the head adds, changes or removes (Amendment 034). A tree's line names how many of
    its packages were added, removed or changed, so a quiet swap inside a large tree is never silent."""
    lines: List[str] = []
    old_tools, new_tools = before.get("tools", {}) or {}, after.get("tools", {}) or {}
    for name in sorted(set(old_tools) | set(new_tools)):
        old, new = old_tools.get(name), new_tools.get(name)
        if old == new:
            continue
        if old is None:
            lines.append(f"pins.json adds tool {name} at {new.get('version')}")
        elif new is None:
            lines.append(f"pins.json removes tool {name}")
        else:
            lines.append(f"pins.json changes tool {name}: {old.get('version')} -> {new.get('version')}")
    old_trees, new_trees = before.get("trees", {}) or {}, after.get("trees", {}) or {}
    for name in sorted(set(old_trees) | set(new_trees)):
        old, new = old_trees.get(name), new_trees.get(name)
        if old == new:
            continue
        if old is None:
            lines.append(f"pins.json adds tree {name}: {new.get('root')}@{new.get('version')}, "
                         f"{len(new.get('packages') or [])} packages")
            continue
        if new is None:
            lines.append(f"pins.json removes tree {name}")
            continue
        was = {p["path"]: p for p in old.get("packages") or []}
        now = {p["path"]: p for p in new.get("packages") or []}
        added, removed = sorted(set(now) - set(was)), sorted(set(was) - set(now))
        changed = sorted(p for p in set(now) & set(was) if now[p] != was[p])
        keys = " (its registry keys changed)" if old.get("registry") != new.get("registry") else ""
        lines.append(f"pins.json changes tree {name}: {old.get('version')} -> {new.get('version')}; "
                     f"{len(added)} packages added, {len(removed)} removed, {len(changed)} changed{keys}")
    return lines


def harness_lines(base: Path, head: Path, tooling: str, before: Mapping, after: Mapping) -> List[str]:
    """A harness pin added, removed or changed (§3p, Amendment 029), with the test it owes; and, at the head, a
    pinned harness whose file is missing or no longer matches its pin. Lines, never findings: the app gateway refuses
    to run such a harness."""
    lines: List[str] = []
    old_h = before.get("harnesses", {}) if isinstance(before.get("harnesses"), dict) else {}
    new_h = after.get("harnesses", {}) if isinstance(after.get("harnesses"), dict) else {}
    owed = ", ".join(HARNESS_TESTS_OWED)
    for name in sorted(set(old_h) | set(new_h)):
        old, new = old_h.get(name), new_h.get(name)
        if old == new:
            continue
        if old is None and isinstance(new, dict):
            review = new.get("review") if isinstance(new.get("review"), dict) else {}
            lines.append(f"pins.json adds harness {name} for app {new.get('app')} at {str(new.get('sha256'))[:16]}..., "
                         f"commit {str(new.get('commit'))[:12]}, reviewed by {review.get('seat')} on "
                         f"{review.get('vendor')} {review.get('model')}; re-run before merging: {owed}")
        elif new is None:
            lines.append(f"pins.json removes harness {name}")
        else:
            changed = sorted(k for k in set(old) | set(new) if old.get(k) != new.get(k))
            lines.append(f"pins.json changes harness {name} ({', '.join(changed)}); re-run before merging: {owed}")
    for name, row in sorted(new_h.items()):
        if not isinstance(row, dict):
            continue
        path = harness_path(Path(head) / tooling, name)
        try:
            data = path.read_bytes() if path.is_file() and not path.is_symlink() else None
        except OSError:
            data = None
        if data is None:
            lines.append(f"harness {name} is pinned but {HARNESS_DIR}/{name}.py is missing; the app gateway will "
                         "refuse to run it")
        elif file_sha256(data) != row.get("sha256"):
            lines.append(f"harness {name}: {HARNESS_DIR}/{name}.py does not match its pin; the app gateway will "
                         "refuse to run it")
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
