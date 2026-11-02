"""Mission data: branch names, the mission manifest, the A3 verdict, scope globs.

Everything an agent writes (branch names, manifest, verdict) is untrusted input.
Each parser either returns a fully validated value or raises ``MissionInputError``;
nothing is interpreted loosely.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

ROLES = ("A1", "A2", "A3")
MAX_ROUNDS_CEILING = 10
MAX_DEPENDENCIES = 20
STACK_KINDS = ("PARALLEL", "CHAINED")  # unrelated missions / missions with built-in dependencies
# Where a stack's passed missions go: all onto the stack branch, landing on the default
# branch together once the whole stack passed ("stack"), or each on its own ("per-leg").
LANDINGS = ("stack", "per-leg")
# Programs the laptop dispatcher can start for an agent. HITL picks one per role in the plan.
RUNTIMES = ("claude-code", "cursor-cli")
# Models HITL may name per role (Amendment 006). Claude Code takes these aliases and model ids; a name it does
# not know would only fail the run, but a fixed list catches a typo at plan time. Cursor lists its models per
# account (`agent models`), so for it only the form is checked: one lowercase name that cannot read as a flag.
CLAUDE_CODE_MODELS = ("opus", "sonnet", "haiku", "fable", "claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5",
                      "claude-fable-5-1")
_CURSOR_MODEL_RE = re.compile(r"[a-z0-9][a-z0-9.-]{0,63}")
DISPATCHED_ROLES = ("A2", "A3")  # A1 is HITL's seat; the dispatcher never starts it

MISSION_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9-]{2,63}$")
BOT_LOGIN_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,38}\[bot\]$")  # GitHub App logins; no user account can hold one
AGENT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
STACK_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9-]{2,63}$")
_MISSION_REF_RE = re.compile(r"^mission/([A-Z0-9][A-Z0-9-]{2,63})/")
_STAGE_BRANCH_RE = re.compile(r"^mission/([A-Z0-9][A-Z0-9-]{2,63})/(a1|a2-r([1-9][0-9]?)|a3-r([1-9][0-9]?))$")
_STACK_BRANCH_RE = re.compile(r"^stack/([A-Z0-9][A-Z0-9-]{2,63})$")
_TARGET_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$")
TARGET_BRANCH_MAX_CHARS = 200
RESERVED_BRANCH_ROOTS = ("mission", "stack")  # the router's own branches (stage, integration, stack)

MANIFEST_SCHEMA = "mission-v1"
VERDICT_SCHEMA = "mission-verdict-v1"
# PASS: the build matches the plan. FAIL: it does not, and A2 can fix it. BLOCKED: something
# kept A2 from completing the plan that A2 cannot fix; it is recorded for HITL, never retried.
VERDICTS = ("PASS", "FAIL", "BLOCKED")
MAX_FINDINGS = 50
FINDING_MAX_CHARS = 2000
SUMMARY_MAX_CHARS = 4000
# An agent run that fails is started again automatically; after this many failures
# in a row (since HITL's last /mission retry) the stage is recorded as blocked.
MAX_AGENT_ATTEMPTS = 3
FAILED_MARKER = "<!-- mission-dispatch:failed:{role}:{round} -->"
_FAILED_RE = re.compile(r"<!-- mission-dispatch:failed:(A2|A3):([1-9][0-9]?) -->")
_RETRY_RE = re.compile(r"(?m)^\s*/mission retry\s*$")
_HALT_RE = re.compile(r"(?m)^\s*/mission halt\s*$")
_RESUME_RE = re.compile(r"(?m)^\s*/mission resume\s*$")
ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
REGISTRY_STATUSES = ("ACTIVE", "SUSPENDED", "RETIRED")
_REGISTRY_ROW_RE = re.compile(r"^\|\s*([a-z0-9][a-z0-9-]{0,39})\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*([A-Z]+)\s*\|")


class MissionInputError(ValueError):
    """Agent-supplied mission input is malformed. The router rejects, never guesses."""


def mission_dir(mission_id: str) -> str:
    return f"missions/{mission_id}/"


def manifest_path(mission_id: str) -> str:
    return f"missions/{mission_id}/mission.json"


def verdict_path(mission_id: str, round_no: int) -> str:
    return f"missions/{mission_id}/reviews/round-{round_no}.json"


def integration_branch(mission_id: str) -> str:
    return f"mission/{mission_id}/integration"


def stack_branch(stack_id: str) -> str:
    return f"stack/{stack_id}"


def parse_stack_branch(ref: Any) -> Optional[str]:
    """The stack id a ``stack/<ID>`` branch names, or None."""
    match = _STACK_BRANCH_RE.fullmatch(ref) if isinstance(ref, str) else None
    return match.group(1) if match else None


def stage_branch(mission_id: str, role: str, round_no: int = 0) -> str:
    if role == "A1":
        return f"mission/{mission_id}/a1"
    return f"mission/{mission_id}/{role.lower()}-r{round_no}"


@dataclass(frozen=True)
class StageRef:
    mission_id: str
    role: str
    round: int  # 0 for A1


def parse_stage_branch(ref: Any) -> Optional[StageRef]:
    """Return the stage a head branch claims, or None if it is not a mission stage branch."""
    if not isinstance(ref, str):
        return None
    match = _STAGE_BRANCH_RE.fullmatch(ref)
    if not match:
        return None
    mission_id, stage = match.group(1), match.group(2)
    if stage == "a1":
        return StageRef(mission_id, "A1", 0)
    round_no = int(match.group(3) or match.group(4))
    return StageRef(mission_id, stage[:2].upper(), round_no)


@dataclass(frozen=True)
class RoleAssignment:
    agent: str  # an identity name from the identity registry, e.g. "a2"
    runtime: Optional[str] = None  # A2/A3 only: which program the dispatcher starts for the agent
    model: Optional[str] = None  # A2/A3 only, with a runtime: the model that program uses (Amendment 006)


@dataclass(frozen=True)
class Manifest:
    mission_id: str
    title: str
    roles: Mapping[str, RoleAssignment]
    build_scope: Tuple[str, ...]
    max_rounds: int
    stack_id: Optional[str] = None
    stack_kind: Optional[str] = None
    depends_on: Tuple[str, ...] = ()
    checks: Tuple[str, ...] = ()  # HITL-approved commands the dispatcher runs on the commit A3 reviews
    landing: str = "per-leg"  # "stack": passed work waits on the stack branch until the whole stack passed
    deliverables: Tuple[str, ...] = ()  # exact files the plan says A2 creates or changes; checked before approval
    branch: Optional[str] = None  # the final merge target (Amendment 008); None: the router's default branch

    @property
    def lands_with_stack(self) -> bool:
        return self.stack_id is not None and self.landing == "stack"


MAX_CHECKS = 10
CHECK_MAX_CHARS = 500
MAX_DELIVERABLES = 200
DELIVERABLE_MAX_CHARS = 300


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise MissionInputError(message)


def _load_json(text: Any, label: str) -> dict:
    _require(isinstance(text, str) and len(text) <= 65536, f"{label}: missing or too large")
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise MissionInputError(f"{label}: not valid JSON ({exc})") from exc
    _require(isinstance(data, dict), f"{label}: must be a JSON object")
    return data


def parse_manifest(text: Any, expected_id: str) -> Manifest:
    data = _load_json(text, "mission.json")
    allowed = {"schema", "mission_id", "title", "roles", "build_scope", "max_rounds", "stack", "depends_on", "checks",
               "deliverables", "branch"}
    _require(set(data) <= allowed, f"mission.json: unknown keys {sorted(set(data) - allowed)}")
    _require(data.get("schema") == MANIFEST_SCHEMA, f"mission.json: schema must be {MANIFEST_SCHEMA}")
    _require(data.get("mission_id") == expected_id, "mission.json: mission_id must match the branch and directory")
    title = data.get("title")
    _require(isinstance(title, str) and 0 < len(title) <= 200, "mission.json: title must be 1-200 characters")

    roles_raw = data.get("roles")
    _require(isinstance(roles_raw, dict) and set(roles_raw) == set(ROLES), "mission.json: roles must assign exactly A1, A2, A3")
    roles = {}
    for role in ROLES:
        entry = roles_raw[role]
        keys = {"agent", "runtime", "model"} if role in DISPATCHED_ROLES else {"agent"}
        _require(isinstance(entry, dict) and "agent" in entry and set(entry) <= keys,
                 f"mission.json: {role} needs an agent" + (" and may name a runtime and a model" if role in DISPATCHED_ROLES
                                                           else " and nothing else"))
        _require(isinstance(entry["agent"], str) and AGENT_RE.fullmatch(entry["agent"]), f"mission.json: {role}.agent is not a valid agent name")
        runtime = entry.get("runtime")
        _require("runtime" not in entry or runtime in RUNTIMES, f"mission.json: {role}.runtime must be one of {list(RUNTIMES)}")
        model = entry.get("model")
        _require("model" not in entry or valid_model(runtime, model),
                 f"mission.json: {role}.model needs a runtime and must be a model that runtime accepts here"
                 + (f" (one of {list(CLAUDE_CODE_MODELS)})" if runtime == "claude-code" else ""))
        roles[role] = RoleAssignment(entry["agent"], runtime, model)
    _require(roles["A3"].agent not in (roles["A1"].agent, roles["A2"].agent),
             "mission.json: A3 must be a different agent from A1 and A2, so its review is independent")

    scope = data.get("build_scope")
    _require(isinstance(scope, list) and 0 < len(scope) <= 50, "mission.json: build_scope must list 1-50 paths")
    for pattern in scope:
        validate_scope_glob(pattern)

    max_rounds = data.get("max_rounds", 5)
    _require(
        isinstance(max_rounds, int) and not isinstance(max_rounds, bool) and 1 <= max_rounds <= MAX_ROUNDS_CEILING,
        f"mission.json: max_rounds must be 1-{MAX_ROUNDS_CEILING}",
    )

    stack_id = stack_kind = None
    landing = "per-leg"
    if "stack" in data:
        stack = data["stack"]
        _require(isinstance(stack, dict) and {"id", "kind"} <= set(stack) <= {"id", "kind", "landing"},
                 "mission.json: stack needs id and kind, and may name a landing")
        _require(isinstance(stack["id"], str) and STACK_ID_RE.fullmatch(stack["id"]), "mission.json: stack.id is not a valid id")
        _require(stack["kind"] in STACK_KINDS, f"mission.json: stack.kind must be one of {list(STACK_KINDS)}")
        _require(stack.get("landing", "stack") in LANDINGS, f"mission.json: stack.landing must be one of {list(LANDINGS)}")
        stack_id, stack_kind, landing = stack["id"], stack["kind"], stack.get("landing", "stack")

    deps = data.get("depends_on", [])
    _require(isinstance(deps, list) and len(deps) <= MAX_DEPENDENCIES, f"mission.json: depends_on must list at most {MAX_DEPENDENCIES} missions")
    _require(all(isinstance(d, str) and MISSION_ID_RE.fullmatch(d) for d in deps), "mission.json: depends_on entries must be mission ids")
    _require(len(set(deps)) == len(deps) and expected_id not in deps, "mission.json: depends_on has duplicates or names the mission itself")
    _require(not deps or stack_kind == "CHAINED", "mission.json: only an CHAINED mission may declare depends_on; PARALLEL missions are independent")

    checks = data.get("checks", [])
    _require(isinstance(checks, list) and len(checks) <= MAX_CHECKS
             and all(isinstance(c, str) and 0 < len(c) <= CHECK_MAX_CHARS and c.strip() and "\0" not in c for c in checks),
             f"mission.json: checks must list at most {MAX_CHECKS} commands of 1-{CHECK_MAX_CHARS} characters")

    deliverables = data.get("deliverables", [])
    _require(isinstance(deliverables, list) and len(deliverables) <= MAX_DELIVERABLES,
             f"mission.json: deliverables must list at most {MAX_DELIVERABLES} paths")
    for path in deliverables:
        validate_deliverable(path)
    _require(len(set(deliverables)) == len(deliverables), "mission.json: deliverables has duplicates")

    branch = data.get("branch")
    _require("branch" not in data or valid_target_branch(branch),
             f"mission.json: branch must be a branch name of at most {TARGET_BRANCH_MAX_CHARS} characters, "
             f"not under {', '.join(r + '/' for r in RESERVED_BRANCH_ROOTS)}")
    return Manifest(expected_id, title, roles, tuple(scope), max_rounds, stack_id, stack_kind, tuple(deps), tuple(checks), landing,
                    tuple(deliverables), branch)


def valid_target_branch(name: Any) -> bool:
    """Whether ``name`` may be a mission's final merge target: a plain branch name the router does not own."""
    return (isinstance(name, str) and len(name) <= TARGET_BRANCH_MAX_CHARS and bool(_TARGET_BRANCH_RE.fullmatch(name))
            and ".." not in name and not name.endswith((".lock", ".")) and name != "HEAD"
            and name.split("/")[0] not in RESERVED_BRANCH_ROOTS)


def parse_identity_registry(text: Any) -> Dict[str, str]:
    """Identity name -> status from the identity registry table.

    Rows look like ``| a2 | <app id> | <installation id> | ACTIVE | ... |``. An unknown
    status or a duplicate name makes the whole registry invalid: identity is fail-closed.
    """
    _require(isinstance(text, str) and len(text) <= 262144, "identity registry: missing or too large")
    statuses: Dict[str, str] = {}
    for line in text.splitlines():
        match = _REGISTRY_ROW_RE.match(line.strip())
        if not match:
            continue
        name, status = match.group(1), match.group(4)
        _require(status in REGISTRY_STATUSES, f"identity registry: {name} has unknown status {status}")
        _require(name not in statuses, f"identity registry: {name} is listed twice")
        statuses[name] = status
    _require(bool(statuses), "identity registry: no identity rows found")
    return statuses


def mission_of_ref(ref: Any) -> Optional[str]:
    """Mission id named by any mission/<ID>/... branch, or None."""
    if not isinstance(ref, str):
        return None
    match = _MISSION_REF_RE.match(ref)
    return match.group(1) if match else None


@dataclass(frozen=True)
class Verdict:
    mission_id: str
    round: int
    verdict: str
    reviewed_sha: str
    summary: str = ""
    findings: Tuple[str, ...] = ()


def parse_verdict(text: Any, mission_id: str, round_no: int) -> Verdict:
    data = _load_json(text, "verdict")
    allowed = {"schema", "mission_id", "round", "verdict", "reviewed_sha", "summary", "findings"}
    _require(set(data) <= allowed, f"verdict: unknown keys {sorted(set(data) - allowed)}")
    _require(data.get("schema") == VERDICT_SCHEMA, f"verdict: schema must be {VERDICT_SCHEMA}")
    _require(data.get("mission_id") == mission_id, "verdict: mission_id does not match the branch")
    _require(data.get("round") == round_no and not isinstance(data.get("round"), bool), "verdict: round does not match the branch")
    _require(data.get("verdict") in VERDICTS, "verdict: verdict must be PASS, FAIL or BLOCKED")
    sha = data.get("reviewed_sha")
    _require(isinstance(sha, str) and SHA_RE.fullmatch(sha), "verdict: reviewed_sha must be a full 40-character commit SHA")
    summary = data.get("summary", "")
    _require(isinstance(summary, str) and len(summary) <= SUMMARY_MAX_CHARS, f"verdict: summary must be text of at most {SUMMARY_MAX_CHARS} characters")
    findings = data.get("findings", [])
    _require(isinstance(findings, list) and len(findings) <= MAX_FINDINGS
             and all(isinstance(f, str) and len(f) <= FINDING_MAX_CHARS for f in findings),
             f"verdict: findings must list at most {MAX_FINDINGS} texts of at most {FINDING_MAX_CHARS} characters")
    _require(data["verdict"] != "BLOCKED" or any(f.strip() for f in findings), "verdict: a BLOCKED verdict must list its blockers in findings")
    return Verdict(mission_id, round_no, data["verdict"], sha, summary, tuple(findings))


def hitl_retries(comments: Sequence[dict], hitl: set) -> Tuple[str, ...]:
    """When HITL commented ``/mission retry`` (ISO timestamps, oldest first). Only HITL user accounts count."""
    return tuple(sorted(str(c.get("created_at") or "") for c in comments
                        if (c.get("user") or {}).get("type") == "User"
                        and str((c.get("user") or {}).get("login", "")).casefold() in hitl
                        and _RETRY_RE.search(c.get("body") or "") and c.get("created_at")))


def hitl_halt(comments: Sequence[dict], hitl: set) -> Optional[str]:
    """The HITL login whose ``/mission halt`` is in force, or None (Amendment 010).

    Comments are read in the order GitHub lists them (oldest first); a ``/mission resume`` after a halt lifts it.
    Only HITL user accounts count. A comment carrying both commands counts as a halt: stopping wins.
    """
    halted_by: Optional[str] = None
    for c in comments:
        user = c.get("user") or {}
        login = str(user.get("login", ""))
        if user.get("type") != "User" or login.casefold() not in hitl:
            continue
        body = c.get("body") or ""
        if _HALT_RE.search(body):
            halted_by = login
        elif _RESUME_RE.search(body):
            halted_by = None
    return halted_by


def parse_iso(text: str) -> Optional[datetime]:
    try:
        return datetime.strptime(text, ISO_FORMAT).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def iso(when: datetime) -> str:
    return when.astimezone(timezone.utc).strftime(ISO_FORMAT)


def failures_since_retry(comments: Sequence[dict], role: str, round_no: int, bot: str, hitl: set) -> List[dict]:
    """The bot's failure records for this stage since HITL's last ``/mission retry``, oldest first."""
    failures: List[dict] = []
    for comment in comments:
        user = comment.get("user") or {}
        login = str(user.get("login", ""))
        body = comment.get("body") or ""
        if login == bot and any(m.group(1) == role and int(m.group(2)) == round_no for m in _FAILED_RE.finditer(body)):
            failures.append(comment)
        elif user.get("type") == "User" and login.casefold() in hitl and _RETRY_RE.search(body):
            failures = []
    return failures


def validate_scope_glob(pattern: Any) -> None:
    _require(isinstance(pattern, str) and 0 < len(pattern) <= 200, "build_scope: entries must be non-empty strings")
    _require(not pattern.startswith("/") and "\\" not in pattern, f"build_scope: {pattern!r} must be repo-relative")
    segments = pattern.split("/")
    _require(all(s not in ("", ".", "..") for s in segments), f"build_scope: {pattern!r} has an empty, '.' or '..' segment")
    _require(segments[0] not in ("*", "**"), f"build_scope: {pattern!r} may not start with a wildcard")
    _require(segments[0].casefold() not in (".github", "missions"), f"build_scope: {pattern!r} may not cover .github/ or missions/")


def validate_deliverable(path: Any) -> None:
    """One exact repo-relative file path: no wildcard, no empty, '.' or '..' segment."""
    _require(isinstance(path, str) and 0 < len(path) <= DELIVERABLE_MAX_CHARS,
             f"deliverables: entries must be paths of 1-{DELIVERABLE_MAX_CHARS} characters")
    _require(not path.startswith("/") and "\\" not in path and "\0" not in path, f"deliverables: {path!r} must be repo-relative")
    _require(not any(ch in path for ch in "*?["), f"deliverables: {path!r} must name one file, not a glob")
    _require(all(s not in ("", ".", "..") for s in path.split("/")), f"deliverables: {path!r} has an empty, '.' or '..' segment")


def valid_model(runtime: Any, model: Any) -> bool:
    """Whether ``model`` may be handed to ``runtime`` as its ``--model`` argument."""
    if runtime == "claude-code":
        return model in CLAUDE_CODE_MODELS
    return runtime == "cursor-cli" and isinstance(model, str) and bool(_CURSOR_MODEL_RE.fullmatch(model))


def is_literal_glob(pattern: str) -> bool:
    """True when a build_scope entry has no wildcard, so it names exactly one path."""
    return not any(ch in pattern for ch in "*?[")


def _match_segments(path: Tuple[str, ...], pattern: Tuple[str, ...]) -> bool:
    from fnmatch import fnmatchcase

    if not pattern:
        return not path
    head, rest = pattern[0], pattern[1:]
    if head == "**":
        return any(_match_segments(path[i:], rest) for i in range(len(path) + 1))
    return bool(path) and fnmatchcase(path[0], head) and _match_segments(path[1:], rest)


def _literal_prefix(pattern: str) -> Tuple[str, ...]:
    out = []
    for segment in pattern.split("/"):
        if any(ch in segment for ch in "*?["):
            break
        out.append(segment)
    return tuple(out)


def scopes_overlap(a: Tuple[str, ...], b: Tuple[str, ...]) -> Optional[Tuple[str, str]]:
    """First pair of globs that could match a common path, or None.

    Conservative: two globs overlap when one's literal leading segments are a prefix
    of the other's. A reported overlap may be a false alarm; a missed one cannot be.
    """
    for pa in a:
        la = _literal_prefix(pa)
        for pb in b:
            lb = _literal_prefix(pb)
            n = min(len(la), len(lb))
            if la[:n] == lb[:n]:
                return pa, pb
    return None


def in_scope(path: str, scope: Tuple[str, ...]) -> bool:
    """Segment-aware glob: '*' stays inside one segment, '**' spans any depth. Case-sensitive."""
    parts = tuple(path.split("/"))
    return any(_match_segments(parts, tuple(pattern.split("/"))) for pattern in scope)
