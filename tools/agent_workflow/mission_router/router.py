"""The mission router: reads GitHub, decides with ``gate``, then merges and hands off.

Each run is a full, idempotent sweep. State is re-derived from merged PR
history every time, so a missed or duplicated event never loses or repeats a
handoff: comments carry hidden markers and are posted once, labels and the
tracking issue are set to the state, not toggled.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from .gate import (MERGE, REJECT, WAIT, WAIT_APPROVAL, CapturePR, Decision, FileChange, LandingPR, OpenStagePR, evaluate,
                   evaluate_capture, evaluate_challenge, evaluate_landing, instruction_build_findings,
                   instruction_plan_findings)
from . import challenge as challenge_mod
from .accounts import AccountGuard, GuardedGitHub, config_accounts, identity_mode
import os

import evidence
from evidence import producer as evidence_producer
from mission_dispatch import login, permissions, quarantine, supply_chain
from mission_dispatch.quarantine import inline as quarantined  # §5, Amendment 012: agent text the router posts
from .github import GitHub, GitHubError
from .model import (
    AGENT_RE,
    BOT_LOGIN_RE,
    FAILED_MARKER,
    MAX_AGENT_ATTEMPTS,
    MAX_ROUNDS_CEILING,
    MISSION_ID_RE,
    _HALT_RE,
    _RESUME_RE,
    _RETRY_RE,
    iso,
    STACK_ID_RE,
    Manifest,
    MissionInputError,
    StageRef,
    failures_since_retry,
    hitl_halt,
    hitl_retries,
    integration_branch,
    manifest_path,
    mission_of_ref,
    scopes_overlap,
    parse_identity_accounts,
    parse_identity_registry,
    validate_deliverable,
    valid_target_branch,
    parse_manifest,
    parse_stack_branch,
    parse_stage_branch,
    parse_verdict,
    stack_branch,
    stage_branch,
    verdict_path,
)
from .state import (AWAIT_A1, AWAIT_A2, AWAIT_A3, BLOCKED, CANCELLED, DONE, HALTED, PAUSED, MergedStage, MissionState,
                    derive_state, history_order)

CONFIG_PATH = Path(__file__).with_name("config.json")
MARKER = "<!-- mission-router:{} -->"
_REOPENED_MARK = "<!-- mission-router:stack:reopened:"
_MARKER_RE = re.compile(r"<!-- mission-router:([A-Za-z0-9:._-]+) -->")
SEALED_CHECK = "evidence-sealed"  # set by the seal job (MISSION-DISPATCH-001 §3m item 6)
# The action a router comment records (Amendment 018), by its marker key's first part.
COMMENT_ACTIONS = {"approval": "router.approval_request", "reject": "router.refusal", "refused": "router.refusal",
                   "wait": "router.decision", "waiting": "router.decision"}
_APPROVE_RE = re.compile(r"(?m)^\s*/mission approve ([0-9a-f]{40})\s*$")
_CANCEL_RE = re.compile(r"(?m)^\s*/mission cancel\s*$")
_TRACKING_RE = re.compile(r"<!-- mission-router:tracking-issue:([1-9][0-9]*) -->")
COMPARE_FILE_CAP = 300
ACTIVITY_CAP = 300
# The required status check on the default branch. The router owns it: it publishes
# the result on every open PR into the default branch, and only a mission whose A3
# PASS clears every routing check gets a success.
CHECK_NAME = "route-handoff-block"
# Started on every handoff to A2 or A3 whose plan names a runtime (mission_dispatch).
AGENT_WORKFLOW = "mission-agent.yml"

LABELS = {
    "mission": ("5319e7", "Mission tracking issue maintained by the mission router"),
    "mission:stage-a2": ("0e8a16", "Mission is waiting for its A2 builder"),
    "mission:stage-a3": ("1d76db", "Mission is waiting for its A3 reviewer"),
    "mission:halted": ("b60205", "Mission router halted this mission for HITL"),
    "mission:paused": ("fbca04", "HITL halted this mission with /mission halt; /mission resume continues it"),
    "mission:done": ("cccccc", "Mission passed A3 review and was merged"),
    "mission:cancelled": ("cccccc", "HITL cancelled this mission; nothing from it reached the default branch"),
    "mission:blocked": ("d93f0b", "A blocker kept this mission (or stack) from completing; recorded for HITL review"),
    "mission:stack": ("5319e7", "Stack tracking issue maintained by the mission router"),
    "mission:stack-active": ("0e8a16", "The stack's missions are running"),
    "agent:handoff-ready": ("0e8a16", "Current agent phase is complete and the next authorized agent may pick up the handoff package."),
    "agent:needs-review": ("fbca04", "Independent review requested"),
    "agent:needs-hitl": ("fbca04", "Human-in-the-loop review is required before this work may advance."),
    "agent:blocked": ("b60205", "Work item is blocked and may not advance until the blocker is resolved."),
}
# Mission issues carry only mission labels for the agent stages: the legacy inner-loop
# orchestrator polls agent:handoff-ready and agent:needs-review, and must not pick up missions.
STAGE_LABELS = {
    AWAIT_A2: ["mission", "mission:stage-a2"],
    AWAIT_A3: ["mission", "mission:stage-a3"],
    HALTED: ["mission", "mission:halted", "agent:needs-hitl"],
    PAUSED: ["mission", "mission:paused", "agent:needs-hitl"],
    DONE: ["mission", "mission:done"],
    CANCELLED: ["mission", "mission:cancelled"],
    BLOCKED: ["mission", "mission:blocked", "agent:needs-hitl"],
}
CLOSED_STAGES = {DONE: "mission:done", CANCELLED: "mission:cancelled"}
# A mission in a stack that lands as a whole keeps its issue open until the stack is
# resolved, so the router keeps reading it. Then its issue closes with one of these.
FINAL_LABELS = ("mission:done", "mission:cancelled", "mission:blocked")
# Stack statuses
STACK_ACTIVE, STACK_READY, STACK_LANDED, STACK_BLOCKED, STACK_HALTED = "ACTIVE", "READY", "LANDED", "BLOCKED", "HALTED"
STACK_PAUSED = "PAUSED"  # a mission of it is halted by HITL (Amendment 010): nothing lands until it resumes
STACK_LABELS = {
    STACK_ACTIVE: ["mission", "mission:stack", "mission:stack-active"],
    STACK_READY: ["mission", "mission:stack", "mission:stack-active"],
    STACK_LANDED: ["mission", "mission:stack", "mission:done"],
    STACK_BLOCKED: ["mission", "mission:stack", "mission:blocked", "agent:needs-hitl"],
    STACK_HALTED: ["mission", "mission:stack", "mission:halted", "agent:needs-hitl"],
    STACK_PAUSED: ["mission", "mission:stack", "mission:paused", "agent:needs-hitl"],
}
_STACK_ISSUE_RE = re.compile(r"<!-- mission-router:stack-issue:([1-9][0-9]*) -->")
_CAPTURE_PREFIX_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,30}/")


@dataclass
class _Context:
    state: MissionState
    manifest: Optional[Manifest]
    integration_actual: Optional[str]
    landing: str = "main"  # where an A3 PASS merges: the default branch or the mission's stack branch
    held_by: Optional[str] = None  # set when an CHAINED stack holds this mission because another mission is blocked


@dataclass(frozen=True)
class StackStatus:
    """One stack that lands as a whole, derived from its missions."""

    stack_id: str
    kind: str
    members: Tuple[str, ...]
    status: str  # STACK_ACTIVE / READY / LANDED / BLOCKED / HALTED
    head: Optional[str]  # the stack branch's head
    lander: Optional[Tuple[str, str]] = None  # (agent, bot login) that opens the landing PR
    landing_pr_open: bool = False
    reason: str = ""
    issue: Optional[dict] = None  # the stack's tracking issue, once it has one
    dismissed: bool = False  # BLOCKED, and HITL closed its tracking issue after the review
    target: str = "main"  # where the whole stack lands: its missions' branch, else the default branch (Amendment 008)

    @property
    def resolved(self) -> bool:
        return self.status in (STACK_LANDED, STACK_BLOCKED)

    @property
    def closed(self) -> bool:
        """Its missions' issues close: the stack landed, or HITL closed the review of a blocked stack."""
        return self.status == STACK_LANDED or self.dismissed


def _halted(state: MissionState, reason: str) -> MissionState:
    return MissionState(state.mission_id, HALTED, state.round, state.integration_head, reason=reason,
                        last_pr=state.last_pr, plan_sha=state.plan_sha)


def load_config(path: Path = CONFIG_PATH) -> dict:
    config = json.loads(path.read_text(encoding="utf-8"))
    hitl = config.get("hitl_logins")
    if not (isinstance(hitl, list) and hitl and all(isinstance(x, str) and x for x in hitl)):
        raise ValueError("config.json: hitl_logins must be a non-empty list")
    if not isinstance(config.get("bot_login"), str) or not isinstance(config.get("default_branch"), str):
        raise ValueError("config.json: bot_login and default_branch are required")
    agents = config.get("agents")
    if not (isinstance(agents, dict) and agents
            and all(isinstance(k, str) and AGENT_RE.fullmatch(k) for k in agents)
            and all(isinstance(v, str) and BOT_LOGIN_RE.fullmatch(v) for v in agents.values())
            and len(set(agents.values())) == len(agents)):
        raise ValueError("config.json: agents must map agent names to distinct GitHub App bot logins")
    if not isinstance(config.get("identity_registry"), str):
        raise ValueError("config.json: identity_registry is required")
    identity_mode(config)
    quarantine.mode(config)  # an unknown value stops the router and the dispatcher alike (vector 71)
    permissions.mode(config)  # ring 2 (MISSION-DISPATCH-001 §3k): likewise (vectors 80, 113)
    login.mode(config)  # ring 1 amendment (MISSION-DISPATCH-001 §3i item 6): likewise (vectors 88, 114)
    supply_chain.mode(config)  # ring 4 (MISSION-DISPATCH-001 §3l): likewise (vectors 97, 116)
    evidence.mode(config)  # ring 6 (MISSION-DISPATCH-001 §3m): likewise (vectors 111, 119)
    challenge_mod.mode(config)  # the challenge loop (MISSION-DISPATCH-001 §3n): likewise (vectors 120, 126)
    config_accounts(config)
    store = config.get("evidence_store")
    if store is not None and not (isinstance(store, str) and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", store)):
        raise ValueError("config.json: evidence_store must be owner/name")
    from evidence import worm as worm_mod
    try:
        worm_mod.config(config)
    except evidence.EvidenceError as exc:
        raise ValueError(f"config.json: {exc}") from None
    if evidence.mode(config) == evidence.ENFORCE and not store:
        # Nothing can be sealed without a store, so every A2 and A3 stage PR would be held for ever.
        raise ValueError("config.json: \"evidence\": \"enforce\" needs an evidence_store")
    if not isinstance(config.get("credentials_register", ""), str):
        raise ValueError("config.json: credentials_register must name a file")
    issues = config.get("tracking_issues", {})
    if not (isinstance(issues, dict) and all(isinstance(k, str) and MISSION_ID_RE.fullmatch(k) for k in issues)
            and all(isinstance(v, int) and not isinstance(v, bool) and v > 0 for v in issues.values())):
        raise ValueError("config.json: tracking_issues must map mission ids to issue numbers")
    per_leg = config.get("per_leg_stacks", [])
    if not (isinstance(per_leg, list) and all(isinstance(x, str) and STACK_ID_RE.fullmatch(x) for x in per_leg)):
        raise ValueError("config.json: per_leg_stacks must list stack ids")
    capture = config.get("l1_capture")
    if capture is not None:
        prefix = capture.get("branch_prefix") if isinstance(capture, dict) else None
        if not (isinstance(capture, dict) and set(capture) == {"path", "branch_prefix"} and isinstance(prefix, str)
                and _CAPTURE_PREFIX_RE.fullmatch(prefix) and prefix.split("/")[0] not in ("mission", "stack")):
            raise ValueError("config.json: l1_capture must be {\"path\": <file>, \"branch_prefix\": \"<name>/\"}")
        try:
            validate_deliverable(capture["path"])
        except MissionInputError as exc:
            raise ValueError(f"config.json: l1_capture path: {exc}") from exc
    targets = config.get("landing_branches", [])
    capture_prefix = (capture or {}).get("branch_prefix") or ""
    if not (isinstance(targets, list) and all(valid_target_branch(b) for b in targets) and len(set(targets)) == len(targets)
            and not any(capture_prefix and b.startswith(capture_prefix) for b in targets)):
        raise ValueError("config.json: landing_branches must list distinct branch names outside mission/, stack/ "
                         "and the capture prefix")
    return config


def write_grant_line(manifest: Optional[Manifest]) -> str:
    """The plan's write grant, stated where HITL approves it (MISSION-ROUTER-001 Amendment 014): under ring 2 the
    agent's write rules are its ``build_scope``, so approving the scope approves what A2 may write."""
    if manifest is None or not manifest.build_scope:
        return ""
    return (f"A2 may write (`{manifest.mission_id}`): " + ", ".join(f"`{quarantined(p)}`" for p in manifest.build_scope)
            + "\n\n")


def check_summary(reasons, title: str) -> str:
    """A ``route-handoff-block`` check-run summary: one line per reason, each through the quarantine for GitHub, as
    the router's comments are (MISSION-ROUTER-001 Amendment 017, MISSION-DISPATCH-001 §3j item 8). A reason that
    quotes agent-chosen text (a path, a branch) cannot notify anyone, read as a command, or carry hidden characters."""
    return "\n".join(f"- {quarantined(r)}" for r in reasons) or title


class MissionRouter:
    def __init__(self, gh: GitHub, config: dict, classify: Callable[[str], str], dry_run: bool = False,
                 log: Callable[[str], None] = print, now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                 recorder=None) -> None:
        # Every record GitHub returns passes the account-ID check before any rule reads it (Amendment 011).
        self.identity_mode = identity_mode(config)
        self.quarantine_mode = quarantine.mode(config)  # Amendment 012
        self.evidence_mode = evidence.mode(config)  # Amendment 018
        self.challenge_mode = challenge_mod.mode(config)  # Amendment 019
        self._loops: Dict[Tuple[str, str], challenge_mod.LoopStatus] = {}
        self.guard = AccountGuard(self.identity_mode, lambda message: self.log(message))
        self.gh = GuardedGitHub(gh, self.guard)
        self._accounts = config_accounts(config)
        self.now = now
        self.hitl = {login.casefold() for login in config["hitl_logins"]}
        self.bot = config["bot_login"]
        self.main = config["default_branch"]
        self.agents = dict(config["agents"])
        self.registry_path = config["identity_registry"]
        # Tracking issues recorded before the router marked them on the plan PR (spec section 1).
        self.recorded_issues: Dict[str, int] = dict(config.get("tracking_issues") or {})
        # Stacks started before stacks landed as a whole: their missions keep landing one by one.
        self.per_leg_stacks = frozenset(config.get("per_leg_stacks") or ())
        # Branches a plan may name as its final merge target (Amendment 008); the default branch always may.
        self.targets = frozenset([self.main, *(config.get("landing_branches") or ())])
        # The L1 capture route (Amendment 005): HITL's DRAFT captures append to one queue file without a mission.
        capture = config.get("l1_capture") or {}
        self.capture_path: Optional[str] = capture.get("path")
        self.capture_prefix: Optional[str] = capture.get("branch_prefix")
        self._stacks: Dict[str, StackStatus] = {}
        self._stack_issues: Dict[str, dict] = {}
        self._landing_prs: Dict[str, List[dict]] = {}
        self._ids: Optional[Dict[str, str]] = None
        self._issues: Dict[str, dict] = {}
        self._tracking: Dict[str, Optional[dict]] = {}
        self._plan_pr: Dict[str, int] = {}
        self.classify = classify
        self.dry_run = dry_run
        self.log = log
        self._comments: Dict[int, list] = {}
        # Ring 6 (Amendment 018): every act is recorded before it is made; without a chain nothing is recorded.
        self.evidence = recorder if recorder is not None else evidence_producer.Recorder.from_env(
            os.environ, warn=lambda m: self.log(f"::warning::{m}"))

    # ------------------------------------------------------------------ sweep
    def sweep(self) -> Dict[str, MissionState]:
        if not self.dry_run:
            existing = {l["name"] for l in self.gh.paginate("/labels", limit=1000)}
            for name, (color, description) in LABELS.items():
                if name not in existing:
                    self.gh.ensure_label(name, color, description)
        outside = self._discover()
        for raw in outside:
            if self.capture_prefix and str(raw["head"]["ref"]).startswith(self.capture_prefix):
                try:
                    self._handle_capture(raw)
                except GitHubError as exc:
                    self.log(f"capture PR #{raw['number']}: GitHub error, will retry next sweep: {exc}")
                continue
            self._publish_check(raw["head"]["sha"], "failure", "Not a mission",
                                f"Only missions that passed A3 merge into `{raw['base']['ref']}`. This PR is not a mission stage "
                                "PR, so the router will not pass it. HITL (the repository admin) can merge it outside "
                                "the mission flow.")

        results = {}
        for mission_id in sorted(self._known):
            if self._finished(mission_id):
                continue  # finished missions cost nothing per sweep
            try:
                results[mission_id] = self.run_mission(mission_id, self._open_prs.get(mission_id, []))
            except GitHubError as exc:
                self.log(f"{mission_id}: GitHub error, will retry next sweep: {exc}")
        self._sweep_stacks()
        return results

    def survey(self) -> Dict[str, "_Context"]:
        """Read-only: every unfinished mission's derived state and approved manifest. Writes nothing.

        The mission dispatcher uses this to decide which agent to start, so it acts on the
        same derivation the router merges by, never on the tracking issue's text.
        """
        self._discover()
        contexts = {}
        for mid in sorted(self._known):
            if self._finished(mid):
                continue
            try:
                contexts[mid] = self.context(mid)
            except GitHubError as exc:  # left out, so nothing is started for it this time
                self.log(f"{mid}: GitHub error, left out of this survey: {exc}")
        return contexts

    def _finished(self, mission_id: str) -> bool:
        """Fast path from the issue listing. A listing that misses the issue only costs a full read of the mission."""
        issue = self._issues.get(mission_id)
        if not issue or issue.get("state") != "closed" or mission_id in self._open_prs:
            return False
        names = {l["name"] for l in issue.get("labels") or []}
        return any(label in names for label in FINAL_LABELS)

    def _discover(self) -> List[dict]:
        """Load tracking issues, open PRs and mission branches. Returns open non-mission PRs into the default branch."""
        self._ids = None
        self._loops = {}
        self.identities()  # sets the account IDs the guard expects before any record is read
        self._histories: Dict[str, Tuple[MergedStage, ...]] = {}
        self._issues, self._stack_issues = {}, {}
        self._tracking, self._plan_pr, self._stacks, self._landing_prs = {}, {}, {}, {}
        for issue in self.gh.paginate("/issues?labels=mission&state=all", limit=1000):
            if "pull_request" in issue or (issue.get("user") or {}).get("login") != self.bot:
                continue
            title = str(issue.get("title", ""))
            for prefix, found in (("[mission] ", self._issues), ("[stack] ", self._stack_issues)):
                if title.startswith(prefix):
                    key = title[len(prefix):]
                    if key not in found or issue["number"] < found[key]["number"]:
                        found[key] = issue

        self._open_prs: Dict[str, List[dict]] = {}
        outside = []
        for raw in self.gh.paginate("/pulls?state=open"):
            ref = parse_stage_branch((raw.get("head") or {}).get("ref"))
            stack = parse_stack_branch((raw.get("head") or {}).get("ref"))
            if ref:
                self._open_prs.setdefault(ref.mission_id, []).append(raw)
            elif stack and (raw.get("base") or {}).get("ref") in self.targets:
                self._landing_prs.setdefault(stack, []).append(raw)
            elif (raw.get("base") or {}).get("ref") in self.targets:
                outside.append(raw)

        # Nothing reaches the default branch before A3 passes, so missions are found
        # from their branches and open PRs, not from files on the default branch.
        self._known = set(self._open_prs)
        for entry in self.gh.paginate("/git/matching-refs/heads/mission/", limit=5000):
            mid = mission_of_ref(str(entry.get("ref", ""))[len("refs/heads/"):])
            if mid:
                self._known.add(mid)
        self._contexts: Dict[str, _Context] = {}
        return outside

    def run_mission(self, mission_id: str, prs: List[dict], depth: int = 0) -> MissionState:
        if not hasattr(self, "_contexts"):
            self._contexts, self._known, self._open_prs = {}, {mission_id}, {mission_id: prs}
        self._contexts.pop(mission_id, None)
        getattr(self, "_histories", {}).pop(mission_id, None)
        ctx = self.context(mission_id)
        state = ctx.state
        self.log(f"{mission_id}: {state.stage} round {state.round} {state.reason}".rstrip())

        for raw in sorted(prs, key=lambda r: r["number"]):
            merged = self._handle_pr(raw, ctx)
            if merged:
                self._stacks.clear()  # a merge can change what this mission's stack is waiting on
            if merged and depth < 4:
                rest = [r for r in prs if r["number"] != raw["number"]]
                return self.run_mission(mission_id, rest, depth + 1)

        if state.stage != AWAIT_A1:
            self._sync_tracking_issue(state, ctx.manifest)
        return state

    def context(self, mission_id: str) -> "_Context":
        """Read-only view of one mission, memoized for the sweep."""
        if mission_id in self._contexts:
            return self._contexts[mission_id]
        history = self._history_cache(mission_id)
        manifest, error = self._approved_manifest(mission_id, history)
        landing = self.landing_branch(manifest)
        self._tracking[mission_id] = self._resolve_tracking_issue(mission_id, history)
        issue = self._tracking[mission_id]
        retries = hitl_retries(self._pr_comments(issue["number"]), self.hitl) if issue else ()
        state = derive_state(mission_id, history, manifest, self.hitl | {self.bot.casefold()}, landing,
                             retries, reopen=self._may_reopen(manifest))
        if error and state.stage != AWAIT_A1:
            state = _halted(state, error)
        integration_actual = self.gh.branch_head(integration_branch(mission_id))
        if state.stage in (AWAIT_A2, AWAIT_A3) and integration_actual != state.integration_head:
            state = _halted(state, f"{integration_branch(mission_id)} is at {integration_actual}, expected "
                                   f"{state.integration_head}: it was changed outside the router")
        if state.stage != DONE:
            cancelled_by = self._cancelled_by(mission_id)
            if cancelled_by:
                state = MissionState(mission_id, CANCELLED, state.round, state.integration_head,
                                     reason=f"HITL {cancelled_by} cancelled it", last_pr=state.last_pr, plan_sha=state.plan_sha)
        state = self._agent_failures(state)
        state = self._hitl_halt(state, manifest)
        ctx = _Context(state, manifest, integration_actual, landing)
        self._contexts[mission_id] = ctx
        # CHAINED: the first blocker blocks everything. Memoized above first, so the other
        # missions' contexts read this one's own state, never a hold derived from it.
        if manifest is not None and manifest.lands_with_stack and manifest.stack_kind == "CHAINED" \
                and state.stage in (AWAIT_A2, AWAIT_A3):
            blocker = self._stack_blocker(manifest.stack_id, mission_id)
            if blocker:
                ctx = _Context(MissionState(mission_id, BLOCKED, state.round, state.integration_head,
                                            reason=f"CHAINED stack {manifest.stack_id} is blocked by {blocker}",
                                            last_pr=state.last_pr, plan_sha=state.plan_sha),
                               manifest, integration_actual, landing, held_by=blocker)
                self._contexts[mission_id] = ctx
        return ctx

    def landing_branch(self, manifest: Optional[Manifest]) -> str:
        """Where this mission's A3 PASS merges: its stack branch when the stack lands as a whole, else its target branch."""
        if self._in_stack(manifest):
            return stack_branch(manifest.stack_id)
        return self.target_branch(manifest)

    def target_branch(self, manifest: Optional[Manifest]) -> str:
        """Where this mission's work finally merges (Amendment 008): the plan's ``branch``, else the default branch."""
        return manifest.branch if manifest is not None and manifest.branch else self.main

    def _in_stack(self, manifest: Optional[Manifest]) -> bool:
        """Whether the mission's A3 PASS collects on its stack branch until the whole stack lands."""
        return manifest is not None and manifest.lands_with_stack and manifest.stack_id not in self.per_leg_stacks

    def _may_reopen(self, manifest: Optional[Manifest]) -> bool:
        """Whether a HITL retry may reopen a blocked mission now (Amendment 004).

        Not once HITL has closed the review of the mission's stack: that is final, and the plans then
        restart as a new stack.
        """
        if self._in_stack(manifest):
            stack_issue = self._stack_issues.get(manifest.stack_id)
            if stack_issue is not None and stack_issue.get("state") == "closed":
                return False
        return True


    def _agent_failures(self, state: MissionState) -> MissionState:
        """A stage whose agent run failed MAX_AGENT_ATTEMPTS times in a row is recorded as blocked (spec section 6)."""
        role = _target(state)
        issue = self._tracking.get(state.mission_id)
        if role is None or issue is None:
            return state
        comments = self._pr_comments(issue["number"])
        failures = failures_since_retry(comments, role, state.round, self.bot, self.hitl)
        if len(failures) < MAX_AGENT_ATTEMPTS:
            return state
        last = failures[-1]
        first_line = (last.get("body") or "").strip().splitlines()[0] if (last.get("body") or "").strip() else ""
        what = first_line.replace("**", "").strip() or f"the {role} agent run did not finish"
        where = str(last.get("html_url") or f"#{issue['number']}")
        return MissionState(state.mission_id, BLOCKED, state.round, state.integration_head,
                            reason=f"the {role} agent run failed {len(failures)} times in a row",
                            last_pr=state.last_pr, plan_sha=state.plan_sha, when=str(last.get("created_at") or ""),
                            details=(f"{what} ({where})",))

    def _hitl_halt(self, state: MissionState, manifest: Optional[Manifest]) -> MissionState:
        """``state`` as PAUSED while HITL's ``/mission halt`` is in force (Amendment 010), else unchanged.

        Read from the mission's tracking issue and, for a stack's mission, the stack's issue. A mission that has
        already landed, or was cancelled, or whose plan has not merged, has nothing to halt.
        """
        if state.stage in (AWAIT_A1, CANCELLED) or (state.stage == DONE and not self._in_stack(manifest)):
            return state
        issues = [self._tracking.get(state.mission_id)]
        if self._in_stack(manifest) or (manifest is not None and manifest.stack_id):
            issues.append(self._stack_issues.get(manifest.stack_id))
        for issue, where in zip(issues, ("its tracking issue", "its stack's issue")):
            if issue is None:
                continue
            login = hitl_halt(self._pr_comments(issue["number"]), self.hitl)
            if login:
                return MissionState(state.mission_id, PAUSED, state.round, state.integration_head, state.review_sha,
                                    reason=f"HITL {login} halted it with /mission halt on {where} (#{issue['number']})",
                                    last_pr=state.last_pr, plan_sha=state.plan_sha, landed_sha=state.landed_sha,
                                    build_sha=state.build_sha, paused_from=state.stage)
        return state

    def _cancelled_by(self, mission_id: str) -> Optional[str]:
        """The HITL login that commented ``/mission cancel`` on the mission's tracking issue, if any.

        Only the router-opened tracking issue counts, and only comments from a HITL user
        account. A cancel is final: the mission id cannot be restarted.
        """
        issue = self._tracking.get(mission_id)
        if issue is None:
            return None
        for comment in self._pr_comments(issue["number"]):
            user = comment.get("user") or {}
            login = str(user.get("login", ""))
            if user.get("type") == "User" and login.casefold() in self.hitl and _CANCEL_RE.search(comment.get("body") or ""):
                return login
        return None

    def _resolve_tracking_issue(self, mission_id: str, history: Tuple[MergedStage, ...]) -> Optional[dict]:
        """The mission's tracking issue, read directly by number. None only when it has none yet.

        The number comes from, in order: ``config.json`` ``tracking_issues``, the router's marker on
        the plan PR, and the issue listing. The listing can come back incomplete, so it is only a
        fallback, and a number found there is marked on the plan PR for the next sweep. A number
        that does not lead to this mission's router-opened issue stops the mission (GitHubError):
        guessing could open a duplicate, lose a cancel or restart a failed run.
        """
        a1 = next((h for h in history if h.ref.role == "A1"), None)
        if a1 is None:
            return None  # the plan has not merged; the mission has no tracking issue yet
        self._plan_pr[mission_id] = a1.number
        number, source = self.recorded_issues.get(mission_id), "config"
        if number is None:
            marked = sorted(int(m) for c in self._pr_comments(a1.number) if (c.get("user") or {}).get("login") == self.bot
                            for m in _TRACKING_RE.findall(c.get("body") or ""))
            number, source = (marked[0] if marked else None), "marker"
        if number is None:
            listed = self._issues.get(mission_id)
            if listed is None:
                return None
            number, source = int(listed["number"]), "listing"
        issue = self.gh.get(f"/issues/{number}")
        if ("pull_request" in issue or (issue.get("user") or {}).get("login") != self.bot
                or issue.get("title") != f"[mission] {mission_id}"):
            raise GitHubError(0, f"#{number} (from the {source}) is not the router's tracking issue for {mission_id}; "
                                 "the mission waits until HITL corrects the record", f"/issues/{number}")
        if source == "listing":
            self._mark_tracking_issue(mission_id, number)
        return issue

    def _mark_tracking_issue(self, mission_id: str, number: int) -> None:
        plan_pr = self._plan_pr.get(mission_id)
        if plan_pr is None:
            return
        self._comment_once(plan_pr, f"tracking-issue:{number}",
                           f"Tracking issue for mission `{mission_id}`: #{number}")

    # ---------------------------------------------------------------- reading
    def identities(self) -> Dict[str, str]:
        """Agent -> GitHub App bot login, for agents ACTIVE in the identity registry on the default branch."""
        if self._ids is None:
            try:
                text = self.gh.file_at(self.registry_path, self.main)
                statuses, accounts = parse_identity_registry(text), parse_identity_accounts(text)
            except MissionInputError as exc:
                self.log(f"identity registry unusable, no agent may act: {exc}")
                statuses, accounts = {}, {}
            active = {agent: login for agent, login in self.agents.items() if statuses.get(agent) == "ACTIVE"}
            for agent in sorted(a for a in active if accounts.get(a) is None):
                self.log(f"identity registry: {agent} has no Account ID, so it may not act")
            active = {agent: login for agent, login in active.items() if accounts.get(agent) is not None}
            self.guard.expect({**self._accounts, **{login: accounts[agent] for agent, login in active.items()}})
            confirmed = self.guard.confirm(self.gh.account, sorted(active.values()))
            self._ids = {agent: login for agent, login in active.items()
                         if login in confirmed or self.identity_mode == "observe"}
        return self._ids

    def _push_evidence(self, branch: str, head_sha: str) -> Tuple[Tuple[str, ...], bool]:
        """Every actor GitHub recorded updating ``branch`` as it now exists, and whether one of those updates produced
        ``head_sha``.

        GitHub keeps a deleted branch's events under its name. The branch as it now exists began after its latest
        deletion, so only the events since then count (newest first, as GitHub lists them): otherwise the router's
        own deletion of a refused stage branch would refuse every new attempt on it (Amendment 003). Whoever
        recreates or pushes to the branch afterwards is still recorded.
        """
        listed = self.gh.activity(branch, ACTIVITY_CAP)
        events = []
        for event in listed:
            if event.get("activity_type") == "branch_deletion":
                break
            events.append(event)
        actors = {str((e.get("actor") or {}).get("login") or "(unknown actor)") for e in events}
        if len(listed) >= ACTIVITY_CAP and len(events) == len(listed):
            actors.add(f"(more than {ACTIVITY_CAP} recorded updates; cannot verify them all)")
        return tuple(sorted(actors)), any(e.get("after") == head_sha for e in events)

    def _approved_manifest(self, mission_id: str, history: Tuple[MergedStage, ...]) -> Tuple[Optional[Manifest], str]:
        """The manifest as HITL approved it: read at the A1 merge commit, which nothing can rewrite."""
        a1 = next((h for h in history if h.ref.role == "A1"), None)
        if a1 is None:
            return None, ""
        try:
            return parse_manifest(self.gh.file_at(manifest_path(mission_id), a1.merge_commit_sha), mission_id), ""
        except MissionInputError as exc:
            return None, f"the approved {manifest_path(mission_id)} is invalid: {exc}"

    def _history_cache(self, mission_id: str) -> Tuple[MergedStage, ...]:
        if not hasattr(self, "_histories"):
            self._histories = {}
        if mission_id not in self._histories:
            self._histories[mission_id] = self._history(mission_id)
        return self._histories[mission_id]

    def _history(self, mission_id: str) -> Tuple[MergedStage, ...]:
        owner = self.gh.repo.split("/")[0]
        candidates = list(self.gh.paginate(f"/pulls?state=closed&base={integration_branch(mission_id)}", limit=500))
        for r in range(1, 11):  # an A3 PASS merges into the landing branch (default or stack branch), not the integration branch
            head = stage_branch(mission_id, "A3", r)
            candidates += list(self.gh.paginate(f"/pulls?state=closed&head={owner}:{head}", limit=20))

        dated = []
        seen = set()
        for raw in candidates:
            if not raw.get("merged_at") or raw["number"] in seen:
                continue
            ref = parse_stage_branch(raw["head"]["ref"])
            if ref is None or ref.mission_id != mission_id or (raw["head"].get("repo") or {}).get("full_name") != self.gh.repo:
                continue
            seen.add(raw["number"])
            detail = self.gh.get(f"/pulls/{raw['number']}")
            verdict = reviewed = None
            findings: Tuple[str, ...] = ()
            if ref.role == "A3":
                try:
                    parsed = parse_verdict(self.gh.file_at(verdict_path(mission_id, ref.round), detail["head"]["sha"]), mission_id, ref.round)
                    verdict, reviewed, findings = parsed.verdict, parsed.reviewed_sha, parsed.findings
                except MissionInputError:
                    pass
            dated.append((raw["merged_at"], MergedStage(
                ref, raw["number"], raw["base"]["ref"], (detail.get("merged_by") or {}).get("login", ""),
                detail.get("merge_commit_sha") or "", verdict, reviewed, (detail.get("head") or {}).get("sha"),
                str(raw["merged_at"]), findings)))
        return history_order(dated)

    def _pr_comments(self, number: int) -> list:
        if number not in self._comments:
            self._comments[number] = list(self.gh.paginate(f"/issues/{number}/comments", limit=1000))
        return self._comments[number]

    def _approvals(self, number: int) -> set:
        shas = set()
        for comment in self._pr_comments(number):
            user = comment.get("user") or {}
            if user.get("type") == "User" and str(user.get("login", "")).casefold() in self.hitl:
                shas.update(_APPROVE_RE.findall(comment.get("body") or ""))
        return shas

    def _changes(self, base: str, head: str) -> Tuple[Tuple[FileChange, ...], bool, int]:
        cmp = self.gh.compare(base, head)
        files = tuple(FileChange(f["filename"], f["status"], f.get("previous_filename")) for f in cmp.get("files") or [])
        return files, len(files) < COMPARE_FILE_CAP, int(cmp.get("behind_by", 1))

    def _contains(self, branch_sha: str, sha: str) -> bool:
        """True when ``branch_sha`` has ``sha`` in its history."""
        return int(self.gh.compare(sha, branch_sha).get("behind_by", 1)) == 0

    # ------------------------------------------------------- stacks (PARALLEL/CHAINED)
    def _head_manifest(self, raw: dict) -> Optional[Manifest]:
        ref = parse_stage_branch(raw["head"]["ref"])
        try:
            return parse_manifest(self.gh.file_at(manifest_path(ref.mission_id), raw["head"]["sha"]), ref.mission_id)
        except MissionInputError:
            return None

    def _declared_manifest(self, mission_id: str) -> Optional[Manifest]:
        """Approved manifest, else the one proposed by the mission's open A1 PR (for cycle checks)."""
        manifest = self.context(mission_id).manifest
        if manifest is not None:
            return manifest
        for raw in self._open_prs.get(mission_id, []):
            if parse_stage_branch(raw["head"]["ref"]).role == "A1":
                return self._head_manifest(raw)
        return None

    def _stack_members(self, stack_id: str) -> Tuple[str, ...]:
        """Missions in a stack that lands as a whole: every unfinished mission whose approved (or proposed) plan names it.

        A member's issue stays open until its stack is resolved, so a member is never "finished" before then.
        """
        members = []
        for mid in sorted(self._known):
            if self._finished(mid):
                continue
            manifest = self._declared_manifest(mid)
            if manifest is not None and manifest.stack_id == stack_id and self._in_stack(manifest) \
                    and (self.context(mid).manifest is not None or self._plan_from_a1_actor(mid, manifest)):
                members.append(mid)
        return tuple(members)

    def _plan_from_a1_actor(self, mission_id: str, manifest: Manifest) -> bool:
        """Whether the mission's open plan PR comes from an actor who may hold A1: HITL in person, or the assigned a1 bot.

        Only such plans count towards a stack, so no other identity can change a stack's fingerprint by proposing a plan.
        """
        a1_login = self.identities().get(manifest.roles["A1"].agent)
        for raw in self._open_prs.get(mission_id, []):
            if parse_stage_branch(raw["head"]["ref"]).role != "A1":
                continue
            user = raw.get("user") or {}
            login, kind = str(user.get("login", "")), str(user.get("type", ""))
            return (kind == "User" and login.casefold() in self.hitl) or (kind == "Bot" and login == a1_login)
        return False

    def _stack_blocker(self, stack_id: str, mission_id: str) -> Optional[str]:
        """Another mission in the stack that is blocked or cancelled by itself (not merely held), if any."""
        for other in self._stack_members(stack_id):
            if other == mission_id:
                continue
            ctx = self.context(other)
            if ctx.state.stage in (BLOCKED, CANCELLED) and ctx.held_by is None:
                return other
        return None

    def _stack_landed(self, stack_id: str, target: str) -> bool:
        owner = self.gh.repo.split("/")[0]
        return any(raw.get("merged_at") for raw in
                   self.gh.paginate(f"/pulls?state=closed&base={target}&head={owner}:{stack_branch(stack_id)}", limit=20))

    def stack_status(self, stack_id: str) -> StackStatus:
        """Where a stack that lands as a whole stands (memoized for the sweep; cleared by every merge)."""
        if stack_id in self._stacks:
            return self._stacks[stack_id]
        members = self._stack_members(stack_id)
        ctxs = {m: self.context(m) for m in members}
        kinds = {c.manifest.stack_kind if c.manifest else self._declared_manifest(m).stack_kind for m, c in ctxs.items()}
        kind = kinds.pop() if len(kinds) == 1 else "CHAINED"  # disagreeing members are rejected at start; be strict meanwhile
        head = self.gh.branch_head(stack_branch(stack_id))
        stages = {m: c.state.stage for m, c in ctxs.items()}
        blocked = [m for m, c in ctxs.items() if c.state.stage in (BLOCKED, CANCELLED) and c.held_by is None]
        finished = all(st in (DONE, BLOCKED, CANCELLED) for st in stages.values())
        lander = None
        if members:
            first = ctxs[members[0]].manifest or self._declared_manifest(members[0])
            agent = first.roles["A3"].agent
            login = self.identities().get(agent)
            lander = (agent, login) if login else None
        # Also with no member left: once a closed review has closed every member's issue, the stack is found by its
        # own issue, so its passed and blocked missions stop holding their files.
        issue = self._resolve_stack_issue(stack_id, members)
        dismissed = bool(issue and issue.get("state") == "closed"
                         and "mission:blocked" in {l["name"] for l in issue.get("labels") or []})
        # Approved plans agree on the branch (checked at start); while none is approved, the proposed ones count.
        approved = {self.target_branch(c.manifest) for c in ctxs.values() if c.manifest is not None}
        targets = approved or {self.target_branch(self._declared_manifest(m)) for m in members}
        target = min(targets) if targets else self.main
        status, reason = STACK_ACTIVE, ""
        if self._stack_landed(stack_id, target):
            status, reason = STACK_LANDED, f"merged into {target}"
        elif dismissed:
            status, reason = STACK_BLOCKED, "blocked; HITL closed the review"
        elif len(targets) > 1:
            status, reason = STACK_HALTED, "its missions name different branches: " + ", ".join(sorted(targets))
        elif any(st == HALTED for st in stages.values()):
            status, reason = STACK_HALTED, "a mission is halted for HITL: " + ", ".join(m for m, st in stages.items() if st == HALTED)
        elif any(st == PAUSED for st in stages.values()):
            status, reason = STACK_PAUSED, "HITL halted " + ", ".join(m for m, st in stages.items() if st == PAUSED)
        elif blocked and (kind == "CHAINED" or finished):
            status, reason = STACK_BLOCKED, "blocked by " + ", ".join(blocked)
        elif members and all(st == DONE for st in stages.values()):
            status = STACK_READY
        result = StackStatus(stack_id, kind, members, status, head, lander, bool(self._landing_prs.get(stack_id)), reason,
                             issue, dismissed, target)
        self._stacks[stack_id] = result
        return result

    def stacks(self) -> Dict[str, StackStatus]:
        """Every stack with an unfinished mission or an open landing PR (read-only)."""
        ids = set(self._landing_prs)
        for mid in self._known:
            if not self._finished(mid):
                manifest = self._declared_manifest(mid)
                if self._in_stack(manifest):
                    ids.add(manifest.stack_id)
        return {sid: self.stack_status(sid) for sid in sorted(ids)}

    def _plan_of(self, mission_id: str) -> Optional[Tuple[int, str]]:
        """(plan PR number, plan commit) of a mission: its merged A1 PR, else its open one."""
        history = self._history_cache(mission_id)
        a1 = next((h for h in history if h.ref.role == "A1"), None)
        if a1 is not None and a1.head_sha:
            return a1.number, a1.head_sha
        for raw in self._open_prs.get(mission_id, []):
            if parse_stage_branch(raw["head"]["ref"]).role == "A1":
                return raw["number"], raw["head"]["sha"]
        return None

    def stack_plans(self, stack_id: str) -> List[Tuple[str, int, str]]:
        """(mission, plan PR, plan commit) for every mission in the stack."""
        plans = []
        for mid in self._stack_members(stack_id):
            plan = self._plan_of(mid)
            if plan:
                plans.append((mid, plan[0], plan[1]))
        return plans

    @staticmethod
    def stack_fingerprint(plans: List[Tuple[str, int, str]]) -> str:
        """One 40-hex value naming every plan of a stack at its exact commit. HITL approves the whole stack with it."""
        text = "\n".join(f"{mid} {sha}" for mid, _, sha in sorted(plans))
        return hashlib.sha256(f"mission-stack-v1\n{text}".encode()).hexdigest()[:40]

    def _stack_approved(self, stack_id: str) -> Tuple[bool, str, List[Tuple[str, int, str]]]:
        """Whether HITL approved the stack's current set of plans, with its fingerprint and plans."""
        plans = self.stack_plans(stack_id)
        fingerprint = self.stack_fingerprint(plans)
        return any(fingerprint in self._approvals(number) for _, number, _ in plans), fingerprint, plans

    def _start_checks(self, mission_id: str, manifest: Manifest, integration_actual: Optional[str]) -> Tuple[List[str], List[str]]:
        rejects, waits = [], []
        landing, target = self.landing_branch(manifest), self.target_branch(manifest)
        if target not in self.targets:
            rejects.append(f"branch {target} is not a landing branch HITL allows (config.json landing_branches: "
                           f"{', '.join(sorted(self.targets))})")
        elif self.gh.branch_head(target) is None:
            waits.append(f"branch {target} does not exist; HITL creates it, with its protection, before the mission starts")
        if manifest.stack_id:
            # A stack builds and lands as one thing, so all of its missions name the same branch.
            for other in sorted(self._known - {mission_id}):
                if self._finished(other):
                    continue
                declared = self._declared_manifest(other)
                if declared is not None and declared.stack_id == manifest.stack_id and self.target_branch(declared) != target:
                    rejects.append(f"stack {manifest.stack_id} lands on {self.target_branch(declared)} in {other} but on "
                                   f"{target} here; a stack has one branch")
        for dep in manifest.depends_on:
            dep_ctx = self.context(dep)
            dep_state = dep_ctx.state
            if dep_state.stage in (BLOCKED, CANCELLED):
                waits.append(f"CHAINED dependency {dep} is {dep_state.stage.lower()}; this mission will not start")
            elif dep_state.stage != DONE:
                waits.append(f"CHAINED dependency {dep} has not passed A3 yet (it is {dep_state.stage})")
            elif dep_ctx.landing not in (landing, target):
                rejects.append(f"CHAINED dependency {dep} landed on {dep_ctx.landing}, which this mission does not build on")
            elif integration_actual and not self._contains(integration_actual, dep_state.landed_sha):
                rejects.append(f"{integration_branch(mission_id)} does not contain {dep}'s landed commit {dep_state.landed_sha}")
        cycle = self._dependency_cycle(mission_id, manifest)
        if cycle:
            rejects.append("depends_on forms a cycle: " + " -> ".join(cycle))
        if self._in_stack(manifest):
            sid = manifest.stack_id
            if self._stack_landed(sid, target):
                rejects.append(f"stack {sid} has already landed on {target}; a new stack needs a new id")
            elif self.stack_status(sid).dismissed:
                rejects.append(f"stack {sid} was blocked and HITL closed its review; restart the plans as a new stack")
            for other in self._stack_members(sid):
                declared = self._declared_manifest(other)
                if other != mission_id and declared is not None and declared.stack_kind != manifest.stack_kind:
                    rejects.append(f"stack {sid} is {declared.stack_kind} in {other} but {manifest.stack_kind} here; a stack has one kind")
            if manifest.stack_kind == "CHAINED" and self._stack_blocker(sid, mission_id):
                waits.append(f"CHAINED stack {sid} is blocked by {self._stack_blocker(sid, mission_id)}; nothing more in it starts")
        for other in sorted(self._known - {mission_id}):
            ctx = self.context(other)
            if ctx.manifest is None or not self._holds_scope(other, ctx):
                continue
            if ctx.manifest.stack_id and ctx.manifest.stack_id == manifest.stack_id and manifest.stack_kind == "CHAINED":
                continue  # CHAINED missions build on each other's results in order
            clash = scopes_overlap(manifest.build_scope, ctx.manifest.build_scope)
            if clash:
                rejects.append(f"build_scope {clash[0]!r} overlaps {clash[1]!r} of active mission {other}; "
                               "concurrent missions must not be able to touch the same files")
        return rejects, waits

    def _holds_scope(self, mission_id: str, ctx: "_Context") -> bool:
        """Whether this mission's files are taken: running, halted, or passed onto a stack branch that has not landed."""
        if ctx.state.stage in (AWAIT_A2, AWAIT_A3, HALTED, PAUSED):
            return True
        if self._in_stack(ctx.manifest) and ctx.state.stage in (DONE, BLOCKED):
            return not self.stack_status(ctx.manifest.stack_id).closed
        return False

    def _dependency_cycle(self, mission_id: str, manifest: Manifest) -> Optional[List[str]]:
        stack = [(dep, [mission_id, dep]) for dep in manifest.depends_on]
        visited = set()
        while stack:
            node, path = stack.pop()
            if node == mission_id:
                return path
            if node in visited or len(path) > 50:
                continue
            visited.add(node)
            declared = self._declared_manifest(node)
            for nxt in (declared.depends_on if declared else ()):
                stack.append((nxt, path + [nxt]))
        return None

    def _prepare_a1(self, raw: dict, ctx: "_Context", manifest: Optional[Manifest]) -> dict:
        """Give an A1 PR its integration branch and point the PR at it. Never touches the default branch."""
        ref = parse_stage_branch(raw["head"]["ref"])
        branch = integration_branch(ref.mission_id)
        actual = ctx.integration_actual
        landing, target = self.landing_branch(manifest), self.target_branch(manifest)
        if target not in self.targets or self.gh.branch_head(target) is None:
            return raw  # the start checks hold the plan; the router never creates a target branch
        if self._in_stack(manifest) and self.gh.branch_head(landing) is None \
                and not self._stack_landed(manifest.stack_id, target):
            # The stack branch starts at the target branch; passed missions of the stack collect on it.
            head = self.gh.branch_head(target)
            self._write(f"create {landing} at {head}", lambda: self.gh.create_branch(landing, head),
                        "router.branch", mission=ref.mission_id, pr=raw["number"], commit=head)
        if actual is None:
            source = landing if self.gh.branch_head(landing) is not None else target
            base = self.gh.compare(source, raw["head"]["sha"]).get("merge_base_commit", {}).get("sha")
            if base:
                self._write(f"create {branch} at {base}", lambda: self.gh.create_branch(branch, base),
                            "router.branch", mission=ref.mission_id, pr=raw["number"], commit=base)
                actual = base
        elif manifest is not None and manifest.depends_on:
            # CHAINED: once every dependency has passed, move a still-empty integration branch up to the
            # landing branch (the stack branch, where the dependencies' results are).
            landed = [self.context(d).state.landed_sha for d in manifest.depends_on if self.context(d).state.stage == DONE]
            if len(landed) == len(manifest.depends_on) and not all(self._contains(actual, sha) for sha in landed):
                if int(self.gh.compare(landing, actual).get("ahead_by", 1)) == 0:
                    head = self.gh.branch_head(landing)
                    self._write(f"fast-forward {branch} to {head}", lambda: self.gh.update_ref(branch, head),
                                "router.branch", mission=ref.mission_id, pr=raw["number"], commit=head)
                    actual = head
        if raw["base"]["ref"] in (self.main, target) and actual is not None:
            self._write(f"retarget PR #{raw['number']} to {branch}", lambda: self.gh.retarget(raw["number"], branch),
                        "router.branch", mission=ref.mission_id, pr=raw["number"], commit=raw["head"]["sha"])
            raw = {**raw, "base": {**raw["base"], "ref": branch}}
        ctx.integration_actual = actual
        return raw

    # -------------------------------------------------------------- deciding
    def decide(self, raw: dict, ctx: "_Context") -> Decision:
        ref = parse_stage_branch(raw["head"]["ref"])
        head_sha = raw["head"]["sha"]
        state, manifest, integration_actual = ctx.state, ctx.manifest, ctx.integration_actual
        start_rejects, start_waits, integration_clean = [], [], True
        if ref.role == "A1" and state.stage == AWAIT_A1:
            try:
                manifest = parse_manifest(self.gh.file_at(manifest_path(ref.mission_id), head_sha), ref.mission_id)
            except MissionInputError as exc:
                return Decision(REJECT, (str(exc),))
            landing = self.landing_branch(manifest)
            if integration_actual is not None:
                integration_clean = int(self.gh.compare(landing, integration_actual).get("ahead_by", 1)) == 0
            start_rejects, start_waits = self._start_checks(ref.mission_id, manifest, integration_actual)
            if self.challenge_mode == challenge_mod.ENFORCE and "AR" not in manifest.roles:
                start_rejects = start_rejects + [
                    "under \"challenge\": \"enforce\" a plan assigns an AR seat, which challenges it before HITL "
                    "approves it (MISSION-DISPATCH-001 §3n item 1)"]
            target = self.target_branch(manifest)
            if integration_actual is None and target in self.targets and self.gh.branch_head(target) is None:
                # Nothing can be prepared without the branch, and nothing merges while this holds (Amendment 008).
                return Decision(WAIT, tuple(start_waits))

        if ref.role == "A1":
            base = integration_actual or self.main
        elif ref.role == "A2":
            base = state.integration_head or raw["base"]["ref"]
        else:
            base = state.review_sha or raw["base"]["ref"]
        files, complete, behind = self._changes(base, head_sha)

        verdict = verdict_error = None
        promotion, promotion_complete = (), True
        if ref.role == "A3":
            try:
                verdict = parse_verdict(self.gh.file_at(verdict_path(ref.mission_id, ref.round), head_sha), ref.mission_id, ref.round)
            except MissionInputError as exc:
                verdict_error = str(exc)
            if verdict is not None and verdict.verdict == "PASS" and not self._in_stack(manifest):
                # A mission in a stack is checked for HITL-only files once, when the whole stack lands.
                promotion, promotion_complete, _ = self._changes(ctx.landing, head_sha)

        user = raw.get("user") or {}
        pushers, head_pushed = self._push_evidence(raw["head"]["ref"], head_sha)
        pr = OpenStagePR(
            number=raw["number"], ref=ref, head_sha=head_sha, base_ref=raw["base"]["ref"],
            author=str(user.get("login", "")), author_type=str(user.get("type", "")),
            same_repo=(raw["head"].get("repo") or {}).get("full_name") == self.gh.repo,
            draft=bool(raw.get("draft")), files=files, files_complete=complete, behind_by=behind,
            pushers=pushers, head_pushed=head_pushed,
        )
        approvals = self._approvals(raw["number"])
        if ref.role == "A1" and self._in_stack(manifest):
            approved, _, _ = self._stack_approved(manifest.stack_id)
            if approved:
                approvals = approvals | {head_sha}  # one approval of the stack covers every plan in it at its exact commit
        enforce = self.quarantine_mode == quarantine.ENFORCE
        if not enforce and manifest is not None:  # vector 109: what enforcement would refuse is logged
            would = (instruction_plan_findings(manifest, self.classify) if ref.role == "A1"
                     else instruction_build_findings(files, self.classify) if ref.role == "A2" else [])
            for reason in would:
                self.log(f"  quarantine (observe): PR #{raw['number']} would be refused: {reason}")
        return evaluate(pr, state, manifest, self.classify, approvals, integration_actual,
                        verdict, verdict_error, promotion, promotion_complete,
                        self.landing_branch(manifest) if ref.role == "A1" else ctx.landing,
                        start_rejects, start_waits, integration_clean, self.identities(),
                        hitl_logins=self.hitl, refuse_instruction_files=enforce, plan_mergers={self.bot})

    # ---------------------------------------------------------------- acting
    def _handle_pr(self, raw: dict, ctx: "_Context") -> bool:
        number, head_sha = raw["number"], raw["head"]["sha"]
        ref = parse_stage_branch(raw["head"]["ref"])
        if ref.role == "AR":
            return self._handle_challenge(raw, ctx)
        if ref.role == "A1" and ctx.state.stage == AWAIT_A1 and not raw.get("draft"):
            raw = self._prepare_a1(raw, ctx, self._head_manifest(raw))
        decision = self._evidence_hold(self.decide(raw, ctx), ref, head_sha)
        if ref.role == "A1" and ctx.state.stage == AWAIT_A1 and not raw.get("draft"):
            decision = self._challenge_gate(raw, decision)
        self.log(f"  PR #{number} {ref.role} r{ref.round}: {decision.action} {decision.summary}".rstrip())
        if raw["base"]["ref"] in self.targets:
            # Published before the merge below, which branch protection holds until the check passes.
            outcome = {MERGE: "success", REJECT: "failure"}.get(decision.action, "pending")
            title = {MERGE: f"Mission {ref.mission_id}: A3 PASS cleared every routing check",
                     REJECT: f"Mission {ref.mission_id}: rejected by the router"}.get(decision.action, f"Mission {ref.mission_id}: held")
            self._publish_check(head_sha, outcome, title, check_summary(decision.reasons, title))

        if decision.action == WAIT:
            if decision.reasons and not raw.get("draft"):
                digest = hashlib.sha256(decision.summary.encode()).hexdigest()[:12]
                self._comment_once(number, f"wait:{head_sha[:12]}:{digest}", "The mission router is holding this PR:\n\n"
                                   + "\n".join(f"- {quarantined(r)}" for r in decision.reasons)
                                   + "\n\nIt will continue on its own once this changes.")
            return False
        if decision.action == REJECT:
            digest = hashlib.sha256(decision.summary.encode()).hexdigest()[:12]
            self._comment_once(number, f"reject:{head_sha[:12]}:{digest}", "The mission router did not merge this PR:\n\n"
                               + "\n".join(f"- {quarantined(r)}" for r in decision.reasons)
                               + "\n\nPush a fix to this branch, or ask HITL if the mission itself needs to change.")
            self._add_labels(number, ["agent:blocked"])
            if ref.role in ("A2", "A3") and ctx.state.expects(ref):
                self._refuse_stage(raw, ref, decision)
            return False
        if decision.action == WAIT_APPROVAL:
            manifest = ctx.manifest or (self._head_manifest(raw) if ref.role == "A1" else None)
            if ref.role == "A1" and self._in_stack(manifest):
                _, fingerprint, plans = self._stack_approved(manifest.stack_id)
                listed = "\n".join(f"- `{mid}`: #{n} at `{sha}`" for mid, n, sha in sorted(plans))
                self._comment_once(number, f"approval:stack:{fingerprint[:12]}",
                                   f"Stack `{manifest.stack_id}` ({manifest.stack_kind}) needs HITL approval to start. "
                                   f"One approval covers every plan in it, each at this exact commit:\n\n{listed}\n\n"
                                   + write_grant_line(manifest) +
                                   f"To approve the whole stack, a HITL login comments (here or on any of those PRs):\n\n"
                                   f"```\n/mission approve {fingerprint}\n```\n\n"
                                   "After that nothing waits for HITL until the stack lands or is blocked. A new push to "
                                   "any of these plans, or a new plan in the stack, needs a new approval.")
            else:
                self._comment_once(number, f"approval:{head_sha[:12]}", "This PR needs HITL approval before the mission router merges it:\n\n"
                                   + "\n".join(f"- {quarantined(r)}" for r in decision.reasons)
                                   + "\n\n" + (write_grant_line(manifest) if ref.role == "A1" else "")
                                   + f"To approve this exact commit, a HITL login comments:\n\n```\n/mission approve {head_sha}\n```\n\n"
                                   "A new push needs a new approval.")
            self._add_labels(number, ["agent:needs-hitl"])
            return False

        # MERGE
        base = raw["base"]["ref"]
        title = f"Mission {ref.mission_id}: merge {ref.role}" + (f" round {ref.round}" if ref.round else "") + \
                (f" ({decision.verdict})" if decision.verdict else "")
        self._record_decision(number, head_sha, base, decision, ref.mission_id, ref.round)
        try:
            if base in self.targets:
                self._approve_once(number, head_sha)
            # A merge into a landing branch (an A3 PASS) is the mission's landing: its EPAP provenance is written
            # when this sweep is sealed (MISSION-DISPATCH-001 §3m item 2).
            result = self._write(f"merge PR #{number} at {head_sha}", lambda: self.gh.merge(number, head_sha, title),
                                 "router.landing" if base in self.targets else "router.merge",
                                 mission=ref.mission_id, round_n=ref.round, pr=number, commit=head_sha)
        except GitHubError as exc:
            if exc.status in (405, 409, 422):
                self._comment_once(number, f"waiting:{head_sha[:12]}",
                                   f"The mission router approved this PR, but GitHub will not merge it yet: {exc.message}. "
                                   "The router retries every sweep (about 5 minutes).")
                return False
            raise
        return bool(result)

    # ------------------------------------------------- the challenge loop (§6a)
    def _plan_raw(self, mission_id: str) -> Optional[dict]:
        """The mission's open plan PR, if any."""
        for raw in self._open_prs.get(mission_id, []) if hasattr(self, "_open_prs") else []:
            if parse_stage_branch(raw["head"]["ref"]).role == "A1":
                return raw
        return None

    def _ar_login(self, manifest: Optional[Manifest]) -> Optional[str]:
        if manifest is None or "AR" not in manifest.roles:
            return None
        return self.identities().get(manifest.roles["AR"].agent)

    def _round_authentic(self, mission_id: str, round_no: int, head: str, ar_login: Optional[str]) -> bool:
        """Whether round N at ``head`` came in through a PR of AR's own App that the router merged into the plan branch,
        and both of its files are still as that PR wrote them (§6a: the router checks who wrote it and where)."""
        if ar_login is None:
            return False
        owner = self.gh.repo.split("/")[0]
        listed = self.gh.paginate(f"/pulls?state=closed&base={challenge_mod.plan_branch(mission_id)}"
                                  f"&head={owner}:{stage_branch(mission_id, 'AR', round_no)}", limit=50)
        for raw in listed:
            if not raw.get("merged_at") or (raw["head"].get("repo") or {}).get("full_name") != self.gh.repo:
                continue
            detail = self.gh.get(f"/pulls/{raw['number']}")
            user = detail.get("user") or {}
            if (user.get("type") != "Bot" or user.get("login") != ar_login
                    or (detail.get("merged_by") or {}).get("login") != self.bot):
                continue
            pr_head = (detail.get("head") or {}).get("sha")
            if pr_head and all(self.gh.file_at(path, pr_head) == self.gh.file_at(path, head)
                               for path in (challenge_mod.round_json(mission_id, round_no),
                                            challenge_mod.round_md(mission_id, round_no))):
                return True
        return False

    def challenge_loop(self, mission_id: str, head: str, manifest: Optional[Manifest]) -> challenge_mod.LoopStatus:
        """Where the challenge loop stands for the plan at ``head`` (MISSION-DISPATCH-001 §3n item 3, router §6a).
        Read-only; memoized for the sweep. The dispatcher starts AR from ``due_round`` (part 2)."""
        key = (mission_id, head)
        if key in self._loops:
            return self._loops[key]
        ar_login = self._ar_login(manifest)
        rounds = []
        for n in range(1, challenge_mod.MAX_ROUNDS + 1):
            text = self.gh.file_at(challenge_mod.round_json(mission_id, n), head)
            if text is None:
                break
            try:
                parsed, error = challenge_mod.parse_challenge(text, mission_id, n), ""
            except MissionInputError as exc:
                parsed, error = None, str(exc)
            rounds.append(challenge_mod.RoundFacts(parsed, error, self._round_authentic(mission_id, n, head, ar_login),
                                                   self.gh.file_at(challenge_mod.response_path(mission_id, n), head)))
        stray = [n for n in (len(rounds) + 1, len(rounds) + 2)
                 if self.gh.file_at(challenge_mod.response_path(mission_id, n), head) is not None]
        plan_changed = False
        latest = rounds[-1].challenge if rounds else None
        if latest is not None:
            try:
                files, complete, _ = self._changes(latest.challenged_sha, head)
                plan_changed = not complete or any(challenge_mod.is_plan_file(p, mission_id)
                                                   for f in files for p in (f.path, f.previous_path or ""))
            except GitHubError:
                plan_changed = True  # a challenged commit GitHub cannot compare is not the plan AR read
        status = challenge_mod.loop_status(mission_id, rounds, plan_changed, stray)
        self._loops[key] = status
        return status

    def _challenge_gate(self, raw: dict, decision: Decision) -> Decision:
        """HITL's approval of a plan head counts under ``"challenge": "enforce"`` only when the loop is complete for that
        head (router §6a, vectors 120-122, 125). Under observe the router says what is missing and counts it (vector
        119). It also says when A1's latest response is missing a line, as AR is not started on it (vector 127)."""
        ref = parse_stage_branch(raw["head"]["ref"])
        head = raw["head"]["sha"]
        manifest = self._head_manifest(raw)
        if manifest is None or (self.challenge_mode == challenge_mod.OBSERVE and "AR" not in manifest.roles):
            return decision  # no seat and nothing enforced: today's flow, unchanged
        loop = self.challenge_loop(ref.mission_id, head, manifest)
        if loop.response_error:
            self._comment_once(raw["number"], f"challenge-response:{head[:12]}",
                               f"The challenge loop is waiting on A1: {quarantined(loop.response_error)}.\n\n"
                               "AR is not started until the response opens with these two lines:\n\n"
                               "```\nPosition: DEFEND\nDrafted-with: <the agent you drafted it with, or HITL>\n```\n\n"
                               "(`Position: ACCEPT` when you accept the points, usually with the plan change in the "
                               "same push.)", mission=ref.mission_id)
        if decision.action != MERGE or loop.complete:
            return decision
        if self.challenge_mode == challenge_mod.ENFORCE:
            self._comment_once(raw["number"], f"challenge-incomplete:{head[:12]}",
                               "HITL's approval of this head is not counted yet: the challenge loop is not complete "
                               f"for it ({quarantined(loop.missing)}).\n\nThe loop is complete when at least one AR "
                               "round exists, AR spoke last, and the plan is unchanged since AR read it. Approving "
                               "again once it is complete is how the mission proceeds (MISSION-ROUTER-001 §6a).",
                               mission=ref.mission_id)
            return Decision(WAIT, (f"the challenge loop is not complete for this head: {loop.missing}",))
        self._comment_once(raw["number"], f"challenge-observe:{head[:12]}",
                           "Challenge loop (observe): under `\"challenge\": \"enforce\"` this approval would not count "
                           f"yet, because {quarantined(loop.missing)}. Under observe it counts as before.",
                           mission=ref.mission_id)
        return decision

    def _handle_challenge(self, raw: dict, ctx: "_Context") -> bool:
        """AR's challenge PR into the plan branch (router §6a): merged when every check holds, then the round is posted
        on the plan PR with its points quarantined and any steering lines listed (§3n item 6)."""
        number, head_sha = raw["number"], raw["head"]["sha"]
        ref = parse_stage_branch(raw["head"]["ref"])
        mid = ref.mission_id
        plan_head = self.gh.branch_head(challenge_mod.plan_branch(mid))
        manifest = None
        if plan_head is not None:
            try:
                manifest = parse_manifest(self.gh.file_at(manifest_path(mid), plan_head), mid)
            except MissionInputError:
                manifest = None
        loop = self.challenge_loop(mid, plan_head, manifest) if plan_head is not None and manifest is not None else None
        parsed = error = None
        try:
            parsed = challenge_mod.parse_challenge(self.gh.file_at(challenge_mod.round_json(mid, ref.round), head_sha),
                                                   mid, ref.round)
        except MissionInputError as exc:
            error = str(exc)
        files, complete, behind = self._changes(plan_head or raw["base"]["ref"], head_sha)
        user = raw.get("user") or {}
        pushers, head_pushed = self._push_evidence(raw["head"]["ref"], head_sha)
        pr = OpenStagePR(number=number, ref=ref, head_sha=head_sha, base_ref=raw["base"]["ref"],
                         author=str(user.get("login", "")), author_type=str(user.get("type", "")),
                         same_repo=(raw["head"].get("repo") or {}).get("full_name") == self.gh.repo,
                         draft=bool(raw.get("draft")), files=files, files_complete=complete, behind_by=behind,
                         pushers=pushers, head_pushed=head_pushed)
        decision = evaluate_challenge(pr, ctx.state, manifest, self.identities(), plan_head,
                                      loop.due_round if loop else None, parsed, error)
        decision = self._evidence_hold(decision, ref, head_sha)
        self.log(f"  PR #{number} AR r{ref.round}: {decision.action} {decision.summary}".rstrip())
        if decision.action == WAIT:
            if decision.reasons and not raw.get("draft"):
                digest = hashlib.sha256(decision.summary.encode()).hexdigest()[:12]
                self._comment_once(number, f"wait:{head_sha[:12]}:{digest}", "The mission router is holding this "
                                   "challenge:\n\n" + "\n".join(f"- {quarantined(r)}" for r in decision.reasons)
                                   + "\n\nIt will continue on its own once this changes.", mission=mid)
            return False
        if decision.action == REJECT:
            digest = hashlib.sha256(decision.summary.encode()).hexdigest()[:12]
            self._comment_once(number, f"reject:{head_sha[:12]}:{digest}", "The mission router did not merge this "
                               "challenge:\n\n" + "\n".join(f"- {quarantined(r)}" for r in decision.reasons)
                               + "\n\nNothing from it reaches the plan (MISSION-ROUTER-001 §6a).", mission=mid)
            self._add_labels(number, ["agent:blocked"])
            return False
        self._record_decision(number, head_sha, raw["base"]["ref"], decision, mid, ref.round)
        md = self.gh.file_at(challenge_mod.round_md(mid, ref.round), head_sha) or ""
        held = quarantine.quarantine(md, "AR", f"challenge round {ref.round} at {head_sha[:12]}", 12000, github=True)
        if held.hits:
            self._comment_once(number, f"challenge-steering:{head_sha[:12]}",
                               "\n".join(quarantine.machine_note(held.hits, github=True)), mission=mid)
        try:
            result = self._write(f"merge PR #{number} at {head_sha}",
                                 lambda: self.gh.merge(number, head_sha,
                                                       f"Mission {mid}: AR round {ref.round} ({decision.verdict})"),
                                 "router.merge", mission=mid, round_n=ref.round, pr=number, commit=head_sha)
        except GitHubError as exc:
            if exc.status in (405, 409, 422):
                self._comment_once(number, f"waiting:{head_sha[:12]}",
                                   f"The mission router approved this challenge, but GitHub will not merge it yet: "
                                   f"{exc.message}. The router retries every sweep (about 5 minutes).", mission=mid)
                return False
            raise
        plan = self._plan_raw(mid)
        if result and plan is not None:
            points = parsed.points if parsed else ()
            listed = "\n".join(f"- `{quarantined(p.id, 60)}` on {quarantined(p.on, 300)}" for p in points)
            self._comment_once(
                plan["number"], f"challenge-round:{ref.round}:{head_sha[:12]}",
                f"**AR challenge round {ref.round}: {decision.verdict}**"
                + (f" ({len(points)} point{'s' if len(points) != 1 else ''})" if points else "") + "\n\n"
                + (listed + "\n\n" if listed else "") + held.text + "\n"
                + (f"To answer, the A1 seat pushes `{challenge_mod.response_path(mid, ref.round)}` to this branch. Its "
                   "first line is `Position: DEFEND` or `Position: ACCEPT`, its second `Drafted-with: <agent>` (or "
                   "`Drafted-with: HITL`); accepting usually changes the plan in the same push. AR then answers in "
                   f"round {ref.round + 1}. " if decision.verdict == "CHALLENGE" else
                   "AR found nothing to challenge: a null loop is a valid outcome. ")
                + "HITL ends the loop by approving the plan's head or cancelling the mission.", mission=mid)
        # Not reported as a stage merge: the plan PR's head moved, so it is decided afresh on the next sweep rather
        # than again in this one from the head it was listed with.
        return False

    def _sealed(self, sha: str) -> bool:
        """Whether the seal job set ``evidence-sealed`` on ``sha``: every chain of the run that published it is sealed
        and in the store (MISSION-DISPATCH-001 §3m item 6)."""
        return any((r.get("app") or {}).get("slug") == "github-actions" and r.get("status") == "completed"
                   and r.get("conclusion") == "success" for r in self.gh.check_runs(sha, SEALED_CHECK))

    def _evidence_hold(self, decision: Decision, ref: StageRef, head_sha: str) -> Decision:
        """Under ``"evidence": "enforce"`` an A2, A3 or AR PR, which a dispatcher run published, is merged only once
        that run is sealed and stored; until then it is held and says why (router vectors 118, and dispatch 118 for
        AR). Under observe the router only says so in its log."""
        if decision.action != MERGE or ref.role not in ("A2", "A3", "AR") or self._sealed(head_sha):
            return decision
        reason = ("the run that published this PR is not sealed and stored yet (MISSION-DISPATCH-001 §3m item 6; "
                  "the seal job sets the evidence-sealed check)")
        if self.evidence_mode != evidence.ENFORCE:
            self.log(f"    evidence (observe): {reason}")
            return decision
        return Decision(WAIT, decision.reasons + (reason,), decision.approval_required, decision.verdict)

    def _publish_check(self, sha: str, outcome: str, title: str, summary: str) -> None:
        """Set this router's ``route-handoff-block`` result on ``sha``; skipped when it already says the same."""
        status, conclusion = ("in_progress", None) if outcome == "pending" else ("completed", outcome)
        ours = [r for r in self.gh.check_runs(sha, CHECK_NAME) if (r.get("app") or {}).get("slug") == "github-actions"]
        if ours:  # branch protection reads the newest run, so only that one can make a republish unnecessary
            newest = max(ours, key=lambda r: int(r.get("id") or 0))
            if (newest.get("status"), newest.get("conclusion"), (newest.get("output") or {}).get("title")) == (status, conclusion, title):
                return
        self._write(f"set {CHECK_NAME} on {sha[:12]} to {outcome}",
                    lambda: self.gh.create_check_run(CHECK_NAME, sha, status, conclusion, title, summary),
                    "router.refusal" if outcome == "failure" else "router.decision", commit=sha,
                    outputs={"summary": evidence_producer.text_digest(summary)})

    def _approve_once(self, number: int, sha: str) -> None:
        for review in self.gh.paginate(f"/pulls/{number}/reviews", limit=500):
            if (review.get("user") or {}).get("login") == self.bot and review.get("state") == "APPROVED" and review.get("commit_id") == sha:
                return
        self._write(f"approve PR #{number}", lambda: self.gh.approve(number, sha, "Mission router: every routing check passed for this commit."),
                    "router.decision", pr=number, commit=sha)

    def _refuse_stage(self, raw: dict, ref: StageRef, decision: Decision) -> None:
        """A refused PR for the A2/A3 stage the mission waits on counts as a failed agent run (Amendment 003).

        The refusal is recorded on the tracking issue as a failure, then the stage branch is deleted, so the
        dispatcher runs the agent again and hands it the reasons. After MAX_AGENT_ATTEMPTS failures in a row the
        stage is recorded as blocked. Without the record nothing is deleted: a branch is only ever deleted once
        its refusal is on the issue.
        """
        branch = stage_branch(ref.mission_id, ref.role, ref.round)
        same_repo = (raw["head"].get("repo") or {}).get("full_name") == self.gh.repo
        issue = self._tracking.get(ref.mission_id)
        if raw["head"]["ref"] != branch or not same_repo or issue is None:
            return
        head = raw["head"]["sha"]
        summary = quarantined(decision.summary, 600)
        self._comment_once(issue["number"], f"refused:{ref.role}:{ref.round}:{head[:12]}",
                           f"**Mission router: {ref.role} round {ref.round} was refused:** {summary}\n\n"
                           f"PR #{raw['number']} at `{head[:12]}`. The stage branch is deleted so the agent runs again "
                           f"with these reasons. After {MAX_AGENT_ATTEMPTS} failures in a row the stage is recorded as "
                           "blocked for HITL review.\n\n" + FAILED_MARKER.format(role=ref.role, round=ref.round))
        self._write(f"delete refused branch {branch}", lambda: self.gh.delete_branch(branch), "router.refusal",
                    mission=ref.mission_id, round_n=ref.round, pr=raw["number"], commit=head)

    def _comment_once(self, number: int, key: str, body: str, action: Optional[str] = None, before=None,
                      mission: Optional[str] = None) -> bool:
        """Post ``body`` once per ``key``; True when this call posted it. ``before`` runs just before it is posted
        (the HITL commands the comment acts on are recorded there)."""
        for comment in self._pr_comments(number):
            if (comment.get("user") or {}).get("login") == self.bot and MARKER.format(key) in (comment.get("body") or ""):
                return False
        text = f"{body}\n\n{MARKER.format(key)}"
        if before is not None and not self.dry_run:
            action = before() or action
        kind = key.split(":", 1)[0]
        action = action or COMMENT_ACTIONS.get(kind, "router.comment")
        self._write(f"comment on #{number} [{key}]", lambda: self.gh.comment(number, text), action, pr=number,
                    mission=mission, outputs={"comment": evidence_producer.text_digest(text)})
        self._pr_comments(number).append({"user": {"login": self.bot}, "body": text})
        return True

    def tracking_issue(self, mission_id: str) -> Optional[dict]:
        """The issue ``context`` resolved for this mission this sweep (None: none, or not read yet)."""
        return self._tracking.get(mission_id)

    def issue_comments(self, number: int) -> list:
        return self._pr_comments(number)

    def _start_agent(self, state: MissionState, manifest: Optional[Manifest]) -> None:
        """Ask the Mission Agent workflow to start the role the mission now waits on.

        A nudge only: the workflow re-derives everything itself and also runs on a
        schedule, so a failed request just means the agent starts a few minutes later.
        """
        role = _target(state)
        if role is None or manifest is None or not manifest.roles[role].runtime:
            return
        try:
            self._write(f"start {AGENT_WORKFLOW} for {state.mission_id} {role}",
                        lambda: self.gh.dispatch_workflow(AGENT_WORKFLOW, self.main), "router.dispatch",
                        mission=state.mission_id, round_n=state.round)
        except GitHubError as exc:
            self.log(f"{state.mission_id}: could not start {AGENT_WORKFLOW}; its schedule will pick it up: {exc}")

    def _add_labels(self, number: int, labels: List[str]) -> None:
        self._write(f"label #{number} {labels}", lambda: self.gh.request("POST", f"/issues/{number}/labels", {"labels": labels}),
                    "router.label", pr=number)

    def _record(self, action: str, reason: str, *, actor: Optional[str] = None, account: Optional[int] = None,
                authority: Tuple[str, str] = ("spec_rule", "MISSION-ROUTER-001"), result: str = "done",
                mission: Optional[str] = None, round_n: Optional[int] = None, pr: Optional[int] = None,
                commit: Optional[str] = None, inputs: Optional[dict] = None, outputs: Optional[dict] = None) -> None:
        """One record in this sweep's chain (MISSION-DISPATCH-001 §3m item 1). The router's own records name the bot
        with its configured account ID; a HITL command's names the commenter with the ID GitHub gave."""
        if self.dry_run or not self.evidence.enabled:
            return
        name = actor or self.bot
        self.evidence.record(actor=name, account_id=account if actor else self._accounts.get(self.bot.casefold()),
                             action=action, result=result, reason=reason, authority_kind=authority[0],
                             authority_ref=authority[1], mission=mission, round_n=round_n, pr=pr,
                             commit=commit if commit and len(commit) == 40 else None,
                             inputs=inputs or {}, outputs=outputs or {})

    def _write(self, what: str, fn, action: str = "router.issue", **subject):
        """Make one write to GitHub, recorded first (Amendment 018). A write GitHub refuses is recorded again as
        failed."""
        if self.dry_run:
            self.log(f"    [dry-run] would {what}")
            return None
        self.log(f"    {what}")
        self._record(action, what, **subject)
        try:
            return fn()
        except GitHubError as exc:
            self._record(action, f"{what}: GitHub refused it ({exc.status})", result="failed", **subject)
            raise

    def _record_decision(self, number: int, head_sha: str, base: str, decision, mission: Optional[str] = None,
                         round_n: Optional[int] = None) -> None:
        """The decision that allows a merge, recorded before the approval and the merge (Amendment 018), with the
        HITL approvals of this exact commit it acted on."""
        for comment in self._pr_comments(number):
            user = comment.get("user") or {}
            body = comment.get("body") or ""
            login = str(user.get("login", ""))
            if user.get("type") == "User" and login.casefold() in self.hitl and head_sha in _APPROVE_RE.findall(body):
                self._record("router.hitl_command", f"HITL command: /mission approve {head_sha}", actor=login,
                             account=user.get("id") if isinstance(user.get("id"), int) else None,
                             authority=("hitl_command", f"comment {comment.get('id')} on #{number}"),
                             mission=mission, round_n=round_n, pr=number, commit=head_sha,
                             outputs={"comment": evidence_producer.text_digest(body)})
        self._record("router.decision", f"merge: {decision.summary}", mission=mission, round_n=round_n, pr=number,
                     commit=head_sha, inputs={"head": evidence_producer.text_digest(head_sha),
                                              "base": evidence_producer.text_digest(base)},
                     outputs={"reasons": evidence_producer.text_digest("\n".join(decision.reasons))})

    def _record_commands(self, number: int, mission: str, stage: str) -> Tuple[bool, ...]:
        """The HITL commands on a tracking issue the router acts on as it posts a stage change: each recorded with
        the commenter's account ID. Returns (retry seen, halt seen)."""
        seen = {"retry": False, "halt": False, "resume": False, "cancel": False}
        for comment in self._pr_comments(number):
            user = comment.get("user") or {}
            login = str(user.get("login", ""))
            body = comment.get("body") or ""
            if user.get("type") != "User" or login.casefold() not in self.hitl:
                continue
            for word, pattern in (("retry", _RETRY_RE), ("halt", _HALT_RE), ("resume", _RESUME_RE),
                                  ("cancel", _CANCEL_RE)):
                if pattern.search(body):
                    seen[word] = True
                    self._record("router.hitl_command", f"HITL command: /mission {word}", actor=login,
                                 account=user.get("id") if isinstance(user.get("id"), int) else None,
                                 authority=("hitl_command", f"comment {comment.get('id')} on #{number}"),
                                 mission=mission, outputs={"comment": evidence_producer.text_digest(body)})
        return seen["retry"], seen["halt"]

    # ------------------------------------------------------- stacks: landing
    def _sweep_stacks(self) -> None:
        self._stacks.clear()
        try:
            statuses = self.stacks()
        except GitHubError as exc:
            self.log(f"stacks: GitHub error, will retry next sweep: {exc}")
            return
        for sid, status in statuses.items():
            try:
                self.log(f"stack {sid}: {status.status} {status.reason}".rstrip())
                for raw in sorted(self._landing_prs.get(sid, []), key=lambda r: r["number"]):
                    if self._handle_landing(raw, status):
                        self._stacks.clear()
                        status = self.stack_status(sid)
                self._sync_stack_issue(status)
                if status.resolved:
                    for mid in status.members:
                        ctx = self.context(mid)
                        if ctx.state.stage != AWAIT_A1:
                            self._sync_tracking_issue(ctx.state, ctx.manifest)
                        elif status.status == STACK_BLOCKED:
                            plan = self._plan_of(mid)
                            if plan:
                                self._comment_once(plan[0], f"stack-blocked:{sid}",
                                                   f"Stack `{sid}` is blocked ({status.reason}), so this plan will not start. "
                                                   f"The review matrix is on the stack's tracking issue.")
            except GitHubError as exc:
                self.log(f"stack {sid}: GitHub error, will retry next sweep: {exc}")

    def _handle_landing(self, raw: dict, status: StackStatus) -> bool:
        """Route one landing PR (stack branch -> default branch). True when it merged."""
        number, head_sha, sid = raw["number"], raw["head"]["sha"], status.stack_id
        pushers, head_pushed = self._push_evidence(stack_branch(sid), head_sha)
        landers = set()
        for mid in status.members:
            manifest = self.context(mid).manifest
            login = self.identities().get(manifest.roles["A3"].agent) if manifest else None
            if login:
                landers.add(login)
        promotion, complete, _ = self._changes(status.target, head_sha)
        user = raw.get("user") or {}
        pr = LandingPR(number, sid, head_sha, raw["base"]["ref"], str(user.get("login", "")), str(user.get("type", "")),
                       (raw["head"].get("repo") or {}).get("full_name") == self.gh.repo, bool(raw.get("draft")),
                       pushers, head_pushed)
        decision = evaluate_landing(pr, status.status, status.reason, status.head, landers, self.hitl | {self.bot.casefold()},
                                    self.classify, self._approvals(number), promotion, complete,
                                    {manifest_path(m) for m in status.members}, status.target)
        self.log(f"  landing PR #{number} for stack {sid}: {decision.action} {decision.summary}".rstrip())
        outcome = {MERGE: "success", REJECT: "failure"}.get(decision.action, "pending")
        title = {MERGE: f"Stack {sid}: every mission passed A3",
                 REJECT: f"Stack {sid}: rejected by the router"}.get(decision.action, f"Stack {sid}: held")
        self._publish_check(head_sha, outcome, title, check_summary(decision.reasons, title))
        digest = hashlib.sha256(decision.summary.encode()).hexdigest()[:12]
        if decision.action == WAIT:
            self._comment_once(number, f"wait:{head_sha[:12]}:{digest}", "The mission router is holding this landing PR:\n\n"
                               + "\n".join(f"- {quarantined(r)}" for r in decision.reasons) + "\n\nIt will continue on its own once this changes.")
            return False
        if decision.action == REJECT:
            self._comment_once(number, f"reject:{head_sha[:12]}:{digest}", "The mission router did not merge this landing PR:\n\n"
                               + "\n".join(f"- {quarantined(r)}" for r in decision.reasons))
            self._add_labels(number, ["agent:blocked"])
            return False
        if decision.action == WAIT_APPROVAL:
            self._comment_once(number, f"approval:{head_sha[:12]}", f"Stack `{sid}` passed, but it needs HITL approval to land:\n\n"
                               + "\n".join(f"- {quarantined(r)}" for r in decision.reasons)
                               + f"\n\nTo approve this exact commit, a HITL login comments:\n\n```\n/mission approve {head_sha}\n```")
            self._add_labels(number, ["agent:needs-hitl"])
            return False
        self._record_decision(number, head_sha, raw["base"]["ref"], decision)
        try:
            self._approve_once(number, head_sha)
            result = self._write(f"merge landing PR #{number} at {head_sha}",
                                 lambda: self.gh.merge(number, head_sha, f"Stack {sid}: land {len(status.members)} missions"),
                                 "router.landing", pr=number, commit=head_sha)
        except GitHubError as exc:
            if exc.status in (405, 409, 422):
                self._comment_once(number, f"waiting:{head_sha[:12]}",
                                   f"The mission router approved this landing PR, but GitHub will not merge it yet: {exc.message}. "
                                   "The router retries every sweep.")
                return False
            raise
        return bool(result)

    # ------------------------------------------------------- L1 capture route
    def _capture_holder(self) -> Optional[str]:
        """An unfinished mission whose files are taken and whose build_scope may include the capture queue."""
        for mid in sorted(self._known):
            if self._finished(mid):
                continue
            ctx = self.context(mid)
            if ctx.manifest is not None and self._holds_scope(mid, ctx) \
                    and scopes_overlap(ctx.manifest.build_scope, (self.capture_path,)):
                return mid
        return None

    def _handle_capture(self, raw: dict) -> bool:
        """Route one capture PR (Amendment 005). True when it merged."""
        number, head_sha, branch = raw["number"], raw["head"]["sha"], raw["head"]["ref"]
        pushers, head_pushed = self._push_evidence(branch, head_sha)
        files, complete, _ = self._changes(self.main, head_sha)
        user = raw.get("user") or {}
        pr = CapturePR(number, head_sha, raw["base"]["ref"], str(user.get("login", "")), str(user.get("type", "")),
                       (raw["head"].get("repo") or {}).get("full_name") == self.gh.repo, bool(raw.get("draft")),
                       files, complete, pushers, head_pushed)
        decision = evaluate_capture(pr, self.capture_path, self.hitl, self.gh.file_at(self.capture_path, self.main),
                                    self.gh.file_at(self.capture_path, head_sha), self._capture_holder(), self.main)
        self.log(f"  capture PR #{number}: {decision.action} {decision.summary}".rstrip())
        outcome = {MERGE: "success", REJECT: "failure"}.get(decision.action, "pending")
        title = {MERGE: "L1 capture: appends DRAFT entries to the capture queue",
                 REJECT: "L1 capture: rejected by the router"}.get(decision.action, "L1 capture: held")
        self._publish_check(head_sha, outcome, title, check_summary(decision.reasons, title))
        digest = hashlib.sha256(decision.summary.encode()).hexdigest()[:12]
        if decision.action == WAIT:
            if not raw.get("draft"):
                self._comment_once(number, f"wait:{head_sha[:12]}:{digest}", "The mission router is holding this capture:\n\n"
                                   + "\n".join(f"- {quarantined(r)}" for r in decision.reasons) + "\n\nIt will continue on its own once this changes.")
            return False
        if decision.action == REJECT:
            self._comment_once(number, f"reject:{head_sha[:12]}:{digest}", "The mission router did not merge this capture:\n\n"
                               + "\n".join(f"- {quarantined(r)}" for r in decision.reasons)
                               + f"\n\nThe L1 capture route only appends DRAFT entries to `{self.capture_path}`, opened and "
                               "pushed by HITL. Push a fix to this branch; anything else goes through a mission.")
            self._add_labels(number, ["agent:blocked"])
            return False
        self._record_decision(number, head_sha, self.main, decision)
        try:
            self._approve_once(number, head_sha)
            result = self._write(f"merge capture PR #{number} at {head_sha}",
                                 lambda: self.gh.merge(number, head_sha, f"L1 capture: merge PR #{number}"),
                                 "router.merge", pr=number, commit=head_sha)
        except GitHubError as exc:
            if exc.status in (405, 409, 422):
                self._comment_once(number, f"waiting:{head_sha[:12]}",
                                   f"The mission router approved this capture, but GitHub will not merge it yet: {exc.message}. "
                                   "The router retries every sweep.")
                return False
            raise
        return bool(result)

    def _resolve_stack_issue(self, sid: str, members: Tuple[str, ...]) -> Optional[dict]:
        """The stack's tracking issue, by the number marked on its plan PRs, else the listing (then marked)."""
        plans = [self._plan_of(m) for m in members]
        numbers = sorted({int(n) for plan in plans if plan for c in self._pr_comments(plan[0])
                          if (c.get("user") or {}).get("login") == self.bot for n in _STACK_ISSUE_RE.findall(c.get("body") or "")})
        number, source = (numbers[0], "marker") if numbers else (None, "")
        if number is None and sid in self._stack_issues:
            number, source = int(self._stack_issues[sid]["number"]), "listing"
        if number is None:
            return None
        issue = self.gh.get(f"/issues/{number}")
        if ("pull_request" in issue or (issue.get("user") or {}).get("login") != self.bot
                or issue.get("title") != f"[stack] {sid}"):
            raise GitHubError(0, f"#{number} (from the {source}) is not the router's tracking issue for stack {sid}",
                              f"/issues/{number}")
        self._mark_stack_issue(sid, members, number)
        return issue

    def _mark_stack_issue(self, sid: str, members: Tuple[str, ...], number: int) -> None:
        for mid in members:
            plan = self._plan_of(mid)
            if plan:
                self._comment_once(plan[0], f"stack-issue:{number}", f"Tracking issue for stack `{sid}`: #{number}")

    def _sync_stack_issue(self, status: StackStatus) -> None:
        ctxs = {m: self.context(m) for m in status.members}
        if not any(c.state.stage != AWAIT_A1 for c in ctxs.values()) and status.status != STACK_LANDED:
            return  # nothing has started; the approval request is on the plan PRs
        if status.dismissed:
            return  # HITL closed the review; the router leaves the issue as it is
        issue = status.issue
        declared = {m: ctxs[m].manifest or self._declared_manifest(m) for m in status.members}
        body = render_stack_body(status, ctxs, declared, self.gh.repo, status.target)
        labels = STACK_LABELS[status.status]
        if issue is None:
            created = self._write(f"open stack issue for {status.stack_id}",
                                  lambda: self.gh.request("POST", "/issues", {"title": f"[stack] {status.stack_id}",
                                                                              "body": body, "labels": labels}))
            if not created:
                return
            issue = created
            self._mark_stack_issue(status.stack_id, status.members, int(created["number"]))
        else:
            number = issue["number"]
            if issue.get("body") != body:
                self._write(f"update stack issue #{number}", lambda: self.gh.request("PATCH", f"/issues/{number}", {"body": body}))
            if sorted(l["name"] for l in issue.get("labels") or []) != sorted(labels):
                self._write(f"set labels on #{number} to {labels}",
                            lambda: self.gh.request("PUT", f"/issues/{number}/labels", {"labels": labels}),
                            "router.label")
            want = "closed" if status.status == STACK_LANDED else "open"
            if issue.get("state") != want:
                self._write(f"{want} stack issue #{number}", lambda: self.gh.request("PATCH", f"/issues/{number}", {"state": want}))
        number = int(issue["number"])
        rounds = hashlib.sha256(" ".join(f"{m}:{c.state.stage}:{c.state.round}" for m, c in sorted(ctxs.items()))
                                .encode()).hexdigest()[:12]
        was_blocked = "mission:blocked" in {l["name"] for l in issue.get("labels") or []}
        if was_blocked and status.status in (STACK_ACTIVE, STACK_READY):
            running = ", ".join(f"`{m}` (round {c.state.round})" for m, c in sorted(ctxs.items())
                                if c.state.stage in (AWAIT_A2, AWAIT_A3))
            self._comment_once(number, f"stack:reopened:{rounds}",
                               f"**Stack resumed.** HITL retried {running or 'a blocked mission'}. The missions that "
                               "passed stay passed; the stack lands only if every mission passes.")
        if status.resolved:
            # The first outcome keeps its original key; after a HITL retry, each new block is announced again.
            reopened = any(_REOPENED_MARK in (c.get("body") or "")
                           for c in self._pr_comments(number) if (c.get("user") or {}).get("login") == self.bot)
            key = f"stack:{status.status}" + (f":{rounds}" if reopened else "")
            self._comment_once(number, key, render_stack_outcome(status))
        elif status.status == STACK_READY and not status.landing_pr_open:
            if self._comment_once(int(issue["number"]), f"stack:READY:{(status.head or '')[:12]}",
                                  f"**Every mission passed.** The Mission Agent workflow opens the landing PR from "
                                  f"`{stack_branch(status.stack_id)}` as `{status.lander[1] if status.lander else 'an A3 agent'}`; "
                                  "the router then lands the whole stack."):
                try:
                    self._write(f"start {AGENT_WORKFLOW} to land stack {status.stack_id}",
                                lambda: self.gh.dispatch_workflow(AGENT_WORKFLOW, self.main), "router.dispatch")
                except GitHubError as exc:
                    self.log(f"stack {status.stack_id}: could not start {AGENT_WORKFLOW}; its schedule will pick it up: {exc}")

    # -------------------------------------------------------- tracking issue
    def _sync_tracking_issue(self, state: MissionState, manifest: Optional[Manifest]) -> None:
        landing, target = self.landing_branch(manifest), self.target_branch(manifest)
        body = render_issue_body(state, manifest, self.gh.repo, target, self.identities(), landing)
        labels = STAGE_LABELS[state.stage]
        if self._in_stack(manifest):
            # A stack's missions stay open until the stack is resolved: the router keeps reading them.
            closed = state.stage in (DONE, CANCELLED, BLOCKED) and self.stack_status(manifest.stack_id).closed
        else:
            closed = state.stage in CLOSED_STAGES
        issue = self._tracking.get(state.mission_id)
        if issue is None and state.stage in CLOSED_STAGES:
            self.log(f"{state.mission_id}: {state.stage} without a tracking issue; not opening one")
            return
        if issue is None:
            created = self._write(f"open tracking issue for {state.mission_id}",
                                  lambda: self.gh.request("POST", "/issues", {"title": f"[mission] {state.mission_id}", "body": body, "labels": labels}),
                                  mission=state.mission_id)
            number = created["number"] if created else None
            if created:
                self._tracking[state.mission_id] = created
                self._mark_tracking_issue(state.mission_id, int(number))
        else:
            number = issue["number"]
            if issue.get("body") != body:
                self._write(f"update issue #{number}", lambda: self.gh.request("PATCH", f"/issues/{number}", {"body": body}),
                            mission=state.mission_id, pr=number)
            current = sorted(l["name"] for l in issue.get("labels") or [])
            if current != sorted(labels):
                self._write(f"set labels on #{number} to {labels}", lambda: self.gh.request("PUT", f"/issues/{number}/labels", {"labels": labels}),
                            "router.label", mission=state.mission_id, pr=number)
            want_state = "closed" if closed else "open"
            if issue.get("state") != want_state:
                self._write(f"{want_state} issue #{number}", lambda: self.gh.request("PATCH", f"/issues/{number}", {"state": want_state}),
                            mission=state.mission_id, pr=number)
        if number is not None:
            def commands():
                retry, halt = self._record_commands(number, state.mission_id, state.stage)
                return "router.halt" if state.stage == PAUSED else ("router.retry" if retry and state.stage in
                                                                     (AWAIT_A2, AWAIT_A3) else None)
            if self._comment_once(number, f"stage:{state.stage}:{state.round}",
                                  render_stage_comment(state, manifest, self.identities(), landing,
                                                       target if target != self.main else ""),
                                  before=commands, mission=state.mission_id):
                self._start_agent(state, manifest)


def _target(state: MissionState) -> Optional[str]:
    return {AWAIT_A2: "A2", AWAIT_A3: "A3"}.get(state.stage)


def _who(manifest: Manifest, role: str, identities: Dict[str, str]) -> Tuple[str, str]:
    agent = manifest.roles[role].agent
    return agent, identities.get(agent, "(no ACTIVE identity)")


def _runtime_note(manifest: Manifest, role: str) -> str:
    runtime, model = manifest.roles[role].runtime, manifest.roles[role].model
    return (f" The Mission Agent workflow starts it as `{runtime}`" + (f" with model `{model}`." if model else ".") if runtime
            else " The plan names no runtime, so nothing starts it automatically.")


def render_issue_body(state: MissionState, manifest: Optional[Manifest], repo: str, main: str,
                      identities: Dict[str, str], landing: Optional[str] = None) -> str:
    landing = landing or main
    mid = state.mission_id
    lines = [f"Mission `{mid}`" + (f": {manifest.title}" if manifest else ""), ""]
    if manifest and manifest.stack_id:
        deps = f"; depends on {', '.join(manifest.depends_on)}" if manifest.depends_on else ""
        lines += [f"Stack `{manifest.stack_id}` ({manifest.stack_kind}){deps}.", ""]
    role = _target(state)
    if state.stage == HALTED:
        lines += [f"**Halted for HITL.** {state.reason}", ""]
    elif state.stage == PAUSED:
        lines += [f"**Halted by HITL.** {state.reason}. Nothing of it merges and no agent starts for it. "
                  "Comment `/mission resume` here to continue from where it stopped.", ""]
    elif state.stage == DONE and landing != main:
        lines += [f"**Passed.** A3 passed round {state.round}; the mission is on `{landing}` and lands on `{main}` "
                  "with the rest of its stack.", ""]
    elif state.stage == DONE:
        lines += [f"**Done.** A3 passed round {state.round} and the mission is merged into `{main}`.", ""]
    elif state.stage == BLOCKED:
        lines += [f"**Blocked.** {state.reason}" + (f" ({state.when})" if state.when else "") + ". Recorded for HITL review; "
                  f"nothing from this mission reached `{main}`.", ""]
        lines += [f"- {quarantined(d)}" for d in state.details] + ([""] if state.details else [])
    elif state.stage == CANCELLED:
        lines += [f"**Cancelled.** {state.reason}. Nothing from this mission reached `{main}`, and its id cannot be reused.", ""]
    elif role and manifest:
        agent, login = _who(manifest, role, identities)
        lines += [f"**Waiting for {role}** (agent `{agent}`, `{login}`), round {state.round}.", ""]
    block = {
        "handoff_block_id": "MISSION_ROUTER_HANDOFF",
        "mission_id": mid,
        "stage": state.stage,
        "target_actor": role or ("HITL" if state.stage in (HALTED, BLOCKED, PAUSED) else "NONE"),
        "round": state.round,
        "stack_id": manifest.stack_id if manifest else None,
        "stack_kind": manifest.stack_kind if manifest else None,
        "depends_on": list(manifest.depends_on) if manifest else [],
        "plan": f"https://github.com/{repo}/tree/{integration_branch(mid)}/missions/{mid}",
    }
    if role and manifest:
        block.update({
            "assigned_agent": _who(manifest, role, identities)[0],
            "assigned_github_login": _who(manifest, role, identities)[1],
            "assigned_runtime": manifest.roles[role].runtime,
            "branch_to_push": stage_branch(mid, role, state.round),
            "integration_branch": integration_branch(mid),
        })
    if state.stage == AWAIT_A2 and manifest:
        block["pr_base"] = integration_branch(mid)
        block["build_scope"] = list(manifest.build_scope)
    if state.stage == AWAIT_A3:
        block["review_sha"] = state.review_sha
        block["verdict_file"] = verdict_path(mid, state.round)
        block["pr_base_if_pass"] = landing
        block["pr_base_if_fail"] = integration_branch(mid)
    if state.stage == HALTED:
        block["halt_reason"] = state.reason
    if state.stage == PAUSED:
        block["paused_reason"] = state.reason
        block["paused_from"] = state.paused_from
    if state.stage == CANCELLED:
        block["cancel_reason"] = state.reason
    if state.stage == BLOCKED:
        block["blocked_reason"] = state.reason
    yaml = "\n".join(f"{k}: {json.dumps(v)}" for k, v in block.items())
    lines += ["```yaml", yaml, "```", "", "This issue is maintained by the mission router. Edits to it are overwritten."]
    return "\n".join(lines)


def render_stage_comment(state: MissionState, manifest: Optional[Manifest], identities: Dict[str, str],
                         landing: str = "main", target: str = "") -> str:
    """``target`` names the mission's own branch (Amendment 008); empty for the default branch."""
    mid, r = state.mission_id, state.round
    in_stack = landing.startswith("stack/")
    final = f"`{target}`" if target else "the default branch"
    if state.stage == AWAIT_A2 and manifest:
        agent, login = _who(manifest, "A2", identities)
        intro = f"The plan is approved and merged into `{integration_branch(mid)}`." if r == 1 else f"A3 failed round {r - 1}. Its findings are merged at `{verdict_path(mid, r - 1)}`."
        return (f"**A2: agent `{agent}` (`{login}`), round {r}.** {intro}\n\n"
                f"Branch `{stage_branch(mid, 'A2', r)}` from `{integration_branch(mid)}`, build inside `build_scope`, "
                f"and open a PR into `{integration_branch(mid)}` as `{login}`. A push to that branch by any other identity is rejected."
                + _runtime_note(manifest, "A2"))
    if state.stage == AWAIT_A3 and manifest:
        agent, login = _who(manifest, "A3", identities)
        if state.build_sha and state.build_sha != state.review_sha:
            intro = (f"HITL retried the block of round {r - 1}: A3 reviews the same build again at `{state.review_sha}` "
                     f"(A2's build, merged at `{state.build_sha}`, plus the round {r - 1} verdict). The plan's checks run again.")
        else:
            intro = f"A2's build is merged at `{state.review_sha}`."
        return (f"**A3: agent `{agent}` (`{login}`), round {r}.** {intro}\n\n"
                f"Compare it with the plan in `missions/{mid}/` on `{integration_branch(mid)}`. Branch `{stage_branch(mid, 'A3', r)}` from that exact commit, "
                f"add only `{verdict_path(mid, r)}` with your verdict, and open the PR into "
                + (f"`{landing}`" if in_stack else final) + " for PASS "
                f"or into `{integration_branch(mid)}` for FAIL or BLOCKED, as `{login}`. A push to that branch by any other identity is rejected."
                + _runtime_note(manifest, "A3"))
    if state.stage == DONE and in_stack:
        return (f"**Mission passed.** A3 passed round {r}; the router merged the mission into `{landing}` at "
                f"`{state.landed_sha}`. It lands on {final} together with the rest of its stack.")
    if state.stage == DONE:
        return f"**Mission complete.** A3 passed round {r}; the router merged the mission into {final} at `{state.landed_sha}`."
    if state.stage == BLOCKED:
        return (f"**Mission blocked.** {state.reason}" + (f" ({state.when})" if state.when else "") + ".\n\n"
                + "".join(f"- {quarantined(d)}\n" for d in state.details)
                + f"\nRecorded for HITL review. Nothing from this mission reaches {final}."
                + _retry_hint(state))
    if state.stage == CANCELLED:
        return (f"**Mission cancelled.** {state.reason}. The router will merge nothing more for it and rejects any "
                "open stage PR. Its build_scope no longer blocks other missions.")
    if state.stage == PAUSED:
        return (f"**Mission halted by HITL.** {state.reason}. The router merges none of its PRs and leaves them "
                "open; no agent starts for it, and a run already going publishes nothing. Comment `/mission resume` "
                "here to continue from where it stopped.")
    return f"**Halted for HITL.** {state.reason}"


def _retry_hint(state: MissionState) -> str:
    if state.resume == "A3" and state.round < MAX_ROUNDS_CEILING:
        return ("\n\nOnce the cause is dealt with, HITL can comment `/mission retry` here: A3 then reviews the same build "
                "again, with the plan's checks run again. Nothing else in the stack reruns.")
    if state.resume == "A2" and state.round < MAX_ROUNDS_CEILING:
        return "\n\nHITL can comment `/mission retry` here to give A2 one more round. Nothing else in the stack reruns."
    return ""


_STACK_SUMMARY = {
    STACK_ACTIVE: "**Running.** Nothing from this stack is on `{main}` yet; passed missions wait on `{branch}`.",
    STACK_READY: "**Every mission passed.** The whole stack lands on `{main}` in one merge.",
    STACK_LANDED: "**Landed.** The whole stack is merged into `{main}`.",
    STACK_BLOCKED: "**Blocked.** Nothing from this stack reached `{main}`. The matrix and blockers below are for HITL review.",
    STACK_HALTED: "**Halted for HITL.** {reason}",
    STACK_PAUSED: "**Halted by HITL.** {reason}. Nothing from this stack lands until `/mission resume`.",
}


def _order(status: StackStatus, manifests: Dict[str, Optional[Manifest]]) -> List[str]:
    """The stack's missions in loop order: each after the missions it depends on."""
    done, out = set(), []
    pending = list(status.members)
    while pending:
        ready = [m for m in pending if all(d in done or d not in pending for d in
                                           (manifests[m].depends_on if manifests.get(m) else ()))] or pending[:1]
        for m in sorted(ready):
            out.append(m)
            done.add(m)
            pending.remove(m)
    return out


def _result(ctx: _Context) -> str:
    st = ctx.state
    if ctx.held_by:
        return f"held: blocked by {ctx.held_by}"
    return {AWAIT_A1: "not started", AWAIT_A2: f"A2 building (round {st.round})", AWAIT_A3: f"A3 reviewing (round {st.round})",
            DONE: "PASS", BLOCKED: f"BLOCKED: {st.reason}", CANCELLED: f"cancelled: {st.reason}",
            HALTED: f"halted: {st.reason}", PAUSED: "halted by HITL"}.get(st.stage, st.stage)


def render_stack_body(status: StackStatus, ctxs: Dict[str, _Context], manifests: Dict[str, Optional[Manifest]],
                      repo: str, main: str) -> str:
    sid, branch = status.stack_id, stack_branch(status.stack_id)
    lines = [f"Stack `{sid}` ({status.kind}), {len(status.members)} missions. Passed missions collect on `{branch}`; "
             f"the stack lands on `{main}` only when every mission has passed.", "",
             _STACK_SUMMARY[status.status].format(main=main, branch=branch, reason=status.reason), "",
             "| Loop | Mission | Depends on | Result | Where | When |", "|---|---|---|---|---|---|"]
    order = _order(status, manifests)
    for n, mid in enumerate(order, 1):
        ctx, manifest = ctxs[mid], manifests.get(mid)
        deps = ", ".join(manifest.depends_on) if manifest and manifest.depends_on else "-"
        where = f"#{ctx.state.last_pr}" if ctx.state.last_pr else "-"
        lines.append(f"| {n} | `{mid}` | {deps} | {_result(ctx)} | {where} | {ctx.state.when or '-'} |")
    blocked = [m for m in order if ctxs[m].state.stage in (BLOCKED, CANCELLED) and not ctxs[m].held_by]
    if blocked:
        lines += ["", "## Blockers", ""]
        for mid in blocked:
            st = ctxs[mid].state
            lines.append(f"- **`{mid}`**, round {st.round}" + (f", {st.when}" if st.when else "")
                         + (f", #{st.last_pr}" if st.last_pr else "") + f": {st.reason}")
            lines += [f"  - {quarantined(d)}" for d in st.details]
    lines += ["", f"Stack branch: https://github.com/{repo}/tree/{branch}", "",
              "This issue is maintained by the mission router. Edits to it are overwritten."]
    return "\n".join(lines)


def render_stack_outcome(status: StackStatus) -> str:
    if status.status == STACK_LANDED:
        return f"**Stack landed.** All {len(status.members)} missions of `{status.stack_id}` are merged into `{status.target}`."
    return (f"**Stack blocked.** {status.reason}. Nothing from `{status.stack_id}` reached `{status.target}`. "
            "Review the matrix above. To have one blocked mission tried again, comment `/mission retry` on its tracking "
            "issue; the missions that passed stay passed. To end the review, close this issue; the plans then restart "
            "as a new stack.")
