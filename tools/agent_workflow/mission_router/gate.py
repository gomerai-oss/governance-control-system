"""Decide what to do with one open stage PR. Pure: no GitHub calls.

The router is a handler and merger, not a judge of the work. These checks only
answer "is this the PR the approved plan said would come next, from the role it
assigned, touching only what it allowed?" They never look at whether the work
is good; that is A3's job.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Mapping, Optional, Sequence, Set, Tuple

from .model import (Manifest, MissionInputError, StageRef, Verdict, integration_branch, is_literal_glob, manifest_path,
                    mission_dir, verdict_path, in_scope)
from .state import AWAIT_A1, CANCELLED, HALTED, MissionState

MERGE = "MERGE"
WAIT_APPROVAL = "WAIT_APPROVAL"
WAIT = "WAIT"
REJECT = "REJECT"


@dataclass(frozen=True)
class FileChange:
    path: str
    status: str
    previous_path: Optional[str] = None


@dataclass(frozen=True)
class OpenStagePR:
    number: int
    ref: StageRef
    head_sha: str
    base_ref: str
    author: str
    same_repo: bool
    draft: bool
    files: Tuple[FileChange, ...]  # vs. the merge base with base_ref
    files_complete: bool
    behind_by: int  # commits on the stage base the PR head does not contain
    # Identity evidence. The defaults fail closed: an unknown author type or push
    # history never passes.
    author_type: str = ""
    pushers: Tuple[str, ...] = ()  # every actor GitHub recorded updating the head branch
    head_pushed: bool = False  # GitHub recorded a push that produced head_sha


@dataclass(frozen=True)
class Decision:
    action: str
    reasons: Tuple[str, ...] = ()
    approval_required: bool = False
    verdict: Optional[str] = None

    @property
    def summary(self) -> str:
        return "; ".join(self.reasons)


@dataclass
class _Checks:
    reasons: list = field(default_factory=list)

    def require(self, condition: bool, reason: str) -> None:
        if not condition:
            self.reasons.append(reason)


_ALLOWED_STATUSES = {"added", "modified", "removed", "renamed", "changed"}


def evaluate(
    pr: OpenStagePR,
    state: MissionState,
    manifest: Optional[Manifest],
    classify,  # path -> SPEC-002 family name, raises ValueError for unsafe paths
    approved_shas: Set[str],
    integration_actual: Optional[str] = None,
    verdict: Optional[Verdict] = None,
    verdict_error: Optional[str] = None,
    promotion_files: Sequence[FileChange] = (),
    promotion_complete: bool = True,
    default_branch: str = "main",
    start_rejects: Sequence[str] = (),
    start_waits: Sequence[str] = (),
    integration_clean: bool = True,
    identities: Mapping[str, str] = {},
    hitl_logins: Set[str] = frozenset(),
) -> Decision:
    """``start_rejects`` / ``start_waits`` are the router's stack checks for an A1 PR
    (scope overlap with active missions, unmet ISAL dependencies); ``integration_clean``
    says the integration branch holds nothing beyond the default branch before A1 merges.
    ``identities`` maps each ACTIVE agent to its GitHub App bot login; an agent missing
    from it cannot act in any role. ``hitl_logins`` names the human seats: A1 is held
    by HITL, so for the plan stage a HITL login is the assigned actor (spec section 5a)."""
    ref = pr.ref
    if pr.draft:
        return Decision(WAIT, ("the PR is a draft",))
    if manifest is None:
        return Decision(REJECT, (f"{manifest_path(ref.mission_id)} could not be read or is invalid",))
    if state.stage == HALTED:
        return Decision(REJECT, (f"the mission is halted for HITL: {state.reason}",))
    if state.stage == CANCELLED:
        return Decision(REJECT, (f"the mission was cancelled: {state.reason}",))

    c = _Checks()
    c.require(pr.same_repo, "the PR must come from a branch in this repository, not a fork")
    agent = manifest.roles[ref.role].agent
    login = identities.get(agent)
    # A1 is a human seat (spec section 5a): for the plan stage only, a HITL login
    # is an assigned actor — it may open the PR and push its branch, and it needs
    # no ACTIVE App identity to do so. Every other role is its App bot alone.
    hitl = {h.casefold() for h in hitl_logins}
    hitl_actor = ref.role == "A1" and pr.author_type == "User" and pr.author.casefold() in hitl
    if login is None and not hitl_actor:
        c.reasons.append(f"{ref.role} is assigned to agent {agent}, which has no ACTIVE GitHub App identity")
    else:
        bot_actor = login is not None and pr.author_type == "Bot" and pr.author == login
        if not (bot_actor or hitl_actor):
            if ref.role == "A1":
                c.reasons.append(f"A1 is held by HITL or assigned to agent {agent} ({login or 'no ACTIVE identity'}), "
                                 f"but this PR was opened by {pr.author}")
            else:
                c.reasons.append(f"{ref.role} is assigned to agent {agent} ({login}), but this PR was opened by {pr.author}")
        allowed = {login.casefold()} if login is not None else set()
        if ref.role == "A1":
            allowed |= hitl
        foreign = sorted({p for p in pr.pushers if p.casefold() not in allowed})
        if foreign:
            if ref.role == "A1":
                who = f"{login} or a HITL login" if login is not None else "a HITL login"
                c.reasons.append(f"the branch was pushed to by {', '.join(foreign)}; only {who} may push an A1 branch")
            else:
                c.reasons.append(f"the branch was pushed to by {', '.join(foreign)}; only {login} may push a {ref.role} branch")
    c.require(state.expects(ref), f"the mission is waiting for {_expected(state)}, not {ref.role} round {ref.round}")
    c.require(pr.files_complete, "the PR's file list could not be read completely (GitHub lists at most 300 files per comparison)")
    # An A2 build may be empty: A2 records blockers instead of building, and A3 confirms them (Amendment 003).
    c.require(len(pr.files) > 0 or ref.role == "A2", "the PR changes no files")
    if c.reasons:
        return Decision(REJECT, tuple(c.reasons))
    if not pr.head_pushed:
        return Decision(WAIT, (f"GitHub has not yet recorded the push of {pr.head_sha} by {login or pr.author}",))

    integration = integration_branch(ref.mission_id)
    if ref.role != "A1":
        c.require(integration_actual == state.integration_head,
                  f"{integration} is at {integration_actual}, not {state.integration_head}: it changed outside the router")

    if ref.role == "A1":
        c.require(state.stage == AWAIT_A1, "the mission has already started")
        c.require(pr.base_ref == integration, f"A1 PRs must target {integration}; nothing reaches {default_branch} before A3 passes")
        c.require(integration_actual is not None and integration_clean,
                  f"{integration} must exist and hold nothing that is not already on {default_branch}")
        # The plan branch may be behind: the integration branch then only holds what is already on
        # the landing branch (checked above), and the plan adds files under its own mission directory
        # only (checked below). This is what lets one approval carry an ISAL stack to its later missions.
        _check_a1_files(pr, c)
        c.reasons.extend(plan_findings(manifest, classify))
        c.reasons.extend(start_rejects)
        if c.reasons:
            return Decision(REJECT, tuple(c.reasons))
        if start_waits:
            return Decision(WAIT, tuple(start_waits))
        if pr.head_sha not in approved_shas:
            return Decision(WAIT_APPROVAL, ("HITL approval of this exact commit is required to start the mission",), approval_required=True)
        return Decision(MERGE)

    if ref.role == "A2":
        c.require(pr.base_ref == integration, f"A2 PRs must target {integration}")
        c.require(pr.behind_by == 0, f"the branch is behind {integration}; rebase or merge it first")
        _check_build_files(pr.files, manifest, classify, c)
        return Decision(REJECT, tuple(c.reasons)) if c.reasons else Decision(MERGE)

    # A3
    if verdict is None:
        return Decision(REJECT, (verdict_error or "the verdict file is missing",))
    c.require(pr.base_ref == (default_branch if verdict.verdict == "PASS" else integration),
              f"a {verdict.verdict} verdict PR must target {default_branch if verdict.verdict == 'PASS' else integration}")
    if verdict.verdict == "BLOCKED":
        c.require(bool(verdict.findings), "a BLOCKED verdict must list its blockers")
    c.require(verdict.reviewed_sha == state.review_sha,
              f"the verdict reviews {verdict.reviewed_sha}, but A3 was handed {state.review_sha}")
    c.require(pr.behind_by == 0, f"the branch does not contain the reviewed head of {integration}")
    expected_file = verdict_path(ref.mission_id, ref.round)
    c.require([(f.path, f.status) for f in pr.files] == [(expected_file, "added")],
              f"an A3 PR must add exactly one file, {expected_file}, on top of the reviewed head")
    if c.reasons:
        return Decision(REJECT, tuple(c.reasons), verdict=verdict.verdict)
    if verdict.verdict in ("FAIL", "BLOCKED"):
        return Decision(MERGE, verdict=verdict.verdict)  # recorded on the integration branch; never reaches the landing branch

    # PASS promotes the whole mission to the default branch.
    hitl_reasons = []
    if not promotion_complete:
        hitl_reasons.append(f"the promotion diff against {default_branch} is too large to list completely")
    own_manifest = manifest_path(ref.mission_id)  # approved by HITL at A1; A2/A3 cannot change it
    for change in promotion_files:
        for path in filter(None, (change.path, change.previous_path)):
            if path == own_manifest and change.status == "added":
                continue
            try:
                family = classify(path)
            except ValueError:
                return Decision(REJECT, (f"unsafe path in promotion diff: {path!r}",), verdict="PASS")
            if family in ("AUTHORITY", "AGENT_POLICY"):
                hitl_reasons.append(f"{path} is {family} and is never merged without HITL")
    if hitl_reasons and pr.head_sha not in approved_shas:
        return Decision(WAIT_APPROVAL, tuple(hitl_reasons), approval_required=True, verdict="PASS")
    return Decision(MERGE, verdict="PASS")


@dataclass(frozen=True)
class LandingPR:
    """An open PR from a stack branch into the default branch."""

    number: int
    stack_id: str
    head_sha: str
    base_ref: str
    author: str
    author_type: str
    same_repo: bool
    draft: bool
    pushers: Tuple[str, ...] = ()  # every actor GitHub recorded updating the stack branch
    head_pushed: bool = False


def evaluate_landing(
    pr: LandingPR,
    stack_status: str,
    stack_reason: str,
    stack_head: Optional[str],
    landers: Set[str],  # bot logins allowed to open the landing PR: A3 agents of the stack's missions
    trusted_pushers: Set[str],  # the router's bot and HITL logins
    classify,
    approved_shas: Set[str],
    promotion_files: Sequence[FileChange],
    promotion_complete: bool,
    own_manifests: Set[str],
    default_branch: str = "main",
) -> Decision:
    """Whether the whole stack may land on the default branch now. Pure, like ``evaluate``."""
    if pr.draft:
        return Decision(WAIT, ("the PR is a draft",))
    c = _Checks()
    c.require(pr.same_repo, "the PR must come from a branch in this repository, not a fork")
    c.require(pr.base_ref == default_branch, f"a landing PR must target {default_branch}")
    c.require(pr.author_type == "Bot" and pr.author in landers,
              f"a landing PR is opened by an A3 agent of the stack ({', '.join(sorted(landers)) or 'none ACTIVE'}), not {pr.author}")
    c.require(stack_head is not None and pr.head_sha == stack_head, "the PR head is not the stack branch's head")
    foreign = sorted(p for p in pr.pushers if p.casefold() not in trusted_pushers)
    c.require(not foreign, f"the stack branch was updated by {', '.join(foreign)}; only the router (or HITL) may update it")
    if stack_status in ("BLOCKED", "HALTED", "LANDED"):
        c.reasons.append(f"the stack is {stack_status.lower()}" + (f": {stack_reason}" if stack_reason else ""))
    if c.reasons:
        return Decision(REJECT, tuple(c.reasons))
    if stack_status != "READY":
        return Decision(WAIT, ("not every mission in the stack has passed A3 yet",))
    if not pr.head_pushed:
        return Decision(WAIT, (f"GitHub has not yet recorded the push of {pr.head_sha}",))
    hitl_reasons = []
    if not promotion_complete:
        hitl_reasons.append(f"the stack's diff against {default_branch} is too large to list completely")
    for change in promotion_files:
        for path in filter(None, (change.path, change.previous_path)):
            if path in own_manifests and change.status == "added":
                continue  # each mission's own plan, approved by HITL when the stack started
            try:
                family = classify(path)
            except ValueError:
                return Decision(REJECT, (f"unsafe path in the stack's diff: {path!r}",))
            if family in ("AUTHORITY", "AGENT_POLICY"):
                hitl_reasons.append(f"{path} is {family} and is never merged without HITL")
    if hitl_reasons and pr.head_sha not in approved_shas:
        return Decision(WAIT_APPROVAL, tuple(hitl_reasons), approval_required=True)
    return Decision(MERGE)


@dataclass(frozen=True)
class CapturePR:
    """An open PR from a capture branch into the default branch: the L1 capture route (Amendment 005)."""

    number: int
    head_sha: str
    base_ref: str
    author: str
    author_type: str
    same_repo: bool
    draft: bool
    files: Tuple[FileChange, ...]  # vs. the merge base with the default branch
    files_complete: bool
    pushers: Tuple[str, ...] = ()  # every actor GitHub recorded updating the capture branch
    head_pushed: bool = False


CAPTURE_MAX_CHARS = 20000
_CAPTURE_HEADING_RE = re.compile(r"(?m)^### CAPTURE-[0-9]{4}-[0-9]{3}\b")
_STATUS_LINE_RE = re.compile(r"(?m)^\s*-\s*\*\*Status:\*\*(.*)$")


def evaluate_capture(
    pr: CapturePR,
    queue_path: str,
    hitl: Set[str],
    queue_on_main: Optional[str],
    queue_at_head: Optional[str],
    held_by: Optional[str] = None,  # an active mission whose build_scope may change the queue
    default_branch: str = "main",
) -> Decision:
    """Whether an L1 capture may merge into the default branch now. Pure, like ``evaluate``.

    A capture only appends DRAFT entries to the queue, and only HITL opens and pushes it, so
    it needs no plan, no A2 build and no A3 review. Anything else on a capture branch is refused.
    """
    if pr.draft:
        return Decision(WAIT, ("the PR is a draft",))
    c = _Checks()
    c.require(pr.same_repo, "the PR must come from a branch in this repository, not a fork")
    c.require(pr.base_ref == default_branch, f"a capture PR must target {default_branch}")
    c.require(pr.author_type == "User" and pr.author.casefold() in hitl,
              f"a capture PR is opened by a HITL login, not {pr.author}")
    foreign = sorted(p for p in pr.pushers if p.casefold() not in hitl)
    c.require(not foreign, f"the capture branch was updated by {', '.join(foreign)}; only HITL may update it")
    c.require(pr.files_complete and len(pr.files) == 1 and pr.files[0].path == queue_path
              and pr.files[0].status == "modified" and not pr.files[0].previous_path,
              f"a capture PR changes exactly one file, {queue_path}, and nothing else")
    if queue_on_main is None:
        c.reasons.append(f"{queue_path} does not exist on {default_branch}")
    elif queue_at_head is None or not queue_at_head.startswith(queue_on_main):
        c.reasons.append(f"a capture only appends to {queue_path}: the PR must keep every line on {default_branch} "
                         f"as it is (update the branch from {default_branch} if another capture landed first)")
    else:
        added = queue_at_head[len(queue_on_main):]
        c.require(len(added) <= CAPTURE_MAX_CHARS, f"a capture appends at most {CAPTURE_MAX_CHARS} characters")
        c.require(bool(_CAPTURE_HEADING_RE.search(added)), "the appended text has no `### CAPTURE-<yyyy>-<nnn>` entry")
        c.require(all(m.strip() == "DRAFT" for m in _STATUS_LINE_RE.findall(added)) and _STATUS_LINE_RE.search(added),
                  "every appended entry has the status line `- **Status:** DRAFT`, and no other status")
    if c.reasons:
        return Decision(REJECT, tuple(c.reasons))
    if held_by:
        return Decision(WAIT, (f"mission {held_by} may change {queue_path}; captures wait until it is finished",))
    if not pr.head_pushed:
        return Decision(WAIT, (f"GitHub has not yet recorded the push of {pr.head_sha}",))
    return Decision(MERGE)


def _expected(state: MissionState) -> str:
    if state.stage == AWAIT_A1:
        return "the A1 plan"
    if state.stage in ("AWAIT_A2", "AWAIT_A3"):
        return f"{state.stage[-2:]} round {state.round}"
    return "nothing (it is finished)"


def _check_a1_files(pr: OpenStagePR, c: _Checks) -> None:
    root = mission_dir(pr.ref.mission_id)
    manifest_file = manifest_path(pr.ref.mission_id)
    seen_manifest = False
    for change in pr.files:
        for path in filter(None, (change.path, change.previous_path)):
            c.require(path.startswith(root), f"A1 PRs may only change {root}; found {path}")
            c.require(not path.startswith(root + "reviews/"), f"A1 PRs may not write review records ({path})")
        c.require(change.status in _ALLOWED_STATUSES, f"unsupported change type {change.status} for {change.path}")
        if change.path == manifest_file:
            seen_manifest = True
            c.require(change.status == "added", f"{manifest_file} must be new in the A1 PR")
    c.require(seen_manifest, f"the A1 PR must add {manifest_file}")


def plan_findings(manifest: Manifest, classify) -> list:
    """Files the plan asks for that no A2 PR could ever deliver (Amendment 004), found before HITL approves.

    The same rules ``_check_build_files`` applies to the build: inside build_scope, a safe path, not
    SPEC-002 AUTHORITY. Checked for every ``deliverables`` entry and every build_scope entry without a
    wildcard. A glob is not expanded: a file it matches is still checked when A2 delivers it.
    """
    reasons = []
    named = [(p, "deliverable") for p in manifest.deliverables]
    named += [(p, "build_scope entry") for p in manifest.build_scope if is_literal_glob(p)]
    for path, what in named:
        if what == "deliverable" and not in_scope(path, manifest.build_scope):
            reasons.append(f"deliverable {path} is outside the plan's build_scope, so no A2 PR could deliver it")
            continue
        try:
            family = classify(path)
        except ValueError:
            reasons.append(f"{what} {path!r} is not a safe path")
            continue
        if family == "AUTHORITY":
            reasons.append(f"{what} {path} is AUTHORITY under SPEC-002; the router refuses it in every A2 PR, so it "
                           "cannot go through a mission")
    return reasons


def _check_build_files(files: Sequence[FileChange], manifest: Manifest, classify, c: _Checks) -> None:
    for change in files:
        c.require(change.status in _ALLOWED_STATUSES, f"unsupported change type {change.status} for {change.path}")
        for path in filter(None, (change.path, change.previous_path)):
            try:
                family = classify(path)
            except ValueError:
                c.reasons.append(f"unsafe path {path!r}")
                continue
            c.require(not path.startswith("missions/"), f"A2 may not change mission records ({path})")
            c.require(in_scope(path, manifest.build_scope), f"{path} is outside the approved build_scope")
            c.require(family != "AUTHORITY", f"{path} is AUTHORITY under SPEC-002; it cannot go through a mission")


def classify_or_raise(tables, normalize):
    """Bind SPEC-002 tables into a classifier that raises ValueError on unsafe paths."""

    def classify(path: str) -> str:
        try:
            return tables.classify(normalize(path))
        except ValueError:
            raise
        except Exception as exc:  # pragma: no cover - defensive
            raise MissionInputError(str(exc)) from exc

    return classify
