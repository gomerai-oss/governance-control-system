"""Mission state, derived from the merged stage PRs. Nothing else is trusted.

The router keeps no state of its own. Each run re-reads the merged PR history
of a mission and replays it through the stage grammar. Every stage merges into
mission/<ID>/integration except the A3 PASS, the only merge into the default
branch, so a mission reaches the default branch only once A3 has passed it:

    A1  ( A2_r  A3_r[FAIL] )*  [ A2_r  [ A3_r[PASS | BLOCKED] ] ]      r = 1, 2, ...

HITL can reopen a BLOCKED mission with ``/mission retry`` on its tracking issue (Amendment 004):
after a BLOCKED verdict A3 reviews the same build again in the next round; after a FAIL in
the last allowed round A2 gets one more round. A retry counts only when posted after the
block it reopens, so each reopening takes its own retry.

A PASS merges into the mission's landing branch: the default branch, or the stack branch
when its stack lands as a whole. BLOCKED (A3 found something that kept A2 from completing
the plan) and a FAIL in the last allowed round end the mission as BLOCKED: recorded for
HITL's review at the end, never escalated mid-stack.

Any history that does not fit the grammar, or that was merged by an identity
that is neither the router nor a HITL login, halts the mission for HITL.
HITL can also cancel a mission that has not landed (the router applies that on
top of the derived state; see router.MissionRouter.context).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional, Sequence, Tuple

from .model import MAX_ROUNDS_CEILING, Manifest, StageRef

AWAIT_A1 = "AWAIT_A1"
AWAIT_A2 = "AWAIT_A2"
AWAIT_A3 = "AWAIT_A3"
DONE = "DONE"
HALTED = "HALTED"
PAUSED = "PAUSED"  # HITL commented /mission halt (Amendment 010); /mission resume lifts it
CANCELLED = "CANCELLED"
BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class MergedStage:
    """One merged stage PR, as read from GitHub."""

    ref: StageRef
    number: int
    base_ref: str
    merged_by: str
    merge_commit_sha: str
    verdict: Optional[str] = None  # A3 only: PASS / FAIL / BLOCKED read from the merged verdict file
    reviewed_sha: Optional[str] = None  # A3 only
    head_sha: Optional[str] = None  # the PR's head when it merged (A1: the plan commit HITL approved)
    merged_at: str = ""
    findings: Tuple[str, ...] = ()  # A3 only


@dataclass(frozen=True)
class MissionState:
    mission_id: str
    stage: str
    round: int = 0
    integration_head: Optional[str] = None  # the head the integration branch must have
    review_sha: Optional[str] = None  # AWAIT_A3: the integration head A3 must review
    reason: str = ""
    last_pr: Optional[int] = None
    plan_sha: Optional[str] = None  # A1's merge commit: the approved manifest is read here
    landed_sha: Optional[str] = None  # DONE: the merge commit that put the mission on its landing branch
    when: str = ""  # DONE / BLOCKED: when it was recorded
    details: Tuple[str, ...] = ()  # BLOCKED: each blocker
    build_sha: Optional[str] = None  # AWAIT_A3 / BLOCKED: the A2 merge commit that brought in the build under review
    resume: Optional[str] = None  # BLOCKED: the role a HITL /mission retry restarts ("A2" or "A3"); None: not reopenable
    paused_from: Optional[str] = None  # PAUSED: the stage the mission is in underneath the halt

    def expects(self, ref: StageRef) -> bool:
        if self.stage == AWAIT_A1:
            return ref.role == "A1"
        if self.stage == AWAIT_A2:
            return ref.role == "A2" and ref.round == self.round
        if self.stage == AWAIT_A3:
            return ref.role == "A3" and ref.round == self.round
        return False


def _halt(mission_id: str, reason: str, prior: Optional[MissionState] = None) -> MissionState:
    return MissionState(
        mission_id,
        HALTED,
        round=prior.round if prior else 0,
        integration_head=prior.integration_head if prior else None,
        reason=reason,
        last_pr=prior.last_pr if prior else None,
        plan_sha=prior.plan_sha if prior else None,
    )


def derive_state(
    mission_id: str,
    merged: Iterable[MergedStage],
    manifest: Optional[Manifest],
    trusted_mergers: Iterable[str],
    default_branch: str = "main",
    retries: Sequence[str] = (),
    reopen: bool = True,
) -> MissionState:
    """Replay merged stage PRs (oldest first) through the stage grammar.

    ``default_branch`` is where an A3 PASS must merge: the mission's landing branch.
    ``retries`` are the times HITL commented ``/mission retry`` on the tracking issue. A retry
    after a block that merged history already continues is always honoured; ``reopen`` says
    whether a retry may reopen the block the history ends in (False once the review is closed).
    """
    trusted = {login.casefold() for login in trusted_mergers}
    integration = f"mission/{mission_id}/integration"
    state = MissionState(mission_id, AWAIT_A1)

    for item in merged:
        state = _reopened(state, retries) or state
        if item.merged_by.casefold() not in trusted:
            return _halt(mission_id, f"PR #{item.number} was merged by {item.merged_by}, which is neither the router nor HITL", state)
        if not state.expects(item.ref):
            return _halt(mission_id, f"PR #{item.number} ({item.ref.role} round {item.ref.round}) merged out of order while the mission was {state.stage}", state)

        if item.ref.role == "A1":
            if item.base_ref != integration:
                return _halt(mission_id, f"A1 PR #{item.number} merged into {item.base_ref}, not {integration}", state)
            if manifest is None:
                return _halt(mission_id, f"A1 PR #{item.number} is merged but its missions/{mission_id}/mission.json is unreadable", state)
            state = MissionState(mission_id, AWAIT_A2, round=1, integration_head=item.merge_commit_sha,
                                 last_pr=item.number, plan_sha=item.merge_commit_sha)

        elif item.ref.role == "A2":
            if item.base_ref != integration:
                return _halt(mission_id, f"A2 PR #{item.number} merged into {item.base_ref}, not {integration}", state)
            state = MissionState(
                mission_id, AWAIT_A3, round=state.round, integration_head=item.merge_commit_sha,
                review_sha=item.merge_commit_sha, last_pr=item.number, plan_sha=state.plan_sha,
                build_sha=item.merge_commit_sha,
            )

        else:  # A3
            expected_base = default_branch if item.verdict == "PASS" else integration
            if item.verdict not in ("PASS", "FAIL", "BLOCKED") or item.base_ref != expected_base:
                return _halt(mission_id, f"A3 PR #{item.number} verdict {item.verdict!r} does not match its base {item.base_ref}", state)
            if item.reviewed_sha != state.review_sha:
                return _halt(mission_id, f"A3 PR #{item.number} reviewed {item.reviewed_sha}, not the handed-off {state.review_sha}", state)
            if item.verdict == "PASS":
                state = MissionState(mission_id, DONE, round=state.round, integration_head=state.integration_head,
                                     last_pr=item.number, plan_sha=state.plan_sha, landed_sha=item.merge_commit_sha,
                                     when=item.merged_at)
            elif item.verdict == "BLOCKED":
                state = MissionState(mission_id, BLOCKED, round=state.round, integration_head=item.merge_commit_sha,
                                     reason=f"A3 recorded a blocker in round {state.round}", last_pr=item.number,
                                     plan_sha=state.plan_sha, when=item.merged_at, details=item.findings,
                                     build_sha=state.build_sha, resume="A3")
            elif manifest is not None and state.round >= manifest.max_rounds:
                state = MissionState(mission_id, BLOCKED, round=state.round, integration_head=item.merge_commit_sha,
                                     reason=f"A3 failed round {state.round}, the last of max_rounds {manifest.max_rounds}",
                                     last_pr=item.number, plan_sha=state.plan_sha, when=item.merged_at, details=item.findings,
                                     build_sha=state.build_sha, resume="A2")
            else:
                state = MissionState(mission_id, AWAIT_A2, round=state.round + 1, integration_head=item.merge_commit_sha,
                                     last_pr=item.number, plan_sha=state.plan_sha)

    return (_reopened(state, retries) if reopen else None) or state


def _reopened(state: MissionState, retries: Sequence[str]) -> Optional[MissionState]:
    """The stage a HITL retry posted after this block reopens, or None.

    A BLOCKED verdict is reviewed again by A3 in the next round, on the integration head (the build
    plus the BLOCKED verdict); a last-round FAIL gives A2 one more round. Rounds stop at
    MAX_ROUNDS_CEILING, the most the router reads back.
    """
    if state.stage != BLOCKED or state.resume is None or not state.when or state.round >= MAX_ROUNDS_CEILING:
        return None
    if not any(t > state.when for t in retries):
        return None
    reason = f"HITL retried the block of round {state.round}"
    if state.resume == "A3":
        return MissionState(state.mission_id, AWAIT_A3, round=state.round + 1, integration_head=state.integration_head,
                            review_sha=state.integration_head, reason=reason, last_pr=state.last_pr,
                            plan_sha=state.plan_sha, build_sha=state.build_sha)
    return MissionState(state.mission_id, AWAIT_A2, round=state.round + 1, integration_head=state.integration_head,
                        reason=reason, last_pr=state.last_pr, plan_sha=state.plan_sha)


def history_order(items: Iterable[Tuple[str, MergedStage]]) -> Tuple[MergedStage, ...]:
    """Sort (merged_at ISO timestamp, stage) pairs oldest first; ties break on PR number."""
    return tuple(stage for _, stage in sorted(items, key=lambda pair: (pair[0], pair[1].number)))
