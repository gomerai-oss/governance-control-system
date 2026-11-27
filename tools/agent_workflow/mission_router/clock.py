"""The mission clock (MISSION-ROUTER-001 Amendment 028; MISSION-DISPATCH-001 Amendment 058).

The router's 5-minute schedule is its own workflow, Mission Clock (``mission-clock.yml``), so it can be switched off: a
scheduled run bills at least a minute whether or not it finds anything to do, and the router's, the dispatcher's and
the seal sweep's schedules cost about 860 billed minutes a day across governance and Core while no mission was open.
The router keeps a 30-minute heartbeat of its own: a plan PR into a mission branch sends it no event.

After every sweep, whatever started it, the router decides whether machines are working on a mission:
- **active:** a mission waits on A2 or A3 (an agent run, its checks, its scan or its evidence seal), or a plan, stage or
  landing PR is open (AR's rounds, the checks on a plan PR, a landing PR's checks);
- **cooling:** none is, but a mission's PR closed less than ``COOL_MINUTES`` ago, so the seal sweep can still seal its
  last runs;
- **idle:** neither. A mission waiting on HITL (an approval, ``/mission retry``, ``/mission resume``) or a plan
  branch with no PR is idle: HITL's comment or PR starts the router by its own event.

While active or cooling the clock is on (every 5 minutes, as the router's schedule was), and the router starts the
Mission Agent workflow and the seal sweep in turn, each at most every ``FALLBACK_MINUTES`` and never while a run of it
is still going: these replace their own 10-minute schedules. While idle the clock is off, and nothing runs on a
schedule but the daily deep sweep (MISSION-DISPATCH-001 Amendment 057), which seals what idle-time runs kept.

Each switch and each start is a write, recorded first like any other (Amendment 018). A clock that must be on but
cannot be switched on fails the router's run, so it is seen.
"""

from __future__ import annotations

import datetime
from typing import Callable, Iterable, List, Mapping, Optional

from .github import GitHubError
from .model import parse_stack_branch, parse_stage_branch
from .state import AWAIT_A2, AWAIT_A3

CLOCK_WORKFLOW = "mission-clock.yml"
AGENT_WORKFLOW = "mission-agent.yml"
SEAL_WORKFLOW = "evidence-seal.yml"
COOL_MINUTES = 30
FALLBACK_MINUTES = 10
RUNNING = frozenset({"queued", "in_progress", "waiting", "pending", "requested"})
_FMT = "%Y-%m-%dT%H:%M:%SZ"


class ClockError(RuntimeError):
    """The clock must be on and could not be switched on."""


def machine_active(states: Mapping[str, object], open_prs: Mapping[str, list], landing_prs: Mapping[str, list]) -> List[str]:
    """Why machines are working on a mission now; empty when none is."""
    why = [f"{mid} waits on {s.stage[-2:]}" for mid, s in sorted(states.items())
           if getattr(s, "stage", None) in (AWAIT_A2, AWAIT_A3)]
    why += [f"{mid} has an open PR" for mid, prs in sorted(open_prs.items()) if prs]
    why += [f"stack {sid} has an open landing PR" for sid, prs in sorted(landing_prs.items()) if prs]
    return why


def last_closed(request: Callable) -> Optional[str]:
    """When the most recently closed mission or stack PR closed (``closed_at``), or None."""
    for pr in request("GET", "/pulls?state=closed&sort=updated&direction=desc&per_page=30") or []:
        ref = str((pr.get("head") or {}).get("ref", ""))
        if pr.get("closed_at") and (parse_stage_branch(ref) or parse_stack_branch(ref)):
            return str(pr["closed_at"])
    return None


def _minutes_since(when: str, now: datetime.datetime) -> float:
    then = datetime.datetime.strptime(when, _FMT).replace(tzinfo=datetime.timezone.utc)
    return (now - then).total_seconds() / 60


def due(request: Callable, workflow: str, events: Iterable[str], now: datetime.datetime) -> bool:
    """Whether to start ``workflow``: no run of it from ``events`` is still going, and none started in the last
    ``FALLBACK_MINUTES``."""
    events = set(events)
    runs = [r for r in (request("GET", f"/actions/workflows/{workflow}/runs?per_page=20") or {}).get("workflow_runs") or []
            if r.get("event") in events]
    if any(r.get("status") in RUNNING for r in runs):
        return False
    started = [str(r.get("created_at")) for r in runs if r.get("created_at")]
    return not started or _minutes_since(max(started), now) >= FALLBACK_MINUTES


def tick(router, states: Mapping[str, object], now: Optional[datetime.datetime] = None) -> List[str]:
    """Switch the clock to what the missions need, and start the fallbacks while it is on. Returns what it did, for
    the log. Raises ``ClockError`` when the clock must be on and GitHub would not switch it on."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    gh, done = router.gh, []
    why = machine_active(states, getattr(router, "_open_prs", {}), getattr(router, "_landing_prs", {}))
    if not why:
        try:
            closed = last_closed(gh.request)
        except GitHubError as exc:
            closed, why = None, [f"the closed PRs could not be read ({exc.status}); kept on"]
        if closed and _minutes_since(closed, now) < COOL_MINUTES:
            why = [f"a mission PR closed at {closed}; cooling for {COOL_MINUTES} minutes"]
    on = bool(why)
    try:
        state = gh.workflow_state(CLOCK_WORKFLOW)
    except GitHubError as exc:
        if exc.status == 404:
            return [f"no {CLOCK_WORKFLOW} in this repository; the clock is not used"]
        if on:
            raise ClockError(f"the clock's state could not be read ({exc.status}) while {why[0]}") from None
        return [f"the clock's state could not be read ({exc.status}); left as it is"]
    if on != (state == "active"):
        what = f"{'switch on' if on else 'switch off'} {CLOCK_WORKFLOW}: " + ("; ".join(why[:3]) if on else "idle")
        try:
            router._write(what, lambda: gh.set_workflow_enabled(CLOCK_WORKFLOW, on), "router.clock")
        except GitHubError as exc:
            if on:
                raise ClockError(f"{CLOCK_WORKFLOW} could not be switched on ({exc.status}) while {why[0]}") from None
            return [f"{CLOCK_WORKFLOW} could not be switched off ({exc.status}); the next sweep tries again"]
        done.append(what)
    if not on:
        return done or ["idle; the clock is off"]
    for workflow, events, inputs in ((AGENT_WORKFLOW, ("workflow_dispatch", "schedule"), None),
                                     (SEAL_WORKFLOW, ("workflow_dispatch", "schedule"), {"sweep": "true"})):
        try:
            if not due(gh.request, workflow, events, now):
                continue
            router._write(f"start {workflow} (the clock's fallback, every {FALLBACK_MINUTES} minutes)",
                          lambda w=workflow, i=inputs: gh.dispatch_workflow(w, router.main, i), "router.dispatch")
            done.append(f"started {workflow}")
        except GitHubError as exc:  # the next sweep, 5 minutes on, tries again
            done.append(f"{workflow} could not be started ({exc.status}); the next sweep tries again")
    return done or ["on; nothing due"]
