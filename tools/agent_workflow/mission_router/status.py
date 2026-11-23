"""Is this work done? The completion check an agent runs before it reports work complete (MISSION-ROUTER-001
Amendment 024).

    PYTHONPATH=tools/agent_workflow python3 -m mission_router.status --repo OWNER/REPO --mission M-EXAMPLE-001
    PYTHONPATH=tools/agent_workflow python3 -m mission_router.status --repo OWNER/REPO --pr 123

- ``--mission``: the router's own reading of the mission, read-only (the router's derivation, run with nothing
  written). Done means ``DONE``: its A3 PASS is merged into its landing branch, and, for a mission in a stack that
  lands as a whole, the stack has landed too.
- ``--pr``: a hand-built PR, which only HITL merges. Done means merged, by one of ``config.json``'s
  ``hitl_logins``.

Prints one line: ``DONE: ...`` or ``NOT DONE: ...``. Exit 0 when done, 3 when not, 2 when it cannot tell. Anything
but 0 is not done: review requested, queued or running is never done, and a builder's own check of its work is
never the review.

Needs ``GITHUB_TOKEN`` (read access is enough).
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Callable, Optional, Tuple

DONE_EXIT, NOT_DONE_EXIT, ERROR_EXIT = 0, 3, 2


def mission_status(router, mission_id: str) -> Tuple[bool, str]:
    """``(done, line)`` for a mission, from ``router`` (a ``MissionRouter`` made with ``dry_run=True``)."""
    from .state import DONE
    router._contexts, router._known, router._open_prs = {}, {mission_id}, {mission_id: []}
    ctx = router.context(mission_id)
    state, manifest = ctx.state, ctx.manifest
    detail = f"{mission_id} is {state.stage}" + (f", round {state.round}" if state.round else "") + \
        (f": {state.reason}" if state.reason else "")
    if state.stage != DONE:
        return False, f"NOT DONE: {detail}"
    if manifest is not None and router._in_stack(manifest):
        from .router import STACK_LANDED
        stack = router.stack_status(manifest.stack_id)
        if stack.status != STACK_LANDED:
            return False, f"NOT DONE: {mission_id} passed A3, but its stack {manifest.stack_id} is {stack.status}"
    return True, f"DONE: {detail}"


def pr_status(request: Callable, hitl_logins, number: int) -> Tuple[bool, str]:
    """``(done, line)`` for a hand-built PR: merged, by a HITL login."""
    pr = request("GET", f"/pulls/{int(number)}")
    hitl = {str(login).casefold() for login in hitl_logins}
    by = str(((pr.get("merged_by") or {}).get("login")) or "")
    if not pr.get("merged_at"):
        return False, f"NOT DONE: PR #{number} is {pr.get('state', 'unknown')} and not merged"
    if by.casefold() not in hitl:
        return False, f"NOT DONE: PR #{number} was merged by {by or 'an unknown account'}, which is not a HITL login"
    return True, f"DONE: PR #{number} was merged by HITL {by} at {pr.get('merged_at')}"


def main(argv: Optional[list] = None, make_router: Optional[Callable] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True)
    which = parser.add_mutually_exclusive_group(required=True)
    which.add_argument("--mission")
    which.add_argument("--pr", type=int)
    args = parser.parse_args(argv)
    try:
        from .github import GitHub
        from .router import MissionRouter, load_config
        config = load_config()
        if args.pr is not None:
            gh = GitHub(os.environ.get("GITHUB_TOKEN", ""), args.repo)
            done, line = pr_status(gh.request, config["hitl_logins"], args.pr)
        else:
            if make_router is None:
                from router_spec002.policy import load_tables, normalize_path
                from .gate import classify_or_raise
                gh = GitHub(os.environ.get("GITHUB_TOKEN", ""), args.repo)
                router = MissionRouter(gh, config, classify_or_raise(load_tables(), normalize_path), dry_run=True,
                                       log=lambda *_: None)
            else:
                router = make_router(config)
            done, line = mission_status(router, args.mission)
    except Exception as exc:  # any failure to read is "cannot tell", never "done"
        print(f"NOT DONE: cannot tell ({type(exc).__name__}: {str(exc)[:300]})")
        return ERROR_EXIT
    print(line)
    return DONE_EXIT if done else NOT_DONE_EXIT


if __name__ == "__main__":
    sys.exit(main())
