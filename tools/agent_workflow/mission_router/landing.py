"""The landing branch's own checks, before a mission spends its rounds (MISSION-ROUTER-001 Amendment 023,
MISSION-DISPATCH-001 Amendment 048).

A mission can pass AR, A2 and A3 and still fail the checks its landing PR must pass: the repository's path policy, or
its own test suite. M-GCS-DEMO-PROOF-002 did both, and was only found out at the landing PR. Two optional
``config.json`` keys bring those checks forward:

- ``landing_path_check``: an argv, run from the repository root of the default branch's checkout, that reads paths one
  per line on stdin and exits 0 when the repository allows them all, or 1 after printing each path it refuses, one per
  line. The router runs it on the plan's deliverables and literal ``build_scope`` entries before HITL approves (the
  same paths Amendment 004 checks), and refuses the plan for each path refused.
- ``landing_checks``: shell commands the landing branch requires. The A3 checks job runs them, as it runs the plan's
  checks (as an unprivileged account, with no credential), on the commit under review merged onto the landing
  branch's head. The publish job refuses an A3 PASS unless every one of them exited 0.

Both are absent by default: nothing changes until a repository names its own.
"""

from __future__ import annotations

import os
import subprocess
from typing import Callable, Iterable, List, Mapping, Tuple

PATH_CHECK_KEY = "landing_path_check"
CHECKS_KEY = "landing_checks"
MAX_CHECKS = 10
MAX_CHARS = 2000
PATH_CHECK_TIMEOUT = 60.0
SHOWN_CHARS = 200


def _strings(value: object, key: str, limit: int) -> Tuple[str, ...]:
    if value is None:
        return ()
    if not (isinstance(value, list) and 0 < len(value) <= limit
            and all(isinstance(s, str) and s.strip() and len(s) <= MAX_CHARS and "\0" not in s for s in value)):
        raise ValueError(f"config.json: {key} must be a list of 1 to {limit} non-empty strings")
    return tuple(value)


def path_check(config: Mapping) -> Tuple[str, ...]:
    """``landing_path_check`` as an argv; ``()`` when absent. An unusable value stops the router."""
    return _strings(config.get(PATH_CHECK_KEY), PATH_CHECK_KEY, 20)


def checks(config: Mapping) -> Tuple[str, ...]:
    """``landing_checks``; ``()`` when absent. An unusable value stops the router and the dispatcher."""
    return _strings(config.get(CHECKS_KEY), CHECKS_KEY, MAX_CHECKS)


def path_findings(argv: Iterable[str], paths: Iterable[str], run: Callable = subprocess.run,
                  cwd: str = ".") -> List[str]:
    """Why the plan's ``paths`` could not land, by the repository's own path policy; empty when it allows them all.

    Only paths are handed over, on stdin; the command gets no token (its environment is PATH and LANG alone). A
    command that cannot run, times out, or fails without naming a path refuses the plan: the paths are then not
    known to be allowed.
    """
    argv, paths = tuple(argv), sorted(set(paths))
    if not argv or not paths:
        return []
    shown = " ".join(argv)[:SHOWN_CHARS]
    try:
        done = run(list(argv), input="".join(f"{p}\n" for p in paths), capture_output=True, text=True,
                   timeout=PATH_CHECK_TIMEOUT, cwd=cwd,
                   env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [f"the landing path check (`{shown}`) could not run, so the plan's paths are not known to be "
                f"allowed: {str(exc)[:SHOWN_CHARS]}"]
    if done.returncode == 0:
        return []
    refused = [line.strip() for line in (done.stdout or "").splitlines() if line.strip() in paths]
    if done.returncode != 1 or not refused:
        return [f"the landing path check (`{shown}`) exited {done.returncode} without naming a path it refuses, so "
                "the plan's paths are not known to be allowed"]
    return [f"{path} is not allowed in this repository by its path policy (`{shown}`), so the mission could not "
            "land" for path in sorted(set(refused))]
