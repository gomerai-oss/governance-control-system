"""The execution substrate (MISSION-DISPATCH-001 Amendment 015, §3h item 6; MISSION-ROUTER-001 Amendment 013).

Ring 5 holds only on a machine that holds nothing but what the job is given. GitHub-hosted runners do; any other
machine needs a declaration HITL wrote. Two checks, both here:

- before merge, ``static_findings`` reads the two mission workflows and lists every job whose ``runs-on`` is not a
  GitHub-hosted ``ubuntu-*`` label (the credentials check prints them);
- at run time, ``python3 -m mission_router.substrate`` reads ``runner.environment`` (passed as
  ``SUBSTRATE_RUNNER``) right after the job's checkout of the default branch's own tooling, and fails a job on any
  other machine when there is no declaration and ``"substrate"`` is ``"enforce"``.

Stdlib only. Workflows are read line by line, as the credentials check reads them: a shape this reader does not know
is a finding, never a guess.

    SUBSTRATE_RUNNER=<runner.environment> python3 -m mission_router.substrate [--root <repo>] [--config <config.json>]

Prints ``substrate: github-hosted``, ``substrate: declared (<file>)`` or ``substrate: <value> (refused|would be
refused)``. Exit 0, 1 when refused under ``"enforce"``, 2 when the config or the declaration cannot be used.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Dict, List, Mapping, Optional

MODES = ("observe", "enforce")
HOSTED = "github-hosted"
DECLARATION_NAME = "SUBSTRATE-DECLARATION.md"  # SPEC-002 AUTHORITY by basename (policy_tables.json)
MAX_DECLARATION = 1 << 16
WORKFLOWS = ("mission-agent.yml", "mission-router.yml")
# The headings a declaration must carry: one per machine property of §3h item 6, and who confirmed it, and when.
SECTIONS = ("## Disposable", "## No ambient credentials", "## Not shared", "## Root for the job")
CONFIRMED = ("Confirmed by:", "Confirmed on:")
REPO_ROOT = Path(__file__).resolve().parents[3]

_HOSTED_LABEL_RE = re.compile(r"ubuntu-(latest|[0-9]{2}\.[0-9]{2})")
_JOB_RE = re.compile(r"^  ([A-Za-z_][A-Za-z0-9_-]*):\s*(#.*)?$")
_RUNS_ON_RE = re.compile(r"^    runs-on:\s*(.*?)\s*(#.*)?$")
_USES_RE = re.compile(r"^    uses:\s*\S")


class SubstrateError(ValueError):
    """The substrate settings cannot be used: no job may run on them."""


def mode(config: Mapping) -> str:
    """``config.json`` ``"substrate"``; ``"observe"`` when absent. Any other value raises."""
    value = config.get("substrate", "observe")
    if value not in MODES:
        raise SubstrateError(f"config.json: substrate must be one of {', '.join(MODES)}, not {value!r}")
    return value


def declaration(config: Mapping, root: Path = REPO_ROOT) -> Optional[str]:
    """The declaration file ``config.json`` names (repository-relative), or None when it names none.

    A named file that is not a usable declaration raises: HITL meant to declare, and a job cannot tell what."""
    value = config.get("substrate_declaration")
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise SubstrateError("config.json: substrate_declaration must name a file")
    rel = PurePosixPath(value)
    if rel.is_absolute() or ".." in rel.parts or "\\" in value:
        raise SubstrateError(f"config.json: substrate_declaration must be a path inside the repository, not {value!r}")
    if rel.name != DECLARATION_NAME:
        raise SubstrateError(f"config.json: substrate_declaration must be a file named {DECLARATION_NAME} "
                             f"(SPEC-002 AUTHORITY by name), not {value!r}")
    path = root / rel
    if path.is_symlink() or not path.is_file():
        raise SubstrateError(f"the substrate declaration {value} does not exist")
    if path.stat().st_size > MAX_DECLARATION:
        raise SubstrateError(f"the substrate declaration {value} is too large")
    text = path.read_text(encoding="utf-8")
    lines = [line.strip() for line in text.splitlines()]
    missing = [s for s in SECTIONS if s not in lines] + [c for c in CONFIRMED
                                                          if not any(l.startswith(c) and l[len(c):].strip() for l in lines)]
    if missing:
        raise SubstrateError(f"the substrate declaration {value} lacks: {', '.join(missing)}")
    return str(rel)


def _scalar(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def scan_workflow(name: str, text: str) -> List[str]:
    """Every job of one workflow whose runner is not a GitHub-hosted ``ubuntu-*`` label."""
    findings: List[str] = []
    in_jobs, job, start, runs_on, calls = False, None, 0, None, False

    def close() -> None:
        if job is None:
            return
        where = f"{name}:{start}"
        if calls:
            findings.append(f"{where}: job {job} calls a reusable workflow, whose runner this check cannot see")
        elif runs_on is None:
            findings.append(f"{where}: job {job} has no runs-on this check can read")

    for number, line in enumerate(text.splitlines(), 1):
        if line.startswith("jobs:"):
            in_jobs = True
            continue
        if line and not line[0].isspace() and not line.startswith("#"):
            close()
            in_jobs, job = False, None
            continue
        match = _JOB_RE.match(line) if in_jobs else None
        if match:
            close()
            job, start, runs_on, calls = match.group(1), number, None, False
            continue
        if job is None:
            continue
        if _USES_RE.match(line):
            calls = True
        runs = _RUNS_ON_RE.match(line)
        if not runs:
            continue
        runs_on = _scalar(runs.group(1))
        where = f"{name}:{number}"
        if "${{" in runs_on:
            findings.append(f"{where}: job {job}'s runs-on is computed, so this check cannot see where it runs")
        elif not runs_on:
            findings.append(f"{where}: job {job}'s runs-on is a label list or a runner group, not a GitHub-hosted label")
        elif runs_on.startswith("["):
            findings.append(f"{where}: job {job}'s runs-on is a label list, not one GitHub-hosted label")
        elif not _HOSTED_LABEL_RE.fullmatch(runs_on):
            findings.append(f"{where}: job {job} runs on {runs_on!r}, not a GitHub-hosted ubuntu-* label")
    close()
    return findings


def static_findings(workflows: Mapping[str, str]) -> List[str]:
    """The before-merge check (§3h item 6) over ``workflows`` (file name -> text): the two mission workflows only."""
    findings: List[str] = []
    for name in WORKFLOWS:
        if name in workflows:
            findings += scan_workflow(name, workflows[name])
    return findings


def runtime_decision(runner: str, substrate_mode: str, declared: Optional[str]) -> Dict[str, object]:
    """What the run-time check does with ``runner`` (the job's ``runner.environment``)."""
    if runner == HOSTED:
        return {"allow": True, "record": f"substrate: {HOSTED}"}
    shown = runner or "empty"
    if declared:
        return {"allow": True, "record": f"substrate: declared ({declared}); runner.environment is {shown}"}
    refused = substrate_mode == "enforce"
    return {"allow": not refused,
            "record": f"substrate: {shown} ({'refused' if refused else 'would be refused'}): this job is not on a "
                      f"GitHub-hosted runner and the repository declares no substrate (MISSION-DISPATCH-001 §3h item 6)"}


def main(argv: Optional[List[str]] = None, environ: Mapping[str, str] = os.environ) -> int:
    parser = argparse.ArgumentParser(prog="mission_router.substrate", description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=None, help="the repository (default: the one this tooling is in)")
    parser.add_argument("--config", default=None, help="mission_router config.json (default: the router's own)")
    args = parser.parse_args(argv)
    from .router import load_config  # not at module level: the credentials check imports this module too

    try:
        config = load_config(Path(args.config)) if args.config else load_config()
        substrate_mode = mode(config)
        declared = declaration(config, Path(args.root) if args.root else REPO_ROOT)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        print(f"::error::substrate: {exc}")
        return 2
    decision = runtime_decision(environ.get("SUBSTRATE_RUNNER", ""), substrate_mode, declared)
    record = str(decision["record"])
    level = "" if environ.get("SUBSTRATE_RUNNER") == HOSTED else ("::error::" if not decision["allow"] else "::warning::")
    print(f"{level}{record} (mode={substrate_mode})")
    summary = environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        try:
            with open(summary, "a", encoding="utf-8") as handle:
                handle.write(f"{record} (mode={substrate_mode})\n")
        except OSError:
            pass
    return 0 if decision["allow"] else 1


if __name__ == "__main__":
    sys.exit(main())
