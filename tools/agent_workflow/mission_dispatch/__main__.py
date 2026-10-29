"""CLI: one step of the Mission Agent workflow per call.

    PYTHONPATH=tools/agent_workflow python3 -m mission_dispatch plan    --repo OWNER/REPO
    PYTHONPATH=tools/agent_workflow python3 -m mission_dispatch due     --repo OWNER/REPO
    PYTHONPATH=tools/agent_workflow python3 -m mission_dispatch checks  --root TREE --out DIR
    PYTHONPATH=tools/agent_workflow python3 -m mission_dispatch prepare --repo OWNER/REPO --root DIR [--checks-report DIR]
    PYTHONPATH=tools/agent_workflow python3 -m mission_dispatch run     --root DIR
    PYTHONPATH=tools/agent_workflow python3 -m mission_dispatch collect --root DIR --out DIR
    PYTHONPATH=tools/agent_workflow python3 -m mission_dispatch publish --repo OWNER/REPO --root DIR --artifact DIR
    PYTHONPATH=tools/agent_workflow python3 -m mission_dispatch report  --repo OWNER/REPO

Environment, per step (each step gets only what it needs):
    plan, due, prepare, report
                           GITHUB_TOKEN (the workflow's own token; plan also reads this workflow's runs,
                           report also posts on the tracking issue)
    checks                 nothing: it runs the code under review, so it gets no credential
    publish                READ_TOKEN (the workflow's token), AGENT_TOKEN and AGENT_SLUG (the agent App)
    collect                the runtime's model login, only to refuse a change that contains it
    all but plan           JOB: the job description plan() produced, as JSON
    publish, report        RUN_URL (optional): this workflow run, linked from the PR or the failure note
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Tuple

from mission_router.github import GitHub, GitHubError
from mission_router.gate import classify_or_raise
from mission_router.router import MissionRouter, load_config
from router_spec002.policy import load_tables, normalize_path

from . import binding
from .dispatch import (
    DispatchError,
    busy_lanes,
    not_due,
    run_checks,
    Job,
    Survey,
    failure_feedback,
    failure_gate,
    land,
    land_matrix,
    plan_landings,
    LandJob,
    collect,
    failure_comment,
    job_matrix,
    outcome,
    plan,
    prepare,
    publish,
    run_agent,
)

CLONE_URL = "https://github.com/{repo}.git"
WORKFLOW = "mission-agent.yml"
UNFINISHED = ("queued", "in_progress", "waiting", "pending", "requested")


def live_survey(gh: GitHub, log: Callable[[str], None]) -> Tuple[Survey, MissionRouter]:
    """The router's own read-only derivation of every unfinished mission (and the router that made it)."""
    config = load_config()
    router = MissionRouter(gh, config, classify_or_raise(load_tables(), normalize_path), dry_run=True, log=log)
    contexts = router.survey()
    hitl = {login.casefold() for login in config["hitl_logins"]}
    blocked = failure_gate(router, config["bot_login"], hitl, log)
    try:
        stacks = router.stacks()
    except GitHubError as exc:  # no landing this time; missions still run
        log(f"stacks could not be read, so no stack lands this time: {exc}")
        stacks = {}
    feedback = failure_feedback(router, config["bot_login"], hitl)

    def order(mission_id: str) -> int:  # the queue runs in approval order: tracking issues open when plans merge
        return int((router.tracking_issue(mission_id) or {}).get("number") or 10 ** 9)

    return Survey(contexts, router.identities(), gh.branch_head, config["default_branch"], blocked, stacks,
                  feedback, order, router.now()), router


def _env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise DispatchError(f"{name} is not set")
    return value


def _job() -> Job:
    try:
        return Job.from_dict(json.loads(_env("JOB")))
    except ValueError:
        raise DispatchError("JOB is not JSON") from None


def _log(message: str) -> None:
    print(message, file=sys.stderr)


def _output(name: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if "\n" in value or "\r" in value:
        raise DispatchError(f"output {name} must be one line")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(f"{name}={value}\n")
    print(f"{name}={value}")


def other_runs(gh: GitHub, own_run_id: str) -> list:
    """Jobs of every other unfinished run of this workflow."""
    runs = {}
    for status in UNFINISHED:
        data = gh.get(f"/actions/workflows/{WORKFLOW}/runs?status={status}&per_page=100") or {}
        for run in data.get("workflow_runs") or []:
            if str(run.get("id")) != own_run_id:
                runs[run["id"]] = run
    return [list((gh.get(f"/actions/runs/{run_id}/jobs?filter=latest&per_page=100") or {}).get("jobs") or [])
            for run_id in sorted(runs)]


def cmd_plan(args) -> int:
    gh = GitHub(_env("GITHUB_TOKEN"), args.repo)
    busy, unknown = busy_lanes(other_runs(gh, os.environ.get("GITHUB_RUN_ID", "")))
    if unknown:
        _log("another run of this workflow is still starting its jobs; starting nothing now, the next run plans again")
        _output("count", "0")
        _output("matrix", json.dumps({"job": []}))
        _output("land_count", "0")
        _output("land_matrix", json.dumps({"land": []}))
        return 0
    survey, _ = live_survey(gh, _log)
    jobs, notes = plan(survey, busy)
    for note in notes:
        _log(note)
    for job in jobs:
        _log(f"due: {job.key}: {job.runtime} as {job.agent} ({job.login}) at {job.base_sha}")
    landings = plan_landings(survey)
    for landing in landings:
        _log(f"due: land stack {landing.stack_id} at {landing.head_sha} as {landing.agent} ({landing.login})")
    _output("count", str(len(jobs)))
    _output("matrix", json.dumps(job_matrix(jobs), separators=(",", ":"), sort_keys=True))
    _output("land_count", str(len(landings)))
    _output("land_matrix", json.dumps(land_matrix(landings), separators=(",", ":"), sort_keys=True))
    return 0


def cmd_due(args) -> int:
    job = _job()
    survey, _ = live_survey(GitHub(_env("GITHUB_TOKEN"), args.repo), _log)
    reason = not_due(job, survey)
    if reason:
        _log(f"{job.key}: not running: {reason}")
    _output("due", "false" if reason else "true")
    return 0


def cmd_checks(args) -> int:
    job = _job()
    results = run_checks(job, Path(args.root), Path(args.out), os.environ, timeout=args.timeout, run_as=args.run_as)
    _log(f"{job.key}: {sum(r['passed'] for r in results)} of {len(results)} checks passed")
    return 0


def _binding_mode(config: dict) -> str:
    try:
        return binding.mode(config)
    except binding.BindingError as exc:
        raise DispatchError(str(exc)) from None


def cmd_prepare(args) -> int:
    job = _job()
    config = load_config()
    prepare(job, Path(args.root), CLONE_URL.format(repo=args.repo), _env("GITHUB_TOKEN"), os.environ, Path.home(),
            config["default_branch"], Path(args.checks_report) if args.checks_report else None,
            binding_mode=_binding_mode(config))
    _log(f"{job.key}: checkout ready at {job.base_sha}")
    return 0


def cmd_run(args) -> int:
    job = _job()
    log_path = run_agent(job, Path(args.root), os.environ, Path.home(), timeout=args.timeout,
                         binding_mode=_binding_mode(load_config()))
    _log(f"{job.key}: {job.runtime} finished (log: {log_path})")
    return 0


def cmd_collect(args) -> int:
    job = _job()
    result = collect(job, Path(args.root), Path(args.out), os.environ)
    _log(f"{job.key}: change accepted: {', '.join(result['paths'])}" + (f"; verdict {result['verdict']}" if result["verdict"] else ""))
    return 0


def cmd_publish(args) -> int:
    job = _job()
    read = GitHub(_env("READ_TOKEN"), args.repo)
    agent = GitHub(_env("AGENT_TOKEN"), args.repo)
    survey, _ = live_survey(read, _log)
    result = publish(job, survey, Path(args.artifact), Path(args.root), CLONE_URL.format(repo=args.repo),
                     _env("READ_TOKEN"), _env("AGENT_TOKEN"), f"{_env('AGENT_SLUG')}[bot]", os.environ,
                     agent.create_pull, os.environ.get("RUN_URL", ""))
    if result["status"] == "skipped":
        _log(f"{job.key}: not published: {result['reason']}")
    else:
        _log(f"{job.key}: opened PR #{result['pr_number']} into {result['base']} as {job.login}: {result['pr_url']}")
    return 0


def cmd_land(args) -> int:
    try:
        job = LandJob.from_dict(json.loads(_env("LAND_JOB")))
    except ValueError:
        raise DispatchError("LAND_JOB is not JSON") from None
    agent = GitHub(_env("AGENT_TOKEN"), args.repo)
    survey, _ = live_survey(GitHub(_env("READ_TOKEN"), args.repo), _log)
    result = land(job, survey, f"{_env('AGENT_SLUG')}[bot]", agent.create_pull, os.environ.get("RUN_URL", ""))
    if result["status"] == "skipped":
        _log(f"stack {job.stack_id}: not landing: {result['reason']}")
    else:
        _log(f"stack {job.stack_id}: opened landing PR #{result['pr_number']} as {job.login}: {result['pr_url']}")
    return 0


def cmd_report(args) -> int:
    job = _job()
    gh = GitHub(_env("GITHUB_TOKEN"), args.repo)
    survey, router = live_survey(gh, _log)
    reason = outcome(job, survey, gh.pulls_from)
    if reason is None:
        _log(f"{job.key}: nothing to report")
        return 0
    issue = router.tracking_issue(job.mission_id)
    if issue is None:
        raise DispatchError(f"{job.mission_id} has no tracking issue to report on")
    run_url = os.environ.get("RUN_URL", "")
    gh.comment(int(issue["number"]), failure_comment(job, reason, run_url))
    _log(f"{job.key}: reported on #{issue['number']}: " + reason)
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="step", required=True)
    for name in ("plan", "due", "prepare", "publish", "report", "land"):
        sub.add_parser(name).add_argument("--repo", required=True)
    for name in ("checks", "prepare", "run", "collect", "publish"):
        (sub.choices.get(name) or sub.add_parser(name)).add_argument("--root", required=True)
    sub.choices["run"].add_argument("--timeout", type=float, default=3600.0)
    sub.choices["checks"].add_argument("--out", required=True)
    sub.choices["checks"].add_argument("--timeout", type=float, default=900.0)
    sub.choices["checks"].add_argument("--run-as", help="unprivileged account to run the checks as")
    sub.choices["prepare"].add_argument("--checks-report")
    sub.choices["collect"].add_argument("--out", required=True)
    sub.choices["publish"].add_argument("--artifact", required=True)
    sub.choices["report"].add_argument("--capacity", help="accepted for workflow compatibility; ignored")
    args = parser.parse_args(argv)
    steps = {"plan": cmd_plan, "due": cmd_due, "checks": cmd_checks, "prepare": cmd_prepare, "run": cmd_run, "collect": cmd_collect,
             "publish": cmd_publish, "report": cmd_report, "land": cmd_land}
    try:
        return steps[args.step](args)
    except DispatchError as exc:
        print(f"::error::{str(exc).splitlines()[0][:500]}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
