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
    publish, land          READ_TOKEN (the workflow's token), AGENT_TOKEN, AGENT_SLUG and APP_ID (the agent App;
                           APP_ID must be the registry's, Amendment 013)
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
from mission_router import substrate
from mission_router.router import MissionRouter, load_config
from router_spec002.policy import load_tables, normalize_path

from . import binding, blast, login, permissions, provenance, quarantine, registry, supply_chain
from .runtimes import BINARIES
from .dispatch import (
    REFUSAL_MAX_CHARS,
    DispatchError,
    key_problems,
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
    _quarantine_mode(load_config())
    network = None
    if args.run_as:  # §3h: the checks account's network is closed (or counted) before the first check
        try:
            network = blast.CheckNetwork(args.run_as, blast.mode(load_config()))
            _log(f"{job.key}: checks network {network.close()['network']} (blast radius {network.mode})")
        except blast.BlastError as exc:
            raise DispatchError(str(exc)) from None
    results = run_checks(job, Path(args.root), Path(args.out), os.environ, timeout=args.timeout, run_as=args.run_as,
                         network=network.report if network else None)
    _log(f"{job.key}: {sum(r['passed'] for r in results)} of {len(results)} checks passed")
    return 0


def _binding_mode(config: dict) -> str:
    try:
        return binding.mode(config)
    except binding.BindingError as exc:
        raise DispatchError(str(exc)) from None


def _permissions_mode(config: dict) -> str:
    """``"permissions"`` (§3k, ring 2); an unknown value fails the job."""
    try:
        value = permissions.mode(config)
    except permissions.PermissionsError as exc:
        raise DispatchError(str(exc)) from None
    _log(f"permissions: {value}")
    return value


def _quarantine_mode(config: dict) -> str:
    """``"quarantine"`` (§3j); an unknown value fails the job. Items 1 and 4 apply in both modes."""
    try:
        value = quarantine.mode(config)
    except quarantine.QuarantineError as exc:
        raise DispatchError(str(exc)) from None
    _log(f"quarantine: {value}")
    return value


def _supply_mode(config: dict) -> str:
    """``"supply_chain"`` (§3l, ring 4); an unknown value fails the job."""
    try:
        value = supply_chain.mode(config)
    except supply_chain.SupplyChainError as exc:
        raise DispatchError(str(exc)) from None
    _log(f"supply chain: {value}")
    return value


def _landing_verifier(config: dict, repo: str, token: str):
    """GitHub's record of a landing (rules G1-G4), with every login checked by account ID, as policy CI checks it."""
    from evidence_graph.github_record import verifier
    from mission_router.accounts import AccountGuard, GuardedGitHub, expected_accounts, identity_mode
    registry_path = Path(__file__).resolve().parents[3] / config["identity_registry"]
    guard = AccountGuard(identity_mode(config), _log)
    guard.expect(expected_accounts(config, registry_path.read_text(encoding="utf-8")
                                   if registry_path.is_file() else None))
    return verifier(GuardedGitHub(GitHub(token, repo), guard))


def cmd_provenance_fetch(args) -> int:
    """The plan job (§3l item 4): hand policy CI's newest verified evidence graph to this run's agent jobs. A
    failure is a warning: every landing is then "not checked", never "proven"."""
    config = load_config()
    try:
        source = provenance.fetch(GitHub(_env("GITHUB_TOKEN"), args.repo), _env("GITHUB_TOKEN"),
                                  config["default_branch"], Path(args.out))
    except (provenance.ProvenanceError, GitHubError, OSError, ValueError) as exc:
        _log(f"::warning::provenance: {str(exc)[:400]}")
        return 0
    _log(f"provenance: policy CI run {source['run_id']} at {source['run_head'][:12]} "
         f"(graph {source['graph_digest'][:12]}, artifact sha256 {source['artifact_sha256'][:12]})")
    return 0


def cmd_prepare(args) -> int:
    job = _job()
    config = load_config()
    _quarantine_mode(config)
    token = _env("GITHUB_TOKEN")
    binding_mode = _binding_mode(config)
    verify = None
    if binding_mode == binding.ENFORCE:
        try:
            verify = _landing_verifier(config, args.repo, token)
        except (OSError, ValueError) as exc:
            _log(f"::warning::provenance: no direct check of GitHub's record ({exc})")
    prepare(job, Path(args.root), CLONE_URL.format(repo=args.repo), token, os.environ, _home(args),
            config["default_branch"], Path(args.checks_report) if args.checks_report else None,
            binding_mode=binding_mode, permissions_mode=_permissions_mode(config),
            supply_mode=_supply_mode(config), verify=verify, log=_log,
            provenance_dir=Path(args.provenance) if args.provenance else None)
    _log(f"{job.key}: checkout ready at {job.base_sha}")
    return 0


def _home(args) -> Path:
    """The agent's home: its own account's under blast radius (§3h), else this account's."""
    return blast.agent_home(args.run_as) if args.run_as else Path.home()


def _blast_mode(config: dict) -> str:
    try:
        return blast.mode(config)
    except blast.BlastError as exc:
        raise DispatchError(str(exc)) from None


def cmd_blast_mode(args) -> int:
    """Print the blast-radius mode for the workflow (``mode=<observe|enforce>`` to GITHUB_OUTPUT)."""
    value = _blast_mode(load_config())
    _output("mode", value)
    _log(f"blast radius: {value}")
    return 0


def _login_mode(config: dict) -> str:
    """``"model_login"`` (§3i item 6, ring 1 amendment); an unknown value fails the job."""
    try:
        value = login.mode(config)
    except login.LoginError as exc:
        raise DispatchError(str(exc)) from None
    _log(f"model login: {value}")
    return value


def cmd_registry_check(args) -> int:
    """§3l item 2 (ring 4): the downloaded runtime package against its registry's signature, before it is installed.
    Under ``"supply_chain": "enforce"`` a failure stops the install; under ``"observe"`` it is a warning."""
    try:
        value = supply_chain.mode(load_config())
    except supply_chain.SupplyChainError as exc:
        raise DispatchError(str(exc)) from None
    table_path = Path(__file__).resolve().parents[1] / supply_chain.PINS_TABLE  # the tooling tree's, never the checkout's
    try:
        _, row = registry.pins_row(args.runtime, table_path)
        found = registry.verify(Path(args.package), row)
    except (registry.RegistryError, supply_chain.SupplyChainError, OSError) as exc:
        if value == supply_chain.ENFORCE:
            raise DispatchError(f"{args.runtime}: the registry signature check failed: {exc}") from None
        _log(f"::warning::{args.runtime}: the registry signature check failed: {exc}; observe: installing anyway")
        return 0
    _log(f"{args.runtime}: {found['package']}@{found['version']} verified against the registry's signature "
         f"(key {found['keyid']}, {found['integrity']} integrity; mode={value})")
    return 0


def cmd_run(args) -> int:
    job = _job()
    config = load_config()
    binaries = BINARIES
    if args.runtime_dir:
        binaries = {name: str(Path(args.runtime_dir) / binary) for name, binary in BINARIES.items()}
    log_path = run_agent(job, Path(args.root), os.environ, _home(args), timeout=args.timeout, binaries=binaries,
                         binding_mode=_binding_mode(config), blast_mode=_blast_mode(config),
                         run_as=args.run_as or None, login_mode=_login_mode(config), log=_log)
    _log(f"{job.key}: {job.runtime} finished (log: {log_path})")
    return 0


def cmd_collect(args) -> int:
    job = _job()
    config = load_config()
    result = collect(job, Path(args.root), Path(args.out), os.environ, quarantine_mode=_quarantine_mode(config),
                     log=_log, login_mode=_login_mode(config))
    _log(f"{job.key}: change accepted: {', '.join(result['paths'])}" + (f"; verdict {result['verdict']}" if result["verdict"] else ""))
    return 0


def check_key(router: MissionRouter, agent: str, login: str) -> None:
    """The App key this job holds must be the registered App's (Amendment 013, §3i item 1). Raises under
    ``"enforce"``, so nothing is pushed; logs under ``"observe"``."""
    registry = router.gh.file_at(router.registry_path, router.main)
    try:
        account = router.gh.account(login)
    except GitHubError as exc:
        account = {"error": str(exc)}
    problems = key_problems(agent, login, os.environ.get("APP_ID", ""), registry, account)
    if not problems:
        return
    reason = f"the App key is not {agent}'s registered App: " + "; ".join(problems)
    if router.identity_mode == "enforce":
        raise DispatchError(reason)
    _log(f"identity (observe): {reason}")


def cmd_publish(args) -> int:
    job = _job()
    read = GitHub(_env("READ_TOKEN"), args.repo)
    agent = GitHub(_env("AGENT_TOKEN"), args.repo)
    config = load_config()
    mode = _quarantine_mode(config)
    try:
        declared = substrate.declaration(config)
    except substrate.SubstrateError as exc:
        raise DispatchError(str(exc)) from None
    survey, router = live_survey(read, _log)
    check_key(router, job.agent, f"{_env('AGENT_SLUG')}[bot]")
    result = publish(job, survey, Path(args.artifact), Path(args.root), CLONE_URL.format(repo=args.repo),
                     _env("READ_TOKEN"), _env("AGENT_TOKEN"), f"{_env('AGENT_SLUG')}[bot]", os.environ,
                     agent.create_pull, os.environ.get("RUN_URL", ""),
                     checks_dir=Path(args.checks) if args.checks else None, quarantine_mode=mode, log=_log,
                     substrate_declared=declared)
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
    survey, router = live_survey(GitHub(_env("READ_TOKEN"), args.repo), _log)
    check_key(router, job.agent, f"{_env('AGENT_SLUG')}[bot]")
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
    gh.comment(int(issue["number"]), failure_comment(job, reason, run_url, read_refusals(args.refusal or [])))
    _log(f"{job.key}: reported on #{issue['number']}: " + reason)
    return 0


def read_refusals(paths) -> list:
    """The ``--refusal`` records the collect and publish steps left (missing ones are skipped)."""
    out = []
    for name in paths:
        path = Path(name)
        if path.is_file() and not path.is_symlink() and path.stat().st_size <= 64 * 1024:
            out.append(path.read_text(encoding="utf-8", errors="replace").strip())
    return out


def write_refusal(path: str, reason: str) -> None:
    """Record why a step refused, for the report job's failure record (vectors 67, 68)."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(reason[:REFUSAL_MAX_CHARS] + "\n", encoding="utf-8")


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
    sub.choices["prepare"].add_argument("--provenance", default="", help="policy CI's graph, handed over by plan")
    fetch = sub.add_parser("provenance-fetch")
    fetch.add_argument("--repo", required=True)
    fetch.add_argument("--out", required=True)
    sub.add_parser("blast-mode")
    check = sub.add_parser("registry-check")
    check.add_argument("--runtime", required=True)
    check.add_argument("--package", required=True)
    for name in ("prepare", "run"):
        sub.choices[name].add_argument("--run-as", default="", help="the agent's own account (blast radius, §3h)")
    sub.choices["run"].add_argument("--runtime-dir", default="", help="where the pinned runtimes are installed")
    sub.choices["collect"].add_argument("--out", required=True)
    sub.choices["publish"].add_argument("--artifact", required=True)
    sub.choices["publish"].add_argument("--checks", default="", help="the checks job's results (A3 PASS, §3j item 3)")
    for name in ("prepare", "run", "registry-check", "collect", "publish"):  # §3j item 10: every refusing step
        sub.choices[name].add_argument("--refusal", default="", help="where to record why this step refused")
    sub.choices["report"].add_argument("--refusal", action="append", help="a refusal record from collect or publish")
    sub.choices["report"].add_argument("--capacity", help="accepted for workflow compatibility; ignored")
    args = parser.parse_args(argv)
    steps = {"blast-mode": cmd_blast_mode, "registry-check": cmd_registry_check, "provenance-fetch": cmd_provenance_fetch, "plan": cmd_plan, "due": cmd_due, "checks": cmd_checks, "prepare": cmd_prepare, "run": cmd_run, "collect": cmd_collect,
             "publish": cmd_publish, "report": cmd_report, "land": cmd_land}
    try:
        return steps[args.step](args)
    except DispatchError as exc:
        print(f"::error::{str(exc).splitlines()[0][:500]}", file=sys.stderr)
        if getattr(args, "refusal", None) and isinstance(args.refusal, str):
            write_refusal(args.refusal, f"{args.step}: {exc}")  # the step is named in the report (§3j item 10)
        return 1


if __name__ == "__main__":
    sys.exit(main())
