"""CLI: one step of the Mission Agent workflow per call.

    PYTHONPATH=tools/agent_workflow python3 -m mission_dispatch plan    --repo OWNER/REPO
    PYTHONPATH=tools/agent_workflow python3 -m mission_dispatch due     --repo OWNER/REPO
    PYTHONPATH=tools/agent_workflow python3 -m mission_dispatch checks  --root TREE --out DIR
    PYTHONPATH=tools/agent_workflow python3 -m mission_dispatch prepare --repo OWNER/REPO --root DIR [--checks-report DIR]
    PYTHONPATH=tools/agent_workflow python3 -m mission_dispatch run     --root DIR
    PYTHONPATH=tools/agent_workflow python3 -m mission_dispatch collect --root DIR --out DIR
    PYTHONPATH=tools/agent_workflow python3 -m mission_dispatch publish --repo OWNER/REPO --root DIR --artifact DIR
    PYTHONPATH=tools/agent_workflow python3 -m mission_dispatch report  --repo OWNER/REPO
    PYTHONPATH=tools/agent_workflow python3 -m mission_dispatch perform --stage check  --repo OWNER/REPO --out DIR
    PYTHONPATH=tools/agent_workflow python3 -m mission_dispatch perform --stage call   --plan DIR --out DIR
    PYTHONPATH=tools/agent_workflow python3 -m mission_dispatch perform --stage report --repo OWNER/REPO \
        --plan DIR --out DIR

Environment, per step (each step gets only what it needs):
    plan, due, prepare, report
                           GITHUB_TOKEN (the workflow's own token; plan also reads this workflow's runs,
                           report also posts on the tracking issue)
    checks                 nothing: it runs the code under review, so it gets no credential
    publish, land          READ_TOKEN (the workflow's token), AGENT_TOKEN, AGENT_SLUG and APP_ID (the agent App;
                           APP_ID must be the registry's, Amendment 013)
    collect                the runtime's model login, only to refuse a change that contains it
    perform                check and report: GITHUB_TOKEN (the workflow's token: reads the missions, the run's
                           artifact, and comments on the tracking issue); call: only the listed apps' APP_KEY_<n>,
                           never a GitHub token (Amendment 032)
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
from typing import Callable, Optional, Tuple

from mission_router.github import GitHub, GitHubError
from mission_router.gate import classify_or_raise
from mission_router import landing as landing_mod
from mission_router import substrate
from mission_router.router import MissionRouter, load_config
from router_spec002.policy import load_tables, normalize_path

from . import binding, blast, login, perform, permissions, provenance, quarantine, registry, secscan, supply_chain
from .workspace import git_env
from evidence import producer as evidence_producer
from mcp_gateway import app_gateway as mcp_app_gateway
from .runtimes import BINARIES
from .dispatch import (
    BOUNDARY_OUT,
    CHECKS_JSON,
    MESSAGE_OUT,
    PATCH_FILE,
    REFUSAL_MAX_CHARS,
    RESULT_FILE,
    DispatchError,
    key_problems,
    busy_lanes,
    not_due,
    run_checks,
    landing_tree,
    baseline_due,
    run_baseline,
    Job,
    Survey,
    failure_feedback,
    failure_gate,
    hitl_note_text,
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
    record_issue,
    run_agent,
)

CLONE_URL = "https://github.com/{repo}.git"
WORKFLOW = "mission-agent.yml"
UNFINISHED = ("queued", "in_progress", "waiting", "pending", "requested")


def live_survey(gh: GitHub, log: Callable[[str], None], only: Optional[str] = None) -> Tuple[Survey, MissionRouter]:
    """The router's own read-only derivation of every unfinished mission (and the router that made it). With
    ``only``, of that one mission and no stack: what a lane's own check needs, at a fraction of the reads
    (Amendment 050)."""
    config = load_config()
    router = MissionRouter(gh, config, classify_or_raise(load_tables(), normalize_path), dry_run=True, log=log)
    contexts = router.survey(only)
    hitl = {login.casefold() for login in config["hitl_logins"]}
    blocked = failure_gate(router, config["bot_login"], hitl, log)
    try:
        stacks = router.stacks() if only is None else {}
    except GitHubError as exc:  # no landing this time; missions still run
        log(f"stacks could not be read, so no stack lands this time: {exc}")
        stacks = {}
    feedback = failure_feedback(router, config["bot_login"], hitl)

    def order(mission_id: str) -> int:  # the queue runs in approval order: tracking issues open when plans merge
        return int((router.tracking_issue(mission_id) or {}).get("number") or 10 ** 9)

    try:
        challenges = router.challenges_due(contexts)
    except GitHubError as exc:  # no AR this time; the other roles still run
        log(f"challenge loops could not be read, so no AR starts this time: {exc}")
        challenges = {}
    return Survey(contexts, router.identities(), gh.branch_head, config["default_branch"], blocked, stacks,
                  feedback, order, router.now(), challenges, hitl_note_text(router, hitl)), router


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
    runs = other_runs(gh, os.environ.get("GITHUB_RUN_ID", ""))
    busy, unknown = busy_lanes(runs)
    if unknown:
        _log("another run of this workflow is still starting its jobs; starting nothing now, the next run plans again")
        _output("count", "0")
        _output("matrix", json.dumps({"job": []}))
        _output("land_count", "0")
        _output("land_matrix", json.dumps({"land": []}))
        _output("scan_count", "0")
        _output("scan_matrix", json.dumps(secscan.scan_matrix([])))
        return 0
    survey, router = live_survey(gh, _log)
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
    scans = plan_scans(gh, router, runs)
    _output("scan_count", str(len(scans)))
    _output("scan_matrix", json.dumps(secscan.scan_matrix(scans), separators=(",", ":"), sort_keys=True))
    return 0


def _scan_mode(config: dict) -> str:
    """``"security_scan"`` (Amendment 036): ``"off"`` when absent; an unknown value fails the job."""
    try:
        return secscan.mode(config)
    except secscan.ScanError as exc:
        raise DispatchError(str(exc)) from None


def plan_scans(gh: GitHub, router: MissionRouter, runs: list) -> list:
    """The security scans due (Amendment 036): none while ``"security_scan"`` is ``"off"``. A target that cannot be
    read is left out this time; the next plan looks again."""
    if _scan_mode(load_config()) == secscan.OFF:
        return []
    try:
        jobs, notes = secscan.plan_scans(secscan.scan_targets(router), lambda sha: gh.check_runs(sha, secscan.CHECK_NAME),
                                         secscan.busy_scans(runs))
    except GitHubError as exc:
        _log(f"scan targets could not be read, so no scan starts this time: {exc}")
        return []
    for note in notes:
        _log(note)
    for job in jobs:
        _log(f"due: {job.name} ({job.kind} {job.subject}, into {job.base_ref})")
    return jobs


def _scan_job() -> "secscan.ScanJob":
    try:
        return secscan.ScanJob.from_dict(json.loads(_env("SCAN")))
    except ValueError:
        raise DispatchError("SCAN is not JSON") from None
    except secscan.ScanError as exc:
        raise DispatchError(str(exc)) from None


def cmd_scan_prepare(args) -> int:
    """Read token only: is the scan still due (the PR open at the same head), and a fresh clone at that head."""
    job = _scan_job()
    if _scan_mode(load_config()) == secscan.OFF:
        raise DispatchError("security_scan is off")
    token = _env("GITHUB_TOKEN")
    pr = GitHub(token, args.repo).get(f"/pulls/{job.pr}") or {}
    due = pr.get("state") == "open" and (pr.get("head") or {}).get("sha") == job.head_sha
    _output("due", "true" if due else "false")
    if not due:
        _log(f"{job.name}: the PR is closed or its head moved; nothing to scan")
        return 0
    try:
        base = secscan.prepare_checkout(job, Path(args.root), CLONE_URL.format(repo=args.repo),
                                        git_env(os.environ, token))
    except secscan.ScanError as exc:
        raise DispatchError(str(exc)) from None
    _log(f"{job.name}: checkout at {job.head_sha}; scanning from the merge base {base}")
    return 0


def cmd_scan(args) -> int:
    """No GitHub token: run the scanner, the proxy holding the key, and write ``result.json``. A scan that cannot
    run writes a failed result too, so the report job never reads silence as green."""
    job = _scan_job()
    root, out = Path(args.root), Path(args.out)
    code, base, error = None, "", ""
    try:
        config = load_config()
        if _scan_mode(config) == secscan.OFF:
            raise secscan.ScanError("security_scan is off")
        base = secscan.read_merge_base(root)
        table = supply_chain.read_pins(Path(__file__).resolve().parents[1] / supply_chain.PINS_TABLE)
        node = ((table.get("tools") or {}).get(secscan.TOOL) or {}).get("version", "")
        program = secscan.access_program(config)  # Amendment 041: absent asks for no program, as before
        code = secscan.run_scan(job, root, Path(args.tools), out, os.environ, _blast_mode(config), args.run_as,
                                node, base, timeout=args.timeout, log=_log, private=Path(args.private),
                                program=program)
    except (secscan.ScanError, DispatchError, supply_chain.SupplyChainError, OSError) as exc:
        error = str(exc) or type(exc).__name__
    failure = secscan.scanner_failure(root / secscan.SCAN_LOG) if code not in (0, None) else ""
    result = secscan.read_result(job, Path(args.private) / secscan.RESULTS_DIR, code, base, error, failure)
    secscan.write_result(out / secscan.RESULT_FILE, result)
    _NOTE.update(result=evidence_producer.text_digest(json.dumps(result, sort_keys=True)),
                 conclusion=result["conclusion"])
    _log(f"{job.name}: {result['conclusion']}: {result['reason']}")
    if error:
        raise DispatchError(error)
    return 0


def cmd_scan_report(args) -> int:
    """Set the ``security-scan`` check on the head and post the result through the quarantine. No result (the scan
    job failed before writing one) is a failure, never green."""
    job = _scan_job()
    gh = GitHub(_env("GITHUB_TOKEN"), args.repo)
    pr = gh.get(f"/pulls/{job.pr}") or {}
    if pr.get("state") != "open" or (pr.get("head") or {}).get("sha") != job.head_sha:
        _log(f"{job.name}: the PR is closed or its head moved; no check is set")
        return 0
    path = Path(args.result) / secscan.RESULT_FILE
    if path.is_file() and not path.is_symlink():
        parsed = secscan.parse_result(path.read_text(encoding="utf-8", errors="replace"), job)
    else:
        parsed = {"conclusion": "failure", "reason": "the scan job ended without a result", "findings": [],
                  "finding_count": 0}
    title, body = secscan.report_text(job, parsed, os.environ.get("RUN_URL", ""), _scan_mode(load_config()))
    gh.create_check_run(secscan.CHECK_NAME, job.head_sha, "completed", parsed["conclusion"], title, body)
    gh.comment(job.pr, body)
    _NOTE.update(comment=evidence_producer.text_digest(body), conclusion=parsed["conclusion"])
    _log(f"{job.name}: {secscan.CHECK_NAME} set to {parsed['conclusion']}: {title}")
    return 0


def cmd_due(args) -> int:
    """Whether the lane is still due, from a survey of its own mission (Amendment 050). When GitHub cannot be read,
    the lane does not run, and ``--not-started`` records why, so the report job records no failure: the agent never
    started, and the next plan starts it again."""
    job = _job()
    earlier = _not_started(getattr(args, "after", "") or "")
    if earlier:  # the checks job could not read GitHub: an A3 without its checks would only be refused
        _log(f"{job.key}: not running: the checks job did not start ({earlier}); the next run plans it again")
        if getattr(args, "not_started", ""):
            write_refusal(args.not_started, f"the checks job did not start: {earlier}")
        _output("due", "false")
        return 0
    try:
        survey, _ = live_survey(GitHub(_env("GITHUB_TOKEN"), args.repo), _log, only=job.mission_id)
        reason = not_due(job, survey)
    except GitHubError as exc:
        _log(f"{job.key}: not running: GitHub could not be read ({exc}); the next run plans it again")
        if getattr(args, "not_started", ""):
            write_refusal(args.not_started, f"GitHub could not be read: {exc}")
        _output("due", "false")
        return 0
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
    landing = None
    commands = _landing_checks(load_config())
    if commands and job.role == "A3":  # Amendment 048: the landing branch's own checks, on the merged tree
        info = {"branch": job.landing_branch, "head": "", "merged": False, "error": "the landing tree was not built"}
        if args.landing_info and Path(args.landing_info).is_file() and not Path(args.landing_info).is_symlink():
            try:
                read = json.loads(Path(args.landing_info).read_text(encoding="utf-8"))
                if isinstance(read, dict) and read.get("branch") == job.landing_branch:
                    info = {k: read.get(k) for k in ("branch", "head", "merged", "error")}
            except (OSError, ValueError):
                pass
        landing = {**info, "commands": commands, "root": args.landing_root or ""}
        if info["merged"] is True and not args.landing_root:
            landing["merged"], landing["error"] = False, "no landing tree was handed to the checks"
    results = run_checks(job, Path(args.root), Path(args.out), os.environ, timeout=args.timeout, run_as=args.run_as,
                         network=network.report if network else None, landing=landing)
    _log(f"{job.key}: {sum(r['passed'] for r in results)} of {len(results)} checks passed")
    if landing is not None:
        _log(f"{job.key}: landing checks on {job.landing_branch}: "
             + ("ran" if landing["merged"] is True else f"not run ({landing['error']})"))
    return 0


def _landing_checks(config: dict) -> tuple:
    try:
        return landing_mod.checks(config)
    except ValueError as exc:
        raise DispatchError(str(exc)) from None


def cmd_landing_tree(args) -> int:
    """Amendment 048: the commit under review merged onto its landing branch, for the landing checks. Nothing is built
    when ``config.json`` names no ``landing_checks``, or for a job that is not A3."""
    job = _job()
    if job.role != "A3" or not _landing_checks(load_config()):
        _log(f"{job.key}: no landing checks")
        return 0
    info = landing_tree(Path(args.review), Path(args.out), job.landing_branch, os.environ)
    Path(args.info).write_text(json.dumps(info) + "\n", encoding="utf-8")
    _log(f"{job.key}: landing tree onto {job.landing_branch} at {info['head'] or 'unknown'}: "
         + ("merged" if info["merged"] else f"not merged ({info['error']})"))
    return 0


def cmd_baseline_due(args) -> int:
    """Amendment 052: outputs ``due`` and ``head``: whether a landing check failed on the merged tree, and the landing
    branch's head the baseline job checks out to run it again alone."""
    job = _job()
    head, failed = baseline_due(job, Path(args.checks), _landing_checks(load_config()))
    _output("due", "true" if failed else "false")
    _output("head", head)
    _log(f"{job.key}: " + (f"{len(failed)} failed landing check(s) to run again on {job.landing_branch} at {head}"
                           if failed else "no failed landing check to run again"))
    return 0


def cmd_baseline(args) -> int:
    """Amendment 052: run the failed landing checks again on the landing branch's head alone (``--root``), as the
    unprivileged checks account, in a job where no code under review has run."""
    job = _job()
    record = run_baseline(job, Path(args.root), Path(args.checks), Path(args.out), os.environ,
                          _landing_checks(load_config()), run_as=args.run_as)
    failing = sum(1 for r in record["results"] if not r["passed"])
    _log(f"{job.key}: {failing} of {len(record['results'])} failed landing check(s) fail on "
         f"{job.landing_branch} alone too")
    return 0


def _binding_mode(config: dict) -> str:
    try:
        return binding.mode(config)
    except binding.BindingError as exc:
        raise DispatchError(str(exc)) from None


def _app_mode(config: dict) -> str:
    """``"app_gateway"`` (Amendment 027): ``"off"`` when absent; an unknown value fails the job."""
    try:
        return binding.app_mode(config)
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
            provenance_dir=Path(args.provenance) if args.provenance else None, app_mode=_app_mode(config),
            landing_checks=_landing_checks(config))
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


def cmd_tree_install(args) -> int:
    """Amendment 034: install a pinned tool (``--tool``) or package tree (``--tree``) from the tooling tree's
    ``pins.json`` into ``--dest``. Always fails closed: there is no unchecked install to fall back to."""
    from mission_dispatch import tree as tree_mod
    table_path = Path(__file__).resolve().parents[1] / supply_chain.PINS_TABLE  # the tooling tree's, never the checkout's
    try:
        table = supply_chain.read_pins(table_path)
        if args.tool:
            row = (table.get("tools") or {}).get(args.tool)
            if row is None:
                raise DispatchError(f"pins.json pins no tool {args.tool!r}")
            top = tree_mod.install_tool(row, Path(args.dest))
            _log(f"tool {args.tool} {row['version']}: SHA-256 checked, unpacked at {top}")
        else:
            row = (table.get("trees") or {}).get(args.tree)
            if row is None:
                raise DispatchError(f"pins.json pins no tree {args.tree!r}")
            tree_mod.install_tree(row, Path(args.dest), log=_log)
    except (tree_mod.TreeError, supply_chain.SupplyChainError, OSError) as exc:
        raise DispatchError(f"the pinned install failed: {exc}") from None
    return 0


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
                     substrate_declared=declared, landing_checks=_landing_checks(config))
    if result["status"] == "skipped":
        _log(f"{job.key}: not published: {result['reason']}")
    else:
        _log(f"{job.key}: opened PR #{result['pr_number']} into {result['base']} as {job.login}: {result['pr_url']}")
        _NOTE.update(pr=result["pr_number"], commit=result["commit"])
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


DRAFTS_MARKER = "<!-- mission-dispatch:drafts:{digest}:{run}:{mission}:{role}:{round} -->"


def drafts_comment(job, doc: dict, digest: str, run_id: str) -> str:
    """The tracking issue's comment for a run's drafted list (Amendment 031): each call's app, tool and class, and its
    arguments as escaped JSON in a quarantined block, with the list's digest and the command that performs it.

    The arguments are shown with every non-ASCII character and backtick escaped, so what HITL reads is exactly what is
    performed and a hidden character shows as its escape. A ``/mission`` line in them is broken (§3j)."""
    calls = doc["calls"]
    lines = [DRAFTS_MARKER.format(digest=digest, run=run_id, mission=job.mission_id, role=job.role, round=job.round),
             f"**{job.mission_id} {job.role} round {job.round} drafted {len(calls)} app "
             f"call{'s' if len(calls) != 1 else ''}.** Nothing has been sent, deleted or written in an app. The calls "
             "are made only if HITL performs this exact list, in this order.", ""]
    for n, call in enumerate(calls, 1):
        shown = json.dumps(call["arguments"], sort_keys=True, indent=1, ensure_ascii=True).replace("`", "\\u0060")
        held = quarantine.quarantine(shown, f"the {job.role} agent", f"drafted call {n} of run {run_id}",
                                     4 * mcp_app_gateway.MAX_DRAFT_ARGUMENTS, github=True)
        lines += [f"**Call {n}:** `{call['action']}` with tool `{call['tool']}` in app `{call['app']}` "
                  f"(resource `{call['resource']}`). Its arguments:", "", held.text, ""]
    lines += ["To perform exactly these calls, a HITL login comments on its own line:", "",
              "```", f"/mission perform {digest}", "```", "",
              "A list that changed has another digest, so a command for this one performs nothing else."]
    return "\n".join(lines)


def post_drafts(gh, router, job, path: str) -> None:
    """Post the run's drafted list, when it has one (Amendment 031). A malformed list is reported, never posted."""
    if not path or not Path(path).exists():
        return
    issue = record_issue(router, job.mission_id, job.role)
    if issue is None:
        raise DispatchError(f"{job.mission_id} has drafted calls and no tracking issue to post them on")
    try:
        doc, digest = mcp_app_gateway.read_drafts(path)
    except mcp_app_gateway.GatewayError as exc:
        text = (f"**{job.mission_id} {job.role} round {job.round}: the run's drafted list is malformed** "
                f"({quarantine.inline(str(exc), 200)}). It is not posted and cannot be performed.")
    else:
        text = drafts_comment(job, doc, digest, os.environ.get("GITHUB_RUN_ID", ""))
        _NOTE.update(drafts=evidence_producer.text_digest(digest))
    _NOTE.update(drafts_comment=evidence_producer.text_digest(text))
    gh.comment(int(issue["number"]), text)
    _log(f"{job.key}: drafted list reported on #{issue['number']}")


def cmd_report(args) -> int:
    job = _job()
    not_started = _not_started(getattr(args, "not_started", "") or "")
    if not_started:  # the lane's own check could not read GitHub: no agent ran, so no failure is recorded
        _log(f"{job.key}: not started ({not_started}); nothing recorded, the next run plans it again")
        return 0
    gh = GitHub(_env("GITHUB_TOKEN"), args.repo)
    survey, router = live_survey(gh, _log, only=job.mission_id)
    post_drafts(gh, router, job, getattr(args, "drafts", "") or "")
    reason = outcome(job, survey, gh.pulls_from)
    if reason is None:
        _log(f"{job.key}: nothing to report")
        return 0
    issue = record_issue(router, job.mission_id, job.role)  # AR: the plan PR (§3n)
    if issue is None:
        raise DispatchError(f"{job.mission_id} has no {'plan PR' if job.role == 'AR' else 'tracking issue'} to report on")
    run_url = os.environ.get("RUN_URL", "")
    text = failure_comment(job, reason, run_url, read_refusals(args.refusal or []))
    _NOTE.update(comment=evidence_producer.text_digest(text))
    post_once(gh, int(issue["number"]), text)
    _log(f"{job.key}: reported on #{issue['number']}: " + reason)
    return 0


def post_once(gh: GitHub, number: int, text: str, tries: int = 3) -> None:
    """Post a failure record so that it is there exactly once (Amendment 051, dispatcher audit F23). The record is
    what counts toward the three failures that block a stage: one that is lost lets the lane run again and again,
    one posted twice counts twice. A post that ends with no HTTP answer, or a 5xx, may have been made: the issue is
    read, and the record posted again only when it is not there. The run's URL makes each record's text unique."""
    for attempt in range(tries):
        try:
            gh.comment(number, text)
            return
        except GitHubError as exc:
            if exc.status not in (0, 500, 502, 503, 504) or attempt == tries - 1:
                raise
            _log(f"posting on #{number} failed ({exc}); looking whether it was posted")
        posted = _same_text(text)
        if any(_same_text(c.get("body") or "") == posted for c in gh.paginate(f"/issues/{number}/comments", limit=1000)):
            return


def _same_text(text: str) -> str:
    return text.replace("\r\n", "\n").strip()


def _not_started(path: str) -> str:
    """The reason a ``due`` step recorded for not starting the lane (Amendment 050), or "" when there is none."""
    if not path:
        return ""
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        return ""
    return quarantine.inline(p.read_text(encoding="utf-8", errors="replace").strip(), 300)


def _perform_record(recorder, comment: dict, mission: str, round_n: int, result: str, reason: str, text: str,
                    hitl: set) -> None:
    """One ``dispatch.perform`` record (``decide``) for one command (Amendment 032): its digest as input."""
    login_name = str((comment.get("user") or {}).get("login", ""))
    try:
        digest = perform.command_digest(comment)
    except perform.PerformError:
        digest = ""
    by_hitl = (comment.get("user") or {}).get("type") == "User" and login_name.casefold() in hitl
    recorder.record(actor=DISPATCH_ACTOR, account_id=None, action="dispatch.perform", result=result, reason=reason,
                    inputs={"list": digest} if digest else {},
                    outputs={"comment": evidence_producer.text_digest(text)}, mission=mission, round_n=round_n,
                    authority_kind="hitl_command" if by_hitl else "spec_rule",
                    authority_ref=f"/mission perform by {login_name} (comment {comment.get('id')})")


def perform_check(args) -> int:
    """``perform --stage check``: answer every unanswered ``/mission perform``; claim and plan the first that passes."""
    token = _env("GITHUB_TOKEN")
    gh = GitHub(token, args.repo)
    config = load_config()
    router = MissionRouter(gh, config, classify_or_raise(load_tables(), normalize_path), dry_run=True, log=_log)
    hitl = {login_name.casefold() for login_name in config["hitl_logins"]}
    bot, app_mode = config["bot_login"], _app_mode(config)
    recorder = evidence_producer.Recorder.from_env(os.environ)

    def download(url: str) -> bytes:
        if not url.startswith("https://api.github.com/"):
            raise perform.PerformError("the artifact's download address is not GitHub's API")
        try:
            return provenance._download(url, token)
        except provenance.ProvenanceError as exc:
            raise DispatchError(f"the drafts artifact could not be downloaded: {exc}") from None

    planned = None
    for mid, ctx in sorted(router.survey().items()):
        issue = router.tracking_issue(mid)
        if issue is None:
            continue
        comments = router.issue_comments(issue["number"])
        answered = perform.handled(comments, bot)
        for comment in perform.commands(comments):
            if comment["id"] in answered:
                continue
            try:
                if planned is not None:
                    raise perform.PerformError("another list is performed in this run; give the command again")
                plan = perform.check_command(comment, mid, ctx.state.stage, comments, hitl, bot, app_mode, gh,
                                             download, config["default_branch"])
            except perform.PerformError as exc:
                text = perform.refusal_text(comment, str(exc))
                gh.comment(int(issue["number"]), text)
                _perform_record(recorder, comment, mid, ctx.state.round, "refused", str(exc), text, hitl)
                _log(f"{mid}: /mission perform (comment {comment['id']}) refused: {exc}")
                continue
            text = perform.claim_text(plan)
            gh.comment(int(issue["number"]), text)  # the claim, before any call is made
            plan["issue"] = int(issue["number"])
            perform.write_json(Path(args.out) / perform.PLAN_FILE, plan)
            planned = plan
            _perform_record(recorder, comment, mid, plan["round"], "done",
                            f"accepted: {len(plan['list']['calls'])} calls to perform", text, hitl)
            _log(f"{mid}: /mission perform (comment {comment['id']}) accepted for list {plan['digest'][:12]}")
    _output("perform", "true" if planned else "false")
    return 0


def perform_call(args) -> int:
    """``perform --stage call``: make the planned calls; no GitHub credential is read here."""
    path = Path(args.plan) / perform.PLAN_FILE
    if not path.is_file():
        _log("nothing to perform")
        return 0
    try:
        plan = perform.read_plan(path)
    except perform.PerformError as exc:
        raise DispatchError(str(exc)) from None
    result = perform.make_calls(plan, Path(args.out), os.environ)
    perform.write_json(Path(args.out) / perform.OUTCOME_FILE, result)
    _log(f"performed {len(result['performed'])} of {len(plan['list']['calls'])} calls")
    return 0


def perform_report(args) -> int:
    """``perform --stage report``: post the outcome and record each call with HITL's command as its authority."""
    path = Path(args.plan) / perform.PLAN_FILE
    if not path.is_file():
        return 0
    try:
        plan = perform.read_plan(path)
    except perform.PerformError as exc:
        raise DispatchError(str(exc)) from None
    gh = GitHub(_env("GITHUB_TOKEN"), args.repo)
    result = perform.read_outcome(Path(args.out) / perform.OUTCOME_FILE, plan)
    text = perform.outcome_text(plan, result, os.environ.get("RUN_URL", ""))
    gh.comment(int(plan["issue"]), text)
    recorder = evidence_producer.Recorder.from_env(os.environ)
    sha = os.environ.get("GITHUB_SHA", "")
    base = dict(mission=plan["mission"], round_n=plan["round"],
                commit=sha if len(sha) == 40 and all(c in "0123456789abcdef" for c in sha) else None,
                authority_kind="hitl_command",
                authority_ref=f"/mission perform {plan['digest']} by {plan['command']['login']} "
                              f"(comment {plan['command']['id']})")
    log = binding.binding_dir(Path(args.out)) / binding.APP_EVIDENCE_DIR / mcp_app_gateway.DECISIONS_FILE
    if log.is_file():
        record_harness_calls(recorder, log, base)
    recorder.record(actor=DISPATCH_ACTOR, account_id=None, action="dispatch.report", result="done",
                    reason=f"the outcome of list {plan['digest'][:12]}",
                    outputs={"comment": evidence_producer.text_digest(text)}, **base)
    return 0


def cmd_perform(args) -> int:
    return {"check": perform_check, "call": perform_call, "report": perform_report}[args.stage](args)


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


# What a step learned that its record carries (§3m item 1): publish's PR and commit, report's comment digest.
_NOTE: dict = {}
STEP_ACTIONS = {"prepare": "dispatch.prepare", "run": "dispatch.run", "collect": "dispatch.collect",
                "publish": "dispatch.publish", "report": "dispatch.report", "registry-check": "dispatch.refusal"}
SCAN_ACTIONS = {"scan": "dispatch.scan", "scan-report": "dispatch.scan_report"}  # Amendment 036
DISPATCH_ACTOR, CHECKS_ACTOR, GATEWAY_ACTOR, EGRESS_ACTOR = "mission-dispatch", "mission-checks", "mcp-gateway", "egress-proxy"
APP_GATEWAY_ACTOR = "app-gateway"
HARNESS_KINDS = ("read", "write", "send", "delete")  # a harness call is recorded as harness.<kind> (Amendment 030)
HARNESS_ENTRIES = ("refusal", "bound", "decision", "harness", "result_error", "result", "boundary", "draft",
                   "draft_refused")


def _hex64(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def harness_calls(log: Path):
    """The app gateway's kept log (``binding/app-decisions.jsonl``) as one ``(action, result, reason, inputs,
    outputs)`` per call, in the order the calls began (Amendment 030).

    A call's lines share its ``request_id``. Its class is the ``kind`` its ``decision`` or ``bound`` line names; a
    call of a tool not in the catalog has none and is ``harness.refusal``. Its result is its last outcome: refused
    for a DENY, a bound, a harness that is not run or a result the secrets boundary withheld; failed for a harness
    that failed, or an ALLOW the log never finishes; done for a result. Inputs are the app's, the tool's and the
    arguments' digests; outputs each line's digest, and the result's digest when there is one."""
    calls = {}
    for n, line, entry in evidence_producer.log_lines(log):
        if not isinstance(entry, dict) or entry.get("entry") not in HARNESS_ENTRIES:
            continue  # catalog_pin, and anything else, is not a call
        kind = entry["entry"]
        rid = entry.get("request_id")
        key = rid if isinstance(rid, str) and rid else f"line-{n}"
        call = calls.get(key)
        if call is None:
            call = calls[key] = {"tool": str(entry.get("tool", "")), "app": str(entry.get("app", "")),
                                 "kind": None, "result": "failed", "outcome": "no outcome logged",
                                 "inputs": {}, "outputs": {}}
        call["outputs"][f"{kind}_line"] = evidence_producer.text_digest(line)
        if entry.get("app") and not call["app"]:
            call["app"] = str(entry["app"])
        if entry.get("kind") in HARNESS_KINDS:
            call["kind"] = entry["kind"]
        if kind == "decision" and entry.get("draft") is True:
            call["draft"] = True  # a draft tool's call (Amendment 031): it writes the drafted list, never the app
        if kind == "refusal":
            call.update(result="refused", outcome="not in the catalog")
        elif kind == "bound":
            call.update(result="refused", outcome=str(entry.get("reason", "over the run's bounds")))
        elif kind == "decision":
            record = entry.get("record") if isinstance(entry.get("record"), dict) else {}
            disposition = str(record.get("disposition", "?"))
            if disposition == "ALLOW":
                call.update(result="failed", outcome="ALLOW, and no result logged")
            else:
                call.update(result="refused", outcome=disposition)
            if _hex64(entry.get("arguments_sha256")):
                call["inputs"]["arguments"] = entry["arguments_sha256"]
        elif kind == "harness":
            call.update(result="refused", outcome=f"harness not run: {entry.get('reason', '')}")
        elif kind == "result_error":
            call.update(result="failed", outcome=f"harness failed: {entry.get('detail') or entry.get('reason', '')}")
        elif kind == "result":
            call.update(result="done", outcome=f"ALLOW, {entry.get('requests', 0)} requests")
            if _hex64(entry.get("result_sha256")):
                call["outputs"]["result"] = entry["result_sha256"]
        elif kind == "draft":
            call.update(result="done", outcome=f"drafted as call {entry.get('index', '?')} of the run's list")
        elif kind == "draft_refused":
            call.update(result="refused", outcome=f"not drafted: {entry.get('reason', '')}")
        elif kind == "boundary":
            record = entry.get("record") if isinstance(entry.get("record"), dict) else {}
            if record.get("allow") is not True:
                call.update(result="refused", outcome="the secrets boundary withheld the result")
    for call in calls.values():
        action = ("harness.draft" if call.get("draft") and call["kind"] else
                  f"harness.{call['kind']}" if call["kind"] else "harness.refusal")
        if action == "harness.refusal":
            call["result"] = "refused"
        inputs = {"app": evidence_producer.text_digest(call["app"]),
                  "tool": evidence_producer.text_digest(call["tool"]), **call["inputs"]}
        yield action, call["result"], f"{call['app']} {call['tool']}".strip() + f": {call['outcome']}", inputs, \
            call["outputs"]


def record_harness_calls(recorder, log: Path, base: dict) -> int:
    """One record per harness call (``harness_calls``), up to ``LOG_RECORDS_MAX``; past that, one ``dispatch.collect``
    record gives the count and the whole log's digest. Returns how many calls were recorded one by one."""
    written = skipped = 0
    for action, result, reason, inputs, outputs in harness_calls(log):
        if written >= evidence_producer.LOG_RECORDS_MAX:
            skipped += 1
            continue
        if recorder.record(actor=APP_GATEWAY_ACTOR, account_id=None, action=action, result=result, reason=reason,
                           inputs=inputs, outputs=outputs, **base) is None:
            return written
        written += 1
    if skipped:
        recorder.record(actor=DISPATCH_ACTOR, account_id=None, action="dispatch.collect", result="done",
                        reason=f"{skipped} more harness calls of {log.name} not recorded one by one "
                               f"(limit {evidence_producer.LOG_RECORDS_MAX})",
                        outputs={log.name: evidence_producer.file_digest(log)}, **base)
    return written


def record_scan(recorder, step: str, result: str, reason: str) -> None:
    """The scan's records (Amendment 036): ``dispatch.scan`` (``decide``) with the result's digest, and
    ``dispatch.scan_report`` (``send``) with the comment's. Never fails the step."""
    try:
        job = _scan_job()
    except DispatchError:
        return
    outputs = {k: _NOTE[k] for k in ("result", "comment") if _NOTE.get(k)}
    recorder.record(actor=DISPATCH_ACTOR, account_id=None, action=SCAN_ACTIONS[step], result=result,
                    reason=reason or f"{secscan.CHECK_NAME}: {_NOTE.get('conclusion', result)}", outputs=outputs,
                    mission=job.subject if job.kind == "mission" else None, pr=job.pr, commit=job.head_sha,
                    authority_kind="spec_rule", authority_ref=f"SECURITY-SCAN-SPEC-001 §3, {job.kind} {job.subject}")


def record_step(recorder, args, result: str, reason: str) -> None:
    """This step's records (§3m item 1, ring 6 part 2): one for the step, with the digests of what it wrote; under
    ``checks``, one per check; after ``collect``, one per gateway decision and per egress decision. Never fails
    the step (``"evidence": "observe"``)."""
    step = args.step
    if step in SCAN_ACTIONS:
        if recorder.enabled:
            record_scan(recorder, step, result, reason)
        return
    if not recorder.enabled or (step not in STEP_ACTIONS and step != "checks"):
        return
    if step == "registry-check" and result == "done":
        return  # only its refusal is recorded; a passed check shows in prepare's run
    try:
        job = _job()
    except DispatchError:
        return
    base = dict(mission=job.mission_id, round_n=job.round, commit=job.build_sha or job.base_sha,
                authority_kind="plan", authority_ref=f"{job.mission_id} {job.role} round {job.round}")
    root = Path(getattr(args, "root", "") or ".")
    if step == "checks":
        path = Path(args.out) / CHECKS_JSON
        try:
            results = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else []
        except ValueError:
            results = []
        for r in results if isinstance(results, list) else []:
            if not isinstance(r, dict):
                continue
            code = r.get("exit_code")
            recorder.record(actor=CHECKS_ACTOR, account_id=None, action="checks.check",
                            result="done" if r.get("passed") else "failed",
                            reason=f"check {r.get('index')}: exit {code if code is not None else 'not run'}",
                            outputs={"command": evidence_producer.text_digest(str(r.get("command", ""))),
                                     "output": evidence_producer.text_digest(str(r.get("output_tail", "")))},
                            **base)
        return
    outputs = {}
    if step == "prepare":
        outputs = evidence_producer.file_digests(root / binding.BINDING_DIR,
                                                 [binding.BINDING_FILE, provenance.RECORD_FILE])
        if job.notes:  # HITL's notes the agent was given (Amendment 025), by digest
            outputs["hitl_notes"] = evidence_producer.text_digest(job.notes)
    elif step == "run":
        outputs = evidence_producer.file_digests(root, ["agent.log", blast.EGRESS_LOG])
    elif step == "collect":
        out = Path(args.out)
        outputs = evidence_producer.file_digests(out, [PATCH_FILE, MESSAGE_OUT, BOUNDARY_OUT, RESULT_FILE,
                                                       f"{binding.OUT_DIR}/{binding.BINDING_FILE}",
                                                       f"{binding.OUT_DIR}/gateway-evidence.jsonl",
                                                       f"{binding.OUT_DIR}/{binding.APP_DECISIONS_OUT}",
                                                       f"{binding.OUT_DIR}/{binding.APP_DRAFTS_OUT}",
                                                       blast.EGRESS_LOG])
    elif step == "publish":
        outputs = {"commit": evidence_producer.text_digest(str(_NOTE["commit"]))} if _NOTE.get("commit") else {}
    elif step == "report":
        outputs = {k: _NOTE[k] for k in ("comment", "drafts_comment", "drafts") if _NOTE.get(k)}
    actor = job.login if step == "publish" and job.login else DISPATCH_ACTOR
    pr = _NOTE.get("pr") if step == "publish" else None
    recorder.record(actor=actor, account_id=None, action=STEP_ACTIONS[step], result=result,
                    reason=reason or result, outputs=outputs, pr=pr or None, **base)
    if step == "collect":
        out = Path(args.out)
        gateway_log = out / binding.OUT_DIR / "gateway-evidence.jsonl"
        logs = [gateway_log] if gateway_log.is_file() else sorted((binding.binding_dir(root) / binding.EVIDENCE_DIR)
                                                                   .glob("*.jsonl"))
        for log in logs:
            recorder.from_log(log, "gateway.tool", GATEWAY_ACTOR, evidence_producer.gateway_result, base)
        app_log = out / binding.OUT_DIR / binding.APP_DECISIONS_OUT
        for log in [app_log] if app_log.is_file() else sorted((binding.binding_dir(root) / binding.APP_EVIDENCE_DIR)
                                                               .glob("*.jsonl")):
            record_harness_calls(recorder, log, base)
        egress_log = out / blast.EGRESS_LOG if (out / blast.EGRESS_LOG).is_file() else root / blast.EGRESS_LOG
        recorder.from_log(egress_log, "dispatch.egress", EGRESS_ACTOR, evidence_producer.egress_result, base)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="step", required=True)
    for name in ("plan", "due", "prepare", "publish", "report", "land"):
        sub.add_parser(name).add_argument("--repo", required=True)
    for name in ("checks", "prepare", "run", "collect", "publish"):
        (sub.choices.get(name) or sub.add_parser(name)).add_argument("--root", required=True)
    sub.choices["run"].add_argument("--timeout", type=float, default=3600.0)
    sub.choices["checks"].add_argument("--out", required=True)
    for name in ("due", "report"):  # Amendment 050: a lane not started because GitHub could not be read
        sub.choices[name].add_argument("--not-started", default="", help="where due records why the lane did not start")
    sub.choices["due"].add_argument("--after", default="", help="the checks job's not-started record, if any")
    sub.choices["checks"].add_argument("--timeout", type=float, default=900.0)
    sub.choices["checks"].add_argument("--run-as", help="unprivileged account to run the checks as")
    sub.choices["checks"].add_argument("--landing-root", default="", help="the landing tree (Amendment 048)")
    sub.choices["checks"].add_argument("--landing-info", default="", help="landing-tree's record (Amendment 048)")
    due_base = sub.add_parser("baseline-due", help="the failed landing checks to run again alone (Amendment 052)")
    due_base.add_argument("--checks", required=True, help="the checks job's results")
    base = sub.add_parser("baseline", help="run the failed landing checks on the landing branch alone (Amendment 052)")
    base.add_argument("--root", required=True, help="a checkout of the landing branch's head")
    base.add_argument("--checks", required=True, help="the checks job's results")
    base.add_argument("--out", required=True)
    base.add_argument("--run-as", help="unprivileged account to run the checks as")
    tree = sub.add_parser("landing-tree", help="the commit under review merged onto its landing branch (Amendment 048)")
    tree.add_argument("--review", required=True)
    tree.add_argument("--out", required=True)
    tree.add_argument("--info", required=True)
    sub.choices["prepare"].add_argument("--checks-report")
    sub.choices["prepare"].add_argument("--provenance", default="", help="policy CI's graph, handed over by plan")
    fetch = sub.add_parser("provenance-fetch")
    fetch.add_argument("--repo", required=True)
    fetch.add_argument("--out", required=True)
    sub.add_parser("blast-mode")
    install = sub.add_parser("tree-install")
    which = install.add_mutually_exclusive_group(required=True)
    which.add_argument("--tool")
    which.add_argument("--tree")
    install.add_argument("--dest", required=True)
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
    sub.choices["report"].add_argument("--drafts", default="", help="the run's drafted list (Amendment 031)")
    scan_prep = sub.add_parser("scan-prepare", help="the security scan's checkout (Amendment 036)")
    scan_prep.add_argument("--repo", required=True)
    scan_prep.add_argument("--root", required=True)
    scanning = sub.add_parser("scan", help="the security scan itself, no GitHub token (Amendment 036)")
    scanning.add_argument("--root", required=True)
    scanning.add_argument("--tools", required=True, help="where tree-install put Node and the scanner")
    scanning.add_argument("--out", required=True)
    scanning.add_argument("--run-as", default="", help="the agent's own account (blast radius, §3h)")
    scanning.add_argument("--timeout", type=float, default=secscan.SCAN_TIMEOUT)
    scanning.add_argument("--private", default=secscan.PRIVATE,
                          help="root-owned area for the scanner's state and output (Amendment 038)")
    scan_report = sub.add_parser("scan-report", help="the security-scan check and comment (Amendment 036)")
    scan_report.add_argument("--repo", required=True)
    scan_report.add_argument("--result", required=True, help="the scan job's result folder")
    performing = sub.add_parser("perform", help="HITL's /mission perform (Amendment 032)")
    performing.add_argument("--stage", required=True, choices=("check", "call", "report"))
    performing.add_argument("--repo", default="")
    performing.add_argument("--out", required=True, help="the stage's work folder")
    performing.add_argument("--plan", default="", help="where check wrote the plan")
    args = parser.parse_args(argv)
    steps = {"blast-mode": cmd_blast_mode, "tree-install": cmd_tree_install, "registry-check": cmd_registry_check, "provenance-fetch": cmd_provenance_fetch, "plan": cmd_plan, "due": cmd_due, "checks": cmd_checks, "landing-tree": cmd_landing_tree, "baseline-due": cmd_baseline_due, "baseline": cmd_baseline, "prepare": cmd_prepare, "run": cmd_run, "collect": cmd_collect,
             "publish": cmd_publish, "report": cmd_report, "land": cmd_land, "perform": cmd_perform,
             "scan-prepare": cmd_scan_prepare, "scan": cmd_scan, "scan-report": cmd_scan_report}
    recorder = evidence_producer.Recorder.from_env(os.environ)
    _NOTE.clear()
    try:
        code = steps[args.step](args)
    except DispatchError as exc:
        print(f"::error::{str(exc).splitlines()[0][:500]}", file=sys.stderr)
        if getattr(args, "refusal", None) and isinstance(args.refusal, str):
            write_refusal(args.refusal, f"{args.step}: {exc}")  # the step is named in the report (§3j item 10)
        record_step(recorder, args, "refused", f"{args.step}: {exc}")
        return 1
    except Exception as exc:
        record_step(recorder, args, "failed", f"{args.step}: {type(exc).__name__}")
        raise
    record_step(recorder, args, "done" if code == 0 else "failed", "")
    return code


if __name__ == "__main__":
    sys.exit(main())
