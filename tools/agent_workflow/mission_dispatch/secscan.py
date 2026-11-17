"""The security scan's job (SECURITY-SCAN-SPEC-001 build part 3; MISSION-DISPATCH-001 §3q, Amendment 036).

A scan is due for each open PR ``scan_targets`` reads from the router's survey (an A3 PR into a landing branch whose
verdict is PASS, or a stack's landing PR) whose head has no ``security-scan`` check run yet. The ``secscan`` job of
``mission-agent.yml`` runs it in three steps, so no step holds both the GitHub token and the OpenAI key:

``scan-prepare``  read token only: a fresh clone at the PR's exact head, and the merge base with its base branch.
``scan``          the OpenAI key only, never the token: the egress proxy holds the key (``dispatch.scan_login_plan``);
                  the scanner runs as the agent's own account with a stand-in, its one way out the proxy, and scans
                  the committed change from the merge base to the head. It writes ``result.json``.
``scan-report``   a separate job, no key, never the scanner's code: it reads ``result.json`` strictly, sets the
                  ``security-scan`` check run on the head and posts the findings through the quarantine.

``"security_scan"`` in ``config.json``: ``"off"`` (the default) plans nothing; ``"observe"`` scans and reports, and the
router does not wait on the check. Part 4 adds ``"enforce"``: the router holds the merge until the check is green.

The check is ``success`` only for a completed scan that reported no finding. HITL decided (2026-11-12) that any
finding the scanner reports blocks, whatever its severity; the scanner validates each finding against the source
before it reports it. Anything else (a refusal, a scan that did not finish, a result that cannot be read) is
``failure``, never green. A head that already has a check run is not scanned again: HITL settles a red scan (part 4).
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from mission_router.model import (MISSION_ID_RE, SHA_RE, STACK_ID_RE, MissionInputError, parse_stage_branch,
                                  parse_verdict, verdict_path)

from . import blast, login, quarantine

OFF, OBSERVE = "off", "observe"
MODES = (OFF, OBSERVE)
CONFIG_KEY = "security_scan"
CHECK_NAME = "security-scan"
CHECK_APP = "github-actions"
TREE, TOOL = "codex-security", "node"  # their pins in pins.json (Amendment 034)
NODE_DIR = "node-{version}-linux-x64"  # the folder Node's pinned archive unpacks to (its version has its "v")
CLI_PATH = "node_modules/@openai/codex-security/bin/codex-security.mjs"
PROVIDER = "egress"  # the scanner's model provider: the proxy's model route
STANDIN_ENV = "MISSION_SCAN_STANDIN"  # the provider's env_key: it holds only the stand-in
SCAN_TIMEOUT = 3 * 3600.0
RESULT_FILE = "result.json"
RESULT_SCHEMA = "mission-secscan-result-v1"
OUT_FILES = ("report.md", "results.sarif")  # kept with result.json as the scan's artifact
SCAN_LOG = "scan.log"
RESULTS_DIR = "results"  # the scanner's --output-dir, under the job root and outside the checkout
MAX_FINDINGS = 200  # findings kept in result.json; the count is always exact
LISTED = 20  # findings listed in the comment and the check
TEXT_MAX = 300
_JOB_NAME_RE = re.compile(r"^secscan #([1-9][0-9]{0,9}) ([0-9a-f]{40})( report)?$")  # the scan job and its report job
_LEVELS = ("critical", "high", "medium", "low", "informational")
_PATH_RE = re.compile(r"^[^\x00-\x1f]{1,400}$")


class ScanError(RuntimeError):
    """The scan cannot go on; the message says why. Its check is ``failure``."""


def mode(config: Mapping[str, Any]) -> str:
    """``"security_scan"``: ``"off"`` when absent; an unknown value is refused, never read as off."""
    value = config.get(CONFIG_KEY, OFF)
    if value not in MODES:
        raise ScanError(f"config.json: {CONFIG_KEY} must be one of {', '.join(MODES)}, not {value!r}")
    return value


@dataclass(frozen=True)
class ScanJob:
    kind: str  # "mission" (an A3 PASS PR) or "stack" (a stack's landing PR)
    subject: str  # the mission id or the stack id
    pr: int
    head_sha: str
    base_ref: str

    @property
    def name(self) -> str:
        """The job's name in the workflow (``secscan #<pr> <head>``), which ``busy_scans`` reads back."""
        return f"secscan #{self.pr} {self.head_sha}"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: object) -> "ScanJob":
        """Rebuild a job handed between workflow jobs, refusing anything ``plan_scans`` could not have made."""
        if not (isinstance(data, dict) and set(data) == set(cls.__dataclass_fields__)
                and data["kind"] in ("mission", "stack") and isinstance(data["subject"], str)
                and (MISSION_ID_RE if data["kind"] == "mission" else STACK_ID_RE).fullmatch(data["subject"])
                and isinstance(data["pr"], int) and not isinstance(data["pr"], bool) and 0 < data["pr"] < 10 ** 10
                and isinstance(data["head_sha"], str) and SHA_RE.fullmatch(data["head_sha"])
                and isinstance(data["base_ref"], str) and 0 < len(data["base_ref"]) <= 200
                and re.fullmatch(r"[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*", data["base_ref"])
                and ".." not in data["base_ref"]):
            raise ScanError("the scan job description is malformed")
        return cls(**data)


def scan_targets(router: Any) -> List[dict]:
    """The open PRs the security scan is for (SECURITY-SCAN-SPEC-001 §3, MISSION-DISPATCH-001 Amendment 036), read
    from ``router`` after its ``survey``, which loaded its open PRs; the router itself is unchanged. Each A3 PR into a
    landing branch whose verdict at its head is PASS, and each stack's landing PR, as
    ``{"kind", "subject", "pr", "head_sha", "base_ref"}`` (``kind`` ``"mission"`` or ``"stack"``). A draft, or a PR
    whose head is in another repository, is left out. Writes nothing."""
    found = []
    for mid, prs in sorted(getattr(router, "_open_prs", {}).items()):
        for raw in prs:
            ref = parse_stage_branch((raw.get("head") or {}).get("ref"))
            if (ref is None or ref.role != "A3" or ref.mission_id != mid or raw.get("draft")
                    or (raw.get("base") or {}).get("ref") not in router.targets
                    or ((raw.get("head") or {}).get("repo") or {}).get("full_name") != router.gh.repo):
                continue
            head_sha = raw["head"]["sha"]
            try:
                verdict = parse_verdict(router.gh.file_at(verdict_path(mid, ref.round), head_sha), mid, ref.round)
            except MissionInputError:
                continue  # no readable verdict: the router rejects it, and there is nothing to scan
            if verdict.verdict == "PASS":
                found.append({"kind": "mission", "subject": mid, "pr": int(raw["number"]), "head_sha": head_sha,
                              "base_ref": raw["base"]["ref"]})
    for sid, prs in sorted(getattr(router, "_landing_prs", {}).items()):
        for raw in prs:
            if raw.get("draft") or ((raw.get("head") or {}).get("repo") or {}).get("full_name") != router.gh.repo:
                continue
            found.append({"kind": "stack", "subject": sid, "pr": int(raw["number"]), "head_sha": raw["head"]["sha"],
                          "base_ref": raw["base"]["ref"]})
    return found


def busy_scans(other_runs: Sequence[Sequence[dict]]) -> set:
    """``(pr, head)`` of every scan another unfinished run of the workflow still owns."""
    busy = set()
    for jobs in other_runs:
        for job in jobs:
            match = _JOB_NAME_RE.fullmatch(str(job.get("name", "")))
            if match and job.get("status") != "completed":
                busy.add((int(match.group(1)), match.group(2)))
    return busy


def scanned(check_runs: Sequence[dict]) -> bool:
    """Whether the head already has this workflow's ``security-scan`` check run, of any outcome."""
    return any((r.get("app") or {}).get("slug") == CHECK_APP for r in check_runs)


def plan_scans(targets: Sequence[Mapping[str, Any]], check_runs: Callable[[str], Sequence[dict]],
               busy: set) -> Tuple[List[ScanJob], List[str]]:
    """The scans due: every target whose head has no check run yet and that no other run is scanning."""
    jobs, notes = [], []
    for target in targets:
        try:
            job = ScanJob.from_dict(dict(target))
        except ScanError:
            notes.append(f"scan: PR #{target.get('pr')} left out: its description is malformed")
            continue
        if (job.pr, job.head_sha) in busy:
            notes.append(f"scan: PR #{job.pr} at {job.head_sha[:12]} is being scanned by another run")
        elif scanned(check_runs(job.head_sha)):
            notes.append(f"scan: PR #{job.pr} at {job.head_sha[:12]} already has its {CHECK_NAME} check")
        else:
            jobs.append(job)
    return jobs, notes


def scan_matrix(jobs: Sequence[ScanJob]) -> Dict[str, list]:
    return {"scan": [job.to_dict() for job in jobs]}


# ------------------------------------------------------------------ the scanner's command
def provider_args(port: int) -> List[str]:
    """The scanner's model provider: the proxy's model route, the Responses API over plain HTTP (the proxy refuses
    a WebSocket upgrade), and the stand-in from ``STANDIN_ENV``. Analytics off."""
    base = f"model_providers.{PROVIDER}"
    settings = [f"model_provider='{PROVIDER}'", f"{base}.name='Egress proxy'",
                f"{base}.base_url='http://127.0.0.1:{int(port)}/model/v1'", f"{base}.wire_api='responses'",
                f"{base}.env_key='{STANDIN_ENV}'", f"{base}.supports_websockets=false", "analytics.enabled=false"]
    return [arg for setting in settings for arg in ("--codex", setting)]


def scan_argv(node: Path, cli: Path, merge_base: str, out_dir: Path, port: int) -> List[str]:
    """``codex-security scan . --diff <merge base>``: the committed change only, every vulnerability type, no cost
    cap, results to ``out_dir`` (outside the checkout), JSON on stdout."""
    if not SHA_RE.fullmatch(merge_base):
        raise ScanError(f"the merge base {merge_base!r} is not a commit")
    return [str(node), str(cli), "scan", ".", "--diff", merge_base, "--output-dir", str(out_dir), "--json",
            "--auth", "api-key", *provider_args(port)]


def scan_env(base: Mapping[str, str], standin: str, state_dir: Path, node_bin: Path) -> Dict[str, str]:
    """The scanner's environment: no credential but the stand-in, no update notices, its state outside the
    checkout. Only ordinary variables of the job's are kept."""
    keep = ("LANG", "LC_ALL", "TZ", "TMPDIR")
    env = {k: v for k, v in base.items() if k in keep and v}
    env.update({"PATH": f"{node_bin}:/usr/local/bin:/usr/bin:/bin", STANDIN_ENV: standin, "CI": "1",
                "CODEX_SECURITY_NO_UPDATE_NOTICE": "1", "NO_UPDATE_NOTIFIER": "1", "NO_COLOR": "1",
                "CODEX_SECURITY_STATE_DIR": str(state_dir), "CODEX_HOME": str(state_dir / "codex-home")})
    return env


# ------------------------------------------------------------------ the result
def _text(value: Any, limit: int = TEXT_MAX) -> str:
    return quarantine.inline(value, limit) if isinstance(value, str) else ""


def _finding(item: Any) -> Dict[str, Any]:
    """One finding as the result keeps it: its level, title, rule and first location, each bounded."""
    if not isinstance(item, dict):
        return {"level": "unknown", "title": "(a finding that is not an object)", "rule": "", "path": "", "line": 0}
    level = (item.get("severity") or {}).get("level") if isinstance(item.get("severity"), dict) else None
    locations = item.get("locations") if isinstance(item.get("locations"), list) else []
    first = locations[0] if locations and isinstance(locations[0], dict) else {}
    path = first.get("path") if isinstance(first.get("path"), str) and _PATH_RE.fullmatch(first["path"]) else ""
    line = first.get("startLine") if isinstance(first.get("startLine"), int) and not isinstance(
        first.get("startLine"), bool) and first["startLine"] > 0 else 0
    return {"level": level if level in _LEVELS else "unknown", "title": _text(item.get("title")) or "(untitled)",
            "rule": _text(item.get("ruleId"), 100), "path": _text(path, 400), "line": line}


def _load(path: Path, document_type: str) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ScanError(f"the scan wrote no {path.name}")
    try:
        doc = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, ValueError) as exc:
        raise ScanError(f"{path.name} cannot be read: {type(exc).__name__}") from None
    if not isinstance(doc, dict) or doc.get("documentType") != document_type:
        raise ScanError(f"{path.name} is not a {document_type} document")
    return doc


def read_result(job: ScanJob, out_dir: Path, exit_code: Optional[int], merge_base: str = "",
                error: str = "") -> Dict[str, Any]:
    """The result ``scan-report`` acts on. ``conclusion`` is ``success`` only for exit 0, a sealed manifest whose
    status is ``completed``, and an empty findings list; everything else is ``failure`` with its reason."""
    result: Dict[str, Any] = {"schema": RESULT_SCHEMA, "job": job.to_dict(), "merge_base": merge_base,
                              "exit_code": exit_code, "conclusion": "failure", "reason": "", "findings": [],
                              "finding_count": 0, "status": ""}
    try:
        if error:
            raise ScanError(error)
        if exit_code != 0:
            raise ScanError(f"the scanner exited {exit_code}" if exit_code is not None
                            else "the scanner did not finish")
        manifest = _load(out_dir / "scan-manifest.json", "codex-security.scan-manifest")
        scan = manifest.get("scan") if isinstance(manifest.get("scan"), dict) else {}
        result["status"] = scan.get("status") if isinstance(scan.get("status"), str) else ""
        if result["status"] != "completed":
            raise ScanError(f"the scan's status is {_text(result['status'], 40) or 'missing'}, not completed")
        findings = _load(out_dir / "findings.json", "codex-security.findings").get("findings")
        if not isinstance(findings, list):
            raise ScanError("findings.json has no findings list")
        result["finding_count"] = len(findings)
        result["findings"] = [_finding(f) for f in findings[:MAX_FINDINGS]]
        if findings:
            raise ScanError(f"the scan reported {len(findings)} finding{'s' if len(findings) != 1 else ''}")
        result["conclusion"], result["reason"] = "success", "the scan completed and reported no finding"
    except ScanError as exc:
        result["reason"] = _text(str(exc), 500)
    return result


def write_result(path: Path, result: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_result(text: str, job: ScanJob) -> Dict[str, Any]:
    """``result.json`` as ``scan-report`` reads it: anything malformed, or for another job, is a failure."""
    def failed(reason: str) -> Dict[str, Any]:
        return {"conclusion": "failure", "reason": reason, "findings": [], "finding_count": 0}
    try:
        doc = json.loads(text)
    except ValueError:
        return failed("the scan's result is not JSON")
    if not isinstance(doc, dict) or doc.get("schema") != RESULT_SCHEMA or doc.get("job") != job.to_dict():
        return failed("the scan's result is not this scan's")
    findings = doc.get("findings") if isinstance(doc.get("findings"), list) else []
    count = doc.get("finding_count")
    kept = [_finding({"severity": {"level": f.get("level")}, "title": f.get("title"), "ruleId": f.get("rule"),
                      "locations": [{"path": f.get("path"), "startLine": f.get("line")}]})
            for f in findings[:MAX_FINDINGS] if isinstance(f, dict)]
    count = count if isinstance(count, int) and not isinstance(count, bool) and count >= len(kept) else len(kept)
    ok = doc.get("conclusion") == "success" and count == 0
    return {"conclusion": "success" if ok else "failure",
            "reason": _text(doc.get("reason"), 500) or ("the scan completed and reported no finding" if ok
                                                         else "the scan did not pass"),
            "findings": kept, "finding_count": count}


def report_text(job: ScanJob, parsed: Mapping[str, Any], run_url: str = "") -> Tuple[str, str]:
    """(check title, body): the body is the check's summary and the PR comment. Every scanner text in it is passed
    through the quarantine, because it quotes code agents wrote."""
    count = parsed["finding_count"]
    if parsed["conclusion"] == "success":
        title = "Security scan: no finding"
    elif count:
        title = f"Security scan: {count} finding{'s' if count != 1 else ''}"
    else:
        title = "Security scan: did not pass"
    lines = [f"**{title}** at `{job.head_sha[:12]}`", "", f"- Result: {_text(parsed['reason'], 500)}"]
    for f in parsed["findings"][:LISTED]:
        where = f" at `{_text(f['path'], 200)}:{f['line']}`" if f["path"] else ""
        lines.append(f"- **{f['level']}**: {_text(f['title'])}{where}" + (f" (`{_text(f['rule'], 80)}`)"
                                                                           if f["rule"] else ""))
    if count > LISTED:
        lines.append(f"- … and {count - LISTED} more, in the scan's artifact")
    lines += ["", "The scan is a check, never a review: a green scan is not an A3 PASS and stands in for no "
                  "independent review (SECURITY-SCAN-SPEC-001 §1). Reporting only: the router does not wait on it "
                  "yet (MISSION-DISPATCH-001 Amendment 036)."]
    if run_url:
        lines.append(f"The SARIF and the report are kept with the [run]({run_url}) for 90 days.")
    return title, "\n".join(lines) + "\n"


# ------------------------------------------------------------------ running it
def run_scan(job: ScanJob, root: Path, tools: Path, out_dir: Path, environ: Mapping[str, str], blast_mode: str,
             run_as: str, node_version: str, merge_base: str, timeout: float = SCAN_TIMEOUT,
             egress: Optional["blast.AgentEgress"] = None, run: Callable[..., Any] = subprocess.run,
             log: Callable[[str], None] = print) -> int:
    """Run the scanner on ``root/checkout`` as ``run_as``, its only way out the proxy, which holds the key. Returns
    its exit code. Raises ``ScanError`` before the scanner starts when the key cannot be kept from it."""
    from .dispatch import DispatchError, SCAN_RUNTIME, scan_login_plan, scrub  # no import cycle
    if not run_as:
        raise ScanError("the scan runs only as the agent's own account (blast_radius enforced)")
    try:
        plan = scan_login_plan(environ, blast_mode)
    except DispatchError as exc:
        raise ScanError(str(exc)) from None
    tree = root / "checkout"
    node_bin = tools / NODE_DIR.format(version=node_version) / "bin"
    cli = tools / TREE / CLI_PATH
    for need in (node_bin / "node", cli):
        if need.is_symlink() or not need.is_file():
            raise ScanError(f"the pinned install has no {need.name}")
    state_dir, results = root / "state", root / RESULTS_DIR
    for folder in (state_dir, results):
        folder.mkdir(mode=0o700)
    log_path = root / SCAN_LOG
    state, endpoint = plan["state"], plan["endpoint"]
    secrets = [plan["proxy_login"]["login"], state["standin"]]
    egress = egress or blast.AgentEgress(SCAN_RUNTIME, blast_mode, root, run_as, model_login=plan["proxy_login"],
                                         exclusive=True)
    try:
        env = scan_env(environ, state["standin"], state_dir, node_bin)
        env.update(egress.start())
        if not getattr(egress, "port", 0):
            raise ScanError("the egress proxy is not running, so the key cannot be kept from the scanner")
        ready = login.readiness(egress.port, state["standin"], endpoint.readiness_route, endpoint.readiness_model)
        if not ready["ok"]:
            raise ScanError(f"the key is not accepted through the proxy ({ready['reason']}); the scanner was not "
                            "started")
        log(f"scan: the proxy holds the key; readiness {ready['reason']}")
        argv = scan_argv(node_bin / "node", cli, merge_base, results, egress.port)
        env = blast.account_env(env, run_as, environ.get("HOME", ""))
        blast.hand_over(root, run_as, [tree, state_dir, results], egress.run)
        argv = [*blast.run_as_argv(run_as, list(env), environ.get("HOME", "")), *argv]
    except (blast.BlastError, ScanError) as exc:
        egress.stop()
        raise ScanError(str(exc)) from None
    code: Optional[int] = None
    problems: List[str] = []
    try:
        with open(log_path, "w", encoding="utf-8") as out:
            code = run(argv, cwd=str(tree), env=env, stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                       timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        log(f"::error::the scan did not finish within {int(timeout)} seconds")
    except OSError as exc:
        log(f"::error::the scanner could not start: {exc}")
    finally:
        problems = blast.take_back(root, run_as, egress.run)
        egress.stop()
        blast.keep_tail(log_path)
        scrub(log_path, secrets)
    if problems:
        raise ScanError("; ".join(problems))
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, src in (("report.md", results / "report.md"), ("results.sarif", results / "exports" / "results.sarif")):
        if src.is_file() and not src.is_symlink():
            data = src.read_bytes()
            for secret in secrets:
                if secret.encode() in data:
                    data = b""  # never kept with the key in it
            (out_dir / name).write_bytes(data)
    return -1 if code is None else code


# ------------------------------------------------------------------ the checkout
MERGE_BASE_FILE = "merge-base.txt"


def prepare_checkout(job: ScanJob, root: Path, clone_url: str, git: Mapping[str, str],
                     run: Callable[..., Any] = subprocess.run) -> str:
    """A fresh, full clone at the PR's exact head, detached, with nothing written into it (a committed-diff scan
    needs a clean checkout at the head it names). Returns the merge base with ``origin/<base_ref>``, which bounds
    the scan to the PR's own change. ``git`` is ``workspace.git_env`` with the read token: no hooks, no global or
    system config. The repository's own files are never read as scanner settings: no ``-c`` file is passed."""
    import shutil
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    tree = root / "checkout"

    def git_call(*args: str, cwd: Path = tree) -> str:
        done = run(["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", *args], cwd=str(cwd),
                   env=dict(git), capture_output=True, text=True, timeout=600)
        if done.returncode != 0:
            raise ScanError(f"git {args[0]} failed: {(done.stderr or done.stdout or '').strip()[:300]}")
        return done.stdout.strip()

    git_call("clone", "--quiet", "--no-checkout", "--", clone_url, str(tree), cwd=root)
    git_call("checkout", "--quiet", "--detach", job.head_sha)
    if git_call("rev-parse", "HEAD") != job.head_sha:
        raise ScanError(f"the checkout is not at {job.head_sha}")
    base = git_call("merge-base", "HEAD", f"refs/remotes/origin/{job.base_ref}")
    if not SHA_RE.fullmatch(base):
        raise ScanError(f"no merge base with {job.base_ref}")
    (root / MERGE_BASE_FILE).write_text(base + "\n", encoding="utf-8")
    return base


def read_merge_base(root: Path) -> str:
    path = root / MERGE_BASE_FILE
    value = path.read_text(encoding="utf-8").strip() if path.is_file() and not path.is_symlink() else ""
    if not SHA_RE.fullmatch(value):
        raise ScanError("scan-prepare left no merge base")
    return value
