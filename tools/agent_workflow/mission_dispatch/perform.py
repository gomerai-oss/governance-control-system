"""The perform step (MISSION-DISPATCH-001 §3p, Amendment 032; APP-CONTROL-HARNESS-SPEC-001 §4.1 Proposal C).

No agent sends, deletes or makes a drafted write: it drafts the call, ``report`` posts the run's drafted list with
its digest (Amendment 031), and HITL performs exactly that list by commenting, on its own line on the mission's
tracking issue::

    /mission perform <digest>

The router ignores the command; this step reads it, as the dispatcher reads ``/mission retry``. It runs in the
``perform`` job of ``mission-agent.yml`` in three stages, so that no stage holds both the GitHub token and an app's
key:

``check`` (the workflow's token, no app key)
    Re-derives every unfinished mission with the router's own read-only survey; nothing in the event is read. For
    each command not yet answered (a bot comment carrying ``HANDLED_MARKER`` answers one) it refuses unless: the
    comment is by a HITL user account and holds exactly one command; the app gateway is not ``"off"``; the mission
    is open (``OPEN_STAGES``) and not halted (``model.hitl_halt``); no claim (``CLAIM_MARKER``) names the digest;
    a report comment by the bot, older than the command, names the digest for this mission, with the run it came
    from; that run is of this workflow, on the default branch; and its ``drafts-<lane>`` artifact, not expired, holds
    a well-formed list of exactly that digest for this mission. The first command that passes is claimed: the claim
    comment is posted before any call is made, so a list is performed at most once, even by a run that stops half
    way. Each command gets one ``dispatch.perform`` record (``decide``), its digest as input.
``call`` (only the listed apps' keys, no token)
    Starts the egress proxy with the listed apps' keys and the listed calls' classes only, and builds the app gateway
    in a ``service`` session of its own, as the ``mission-perform`` principal (role ``APP_PERFORM``). The keys are
    taken out of the environment before the gateway is built. Each call is made in order through
    ``AppGateway.perform``: bounded, decided by the fabric again as its own action, its pinned harness run. The first
    call that is not ALLOWed and done stops the rest.
``report`` (the workflow's token)
    Posts which calls were performed, which was refused and why, and which were not reached, and records each call
    as one ``harness.<kind>`` record with authority ``hitl_command``.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from mcp_gateway import app_gateway
from mission_router.github import GitHubError
from mission_router.model import hitl_halt
from mission_router.state import AWAIT_A2, AWAIT_A3, BLOCKED

from . import binding, blast, login, quarantine

PERFORM_RE = re.compile(r"(?m)^[ \t]*/mission perform[ \t]+([0-9a-f]{64})[ \t]*\r?$")
ANY_PERFORM_RE = re.compile(r"(?m)^[ \t]*/mission perform(?=[ \t]|\r?$)")
# A marker counts only as a whole line of a bot comment. The bot quotes agent text only as indented JSON in a
# drafts comment (Amendment 031) or on one line after other words, so a marker an agent wrote never fills a line.
DRAFTS_RE = re.compile(r"(?m)^<!-- mission-dispatch:drafts:([0-9a-f]{64}):([1-9][0-9]{0,19}):([A-Za-z0-9._-]{1,100}):"
                       r"(A2|A3|AR):([1-9][0-9]?) -->\r?$")
CLAIM_MARKER = "<!-- mission-dispatch:performing:{digest} -->"
HANDLED_MARKER = "<!-- mission-dispatch:perform-command:{comment} -->"
_CLAIM_RE = re.compile(r"(?m)^<!-- mission-dispatch:performing:([0-9a-f]{64}) -->\r?$")
_HANDLED_RE = re.compile(r"(?m)^<!-- mission-dispatch:perform-command:([0-9]{1,20}) -->\r?$")
OPEN_STAGES = (AWAIT_A2, AWAIT_A3, BLOCKED)  # open: not landed, cancelled, halted or paused
WORKFLOW_PATH = ".github/workflows/mission-agent.yml"
ARTIFACT = "drafts-{mission}-{role}-r{round}"
MAX_ZIP_BYTES = 1024 * 1024
MAX_LIST_BYTES = 256 * 1024
PRINCIPAL, ROLE = "mission-perform", "APP_PERFORM"  # mcp_auth/policy.json: kind service; no grant names the role
# The egress policy (unchanged) lists hosts by runtime only. The proxy here serves the app endpoint; nothing in the
# perform job opens a tunnel through it, and it is given no model login.
PROXY_RUNTIME = "claude-code"
PLAN_FILE, OUTCOME_FILE = "perform-plan.json", "perform-outcome.json"
PLAN_SCHEMA, OUTCOME_SCHEMA = "perform-plan-v1", "perform-outcome-v1"
_SHA = re.compile(r"[0-9a-f]{40}")


class PerformError(RuntimeError):
    """A command that is refused, or a stage that cannot go on."""


# ------------------------------------------------------------------ reading the issue


def _user(comment: Mapping) -> Tuple[str, str]:
    user = comment.get("user") or {}
    return str(user.get("login", "")), str(user.get("type", ""))


def commands(comments: Sequence[Mapping]) -> List[Mapping]:
    """Every comment that holds a ``/mission perform`` line, by anyone, oldest first."""
    return [c for c in comments if ANY_PERFORM_RE.search(str(c.get("body") or "")) and isinstance(c.get("id"), int)]


def handled(comments: Sequence[Mapping], bot: str) -> set:
    """The ids of the commands the bot has answered."""
    return {int(m) for c in comments if _user(c)[0] == bot for m in _HANDLED_RE.findall(str(c.get("body") or ""))}


def claimed(comments: Sequence[Mapping], bot: str) -> set:
    """The digests the bot has claimed for performing: each is performed at most once."""
    return {m for c in comments if _user(c)[0] == bot for m in _CLAIM_RE.findall(str(c.get("body") or ""))}


def find_report(comments: Sequence[Mapping], bot: str, digest: str, mission: str, before: str) -> Optional[dict]:
    """The newest bot report naming ``digest`` for ``mission`` posted before ``before``: its run, role and round."""
    found = None
    for c in comments:
        if _user(c)[0] != bot or not str(c.get("created_at") or "") < before:
            continue
        for m in DRAFTS_RE.finditer(str(c.get("body") or "")):
            if m.group(1) == digest and m.group(3) == mission:
                found = {"run": m.group(2), "role": m.group(4), "round": int(m.group(5)),
                         "comment": c.get("id")}
    return found


def command_digest(comment: Mapping) -> str:
    """The one digest a command comment names; ``PerformError`` when it names none or more than one line."""
    body = str(comment.get("body") or "")
    if len(ANY_PERFORM_RE.findall(body)) != 1:
        raise PerformError("a comment gives one /mission perform command, on its own line")
    found = PERFORM_RE.findall(body)
    if len(found) != 1:
        raise PerformError("the command names no list digest (64 lowercase hex characters)")
    return found[0]


# ------------------------------------------------------------------ the drafted list


def list_from_zip(data: bytes) -> bytes:
    if len(data) > MAX_ZIP_BYTES:
        raise PerformError("the drafts artifact is too large")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            info = archive.getinfo(app_gateway.DRAFTS_FILE)
            if info.file_size > MAX_LIST_BYTES:
                raise PerformError("the drafted list is too large")
            return archive.read(info)
    except (zipfile.BadZipFile, KeyError) as exc:
        raise PerformError(f"the drafts artifact holds no {app_gateway.DRAFTS_FILE} ({type(exc).__name__})") from None


def parse_list(data: bytes) -> Tuple[dict, str]:
    """A well-formed drafted list and its digest from the artifact's bytes."""
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise PerformError("the drafted list is not JSON") from None
    found = app_gateway.check_drafts(doc)
    if found:
        raise PerformError("the drafted list is malformed: " + "; ".join(found))
    return doc, app_gateway.drafts_digest(doc)


def fetch_list(gh: Any, download: Callable[[str], bytes], report: Mapping, mission: str,
               default_branch: str) -> bytes:
    """The drafted list's bytes from the run the report names: a run of this workflow on the default branch, its
    ``drafts-<lane>`` artifact not expired."""
    try:
        run = gh.get(f"/actions/runs/{report['run']}") or {}
    except GitHubError as exc:
        if exc.status != 404:
            raise
        raise PerformError(f"run {report['run']} is not found") from None
    if run.get("path") != WORKFLOW_PATH or run.get("head_branch") != default_branch:
        raise PerformError(f"run {report['run']} is not a {WORKFLOW_PATH} run on {default_branch}")
    name = ARTIFACT.format(mission=mission, role=report["role"], round=report["round"])
    listing = gh.get(f"/actions/runs/{report['run']}/artifacts?name={name}") or {}
    found = [a for a in listing.get("artifacts") or [] if a.get("name") == name]
    if len(found) != 1:
        raise PerformError(f"run {report['run']} has no {name} artifact")
    if found[0].get("expired"):
        raise PerformError(f"the {name} artifact has expired")
    return list_from_zip(download(str(found[0].get("archive_download_url") or "")))


# ------------------------------------------------------------------ check


def check_command(comment: Mapping, mission: str, stage: str, comments: Sequence[Mapping], hitl: set, bot: str,
                  app_mode: str, gh: Any, download: Callable[[str], bytes], default_branch: str) -> dict:
    """The plan for one command, or ``PerformError`` with why it is refused."""
    login_name, kind = _user(comment)
    if kind != "User" or login_name.casefold() not in hitl:
        raise PerformError(f"{login_name or 'an unknown account'} is not a HITL login")
    digest = command_digest(comment)
    if app_mode == binding.OFF:
        raise PerformError('the app gateway is "off", so no drafted call is performed')
    if hitl_halt(comments, hitl) is not None:
        raise PerformError("the mission is halted (/mission halt); /mission resume lifts it")
    if stage not in OPEN_STAGES:
        raise PerformError(f"the mission is not open ({stage})")
    if digest in claimed(comments, bot):
        raise PerformError("that list was performed already; a list is performed at most once")
    report = find_report(comments, bot, digest, mission, str(comment.get("created_at") or ""))
    if report is None:
        raise PerformError("no report on this issue names that digest; a list that changed has another digest")
    doc, found = parse_list(fetch_list(gh, download, report, mission, default_branch))
    if found != digest or doc["mission"] != mission:
        raise PerformError("the run's drafted list is not the one the report names")
    return {"schema": PLAN_SCHEMA, "digest": digest, "mission": mission, "role": report["role"],
            "round": report["round"], "run": report["run"], "report_comment": report["comment"],
            "command": {"id": comment["id"], "login": login_name, "url": str(comment.get("html_url") or "")},
            "list": doc}


def claim_text(plan: Mapping) -> str:
    n = len(plan["list"]["calls"])
    return (f"**Performing the drafted list `{plan['digest'][:12]}`** for {plan['mission']} ({plan['role']} round "
            f"{plan['round']}): {n} call{'s' if n != 1 else ''}, in order, on HITL "
            f"{quarantine.inline(plan['command']['login'], 40)}'s command. This list is now claimed, so it is never "
            "performed again.\n\n" + CLAIM_MARKER.format(digest=plan["digest"]) + "\n"
            + HANDLED_MARKER.format(comment=plan["command"]["id"]))


def refusal_text(comment: Mapping, reason: str) -> str:
    return (f"**`/mission perform` refused:** {quarantine.inline(reason, 300)}. Nothing was performed.\n\n"
            + HANDLED_MARKER.format(comment=comment["id"]))


# ------------------------------------------------------------------ call


def service_session(plan: Mapping, base_sha: str, now: int, seconds: int) -> dict:
    """The perform step's own session (kind ``service``) for the mission whose list HITL performs, ``seconds``
    long."""
    if not _SHA.fullmatch(base_sha or ""):
        raise PerformError("the tooling commit (GITHUB_SHA) is not a 40-hex commit")
    resources = sorted({c["resource"] for c in plan["list"]["calls"]})
    return {"principal": PRINCIPAL, "acting_identity": PRINCIPAL, "role": ROLE, "kind": app_gateway.SERVICE_KIND,
            "mission": {"id": plan["mission"], "authority_ref": "MISSION-ROUTER-001", "base_sha": base_sha,
                        "round": plan["round"]},
            "resources": resources, "issued_at": now, "expires_at": now + seconds}


def read_plan(path: Path) -> dict:
    """The plan ``check`` wrote; its list must still be of its digest."""
    try:
        plan = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise PerformError(f"the perform plan is unreadable ({type(exc).__name__})") from None
    if not (isinstance(plan, dict) and plan.get("schema") == PLAN_SCHEMA and isinstance(plan.get("list"), dict)):
        raise PerformError("the perform plan is malformed")
    if app_gateway.check_drafts(plan["list"]) or app_gateway.drafts_digest(plan["list"]) != plan.get("digest"):
        raise PerformError("the perform plan's list is not of its digest")
    return plan


def outcome(plan: Mapping, performed: Sequence[int], stopped: Optional[dict], problem: Optional[str]) -> dict:
    n = len(plan["list"]["calls"])
    last = stopped["call"] if stopped else (len(performed) if problem is None else 0)
    return {"schema": OUTCOME_SCHEMA, "digest": plan["digest"], "performed": list(performed), "stopped": stopped,
            "not_reached": list(range(last + 1, n + 1)), "problem": problem}


def make_calls(plan: Mapping, work: Path, environ: Mapping[str, str], *, clock: Callable[[], int] = None,
               egress_factory: Callable[..., Any] = None, gateway_factory: Callable[..., Any] = None,
               register: Optional[Mapping] = None, pop_env: Callable[[str], None] = None) -> dict:
    """Make the plan's calls in order (the ``call`` stage); returns the outcome. Nothing here holds a GitHub
    credential. The keys go to the proxy by file and are taken out of the environment before the gateway starts."""
    from mcp_auth import policy as policy_mod
    from tool_selection import apps as apps_mod
    clock = clock or (lambda: int(time.time()))
    egress_factory = egress_factory or blast.AgentEgress
    gateway_factory = gateway_factory or app_gateway.AppGateway
    pop_env = pop_env or (lambda name: os.environ.pop(name, None))
    calls = plan["list"]["calls"]
    try:
        register = register if register is not None else apps_mod.load_file()
    except apps_mod.AppsError as exc:
        return outcome(plan, [], None, f"the app register is unavailable: {exc}")
    keys: Dict[str, str] = {}
    for app in sorted({c["app"] for c in calls}):
        entry = register["apps"].get(app)
        if entry is None:
            return outcome(plan, [], None, f"app {app!r} is not in the app register")
        value = environ.get(entry["key_slot"], "")
        if not value:
            return outcome(plan, [], None, f"app {app}'s key ({entry['key_slot']}) is not set in this job")
        keys[app] = value
    for name in [k for k in environ if re.fullmatch(r"APP_KEY_[0-9]{1,2}", k)]:
        pop_env(name)
    checkout, private = work / "checkout", binding.binding_dir(work)
    evidence = private / binding.APP_EVIDENCE_DIR
    for folder in (checkout, evidence):
        folder.mkdir(parents=True, exist_ok=True)
    try:
        minutes = min([register["bounds"]["minutes"]] + [register["apps"][a]["bounds"]["minutes"] for a in keys
                                                          if register["apps"][a]["bounds"] is not None])
        ttl = policy_mod.load_file()["session"]["max_ttl_seconds"]  # the fabric refuses a longer session (stop 13)
        session = service_session(plan, environ.get("GITHUB_SHA", ""), clock(), min(minutes * 60, ttl))
    except policy_mod.PolicyError as exc:
        return outcome(plan, [], None, f"the fabric policy is unavailable: {exc}")
    except PerformError as exc:
        return outcome(plan, [], None, str(exc))
    session_path = private / binding.SESSION_FILE
    session_path.write_text(json.dumps(session, sort_keys=True) + "\n", encoding="utf-8")
    standin = login.new_standin()
    egress = egress_factory(PROXY_RUNTIME, blast.OBSERVE, work, None,
                            app_keys={"standin": standin, "keys": keys,
                                      "classes": sorted({c["kind"] for c in calls})})
    performed: List[int] = []
    try:
        try:
            egress.start()
        except blast.BlastError as exc:
            return outcome(plan, [], None, f"the egress proxy did not start: {exc}")
        if not getattr(egress, "port", 0):
            return outcome(plan, [], None, "the egress proxy is not running, so no app can be reached")
        egress.app_keys = None  # the proxy has read and deleted its file; nothing here keeps the keys
        keys.clear()
        try:
            endpoint = binding.write_app_endpoint(work, egress.port, standin)
            gateway = gateway_factory(checkout, session_path, evidence, endpoint_path=endpoint,
                                      kind=app_gateway.SERVICE_KIND)
        except (binding.BindingError, app_gateway.GatewayError) as exc:
            return outcome(plan, [], None, f"the app gateway did not start: {exc}")
        for n, call in enumerate(calls, 1):
            result = gateway.perform(call)
            structured = result.get("structuredContent") or {}
            if result.get("isError") or structured.get("disposition") != "ALLOW":
                reason = structured.get("reason") or (result.get("content") or [{}])[0].get("text", "refused")
                return outcome(plan, performed, {"call": n, "disposition": str(structured.get("disposition") or
                                                                              "REFUSED"),
                                                 "reason": str(reason)[:500]}, None)
            performed.append(n)
        return outcome(plan, performed, None, None)
    finally:
        keys.clear()
        egress.app_keys = None
        egress.stop()


# ------------------------------------------------------------------ report


def outcome_text(plan: Mapping, result: Optional[Mapping], run_url: str) -> str:
    n = len(plan["list"]["calls"])
    head = f"**The drafted list `{plan['digest'][:12]}`** for {plan['mission']}"
    if result is None:
        lines = [f"{head}: the perform step ended without an outcome. The list is claimed, so it is not performed "
                 "again; see the run for what was made." + (f" ({run_url})" if run_url else "")]
    else:
        done = result["performed"]
        lines = [f"{head}: {len(done)} of {n} call{'s' if n != 1 else ''} performed."]
        if done:
            lines.append("- Performed: " + ", ".join(f"call {i}" for i in done) + ".")
        if result.get("stopped"):
            stop = result["stopped"]
            lines.append(f"- Call {stop['call']} was {'denied' if stop['disposition'] == 'DENY' else 'refused'}: "
                         f"{quarantine.inline(stop['reason'], 300)}.")
        if result.get("problem"):
            lines.append(f"- No call was made: {quarantine.inline(result['problem'], 300)}.")
        if result.get("not_reached"):
            lines.append("- Not reached: " + ", ".join(f"call {i}" for i in result["not_reached"]) + ".")
        lines.append("The list is claimed and is not performed again; to make the rest, an agent drafts them anew.")
    return "\n".join(lines)


def write_json(path: Path, doc: Mapping) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def read_outcome(path: Path, plan: Mapping) -> Optional[dict]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    if not (isinstance(doc, dict) and doc.get("schema") == OUTCOME_SCHEMA and doc.get("digest") == plan["digest"]):
        return None
    return doc


def private_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="mission-perform-"))


def remove(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)
