"""The checker (§3m item 7; part 5): the verifier run on its own, over the whole store, by an identity that cannot
write the store.

``check`` verifies a clone of the store: every run's chain and seal against the pinned keys (``--sealed``), the
store's history (every file added once, never changed), and every record's commit in this repository's clone. A
commit the clone lacks is first asked of the repository by its id (Amendment 045). It writes the result as JSON and
records it as one ``evidence.verify`` record in the job's chain, which the seal job then seals like any other. It never fails the job itself: ``report`` turns the result into the ``evidence-verified``
check on the commit and, when verification failed, an issue for HITL.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping, Optional

from evidence import EvidenceError, producer
from evidence import store as store_mod
from evidence import verify

CHECK_NAME = "evidence-verified"
ISSUE_TITLE = "Evidence verification failed"
ISSUE_LABEL = "evidence:failed"
ACTOR = "evidence-verify"
AUTHORITY = "MISSION-DISPATCH-001 section 3m item 7"


def check(store: Path, keys: Mapping[str, str], git: Optional[Path], recorder=None, worm=None,
          retention_years: int = 0, worm_error: str = "", landing_branches=("main",)) -> dict:
    """``{"ok", "runs", "records", "commits", "unsealed", "withdrawn", "failures", "worm"}`` for the whole store. With
    ``worm`` (a declared WORM bucket), every stored file must also have its copy there, byte-identical and retained
    for ``retention_years``."""
    report = verify.verify_store(Path(store), keys, require_seal=True, git=git, fetch=True)
    failures = ([report.failure] if report.failure else []) + store_mod.history_problems(Path(store))
    from evidence import pack as pack_mod
    # every landing attestation (§3m item 2): a landing GitHub refused, or never merged, is refused unless withdrawn
    failures += pack_mod.store_problems(Path(store), keys, git, landing_branches)
    if worm_error:  # a declared WORM bucket the checker could not reach is a failure to verify, reported like any
        failures.append(f"the WORM copy could not be checked: {worm_error}")
    if worm is not None:
        from evidence import worm as worm_mod
        try:
            failures += worm_mod.check_copies(Path(store), worm, retention_years)
        except EvidenceError as exc:
            failures.append(f"the WORM copy could not be checked: {exc}")
    result = {"ok": not failures, "runs": report.runs, "records": report.records, "commits": report.commits_checked,
              "unsealed": report.unsealed, "withdrawn": dict(sorted(report.withdrawn.items())), "failures": failures,
              "worm": worm is not None or bool(worm_error)}
    if recorder is not None:
        recorder.record(actor=ACTOR, account_id=None, action="evidence.verify",
                        result="done" if result["ok"] else "refused",
                        reason=(f"{report.runs} runs, {report.records} records verified" if result["ok"]
                                else f"refused: {failures[0]}"),
                        outputs={"result": producer.text_digest(json.dumps(result, sort_keys=True))},
                        authority_kind="spec_rule", authority_ref=AUTHORITY)
    return result


def summary(result: Mapping, store_repo: str) -> str:
    lines = [f"Store `{store_repo}`: {result['runs']} runs, {result['records']} records, {result['commits']} commits "
             "checked; every run sealed with a pinned key, every stored file added once and never changed"
             + ("; every file's WORM copy identical and retained." if result.get("worm") else ".")
             if result["ok"] else f"Store `{store_repo}`: verification **refused**."]
    lines += [f"- {f}" for f in result.get("failures", [])]
    if result.get("withdrawn"):
        lines += ["", "Withdrawn records (kept, marked):"] + [f"- `{t}` by `{w}`" for t, w in result["withdrawn"].items()]
    return "\n".join(lines)


def report(result: Mapping, gh, sha: str, store_repo: str, run_url: str = "") -> str:
    """Set ``evidence-verified`` on ``sha``. On a failure, open the HITL issue, or comment on the open one only when
    the failures differ from those it last reported: the same cause is not reported again every run (Amendment 056).
    On a pass, close the open issue, saying which commit verified. Returns what it did."""
    text = summary(result, store_repo)
    from mission_dispatch.quarantine import neutralise
    text = neutralise(text)  # store paths and reasons are data: no mention, no command
    gh.create_check_run(CHECK_NAME, sha, "completed", "success" if result["ok"] else "failure",
                        "Evidence store verified" if result["ok"] else "Evidence store verification refused", text)
    open_issues = [i for i in gh.paginate(f"/issues?state=open&labels={ISSUE_LABEL}", limit=50)
                   if not i.get("pull_request") and i.get("title") == ISSUE_TITLE]
    if result["ok"]:
        for issue in open_issues:
            gh.comment(int(issue["number"]), f"The store verified cleanly at commit `{sha[:12]}`"
                       + (f" (run: {run_url})" if run_url else "") + ". Closing.")
            gh.request("PATCH", f"/issues/{int(issue['number'])}", {"state": "closed", "state_reason": "completed"})
        return "verified" + (f"; closed {', '.join('#' + str(i['number']) for i in open_issues)}" if open_issues else "")
    mark = f"<!-- evidence-failures:{_failures_digest(result)} -->"
    body = f"{text}\n\nCommit `{sha[:12]}`." + (f" Run: {run_url}" if run_url else "") + \
        "\n\nNothing in the store is changed by the checker. HITL decides what follows (§3m item 4: a wrong record is " \
        "withdrawn, never deleted).\n\n" + mark
    from mission_router.github import GitHubError
    if open_issues:
        number = int(open_issues[0]["number"])
        if _last_mark(gh, open_issues[0]) == mark:
            return f"#{number} already reports these failures"
        gh.comment(number, body)
        return f"commented on #{number}"
    try:  # the label the issue carries; GitHub refuses a second one with the same name, which is fine
        gh.request("POST", "/labels", {"name": ISSUE_LABEL, "color": "b60205",
                                       "description": "The evidence checker refused the store (MISSION-DISPATCH-001 §3m item 7)"})
    except GitHubError:
        pass
    created = gh.request("POST", "/issues", {"title": ISSUE_TITLE, "body": body, "labels": [ISSUE_LABEL]})
    return f"opened #{created.get('number')}"


def _failures_digest(result: Mapping) -> str:
    return producer.text_digest("\n".join(result.get("failures", [])))[:16]


def _last_mark(gh, issue: Mapping) -> str:
    """The failures mark of the newest report on the issue: its last comment that carries one, else its body."""
    import re
    found = re.findall(r"<!-- evidence-failures:[0-9a-f]{16} -->", issue.get("body") or "")
    for comment in gh.paginate(f"/issues/{int(issue['number'])}/comments", limit=1000):
        found += re.findall(r"<!-- evidence-failures:[0-9a-f]{16} -->", comment.get("body") or "")
    return found[-1] if found else ""
