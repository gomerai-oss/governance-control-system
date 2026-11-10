"""The checker (§3m item 7; part 5): the verifier run on its own, over the whole store, by an identity that cannot
write the store.

``check`` verifies a clone of the store: every run's chain and seal against the pinned keys (``--sealed``), the
store's history (every file added once, never changed), and every record's commit in this repository's clone. It
writes the result as JSON and records it as one ``evidence.verify`` record in the job's chain, which the seal job
then seals like any other. It never fails the job itself: ``report`` turns the result into the ``evidence-verified``
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
          retention_years: int = 0, worm_error: str = "") -> dict:
    """``{"ok", "runs", "records", "commits", "unsealed", "withdrawn", "failures", "worm"}`` for the whole store. With
    ``worm`` (a declared WORM bucket), every stored file must also have its copy there, byte-identical and retained
    for ``retention_years``."""
    report = verify.verify_store(Path(store), keys, require_seal=True, git=git)
    failures = ([report.failure] if report.failure else []) + store_mod.history_problems(Path(store))
    from evidence import pack as pack_mod
    failures += pack_mod.store_problems(Path(store), keys)  # every landing attestation (§3m item 2)
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
    """Set ``evidence-verified`` on ``sha``; on a failure open the HITL issue, or comment on the open one. Returns
    what it did."""
    text = summary(result, store_repo)
    from mission_dispatch.quarantine import neutralise
    text = neutralise(text)  # store paths and reasons are data: no mention, no command
    gh.create_check_run(CHECK_NAME, sha, "completed", "success" if result["ok"] else "failure",
                        "Evidence store verified" if result["ok"] else "Evidence store verification refused", text)
    if result["ok"]:
        return "verified"
    body = f"{text}\n\nCommit `{sha[:12]}`." + (f" Run: {run_url}" if run_url else "") + \
        "\n\nNothing in the store is changed by the checker. HITL decides what follows (§3m item 4: a wrong record is " \
        "withdrawn, never deleted)."
    from mission_router.github import GitHubError
    try:  # the label the issue carries; GitHub refuses a second one with the same name, which is fine
        gh.request("POST", "/labels", {"name": ISSUE_LABEL, "color": "b60205",
                                       "description": "The evidence checker refused the store (MISSION-DISPATCH-001 §3m item 7)"})
    except GitHubError:
        pass
    open_issues = [i for i in gh.paginate(f"/issues?state=open&labels={ISSUE_LABEL}", limit=50)
                   if not i.get("pull_request") and i.get("title") == ISSUE_TITLE]
    if open_issues:
        gh.comment(int(open_issues[0]["number"]), body)
        return f"commented on #{open_issues[0]['number']}"
    created = gh.request("POST", "/issues", {"title": ISSUE_TITLE, "body": body, "labels": [ISSUE_LABEL]})
    return f"opened #{created.get('number')}"
