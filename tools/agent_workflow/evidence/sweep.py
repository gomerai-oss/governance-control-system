"""The seal sweep (§3m item 2; Amendment 022): find the ended runs the seal job was never started for.

The seal workflow starts on ``workflow_run``. GitHub does not send that event when the run that ended was started with
a workflow's own ``GITHUB_TOKEN``, and the router starts every Mission Agent run it dispatches that way. Such a run's
chains would never be sealed, its stage PR never marked ``evidence-sealed``, and under ``"evidence": "enforce"`` the
router would hold that PR for good.

So the seal workflow also runs on a schedule. Each sweep lists the ended runs of the sealed workflows that were
started by ``github-actions[bot]`` in the last ``LOOKBACK_DAYS`` days, and names each one whose evidence artifacts
outnumber its sealed chains in the store. The seal job then downloads those runs' ``evidence-*`` artifacts and seals
them as it would for ``workflow_run``. A run started any other way gets ``workflow_run`` and is never swept, so the two
paths never seal the same run. A chain already sealed (an earlier sweep that stopped part way) is not sealed again:
``seal_runs`` with ``resume=True`` reads its records back for the PRs to mark and makes no second seal.
"""

from __future__ import annotations

import datetime
from typing import Callable, Dict, Iterable, List, Set

from evidence import EvidenceError
from evidence import seal as seal_mod
from evidence import store as store_mod

# The workflows the seal workflow's ``workflow_run`` names (its file, by name) and their files.
WORKFLOWS = {
    "Mission Agent": "mission-agent.yml",
    "Mission Router": "mission-router.yml",
    "Credentials Check": "credentials-check.yml",
    "Evidence Verify": "evidence-verify.yml",
}
TOKEN_ACTOR = "github-actions[bot]"  # who a run started with GITHUB_TOKEN is triggered by
LOOKBACK_DAYS = 2
EVIDENCE_PREFIX = "evidence-"


def run_prefix(run_id: int, attempt: int) -> str:
    """Every chain a run's jobs keep is named ``gh-<run id>-<attempt>-<job>...`` (the workflows' EVIDENCE_RUN)."""
    return f"gh-{int(run_id)}-{int(attempt)}-"


def sealed_chains(store_request: Callable) -> Set[str]:
    """The chains the store holds a seal for. Listed through the git trees API, which says when it is truncated."""
    store = store_mod.Store(store_request)
    root = store_request("GET", f"/git/trees/{store.branch}")
    runs = [e for e in root.get("tree", []) if e.get("path") == store_mod.RUNS and e.get("type") == "tree"]
    if not runs:
        return set()
    tree = store_request("GET", f"/git/trees/{runs[0]['sha']}?recursive=1")
    if tree.get("truncated"):
        raise EvidenceError("the store's runs/ tree is too large to list in one call; nothing was swept")
    out = set()
    for entry in tree.get("tree", []):
        parts = entry.get("path", "").split("/")
        if entry.get("type") == "blob" and len(parts) == 2 and parts[1] == seal_mod.SEAL:
            out.add(parts[0])
    return out


def _token_runs(request: Callable, workflow_file: str, since: str) -> Iterable[dict]:
    """The ended runs of one workflow, started by workflow_dispatch since ``since``, whose triggering actor is the
    token. GITHUB_TOKEN can start no other event a sealed workflow listens to."""
    page = 1
    while True:
        batch = request("GET", f"/actions/workflows/{workflow_file}/runs?event=workflow_dispatch&status=completed"
                               f"&created=%3E%3D{since}&per_page=100&page={page}")
        runs = batch.get("workflow_runs") or []
        for run in runs:
            if (run.get("triggering_actor") or {}).get("login") == TOKEN_ACTOR:
                yield run
        if len(runs) < 100:
            return
        page += 1


def _evidence_artifacts(request: Callable, run_id: int) -> int:
    batch = request("GET", f"/actions/runs/{int(run_id)}/artifacts?per_page=100")
    return sum(1 for a in batch.get("artifacts") or []
               if str(a.get("name", "")).startswith(EVIDENCE_PREFIX) and not a.get("expired"))


def unsealed_runs(request: Callable, store_request: Callable, now: datetime.datetime) -> List[Dict[str, int]]:
    """``[{"id", "attempt"}]``: each token-started run of a sealed workflow, in the lookback, with an evidence
    artifact the store holds no seal for. ``request`` reads this repository (Actions read); ``store_request`` the
    store."""
    since = (now - datetime.timedelta(days=LOOKBACK_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    sealed = sealed_chains(store_request)
    out = []
    for workflow_file in WORKFLOWS.values():
        for run in _token_runs(request, workflow_file, since):
            attempt = int(run.get("run_attempt") or 1)
            prefix = run_prefix(run["id"], attempt)
            have = sum(1 for chain in sealed if chain.startswith(prefix))
            if _evidence_artifacts(request, run["id"]) > have:
                out.append({"id": int(run["id"]), "attempt": attempt})
    return out
