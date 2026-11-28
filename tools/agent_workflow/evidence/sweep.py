"""The seal sweep (§3m item 2; Amendments 022 and 047): find the ended runs whose evidence is not all sealed.

The seal workflow runs on a schedule only (Amendment 047). It used to start on ``workflow_run`` as well, after every
run of the sealed workflows; most of those runs (router sweeps and dispatcher plans that found nothing to do) kept no
evidence, and each still cost two jobs. GitHub sends no ``workflow_run`` for a run started with a workflow's own
``GITHUB_TOKEN`` anyway, which is how the router starts every Mission Agent run it dispatches (Amendment 022), so the
schedule was already the only path for those.

Each sweep lists this repository's unexpired chain artifacts (``CHAIN_ARTIFACT``) from the last ``LOOKBACK_DAYS``
days, in one paged call, and counts them per run. Once a day the deep sweep looks back ``DEEP_LOOKBACK_DAYS``
instead, past the time GitHub keeps a chain artifact, so an outage longer than ``LOOKBACK_DAYS`` loses nothing that
still exists, and an artifact that expired unsealed is named as lost (Amendment 057). A sweep names at most
``MAX_RUNS`` runs, oldest first; the rest wait for the next one. A run with more evidence artifacts than chains sealed in the store is read once:
it is named when it has ended and is a run of a sealed workflow. So is a run whose publish chain names an open stage
PR with no ``evidence-sealed`` on its head, even when every chain is sealed: a sweep that sealed it and then stopped, or
whose mark job failed, never marked that PR (Amendment 049). The seal job then downloads those runs' ``evidence-*``
artifacts and seals them. A chain already sealed (an earlier sweep that stopped part way) is not sealed again:
``seal_runs`` with ``resume=True`` reads its records back for the PRs to mark and makes no second seal.
"""

from __future__ import annotations

import datetime
import re
from typing import Callable, Dict, List, Set, Tuple

from evidence import EvidenceError
from evidence import seal as seal_mod
from evidence import sealer as sealer_mod
from evidence import store as store_mod

# The sealed workflows, by name, and their files.
WORKFLOWS = {
    "Mission Agent": "mission-agent.yml",
    "Mission Router": "mission-router.yml",
    "Mission Clock": "mission-clock.yml",  # the router's sweep while a mission is open (router Amendment 028)
    "Credentials Check": "credentials-check.yml",
    "Evidence Verify": "evidence-verify.yml",
    "Evidence Pack": "evidence-pack.yml",  # who summoned which pack (Amendment 061)
}
LOOKBACK_DAYS = 2
# The daily deep sweep (Amendment 057) looks back a week further than GitHub keeps a chain artifact (each evidence
# upload's retention-days, 90): a run an outage left unsealed for longer than LOOKBACK_DAYS is still sealed while its
# chains exist, and one whose chain artifact expired unsealed is still seen, and named as lost.
ARTIFACT_RETENTION_DAYS = 90
DEEP_LOOKBACK_DAYS = ARTIFACT_RETENTION_DAYS + 7
# At most this many runs per sweep, oldest first: a backlog is sealed over several sweeps, inside the job's time limit.
MAX_RUNS = 50
EVIDENCE_PREFIX = "evidence-"
# The evidence chain artifacts the sealed workflows upload (Amendment 057). Another workflow's artifact that happens to
# start with "evidence-" (Policy CI's evidence-graph) is not a chain: it is not counted, and its run is never read.
CHAIN_ARTIFACT = re.compile(r"evidence-(router|credentials|verify|withdraw|summon|agent-.+|baseline-.+|checks-.+|perform-.+|"
                            r"publish-.+|report-.+|secscan-.+)")


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


# The publish job's chain, named by the stage it published (mission-agent.yml): its run published that stage's PR.
_PUBLISH = re.compile(r"evidence-publish-(M-[A-Z0-9-]+)-(A2|A3|AR)-r([1-9][0-9]*)")


def _evidence_counts(request: Callable, since: str, expired: Dict[int, int] = None
                     ) -> Tuple[Dict[int, int], Dict[str, Tuple[str, int]]]:
    """``{run id: unexpired chain artifacts}`` for the artifacts created since ``since``, and ``{stage branch:
    (created at, run id)}``, the newest run whose publish chain names that stage. ``expired``, when given, gains
    ``{run id: expired chain artifacts}``. GitHub lists a repository's artifacts newest first, though not strictly, so
    paging stops only after a whole page older than ``since``, or at the last page."""
    counts: Dict[int, int] = {}
    published: Dict[str, Tuple[str, int]] = {}
    page = 1
    while True:
        batch = request("GET", f"/actions/artifacts?per_page=100&page={page}") or {}
        artifacts = batch.get("artifacts") or []
        for a in artifacts:
            run = (a.get("workflow_run") or {}).get("id")
            name, created = str(a.get("name", "")), str(a.get("created_at", ""))
            if not (CHAIN_ARTIFACT.fullmatch(name) and run and created >= since):
                continue
            if a.get("expired"):
                if expired is not None:
                    expired[int(run)] = expired.get(int(run), 0) + 1
                continue
            counts[int(run)] = counts.get(int(run), 0) + 1
            stage = _PUBLISH.fullmatch(name)
            if stage:
                branch = f"mission/{stage.group(1)}/{stage.group(2).lower()}-r{stage.group(3)}"
                if branch not in published or published[branch] < (created, int(run)):
                    published[branch] = (created, int(run))
        if len(artifacts) < 100 or all(str(a.get("created_at", "")) < since for a in artifacts):
            return counts, published
        page += 1


def _unmarked(request: Callable, published: Dict[str, Tuple[str, int]]) -> List[int]:
    """The runs that published an open stage PR whose head has no ``evidence-sealed`` from this repository's
    workflows (Amendment 049). Their chains may all be sealed: a sweep that sealed them and then stopped, or whose
    mark job failed, never marked the PR, and no later sweep read the run again. A publish chain older than the PR
    is an earlier attempt at the same stage, not this PR's run. One call lists the open PRs, and one call per open
    stage PR the sweep has a publishing run for reads its head's checks."""
    if not published:
        return []
    runs = []
    for pr in request("GET", "/pulls?state=open&per_page=100") or []:
        head = pr.get("head") or {}
        created, run = published.get(str(head.get("ref", "")), ("", None))
        if run is None or not head.get("sha") or created < str(pr.get("created_at", "")):
            continue
        sha = head["sha"]
        checks = request("GET", f"/commits/{sha}/check-runs?check_name={sealer_mod.CHECK_NAME}&per_page=100")
        if not any((c.get("app") or {}).get("slug") == "github-actions" and c.get("conclusion") == "success"
                   for c in (checks or {}).get("check_runs") or []):
            runs.append(run)
    return runs


def _workflow_file(run: dict) -> str:
    """``mission-agent.yml`` from a run's ``path`` (``.github/workflows/mission-agent.yml``, maybe ``@ref``)."""
    return str(run.get("path") or "").split("@", 1)[0].rsplit("/", 1)[-1]


def unsealed_runs(request: Callable, store_request: Callable, now: datetime.datetime, deep: bool = False,
                  lost: List[Dict[str, int]] = None) -> List[Dict[str, int]]:
    """``[{"id", "attempt"}]``: each ended run of a sealed workflow, with a chain artifact from the lookback, that
    holds more chain artifacts than the store holds seals for, oldest first and at most ``MAX_RUNS``. ``deep`` (the
    daily deep sweep, Amendment 057) looks back ``DEEP_LOOKBACK_DAYS``, beyond the time GitHub keeps a chain artifact,
    and adds to ``lost`` each run of a sealed workflow whose chain artifact expired before the store held its seal.
    ``request`` reads this repository (Actions read); ``store_request`` the store."""
    days = DEEP_LOOKBACK_DAYS if deep else LOOKBACK_DAYS
    since = (now - datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    sealed = sealed_chains(store_request)
    files = set(WORKFLOWS.values())
    out = []
    expired: Dict[int, int] = {}
    counts, published = _evidence_counts(request, since, expired if deep else None)
    unmarked = set(_unmarked(request, published))
    for run_id, count in sorted(counts.items()):
        if count <= sum(1 for chain in sealed if chain.startswith(f"gh-{run_id}-")) and run_id not in unmarked:
            continue  # every artifact has its seal and nothing is left to mark: no need to read the run
        run = request("GET", f"/actions/runs/{run_id}")
        if run.get("status") != "completed" or _workflow_file(run) not in files:
            continue  # still running (the next sweep has it), or not a sealed workflow
        attempt = int(run.get("run_attempt") or 1)
        prefix = run_prefix(run_id, attempt)
        if count > sum(1 for chain in sealed if chain.startswith(prefix)) or run_id in unmarked:
            out.append({"id": run_id, "attempt": attempt})  # an unmarked run is all sealed: --resume marks it
    if lost is not None:
        for run_id, gone in sorted(expired.items()):
            held = sum(1 for chain in sealed if chain.startswith(f"gh-{run_id}-"))
            if held < gone + counts.get(run_id, 0):
                run = request("GET", f"/actions/runs/{run_id}")
                if _workflow_file(run) in files:
                    lost.append({"id": run_id, "attempt": int(run.get("run_attempt") or 1)})
    return out[:MAX_RUNS]
