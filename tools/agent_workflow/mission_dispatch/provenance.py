"""Proof checked against GitHub's own record (ring 4, MISSION-DISPATCH-001 §3l item 4, Amendment 018, part 2).

The gateway's ``trace`` tool tells an agent which mission made a file what it is. Its git-only walk reads identities
from commit author names, which whoever writes a commit chooses; GitHub's record of each landing's pull requests
(``evidence_graph.github_record``, rules G1-G4) is not chosen by the committer. Checking that record directly costs
about 11 API calls and 4.6 seconds per landing (measured on this repository's 15 landings, 2026-11-06), so it is not
redone in every job. Policy CI already checks every landing on ``main`` against it on every push
(``evidence_graph check --github``) and uploads the result as the ``evidence-graph`` artifact. So:

1. ``fetch`` (the ``plan`` job, which may read Actions): the newest ``evidence-graph`` artifact of a completed push
   run of ``.github/workflows/policy-ci.yml`` on the default branch, re-checked (its schema, its own digest, its head
   is the run's head) and handed to the agent jobs of this run as the ``provenance`` artifact, with where it came from.
   The download link is asked for without following its redirect, and the redirect is followed without the token,
   so the token never leaves the GitHub API.
2. ``record`` (``prepare``, with the run's read-only token): for each landing in the checkout's first-parent history,
   GitHub's result from that graph; a landing the graph does not hold (newer than it, or on a branch it never saw) is
   checked directly, at most ``MAX_DIRECT`` of them; any beyond that is ``"not checked"``. The record is written
   read-only beside the binding record, as ``binding/provenance.json``.
3. The gateway's ``trace`` reads it: under ``"supply_chain": "enforce"`` a landing is ``"proven": true`` only when its
   git rules and GitHub's record both pass; under ``"observe"`` the answer is as before, with GitHub's result beside
   it. A missing or unreadable record means every landing is ``"not checked"``.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional

POLICY_WORKFLOW = "policy-ci.yml"
POLICY_PATH = ".github/workflows/policy-ci.yml"
GRAPH_ARTIFACT, GRAPH_FILE = "evidence-graph", "evidence-graph.json"
HANDED_GRAPH, HANDED_SOURCE = "graph.json", "source.json"
RECORD_FILE = "provenance.json"
RECORD_SCHEMA = "provenance-record-v1"
MAX_RUNS = 20  # completed push runs looked at, newest first
MAX_ZIP_BYTES = 64 * 1024 * 1024
MAX_GRAPH_BYTES = 64 * 1024 * 1024
MAX_DIRECT = 10  # landings checked directly in one job (~11 API calls each)
PASSED, NOT_CHECKED = "passed", "not checked"


class ProvenanceError(RuntimeError):
    """The verified graph could not be fetched or does not check."""


# ------------------------------------------------------------------ the graph (plan job)
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # the caller follows it itself, without the token
        return None


def _download(url: str, token: str, timeout: int = 60) -> bytes:
    """An artifact's zip: the API answers with a redirect to a signed URL, which is fetched without the token."""
    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        opener.open(req, timeout=timeout)
        raise ProvenanceError("the artifact download did not redirect")
    except urllib.error.HTTPError as exc:
        if exc.code not in (301, 302, 303, 307, 308):
            raise ProvenanceError(f"the artifact download failed (HTTP {exc.code})") from None
        location = exc.headers.get("Location", "")
    if not location.startswith("https://"):
        raise ProvenanceError("the artifact download redirected to a non-https URL")
    with urllib.request.urlopen(urllib.request.Request(location, method="GET"), timeout=timeout) as reply:
        data = reply.read(MAX_ZIP_BYTES + 1)
    if len(data) > MAX_ZIP_BYTES:
        raise ProvenanceError("the artifact is too large")
    return data


def check_graph(doc: Any, head: str) -> dict:
    """The graph policy CI wrote: ``evidence-graph-v1``, its own digest holds, built at ``head``."""
    from evidence_graph.graph import SCHEMA, digest
    if not (isinstance(doc, dict) and doc.get("schema") == SCHEMA):
        raise ProvenanceError("the graph is not an evidence-graph-v1 document")
    if doc.get("digest") != digest(doc):
        raise ProvenanceError("the graph's digest does not hold")
    if doc.get("head") != head:
        raise ProvenanceError(f"the graph was built at {str(doc.get('head'))[:12]}, not the run's head {head[:12]}")
    if not isinstance(doc.get("nodes"), list) or not isinstance(doc.get("findings"), list):
        raise ProvenanceError("the graph has no nodes or findings list")
    return doc


def graph_from_zip(data: bytes, head: str) -> dict:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            info = archive.getinfo(GRAPH_FILE)
            if info.file_size > MAX_GRAPH_BYTES:
                raise ProvenanceError("the graph is too large")
            raw = archive.read(info)
    except (zipfile.BadZipFile, KeyError) as exc:
        raise ProvenanceError(f"the artifact holds no {GRAPH_FILE} ({type(exc).__name__})") from None
    try:
        doc = json.loads(raw)
    except ValueError:
        raise ProvenanceError("the graph is not JSON") from None
    return check_graph(doc, head)


def fetch(gh: Any, token: str, default_branch: str, out_dir: Path,
          download: Callable[[str, str], bytes] = _download) -> dict:
    """Write the newest verified graph and its source to ``out_dir``; returns the source. Raises ProvenanceError."""
    runs = gh.get(f"/actions/workflows/{POLICY_WORKFLOW}/runs?branch={default_branch}&event=push&status=completed"
                  f"&per_page={MAX_RUNS}") or {}
    problems: List[str] = []
    for run in runs.get("workflow_runs") or []:
        if not (isinstance(run, dict) and run.get("path") == POLICY_PATH and run.get("event") == "push"
                and run.get("head_branch") == default_branch
                and (run.get("repository") or {}).get("full_name") == gh.repo):
            continue
        head = str(run.get("head_sha", ""))
        try:
            artifacts = gh.get(f"/actions/runs/{run['id']}/artifacts?name={GRAPH_ARTIFACT}") or {}
            found = [a for a in artifacts.get("artifacts") or [] if a.get("name") == GRAPH_ARTIFACT
                     and not a.get("expired")]
            if not found:
                problems.append(f"run {run['id']}: no {GRAPH_ARTIFACT} artifact")
                continue
            artifact = found[0]
            data = download(artifact["archive_download_url"], token)
            doc = graph_from_zip(data, head)
        except (ProvenanceError, OSError, KeyError, ValueError) as exc:
            problems.append(f"run {run.get('id')}: {exc}")
            continue
        source = {"workflow": POLICY_PATH, "run_id": run["id"], "run_head": head, "run_url": run.get("html_url", ""),
                  "conclusion": run.get("conclusion"), "artifact_id": artifact.get("id"),
                  "artifact_sha256": hashlib.sha256(data).hexdigest(), "graph_digest": doc["digest"]}
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / HANDED_GRAPH).write_text(json.dumps(doc, sort_keys=True), encoding="utf-8")
        (out_dir / HANDED_SOURCE).write_text(json.dumps(source, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return source
    raise ProvenanceError("no verified evidence graph from policy CI on the default branch"
                          + (f" ({'; '.join(problems[:3])})" if problems else ""))


# ------------------------------------------------------------------ the record (prepare)
def _graph_results(doc: Mapping) -> Dict[str, str]:
    """Each landing the graph holds: ``passed``, or ``finding: <first G-rule finding>``."""
    landings = {str(n["id"])[len("commit:"):] for n in doc.get("nodes", [])
                if isinstance(n, dict) and n.get("kind") == "landing" and str(n.get("id", "")).startswith("commit:")}
    results = {sha: PASSED for sha in landings}
    for finding in doc.get("findings", []):
        if isinstance(finding, dict) and str(finding.get("rule", "")).startswith("G") and finding.get("landing") in results:
            if results[finding["landing"]] == PASSED:
                results[finding["landing"]] = f"finding: {finding.get('rule')} {str(finding.get('detail', ''))[:300]}"
    return results


def handed_graph(folder: Optional[Path]) -> Optional[tuple]:
    """The graph the plan job handed over, re-checked; None when there is none or it does not check."""
    if folder is None:
        return None
    try:
        source = json.loads((folder / HANDED_SOURCE).read_text(encoding="utf-8"))
        doc = check_graph(json.loads((folder / HANDED_GRAPH).read_text(encoding="utf-8")), source["run_head"])
    except (OSError, ValueError, KeyError, ProvenanceError):
        return None
    if doc["digest"] != source.get("graph_digest"):
        return None
    return doc, source


def record(root: Path, checkout: Path, git_dir: Path, mode: str, folder: Optional[Path],
           verify: Optional[Callable] = None, log: Callable[[str], None] = print) -> dict:
    """Write ``binding/provenance.json`` (read-only) for the checkout's landings and return it."""
    from evidence_graph import history as evidence_history
    from evidence_graph.graph import walk
    repo = evidence_history.Repo(str(checkout), str(git_dir))
    repo.ensure_full_history()
    ids = evidence_history.load_identities()  # the tooling tree's router config, never the checkout's
    head = repo.resolve("HEAD")
    entries = walk(repo, ids, head)  # git rules only; GitHub's record comes from the graph or a direct check
    handed = handed_graph(folder)
    from_graph = _graph_results(handed[0]) if handed else {}
    results: Dict[str, str] = {}
    direct = 0
    for entry in reversed(entries):  # newest first, so the direct budget goes to the landings the graph lacks first
        if entry.kind != evidence_history.LANDING:
            continue
        sha = entry.commit.sha
        if not entry.proof.authentic:  # R1 failed: GitHub's record is never asked, so it is never a pass
            results[sha] = f"{NOT_CHECKED} (the landing fails git rule R1)"
        elif sha in from_graph:
            results[sha] = from_graph[sha]
        elif verify is not None and direct < MAX_DIRECT:
            direct += 1
            before = len(entry.proof.findings)
            try:
                verify(entry.proof, repo, ids)
                found = [f for f in entry.proof.findings[before:] if str(f.get("rule", "")).startswith("G")]
                results[sha] = (f"finding: {found[0]['rule']} {str(found[0]['detail'])[:300]}" if found else PASSED)
            except Exception as exc:  # a record that cannot be read is never a pass
                results[sha] = f"{NOT_CHECKED} ({type(exc).__name__})"
        else:
            results[sha] = NOT_CHECKED
    doc = {"schema": RECORD_SCHEMA, "mode": mode, "head": head,
           "source": handed[1] if handed else None, "checked_directly": direct, "landings": results}
    path = root / "binding" / RECORD_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        path.chmod(0o644)
        path.unlink()
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o444)
    passed = sum(1 for v in results.values() if v == PASSED)
    log(f"provenance: {len(results)} landing(s): {passed} passed GitHub's record, "
        f"{sum(1 for v in results.values() if v.startswith('finding'))} with findings, "
        f"{sum(1 for v in results.values() if v.startswith(NOT_CHECKED))} not checked "
        f"(graph from {'policy CI run ' + str(handed[1]['run_id']) if handed else 'nowhere'}; "
        f"{direct} checked directly; mode={mode})")
    return doc


def read_record(session_path: Path) -> dict:
    """The record beside the gateway's session file; ``{}`` when there is none or it cannot be read."""
    path = session_path.parent / RECORD_FILE
    if path.is_symlink() or not path.is_file():
        return {}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) and doc.get("schema") == RECORD_SCHEMA else {}
