"""The evidence graph (PLAN §3): nodes, edges, findings, counts and the canonical JSON form."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from .chain import LandingProof, prove
from .history import DIRECT, HAND_MERGE, LANDING, Commit, Identities, Repo, classify

SCHEMA = "evidence-graph-v1"
FIELDS = ("schema", "ref", "head", "nodes", "edges", "findings", "counts", "digest")
# Relation names are carried over from the retired governance/context/reporting vocabulary.
SPECIFIES, APPROVES, IMPLEMENTS, PRODUCES = "SPECIFIES", "APPROVES", "IMPLEMENTS", "PRODUCES"
REVIEWS, FINDS_MISMATCH, CORRECTS, MERGED_AS, CHANGES = "REVIEWS", "FINDS_MISMATCH", "CORRECTS", "MERGED_AS", "CHANGES"
RELATIONS = (SPECIFIES, APPROVES, IMPLEMENTS, PRODUCES, REVIEWS, FINDS_MISMATCH, CORRECTS, MERGED_AS, CHANGES)
NO_REVIEW = "none"


@dataclass(frozen=True)
class Entry:
    """One commit of the first-parent walk."""

    commit: Commit
    kind: str  # landing, hand_merge or direct
    position: int
    pr: Optional[int] = None
    proof: Optional[LandingProof] = None


def walk(repo: Repo, ids: Identities, head: str) -> List[Entry]:
    """The first-parent history of ``head``, oldest first, with every landing proved."""
    entries = []
    for position, commit in enumerate(repo.first_parent(head)):
        kind, match = classify(commit)
        if kind == LANDING:
            proof = prove(repo, ids, commit, position, match.group(1), int(match.group(2)))
            entries.append(Entry(commit, kind, position, proof=proof))
        elif kind == HAND_MERGE:
            entries.append(Entry(commit, kind, position, pr=int(match.group(1))))
        else:
            entries.append(Entry(commit, kind, position))
    return entries


def sorted_findings(entries: List[Entry]) -> List[dict]:
    findings = [f for e in entries if e.proof for f in e.proof.findings]
    return sorted(findings, key=lambda f: (f["landing"], f["rule"], f["detail"]))


def counts(entries: List[Entry]) -> Dict[str, int]:
    landings = [e for e in entries if e.kind == LANDING]
    return {"landings": len(landings), "proven": sum(1 for e in landings if e.proof.proven),
            "findings": sum(len(e.proof.findings) for e in landings),
            "hand_merges": sum(1 for e in entries if e.kind == HAND_MERGE),
            "direct": sum(1 for e in entries if e.kind == DIRECT)}


def canonical(doc: dict) -> bytes:
    """Sorted keys, compact separators, UTF-8 and a final newline. A path git gave as undecodable
    bytes is written back as those same bytes."""
    text = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n"
    return text.encode("utf-8", "surrogateescape")


def digest(doc: dict) -> str:
    """SHA-256 hex of the canonical document without ``digest``."""
    return hashlib.sha256(canonical({k: v for k, v in doc.items() if k != "digest"})).hexdigest()


def _commit_id(sha: str) -> str:
    return f"commit:{sha}"


class _Builder:
    def __init__(self) -> None:
        self.nodes: Dict[str, dict] = {}
        self.edges: Set[Tuple[str, str, str]] = set()

    def node(self, node_id: str, kind: str, **attrs) -> None:
        # A commit can be reached from two landings (a shared range); the earliest landing's view is kept.
        self.nodes.setdefault(node_id, {"id": node_id, "kind": kind, **attrs})

    def edge(self, source: str, target: str, relation: str) -> None:
        self.edges.add((source, target, relation))


def _landing(b: _Builder, proof: LandingProof) -> None:
    mission_id = f"mission:{proof.mission}"
    b.node(_commit_id(proof.commit.sha), "landing", mission=proof.mission, position=proof.position)
    b.edge(mission_id, _commit_id(proof.commit.sha), MERGED_AS)
    if not proof.authentic:
        return
    plan = _commit_id(proof.plan_sha) if proof.plan_sha else None
    if plan:
        b.node(plan, "plan", mission=proof.mission, unresolved_specs=list(proof.unresolved_specs))
        for path in proof.specs:
            b.node(f"spec:{path}", "spec")
            b.edge(f"spec:{path}", plan, SPECIFIES)
    if proof.approval is not None:
        approval = _commit_id(proof.approval.sha)
        b.node(approval, "approval", mission=proof.mission, approval=proof.approval_kind)
        if plan:
            b.edge(approval, plan, APPROVES)
    for k, sha in sorted(proof.build_merges.items()):
        b.node(_commit_id(sha), "build_merge", mission=proof.mission, round=k)
    for build in proof.builds:
        build_id = _commit_id(build.commit.sha)
        b.node(build_id, "build", mission=proof.mission, round=build.round)
        if plan:
            b.edge(build_id, plan, IMPLEMENTS)
        for path in build.files:
            b.node(f"file:{path}", "file")
            b.edge(build_id, f"file:{path}", PRODUCES)
    for k, review in sorted(proof.reviews.items()):
        review_id = f"review:{proof.mission}:{k}"
        b.node(review_id, "review", mission=proof.mission, round=k, verdict=review.verdict,
               reviewed_sha=review.reviewed_sha, path=review.path)
        if review.reviewed_sha is not None and proof.build_merges.get(k) == review.reviewed_sha:
            b.edge(review_id, _commit_id(review.reviewed_sha), REVIEWS)
            if review.verdict == "FAIL":
                b.edge(review_id, _commit_id(review.reviewed_sha), FINDS_MISMATCH)
    for build in proof.builds:
        if build.round is not None and build.round - 1 in proof.reviews:
            b.edge(_commit_id(build.commit.sha), f"review:{proof.mission}:{build.round - 1}", CORRECTS)


def document(repo: Repo, ref: str, head: str, entries: List[Entry]) -> dict:
    """The ``evidence-graph-v1`` document, in canonical order, with its digest."""
    b = _Builder()
    by_mission: Dict[str, List[LandingProof]] = {}
    for entry in entries:
        if entry.kind == LANDING:
            by_mission.setdefault(entry.proof.mission, []).append(entry.proof)
            _landing(b, entry.proof)
            continue
        commit_id = _commit_id(entry.commit.sha)
        if entry.kind == HAND_MERGE:
            b.node(commit_id, HAND_MERGE, pr=entry.pr, position=entry.position, independent_review=NO_REVIEW)
        else:
            b.node(commit_id, DIRECT, position=entry.position, independent_review=NO_REVIEW)
        for path in repo.files(entry.commit):
            b.node(f"file:{path}", "file")
            b.edge(commit_id, f"file:{path}", CHANGES)
    # A mission that landed more than once is proven only if every landing is; the rest is the latest's.
    for mission, proofs in by_mission.items():
        latest = proofs[-1]
        b.nodes[f"mission:{mission}"] = {"id": f"mission:{mission}", "kind": "mission", "title": latest.title,
                                         "proven": all(p.proven for p in proofs), "approval": latest.approval_kind,
                                         "rounds": latest.round}
    doc = {
        "schema": SCHEMA,
        "ref": ref,
        "head": head,
        "nodes": [b.nodes[k] for k in sorted(b.nodes)],
        "edges": [{"from": s, "to": t, "relation": r} for s, t, r in sorted(b.edges)],
        "findings": sorted_findings(entries),
        "counts": counts(entries),
    }
    doc["digest"] = digest(doc)
    return doc


def build_graph(repo: Repo, ids: Identities, ref: str) -> Tuple[dict, List[Entry]]:
    """Refuse a shallow clone, resolve ``ref``, walk it and build the graph."""
    repo.ensure_full_history()
    head = repo.resolve(ref)
    entries = walk(repo, ids, head)
    return document(repo, ref, head, entries), entries
