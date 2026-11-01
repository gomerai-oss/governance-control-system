"""The proof rules R1-R8 for one mission landing (PLAN §2).

For a landing ``L`` of mission ``ID`` in round ``N``: ``base`` = ``L^1``, ``top`` = ``L^2``,
``mdir`` = ``missions/ID/``, and the range is ``git log base..top``. Every failed rule is a
finding; a landing with no findings is proven. Besides the findings, ``prove`` keeps what it
established (approval, plan, builds, reviews, specs) so the graph can draw only that.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from mission_router.model import (MAX_ROUNDS_CEILING, MissionInputError, in_scope, manifest_path, mission_dir,
                                  parse_manifest, verdict_path)

from .history import Commit, Identities, Repo, authored_by

VERDICT_SCHEMA = "mission-verdict-v1"
ROUTER, HITL_MERGE = "router", "hitl-merge"
SPEC_RE = re.compile(r"\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-[0-9]{3}\b")


@dataclass(frozen=True)
class Build:
    commit: Commit
    round: Optional[int]  # the k of the ``merge A2 round k`` whose second-parent side holds it
    files: Tuple[str, ...]


@dataclass(frozen=True)
class Review:
    round: int
    verdict: Optional[str]
    reviewed_sha: Optional[str]
    path: str


@dataclass
class LandingProof:
    commit: Commit
    position: int
    mission: str
    round: int
    findings: List[dict] = field(default_factory=list)
    authentic: bool = False  # R1 held; only then do R2-R8 run
    title: Optional[str] = None
    approval: Optional[Commit] = None
    approval_kind: Optional[str] = None
    plan_sha: Optional[str] = None
    specs: Tuple[str, ...] = ()
    unresolved_specs: Tuple[str, ...] = ()
    builds: List[Build] = field(default_factory=list)
    build_merges: Dict[int, str] = field(default_factory=dict)
    reviews: Dict[int, Review] = field(default_factory=dict)

    @property
    def proven(self) -> bool:
        return not self.findings

    @property
    def rules(self) -> List[str]:
        return sorted({f["rule"] for f in self.findings}, key=lambda r: int(r[1:]))

    def find(self, rule: str, detail: str) -> None:
        self.findings.append({"mission": self.mission, "landing": self.commit.sha, "rule": rule, "detail": detail})


def _who(commit: Commit) -> str:
    return f"{commit.author_name} <{commit.author_email}>"


def approval_kind(commit: Commit, mission: str, ids: Identities) -> Optional[str]:
    """``router`` or ``hitl-merge`` when the commit is one of R3's two approval forms, else None."""
    if len(commit.parents) != 2:
        return None
    if authored_by(commit, ids.bot) and commit.subject == f"Mission {mission}: merge A1":
        return ROUTER
    if (any(authored_by(commit, login) for login in ids.hitl)
            and re.fullmatch(rf"Merge pull request #[0-9]+ from \S+/mission/{re.escape(mission)}/a1", commit.subject)):
        return HITL_MERGE
    return None


def _verdict(text: Optional[str], mission: str, round_no: int) -> Tuple[Optional[dict], str]:
    """The verdict object, or None with the reason it does not parse as R4 requires."""
    if text is None:
        return None, "missing"
    try:
        data = json.loads(text)
    except ValueError as exc:
        return None, f"not valid JSON ({exc})"
    if not isinstance(data, dict):
        return None, "not a JSON object"
    if data.get("schema") != VERDICT_SCHEMA:
        return None, f"schema is not {VERDICT_SCHEMA}"
    if data.get("mission_id") != mission:
        return None, f"mission_id is not {mission}"
    if data.get("round") != round_no or isinstance(data.get("round"), bool):
        return None, f"round is not {round_no}"
    return data, ""


def _specs(repo: Repo, proof: LandingProof) -> None:
    """Spec names in the plan text, resolved against the tree at the landing."""
    plan_path = mission_dir(proof.mission) + "PLAN.md"
    plan_text = repo.show(proof.plan_sha, plan_path)
    if plan_text is None:
        plan_text = repo.show(proof.commit.sha, plan_path)
    tokens = sorted({t for t in SPEC_RE.findall(plan_text or "") if not t.startswith("M-")})
    if not tokens:
        return
    by_name: Dict[str, List[str]] = {}
    for path in repo.tree(proof.commit.sha):
        by_name.setdefault(path.rsplit("/", 1)[-1], []).append(path)
    resolved, unresolved = set(), set()
    for token in tokens:
        hits = by_name.get(f"{token}.md", [])
        if len(hits) == 1:
            resolved.add(hits[0])
        else:
            unresolved.add(token)
    proof.specs, proof.unresolved_specs = tuple(sorted(resolved)), tuple(sorted(unresolved))


def prove(repo: Repo, ids: Identities, commit: Commit, position: int, mission: str, round_n: int) -> LandingProof:
    proof = LandingProof(commit, position, mission, round_n)

    # R1: the bot merged it, as a two-parent merge.
    if not authored_by(commit, ids.bot):
        proof.find("R1", f"landing is authored by {_who(commit)}, not {ids.bot}")
    if len(commit.parents) != 2:
        proof.find("R1", f"landing has {len(commit.parents)} parents, not 2")
    if proof.findings:
        return proof
    proof.authentic = True
    base, top = commit.parents
    mdir = mission_dir(mission)
    commits = repo.range(base, top)

    # R2: the manifest at L parses. Without it R5 has no scope and is skipped.
    manifest = None
    try:
        manifest = parse_manifest(repo.show(commit.sha, manifest_path(mission)), mission)
        proof.title = manifest.title
    except MissionInputError as exc:
        proof.find("R2", f"{manifest_path(mission)}: {exc}")

    # R3: exactly one approval commit; the plan commit is its second parent.
    approvals = [c for c in commits if approval_kind(c, mission, ids)]
    if len(approvals) == 1:
        proof.approval = approvals[0]
        proof.approval_kind = approval_kind(approvals[0], mission, ids)
        proof.plan_sha = approvals[0].parents[1]
    else:
        proof.find("R3", f"range holds {len(approvals)} approval commits, not 1"
                   + (f" ({', '.join(sorted(c.sha[:12] for c in approvals))})" if approvals else ""))

    # R4: a verdict per round, each naming its round's merge A2 commit; the final one sits under top.
    rounds = min(round_n, MAX_ROUNDS_CEILING)
    if round_n > MAX_ROUNDS_CEILING:
        proof.find("R4", f"round {round_n} exceeds the ceiling of {MAX_ROUNDS_CEILING} rounds")
    for k in range(1, rounds + 1):
        path = verdict_path(mission, k)
        data, problem = _verdict(repo.show(commit.sha, path), mission, k)
        if data is None:
            proof.find("R4", f"{path}: {problem}")
        else:
            verdict, reviewed = data.get("verdict"), data.get("reviewed_sha")
            proof.reviews[k] = Review(k, verdict if isinstance(verdict, str) else None,
                                      reviewed if isinstance(reviewed, str) else None, path)
        subject = f"Mission {mission}: merge A2 round {k}"
        merges = [c for c in commits if len(c.parents) == 2 and authored_by(c, ids.bot) and c.subject == subject]
        if len(merges) != 1:
            proof.find("R4", f"range holds {len(merges)} '{subject}' commits by {ids.bot}, not 1")
            continue
        proof.build_merges[k] = merges[0].sha
        review = proof.reviews.get(k)
        if review is not None and review.reviewed_sha != merges[0].sha:
            proof.find("R4", f"round {k} reviewed_sha {review.reviewed_sha} is not the merge A2 round {k} commit "
                             f"{merges[0].sha}")
    top_commit = repo.commit(top)
    final = proof.reviews.get(round_n)
    if not top_commit.parents:
        proof.find("R4", f"top {top[:12]} has no parent")
    elif final is not None and top_commit.parents[0] != final.reviewed_sha:
        proof.find("R4", f"top's first parent {top_commit.parents[0]} is not round {round_n} reviewed_sha "
                         f"{final.reviewed_sha}")

    # R5 / R6: the builder stays in build_scope (or mdir), the reviewer in mdir/reviews/.
    for c in commits:
        if c.is_merge:
            continue
        if manifest is not None and authored_by(c, ids.a2):
            for path in repo.files(c):
                if not (in_scope(path, manifest.build_scope) or path.startswith(mdir)):
                    proof.find("R5", f"{c.sha[:12]} changes {path} outside build_scope")
        if authored_by(c, ids.a3):
            for path in repo.files(c):
                if not path.startswith(mdir + "reviews/"):
                    proof.find("R6", f"{c.sha[:12]} changes {path} outside {mdir}reviews/")

    # R7: only the bot merges (besides the approval), and nobody else changes code.
    approval_shas = {c.sha for c in approvals}
    for c in commits:
        if c.is_merge:
            if c.sha not in approval_shas and not authored_by(c, ids.bot):
                proof.find("R7", f"merge {c.sha[:12]} is authored by {_who(c)}, not {ids.bot}")
        elif not authored_by(c, ids.a2) and not authored_by(c, ids.a3):
            for path in repo.files(c):
                if not path.startswith(mdir):
                    proof.find("R7", f"{c.sha[:12]} by {_who(c)} changes {path} outside {mdir}")

    # R8: every round but the last failed, the last passed.
    for k, review in sorted(proof.reviews.items()):
        want = "PASS" if k == round_n else "FAIL"
        if review.verdict != want:
            proof.find("R8", f"round {k} verdict is {review.verdict}, not {want}")

    # What the graph draws: builds with their rounds, and the plan's spec links.
    sides: Dict[str, int] = {}
    for k in sorted(proof.build_merges):
        merge = repo.commit(proof.build_merges[k])
        for c in repo.range(merge.parents[0], merge.parents[1]):
            sides.setdefault(c.sha, k)
    proof.builds = [Build(c, sides.get(c.sha), repo.files(c))
                    for c in sorted(commits, key=lambda c: c.sha) if not c.is_merge and authored_by(c, ids.a2)]
    if proof.plan_sha:
        _specs(repo, proof)
    return proof
