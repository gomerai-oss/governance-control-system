"""GitHub's own record of each landing, checked against the chain proved from git (rules G1-G4).

The rules in ``chain.py`` read identities from commit author names and e-mails, which whoever writes a commit
chooses. GitHub's record is not chosen by the committer: which pull request a merge commit closed, who opened
that pull request, who merged it, and which commits it carried. For every landing, each merge the chain names
must be the merge commit of a merged pull request on the expected stage branch, opened and merged by the
expected identities:

G1  the landing      merges ``mission/<ID>/a3-r<N>``, opened by A3, merged by the bot
G2  the approval     merges ``mission/<ID>/a1``: merged by the bot, with a HITL ``/mission approve <head>`` comment
                     on that pull request naming its head, which is the plan commit; or merged by a HITL login.
                     A HITL approval of an earlier plan commit counts when it carried to the head (MISSION-ROUTER-001
                     Amendment 025): that commit is in the head's history, AR's latest round at the head is
                     NO_CHALLENGE, came in through AR's own pull request merged by the bot and is unchanged since,
                     A1 has not answered it, and no plan file changed since the commit AR read
G3  each build       ``merge A2 round k`` merges ``mission/<ID>/a2-r<k>``, opened by A2, merged by the bot; every
                     commit GitHub lists in that pull request stays inside build_scope and out of ``missions/``
                     (the router's own rule for A2), whatever its author name says
G4  each failed round ``merge A3 round k (FAIL)`` merges ``mission/<ID>/a3-r<k>``, opened by A3, merged by the bot

Logins are compared case-insensitively, as GitHub treats them. A pull request whose GitHub record cannot be read
is a finding, never a pass.
"""

from __future__ import annotations

from typing import Callable, Dict, Optional

from mission_router import challenge as challenge_mod
from mission_router.model import MissionInputError, in_scope, manifest_path, parse_manifest
from mission_router.router import _APPROVE_RE  # the router's own approval syntax, so the two never drift

from .chain import LandingProof
from .history import Identities, Repo

MAX_PR_COMMITS = 250  # GitHub lists at most 250 commits of a pull request


def _login(user: Optional[dict]) -> str:
    return str((user or {}).get("login", "")).casefold()


class Record:
    """Read-only lookups of GitHub's record, cached for the run. ``gh`` is a ``mission_router.github.GitHub``."""

    def __init__(self, gh) -> None:
        self.gh = gh
        self._merged: Dict[str, Optional[dict]] = {}

    def merged_pull(self, sha: str) -> Optional[dict]:
        """The merged pull request whose merge commit is ``sha``, or None."""
        if sha not in self._merged:
            found = None
            for pr in self.gh.get(f"/commits/{sha}/pulls") or []:
                if pr.get("merge_commit_sha") == sha and pr.get("merged_at"):
                    found = pr
                    break
            if found is not None:
                found = self.gh.get(f"/pulls/{found['number']}")  # merged_by is only on the single-PR record
            self._merged[sha] = found
        return self._merged[sha]

    def comments(self, number: int) -> list:
        return list(self.gh.paginate(f"/issues/{number}/comments", limit=1000))

    def commits(self, number: int) -> list:
        return list(self.gh.paginate(f"/pulls/{number}/commits", limit=MAX_PR_COMMITS))


def _stage(proof: LandingProof, rec: Record, rule: str, sha: Optional[str], branch: str, opener: Optional[str],
           mergers: set, what: str) -> Optional[dict]:
    """The pull request GitHub records for merge ``sha``, checked; findings go on ``proof`` under ``rule``."""
    if not sha:
        return None
    try:
        pr = rec.merged_pull(sha)
    except Exception as exc:  # an unreadable record is never a pass
        proof.find(rule, f"{what} {sha[:12]}: GitHub's record cannot be read ({type(exc).__name__})")
        return None
    if pr is None:
        proof.find(rule, f"{what} {sha[:12]} is not the merge commit of any merged pull request")
        return None
    number = pr.get("number")
    head = (pr.get("head") or {}).get("ref", "")
    if head != branch:
        proof.find(rule, f"{what} {sha[:12]} merged #{number} from {head!r}, not {branch!r}")
    if opener is not None and _login(pr.get("user")) != opener.casefold():
        proof.find(rule, f"{what} #{number} was opened by {_login(pr.get('user')) or '-'}, not {opener}")
    if _login(pr.get("merged_by")) not in mergers:
        proof.find(rule, f"{what} #{number} was merged by {_login(pr.get('merged_by')) or '-'}, "
                         f"not {' or '.join(sorted(mergers))}")
    return pr


def _carried(proof: LandingProof, repo: Repo, ids: Identities, rec: Record, pr: dict, head: str) -> str:
    """Why no HITL approval on plan PR ``pr`` carried to its merged ``head`` under Amendment 025; "" when one did.

    The router carries an approval of an earlier plan commit once AR passes the plan at the head (router.py
    ``_carried_approval``). This reads the same facts from git and GitHub's record, not from the router's word:
    when the plan did not change it posts no comment at all. Only AR's latest round is checked for authorship: it
    is the round whose NO_CHALLENGE the carry rests on."""
    mission = proof.mission
    hitl = {h.casefold() for h in ids.hitl}
    approved = sorted({sha for c in rec.comments(pr["number"])
                       if (c.get("user") or {}).get("type") == "User" and _login(c.get("user")) in hitl
                       for sha in _APPROVE_RE.findall(c.get("body") or "")} - {head})
    earlier = [sha for sha in approved if repo.contains(head, sha)]
    if not earlier:
        return "no HITL approval names a commit in its history"
    n = 0
    while n < challenge_mod.MAX_ROUNDS and repo.show(head, challenge_mod.round_json(mission, n + 1)) is not None:
        n += 1
    if n == 0:
        return "the plan has no AR round"
    try:
        latest = challenge_mod.parse_challenge(repo.show(head, challenge_mod.round_json(mission, n)), mission, n)
    except MissionInputError as exc:
        return f"AR round {n} is not valid ({exc})"
    if latest.verdict != "NO_CHALLENGE":
        return f"AR's latest round, {n}, is {latest.verdict}"
    if repo.show(head, challenge_mod.response_path(mission, n)) is not None:
        return f"A1 answered AR round {n}, and AR has not read the answer"
    if not repo.contains(head, latest.challenged_sha):
        return f"AR round {n} read {latest.challenged_sha[:12]}, which is not in the head's history"
    changed = [p for p in repo.changed(latest.challenged_sha, head) if challenge_mod.is_plan_file(p, mission)]
    if changed:
        return f"the plan changed after AR read it in round {n}: {', '.join(changed[:5])}"
    if not ids.ar:
        return "config.json names no AR agent, so AR's round cannot be checked"
    subject = f"Mission {mission}: AR round {n} ("
    merges = [c for c in repo.range(latest.challenged_sha, head) if c.is_merge and c.subject.startswith(subject)]
    if len(merges) != 1:
        return f"{len(merges)} merges of AR round {n} follow the commit AR read, not 1"
    before = len(proof.findings)
    ar_pr = _stage(proof, rec, "G2", merges[0].sha, f"mission/{mission}/ar-r{n}", ids.ar, {ids.bot.casefold()},
                   f"AR round {n}")
    if ar_pr is None or len(proof.findings) != before:
        return f"AR round {n} did not come in through AR's own pull request merged by the bot"
    side = merges[0].parents[1]
    for path in (challenge_mod.round_json(mission, n), challenge_mod.round_md(mission, n)):
        if repo.show(side, path) != repo.show(head, path):
            return f"{path} changed after AR's pull request merged it"
    return ""


def verify(proof: LandingProof, repo: Repo, ids: Identities, rec: Record) -> None:
    """Add G1-G4 findings to ``proof``. Only a landing that passed R1 is checked: one that did not is unproven already."""
    if not proof.authentic:
        return
    mission, n = proof.mission, proof.round
    bot, hitl = {ids.bot.casefold()}, {h.casefold() for h in ids.hitl}
    prefix = f"mission/{mission}/"

    _stage(proof, rec, "G1", proof.commit.sha, f"{prefix}a3-r{n}", ids.a3, bot, "landing")

    if proof.approval is not None:
        router = proof.approval_kind == "router"
        pr = _stage(proof, rec, "G2", proof.approval.sha, f"{prefix}a1", None, bot if router else hitl, "approval")
        if pr is not None and router:
            head = (pr.get("head") or {}).get("sha")
            if head != proof.plan_sha:
                proof.find("G2", f"approval #{pr['number']} head {str(head)[:12]} is not the plan commit "
                                 f"{str(proof.plan_sha)[:12]}")
            try:
                approved = any(
                    (c.get("user") or {}).get("type") == "User" and _login(c.get("user")) in hitl
                    and head in _APPROVE_RE.findall(c.get("body") or "")
                    for c in rec.comments(pr["number"]))
            except Exception as exc:
                proof.find("G2", f"approval #{pr['number']}: its comments cannot be read ({type(exc).__name__})")
            else:
                if not approved:
                    try:
                        why = _carried(proof, repo, ids, rec, pr, str(head))
                    except Exception as exc:  # an unreadable record is never a pass
                        why = f"the record of a carried approval cannot be read ({type(exc).__name__})"
                    if why:
                        proof.find("G2", f"approval #{pr['number']} has no HITL '/mission approve {str(head)[:12]}...' "
                                         f"comment naming its head, and no approval carried to it: {why}")

    scope = None
    try:
        scope = parse_manifest(repo.show(proof.commit.sha, manifest_path(mission)), mission).build_scope
    except MissionInputError:
        pass  # R2 already records it
    for k, sha in sorted(proof.build_merges.items()):
        pr = _stage(proof, rec, "G3", sha, f"{prefix}a2-r{k}", ids.a2, bot, f"build round {k}")
        if pr is None or scope is None:
            continue
        try:
            pushed = rec.commits(pr["number"])
        except Exception as exc:
            proof.find("G3", f"build #{pr['number']}: its commits cannot be read ({type(exc).__name__})")
            continue
        if len(pushed) >= MAX_PR_COMMITS:
            proof.find("G3", f"build #{pr['number']} lists {len(pushed)} commits; GitHub shows at most "
                             f"{MAX_PR_COMMITS}, so the rest cannot be checked")
        for item in pushed:
            commit = repo.commit(item["sha"])
            if commit.is_merge:
                continue
            for path in repo.files(commit):
                if path.startswith("missions/") or not in_scope(path, scope):
                    proof.find("G3", f"build #{pr['number']} commit {commit.sha[:12]} changes {path}, which A2 "
                                     "may not change")

    base, top = proof.commit.parents
    for c in repo.range(base, top):
        for k in range(1, n):
            if c.is_merge and c.subject == f"Mission {mission}: merge A3 round {k} (FAIL)":
                _stage(proof, rec, "G4", c.sha, f"{prefix}a3-r{k}", ids.a3, bot, f"review round {k}")


def verifier(gh) -> Callable[[LandingProof, Repo, Identities], None]:
    """``verify`` bound to one GitHub client and its cache, as ``graph.walk`` calls it."""
    rec = Record(gh)
    return lambda proof, repo, ids: verify(proof, repo, ids, rec)
