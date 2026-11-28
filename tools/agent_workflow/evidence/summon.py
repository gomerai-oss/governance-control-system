"""EPAP summon (MISSION-DISPATCH-001 Amendment 061): the evidence pack of one PR, for an outside auditor.

Electronic Proof As Product: whoever HITL hands the pack to can check, with no access to this repository, its store or
GitHub, what was done for the PR's mission, by whom, under whose approval, and that what landed is exactly what each
agent produced. The pack is built from three sources and says which each statement rests on:

- **the evidence store** (a clone, read with the evidence reader App): every sealed chain that holds a record of the
  PR's mission, with its seal, the withdrawals that name them, and the mission's landing attestations, copied byte for
  byte; and the pinned public evidence keys, so each seal can be checked;
- **git** (a clone with the PR heads fetched): each agent stage's change, regenerated as the dispatcher made it
  (``git diff --binary --no-renames --no-ext-diff --no-textconv <base> <head>``) and proven against the SHA-256 the
  sealed ``dispatch.collect`` record holds; and a git bundle of every commit the pack names, with its history, so the
  changes can be rebuilt offline;
- **GitHub** (the PRs' metadata at summon time: titles, bodies, states, merge commits): not sealed, and marked so.

Each stage is bound end to end: the ``dispatch.collect`` record holds the commit the agent started from and its
change's SHA-256, the ``dispatch.publish`` record holds the SHA-256 of the PR head's commit id, and git ties the two.
Nothing is trusted that the pack cannot show: a chain that does not verify, a head that does not match its record, or
a change that does not match its digest is reported as such, and the pack is still written so the auditor sees it.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional

from evidence import EvidenceError
from evidence import chain as chain_mod
from evidence import pack as pack_mod
from evidence import record as rec_mod
from evidence import seal as seal_mod
from evidence import verify

SCHEMA = "evidence-pack-v1"
PATCH = "change.patch"
DIFF = ("diff", "--binary", "--no-renames", "--no-ext-diff", "--no-textconv")
_LANE = re.compile(r"gh-(\d+)-(\d+)-(agent|publish|report|checks|baseline)-(M-[A-Z0-9-]+)-(A2|A3|AR)-r(\d+)")
_STAGE = re.compile(r"mission/(M-[A-Z0-9-]+)/(?:a1|(a2|a3|ar)-r([1-9][0-9]*))")
_LANDING_AT = re.compile(r"^landing check \d+ on \S+ at ([0-9a-f]{12}): exit ")
_APPROVE = re.compile(r"/mission approve ([0-9a-f]{40})(?: \(carried to ([0-9a-f]{12}))?")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git(git: Path, *args: str, binary: bool = False):
    done = subprocess.run(["git", "-C", str(git), *args], capture_output=True)
    if done.returncode != 0:
        raise EvidenceError(f"git {' '.join(args[:2])}: {done.stderr.decode('utf-8', 'replace').strip()[:200]}")
    return done.stdout if binary else done.stdout.decode("utf-8").strip()


def _commit(git: Path, ref: str) -> Optional[str]:
    try:
        return _git(git, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}") or None
    except EvidenceError:
        return None


def mission_of(head_ref: str) -> Optional[str]:
    match = _STAGE.fullmatch(head_ref or "")
    return match.group(1) if match else None


def read_store(store: Path) -> Dict[str, List[dict]]:
    """Every chain in a clone of the store, by name. A chain that cannot be read is left out here; ``verify_run``
    names it when the pack is checked."""
    out: Dict[str, List[dict]] = {}
    base = Path(store) / verify.RUNS
    for path in sorted(base.glob(f"*/{chain_mod.RECORDS}")) if base.is_dir() else []:
        try:
            out[path.parent.name] = chain_mod.read(path)
        except EvidenceError:
            continue
    return out


def _stages(chains: Mapping[str, List[dict]]) -> List[dict]:
    """Each agent stage that published a PR: its records by role, from the chains its run kept."""
    by_lane: Dict[tuple, Dict[str, str]] = {}
    for name in chains:
        m = _LANE.fullmatch(name)
        if m:
            run, attempt, job, mission, role, rnd = m.groups()
            by_lane.setdefault((run, attempt, mission, role, int(rnd)), {})[job] = name
    stages = []
    for (run, attempt, mission, role, rnd), jobs in sorted(by_lane.items(), key=lambda kv: (kv[0][3] != "AR", kv[0][4],
                                                                                            kv[0][3], kv[0][0])):
        publish = next((r for r in chains.get(jobs.get("publish", ""), [])
                        if r["action"] == "dispatch.publish" and r["result"] == "done" and r["subject"]["pr"]), None)
        collect = next((r for r in chains.get(jobs.get("agent", ""), [])
                        if r["action"] == "dispatch.collect" and r["result"] == "done"), None)
        checks = [r for job in ("checks", "baseline") for r in chains.get(jobs.get(job, ""), [])
                  if r["action"] in ("checks.check", "checks.environment")]
        stages.append({"role": role, "round": rnd, "run": f"gh-{run}-{attempt}", "chains": sorted(jobs.values()),
                       "pr": publish["subject"]["pr"] if publish else None, "publish": publish, "collect": collect,
                       "checks": checks})
    return stages


def _approvals(records: List[dict]) -> List[dict]:
    out = []
    for r in records:
        m = _APPROVE.search(r["reason"]) if r["action"] == "router.hitl_command" else None
        if m:
            out.append({"record": r["id"], "login": r["actor"]["name"], "account_id": r["actor"]["account_id"],
                        "approved": m.group(1), "carried_to": m.group(2), "pr": r["subject"]["pr"],
                        "time": r["time"], "authority": r["authority"]["ref"]})
    return out


def _merges(chains: Mapping[str, List[dict]], mission: str) -> List[dict]:
    out = []
    for name, records in chains.items():
        refused = {r["id"] for r in pack_mod.refused_landings(records)}
        for r in records:
            if r["subject"]["mission"] != mission or r["action"] not in ("router.merge", "router.landing"):
                continue
            if r["result"] != "done":
                continue
            if r["action"] == "router.landing" and r["id"] in refused:
                kind = "landing attempt GitHub refused"
            elif r["action"] == "router.landing":
                kind = "landing"
            else:
                follow = next((x for x in records[records.index(r) + 1:] if x["action"] == "router.merge"
                               and x["result"] == "failed" and x["subject"]["pr"] == r["subject"]["pr"]
                               and x["subject"]["commit"] == r["subject"]["commit"]), None)
                kind = "merge attempt GitHub refused" if follow else "merge"
            out.append({"record": r["id"], "kind": kind, "pr": r["subject"]["pr"], "commit": r["subject"]["commit"],
                        "round": r["subject"]["round"], "time": r["time"]})
    return sorted(out, key=lambda m: (m["time"], m["record"]))


def summon(store: Path, git: Path, repository: str, pr: int, pulls: Callable[[int], Optional[dict]], out: Path,
           keys: Mapping[str, str], keys_doc: Mapping, summoned_by: str = "", bundle: bool = True,
           now: Optional[str] = None) -> dict:
    """Write the evidence pack of PR ``pr`` to ``out`` (which must not exist) and return its manifest. ``pulls(n)``
    gives GitHub's PR ``n`` (``/pulls/n``), or None. ``keys`` are the pinned evidence keys (``keys_doc`` their file)."""
    out = Path(out)
    if out.exists():
        raise EvidenceError(f"{out} exists; a pack is written once, to a new directory")
    raw = pulls(pr)
    if raw is None:
        raise EvidenceError(f"PR #{pr} is not in {repository}")
    mission = mission_of(str((raw.get("head") or {}).get("ref", "")))
    now = now or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    manifest: dict = {"schema": SCHEMA, "repository": repository, "summoned_at": now, "summoned_by": summoned_by,
                      "pr": pr, "mission": mission, "chains": [], "stages": [], "approvals": [], "merges": [],
                      "attestations": [], "withdrawn": {}, "limits": [], "github": {}, "bundle": None, "files": {}}
    (out / "evidence" / verify.RUNS).mkdir(parents=True)
    (out / "evidence" / "key.json").write_text(json.dumps(keys_doc, indent=2, sort_keys=True) + "\n")
    (out / "github").mkdir()
    snapshot = {n: pulls(n) for n in [pr]}
    if mission is None:
        manifest["limits"].append(f"PR #{pr} is not a mission stage PR ({(raw.get('head') or {}).get('ref')}): it went "
                                  "outside the mission flow, so the evidence store holds no record of it. The pack "
                                  "holds only GitHub's metadata and, in the bundle, its commits.")
        stages, records = [], []
    else:
        everything = read_store(store)
        mine = {n: rs for n, rs in everything.items() if any(r["subject"]["mission"] == mission for r in rs)}
        # This mission's own records: a router chain also holds other missions' records, whose landing attestations
        # cite chains that are not in this pack.
        ids = {r["id"] for rs in mine.values() for r in rs if r["subject"]["mission"] == mission}
        for name in sorted(mine):
            src = Path(store) / verify.RUNS / name
            dst = out / "evidence" / verify.RUNS / name
            dst.mkdir()
            for f in (chain_mod.RECORDS, seal_mod.SEAL):
                if (src / f).is_file():
                    shutil.copyfile(src / f, dst / f)
            try:
                _, sealed = verify.verify_run(src, name, keys)
                state = "verified" if sealed else "not sealed"
            except verify.Refused as exc:
                state = f"refused: {exc}"
            manifest["chains"].append({"name": name, "records": len(mine[name]), "state": state})
        packs = Path(store) / pack_mod.PACKS
        for path in sorted(packs.glob(f"*{pack_mod.SUFFIX}")) if packs.is_dir() else []:
            if pack_mod.landing_of(path.read_bytes()) in ids:
                (out / "evidence" / pack_mod.PACKS).mkdir(exist_ok=True)
                shutil.copyfile(path, out / "evidence" / pack_mod.PACKS / path.name)
                manifest["attestations"].append(f"evidence/{pack_mod.PACKS}/{path.name}")
        records = sorted((r for rs in mine.values() for r in rs), key=lambda r: (r["time"], r["id"]))
        manifest["withdrawn"] = {r["withdraws"]["id"]: r["id"] for r in records if r["class"] == "withdraw"}
        manifest["approvals"] = _approvals(records)
        manifest["merges"] = _merges(mine, mission)
        stages = _stages(mine)
        for s in stages:
            if s["pr"] and s["pr"] not in snapshot:
                snapshot[s["pr"]] = pulls(s["pr"])
        for a in manifest["approvals"]:
            if a["pr"] and a["pr"] not in snapshot:
                snapshot[a["pr"]] = pulls(a["pr"])
        if not any(r["action"] == "checks.check" for r in records):
            manifest["limits"].append("No check result of this mission is in the evidence: they were recorded only "
                                      "from MISSION-DISPATCH-001 Amendment 060 on. GitHub's PR bodies (github/) "
                                      "quote them, unsealed.")
        manifest["limits"].append("The plan (A1) and HITL's approvals are bound by commit id and account, not by a "
                                  "sealed patch: A1 is HITL's own work, and the approval names the exact commit.")
    needed = set()
    for s in stages:
        entry = _stage_entry(s, git, out, snapshot, needed)
        if not entry["published"]:  # another run of the same stage published its PR, or none did
            others = [x["pr"] for x in stages if x is not s and x["role"] == s["role"] and x["round"] == s["round"]
                      and x["pr"]]
            entry["note"] = ("this run collected a change but published no PR (its dispatch.publish record names "
                             "none and gives no reason)" + (f"; PR #{others[0]} was published for this stage by another "
                                                            "run" if others else "; no run published one"))
        manifest["stages"].append(entry)
    for m in manifest["merges"]:
        if m["commit"]:
            needed.add(m["commit"])
    for a in manifest["approvals"]:
        needed.add(a["approved"])
    for n, p in sorted(snapshot.items()):
        if p is None:
            continue
        keep = {k: p.get(k) for k in ("number", "title", "body", "state", "merged_at", "merge_commit_sha",
                                      "created_at", "closed_at", "html_url")}
        keep["head"] = {k: (p.get("head") or {}).get(k) for k in ("ref", "sha")}
        keep["base"] = {k: (p.get("base") or {}).get(k) for k in ("ref", "sha")}
        keep["user"] = (p.get("user") or {}).get("login")
        (out / "github" / f"pr-{n}.json").write_text(json.dumps(keep, indent=2, sort_keys=True) + "\n")
        manifest["github"][str(n)] = f"github/pr-{n}.json"
        # An unmerged PR's merge_commit_sha is GitHub's test merge, not part of the repository's history.
        for sha in (keep["head"]["sha"], keep["merge_commit_sha"] if keep["merged_at"] else None):
            if sha:
                needed.add(sha)
    if bundle:
        manifest["bundle"] = _bundle(git, sorted(needed), out / "repo.bundle")
    manifest["limits"].append("github/ is GitHub's word at summon time, not sealed evidence.")
    (out / "README.md").write_text(readme(manifest))
    for path in sorted(p for p in out.rglob("*") if p.is_file()):
        manifest["files"][path.relative_to(out).as_posix()] = _sha256(path.read_bytes())
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def _stage_entry(s: dict, git: Path, out: Path, snapshot: Mapping[int, Optional[dict]], needed: set) -> dict:
    collect, publish = s["collect"], s["publish"]
    entry = {"role": s["role"], "round": s["round"], "run": s["run"], "pr": s["pr"], "chains": s["chains"],
             "agent": (publish or {}).get("actor", {}).get("name") if publish else None,
             "base": collect["subject"]["commit"] if collect else None, "head": None, "head_bound": False,
             "change": None, "checks": [r["reason"] for r in s["checks"]], "problems": []}
    entry["published"] = publish is not None
    if collect is None:
        entry["problems"].append("no dispatch.collect record for this run")
    head = None
    if s["pr"]:
        head = _commit(git, f"refs/remotes/pull/{s['pr']}") or _commit(git, f"refs/pull/{s['pr']}/head")
        if head is None and snapshot.get(s["pr"]):
            head = _commit(git, str((snapshot[s["pr"]].get("head") or {}).get("sha", "")))
    if head:
        entry["head"] = head
        needed.add(head)
        sealed = (publish or {}).get("outputs", {}).get("commit")
        entry["head_bound"] = bool(sealed) and _sha256(head.encode()) == sealed
        if not entry["head_bound"]:
            entry["problems"].append("the PR's head is not the commit the sealed dispatch.publish record names")
    elif s["pr"]:
        entry["problems"].append(f"PR #{s['pr']}'s head is not in the clone")
    if entry["base"]:
        needed.add(entry["base"])
    for rec in s["checks"]:  # the landing branch's head the landing checks ran on, so a replay can merge onto it
        m = _LANDING_AT.search(rec["reason"])
        full = _commit(git, m.group(1)) if m else None
        if full and _sha256(full.encode()) == (rec.get("inputs") or {}).get("head"):
            needed.add(full)
    sealed_patch = (collect or {}).get("outputs", {}).get(PATCH)
    if entry["base"] and head and sealed_patch:
        try:
            data = _git(git, *DIFF, entry["base"], head, "--", binary=True)
        except EvidenceError as exc:
            entry["problems"].append(f"the change could not be regenerated: {exc}")
        else:
            rel = f"changes/{s['role']}-r{s['round']}-{s['run']}/{PATCH}"
            (out / rel).parent.mkdir(parents=True, exist_ok=True)
            (out / rel).write_bytes(data)
            proven = _sha256(data) == sealed_patch
            entry["change"] = {"path": rel, "sha256": _sha256(data), "sealed_sha256": sealed_patch, "proven": proven}
            if not proven:
                entry["problems"].append("the change regenerated from git does not match the sealed digest")
    return entry


BUNDLE_REFS = "refs/heads/epap-pack/"


def _bundle(git: Path, commits: List[str], path: Path) -> dict:
    """A git bundle of ``commits`` with their whole history, through temporary branches that are removed after.

    They are branches (``refs/heads/epap-pack/<i>``) so that a plain ``git clone repo.bundle`` takes every commit:
    a clone fetches branches and tags only, and git 2.56 then keeps none of a bundle's other objects (Amendment 063).
    A branch of that name already in the clone is never overwritten: the summon is refused."""
    present = [c for c in commits if _commit(git, c)]
    missing = [c for c in commits if c not in present]
    if not present:
        return {"path": None, "commits": [], "missing": missing}
    if _git(git, "for-each-ref", "--format=%(refname)", BUNDLE_REFS):
        raise EvidenceError(f"{git} already has branches under {BUNDLE_REFS}; they are not overwritten")
    refs = [f"{BUNDLE_REFS}{i}" for i in range(len(present))]
    made = []
    try:
        for ref, sha in zip(refs, present):
            _git(git, "update-ref", ref, sha, "0" * 40)  # only if it does not exist
            made.append(ref)
        _git(git, "bundle", "create", str(path), *refs)
    finally:
        for ref in made:
            subprocess.run(["git", "-C", str(git), "update-ref", "-d", ref], capture_output=True)
    return {"path": "repo.bundle", "commits": present, "missing": missing,
            "sha256": _sha256(path.read_bytes())}


def readme(manifest: Mapping) -> str:
    stages = manifest["stages"]
    lines = [f"# EPAP evidence pack: {manifest['repository']} PR #{manifest['pr']}", "",
             f"Summoned {manifest['summoned_at']}" + (f" by {manifest['summoned_by']}" if manifest['summoned_by'] else "")
             + f". Mission: {manifest['mission'] or 'none (outside the mission flow)'}.", "",
             "## What is here", "",
             "- `evidence/runs/<chain>/records.jsonl` and `seal.json`: every sealed chain holding a record of the "
             "mission, byte for byte as the evidence store holds them. Each seal is signed with an evidence key in "
             "`evidence/key.json` (Ed25519; the key id is the SHA-256 of the public key).",
             "- `evidence/packs/`: the mission's landing attestations (in-toto Statement v1, SLSA Provenance v1, DSSE).",
             "- `changes/<stage>/change.patch`: each agent stage's change, regenerated from git and compared with the "
             "SHA-256 its sealed `dispatch.collect` record holds.",
             "- `repo.bundle`: the commits this pack names, with their history (`git clone repo.bundle`).",
             "- `github/`: the PRs as GitHub showed them when the pack was summoned. Not sealed.",
             "- `manifest.json`: this pack's index, with the SHA-256 of every file.", "",
             "## The stages", ""]
    if not stages:
        lines.append("No agent stage.")
    for s in stages:
        change = s.get("change") or {}
        if not s.get("published"):
            lines.append(f"- {s['role']} round {s['round']} (run {s['run']}): {s.get('note', 'published no PR')}")
            continue
        lines.append(f"- {s['role']} round {s['round']} (run {s['run']}, PR #{s['pr']}): base `{(s['base'] or '?')[:12]}`, "
                     f"head `{(s['head'] or '?')[:12]}` {'bound to its record' if s['head_bound'] else 'NOT bound'}; "
                     f"change {'matches its sealed digest' if change.get('proven') else 'NOT proven'}"
                     + (f"; problems: {'; '.join(s['problems'])}" if s["problems"] else ""))
    lines += ["", "## HITL's approvals", ""]
    lines += [f"- {a['login']} (account {a['account_id']}) approved `{a['approved'][:12]}`"
              + (f", carried to `{a['carried_to']}`" if a["carried_to"] else "") + f" ({a['record']})"
              for a in manifest["approvals"]] or ["None recorded."]
    lines += ["", "## Limits", ""] + [f"- {x}" for x in manifest["limits"]]
    lines += ["", "## Checking it by hand", "",
              "1. `sha256sum` each file and compare with `manifest.json` `files`.",
              "2. Each record line is canonical JSON; each record's `prev` is the SHA-256 of the line before (the first's "
              "is the SHA-256 of `{\"run\":\"<chain>\",\"schema\":\"evidence-record-v1\"}` in canonical form).",
              "3. Each `seal.json` signs the chain's head and count with the key in `evidence/key.json`.",
              "4. `git clone repo.bundle repo && cd repo && git diff --binary --no-renames --no-ext-diff --no-textconv "
              "<base> <head> | sha256sum` gives each stage's sealed `change.patch` digest.", "",
              "## Replaying it", "",
              "With your own copy of the tooling (GCS, from its public release), and no network: `python3 -m evidence "
              "replay --pack <this directory> --work <a new directory>`. It does again every step of the mission that "
              "is not an AI agent's own work (the plan's authority, each change rebuilt with the dispatcher's own code "
              "and its gates, the router's decisions, the landed result, the checks, in a sandbox with no network) and "
              "reports each as reproduced or the first divergence (MISSION-DISPATCH-001 Amendment 062).", ""]
    return "\n".join(lines)
