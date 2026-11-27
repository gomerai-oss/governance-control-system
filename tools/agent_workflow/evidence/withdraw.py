"""HITL's withdrawal of stored records (§3m item 4; Amendment 055).

A record that must no longer be relied on is withdrawn by a later record of class ``withdraw``, never deleted. Here
the later record is written by the ``withdraw`` job of Evidence Verify (``evidence-verify.yml``), which runs only when
HITL starts that workflow by hand with the records to withdraw and the reason. The job reads a clone of the store
with the evidence reader App, so it cannot change the store; its chain is sealed and stored by Evidence Seal like
any other, and from then the verifier lists each record as withdrawn.

What is checked before anything is written:
- **Who:** the workflow was started by hand (``workflow_dispatch``), by a login in ``config.json``'s
  ``hitl_logins``, whose account id is the one pinned in ``hitl_account_ids``, and was not re-run by anyone else.
- **What:** each record named is in the store, and is not itself a withdrawal. ``refused-landings`` names every
  landing record whose stored attestation is false: the router asked GitHub to merge, GitHub refused, and the
  attestation was made anyway (Amendment 055 stops that from now on). One that is already withdrawn is skipped.
  One unknown record writes nothing at all.
- **The digest** of each withdrawn record is computed from the store, never typed in: a withdrawal naming a wrong
  digest could never be taken back, and every later verification would refuse the store.

Without ``--confirm`` nothing is written: the records that would be withdrawn are listed. A confirmed withdrawal is
refused while an earlier one is not in the store yet (``unstored``, Amendment 056): it could not see those records'
withdrawals, and would write them again.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Mapping, Tuple

from evidence import EvidenceError
from evidence import chain as chain_mod
from evidence import pack as pack_mod
from evidence import record as rec_mod
from evidence import verify

REFUSED_LANDINGS = "refused-landings"
WORKFLOW = "evidence-verify.yml"
ACTION = "evidence.withdraw"


def read_store(store: Path) -> Tuple[Dict[str, dict], Dict[str, List[dict]], Dict[str, str]]:
    """``(records by id, records by chain, {withdrawn record id: the withdrawal's id})`` for a clone of the store. A
    chain that cannot be read is left out: a record in it cannot be named, and the checker names the chain."""
    records: Dict[str, dict] = {}
    chains: Dict[str, List[dict]] = {}
    withdrawn: Dict[str, str] = {}
    base = Path(store) / verify.RUNS
    for path in sorted(base.glob(f"*/{chain_mod.RECORDS}")) if base.is_dir() else []:
        try:
            chain = chain_mod.read(path)
        except EvidenceError:
            continue
        chains[path.parent.name] = chain
        for rec in chain:
            records[rec["id"]] = rec
            if rec.get("class") == "withdraw" and isinstance(rec.get("withdraws"), dict):
                withdrawn[str(rec["withdraws"].get("id"))] = rec["id"]
    return records, chains, withdrawn


def refused_attested(store: Path, chains: Mapping[str, List[dict]]) -> List[str]:
    """The landing records whose stored attestation is false: GitHub refused that merge (``pack.refused_landings``)."""
    refused = {r["id"] for chain in chains.values() for r in pack_mod.refused_landings(chain)}
    out = []
    packs = Path(store) / pack_mod.PACKS
    for path in sorted(packs.glob(f"*{pack_mod.SUFFIX}")) if packs.is_dir() else []:
        landing = pack_mod.landing_of(path.read_bytes())
        if landing in refused and landing not in out:
            out.append(landing)
    return out


def hitl(environ: Mapping[str, str], config: Mapping) -> Tuple[str, int]:
    """``(login, account id)`` of the HITL login that started this run by hand; raises ``EvidenceError`` otherwise."""
    from mission_router.accounts import config_accounts
    event = environ.get("GITHUB_EVENT_NAME", "")
    actor = environ.get("GITHUB_ACTOR", "")
    triggering = environ.get("GITHUB_TRIGGERING_ACTOR", "")
    if event != "workflow_dispatch":
        raise EvidenceError(f"a withdrawal is started by hand only (workflow_dispatch), not by {event or 'nothing'}")
    if not actor or actor.casefold() != triggering.casefold():
        raise EvidenceError(f"this run was started by {actor or 'nobody'} and run by {triggering or 'nobody'}: "
                            "a withdrawal is HITL's own run, never a re-run by anyone else")
    if actor.casefold() not in {login.casefold() for login in config.get("hitl_logins") or []}:
        raise EvidenceError(f"{actor} is not a HITL login (config.json hitl_logins): a withdrawal is HITL's only")
    try:
        accounts = config_accounts(dict(config))
    except ValueError as exc:
        raise EvidenceError(str(exc)) from None
    pinned = accounts.get(actor.casefold())
    if pinned is None:
        raise EvidenceError("config.json pins no hitl_account_ids, so the HITL account cannot be checked")
    try:
        account = int(environ.get("GITHUB_ACTOR_ID", ""))
    except ValueError:
        account = 0
    if account != pinned:
        raise EvidenceError(f"{actor}'s account id is not the one pinned in config.json hitl_account_ids")
    return actor, account


def select(names: List[str], store: Path, records: Mapping[str, dict], chains: Mapping[str, List[dict]],
           withdrawn: Mapping[str, str]) -> Tuple[List[dict], List[str]]:
    """``(records to withdraw, ids skipped as already withdrawn)``, in order and once each. An unknown record, or a
    withdrawal, raises: nothing is written."""
    wanted: List[str] = []
    for name in names:
        for rid in (refused_attested(store, chains) if name == REFUSED_LANDINGS else [name]):
            if rid not in wanted:
                wanted.append(rid)
    unknown = [rid for rid in wanted if rid not in records]
    if unknown:
        raise EvidenceError(f"not in the store: {', '.join(unknown[:5])}" + (" ..." if len(unknown) > 5 else "")
                            + "; nothing was withdrawn")
    withdrawals = [rid for rid in wanted if records[rid].get("class") == "withdraw"]
    if withdrawals:
        raise EvidenceError(f"{withdrawals[0]} is itself a withdrawal; nothing was withdrawn")
    return ([records[rid] for rid in wanted if rid not in withdrawn],
            [rid for rid in wanted if rid in withdrawn])


def unstored(request, store: Path, current_run: str, now) -> List[str]:
    """The runs whose withdrawal chain (artifact ``evidence-withdraw``) was kept within the seal sweep's lookback and
    is not in the store yet (Amendment 056). Until Evidence Seal stores it, its withdrawals are not in the store, so
    a second withdrawal could not see them and would write them again. ``request`` reads this repository's
    artifacts (``actions: read``)."""
    import datetime
    from evidence import sweep
    since = (now - datetime.timedelta(days=sweep.LOOKBACK_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = set()
    runs = Path(store) / verify.RUNS
    for a in (request("GET", "/actions/artifacts?name=evidence-withdraw&per_page=100") or {}).get("artifacts") or []:
        run = (a.get("workflow_run") or {}).get("id")
        if not run or a.get("expired") or str(a.get("created_at", "")) < since or str(run) == str(current_run):
            continue
        if not any(runs.glob(f"gh-{int(run)}-*-withdraw/seal.json")):
            out.add(str(run))
    return sorted(out)


def run(store: Path, names: List[str], reason: str, environ: Mapping[str, str], config: Mapping,
        recorder=None, confirm: bool = False, pending=None) -> dict:
    """``{"actor", "withdrawn": [{id, digest}], "skipped": [id], "written": bool}``. Raises ``EvidenceError`` on a
    refusal, with nothing written. ``pending()`` names the earlier withdrawal runs not yet in the store
    (``unstored``); a confirmed withdrawal is refused while there is one, or when it cannot be asked."""
    reason = " ".join((reason or "").split())
    if not reason:
        raise EvidenceError("a withdrawal names its reason")
    if not [n for n in names if n.strip()]:
        raise EvidenceError(f"name the records to withdraw, or {REFUSED_LANDINGS}")
    login, account = hitl(environ, config)
    records, chains, withdrawn = read_store(store)
    targets, skipped = select([n for n in names if n.strip()], store, records, chains, withdrawn)
    out = {"actor": login, "withdrawn": [{"id": r["id"], "digest": rec_mod.digest(r)} for r in targets],
           "skipped": skipped, "written": False}
    if not confirm or not targets:
        return out
    if pending is None:
        raise EvidenceError("cannot check for an earlier withdrawal not yet stored; nothing was withdrawn")
    waiting = pending()
    if waiting:
        raise EvidenceError(f"the withdrawal of run {', '.join(waiting)} is not in the store yet, so this one cannot see "
                            "it: Evidence Seal stores it within about 10 minutes. Start this again after that; "
                            "nothing was withdrawn")
    if recorder is None or not recorder.enabled:
        raise EvidenceError("this job keeps no evidence chain (EVIDENCE_DIR and EVIDENCE_RUN); nothing was withdrawn")
    ref = f"workflow_dispatch run {environ.get('GITHUB_RUN_ID', '?')} of {WORKFLOW} by {login}"
    for rec, target in zip(targets, out["withdrawn"]):
        s = rec["subject"]
        done = recorder.record(actor=login, account_id=account, action=ACTION, result="done",
                               reason=f"withdrawn by HITL: {reason}", authority_kind="hitl_command",
                               authority_ref=ref, mission=s["mission"], round_n=s["round"], pr=s["pr"],
                               commit=s["commit"], inputs={"reason": _digest(reason)}, withdraws=target)
        if done is None:
            raise EvidenceError(f"the withdrawal of {target['id']} could not be recorded; see the warning above")
    out["written"] = True
    return out


def _digest(text: str) -> str:
    from evidence.producer import text_digest
    return text_digest(text)


def lines(result: Mapping, confirm: bool) -> List[str]:
    verb = "withdrawn" if result["written"] else "would withdraw"
    out = [f"{verb}: {w['id']} ({w['digest'][:12]})" for w in result["withdrawn"]]
    out += [f"already withdrawn: {rid}" for rid in result["skipped"]]
    count = len(result["withdrawn"])
    if result["written"]:
        out.append(f"{count} withdrawn by {result['actor']}; Evidence Seal stores them with this run's chain")
    elif not count:
        out.append("nothing to withdraw")
    elif not confirm:
        out.append(f"{count} would be withdrawn by {result['actor']}: nothing was written. Start the workflow again "
                   "with confirm ticked to write them")
    return out

