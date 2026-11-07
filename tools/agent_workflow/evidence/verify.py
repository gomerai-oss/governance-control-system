"""The verifier (§3m item 5): replays the chain of every run in a store, or of one run.

A store holds one directory per run, ``runs/<run>/``, with the run's ``records.jsonl`` and, once sealed, its
``seal.json``. For each run the verifier checks every record's schema, every chain link, and the seal against the
pinned evidence keys (its run, record count and head). It then checks every withdrawal names a record that exists,
by its digest. It stops on the first broken link, bad seal or mismatch, naming it.

Checking the recorded digests against what git, GitHub and the store hold, and recomputing router decisions, are
added when those records have producers (§3m item 5; part 2).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Mapping, Optional

from evidence import EvidenceError
from evidence import chain as chain_mod
from evidence import record as rec_mod
from evidence import seal as seal_mod

RUNS = "runs"


class Refused(Exception):
    """The first broken link, bad seal or mismatch the verifier found."""


@dataclass
class Report:
    runs: int = 0
    records: int = 0
    unsealed: List[str] = field(default_factory=list)
    withdrawn: Dict[str, str] = field(default_factory=dict)  # withdrawn record id -> the withdrawal's id
    failure: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.failure is None


def verify_run(directory: Path, run: str, keys: Mapping[str, str]) -> tuple:
    """``(records, sealed)`` for one run; raises ``Refused`` naming the first problem."""
    path = Path(directory) / chain_mod.RECORDS
    if not path.is_file():
        raise Refused(f"run {run}: no {chain_mod.RECORDS}")
    try:
        records = chain_mod.read(path)
    except EvidenceError as exc:
        raise Refused(f"run {run}: {exc}") from None
    expected = rec_mod.genesis(run)
    for n, rec in enumerate(records):
        where = f"{run}/{n}"
        found = rec_mod.problems(rec)
        if found:
            raise Refused(f"record {where}: {'; '.join(found)}")
        if rec["subject"]["run"] != run:
            raise Refused(f"record {where}: belongs to run {rec['subject']['run']}, not {run}")
        if rec["seq"] != n:
            raise Refused(f"run {run}: a gap in the chain: record {where} is missing (found {rec['id']} there)")
        if rec["prev"] != expected:
            before = f"{run}/{n - 1}" if n else "the run's start"
            raise Refused(f"run {run}: the chain is broken at record {where}: {before} was changed or removed")
        expected = rec_mod.digest(rec)
    seal_path = Path(directory) / seal_mod.SEAL
    if not seal_path.is_file():
        return records, False
    import json
    try:
        seal = json.loads(seal_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise Refused(f"run {run}: {seal_mod.SEAL}: {exc}") from None
    found = seal_mod.problems(seal, keys)
    if found:
        raise Refused(f"run {run}: bad seal: {'; '.join(found)}")
    signed = seal["signed"]
    if signed["run"] != run:
        raise Refused(f"run {run}: the seal is for run {signed['run']}")
    if signed["count"] != len(records):
        raise Refused(f"run {run}: the seal covers {signed['count']} records, the chain has {len(records)}")
    if signed["head"] != expected:
        raise Refused(f"run {run}: the seal's head does not match the chain: the last record was changed")
    return records, True


def verify_store(store: Path, keys: Mapping[str, str], run: Optional[str] = None,
                 require_seal: bool = False) -> Report:
    report = Report()
    base = Path(store) / RUNS
    names = [run] if run else sorted(p.name for p in base.iterdir() if p.is_dir()) if base.is_dir() else []
    known: Dict[str, str] = {}  # record id -> digest, for the runs read
    withdrawals: List[dict] = []
    try:
        for name in names:
            records, sealed = verify_run(base / name, name, keys)
            report.runs += 1
            report.records += len(records)
            if not sealed:
                if require_seal:
                    raise Refused(f"run {name}: not sealed")
                report.unsealed.append(name)
            for rec in records:
                known[rec["id"]] = rec_mod.digest(rec)
                if rec["class"] == "withdraw":
                    withdrawals.append(rec)
        for w in withdrawals:
            target = w["withdraws"]
            if target["id"] not in known:
                other = target["id"].rsplit("/", 1)[0]
                if (base / other).is_dir() and other not in names:
                    for rec in verify_run(base / other, other, keys)[0]:
                        known[rec["id"]] = rec_mod.digest(rec)
            if known.get(target["id"]) != target["digest"]:
                raise Refused(f"withdrawal {w['id']}: names {target['id']}, which is not in the store as recorded")
            report.withdrawn[target["id"]] = w["id"]
    except Refused as exc:
        report.failure = str(exc)
    return report
