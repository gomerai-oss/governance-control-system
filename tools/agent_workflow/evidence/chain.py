"""A run's records, chained (§3m item 2): every record carries the digest of the one before it in its run, so a
removed or changed record breaks the chain. A run is stored as ``records.jsonl``: one record per line, each line
exactly the record's canonical bytes."""

from __future__ import annotations

import time as _time
from pathlib import Path
from typing import Any, Dict, List, Optional

from epap.signing import canonical_bytes
from evidence import EvidenceError
from evidence import record as rec_mod

RECORDS = "records.jsonl"


def now() -> str:
    return _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())


def read(path: Path) -> List[Dict[str, Any]]:
    """A run's records as stored. Raises ``EvidenceError`` on a line that is not a record's canonical bytes."""
    import json
    out = []
    data = path.read_bytes()
    if data and not data.endswith(b"\n"):
        raise EvidenceError(f"{path.name}: the last line is incomplete")
    for n, line in enumerate(data.split(b"\n")[:-1] if data else [], 1):
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise EvidenceError(f"{path.name} line {n}: not JSON") from None
        try:
            same = canonical_bytes(value) == line
        except Exception:  # noqa: BLE001 - a value with no canonical form
            same = False
        if not same:
            raise EvidenceError(f"{path.name} line {n}: not a record's canonical bytes")
        out.append(value)
    return out


class Chain:
    """Appends records to one run's ``records.jsonl``, each chained to the one before it."""

    def __init__(self, directory: Path, run: str):
        self.path = Path(directory) / RECORDS
        self.run = run
        self.path.parent.mkdir(parents=True, exist_ok=True)
        existing = read(self.path) if self.path.is_file() else []
        self.seq = len(existing)
        self.head = rec_mod.digest(existing[-1]) if existing else rec_mod.genesis(run)

    def append(self, *, time: Optional[str] = None, **fields: Any) -> Dict[str, Any]:
        record = rec_mod.make(run=self.run, seq=self.seq, prev=self.head, time=time or now(), **fields)
        with self.path.open("ab") as fh:
            fh.write(canonical_bytes(record) + b"\n")
        self.seq += 1
        self.head = rec_mod.digest(record)
        return record
