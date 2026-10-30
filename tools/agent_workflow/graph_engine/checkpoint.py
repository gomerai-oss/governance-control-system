"""Checkpoints and bounded recovery for the GE graph engine.

The engine writes a checkpoint when a run starts and after every accepted node, suspension and terminal
status, as ``<run>/checkpoints/NNNNNN.json`` (``seq`` from 1). A checkpoint is canonical JSON holding exactly
``BODY_FIELDS`` plus ``digest``, the SHA-256 of the canonical body:

``schema``, ``run_id``, ``graph_id``, ``version``  the run and its contract
``seq``, ``previous``                              its place, and the digest of the checkpoint before it
``status``, ``position``, ``child``                where the run is: the next node, and a suspended child
``carry``, ``output``                              the value flowing into ``position``; the final output
``state``, ``actors``, ``evidence``, ``step``      scoped state, recorded node actors, artifact evidence
``rule``, ``detail``, ``recovery``                 why a run was refused or failed
``max_steps``                                      the run's step bound
``chain_head``, ``event_count``                    the head of the event chain the checkpoint commits

``load_all`` verifies every checkpoint: contiguous files, canonical form, digest, the link to its
predecessor, and that its chain head is the event log's head at its event count. Anything else is
``IntegrityError``; the engine then reports ``CHECKPOINT_INTEGRITY`` and runs nothing.

Bounded recovery: ``attempt`` calls a handler at most ``bound + 1`` times; a run whose handler is still
failing past its bound ends ``FAILED`` with a ``recovery_record``. No loop here is unbounded.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable, Iterable, List, Optional, Tuple

from graph_engine import state as ST
from graph_engine.state import IntegrityError

SCHEMA = "ge-run-checkpoint-v1"
BODY_FIELDS = ("schema", "run_id", "graph_id", "version", "seq", "previous", "status", "position", "child",
               "carry", "output", "state", "actors", "evidence", "step", "rule", "detail", "recovery", "max_steps",
               "chain_head", "event_count")
NAME_RE = re.compile(r"^\d{6}\.json$")

RETRY_BOUND = "RETRY_BOUND_EXHAUSTED"
STEP_BOUND = "STEP_BOUND_EXHAUSTED"
SUBGRAPH_FAILED = "SUBGRAPH_FAILED"


def path_for(run_dir: Path, seq: int) -> Path:
    return Path(run_dir) / ST.CHECKPOINTS / f"{seq:06d}.json"


def seal(body: dict) -> dict:
    """``body`` with its ``digest``."""
    if set(body) != set(BODY_FIELDS):
        raise ValueError(f"a checkpoint body has exactly the fields {list(BODY_FIELDS)}")
    doc = dict(body)
    doc["digest"] = ST.value_digest(body)
    return doc


def write(run_dir: Path, body: dict) -> dict:
    """Seal ``body`` and write it as checkpoint ``body['seq']``; returns the sealed checkpoint."""
    doc = seal(body)
    (Path(run_dir) / ST.CHECKPOINTS).mkdir(exist_ok=True)
    ST.write_atomic(path_for(run_dir, doc["seq"]), ST.canonical(doc) + b"\n")
    return doc


def load_all(run_dir: Path, log: ST.EventLog) -> List[dict]:
    """Every checkpoint of the run at ``run_dir``, verified against itself, its predecessor and ``log``."""
    root = Path(run_dir) / ST.CHECKPOINTS
    if root.is_symlink() or not root.is_dir():
        raise IntegrityError("the run has no checkpoints")
    # A *.tmp file is a checkpoint write that never completed; it was never committed.
    names = sorted(p.name for p in root.iterdir() if not p.name.endswith(".tmp"))
    if not names or names != [f"{i:06d}.json" for i in range(1, len(names) + 1)]:
        raise IntegrityError("checkpoint files are not a contiguous sequence from 000001.json")
    docs: List[dict] = []
    previous, count = ST.ZERO, 0
    for seq, name in enumerate(names, start=1):
        data = ST.read_file(root / name, f"checkpoint {name}")
        if not data.endswith(b"\n"):
            raise IntegrityError(f"checkpoint {name} is incomplete")
        doc = ST.parse_canonical(data[:-1], f"checkpoint {name}")
        if not isinstance(doc, dict) or set(doc) != set(BODY_FIELDS) | {"digest"}:
            raise IntegrityError(f"checkpoint {name} does not have the checkpoint fields")
        if doc["digest"] != ST.value_digest({k: doc[k] for k in BODY_FIELDS}):
            raise IntegrityError(f"checkpoint {name}: digest does not verify")
        if doc["schema"] != SCHEMA or doc["seq"] != seq:
            raise IntegrityError(f"checkpoint {name} is not checkpoint {seq} of schema {SCHEMA}")
        if doc["previous"] != previous:
            raise IntegrityError(f"checkpoint {name} does not link to the checkpoint before it")
        events = doc["event_count"]
        if type(events) is not int or not count < events <= log.count:
            raise IntegrityError(f"checkpoint {name} commits an event count the log does not hold")
        if doc["chain_head"] != log.head_at(events):
            raise IntegrityError(f"checkpoint {name}: chain head does not match the event log")
        previous, count = doc["digest"], events
        docs.append(doc)
    return docs


def attempt(call: Callable[[], Any], bound: int) -> Tuple[bool, Any, List[str]]:
    """Call ``call`` until it returns, at most ``bound + 1`` times: ``(ok, value, failure type names)``.

    Only ``Exception`` counts as a handler failure; anything else (an interrupt) propagates and leaves the
    run at its last checkpoint.
    """
    failures: List[str] = []
    for _ in range(bound + 1):
        try:
            return True, call(), failures
        except Exception as exc:  # a failing handler, retried within its bound
            failures.append(type(exc).__name__)
    return False, None, failures


def recovery_record(node_id: str, reason: str, bound: int, errors: Iterable[str] = (),
                    child: Optional[str] = None, child_recovery: Optional[dict] = None) -> dict:
    errors = list(errors)
    return {"node": node_id, "reason": reason, "bound": bound, "attempts": len(errors), "errors": errors,
            "child": child, "child_recovery": child_recovery, "outcome": "FAILED"}
