"""Run state for the GE graph engine: run directories, scoped state, the event chain and evidence.

A run lives in one directory under a caller-supplied store root::

    <store>/<run_id>/
        contracts.json   the validated contract and every subgraph contract it reaches (canonical JSON)
        events.jsonl     the append-only event log, one canonical JSON event per line
        checkpoints/     NNNNNN.json, one per checkpoint (``checkpoint.py``)
        artifacts/       artifact content named by its SHA-256 digest: evidence, never state
        children/        one child run directory per SUBGRAPH execution, same layout

A run the engine refuses to start holds ``refusal.json`` and nothing else.

State is scoped to one run of one contract and changes only through the contract's declared transitions:
when a node is accepted, each key a declared transition of that node writes takes the value the node's
output carries for it. A handler that asks to write any other key, or another value, is refused with
``STATE_TRANSITION_UNDECLARED``.

Every event carries ``seq`` (from 1), ``prev`` (the SHA-256 of the previous event's line, 64 zeros for the
first), ``at`` (the caller's ``now``) and ``type``. The chain head is the SHA-256 of the last line.
Canonical JSON is sorted-key, separator-compact UTF-8 without NaN or infinities.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from graph_engine import handlers as H

ZERO = "0" * 64
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

CONTRACTS = "contracts.json"
EVENTS = "events.jsonl"
CHECKPOINTS = "checkpoints"
ARTIFACTS = "artifacts"
CHILDREN = "children"
REFUSAL = "refusal.json"

STATE_TRANSITION_UNDECLARED = "STATE_TRANSITION_UNDECLARED"
TYPED_STATE = "TYPED_STATE"
ARTIFACT_UNDECLARED = "ARTIFACT_UNDECLARED"
EVENT_FIELDS = ("seq", "prev", "at", "type")


class IntegrityError(Exception):
    """A run directory whose event chain, checkpoints or contracts do not verify."""


class Refusal(Exception):
    """A rule the engine refuses on, with a detail line."""

    def __init__(self, rule: str, detail: str):
        super().__init__(f"{rule}: {detail}")
        self.rule = rule
        self.detail = detail


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def value_digest(value: Any) -> str:
    return sha256_hex(canonical(value))


def plain_problem(value: Any, where: str = "value") -> Optional[str]:
    """Why ``value`` is not plain JSON data, or None.

    Plain data is ``dict`` with string keys, ``list``, ``str``, ``int``, finite ``float``, ``bool`` and
    ``None``, exactly; tuples, sets, bytes, subclasses and other objects are not.
    """
    if value is None or type(value) in (bool, int, str):
        return None
    if type(value) is float:
        return None if math.isfinite(value) else f"{where} is not a finite number"
    if type(value) is list:
        for i, item in enumerate(value):
            problem = plain_problem(item, f"{where}[{i}]")
            if problem:
                return problem
        return None
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                return f"{where} has a non-string key {key!r}"
            problem = plain_problem(item, f"{where}.{key}")
            if problem:
                return problem
        return None
    return f"{where} is a {type(value).__name__}, not JSON data"


def detach(value: Any, where: str = "value") -> Any:
    """A copy of plain JSON ``value`` sharing nothing with it; anything else raises ``ValueError``."""
    try:
        problem = plain_problem(value, where)
    except RecursionError:
        problem = f"{where} is nested too deeply"
    if problem:
        raise ValueError(problem)
    return json.loads(canonical(value))


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def parse_canonical(data: bytes, what: str) -> Any:
    """Parse ``data``, which must be exactly the canonical JSON of what it holds; else ``IntegrityError``."""
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise IntegrityError(f"{what} is not valid JSON ({type(exc).__name__})") from None
    try:
        same = canonical(value) == data
    except (ValueError, RecursionError):
        same = False
    if not same:
        raise IntegrityError(f"{what} is not canonical JSON")
    return value


def read_file(path: Path, what: str) -> bytes:
    path = Path(path)
    try:
        if path.is_symlink() or not path.is_file():
            raise IntegrityError(f"{what} is missing")
        return path.read_bytes()
    except OSError as exc:
        raise IntegrityError(f"{what} is unreadable ({exc.strerror})") from None


def write_atomic(path: Path, data: bytes) -> None:
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)


class EventLog:
    """The append-only, hash-chained event log of one run."""

    def __init__(self, path: Path, lines: List[bytes], events: List[dict]):
        self.path = Path(path)
        self.lines = lines
        self.events = events
        self.hashes = [sha256_hex(line) for line in lines]

    @classmethod
    def create(cls, path: Path) -> "EventLog":
        path = Path(path)
        if path.exists() or path.is_symlink():
            raise FileExistsError(str(path))
        path.write_bytes(b"")
        return cls(path, [], [])

    @classmethod
    def load(cls, path: Path) -> "EventLog":
        """The verified log at ``path``; a broken chain, a gap or a non-canonical line is ``IntegrityError``."""
        data = read_file(path, "event log")
        if data and not data.endswith(b"\n"):
            raise IntegrityError("event log ends inside an event")
        lines = data.split(b"\n")[:-1] if data else []
        events: List[dict] = []
        prev = ZERO
        for i, line in enumerate(lines, start=1):
            event = parse_canonical(line, f"event {i}")
            if not isinstance(event, dict) or any(name not in event for name in EVENT_FIELDS):
                raise IntegrityError(f"event {i} lacks the fields {list(EVENT_FIELDS)}")
            if type(event["seq"]) is not int or event["seq"] != i:
                raise IntegrityError(f"event {i} is out of sequence")
            if event["prev"] != prev:
                raise IntegrityError(f"event {i} does not chain to the event before it")
            if not isinstance(event["at"], str) or not isinstance(event["type"], str):
                raise IntegrityError(f"event {i} has a malformed time or type")
            events.append(event)
            prev = sha256_hex(line)
        return cls(path, lines, events)

    @property
    def count(self) -> int:
        return len(self.lines)

    @property
    def head(self) -> str:
        return self.head_at(self.count)

    def head_at(self, count: int) -> str:
        return self.hashes[count - 1] if count else ZERO

    def append(self, at: str, event_type: str, /, **payload: Any) -> dict:
        """Append an event of ``event_type``; positional-only, so a payload may carry any other field name."""
        if set(payload) & set(EVENT_FIELDS):
            raise ValueError(f"event payload may not set {list(EVENT_FIELDS)}")
        event = {"seq": self.count + 1, "prev": self.head, "at": at, "type": event_type, **payload}
        line = canonical(event)
        with open(self.path, "ab") as fh:
            fh.write(line + b"\n")
        self.lines.append(line)
        self.events.append(json.loads(line))
        self.hashes.append(sha256_hex(line))
        return event

    def truncate(self, count: int) -> None:
        """Drop the events after ``count``: a tail no checkpoint committed (see IMPLEMENTATION-DECISIONS)."""
        if count >= self.count:
            return
        write_atomic(self.path, b"".join(line + b"\n" for line in self.lines[:count]))
        del self.lines[count:], self.events[count:], self.hashes[count:]


class Scope:
    """One run's state scope: the contract's declared keys, changed only by its declared transitions."""

    def __init__(self, contract: dict, values: Optional[dict] = None):
        state = contract["state"]
        self.name = state["scope"]
        self.keys = state["keys"]
        self.transitions: Dict[str, List[str]] = {}
        for transition in state["transitions"]:
            writes = self.transitions.setdefault(transition["node"], [])
            writes.extend(key for key in transition["writes"] if key not in writes)
        self.values: Dict[str, Any] = dict(values or {})

    def snapshot(self) -> dict:
        return detach(self.values, "state")

    def apply(self, node_id: str, output: Any, requested: Optional[Mapping[str, Any]] = None) -> Tuple[dict, List[str]]:
        """The state after ``node_id`` is accepted with ``output``, and the keys written; refuses otherwise."""
        declared = sorted(self.transitions.get(node_id, []))
        for key in sorted(requested or {}):
            if key not in declared:
                raise Refusal(STATE_TRANSITION_UNDECLARED,
                              f"node {node_id} writes state key {key!r}, which no declared transition of {node_id} writes")
            if not isinstance(output, dict) or key not in output or canonical(requested[key]) != canonical(output[key]):
                raise Refusal(STATE_TRANSITION_UNDECLARED,
                              f"node {node_id} writes state key {key!r} with a value its declared transition does not carry")
        values = dict(self.values)
        for key in declared:
            if not isinstance(output, dict) or key not in output:
                raise Refusal(STATE_TRANSITION_UNDECLARED,
                              f"node {node_id} output carries no value for its declared transition of {key!r}")
            problem = H.io_problem(output[key], self.keys[key], f"state.{key}")
            if problem:
                raise Refusal(TYPED_STATE, problem)
            values[key] = output[key]
        return values, declared


def evidence(contract: dict, node_id: str, step: int, produced: Mapping[str, Any]) -> List[Tuple[dict, bytes]]:
    """Versioned evidence entries for the artifacts ``node_id`` produced, with their content."""
    declared = {artifact["id"]: artifact for artifact in contract["artifacts"]}
    out: List[Tuple[dict, bytes]] = []
    for artifact_id in sorted(produced):
        decl = declared.get(artifact_id)
        if decl is None or decl["produced_by"] != node_id:
            raise Refusal(ARTIFACT_UNDECLARED,
                          f"node {node_id} produced artifact {artifact_id!r}, which the contract does not declare as "
                          f"produced by {node_id}")
        content = produced[artifact_id]
        if type(content) is str:
            content = content.encode("utf-8")
        if type(content) is not bytes:
            raise Refusal(ARTIFACT_UNDECLARED, f"artifact {artifact_id!r} content must be bytes or str")
        entry = {"id": artifact_id, "version": decl["version"], "media_type": decl["media_type"], "node": node_id,
                 "step": step, "digest": sha256_hex(content), "size": len(content)}
        out.append((entry, content))
    return out


def store_artifact(run_dir: Path, content: bytes) -> None:
    root = Path(run_dir) / ARTIFACTS
    root.mkdir(exist_ok=True)
    path = root / sha256_hex(content)
    if not path.exists():
        write_atomic(path, content)
