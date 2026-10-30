"""The GE graph engine: run a validated graph contract deterministically, with run state and checkpoints.

``start(contract, handlers, store, run_id, now)`` starts a run of ``contract`` in ``<store>/<run_id>``.
``resume(run_id, handlers, store, now, approval=None)`` continues it from its last checkpoint. Both return
an ``Outcome``; ``status(run_id, store)`` reports a run's verified state. A run starts only for a contract
``graph_contracts.validate.validate`` returns ``CONTRACT_VALID`` for; otherwise it is ``REFUSED`` with the
validator's rule, and its directory holds only the refusal record.

Node semantics by kind:

``DETERMINISTIC_TASK``, ``AGENT_TASK``  call the handler the caller registered for the node (``handlers.py``).
                                       The output is checked against the node's ``output_schema`` before
                                       it is accepted. The engine calls no model and no network.
``ROUTER``                             takes the route-map edge whose label is the value of the declared
                                       state key the route-map's ``route_key`` names. Nothing else counts.
``HITL_GATE``                          suspends the run (``AWAITING_HITL``). Only an approval record passed
                                       to ``resume`` passes it; no node output, state value or artifact does.
``VERIFICATION_GATE``                  suspends the run (``AWAITING_VERIFICATION``). Only a verification
                                       record passed to ``resume`` passes it, and only if its ``actor``
                                       differs from the actor recorded for every node the gate guards.
``SUBGRAPH``                           runs the referenced contract, resolved at start from the caller's
                                       contract set, as a child run with its own state scope.

A checkpoint follows every accepted node (``checkpoint.py``). ``resume`` verifies the event chain, every
checkpoint, the contracts and every child run before anything runs, and refuses with
``CHECKPOINT_INTEGRITY`` otherwise. Time is the caller's ``now``: the same contract, handlers and inputs give
byte-identical run directories.

The engine is a library and a CLI (``python3 -m graph_engine.engine run|resume|status``). Running a graph
here activates nothing on any live system and is not evidence of production operation (directive section 8
non-equivalence rule); activation is a separate HITL-gated decision. Every ``Outcome`` says so in ``scope``.
"""

from __future__ import annotations

import argparse
import functools
import importlib
import os
import shutil
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from graph_contracts import gates as G
from graph_contracts import schema as S
from graph_contracts import validate as V
from graph_engine import checkpoint as CK
from graph_engine import handlers as H
from graph_engine import state as ST

RUNNING = "RUNNING"
AWAITING_HITL = "AWAITING_HITL"
AWAITING_VERIFICATION = "AWAITING_VERIFICATION"
COMPLETED = "COMPLETED"
FAILED = "FAILED"
REFUSED = "REFUSED"
STATUSES = (RUNNING, AWAITING_HITL, AWAITING_VERIFICATION, COMPLETED, FAILED, REFUSED)
SUSPENDED = (AWAITING_HITL, AWAITING_VERIFICATION)
TERMINAL = (COMPLETED, FAILED, REFUSED)
GATE_STATUS = {"HITL_GATE": AWAITING_HITL, "VERIFICATION_GATE": AWAITING_VERIFICATION}

CHECKPOINT_INTEGRITY = "CHECKPOINT_INTEGRITY"
DEFAULT_MAX_STEPS = 10000
SCOPE = ("graph run under a caller-supplied store only: not activation of a graph on a live system and not "
         "evidence of production operation (directive section 8 non-equivalence rule)")

RUN_STARTED = "RUN_STARTED"
NODE_ACCEPTED = "NODE_ACCEPTED"
NODE_ATTEMPT_FAILED = "NODE_ATTEMPT_FAILED"
GATE_AWAITING = "GATE_AWAITING"
GATE_PASSED = "GATE_PASSED"
CHILD_AWAITING = "CHILD_AWAITING"
RUN_COMPLETED = "RUN_COMPLETED"
RUN_FAILED = "RUN_FAILED"
RUN_REFUSED = "RUN_REFUSED"

CONTRACTS_SCHEMA = "ge-run-contracts-v1"
REFUSAL_SCHEMA = "ge-run-refusal-v1"
STAGING_PREFIX = ".starting-"
HITL_RECORD_FIELDS = frozenset({"gate", "boundary", "decided_by", "decision"})
VERIFICATION_RECORD_FIELDS = frozenset({"gate", "actor", "completion_state"})


@dataclass(frozen=True)
class Outcome:
    run_id: str
    status: str
    position: Optional[str] = None
    rule: Optional[str] = None
    detail: Optional[str] = None
    state: Dict[str, Any] = field(default_factory=dict)
    output: Any = None
    chain_head: Optional[str] = None
    event_count: int = 0
    scope: str = SCOPE

    def to_json(self) -> dict:
        return asdict(self)


@functools.lru_cache(maxsize=1)
def _gate_table() -> dict:
    return G.load_file()


def _key(graph_id: str, version: str) -> str:
    return f"{graph_id}@{version}"


def _ref(node: dict) -> str:
    return _key(node["subgraph"]["graph_id"], node["subgraph"]["version"])


def _closure(contracts: Dict[str, dict], root: str) -> Dict[str, dict]:
    """``root`` and every contract its SUBGRAPH nodes reach, transitively."""
    seen, todo = {root}, [root]
    while todo:
        for node in contracts[todo.pop()]["nodes"]:
            if node["kind"] == "SUBGRAPH" and _ref(node) not in seen:
                seen.add(_ref(node))
                todo.append(_ref(node))
    return {key: contracts[key] for key in sorted(seen)}


def _resolve(contract: dict, extra: Iterable) -> Tuple[Dict[str, dict], str]:
    """The (validated) contract and every subgraph contract it reaches, keyed ``graph_id@version``."""
    try:
        root_doc = ST.detach(contract, "contract")
    except ValueError as exc:
        raise ST.Refusal("CONTRACT_SHAPE", str(exc)) from None
    root = _key(root_doc["graph_id"], root_doc["version"])
    pool: Dict[str, dict] = {}
    for i, doc in enumerate(extra):
        if not isinstance(doc, dict) or not S.is_name(doc.get("graph_id")) or not S.is_name(doc.get("version")):
            raise ST.Refusal("SUBGRAPH_UNRESOLVED", f"contract set entry {i} names no graph_id and version")
        try:
            doc = ST.detach(doc, f"contract set entry {i}")
        except ValueError as exc:
            raise ST.Refusal("SUBGRAPH_UNRESOLVED", str(exc)) from None
        key = _key(doc["graph_id"], doc["version"])
        if key in pool and ST.canonical(pool[key]) != ST.canonical(doc):
            raise ST.Refusal("SUBGRAPH_AMBIGUOUS", f"the contract set holds two different contracts {key}")
        pool[key] = doc
    if root in pool and ST.canonical(pool[root]) != ST.canonical(root_doc):
        raise ST.Refusal("SUBGRAPH_AMBIGUOUS", f"the contract set holds a different contract {root}")
    resolved = {root: root_doc}
    marks: Dict[str, int] = {}

    def visit(key: str, path: List[str]) -> None:
        marks[key] = 1
        for node in resolved[key]["nodes"]:
            if node["kind"] != "SUBGRAPH":
                continue
            ref = _ref(node)
            if marks.get(ref) == 1:
                raise ST.Refusal("SUBGRAPH_CYCLE", f"subgraphs reference each other: {' -> '.join(path + [ref])}")
            if ref in marks:
                continue
            if ref not in pool:
                raise ST.Refusal("SUBGRAPH_UNRESOLVED",
                                 f"node {node['id']} of {key} references {ref}, which the contract set does not hold")
            result = V.validate(pool[ref])
            if not result.valid:
                raise ST.Refusal(result.rule, f"subgraph contract {ref}: {result.detail}")
            resolved[ref] = pool[ref]
            visit(ref, path + [ref])
        marks[key] = 2

    visit(root, [root])
    return {key: resolved[key] for key in sorted(resolved)}, root


def _preflight(contracts: Dict[str, dict], registry: H.Registry) -> None:
    """Refuse a run whose contracts the engine cannot execute with ``registry`` exactly as declared."""
    graphs: Dict[str, str] = {}
    expected = set()
    for key in sorted(contracts):
        doc = contracts[key]
        if doc["graph_id"] in graphs:
            raise ST.Refusal("SUBGRAPH_AMBIGUOUS",
                             f"the run reaches {graphs[doc['graph_id']]} and {key}; one version per graph_id")
        graphs[doc["graph_id"]] = key
        for node in doc["nodes"]:
            if node["kind"] in H.TASK_KINDS:
                expected.add((doc["graph_id"], node["id"]))
            elif node["kind"] == "ROUTER":
                edge = next(e for e in doc["edges"] if e["kind"] == "conditional" and e["from"] == node["id"])
                if edge["route_key"] not in doc["state"]["keys"]:
                    raise ST.Refusal("ROUTE_STATE_UNDECLARED",
                                     f"router {node['id']} of {key} routes on {edge['route_key']!r}, which is not a "
                                     f"declared state key")
    registered = set(registry.keys())
    missing = sorted(expected - registered)
    if missing:
        raise ST.Refusal("HANDLER_MISSING", f"no handler is registered for task nodes {missing}")
    unexpected = sorted(registered - expected)
    if unexpected:
        raise ST.Refusal("HANDLER_UNEXPECTED", f"handlers are registered for {unexpected}, which are not task nodes "
                                               f"of this run")


def _run_dir(store: Any, run_id: Any) -> Path:
    if not isinstance(run_id, str) or not ST.RUN_ID_RE.match(run_id):
        raise ValueError(f"run_id must match {ST.RUN_ID_RE.pattern}")
    return Path(store) / run_id


def _check_call(handlers: Any, now: Any) -> None:
    if not isinstance(handlers, H.Registry):
        raise TypeError("handlers must be a graph_engine.handlers.Registry")
    if not S.is_name(now):
        raise ValueError("now must be a non-empty timestamp string")


class _Run:
    """One run (or child run) of one contract, held in one run directory."""

    def __init__(self, run_dir: Path, run_id: str, contracts: Dict[str, dict], root: str,
                 registry: Optional[H.Registry], now: Optional[str]):
        self.dir = Path(run_dir)
        self.run_id = run_id
        self.contracts = contracts
        self.root = root
        self.contract = contracts[root]
        self.registry = registry
        self.now = now
        self.graph_id = self.contract["graph_id"]
        self.version = self.contract["version"]
        self.nodes = {node["id"]: node for node in self.contract["nodes"]}
        self.static = {e["from"]: e["to"] for e in self.contract["edges"] if e["kind"] == "static"}
        self.routes = {e["from"]: e for e in self.contract["edges"] if e["kind"] == "conditional"}
        self.scope = ST.Scope(self.contract)
        self.log: ST.EventLog
        self.status = RUNNING
        self.position: Optional[str] = self.contract["entry"]
        self.child: Optional[str] = None
        self.carry: Any = None
        self.output: Any = None
        self.actors: Dict[str, str] = {}
        self.evidence: List[dict] = []
        self.step = 0
        self.rule: Optional[str] = None
        self.detail: Optional[str] = None
        self.recovery: Optional[dict] = None
        self.max_steps = DEFAULT_MAX_STEPS
        self.seq = 0
        self.last = ST.ZERO
        self.committed = 0

    # -- creating and loading -------------------------------------------------------------------------------

    @classmethod
    def create(cls, run_dir: Path, run_id: str, contracts: Dict[str, dict], root: str, registry: H.Registry,
               now: str, inputs: Any, max_steps: int) -> "_Run":
        """Write a new run directory atomically: staged under a dot-name, renamed once its first checkpoint exists."""
        run_dir = Path(run_dir)
        staging = run_dir.parent / f"{STAGING_PREFIX}{run_dir.name}"
        if staging.is_symlink():
            raise ValueError(f"staging path {staging} is a symbolic link")
        if staging.exists():  # an earlier start that never completed; it was never a run
            shutil.rmtree(staging)
        staging.mkdir(parents=True)
        run = cls(staging, run_id, contracts, root, registry, now)
        data = ST.canonical({"schema": CONTRACTS_SCHEMA, "root": root, "contracts": contracts})
        ST.write_atomic(staging / ST.CONTRACTS, data)
        run.log = ST.EventLog.create(staging / ST.EVENTS)
        run.carry, run.max_steps = inputs, max_steps
        run.log.append(now, RUN_STARTED, graph_id=run.graph_id, version=run.version, contracts=ST.sha256_hex(data),
                       input=ST.value_digest(inputs), max_steps=max_steps)
        run._checkpoint()
        os.rename(staging, run_dir)
        run.dir = run_dir
        run.log.path = run_dir / ST.EVENTS
        return run

    @classmethod
    def load(cls, run_dir: Path, run_id: str, registry: Optional[H.Registry], now: Optional[str]) -> "_Run":
        """The run at ``run_dir``, restored from its last checkpoint once everything verifies."""
        try:
            return cls._load(Path(run_dir), run_id, registry, now)
        except (KeyError, TypeError, IndexError, AttributeError, ValueError) as exc:
            raise ST.IntegrityError(f"run record is malformed ({type(exc).__name__})") from None

    @classmethod
    def _load(cls, run_dir: Path, run_id: str, registry: Optional[H.Registry], now: Optional[str]) -> "_Run":
        if run_dir.is_symlink() or not run_dir.is_dir():
            raise ST.IntegrityError(f"run {run_id} has no run directory")
        log = ST.EventLog.load(run_dir / ST.EVENTS)
        if not log.count or log.events[0]["type"] != RUN_STARTED:
            raise ST.IntegrityError("the event log does not open with RUN_STARTED")
        data = ST.read_file(run_dir / ST.CONTRACTS, "contracts.json")
        if ST.sha256_hex(data) != log.events[0]["contracts"]:
            raise ST.IntegrityError("contracts.json is not the contract set the run started with")
        doc = ST.parse_canonical(data, "contracts.json")
        if (not isinstance(doc, dict) or set(doc) != {"schema", "root", "contracts"}
                or doc["schema"] != CONTRACTS_SCHEMA or not isinstance(doc["contracts"], dict)
                or doc["root"] not in doc["contracts"]):
            raise ST.IntegrityError("contracts.json is malformed")
        for key, contract in doc["contracts"].items():
            if not V.validate(contract).valid or key != _key(contract["graph_id"], contract["version"]):
                raise ST.IntegrityError(f"contracts.json: {key} is not a valid contract under its own key")
            for node in contract["nodes"]:
                if node["kind"] == "SUBGRAPH" and _ref(node) not in doc["contracts"]:
                    raise ST.IntegrityError(f"contracts.json: {key} references {_ref(node)}, which it does not hold")
        run = cls(run_dir, run_id, doc["contracts"], doc["root"], registry, now)
        run.log = log
        docs = CK.load_all(run_dir, log)
        run._verify(docs)
        last = docs[-1]
        run.status, run.position, run.child = last["status"], last["position"], last["child"]
        run.carry, run.output = last["carry"], last["output"]
        run.scope = ST.Scope(run.contract, last["state"])
        run.actors, run.evidence, run.step = dict(last["actors"]), list(last["evidence"]), last["step"]
        run.rule, run.detail, run.recovery = last["rule"], last["detail"], last["recovery"]
        run.max_steps, run.seq, run.last, run.committed = last["max_steps"], last["seq"], last["digest"], last["event_count"]
        children = run_dir / ST.CHILDREN
        if children.exists() or children.is_symlink():
            if children.is_symlink() or not children.is_dir():
                raise ST.IntegrityError("children is not a directory")
            for path in sorted(children.iterdir()):
                if not path.name.startswith(STAGING_PREFIX):
                    cls._load(path, path.name, registry, now)
        return run

    def _verify(self, docs: List[dict]) -> None:
        """Replay the event log and require every checkpoint to equal the replay at its event count."""
        events = self.log.events
        started = events[0]
        if (started["graph_id"], started["version"]) != (self.graph_id, self.version):
            raise ST.IntegrityError("the event log was started for another contract")
        if type(started["max_steps"]) is not int or started["max_steps"] < 1:
            raise ST.IntegrityError("the event log records no step bound")
        p: Dict[str, Any] = {
            "status": RUNNING, "position": self.contract["entry"], "child": None, "carry": started["input"],
            "output": None, "state": ST.value_digest({}), "actors": {}, "evidence": [], "step": 0, "rule": None,
            "detail": None, "recovery": None, "max_steps": started["max_steps"]}
        pending = list(docs)
        for n, event in enumerate(events, start=1):
            kind = event["type"]
            if n == 1:
                pass
            elif p["status"] in TERMINAL:
                raise ST.IntegrityError(f"event {n} follows the end of the run")
            elif kind == NODE_ACCEPTED:
                if event["node"] != p["position"] or event["step"] != p["step"] + 1:
                    raise ST.IntegrityError(f"event {n} accepts a node out of order")
                p.update(status=RUNNING, position=event["next"], child=None, state=event["state"], step=p["step"] + 1)
                if event["actor"] is not None:
                    p["actors"] = {**p["actors"], event["node"]: event["actor"]}
                p["evidence"] = p["evidence"] + event["evidence"]
                if event["next"] is None:
                    p["carry"], p["output"] = None, event["output"]
                else:
                    p["carry"] = event["output"]
            elif kind == NODE_ATTEMPT_FAILED:
                pass
            elif kind in (GATE_AWAITING, CHILD_AWAITING):
                if event["node"] != p["position"] or event["status"] not in SUSPENDED:
                    raise ST.IntegrityError(f"event {n} suspends the run out of order")
                p["status"] = event["status"]
                if kind == CHILD_AWAITING:
                    p["child"] = event["child"]
            elif kind == GATE_PASSED:
                if event["node"] != p["position"] or p["status"] not in SUSPENDED:
                    raise ST.IntegrityError(f"event {n} passes a gate the run does not await")
                p["status"] = RUNNING
            elif kind == RUN_COMPLETED:
                p["status"] = COMPLETED
            elif kind == RUN_FAILED:
                p["status"], p["recovery"] = FAILED, event["recovery"]
            elif kind == RUN_REFUSED:
                p["status"], p["rule"], p["detail"] = REFUSED, event["rule"], event["detail"]
            else:
                raise ST.IntegrityError(f"event {n} has unknown type {kind!r}")
            while pending and pending[0]["event_count"] == n:
                self._match(pending.pop(0), p)
        if pending:
            raise ST.IntegrityError("a checkpoint commits events the log does not hold")

    def _match(self, doc: dict, p: Dict[str, Any]) -> None:
        where = f"checkpoint {doc['seq']}"
        if (doc["run_id"], doc["graph_id"], doc["version"]) != (self.run_id, self.graph_id, self.version):
            raise ST.IntegrityError(f"{where} belongs to another run")
        for name in ("status", "position", "child", "actors", "evidence", "step", "rule", "detail", "recovery",
                     "max_steps"):
            if ST.canonical(doc[name]) != ST.canonical(p[name]):
                raise ST.IntegrityError(f"{where}: {name} does not match the event log")
        if ST.value_digest(doc["state"]) != p["state"]:
            raise ST.IntegrityError(f"{where}: state does not match the event log")
        for name in ("carry", "output"):
            ok = doc[name] is None if p[name] is None else ST.value_digest(doc[name]) == p[name]
            if not ok:
                raise ST.IntegrityError(f"{where}: {name} does not match the event log")

    # -- recording ------------------------------------------------------------------------------------------

    def _checkpoint(self) -> None:
        body = {"schema": CK.SCHEMA, "run_id": self.run_id, "graph_id": self.graph_id, "version": self.version,
                "seq": self.seq + 1, "previous": self.last, "status": self.status, "position": self.position,
                "child": self.child, "carry": self.carry, "output": self.output, "state": self.scope.values,
                "actors": self.actors, "evidence": self.evidence, "step": self.step, "rule": self.rule,
                "detail": self.detail, "recovery": self.recovery, "max_steps": self.max_steps,
                "chain_head": self.log.head, "event_count": self.log.count}
        doc = CK.write(self.dir, body)
        self.seq, self.last, self.committed = doc["seq"], doc["digest"], doc["event_count"]

    def _rollback_tail(self) -> None:
        self.log.truncate(self.committed)

    def _refuse(self, node_id: str, rule: str, detail: str) -> None:
        self.status, self.rule, self.detail = REFUSED, rule, detail
        self.log.append(self.now, RUN_REFUSED, node=node_id, rule=rule, detail=detail)
        self._checkpoint()

    def _fail(self, record: dict) -> None:
        self.status, self.recovery = FAILED, record
        self.log.append(self.now, RUN_FAILED, node=record["node"], recovery=record)
        self._checkpoint()

    def _accept(self, node: dict, output: Any, nxt: Optional[str], writes: Optional[dict] = None,
                artifacts: Optional[dict] = None, actor: Optional[str] = None, **extra: Any) -> None:
        """Accept ``output`` for ``node`` (type-checked, state via declared transitions only) and checkpoint."""
        node_id = node["id"]
        problem = H.io_problem(output, node["output_schema"], f"output of {node_id}")
        if problem:
            return self._refuse(node_id, "TYPED_OUTPUT", problem)
        try:
            values, written = self.scope.apply(node_id, output, writes)
            produced = ST.evidence(self.contract, node_id, self.step + 1, artifacts or {})
        except ST.Refusal as refusal:
            return self._refuse(node_id, refusal.rule, refusal.detail)
        for _, content in produced:
            ST.store_artifact(self.dir, content)
        entries = [entry for entry, _ in produced]
        self.step += 1
        self.scope.values = values
        if actor is not None:
            self.actors[node_id] = actor
        self.evidence.extend(entries)
        self.child = None
        self.log.append(self.now, NODE_ACCEPTED, node=node_id, kind=node["kind"], step=self.step, actor=actor,
                        output=ST.value_digest(output), state=ST.value_digest(values), writes=written,
                        evidence=entries, next=nxt, **extra)
        self.position = nxt
        if nxt is None:
            self.carry, self.output, self.status = None, output, COMPLETED
            self.log.append(self.now, RUN_COMPLETED, output=ST.value_digest(output))
        else:
            self.carry = output
        self._checkpoint()

    # -- executing ------------------------------------------------------------------------------------------

    def _advance(self) -> None:
        while self.status == RUNNING:
            node = self.nodes[self.position]
            if self.step >= self.max_steps:
                self._fail(CK.recovery_record(node["id"], CK.STEP_BOUND, self.max_steps))
                break
            problem = H.io_problem(self.carry, node["input_schema"], f"input of {node['id']}")
            if problem:
                self._refuse(node["id"], "TYPED_INPUT", problem)
                break
            kind = node["kind"]
            if kind in H.TASK_KINDS:
                self._task(node)
            elif kind == "ROUTER":
                self._router(node)
            elif kind in GATE_STATUS:
                self.status = GATE_STATUS[kind]
                self.log.append(self.now, GATE_AWAITING, node=node["id"], status=self.status)
                self._checkpoint()
            else:
                self._subgraph(node)

    def _task(self, node: dict) -> None:
        node_id = node["id"]
        handler = self.registry.get(self.graph_id, node_id)

        def call() -> Any:
            return handler.fn(ST.detach(self.carry, f"input of {node_id}"), self.scope.snapshot())

        ok, result, errors = CK.attempt(call, handler.retries)
        for number, error in enumerate(errors, start=1):
            self.log.append(self.now, NODE_ATTEMPT_FAILED, node=node_id, attempt=number, error=error)
        if not ok:
            return self._fail(CK.recovery_record(node_id, CK.RETRY_BOUND, handler.retries, errors))
        try:
            output, writes, artifacts = H.unpack(result)
            output = ST.detach(output, f"output of {node_id}")
            writes = ST.detach(writes, f"state writes of {node_id}")
        except ValueError as exc:
            return self._refuse(node_id, "TYPED_OUTPUT", str(exc))
        self._accept(node, output, self.static.get(node_id), writes, artifacts, actor=handler.actor)

    def _router(self, node: dict) -> None:
        node_id = node["id"]
        edge = self.routes[node_id]
        key = edge["route_key"]
        if key not in self.scope.values:
            return self._refuse(node_id, "ROUTE_STATE_UNSET",
                                f"router {node_id} routes on state key {key!r}, which no accepted transition has written")
        label = self.scope.values[key]
        if not isinstance(label, str) or label not in edge["routes"]:
            return self._refuse(node_id, "ROUTE_LABEL_UNDECLARED",
                                f"router {node_id}: state {key!r} holds {label!r}, which is not a route-map label")
        output = dict(self.carry) if isinstance(self.carry, dict) else {}
        output[key] = label
        self._accept(node, output, edge["routes"][label], route=label)

    def _subgraph(self, node: dict, approval: Any = None, verification: Any = None) -> Optional[Tuple[str, str]]:
        node_id = node["id"]
        ref = _ref(node)
        child_id = self.child or f"{self.step + 1:06d}-{node_id}"
        child_dir = self.dir / ST.CHILDREN / child_id
        if child_dir.exists() or child_dir.is_symlink():
            child = _Run.load(child_dir, child_id, self.registry, self.now)
            record = approval is not None or verification is not None
            if child.status == RUNNING or (child.status in SUSPENDED and record):
                problem = child._resume(approval, verification)
                if problem:
                    return problem
        else:
            entry = self.contracts[ref]["entry"]
            entry_schema = next(n for n in self.contracts[ref]["nodes"] if n["id"] == entry)["input_schema"]
            problem = H.io_problem(self.carry, entry_schema, f"input of subgraph {node_id}")
            if problem:
                self._refuse(node_id, "TYPED_INPUT", problem)
                return None
            child = _Run.create(child_dir, child_id, _closure(self.contracts, ref), ref, self.registry, self.now,
                                self.carry, self.max_steps)
            child._advance()
        if child.status in SUSPENDED:
            if (self.status, self.child) != (child.status, child_id):
                self.status, self.child = child.status, child_id
                self.log.append(self.now, CHILD_AWAITING, node=node_id, child=child_id, status=child.status)
                self._checkpoint()
            return None
        self.status = RUNNING
        if child.status == COMPLETED:
            self._accept(node, child.output, self.static.get(node_id), child=child_id)
        elif child.status == FAILED:
            self._fail(CK.recovery_record(node_id, CK.SUBGRAPH_FAILED, self.max_steps, child=child_id,
                                          child_recovery=child.recovery))
        else:
            self._refuse(node_id, child.rule, f"child run {child_id} of subgraph {node_id}: {child.detail}")
        return None

    # -- gates ----------------------------------------------------------------------------------------------

    def _approval_problem(self, node: dict, record: Any) -> Optional[Tuple[str, str]]:
        invalid = "HITL_APPROVAL_INVALID"
        if not isinstance(record, dict) or set(record) != HITL_RECORD_FIELDS:
            return invalid, f"an approval record has exactly the fields {sorted(HITL_RECORD_FIELDS)}"
        if record["gate"] != node["id"]:
            return invalid, f"the approval names gate {record['gate']!r}; the run awaits {node['id']}"
        if record["boundary"] != node["gate"]["boundary"]:
            return invalid, f"the approval is for boundary {record['boundary']!r}; gate {node['id']} guards " \
                            f"{node['gate']['boundary']}"
        met, reason = G.hitl_criterion_met({k: record[k] for k in ("boundary", "decided_by", "decision")},
                                           _gate_table())
        if not met:
            return invalid, reason
        if ST.plain_problem(record, "approval"):
            return invalid, "the approval record is not JSON data"
        return None

    def _verification_problem(self, node: dict, record: Any) -> Optional[Tuple[str, str]]:
        invalid = "VERIFICATION_INVALID"
        gate = node["gate"]
        if not isinstance(record, dict) or set(record) != VERIFICATION_RECORD_FIELDS:
            return invalid, f"a verification record has exactly the fields {sorted(VERIFICATION_RECORD_FIELDS)}"
        if record["gate"] != node["id"]:
            return invalid, f"the verification names gate {record['gate']!r}; the run awaits {node['id']}"
        if record["completion_state"] != gate["completion_state"]:
            return invalid, f"verification state {record['completion_state']!r} does not complete gate " \
                            f"{node['id']}; only {gate['completion_state']} does"
        if not S.is_name(record["actor"]):
            return invalid, "the verification record names no actor"
        for guarded in gate["guards"]:
            producer = self.actors.get(guarded)
            if producer is None:
                return invalid, f"node {guarded} has no recorded actor in this run, so nothing can verify it " \
                                f"independently"
            if producer == record["actor"]:
                return ("SELF_CHECK_NEVER_EQUALS_INDEPENDENT_REVIEW",
                        f"verifier {record['actor']!r} is the actor recorded for {guarded}; a self-check never "
                        f"passes gate {node['id']}")
        return None

    def _resume(self, approval: Any, verification: Any) -> Optional[Tuple[str, str]]:
        """Continue the run; ``(rule, detail)`` when it does not move, in which case nothing was written."""
        if self.status in TERMINAL:
            return "RUN_TERMINAL", f"the run is {self.status}; a terminal run does not resume"
        if self.status == RUNNING:
            if approval is not None or verification is not None:
                return "GATE_RECORD_UNEXPECTED", "the run awaits no gate; a gate record passes only the gate awaited"
            self._rollback_tail()
            self._advance()
            return None
        hitl = self.status == AWAITING_HITL
        record, other = (approval, verification) if hitl else (verification, approval)
        if other is not None:
            return "GATE_RECORD_UNEXPECTED", f"the run is {self.status}; that record does not pass its gate"
        if record is None:
            if hitl:
                return "HITL_APPROVAL_REQUIRED", f"the run awaits HITL at {self._awaited()}; only an approval " \
                                                 f"record passed to resume passes it"
            return "VERIFICATION_REQUIRED", f"the run awaits verification at {self._awaited()}; only a " \
                                            f"verification record passed to resume passes it"
        node = self.nodes[self.position]
        if self.child is not None:
            self._rollback_tail()
            problem = self._subgraph(node, approval, verification)
            if problem:
                return problem
            self._advance()
            return None
        problem = self._approval_problem(node, record) if hitl else self._verification_problem(node, record)
        if problem:
            return problem
        self._rollback_tail()
        self.status = RUNNING
        self.log.append(self.now, GATE_PASSED, node=node["id"], record=ST.detach(record, "gate record"))
        self._accept(node, self.carry, self.static.get(node["id"]))
        self._advance()
        return None

    def _awaited(self) -> str:
        return f"{self.position} (child run {self.child})" if self.child else str(self.position)

    def outcome(self, rule: Optional[str] = None, detail: Optional[str] = None) -> Outcome:
        return Outcome(self.run_id, self.status, self.position, rule or self.rule, detail or self.detail,
                       ST.detach(self.scope.values, "state"), self.output, self.log.head, self.log.count)


def start(contract: Any, handlers: H.Registry, store: Any, run_id: str, now: str, *, contracts: Iterable = (),
          inputs: Any = None, max_steps: int = DEFAULT_MAX_STEPS) -> Outcome:
    """Start a run of ``contract`` as ``<store>/<run_id>`` and execute it until it completes, fails, is
    refused or suspends at a gate.

    ``contracts`` is the caller's contract set for SUBGRAPH references; ``inputs`` is the entry node's input
    (default ``{}``); ``max_steps`` bounds the accepted nodes of the run and of each child run.
    """
    run_dir = _run_dir(store, run_id)
    _check_call(handlers, now)
    if type(max_steps) is not int or max_steps < 1:
        raise ValueError("max_steps must be a positive integer")
    if run_dir.exists() or run_dir.is_symlink():
        return Outcome(run_id, REFUSED, rule="RUN_EXISTS", detail=f"run {run_id} already exists in the store")
    result = V.validate(contract)
    if not result.valid:
        return _refuse_start(run_dir, run_id, now, result.rule, result.detail)
    try:
        resolved, root = _resolve(contract, contracts or ())
        _preflight(resolved, handlers)
        try:
            inputs = ST.detach({} if inputs is None else inputs, "inputs")
        except ValueError as exc:
            raise ST.Refusal("TYPED_INPUT", str(exc)) from None
        entry = next(n for n in resolved[root]["nodes"] if n["id"] == resolved[root]["entry"])
        problem = H.io_problem(inputs, entry["input_schema"], "inputs")
        if problem:
            raise ST.Refusal("TYPED_INPUT", problem)
    except ST.Refusal as refusal:
        return _refuse_start(run_dir, run_id, now, refusal.rule, refusal.detail)
    run = _Run.create(run_dir, run_id, resolved, root, handlers, now, inputs, max_steps)
    run._advance()
    return run.outcome()


def _refuse_start(run_dir: Path, run_id: str, now: str, rule: str, detail: str) -> Outcome:
    run_dir.mkdir(parents=True)
    record = {"schema": REFUSAL_SCHEMA, "run_id": run_id, "status": REFUSED, "rule": rule, "detail": detail,
              "at": now, "scope": SCOPE}
    ST.write_atomic(run_dir / ST.REFUSAL, ST.canonical(record) + b"\n")
    return Outcome(run_id, REFUSED, rule=rule, detail=detail)


def _read_refusal(run_dir: Path) -> dict:
    record = ST.parse_canonical(ST.read_file(run_dir / ST.REFUSAL, "refusal record").rstrip(b"\n"), "refusal record")
    if not isinstance(record, dict) or record.get("schema") != REFUSAL_SCHEMA:
        raise ST.IntegrityError("refusal record is malformed")
    return record


def resume(run_id: str, handlers: H.Registry, store: Any, now: str, approval: Any = None, *,
           verification: Any = None) -> Outcome:
    """Resume run ``run_id`` from its last checkpoint.

    A run awaiting HITL moves only with an ``approval`` record ``{gate, boundary, decided_by, decision}``
    meeting gate-table stage 8.6; a run awaiting verification only with a ``verification`` record
    ``{gate, actor, completion_state}`` whose actor did not produce what the gate guards. A run whose event
    chain or checkpoints do not verify is refused with ``CHECKPOINT_INTEGRITY`` and nothing runs.
    """
    run_dir = _run_dir(store, run_id)
    _check_call(handlers, now)
    if (run_dir / ST.REFUSAL).exists():
        try:
            record = _read_refusal(run_dir)
        except ST.IntegrityError as exc:
            return Outcome(run_id, REFUSED, rule=CHECKPOINT_INTEGRITY, detail=str(exc))
        return Outcome(run_id, REFUSED, rule=record["rule"], detail="the run was refused at start and never ran")
    if not run_dir.exists():
        return Outcome(run_id, REFUSED, rule="RUN_UNKNOWN", detail=f"no run {run_id} in the store")
    try:
        run = _Run.load(run_dir, run_id, handlers, now)
    except ST.IntegrityError as exc:
        return Outcome(run_id, REFUSED, rule=CHECKPOINT_INTEGRITY, detail=str(exc))
    try:
        _preflight(run.contracts, handlers)
    except ST.Refusal as refusal:
        return run.outcome(refusal.rule, refusal.detail)
    problem = run._resume(approval, verification)
    return run.outcome(*problem) if problem else run.outcome()


def status(run_id: str, store: Any) -> dict:
    """The run's verified status: state, position, chain head and event count (the observability surface)."""
    run_dir = _run_dir(store, run_id)
    doc = {"run_id": run_id, "graph_id": None, "version": None, "status": None, "position": None, "child": None,
           "state": {}, "step": 0, "chain_head": None, "event_count": 0, "checkpoints": 0, "rule": None,
           "detail": None, "recovery": None, "integrity": None, "scope": SCOPE}
    if (run_dir / ST.REFUSAL).exists():
        try:
            record = _read_refusal(run_dir)
        except ST.IntegrityError as exc:
            return {**doc, "integrity": "FAILED", "rule": CHECKPOINT_INTEGRITY, "detail": str(exc)}
        return {**doc, "status": REFUSED, "rule": record["rule"], "detail": record["detail"],
                "integrity": "REFUSAL_RECORD"}
    if not run_dir.exists():
        return {**doc, "integrity": "FAILED", "rule": "RUN_UNKNOWN", "detail": f"no run {run_id} in the store"}
    try:
        run = _Run.load(run_dir, run_id, None, None)
    except ST.IntegrityError as exc:
        return {**doc, "integrity": "FAILED", "rule": CHECKPOINT_INTEGRITY, "detail": str(exc)}
    return {**doc, "graph_id": run.graph_id, "version": run.version, "status": run.status, "position": run.position,
            "child": run.child, "state": run.scope.values, "step": run.step, "chain_head": run.log.head,
            "event_count": run.log.count, "checkpoints": run.seq, "rule": run.rule, "detail": run.detail,
            "recovery": run.recovery, "integrity": "VERIFIED"}


# -- CLI ----------------------------------------------------------------------------------------------------

def load_handlers(spec: str) -> H.Registry:
    """The registry named ``module:attribute``; a callable attribute is called to build it."""
    module, _, attribute = spec.partition(":")
    if not module or not attribute:
        raise ValueError("--handlers must be MODULE:ATTRIBUTE")
    registry = getattr(importlib.import_module(module), attribute)
    if callable(registry) and not isinstance(registry, H.Registry):
        registry = registry()
    if not isinstance(registry, H.Registry):
        raise TypeError(f"{spec} is not a graph_engine.handlers.Registry")
    return registry


def _json_file(path: Optional[str], what: str) -> Any:
    return None if path is None else S.read_file(Path(path), what)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m graph_engine.engine",
                                     description="Run, resume or inspect a GE graph run (canonical JSON output).")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "resume", "status"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--store", required=True)
        cmd.add_argument("--run-id", required=True)
        if name == "status":
            continue
        cmd.add_argument("--now", required=True)
        cmd.add_argument("--handlers", required=True, help="MODULE:ATTRIBUTE naming a handlers.Registry")
        if name == "run":
            cmd.add_argument("--contract", required=True)
            cmd.add_argument("--contracts", action="append", default=[], help="a subgraph contract (repeatable)")
            cmd.add_argument("--input")
            cmd.add_argument("--max-steps", type=int, default=DEFAULT_MAX_STEPS)
        else:
            cmd.add_argument("--approval")
            cmd.add_argument("--verification")
    args = parser.parse_args(argv)
    try:
        if args.command == "status":
            doc = status(args.run_id, args.store)
            code = 0 if doc["integrity"] in ("VERIFIED", "REFUSAL_RECORD") else 1
        else:
            registry = load_handlers(args.handlers)
            if args.command == "run":
                outcome = start(_json_file(args.contract, "contract"), registry, args.store, args.run_id, args.now,
                                contracts=[_json_file(p, "contract") for p in args.contracts],
                                inputs=_json_file(args.input, "input"), max_steps=args.max_steps)
            else:
                outcome = resume(args.run_id, registry, args.store, args.now,
                                 approval=_json_file(args.approval, "approval record"),
                                 verification=_json_file(args.verification, "verification record"))
            doc = outcome.to_json()
            code = 0 if outcome.status in (COMPLETED,) + SUSPENDED and outcome.rule is None else 1
    except (ValueError, TypeError, ImportError, AttributeError) as exc:
        sys.stderr.write(f"graph_engine: {exc}\n")
        return 2
    sys.stdout.write(ST.canonical(doc).decode("utf-8") + "\n")
    return code


if __name__ == "__main__":
    sys.exit(main())
