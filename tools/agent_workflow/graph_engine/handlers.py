"""The GE graph engine's handler registry and typed-I/O check, kept apart so callers never touch the engine.

Callers register one handler per task node, keyed by the node's ``graph_id`` and node id::

    registry = Registry().register("GE-EXAMPLE-001", "build", build, actor="builder", retries=1)

A handler is called as ``handler(value, state)``. ``value`` is the node's input (the previous node's
accepted output, or the run input at the entry node) and ``state`` is a copy of the run's scoped state.
Neither is shared with the engine, so mutating them changes nothing. A handler returns the node output, or
a ``Result`` that also names state writes and artifacts. ``actor`` is the identity the engine records for
the node; a verification gate compares its verifier against it. ``retries`` is the node's bounded-recovery
bound: default 0, at most ``MAX_RETRIES``.

Only ``DETERMINISTIC_TASK`` and ``AGENT_TASK`` nodes have handlers. The engine calls no model and no
network: an agent task is whatever handler the caller registers.

``io_problem(value, schema)`` checks a value against a framework-neutral io schema, the subset
``graph_contracts`` validates: ``type``, ``properties`` / ``required`` / ``additionalProperties`` on objects,
``items`` on arrays and ``enum`` on scalars.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from graph_contracts import schema as S
from graph_contracts import validate as V

TASK_KINDS = ("DETERMINISTIC_TASK", "AGENT_TASK")
MAX_RETRIES = 100


class RegistrationError(ValueError):
    pass


@dataclass(frozen=True)
class Handler:
    fn: Callable[[Any, dict], Any]
    actor: str
    retries: int = 0


@dataclass(frozen=True)
class Result:
    """A handler result with explicit state writes and artifacts.

    ``writes`` maps state keys to values. Each key must be one a declared transition of the node writes,
    with the value the node output carries for it; anything else is ``STATE_TRANSITION_UNDECLARED``.
    ``artifacts`` maps artifact ids the contract declares as produced by the node to their content
    (``bytes`` or ``str``). Artifacts are recorded as versioned evidence and never become state.
    """

    output: Any
    writes: Optional[Mapping[str, Any]] = None
    artifacts: Optional[Mapping[str, Any]] = None


class Registry:
    """Task-node handlers keyed by ``(graph_id, node_id)``."""

    def __init__(self) -> None:
        self._handlers: Dict[Tuple[str, str], Handler] = {}

    def register(self, graph_id: str, node_id: str, fn: Callable[[Any, dict], Any], *, actor: str,
                 retries: int = 0) -> "Registry":
        for name, value in (("graph_id", graph_id), ("node_id", node_id)):
            if not isinstance(value, str) or not V.ID_RE.match(value):
                raise RegistrationError(f"{name} must be an identifier matching {V.ID_RE.pattern}")
        if not callable(fn):
            raise RegistrationError(f"handler for {graph_id} {node_id} must be callable")
        if not S.is_name(actor):
            raise RegistrationError(f"handler for {graph_id} {node_id} needs a non-empty actor")
        if type(retries) is not int or not 0 <= retries <= MAX_RETRIES:
            raise RegistrationError(f"retries for {graph_id} {node_id} must be an integer from 0 to {MAX_RETRIES}")
        key = (graph_id, node_id)
        if key in self._handlers:
            raise RegistrationError(f"a handler for {graph_id} {node_id} is already registered")
        self._handlers[key] = Handler(fn, actor, retries)
        return self

    def get(self, graph_id: str, node_id: str) -> Handler:
        return self._handlers[(graph_id, node_id)]

    def keys(self) -> List[Tuple[str, str]]:
        return sorted(self._handlers)


def unpack(value: Any) -> Tuple[Any, dict, dict]:
    """``(output, writes, artifacts)`` from a handler's return value; a malformed ``Result`` raises ``ValueError``."""
    if not isinstance(value, Result):
        return value, {}, {}
    writes = {} if value.writes is None else value.writes
    artifacts = {} if value.artifacts is None else value.artifacts
    for name, table in (("state writes", writes), ("artifacts", artifacts)):
        if not isinstance(table, Mapping) or any(type(key) is not str for key in table):
            raise ValueError(f"{name} must map names to values")
    return value.output, dict(writes), dict(artifacts)


def _is_type(value: Any, kind: str) -> bool:
    if kind == "object":
        return type(value) is dict and all(type(key) is str for key in value)
    if kind == "array":
        return type(value) is list
    if kind == "string":
        return type(value) is str
    if kind == "integer":
        return type(value) is int
    if kind == "number":
        return type(value) in (int, float) and math.isfinite(value)
    if kind == "boolean":
        return type(value) is bool
    if kind == "null":
        return value is None
    return False


def io_problem(value: Any, schema: dict, where: str = "value") -> Optional[str]:
    """Why ``value`` does not satisfy the io schema ``schema``, or None."""
    kind = schema["type"]
    if not _is_type(value, kind):
        return f"{where} must be of type {kind!r}, not {type(value).__name__}"
    if "enum" in schema and not any(type(value) is type(v) and value == v for v in schema["enum"]):
        return f"{where} must be one of {schema['enum']}"
    if kind == "object":
        props = schema["properties"]
        for name in schema.get("required", []):
            if name not in value:
                return f"{where} lacks required property {name!r}"
        for name in sorted(value):
            if name in props:
                problem = io_problem(value[name], props[name], f"{where}.{name}")
                if problem:
                    return problem
            elif schema.get("additionalProperties", True) is False:
                return f"{where} has undeclared property {name!r}"
    elif kind == "array":
        for i, item in enumerate(value):
            problem = io_problem(item, schema["items"], f"{where}[{i}]")
            if problem:
                return problem
    return None
