"""Runtime tool binding (RUNTIME-TOOL-BINDING-SPEC-001): a mission seat's admitted surface as runtime tool flags.

``bind(seat, runtime, mission, checkout, session_path, evidence_dir, gateway_root, now)`` is the interface
the dispatcher's binding module (MISSION-DISPATCH-001 Amendment 011) calls. It runs the governed selection
(``tool_selection.select.select``) for the seat's role and mission type over ``runtime_registry.json`` and the
shipped matrix, and turns the admitted surface into a ``Binding``:

``tools``          admitted built-in tools, in the order ``Read, Edit, Write, Glob, Grep``
``allowed_rules``  ``Read(<glob>)`` / ``Edit(<glob>)``, the glob relative to the checkout
``denied_rules``   extra denials (none today)
``mcp_tools``      admitted gateway tools, bare names
``session``        the gateway session document (``mcp_gateway/session.py`` format)
``audit``          the ``signed`` part of an EPAP link named ``RUNTIME_BINDING``

The binding is a consumer of the selection, never a second policy: every bound tool comes from an admitted
registry entry, so it can only be as wide as the selection. Anything that is not an admitted surface (an
unknown seat or runtime, a malformed mission, a selection that does not admit, a session or evidence path
inside the checkout) raises ``BindingRefused`` and nothing is returned. It does not write the MCP config or any
runtime rules: the dispatcher renders those itself.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Tuple

from epap import links
from tool_selection import matrix as M
from tool_selection import records as R
from tool_selection import registry as REG
from tool_selection import select as S

HERE = Path(__file__).resolve().parent
SEATS_PATH = HERE / "seats.json"
REGISTRY_PATH = HERE / "runtime_registry.json"
GATEWAY_CATALOG = Path("mcp_gateway") / "tools.json"  # under gateway_root

SEATS_SCHEMA = "mission-seats-v1"
SEAT_FIELDS = frozenset({"role", "mission_type", "fabric_role", "principal", "resources"})
MISSION_FIELDS = frozenset({"id", "round", "agent", "base_sha", "build_scope"})
RUNTIMES = ("claude-code", "cursor-cli")
BUILTINS = ("Read", "Edit", "Write", "Glob", "Grep")
GATEWAY_PREFIX = "mcp__governed-retrieval__"
REPO = "checkout"  # the registry's one repository: the agent's checkout
MISSION_PLACEHOLDER = "{mission_id}"
AUTHORITY_REF = "MISSION-ROUTER-001"
SESSION_TTL = 3600  # the fabric's max_ttl_seconds, equal to the dispatcher's agent timeout
LINK_NAME = "RUNTIME_BINDING"
COMMAND = "tool_selection.runtime_binding.bind"

_MISSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_SHA = re.compile(r"[0-9a-f]{40}")
_GATEWAY_TOOL = re.compile(r"[a-z][a-z0-9_]{0,63}")


class BindingRefused(ValueError):
    """The seat cannot be bound to an admitted surface; no binding exists."""


@dataclass(frozen=True)
class Binding:
    tools: Tuple[str, ...]
    allowed_rules: list
    denied_rules: list
    mcp_tools: Tuple[str, ...]
    session: dict
    audit: dict


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _inside(path: Path, root: Path) -> bool:
    for p in (path.absolute(), path.resolve()):
        for r in (root.absolute(), root.resolve()):
            try:
                p.relative_to(r)
            except ValueError:
                continue
            return True
    return False


def load_seats(path: Path) -> dict:
    """The validated seat table at ``path``; any defect is ``BindingRefused``."""
    try:
        doc = M.read_file(path, "seat table")
    except ValueError as exc:
        raise BindingRefused(str(exc)) from None
    if not isinstance(doc, dict) or set(doc) != {"schema", "seats"} or doc["schema"] != SEATS_SCHEMA \
            or not isinstance(doc["seats"], dict):
        raise BindingRefused(f"seat table must be a {SEATS_SCHEMA!r} document")
    for name, seat in doc["seats"].items():
        if not isinstance(seat, dict) or set(seat) != SEAT_FIELDS \
                or not all(M.is_name(seat[f]) for f in ("role", "mission_type", "fabric_role", "principal")):
            raise BindingRefused(f"seat {name!r} must have exactly the fields {sorted(SEAT_FIELDS)}")
        res = seat["resources"]
        if not isinstance(res, list) or not res or not all(M.is_name(r) for r in res) or len(set(res)) != len(res):
            raise BindingRefused(f"seat {name!r} resources must be a non-empty list of distinct ids")
    return doc


def _mission(mission: Any) -> dict:
    if not isinstance(mission, dict) or set(mission) != MISSION_FIELDS:
        raise BindingRefused(f"mission must have exactly the fields {sorted(MISSION_FIELDS)}")
    if not isinstance(mission["id"], str) or not _MISSION_ID.fullmatch(mission["id"]):
        raise BindingRefused("mission id must be letters, digits and _ . - only")
    if not _is_int(mission["round"]) or mission["round"] < 1:
        raise BindingRefused("mission round must be an integer >= 1")
    if not M.is_name(mission["agent"]):
        raise BindingRefused("mission agent must be a non-empty string")
    if not isinstance(mission["base_sha"], str) or not _SHA.fullmatch(mission["base_sha"]):
        raise BindingRefused("mission base_sha must be 40 lowercase hex characters")
    scope = mission["build_scope"]
    if not isinstance(scope, (list, tuple)) or not all(isinstance(p, str) and p for p in scope):
        raise BindingRefused("mission build_scope must be a list of path patterns")
    return {"id": mission["id"], "round": mission["round"], "agent": mission["agent"],
            "base_sha": mission["base_sha"], "build_scope": list(scope)}


def render_registry(doc: Mapping, mission_id: str) -> dict:
    """The runtime registry with the mission id put into its resource paths."""
    out = copy.deepcopy(dict(doc))
    for entry in out["tools"]:
        res = entry.get("resource") if isinstance(entry, dict) else None
        if isinstance(res, dict) and isinstance(res.get("path"), str):
            res["path"] = res["path"].replace(MISSION_PLACEHOLDER, mission_id)
    return out


def _gateway_tools(gateway_root: Path) -> frozenset:
    try:
        doc = M.read_file(Path(gateway_root) / GATEWAY_CATALOG, "gateway catalog")
        return frozenset(t["name"] for t in doc["tools"])
    except (ValueError, KeyError, TypeError) as exc:
        raise BindingRefused(f"the gateway catalog under {gateway_root} cannot be read: {exc}") from None


def _rule(kind: str, path: str) -> str:
    return f"{kind}(**)" if path == "." else f"{kind}({path}/**)"


def _surface(selection: S.Selection, registry: Mapping, matrix: Mapping) -> Tuple[tuple, list, tuple, dict]:
    """(tools, allowed rules, gateway tools, registry name -> bound name) for the admitted surface only."""
    entries = [(REG.tool_name(e), e) for e in registry["tools"]]
    unknown = sorted(selection.surface - {name for name, _ in entries})
    if unknown:
        raise BindingRefused(f"admitted tools {unknown} have no registry entry")
    tools, rules, gateway, bound = set(), [], [], {}
    for name, entry in entries:  # registry order
        if name not in selection.surface:
            continue
        if name.startswith(GATEWAY_PREFIX):
            bare = name[len(GATEWAY_PREFIX):]
            if not _GATEWAY_TOOL.fullmatch(bare):
                raise BindingRefused(f"admitted gateway tool {name!r} is not a plain tool name")
            gateway.append(bare)
            bound[name] = bare
            continue
        builtin = name.split(":", 1)[0]
        if builtin not in BUILTINS:
            raise BindingRefused(f"admitted tool {name!r} is not a runtime tool the dispatcher can grant")
        cls = matrix["capabilities"][entry["capability"]]
        kind = "Read" if cls == "read" else "Edit"
        tools.add(builtin)
        rule = _rule(kind, entry["resource"]["path"])
        if rule not in rules:
            rules.append(rule)
        bound[name] = builtin
    rules.sort(key=lambda r: (not r.startswith("Read("), r))
    return tuple(t for t in BUILTINS if t in tools), rules, tuple(gateway), bound


def _artifact(folder: str, value: Any) -> Tuple[str, dict]:
    sha = R.digest(value)
    if sha is None:
        raise BindingRefused(f"the binding's {folder} has no canonical form")
    return f"tool_selection/{folder}/{sha}.json", {"sha256": sha}


def audit_material(seat: str, runtime: str, seat_doc: Mapping, seats: Mapping, matrix: Mapping,
                   registry: Mapping, request: Mapping, selection: S.Selection, bound_doc: Mapping) -> dict:
    """The ``signed`` part of the ``RUNTIME_BINDING`` link: inputs as materials, record and binding as products."""
    materials = dict(_artifact(folder, value) for folder, value in
                     (("matrix", matrix), ("registries", registry), ("requests", request), ("seats", seats)))
    products = dict(materials)
    products.update(dict(_artifact(folder, value) for folder, value in
                         (("records", selection.record), ("bindings", bound_doc))))
    byproducts = {
        "seat": seat, "runtime": runtime, "role": seat_doc["role"], "mission_type": seat_doc["mission_type"],
        "matrix_version": matrix["matrix_version"], "selection": copy.deepcopy(selection.record),
        "binding": copy.deepcopy(dict(bound_doc)),
    }
    return links.make_link(LINK_NAME, materials, products, [COMMAND, seat, runtime, matrix["matrix_version"]],
                           byproducts)


def bind(seat: Any, runtime: Any, mission: Any, checkout: Path, session_path: Path, evidence_dir: Path,
         gateway_root: Path, now: Any) -> Binding:
    """The admitted runtime surface of ``seat`` for ``mission``; raises ``BindingRefused`` otherwise."""
    if runtime not in RUNTIMES:
        raise BindingRefused(f"unknown runtime {runtime!r}")
    seats = load_seats(SEATS_PATH)
    if not isinstance(seat, str) or seat not in seats["seats"]:
        raise BindingRefused(f"unknown seat {seat!r}")
    seat_doc = seats["seats"][seat]
    mission = _mission(mission)
    if mission["agent"] != seat_doc["principal"]:
        raise BindingRefused(f"mission agent {mission['agent']!r} is not seat {seat}'s principal")
    if not _is_int(now) or now < 0:
        raise BindingRefused("now must be integer epoch seconds")
    checkout = Path(checkout)
    for what, path in (("session_path", session_path), ("evidence_dir", evidence_dir)):
        if _inside(Path(path), checkout):
            raise BindingRefused(f"{what} lies inside the checkout")

    try:
        matrix = M.load_file(M.DEFAULT_PATH)
        registry = render_registry(REG.load_file(REGISTRY_PATH), mission["id"])
    except (M.MatrixError, REG.RegistryError) as exc:
        raise BindingRefused(str(exc)) from None
    row = matrix["roles"].get(seat_doc["role"])
    if row is None:
        raise BindingRefused(f"seat {seat}'s role {seat_doc['role']!r} is not a matrix row")
    offered = {REG.capability(e, matrix["capabilities"]) for e in registry["tools"]} - {None}
    request = {
        "request_id": f"{mission['id']}.r{mission['round']}.{seat}",
        "role": seat_doc["role"],
        "mission": {"id": mission["id"], "type": seat_doc["mission_type"], "authority_ref": AUTHORITY_REF,
                    "repo": REPO, "scope": {"read": ["."], "write": [] if row["read_only"] else ["."]}},
        "needs": sorted(offered & set(row["admit"])),
    }
    selection = S.select(request, matrix, registry)
    if selection.disposition != R.ADMITTED:
        raise BindingRefused(f"selection for {seat} is {selection.disposition}: {selection.reason}")
    problem = R.record_problem(selection.record)
    if problem:
        raise BindingRefused(f"selection record is inconsistent: {problem}")

    tools, allowed, mcp_tools, bound = _surface(selection, registry, matrix)
    if not set(bound) <= selection.surface:
        raise BindingRefused("the binding would grant a tool outside the admitted surface")
    missing = sorted(set(mcp_tools) - _gateway_tools(gateway_root))
    if missing:
        raise BindingRefused(f"admitted gateway tools {missing} are not served by the gateway")

    session = {
        "principal": seat_doc["principal"],
        "acting_identity": mission["agent"],
        "role": seat_doc["fabric_role"],
        "mission": {"id": mission["id"], "authority_ref": AUTHORITY_REF, "base_sha": mission["base_sha"],
                    "round": mission["round"]},
        "resources": list(seat_doc["resources"]),
        "issued_at": now,
        "expires_at": now + SESSION_TTL,
    }
    denied: list = []
    bound_doc = {"seat": seat, "runtime": runtime, "mission": mission, "tools": list(tools),
                 "allowed_rules": list(allowed), "denied_rules": list(denied), "mcp_tools": list(mcp_tools),
                 "tool_map": bound, "session": session}
    audit = audit_material(seat, runtime, seat_doc, seats, matrix, registry, request, selection, bound_doc)
    if links.link_problem(audit):
        raise BindingRefused(f"the binding's audit link is malformed: {links.link_problem(audit)}")
    return Binding(tools, allowed, denied, mcp_tools, session, audit)
