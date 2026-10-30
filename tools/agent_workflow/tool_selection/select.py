"""Governed tool selection: the admitted tool surface for one role and mission.

``select(request, matrix, registry)`` checks its three inputs, then walks the
spec's fixed order::

    need_detection -> role_admission -> boundary_filtering -> mission_type_filtering
        -> evidence_class_filtering -> confidence_scoring -> fallback_routing -> fail_closed

Each filtering step first resolves what it needs for the whole selection (the
tool needs, the acting role, the mission boundary, the mission type) and stops
fail-closed when it cannot. It then denies, per candidate, only on resolved
facts: a candidate the step cannot decide passes on with an unresolved
confidence signal, so it can still be denied later but never admitted. On a
read-only row every mutation-class candidate is denied at role admission
under the row's separation rule, whatever the tool needs; narrowing the row's
surface to the needed capabilities comes after that.

Confidence is the spec's deterministic score over five signals (role
resolved; mission type resolved; resource in scope; registry entry present
with valid schema; evidence class resolved): resolved / 5. A candidate is
admitted only when every signal is resolved and the score meets the matrix's
admission threshold. Every other surviving candidate is routed to fallback,
which only ever removes candidates from the pre-fallback surface. The final
step re-checks every admitted tool against the matrix and the mission and
stops with an empty surface if anything is broader than authorized.

A request has exactly these fields::

    request_id  non-empty string
    role        the acting role: a matrix row (writer, reviewer, router)
    mission     {"id", "type", "authority_ref", "repo", "scope": {"read": [path, ...], "write": [path, ...]}}
    needs       [capability, ...]: the tool needs detected for the mission;
                [] when the mission is answerable from closed mission context

Scope paths are clean relative paths (``"."`` is the whole repo). Read- and
draft-class tools must fall under ``scope.read``; any other class, or a
candidate whose class is unknown, under ``scope.write``.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence, Tuple

from tool_selection import matrix as M
from tool_selection import records as R
from tool_selection import registry as REG

PRECHECKS = ("matrix", "registry", "request")
STEPS = ("need_detection", "role_admission", "boundary_filtering", "mission_type_filtering",
         "evidence_class_filtering", "confidence_scoring", "fallback_routing", "fail_closed")
FILTER_STEPS = STEPS[:5]

REQUEST_FIELDS = frozenset({"request_id", "role", "mission", "needs"})
MISSION_FIELDS = frozenset({"id", "type", "authority_ref", "repo", "scope"})
STOP_ROUTE = "HITL_GATE"


@dataclass(frozen=True)
class Selection:
    disposition: str
    surface: frozenset
    pre_fallback: frozenset
    failed_step: Optional[str]
    reason: str
    record: dict

    @property
    def stopped(self) -> bool:
        return self.disposition == R.STOP_AND_FAIL_CLOSED


class _Stop(Exception):
    def __init__(self, step: str, reason: str, route: str = STOP_ROUTE):
        super().__init__(reason)
        self.step, self.reason, self.route = step, reason, route


def fallback(pre_fallback: frozenset, unresolved: Mapping[str, Sequence[str]]) -> frozenset:
    """The surface after fallback routing: ``pre_fallback`` less every unresolved candidate.

    It is built by filtering ``pre_fallback`` itself, so it can only narrow.
    Fallback routes a candidate to a clarification packet or authority gate,
    never to broader tool access.
    """
    return frozenset(tool for tool in pre_fallback if tool not in unresolved)


def within(path: str, scope: str) -> bool:
    return scope == "." or path == scope or path.startswith(scope + "/")


class _Selection:
    def __init__(self, request: Any, matrix: Any, registry: Any,
                 matrix_problem: Optional[str], registry_problem: Optional[str]):
        self.request = request
        self.raw_matrix, self.raw_registry = matrix, registry
        self.matrix_problem, self.registry_problem = matrix_problem, registry_problem
        self.matrix: Optional[dict] = None
        self.registry: Optional[dict] = None
        self.duplicates: frozenset = frozenset()
        self.mission_id: Optional[str] = None
        self.needs: Optional[list] = None
        self.role: Optional[str] = None
        self.mission: Optional[dict] = None
        self.mission_type: Optional[str] = None
        self.entries: dict = {}
        self.candidates: list = []
        self.pre: frozenset = frozenset()
        self.surface: frozenset = frozenset()
        self.fallbacks: list = []
        self.step = PRECHECKS[0]

    def run(self) -> Selection:
        try:
            for step in PRECHECKS + FILTER_STEPS[:4]:
                self.step = step
                getattr(self, "_" + step)()
            self._candidates()
        except _Stop as stop:
            return self._stop(stop.step, stop.reason, stop.route)
        except Exception as exc:  # fail closed on any defect in the selector itself
            return self._stop(self.step, f"selection error: {type(exc).__name__}", STOP_ROUTE)
        if not self.needs:
            return self._finish(R.NO_TOOL_REQUIRED, None, "no tool need: answerable from closed mission context", None)
        if self.fallbacks:
            return self._finish(R.BOUNDED_CLARIFICATION, None,
                                f"{len(self.fallbacks)} candidate(s) routed to fallback; surface narrowed, not widened",
                                None)
        return self._finish(R.ADMITTED, None, f"{len(self.surface)} tool(s) admitted, every signal resolved", None)

    # -- prechecks ------------------------------------------------------

    def _matrix(self) -> None:
        if self.matrix_problem:
            raise _Stop("matrix", self.matrix_problem)
        if self.raw_matrix is None:
            raise _Stop("matrix", "tool-surface matrix unavailable")
        try:
            self.matrix = M.validate(self.raw_matrix)
        except M.MatrixError as exc:
            raise _Stop("matrix", f"tool-surface matrix malformed: {exc}") from None

    def _registry(self) -> None:
        if self.registry_problem:
            raise _Stop("registry", self.registry_problem)
        try:
            self.registry = REG.validate(self.raw_registry)
        except REG.RegistryError as exc:
            raise _Stop("registry", f"candidate registry malformed: {exc}") from None
        self.duplicates = REG.duplicate_names(self.registry["tools"])

    def _request(self) -> None:
        if not isinstance(self.request, dict):
            raise _Stop("request", "request is not an object")
        unknown = sorted(set(self.request) - REQUEST_FIELDS, key=str)
        if unknown:
            raise _Stop("request", f"request carries unknown fields {unknown}")
        if not M.is_name(self.request.get("request_id")):
            raise _Stop("request", "request_id is missing")
        mission = self.request.get("mission")
        if not isinstance(mission, dict) or set(mission) != MISSION_FIELDS \
                or not M.is_name(mission["id"]) or not M.is_name(mission["authority_ref"]):
            raise _Stop("request", "SOT mission authority is missing")
        self.mission_id = mission["id"]

    # -- selection-level resolution, in the fixed order -----------------

    def _need_detection(self) -> None:
        needs = self.request.get("needs")
        catalog = self.matrix["capabilities"]
        if not isinstance(needs, list) or not all(isinstance(n, str) and n in catalog for n in needs) \
                or len(set(needs)) != len(needs):
            raise _Stop("need_detection", "tool needs are missing or name capabilities outside the catalog")
        self.needs = list(needs)

    def _role_admission(self) -> None:
        role = self.request.get("role")
        if not isinstance(role, str) or role not in self.matrix["roles"]:
            raise _Stop("role_admission", "acting role cannot be resolved",
                        self.matrix["fallback_routes"]["role_resolved"])
        self.role = role

    def _boundary_filtering(self) -> None:
        mission = self.request["mission"]
        scope = mission["scope"]
        if not M.is_name(mission["repo"]) or not isinstance(scope, dict) or set(scope) != {"read", "write"} \
                or not all(isinstance(scope[k], list) and all(REG.clean_path(p) for p in scope[k])
                           for k in ("read", "write")):
            raise _Stop("boundary_filtering", "mission repo/path boundary cannot be resolved")
        self.mission = mission

    def _mission_type_filtering(self) -> None:
        mtype = self.mission["type"]
        if not isinstance(mtype, str) or mtype not in self.matrix["mission_types"]:
            raise _Stop("mission_type_filtering", "mission type cannot be resolved",
                        self.matrix["fallback_routes"]["mission_type_resolved"])
        self.mission_type = mtype

    # -- per-candidate --------------------------------------------------

    def _id(self, index: int, entry: Any) -> str:
        name = REG.tool_name(entry)
        return name if name is not None and name not in self.duplicates else f"#{index}"

    def _classes(self, entry: Any) -> Tuple[Optional[str], Optional[str], frozenset]:
        """(capability, declared class, every class the candidate may be: catalog and declared)."""
        catalog = self.matrix["capabilities"]
        cap = REG.capability(entry, catalog)
        declared = REG.declared_class(entry)
        return cap, declared, frozenset(c for c in (catalog[cap] if cap else None, declared) if c)

    def _scope_kind(self, cap: Optional[str], classes: frozenset) -> str:
        if cap is None or not classes or classes - {"read", "draft"}:
            return "write"
        return "read"

    def _in_scope(self, entry: Any) -> Optional[bool]:
        """True or False once the resource and mission boundary resolve; None while either does not."""
        res = REG.resource(entry)
        if res is None or self.mission is None or self.matrix is None:
            return None
        if res["repo"] != self.mission["repo"]:
            return False
        cap, _, classes = self._classes(entry)
        return any(within(res["path"], p) for p in self.mission["scope"][self._scope_kind(cap, classes)])

    def _signals(self, entry: Any) -> dict:
        catalog = self.matrix["capabilities"]
        cap, declared, _ = self._classes(entry)
        return {
            "role_resolved": self.role is not None,
            "mission_type_resolved": self.mission_type is not None,
            "resource_in_scope": self._in_scope(entry) is True,
            "registry_entry_valid": REG.entry_problem(entry, catalog, self.duplicates) is None,
            "evidence_class_resolved": cap is not None and declared == catalog[cap],
        }

    def _filters(self, entry: Any) -> Optional[Tuple[str, str, str]]:
        """The first (step, rule, reason) that denies the candidate on resolved facts, or None."""
        row = self.matrix["roles"][self.role]
        cap, _, classes = self._classes(entry)
        name = repr(cap) if cap else "candidate"

        # The separation rule comes first: whatever the needs say, a read-only row
        # denies every mutation-class candidate by name of its rule.
        mutating = sorted(classes & set(M.MUTATION_CLASSES))
        if row["read_only"] and mutating:
            rule = row["separation_rule"]
            return ("role_admission", rule,
                    f"{name} is {'/'.join(mutating)}-class and the {self.role} row is read-only ({rule})")
        if not self.needs:
            return "need_detection", "NO_TOOL_NEED", "no tool need: answerable from closed mission context"
        if cap in row["blocked"]:
            return "role_admission", "ROLE_BLOCKED", row["blocked"][cap]
        if cap is not None and cap not in row["admit"]:
            return "role_admission", "ROLE_NOT_ADMITTED", f"{cap!r} is not on the {self.role} row's admitted surface"
        # Per-capability narrowing: the row's surface less what the mission does not need.
        if cap is not None and cap not in self.needs:
            return "role_admission", "NOT_NEEDED", f"capability {cap!r} is not among the mission's tool needs"

        res = REG.resource(entry)
        if res is not None:
            if res["repo"] != self.mission["repo"]:
                return ("boundary_filtering", "REPO_BOUNDARY",
                        f"resource repo {res['repo']!r} is outside the mission repo {self.mission['repo']!r}")
            kind = self._scope_kind(cap, classes)
            if not any(within(res["path"], p) for p in self.mission["scope"][kind]):
                return "boundary_filtering", "PATH_BOUNDARY", f"path {res['path']!r} is outside the mission's {kind} scope"

        outside = sorted(classes - set(self.matrix["mission_types"][self.mission_type]))
        if outside:
            return ("mission_type_filtering", "MISSION_TYPE",
                    f"{'/'.join(outside)}-class tools are not admissible in a {self.mission_type} mission")

        outside = sorted(classes - set(row["evidence_classes"]))
        if outside:
            return ("evidence_class_filtering", "EVIDENCE_CLASS",
                    f"{'/'.join(outside)}-class is not among the {self.role} row's evidence classes")
        return None

    def _assure(self, entry: Any) -> Optional[str]:
        """Independent re-check of one admitted tool: why it is broader than authorized, or None."""
        row = self.matrix["roles"][self.role]
        catalog = self.matrix["capabilities"]
        cap = REG.capability(entry, catalog)
        if cap is None or cap not in row["admit"] or cap not in self.needs:
            return "capability is not an admitted, needed capability of the role"
        cls = catalog[cap]
        if row["read_only"] and cls in M.MUTATION_CLASSES:
            return f"mutation-class tool on a read-only row ({row['separation_rule']})"
        if cls not in row["evidence_classes"] or cls not in self.matrix["mission_types"][self.mission_type]:
            return f"{cls}-class is not admissible for this role and mission type"
        if REG.declared_class(entry) != cls or REG.entry_problem(entry, catalog, self.duplicates) is not None:
            return "registry entry is unresolved"
        if self._in_scope(entry) is not True:
            return "resource is outside the mission boundary"
        return None

    def _candidate(self, index: int, entry: Any) -> dict:
        signals = self._signals(entry)
        cap, declared, _ = self._classes(entry)
        return {"tool": self._id(index, entry), "capability": cap, "evidence_class": declared,
                "outcome": None, "step": None, "reason": None, "rule": None, "signals": signals,
                "score": f"{sum(signals.values())}/{len(M.SIGNALS)}", "route": None}

    def _candidates(self) -> None:
        self.step = FILTER_STEPS[0]
        for index, entry in enumerate(self.registry["tools"]):
            cand = self._candidate(index, entry)
            self.entries[cand["tool"]] = entry
            denied = self._filters(entry)
            if denied:
                step, rule, reason = denied
                cand.update(outcome=R.DENY, step=step, rule=rule, reason=reason)
            self.candidates.append(cand)
        self.pre = frozenset(c["tool"] for c in self.candidates if c["outcome"] is None)

        self.step = "confidence_scoring"
        threshold = M.threshold(self.matrix["admission_threshold"])
        unresolved = {}
        for cand in self.candidates:
            if cand["outcome"] is None:
                missing = [s for s in M.SIGNALS if not cand["signals"][s]]
                if missing or Fraction(len(M.SIGNALS) - len(missing), len(M.SIGNALS)) < threshold:
                    unresolved[cand["tool"]] = missing

        self.step = "fallback_routing"
        self.surface = fallback(self.pre, unresolved)
        routes = self.matrix["fallback_routes"]
        limit = self.matrix["admission_threshold"]
        for cand in self.candidates:
            if cand["outcome"] is not None:
                continue
            if cand["tool"] in self.surface:
                cand.update(outcome=R.ADMIT, step="confidence_scoring", rule=None,
                            reason=f"every signal resolved; confidence {cand['score']} meets threshold {limit}")
                continue
            missing = unresolved.get(cand["tool"], [])
            route = routes[missing[0]] if missing else "BOUNDED_CLARIFICATION"
            cand.update(outcome=R.FALLBACK, step="fallback_routing", rule="LOW_CONFIDENCE", route=route,
                        reason=f"confidence {cand['score']} below threshold {limit}; unresolved {missing}; "
                               f"routed to {route}, surface not widened")
            self.fallbacks.append({"tool": cand["tool"], "route": route, "unresolved": missing})

        self.step = "fail_closed"
        if not self.surface <= self.pre:
            raise _Stop("fail_closed", "fallback routing would widen the surface beyond the pre-fallback set")
        for tool in sorted(self.surface):
            problem = self._assure(self.entries[tool])
            if problem:
                raise _Stop("fail_closed", f"selector would expose {tool!r} beyond what the mission authorizes: {problem}")

    # -- outcome --------------------------------------------------------

    def _stop(self, step: str, reason: str, route: str) -> Selection:
        self.surface = frozenset()
        self.fallbacks = []
        candidates = []
        if self.matrix is not None and self.registry is not None:
            try:
                for index, entry in enumerate(self.registry["tools"]):
                    cand = self._candidate(index, entry)
                    cand.update(outcome=R.DENY, step=step, rule="STOP_AND_FAIL_CLOSED",
                                reason=f"selection stopped: {reason}")
                    candidates.append(cand)
            except Exception:  # the record still says STOP; it just lists no candidates
                candidates = []
        self.candidates = candidates
        return self._finish(R.STOP_AND_FAIL_CLOSED, step, reason, route)

    def _finish(self, disposition: str, step: Optional[str], reason: str, route: Optional[str]) -> Selection:
        request_id = self.request.get("request_id") if isinstance(self.request, dict) else None
        admitted_caps = {c["capability"] for c in self.candidates if c["outcome"] == R.ADMIT}
        needs = list(self.needs or [])
        record = R.make_record(
            request_id=request_id if M.is_name(request_id) else None,
            request_digest=R.digest(self.request),
            role=self.role,
            mission_type=self.mission_type,
            mission_id=self.mission_id,
            matrix_version=self.matrix["matrix_version"] if self.matrix else None,
            matrix_digest=R.digest(self.matrix) if self.matrix else None,
            threshold=self.matrix["admission_threshold"] if self.matrix else None,
            registry_version=self.registry["registry_version"] if self.registry else None,
            registry_digest=R.digest(self.registry) if self.registry else None,
            disposition=disposition,
            failed_step=step,
            reason=reason,
            route=route,
            needs=needs,
            unmet_needs=[n for n in needs if n not in admitted_caps],
            candidates=self.candidates,
            pre_fallback_surface=sorted(self.pre),
            admitted_surface=sorted(self.surface),
            fallbacks=self.fallbacks,
        )
        return Selection(disposition, frozenset(self.surface), frozenset(self.pre), step, reason, record)


def select(request: Any, matrix: Optional[Mapping], registry: Any) -> Selection:
    """The admitted tool surface for ``request`` under ``matrix`` (None when unavailable) from ``registry``."""
    return _Selection(request, matrix, registry, None, None).run()


def select_files(request: Any, registry_path: Path, matrix_path: Path = M.DEFAULT_PATH) -> Selection:
    """``select`` with the registry and matrix read from files (default matrix: the shipped one)."""
    matrix = registry = None
    matrix_problem = registry_problem = None
    try:
        matrix = M.load_file(matrix_path)
    except M.MatrixError as exc:
        matrix_problem = f"tool-surface matrix unavailable or malformed: {exc}"
    try:
        registry = REG.load_file(registry_path)
    except REG.RegistryError as exc:
        registry_problem = f"candidate registry unavailable or malformed: {exc}"
    return _Selection(request, matrix, registry, matrix_problem, registry_problem).run()
