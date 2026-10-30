"""Authorization decision point for MCP-mediated RAG/EPAP actions.

``evaluate(request, policy, now)`` checks the policy and the request envelope,
then walks the spec's fixed order and stops at the first failure::

    identity -> role_class -> authority -> scope -> action_grant -> evidence -> stop_conditions

It returns ALLOW with a decision record, or DENY naming the failed step and,
where one applies, the doctrine section 9 stop condition. Fail-closed is the
only unresolved outcome: an unexpected error is a DENY too, and a denied
write or execute is never answered with a read.

A request has exactly these fields (a missing one fails the step that reads it)::

    request_id       non-empty string
    principal        {"id", "kind"}
    acting_identity  string bound to the principal and the session
    session          {"id", "principal", "acting_identity", "mission", "issued_at", "expires_at"}
    role             governed role the principal acts under
    mission          {"id", "authority_ref"}: the mission and the SOT reference it cites
    resource         {"class": "rag" | "epap", "id"}
    action           action name from the policy's catalog
    connector        {"id", "capabilities": [action, ...], "credential_bearing": bool}
    evidence         {"can_produce": [obligation, ...]}
    implicates       [runtime_bridge | trading_system | production_system | external_exposure, ...]

``now`` is integer seconds since the epoch, supplied by the caller, so the
same inputs always give the same record.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional

from mcp_auth import policy as P
from mcp_auth import records

ALLOW = "ALLOW"
DENY = "DENY"

STEPS = ("policy", "request", "identity", "role_class", "authority", "scope",
         "action_grant", "evidence", "stop_conditions")

STOP_CONDITIONS = {
    1: "MCP connector exposes broader capability than authorized",
    2: "Agent principal cannot be identified",
    3: "Mission authority cannot be resolved to SOT",
    4: "Requested tool/resource is outside mission scope",
    5: "MCP action would cross from read-only to write/execute without explicit authority",
    6: "EPAP artifact write/update lacks authorization",
    7: "RAG corpus includes restricted or credential-bearing material outside scope",
    8: "Credential-bearing tool access is requested without separate approval",
    9: "Runtime bridge, trading system, production system, or external exposure is implicated "
       "without explicit authorization",
    10: "Evidence obligation cannot be satisfied",
    11: "Policy result is ambiguous",
    12: "Authorization service is unavailable",
    13: "Session context cannot be validated",
}

# The stop conditions each step rules out once it passes.
STEP_CLEARS = {
    "policy": (12,),
    "request": (),
    "identity": (2, 13),
    "role_class": (),
    "authority": (3,),
    "scope": (4,),
    "action_grant": (5, 6, 11),
    "evidence": (10,),
    "stop_conditions": (1, 7, 8, 9),
}

REQUEST_FIELDS = frozenset({"request_id", "principal", "acting_identity", "session", "role", "mission",
                            "resource", "action", "connector", "evidence", "implicates"})
SESSION_FIELDS = frozenset({"id", "principal", "acting_identity", "mission", "issued_at", "expires_at"})
MAX_EPOCH = 253402300799  # 9999-12-31T23:59:59Z


@dataclass(frozen=True)
class Decision:
    disposition: str
    step: Optional[str]
    stop_condition: Optional[int]
    reason: str
    record: dict

    @property
    def allowed(self) -> bool:
        return self.disposition == ALLOW


class _Deny(Exception):
    def __init__(self, step: str, stop: Optional[int], reason: str):
        super().__init__(reason)
        self.step, self.stop, self.reason = step, stop, reason


def _fields(value: Any, fields: frozenset) -> Optional[dict]:
    return value if isinstance(value, dict) and set(value) == fields else None


def _name_list(value: Any) -> Optional[list]:
    if isinstance(value, list) and all(P.is_name(v) for v in value) and len(set(value)) == len(value):
        return value
    return None


class _Evaluation:
    def __init__(self, request: Any, policy: Any, now: Any, policy_problem: Optional[str]):
        self.request = request
        self.raw_policy = policy
        self.now = now
        self.policy_problem = policy_problem
        self.policy: Optional[dict] = None
        self.grant: Optional[dict] = None
        self.answers = records.blank_answers()
        self.step = STEPS[0]
        self.cleared: list = []

    # -- helpers --------------------------------------------------------

    def deny(self, stop: Optional[int], reason: str) -> None:
        raise _Deny(self.step, stop, reason)

    def get(self, field: str) -> Any:
        return self.request.get(field)

    def run(self) -> Decision:
        try:
            for step in STEPS:
                self.step = step
                getattr(self, "_" + step)()
                self.cleared.extend(STEP_CLEARS[step])
        except _Deny as deny:
            return self._finish(DENY, deny.step, deny.stop, deny.reason)
        except Exception as exc:  # fail closed on any defect in the engine itself
            return self._finish(DENY, self.step, 12, f"evaluation error: {type(exc).__name__}")
        return self._finish(ALLOW, None, None, "every step resolved")

    def _finish(self, disposition: str, step: Optional[str], stop: Optional[int], reason: str) -> Decision:
        cleared = sorted(c for c in self.cleared if c != stop)
        self.answers["stop_conditions"] = {"cleared": cleared, "triggered": stop}
        request_id = None
        if isinstance(self.request, dict) and P.is_name(self.request.get("request_id")):
            request_id = self.request["request_id"]
        record = records.make_record(
            request_id=request_id,
            request_digest=records.digest(self.request),
            policy_version=self.policy["policy_version"] if self.policy else None,
            policy_digest=records.digest(self.policy) if self.policy else None,
            timestamp=_timestamp(self.now),
            disposition=disposition,
            failed_step=step,
            stop_condition={"number": stop, "text": STOP_CONDITIONS[stop]} if stop else None,
            reason=reason,
            answers=self.answers,
        )
        return Decision(disposition, step, stop, reason, record)

    # -- prechecks ------------------------------------------------------

    def _policy(self) -> None:
        if self.policy_problem:
            self.deny(12, self.policy_problem)
        if self.raw_policy is None:
            self.deny(12, "authorization data unavailable")
        try:
            self.policy = P.validate(self.raw_policy)
        except P.PolicyError as exc:
            self.deny(12, f"authorization data malformed: {exc}")

    def _request(self) -> None:
        if not isinstance(self.request, dict):
            self.deny(13, "request is not an object")
        unknown = sorted(set(self.request) - REQUEST_FIELDS, key=str)
        if unknown:
            self.deny(13, f"request carries unknown fields {unknown}")
        if not P.is_name(self.get("request_id")):
            self.deny(13, "request_id is missing")
        if _timestamp(self.now) is None:
            self.deny(13, "evaluation time is not integer epoch seconds")

    # -- the fixed order ------------------------------------------------

    def _identity(self) -> None:
        principal = _fields(self.get("principal"), frozenset({"id", "kind"}))
        if principal is None or not P.is_name(principal["id"]):
            self.deny(2, "principal is not identified")
        entry = self.policy["principals"].get(principal["id"])
        if entry is None:
            self.deny(2, f"principal {principal['id']!r} is not known to policy")
        if principal["kind"] != entry["kind"]:
            self.deny(2, f"principal {principal['id']!r} is not a {principal['kind']!r} identity")
        self.answers["principal"] = {"id": principal["id"], "kind": entry["kind"]}
        acting = self.get("acting_identity")
        if not P.is_name(acting) or acting not in entry["acting_identities"]:
            self.deny(2, "acting identity is not bound to the principal")
        self.answers["acting_identity"] = acting

        session = _fields(self.get("session"), SESSION_FIELDS)
        if session is None or not P.is_name(session["id"]):
            self.deny(13, "session context is missing or malformed")
        if session["principal"] != principal["id"] or session["acting_identity"] != acting:
            self.deny(13, "session is bound to a different identity")
        mission = self.get("mission")
        mission_id = mission.get("id") if isinstance(mission, dict) else None
        if not P.is_name(session["mission"]) or session["mission"] != mission_id:
            self.deny(13, "session is not bound to the requested mission")
        issued, expires = session["issued_at"], session["expires_at"]
        if not (P.is_int(issued) and P.is_int(expires)):
            self.deny(13, "session time bounds are not integer epoch seconds")
        if expires - issued > self.policy["session"]["max_ttl_seconds"]:
            self.deny(13, "session lifetime exceeds the policy maximum")
        if not issued <= self.now < expires:
            self.deny(13, "session is outside its time bounds")

    def _role_class(self) -> None:
        role = self.get("role")
        if not P.is_name(role) or role not in self.policy["roles"]:
            self.deny(None, "role is not a governed role")
        if role not in self.policy["principals"][self.answers["principal"]["id"]]["roles"]:
            self.deny(None, f"principal does not hold role {role!r}")
        resource = _fields(self.get("resource"), frozenset({"class", "id"}))
        if resource is None or resource["class"] not in P.CLASSES:
            self.deny(None, "resource class is not a governed class")
        self.answers["role_class"] = {"role": role, "class": resource["class"]}

    def _authority(self) -> None:
        mission = _fields(self.get("mission"), frozenset({"id", "authority_ref"}))
        if mission is None or not P.is_name(mission["id"]) or not P.is_name(mission["authority_ref"]):
            self.deny(3, "mission authority is not stated")
        entry = self.policy["missions"].get(mission["id"])
        if entry is None:
            self.deny(3, f"mission {mission['id']!r} is not known to policy")
        if mission["authority_ref"] != entry["authority_ref"]:
            self.deny(3, f"request cites {mission['authority_ref']!r}; mission rests on {entry['authority_ref']!r}")
        ref = self.policy["authority_refs"][entry["authority_ref"]]
        if mission["id"] not in ref["missions"]:
            self.deny(3, f"{entry['authority_ref']!r} does not cover mission {mission['id']!r}")
        self.answers["sot_authority"] = {"mission": _ref(entry["authority_ref"], ref), "grant": None}

    def _scope(self) -> None:
        mission_id = self.get("mission")["id"]
        cls = self.answers["role_class"]["class"]
        rid = self.get("resource")["id"]
        entry = self.policy["resources"].get(rid) if P.is_name(rid) else None
        if entry is None:
            self.deny(4, "resource is not known to policy")
        if entry["class"] != cls:
            self.deny(4, f"resource {rid!r} is not in class {cls!r}")
        if rid not in self.policy["missions"][mission_id]["resources"]:
            self.deny(4, f"resource {rid!r} is outside mission {mission_id!r} scope")
        self.answers["scope"] = {"mission": mission_id, "class": cls, "resource": rid}

    def _matching_grants(self, action: Optional[str] = None) -> list:
        scope = self.answers["scope"]
        role = self.answers["role_class"]["role"]
        refs = self.policy["authority_refs"]
        return [g for g in self.policy["grants"]
                if g["role"] == role and g["class"] == scope["class"] and scope["resource"] in g["resources"]
                and (action is None or action in g["actions"])
                and scope["mission"] in refs[g["authority_ref"]]["missions"]]

    def _action_grant(self) -> None:
        action = self.get("action")
        entry = self.policy["actions"].get(action) if P.is_name(action) else None
        if entry is None:
            self.deny(11, "action is not in the policy's action catalog")
        cls = self.answers["scope"]["class"]
        self.answers["action"] = {"name": action, "kind": entry["kind"]}

        matching = self._matching_grants(action)
        outcomes = {(g["effect"], g["authority_ref"], g["evidence"]) for g in matching}
        if len(outcomes) > 1:
            ids = sorted(g["id"] for g in matching)
            self.deny(11, f"conflicting grants {ids}")
        allowing = sorted((g for g in matching if g["effect"] == "allow"), key=lambda g: g["id"])
        if not allowing:
            why = f"denied by grant {sorted(g['id'] for g in matching)}" if matching else "no SOT-scoped grant"
            if action in self.policy["classes"][cls]["mutation"]:
                self.deny(6, f"{action!r}: {why}")
            if entry["kind"] != "read":
                self.deny(5, f"{action!r} is a {entry['kind']} action: {why}; no read is substituted")
            self.deny(None, f"{action!r}: {why}")
        grant = allowing[0]
        ref = self.policy["authority_refs"][grant["authority_ref"]]
        self.answers["sot_authority"]["grant"] = {"id": grant["id"], **_ref(grant["authority_ref"], ref)}
        self.grant = grant

    def _evidence(self) -> None:
        obligation = self.grant["evidence"]
        self.answers["evidence"] = obligation
        evidence = _fields(self.get("evidence"), frozenset({"can_produce"}))
        can_produce = _name_list(evidence["can_produce"]) if evidence else None
        if can_produce is None:
            self.deny(10, "evidence capability is not stated")
        if obligation != "none" and obligation not in can_produce:
            self.deny(10, f"obligation {obligation!r} cannot be satisfied")

    def _stop_conditions(self) -> None:
        connector = _fields(self.get("connector"), frozenset({"id", "capabilities", "credential_bearing"}))
        capabilities = _name_list(connector["capabilities"]) if connector else None
        if capabilities is None or not P.is_name(connector["id"]):
            self.deny(1, "connector capability surface is not stated")
        authorized = {a for g in self._matching_grants() if g["effect"] == "allow" for a in g["actions"]}
        broader = sorted(set(capabilities) - authorized)
        if broader:
            self.deny(1, f"connector {connector['id']!r} also exposes {broader}")

        scope = self.answers["scope"]
        mission = self.policy["missions"][scope["mission"]]
        resource = self.policy["resources"][scope["resource"]]
        if (resource["restricted"] or resource["credential_bearing"]) \
                and scope["resource"] not in mission["approvals"]["restricted"]:
            self.deny(7, f"resource {scope['resource']!r} is restricted or credential-bearing and not approved")

        if not isinstance(connector["credential_bearing"], bool):
            self.deny(8, "connector credential class is not stated")
        if connector["credential_bearing"] and connector["id"] not in mission["approvals"]["credential"]:
            self.deny(8, f"connector {connector['id']!r} is credential-bearing and not separately approved")

        implicates = _name_list(self.get("implicates"))
        if implicates is None or any(i not in P.IMPLICATIONS for i in implicates):
            self.deny(9, "runtime implications are not stated in the known vocabulary")
        unapproved = sorted(i for i in implicates if i not in mission["approvals"]["runtime"])
        if unapproved:
            self.deny(9, f"implicates {unapproved} without explicit authorization")


def _ref(name: str, entry: Mapping) -> dict:
    return {"ref": name, "kind": entry["kind"], "source": entry["source"]}


def _timestamp(now: Any) -> Optional[str]:
    if not P.is_int(now) or not 0 <= now <= MAX_EPOCH:
        return None
    return datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def evaluate(request: Any, policy: Optional[Mapping], now: int) -> Decision:
    """Decide ``request`` against ``policy`` (a policy document, or None when unavailable)."""
    return _Evaluation(request, policy, now, None).run()


def evaluate_file(request: Any, now: int, path: Path = P.DEFAULT_PATH) -> Decision:
    """Decide ``request`` against the policy file at ``path`` (default: the shipped policy)."""
    try:
        policy = P.load_file(path)
    except P.PolicyError as exc:
        return _Evaluation(request, None, now, f"authorization data unavailable or malformed: {exc}").run()
    return evaluate(request, policy, now)
