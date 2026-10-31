"""The EPAP pipeline layout (spec section 2), as data the verifier enforces.

Five steps in a fixed order: A1_SPEC -> HITL_APPROVAL -> A2_BUILD -> A3_REVIEW
-> HITL_MERGE. Each step names its role and the kinds of principal that may act
in it. The model fixes roles and order, not the merging hand: the merge step
accepts HITL or the Mission Router, whichever the router's record shows acted.

A layout document instantiates the model for one mission: it declares the keys
of every principal and, per step, which of them are the step's functionaries.
HITL is the layout owner and signs it; the verifier is handed HITL's public key
out of band, so nobody else can rewrite the layout.

Key ids are the acting identity itself:

- agent App: the registry role (``a1``, ``a2``, ``a3``, ...)
- HITL: ``hitl:<login>``
- Mission Router: ``router:<login>``
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from epap.signing import is_hex

PIPELINE_ID = "EPAP-PIPELINE-v1"
SPEC_ID = "EPAP-EVIDENCE-SPEC-001"

AGENT_APP = "agent-app"
HITL = "hitl"
ROUTER = "router"
PRINCIPAL_KINDS = (AGENT_APP, HITL, ROUTER)

A1_SPEC = "A1_SPEC"
HITL_APPROVAL = "HITL_APPROVAL"
A2_BUILD = "A2_BUILD"
A3_REVIEW = "A3_REVIEW"
HITL_MERGE = "HITL_MERGE"


@dataclass(frozen=True)
class Step:
    name: str
    role: str
    # (principal kind, agent role or None for any principal of that kind)
    allowed: Tuple[Tuple[str, Optional[str]], ...]

    def admits(self, principal: Mapping[str, str]) -> bool:
        return any(principal.get("kind") == kind and (role is None or principal.get("role") == role)
                   for kind, role in self.allowed)


STEPS: Tuple[Step, ...] = (
    Step(A1_SPEC, "A1", ((AGENT_APP, "a1"), (HITL, None))),
    Step(HITL_APPROVAL, "HITL", ((HITL, None),)),
    Step(A2_BUILD, "A2", ((AGENT_APP, "a2"),)),
    Step(A3_REVIEW, "A3", ((AGENT_APP, "a3"),)),
    Step(HITL_MERGE, "HITL", ((HITL, None), (ROUTER, None))),
)
STEP_NAMES: Tuple[str, ...] = tuple(s.name for s in STEPS)

LAYOUT_FIELDS = frozenset({"_type", "pipeline", "spec", "mission_id", "owner", "keys", "steps"})
KEY_FIELDS = frozenset({"keytype", "scheme", "public", "principal"})
STEP_FIELDS = frozenset({"name", "role", "functionaries"})
PRINCIPAL_FIELDS = {
    AGENT_APP: frozenset({"kind", "role", "app_id"}),
    HITL: frozenset({"kind", "login"}),
    ROUTER: frozenset({"kind", "login"}),
}


def step(name: str) -> Step:
    for s in STEPS:
        if s.name == name:
            return s
    raise KeyError(name)


def agent_app(role: str, app_id: str) -> dict:
    return {"kind": AGENT_APP, "role": role, "app_id": str(app_id)}


def hitl(login: str) -> dict:
    return {"kind": HITL, "login": login}


def router(login: str) -> dict:
    return {"kind": ROUTER, "login": login}


def principal_problem(principal: object) -> Optional[str]:
    """Why ``principal`` is malformed, or None."""
    if not isinstance(principal, dict) or principal.get("kind") not in PRINCIPAL_KINDS:
        return "principal kind must be one of " + ", ".join(PRINCIPAL_KINDS)
    if set(principal) != PRINCIPAL_FIELDS[principal["kind"]]:
        return f"{principal['kind']} principal must have exactly {sorted(PRINCIPAL_FIELDS[principal['kind']])}"
    if not all(isinstance(v, str) and v for v in principal.values()):
        return "principal fields must be non-empty strings"
    return None


def keyid_for(principal: Mapping[str, str]) -> str:
    if principal["kind"] == AGENT_APP:
        return principal["role"]
    return f"{principal['kind']}:{principal['login']}"


def key_entry(principal: Mapping[str, str], public: bytes) -> dict:
    return {"keytype": "ed25519", "scheme": "ed25519", "public": bytes(public).hex(), "principal": dict(principal)}


def default_functionaries(keys: Mapping[str, Mapping]) -> Dict[str, List[str]]:
    """Every declared key the model admits, per step."""
    return {s.name: sorted(k for k, entry in keys.items() if s.admits(entry["principal"])) for s in STEPS}


def make_layout(mission_id: str, keys: Mapping[str, Mapping], owner: str,
                functionaries: Optional[Mapping[str, Sequence[str]]] = None) -> dict:
    """The ``signed`` part of a layout; sign it with the owner's (HITL's) key."""
    funcs = default_functionaries(keys) if functionaries is None else functionaries
    return {
        "_type": "layout",
        "pipeline": PIPELINE_ID,
        "spec": SPEC_ID,
        "mission_id": mission_id,
        "owner": owner,
        "keys": {k: dict(v) for k, v in keys.items()},
        "steps": [{"name": s.name, "role": s.role, "functionaries": list(funcs.get(s.name, ()))} for s in STEPS],
    }


def layout_problem(signed: Mapping) -> Optional[str]:
    """Why a layout does not conform to the pipeline model, or None.

    Assumes the caller has already checked the owner signature.
    """
    if set(signed) != LAYOUT_FIELDS:
        return f"layout must have exactly the fields {sorted(LAYOUT_FIELDS)}"
    if signed["_type"] != "layout" or signed["pipeline"] != PIPELINE_ID or signed["spec"] != SPEC_ID:
        return f"layout is not a {PIPELINE_ID} layout for {SPEC_ID}"
    if not isinstance(signed["mission_id"], str) or not signed["mission_id"]:
        return "layout has no mission_id"
    keys = signed["keys"]
    if not isinstance(keys, dict) or not keys:
        return "layout declares no keys"
    for keyid, entry in keys.items():
        if not isinstance(entry, dict) or set(entry) != KEY_FIELDS:
            return f"key {keyid!r} must have exactly {sorted(KEY_FIELDS)}"
        if entry["keytype"] != "ed25519" or entry["scheme"] != "ed25519":
            return f"key {keyid!r} is not ed25519"
        if not is_hex(entry["public"], 64):
            return f"key {keyid!r} public key is not 32 bytes of hex"
        problem = principal_problem(entry["principal"])
        if problem:
            return f"key {keyid!r}: {problem}"
        if keyid != keyid_for(entry["principal"]):
            return f"key id {keyid!r} does not name its principal ({keyid_for(entry['principal'])!r})"
    hitl_keys = [k for k, e in keys.items() if e["principal"]["kind"] == HITL]
    if hitl_keys != [signed["owner"]]:
        return "the layout owner must be the one and only HITL key"
    steps = signed["steps"]
    if not isinstance(steps, list) or [s.get("name") if isinstance(s, dict) else None for s in steps] != list(STEP_NAMES):
        return "layout steps must be exactly " + " -> ".join(STEP_NAMES)
    for model, entry in zip(STEPS, steps):
        if set(entry) != STEP_FIELDS or entry["role"] != model.role:
            return f"step {model.name} must have role {model.role} and exactly {sorted(STEP_FIELDS)}"
        funcs = entry["functionaries"]
        if not isinstance(funcs, list) or not funcs or len(set(funcs)) != len(funcs):
            return f"step {model.name} needs a non-empty list of distinct functionaries"
        for keyid in funcs:
            if keyid not in keys:
                return f"step {model.name} functionary {keyid!r} has no declared key"
            if not model.admits(keys[keyid]["principal"]):
                return f"step {model.name} cannot be performed by {keyid!r}"
    return None


def functionaries_of(signed: Mapping, name: str) -> Iterable[str]:
    for entry in signed["steps"]:
        if entry["name"] == name:
            return entry["functionaries"]
    return ()
