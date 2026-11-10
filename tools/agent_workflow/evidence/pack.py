"""The landing provenance (§3m item 2; Amendment 020, the EPAP landing part): for each mission that lands, a signed
in-toto attestation of what the evidence records show. Standard library only.

A landing is a ``router.landing`` record (the router's merge of an A3 PASS into a landing branch) that names its
mission. When the run holding it is sealed, the seal job writes one attestation for it:

- an in-toto Statement v1 (``https://in-toto.io/Statement/v1``) whose subject is the landed commit,
- with a SLSA Provenance v1 predicate (``https://slsa.dev/provenance/v1``) whose ``internalParameters.records``
  lists every sealed record of that mission, across all its runs (the plan's approval with HITL's account id, each
  A2 build and A3 review, each router decision and merge), each by id and digest,
- in a DSSE envelope (``application/vnd.in-toto+json``) signed with the evidence key.

The signer is the pipeline's attestor, the seal job, not the actors: the attestation says what the sealed records
show, not that each actor signed its step. That is SLSA's own model (the build platform signs the provenance). The
full EPAP pack (``epap.writer``: a HITL-signed layout and one link per step, each signed by its own functionary) needs
each actor to hold and use its own signing key, and is deferred to the identity work (§3m, "the EPAP landing part").

It is stored at ``packs/<landing record id>.provenance.json`` in the store and copied to the WORM bucket. The
checker verifies every attestation: the envelope's signature against the pinned keys, its form, and that every
record it cites is in the store as recorded, and that its subject is the landing's commit.
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional

from epap import ed25519
from epap.signing import is_hex
from evidence import EvidenceError
from evidence import record as rec_mod
from evidence import seal as seal_mod

PACKS = "packs"
SUFFIX = ".provenance.json"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
BUILD_TYPE = "urn:evidence:mission-landing:v1"
_ROLE = re.compile(r"\b(A[123]) round (\d+)\b")


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE's pre-authentication encoding: what a DSSE signature covers."""
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def landings(records: Iterable[Mapping]) -> List[Mapping]:
    return [r for r in records if r["action"] == "router.landing" and r["result"] == "done"
            and r["subject"]["mission"] and r["subject"]["commit"]]


def name_for(landing: Mapping) -> str:
    return f"{PACKS}/{landing['id'].replace('/', '-')}{SUFFIX}"


def _entry(rec: Mapping) -> dict:
    role = _ROLE.search(rec["authority"]["ref"]) if rec["action"].startswith("dispatch.") else None
    return {"record": rec["id"], "digest": rec_mod.digest(rec), "action": rec["action"], "result": rec["result"],
            "actor": dict(rec["actor"]), "role": role.group(1) if role else None,
            "round": rec["subject"]["round"], "pr": rec["subject"]["pr"], "commit": rec["subject"]["commit"],
            "time": rec["time"]}


def statement(landing: Mapping, mission_records: Iterable[Mapping], repository: str) -> dict:
    """The in-toto Statement for one landing. ``mission_records`` are the sealed records of its mission."""
    mission = landing["subject"]["mission"]
    records = sorted((r for r in mission_records if r["subject"]["mission"] == mission),
                     key=lambda r: (r["time"], r["id"]))
    if not any(r["id"] == landing["id"] for r in records):
        records.append(landing)
    commits = sorted({r["subject"]["commit"] for r in records if r["action"] == "router.merge"
                      and r["result"] == "done" and r["subject"]["commit"]})
    approvals = [r["id"] for r in records if r["action"] == "router.hitl_command"
                 and r["reason"].startswith("HITL command: /mission approve")]
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": f"git+https://github.com/{repository}", "digest": {"gitCommit": landing["subject"]["commit"]}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": BUILD_TYPE,
                "externalParameters": {"repository": repository, "mission": mission,
                                       "landing_pr": landing["subject"]["pr"], "approvals": approvals},
                "internalParameters": {"landing": landing["id"], "records": [_entry(r) for r in records]},
                "resolvedDependencies": [{"uri": f"git+https://github.com/{repository}@{c}", "digest": {"gitCommit": c}}
                                         for c in commits],
            },
            "runDetails": {
                "builder": {"id": f"https://github.com/{repository}/.github/workflows/evidence-seal.yml"},
                "metadata": {"invocationId": landing["id"], "finishedOn": landing["time"]},
            },
        },
    }


def sign(statement_doc: Mapping, seed: bytes) -> bytes:
    """The DSSE envelope, signed with the evidence key, as the stored bytes."""
    payload = json.dumps(statement_doc, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = ed25519.sign(seed, pae(PAYLOAD_TYPE, payload))
    envelope = {"payloadType": PAYLOAD_TYPE, "payload": base64.b64encode(payload).decode("ascii"),
                "signatures": [{"keyid": seal_mod.keyid(ed25519.public_key(seed)), "sig": base64.b64encode(sig).decode()}]}
    return (json.dumps(envelope, indent=2, sort_keys=True) + "\n").encode("utf-8")


def problems(data: bytes, keys: Mapping[str, str], index: Mapping[str, str], name: str = "") -> List[str]:
    """Why a stored attestation does not verify; empty when it does. ``index`` maps every stored record's id to its
    digest."""
    where = name or "attestation"
    try:
        env = json.loads(data)
        payload = base64.b64decode(env["payload"], validate=True)
        sigs = env["signatures"]
    except (ValueError, KeyError, TypeError):
        return [f"{where}: not a DSSE envelope"]
    if env.get("payloadType") != PAYLOAD_TYPE or not (isinstance(sigs, list) and len(sigs) == 1):
        return [f"{where}: a DSSE envelope of {PAYLOAD_TYPE} with exactly one signature"]
    kid = sigs[0].get("keyid")
    if kid not in keys:
        return [f"{where}: signed by {str(kid)[:16]}..., which is not a pinned evidence key"]
    try:
        sig = base64.b64decode(sigs[0]["sig"], validate=True)
    except (ValueError, KeyError, TypeError):
        return [f"{where}: a malformed signature"]
    if not ed25519.verify(bytes.fromhex(keys[kid]), pae(PAYLOAD_TYPE, payload), sig):
        return [f"{where}: the signature does not verify against the pinned evidence key"]
    try:
        st = json.loads(payload)
        landing = st["predicate"]["buildDefinition"]["internalParameters"]["landing"]
        cited = st["predicate"]["buildDefinition"]["internalParameters"]["records"]
        subject = st["subject"][0]["digest"]["gitCommit"]
    except (ValueError, KeyError, TypeError, IndexError):
        return [f"{where}: not an in-toto Statement of this form"]
    out = []
    if st.get("_type") != STATEMENT_TYPE or st.get("predicateType") != PREDICATE_TYPE:
        out.append(f"{where}: not an in-toto Statement v1 with SLSA Provenance v1")
    for entry in cited:
        rid, digest = entry.get("record"), entry.get("digest")
        if index.get(rid) != digest:
            out.append(f"{where}: cites {rid}, which is not in the store as recorded")
    landing_entry = next((e for e in cited if e.get("record") == landing), None)
    if landing_entry is None or landing_entry.get("action") != "router.landing" \
            or landing_entry.get("commit") != subject or not is_hex(subject, 40):
        out.append(f"{where}: its subject is not the landing's commit")
    return out


def store_problems(store: Path, keys: Mapping[str, str]) -> List[str]:
    """Every attestation in a clone of the store, against every record the store holds (the checker)."""
    from evidence import chain as chain_mod
    base = Path(store)
    index: Dict[str, str] = {}
    for path in sorted((base / "runs").glob(f"*/{chain_mod.RECORDS}")):
        try:
            for rec in chain_mod.read(path):
                index[rec["id"]] = rec_mod.digest(rec)
        except EvidenceError:
            continue  # the chain checks name a broken run
    out: List[str] = []
    for path in sorted((base / PACKS).glob(f"*{SUFFIX}")) if (base / PACKS).is_dir() else []:
        out += problems(path.read_bytes(), keys, index, path.relative_to(base).as_posix())
    return out
