"""The seal over a run's chain (§3m item 2), and the pinned evidence keys (``key.json``, SPEC-002 AUTHORITY).

A seal is an EPAP signed envelope (``epap.signing``, Ed25519): ``{"signed": {...}, "signatures": [{keyid, sig}]}``.
It covers the run, the chain's head digest, the record count, and the digests of the run's artifacts. A key id is the
SHA-256 of the public key's 32 bytes, in hex. ``key.json`` lists the public halves a seal may be checked against;
the private half is held in the ``evidence-seal`` environment and used by the seal job only.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, Mapping

from epap import ed25519
from epap.signing import is_hex, sign_metablock, signature_valid
from evidence import EvidenceError

SCHEMA = "evidence-seal-v1"
KEYS_SCHEMA = "evidence-keys-v1"
KEYS_FILE = Path(__file__).resolve().parent / "key.json"
SEAL = "seal.json"
SIGNED_FIELDS = frozenset({"schema", "run", "head", "count", "artifacts", "time"})
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./-]{0,127}")


def keyid(public: bytes) -> str:
    return hashlib.sha256(public).hexdigest()


def make(run: str, head: str, count: int, artifacts: Mapping[str, str], time: str, seed: bytes) -> Dict[str, Any]:
    """A seal signed with ``seed`` (the seal job's key)."""
    signed = {"schema": SCHEMA, "run": run, "head": head, "count": count, "artifacts": dict(artifacts), "time": time}
    return sign_metablock(signed, keyid(ed25519.public_key(seed)), seed)


def load_keys(path: Path = KEYS_FILE) -> Dict[str, str]:
    """The pinned public halves, by key id. Raises ``EvidenceError`` on a malformed pin."""
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise EvidenceError(f"{Path(path).name}: {exc}") from None
    if not (isinstance(doc, dict) and doc.get("schema") == KEYS_SCHEMA and isinstance(doc.get("keys"), list)):
        raise EvidenceError(f"{Path(path).name}: must be {{schema: {KEYS_SCHEMA}, keys: [...]}}")
    keys: Dict[str, str] = {}
    for entry in doc["keys"]:
        if not (isinstance(entry, dict) and is_hex(entry.get("public"), 64) and is_hex(entry.get("keyid"), 64)
                and keyid(bytes.fromhex(entry["public"])) == entry["keyid"]):
            raise EvidenceError(f"{Path(path).name}: each key needs a 64-hex public key and its key id")
        keys[entry["keyid"]] = entry["public"]
    return keys


def problems(seal: object, keys: Mapping[str, str]) -> list:
    """What makes ``seal`` not a valid seal under the pinned ``keys``; empty when it is one. Its fit to the chain is
    checked by ``verify``."""
    if not (isinstance(seal, dict) and set(seal) == {"signed", "signatures"} and isinstance(seal["signed"], dict)
            and isinstance(seal["signatures"], list)):
        return ["a seal must be {signed, signatures}"]
    signed = seal["signed"]
    if set(signed) != SIGNED_FIELDS or signed["schema"] != SCHEMA:
        return [f"a seal's signed part must be {SCHEMA} with exactly: {', '.join(sorted(SIGNED_FIELDS))}"]
    if not (is_hex(signed["head"], 64) and isinstance(signed["count"], int) and not isinstance(signed["count"], bool)
            and signed["count"] >= 0 and isinstance(signed["artifacts"], dict)
            and all(isinstance(k, str) and _NAME.fullmatch(k) and is_hex(v, 64)
                    for k, v in signed["artifacts"].items())):
        return ["a seal's head, count or artifacts are malformed"]
    sigs = seal["signatures"]
    if not (len(sigs) == 1 and isinstance(sigs[0], dict) and set(sigs[0]) == {"keyid", "sig"}):
        return ["a seal carries exactly one signature"]
    kid = sigs[0]["keyid"]
    if kid not in keys:
        return [f"the seal is signed by {str(kid)[:16]}..., which is not a pinned evidence key"]
    if not signature_valid(keys[kid], signed, sigs[0]["sig"]):
        return ["the seal's signature does not verify against the pinned evidence key"]
    return []
