"""Canonical JSON and signed envelopes (in-toto metablocks).

Every signed document has the in-toto shape ``{"signed": {...}, "signatures":
[{"keyid": ..., "sig": ...}]}``. A signature covers the canonical bytes of
``signed``: JSON with sorted keys, no insignificant whitespace, UTF-8, no
floats. The on-disk formatting of a pack therefore never affects a signature.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from epap import ed25519


class CanonicalError(ValueError):
    pass


def _check(value: Any) -> None:
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        return
    if isinstance(value, list):
        for item in value:
            _check(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalError("object keys must be strings")
            _check(item)
        return
    raise CanonicalError(f"value of type {type(value).__name__} has no canonical form")


def canonical_bytes(value: Any) -> bytes:
    _check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def is_hex(value: object, length: int) -> bool:
    """Lowercase hex of exactly ``length`` characters."""
    return (isinstance(value, str) and len(value) == length
            and all(c in "0123456789abcdef" for c in value))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sign_metablock(signed: Mapping[str, Any], keyid: str, seed: bytes) -> dict:
    """Wrap ``signed`` in a metablock carrying one signature by ``keyid``."""
    sig = ed25519.sign(seed, canonical_bytes(signed))
    return {"signed": dict(signed), "signatures": [{"keyid": keyid, "sig": sig.hex()}]}


def signature_valid(public_hex: str, signed: Any, sig_hex: str) -> bool:
    try:
        public = bytes.fromhex(public_hex)
        sig = bytes.fromhex(sig_hex)
        message = canonical_bytes(signed)
    except (ValueError, TypeError):
        return False
    return ed25519.verify(public, message, sig)


def dump(doc: Any) -> bytes:
    """The bytes a pack file is written with."""
    _check(doc)
    return (json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
