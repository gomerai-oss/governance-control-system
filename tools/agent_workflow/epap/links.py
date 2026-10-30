"""in-toto v1 link records (spec section 3).

A link records one step: ``_type``, ``name``, ``materials`` (artifacts the step
started from), ``products`` (artifacts it left), ``byproducts``, ``command``,
and, in the enclosing metablock, ``signatures`` whose key id is the identity
that acted. Artifacts map a repository path to ``{"sha256": <hex>}``.

Products are the whole artifact set after the step, not only what the step
added, so each step's materials equal the previous step's products.

The A3_REVIEW link carries the review's test vectors in its byproducts::

    {"verdict": "PASS" | "FAIL",
     "vectors": [{"id": ..., "expected": ..., "observed": ..., "result": "pass" | "fail"}]}
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence

from epap.signing import is_hex, sha256_hex

LINK_FIELDS = frozenset({"_type", "name", "materials", "products", "byproducts", "command"})
VECTOR_FIELDS = frozenset({"id", "expected", "observed", "result"})
VERDICTS = ("PASS", "FAIL")
RESULTS = ("pass", "fail")


def digest_bytes(artifacts: Mapping[str, bytes]) -> dict:
    """``{path: {"sha256": hex}}`` for in-memory artifacts."""
    return {path: {"sha256": sha256_hex(data)} for path, data in artifacts.items()}


def digest_files(root: Path, paths: Iterable[str]) -> dict:
    """``{path: {"sha256": hex}}`` for files under ``root``, keyed by POSIX relative path."""
    root = Path(root)
    out = {}
    for rel in paths:
        target = root / rel
        if target.is_symlink() or not target.is_file():
            raise ValueError(f"{rel}: not a regular file")
        out[Path(rel).as_posix()] = {"sha256": sha256_hex(target.read_bytes())}
    return out


def vector(vector_id: str, expected: Any, observed: Any) -> dict:
    """One recorded A3 test vector; its result follows from expected vs observed."""
    return {"id": vector_id, "expected": expected, "observed": observed,
            "result": "pass" if observed == expected else "fail"}


def review_byproducts(vectors: Sequence[Mapping], verdict: Optional[str] = None) -> dict:
    """A3 byproducts; the verdict defaults to PASS exactly when every vector passed."""
    if verdict is None:
        verdict = "PASS" if vectors and all(v["result"] == "pass" for v in vectors) else "FAIL"
    return {"verdict": verdict, "vectors": [dict(v) for v in vectors]}


def make_link(name: str, materials: Mapping, products: Mapping, command: Sequence[str],
              byproducts: Optional[Mapping] = None) -> dict:
    """The ``signed`` part of a link; wrap it with ``signing.sign_metablock``."""
    return {
        "_type": "link",
        "name": name,
        "materials": {k: dict(v) for k, v in materials.items()},
        "products": {k: dict(v) for k, v in products.items()},
        "byproducts": dict(byproducts or {}),
        "command": list(command),
    }


def artifacts_problem(value: object) -> Optional[str]:
    if not isinstance(value, dict):
        return "must be an object"
    for path, digest in value.items():
        if not path or path.startswith("/") or "\\" in path or any(p in ("", ".", "..") for p in path.split("/")):
            return f"path {path!r} is not a clean relative path"
        if not isinstance(digest, dict) or set(digest) != {"sha256"} or not is_hex(digest["sha256"], 64):
            return f"{path!r} must be exactly {{\"sha256\": <64 lowercase hex>}}"
    return None


def link_problem(signed: object) -> Optional[str]:
    """Why a link's ``signed`` part is malformed, or None."""
    if not isinstance(signed, dict) or set(signed) != LINK_FIELDS:
        return f"link must have exactly the fields {sorted(LINK_FIELDS)}"
    if signed["_type"] != "link" or not isinstance(signed["name"], str):
        return "not a link"
    for field in ("materials", "products"):
        problem = artifacts_problem(signed[field])
        if problem:
            return f"{field}: {problem}"
    if not isinstance(signed["byproducts"], dict):
        return "byproducts must be an object"
    command = signed["command"]
    if not isinstance(command, list) or not all(isinstance(c, str) for c in command):
        return "command must be a list of strings"
    return None


def metablock_problem(doc: object) -> Optional[str]:
    if not isinstance(doc, dict) or set(doc) != {"signed", "signatures"}:
        return "must be exactly {\"signed\": ..., \"signatures\": [...]}"
    sigs = doc["signatures"]
    if not isinstance(sigs, list) or not sigs:
        return "carries no signatures"
    for sig in sigs:
        if not isinstance(sig, dict) or set(sig) != {"keyid", "sig"}:
            return "each signature must be exactly {\"keyid\": ..., \"sig\": ...}"
        if not isinstance(sig["keyid"], str) or not is_hex(sig["sig"], 128):
            return "signature keyid must be a string and sig 64 bytes of hex"
    return None
