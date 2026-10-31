"""Independent verifier for EPAP evidence packs (spec section 4).

Run by a party other than the builder, against a pack directory, the identity
registry and HITL's public key (the layout owner, handed over out of band). It
shares only the file formats with the writer, and emits ``VERIFY_PASS`` or
``VERIFY_FAIL`` naming the check that failed. The failure names are:

- ``MALFORMED``: a file cannot be read as the pack format requires
- ``BAD_SIGNATURE``: the layout is not signed by the trusted HITL key; or a
  link signature does not verify, is by a key the layout does not authorize for
  that step, or is by a agent App that is not ``ACTIVE`` in the registry with
  the App ID the layout records
- ``LAYOUT_VIOLATION``: the layout departs from the five-step pipeline model,
  the pack holds a step (or any file) the layout does not have, or a merge
  follows an A3 verdict other than PASS
- ``INCOMPLETE``: the layout, the provenance or a step's link is missing
- ``CHAIN_BROKEN``: a step's materials differ from the previous step's products
- ``PROVENANCE_MISMATCH``: provenance.json does not describe this pack
- ``VECTOR_MISMATCH``: replaying the A3 test vectors does not reproduce the
  recorded results and verdict

Verification stops at the first failure, in this order: read the layout; check
its signature against the trusted HITL key; check it against the pipeline model;
check the pack's shape (extra steps or files, then missing ones); read the
links; check every link signature; check the chain; check the provenance; replay
the A3 vectors. Shape is checked before link signatures, so a pack with a step
missing or added fails for that reason whatever its other defects.

Usage::

    python3 -m epap.verifier PACK_DIR --owner-key HEX --registry REGISTRY

where REGISTRY is the identity registry file.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Tuple, Union

from epap import layout as model
from epap.links import RESULTS, VECTOR_FIELDS, VERDICTS, link_problem, metablock_problem
from epap.registry import Identity, RegistryError, load_registry
from epap.signing import sha256_hex, signature_valid

VERIFY_PASS = "VERIFY_PASS"
VERIFY_FAIL = "VERIFY_FAIL"

MALFORMED = "MALFORMED"
BAD_SIGNATURE = "BAD_SIGNATURE"
LAYOUT_VIOLATION = "LAYOUT_VIOLATION"
INCOMPLETE = "INCOMPLETE"
CHAIN_BROKEN = "CHAIN_BROKEN"
PROVENANCE_MISMATCH = "PROVENANCE_MISMATCH"
VECTOR_MISMATCH = "VECTOR_MISMATCH"

# The pack format, restated here rather than imported from the writer.
LAYOUT_FILE = "layout.json"
PROVENANCE_FILE = "provenance.json"
LINK_SUFFIX = ".link"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
BUILD_TYPE = "urn:epap:pipeline:" + model.PIPELINE_ID

Runner = Callable[[], Any]


@dataclass(frozen=True)
class Result:
    status: str
    failed_check: Optional[str] = None
    detail: str = ""

    @property
    def passed(self) -> bool:
        return self.status == VERIFY_PASS

    def to_dict(self) -> dict:
        return {"status": self.status, "failed_check": self.failed_check, "detail": self.detail}


class _Fail(Exception):
    def __init__(self, check: str, detail: str):
        super().__init__(detail)
        self.check = check
        self.detail = detail


def verify_pack(pack_dir: Union[str, Path], registry: Union[str, Path, Mapping[str, Identity]],
                owner_public_key: Union[str, bytes],
                vector_runners: Optional[Mapping[str, Runner]] = None) -> Result:
    """Verify one pack. ``vector_runners`` maps an A3 vector id to a callable that
    re-observes it; vectors without a runner are replayed from their record."""
    try:
        return _verify(Path(pack_dir), registry, owner_public_key, vector_runners or {})
    except _Fail as fail:
        return Result(VERIFY_FAIL, fail.check, fail.detail)


def _verify(pack: Path, registry_src, owner_public_key, runners: Mapping[str, Runner]) -> Result:
    owner_hex = owner_public_key.hex() if isinstance(owner_public_key, (bytes, bytearray)) else str(owner_public_key).lower()
    registry = _registry(registry_src)
    if pack.is_symlink() or not pack.is_dir():
        raise _Fail(MALFORMED, f"{pack} is not a pack directory")

    layout_doc, layout_raw = _load(pack / LAYOUT_FILE, INCOMPLETE)
    _require(metablock_problem(layout_doc) is None and isinstance(layout_doc["signed"], dict),
             MALFORMED, f"{LAYOUT_FILE}: {metablock_problem(layout_doc) or 'signed part is not an object'}")
    layout = layout_doc["signed"]
    _check_layout_signature(layout_doc, owner_hex)
    problem = model.layout_problem(layout)
    _require(problem is None, LAYOUT_VIOLATION, f"{LAYOUT_FILE}: {problem}")

    _check_pack_shape(pack)
    links: Dict[str, dict] = {}
    raws: Dict[str, bytes] = {}
    for name in model.STEP_NAMES:
        doc, raw = _load(pack / (name + LINK_SUFFIX), INCOMPLETE)
        problem = metablock_problem(doc) or link_problem(doc["signed"])
        _require(problem is None, MALFORMED, f"{name}{LINK_SUFFIX}: {problem}")
        _require(doc["signed"]["name"] == name, LAYOUT_VIOLATION,
                 f"{name}{LINK_SUFFIX} records step {doc['signed']['name']!r}")
        links[name], raws[name] = doc, raw

    for name in model.STEP_NAMES:
        _check_link_signatures(name, links[name], layout, registry)

    for prev, cur in zip(model.STEP_NAMES, model.STEP_NAMES[1:]):
        _check_chain(prev, links[prev]["signed"]["products"], cur, links[cur]["signed"]["materials"])

    provenance, _ = _load(pack / PROVENANCE_FILE, INCOMPLETE)
    _check_provenance(provenance, layout, layout_raw, links, raws)

    replayed = _replay_vectors(links[model.A3_REVIEW]["signed"]["byproducts"], runners)
    return Result(VERIFY_PASS, None,
                  f"{len(model.STEP_NAMES)} steps signed by authorized identities, chain intact, "
                  f"provenance consistent, {replayed} A3 vectors replayed to the recorded PASS")


def _require(condition: bool, check: str, detail: str) -> None:
    if not condition:
        raise _Fail(check, detail)


def _registry(source) -> Mapping[str, Identity]:
    if isinstance(source, Mapping):
        return source
    try:
        return load_registry(Path(source))
    except (OSError, UnicodeDecodeError, RegistryError) as exc:
        raise _Fail(MALFORMED, f"identity registry {source}: {exc}") from None


def _no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _reject_constant(name):
    raise ValueError(f"{name} is not valid JSON")


def _load(path: Path, missing_check: str) -> Tuple[Any, bytes]:
    if not os.path.lexists(path):
        raise _Fail(missing_check, f"{path.name} is missing")
    if path.is_symlink() or not path.is_file():
        raise _Fail(LAYOUT_VIOLATION, f"{path.name} is not a regular file")
    raw = path.read_bytes()
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError) as exc:
        raise _Fail(MALFORMED, f"{path.name}: not valid JSON ({exc})") from None
    return doc, raw


def _check_layout_signature(layout_doc: Mapping, owner_hex: str) -> None:
    layout = layout_doc["signed"]
    owner = layout.get("owner")
    sigs = layout_doc["signatures"]
    _require(len(sigs) == 1 and sigs[0]["keyid"] == owner, BAD_SIGNATURE,
             "the layout must carry exactly one signature, by its owner")
    keys = layout.get("keys")
    owner_entry = keys.get(owner) if isinstance(keys, dict) and isinstance(owner, str) else None
    _require(isinstance(owner_entry, dict) and owner_entry.get("public") == owner_hex, BAD_SIGNATURE,
             "the layout owner's key is not the trusted HITL key")
    _require(signature_valid(owner_hex, layout, sigs[0]["sig"]), BAD_SIGNATURE,
             "the layout signature does not verify against the trusted HITL key")


def _check_pack_shape(pack: Path) -> None:
    present = set()
    for entry in sorted(os.listdir(pack)):
        if entry in (LAYOUT_FILE, PROVENANCE_FILE):
            continue
        if not entry.endswith(LINK_SUFFIX):
            raise _Fail(LAYOUT_VIOLATION, f"{entry} is not part of an evidence pack")
        name = entry[: -len(LINK_SUFFIX)]
        if name not in model.STEP_NAMES:
            raise _Fail(LAYOUT_VIOLATION, f"{entry} records a step the layout does not have")
        present.add(name)
    missing = [n for n in model.STEP_NAMES if n not in present]
    _require(not missing, INCOMPLETE, "no link for step(s) " + ", ".join(missing))
    _require(os.path.lexists(pack / PROVENANCE_FILE), INCOMPLETE, f"{PROVENANCE_FILE} is missing")


def _check_link_signatures(name: str, doc: Mapping, layout: Mapping, registry: Mapping[str, Identity]) -> None:
    authorized = list(model.functionaries_of(layout, name))
    keys = layout["keys"]
    for sig in doc["signatures"]:
        keyid = sig["keyid"]
        _require(keyid in authorized, BAD_SIGNATURE,
                 f"{name} is signed by {keyid!r}, which the layout does not authorize for this step")
        entry = keys[keyid]
        _require(signature_valid(entry["public"], doc["signed"], sig["sig"]), BAD_SIGNATURE,
                 f"{name}: the signature by {keyid!r} does not verify")
        principal = entry["principal"]
        if principal["kind"] == model.AGENT_APP:
            ident = registry.get(principal["role"])
            _require(ident is not None, BAD_SIGNATURE,
                     f"{name}: {keyid!r} is not in the identity registry")
            _require(ident.active, BAD_SIGNATURE,
                     f"{name}: {keyid!r} is {ident.status} in the identity registry, not ACTIVE")
            _require(ident.app_id == principal["app_id"], BAD_SIGNATURE,
                     f"{name}: {keyid!r} has App ID {ident.app_id} in the registry, "
                     f"the layout says {principal['app_id']}")


def _check_chain(prev: str, products: Mapping, cur: str, materials: Mapping) -> None:
    if materials == products:
        return
    changed = sorted(p for p in set(products) | set(materials) if products.get(p) != materials.get(p))
    raise _Fail(CHAIN_BROKEN, f"{cur} materials differ from {prev} products at: " + ", ".join(changed))


def _descriptors(artifacts: Mapping) -> list:
    return [{"name": p, "digest": {"sha256": artifacts[p]["sha256"]}} for p in sorted(artifacts)]


def _check_provenance(prov: Any, layout: Mapping, layout_raw: bytes,
                      links: Mapping[str, Mapping], raws: Mapping[str, bytes]) -> None:
    def field(*path):
        node = prov
        for key in path:
            if not isinstance(node, dict) or key not in node:
                raise _Fail(PROVENANCE_MISMATCH, "provenance has no " + ".".join(path))
            node = node[key]
        return node

    def expect(value, wanted, what):
        _require(value == wanted, PROVENANCE_MISMATCH, f"provenance {what} does not match the pack")

    first, last = links[model.STEP_NAMES[0]]["signed"], links[model.STEP_NAMES[-1]]["signed"]
    expect(field("_type"), STATEMENT_TYPE, "_type")
    expect(field("predicateType"), PREDICATE_TYPE, "predicateType")
    expect(field("subject"), _descriptors(last["products"]), "subject (final products)")
    build = ("predicate", "buildDefinition")
    expect(field(*build, "buildType"), BUILD_TYPE, "buildType")
    expect(field(*build, "externalParameters", "mission_id"), layout["mission_id"], "mission_id")
    expect(field(*build, "externalParameters", "spec"), model.SPEC_ID, "spec")
    authority = field(*build, "externalParameters", "authority")
    _require(isinstance(authority, dict) and bool(authority), PROVENANCE_MISMATCH,
             "provenance records no authority")
    expect(field(*build, "internalParameters", "pipeline"), model.PIPELINE_ID, "pipeline")
    expect(field(*build, "internalParameters", "layout"), LAYOUT_FILE, "layout")
    expect(field(*build, "internalParameters", "layout_sha256"), sha256_hex(layout_raw), "layout digest")
    expect(field(*build, "resolvedDependencies"), _descriptors(first["materials"]),
           "resolvedDependencies (first materials)")
    steps = []
    for step in model.STEPS:
        doc = links[step.name]
        actor = doc["signatures"][0]["keyid"]
        steps.append({
            "name": step.name,
            "role": step.role,
            "actor": actor,
            "principal": layout["keys"][actor]["principal"],
            "command": doc["signed"]["command"],
            "link": step.name + LINK_SUFFIX,
            "link_sha256": sha256_hex(raws[step.name]),
        })
    expect(field(*build, "internalParameters", "steps"), steps, "steps (actors, commands, link digests)")
    builder = field("predicate", "runDetails", "builder", "id")
    _require(isinstance(builder, str) and bool(builder), PROVENANCE_MISMATCH, "provenance names no builder")
    expect(field("predicate", "runDetails", "metadata", "invocationId"), layout["mission_id"], "invocationId")


def _replay_vectors(byproducts: Mapping, runners: Mapping[str, Runner]) -> int:
    verdict, vectors = byproducts.get("verdict"), byproducts.get("vectors")
    _require(verdict in VERDICTS, VECTOR_MISMATCH, f"A3 recorded no verdict (got {verdict!r})")
    _require(isinstance(vectors, list) and bool(vectors), VECTOR_MISMATCH, "A3 recorded no test vectors")
    seen = set()
    results = []
    for vec in vectors:
        _require(isinstance(vec, dict) and set(vec) == VECTOR_FIELDS and isinstance(vec["id"], str)
                 and vec["result"] in RESULTS, VECTOR_MISMATCH, f"malformed A3 vector record: {vec!r}")
        vid = vec["id"]
        _require(vid not in seen, VECTOR_MISMATCH, f"A3 vector {vid!r} is recorded twice")
        seen.add(vid)
        observed = vec["observed"]
        if vid in runners:
            try:
                observed = runners[vid]()
            except Exception as exc:  # a replay that cannot run does not reproduce the record
                raise _Fail(VECTOR_MISMATCH, f"replay of A3 vector {vid!r} raised {exc!r}") from None
            _require(observed == vec["observed"], VECTOR_MISMATCH,
                     f"replay of A3 vector {vid!r} observed {observed!r}; A3 recorded {vec['observed']!r}")
        result = "pass" if observed == vec["expected"] else "fail"
        _require(result == vec["result"], VECTOR_MISMATCH,
                 f"A3 vector {vid!r} replays as {result}; A3 recorded {vec['result']}")
        results.append(result)
    unknown = sorted(set(runners) - seen)
    _require(not unknown, VECTOR_MISMATCH, "A3 did not record vector(s) " + ", ".join(unknown))
    replayed = "PASS" if all(r == "pass" for r in results) else "FAIL"
    _require(replayed == verdict, VECTOR_MISMATCH,
             f"A3 vectors replay to {replayed}; A3 recorded verdict {verdict}")
    _require(verdict == "PASS", LAYOUT_VIOLATION, "the pack records a merge after an A3 FAIL verdict")
    return len(results)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m epap.verifier", description=__doc__.splitlines()[0])
    parser.add_argument("pack", type=Path, help="evidence pack directory")
    parser.add_argument("--owner-key", required=True, help="HITL's Ed25519 public key (hex), the layout owner")
    parser.add_argument("--registry", type=Path, required=True, help="the identity registry file")
    args = parser.parse_args(argv)
    result = verify_pack(args.pack, args.registry, args.owner_key)
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
