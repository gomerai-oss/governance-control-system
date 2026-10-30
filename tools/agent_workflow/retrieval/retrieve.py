"""The deterministic structure-first retriever and its CLI.

``retrieve(request, root, corpus_registry=None, semantic_backend=None)`` runs the
doctrine section 2 stages in order over a corpus and returns a
``retrieval-result-v1`` record. The same request over the same tree yields a
byte-identical record: there are no clocks and no randomness, and any timestamp a
caller needs is supplied by the caller, not by this module.

Every result carries ``stop_reason`` and, in ``provenance``, the ordered list of
stages run with their outcomes. ``citations(result)`` returns the evidence
contracts the result stands on, and ``evidence_link(result)`` returns the signed
part of an EPAP ``RETRIEVAL`` link over the request, the cited sources and the
result. Nothing a result carries is phrased or typed as permission to act.

CLI::

    python3 -m retrieval.retrieve --root DIR --request FILE
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, List, Mapping, Optional

if __package__ in (None, ""):  # pragma: no cover - direct execution fallback
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from epap import links, signing

from retrieval import corpus as corpus_mod
from retrieval import failures, records, stages

RETRIEVAL_LINK_NAME = "RETRIEVAL"
RESULT_ARTIFACT_PATH = "retrieval-result.json"


def _load_registry(corpus_registry: Any) -> corpus_mod.CorpusRegistry:
    if corpus_registry is None:
        return corpus_mod.load_registry(corpus_mod.default_registry_path())
    if isinstance(corpus_registry, corpus_mod.CorpusRegistry):
        return corpus_registry
    if isinstance(corpus_registry, (str, Path)):
        return corpus_mod.load_registry(Path(corpus_registry))
    if isinstance(corpus_registry, Mapping):
        return corpus_mod.parse_registry(dict(corpus_registry))
    raise TypeError("corpus_registry must be None, a CorpusRegistry, a path, or a decoded registry")


def _recovery_limit(constraints: Mapping[str, Any]) -> int:
    raw = constraints.get("max_recovery_iterations")
    if isinstance(raw, int) and not isinstance(raw, bool) and raw > 0:
        return raw
    return stages.DEFAULT_RECOVERY_ITERATIONS


def _active_core(method: Optional[str]) -> List[str]:
    if method is None:
        return list(stages.CORE_STAGE_NAMES)
    if method in stages.CORE_STAGE_NAMES:
        return [method]
    return []


def _run_core(ctx: stages.StageContext, constraints: Mapping[str, Any], method: Optional[str]):
    recs: List[dict] = []
    deferred = None
    for name in _active_core(method):
        if name == stages.EXACT:
            oc = stages.stage_exact(ctx, constraints)
        elif name == stages.METADATA:
            oc = stages.stage_metadata(ctx, constraints)
        elif name == stages.STRUCTURE:
            oc = stages.stage_structure(ctx, constraints, deferred)
        elif name == stages.VOCABULARY:
            oc = stages.stage_vocabulary(ctx, constraints)
        else:
            oc = stages.stage_lexical(ctx, constraints)
        recs.append(oc.record())
        if oc.outcome == stages.DEFERRED_SUPERSEDED:
            deferred = oc.doc
            continue
        if oc.resolved or oc.abstain:
            return oc, recs
    return None, recs


def _run_recovery(ctx: stages.StageContext) -> stages.StageOutcome:
    declared = [k for k in stages.RELAXABLE_KEYS if k in ctx.constraints]
    limit = min(_recovery_limit(ctx.constraints), len(declared))
    relaxations: List[str] = []
    constraints = dict(ctx.constraints)
    for i in range(limit):
        key = declared[i]
        constraints.pop(key, None)
        relaxations.append(key)
        oc, _ = _run_core(ctx, constraints, None)
        if oc is not None and oc.resolved:
            oc.name = stages.RECOVERY
            oc.outcome = stages.RESOLVED
            oc.detail = {"relaxations": list(relaxations)}
            return oc
    return stages.StageOutcome(
        name=stages.RECOVERY, outcome=stages.LOOP_EXHAUSTED, abstain=True,
        failure_class="MISSING_REQUIRED_SOURCE",
        detail={"outcome": stages.LOOP_EXHAUSTED, "iterations": len(relaxations),
                "relaxations": list(relaxations)})


def _acl_gate(ctx: stages.StageContext) -> Optional[stages.StageOutcome]:
    """Classify every requested path against the request's corpora before any stage.

    A ``path`` or ``location`` constraint that is not a clean relative path, falls
    outside every corpus root, or matches a deny pattern denies the whole request
    with ``ACL_SCOPE_FAILURE`` and reads no bytes — whatever lifecycle constraints
    accompany it and whatever ``retrieval_method`` is pinned (recovery included).
    This runs ahead of the stages so the ACL can never be skipped by a request
    shape that keeps stage ``exact`` from classifying the path.
    """
    for key in ("path", "location"):
        if key not in ctx.constraints:
            continue
        target = ctx.constraints[key]
        state, _ = stages._classify_requested(ctx, target)
        if state == corpus_mod.PATH_DENIED:
            return stages._acl_failure("acl", target)
    return None


def _run_pipeline(ctx: stages.StageContext):
    method = ctx.request["retrieval_method"]
    stage_records: List[dict] = []

    gate = _acl_gate(ctx)
    if gate is not None:
        stage_records.append(gate.record())
        return gate, stage_records

    if method is None or method in stages.CORE_STAGE_NAMES:
        oc, recs = _run_core(ctx, ctx.constraints, method)
        stage_records += recs
        if oc is not None and (oc.resolved or oc.abstain):
            return oc, stage_records

    if method is None or method == stages.SEMANTIC:
        sem = stages.stage_semantic(ctx, ctx.constraints)
        stage_records.append(sem.record())
        if sem.resolved or sem.abstain:
            return sem, stage_records

    # Pinned, recovery runs on its own: it relaxes the declared constraints one
    # per iteration and re-runs stages 1-5 over what is left, as it does in the
    # full hierarchy.
    if method is None or method == stages.RECOVERY:
        rec = _run_recovery(ctx)
        stage_records.append(rec.record())
        return rec, stage_records

    return stages.StageOutcome(name=method, outcome=stages.NO_MATCH, abstain=True,
                               failure_class="MISSING_REQUIRED_SOURCE"), stage_records


def _superseded_citations(ctx: stages.StageContext, claim_id: str,
                          docs: List[stages.Document]) -> List[dict]:
    out = []
    for doc in docs:
        out.append(records.make_citation(
            claim_id=claim_id, source_id=doc.document_id, source_path=doc.relpath,
            source_authority=doc.authority, source_version=doc.sha256,
            evidence_span=doc.full_span(), evidence_relationship="UNVERIFIED",
            contradiction_state="SUPERSEDED", validation_state="VALIDATED"))
    return out


def _build_result(ctx: stages.StageContext, outcome: stages.StageOutcome,
                  stage_records: List[dict]) -> dict:
    request = ctx.request
    claim_id = request["request_id"]
    claim_text = request["query_intent"] or None
    request_bytes = signing.canonical_bytes(dict(request))
    provenance = {
        "request_id": request["request_id"],
        "mission_id": request["mission_id"],
        "corpus_scope": [c.id for c in ctx.corpora],
        "registry_version": ctx.registry_version,
        "resolved_stage": outcome.name if outcome.resolved else None,
        "stages": stage_records,
        "superseded": _superseded_citations(ctx, claim_id, outcome.superseded),
        "source_path": outcome.doc.relpath if (outcome.resolved and outcome.doc) else None,
        "request_artifact": {
            "path": f"{request['request_id']}.request.json",
            "sha256": signing.sha256_hex(request_bytes),
        },
        "result_artifact_path": RESULT_ARTIFACT_PATH,
    }

    if outcome.resolved and outcome.doc is not None:
        doc = outcome.doc
        result = {
            "source_id": doc.document_id,
            "source_authority": doc.authority,
            "source_version": doc.sha256,
            "source_date": doc.metadata["date"],
            "claim_id": claim_id,
            "claim_text": claim_text,
            "evidence_span": outcome.span,
            "evidence_relationship": outcome.relationship,
            "confidence_state": "RESOLVED",
            "contradiction_state": outcome.contradiction_state,
            "missing_evidence": [],
            "validation_state": "VALIDATED",
            "provenance": provenance,
            "stop_reason": "RESOLVED",
        }
    else:
        stop_reason = outcome.failure_class or "MISSING_REQUIRED_SOURCE"
        missing = _missing_evidence(outcome, request)
        result = {
            "source_id": None,
            "source_authority": None,
            "source_version": None,
            "source_date": None,
            "claim_id": claim_id,
            "claim_text": claim_text,
            "evidence_span": None,
            "evidence_relationship": None,
            "confidence_state": "ABSTAINED",
            "contradiction_state": "SUPERSEDED" if outcome.superseded else "NONE",
            "missing_evidence": missing,
            "validation_state": "ABSTAINED",
            "provenance": provenance,
            "stop_reason": stop_reason,
        }
    return records.validate_result(result)


def _missing_evidence(outcome: stages.StageOutcome, request: Mapping[str, Any]) -> List[str]:
    if outcome.failure_class == "WRONG_DOCUMENT_VERSION":
        superseding = ""
        if isinstance(outcome.detail, dict):
            superseding = outcome.detail.get("superseding_document") or ""
        return [f"current version of the requested document ({superseding})".strip()]
    if outcome.failure_class == "ACL_SCOPE_FAILURE":
        return ["a source inside the corpus allow-list"]
    return ["a supporting source for the request"]


def retrieve(request: Mapping[str, Any], root: Any, corpus_registry: Any = None,
             semantic_backend: Any = None) -> dict:
    """Resolve ``request`` over the corpus under ``root`` and return the result record."""
    request = records.validate_request(request)
    registry = _load_registry(corpus_registry)
    corpora = registry.resolve_scope(request["corpus_scope"])
    ctx = stages.StageContext(
        root=Path(root), request=request, constraints=request["constraints"],
        corpora=corpora, semantic_backend=semantic_backend)
    ctx.registry_version = registry.version
    outcome, stage_records = _run_pipeline(ctx)
    return _build_result(ctx, outcome, stage_records)


def citations(result: Mapping[str, Any]) -> List[dict]:
    """The evidence contracts the result stands on: the cited source, then any superseded ones."""
    out: List[dict] = []
    provenance = result["provenance"]
    if result["source_id"] and result["evidence_span"] and result["evidence_relationship"]:
        out.append(records.make_citation(
            claim_id=result["claim_id"], source_id=result["source_id"],
            source_path=provenance["source_path"], source_authority=result["source_authority"],
            source_version=result["source_version"], evidence_span=result["evidence_span"],
            evidence_relationship=result["evidence_relationship"],
            contradiction_state=result["contradiction_state"],
            validation_state=result["validation_state"]))
    out.extend(records.validate_citation(c) for c in provenance.get("superseded", []))
    return out


def evidence_link(result: Mapping[str, Any]) -> dict:
    """The signed part of an EPAP ``RETRIEVAL`` link for this result.

    Materials: the request and the cited source files, by digest. Products: the
    result record. Byproducts: the citations.
    """
    provenance = result["provenance"]
    cites = citations(result)
    materials = {provenance["request_artifact"]["path"]: {"sha256": provenance["request_artifact"]["sha256"]}}
    for c in cites:
        materials[c["source_path"]] = {"sha256": c["source_version"]}
    products = {provenance["result_artifact_path"]:
                {"sha256": signing.sha256_hex(signing.canonical_bytes(dict(result)))}}
    byproducts = {"citations": cites, "stop_reason": result["stop_reason"]}
    command = ["retrieve", "--request", provenance["request_artifact"]["path"]]
    return links.make_link(RETRIEVAL_LINK_NAME, materials, products, command, byproducts)


def audit(result: Mapping[str, Any], root: Any) -> List[str]:
    """The detectable doctrine section 10 failure classes this result exhibits."""
    return failures.audit_result(result, Path(root), citations(result))


def _main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="retrieval.retrieve", description="Structure-first retriever")
    parser.add_argument("--root", required=True, help="repository root the corpus is resolved under")
    parser.add_argument("--request", required=True, help="path to a retrieval-request-v1 JSON file")
    args = parser.parse_args(argv)
    request = json.loads(Path(args.request).read_text(encoding="utf-8"))
    result = retrieve(request, args.root)
    sys.stdout.write(signing.canonical_bytes(result).decode("utf-8") + "\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
