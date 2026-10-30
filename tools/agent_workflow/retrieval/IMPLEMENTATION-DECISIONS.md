# STRUCTURAL-RETRIEVAL-SPEC-001 — A2 implementation decisions

**Mission:** M-EPAP-RETRIEVE-001, round 4 (resolutions 6 and 12 revised for the
round-3 review finding; resolutions 6, 8 and 11 were revised in round 3 for the
round-2 findings, and resolutions 8, 9 and 11 in round 2 for the round-1 findings)
**Built from:** `missions/M-EPAP-RETRIEVE-001/PLAN.md`, whose operative content is the
spec. The code does not amend the spec: where the plan leaves a choice open, the
choice below fails closed and is recorded here so A1 or HITL can reject it.

## Layout

| File | Role |
|---|---|
| `corpus.json` | Corpus registry as data (`retrieval-corpus-v1`): one corpus `corpus:governance-doctrine` |
| `corpus.py` | Loads and strictly validates the registry; resolves a corpus to a sorted file set; refuses symlinks, out-of-root paths and deny-pattern matches |
| `records.py` | The doctrine section 8 inter-stage records (`retrieval-request-v1`, `retrieval-result-v1`) and section 9 citations (`citation-v1`), validated both ways |
| `stages.py` | The seven section 2 stages in their fixed order, plus document loading, metadata extraction and deterministic BM25 |
| `failures.py` | The seventeen section 10 failure classes as data, with detectors for the ones this build is responsible for |
| `retrieve.py` | `retrieve(...)`, `citations(...)`, `evidence_link(...)`, and the CLI |
| `../tests/test_retrieval.py` | One named case per vector P1–P8, plus hardening cases |

There is no `__init__.py`: `retrieval` is a namespace package, as the earlier legs
(an `__init__.py` here would classify SPEC-002 `AUTHORITY`).

## Resolutions

1. **The section 8 field set is split, not duplicated.** The twenty section 8 fields
   are partitioned so their union is exactly that set and their intersection is
   empty: the six a caller declares (`request_id`, `mission_id`, `query_intent`,
   `constraints`, `corpus_scope`, `retrieval_method`) form `retrieval-request-v1`;
   the remaining fourteen form `retrieval-result-v1`. The plan says "exactly the
   section 8 field set"; this is the only split that adds nothing and drops nothing.
2. **Both records are strict.** Unknown fields, missing fields, wrong types, floats
   and out-of-range enum values are rejected on the way in and on the way out. A
   record that does not validate is a `SCHEMA_FAILURE`.
3. **Determinism.** No clocks, no randomness. The same request over the same tree
   yields a byte-identical result record. A file set is sorted; BM25 ties break on
   path; the best supporting line breaks ties on the lowest line number. BM25 scores
   are internal only and never enter the record, so no float reaches the output.
   Any timestamp a caller needs is the caller's to add.
4. **Retrieval is not authority.** No field value names a permission.
   `confidence_state` is only `RESOLVED` or `ABSTAINED`; `validation_state` is only
   `VALIDATED`, `UNVERIFIED`, `FAILED` or `ABSTAINED`. Nothing in a result is phrased
   or typed as leave to act.
5. **Stage order and the "later stage runs only when every earlier stage left the
   request unresolved" rule.** Stages run in the fixed section 2 order; the first
   stage that resolves or abstains stops the run, and no later stage runs. A stage
   with no relevant constraint records `NOT_APPLICABLE`; one that is relevant but
   finds nothing records `NO_MATCH`. The ordered list of stages run, with their
   outcomes, is kept in `provenance.stages`.
6. **Supersession is a structural concern.** When an exact or metadata candidate is
   marked superseded (a `**Superseded-By:**` line, or `**Status:** SUPERSEDED`), that
   stage defers (`DEFERRED_SUPERSEDED`) and the structure stage resolves it. Every
   supersession path (structure, vocabulary, lexical, semantic) follows
   `Superseded-By` through the corpus, hop by hop, to a document that is not itself
   superseded, keeping a visited set and bounded by the corpus size. That document
   is cited, and every superseded document on the way is listed, in chain order, as
   a citation in `provenance.superseded` with `contradiction_state: SUPERSEDED`. A
   superseded document is never the cited source. The result abstains with
   `WRONG_DOCUMENT_VERSION`, citing nothing, when the chain leaves the corpus (a
   successor id no corpus document carries, or a superseded document naming no
   successor), names the document itself, or returns to a document already on it
   (a cycle); the stage detail records the chain and the reason. `audit_result`
   flags `WRONG_DOCUMENT_VERSION` for any result whose primary cited source is
   itself marked superseded, whatever the result's `contradiction_state`, and also
   `CONTRADICTION_MISSED` when that state is `NONE`. The successor
   cited in place of a deferred `exact`/`metadata`/`vocabulary`/`structure` candidate
   carries `EXACT_MATCH` because the superseded candidate was matched by id or field,
   and the successor is its declared current version. A **lexical** hit on a superseded
   document is different: BM25 matched the stale document, not the successor, so the
   successor is cited no more strongly than it supports itself — `LEXICAL_SUPPORT`
   with a matching line span only when the successor itself scores for the terms,
   otherwise `UNVERIFIED` with its whole-file span. This matches the semantic rule
   (resolution 9): nothing stronger than the retrieval produced is ever claimed.
7. **Metadata is extracted, not configured.** `document_id` is the file-name stem;
   `status`, `title`, `date` and the supersession fields come from `**Field:**` lines
   (title falls back to the first `# ` heading, date to the first `YYYY-MM-DD` on a
   line naming a date). Metadata filters compare case-insensitively.
8. **The ACL is an allow-list.** A corpus reads only files its `roots` admit; a path
   outside every root, or one matching a generic credential deny pattern, yields
   `ACL_SCOPE_FAILURE` and no bytes are read from it. Symlinks under a root, and
   anything that resolves outside the root, are refused. A requested path (from the
   `path` or `location` constraint, or from a semantic backend hit) is taken exactly
   as given and never normalised; one that is not a string, is empty or absolute,
   holds a backslash or NUL, or has an empty, `.` or `..` segment is denied before any
   root is consulted, because glob matching is lexical and `docs/../x.md` would
   otherwise match `docs/**`. A present but empty `path` is such a path, not an
   absent constraint. Deny-pattern matching is per path segment, so a pattern such as
   `*secret*` excludes a matching directory too, and case-insensitive on every
   platform, so `API-TOKEN.md` is denied by `*token*`. The ACL is a gate at pipeline
   entry: before any stage runs, and for every `retrieval_method` (null, any pinned
   stage, or `recovery`), each present `path` and `location` constraint is classified
   against the request's corpora. A `DENIED` classification abstains the whole request
   with `ACL_SCOPE_FAILURE`, recorded as an `acl` entry in `provenance.stages`, so the
   failure can never be skipped by a request shape that keeps stage `exact` from
   classifying the path — a lifecycle constraint alongside the path, a pinned non-exact
   stage, pinned recovery relaxing `path` first, or `path` and `location` together.
9. **No semantic backend ships.** The semantic stage is an interface
   (`backend.retrieve(request, context)` returning `{source_path, start_line,
   end_line}` or nothing); with none configured it records `SEMANTIC_UNAVAILABLE` and
   never substitutes another method under its name. A configured backend runs only
   after stages 1–5 leave the request unresolved. Its hit is held to the same rules as
   stages 1–5: the path passes the resolution 8 ACL (a denied path is
   `ACL_SCOPE_FAILURE` and stops the run); a span that is not integers with
   `1 <= start_line <= end_line <= ` the file's line count is `NO_MATCH`, so the run
   continues to recovery; and a hit on a superseded document goes through the
   resolution 6 supersession rule (cite the in-corpus successor and list the
   superseded one, or abstain with `WRONG_DOCUMENT_VERSION`). A span the backend
   returns is hashed like any other, with `evidence_relationship: UNVERIFIED` because
   no entailment is claimed; a successor cited in place of a superseded hit carries
   its whole-file span and is also `UNVERIFIED`, because the backend did not match it.
10. **The recovery loop is bounded and honest.** Its maximum iteration count is data
    (`constraints.max_recovery_iterations`, default 3), further bounded by the number
    of declared constraints. It relaxes one declared constraint per iteration, in a
    fixed order, and records each relaxation. When it runs out it records
    `LOOP_EXHAUSTED` with its iteration count and the result abstains with
    `MISSING_REQUIRED_SOURCE`; an exhausted loop is never reported as a success, and a
    result that did so would be `LOOP_EXHAUSTION_MISREPRESENTED`.
11. **`retrieval_method` selects a method.** Left null, the full hierarchy runs. It
    is validated as null or one of the seven stage names
    (`records.RETRIEVAL_METHODS`, equal to `stages.ALL_STAGE_NAMES`); any other value
    is a `SCHEMA_FAILURE` and the request is rejected before any stage runs. Set to
    one of stages 1–5 or `semantic`, only that stage runs, and if it does not resolve
    the result abstains with `MISSING_REQUIRED_SOURCE`. Set to `recovery`, only the
    recovery loop runs: it relaxes the declared constraints one per iteration and
    re-runs stages 1–5 over what is left, exactly as it does at the end of the full
    hierarchy, and records `LOOP_EXHAUSTED` with its iteration count when it runs out.
12. **Eight failure classes are detected; nine are declared not detectable here, each
    with a reason.** The detected set is `WRONG_DOCUMENT_VERSION`,
    `MISSING_REQUIRED_SOURCE`, `ACL_SCOPE_FAILURE`, `SCHEMA_FAILURE`,
    `CONTRADICTION_MISSED` (supersession), `ABSTENTION_FAILURE`,
    `LOOP_EXHAUSTION_MISREPRESENTED` and `UNSUPPORTED_ASSERTION`.
    `WRONG_DOCUMENT_VERSION` covers both an abstention on a broken supersession chain
    and a primary citation whose own source is superseded (resolution 6). The rest need an
    answer key, a declared expectation, a freshness or jurisdiction field, or a model
    judgement this build does not carry, so they fail closed to
    `NOT_DETECTABLE_IN_THIS_BUILD` with the reason recorded, never silently claimed.
13. **Evidence links reuse leg 2.** `evidence_link(result)` returns the `signed` part
    of an EPAP `RETRIEVAL` link: materials are the request and the cited source files
    by digest, products are the result record, byproducts are the citations. It is a
    link body; signing it with a real key is out of scope (scope fence) and uses the
    leg-2 signer. `source_version` is the SHA-256 of the file; a citation whose span
    no longer hashes to its recorded value is an `UNSUPPORTED_ASSERTION`.
14. **Tests build their own corpus.** Every case writes its corpus and a registry
    into a temporary directory; none reads `governance/doctrine/` or
    `tools/agent_workflow/specs/` from the checkout, so documents added or deleted
    there never change a result.
