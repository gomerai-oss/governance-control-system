# EPAP-EVIDENCE-SPEC-001 — A2 implementation decisions

**Mission:** M-EPAP-EVIDENCE-001, round 1
**Built from:** `missions/M-EPAP-EVIDENCE-001/PLAN.md`, which restates the spec's operative content. The spec text itself is not in the checkout.

The code does not amend the spec. Where the plan leaves a choice open, the choice below fails closed and is recorded here so A1 or HITL can reject it.

## Layout

| File | Role |
|---|---|
| `layout.py` | Spec section 2: the five-step pipeline model as data (`STEPS`), principals, layout construction and conformance |
| `links.py` | Spec section 3: in-toto link records, artifact digests, A3 vector records |
| `signing.py` | Canonical JSON, in-toto metablocks (`signed` + `signatures`), on-disk serialization |
| `ed25519.py` | RFC 8032 Ed25519, standard library only |
| `registry.py` | Reads the identity registry file |
| `writer.py` | Spec section 3: writes `layout.json`, one `<STEP>.link` per step, `provenance.json` |
| `verifier.py` | Spec section 4: independent verifier and CLI (`python3 -m epap.verifier`) |
| `../tests/test_epap_evidence.py` | Spec vectors 1-6 (plan P1-P6), plus hardening cases |

There is no `__init__.py`: `epap` is a namespace package (an `__init__.py` here would classify SPEC-002 `AUTHORITY`).

## Resolutions

1. **Signatures are Ed25519, in pure Python.** The standard library has no public-key signatures, and the plan allows no dependencies. HMAC would make every verifier a possible signer, so it cannot show who acted. `ed25519.py` is the RFC 8032 reference algorithm and is tested against RFC 8032 TEST 1. Verification handles no secrets. Signing is not constant-time, so it is for fixture keys only. Signing live packs with real App keys is out of scope (scope fence) and should use a vetted signer; packs it produces verify unchanged.
2. **Trust root.** HITL owns and signs the layout. The verifier is given HITL's public key out of band (`--owner-key`). Without that, anyone could write a layout listing their own keys. The layout must name exactly one HITL key, and that key is its owner.
3. **Key ids are identities.** A Campus App's key id is its registry role (`a2`). HITL's is `hitl:<login>` and the Mission Router's is `router:<login>`. The layout rejects a key id that does not name its principal.
4. **Registry scope.** Every Campus App signature is checked against the registry: the role must be listed, `ACTIVE`, and have the App ID the layout records. HITL and the Mission Router are not Campus Apps and are not in the registry. A HITL signature is trusted through the out-of-band owner key. A router key is trusted because the HITL-signed layout declares it, and the model lets the router act only in the merge step. The registry is read as it stands at verification time, so a pack signed by an App that has since been `SUSPENDED` or `RETIRED` fails. That matches the registry's rule that only `ACTIVE` roles verify.
5. **Roles and order, not the merging hand.** The model admits HITL or the Mission Router for `HITL_MERGE`, whichever the router's record shows acted. It admits the a1 App or HITL in person for `A1_SPEC`, as MISSION-ROUTER-001 allows. `A2_BUILD` admits only a2, `A3_REVIEW` only a3, and `HITL_APPROVAL` only HITL. A layout that assigns any other identity to a step fails as `LAYOUT_VIOLATION`, even when HITL signed it.
6. **Products are cumulative.** A step's products are the whole artifact set after the step, so the chain rule "each step's materials equal the previous step's products" holds exactly. HITL's approval and the merge carry their artifacts through unchanged.
7. **One named failure.** Verification stops at the first failed check and names it. The order is listed in `verifier.py`. Pack shape (extra steps or files, then missing ones) is checked right after the layout signature, so vector 2 always reports `INCOMPLETE` and vector 5 always reports `LAYOUT_VIOLATION`. An extra step is reported before a missing one.
8. **Strict format.** Unknown fields, duplicate JSON keys, floats, NaN, symlinks and stray files in the pack are all rejected. Every signature on a link must verify and come from a functionary of that step. Extra signatures are not ignored.
9. **Vector replay.** A3's link byproducts record `verdict` and `vectors` (`id`, `expected`, `observed`, `result`). Replay recomputes each result from expected vs observed and the verdict from the results, and both must match the record. A caller may pass `vector_runners` to observe a vector again instead of trusting its recorded `observed` value. A runner for a vector A3 did not record is a mismatch. A pack with no vectors fails. A consistent `FAIL` verdict followed by a merge step is a `LAYOUT_VIOLATION`, because the pipeline merges only on PASS.
10. **Provenance.** An in-toto Statement v1 with a SLSA provenance v1 predicate. The subject is the final products and `resolvedDependencies` is the first step's materials. `externalParameters` records the mission, the spec and the authority. `internalParameters.steps` records each step's actor, principal and command, plus the SHA-256 of its link file and of the layout. The verifier rebuilds these fields from the signed links on its own. It does not import the writer.
11. **Writer checks shape only.** It refuses a pack that does not have exactly one link per layout step, an empty authority, or an occupied directory. It does not check signatures or the chain, because judging those is the verifier's job.
