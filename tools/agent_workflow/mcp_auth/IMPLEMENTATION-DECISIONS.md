# MCP-AUTHORIZATION-FABRIC-SPEC-001 — A2 implementation decisions

**Mission:** M-EPAP-FABRIC-001, round 1
**Built from:** `missions/M-EPAP-FABRIC-001/PLAN.md`, which restates the spec's operative content, with the parent doctrine `governance/doctrine/L1-MCP-AUTHORIZATION-FABRIC-GOVERNED-RAG-EPAP-ACCESS-001.md` as reference. The spec text itself is not in the checkout.

The code does not amend the spec. Where the plan leaves a choice open, the choice below fails closed and is recorded here so A1 or HITL can reject it.

## Layout

| File | Role |
|---|---|
| `decide.py` | The decision engine: `evaluate(request, policy, now)` and `evaluate_file(request, now, path)` |
| `policy.py` | Policy schema, strict validation and loading |
| `policy.json` | The shipped policy data |
| `records.py` | Decision records and their EPAP link material (leg-2 `epap.links` format) |
| `../tests/test_mcp_auth.py` | Spec vectors 1-6 (plan P1-P6) as `test_vector1_…` to `test_vector6_…`, plus hardening cases |

There is no `__init__.py`: `mcp_auth` is a namespace package.

## Resolutions

1. **Order.** Two prechecks run before the spec's seven steps: `policy` (missing or malformed policy is stop 12) and `request` (a request that is not an object, carries unknown fields, has no `request_id`, or comes with no integer `now` is stop 13). Then `identity → role_class → authority → scope → action_grant → evidence → stop_conditions`, stopping at the first failure. A missing request field fails the step that reads it. That is why a request with no principal reports stop 2, not 13.
2. **Step-to-stop mapping.** identity: 2 (principal, acting identity), 13 (session). authority: 3. scope: 4. action_grant: 6 (EPAP mutation action with no allowing grant), 5 (any other write/execute action with no allowing grant), 11 (conflicting grants, or an action the catalog cannot classify). evidence: 10. stop_conditions: 1, 7, 8, 9, checked in that order. `role_class` has no matching §9 condition. It denies with the step named and `stop_condition: null`, as does a read action with no grant. Both are still DENY.
3. **Grants are SOT-scoped by their authority reference.** A grant applies to a request only if its `authority_ref` lists the request's mission in `authority_refs[...].missions`. A grant resting on another mission's authority does not match. For an EPAP mutation, that gives stop 6 (vector 3).
4. **Explicit mutation grants.** An allow grant that contains an EPAP mutation action must name exactly that one action and one resource, and must carry an evidence obligation other than `none`. Otherwise the policy is malformed (stop 12). The `rag` class must have no mutation action.
5. **Conflict means more than one outcome.** Two or more grants match the same role, class, resource, action and mission, and they disagree on effect, authority reference or evidence obligation: stop 11 (vector 5). Identical duplicates are not a conflict. A matching `deny` grant with no allow is a DENY at `action_grant`.
6. **No downgrade.** A denied write/execute is reported as such. The engine never re-evaluates it as a read (vector 4).
7. **Connector surface (stop 1).** The connector's declared `capabilities` must be a subset of the actions the role is granted on that resource under the mission. Anything broader is stop 1, even when the requested action itself is granted.
8. **Restricted material (stop 7)** applies to any resource marked `restricted` or `credential_bearing`, unless the mission lists it in `approvals.restricted`. This covers EPAP indexes as well as RAG corpora. **Credential access (stop 8)** needs the connector id in `approvals.credential`. **Runtime implications (stop 9)** need each implicated surface in `approvals.runtime`. An unknown surface name is itself stop 9.
9. **Sessions (stop 13).** The session must name the same principal, acting identity and mission as the request. Its lifetime must not exceed `session.max_ttl_seconds`, and `issued_at <= now < expires_at` must hold. `now` is supplied by the caller, so evaluation is deterministic.
10. **Engine errors fail closed.** An unexpected exception during evaluation is a DENY at the current step with stop 12 (the authorization service could not produce a result).
11. **Decision records.** Every evaluation emits a `mcp-auth-decision-v1` record holding the nine §5 answers as resolved (`null` where unresolved; the ninth is always `FAIL_CLOSED`), the disposition, the failed step and stop condition, the policy version and digest, the request digest, and a UTC timestamp derived from `now`. `answers.stop_conditions` lists the conditions cleared by the steps that passed and the one triggered.
12. **EPAP link material.** `records.link_material(record)` returns the `signed` part of an `epap.links` link named `MCP_AUTH_DECISION`. Its materials are the canonical policy and request (`mcp_auth/policy/<sha>.json`, `mcp_auth/requests/<sha>.json`). Its products are those plus the record (`mcp_auth/decisions/<sha>.json`), cumulative as in leg 2. Its byproducts are the record. It is not signed here: signing and pack assembly belong to the enforcement wiring, which is outside this leg.
13. **Shipped policy binds no identity.** `policy.json` carries the binding classes and action catalog, the governed roles, and read-only role grants resting on the L3 lane's SPEC reference. It has no principals, no missions and no mutation grants. With the shipped data, every request is therefore denied (stop 2) until a governed change admits principals and missions. Tests use their own fixture policy.
