# GRAPH-ENGINEERING-CONTRACT-SPEC-001 — A2 implementation decisions

**Mission:** M-EPAP-GRAPH-001, round 2 (round 1 finding fixed: the vendor scan's `description` exemption, item 10)
**Built from:** `missions/M-EPAP-GRAPH-001/PLAN.md`, which restates the spec's operative content, with the parent directive `governance/doctrine/L1-ENTERPRISE-GRAPH-ENGINEERING-ARCHITECTURE-DIRECTIVE-001.md` (§§5–9) as reference. The spec text itself is not in the checkout.

The code does not amend the spec. Where the plan leaves a choice open, the choice below fails closed and is recorded here so A1 or HITL can reject it.

This package is a contract layer only. It defines and checks contracts; it executes nothing, stores no run state, checkpoints nothing and activates nothing. A `CONTRACT_VALID` result is not evidence of a graph runtime or of production operation (directive §8 non-equivalence rule), and every result says so in its `scope` field.

## Layout

| File | Role |
|---|---|
| `schema.json` / `schema.py` | Contract schema as data (directive §7): node kinds, edge kinds, field sets, state scopes and store, artifact role, typed-I/O vocabulary, vendor denylist, and the rule table. Strict loading and validation |
| `gates.json` / `gates.py` | Gate-criteria table as data (directive §8.1–8.14), strict loading and validation, and the two pure predicates `review_criterion_met` / `hitl_criterion_met` |
| `validate.py` | The validator: `validate(contract)` and `validate_file(path)` → `Result(verdict, rule, detail, scope)` |
| `../tests/test_graph_contracts.py` | Spec vectors 1–6 (plan P1–P6) as `test_vector1_…` to `test_vector6_…`, plus hardening cases for every rule, the schema data and the gate table |

There is no `__init__.py`: `graph_contracts` is a namespace package. The modules import only the standard library and each other, and a test checks that.

## Resolutions

1. **Contract document.** A contract is `ge-graph-contract-v1` with exactly `schema`, `graph_id`, `version`, `entry`, `nodes`, `edges`, `state`, `artifacts`, plus optional free-text `description`. `graph_id` must start with `GE-` (directive §6 asks GE artifacts to use unambiguous `GE-` naming). Every object in the contract has a closed field set. An unknown field, such as a node-level `state_writes` or a top-level `production_ready`, is `CONTRACT_SHAPE`.
2. **Typed I/O.** Every node must carry `input_schema` and `output_schema`. A missing one is `TYPED_IO`, checked before the general field-set check so that vector 3 names the typed-I/O rule. The schemas are a framework-neutral JSON-Schema subset: `type`, plus `properties`/`required`/`additionalProperties` on objects, `items` on arrays, `enum` on scalars, and `description`. `$ref` and anything else is rejected. Each edge must also type-check: the source's `output_schema` must satisfy the target's `input_schema`. That means every required input property is a required output property with an accepted schema, enums narrow, and a closed input needs a closed output with no extra properties.
3. **Gates and NO_SELF_SATISFIED_GATES.** `HITL_GATE` and `VERIFICATION_GATE` nodes carry a `gate` object: `guards` (the nodes whose output the gate judges) and `satisfied_by`, plus `boundary` (HITL) or `exact_head`, `session_independent`, `completion_state` (verification). A gate decision never travels on a graph edge; it comes from the gate's external principal. A contract violates `NO_SELF_SATISFIED_GATES` if any of these hold:
   - an edge, static or a route-map target, leads from a gate to itself (the "self-satisfying gate edge" of vector 2);
   - a gate guards itself;
   - `satisfied_by` is anything other than the principal in the gate table (`HITL` from stage 8.6, `INDEPENDENT_REVIEW` from stage 8.5), such as a node id, `SELF_CHECK` or `ENGINE`;
   - gates guard each other in a ring.
4. **Verification gate criteria.** These come from the gate table's 8.5 entry, not from code constants. A verification gate whose `exact_head` or `session_independent` is not `true`, or whose `completion_state` is not `REVIEW_COMPLETED` (for example `REVIEW_REQUESTED`), is `SELF_CHECK_NEVER_EQUALS_INDEPENDENT_REVIEW`. A HITL gate's `boundary` must be one of the 8.6 boundaries (`MERGE`, `ACTIVATION`, `RELIANCE`), else `HITL_BOUNDARY`. The schema's `gate_stages` maps each gate kind to its stage.
5. **Load-bearing gate table.** `gates.py` refuses to load a table that weakens 8.5 or 8.6, marks any stage satisfiable by node output, makes 8.12 (deployment/activation) anything but `HITL`, or lists stages out of order or incomplete. The validator always loads the table. A weakened table therefore stops validation with `GateTableError`; it never yields a more permissive validator.
6. **Routing.** Conditional edges may leave `ROUTER` nodes only. A router has exactly one route-map and no static edge. Its `route_key` must be a required `string` property of its `output_schema` with an `enum` equal to the route-map labels, so the route-map is total and typed. Any other node has at most one static successor. Fan-out to more than one successor goes through a router. A route-map naming an undeclared node, an undeclared static target or an undeclared `entry` is `NO_DANGLING_ROUTES` (vector 4). An empty route-map is `DETERMINISTIC_ROUTING`.
7. **Reachability.** Every node must be reachable from `entry`, the graph must have a terminal node (no outgoing edge), and every node must be able to reach a terminal. Cycles are allowed when they have an exit (for example a router's rework loop). Bounding the number of passes is §8.8 bounded recovery, which is a runtime control and outside this contract layer.
8. **State.** `state` is `{scope, store, keys, transitions}`. `scope` is `GRAPH_RUN`, `CROSS_RUN` or `TENANT`, and `store` must be `CONTROL_PLANE`. Keys are typed with the same I/O subset. State changes only through declared transitions `{id, node, writes}`. Each written key must be declared and must be a required property of the node's `output_schema` whose schema the key's schema accepts. Nodes have no other way to write state.
9. **Artifacts are evidence.** Artifacts are `{id, version (positive integer), media_type, produced_by, role}` and `role` must be `EVIDENCE`. A contract violates `ARTIFACTS_ARE_EVIDENCE` (vector 5) if any of these hold:
   - an artifact id, or any value beginning `artifact`, is the state store;
   - an artifact id is a state key;
   - a transition writes an artifact id;
   - an artifact's role is not `EVIDENCE`.
10. **Vendor neutrality.** The check runs right after the top-level type check and covers every key and string value except free-text `description` fields. The exemption is positional: it skips a `description` only when it is a field of a structural object (the contract envelope, a node, an io schema, or another contract object that allows free text) and its value is a string. The keys of a name map, which are io-schema `properties`, `state.keys` and route-map `routes`, are contract-chosen names. A property, state key or route label named `description` is therefore a name, and it and its whole subtree are scanned. A non-string `description` is scanned too. A value is a vendor-specific construct when either of these holds:
    - any of its alphanumeric segments, their camel-case parts, or two adjacent segments joined (so `vertex_ai` matches) equals a `vendor_tokens` entry (frameworks, SDKs, providers, model families, such as `adk`, `langgraph`, `openai`, `gpt`, `pydantic`);
    - a segment equals a `vendor_constructs` class name (`LlmAgent`, `RequestInput`, `StateGraph`, …).

    Either hit is `NO_VENDOR_LOCK_IN` (vector 6), wherever it sits. Ordinary words (`request_input`, `vertex`, `command`) do not match. This is fail-closed: a property named after a vendor (`openai_response`) is rejected too. Descriptions are never interpreted, so prose may mention vendors as design references.
11. **Order.** These checks run in a fixed order, and the first violation is reported:
    1. Top-level type, then the vendor scan.
    2. Envelope.
    3. Nodes: kind, then typed-I/O presence, then fields and ids, then I/O schema well-formedness, then gate and subgraph shape.
    4. Edge shape.
    5. Dangling routes and declared references.
    6. Gates: self-satisfaction, then review criteria, then HITL boundary.
    7. Routing.
    8. Reachability.
    9. Edge typing.
    10. Artifacts.
    11. State.

    Any unexpected exception during checking is reported as `INVALID` / `CONTRACT_SHAPE`. A contract the checks cannot evaluate is never valid.
12. **Subgraphs.** A `SUBGRAPH` node references another contract by `{graph_id, version}`. The reference is not resolved here, because resolution belongs to a later engine mission. A subgraph that references its own graph is `DECLARED_REFERENCES`.
13. **Criteria predicates.** `review_criterion_met` meets stage 8.5 only when all of these hold:
    - `state` is `REVIEW_COMPLETED`;
    - `reviewed_head == head`, and the head is non-empty;
    - the reviewer and builder sessions are distinct and non-empty;
    - `self_check` is `false`.

    `hitl_criterion_met` meets stage 8.6 only for `decided_by == "HITL"` with `APPROVED` on a listed boundary. Both predicates decide over presented evidence and record nothing.
