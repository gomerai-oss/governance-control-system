# GRAPH-ENGINE-RUNTIME-SPEC-001 — A2 implementation decisions

**Mission:** M-EPAP-GRAPHRUN-001, round 1
**Built from:** `missions/M-EPAP-GRAPHRUN-001/PLAN.md`, whose operative content is the spec, with the parent directive `governance/doctrine/L1-GRAPH-ENGINEERING-ARCHITECTURE-DIRECTIVE-001.md` (§§7–9, §11) as reference. It builds on `tools/agent_workflow/graph_contracts/`, which this package imports and does not change.

The code does not amend the spec. Where the plan leaves a choice open, the choice below fails closed and is recorded here so A1 or HITL can reject it.

This package is a library and a CLI. It runs a graph against a caller-supplied store directory, with caller-registered handlers and the caller's `now`. It calls no model and no network, runs no daemon or scheduler, adds no workflow and builds no dashboard. Running a graph here activates nothing on any live system and is not evidence of production operation (directive §8 non-equivalence rule); every `Outcome` and every `status` document says so in its `scope` field. Activation stays a separate HITL-gated decision.

## Layout

| File | Role |
|---|---|
| `engine.py` | `start`, `resume`, `status`, the node semantics, the replay check behind `CHECKPOINT_INTEGRITY`, and the CLI `python3 -m graph_engine.engine run\|resume\|status` |
| `state.py` | Run directories, canonical JSON, the hash-chained event log, the state scope (`STATE_TRANSITION_UNDECLARED`), artifact evidence |
| `checkpoint.py` | Checkpoint writing and verification, bounded recovery (`attempt`, `recovery_record`) |
| `handlers.py` | The handler registry, `Result`, and the typed-I/O check `io_problem` |
| `../tests/test_graph_engine.py` | Plan vectors P1–P9 as `test_vector1_…` to `test_vector9_…`, plus hardening cases |

There is no `__init__.py` and no `__main__.py`. `graph_engine` is a namespace package, imported as `import graph_engine.engine`. The modules import only the standard library, `graph_contracts` and each other, and a test checks that. Another test checks that none of GCS's `deny_terms` matches any file of the package or its test.

## Resolutions

1. **Start.** `start(contract, handlers, store, run_id, now, *, contracts=(), inputs=None, max_steps=10000)`. The five positional parameters are the plan's. The keyword-only ones carry what the plan requires but does not place: the contract set for `SUBGRAPH` (plan: "a caller-supplied contract set"), the run input (plan: "the same contract, handlers and inputs"), and a step bound (item 9). Before anything is written, these hold in order:
   - `run_id` matches `^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`, so it can never leave the store. A bad `run_id`, a `handlers` that is not a `Registry`, or an empty `now` raise `ValueError` / `TypeError`, because there is no run to record a refusal in.
   - If `<store>/<run_id>` already exists, the result is `REFUSED` / `RUN_EXISTS` and nothing is written.
   - `graph_contracts.validate.validate(contract)` must return `CONTRACT_VALID`. Otherwise the result is `REFUSED` with the validator's rule and detail.
   - The engine then runs its own preconditions:
     - every subgraph reference resolves in the contract set (`SUBGRAPH_UNRESOLVED`);
     - every resolved contract validates (the validator's rule);
     - references are acyclic (`SUBGRAPH_CYCLE`);
     - each `graph_id` appears in one version only, and the set holds no two different contracts under one key (`SUBGRAPH_AMBIGUOUS`);
     - every router's `route_key` is a declared state key (`ROUTE_STATE_UNDECLARED`, see item 5);
     - the registry holds exactly one handler per task node of the resolved contracts (`HANDLER_MISSING`, `HANDLER_UNEXPECTED`);
     - the input is plain JSON that satisfies the entry node's `input_schema` (`TYPED_INPUT`).

   Any refusal writes `<store>/<run_id>/refusal.json` and nothing else (P2). No handler is called. `resume` on a refused run returns its rule and runs nothing.
2. **Run directory.** A run is `contracts.json` (the resolved contract set, canonical JSON), `events.jsonl`, `checkpoints/NNNNNN.json`, `artifacts/<sha256>` and `children/`. A new run is written under `.starting-<run_id>` and renamed into place once its first checkpoint exists. A run directory is therefore either complete or absent. A stale `.starting-*` directory is an earlier start that never completed, and the next start of that run id removes it. The dot prefix can never be a run id.
3. **Handlers.** `Registry.register(graph_id, node_id, fn, *, actor, retries=0)`. Handlers are keyed by graph and node, because a child contract may reuse a parent's node ids. Only `DETERMINISTIC_TASK` and `AGENT_TASK` nodes have handlers, and the engine never calls one for a router, gate or subgraph node. A handler is called as `fn(value, state)`, where `value` is the node input and `state` is the run's scoped state. Both are fresh JSON copies, so mutating them changes nothing.
   - The handler returns the output, or `Result(output, writes=None, artifacts=None)`.
   - Output that is not plain JSON (a set, a tuple, NaN, a non-string key) is `TYPED_OUTPUT`.
   - Output that does not satisfy the node's `output_schema` is `TYPED_OUTPUT`. This check runs before the output is accepted.
   - The typed-I/O check follows the contract layer's JSON-Schema subset. `integer` excludes booleans and floats, enums compare by type and value, and `additionalProperties` defaults to `true` as in `graph_contracts.validate.accepts`.
4. **State only through declared transitions.** When a node is accepted, each key that a declared transition of that node writes takes the value the output carries for it. Nothing else writes state. A `Result.writes` entry is a handler's request to write. It is refused with `STATE_TRANSITION_UNDECLARED` when the key is not written by a declared transition of that node, which covers keys of another node, undeclared keys and, in a child run, the parent's keys. It is also refused when the value differs from what the declared transition carries. A state value outside its key's schema is `TYPED_STATE`. A refused write leaves state unchanged and ends the run `REFUSED`. It is not retried, because it is a contract violation, not a handler failure.
5. **Routers use declared state only.** A `ROUTER` has no handler. It reads the state key named by its route-map's `route_key` and takes the route-map edge with that label. The label is not taken from its input or from any handler. The route key must therefore be a declared state key (checked at start, `ROUTE_STATE_UNDECLARED`). An unset key is `ROUTE_STATE_UNSET`, and a value that is not a label is `ROUTE_LABEL_UNDECLARED`. The router's output is its input object with `route_key` set to the label, checked against its `output_schema`.
6. **HITL gates.** A `HITL_GATE` suspends the run as `AWAITING_HITL`. Only `resume(..., approval=record)` passes it. The record must meet all of these:
   - it has exactly `{gate, boundary, decided_by, decision}`;
   - `gate` names the gate the run awaits;
   - `boundary` is the gate's boundary;
   - `graph_contracts.gates.hitl_criterion_met` holds, so `decided_by` is `HITL` and `decision` is `APPROVED`.

   The engine never reads node outputs, state values or artifacts at a gate, so none of them can pass it (directive §9). Rejected records:
   - a missing record returns `HITL_APPROVAL_REQUIRED`;
   - an invalid record returns `HITL_APPROVAL_INVALID`;
   - a record of the wrong kind returns `GATE_RECORD_UNEXPECTED`;
   - a gate record passed to a run that awaits no gate returns `GATE_RECORD_UNEXPECTED`. A record never pre-approves a gate the run reaches later.

   In each of these cases the run stays where it is and **nothing is written**. A passed gate logs `GATE_PASSED` with the record, then accepts its input as its output (type-checked against its `output_schema`).
7. **Verification gates.** A `VERIFICATION_GATE` suspends the run as `AWAITING_VERIFICATION`. Only `resume(..., verification=record)` passes it. This keyword-only argument is added to the plan's `resume` signature, because the plan's `approval` is the HITL record and a verification record is a different thing. The record must meet all of these:
   - it has exactly `{gate, actor, completion_state}`;
   - `gate` names the awaited gate;
   - `completion_state` equals the gate's `completion_state` (`REVIEW_COMPLETED`), so `REVIEW_REQUESTED` never passes;
   - `actor` is non-empty and differs from the actor recorded in this run for **every** node the gate guards.

   The actor recorded for a node is the `actor` its handler was registered with, kept per node in the checkpoint and in each `NODE_ACCEPTED` event. A guarded node with no recorded actor, such as one not yet run, a router or a gate, cannot be verified independently, so the record is refused (`VERIFICATION_INVALID`). The same actor is `SELF_CHECK_NEVER_EQUALS_INDEPENDENT_REVIEW`, the contract layer's rule name for directive §9. A refused record changes nothing.
8. **Subgraphs.** A `SUBGRAPH` node runs its referenced contract as a child run in `<run>/children/<step>-<node id>`. The step is the parent's next step number, zero-padded to six digits, so names are unique and deterministic. The child has its own contract, state scope, event chain and checkpoints. Its entry input is the parent node's input, checked against the child entry's `input_schema` (`TYPED_INPUT`). The child's final output becomes the `SUBGRAPH` node's output, and the parent's transitions decide what of it reaches parent state.
   - A child suspended at a gate suspends the parent with the same status (`CHILD_AWAITING`). The parent's `resume` hands the record to the child.
   - A failed child fails the parent with a recovery record naming the child.
   - A refused child refuses the parent with the child's rule.
9. **Bounded recovery.** Contract nodes have a closed field set, and `graph_contracts/` may not change, so a node cannot declare its retry bound in the contract. The bound is therefore declared with the node's handler (`retries`, default 0, at most 100). A handler that raises an `Exception` is called again, at most `retries + 1` times in all. Each failure logs `NODE_ATTEMPT_FAILED` with the attempt number and the exception type name; messages are not logged, so the log stays deterministic and free of handler data. Past the bound the run ends `FAILED`, with a recovery record `{node, reason: RETRY_BOUND_EXHAUSTED, bound, attempts, errors, child, child_recovery, outcome}` in the `RUN_FAILED` event and the checkpoint. A graph cycle with an exit is legal in a contract, so a run is also bounded by `max_steps` accepted nodes (default 10000, recorded at start). Past that bound the run ends `FAILED` with `STEP_BOUND_EXHAUSTED`. Nothing in the engine loops without a bound. A `BaseException` that is not an `Exception`, such as an interrupt, is not a handler failure. It propagates and leaves the run at its last checkpoint.
10. **Events.** Each event is one canonical JSON line: sorted keys, compact separators, UTF-8, no NaN. Every event has `seq` (from 1), `prev` (the SHA-256 of the previous line, or 64 zeros) and `at` (the caller's `now`). The types are `RUN_STARTED`, `NODE_ACCEPTED`, `NODE_ATTEMPT_FAILED`, `GATE_AWAITING`, `GATE_PASSED`, `CHILD_AWAITING`, `RUN_COMPLETED`, `RUN_FAILED` and `RUN_REFUSED`. The event type is the `type` field. `EventLog.append` takes it as a positional-only argument, so a payload field may have any other name: `NODE_ACCEPTED` records the node's kind as `kind`. A payload that tries to set `seq`, `prev`, `at` or `type` raises an error. `NODE_ACCEPTED` carries the node, its kind, step, actor, the digests of the output and of the new state, the keys written, the evidence entries and the next node. Values themselves are kept in checkpoints, not in the log. `RUN_STARTED` carries the digest of `contracts.json` and of the input.
11. **Checkpoints.** A checkpoint is written when a run starts, after every accepted node, and on every suspension and terminal status. A checkpoint has exactly the `checkpoint.BODY_FIELDS` plus `digest`, the SHA-256 of the canonical body. Among them are the state, the position (the next node), the value flowing into it, the head of the event chain and the event count. Files are written atomically (temporary file, then rename). A crash can therefore leave only a `*.tmp` file, which is ignored as never committed.
12. **`CHECKPOINT_INTEGRITY`.** Before `resume` runs anything it verifies the run. Every check below must pass, or the result is `REFUSED` / `CHECKPOINT_INTEGRITY` and nothing runs or is written (P5):
    - the event log is canonical, contiguous and hash-chained;
    - `contracts.json` matches the digest in `RUN_STARTED`, and every contract in it validates;
    - the checkpoint files run contiguously from `000001.json`;
    - each checkpoint is canonical, its digest verifies, it links to its predecessor's digest, and its chain head is the log's head at its event count;
    - every checkpoint equals a replay of the event log up to its event count, in status, position, child, actors, evidence, step, rule, detail, recovery and step bound, and by digest in state, carry and output. A checkpoint that is edited and then resealed with a new digest is still caught;
    - every child run under `children/` verifies the same way.

    `status` makes the same verification and reports `integrity: FAILED` rather than a status it cannot vouch for. The chain is an integrity check, not a signature. It detects edits and loss; it does not authenticate a writer who rebuilds the whole chain.
13. **Uncommitted event tail.** Events between the last checkpoint and a crash were never committed. On resume they must still verify as part of the chain, and they are then dropped before the run continues. The node they describe runs again. Re-running it reproduces exactly those events, so an interrupted run that is resumed is byte-identical to an uninterrupted one (P4). This truncation is the one exception to append-only. It removes only events that no checkpoint commits.
14. **Determinism.** Everything written is a function of the contract set, the handlers' return values, the inputs, the gate records and `now`. Nothing is clock-, random-, PID- or path-dependent. Resuming an interrupted run writes no "resumed" event, and the same `now` gives byte-identical events and checkpoints (P4).
15. **Artifacts are evidence.** A handler may return artifacts only for ids that the contract declares as produced by that node (`ARTIFACT_UNDECLARED` otherwise). Content (`bytes` or `str`) is stored as `artifacts/<sha256>`, and the evidence entry `{id, version, media_type, node, step, digest, size}` is recorded in the `NODE_ACCEPTED` event and the checkpoint. The artifact `version` is the contract's declared version. Artifacts never enter state, and the engine never reads them for a decision.
16. **Status surface.** `status(run_id, store)` and `python3 -m graph_engine.engine status --store S --run-id R` produce one canonical JSON document. It holds `run_id`, `graph_id`, `version`, `status`, `position`, `child`, `state`, `step`, `chain_head`, `event_count`, `checkpoints`, `rule`, `detail`, `recovery`, `integrity` and `scope`. A child run's status is read with its parent's `children/` directory as the store.
17. **CLI.** `run` takes `--store --run-id --now --handlers MODULE:ATTRIBUTE --contract FILE [--contracts FILE]... [--input FILE] [--max-steps N]`. `resume` takes `--store --run-id --now --handlers MODULE:ATTRIBUTE [--approval FILE] [--verification FILE]`. `--handlers` imports the named module, which is the caller's code, and takes the `Registry` it names, calling it first if it is a factory. JSON files are read strictly (`graph_contracts.schema.read_file`: no duplicate keys, no floats). The exit code is 0 for `COMPLETED` or a suspension with no rule, 1 for anything else, and 2 for usage errors.
