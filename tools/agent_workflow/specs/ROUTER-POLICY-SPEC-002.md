# Router Policy Specification 002

**Status:** DRAFT — A1 architecture, not yet HITL-approved
**Date:** 2026-10-19
**Author:** A1
**Basis:** Open Policy Agent (OPA) policy-engine model; Kubernetes admission-control architecture. Derived from research, not from any existing implementation.
**Supersedes:** ROUTER-POLICY-SPEC-001 (withdrawn — written post-hoc from implementation; no ground truth)
**Amendment 2026-10-19 (A1):** §3d row 1 removed — REVIEWER review *request* without waiver no longer mergeable. A request is not an approval; only an operator waiver authorizes merge.
**Amendment 2026-10-29 (HITL direction):** code the pipeline runs for agent runs, and the permission data it reads, is AUTHORITY. The runtime tool binding (`tools/agent_workflow/tool_selection/`), the MCP gateway the dispatcher launches for agent runs (`mcp_gateway/`), the authorization fabric (`mcp_auth/`), governed retrieval (`retrieval/`) and the three EPAP modules they import (`epap/ed25519.py`, `epap/links.py`, `epap/signing.py`) join the AUTHORITY family in `policy_tables.json`, their data files included (fabric policy, tool-selection matrix, seats, runtime registry, corpus registry, gateway tool catalog). Changing them is a HITL pipeline patch, never mission work. A test pins the gateway's import closure and that data as AUTHORITY, as the workflow import closure already is.
**Amendment 2026-10-31 (HITL direction):** the secrets boundary (`tools/agent_workflow/secrets_boundary/`) is AUTHORITY under the 2026-10-29 rule: the dispatcher and the MCP gateway import it, so it runs for every agent run.
**Amendment 2026-11-01 (HITL direction):** the evidence graph (`tools/agent_workflow/evidence_graph/`) is AUTHORITY under the 2026-10-29 rule: the MCP gateway imports it for its `trace` tool, so it runs for every agent run. It was built as mission work (`M-EVGRAPH-001`); changing it is now a HITL pipeline patch.
**A1 verdict 2026-10-19 ~19:15 CDT:** PASS. SPEC-002 router approved for merge. the builder's defense accepted (BLOCKED_PROTECTION row removed from §3d). CC's 12 findings fixed and committed (9ed5a7cb). the builder's S-1..S-3 implementation committed (11bbb7e7). Gomer ordered: "We have beat this router to death. It goes as is until it breaks and then we will debug it then. Push this to the main." PR opened for merge.

---

## 1. Architecture

The router is a **Policy Decision Point (PDP)** in the OPA sense. It does not enforce; it decides. Enforcement (merge, block, comment) is the Policy Enforcement Point (PEP) — the GitHub Actions workflow and the merge agent.

Like a Kubernetes validating admission webhook:
- It intercepts a PR event
- Evaluates the PR against policy tables (not code branches)
- Returns allow or deny with a reason
- **Fails closed**: any evaluation error, unknown input, or ambiguous state → deny

### Core principles (from OPA)

1. **Default deny.** Nothing is permitted unless a policy table explicitly allows it.
2. **Policy as data.** The mapping of "what files can a class touch" is a table. Adding a file type means editing the table, not the evaluator.
3. **Deterministic evaluation order.** Steps run in a fixed sequence. A later step cannot override an earlier denial.
4. **No invention in the evaluator.** The evaluator reads tables and applies rules. All judgment lives in the tables.

### Core principles (from K8s admission control)

5. **Intercept, don't poll.** The router runs on the PR event, evaluates once, records the decision bound to the exact head SHA it evaluated.
6. **Decision binds to input.** The decision is only valid for the exact (head SHA, file list) that was evaluated. If either changes, re-evaluate.
7. **Fail closed on infrastructure failure.** Cannot list files, cannot read the head SHA, API error → deny. Never "allow because we couldn't check."

---

## 2. Inputs

| Input | Source | Required |
|---|---|---|
| `head_sha` | PR head commit SHA, read before and after file listing | Yes |
| `file_list` | Full list of changed files (path + status + rename info) | Yes |
| `handoff_block` | Parsed handoff block from PR body (type, class, waiver ref) | Yes, but may be absent |
| `waiver_state` | Whether an operator waiver is active for this PR | Yes (boolean) |

If any required input is missing or cannot be obtained → deny (fail closed).

---

## 3. Policy Tables

### 3a. File families

Every file path maps to exactly one family by prefix/extension rules:

| Family | Definition | Rationale |
|---|---|---|
| `AUTHORITY` | Paths that define merge/waiver/review policy themselves | A PR cannot change the rules that govern it |
| `AGENT_POLICY` | Files that govern agent behavior (instructions, rules, prompts) | Changes require human review, never auto-merge |
| `TOOL_CONFIG` | Tool configuration that can execute code or inject instructions (`.github/`, `.cursor/`, `.vscode/`, `.devcontainer/`) | Can alter what the pipeline does |
| `CODE` | Source files, scripts, anything executable or importable | The actual implementation |
| `PROBE_EVIDENCE` | Test/probe output files in designated evidence directories | Verification artifacts, not production code |
| `INERT` | Documentation, data files, images — cannot execute | Safe for auto-processing |

**Rule:** If a path does not match any family → it is `CODE` (fail closed toward the most restrictive non-authority family).

### 3b. Class permissions

| Claimed class | Permitted families |
|---|---|
| `PLAN_ONLY` | `INERT` only |
| `DOC_WORKFLOW` | `INERT` + `PROBE_EVIDENCE` |
| `BOUNDED_IMPLEMENT` | All except `AUTHORITY` |
| `IMPLEMENT_ONLY` | All except `AUTHORITY` |
| Any other class, or missing class | **Nothing** (deny all) |

**Rule:** Unknown class → permits nothing. This is default-deny applied to the class dimension.

### 3c. Authority file list

Files in `AUTHORITY` (deny if touched, regardless of class or waiver):
- The waiver configuration file itself
- The merge standing-authority document
- The router's own policy tables (if stored in-repo)
- Any file that defines who can approve, waive, or merge

**Rule:** A PR touching `AUTHORITY` is denied. No waiver applies. This is not overridable.

### 3d. the merge agent merge allowlist

The merge agent may merge **only** when the router outputs `merge_allowed=true`. The router sets this true **only** for:

| PR type | Disposition | Condition |
|---|---|---|
| review request | Waived by operator | Valid waiver active |
| review request | Blocked protection | Waived PR waiting on transient merge state; the merge agent waits it out |
| Plan | Waived by operator | Valid waiver active; unwaived plans are human-merged |
| Docs-only | Acknowledged | No waiver needed |
| Closeout | Acknowledged | No waiver needed |

A REVIEWER review *request* without an operator waiver is not mergeable. A request is not an approval.

**Amendment 2026-10-19 (A1, per BUILDER defense):** The `BLOCKED_PROTECTION` row is removed from §3d. Rationale: the router has no merge-state input (§2); transient blocks are an enforcement concern for the merge agent, not a decision for the router. A transient branch-protection block on a `WAIVED` decision is handled by the merge agent, which retries while the current head still equals the decision's `head_sha`.

**Everything else → `merge_allowed=false`.** Specifically:
- Any breach type → false
- Any HITL-bound type → false
- Any agent-policy change → false
- Unknown block, unknown diff, unknown class → false
- Plan acknowledgments → false (plans are human-merged)

---

## 4. Evaluation Order

Steps execute in this fixed order. The first step that denies stops evaluation.

1. **Input integrity.** Read `head_sha`. List files. Re-read `head_sha`. If the two SHAs differ, or if file listing failed or is incomplete → `DIFF_UNKNOWN`, deny. Bind the decision to the verified SHA.

2. **Authority check.** If any file is in `AUTHORITY` → deny. No further evaluation. No waiver.

3. **Agent policy check.** If any file is in `AGENT_POLICY` → route to HITL (not a breach, not auto-mergeable). Record the HITL requirement. Stop.

4. **Class-diff check.** Look up the claimed `pr_class` in §3b. If unknown/missing → deny (permits nothing). If any file's family is not in the permitted set → deny (class mismatch).

5. **Waiver check.** Only if steps 1–4 passed. If a valid operator waiver is active and the class is waiver-eligible → mark as waived. A waiver cannot override steps 1–4.

6. **Output.** Compute the decision: PR type, disposition, exit code (0=pass, 1=deny), `merge_allowed` (per §3d), and the bound `head_sha`.

**Invariant:** No step may widen a denial from an earlier step. Waivers, acknowledgments, and special cases only apply if all prior steps passed.

---

## 5. Outputs

| Output | Values | Meaning |
|---|---|---|
| `pr_type` | String identifier | What kind of PR this is |
| `disposition` | String identifier | What should happen to it |
| `exit_code` | 0 or 1 | 0 = check passes (green), 1 = check fails (red) |
| `merge_allowed` | true/false | Whether the merge agent may merge this PR |
| `head_sha` | SHA string | The exact commit this decision applies to |

**Critical distinction:** `exit_code=0` does NOT mean "merge it." It means "the check passes." A PR can have `exit_code=0` and `merge_allowed=false` (e.g., a plan acknowledgment, or a HITL-required change). the merge agent only merges when `merge_allowed=true` AND the current head matches `head_sha`.

---

## 6. Invariants

These must hold for any implementation. A3 verifies each.

1. **No green breach.** If any file violates the class permission table, the result is deny (exit 1). No waiver, acknowledgment, or later step changes this.
2. **Waiver cannot override steps 1–4.** The waiver is only consulted after input integrity, authority, agent-policy, and class-diff checks pass.
3. **Merge allowed only per §3d.** `merge_allowed=true` only for the listed (type, disposition) pairs. Nothing else.
4. **Decision binds to SHA.** The output `head_sha` is the SHA that was verified (read before and after listing). the merge agent must refuse if the current head differs.
5. **Self-modification denied.** A PR touching `AUTHORITY` files is denied unconditionally.
6. **Unknown input denied.** Unknown block type, unknown class, unknown diff, missing inputs → deny. Default deny in all dimensions.
7. **No silent widening.** No code path may set `merge_allowed=true` except through the §3d table lookup.

---

## 7. Predicted Test Vectors

A3 runs each vector through the implementation and compares actual vs predicted. All must match.

| # | Input | Predicted pr_type | Predicted exit | Predicted merge_allowed |
|---|---|---|---|---|
| 1 | Valid block, `PLAN_ONLY`, inert files only, no waiver | Plan acknowledged | 0 | false |
| 2 | Valid block, `PLAN_ONLY`, includes a `.py` file, waiver on | Class mismatch | 1 | false |
| 3 | Valid block, `DOC_WORKFLOW`, touches `AGENTS.md`, waiver on | HITL required (agent policy) | 0 | false |
| 4 | Valid block, `DOC_WORKFLOW`, touches `.py` file, waiver on | Class mismatch | 1 | false |
| 5 | Valid block, `DOC_WORKFLOW`, inert files only, waiver on | Waived | 0 | true |
| 6 | Valid block, `BOUNDED_IMPLEMENT`, code files, waiver on | Waived | 0 | true |
| 7 | Any block, touches waiver config file | Authority violation | 1 | false |
| 8 | No block, inert files only | Docs acknowledged | 0 | true |
| 9 | No block, touches `.py` file | Deny (no block) | 1 | false |
| 10 | `STOP_ESCALATE` block, inert files | Escalation acknowledged | 0 | false |
| 11 | Valid block, `PLAN_ONLY`, touches `.cursor/rules/x.md` | HITL required (agent policy) | 0 | false |
| 12 | Head SHA changes during file listing | Unknown diff | 1 | false |
| 13 | Valid block, unknown `pr_class`, inert files only | Class mismatch (unknown class) | 1 | false |
| 14 | Valid block, missing `pr_class`, inert files only | Class mismatch (unknown class) | 1 | false |

---

## 8. Amendment Process

This spec is the source of truth. Changes require:
1. A1 proposes the amendment with rationale.
2. HITL approves.
3. A2 implements to the amended spec.
4. A3 verifies.

Code never amends the spec. If the code cannot satisfy the spec, A2 raises to A1.
