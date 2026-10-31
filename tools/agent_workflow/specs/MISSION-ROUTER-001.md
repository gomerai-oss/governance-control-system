# MISSION-ROUTER-001: A1 → A2 → A3 mission router

**Status:** DRAFT, built by A3 at HITL direction 2026-10-19, not yet HITL-approved
**Amendment 001 (2026-10-20, HITL direction):** A1 is a human seat. A HITL login may open and push the A1 plan PR and is accepted as the A1 actor (§5a); the a1 App remains an accepted A1 actor while it is `ACTIVE` in the registry. A2 and A3 are unchanged.
**Amendment 002 (2026-10-22, HITL direction, "option 2"):** a stack lands as a whole. Its passed missions collect on
the stack branch `stack/<STACK-ID>`, and nothing reaches `main` until every mission in the stack has passed; then the
whole stack lands in one merge (§2). One `/mission approve` covers every plan in the stack. PARALLEL and CHAINED both follow the
ADD protocol: nothing waits for HITL mid-stack; blockers are recorded (A3 verdict `BLOCKED`, §3), and the stack ends
either on `main` or blocked with a review matrix. `"landing": "per-leg"` keeps the earlier behavior for a stack.
**Amendment 003 (2026-10-23, HITL-approved pipeline patch):** a refused PR for the A2 or A3 stage the mission waits
on counts as a failed agent run. The router records the refusal on the tracking issue as a failure and deletes the
stage branch, so the agent runs again with the reasons; after 3 failures in a row the stage is `BLOCKED` (§5). An A2
build may change no files: A2 then records blockers instead of building, and A3 confirms them.
**Amendment 004 (2026-10-24, HITL-approved pipeline patch):** a plan is checked before approval for files no mission
can deliver: each `deliverables` entry and each `build_scope` entry without a wildcard must be inside `build_scope` and
not SPEC-002 `AUTHORITY` (§3, §5). And HITL's `/mission retry` on a blocked mission's tracking issue reopens that
mission alone: A3 reviews the same build again after a `BLOCKED` verdict, or A2 gets one more round after a FAIL in the
last round. The missions that passed stay passed, and the stack lands only when every mission has passed (§4, §6).
**Amendment 005 (2026-10-24, HITL direction, HITL-approved pipeline patch):** the L1 capture route. L1 artifacts are
the starting point of new development, not mission work: HITL's DRAFT captures enter the L1 capture queue
(`change-specs/CONTROL_MATRIX/L1-CAPTURE-QUEUE.md`) without a plan, an A2 build or an A3 review, and the router merges them into
`main` (§5d). The route only appends DRAFT entries to that one file, opened and pushed by HITL; it promotes nothing, and
filing captures into the matrices stays mission work. A capture is not a pipeline violation.
**Amendment 006 (2026-10-24, HITL direction, HITL-approved pipeline patch):** a plan may name the `model` for A2 and A3
next to the `runtime` (§3). HITL's approval binds it like the rest of the plan; the Mission Agent workflow starts the
runtime with that model (MISSION-DISPATCH-001). Without it the runtime uses its own default, as before.
**Amendment 009 (2026-10-25, HITL direction, HITL-approved pipeline patch):** the capacity queue is removed
(Amendment 007 is superseded in full). No timer is consulted: jobs start in approval order, and a run whose
runtime is out of compute is an ordinary failure, counting toward the 3 failures that block a stage for HITL
review (MISSION-DISPATCH-001 §4). Only money — actual meter exhaustion, as failed runs — stops production.
**Amendment 008 (2026-10-24, HITL direction, HITL-approved pipeline patch):** a plan may name the `branch` its work
finally merges into (§3), so a team whose `main` only humans may merge into can stage passed missions on a branch
for its own review. The branch must be one HITL lists in `config.json` `landing_branches` and has already created;
the router never creates it. Without `branch` a mission lands on `main`, as before. HITL's approval binds the branch
with the rest of the plan, so it cannot change mid-mission. A mission starts from its branch and its PASS (or its
stack's landing) merges into it; all missions of one stack name the same branch. Everything this spec says of `main`
as a mission's destination holds for that branch. Moving work from that branch to `main` is not mission work.
**Code:** `tools/agent_workflow/mission_router/` · **Workflow:** `.github/workflows/mission-router.yml`
**Tests:** `tools/agent_workflow/tests/test_mission_router.py`

The mission router carries each mission through its roles. It merges each stage's PR and alerts the role that acts next.
It is a handler and merger, not a judge: it checks that a PR is the one the approved plan said would come next,
from the role the plan assigned, touching only what the plan allowed. Whether the work is good is A3's call.

**Nothing reaches `main` until A3 passes it.** Every stage merges into the mission's own integration branch. The A3 PASS
is the only merge out of it, and it carries the whole mission at once: plan, build and every review record. It merges
into the mission's landing branch: `main`, or, for a stack that lands as a whole, the stack branch, which lands on
`main` only when the whole stack has passed. Missions that never pass never touch `main`. A plan may name another
branch HITL allows instead of `main` (Amendment 008, §3); the same then holds for that branch.

**Identity is the foundation.** Every agent acts only as its own GitHub App. The router accepts a stage PR only when
GitHub itself shows that the agent the approved plan assigned to that role opened the PR and made every push to its
branch (§5a). A human account, a shared login or a different app cannot act in any agent role. The one exception is
A1: that seat is held by HITL, who acts as himself (§5a).

**The router owns `main`'s required check.** It publishes `route-handoff-block` on every open PR into `main`. Only a
mission whose A3 PASS cleared every routing check gets a success (§5b). This replaces the legacy PR handoff router
(`pr-handoff-router.yml`), which is retired.

## 1. Flow

| Stage | Who opens the PR | Head branch | Base | The router then |
|---|---|---|---|---|
| Plan | A1 — HITL in person, or the a1 App while it is `ACTIVE` | `mission/<ID>/a1` | `mission/<ID>/integration` | Creates the integration branch if needed (and retargets an A1 PR opened against `main`); merges after HITL approves the exact commit; alerts A2 |
| Build, round N | A2 | `mission/<ID>/a2-rN` | `mission/<ID>/integration` | Merges; alerts A3 with the commit to review |
| Review FAIL, round N | A3 | `mission/<ID>/a3-rN` | `mission/<ID>/integration` | Merges the verdict record; alerts A2 for round N+1 |
| Review BLOCKED, round N | A3 | `mission/<ID>/a3-rN` | `mission/<ID>/integration` | Merges the verdict record; the mission is `BLOCKED`, recorded for HITL review |
| Review PASS, round N | A3 | `mission/<ID>/a3-rN` | the landing branch: `main`, or `stack/<STACK-ID>` | Merges the mission there (into `main`: HITL first where §6 says); the mission is done |
| Landing (stacks that land as a whole) | an A3 agent of the stack, via the Mission Agent workflow | `stack/<STACK-ID>` | `main` | When every mission in the stack has passed: checks the stack and merges it into `main` in one merge (HITL first where §6 says) |

A FAIL in the last of `max_rounds` is recorded the same way as a BLOCKED verdict: the mission is `BLOCKED`.

**Alerts.** One tracking issue per mission, `[mission] <ID>`, opened by the router. Mission issues carry only
`mission*` labels for the agent stages, so the legacy inner-loop orchestrator (which polls `agent:handoff-ready` and
`agent:needs-review` and starts fixed tools per label) never picks up a mission:

| Mission stage | Issue labels | `target_actor` |
|---|---|---|
| `AWAIT_A2` | `mission`, `mission:stage-a2` | `A2` |
| `AWAIT_A3` | `mission`, `mission:stage-a3` | `A3` |
| `HALTED` | `mission`, `mission:halted`, `agent:needs-hitl` | `HITL` |
| `DONE` | `mission`, `mission:done` (issue closed; in a stack that lands as a whole, once the stack lands) | `NONE` |
| `CANCELLED` | `mission`, `mission:cancelled` (issue closed; in a stack, as for `DONE`) | `NONE` |
| `BLOCKED` | `mission`, `mission:blocked`, `agent:needs-hitl` (open; in a stack, closes when the stack lands or HITL closes the stack's review) | `HITL` |

Each stack that lands as a whole also has a tracking issue, `[stack] <STACK-ID>`, labelled `mission`, `mission:stack`
and its status: `mission:stack-active` while it runs or is ready, `mission:done` (closed) when it landed, and
`mission:blocked` with `agent:needs-hitl` when it is blocked. Its body is the review matrix (§2).

The body's handoff block also names `assigned_agent` and `assigned_github_login`, the identity the router will accept
for the next PR, and `assigned_runtime`. Each stage change posts one comment with the branch, base and, for A3, the
exact SHA to review.

**Finding the tracking issue.** The issue carries the mission's cancel and the Mission Agent's failure records, so
the router never guesses it. When it opens the issue, it posts `Tracking issue for mission <ID>: #<N>` with the
marker `<!-- mission-router:tracking-issue:<N> -->` on the A1 plan PR. Each sweep reads the number from, in order:

1. `config.json` `tracking_issues`, which records the issues of missions started before the marker existed;
2. the router's marker on the plan PR;
3. the repository's issue listing, as a fallback only: a number found there is marked on the plan PR.

It then reads that issue directly by number, which does not depend on the listing. If the number does not lead to an
open or closed issue titled `[mission] <ID>` opened by the router's bot, the mission waits that sweep, logged, and
nothing is created; HITL corrects the record. With no number from any source, the router opens the issue, but never
for a mission that is already `DONE` or `CANCELLED`. On 2026-10-22 the issue listing came back without any mission
issue for about two hours: the router of that day opened 24 duplicate issues, read a cancelled mission as active, and
the Mission Agent restarted a failed run twice. Vectors 40–43 cover it.

**Starting the agent.** When that comment is first posted for an `AWAIT_A2` or `AWAIT_A3` stage whose role names a
`runtime`, the router starts the Mission Agent workflow (`mission-agent.yml`) on `main`. That workflow starts the
assigned runtime and opens the stage PR as the assigned agent's App (MISSION-DISPATCH-001). The request is a nudge
only: the workflow derives everything itself and also runs on a schedule, so a failed request is logged, not fatal.

## 2. Stacks: PARALLEL and CHAINED

HITL designs stacks at runtime. The router reads each mission's stack membership from its manifest; nothing about a
stack is hard-coded.

### 2a. A stack lands as a whole (Amendment 002)

Unless its plans say `"landing": "per-leg"` (or `config.json` `per_leg_stacks` lists it), a stack lands as a whole:

1. **One approval.** Every plan in the stack is opened as its own A1 PR, as for any mission. The router posts one
   approval request listing every plan and its exact commit, with a fingerprint of that set
   (`sha256("mission-stack-v1\n" + sorted "<mission> <commit>" lines)`, first 40 hex). HITL approves the whole stack
   once: `/mission approve <fingerprint>` on any of those PRs. The approval covers each plan at its listed commit,
   including later CHAINED plans that merge only when their turn comes. A new push to any plan, or a new plan in the
   stack, changes the fingerprint and needs a new approval. Only plans opened by an actor who may hold A1 (HITL in person,
   or the assigned a1 bot) count towards a stack, so no other identity can change its fingerprint.
2. **The stack branch.** The first plan to start creates `stack/<STACK-ID>` from `main`. Each mission's integration
   branch starts from it, and each A3 PASS merges into it. Only the router (and HITL) may update it.
3. **CHAINED:** loop N+1 starts only when loop N has passed. Its still-empty integration branch is fast-forwarded to the
   stack branch, so it builds on loop N's result. A plan branch may be behind its integration branch: the integration
   branch then only holds what is already on the stack branch, and the plan adds files under its own mission only.
4. **PARALLEL:** the loops run side by side, with no overlapping `build_scope`.
5. **Landing.** When every mission has passed, the router starts the Mission Agent workflow, which opens the PR from
   the stack branch into `main` as an A3 agent of the stack (the router's own token cannot approve a PR it opened).
   The router checks it (§5c) and merges the whole stack in one merge. The missions' issues and the stack's issue close.
6. **Blockers (ADD).** Nothing waits for HITL mid-stack. A3 records a blocker with a `BLOCKED` verdict (§3); a FAIL in
   the last allowed round, and an agent run that failed 3 times in a row (MISSION-DISPATCH-001 §4), are recorded the
   same way. In an **CHAINED** the first blocker blocks everything: nothing more in the stack starts or merges. In an
   **PARALLEL** the other loops carry on, and the stack is blocked once every loop has finished. A cancelled mission counts
   as a blocker. A blocked stack never lands.
7. **Review matrix.** The stack's issue shows every loop: its dependencies, result, PR and time, and a Blockers section
   with what, where and when for each one. A blocked stack stays whole, its issues open, until HITL closes the
   stack's issue after the review. Then its missions' issues close and the stack id cannot start again: the corrected
   plans restart as a new stack, under one new approval.

The files of a stack that has not landed stay reserved: no other mission may start on an overlapping `build_scope`
until the stack lands or its review is closed. A stack id that landed cannot be reused. All missions in a stack share
one kind.

### 2b. Kinds

- **PARALLEL (parallel stack):** unrelated missions run side by side. The router enforces that they really are
  unrelated: a mission cannot start while its `build_scope` overlaps the scope of any active mission (started, not
  yet passed, including halted ones). The overlap test is conservative: two scopes overlap when one's literal leading
  path segments are a prefix of the other's. It can report a false overlap but never misses a real one. An PARALLEL mission
  may not declare `depends_on`.
- **CHAINED (chained stack):** a mission lists the missions whose results it needs in `depends_on`. It
  does not start until every dependency has passed A3 and landed on its landing branch (the stack branch, or `main`
  for a per-leg stack). Its integration branch then starts from there: the router fast-forwards a still-empty
  integration branch to it. A dependency cycle is rejected. If a dependency halts or is blocked, its dependents wait.

Because only passed missions reach a landing branch, a downstream mission only ever builds on reviewed upstream results.

## 3. Mission files

**Manifest** `missions/<ID>/mission.json`, added by the A1 PR. `<ID>` matches `[A-Z0-9][A-Z0-9-]{2,63}`.

```json
{
  "schema": "mission-v1",
  "mission_id": "M-EXAMPLE-002",
  "title": "What the mission delivers",
  "roles": {
    "A1": {"agent": "a1"},
    "A2": {"agent": "a2", "runtime": "claude-code"},
    "A3": {"agent": "a3", "runtime": "cursor-cli"}
  },
  "build_scope": ["tools/example/**", "docs/example/*.md"],
  "max_rounds": 5,
  "stack": {"id": "S-EXAMPLE", "kind": "CHAINED"},
  "depends_on": ["M-EXAMPLE-001"]
}
```

- `roles` is the HITL's role assignment for this mission. Any agent may hold any role, with one rule: A3 must be a
  different agent from both A1 and A2, so the review is independent of the plan and of the build. An `agent` is a
  name from `config.json` `agents`, which maps it to that agent's GitHub App bot login. The manifest cannot name a
  login, so a plan can never assign a role to a human account or to an identity outside the registry. For A1 the
  named agent is the role of record; the seat itself is held by HITL, who may open and push the plan PR as his own
  login (§5a). If the a1 identity is retired in the registry, HITL is the only A1 actor.
- `runtime` (A2 and A3 only, optional): `claude-code` or `cursor-cli`, the program the Mission Agent workflow runs
  for that role. Without it nothing starts the agent automatically; it must be started by hand.
- `model` (A2 and A3 only, optional, Amendment 006; needs a `runtime`): the model that runtime uses for the role. For
  `claude-code` one of `opus`, `sonnet`, `haiku`, `fable`, `claude-opus-5-5`, `claude-sonnet-5-5`, `claude-haiku-5-5`,
  `claude-fable-5-1`, so a typo makes the plan invalid. Cursor lists its models per account (`agent models`), so for
  `cursor-cli` only the form is checked: one lowercase name of letters, digits, `.` and `-`, up to 64 characters,
  never starting with `-`. A name the runtime does not know fails the agent run, which is recorded like any failed run.
  Without it the runtime uses its own default. The stage comment names the model.
- `checks` (optional): up to 10 shell commands of up to 500 characters each. The Mission Agent workflow runs them,
  isolated, on the commit A3 reviews, and gives A3 the results as evidence (MISSION-DISPATCH-001 §3f).
- `build_scope`: repo-relative globs. `*` stays inside one path segment and `**` spans any depth. Matching is
  case-sensitive. A glob may not start with a wildcard or cover `.github/` or `missions/`.
- `max_rounds`: 1–10, default 5.
- `stack` (optional): `kind` is `PARALLEL` or `CHAINED`; `landing` (optional) is `stack` (the default: the stack lands as a
  whole, §2a) or `per-leg` (each mission lands on `main` when it passes). `depends_on` (optional, CHAINED only): up to 20
  mission ids.
- `deliverables` (optional, Amendment 004): up to 200 exact repo-relative file paths (no wildcard) that the plan says
  A2 creates or changes. Before approval the router refuses a plan in which any of them is outside `build_scope` or
  SPEC-002 `AUTHORITY`, since no A2 PR could ever deliver it. It does not require A2 to deliver them; that comparison
  is A3's.
- `branch` (optional, Amendment 008): where the mission's work finally merges, instead of `main`. It must be listed
  in `config.json` `landing_branches`, which only a HITL-merged pipeline patch can change; a plan naming any other
  branch is refused. It must already exist: until HITL creates it, with its protection, the plan waits and the router
  prepares nothing. The router never creates it. The name is a plain branch name of up to 200 characters, each part
  starting with a letter or digit, without `..`, not `HEAD`, not ending in `.lock` or `.`, and never under `mission/`
  or `stack/`. With `branch`:
  - the integration branch starts from that branch, the PASS PR targets it, and every diff check (§5, §6) compares
    against it. A1 branches the plan from it: a plan carrying commits that are not on it is refused (§5, A1 files);
  - a stack that lands as a whole starts its stack branch from it and lands on it (§2a, §5c);
  - every mission of one stack names the same branch (or none): a plan that differs from another plan of its stack
    is refused, and a stack whose plans disagree is halted. An CHAINED dependency must have landed where the mission
    builds;
  - HITL's approval binds it with the rest of `mission.json`, so it cannot change mid-mission: a different branch
    needs a new plan and a new approval.
- Unknown keys are rejected.

The router reads the approved manifest at A1's merge commit, which nothing can rewrite.

**Verdict** `missions/<ID>/reviews/round-<N>.json`, the only file an A3 PR adds:

```json
{"schema": "mission-verdict-v1", "mission_id": "M-EXAMPLE-002", "round": 1,
 "verdict": "FAIL", "reviewed_sha": "<40-hex integration commit A3 was handed>",
 "summary": "...", "findings": [...]}
```

`verdict` is `PASS` (the build matches the plan), `FAIL` (it does not, and A2 can fix it: the findings go back to A2)
or `BLOCKED` (something A2 cannot fix kept the plan from being completed). A `BLOCKED` verdict must list each blocker
in `findings`. `summary` is at most 4,000 characters; `findings` at most 50 texts of at most 2,000 characters.

## 4. State

The router stores no state. Each run finds missions from their `mission/*` branches and open PRs. For each one, it
replays the merged stage PRs, oldest first, through this grammar:

```
A1  ( A2_r  A3_r[FAIL] )*  [ A2_r  [ A3_r[PASS | BLOCKED] ] ]        r = 1, 2, ... ≤ max_rounds
```

A1, A2, FAIL and BLOCKED PRs must have merged into the integration branch, and only a PASS into the landing branch. A
history that breaks the grammar halts the mission with the reason. So does a merge by anyone other than the router
(`github-actions[bot]`) or a HITL login (`config.json`). A FAIL at `max_rounds` makes the mission `BLOCKED`. HITL may
merge a stage PR by hand, and the router follows it.

**A HITL retry reopens a blocked mission (Amendment 004).** A `/mission retry` that HITL posts on the tracking issue
after a block reopens it, once:

- after a `BLOCKED` verdict in round r: `AWAIT_A3` in round r+1, on the integration head (A2's unchanged build plus the
  round r verdict). A3 reviews the same build again, with the plan's checks run again;
- after a FAIL in the last allowed round: `AWAIT_A2` in round r+1, one more round for A2.

Each reopening takes its own retry: a retry counts only for a block that merged before it. Rounds stop at 10, the most
the router reads back. Once HITL has closed the review of a stack, a retry no longer reopens its missions. History that
already follows a retry is replayed as it merged. A stage recorded as blocked after 3 failed runs is retried as before
(§6).

Before A1 merges, the integration branch must hold nothing that is not already on `main`. After that, it must sit
exactly at the last stage merge. If anything else moved it, the mission halts.

## 5. Checks on an open stage PR (all must hold)

| Check | A1 | A2 | A3 |
|---|---|---|---|
| Same-repo branch, not a fork; not a draft (drafts wait) | ✓ | ✓ | ✓ |
| Opened by the assigned agent's GitHub App (account type `Bot`, exact login), and that identity is `ACTIVE` | ✓* | ✓ | ✓ |
| Every recorded update of the head branch was made by that same identity, and one of them produced the head SHA (§5a) | ✓* | ✓ | ✓ |
| The mission is waiting for exactly this role and round | ✓ | ✓ | ✓ |
| Base branch as in §1 | ✓ | ✓ | ✓ (by verdict) |
| Files | Only under `missions/<ID>/`, not `reviews/`; adds `mission.json`. Every `deliverables` entry and literal `build_scope` entry is inside `build_scope` and not `AUTHORITY` (Amendment 004) | Every path (both sides of a rename) inside `build_scope`, not under `missions/`, not SPEC-002 `AUTHORITY`; may be none (Amendment 003) | Exactly one added file, the round's verdict, on top of the reviewed commit |
| Up to date with the integration branch | (may be behind; §2a) | ✓ | Contains the reviewed commit |
| Integration branch untouched outside the router | ✓ | ✓ | ✓ |
| Stack: no scope overlap with active missions or unlanded stacks; CHAINED dependencies passed; no cycle; one kind per stack; stack id not landed or closed; CHAINED stack not blocked | ✓ | | |
| Verdict parses, round matches, `reviewed_sha` = the commit A3 was handed | | | ✓ |
| File list complete (under GitHub's 300-file comparison cap) | ✓ | ✓ | ✓ |

\* A1 only: a HITL login is accepted in place of the App bot for these two checks (§5a).

A PR that fails gets one comment listing every failed check, plus `agent:blocked`. A PR held for a dependency gets
one comment saying what it is waiting for. A new push is re-checked.

**A refused stage PR is a failed run (Amendment 003).** When the refused PR is for the A2 or A3 stage the mission is
waiting on, and its head is that stage's branch in this repository, the router also:

1. posts one comment per refused head on the tracking issue, with the reasons on its first line and the marker
   `<!-- mission-dispatch:failed:<role>:<round> -->`, so it counts toward the 3 failures of MISSION-DISPATCH-001 §4;
2. then deletes the stage branch, which closes the PR. The Mission Agent workflow, which never overwrites a branch,
   can then run the agent again, and hands it the reasons.

Without a readable tracking issue nothing is deleted. A refused PR for any other stage (a stale round, a PR from
another branch or a fork) keeps its branch and records nothing. Before this, a refused A2 PR left its branch in
place: the workflow treated the stage as handed in and never ran the agent again, and nothing was recorded as
blocked (CCSYNC-CHAINED-001, 2026-10-23).

Every merge is pinned to the SHA that was checked (`PUT /pulls/{n}/merge` with `sha`). A push that lands after the
check makes the merge fail, and the new commit is checked on the next sweep.

### 5a. Identity

- **Who may act.** `config.json` `agents` maps each agent name to its GitHub App bot login
  (`agent-a2[bot]`, …). An agent may act only while the identity registry `config.json` names on `main` lists it as
  `ACTIVE`. Suspending or retiring an identity there stops it at the next sweep. An unreadable registry stops every
  agent.
- **The A1 exception (Amendment 001).** A1 is a human seat: the plan is HITL's own act. For the A1 stage only, the
  router accepts a PR opened by a `hitl_logins` user account, and an A1 branch whose recorded updates are all by
  that HITL login or by the assigned a1 bot. HITL needs no registry status to act as A1; retiring the a1 identity
  leaves HITL as the only A1 actor. The exception exists for no other role: a HITL login opening or pushing an A2
  or A3 branch is rejected like any other foreign identity.
- **Who opened the PR.** The PR author must be the assigned bot login and GitHub must report the account as a `Bot`.
  No user account can hold a `[bot]` login.
- **Who pushed the branch.** GitHub records every update to a branch, with its actor and SHAs, in the repository
  activity log (`GET /repos/{owner}/{repo}/activity?ref=refs/heads/<branch>`). Every recorded update to the stage
  branch must be by the assigned bot — for the A1 branch, by the assigned bot or a HITL login. A push by anyone else
  is rejected, including HITL on an A2 or A3 branch and other agents, so an agent must update its own branch. If
  GitHub has not yet recorded the push that produced the head SHA, the PR waits. A branch with more than 300
  recorded updates is rejected, because they cannot all be verified.
- **Who approves.** `/mission approve <sha>` counts only from a `hitl_logins` user account. This is meaningful only
  while agents never run with the HITL's own GitHub credentials. The laptop orchestrator gives each agent its role's
  installation token and denies it the HITL's credential stores.

### 5b. The required check `route-handoff-block`

Branch protection on `main` requires `route-handoff-block` from GitHub Actions. The router publishes it as a check run
on the head commit of every open PR into `main` during each sweep. It republishes only when the result changes.

| PR into `main` | Check |
|---|---|
| A3 PASS that clears every check in §5, or a landing PR that clears §5c | `success`, published just before the router merges it |
| A3 PASS held for HITL approval (§6) or waiting on a push record | in progress (pending) |
| Any stage PR the router rejects | `failure`, with the reasons |
| A capture PR that clears §5d | `success`, published just before the router merges it |
| A capture PR held by a mission that may change the queue, or waiting on a push record | in progress (pending) |
| A capture PR that fails §5d | `failure`, with the reasons |
| Anything else that is not a mission stage PR | `failure`: "Only missions that passed A3 merge into `main`" |

Only the repository admin (HITL) can merge a PR with a failing required check. That is the deliberate path for
changes outside the mission flow.

The router publishes the check, and approves the PRs it merges, the same way on PRs into every branch in
`config.json` `landing_branches` (Amendment 008), so their protection can require it as `main`'s does.

### 5c. The landing PR (all must hold)

From `stack/<STACK-ID>` into `main` (or the stack's `branch`, Amendment 008), same repository, not a draft; opened by the bot of an A3 agent of the stack's
missions; its head is the stack branch's head; every recorded update of the stack branch was made by the router or a
HITL login; and every mission in the stack has passed (otherwise it waits, or is rejected if the stack is blocked,
halted or already landed). A diff with SPEC-002 `AUTHORITY` or `AGENT_POLICY` files other than the stack's own
`mission.json` files, or too large to list, waits for HITL (§6). The router publishes `route-handoff-block` on it as on
any PR into `main`.

### 5d. The L1 capture route (Amendment 005; all must hold)

Set in `config.json` as `l1_capture`: `{"path": <the queue file>, "branch_prefix": "capture/"}`. Without it the route
is off and a capture PR is "not a mission". A PR into `main` from a branch starting with the prefix is a capture PR:

- from a branch in this repository, not a draft (a draft waits);
- opened by a `hitl_logins` user account, and every recorded update of its branch made by a HITL login;
- its diff against `main` changes exactly one file, the queue, which must already exist on `main` (status `modified`);
- the queue at the PR head is the queue on `main` with text appended, and nothing before it changed. A capture
  written before another capture landed is refused until its branch is updated from `main`;
- the appended text is at most 20,000 characters, has at least one `### CAPTURE-<yyyy>-<nnn>` entry, and every status
  line in it is `- **Status:** DRAFT`.

It waits while any unfinished mission that holds its files (§2a) has a `build_scope` that may include the queue, so a
capture never races the mission that files the queue into the matrices. The router checks structure only, never the
content of a capture. On success it approves and merges the PR into `main` and publishes `route-handoff-block` as
`success`; otherwise it comments the reasons once and publishes `failure` or pending. Anything else on a capture branch
is refused and goes through a mission (or HITL's own admin merge, as for any PR outside the mission flow).

## 6. HITL gates

HITL approves a commit by commenting `/mission approve <40-hex head SHA>` on its own line. Only comments by a
`hitl_logins` user account count, only for that exact SHA, so any new push needs a new approval.

| When | Why |
|---|---|
| Every A1 plan | Starting a mission authorizes its roles, scope and stack. The approval is a separate recorded act from opening the PR, whoever opened it — including when HITL authored the plan himself. For a stack that lands as a whole, one approval of the stack's fingerprint (§2a) covers every plan in it |
| A landing PR whose diff into `main` has SPEC-002 `AUTHORITY` or `AGENT_POLICY` files (except the stack's own `mission.json` files), or is too large to list | The same rule, applied once for the whole stack instead of mid-stack |
| A3 PASS whose diff into `main` has SPEC-002 `AUTHORITY` or `AGENT_POLICY` files (except the mission's own approved `mission.json`) | These are never merged without HITL |
| A3 PASS whose diff is too large to list | The router cannot see what it would merge |

HITL can also end or resume work with a command on its own line in a comment on the mission's tracking issue (the
router-opened issue only, from a `hitl_logins` user account only):

| Command | Effect |
|---|---|
| `/mission cancel` | The mission becomes `CANCELLED` and its issue closes. Every open stage PR is rejected, nothing more is merged, nothing reaches `main`, and its `build_scope` no longer blocks other missions. Final: a restart takes a new mission id. A mission already `DONE` is not affected |
| `/mission retry` | Gives a stage recorded as failed 3 times in a row new attempts: failed agent runs (MISSION-DISPATCH-001 §4) and refused stage PRs (§5). On a mission blocked by A3, it reopens that mission alone (§4, Amendment 004): A3 reviews the same build again after `BLOCKED`, or A2 gets one more round after a last-round FAIL. Nothing else in the stack reruns |

Closing a blocked stack's issue ends its review: the router closes its missions' issues and the stack id cannot start
again. Until then, a retried mission reopens the stack: the stack issue says which mission resumed, and if the stack is
blocked again it says so again.

## 7. Security model

- **Only `main`'s code runs.** `pull_request_target` is limited to PRs into `main`, so its workflow file comes from
  `main`. PRs into integration branches are handled by the 5-minute schedule, which also runs from `main`. No PR code is
  checked out or executed, and no event text reaches a shell: every trigger runs the same sweep.
- **The router cannot change itself through a mission.** The router package, this spec, all workflows and every
  `missions/*/mission.json` are SPEC-002 `AUTHORITY`. A2 can never merge them, and a PASS diff containing them needs HITL.
- **The router never writes to `main` except the PASS merge.** It creates and fast-forwards integration branches
  (fast-forward only; GitHub refuses anything that would drop commits) and retargets A1 PRs away from `main`.
- **Least privilege.** The workflow token has `contents`, `pull-requests`, `issues` and `checks` write for this job
  only, plus `actions` write, used only to start `mission-agent.yml` on `main`. Top-level permissions are empty.
- **Only the router can pass the required check.** Check runs from GitHub Actions can be created only by a workflow
  token. The router runs only from `main`. A workflow on a PR branch runs from that branch, but adding or changing
  one requires the `workflows` permission, which no agent app holds. The legacy `pull_request` router is deleted,
  and the remaining `pull_request` workflows have read-only tokens.
- **A stack lands only as checked.** The stack branch is never written by an agent: a landing PR whose stack branch
  was updated by anyone but the router or HITL is rejected. The landing PR is opened by an A3 agent's App, because
  branch protection needs an approving review and the router cannot approve a PR its own token opened; the agent only
  opens it, and the router checks and merges it. One approval binds every plan of the stack at its exact commit
  through the fingerprint; a later push to any plan needs a new approval.
- **The capture route cannot carry anything but captures.** It changes one configured file, append-only, and only
  for a PR that a HITL user account opened and only HITL pushed to: an agent App cannot open or update a capture, and
  a push by anyone else is refused. The route and its file are set in `config.json`, which is `AUTHORITY`, so only a
  HITL-merged pipeline patch can change them. A capture is DRAFT and promotes nothing.
- **A mission lands only where HITL allows (Amendment 008).** A plan can name only a branch HITL listed in
  `config.json`, which is `AUTHORITY`, and HITL created beforehand. The router never creates such a branch, so none
  exists without the protection HITL gave it, and a plan cannot point a mission at a router-owned branch
  (`mission/`, `stack/`, the capture prefix) or at an unlisted branch that other workflows may treat specially.
- **Idempotent and convergent.** Comments carry hidden markers and post once; labels and the issue are set to the
  state, not toggled. Runs are serialized, and a missed event is picked up by the next sweep.

## 8. Settings outside this repository's files (HITL applies)

The router enforces everything it can see. These settings live in GitHub and only HITL can change them:

1. **Agent app permissions.** Every agent app that can hold the A2 or A3 role needs `Contents: write` and
   `Pull requests: write` to push its branch and open its PR. No agent app may hold `Workflows` or `Administration`.
   The keys the Mission Agent workflow uses live in GitHub environments (MISSION-DISPATCH-001 §6).
2. **`main` force pushes and deletions.** Branch protection allows both, which means anyone with write access can do
   them, agent apps and workflow tokens included. With `enforce_admins` off, setting both to false leaves the
   repository admin (HITL, the only admin) as the only account that can still do either.
3. **Landing branches (Amendment 008).** Before listing a branch in `config.json` `landing_branches`, HITL creates
   it and protects it as `main` is protected: require `route-handoff-block` from GitHub Actions and an approving
   review, and block force pushes and deletions. Without that protection a push straight to the branch bypasses the
   pipeline. The `mission-agent-*` environments need no change: their jobs run from `main` whatever a mission targets.
4. **Bot logins.** Each `config.json` `agents` value is the App's exact bot login (`<app-slug>[bot]`), confirmed
   from GitHub. A wrong login fails closed: that agent's PRs are rejected.

## 9. Known limits

1. **Starting the agent process** is MISSION-DISPATCH-001's job, for roles whose plan names a `runtime`.
2. **Merge conflicts at PASS.** If `main` moved in a way that conflicts with a mission, GitHub refuses the PASS merge.
   The router reports it; the fix is an A2 round that merges `main` into the integration branch. Non-overlapping PARALLEL
   scopes make this rare.
3. **Legacy producer docs.** `AGENTS.md` and `CLAUDE.md` still describe the retired handoff-block flow for
   `route-handoff-block`.
4. **Stack branches are not protected by GitHub.** Agent Apps hold `Contents: write`, so one could push to
   `stack/<ID>`. The router then refuses to land the stack (§5c), and the stack waits for HITL. A ruleset on `stack/*`
   that only GitHub Actions may bypass would stop such a push at GitHub; it is optional.
5. **Merge conflicts at landing.** Missions outside a stack may land on `main` while the stack runs, but not on files
   the stack has reserved (§2a). A conflict elsewhere makes GitHub refuse the landing merge; the router reports it and
   retries, and HITL resolves it.

6. **From a landing branch to `main` (Amendment 008).** A PR from a landing branch into `main` is not a mission:
   it gets the "Not a mission" `failure` and only the repository admin can merge it. Teams that stage on a branch for
   their own review merge it to `main` by their own rules.

## 10. Predicted vectors (A3 verifies)

| # | Input | Expected |
|---|---|---|
| 1 | A1 PR into `main`, valid manifest, no approval | Integration branch created at the merge base; PR retargeted to it; one approval-request comment with the head SHA; `main` unchanged |
| 2 | Vector 1 + HITL `/mission approve <head>` | Merged into the integration branch; `main` unchanged; issue `AWAIT_A2`, `mission:stage-a2` |
| 3 | Approval by a non-HITL login, by a bot, for another SHA, or inline in a sentence | No merge |
| 4 | Approved A1, then a new push | No merge until the new head is approved |
| 5 | A2 PR in scope, right author and round | Merged into integration; issue `AWAIT_A3` with `review_sha` = merge commit |
| 6 | A2 PR touching a path outside `build_scope`, a SPEC-002 `AUTHORITY` path (even in scope), or `missions/` | Rejected, `agent:blocked` |
| 7 | A2 PR from the A3 app, from a user account (including HITL), or from a user named like the bot | Rejected |
| 8 | Direct push to the integration branch | Mission `HALTED`; no further merges |
| 9 | A3 FAIL, verdict only, on the reviewed commit | Merged into integration; `AWAIT_A2` round N+1; `main` unchanged |
| 10 | A3 PR that also changes any other file | Rejected |
| 11 | A3 verdict with a `reviewed_sha` other than the handed-off commit | Rejected |
| 12 | A3 PASS, no authority files | `route-handoff-block` success, then plan, build and all verdicts merged into `main` in one merge; issue closed, `mission:done` |
| 13 | Manifest with A3 equal to A1 or A2, or naming a login | Manifest rejected |
| 14 | FAIL at `max_rounds` | `HALTED`, `agent:needs-hitl` |
| 15 | Stage PR merged by a login that is neither router nor HITL | `HALTED` |
| 16 | Push between the check and the merge | Merge refused; the new commit is checked next sweep |
| 17 | Required checks failing on a PASS PR | Not merged; one "waiting" comment; retried each sweep |
| 18 | Three consecutive sweeps with no change | No new comments, labels, issues or branches |
| 19 | Two PARALLEL missions with disjoint scopes | Both run and both land on `main` |
| 20 | A1 whose `build_scope` overlaps an active mission | Rejected with the overlapping globs |
| 21 | CHAINED A1 whose dependency has not passed | Held with a comment naming the dependency |
| 22 | Vector 21 after the dependency lands | Integration branch fast-forwarded to `main` (contains the dependency's result); A1 asked to update; then normal approval and merge |
| 23 | Two CHAINED missions depending on each other | Both rejected as a cycle |
| 24 | `depends_on` in an PARALLEL or stack-less manifest | Manifest rejected |
| 25 | A2/A3 branch also pushed by another identity (another agent, HITL, `cursor[bot]`), or an A1 branch pushed by anyone other than the a1 bot or a HITL login | Rejected, naming the pusher |
| 26 | Push not yet in GitHub's activity log | Held until it is recorded |
| 27 | Assigned identity `SUSPENDED` or `RETIRED` in the registry | Rejected: no ACTIVE identity |
| 28 | Non-mission PR into `main` | `route-handoff-block` failure; never merged by the router |
| 29 | A3 PASS held for HITL | `route-handoff-block` pending; success and merge after `/mission approve` |
| 30 | Rejected A3 PASS | `route-handoff-block` failure |
| 31 | A1 plan PR opened and pushed by a HITL login, valid manifest, no approval | Same as vector 1: integration branch created, PR retargeted, one approval-request comment; `main` unchanged |
| 32 | Vector 31 + HITL `/mission approve <head>` | Same as vector 2: merged into the integration branch; issue `AWAIT_A2` |
| 33 | A1 plan PR from a user account that is not a HITL login | Rejected |
| 34 | a1 identity `RETIRED` in the registry; A1 plan PR opened and pushed by a HITL login | Accepted as in vectors 31–32; a plan PR from the retired a1 bot is rejected |
| 35 | HITL comments `/mission cancel` on the tracking issue | `CANCELLED`, issue closed, `mission:cancelled`; open stage PRs rejected; nothing merged; the scope is free for a new mission |
| 36 | `/mission cancel` from a bot, from a non-HITL user, on another issue, or inline in a sentence | No effect |
| 37 | `/mission cancel` after the mission is `DONE` | No effect |
| 38 | Handoff to a role with a `runtime` | `mission-agent.yml` started on `main` once per handoff; none for a role without one |
| 39 | Starting `mission-agent.yml` fails | The sweep goes on and logs it; the workflow's schedule starts the agent |
| 40 | The issue listing returns no mission issues, for an active, a cancelled and a finished mission | No new issue; the cancel still holds; stages still advance and the issue follows them |
| 41 | A mission's tracking issue is opened | The plan PR gets one `tracking-issue:<N>` marker comment naming it |
| 42 | No marker and no `config.json` record, but the listing finds the issue | The issue is used and the marker is posted once |
| 43 | The recorded number is a PR, another mission's issue, an issue not opened by the bot, or missing | The mission waits, logged; nothing is merged or opened; the Mission Agent leaves it out |
| 44 | Three CHAINED plans opened; HITL approves the stack fingerprint once | Loop 1 merges; loops 2 and 3 merge in turn without another approval, each building on the previous loop's result |
| 45 | Every loop of a stack passes | Each PASS merges into `stack/<ID>`; `main` is unchanged until the landing PR, which lands the whole stack in one merge; all issues close |
| 46 | CHAINED loop 2 is `BLOCKED` | Loop 3 never starts; any running loop is held; the stack issue shows the matrix and the blocker (what, where, when); nothing reaches `main`; a landing PR is rejected |
| 47 | PARALLEL loop 1 is `BLOCKED` | Loop 2 carries on; the stack is blocked once both finished; nothing lands |
| 48 | A plan is pushed after the stack approval request | The fingerprint changes; no plan merges on the old approval; a new request is posted |
| 49 | Landing PR before every loop passed, by a non-A3 bot, or after someone else updated the stack branch | Waits, rejected, rejected |
| 50 | Landing diff with `AUTHORITY` files (other than the stack's own plans) | Held for HITL `/mission approve <head>` |
| 51 | An agent run fails 3 times in a row | The stage is `BLOCKED`; `/mission retry` allows new attempts |
| 52 | Another mission's scope overlaps a passed mission of an unlanded stack | Rejected until the stack lands or its review is closed |
| 53 | HITL closes a blocked stack's issue | Its missions' issues close; a new plan with that stack id is rejected |
| 54 | A plan reuses the id of a landed stack, or a stack mixes PARALLEL and CHAINED | Rejected |
| 55 | `"landing": "per-leg"`, or a stack in `config.json` `per_leg_stacks` | Each mission lands on `main` when it passes, as before Amendment 002 |
| 56 | The A2 PR the mission waits on is refused (for example an `AUTHORITY` file) | One failure record on the tracking issue, naming the reasons; the stage branch is deleted and its PR closed |
| 57 | The same stage is refused 3 times in a row | `BLOCKED`, with the last refusal in the review matrix; `/mission retry` allows new attempts |
| 58 | A refused PR for a round the mission is not waiting on, or from a fork or another branch | Refused; its branch is kept and nothing is recorded |
| 59 | The refusal cannot be recorded (no readable tracking issue) | The branch is kept |
| 60 | An A2 PR that changes no files | Merged like any A2 build; A3 reviews it |
| 61 | A plan whose `deliverables` include an `AUTHORITY` file, or a file outside `build_scope`, or a literal `build_scope` entry that is `AUTHORITY` | Rejected before any approval is requested; an approval comment does not merge it |
| 62 | `deliverables` with a wildcard, `..`, an absolute path or a duplicate | The manifest is invalid |
| 63 | HITL comments `/mission retry` on a PARALLEL mission blocked by A3 | That mission goes to A3 round r+1 on the integration head; the stack issue says it resumed; the passed missions are not run again; on PASS the whole stack lands |
| 64 | The re-reviewed mission is `BLOCKED` again | The stack is blocked again and the stack issue says so again; another retry is needed to reopen it |
| 65 | `/mission retry` from a bot, a non-HITL user, or posted before the block | Nothing reopens |
| 66 | HITL closed the stack's review, then comments `/mission retry` | Nothing reopens |
| 67 | `/mission retry` on the CHAINED mission that blocked its stack | It is reviewed again; once it passes, the loops it held start |
| 68 | `/mission retry` after a FAIL in the last allowed round | A2 gets one more round |
| 69 | HITL opens a PR from `capture/<name>` that appends DRAFT entries to the queue | The router merges it into `main`; `route-handoff-block` success |
| 70 | A capture PR opened by an agent App or another user, or its branch pushed to by anyone but HITL | Refused, not merged; `failure` |
| 71 | A capture PR that edits an existing line of the queue, touches another file, renames or adds the queue | Refused |
| 72 | Appended text with no `### CAPTURE-` entry, a status other than `DRAFT`, no status line, or over 20,000 characters | Refused |
| 73 | A capture written before another capture landed | Refused until its branch is updated from `main`; then merged |
| 74 | A capture while an unfinished mission holding its files may change the queue | Held (pending) until that mission is finished |
| 75 | No `l1_capture` in `config.json`, or a PR into `main` from any other branch | "Not a mission" `failure`, as before |
| 76 | `l1_capture` with a wildcard or `..` path, extra keys, or a prefix that is not one lowercase name ending in `/` (or is `mission/` or `stack/`) | `config.json` is invalid; the router does not run |
| 77 | A plan names `"model": "sonnet"` for A2 with `runtime` `claude-code` | Valid; the stage comment says the agent starts as `claude-code` with model `sonnet` |
| 78 | A `model` without a `runtime`, on A1, not in the `claude-code` list, or for `cursor-cli` with capitals, spaces, a leading `-` or over 64 characters | The manifest is invalid |
| 79 | The bot's queued record for the stage a mission waits on | The mission stays in its stage, not `BLOCKED`; the stack matrix shows "queued: <runtime> is out of compute until <time>" until that time |
| 80 | The stage is still queued 7 days after its first queued record (since HITL's last `/mission retry`) | `BLOCKED`, "the <role> runtime was out of compute for 7 days"; `/mission retry` queues it again |
| 81 | A queued record for another stage, or one not posted by the bot | Ignored |
| 82 | A plan names `"branch": "release"`, listed in `landing_branches` and existing | The integration branch starts from `release`; the A3 PASS PR into `release` gets `route-handoff-block` success and an approval and is merged; `main` is unchanged; the issue says "merged into `release`" |
| 83 | That mission's A3 PASS opened into `main` | Refused like any wrong stage PR (Amendment 003) |
| 84 | A plan names a branch not in `landing_branches` | Refused; nothing is created |
| 85 | A plan names a listed branch that does not exist | Held, saying HITL must create it; no approval request, no integration branch; once HITL creates it, the plan asks for approval |
| 86 | A plan branched from `main` with commits that are not on its `branch` | Refused: those files are outside the plan's directory |
| 87 | A stack whose plans name `release` | Its stack branch starts from `release`; a landing PR into `main` is refused; one into `release` is merged; a new plan in the stack is refused as already landed on `release` |
| 88 | Two plans of one stack name different branches (or one names none) | The later plan is refused; while both are proposed the stack is halted |
| 89 | An CHAINED mission whose dependency landed on another branch | Refused |
| 90 | A PR into a landing branch from any other branch | "Not a mission" `failure`, as on `main` |
| 91 | `branch` empty, under `mission/` or `stack/`, with `..`, `HEAD`, a leading `-` or `.` in a part, ending in `.lock` or `.`, a space, or over 200 characters; `landing_branches` not a list, with duplicates, or naming such a branch or one under the capture prefix | The manifest, or `config.json`, is invalid |
