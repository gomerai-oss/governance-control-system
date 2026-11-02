# MISSION-DISPATCH-001: starting the assigned agent and opening its PR as that agent

**Status:** LIVE, with the code in `tools/agent_workflow/mission_dispatch/` and `.github/workflows/mission-agent.yml`: it has started every mission agent since M-ZERO-002 (2026-10-22). Marked current on HITL direction, 2026-11-01 (M-METHOD-001, after-it-lands step 1). Earlier status: proposed.
**Depends on:** MISSION-ROUTER-001 (the router decides and merges; this only starts agents and opens their PRs).
**Amendment 002 (2026-10-22, with MISSION-ROUTER-001 Amendment 002):** an A3 PASS goes to the mission's landing branch
(its stack branch when the stack lands as a whole); A3 may hand in a `BLOCKED` verdict, and A2 records blockers instead
of stopping; a failed run is started again automatically, up to 3 times in a row; and a `land` job opens the PR that
lands a whole stack.
**Amendment 003 (2026-10-23, with MISSION-ROUTER-001 Amendment 003):** an A2 that can build nothing records only its
blockers, and that empty build goes to A3 instead of counting as a failed run; a new attempt at a stage is handed the
last failure record (including a router refusal); and throwaway checkouts run no background git gc.
**Amendment 004 (2026-10-24, with MISSION-ROUTER-001 Amendment 004):** when HITL retries a mission blocked by A3, the
A3 job reviews the same build again: its task says so, A2's notes come from the build's merge, and the checks run again.
Checks start no background git gc or maintenance either.
**Amendment 006 (2026-10-24, with MISSION-ROUTER-001 Amendment 006):** a job carries the model the approved plan names
for its role, and the runtime is started with `--model <name>` (Claude Code and the Cursor agent both take it). Without
a model nothing changes. The job description refuses a model the plan could not have named, and a model that would read
as a flag never reaches the runtime. Failure records and PRs name the model.
**Amendment 009 (2026-10-25, with MISSION-ROUTER-001 Amendment 009):** the capacity queue is removed
(Amendment 007 is superseded in full). No timer is consulted: a run that ends because its runtime is out of
compute is an ordinary failure, counting toward the 3 failures that block a stage for HITL review (§4).
**Amendment 008 (2026-10-24, with MISSION-ROUTER-001 Amendment 008):** a plan may name the `branch` its work finally
merges into. A job's landing branch is then that branch (or the mission's stack branch), and the `land` job opens the
stack's landing PR into the stack's branch instead of `main`. The workflow itself still runs only from `main`.
**Amendment 010 (2026-10-26):** A2 deletes a file by listing it in `.mission-dispatch/DELETE`; the dispatcher deletes
the listed files before it checks the change (§3c). Claude Code has no shell, so it could only empty a file the plan
said to delete (M-CCSYNC-AUDIT-003, A3 BLOCKED, governance #1116). The runtimes' sandboxes are unchanged.
**Amendment 011 (2026-10-28, HITL direction, HITL pipeline patch):** live runtime binding. With
`"runtime_binding": "enforce"` in the repository's `config.json`, each run is narrowed to its seat's admitted tool
surface (`tool_selection.runtime_binding`) and gets one MCP server, the governed retrieval gateway (`mcp_gateway`),
whose every call the MCP authorization fabric decides (§3b). The default is `"off"`, under which every runtime argument
is as before. Binding never widens the dispatcher's own ceiling.
**Amendment 012 (2026-11-01, HITL direction: ring 5 of the six-ring security system, with MISSION-ROUTER-001
Amendment 010):** blast radius. Checks run with no network; the agent runs as its own account whose only way out is a
proxy that admits listed hosts; every run is capped in processes, file size, change size and turns; and HITL can halt
one mission, which stops any change of it reaching a PR (§3h). The mode is set by `"blast_radius"` in `config.json`.

## 1. Purpose

When a mission waits on A2 (build) or A3 (review), the dispatcher does three things:

1. It starts the runtime the approved plan names for that role.
2. It lets the runtime change files and nothing else.
3. It opens the stage PR as the agent HITL assigned, so GitHub itself records that agent's App as the actor.

Goals, in priority order:

1. **No impersonation.** An agent can act on GitHub only as its own App, and only through code on `main` that checks
   its work first. It can never act as HITL, as another agent, or as the router.
2. **No authority for agent output.** Nothing the agent writes is executed with a credential. Its change travels as
   data (a patch), is re-checked on a fresh clone, and only then committed.
3. **Automatic.** No human starts agents or opens stage PRs. HITL approves plans, can cancel, and clears failures.

## 2. Where it runs

Everything runs on GitHub Actions in `.github/workflows/mission-agent.yml`, on throwaway GitHub-hosted VMs. No laptop,
no laptop credentials, and no HITL login are involved. The workflow runs:

- when the router starts it at a handoff;
- every 10 minutes on a schedule, as a fallback;
- when HITL comments `/mission retry`.

Every run re-derives the missions itself. A trigger is only a nudge, and no event payload is read.

## 3. Jobs and what each holds

| Job | VM | Credentials | Does |
|---|---|---|---|
| `plan` | own | workflow token: read (and `actions: read`) | Calls the router's read-only `MissionRouter.survey()` (the same derivation the router merges by) and lists the jobs due, skipping lanes another run still owns (§3e) |
| `checks` | own, per job | none while the checks run | A3 only, when the plan lists `checks`. Runs them on the commit A3 reviews, as a separate unprivileged account (§3f) |
| `agent` | own, per job | model login only, from environment `mission-runtime`; a read-only token in the `due` and `prepare` steps only | `due`: re-check the lane is still due. `prepare`: clone the integration branch at the handed-over commit and write the task (and, for A3, the checks report). `run`: start the pinned runtime with no GitHub credential. `collect`: check the change, refuse it if it contains the model login, write it as a patch |
| `publish` | own, per job | environment `mission-agent-<agent>`: that agent's App key; workflow token: read | Re-derive the mission, re-check the patch on a fresh clone, push the stage branch, open the PR as the App |
| `report` | own, per job | workflow token: issues write | If a due job did not end in an open PR, record that on the tracking issue |
| `land` | own, per stack | environment `mission-agent-<agent>` of an A3 agent of the stack: that App's key; workflow token: read | When every mission of a stack that lands as a whole has passed (§3g): re-check the stack, then open the PR from `stack/<ID>` into `main` (or the stack's `branch`, Amendment 008) as that App. No agent content is involved |

All jobs run only `main`'s code (`github.ref` must be `refs/heads/main`; environments deploy from `main` only).
Top-level permissions are empty.

### 3a. A job is due when all of these hold

- The mission is `AWAIT_A2` or `AWAIT_A3` and not cancelled.
- The role names a `runtime`.
- The assigned agent is `ACTIVE` in the registry.
- The integration branch is exactly where the router expects it.
- The stage branch does not exist yet.
- Fewer than 3 failures in a row are recorded for that role and round since HITL's last `/mission retry` (§4).

### 3b. The agent's sandbox

- **Environment.** It holds no GitHub credential: every `*TOKEN*`, `*SECRET*`, `*KEY`, `*PRIVATE*` and `SSH_AUTH_SOCK`
  variable is dropped, except the runtime's own model login. git is pinned to the job's own git directory, which
  lives outside the checkout, with no global or system config.
- **Claude Code.** `--tools Read,Edit,Write,Glob,Grep` (no shell, web or subagents). `--setting-sources user`, so the
  checkout's own `.claude/` cannot load. `--strict-mcp-config`. Read and edit are allowed in the checkout only.
  None of these tools removes a file; A2 deletes by listing (§3c, Amendment 010).
- **Cursor CLI.** `.cursor/cli.json` written by the dispatcher (read-only): read-only git as its only shell, writes
  in the checkout only, and secrets and `.git` denied.
- **Runtime binding (Amendment 011, `binding.py`).** Off unless `config.json` sets `"runtime_binding": "enforce"`;
  any other value fails the job. Enforced, `prepare` calls `tool_selection.runtime_binding.bind` from the tooling
  tree (never the checkout's copy) and holds the result to the dispatcher's ceiling: built-in tools only from
  `Read, Edit, Write, Glob, Grep`; allow rules only `Read(<glob>)` / `Edit(<glob>)` relative to the checkout, with no
  absolute path and no `..`, which the dispatcher renders inside the checkout; extra denials are added to, never
  replace, the dispatcher's own; gateway tools only as plain names. A refusal, a missing library, or anything over
  the ceiling fails the job before an agent starts. The session file, the MCP config and the binding record are
  written read-only under `<job root>/binding/`, beside the checkout, and the dispatcher writes the MCP config
  itself: one server, `governed-retrieval`, `python3 -m mcp_gateway` with `PYTHONPATH` set to the tooling tree.
  `run_agent` re-reads and re-checks the record and refuses a missing or altered one. Claude Code gets `--tools`
  from the binding, the rendered allow rules plus `mcp__governed-retrieval__<tool>`, and `--mcp-config` beside
  `--strict-mcp-config`. Cursor gets `Mcp(governed-retrieval:<tool>)` allow rules, read or write denied in the
  checkout when the binding admits neither, a dispatcher-written read-only `.cursor/mcp.json` removed after the run,
  and `--approve-mcps`; a `~/.cursor/mcp.json` on the runner fails the job, since that flag would approve it too.
  `collect` keeps the binding record and the gateway's evidence log (capped at 4 MiB) in `binding/` beside the patch,
  so they stay with the run's artifact; `publish` never reads them.
- **Refusal.** A checkout that carries runtime configuration (`.claude`, `.mcp.json`, `.cursor/{cli,hooks,mcp,environment,sandbox}.json`,
  `.vscode/settings.json`) is refused before any agent starts.

- **Pinned runtimes.** Claude Code (the `@anthropic-ai/claude-code-linux-x64` package, a single binary) and the
  Cursor CLI (its versioned package) are downloaded by exact version and installed only if their SHA-256 matches the
  value in the workflow. Updating either is a reviewed PR. No install script runs.

### 3c. What a change may contain (checked in `collect`, and again in `publish`)

- **A2.**
  - It may only create, change or delete paths matching `build_scope`.
  - To delete a file it lists the path in `.mission-dispatch/DELETE`, one per line (Amendment 010). Before staging,
    `collect` checks every listed path: a plain relative path (no `/` prefix, `.`, `..`, empty or `.git` segment, no
    backslash or control character), inside `build_scope`, not under `missions/` or `.mission-dispatch/`, not behind a
    symbolic link, and an existing regular file. One path that fails refuses the whole run and nothing is deleted;
    otherwise every listed file is deleted. The listing is at most 64 KiB, is never committed, and A3's is never read.
    The deletions are then checked with the rest of the change, here and again in `publish`.
  - It may not touch anything under `missions/`.
  - It may only contain regular files: no symbolic links and no submodules.
  - No path may contain a control character.
- **A3.**
  - It must add exactly `missions/<ID>/reviews/round-<N>.json` as a new regular file, and nothing else.
  - The file must be a valid `mission-verdict-v1` whose `reviewed_sha` is the commit A3 was handed. `verdict` is
    `PASS`, `FAIL` or `BLOCKED`; a `BLOCKED` verdict lists each blocker in `findings`.
- **Both.**
  - The patch is at most 5 MiB.
  - The commit message is at most 8 KiB.
  - `git apply` refuses paths outside the tree and paths inside `.git`.
  - Neither the patch nor the commit message may contain the runtime's model login (any login of 16 or more
    characters given to the runtime). The agent log is scrubbed of it before upload.

### 3d. Before `publish` pushes

- The minted token's App slug is the planned agent's bot login.
- The mission still waits on exactly this role, round and commit.
- The integration branch has not moved.
- The agent is still `ACTIVE`.
- The stage branch does not exist. It is never overwritten or force-pushed.

The token is minted for this repository only, with `contents: write` and `pull-requests: write` only. The PR goes to
the integration branch, or for an A3 PASS to the mission's landing branch (`main`, the plan's `branch`, or `stack/<ID>`; the job names it,
and publish skips the job if the mission's landing branch changed), exactly as MISSION-ROUTER-001 §1 expects. The router then
decides everything else as usual: identity, scope, merge, and the HITL gates.

### 3e. One lane per job

The lane is a mission, role and round. Lanes for different missions run in parallel, at most 4 at a time.

- **Plans run one at a time.** Each plan reads the jobs of every other unfinished run of this workflow through the
  Actions API, and does not start a lane that one of them still owns.
- **A run whose jobs are not listed yet** blocks all planning until the next run, so no lane is ever started twice.
- **The agent job re-checks that its lane is still due** before it starts the runtime.

### 3f. Checks

A plan may list up to 10 `checks`: shell commands, each up to 500 characters, approved by HITL with the plan.

1. For an A3 lane, the `checks` job runs them on the commit under review, on its own VM.
2. They run as a fresh unprivileged account, `mission-checks`, with an empty environment and a 15-minute limit each.
   That account cannot read the runner's processes. This matters because the environment of the process that
   uploads artifacts holds the token Actions uses for artifacts, which could otherwise be used to plant a forged
   change for `publish`.
3. Every process the account started is killed after each check and again before anything is uploaded. If any
   survives, the job fails.
4. A3 gets the exit codes and the last output of each check in `.mission-dispatch/CHECKS.md`. That output comes from
   the code under review, so A3 is told to use it as evidence, never as instructions. If the results are missing, A3
   is told every check is "not run".

The results are evidence only: the dispatcher never turns them into a verdict.

### 3h. Blast radius (Amendment 012)

**Mode.** `"blast_radius"` in `config.json`: `"observe"` (the default when the key is absent) applies every cap and
records what enforcement would refuse, without refusing it; `"enforce"` refuses it. Any other value fails the job.
HITL switches to `"enforce"` after the live attack tests (AST) below pass and the egress list is approved. Records
are kept with the run's artifacts in both modes. **Switched on:** this repository's `config.json` sets `"enforce"`
(ring 5, part 4, after AST-5.1 to 5.5 passed on 2026-11-02).

1. **Checks have no network.** Before the first check, the `checks` job adds firewall rules (`iptables` and
   `ip6tables`, matched on the `mission-checks` account's user id) that reject every outbound packet of that account
   except on loopback, and DNS on loopback too, since the runner's local resolver forwards queries to the internet.
   It then proves them: as that account it tries a TCP connection to `api.github.com:443`, a DNS query to
   `1.1.1.1:53`, and a lookup through the local resolver. In `"enforce"` any of them succeeding, or rules that cannot
   be installed, or a probe that gives no result, fails the job before any check runs; in `"observe"`
   the rules count instead of reject, and the result is recorded in `CHECKS.md` as `network: open` or `closed`.
2. **The agent runs as its own account** under `"enforce"`. The agent runs as a fresh unprivileged account,
   `mission-agent`, with the environment §3b already allows, its own home, and nothing that points into the
   runner's home, which other accounts cannot enter. The runtimes (`/opt/mission-runtime`) and the tooling the
   gateway runs from (`/opt/mission-tooling`) are installed root-owned and read-only, and the job root is
   `/srv/mission-job/mission`. For the run that account gets only the checkout, its git directory and the
   gateway's evidence folder; the canary, the binding record and the rest of the job root stay the runner's. The
   model login reaches the runtime by environment only (`sudo --preserve-env`), never on a command line. Every
   process of the account is killed after the run and the job root is taken back; if any process survives, the
   job fails. The MCP gateway runs as that account too, as the runtime's child, and needs no network. Under
   `"observe"` the agent runs as before, as the runner account, pointed at the proxy (item 3).
3. **The agent's only way out is the egress proxy.** Firewall rules reject every outbound packet of
   `mission-agent`, DNS included, except to the egress proxy on loopback (`tools/agent_workflow/egress/`). The
   proxy runs as the runner account and accepts only HTTPS `CONNECT host:443`. It refuses an IP-literal host, any
   other port, and any host not listed for the job's runtime in `mission_dispatch/egress-policy.json` (a SPEC-002
   `AUTHORITY` file, so the list changes only by a hand-merged PR). It resolves the name itself and refuses a name
   that resolves to a private, loopback or link-local address. It stops admitting after 256 MiB in total. Every
   decision is one line of `egress.jsonl` (time, host, port, allowed or refused, reason, bytes). The runtime is
   pointed at the proxy with `HTTPS_PROXY`, `HTTP_PROXY` and `ALL_PROXY`, and `NO_PROXY` is set to the loopback
   names only (`localhost,127.0.0.1,::1`), replacing any the runner had, so a runtime's own loopback calls stay off
   the proxy while the firewall still decides them; a runtime that ignores the proxy reaches nothing. Claude Code
   runs with `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`: no telemetry, error reports or update checks. Before the agent starts, a probe as that account must find a direct connection,
   a DNS query and a lookup through the local resolver all refused, or the job fails. In `"observe"` the proxy
   admits every tunnel and records what it would refuse; a request that is not a tunnel is still refused. The
   proxy failing to start fails the job under `"enforce"` and is a warning under `"observe"`. `collect` keeps the
   proxy's log (capped at 4 MiB) beside the patch, with a summary of the hosts off the list; `publish` never reads
   it.
4. **Caps.** Each check and the agent run under `prlimit`: 1 GiB per written file and 4096 open files, and, when
   the run has an account of its own (the checks always, the agent under `"enforce"`), at most 512 processes. The
   process cap counts every process of the account, so on the shared runner account it would count the runner's
   own. A change is at most 5 MiB (§3c) and at most 300 files. The agent log is cut to its last 8 MiB. Time
   caps are unchanged: 15 minutes per check, 60 minutes per agent run. Claude Code runs with `--max-turns 200`. The
   pinned Cursor CLI has no turn cap, so it is bounded by time alone (§7).
5. **HITL can halt a mission.** A job for a mission HITL halted (MISSION-ROUTER-001 Amendment 010) is not due: `plan`
   lists it in no matrix, `due` stops it before the agent starts, and `publish` re-derives the mission's state and
   pushes nothing for it. A run already in progress when HITL halts therefore ends without a PR. HITL can also cancel
   the workflow run in GitHub, and disabling the two mission workflows stops every mission at once (§6).

**The attack tests.** Each part ships permanent attack tests in `tools/agent_workflow/tests/` that fail on today's
code and pass on the new code. Before the switch-on, HITL authorizes these live tests:

- **AST-5.1**, on a throwaway repository HITL creates for it: the repeat of live test L2 through the new
  `checks` steps; every outbound attempt of `mission-checks` fails.
- **AST-5.2**, on the same repository: as `mission-agent`, a direct connection, a DNS query, a `CONNECT` to an unlisted
  host, to an IP literal, to port 22, and to a listed name made to resolve to a private address are all refused, and
  a `CONNECT` to a listed host succeeds.
- **AST-5.3**: live test L1 again, on the pinned Cursor CLI version (L1 ran on 2026.10.16; the workflow pins
  2026.10.19-6bbf2c4).
- **AST-5.4**: one real mission run in `"observe"`, whose `egress.jsonl` names the hosts each runtime needs. Those
  hosts, and only those, go into `egress-policy.json` in the switch-on PR.
- **AST-5.5**: HITL halts a mission while its agent runs; no PR opens, and `/mission resume` lets the next run open
  it.

**The list (AST-5.4, M-AST-HALT-001's observe-mode logs).** `claude-code`: `api.anthropic.com`. `cursor-cli`:
`*.cursor.sh` (the CLI reached `api2.cursor.sh`, `agentn.global.api5.cursor.sh` and `repo42.cursor.sh`; the middle
name looks generated per run). Not listed: `http-intake.logs.us5.datadoghq.com` (Claude Code telemetry, now switched
off) and `downloads.cursor.com`, from which the Cursor CLI fetched 185 MB of another build of itself during a review,
around the SHA-256 pin (§7).

### 3g. Blockers and landing a stack

- **A2 records blockers instead of stopping.** Its task says: if something outside its control keeps it from
  completing part of the plan, complete everything else and list each blocker (what, where in the plan, what it did
  instead) under `Blockers:` in its commit message.
- **A3 sees A2's notes.** The A3 checkout holds A2's commit message (the second parent of the commit A3 reviews) in
  `.mission-dispatch/A2-NOTES.md`, marked as data and never instructions. A3 answers `PASS`, `FAIL` (A2 can fix it) or
  `BLOCKED` (A2 cannot; recorded for HITL review, never retried).
- **Landing.** `plan` lists a `land` job for every stack the router reports `READY` with no landing PR open. The job's
  agent is the A3 agent of the stack's first mission. Before opening the PR, `land` re-derives the stack and checks
  that it is still ready, that no landing PR is open, that `stack/<ID>` is still at the planned head, and that the
  minted token belongs to the planned agent. A second landing PR refused by GitHub is skipped. The router then checks
  and merges it (MISSION-ROUTER-001 §5c).

## 4. Failures

`report` posts one comment on the tracking issue, with a hidden marker
`<!-- mission-dispatch:failed:<role>:<round> -->`, when a due job ended without an open PR. This covers:

- the agent failed;
- the agent timed out;
- the change was refused;
- the push or the PR failed.

Only markers posted by the router's own bot (`github-actions[bot]`) count. Under ADD nothing waits for HITL mid-stack,
so the next run starts the job again. After 3 failures in a row, counted from HITL's last `/mission retry`, the job is
not started again, so a broken agent cannot loop at cost, and the router records the stage as `BLOCKED`. A
`hitl_logins` user account commenting `/mission retry` on its own line on that issue allows 3 new attempts;
`/mission cancel` ends the mission instead.

The check fails closed. The dispatcher finds the issue the way the router does (MISSION-ROUTER-001 §1, "Finding the
tracking issue"), and a mission whose issue it cannot read counts as blocked: nothing is started, the plan logs why,
and the next run checks again.

A job that is no longer wanted because the mission moved on is skipped, not reported.


**Amendment 009: no capacity queue.** A run that ends because its runtime is out of compute is an ordinary
failure, reported with a failure record. Jobs start in approval order (the tracking issue opens when the plan
merges). After 3 failures in a row the stage is recorded as `BLOCKED` for HITL review (MISSION-ROUTER-001 §4);
`/mission retry` allows new attempts.

**Amendment 003.**

- **An A2 that can build nothing.** If A2 changes no files but its commit message has a `Blockers:` section with
  something in it, that is not a failure. The empty build is committed (`--allow-empty`) and opened as A2's PR, and A3
  reviews the blockers against the plan: `BLOCKED` records them for HITL, `FAIL` sends the build back to A2. An A2 that
  changes nothing and records no blockers still fails. Before this, a deliberate stop counted as a crash: it was run
  3 times at cost, and the review matrix said "failed 3 times" without A2's reasons (CM-MOVE-001, 2026-10-23).
- **Feedback to the next attempt.** The planner hands each job the newest failure record for its stage since HITL's
  last `/mission retry`, without markers, at most 2,000 characters. This includes the router's refusals
  (MISSION-ROUTER-001 §5). The task shows it under "An earlier attempt at this stage did not get through", fenced, as
  data and never as instructions.
- **No background git.** Every git call sets `gc.auto=0`, `maintenance.auto=false` and `receive.autogc=false`.
  Checkouts are thrown away, and a background gc could outlive the call that started it; in the tests one raced
  directory cleanup (`Directory not empty: 'pack'`, L2-ADMISSION-002, 2026-10-23).

**Amendment 004.**

- **A review HITL asked for again.** After a HITL `/mission retry` reopens a `BLOCKED` verdict (MISSION-ROUTER-001 §4),
  the router waits on A3 in the next round, on the integration head. The job carries `build_sha`, the merge that
  brought in A2's build. When it differs from the commit under review, the task opens with "This is a review HITL
  asked for again", names the earlier verdict, and says the build is unchanged and the checks were run again. A2's
  notes are read from `build_sha`'s merge, never from the earlier verdict's.
- **Checks start no background git either.** Every check runs with `gc.auto=0` and `maintenance.auto=false` (through
  `GIT_CONFIG_COUNT`), so the git a test starts cannot leave a gc running after it. The tearDown race that blocked
  M-PRIE-GENERALIZE-001 came from the code under review, which the checks run as it was then.

## 5. Security model

- **Agent output is never trusted.** It crosses from `agent` to `publish` as an artifact holding a patch, a message
  and a summary. `publish` reads it as data and applies it with `git apply`, which runs no hooks. It re-runs every
  §3c check on a fresh clone. An agent that tampers with its own artifact gains nothing that the checks do not
  already allow.
- **Credentials are split by job.** The job that runs the agent never holds an App key or a write token. The job that
  holds an App key never runs agent code and holds the key of only the one agent the approved plan names.
- **HITL cannot be impersonated.** No job ever holds a HITL user credential. The router accepts `/mission approve`,
  `cancel` and `retry` only from `hitl_logins` user accounts, and approvals only for an exact SHA.
- **Agents cannot change this machinery.** The `mission_dispatch` package, this spec and all workflows are
  SPEC-002 `AUTHORITY`: no A2 build can change them, and a PASS that contains them needs HITL. No agent App may
  hold the `Workflows` permission, so no agent can add or change a workflow on any branch.
- **Pinned.** Actions are pinned by commit SHA. Both runtimes are pinned by exact version and SHA-256.
- **Model logins stay in the agent job.** A change or message containing one is refused, and the uploaded log is
  scrubbed. Agents have no shell and cannot read outside the checkout, so they do not see the value in the first place.
- **Bound runs cannot widen themselves (Amendment 011).** The binding library is ordinary code that missions may
  change, so the dispatcher treats its output as a request inside a fixed ceiling, and writes the one MCP command
  itself. The gateway and the library run from the default branch's tooling, never from the checkout the agent edits.
  The gateway's session file and evidence live outside the checkout, where neither runtime may write.
- **Code under review runs isolated.** It runs only in the `checks` job, which has no credential, under an account
  that cannot reach the runner's processes.

## 6. Settings outside this repository's files (HITL-owned)

1. **Environment `mission-agent-<agent>`** for each agent that may hold A2 or A3 (today `a2` and `a3`):
   - deployment branches: `main` only;
   - variable `APP_ID`: that agent's GitHub App ID;
   - secret `APP_PRIVATE_KEY`: that App's private key, placed by HITL in person and never by an agent or a virtual
     team. Whoever can write environment secrets can replace an agent's key, and so act as that agent. The steps:
     generate a new private key on the App's settings page; paste the downloaded `.pem` into the secret; delete the
     file. GitHub never shows the secret again.
   - Each App needs `Contents: write`, `Pull requests: write` and `Metadata: read` on this repository, and never
     `Workflows` or `Administration`.
2. **Environment `mission-runtime`:**
   - deployment branches: `main` only;
   - secrets: `ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN` for `claude-code`, and `CURSOR_API_KEY` for `cursor-cli`.
3. **Actions settings.** Allow the actions this workflow pins (`actions/checkout`, `upload-artifact`,
   `download-artifact` and `create-github-app-token`). Fork PRs need no access.

## 7. Known limits

1. **The runtime needs its model login.** The login is in the runtime's process environment. The agent can't read it,
   and a change containing it is refused. A leak would need a runtime bug. Use a dedicated, spend-limited key.
2. **A2 builds without running the checks.** A3 sees the results on the commit it reviews, and a FAIL sends the
   findings back to A2 for the next round.
3. **The checks job's network.** Under `"enforce"` (this repository, §3h) the account running the checks has no
   network. A repository left on `"observe"` runs the code under review on a GitHub VM with network access, though
   with no credential.
4. **The agent log is a workflow artifact**, kept 7 days and readable by anyone who can read the repository's Actions.
   It is scrubbed of the model login.
5. **The Cursor CLI sandbox rules were verified live on the pinned 2026.10.19-6bbf2c4** (AST-5.3, 2026-11-02): it
   ran plain `git status` and rejected `&&`, `;`, a pipe, `$(...)` and a second line, and a planted file outside the
   workspace never reached its output. Re-check when the pin changes.
6. **Runtime binding is verified against a stand-in library (Amendment 011).** Until `tool_selection.runtime_binding`
   and `mcp_gateway` land (stack EPAP-CHAINED-002), `"enforce"` fails every job, by design; leave it `"off"` until both
   are on the default branch. `Mcp(server:tool)` rules and `--approve-mcps` follow the Cursor CLI's documented
   options and have not yet been exercised live on the pinned version.
7. **The Cursor CLI has no turn cap** (§3h): a Cursor run is bounded by its 60-minute limit alone.
8. **The egress list admits whole hosts.** An agent can still send data to a listed host, such as its own model
   provider's API, inside its normal traffic. The list keeps that to the hosts the runtime needs.
9. **The Cursor CLI updates itself.** In a run with open network (`"observe"`), it downloaded another build of itself
   mid-run, so the SHA-256 pin held only for the install. Under `"enforce"` the download host is not listed and the
   install is root-owned and read-only.

## 8. Predicted vectors (A3 verifies)

| # | Input | Expected |
|---|---|---|
| 1 | Handoff to A2 with `runtime: claude-code` | One run; the agent edits in scope; a PR from `mission/<ID>/a2-r1` into the integration branch, authored and opened by the a2 App |
| 2 | Handoff with no `runtime` | Nothing starts; a note in the plan log |
| 3 | A2 edits outside `build_scope`, under `missions/`, or adds a symlink or submodule | No branch, no PR; a failure comment; not restarted until `/mission retry` |
| 4 | The agent artifact's patch is swapped for one that edits outside scope or escapes the tree | `publish` refuses; no branch, no PR |
| 5 | The publish token belongs to another App | Refused before anything is pushed |
| 6 | The mission is cancelled or moves on while the agent runs | `publish` skips; nothing pushed; no failure comment |
| 7 | The stage branch already exists | `publish` skips; the branch is untouched |
| 8 | A3 writes a PASS verdict for the handed commit | A PR into the mission's landing branch (`main`, or `stack/<ID>`) as the a3 App; the router takes it from there |
| 9 | A3 also edits code, or its verdict names another commit | Refused |
| 10 | The checkout carries `.claude/` or `.cursor/hooks.json` | No agent is started |
| 11 | `/mission retry` from a bot or a non-HITL user | Still blocked |
| 12 | The agent process environment | No `GITHUB_TOKEN`, App key or other GitHub credential |
| 13 | The patch or commit message contains the runtime's model login | Refused in `collect`; nothing handed on |
| 14 | The agent prints its model login | The uploaded log shows `***` |
| 15 | The runtime package does not match its pinned SHA-256 | The install step fails; no agent starts |
| 16 | Two runs plan while one lane's agent is still running | The second run does not start that lane |
| 17 | A3 lane with `checks` | Checks run on the review commit as `mission-checks`; A3's task points at `.mission-dispatch/CHECKS.md` |
| 18 | A check tries to read a credential or leave a process behind | Its environment is empty; its processes are killed; a survivor fails the job |
| 19 | A due job whose mission's tracking issue cannot be read | Held, logged; no agent starts, even if the job failed before and HITL did not retry |
| 20 | A3 writes a BLOCKED verdict listing blockers | A PR into the integration branch as the a3 App; a BLOCKED verdict without blockers is refused |
| 21 | A2's build commit lists `Blockers:` | A3's checkout holds it in `.mission-dispatch/A2-NOTES.md`, and its task points to it as data |
| 22 | A job fails once, then twice | Started again by the next run each time; after the third failure it is held and the stage is `BLOCKED` |
| 23 | A stack is `READY` with no landing PR | One `land` job opens it as the A3 agent's App; none when a landing PR is open, the stack is not ready, or the stack branch moved |
| 24 | Two runs both try to open the landing PR | The second is skipped |
| 25 | A job was planned for a landing branch the mission no longer has | Skipped, not published |
| 26 | A2 changes nothing and its message lists `Blockers:` | An empty commit is published as A2's PR; A3 reviews it |
| 27 | A2 changes nothing and lists no blockers, or A3 changes nothing | The job fails, as before |
| 28 | A stage failed or was refused before | The next attempt's task shows the last record, fenced, as data; the job description refuses a record over 2,000 characters |
| 29 | Any git call by the dispatcher | No background gc or maintenance |
| 30 | A3 job after a HITL retry of a `BLOCKED` verdict | Reviews the integration head; the task says it is a review asked for again; A2's notes come from the build's merge; the job description refuses a `build_sha` that is not a full SHA |
| 31 | A check runs git | `gc.auto` is `0` and `maintenance.auto` is `false`, also as the separate checks account |
| 32 | The plan names a model for the role | The job carries it; the runtime is started with `--model <name>` before the task; failure records name it |
| 33 | No model in the plan | No `--model`; the runtime uses its default |
| 34 | A job description whose model the plan could not have named (wrong runtime's list, a flag, not text) | Refused as malformed; a model starting with `-` never reaches the runtime |


| 42 | A stack whose plans name `"branch": "release"` is ready | The `land` job opens the landing PR from `stack/<ID>` into `release`, and its body says so |
| 43 | A per-leg mission names a `branch` | Its jobs' landing branch is that branch; an A3 PASS PR targets it |
| 44 | A2 lists an in-scope file in `.mission-dispatch/DELETE` | The file is deleted in A2's PR (not emptied); the listing is not committed; a deletion alone is a build |
| 45 | A2 lists a path outside `build_scope`, under `missions/`, missing, a directory, absolute, with `.`/`..`, or behind a symbolic link | The run is refused and no listed file is deleted, even when other listed paths are valid |
| 46 | A3 writes `.mission-dispatch/DELETE` | Ignored; A3 may still only add its verdict |
| 47 | `runtime_binding` absent or `"off"` | Every runtime argument as before; no `binding/` directory |
| 48 | `runtime_binding` set to anything but `"off"` or `"enforce"` | The job fails |
| 49 | Enforced, Claude Code | `--tools`, allow rules and `mcp__governed-retrieval__*` from the binding; `--mcp-config` beside `--strict-mcp-config`; the dispatcher's denials all still present |
| 50 | Enforced, the binding names `Bash`, an allow rule outside the checkout, or refuses | The job fails before any agent starts |
| 51 | Enforced, the binding library is missing | The job fails before any agent starts |
| 52 | Enforced, the binding record is missing or altered when the agent starts | The job fails; no agent starts |
| 53 | Enforced, Cursor | `Mcp(governed-retrieval:*)` rules, `--approve-mcps`, `.cursor/mcp.json` naming only the gateway and removed after the run; refused when `~/.cursor/mcp.json` exists |
| 54 | Enforced, the MCP config | One server; `python3 -m mcp_gateway`; `PYTHONPATH` the tooling tree; session and evidence read-only and outside the checkout |
| 55 | Enforced, `collect` | The binding record and the gateway's evidence log are kept in `binding/` beside the patch; `publish` ignores them |
