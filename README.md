# Governance Control System (GCS)

GCS runs AI coding agents inside a GitHub repository under rules a person sets and can check afterwards.
Every change follows the same path: a plan a person approves, a build by one agent, a review by a different agent
against that plan, and only then a merge into `main`. Each step is a pull request made under the agent's own GitHub
App identity, so the history shows who did what, when, and under which approval.

GCS is audit-ready by design: the plan, the build, the review verdict and the merge are all kept in the repository and
its pull requests. It is not a compliance certification, and it does not replace your own review of what you merge.

**Status:** early release. The design is stable and in daily use; expect rough edges in setup.

## How it works

```
A1  plan    a person writes missions/<ID>/PLAN.md and mission.json, opens a PR, and approves its exact commit
A2  build   an agent builds only inside the plan's build_scope, as its own GitHub App, in its own PR
A3  review  a different agent compares A2's build with the plan and records PASS, FAIL or BLOCKED
land        on PASS the router merges the mission into main; on FAIL the build goes back to A2
```

- **The router** (`tools/agent_workflow/mission_router/`) is a GitHub Actions workflow. It is a handler and a merger,
  not a judge: it checks who opened each PR, whether it stays inside the approved scope, and whether the review
  passed, then merges or refuses. It owns `main`'s required check, `route-handoff-block`; a PR that is not a passed
  mission fails it.
- **The Mission Agent** (`tools/agent_workflow/mission_dispatch/`) starts A2 and A3 on GitHub Actions with the runtime
  the plan names (`claude-code` or `cursor-cli`), and opens their PRs under each agent's App identity. The agent never
  holds a GitHub token.
- **The policy engine** (`tools/agent_workflow/router_spec002/`) classifies every changed path. Paths that control the
  pipeline itself (its code, its workflows, its policy tables) are `AUTHORITY`: no mission may change them; only a
  person can.
- **One approval.** A person approves a plan once, by its exact commit (`/mission approve <sha>`). A new push needs a
  new approval. `/mission cancel` and `/mission retry` are the only other commands, and only listed people may use
  them.

The specifications are in `tools/agent_workflow/specs/`: `MISSION-ROUTER-001.md`, `MISSION-DISPATCH-001.md` and
`ROUTER-POLICY-SPEC-002.md`.

**EPAP** (Evidence, Provenance and Audit Proof) is the record that ties each change to its plan, its build, its review
and its merge, signed so it can be checked later. Its code is in `tools/agent_workflow/epap/`.

## Requirements

- A GitHub repository with GitHub Actions, admin rights on it, and a `main` branch. For a new repository, tick "Add a
  README file" when you create it, so `main` exists and the install can arrive as a pull request.
- **Public repository, or a paid GitHub plan.** On GitHub Free, branch protection (step 7) is not enforced in a private
  repository, so `main` would accept merges and pushes the router never checked. A private repository needs GitHub
  Team or Enterprise.
- Two GitHub Apps: `a2` (the builder) and `a3` (the reviewer). The A1 seat is a person: you write each plan and open its
  PR from your own account, which the router accepts from any login in `hitl_logins`. A1 needs no App.
- An account for each runtime you use: an Anthropic API key (or a Claude Code OAuth token) for `claude-code`, a Cursor
  API key for `cursor-cli`.
- Familiarity with GitHub Apps, Actions environments and repository secrets. Setup takes about an hour.

**Running cost.** The router runs every 5 minutes and the Mission Agent every 10, whether or not a mission is running.
In a public repository Actions minutes are free. In a private one each run is billed as at least one minute, which can
use up GitHub Free's monthly allowance in about two weeks. The Mission Agent's schedule is only a fallback (the router
starts it on every handoff), so it can be slowed. The router's cannot be removed: pull requests into mission branches
are seen only by its schedule.

## Install

1. **Copy the files** into your repository at the same paths: everything under `tools/agent_workflow/` and
   `docs/IDENTITY-REGISTRY.md`. Copy `packaging/workflows/mission-router.yml` and
   `packaging/workflows/mission-agent.yml` into `.github/workflows/`. Commit them on a branch, open a pull request,
   and merge it yourself; nothing checks it yet.
2. **Create two GitHub Apps** (for example `yourorg-agent-a2` and `yourorg-agent-a3`), in your organization's
   settings → Developer settings → GitHub Apps:
   - Homepage URL: any URL, for example your repository's.
   - Webhook: untick **Active**. GCS uses no webhooks.
   - Repository permissions: Contents: read and write, Pull requests: read and write, and nothing else. Never give an
     agent App Workflows or Administration.
   - Where can this App be installed: only on this account.

   After creating each App, note its **App ID** (App settings → General) and, at the bottom of that page, **Generate a
   private key** (a `.pem` file, used in step 5; not a client secret). Install each App on this repository only, and
   note its **installation ID**: the number at the end of the installation's settings URL.
3. **Fill in the identity registry** (`docs/IDENTITY-REGISTRY.md`): each App's ID and installation ID in place of
   the examples. An agent may act only while its row says `ACTIVE`.
4. **Fill in the config** (`tools/agent_workflow/mission_router/config.json`): `hitl_logins` lists the GitHub logins
   allowed to approve plans (and to hold the A1 seat), `identity_registry` is the registry's path, and `agents` maps
   `a2` and `a3` to each App's bot login (`<app-slug>[bot]`). Merge steps 3 and 4 by hand, like step 1.
5. **Create the environments** (repository Settings → Environments; environments belong to the repository, not the
   organization), each limited to the `main` branch ("Selected branches and tags", rule `main`), with no required
   reviewers and administrator bypass off:
   - `mission-agent-a2` and `mission-agent-a3`: variable `APP_ID` (the App's ID) and secret `APP_PRIVATE_KEY` (the
     App's private key: the whole `.pem` file, including its BEGIN and END lines). Delete the `.pem` files afterwards.
   - `mission-runtime`: secret `ANTHROPIC_API_KEY` (or `CLAUDE_CODE_OAUTH_TOKEN`) and/or `CURSOR_API_KEY`. No
     variables.

   Where the page offers no "Allow administrators to bypass" checkbox (a private repository on GitHub Free), turn it
   off with the API, for each environment:

   ```
   echo '{"can_admins_bypass":false,"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}' \
     | gh api -X PUT repos/<owner>/<repo>/environments/<name> --input -
   ```
6. **Let the router approve pull requests.** The router approves each passed mission before it merges it, so in
   Settings → Actions → General → Workflow permissions, tick **Allow GitHub Actions to create and approve pull
   requests** and save. Keep "Read repository contents and packages permissions": each workflow asks for its own write
   permissions. In an organization the box is greyed out until the organization allows it (organization Settings →
   Actions → General, same section). Without it, an A3 PASS never merges and the router reports "GitHub will not merge
   it yet".
7. **Protect `main`** (Settings → Branches): require the status check `route-handoff-block` from GitHub Actions, and
   block force pushes and deletions. Merge the install itself by hand before you add the check (steps 1, 3 and 4).
8. **Run a first mission.** On a branch named exactly `mission/M-ZERO-001/a1`, add `missions/M-ZERO-001/PLAN.md` and
   `missions/M-ZERO-001/mission.json`, and open the pull request from your own account. The router takes only plan
   PRs from a branch named `mission/<ID>/a1`; any other branch name gets "Not a mission". It points the PR at a new
   `mission/M-ZERO-001/integration` branch and comments the command to approve it. Comment `/mission approve <commit
   sha>` on the PR. The router takes it from there.

A `mission.json`:

```json
{
  "schema": "mission-v1",
  "mission_id": "M-ZERO-001",
  "title": "Prove the mission loop with one new file",
  "roles": {
    "A1": {"agent": "a1"},
    "A2": {"agent": "a2", "runtime": "claude-code"},
    "A3": {"agent": "a3", "runtime": "cursor-cli"}
  },
  "build_scope": ["docs/PIPELINE-PROOF.md"]
}
```

`A1`'s agent is a label only: the person who opens the plan holds the seat. `A3` must be a different agent from `A1`
and `A2`.

A `PLAN.md`: the agents read it; the router does not. Say what to build, and what A3 must check to PASS.

```markdown
# M-ZERO-001: Prove the mission loop with one new file

## Build (A2)

Create `docs/PIPELINE-PROOF.md` containing a level-one heading `Pipeline proof` and one sentence saying this file was
written by the A2 agent for mission M-ZERO-001. Change nothing else.

## Review (A3)

PASS only if `docs/PIPELINE-PROOF.md` is the only file the build changed, and it has the heading and the sentence
described above. Otherwise FAIL, naming what is missing.
```

### If a mission does not move

- **It waits after A2 or A3 opens its PR.** Those PRs are picked up by the router's 5-minute schedule, and GitHub may
  take hours to start a new repository's schedules and skips some runs under load. Actions → Mission Router → **Run
  workflow** runs the same sweep at once.
- **"GitHub will not merge it yet" on a PASS.** Step 6 is missing.
- **"Not a mission" on a plan.** The branch name is not `mission/<ID>/a1` (step 8).

## Adapting the policy tables

`tools/agent_workflow/router_spec002/policy_tables.json` ships with the rules of the deployment GCS came from. Review
it before your first mission: it decides which paths are `AUTHORITY` in your repository. Changing it is itself an
`AUTHORITY` change, made by a person.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) (contributions are signed off under the Developer Certificate of Origin),
[SECURITY.md](SECURITY.md) (report vulnerabilities privately, never in a public issue) and the
[Code of Conduct](CODE_OF_CONDUCT.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
