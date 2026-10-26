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

## Requirements

- A GitHub repository with GitHub Actions, and admin rights on it.
- One GitHub App per agent: `a1`, `a2` and `a3`. A person may hold the A1 seat and write every plan; the `a1` App
  still needs its entry in the config and its row in the registry.
- An account for each runtime you use: an Anthropic API key (or a Claude Code OAuth token) for `claude-code`, a Cursor
  API key for `cursor-cli`.
- Familiarity with GitHub Apps, Actions environments and repository secrets. Setup takes about an hour.

## Install

1. **Copy the files** into your repository at the same paths: everything under `tools/agent_workflow/` and
   `docs/IDENTITY-REGISTRY.md`. Copy `packaging/workflows/mission-router.yml` and
   `packaging/workflows/mission-agent.yml` into `.github/workflows/`.
2. **Create a GitHub App per agent** (for example `yourorg-agent-a1`, `yourorg-agent-a2`, `yourorg-agent-a3`) with
   repository permissions
   Contents: read and write, Pull requests: read and write, and nothing else. Never give an agent App Workflows or
   Administration. Install each App on the repository.
3. **Fill in the identity registry** (`docs/IDENTITY-REGISTRY.md`): each App's ID and installation ID in place of
   the examples. An agent may act only while its row says `ACTIVE`.
4. **Fill in the config** (`tools/agent_workflow/mission_router/config.json`): `hitl_logins` lists the GitHub logins
   allowed to approve, `identity_registry` is the registry's path, and `agents` maps `a1`, `a2` and `a3` to each App's
   bot login (`<app-slug>[bot]`).
5. **Create the environments** (Settings → Environments), each limited to the `main` branch, with no required reviewers
   and administrator bypass off:
   - `mission-agent-a2` and `mission-agent-a3`: variable `APP_ID` (the App's ID) and secret `APP_PRIVATE_KEY` (the
     App's private key, pasted from its `.pem` file).
   - `mission-runtime`: secret `ANTHROPIC_API_KEY` (or `CLAUDE_CODE_OAUTH_TOKEN`) and/or `CURSOR_API_KEY`.
6. **Protect `main`** (Settings → Branches): require the status check `route-handoff-block` from GitHub Actions, and
   block force pushes and deletions. Merge the install itself by hand before you add the check.
7. **Run a first mission.** Add `missions/M-ZERO-001/PLAN.md` and `missions/M-ZERO-001/mission.json` that create one
   small file, open the PR, and comment `/mission approve <commit sha>` on it. The router takes it from there.

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

## Adapting the policy tables

`tools/agent_workflow/router_spec002/policy_tables.json` ships with the rules of the deployment GCS came from. Review
it before your first mission: it decides which paths are `AUTHORITY` in your repository. Changing it is itself an
`AUTHORITY` change, made by a person.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) (contributions are signed off under the Developer Certificate of Origin) and
[SECURITY.md](SECURITY.md) (report vulnerabilities privately, never in a public issue).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
