# Credentials register

Every credential the mission pipeline uses, or that can act on its repositories: where it is held, what it can do,
and how to make it useless. **It never holds a value.** `config.json` names this file as `credentials_register`.

The Credentials Check workflow (`packaging/workflows/credentials-check.yml`) compares every `secrets.<NAME>` and
`vars.<NAME>` in your workflows with this table, on every pull request and every push to `main`. A use with no row, a
row naming a job that no longer uses it, a job holding a credential somewhere else than its row says, and
`secrets: inherit`, `toJSON(secrets)` or `secrets[...]` are findings. Under `"identity": "observe"` they are printed;
under `"enforce"` the check fails. No mission can change this file.

| Credential | Kind | Held in | Used by | Can do | Revoke | Rotated |
|---|---|---|---|---|---|---|
| APP_PRIVATE_KEY | secret | environment:mission-agent-* | mission-agent.yml:publish, mission-agent.yml:land | One per agent environment (`mission-agent-a2`, `mission-agent-a3`), usable only by workflows running on `main`. Mints that agent App's token: the job narrows it to this repository with contents and pull requests write, but the key itself can mint a token for every repository the App is installed on | On the App's settings page (GitHub → Settings → Developer settings → GitHub Apps → the App → Private keys), delete the key. Generate a new one and paste the downloaded `.pem` into the environment secret, then delete the file | - |
| APP_ID | variable | environment:mission-agent-* | mission-agent.yml:publish, mission-agent.yml:land | Not secret: names which App a key belongs to. The job refuses to push when it differs from the identity registry | Nothing to revoke; correct it in the environment's variables | - |
| EVIDENCE_SEAL_KEY | secret | environment:evidence-seal | evidence-seal.yml:seal | The evidence key's 32-byte Ed25519 seed (MISSION-DISPATCH-001 §3m item 2), usable only by workflows running on `main`. Seals each job's evidence chain; whoever holds it can seal a false record (limit 30). Its public half is pinned in `tools/agent_workflow/evidence/key.json`, so a seal by any other key is refused. Made by `python3 -m evidence keygen`, which sets this secret through `gh` and never prints the seed | Run `python3 -m evidence keygen --repo <this repository> --env evidence-seal` in HITL's own terminal: it replaces the secret. Pin the new public half in `key.json` by a HITL hand-merged PR, keeping the old one listed so earlier seals still verify | - |
| EVIDENCE_APP_PRIVATE_KEY | secret | environment:evidence-seal | evidence-seal.yml:seal | Mints the evidence App's token: the job narrows it to the evidence store (`config.json` `evidence_store`) with contents write. The App is installed only on the store, and no agent App is installed there; the store's protection stops force-pushes and deletion (§3m item 3) | On the evidence App's settings page (GitHub → Settings → Developer settings → GitHub Apps → the App → Private keys), delete the key. Generate a new one, set it as this environment secret from HITL's own terminal, then delete the downloaded file | - |
| EVIDENCE_APP_ID | variable | environment:evidence-seal | evidence-seal.yml:seal | Not secret: names the evidence App | Nothing to revoke; correct it in the environment's variables | - |
| EVIDENCE_READER_PRIVATE_KEY | secret | environment:evidence-verify | evidence-verify.yml:verify | Mints the evidence reader App's token: the job narrows it to the evidence store (`config.json` `evidence_store`) with contents read. The reader App is a different identity from the evidence App that writes the store (MISSION-DISPATCH-001 §3m item 7): it is installed only on the store, with Contents read only, so it can read the store and nothing else | On the reader App's settings page (GitHub → Settings → Developer settings → GitHub Apps → the App → Private keys), delete the key. Generate a new one, set it as this environment secret from HITL's own terminal, then delete the downloaded file | - |
| EVIDENCE_READER_APP_ID | variable | environment:evidence-verify | evidence-verify.yml:verify | Not secret: names the evidence reader App | Nothing to revoke; correct it in the environment's variables | - |
| ANTHROPIC_API_KEY | secret | environment:mission-runtime | mission-agent.yml:agent | Spends on the Anthropic account it belongs to (Claude Code, when set instead of the OAuth token). Lives only in the agent's runtime process; a change containing it is refused | Anthropic Console → API keys: delete the key; create a new one and paste it into the environment secret | - |
| CLAUDE_CODE_OAUTH_TOKEN | secret | environment:mission-runtime | mission-agent.yml:agent | Runs Claude Code on the Claude subscription it was made from. Lives only in the agent's runtime process; a change containing it is refused | Revoke it from the Claude account it was made with; make a new one with `claude setup-token` and paste it into the environment secret | - |
| CURSOR_API_KEY | secret | environment:mission-runtime | mission-agent.yml:agent | Runs the Cursor CLI on the Cursor account it belongs to. Lives only in the agent's runtime process; a change containing it is refused | Cursor dashboard → API keys: delete the key; create a new one and paste it into the environment secret | - |
| Maintainer GitHub login | user-login | outside:the maintainer's own machine | - | Everything the repository owner can do, including merging, settings and secrets | GitHub → Settings → Sessions and Developer settings → tokens: sign out the session or revoke the token | - |

Delete the rows for the runtimes you do not use, and the matching workflow lines, together. Add a row for every
other credential that can act on your repositories, such as App keys kept outside GitHub (`outside:<where>`).

`GITHUB_TOKEN` has no row: GitHub mints it for each run, and each workflow's `permissions` limits it.

**Revoking a credential:** `/mission halt` every mission that could be using it; for an agent App, set its identity
registry row to `SUSPENDED`; follow the row's **Revoke** steps; place the replacement; write the date in **Rotated**;
then `/mission resume`.
