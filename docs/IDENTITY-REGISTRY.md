# Identity registry

The mission router reads this table on `main`. An agent may act only while its row says `ACTIVE`. Change a row to
`SUSPENDED` or `RETIRED` to stop that agent at the router's next sweep. Changes to this file are made by a person, not
by a mission.

| Role | App ID | Installation ID | Status | Permissions | Account ID |
|---|---|---|---|---|---|
| a2 | 1000002 | 2000002 | ACTIVE | contents write, PRs write | 3000002 |
| a3 | 1000003 | 2000003 | ACTIVE | contents write, PRs write | 3000003 |

Replace the example IDs with your Apps' IDs (App settings → General), installation IDs (the number at the end of
the installation's settings URL) and account IDs. An App's account ID is the `id` GitHub returns for its bot:
`gh api 'users/<app-slug>[bot]' --jq .id`. The router checks every login together with its account ID, and a row
without one cannot act. Put your own account ID in `hitl_account_ids` in `config.json` the same way
(`gh api users/<your-login> --jq .id`). This file cannot be changed by a mission.
