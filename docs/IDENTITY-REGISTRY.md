# Identity registry

The mission router reads this table on `main`. An agent may act only while its row says `ACTIVE`. Change a row to
`SUSPENDED` or `RETIRED` to stop that agent at the router's next sweep. Changes to this file are made by a person, not
by a mission.

| Role | App ID | Installation ID | Status | Permissions |
|---|---|---|---|---|
| a1 | 1000001 | 2000001 | ACTIVE | contents write, PRs write |
| a2 | 1000002 | 2000002 | ACTIVE | contents write, PRs write |
| a3 | 1000003 | 2000003 | ACTIVE | contents write, PRs write |

Replace the example IDs with your Apps' IDs (App settings → General) and installation IDs (the number at the end of
the installation's settings URL).
