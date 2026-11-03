"""Credentials register against the workflows (MISSION-DISPATCH-001 Amendment 013, §3i; vectors 59-63)."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from credentials_check.__main__ import main
from credentials_check.check import RegisterError, check, parse_register, scan_workflow

HEADER = "| Credential | Kind | Held in | Used by | Can do | Revoke | Rotated |\n|---|---|---|---|---|---|---|\n"
REGISTER = HEADER + (
    "| APP_PRIVATE_KEY | secret | environment:agent-* | agent.yml:publish | mint | delete the key | - |\n"
    "| APP_ID | variable | environment:agent-* | agent.yml:publish | names the App | fix it | - |\n"
    "| MODEL_KEY | secret | environment:runtime | agent.yml:run | run the model | delete it | - |\n"
    "| spare App key | app-key | outside:HITL laptop | - | write | delete it | - |\n")
WORKFLOW = """name: Agent
on:
  push:
permissions: {}
jobs:
  run:
    runs-on: ubuntu-latest
    environment: runtime
    steps:
      - run: echo
        env:
          MODEL_KEY: ${{ secrets.MODEL_KEY }}
          TOKEN: ${{ secrets.GITHUB_TOKEN }}
  publish:
    runs-on: ubuntu-latest
    environment:
      name: agent-${{ matrix.job.agent }}
    steps:
      # a comment naming secrets.ANYTHING and secrets: inherit is not code
      - uses: some/action@0123
        with:
          app-id: ${{ vars.APP_ID }}
          private-key: ${{ secrets.APP_PRIVATE_KEY }}
"""


class CredentialsCheckTests(unittest.TestCase):
    def findings(self, register=REGISTER, workflow=WORKFLOW, **more):
        return check(register, {"agent.yml": workflow, **more})

    def test_a_register_that_matches_has_no_findings(self):
        self.assertEqual(self.findings(), [])

    def test_an_unlisted_secret_is_a_finding(self):  # vector 59
        workflow = WORKFLOW + "          OTHER: ${{ secrets.NEW_TOKEN }}\n"
        (finding,) = self.findings(workflow=workflow)
        self.assertIn("agent.yml:24: secret NEW_TOKEN has no row", finding)

    def test_a_listed_secret_used_by_another_job_is_a_finding(self):
        workflow = WORKFLOW.replace("          TOKEN: ${{ secrets.GITHUB_TOKEN }}\n",
                                    "          KEY: ${{ secrets.APP_PRIVATE_KEY }}\n")
        found = self.findings(workflow=workflow)
        self.assertTrue(any("used by job run, which no row" in f for f in found), found)

    def test_wholesale_and_computed_secrets_are_refused(self):  # vector 60
        for line, why in (("    secrets: inherit", "secrets: inherit"), ("          ALL: ${{ toJSON(secrets) }}", "toJSON"),
                          ("          ONE: ${{ secrets[format('K_{0}', github.actor)] }}", "secrets[...]")):
            with self.subTest(why=why):
                found = self.findings(workflow=WORKFLOW + line + "\n")
                self.assertTrue(any(why in f for f in found), found)

    def test_a_row_naming_a_job_that_no_longer_uses_it_is_stale(self):  # vector 61
        register = REGISTER.replace("| agent.yml:run |", "| agent.yml:run, agent.yml:publish |")
        (finding,) = self.findings(register=register)
        self.assertIn("stale row: MODEL_KEY (secret) names agent.yml:publish", finding)
        (finding,) = self.findings(workflow=WORKFLOW.replace("          MODEL_KEY: ${{ secrets.MODEL_KEY }}\n", ""))
        self.assertIn("stale row: MODEL_KEY", finding)

    def test_held_somewhere_else_than_the_row_says_is_a_finding(self):  # vector 62
        found = self.findings(workflow=WORKFLOW.replace("    environment: runtime\n", "    environment: production\n"))
        self.assertTrue(any("holds MODEL_KEY in environment:production" in f for f in found), found)
        found = self.findings(workflow=WORKFLOW.replace("    environment: runtime\n", ""))
        self.assertTrue(any("holds MODEL_KEY in repository or organization" in f for f in found), found)

    def test_a_run_time_environment_name_is_matched_as_a_star(self):
        uses, problems = scan_workflow("agent.yml", WORKFLOW)
        self.assertEqual(problems, [])
        self.assertEqual({u.held_in for u in uses if u.job == "publish"}, {("environment:agent-*",)})
        self.assertNotIn("GITHUB_TOKEN", {u.name for u in uses})

    def test_a_secret_outside_any_job_is_refused(self):
        workflow = WORKFLOW.replace("permissions: {}\n", "permissions: {}\nenv:\n  K: ${{ secrets.MODEL_KEY }}\n")
        self.assertTrue(any("outside any job" in f for f in self.findings(workflow=workflow)))

    def test_an_unusable_register_is_one_finding(self):
        for bad in ("", "no table", HEADER + "| X | secret | somewhere | - | a | b | - |\n",
                    HEADER + "| X | weird | repository | - | a | b | - |\n",
                    HEADER + "| X | secret | repository | not a use | a | b | - |\n",
                    REGISTER + "| MODEL_KEY | secret | environment:runtime | - | a | b | - |\n",
                    HEADER + "| X | secret | repository | - | a | b |\n"):
            with self.subTest(bad=bad[-60:]):
                (finding,) = self.findings(register=bad)
                self.assertIn("register is unusable", finding)

    def test_the_register_never_holds_a_value(self):
        leaked = REGISTER.replace("| mint |", "| ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8 |")
        with self.assertRaises(RegisterError):
            parse_register(leaked)

    def test_the_cli_fails_only_under_enforce(self):  # vector 63
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github" / "workflows" / "agent.yml").write_text(WORKFLOW + "          X: ${{ secrets.NEW }}\n")
            (root / "REG.md").write_text(REGISTER)
            config = {"hitl_logins": ["hitl"], "bot_login": "github-actions[bot]", "default_branch": "main",
                      "identity_registry": "IDS.md", "agents": {"a2": "agent-a2[bot]"}, "credentials_register": "REG.md"}
            for mode, code in (("observe", 0), ("enforce", 1)):
                (root / "config.json").write_text(json.dumps({**config, "identity": mode}))
                out = io.StringIO()
                with redirect_stdout(out):
                    self.assertEqual(main(["--root", tmp, "--config", str(root / "config.json")]), code)
                self.assertIn("FINDING agent.yml:24: secret NEW has no row", out.getvalue())
                self.assertIn(f"findings=1 mode={mode}", out.getvalue())
            (root / "config.json").write_text(json.dumps({**config, "credentials_register": "MISSING.md"}))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--root", tmp, "--config", str(root / "config.json")]), 2)

    def test_this_repository_register_matches_its_workflows(self):
        root = Path(__file__).resolve().parents[3]
        installed = (root / ".github" / "workflows" / "mission-agent.yml").is_file()
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(["--root", str(root), "--workflows", ".github/workflows" if installed else "packaging/workflows"])
        self.assertEqual((code, out.getvalue().strip().splitlines()[-1].split()[0]), (0, "findings=0"), out.getvalue())


if __name__ == "__main__":
    unittest.main()
