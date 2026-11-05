"""The execution substrate (MISSION-DISPATCH-001 Amendment 015, §3h item 6; MISSION-ROUTER-001 Amendment 013)."""

from __future__ import annotations

import io
import json
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from credentials_check.__main__ import main as credentials_main
from mission_router import substrate
from router_spec002.policy import load_tables, match_key

REPO = Path(__file__).resolve().parents[3]
CONFIG = {"hitl_logins": ["hitl"], "bot_login": "github-actions[bot]", "default_branch": "main",
          "identity_registry": "IDS.md", "agents": {"a2": "agent-a2[bot]"}, "credentials_register": "REG.md"}
REGISTER = ("| Credential | Kind | Held in | Used by | Can do | Revoke | Rotated |\n|---|---|---|---|---|---|---|\n"
            "| spare App key | app-key | outside:HITL laptop | - | write | delete it | - |\n")
DECLARATION = """# Substrate declaration
## Disposable
Each runner is a VM made for one job and deleted after it.
## No ambient credentials
The image holds no logins; no metadata service hands out credentials.
## Not shared
One job per VM.
## Root for the job
The job runs with passwordless sudo.

Confirmed by: hitl
Confirmed on: 2026-11-04
"""


def workflow(*jobs: str) -> str:
    return "name: W\non:\n  push:\npermissions: {}\njobs:\n" + "".join(jobs)


def job(name: str, runs_on: str = "ubuntu-latest", extra: str = "") -> str:
    head = f"  {name}:\n" + (f"    runs-on: {runs_on}\n" if runs_on is not None else "")
    return head + extra + "    steps:\n      - run: echo\n"


class ModeAndDeclarationTests(unittest.TestCase):
    def test_mode_defaults_to_observe_and_refuses_anything_else(self):
        self.assertEqual(substrate.mode({}), "observe")
        self.assertEqual(substrate.mode({"substrate": "enforce"}), "enforce")
        for bad in ("off", "", None, True):
            with self.subTest(bad=bad), self.assertRaises(substrate.SubstrateError):
                substrate.mode({"substrate": bad})

    def test_no_declaration_named_is_none(self):
        self.assertIsNone(substrate.declaration({}, REPO))

    def test_a_complete_declaration_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "docs").mkdir()
            (Path(tmp) / "docs" / substrate.DECLARATION_NAME).write_text(DECLARATION)
            self.assertEqual(substrate.declaration({"substrate_declaration": "docs/SUBSTRATE-DECLARATION.md"}, Path(tmp)),
                             "docs/SUBSTRATE-DECLARATION.md")

    def test_a_named_declaration_that_cannot_be_used_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / substrate.DECLARATION_NAME).write_text(DECLARATION.replace("## Not shared", "## Shared"))
            (root / "OTHER.md").write_text(DECLARATION)
            (root / "unconfirmed").mkdir()
            (root / "unconfirmed" / substrate.DECLARATION_NAME).write_text(DECLARATION.replace("hitl", ""))
            for value in ("", 5, "/etc/SUBSTRATE-DECLARATION.md", "../SUBSTRATE-DECLARATION.md", "OTHER.md",
                          "missing/SUBSTRATE-DECLARATION.md", substrate.DECLARATION_NAME,
                          "unconfirmed/SUBSTRATE-DECLARATION.md"):
                with self.subTest(value=value), self.assertRaises(substrate.SubstrateError):
                    substrate.declaration({"substrate_declaration": value}, root)

    def test_the_declaration_is_authority_by_name(self):
        tables = load_tables()
        for path in ("SUBSTRATE-DECLARATION.md", "docs/SUBSTRATE-DECLARATION.md", "ops/SUBSTRATE-DECLARATION.md"):
            with self.subTest(path=path):
                self.assertEqual(tables.classify(match_key(path)), "AUTHORITY")


class StaticCheckTests(unittest.TestCase):
    def test_github_hosted_labels_pass(self):
        text = workflow(job("a"), job("b", "ubuntu-24.04"), job("c", '"ubuntu-22.04"'), job("d", "ubuntu-latest  # pinned"))
        self.assertEqual(substrate.scan_workflow("mission-agent.yml", text), [])

    def test_every_other_runner_is_a_finding(self):
        text = workflow(job("selfhosted", "self-hosted"), job("computed", "${{ matrix.os }}"),
                        job("labels", "[self-hosted, linux]"), job("group", "", "      group: big\n"),
                        job("windows", "windows-latest"), job("arm", "ubuntu-24.04-arm"),
                        job("missing", None), "  call:\n    uses: org/repo/.github/workflows/x.yml@0123\n")
        findings = substrate.scan_workflow("mission-agent.yml", text)
        for name in ("selfhosted", "computed", "labels", "group", "windows", "arm", "missing", "call"):
            with self.subTest(job=name):
                self.assertTrue(any(f" job {name}" in f for f in findings), findings)
        self.assertEqual(len(findings), 8, findings)

    def test_only_the_two_mission_workflows_are_checked(self):
        bad = workflow(job("a", "self-hosted"))
        found = substrate.static_findings({"other.yml": bad, "mission-router.yml": bad, "mission-agent.yml": bad})
        self.assertEqual([f.split(":")[0] for f in found], ["mission-agent.yml", "mission-router.yml"])

    def test_this_repository_workflows_pass(self):
        for folder in (".github/workflows", "packaging/workflows"):
            path = REPO / folder
            if not (path / "mission-agent.yml").is_file():
                continue
            texts = {n: (path / n).read_text(encoding="utf-8") for n in substrate.WORKFLOWS if (path / n).is_file()}
            with self.subTest(folder=folder):
                self.assertEqual(substrate.static_findings(texts), [])


class CredentialsCheckTests(unittest.TestCase):
    def run_check(self, root: Path, config: dict) -> tuple:
        (root / "config.json").write_text(json.dumps(config))
        out = io.StringIO()
        with redirect_stdout(out):
            code = credentials_main(["--root", str(root), "--config", str(root / "config.json")])
        return code, out.getvalue()

    def test_substrate_findings_fail_only_under_enforce_and_not_with_a_declaration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github" / "workflows" / "mission-agent.yml").write_text(workflow(job("agent", "self-hosted")))
            (root / "REG.md").write_text(REGISTER)
            (root / substrate.DECLARATION_NAME).write_text(DECLARATION)
            code, out = self.run_check(root, {**CONFIG, "substrate": "observe"})
            self.assertEqual(code, 0)
            self.assertIn("SUBSTRATE mission-agent.yml:7: job agent runs on 'self-hosted'", out)
            self.assertIn("substrate_findings=1 mode=observe declared=none", out)
            self.assertEqual(self.run_check(root, {**CONFIG, "substrate": "enforce"})[0], 1)
            code, out = self.run_check(root, {**CONFIG, "substrate": "enforce",
                                              "substrate_declaration": substrate.DECLARATION_NAME})
            self.assertEqual(code, 0)
            self.assertIn(f"substrate_findings=0 mode=enforce declared={substrate.DECLARATION_NAME}", out)
            self.assertEqual(out.strip().splitlines()[-1], "findings=0 mode=observe")
            with redirect_stdout(io.StringIO()):  # the CLI writes its reason to stderr
                self.assertEqual(self.run_check(root, {**CONFIG, "substrate_declaration": "x/SUBSTRATE-DECLARATION.md"})[0], 2)
                self.assertEqual(self.run_check(root, {**CONFIG, "substrate": "on"})[0], 2)


class RunTimeCheckTests(unittest.TestCase):
    def test_the_decision(self):
        self.assertTrue(substrate.runtime_decision("github-hosted", "enforce", None)["allow"])
        self.assertTrue(substrate.runtime_decision("self-hosted", "enforce", "docs/SUBSTRATE-DECLARATION.md")["allow"])
        self.assertTrue(substrate.runtime_decision("self-hosted", "observe", None)["allow"])
        for runner in ("self-hosted", "", "GitHub-Hosted"):
            with self.subTest(runner=runner):
                decision = substrate.runtime_decision(runner, "enforce", None)
                self.assertFalse(decision["allow"])
                self.assertIn("refused", decision["record"])

    def test_the_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / substrate.DECLARATION_NAME).write_text(DECLARATION)
            summary = root / "summary.md"
            cases = (({"substrate": "enforce"}, "github-hosted", 0, "substrate: github-hosted (mode=enforce)"),
                     ({"substrate": "observe"}, "self-hosted", 0, "::warning::substrate: self-hosted (would be refused)"),
                     ({"substrate": "enforce"}, "self-hosted", 1, "::error::substrate: self-hosted (refused)"),
                     ({"substrate": "enforce", "substrate_declaration": substrate.DECLARATION_NAME}, "self-hosted", 0,
                      "::warning::substrate: declared (SUBSTRATE-DECLARATION.md)"),
                     ({"substrate": "maybe"}, "github-hosted", 2, "::error::substrate: config.json: substrate must be"))
            for extra, runner, code, line in cases:
                with self.subTest(extra=extra, runner=runner):
                    (root / "config.json").write_text(json.dumps({**CONFIG, **extra}))
                    out = io.StringIO()
                    with redirect_stdout(out):
                        got = substrate.main(["--root", tmp, "--config", str(root / "config.json")],
                                             {"SUBSTRATE_RUNNER": runner, "GITHUB_STEP_SUMMARY": str(summary)})
                    self.assertEqual(got, code, out.getvalue())
                    self.assertTrue(out.getvalue().startswith(line), out.getvalue())
            self.assertIn("substrate: github-hosted (mode=enforce)", summary.read_text())


class WorkflowStepTests(unittest.TestCase):
    """Every job of the two mission workflows runs the run-time check right after its checkout of the default
    branch's own tooling, before any other step (HITL's reading of §3h item 6, governance part 1 PR)."""

    def test_the_check_follows_the_tooling_checkout_in_every_job(self):
        for folder in (".github/workflows", "packaging/workflows"):
            for name in substrate.WORKFLOWS:
                path = REPO / folder / name
                if not path.is_file():
                    continue
                text = path.read_text(encoding="utf-8")
                jobs = re.split(r"\n  (?=[A-Za-z_][A-Za-z0-9_-]*:\n)", text.split("\njobs:\n", 1)[1])
                for body in jobs:
                    steps = re.findall(r"\n      - name: ([^\n]*)", "\n" + body)
                    with self.subTest(workflow=f"{folder}/{name}", job=body.split(":", 1)[0]):
                        self.assertGreaterEqual(len(steps), 2)
                        self.assertTrue(steps[0].startswith("Check out the default branch"), steps[0])
                        self.assertTrue(steps[1].startswith("Check the machine is a GitHub-hosted runner"), steps[1])
                        self.assertIn("SUBSTRATE_RUNNER: ${{ runner.environment }}", body)


class PullRequestBodyTests(unittest.TestCase):
    def test_a_declared_substrate_is_named_in_the_stage_pr(self):
        from mission_dispatch.dispatch import Job, pr_body
        job = Job(mission_id="M-X-001", role="A2", round=1, agent="a2", login="agent-a2[bot]", runtime="claude-code",
                  base_sha="0" * 40, build_scope=("src/**",), title="t")
        self.assertNotIn("declared substrate", pr_body(job, "msg", ""))
        self.assertIn("Runs on a declared substrate: `docs/SUBSTRATE-DECLARATION.md`.",
                      pr_body(job, "msg", "", substrate_declared="docs/SUBSTRATE-DECLARATION.md"))


if __name__ == "__main__":
    unittest.main()
