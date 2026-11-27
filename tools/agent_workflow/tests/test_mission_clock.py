"""The mission clock (MISSION-ROUTER-001 Amendment 028; MISSION-DISPATCH-001 Amendment 058): the router's 5-minute
sweep runs only while machines work on a mission, and the router starts the Mission Agent workflow and the seal sweep
as the fallbacks that replaced their own schedules. Placeholder repositories and accounts only."""

from __future__ import annotations

import datetime
import re
import unittest
from pathlib import Path
from types import SimpleNamespace

from mission_router import clock
from mission_router.github import GitHubError
from mission_router.state import AWAIT_A1, AWAIT_A2, AWAIT_A3, BLOCKED, DONE

ROOT = Path(__file__).resolve().parents[3]
NOW = datetime.datetime(2026, 11, 27, 12, 0, tzinfo=datetime.timezone.utc)


def at(minutes_ago: float) -> str:
    return (NOW - datetime.timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def workflow(name: str) -> str:
    live = ROOT / ".github" / "workflows" / name
    return (live if live.is_file() else ROOT / "packaging" / "workflows" / name).read_text(encoding="utf-8")


class FakeGH:
    """The Actions and pulls API the clock reads, and the writes it makes."""

    def __init__(self, clock_state="active", closed=(), runs=None, missing=False, refuse=()):
        self.clock_state, self.closed, self.missing, self.refuse = clock_state, list(closed), missing, set(refuse)
        self.runs = runs or {}  # {workflow: [run]}
        self.writes = []

    def _check(self, what):
        if what in self.refuse:
            raise GitHubError(403, "Resource not accessible by integration", what)

    def request(self, method, path, body=None):
        if path.startswith("/pulls?state=closed"):
            return self.closed
        m = re.fullmatch(r"/actions/workflows/([\w.-]+)/runs\?per_page=20", path)
        if m:
            return {"workflow_runs": self.runs.get(m.group(1), [])}
        raise AssertionError(path)

    def workflow_state(self, name):
        assert name == clock.CLOCK_WORKFLOW
        if self.missing:
            raise GitHubError(404, "Not Found", name)
        self._check("state")
        return self.clock_state

    def set_workflow_enabled(self, name, enabled):
        self._check("enable" if enabled else "disable")
        self.writes.append(("enable" if enabled else "disable", name))
        self.clock_state = "active" if enabled else "disabled_manually"

    def dispatch_workflow(self, name, ref, inputs=None):
        self._check(name)
        self.writes.append(("dispatch", name, ref, inputs))


class FakeRouter:
    def __init__(self, gh, open_prs=None, landing_prs=None):
        self.gh, self.main = gh, "main"
        self._open_prs, self._landing_prs = open_prs or {}, landing_prs or {}
        self.records = []

    def _write(self, what, fn, action, **subject):
        self.records.append((action, what))  # recorded first (Amendment 018)
        return fn()


def state(stage):
    return SimpleNamespace(stage=stage)


def stage_pr(mission="M-DEMO-001", role="a3-r1", closed_minutes_ago=None):
    pr = {"head": {"ref": f"mission/{mission}/{role}"}}
    if closed_minutes_ago is not None:
        pr["closed_at"] = at(closed_minutes_ago)
    return pr


class ActivityTests(unittest.TestCase):
    def test_vector_146_what_counts_as_machines_working(self):
        self.assertEqual(clock.machine_active({"M-A": state(AWAIT_A2), "M-B": state(AWAIT_A3)}, {}, {}),
                         ["M-A waits on A2", "M-B waits on A3"])
        self.assertEqual(clock.machine_active({"M-C": state(AWAIT_A1)}, {"M-C": [stage_pr("M-C", "a1")]}, {}),
                         ["M-C has an open PR"], "a plan PR: AR's rounds, its checks")
        self.assertEqual(clock.machine_active({}, {}, {"S-1": [{}]}), ["stack S-1 has an open landing PR"])
        idle = {"M-D": state(AWAIT_A1), "M-E": state(BLOCKED), "M-F": state(DONE)}
        self.assertEqual(clock.machine_active(idle, {"M-D": []}, {}), [],
                         "a plan branch with no PR, and missions waiting on HITL, wake the router by their own event")

    def test_vector_146_the_last_closed_mission_pr(self):
        gh = FakeGH(closed=[{"head": {"ref": "docs/x"}, "closed_at": at(1)}, stage_pr(closed_minutes_ago=12),
                            stage_pr(closed_minutes_ago=50)])
        self.assertEqual(clock.last_closed(gh.request), at(12), "a PR outside the missions does not count")


class TickTests(unittest.TestCase):
    def tick(self, gh, states=None, **kw):
        router = FakeRouter(gh, **kw)
        return router, clock.tick(router, states or {}, NOW)

    def test_vector_146_idle_switches_the_clock_off_and_starts_nothing(self):
        gh = FakeGH(closed=[stage_pr(closed_minutes_ago=31)])
        router, done = self.tick(gh, {"M-OLD": state(AWAIT_A1)})
        self.assertEqual(gh.writes, [("disable", clock.CLOCK_WORKFLOW)])
        self.assertEqual(router.records, [("router.clock", f"switch off {clock.CLOCK_WORKFLOW}: idle")])
        gh.writes.clear()
        self.tick(gh)
        self.assertEqual(gh.writes, [], "already off: nothing written")

    def test_vector_146_cooling_keeps_it_on_for_30_minutes(self):
        gh = FakeGH(clock_state="active", closed=[stage_pr(closed_minutes_ago=29)])
        _, done = self.tick(gh)
        self.assertNotIn(("disable", clock.CLOCK_WORKFLOW), gh.writes)
        self.assertIn(("dispatch", clock.SEAL_WORKFLOW, "main", {"sweep": "true"}), gh.writes,
                      "the seal sweep still seals the last runs")

    def test_vector_146_a_mission_switches_it_on_and_starts_the_fallbacks(self):
        gh = FakeGH(clock_state="disabled_manually")
        router, done = self.tick(gh, {"M-A": state(AWAIT_A3)})
        self.assertEqual(gh.writes, [("enable", clock.CLOCK_WORKFLOW),
                                     ("dispatch", clock.AGENT_WORKFLOW, "main", None),
                                     ("dispatch", clock.SEAL_WORKFLOW, "main", {"sweep": "true"})])
        self.assertEqual([a for a, _ in router.records], ["router.clock", "router.dispatch", "router.dispatch"])
        self.assertIn("M-A waits on A3", router.records[0][1])

    def test_vector_147_each_fallback_at_most_every_10_minutes_and_never_twice_at_once(self):
        runs = {clock.AGENT_WORKFLOW: [{"event": "workflow_dispatch", "status": "completed", "created_at": at(9)},
                                       {"event": "issue_comment", "status": "in_progress", "created_at": at(1)}],
                clock.SEAL_WORKFLOW: [{"event": "workflow_dispatch", "status": "in_progress", "created_at": at(20)}]}
        gh = FakeGH(runs=runs)
        _, done = self.tick(gh, {"M-A": state(AWAIT_A2)})
        self.assertEqual(gh.writes, [], "the agent started 9 minutes ago (a comment's run does not count); the seal "
                                        "sweep is still going")
        runs[clock.AGENT_WORKFLOW][0]["created_at"] = at(10)
        runs[clock.SEAL_WORKFLOW][0]["status"] = "completed"
        self.tick(gh, {"M-A": state(AWAIT_A2)})
        self.assertEqual([w[1] for w in gh.writes], [clock.AGENT_WORKFLOW, clock.SEAL_WORKFLOW])

    def test_vector_147_a_clock_that_cannot_be_switched_on_fails_the_run(self):
        for refused in ("enable", "state"):
            gh = FakeGH(clock_state="disabled_manually", refuse={refused})
            with self.subTest(refused), self.assertRaises(clock.ClockError):
                self.tick(gh, {"M-A": state(AWAIT_A2)})
        gh = FakeGH(clock_state="active", refuse={"disable"}, closed=[])
        _, done = self.tick(gh)
        self.assertIn("could not be switched off", done[0], "off is only cost: the next sweep tries again")

    def test_vector_147_a_fallback_github_refuses_is_left_for_the_next_sweep(self):
        gh = FakeGH(refuse={clock.AGENT_WORKFLOW})
        _, done = self.tick(gh, {"M-A": state(AWAIT_A2)})
        self.assertIn(f"{clock.AGENT_WORKFLOW} could not be started (403); the next sweep tries again", done)
        self.assertIn(("dispatch", clock.SEAL_WORKFLOW, "main", {"sweep": "true"}), gh.writes)

    def test_vector_147_no_clock_workflow_no_clock(self):
        gh = FakeGH(missing=True)
        _, done = self.tick(gh, {"M-A": state(AWAIT_A2)})
        self.assertEqual((gh.writes, done), ([], [f"no {clock.CLOCK_WORKFLOW} in this repository; the clock is not used"]))

    def test_vector_147_the_router_runs_the_clock_after_each_sweep(self):
        import io
        from contextlib import redirect_stdout
        from unittest import mock
        from mission_router import __main__ as cli
        fake = mock.MagicMock()
        fake.sweep.return_value = {}
        with mock.patch.object(cli, "MissionRouter", return_value=fake), mock.patch.object(cli, "load_config"), \
                mock.patch.object(cli, "GitHub"), \
                mock.patch.object(cli, "classify_or_raise"), mock.patch.object(cli, "load_tables"), \
                mock.patch.object(clock, "tick", side_effect=clock.ClockError("x")) as tick:
            with redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["--repo", "o/r"]), 1, "a clock that must be on and is not fails the run")
                self.assertEqual(cli.main(["--repo", "o/r", "--dry-run"]), 0)
        self.assertEqual(tick.call_count, 1, "a dry run writes nothing, so it switches nothing")


class WorkflowTests(unittest.TestCase):
    def test_vector_148_the_clock_is_the_router_sweep_step_for_step(self):
        router, clocked = workflow("mission-router.yml"), workflow("mission-clock.yml")
        body = lambda text: text[text.index("    runs-on: ubuntu-latest"):]  # noqa: E731
        self.assertEqual(body(clocked), body(router), "the same job, steps, token and permissions")
        for text in (router, clocked):
            self.assertIn("concurrency:\n  group: mission-router\n", text, "never two sweeps at once")
        self.assertIn('    - cron: "*/5 * * * *"', clocked)
        on = clocked[clocked.index("\non:\n"):clocked.index("\npermissions:")]
        self.assertNotIn("pull_request", on)
        self.assertNotIn("workflow_dispatch", on, "only the router switches it; only the schedule starts it")

    def test_vector_148_the_schedules_the_clock_replaced(self):
        router = workflow("mission-router.yml")
        self.assertIn('    - cron: "*/30 * * * *"', router, "the heartbeat: a plan PR into a mission branch sends no event")
        self.assertNotIn("*/5", router)
        agent = workflow("mission-agent.yml")
        self.assertNotIn("schedule:", agent[agent.index("\non:\n"):agent.index("\npermissions:")])
        seal = workflow("evidence-seal.yml")
        on = seal[seal.index("\non:\n"):seal.index("\npermissions:")]
        self.assertEqual(re.findall(r'cron: "([^"]+)"', on), ["23 4 * * *"], "only the daily deep sweep")
        self.assertIn("sweep:\n", on)
        for line in seal.splitlines():
            if "github.event_name == 'schedule'" in line:
                with self.subTest(line=line.strip()):
                    self.assertIn("(github.event_name == 'schedule' || inputs.sweep)", line)
        self.assertIn("github.event_name == 'workflow_dispatch' && !inputs.sweep", seal, "by hand: the backfill")

    def test_vector_148_the_clock_is_sealed_and_checked_like_the_router(self):
        from evidence import sweep
        from mission_dispatch import permissions, supply_chain
        from mission_router import substrate
        self.assertEqual(sweep.WORKFLOWS.get("Mission Clock"), "mission-clock.yml")
        for names in (permissions.WORKFLOWS, supply_chain.MISSION_WORKFLOWS, substrate.WORKFLOWS):
            self.assertIn("mission-clock.yml", names)
        from evidence import record
        self.assertEqual(record.ACTIONS["router.clock"], "write")


if __name__ == "__main__":
    unittest.main()
