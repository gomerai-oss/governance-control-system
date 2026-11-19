"""The first harness, read-only: Slack (MISSION-DISPATCH-001 §3p, Amendment 043; APP-CONTROL-HARNESS build part 6).

Vectors 229 to 233: its pin and the review that admits it; the register, catalog, policy, seats and matrix agree on
one app and one seat; its key reaches only that seat's run and collect steps and the perform job's call step; a change
holding the key is refused; and while ``"app_gateway"`` is off, nothing a mission can do changes.
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

AW = Path(__file__).resolve().parents[1]
REPO = AW.parents[1]
sys.path.insert(0, str(AW))

from mcp_auth import policy as P  # noqa: E402
from mcp_gateway import app_gateway as A  # noqa: E402
from mission_dispatch import binding as dispatch_binding  # noqa: E402
from mission_dispatch import dispatch as dispatch_mod  # noqa: E402
from mission_dispatch import runtimes  # noqa: E402
from mission_dispatch import supply_chain as SC  # noqa: E402
from tool_selection import apps as apps_mod  # noqa: E402
from tool_selection import matrix as M  # noqa: E402

RB = None  # tool_selection.runtime_binding, imported for this module's tests only (see setUpModule)


def setUpModule():
    # Not at module level: a loaded tool_selection.runtime_binding would stop test_mission_dispatch's "binding
    # library missing" case from making the import fail (as test_runtime_binding does).
    global RB
    import tool_selection.runtime_binding as RB


def tearDownModule():
    import tool_selection

    sys.modules.pop("tool_selection.runtime_binding", None)
    if hasattr(tool_selection, "runtime_binding"):
        delattr(tool_selection, "runtime_binding")


LIVE = REPO / ".github" / "workflows"
WORKFLOWS = LIVE if LIVE.is_dir() else REPO / "packaging" / "workflows"  # a GCS release ships them as templates
HARNESS = "slack_read"
TOOLS = ["slack_list_channels", "slack_read_channel"]
SEATS = json.loads((AW / "tool_selection" / "seats.json").read_text(encoding="utf-8"))["seats"]
NOW = 1_800_000_000
BASE_SHA = "a" * 40


class Vector229Pin(unittest.TestCase):
    """229: the harness is pinned by its SHA-256, with an independent review of the commit pinned."""

    def test_the_pin_admits_the_file(self):
        row = SC.read_pins(AW / SC.PINS_TABLE)["harnesses"][HARNESS]  # read_pins runs check_harnesses
        data = SC.harness_path(AW, HARNESS).read_bytes()
        self.assertEqual(row["app"], "slack")
        self.assertEqual(row["sha256"], SC.file_sha256(data))
        self.assertEqual(row["review"]["commit"], row["commit"])
        self.assertNotEqual(row["review"]["seat"].lower(), row["built_by"]["seat"].lower())
        self.assertNotEqual(row["review"]["vendor"].lower(), row["built_by"]["vendor"].lower())
        self.assertTrue(row["review"]["report"].startswith("https://"))

    def test_the_review_record_names_the_pin(self):
        row = SC.read_pins(AW / SC.PINS_TABLE)["harnesses"][HARNESS]
        record = (AW / "mcp_gateway" / "HARNESS-REVIEWS.md").read_text(encoding="utf-8")
        section = record.split(f"## `{HARNESS}`", 1)[1]
        for value in (row["sha256"], row["commit"], row["review"]["model"], row["review"]["date"], "**PASS**"):
            self.assertIn(value, section)

    def test_the_public_release_links_the_review_record(self):
        manifests = sorted(AW.glob("*/manifest-gcs.json"))
        if not manifests:
            self.skipTest("no release manifest in this tree; the source repository runs this check")
        doc = json.loads(manifests[0].read_text(encoding="utf-8"))
        pins = (AW / SC.PINS_TABLE).read_text(encoding="utf-8")
        for rule in doc["translate"]:  # as the release build applies them: in order, the replacement literal
            pins = re.sub(rule["pattern"], lambda m, replace=rule["replace"]: replace, pins)
        link = json.loads(pins)["harnesses"][HARNESS]["review"]["report"]
        self.assertEqual(link, f"https://github.com/{doc['target_repo']}/blob/main/tools/agent_workflow/mcp_gateway/"
                               "HARNESS-REVIEWS.md")
        self.assertFalse([t for t in doc["deny_terms"] if re.search(t, pins)])

    def test_the_gateway_runs_the_pinned_bytes(self):
        row = SC.read_pins(AW / SC.PINS_TABLE)["harnesses"][HARNESS]
        run, problem = A.load_harness(AW, HARNESS, row)
        self.assertEqual((problem, callable(run)), (None, True))
        with mock.patch.dict(row, {"sha256": "0" * 64}):
            self.assertEqual(A.load_harness(AW, HARNESS, row), (None, f"harness {HARNESS!r} does not match its pin"))


class Vector230OneAppOneSeat(unittest.TestCase):
    """230: the register, catalog, policy, seats and matrix agree: one app, read-only, for the writer seat only."""

    def test_they_agree(self):
        register, policy = apps_mod.load_file(), P.load_file()
        A.check_register(policy, register)
        catalog = A.load_catalog(A.DEFAULT_CATALOG, policy, register)
        self.assertEqual(sorted(t.name for t in catalog), TOOLS)
        self.assertEqual({(t.app, t.action, t.resource) for t in catalog}, {("slack", "app.read", "app:slack")})
        app = register["apps"]["slack"]
        self.assertEqual((app["classes"], app["writes"], app["tools"]), (["read"], None, TOOLS))
        self.assertEqual({r["method"] for r in app["requests"]}, {"GET"})
        self.assertEqual({seat for seat, row in SEATS.items() if "app:slack" in row["resources"]}, {"A2"})
        matrix = M.load_file()
        self.assertEqual({role for role, row in matrix["roles"].items()
                          if {"app_read", "app_write", "app_send", "app_delete", "app_draft"} & set(row["admit"])},
                         {SEATS["A2"]["role"]})
        self.assertEqual({role for role, row in matrix["roles"].items() if "app_read" in row["admit"]}, {"writer"})
        grants = [g for g in policy["grants"] if g["class"] == "app"]
        self.assertEqual([(g["role"], g["actions"], g["resources"]) for g in grants],
                         [(SEATS["A2"]["fabric_role"], ["app.read"], ["app:slack"])])

    def test_the_writer_is_admitted_the_tools_and_the_reviewers_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "checkout").mkdir()
            for seat in SEATS:
                mission = {"id": "M-TEST-SLACK-001", "round": 1, "agent": SEATS[seat]["principal"],
                           "base_sha": BASE_SHA, "build_scope": ["docs/**"]}
                result = RB.bind(seat, "claude-code", mission, tmp / "checkout", tmp / f"{seat}.json", tmp / seat,
                                 AW, NOW, catalog_mode="enforce")
                with self.subTest(seat=seat):
                    self.assertEqual(list(result.app_mcp_tools), TOOLS if seat == "A2" else [])


class Vector231KeyRoute(unittest.TestCase):
    """231: each app key slot reaches only the run and collect steps of a seat whose resources name its app, and
    the perform job's call step; never by a computed name."""

    def uses(self):
        """(job, step, line) for each line of mission-agent.yml naming an app key slot."""
        found, job, step = [], None, None
        for line in (WORKFLOWS / "mission-agent.yml").read_text(encoding="utf-8").splitlines():
            if re.fullmatch(r"  [a-z][a-z-]*:", line):
                job, step = line.strip()[:-1], None
            match = re.match(r"\s*- name: (.*)", line)
            if match:
                step = match.group(1)
            if "APP_KEY" in line and not line.lstrip().startswith("#"):
                found.append((job, step, line.strip()))
        return found

    def test_the_slots_the_workflow_names_are_the_registers(self):
        slots = {app["key_slot"] for app in apps_mod.load_file()["apps"].values()}
        named = {m for _, _, line in self.uses() for m in re.findall(r"secrets\.(APP_KEY_[0-9]+)", line)}
        self.assertEqual(named, slots)
        self.assertFalse([u for u in self.uses() if "secrets[" in u[2]])

    def test_each_slot_only_where_its_seats_and_the_perform_call_run(self):
        register = apps_mod.load_file()
        for name, app in register["apps"].items():
            slot = app["key_slot"]
            seats = sorted(s for s, row in SEATS.items() if set(app["resources"]) & set(row["resources"]))
            condition = " || ".join(f"matrix.job.role == '{s}'" for s in seats)
            gated = f"{slot}: ${{{{ {condition} && secrets.{slot} || '' }}}}"
            with self.subTest(app=name):
                uses = [(job, step, line.split("  #")[0].strip()) for job, step, line in self.uses() if slot in line]
                self.assertEqual(sorted((job, step.split(" (")[0]) for job, step, _ in uses), [
                    ("agent", "Check and collect the change"), ("agent", "Run the agent"),
                    ("perform", "Make the listed calls through the app gateway, as the service principal")])
                for job, step, line in uses:
                    self.assertEqual(line, gated if job == "agent" else f"{slot}: ${{{{ secrets.{slot} }}}}")


class Vector232KeyNeverLeaves(unittest.TestCase):
    """232: a change holding an app key is refused and the agent's log scrubbed of it; the runtime never gets it."""

    def test_collect_knows_the_key(self):
        key = "xoxb-" + "1" * 40
        environ = {"APP_KEY_1": key, "CURSOR_API_KEY": "c" * 40, "OTHER": "o" * 40}
        self.assertEqual(dispatch_mod.secret_values(environ), sorted([key, "c" * 40]))
        self.assertNotIn("APP_KEY_1", runtimes.agent_env(environ, Path("/tmp/t"), Path("/tmp/g"), Path("/tmp/e")))
        self.assertEqual(dispatch_mod.secret_values({"APP_KEY_1": ""}), [])


class Vector233OffChangesNothing(unittest.TestCase):
    """233: while "app_gateway" is off, the writer seat's run gets no app server, though its row admits the tools."""

    def test_off_binds_no_app_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "checkout").mkdir()
            job = mock.Mock(role="A2", runtime="claude-code", mission_id="M-TEST-SLACK-001", round=1, agent="a2",
                            base_sha=BASE_SHA, build_scope=("docs/**",))
            lines = []
            bound = dispatch_binding.bind(job, root, root / "checkout", root, NOW, permissions_mode="enforce",
                                          log=lines.append, apps="off")
            config = json.loads((dispatch_binding.binding_dir(root) / dispatch_binding.MCP_FILE).read_text())
        self.assertEqual(bound.app_mcp_tools, ())
        self.assertEqual(list(config["mcpServers"]), ["governed-retrieval"])
        self.assertTrue(any("2 admitted app tool(s) not granted" in line for line in lines), lines)
        self.assertIsNone(dispatch_mod.app_keys_plan(bound, root, {"APP_KEY_1": "xoxb-" + "1" * 40}))


if __name__ == "__main__":
    unittest.main()
