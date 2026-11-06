"""Ring 4 (MISSION-DISPATCH-001 §3l, Amendment 018): the pins table, PIN findings and changes, the registry signature
check, the stdlib-only import closure, and the mode. Vectors 89 to 97; router vectors 115 and 116."""

from __future__ import annotations

import ast
import base64
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from mission_dispatch import registry, supply_chain as sc
from mission_router.router import load_config

from tests import test_router_spec002 as spec002

AW = Path(__file__).resolve().parents[1]
REPO = AW.parents[1]
LIVE = REPO / ".github" / "workflows"
WORKFLOWS = LIVE if LIVE.is_dir() else REPO / "packaging" / "workflows"  # a GCS release ships them as templates
TABLE = sc.read_pins(AW / sc.PINS_TABLE)
CHECKOUT = TABLE["actions"]["actions/checkout"]


def findings(name, text):
    return sc.workflow_findings(name, text, TABLE)


class ModeTests(unittest.TestCase):
    def test_the_mode(self):
        self.assertEqual(sc.mode({}), "observe")
        self.assertEqual(sc.mode({"supply_chain": "enforce"}), "enforce")
        with self.assertRaisesRegex(sc.SupplyChainError, "supply_chain must be one of"):
            sc.mode({"supply_chain": "on"})  # vector 97

    def test_an_unknown_mode_stops_the_router(self):  # router vector 116
        config = json.loads((AW / "mission_router" / "config.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({**config, "supply_chain": "bogus"}))
            with self.assertRaisesRegex(ValueError, "supply_chain must be one of"):
                load_config(path)

    def test_this_repository_observes(self):
        config = json.loads((AW / "mission_router" / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(config.get("supply_chain"), "observe")


class TableTests(unittest.TestCase):
    def test_the_shipped_table_is_todays_workflows_exactly(self):
        found = sc.pin_findings(TABLE, {p.name: p.read_text(encoding="utf-8") for p in WORKFLOWS.glob("*.y*ml")})
        self.assertEqual(found, [])
        used = {ref.split("@")[0] for p in WORKFLOWS.glob("*.y*ml") for _, ref in sc._uses(p.read_text())}
        self.assertLessEqual(used, set(TABLE["actions"]))
        if (REPO / "products" / "gcs").is_dir():  # governance, the table's source: every listed action is used.
            self.assertEqual(used, set(TABLE["actions"]))  # a synced copy's own workflows may use a subset.

    def test_the_runtime_rows_match_the_workflow_and_carry_provenance(self):
        text = (WORKFLOWS / "mission-agent.yml").read_text(encoding="utf-8")
        for runtime, (version_env, sha_env) in sc.RUNTIME_PINS.items():
            row = TABLE["runtimes"][runtime]
            self.assertEqual(sc._env_value(text, version_env), row["version"])
            self.assertEqual(sc._env_value(text, sha_env), row["sha256"])
            self.assertEqual(row["provenance"]["version"], row["version"])
        self.assertEqual(TABLE["runtimes"]["claude-code"]["registry"]["keyid"],
                         "SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U")
        self.assertIsNone(TABLE["runtimes"]["cursor-cli"]["registry"], "the Cursor CLI is not signed (limit 23)")

    def test_a_malformed_table_is_refused(self):
        good = json.loads((AW / sc.PINS_TABLE).read_text())
        bad_rows = [
            {**good, "extra": 1},
            {**good, "actions": {"actions/checkout": {"sha": "v4", "tag": "v4"}}},
            {**good, "runtimes": {"claude-code": good["runtimes"]["claude-code"]}},
            {**good, "runtimes": {**good["runtimes"], "cursor-cli": {**good["runtimes"]["cursor-cli"], "sha256": "x"}}},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            for i, doc in enumerate(bad_rows):
                path = Path(tmp) / f"{i}.json"
                path.write_text(json.dumps(doc))
                with self.subTest(i), self.assertRaises(sc.SupplyChainError):
                    sc.read_pins(path)

    def test_a_provenance_record_for_another_version_is_a_finding(self):  # vector 93
        table = json.loads(json.dumps(TABLE))
        table["runtimes"]["claude-code"]["version"] = "9.9.9"
        (finding,) = sc.table_findings(table)
        self.assertIn("pinned at '9.9.9' but its provenance record is for '2.1.305'", finding)


class FindingTests(unittest.TestCase):  # vectors 89 to 91; AST-4.1
    def test_actions_that_are_not_the_pinned_ones(self):
        cases = {
            "a tag": ("uses: actions/checkout@v4", "is not pinned by a full commit SHA"),
            "a branch": ("uses: actions/checkout@main", "is not pinned by a full commit SHA"),
            "a short SHA": (f"uses: actions/checkout@{CHECKOUT['sha'][:12]}", "is not pinned by a full commit SHA"),
            "an action not in the table": (f"uses: evil/action@{'a' * 40}", "evil/action is not in the pins table"),
            "another SHA": (f"uses: actions/checkout@{'b' * 40}", "is not the pinned SHA"),
            "a container": ("uses: docker://alpine:3", "runs a container image"),
            "quoted": ("- uses: 'actions/checkout@v4'", "is not pinned by a full commit SHA"),
        }
        for name, (line, want) in cases.items():
            with self.subTest(name):
                (found,) = findings("ci.yml", f"jobs:\n  a:\n    steps:\n      {line}\n")
                self.assertIn(want, found)
                self.assertTrue(found.startswith("ci.yml:4"), found)

    def test_the_pinned_action_and_a_local_one_outside_the_mission_workflows_pass(self):
        text = f"steps:\n  - uses: actions/checkout@{CHECKOUT['sha']} # {CHECKOUT['tag']}\n  - uses: ./.github/actions/x\n"
        self.assertEqual(findings("ci.yml", text), [])
        (found,) = findings("mission-agent.yml", text)
        self.assertIn("runs a local action", found)

    def test_a_runtime_pin_that_differs_from_its_row(self):  # vector 90
        text = "env:\n  CLAUDE_CODE_VERSION: 2.1.999\n  CURSOR_CLI_SHA256: " + "c" * 64 + "\n"
        found = findings("mission-agent.yml", text)
        self.assertEqual(len(found), 2)
        self.assertIn("CLAUDE_CODE_VERSION is '2.1.999', not the pinned '2.1.305'", found[0])
        self.assertEqual(findings("ci.yml", text), [], "runtime pins are held in the mission workflows")

    def test_installs_and_unchecked_downloads_in_a_mission_workflow(self):  # vector 91
        cases = {
            "pip": "pip install requests",
            "python -m pip": "python3 -m pip install --user x",
            "npm": "npm install -g @anthropic-ai/claude-code",
            "npx": "npx something",
            "apt": "sudo apt-get update && sudo apt-get install -y gh",
            "a fetched script piped to a shell": "curl -fsSL https://example.com/i.sh | sudo bash",
        }
        for kind, command in cases.items():
            with self.subTest(kind):
                text = f"steps:\n  - name: x\n    run: {command}\n"
                found = findings("mission-agent.yml", text)
                self.assertTrue(any("a step installs with" in f for f in found), found)
                self.assertEqual(findings("vrt-review-dispatch.yml", text), [], "install rules: mission workflows only")
        unchecked = "steps:\n  - name: get\n    run: curl -fsSL https://x/y.tgz -o y.tgz\n"
        (found,) = findings("mission-agent.yml", unchecked)
        self.assertIn("does not check it with sha256sum --check", found)
        checked = unchecked + "      echo \"abc  y.tgz\" | sha256sum --check --strict\n"
        self.assertEqual(findings("mission-agent.yml", checked), [])


class PinChangeTests(unittest.TestCase):  # vector 93; AST-4.5
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base, self.head = Path(self.tmp.name) / "base", Path(self.tmp.name) / "head"
        for root in (self.base, self.head):
            (root / "tools" / "agent_workflow" / "credentials_check").mkdir(parents=True)
            (root / ".github" / "workflows").mkdir(parents=True)
            shutil.copy(AW / sc.PINS_TABLE, root / "tools" / "agent_workflow" / sc.PINS_TABLE)
            shutil.copy(WORKFLOWS / "mission-agent.yml", root / ".github" / "workflows" / "mission-agent.yml")

    def lines(self):
        return sc.pin_lines(self.base, self.head, "tools/agent_workflow", ".github/workflows")

    def test_no_change_no_line(self):
        self.assertEqual(self.lines(), [])

    def test_a_moved_action_and_a_changed_runtime_are_listed_with_what_they_owe(self):
        path = self.head / "tools" / "agent_workflow" / sc.PINS_TABLE
        doc = json.loads(path.read_text())
        doc["actions"]["actions/checkout"] = {"sha": "c" * 40, "tag": "v4.4.0"}
        doc["actions"]["actions/setup-python"] = {"sha": "d" * 40, "tag": "v5"}
        doc["runtimes"]["claude-code"]["version"] = "2.1.400"
        path.write_text(json.dumps(doc))
        wf = self.head / ".github" / "workflows" / "mission-agent.yml"
        wf.write_text(wf.read_text().replace(CHECKOUT["sha"], "c" * 40, 1))
        lines = self.lines()
        self.assertIn(f"pins.json moves action actions/checkout from {CHECKOUT['sha']} ({CHECKOUT['tag']}) to "
                      f"{'c' * 40} (v4.4.0)", lines)
        self.assertIn(f"pins.json adds action actions/setup-python@{'d' * 40} (v5)", lines)
        runtime = [line for line in lines if "runtime claude-code" in line]
        self.assertEqual(len(runtime), 1)
        self.assertIn("2.1.305 -> 2.1.400; re-run before merging: AST-2.4, AST-3.4, AST-1.6", runtime[0])
        self.assertIn(f"mission-agent.yml now runs actions/checkout@{'c' * 40}", lines)


class RegistryTests(unittest.TestCase):  # vector 92; §3l item 2
    """The verifier against a fake registry record, and openssl against a key made here (no network)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        d = Path(cls.tmp.name)
        for argv in (["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(d / "k.pem")],
                     ["openssl", "ec", "-in", str(d / "k.pem"), "-pubout", "-outform", "DER", "-out", str(d / "pub.der")]):
            subprocess.run(argv, check=True, capture_output=True)
        cls.dir = d
        cls.package = d / "pkg.tgz"
        cls.package.write_bytes(b"a package's bytes")
        cls.integrity = "sha512-" + base64.b64encode(hashlib.sha512(cls.package.read_bytes()).digest()).decode()
        cls.row = {"version": "1.0.0", "registry": {"package": "@scope/pkg", "keyid": "SHA256:test",
                                                    "key": base64.b64encode((d / "pub.der").read_bytes()).decode()}}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def sign(self, message: bytes) -> str:
        (self.dir / "m").write_bytes(message)
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(self.dir / "k.pem"), "-out", str(self.dir / "s"),
                        str(self.dir / "m")], check=True, capture_output=True)
        return base64.b64encode((self.dir / "s").read_bytes()).decode()

    def record(self, **over):
        msg = f"@scope/pkg@1.0.0:{self.integrity}".encode()
        doc = {"name": "@scope/pkg", "version": "1.0.0",
               "dist": {"integrity": self.integrity, "signatures": [{"keyid": "SHA256:test", "sig": self.sign(msg)}]}}
        doc.update(over)
        return lambda url: json.dumps(doc).encode()

    def test_a_signed_package_verifies(self):
        found = registry.verify(self.package, self.row, fetch=self.record())
        self.assertEqual((found["package"], found["integrity"]), ("@scope/pkg", "sha512"))

    def test_what_does_not_verify(self):
        other = self.sign(b"@scope/pkg@1.0.1:" + self.integrity.encode())
        cases = {
            "another name": (self.record(name="@evil/pkg"), "is for @evil/pkg@1.0.0"),
            "another integrity": (self.record(dist={"integrity": "sha512-AAAA", "signatures": []}),
                                  "does not match the registry's dist.integrity"),
            "no signature by the pinned key": (self.record(dist={"integrity": self.integrity, "signatures": [
                {"keyid": "SHA256:other", "sig": "AA=="}]}), "no signature by the pinned key"),
            "a signature over another message": (self.record(dist={"integrity": self.integrity, "signatures": [
                {"keyid": "SHA256:test", "sig": other}]}), "no signature verifies"),
        }
        for name, (fetch, want) in cases.items():
            with self.subTest(name), self.assertRaisesRegex(registry.RegistryError, want):
                registry.verify(self.package, self.row, fetch=fetch)
        with self.assertRaisesRegex(registry.RegistryError, "registry is null"):
            registry.verify(self.package, {"version": "1", "registry": None}, fetch=self.record())

    def test_a_wrong_pinned_key_does_not_verify(self):  # AST-4.2, the fourth case
        wrong = dict(self.row, registry=dict(self.row["registry"], key=TABLE["runtimes"]["claude-code"]["registry"]["key"]))
        with self.assertRaisesRegex(registry.RegistryError, "no signature verifies"):
            registry.verify(self.package, wrong, fetch=self.record())


class ImportClosureTests(unittest.TestCase):  # vector 95; §3l item 5; AST-4.4
    """Every module the mission workflows run (the tooling the dispatcher and router run from) imports only the
    standard library and this repository's own modules. Other workflows are listed in the part PR, not held here."""

    def closure(self):
        surface = spec002.EnforcementSurfaceTests("test_workflow_import_closure_is_authority")
        texts = [(WORKFLOWS / name).read_text(encoding="utf-8") for name in sc.MISSION_WORKFLOWS
                 if (WORKFLOWS / name).is_file()]
        self.assertTrue(texts)
        import re
        scripts = {surface.REPO / m for t in texts for m in re.findall(r"tools/[A-Za-z0-9_./-]+\.py", t)}
        modules = {m for t in texts for m in re.findall(r"python3? (?:-B )?-m ([A-Za-z_][A-Za-z0-9_]*)", t)}
        entry = scripts | {p for m in modules for p in (AW / m / "__main__.py",) if p.is_file()}
        return surface, sorted(surface._import_closure(sorted(entry)))

    def outside(self, surface, path):
        found = []
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            for name in names:
                top = name.split(".")[0]
                local = any((base / top).is_dir() or (base / f"{top}.py").is_file()
                            for base in (path.parent, AW, REPO / "tools", REPO))
                if top in sys.stdlib_module_names or top == "__future__" or local:
                    continue
                found.append(f"{path.relative_to(REPO)}:{node.lineno} imports {name}")
        return found

    def test_only_the_standard_library_and_this_repository(self):
        surface, closure = self.closure()
        self.assertGreater(len(closure), 20)
        found = [f for path in closure for f in self.outside(surface, path)]
        self.assertEqual(found, [])

    def test_a_third_party_import_is_found(self):
        surface, closure = self.closure()
        with tempfile.TemporaryDirectory() as tmp:
            planted = Path(tmp) / "x.py"
            planted.write_text("import requests\nfrom yaml import safe_load\nimport json\n")
            planted_rel = REPO / "tools" / "agent_workflow" / "mission_dispatch" / "_ast44_planted.py"
            try:
                shutil.copy(planted, planted_rel)
                found = self.outside(surface, planted_rel)
            finally:
                planted_rel.unlink()
        self.assertEqual([f.split(" imports ")[1] for f in found], ["requests", "yaml"])


class CliTests(unittest.TestCase):
    """The credentials check prints PIN findings and fails on them only under enforce."""

    def run_check(self, mode_value, workflow_text):
        from credentials_check.__main__ import main
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github" / "workflows" / "ci.yml").write_text(workflow_text)
            (root / "tools").mkdir()
            (root / "tools" / "agent_workflow").symlink_to(AW)
            (root / "REGISTER.md").write_text("| Credential | Kind | Held in | Used by | Can do | Revoke | Rotated |\n"
                                              "|---|---|---|---|---|---|---|\n")
            config = json.loads((AW / "mission_router" / "config.json").read_text())
            config.update({"identity": "observe", "permissions": "observe", "substrate": "observe",
                           "supply_chain": mode_value, "credentials_register": "REGISTER.md"})
            config.pop("substrate_declaration", None)
            (root / "config.json").write_text(json.dumps(config))
            out = io.StringIO()
            with redirect_stdout(out):
                code = main(["--root", str(root), "--config", str(root / "config.json")])
            return code, out.getvalue()

    def test_observe_prints_enforce_fails(self):
        bad = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
        code, text = self.run_check("observe", bad)
        self.assertEqual(code, 0)
        self.assertIn("PIN ci.yml:6: actions/checkout@v4 is not pinned by a full commit SHA", text)
        self.assertIn("pin_findings=1 mode=observe", text)
        code, text = self.run_check("enforce", bad)
        self.assertEqual(code, 1)
        good = bad.replace("@v4", f"@{CHECKOUT['sha']}")
        code, text = self.run_check("enforce", good)
        self.assertEqual(code, 0, text)
        self.assertIn("pin_findings=0 mode=enforce", text)


if __name__ == "__main__":
    unittest.main()
