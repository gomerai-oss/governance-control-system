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

    def test_this_repository_enforces(self):  # switched on after AST-4.1 to 4.5 (2026-11-06)
        config = json.loads((AW / "mission_router" / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(config.get("supply_chain"), "enforce")


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
            harness = sc.harness_path(root / "tools" / "agent_workflow", "slack_read")  # the shipped pin's file
            harness.parent.mkdir(parents=True)
            shutil.copy(sc.harness_path(AW, "slack_read"), harness)

    def lines(self):
        return sc.pin_lines(self.base, self.head, "tools/agent_workflow", ".github/workflows")

    def test_no_change_no_line(self):
        self.assertEqual(self.lines(), [])

    def test_a_new_table_adds_rows_and_owes_nothing(self):
        (self.base / "tools" / "agent_workflow" / sc.PINS_TABLE).unlink()
        lines = self.lines()
        self.assertIn("pins.json adds runtime claude-code at 2.1.305", lines)
        # Only the harness pin owes a test (AST-H.6, its live run); a new table's other rows owe nothing.
        self.assertEqual([line for line in lines if "re-run before merging" in line],
                         [line for line in lines if line.startswith("pins.json adds harness slack_read")])

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



# ------------------------------------------------------------------ Amendment 034: pinned tools and package trees
from mission_dispatch import tree as tree_mod  # noqa: E402
import tarfile  # noqa: E402

KEY_NEW, KEY_OLD = "SHA256:" + "N" * 43, "SHA256:" + "O" * 43
SHIPPED_PINS = Path(__file__).resolve().parents[1] / sc.PINS_TABLE


def _tgz(files, extra=None):
    """An npm-style tarball: ``files`` under ``package/``; ``extra`` adds raw TarInfo entries."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, (data, mode) in files.items():
            info = tarfile.TarInfo(f"package/{name}")
            info.size, info.mode = len(data), mode
            tar.addfile(info, io.BytesIO(data))
        for info, data in (extra or []):
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
    return buf.getvalue()


class TreeCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        d = Path(cls.tmp.name)
        for name in ("new", "old"):
            for argv in (["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(d / f"{name}.pem")],
                         ["openssl", "ec", "-in", str(d / f"{name}.pem"), "-pubout", "-outform", "DER",
                          "-out", str(d / f"{name}.der")]):
                subprocess.run(argv, check=True, capture_output=True)
        cls.dir = d
        cls.keys = {KEY_NEW: {"key": base64.b64encode((d / "new.der").read_bytes()).decode(), "expires": None},
                    KEY_OLD: {"key": base64.b64encode((d / "old.der").read_bytes()).decode(),
                              "expires": "2025-01-29T00:00:00Z"}}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def sign(self, key, message):
        (self.dir / "m").write_bytes(message)
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(self.dir / f"{key}.pem"), "-out",
                        str(self.dir / "s"), str(self.dir / "m")], check=True, capture_output=True)
        return base64.b64encode((self.dir / "s").read_bytes()).decode()

    def package(self, path, name, version, data, key="new", published="2026-01-01T00:00:00.000Z"):
        integrity = tree_mod._integrity(data)
        keyid = KEY_NEW if key == "new" else KEY_OLD
        sig = base64.b64decode(self.sign(key, f"{name}@{version}:{integrity}".encode()))
        return {"path": path, "name": name, "version": version,
                "sha512": tree_mod.to_decimal(hashlib.sha512(data).digest()), "keyid": keyid,
                "sig": tree_mod.to_decimal(sig), "published": published,
                "_integrity": integrity, "_raw_sig": self.sign(key, f"{name}@{version}:{integrity}".encode())}

    def tree(self, packages):
        return {"root": "@scope/tool", "version": "1.0.0", "platform": "linux-x64",
                "registry": {"keys": dict(self.keys)}, "packages": packages,
                "provenance": {"version": "1.0.0", "checked": "2026-11-16", "how": "test", "by": "test"}}

    def setUp(self):
        self.root_tgz = _tgz({"package.json": (b'{"name":"@scope/tool"}', 0o644), "bin/tool.mjs": (b"// tool", 0o755)})
        self.dep_tgz = _tgz({"index.js": (b"module.exports = 1", 0o644)})
        self.served = {tree_mod.tarball_url("@scope/tool", "1.0.0"): self.root_tgz,
                       tree_mod.tarball_url("dep", "2.0.0"): self.dep_tgz}
        self.full = [self.package("node_modules/@scope/tool", "@scope/tool", "1.0.0", self.root_tgz),
                     self.package("node_modules/dep", "dep", "2.0.0", self.dep_tgz, key="old",
                                  published="2024-06-01T00:00:00.000Z")]
        self.packages = [self.pinned(p) for p in self.full]
        out = tempfile.TemporaryDirectory()
        self.addCleanup(out.cleanup)
        self.dest = Path(out.name) / "tree"

    @staticmethod
    def pinned(pkg):
        return {k: v for k, v in pkg.items() if not k.startswith("_")}

    def fetch(self, url):
        return self.served[url]


class Vector196TheShippedPins(unittest.TestCase):
    """196: pins.json pins Node and the scanner's tree, and ring 4's reader accepts it."""

    def test_the_shipped_table(self):
        doc = sc.read_pins(SHIPPED_PINS)
        self.assertEqual(doc["tools"]["node"]["url"],
                         f"https://nodejs.org/dist/{doc['tools']['node']['version']}/node-"
                         f"{doc['tools']['node']['version']}-linux-x64.tar.xz")
        tree = doc["trees"]["codex-security"]
        self.assertEqual((tree["root"], tree["platform"]), ("@openai/codex-security", "linux-x64"))
        self.assertIn(doc["runtimes"]["claude-code"]["registry"]["keyid"], tree["registry"]["keys"],
                      "the tree trusts the same current registry key as Claude Code's pin")
        self.assertEqual(tree["registry"]["keys"][doc["runtimes"]["claude-code"]["registry"]["keyid"]]["key"],
                         doc["runtimes"]["claude-code"]["registry"]["key"])
        self.assertTrue(all(p["path"].startswith("node_modules/") for p in tree["packages"]))


class Vector197TreeInstall(TreeCase):
    """197: a tree installs only when every package matches its integrity and a valid signature."""

    def test_a_good_tree_installs_into_its_paths(self):
        out = tree_mod.install_tree(self.tree(self.packages), self.dest, fetch=self.fetch)
        self.assertEqual(out["packages"], 2)
        self.assertTrue((self.dest / "node_modules/@scope/tool/bin/tool.mjs").is_file())
        self.assertEqual(oct((self.dest / "node_modules/@scope/tool/bin/tool.mjs").stat().st_mode & 0o777), "0o755")
        self.assertEqual((self.dest / "node_modules/dep/index.js").read_bytes(), b"module.exports = 1")

    def test_wrong_bytes_or_signature_stop_it(self):
        self.served[tree_mod.tarball_url("dep", "2.0.0")] = _tgz({"index.js": (b"evil", 0o644)})
        with self.assertRaisesRegex(tree_mod.TreeError, "integrity"):
            tree_mod.install_tree(self.tree(self.packages), self.dest, fetch=self.fetch)
        self.setUp()
        forged = dict(self.packages[1], keyid=KEY_NEW, sig=tree_mod.to_decimal(base64.b64decode(
            self.sign("new", b"dep@2.0.1:" + self.full[1]["_integrity"].encode()))))
        with self.assertRaisesRegex(tree_mod.TreeError, "does not verify"):
            tree_mod.install_tree(self.tree([self.packages[0], forged]), self.dest, fetch=self.fetch)

    def test_an_old_key_counts_only_before_it_expired(self):
        late = self.pinned(self.package("node_modules/dep", "dep", "2.0.0", self.dep_tgz, key="old",
                                        published="2025-03-01T00:00:00.000Z"))
        with self.assertRaisesRegex(tree_mod.TreeError, "after its key expired"):
            tree_mod.install_tree(self.tree([self.packages[0], late]), self.dest, fetch=self.fetch)

    def test_a_non_empty_destination_is_refused(self):
        self.dest.mkdir(parents=True)
        (self.dest / "x").write_text("x")
        with self.assertRaisesRegex(tree_mod.TreeError, "not empty"):
            tree_mod.install_tree(self.tree(self.packages), self.dest, fetch=self.fetch)


class Vector198UnsafeTarballs(TreeCase):
    """198: an entry that is a link, absolute, outside package/ or leaves its folder is refused."""

    def test_each(self):
        link = tarfile.TarInfo("package/l")
        link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
        dev = tarfile.TarInfo("package/d")
        dev.type = tarfile.CHRTYPE
        for name, extra in (("a symlink", [(link, None)]), ("a device", [(dev, None)]),
                            ("leaving the folder", [(tarfile.TarInfo("package/../../x"), b"")]),
                            ("outside package/", [(tarfile.TarInfo("other/x"), b"")])):
            with self.subTest(name):
                with self.assertRaises(tree_mod.TreeError):
                    tree_mod.unpack(_tgz({"ok": (b"1", 0o644)}, extra), self.dest / name.replace(" ", "_"))


class Vector199ThePinIsTheOnlySource(TreeCase):
    """199: the tarball URL comes from the pinned name and version, and malformed pins are refused."""

    def test_url(self):
        self.assertEqual(tree_mod.tarball_url("@openai/codex", "0.167.1-linux-x64"),
                         "https://registry.npmjs.org/@openai/codex/-/codex-0.167.1-linux-x64.tgz")
        self.assertEqual(tree_mod.tarball_url("dep", "2.0.0"), "https://registry.npmjs.org/dep/-/dep-2.0.0.tgz")

    def test_malformed_trees(self):
        good = self.tree(self.packages)
        bad = {
            "a key the tree does not hold": dict(good, packages=[self.packages[0], dict(self.packages[1], keyid="SHA256:" + "X" * 43)]),
            "the root missing": dict(good, packages=[self.packages[1]]),
            "a path twice": dict(good, packages=[self.packages[0], self.packages[0]]),
            "a path that leaves node_modules": dict(good, packages=[self.packages[0], dict(self.packages[1], path="node_modules/../x")]),
            "a digest in base64": dict(good, packages=[self.packages[0], dict(self.packages[1], sha512="AAAA==")]),
            "another platform": dict(good, platform="darwin-arm64"),
        }
        for name, row in bad.items():
            with self.subTest(name), self.assertRaises(tree_mod.TreeError):
                tree_mod.check_trees({"t": row})


class Vector200ToolInstall(unittest.TestCase):
    """200: a pinned tool installs only with its SHA-256, and never writes outside its folder."""

    def row(self, data):
        return {"version": "v1", "sha256": hashlib.sha256(data).hexdigest(), "url": "https://example.test/t.tar.gz",
                "provenance": {"version": "v1", "checked": "2026-11-16", "how": "test", "by": "test"}}

    def archive(self, extra=None):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            info = tarfile.TarInfo("tool-v1/bin/tool")
            data = b"#!/bin/sh\n"
            info.size, info.mode = len(data), 0o755
            tar.addfile(info, io.BytesIO(data))
            for i in extra or []:
                tar.addfile(i)
        return buf.getvalue()

    def test_good_and_bad(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = self.archive()
            top = tree_mod.install_tool(self.row(data), Path(tmp) / "a", fetch=lambda url: data)
            self.assertTrue((top / "bin" / "tool").is_file())
            with self.assertRaisesRegex(tree_mod.TreeError, "SHA-256"):
                tree_mod.install_tool(self.row(b"other"), Path(tmp) / "b", fetch=lambda url: data)
            link = tarfile.TarInfo("tool-v1/escape")
            link.type, link.linkname = tarfile.SYMTYPE, "../../../etc/passwd"
            evil = self.archive([link])
            with self.assertRaises(tree_mod.TreeError):
                tree_mod.install_tool(self.row(evil), Path(tmp) / "c", fetch=lambda url: evil)


class Vector201PinChangesAreListed(TreeCase):
    """201: the credentials check lists every tool and tree change, with counts inside a tree."""

    def test_lines(self):
        base = {"tools": {}, "trees": {}}
        head = {"tools": {"node": {"version": "v22"}}, "trees": {"t": self.tree(self.packages)}}
        self.assertEqual(sc.tree_lines(base, head), ["pins.json adds tool node at v22",
                                                     "pins.json adds tree t: @scope/tool@1.0.0, 2 packages"])
        swapped = self.tree([self.packages[0], dict(self.packages[1], version="2.0.1")])
        self.assertEqual(sc.tree_lines(head, dict(head, trees={"t": swapped})),
                         ["pins.json changes tree t: 1.0.0 -> 1.0.0; 0 packages added, 0 removed, 1 changed"])


class Vector202MakingAPin(TreeCase):
    """202: a pin is made from a lockfile and the registry's records: other platforms left out, a package with an
    install script refused, a record that disagrees with the lockfile refused."""

    def lock(self, **dep):
        return {"packages": {"": {}, "node_modules/@scope/tool": {"version": "1.0.0",
                                                                 "integrity": self.full[0]["_integrity"]},
                             "node_modules/dep": dict({"version": "2.0.0", "integrity": self.full[1]["_integrity"]}, **dep),
                             "node_modules/dep-darwin": {"version": "1.0.0", "integrity": "x", "os": ["darwin"]}}}

    def record(self, name, version):
        pkg = {p["name"]: p for p in self.full}[name]
        return {"name": name, "version": version,
                "dist": {"integrity": pkg["_integrity"], "signatures": [{"keyid": pkg["keyid"], "sig": pkg["_raw_sig"]}]}}

    def make(self, lock):
        return tree_mod.make_tree_pin(lock, "@scope/tool", "linux-x64", self.keys, "2026-11-16", "test",
                                      fetch_record=self.record, fetch_published=lambda n, v: "2024-06-01T00:00:00.000Z")

    def test_made_and_refused(self):
        row = self.make(self.lock())
        self.assertEqual([p["path"] for p in row["packages"]], ["node_modules/@scope/tool", "node_modules/dep"])
        with self.assertRaisesRegex(tree_mod.TreeError, "install script"):
            self.make(self.lock(hasInstallScript=True))
        with self.assertRaisesRegex(tree_mod.TreeError, "does not match"):
            self.make(self.lock(integrity=self.full[0]["_integrity"]))
        self.assertEqual(row["packages"][1]["sha512"], self.packages[1]["sha512"], "decimal, as the pin stores it")


if __name__ == "__main__":
    unittest.main()
