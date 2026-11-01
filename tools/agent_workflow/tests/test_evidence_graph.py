"""M-EVGRAPH-001: the live evidence graph, vectors V1-V15 on throwaway git repositories."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

AGENT_WORKFLOW = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AGENT_WORKFLOW))

from evidence_graph import graph, history  # noqa: E402

PACKAGE = AGENT_WORKFLOW / "evidence_graph"
MID = "M-DEMO-001"
MDIR = f"missions/{MID}/"
BOT, HITL, A2, A3 = "test-bot[bot]", "hitl-user", "test-a2[bot]", "test-a3[bot]"
# Author name and email per actor. HITL commits under a display name with the GitHub no-reply
# address, as the web UI does, so the login comes from the email.
IDENT = {
    BOT: (BOT, "bot@example.invalid"),
    HITL: ("Hitl Person", "1234+hitl-user@users.noreply.github.com"),
    A2: (A2, f"{A2}@users.noreply.github.com"),
    A3: (A3, f"{A3}@users.noreply.github.com"),
    "seed": ("seed", "seed@example.invalid"),
    "dev": ("dev", "dev@example.invalid"),
    "intruder": ("intruder", "intruder@example.invalid"),
}
CONFIG = {"hitl_logins": [HITL], "bot_login": BOT, "default_branch": "main", "identity_registry": "REGISTRY.md",
          "agents": {"a1": "test-a1[bot]", "a2": A2, "a3": A3}}
MANIFEST = {"schema": "mission-v1", "mission_id": MID, "title": "Demo mission",
            "roles": {"A1": {"agent": "a1"}, "A2": {"agent": "a2"}, "A3": {"agent": "a3"}},
            "build_scope": ["tools/demo/**"], "max_rounds": 3}
PLAN = f"# PLAN {MID}\n\nBuilt against DEMO-SPEC-001 as {MID} requires.\n"
DATE = "2026-01-01T00:00:00+00:00"
APP = "tools/demo/app.py"


class Fixture:
    """A throwaway repository whose commits are written with plumbing, so every parent is exact.

    A merge takes its second parent's tree: every side branch here contains the first parent."""

    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.root = tmp / "repo"
        empty = tmp / "empty-gitconfig"
        empty.write_text("")
        self.config = tmp / "config.json"
        self.config.write_text(json.dumps(CONFIG))
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith("GIT_") and k not in ("EMAIL", "PYTHONPATH")}
        self.env.update({"GIT_CONFIG_GLOBAL": str(empty), "GIT_CONFIG_SYSTEM": str(empty),
                         "GIT_AUTHOR_DATE": DATE, "GIT_COMMITTER_DATE": DATE})
        self.git("init", "--quiet", "--initial-branch=main", str(self.root), cwd=tmp)

    def git(self, *args, cwd=None, data=None, who=None, env=None):
        argv = ["git"]
        if who:
            name, email = IDENT[who]
            argv += ["-c", f"user.name={name}", "-c", f"user.email={email}"]
        done = subprocess.run(argv + list(args), cwd=str(cwd or self.root), input=data, capture_output=True,
                              env={**self.env, **(env or {})})
        if done.returncode:
            raise AssertionError(done.stderr.decode())
        return done.stdout.decode().strip()

    def commit(self, who, message, parent, files):
        index = {"GIT_INDEX_FILE": str(self.tmp / "fixture-index")}
        if parent:
            self.git("read-tree", parent, env=index)
        else:
            self.git("read-tree", "--empty", env=index)
        for path, content in files.items():
            blob = self.git("hash-object", "-w", "--stdin", data=content.encode())
            self.git("update-index", "--add", "--cacheinfo", f"100644,{blob},{path}", env=index)
        tree = self.git("write-tree", env=index)
        return self.git("commit-tree", tree, "-m", message, *(["-p", parent] if parent else []), who=who)

    def merge(self, who, message, first, second):
        return self.git("commit-tree", f"{second}^{{tree}}", "-p", first, "-p", second, "-m", message, who=who)

    def set_main(self, sha):
        self.git("update-ref", "refs/heads/main", sha)

    def cli(self, *args, root=None):
        env = {**self.env, "PYTHONPATH": str(AGENT_WORKFLOW)}
        argv = [sys.executable, "-m", "evidence_graph", *args, "--root", str(root or self.root), "--config", str(self.config)]
        return subprocess.run(argv, cwd=str(self.tmp), capture_output=True, text=True, env=env)

    def graph(self):
        """The graph through the functions, with the same git settings isolation as the command line."""
        isolated = {k: self.env[k] for k in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM")}
        with mock.patch.dict(os.environ, isolated):
            repo = history.Repo(str(self.root))
            doc, _ = graph.build_graph(repo, history.load_identities(str(self.config)), "HEAD")
        return doc

    def seed(self, extra=None):
        files = {"README.md": "demo\n", APP: "v0\n", "docs/specs/DEMO-SPEC-001.md": "spec\n", **(extra or {})}
        sha = self.commit("seed", "seed", None, files)
        self.set_main(sha)
        return sha

    def mission(self, main, verdicts=("PASS",), approval="router", plan=PLAN, manifest_text=None, build_extra=None,
                review_extra=None, wrong_reviewed=False, extra_merge_by=None, intruder=False):
        """One mission from plan to landing on ``main``, the way the router records it."""
        out = {"builds": {}, "merges": {}, "reviews": {}}
        head = main
        manifest = manifest_text if manifest_text is not None else json.dumps(MANIFEST, indent=2) + "\n"
        out["plan"] = self.commit(HITL, f"{MID}: plan", head, {MDIR + "mission.json": manifest, MDIR + "PLAN.md": plan})
        if approval == "router":
            head = self.merge(BOT, f"Mission {MID}: merge A1", head, out["plan"])
        elif approval == "hitl-merge":
            head = self.merge(HITL, f"Merge pull request #5 from hitl-user/mission/{MID}/a1", head, out["plan"])
        else:
            head = out["plan"]
        out["approval"] = head
        if intruder:
            head = self.commit("intruder", "tweak the app", head, {APP: "intruder\n"})
        if extra_merge_by:
            side = self.commit(A2, "extra", head, {"tools/demo/extra.py": "x\n"})
            head = self.merge(extra_merge_by, "Merge branch extra", head, side)
        n = len(verdicts)
        for k, verdict in enumerate(verdicts, 1):
            files = {APP: f"v{k}\n", **(build_extra if k == 1 and build_extra else {})}
            build = self.commit(A2, f"build round {k}", head, files)
            merge = self.merge(BOT, f"Mission {MID}: merge A2 round {k}", head, build)
            doc = {"schema": "mission-verdict-v1", "mission_id": MID, "round": k, "verdict": verdict,
                   "reviewed_sha": build if wrong_reviewed else merge, "summary": "",
                   "findings": [] if verdict == "PASS" else ["needs work"]}
            files = {f"{MDIR}reviews/round-{k}.json": json.dumps(doc) + "\n", **(review_extra or {})}
            review = self.commit(A3, f"review round {k}", merge, files)
            out["builds"][k], out["merges"][k], out["reviews"][k] = build, merge, review
            if k < n:
                head = self.merge(BOT, f"Mission {MID}: merge A3 round {k} (FAIL)", merge, review)
        out["landing"] = self.merge(BOT, f"Mission {MID}: merge A3 round {n} (PASS)", main, review)
        self.set_main(out["landing"])
        return out


def nodes(doc):
    return {n["id"]: n for n in doc["nodes"]}


def edges(doc):
    return {(e["from"], e["to"], e["relation"]) for e in doc["edges"]}


def rules(doc):
    return {f["rule"] for f in doc["findings"]}


class EvidenceGraphTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.fx = Fixture(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def assert_findings(self, expected_rules):
        doc = self.fx.graph()
        self.assertEqual(rules(doc), set(expected_rules), doc["findings"])
        self.assertFalse(nodes(doc)[f"mission:{MID}"]["proven"])
        done = self.fx.cli("check")
        self.assertEqual(done.returncode, 1, done.stderr)
        for rule in expected_rules:
            self.assertIn(f"FINDING {MID} {rule} ", done.stdout)
        return doc

    def test_v1_clean_router_mission_is_proven(self):
        seed = self.fx.seed()
        m = self.fx.mission(seed)
        done = self.fx.cli("check")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(done.stdout.splitlines(), ["landings=1 proven=1 findings=0 hand_merges=0 direct=1"])
        doc = self.fx.graph()
        e, n = edges(doc), nodes(doc)
        plan, build, merge = f"commit:{m['plan']}", f"commit:{m['builds'][1]}", f"commit:{m['merges'][1]}"
        self.assertIn((f"commit:{m['approval']}", plan, "APPROVES"), e)
        self.assertIn((build, plan, "IMPLEMENTS"), e)
        self.assertIn((build, f"file:{APP}", "PRODUCES"), e)
        self.assertIn((f"review:{MID}:1", merge, "REVIEWS"), e)
        self.assertIn((f"mission:{MID}", f"commit:{m['landing']}", "MERGED_AS"), e)
        self.assertIn(("spec:docs/specs/DEMO-SPEC-001.md", plan, "SPECIFIES"), e)
        self.assertNotIn("FINDS_MISMATCH", {r for _, _, r in e})
        self.assertEqual(n[f"mission:{MID}"], {"id": f"mission:{MID}", "kind": "mission", "title": "Demo mission",
                                               "proven": True, "approval": "router", "rounds": 1})
        self.assertEqual(n[plan], {"id": plan, "kind": "plan", "mission": MID, "unresolved_specs": []})
        self.assertEqual(n[build]["round"], 1)
        self.assertEqual(n[merge]["kind"], "build_merge")
        self.assertEqual(n[f"commit:{m['landing']}"], {"id": f"commit:{m['landing']}", "kind": "landing", "mission": MID,
                                                       "position": 1})
        self.assertEqual(n[f"review:{MID}:1"]["path"], f"{MDIR}reviews/round-1.json")
        self.assertEqual(doc["findings"], [])
        self.assertEqual(doc["counts"], {"landings": 1, "proven": 1, "findings": 0, "hand_merges": 0, "direct": 1})
        self.assertEqual(set(doc), set(graph.FIELDS))

    def test_v2_hitl_merge_approval_is_proven(self):
        m = self.fx.mission(self.fx.seed(), approval="hitl-merge")
        doc = self.fx.graph()
        self.assertEqual(doc["findings"], [])
        n = nodes(doc)
        self.assertTrue(n[f"mission:{MID}"]["proven"])
        self.assertEqual(n[f"mission:{MID}"]["approval"], "hitl-merge")
        self.assertEqual(n[f"commit:{m['approval']}"]["approval"], "hitl-merge")
        self.assertEqual(self.fx.cli("check").returncode, 0)

    def test_v3_two_round_mission_corrects_its_failed_review(self):
        m = self.fx.mission(self.fx.seed(), verdicts=("FAIL", "PASS"))
        doc = self.fx.graph()
        self.assertEqual(doc["findings"], [])
        e, n = edges(doc), nodes(doc)
        self.assertEqual(n[f"mission:{MID}"]["rounds"], 2)
        self.assertIn((f"review:{MID}:1", f"commit:{m['merges'][1]}", "FINDS_MISMATCH"), e)
        self.assertIn((f"review:{MID}:1", f"commit:{m['merges'][1]}", "REVIEWS"), e)
        self.assertNotIn((f"review:{MID}:2", f"commit:{m['merges'][2]}", "FINDS_MISMATCH"), e)
        self.assertIn((f"commit:{m['builds'][2]}", f"review:{MID}:1", "CORRECTS"), e)
        self.assertEqual(n[f"commit:{m['builds'][1]}"]["round"], 1)
        self.assertEqual(n[f"commit:{m['builds'][2]}"]["round"], 2)
        self.assertEqual(self.fx.cli("check").returncode, 0)

    def test_v4_builder_outside_build_scope_is_r5(self):
        self.fx.mission(self.fx.seed(), build_extra={"outside/notes.txt": "x\n"})
        doc = self.assert_findings({"R5"})
        self.assertIn("outside/notes.txt", doc["findings"][0]["detail"])

    def test_v5_reviewer_changing_code_is_r6(self):
        self.fx.mission(self.fx.seed(), review_extra={APP: "reviewer edit\n"})
        self.assert_findings({"R6"})

    def test_v6_reviewed_sha_not_the_merge_a2_commit_is_r4(self):
        self.fx.mission(self.fx.seed(), wrong_reviewed=True)
        doc = self.assert_findings({"R4"})
        self.assertNotIn("REVIEWS", {r for _, _, r in edges(doc)})

    def test_v7_no_approval_commit_is_r3(self):
        m = self.fx.mission(self.fx.seed(), approval=None)
        doc = self.assert_findings({"R3"})
        n = nodes(doc)
        self.assertNotIn(f"commit:{m['plan']}", n)
        self.assertIsNone(n[f"mission:{MID}"]["approval"])

    def test_v8_merge_by_non_bot_is_r7(self):
        self.fx.mission(self.fx.seed(), extra_merge_by=HITL)
        self.assert_findings({"R7"})

    def test_v8_code_change_by_another_author_is_r7(self):
        self.fx.mission(self.fx.seed(), intruder=True)
        doc = self.assert_findings({"R7"})
        self.assertIn(APP, doc["findings"][0]["detail"])

    def test_v9_final_verdict_fail_under_pass_subject_is_r8(self):
        self.fx.mission(self.fx.seed(), verdicts=("FAIL",))
        self.assert_findings({"R8"})

    def test_v10_unparsable_manifest_is_r2_and_skips_r5(self):
        self.fx.mission(self.fx.seed(), manifest_text="{not json", build_extra={"outside/notes.txt": "x\n"})
        doc = self.assert_findings({"R2"})
        self.assertIsNone(nodes(doc)[f"mission:{MID}"]["title"])

    def test_v11_hand_merge_and_direct_commit_have_no_independent_review(self):
        seed = self.fx.seed()
        m = self.fx.mission(seed)
        side = self.fx.commit("dev", "feature", m["landing"], {APP: "feature\n"})
        hand = self.fx.merge(HITL, "Merge pull request #7 from dev/feature", m["landing"], side)
        direct = self.fx.commit("dev", "fix typo", hand, {APP: "fixed\n"})
        self.fx.set_main(direct)
        doc = self.fx.graph()
        n, e = nodes(doc), edges(doc)
        self.assertEqual(n[f"commit:{hand}"], {"id": f"commit:{hand}", "kind": "hand_merge", "pr": 7, "position": 2,
                                               "independent_review": "none"})
        self.assertEqual(n[f"commit:{direct}"], {"id": f"commit:{direct}", "kind": "direct", "position": 3,
                                                 "independent_review": "none"})
        self.assertIn((f"commit:{hand}", f"file:{APP}", "CHANGES"), e)
        self.assertIn((f"commit:{direct}", f"file:{APP}", "CHANGES"), e)
        self.assertEqual(doc["counts"], {"landings": 1, "proven": 1, "findings": 0, "hand_merges": 1, "direct": 2})
        done = self.fx.cli("trace", APP)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.splitlines(), [
            f"direct {direct[:12]} independent-review none",
            f"hand-merge #7 {hand[:12]} independent-review none",
            f"mission {MID} landing {m['landing'][:12]} plan {m['plan'][:12]} approval router review round 1 PASS "
            f"on {m['merges'][1][:12]} specs docs/specs/DEMO-SPEC-001.md",
            f"direct {seed[:12]} independent-review none",
        ])

    def test_v11_trace_marks_an_unproven_landing(self):
        m = self.fx.mission(self.fx.seed(), intruder=True)
        done = self.fx.cli("trace", APP)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue(done.stdout.splitlines()[0].startswith(f"mission {MID} landing {m['landing'][:12]} "))
        self.assertTrue(done.stdout.splitlines()[0].endswith(" UNPROVEN R7"))

    def test_v12_builds_are_byte_identical_and_digest_verifies(self):
        self.fx.mission(self.fx.seed(), verdicts=("FAIL", "PASS"))
        first, second = self.fx.tmp / "a.json", self.fx.tmp / "b.json"
        for out in (first, second):
            done = self.fx.cli("build", "--out", str(out))
            self.assertEqual(done.returncode, 0, done.stderr)
        raw = first.read_bytes()
        self.assertEqual(raw, second.read_bytes())
        doc = json.loads(raw)
        body = {k: v for k, v in doc.items() if k != "digest"}
        canonical = (json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
        self.assertEqual(doc["digest"], hashlib.sha256(canonical).hexdigest())
        self.assertEqual(raw, (json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode())
        self.assertEqual(doc["schema"], "evidence-graph-v1")
        self.assertEqual(doc["ref"], "HEAD")
        self.assertEqual(doc["head"], self.fx.git("rev-parse", "HEAD"))
        self.assertEqual([n["id"] for n in doc["nodes"]], sorted(n["id"] for n in doc["nodes"]))
        keys = [(e["from"], e["to"], e["relation"]) for e in doc["edges"]]
        self.assertEqual(keys, sorted(set(keys)))
        self.assertEqual(raw, graph.canonical(self.fx.graph()))

    def test_v12_build_writes_the_graph_and_exits_1_on_findings(self):
        self.fx.mission(self.fx.seed(), intruder=True)
        out = self.fx.tmp / "graph.json"
        done = self.fx.cli("build", "--out", str(out))
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertEqual(json.loads(out.read_bytes())["counts"]["findings"], 1)

    def test_v13_shallow_clone_is_refused(self):
        self.fx.mission(self.fx.seed())
        shallow = self.fx.tmp / "shallow"
        self.fx.git("clone", "--quiet", "--depth", "1", self.fx.root.as_uri(), str(shallow), cwd=self.fx.tmp)
        for args in (("check",), ("trace", APP), ("build", "--out", str(self.fx.tmp / "never.json"))):
            done = self.fx.cli(*args, root=shallow)
            self.assertEqual(done.returncode, 2, done.stdout)
            self.assertEqual(done.stderr.strip(), "shallow clone: full history required")
        self.assertFalse((self.fx.tmp / "never.json").exists())

    def test_v14_trace_of_a_path_that_never_changed_exits_2(self):
        self.fx.mission(self.fx.seed())
        done = self.fx.cli("trace", "no/such/file.txt")
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, "")
        self.assertEqual(len(done.stderr.strip().splitlines()), 1)

    def test_v15_unresolved_and_ambiguous_specs(self):
        seed = self.fx.seed({"docs/a/DUP-SPEC-001.md": "a\n", "docs/b/DUP-SPEC-001.md": "b\n"})
        plan = f"# PLAN {MID}\n\nNames DEMO-SPEC-001, NOPE-SPEC-001 and DUP-SPEC-001.\n"
        m = self.fx.mission(seed, plan=plan)
        doc = self.fx.graph()
        self.assertEqual(doc["findings"], [])
        n, e = nodes(doc), edges(doc)
        self.assertEqual(n[f"commit:{m['plan']}"]["unresolved_specs"], ["DUP-SPEC-001", "NOPE-SPEC-001"])
        self.assertEqual({s for s, _, r in e if r == "SPECIFIES"}, {"spec:docs/specs/DEMO-SPEC-001.md"})
        self.assertNotIn(f"spec:{MID}", " ".join(n))

    def test_missing_ref_and_bad_usage_exit_2(self):
        self.fx.seed()
        done = self.fx.cli("check", "--ref", "no-such-branch")
        self.assertEqual(done.returncode, 2)
        self.assertEqual(len(done.stderr.strip().splitlines()), 1)
        done = self.fx.cli("frobnicate")
        self.assertEqual(done.returncode, 2)
        self.assertEqual(len(done.stderr.strip().splitlines()), 1)

    def test_landing_not_by_the_bot_is_r1_and_draws_only_its_mission(self):
        seed = self.fx.seed()
        m = self.fx.mission(seed)
        forged = self.fx.merge(HITL, f"Mission {MID}: merge A3 round 1 (PASS)", m["landing"], m["reviews"][1])
        self.fx.set_main(forged)
        doc = self.fx.graph()
        forged_findings = [f for f in doc["findings"] if f["landing"] == forged]
        self.assertEqual({f["rule"] for f in forged_findings}, {"R1"})
        self.assertIn((f"mission:{MID}", f"commit:{forged}", "MERGED_AS"), edges(doc))
        self.assertFalse(nodes(doc)[f"mission:{MID}"]["proven"])
        self.assertEqual(doc["counts"]["landings"], 2)
        self.assertEqual(doc["counts"]["proven"], 1)

    def test_a_git_dir_outside_the_work_tree_reads_the_same_graph(self):
        """The dispatcher keeps the checkout's git dir beside the work tree; ``Repo`` can be pointed at it."""
        seed = self.fx.seed()
        self.fx.mission(seed)
        expected = self.fx.graph()
        git_dir = self.fx.tmp / "git"
        (self.fx.root / ".git").rename(git_dir)
        isolated = {k: self.fx.env[k] for k in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM")}
        with mock.patch.dict(os.environ, isolated):
            repo = history.Repo(str(self.fx.root), str(git_dir))
            doc, _ = graph.build_graph(repo, history.load_identities(str(self.fx.config)), "HEAD")
        self.assertEqual(graph.canonical(doc), graph.canonical(expected))


    def test_prefetched_files_match_one_call_per_commit(self):
        seed = self.fx.seed()
        m = self.fx.mission(seed, verdicts=("FAIL", "PASS"))
        empty = self.fx.git("commit-tree", f"{m['landing']}^{{tree}}", "-p", m["landing"], "-m", "no change",
                            who="dev")
        self.fx.set_main(empty)
        isolated = {k: self.fx.env[k] for k in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM")}
        with mock.patch.dict(os.environ, isolated):
            one, many = history.Repo(str(self.fx.root)), history.Repo(str(self.fx.root))
            commits = one.first_parent(one.resolve("HEAD")) + one.range(seed, m["reviews"][2])
            many.prefetch_files(commits)
            self.assertEqual([many.files(c) for c in commits], [one.files(c) for c in commits])
            self.assertEqual(many.files(one.first_parent(one.resolve("HEAD"))[-1]), (), "a commit with no changes")


class PackageShapeTests(unittest.TestCase):
    def test_no_init_py_in_the_package(self):
        self.assertEqual(list(PACKAGE.rglob("__init__.py")), [])

    def test_imports_only_stdlib_and_mission_router(self):
        allowed_roots = {"__future__", "argparse", "dataclasses", "hashlib", "json", "pathlib", "re", "subprocess", "sys",
                         "typing", "mission_router"}
        for path in PACKAGE.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    names = [node.module]
                else:
                    continue
                for name in names:
                    self.assertIn(name.split(".")[0], allowed_roots, f"{path.name} imports {name}")

    def test_git_subcommands_are_read_only(self):
        self.assertEqual(history.READ_ONLY, ("rev-parse", "log", "show", "diff-tree", "ls-tree", "cat-file"))
        with self.assertRaises(history.GitError):
            history.Repo(".")._run("commit", "-m", "x")


if __name__ == "__main__":
    unittest.main()
