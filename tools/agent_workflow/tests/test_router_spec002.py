from __future__ import annotations

import copy
import inspect
import itertools
import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from router_spec002 import FileChange, FileListing, build_tables, evaluate, load_tables
from router_spec002 import evaluator as evaluator_module
from router_spec002.github_source import GitHubPullRequestSource
from router_spec002.policy import TABLES_PATH, PolicyTableError

SHA = "a" * 40
SHA2 = "b" * 40

INERT_FILE = "docs/notes.md"
CODE_FILE = "tools/example/thing.py"
AGENTS_FILE = "AGENTS.md"
CURSOR_RULE = ".cursor/rules/x.md"
WAIVER_CONFIG = "governance/reviewer_execution/sal3/temporary-review-waiver.yaml"
EVIDENCE_FILE = "CCP_UPGRADES/UPG/UPG-X-001/evidence/run.json"
TOOL_CONFIG_FILE = ".vscode/settings.json"
WORKFLOW_FILE = ".github/workflows/policy-ci.yml"

VQT = "NEXT_VQT_REVIEW_REQUEST"
ALL_CLASSES = ("PLAN_ONLY", "DOC_WORKFLOW", "BOUNDED_IMPLEMENT", "IMPLEMENT_ONLY")


class Source:
    def __init__(self, files, shas=(SHA, SHA), complete=True):
        self._shas = list(shas)
        self._listing = FileListing(
            files=tuple(f if isinstance(f, FileChange) else FileChange(f, "modified") for f in files),
            complete=complete,
        )

    def read_head_sha(self):
        return self._shas.pop(0)

    def list_files(self):
        return self._listing


class RaisingSource:
    def read_head_sha(self):
        raise RuntimeError("api down")

    def list_files(self):
        raise RuntimeError("api down")


def vqt(pr_class=None, **extra):
    block = {"handoff_block_id": VQT}
    if pr_class is not None:
        block["pr_class"] = pr_class
    block.update(extra)
    return block


def run(files, block, waiver=False, **source_kwargs):
    return evaluate(Source(files, **source_kwargs), block, waiver)


class SpecVectorTests(unittest.TestCase):
    """ROUTER-POLICY-SPEC-002 section 7. Columns: pr_type, disposition, reason, exit, merge_allowed."""

    VECTORS = [
        (1, lambda: run([INERT_FILE], vqt("PLAN_ONLY"), False), ("PLAN", "ACKNOWLEDGED", "POLICY_PASS", 0, False)),
        (2, lambda: run([INERT_FILE, CODE_FILE], vqt("PLAN_ONLY"), True), ("PLAN", "DENIED", "CLASS_MISMATCH", 1, False)),
        (3, lambda: run([AGENTS_FILE], vqt("DOC_WORKFLOW"), True),
         ("VQT_REVIEW_REQUEST", "HITL_REQUIRED", "AGENT_POLICY_CHANGE", 0, False)),
        (4, lambda: run([CODE_FILE], vqt("DOC_WORKFLOW"), True),
         ("VQT_REVIEW_REQUEST", "DENIED", "CLASS_MISMATCH", 1, False)),
        (5, lambda: run([INERT_FILE], vqt("DOC_WORKFLOW"), True),
         ("VQT_REVIEW_REQUEST", "WAIVED", "OPERATOR_WAIVER", 0, True)),
        (6, lambda: run([CODE_FILE, "tools/example/other.py"], vqt("BOUNDED_IMPLEMENT"), True),
         ("VQT_REVIEW_REQUEST", "WAIVED", "OPERATOR_WAIVER", 0, True)),
        (7, lambda: run([WAIVER_CONFIG], vqt("BOUNDED_IMPLEMENT"), True),
         ("VQT_REVIEW_REQUEST", "DENIED", "AUTHORITY_VIOLATION", 1, False)),
        (8, lambda: run([INERT_FILE], None, False), ("DOCS_ONLY", "ACKNOWLEDGED", "POLICY_PASS", 0, True)),
        (9, lambda: run([CODE_FILE], None, False), ("DOCS_ONLY", "DENIED", "NO_BLOCK", 1, False)),
        (10, lambda: run([INERT_FILE], {"handoff_block_id": "STOP_ESCALATE"}, False),
         ("ESCALATION", "ACKNOWLEDGED", "POLICY_PASS", 0, False)),
        (11, lambda: run([CURSOR_RULE], vqt("PLAN_ONLY"), False),
         ("PLAN", "HITL_REQUIRED", "AGENT_POLICY_CHANGE", 0, False)),
        (12, lambda: run([INERT_FILE], vqt("DOC_WORKFLOW"), False, shas=(SHA, SHA2)),
         ("UNKNOWN", "DENIED", "DIFF_UNKNOWN", 1, False)),
        (13, lambda: run([INERT_FILE], vqt("SOMETHING_NEW"), False),
         ("VQT_REVIEW_REQUEST", "DENIED", "UNKNOWN_CLASS", 1, False)),
        (14, lambda: run([INERT_FILE], vqt(), False), ("VQT_REVIEW_REQUEST", "DENIED", "UNKNOWN_CLASS", 1, False)),
    ]

    def test_all_fourteen_vectors(self):
        self.assertEqual([v[0] for v in self.VECTORS], list(range(1, 15)))
        for number, scenario, expected in self.VECTORS:
            with self.subTest(vector=number):
                d = scenario()
                self.assertEqual((d.pr_type, d.disposition, d.reason, d.exit_code, d.merge_allowed), expected)

    def test_vector_7_holds_for_every_block_and_waiver(self):
        blocks = [None, {"handoff_block_id": "STOP_ESCALATE"}, {"handoff_block_id": "CLOSEOUT"}]
        blocks += [{"handoff_block_id": "STOP_ESCALATE_TO_HITL"}, {"handoff_block_id": "PLAN"}]
        blocks += [vqt(c) for c in ALL_CLASSES] + [vqt(), vqt("NOPE")]
        for block, waiver in itertools.product(blocks, (True, False)):
            with self.subTest(block=block, waiver=waiver):
                d = run([INERT_FILE, WAIVER_CONFIG], block, waiver)
                self.assertEqual((d.reason, d.exit_code, d.merge_allowed), ("AUTHORITY_VIOLATION", 1, False))

    def test_vector_12_binds_no_sha(self):
        d = run([INERT_FILE], vqt("DOC_WORKFLOW"), False, shas=(SHA, SHA2))
        self.assertIsNone(d.head_sha)
        self.assertIsNone(d.file_list_digest)


def _scenario_space():
    blocks = [None, {"handoff_block_id": "STOP_ESCALATE"}, {"handoff_block_id": "CLOSEOUT"}, {"handoff_block_id": "X"}, {}]
    blocks += [vqt(c) for c in ALL_CLASSES] + [vqt(), vqt("plan_only"), vqt(7)]
    blocks += [{"handoff_block_id": "STOP_ESCALATE", "pr_class": c} for c in ("PLAN_ONLY", "BOUNDED_IMPLEMENT", "NOPE")]
    blocks += [{"handoff_block_id": "STOP_ESCALATE_TO_HITL"}, {"handoff_block_id": "PLAN"}]
    blocks += [{"handoff_block_id": "PLAN", "pr_class": c} for c in ("PLAN_ONLY", "BOUNDED_IMPLEMENT", "NOPE")]
    file_sets = [
        [INERT_FILE],
        [EVIDENCE_FILE],
        [CODE_FILE],
        [TOOL_CONFIG_FILE],
        [WORKFLOW_FILE],
        [AGENTS_FILE],
        [CURSOR_RULE],
        [WAIVER_CONFIG],
        [INERT_FILE, CODE_FILE],
        [INERT_FILE, EVIDENCE_FILE],
        [CODE_FILE, AGENTS_FILE],
    ]
    return list(itertools.product(blocks, file_sets, (True, False, None, "true")))


class InvariantTests(unittest.TestCase):
    """ROUTER-POLICY-SPEC-002 section 6."""

    def setUp(self):
        self.tables = load_tables()

    def test_1_no_green_breach(self):
        for name, policy in self.tables.classes.items():
            forbidden = {"CODE": CODE_FILE, "TOOL_CONFIG": TOOL_CONFIG_FILE, "PROBE_EVIDENCE": EVIDENCE_FILE}
            for family, path in forbidden.items():
                if family in policy.permitted_families:
                    continue
                for waiver in (True, False):
                    with self.subTest(cls=name, family=family, waiver=waiver):
                        d = run([INERT_FILE, path], vqt(name), waiver)
                        self.assertEqual((d.disposition, d.exit_code, d.merge_allowed), ("DENIED", 1, False))

    def test_2_waiver_cannot_override_steps_1_to_4(self):
        for block, files, _ in _scenario_space():
            off = run(files, copy.deepcopy(block), False)
            if off.decided_at_step > 4:
                continue
            on = run(files, copy.deepcopy(block), True)
            with self.subTest(block=block, files=files):
                self.assertEqual(on, off)

    def test_3_merge_allowed_only_per_allowlist(self):
        seen = set()
        for block, files, waiver in _scenario_space():
            d = run(files, copy.deepcopy(block), waiver)
            if d.merge_allowed:
                seen.add((d.pr_type, d.disposition))
                self.assertIn((d.pr_type, d.disposition), self.tables.merge_allowlist)
                self.assertEqual(d.exit_code, 0)
                self.assertEqual(d.head_sha, SHA)
        self.assertEqual(seen, set(self.tables.merge_allowlist))

    def test_4_decision_binds_to_verified_sha(self):
        d = run([INERT_FILE], None, False)
        self.assertEqual(d.head_sha, SHA)
        other = run([INERT_FILE, "docs/more.md"], None, False)
        self.assertNotEqual(d.file_list_digest, other.file_list_digest)
        for shas in [(SHA, SHA2), (SHA.upper(), SHA.upper()), ("abc", "abc"), (None, None), ("", "")]:
            with self.subTest(shas=shas):
                bad = run([INERT_FILE], None, False, shas=shas)
                self.assertEqual((bad.reason, bad.merge_allowed, bad.head_sha), ("DIFF_UNKNOWN", False, None))

    def test_5_self_modification_denied(self):
        authority_paths = [
            WAIVER_CONFIG,
            "governance/reviewer_execution/sal3/other.yaml",
            "tools/reviewer_execution/sal3/review_waiver.py",
            "POLICIES/ENTERPRISE-DELEGATED-MERGE-STANDING-AUTHORITY-001.md",
            ".github/CODEOWNERS",
            "CODEOWNERS",
            "docs/CODEOWNERS",
            ".cursor/approval-policies/ROUTING.md",
            "tools/agent_workflow/router_spec002/policy_tables.json",
            "tools/agent_workflow/router_spec002/evaluator.py",
            "tools/agent_workflow/router_spec002",
            "tools/agent_workflow/specs/ROUTER-POLICY-SPEC-002.md",
            ".github/workflows/pr-handoff-router.yml",
            # every workflow holds a write token; a new one can merge
            WORKFLOW_FILE,
            ".github/workflows/brand-new.yml",
            ".github/actions/merge/action.yml",
            ".github/settings.yml",
            # live delegation grants read by the merge evaluators
            "UPG/delegation/ENTERPRISE-GOVERNED-DELEGATED-DOCS-ONLY-MERGE-LIVE-DELEGATION-RENEWAL-003.md",
            "docs/delegation/OFFLINE-NON-RUNTIME-VALIDATION-TOOLING-PRODUCTION-GRANT-LIVE-001.md",
            # enforcement code run by write-token workflows
            "tools/agent_workflow/pr_handoff_router.py",
            "tools/agent_workflow/handoff_block_parser.py",
            "tools/agent_workflow/mission_state.py",
            "tools/reviewer_execution/runtime/engine.py",
            "tools/vrt/vrt_delegated_merge.py",
            "tools/vrt/tests/test_anything.py",
            "tools/policy/cc_lightweight_policy_check.py",
            # module shadowing on the workflow sys.path
            "tools/agent_workflow/json.py",
            "tools/agent_workflow/yaml/__init__.py",
            "tools/sitecustomize.py",
            "tools/vrt/urllib.pyc",
            "tools/agent_workflow/_ssl.so",
            "subprocess.py",
            "yaml/__init__.py",
            # case aliasing on case-insensitive checkouts
            "Governance/Reviewer_Execution/SAL3/Temporary-Review-Waiver.YAML",
            ".GITHUB/codeowners",
        ]
        for path in authority_paths:
            for block, waiver in itertools.product([None, vqt("BOUNDED_IMPLEMENT"), vqt("IMPLEMENT_ONLY")], (True, False)):
                with self.subTest(path=path, block=block, waiver=waiver):
                    d = run([path], block, waiver)
                    self.assertEqual((d.reason, d.exit_code, d.merge_allowed), ("AUTHORITY_VIOLATION", 1, False))

    def test_5_rename_or_delete_of_authority_file_denied(self):
        for change in [
            FileChange("docs/old-waiver.yaml", "renamed", WAIVER_CONFIG),
            FileChange(WAIVER_CONFIG, "renamed", "docs/x.md"),
            FileChange(WAIVER_CONFIG, "removed"),
            FileChange("docs/copy.md", "copied", ".github/CODEOWNERS"),
        ]:
            with self.subTest(change=change):
                d = run([change], vqt("BOUNDED_IMPLEMENT"), True)
                self.assertEqual(d.reason, "AUTHORITY_VIOLATION")

    def test_6_unknown_input_denied(self):
        cases = [
            ("unknown block", lambda: run([INERT_FILE], {"handoff_block_id": "NEXT_HITL_THING"}), "UNKNOWN_BLOCK"),
            ("malformed block", lambda: run([INERT_FILE], {}), "INVALID_INPUT"),
            ("block id wrong type", lambda: run([INERT_FILE], {"handoff_block_id": 3}), "INVALID_INPUT"),
            ("block not a mapping", lambda: run([INERT_FILE], "NEXT_VQT_REVIEW_REQUEST"), "INVALID_INPUT"),
            ("block id case", lambda: run([INERT_FILE], {"handoff_block_id": VQT.lower(), "pr_class": "PLAN_ONLY"}),
             "UNKNOWN_BLOCK"),
            ("waiver missing", lambda: run([INERT_FILE], None, None), "INVALID_INPUT"),
            ("waiver string", lambda: run([INERT_FILE], None, "true"), "INVALID_INPUT"),
            ("waiver int", lambda: run([INERT_FILE], None, 1), "INVALID_INPUT"),
            ("unknown class", lambda: run([INERT_FILE], vqt("SUPER_IMPLEMENT")), "UNKNOWN_CLASS"),
            ("class case", lambda: run([INERT_FILE], vqt("plan_only")), "UNKNOWN_CLASS"),
            ("class padded", lambda: run([INERT_FILE], vqt(" PLAN_ONLY")), "UNKNOWN_CLASS"),
            ("class non-string", lambda: run([INERT_FILE], vqt(["PLAN_ONLY"])), "UNKNOWN_CLASS"),
            ("missing class", lambda: run([INERT_FILE], vqt()), "UNKNOWN_CLASS"),
            ("empty class", lambda: run([INERT_FILE], vqt("")), "UNKNOWN_CLASS"),
            ("unknown class on optional block",
             lambda: run([INERT_FILE], {"handoff_block_id": "STOP_ESCALATE", "pr_class": "NOPE"}), "UNKNOWN_CLASS"),
            ("incomplete listing", lambda: run([INERT_FILE], None, complete=False), "DIFF_UNKNOWN"),
            ("truthy complete", lambda: run([INERT_FILE], None, complete=1), "DIFF_UNKNOWN"),
            ("empty listing", lambda: run([], None), "DIFF_UNKNOWN"),
            ("unknown status", lambda: run([FileChange(INERT_FILE, "mystery")], None), "DIFF_UNKNOWN"),
            ("rename without origin", lambda: run([FileChange(INERT_FILE, "renamed")], None), "DIFF_UNKNOWN"),
            ("api failure", lambda: evaluate(RaisingSource(), None, False), "DIFF_UNKNOWN"),
        ]
        for label, scenario, reason in cases:
            with self.subTest(case=label):
                d = scenario()
                self.assertEqual((d.disposition, d.reason, d.exit_code, d.merge_allowed), ("DENIED", reason, 1, False))

    def test_6_unknown_path_is_code(self):
        tables = self.tables
        for path in ["LICENSE", "Makefile", "tools/x.yaml", "data/blob.json", "site/index.html", "img/logo.svg"]:
            with self.subTest(path=path):
                self.assertEqual(tables.classify(path.casefold()), "CODE")

    def test_6_broken_tables_deny(self):
        d = evaluate(Source([INERT_FILE]), None, False, tables=object())
        self.assertEqual((d.reason, d.exit_code, d.merge_allowed), ("EVALUATION_ERROR", 1, False))

    def test_7_merge_allowed_only_computed_in_decide(self):
        source = inspect.getsource(evaluator_module)
        self.assertEqual(len(re.findall(r"\bDecision\(", source)), 1)
        self.assertEqual(len(re.findall(r"merge_allowed\s*=", source)), 2)  # local + constructor field
        self.assertNotRegex(source, r"merge_allowed\s*=\s*True")

    def test_7_empty_allowlist_never_merges(self):
        data = json.loads(TABLES_PATH.read_text(encoding="utf-8"))
        data["merge_allowlist"] = []
        tables = build_tables(data)
        for block, files, waiver in _scenario_space():
            d = evaluate(Source(files), copy.deepcopy(block), waiver, tables=tables)
            self.assertFalse(d.merge_allowed)


class EvaluationOrderTests(unittest.TestCase):
    def test_authority_beats_agent_policy_and_class(self):
        d = run([AGENTS_FILE, CODE_FILE, WAIVER_CONFIG], vqt("NOPE"), True)
        self.assertEqual((d.decided_at_step, d.reason, d.offending_paths), (2, "AUTHORITY_VIOLATION", (WAIVER_CONFIG,)))

    def test_agent_policy_beats_class_check(self):
        d = run([AGENTS_FILE, CODE_FILE], vqt("PLAN_ONLY"), False)
        self.assertEqual((d.decided_at_step, d.disposition, d.merge_allowed), (3, "HITL_REQUIRED", False))

    def test_implement_class_touching_agent_policy_still_hitl(self):
        d = run([CODE_FILE, ".cursor/rules/new.mdc"], vqt("BOUNDED_IMPLEMENT"), True)
        self.assertEqual((d.disposition, d.merge_allowed), ("HITL_REQUIRED", False))

    def test_waived_plan_merges_unwaived_plan_does_not(self):
        # A1 decision S-1: "Plan / Waived by operator" is mergeable.
        for block in [vqt("PLAN_ONLY"), {"handoff_block_id": "PLAN"}, {"handoff_block_id": "PLAN", "pr_class": "PLAN_ONLY"}]:
            with self.subTest(block=block):
                d = run([INERT_FILE], block, True)
                self.assertEqual((d.pr_type, d.disposition, d.exit_code, d.merge_allowed), ("PLAN", "WAIVED", 0, True))
                d = run([INERT_FILE], block, False)
                self.assertEqual((d.pr_type, d.disposition, d.exit_code, d.merge_allowed), ("PLAN", "ACKNOWLEDGED", 0, False))

    def test_plan_block_carries_inert_only(self):
        for files in ([CODE_FILE], [EVIDENCE_FILE], [TOOL_CONFIG_FILE]):
            for block in [{"handoff_block_id": "PLAN"}, {"handoff_block_id": "PLAN", "pr_class": "BOUNDED_IMPLEMENT"}]:
                with self.subTest(files=files, block=block):
                    d = run(files, block, True)
                    self.assertEqual((d.reason, d.exit_code, d.merge_allowed), ("CLASS_MISMATCH", 1, False))

    def test_plan_block_unknown_class_denied(self):
        d = run([INERT_FILE], {"handoff_block_id": "PLAN", "pr_class": "NOPE"}, True)
        self.assertEqual((d.reason, d.merge_allowed), ("UNKNOWN_CLASS", False))

    def test_escalation_ids_are_one_block_type(self):
        # Vector 10 uses STOP_ESCALATE; A1 decision S-2 names STOP_ESCALATE_TO_HITL. Both are accepted, identically.
        tables = load_tables()
        self.assertEqual(tables.block_types["STOP_ESCALATE"], tables.block_types["STOP_ESCALATE_TO_HITL"])
        for files, waiver in itertools.product(([INERT_FILE], [EVIDENCE_FILE], [CODE_FILE]), (True, False)):
            with self.subTest(files=files, waiver=waiver):
                a = run(files, {"handoff_block_id": "STOP_ESCALATE"}, waiver)
                b = run(files, {"handoff_block_id": "STOP_ESCALATE_TO_HITL"}, waiver)
                self.assertEqual(a, b)
                self.assertFalse(a.merge_allowed)

    def test_waiver_ignored_outside_vqt_review_requests(self):
        for block in [None, {"handoff_block_id": "CLOSEOUT"}, {"handoff_block_id": "STOP_ESCALATE"},
                      {"handoff_block_id": "STOP_ESCALATE_TO_HITL"}]:
            with self.subTest(block=block):
                self.assertEqual(run([INERT_FILE], block, True).disposition, "ACKNOWLEDGED")

    def test_vqt_request_without_waiver_never_merges(self):
        # SPEC-002 amendment 2026-10-19: a request is not an approval.
        for pr_class, files in [("IMPLEMENT_ONLY", [CODE_FILE]), ("BOUNDED_IMPLEMENT", [CODE_FILE, TOOL_CONFIG_FILE]),
                                ("DOC_WORKFLOW", [INERT_FILE, EVIDENCE_FILE])]:
            with self.subTest(pr_class=pr_class):
                d = run(files, vqt(pr_class), False)
                self.assertEqual((d.disposition, d.exit_code, d.merge_allowed), ("ACKNOWLEDGED", 0, False))
                d = run(files, vqt(pr_class), True)
                self.assertEqual((d.disposition, d.exit_code, d.merge_allowed), ("WAIVED", 0, True))

    def test_closeout_carries_inert_only(self):
        # A1 decision S-2: closeout and escalation may carry inert files only.
        d = run([INERT_FILE], {"handoff_block_id": "CLOSEOUT"}, False)
        self.assertEqual((d.pr_type, d.disposition, d.merge_allowed), ("CLOSEOUT", "ACKNOWLEDGED", True))
        for files in ([INERT_FILE, EVIDENCE_FILE], [CODE_FILE]):
            with self.subTest(files=files):
                d = run(files, {"handoff_block_id": "CLOSEOUT"}, False)
                self.assertEqual((d.reason, d.merge_allowed), ("CLASS_MISMATCH", False))

    def test_escalation_cannot_carry_code_even_with_implement_class(self):
        d = run([CODE_FILE], {"handoff_block_id": "STOP_ESCALATE", "pr_class": "BOUNDED_IMPLEMENT"}, False)
        self.assertEqual(d.reason, "CLASS_MISMATCH")

    def test_no_block_is_implicit_doc_workflow(self):
        # A1 decision S-2: a no-block PR is a docs-only claim with implicit DOC_WORKFLOW class.
        d = run([INERT_FILE, EVIDENCE_FILE], None, False)
        self.assertEqual((d.pr_type, d.disposition, d.merge_allowed), ("DOCS_ONLY", "ACKNOWLEDGED", True))
        for files in ([CODE_FILE], [TOOL_CONFIG_FILE]):
            with self.subTest(files=files):
                d = run(files, None, True)
                self.assertEqual((d.reason, d.merge_allowed), ("NO_BLOCK", False))

    def test_evidence_takes_precedence_over_inert(self):
        # A1 decision S-3: PROBE_EVIDENCE ranks above INERT, so plans cannot carry evidence Markdown.
        evidence_md = "CCP_UPGRADES/UPG/UPG-X-001/evidence/notes.md"
        d = run([evidence_md], vqt("PLAN_ONLY"), True)
        self.assertEqual((d.reason, d.merge_allowed), ("CLASS_MISMATCH", False))
        d = run([evidence_md], vqt("DOC_WORKFLOW"), True)
        self.assertEqual((d.disposition, d.merge_allowed), ("WAIVED", True))


class PathAttackTests(unittest.TestCase):
    def test_rejected_paths_deny_as_unknown_diff(self):
        for path in [
            "../AGENTS.md",
            "docs/../AGENTS.md",
            "./AGENTS.md",
            "docs//notes.md",
            "/etc/passwd",
            "docs/",
            "docs\\..\\AGENTS.md",
            "AGENTS.md:stream",
            "AGENTS.md.",
            "AGENTS.md ",
            "docs/notes.md\x00.py",
            "docs/no\u200btes.md",
            "docs/notes\n.md",
            ".git/hooks/pre-commit",
            ".GIT/config",
            "",
        ]:
            with self.subTest(path=path):
                d = run([path], vqt("BOUNDED_IMPLEMENT"), True)
                self.assertEqual((d.reason, d.merge_allowed), ("DIFF_UNKNOWN", False))

    def test_rejected_previous_path_denies(self):
        d = run([FileChange(INERT_FILE, "renamed", "../AGENTS.md")], None)
        self.assertEqual(d.reason, "DIFF_UNKNOWN")

    def test_aliases_classify_restrictively(self):
        tables = load_tables()
        expectations = {
            "agents.md": "AGENT_POLICY",
            "sub/dir/AGENTS.md": "AGENT_POLICY",
            "pkg/.cursor/rules/r.md": "AGENT_POLICY",
            ".Cursor/Rules/x.md": "AGENT_POLICY",
            "docs/thing.MDC": "AGENT_POLICY",
            "docs/thing.prompt.md": "AGENT_POLICY",
            ".claude/settings.json": "AGENT_POLICY",
            "AGENT_SKILLS_LIBRARY/x/README.md": "AGENT_POLICY",
            ".github/pull_request_template.md": "AGENT_POLICY",
            ".github/PULL_REQUEST_TEMPLATE/feature.md": "AGENT_POLICY",
            "governance/doctrine/AGENT-GOVERNANCE-ROUTING-INDEX-001.md": "AGENT_POLICY",
            "governance/agent-workflows/AL-HANDOFF-BLOCK-TEMPLATE-001.md": "AGENT_POLICY",
            "docs/notes.py.md": "INERT",
            "docs/pkg/__init__.py": "CODE",
            "tools/agent_workflow/tests/test_x.py": "CODE",
            "nested/.github/notes.md": "TOOL_CONFIG",
            ".cursor/mcp.json": "TOOL_CONFIG",
            ".cursor/hooks.json": "TOOL_CONFIG",
            "docs/.gitattributes": "TOOL_CONFIG",
            "docs/notes.md.py": "CODE",
            "tools/evidence/run.json": "CODE",
            "CCP_UPGRADES/UPG/X/evidence/run.py": "CODE",
            "CCP_UPGRADES/UPG/X/evidence/run.json": "PROBE_EVIDENCE",
            "CCP_UPGRADES/UPG/X/evidence/run.md": "PROBE_EVIDENCE",
            "docs/\uff21GENTS.md": "AGENT_POLICY",
        }
        from router_spec002.policy import normalize_path

        for path, family in expectations.items():
            with self.subTest(path=path):
                self.assertEqual(tables.classify(normalize_path(path)), family)

class PolicyTableValidationTests(unittest.TestCase):
    def mutate(self, fn):
        data = json.loads(TABLES_PATH.read_text(encoding="utf-8"))
        fn(data)
        return data

    def test_shipped_tables_load(self):
        tables = load_tables()
        self.assertEqual(set(tables.classes), set(ALL_CLASSES))

    def test_invalid_tables_rejected(self):
        mutations = {
            "class permits authority": lambda d: d["classes"]["PLAN_ONLY"]["permitted_families"].append("AUTHORITY"),
            "unknown family": lambda d: d["classes"]["PLAN_ONLY"]["permitted_families"].append("SPECIAL"),
            "authority not first": lambda d: d.__setitem__("family_precedence", d["family_precedence"][::-1]),
            "fallback not code": lambda d: d.__setitem__("fallback_family", "INERT"),
            "allowlist denied disposition": lambda d: d["merge_allowlist"].append(
                {"pr_type": "PLAN", "disposition": "HITL_REQUIRED"}),
            "allowlist unknown type": lambda d: d["merge_allowlist"].append(
                {"pr_type": "ANYTHING", "disposition": "ACKNOWLEDGED"}),
            "unknown rule key": lambda d: d["families"]["INERT"].append({"regex": ".*"}),
            "glob feeding inert": lambda d: d["families"]["INERT"].append({"glob": "*"}),
            "implicit class unknown": lambda d: d["absent_block"].__setitem__("implicit_class", "NOPE"),
            "implicit class on required block": lambda d: d["block_types"]["NEXT_VQT_REVIEW_REQUEST"].__setitem__(
                "implicit_class", "PLAN_ONLY"),
            "block missing implicit_class": lambda d: d["block_types"]["PLAN"].pop("implicit_class"),
            "glob feeding evidence": lambda d: d["families"]["PROBE_EVIDENCE"].append({"glob": "*/*"}),
            "block permits authority": lambda d: d["absent_block"]["permitted_families"].append("AUTHORITY"),
            "unknown top key": lambda d: d.__setitem__("override", True),
            "prefix without slash": lambda d: d["families"]["AUTHORITY"].append({"prefix": "tools"}),
            "waiver flag not bool": lambda d: d["classes"]["PLAN_ONLY"].__setitem__("waiver_eligible", "no"),
        }
        for label, fn in mutations.items():
            with self.subTest(mutation=label):
                with self.assertRaises(PolicyTableError):
                    build_tables(self.mutate(fn))

    def test_unreadable_tables_deny(self):
        from router_spec002 import policy

        original = policy.TABLES_PATH
        try:
            policy.load_tables.__defaults__ = (Path("/nonexistent/tables.json"),)
            d = evaluate(Source([INERT_FILE]), None, False)
            self.assertEqual((d.reason, d.merge_allowed), ("EVALUATION_ERROR", False))
        finally:
            policy.load_tables.__defaults__ = (original,)


class EnforcementSurfaceTests(unittest.TestCase):
    """Every file a write-token workflow executes must be AUTHORITY, so the table cannot drift behind the code."""

    REPO = Path(__file__).resolve().parents[3]

    def _resolve(self, name, here):
        parts = name.split(".")
        for base in (here.parent, self.REPO / "tools", self.REPO, self.REPO / "tools" / "agent_workflow"):
            for cand in (base.joinpath(*parts).with_suffix(".py"), base.joinpath(*parts, "__init__.py")):
                if cand.is_file():
                    return cand
        return None

    def _import_closure(self, entrypoints):
        import ast

        seen, todo = set(), list(entrypoints)
        while todo:
            path = todo.pop()
            if path in seen or not path.is_file():
                continue
            seen.add(path)
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    names = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    base = path.parent
                    for _ in range(node.level - 1):
                        base = base.parent
                    mod = base.joinpath(*node.module.split(".")) if node.module else base
                    todo += [p for p in (mod.with_suffix(".py"), mod / "__init__.py") if p.is_file()]
                    todo += [p for a in node.names for p in (mod / f"{a.name}.py",) if p.is_file()]
                    continue
                else:
                    continue
                for name in names:
                    dotted = name.split(".")
                    for i in range(1, len(dotted) + 1):
                        found = self._resolve(".".join(dotted[:i]), path)
                        if found:
                            todo.append(found)
        return seen

    def test_workflow_import_closure_is_authority(self):
        live = self.REPO / ".github" / "workflows"
        # A GCS release tree ships the workflows as templates under packaging/workflows/, to be installed in .github/workflows/.
        workflows = sorted((live if live.is_dir() else self.REPO / "packaging" / "workflows").glob("*.y*ml"))
        self.assertTrue(workflows)
        texts = [wf.read_text(encoding="utf-8") for wf in workflows]
        scripts = {self.REPO / m for text in texts for m in re.findall(r"tools/[A-Za-z0-9_./-]+\.py", text)}
        # Pipeline packages run with `python3 -m <package>` from tools/agent_workflow.
        modules = {m for text in texts for m in re.findall(r"python3? -m ([A-Za-z_][A-Za-z0-9_]*)", text)}
        entrypoints = scripts | {p for m in modules for p in (self.REPO / "tools" / "agent_workflow" / m / "__main__.py",)
                                 if p.is_file()}
        closure = self._import_closure(sorted(entrypoints))
        self.assertGreater(len(closure), len(entrypoints))
        tables = load_tables()
        from router_spec002.policy import normalize_path

        for path in sorted(closure):
            rel = path.relative_to(self.REPO).as_posix()
            with self.subTest(path=rel):
                self.assertEqual(tables.classify(normalize_path(rel)), "AUTHORITY")
        for wf in workflows:
            rel = f".github/workflows/{wf.name}"
            with self.subTest(workflow=rel):
                self.assertEqual(tables.classify(normalize_path(rel)), "AUTHORITY")

    def test_dispatcher_gateway_closure_is_authority(self):
        """The MCP gateway the dispatcher launches for agent runs, its import closure and the permission data it and
        the runtime binding read are AUTHORITY: a mission cannot change what an agent may reach."""
        from mission_dispatch import binding
        from router_spec002.policy import normalize_path

        aw = self.REPO / "tools" / "agent_workflow"
        entry = aw / binding.GATEWAY_MODULE / "__main__.py"
        if not entry.is_file():
            self.skipTest("this tree does not ship the gateway yet")
        closure = self._import_closure([entry])
        self.assertGreater(len(closure), 1)
        data = [aw / "mcp_auth" / "policy.json", aw / "retrieval" / "corpus.json", aw / "mcp_gateway" / "tools.json",
                aw / "tool_selection" / "matrix.json", aw / "tool_selection" / "seats.json",
                aw / "tool_selection" / "runtime_registry.json"]
        tables = load_tables()
        for path in sorted(closure) + [p for p in data if p.is_file()]:
            rel = path.relative_to(self.REPO).as_posix()
            with self.subTest(path=rel):
                self.assertEqual(tables.classify(normalize_path(rel)), "AUTHORITY")


class GitHubSourceTests(unittest.TestCase):
    BASE = "c" * 40

    def make_runner(self, heads, files_by_head, changed_files=None):
        """heads: successive PR head reads. files_by_head: compare file list per pinned head SHA."""
        pr_reads = iter(heads)
        calls = []

        def runner(args):
            (url,) = args
            calls.append(url)
            if "/compare/" in url:
                base, head = url.rsplit("/", 1)[1].split("...")
                self.assertEqual(base, self.BASE)
                return json.dumps({"files": files_by_head[head]})
            head = next(pr_reads)
            count = len(files_by_head.get(head, [])) if changed_files is None else changed_files
            return json.dumps({"head": {"sha": head}, "base": {"sha": self.BASE}, "changed_files": count})

        runner.calls = calls
        return runner

    def source(self, runner):
        return GitHubPullRequestSource("example-org/example-repo", 1, runner)

    def test_live_style_evaluation(self):
        files = [{"filename": f"docs/f{i}.md", "status": "added"} for i in range(150)]
        d = evaluate(self.source(self.make_runner([SHA, SHA], {SHA: files})), None, False)
        self.assertEqual((d.pr_type, d.disposition, d.merge_allowed, d.head_sha), ("DOCS_ONLY", "ACKNOWLEDGED", True, SHA))

    def test_listing_is_pinned_to_the_verified_head(self):
        runner = self.make_runner([SHA, SHA], {SHA: [{"filename": "docs/a.md", "status": "added"}]})
        evaluate(self.source(runner), None, False)
        self.assertIn(f"repos/example-org/example-repo/compare/{self.BASE}...{SHA}", runner.calls)
        self.assertFalse(any(url.endswith("/files") or "/files?" in url for url in runner.calls))

    def test_head_a_b_a_lists_files_of_a(self):
        # Head moves A -> B -> A around the listing. Both SHA reads agree, so the listing must be A's, not B's.
        benign = [{"filename": "docs/a.md", "status": "modified"}]
        malicious = [{"filename": WAIVER_CONFIG, "status": "modified"}]
        runner = self.make_runner([SHA, SHA], {SHA: malicious, SHA2: benign})
        d = evaluate(self.source(runner), vqt("DOC_WORKFLOW"), True)
        self.assertEqual((d.reason, d.merge_allowed), ("AUTHORITY_VIOLATION", False))

    def test_short_listing_is_incomplete(self):
        files = [{"filename": "docs/a.md", "status": "added"}]
        d = evaluate(self.source(self.make_runner([SHA, SHA], {SHA: files}, 2)), None, False)
        self.assertEqual(d.reason, "DIFF_UNKNOWN")

    def test_listing_at_compare_cap_is_incomplete(self):
        files = [{"filename": f"docs/f{i}.md", "status": "added"} for i in range(300)]
        d = evaluate(self.source(self.make_runner([SHA, SHA], {SHA: files})), None, False)
        self.assertEqual((d.reason, d.merge_allowed), ("DIFF_UNKNOWN", False))

    def test_head_moves_during_listing(self):
        files = [{"filename": "docs/a.md", "status": "added"}]
        d = evaluate(self.source(self.make_runner([SHA, SHA2], {SHA: files, SHA2: files})), None, False)
        self.assertEqual(d.reason, "DIFF_UNKNOWN")

    def test_malformed_sha_never_reaches_a_url(self):
        for bad in ["HEAD", "a" * 39, "../../x", SHA.upper()]:
            with self.subTest(sha=bad):
                runner = self.make_runner([bad, bad], {bad: [{"filename": "docs/a.md", "status": "added"}]})
                d = evaluate(self.source(runner), None, False)
                self.assertEqual((d.reason, d.merge_allowed), ("DIFF_UNKNOWN", False))
                self.assertFalse(any("/compare/" in url for url in runner.calls))

    def test_rename_metadata_carried(self):
        files = [{"filename": "docs/a.md", "status": "renamed", "previous_filename": WAIVER_CONFIG}]
        d = evaluate(self.source(self.make_runner([SHA, SHA], {SHA: files})), vqt("BOUNDED_IMPLEMENT"), True)
        self.assertEqual(d.reason, "AUTHORITY_VIOLATION")

    def test_bad_identifiers_rejected(self):
        for repo, number in [("a/b; rm -rf", 1), ("noslash", 1), ("a/b", 0), ("a/b", "1")]:
            with self.subTest(repo=repo, number=number):
                with self.assertRaises(ValueError):
                    GitHubPullRequestSource(repo, number)


if __name__ == "__main__":
    unittest.main()
