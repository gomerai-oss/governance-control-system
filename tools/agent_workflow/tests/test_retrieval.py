"""Tests for the structure-first retriever (STRUCTURAL-RETRIEVAL-SPEC-001).

One named case per predicted vector P1-P8, plus hardening cases. Every case
writes its own corpus and corpus registry into a temporary directory; no case
reads ``governance/doctrine/`` or ``tools/agent_workflow/specs/`` from the
checkout, so documents added or deleted there never change a result.
"""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from epap import ed25519, links, signing

from retrieval import corpus as corpus_mod
from retrieval import failures, records, retrieve, stages


DEFAULT_DENY = ["*.pem", "*.key", "*secret*", "*token*", "*credential*", "id_rsa*", ".env*"]


def doc(title, body="", status=None, superseded_by=None, date=None):
    lines = [f"# {title}", "", f"**Title:** {title}"]
    if status is not None:
        lines.append(f"**Status:** {status}")
    if superseded_by is not None:
        lines.append(f"**Superseded-By:** {superseded_by}")
    if date is not None:
        lines.append(f"**Date Captured:** {date}")
    lines += ["", body, ""]
    return "\n".join(lines)


class RetrievalCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        (self.root / "docs").mkdir()

    def write(self, relpath, text):
        target = self.root / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        return relpath

    def registry(self, vocabulary=None, roots=("docs/**/*.md",), corpus_id="corpus:docs"):
        data = {
            "schema": "retrieval-corpus-v1",
            "registry_version": "test-registry-1",
            "corpora": [{
                "id": corpus_id,
                "roots": list(roots),
                "deny_patterns": list(DEFAULT_DENY),
                "authority": {"docs/": "doctrine"},
                "vocabulary": dict(vocabulary or {}),
            }],
        }
        return corpus_mod.parse_registry(data)

    def request(self, request_id, **kw):
        return records.make_request(request_id, **kw)


class VectorTests(RetrievalCase):
    def test_p1_exact_document_id_resolves_at_exact(self):
        self.write("docs/ALPHA-001.md", doc("Alpha", "the alpha body"))
        self.write("docs/BETA-001.md", doc("Beta", "unrelated"))
        result = retrieve.retrieve(
            self.request("P1", constraints={"document_id": "ALPHA-001"}),
            self.root, self.registry())
        self.assertEqual(result["source_id"], "ALPHA-001")
        self.assertEqual(result["evidence_relationship"], "EXACT_MATCH")
        self.assertEqual(result["confidence_state"], "RESOLVED")
        self.assertEqual(result["provenance"]["resolved_stage"], "exact")
        ran = [s["stage"] for s in result["provenance"]["stages"]]
        self.assertEqual(ran, ["exact"])  # no later stage runs
        cites = retrieve.citations(result)
        self.assertEqual(len(cites), 1)
        self.assertIsNone(records.citation_problem(cites[0]))
        self.assertEqual(cites[0]["evidence_relationship"], "EXACT_MATCH")

    def test_p2_registered_alias_resolves_at_vocabulary(self):
        self.write("docs/BETA-001.md", doc("Beta", "canonical content"))
        result = retrieve.retrieve(
            self.request("P2", constraints={"alias": "beta-alias"}),
            self.root, self.registry(vocabulary={"beta-alias": "BETA-001"}))
        self.assertEqual(result["source_id"], "BETA-001")
        self.assertEqual(result["provenance"]["resolved_stage"], "vocabulary")
        self.assertEqual(result["provenance"]["stages"][-1]["outcome"], "RESOLVED")

    def test_p3_keyword_resolves_at_lexical_and_is_byte_identical(self):
        self.write("docs/ALPHA-001.md", doc("Alpha", "ordinary prose about widgets"))
        self.write("docs/GAMMA-001.md", doc("Gamma", "a passage mentioning quantum lattices"))
        self.write("docs/BETA-001.md", doc("Beta", "neutral filler text"))
        req = self.request("P3", constraints={"keywords": ["quantum"]})
        reg = self.registry()
        first = retrieve.retrieve(req, self.root, reg)
        second = retrieve.retrieve(req, self.root, reg)
        self.assertEqual(first["source_id"], "GAMMA-001")
        self.assertEqual(first["provenance"]["resolved_stage"], "lexical")
        self.assertEqual(first["evidence_relationship"], "LEXICAL_SUPPORT")
        self.assertEqual(signing.canonical_bytes(first), signing.canonical_bytes(second))

    def test_p4_superseded_best_hit_cites_the_superseding_document(self):
        self.write("docs/OLD-001.md", doc("Old policy", "stale", status="SUPERSEDED",
                                          superseded_by="NEW-001"))
        self.write("docs/NEW-001.md", doc("New policy", "current body"))
        result = retrieve.retrieve(
            self.request("P4", constraints={"document_id": "OLD-001"}),
            self.root, self.registry())
        self.assertEqual(result["source_id"], "NEW-001")
        self.assertNotEqual(result["source_id"], "OLD-001")
        self.assertEqual(result["contradiction_state"], "SUPERSEDES")
        superseded = result["provenance"]["superseded"]
        self.assertEqual([c["source_id"] for c in superseded], ["OLD-001"])
        self.assertEqual(superseded[0]["contradiction_state"], "SUPERSEDED")
        # the superseded document is never the cited source
        self.assertTrue(all(c["source_id"] == "NEW-001" or c["contradiction_state"] == "SUPERSEDED"
                            for c in retrieve.citations(result)))

    def test_p4_superseding_document_outside_corpus_abstains(self):
        self.write("docs/OLD-001.md", doc("Old policy", "stale", status="SUPERSEDED",
                                          superseded_by="NEW-001"))
        result = retrieve.retrieve(
            self.request("P4b", constraints={"document_id": "OLD-001"}),
            self.root, self.registry())
        self.assertIsNone(result["source_id"])
        self.assertEqual(result["stop_reason"], "WRONG_DOCUMENT_VERSION")
        self.assertEqual(result["confidence_state"], "ABSTAINED")
        self.assertIn("WRONG_DOCUMENT_VERSION", failures.audit_result(result, self.root))

    def test_p4_lexical_hit_on_superseded_document_does_not_overclaim(self):
        # BM25 matches the stale document on a term its successor lacks. The
        # successor was never matched against the keywords, so it is cited no more
        # strongly than it supports itself: UNVERIFIED, never EXACT_MATCH.
        self.write("docs/OLD-001.md", doc("Old policy", "the quantum lattice passage",
                                          status="SUPERSEDED", superseded_by="NEW-001"))
        self.write("docs/NEW-001.md", doc("New policy", "an entirely different subject"))
        self.write("docs/BETA-001.md", doc("Beta", "neutral filler text"))
        result = retrieve.retrieve(
            self.request("P4c", constraints={"keywords": ["quantum"]}),
            self.root, self.registry())
        self.assertEqual(result["provenance"]["resolved_stage"], "lexical")
        self.assertEqual(result["source_id"], "NEW-001")
        self.assertEqual(result["evidence_relationship"], "UNVERIFIED")
        self.assertNotEqual(result["evidence_relationship"], "EXACT_MATCH")
        self.assertEqual(result["contradiction_state"], "SUPERSEDES")
        self.assertEqual([c["source_id"] for c in result["provenance"]["superseded"]], ["OLD-001"])
        cite = retrieve.citations(result)[0]
        self.assertEqual(cite["source_id"], "NEW-001")
        self.assertIsNone(failures.check_citation_support(cite, self.root))
        self.assertNotIn("CONTRADICTION_MISSED", retrieve.audit(result, self.root))

    def test_p4_lexical_hit_on_superseded_document_with_scoring_successor(self):
        # When the successor itself scores for the terms, LEXICAL_SUPPORT with a
        # matching line span is honest evidence.
        self.write("docs/OLD-001.md", doc("Old policy", "quantum quantum lattice passage",
                                          status="SUPERSEDED", superseded_by="NEW-001"))
        self.write("docs/NEW-001.md", doc("New policy", "the quantum lattice, revised"))
        result = retrieve.retrieve(
            self.request("P4d", constraints={"keywords": ["quantum"]}),
            self.root, self.registry())
        self.assertEqual(result["provenance"]["resolved_stage"], "lexical")
        self.assertEqual(result["source_id"], "NEW-001")
        self.assertEqual(result["evidence_relationship"], "LEXICAL_SUPPORT")
        self.assertEqual(result["contradiction_state"], "SUPERSEDES")
        self.assertIsNone(failures.check_citation_support(retrieve.citations(result)[0], self.root))

    def test_p4_lexical_hit_on_superseded_document_without_successor_abstains(self):
        self.write("docs/OLD-001.md", doc("Old policy", "the quantum lattice passage",
                                          status="SUPERSEDED", superseded_by="NEW-001"))
        result = retrieve.retrieve(
            self.request("P4e", constraints={"keywords": ["quantum"]}),
            self.root, self.registry())
        self.assertIsNone(result["source_id"])
        self.assertEqual(result["stop_reason"], "WRONG_DOCUMENT_VERSION")
        self.assertEqual(retrieve.citations(result)[0]["contradiction_state"], "SUPERSEDED")

    def test_p5_path_outside_roots_or_deny_pattern_is_acl_scope_failure(self):
        self.write("docs/ALPHA-001.md", doc("Alpha", "body"))
        self.write("docs/notes-secret.md", doc("Secret", "sensitive"))
        self.write("outside/other.md", doc("Outside", "not in any root"))
        reg = self.registry()
        outside = retrieve.retrieve(
            self.request("P5a", constraints={"path": "outside/other.md"}), self.root, reg)
        self.assertEqual(outside["stop_reason"], "ACL_SCOPE_FAILURE")
        self.assertIsNone(outside["source_id"])
        self.assertEqual(retrieve.citations(outside), [])
        denied = retrieve.retrieve(
            self.request("P5b", constraints={"path": "docs/notes-secret.md"}), self.root, reg)
        self.assertEqual(denied["stop_reason"], "ACL_SCOPE_FAILURE")
        self.assertIsNone(denied["source_id"])
        # the deny-pattern file never enters the corpus file set
        corpus = reg.get("corpus:docs")
        self.assertNotIn("docs/notes-secret.md", corpus_mod.resolve_files(corpus, self.root))

    def test_p6_no_evidence_abstains_and_recovery_records_exhaustion(self):
        self.write("docs/ALPHA-001.md", doc("Alpha", "ordinary body"))
        result = retrieve.retrieve(
            self.request("P6", constraints={"document_id": "NOPE-999",
                                            "keywords": ["zzznonexistent"]}),
            self.root, self.registry())
        self.assertIsNone(result["source_id"])
        self.assertEqual(result["stop_reason"], "MISSING_REQUIRED_SOURCE")
        self.assertEqual(retrieve.citations(result), [])
        last = result["provenance"]["stages"][-1]
        self.assertEqual(last["stage"], "recovery")
        self.assertEqual(last["outcome"], "LOOP_EXHAUSTED")
        self.assertEqual(last["detail"]["iterations"], 2)
        outcomes = {s["stage"]: s["outcome"] for s in result["provenance"]["stages"]}
        self.assertEqual(outcomes["semantic"], "SEMANTIC_UNAVAILABLE")
        self.assertIn("MISSING_REQUIRED_SOURCE", failures.audit_result(result, self.root))

    def test_p7_span_rehash_edit_detection_and_signed_link(self):
        rel = self.write("docs/ALPHA-001.md", doc("Alpha", "the original supporting passage"))
        result = retrieve.retrieve(
            self.request("P7", query_intent="find alpha",
                         constraints={"document_id": "ALPHA-001"}),
            self.root, self.registry())
        citation = retrieve.citations(result)[0]
        self.assertIsNone(failures.check_citation_support(citation, self.root))

        # the RETRIEVAL link wraps as a signed link with a test key
        body = retrieve.evidence_link(result)
        self.assertIsNone(links.link_problem(body))
        self.assertEqual(body["name"], "RETRIEVAL")
        seed = ed25519.generate_seed()
        meta = signing.sign_metablock(body, "a2", seed)
        self.assertIsNone(links.metablock_problem(meta))
        self.assertTrue(signing.signature_valid(ed25519.public_key(seed).hex(),
                                                 meta["signed"], meta["signatures"][0]["sig"]))

        # after the file is edited the same citation is unsupported
        (self.root / rel).write_text(doc("Alpha", "a completely different passage now"),
                                     encoding="utf-8")
        self.assertEqual(failures.check_citation_support(citation, self.root),
                         "UNSUPPORTED_ASSERTION")

    def test_p8_semantic_runs_only_after_stages_1_to_5_unresolved(self):
        self.write("docs/ALPHA-001.md", doc("Alpha", "ordinary body"))
        reg = self.registry()
        miss = self.request("P8a", constraints={"keywords": ["zzzmissing"]})

        # (a) no backend: records SEMANTIC_UNAVAILABLE, then runs recovery
        a = retrieve.retrieve(miss, self.root, reg)
        outcomes = {s["stage"]: s["outcome"] for s in a["provenance"]["stages"]}
        self.assertEqual(outcomes["semantic"], "SEMANTIC_UNAVAILABLE")
        self.assertIn("recovery", outcomes)

        # (b) stub backend resolves the otherwise unresolved request
        stub = StubBackend("docs/ALPHA-001.md")
        b = retrieve.retrieve(miss, self.root, reg, semantic_backend=stub)
        self.assertEqual(b["provenance"]["resolved_stage"], "semantic")
        self.assertEqual(b["evidence_relationship"], "UNVERIFIED")
        self.assertEqual(stub.calls, 1)

        # (c) when stages 1-5 resolve, the semantic stage never runs
        stub2 = StubBackend("docs/ALPHA-001.md")
        c = retrieve.retrieve(self.request("P8c", constraints={"document_id": "ALPHA-001"}),
                              self.root, reg, semantic_backend=stub2)
        self.assertEqual(c["provenance"]["resolved_stage"], "exact")
        self.assertNotIn("semantic", [s["stage"] for s in c["provenance"]["stages"]])
        self.assertEqual(stub2.calls, 0)


class PathHardeningTests(RetrievalCase):
    """P5 hardening: a requested path is never normalised into a root."""

    def setUp(self):
        super().setUp()
        self.write("docs/ALPHA-001.md", doc("Alpha", "body"))
        self.write("outside/other.md", doc("Outside", "not in any root"))
        self.reg = self.registry()

    def assert_acl_failure(self, request_id, constraints, **request_kw):
        result = retrieve.retrieve(self.request(request_id, constraints=constraints, **request_kw),
                                   self.root, self.reg)
        self.assertEqual(result["stop_reason"], "ACL_SCOPE_FAILURE")
        self.assertEqual(result["confidence_state"], "ABSTAINED")
        self.assertIsNone(result["source_id"])
        self.assertIsNone(result["provenance"]["source_path"])
        self.assertEqual(retrieve.citations(result), [])
        self.assertIsNone(links.link_problem(retrieve.evidence_link(result)))
        self.assertIn("ACL_SCOPE_FAILURE", failures.audit_result(result, self.root))
        return result

    def test_in_repo_dotdot_traversal_is_acl_scope_failure(self):
        self.assert_acl_failure("H1", {"path": "docs/../outside/other.md"})
        self.assert_acl_failure("H1b", {"location": "docs/sub/../../outside/other.md"})

    def test_out_of_repo_dotdot_traversal_is_acl_scope_failure(self):
        self.assert_acl_failure("H2", {"path": "docs/../../escape.md"})

    def test_absolute_path_is_acl_scope_failure(self):
        self.assert_acl_failure("H3", {"path": str(self.root / "docs" / "ALPHA-001.md")})

    def test_unclean_segments_and_backslash_are_acl_scope_failure(self):
        for i, path in enumerate(["docs/./ALPHA-001.md", "docs//ALPHA-001.md",
                                  "docs\\ALPHA-001.md", "", "docs/ALPHA-001.md/"]):
            self.assert_acl_failure(f"H4-{i}", {"path": path})
        self.assert_acl_failure("H4-list", {"path": ["docs/ALPHA-001.md"]})

    def test_classify_path_denies_unclean_paths(self):
        corpus = self.reg.get("corpus:docs")
        self.assertEqual(corpus_mod.classify_path(corpus, self.root, "docs/ALPHA-001.md"),
                         corpus_mod.PATH_ALLOWED)
        for path in ("docs/../outside/other.md", "docs/../../x.md", "/docs/ALPHA-001.md",
                     "docs/./ALPHA-001.md", "docs\\ALPHA-001.md"):
            self.assertEqual(corpus_mod.classify_path(corpus, self.root, path),
                             corpus_mod.PATH_DENIED, path)
            self.assertFalse(corpus.within_roots(path), path)

    def test_acl_gate_fires_before_stages_whatever_the_request_shape(self):
        # A lifecycle constraint alongside a denied path (which once let stage
        # 'exact' return NOT_APPLICABLE before classifying the path).
        self.assert_acl_failure("H6a", {"path": "outside/other.md", "version": "1"})
        self.assert_acl_failure("H6b", {"location": "docs/../outside/other.md",
                                        "lifecycle": "current"})
        # A denied path with keywords must not fall through to a lexical RESOLVED.
        r = self.assert_acl_failure("H6c", {"path": "outside/other.md", "keywords": ["body"]})
        self.assertEqual([s["stage"] for s in r["provenance"]["stages"]], ["acl"])
        # path and location together: an allowed path does not excuse a denied location.
        self.assert_acl_failure("H6d", {"path": "docs/ALPHA-001.md",
                                        "location": "outside/other.md"})

    def test_acl_gate_fires_for_any_pinned_retrieval_method(self):
        # Pinned recovery relaxes 'path' first, so it once never classified it.
        self.assert_acl_failure("H7a", {"path": "docs/../outside/other.md",
                                        "document_id": "ALPHA-001"},
                                retrieval_method="recovery")
        # A pinned non-exact stage never reaches stage 'exact' at all.
        for method in ("lexical", "metadata", "structure", "vocabulary", "semantic"):
            self.assert_acl_failure(f"H7-{method}", {"path": "outside/other.md",
                                                     "keywords": ["body"]},
                                    retrieval_method=method)

    def test_deny_patterns_match_case_insensitively(self):
        upper = ["docs/API-TOKEN.md", "docs/Secret-Notes.md", "docs/AWS_CREDENTIALS.md",
                 "docs/Server.PEM", "docs/.ENV.md"]
        for rel in upper:
            self.write(rel, doc("Sensitive", "sensitive words"))
        files = corpus_mod.resolve_files(self.reg.get("corpus:docs"), self.root)
        self.assertEqual(files, ["docs/ALPHA-001.md"])
        for i, rel in enumerate(upper):
            self.assert_acl_failure(f"H5-{i}", {"path": rel})
        lexical = retrieve.retrieve(self.request("H5-lex", constraints={"keywords": ["sensitive"]}),
                                    self.root, self.reg)
        self.assertIsNone(lexical["source_id"])


class SupersessionChainTests(RetrievalCase):
    """P4 hardening: Superseded-By is followed to a current document, never one hop only."""

    def assert_current_cited(self, result, current, superseded_ids):
        self.assertEqual(result["source_id"], current)
        self.assertEqual(result["confidence_state"], "RESOLVED")
        self.assertEqual(result["contradiction_state"], "SUPERSEDES")
        superseded = result["provenance"]["superseded"]
        self.assertEqual([c["source_id"] for c in superseded], superseded_ids)
        self.assertTrue(all(c["contradiction_state"] == "SUPERSEDED" for c in superseded))
        self.assertNotIn(current, superseded_ids)
        audit = retrieve.audit(result, self.root)
        self.assertNotIn("WRONG_DOCUMENT_VERSION", audit)
        self.assertNotIn("CONTRADICTION_MISSED", audit)

    def assert_wrong_version(self, result, superseded_ids, reason):
        self.assertIsNone(result["source_id"])
        self.assertEqual(result["confidence_state"], "ABSTAINED")
        self.assertEqual(result["stop_reason"], "WRONG_DOCUMENT_VERSION")
        self.assertEqual([c["source_id"] for c in result["provenance"]["superseded"]], superseded_ids)
        cites = retrieve.citations(result)
        self.assertTrue(cites)
        self.assertTrue(all(c["contradiction_state"] == "SUPERSEDED" for c in cites))
        last = result["provenance"]["stages"][-1]
        self.assertEqual(last["outcome"], "WRONG_DOCUMENT_VERSION")
        self.assertEqual(last["detail"]["reason"], reason)
        self.assertNotIn("recovery", [s["stage"] for s in result["provenance"]["stages"]])
        self.assertIn("WRONG_DOCUMENT_VERSION", retrieve.audit(result, self.root))

    def test_three_document_chain_at_exact_and_structure_cites_the_current_one(self):
        self.write("docs/V1.md", doc("Version one", "first", superseded_by="V2"))
        self.write("docs/V2.md", doc("Version two", "second", superseded_by="V3"))
        self.write("docs/V3.md", doc("Version three", "current"))
        result = retrieve.retrieve(self.request("C1", constraints={"document_id": "V1"}),
                                   self.root, self.registry())
        self.assert_current_cited(result, "V3", ["V1", "V2"])
        self.assertEqual(result["provenance"]["resolved_stage"], "structure")
        self.assertEqual(result["evidence_relationship"], "EXACT_MATCH")
        outcomes = [(s["stage"], s["outcome"]) for s in result["provenance"]["stages"]]
        self.assertEqual(outcomes[0], ("exact", "DEFERRED_SUPERSEDED"))
        self.assertEqual(outcomes[-1], ("structure", "RESOLVED"))
        # a request starting midway down the chain also reaches the current document
        mid = retrieve.retrieve(self.request("C1b", constraints={"document_id": "V2"}),
                                self.root, self.registry())
        self.assert_current_cited(mid, "V3", ["V2"])

    def test_three_document_chain_from_a_lexical_hit_cites_the_current_one(self):
        self.write("docs/V1.md", doc("Version one", "quantum quantum quantum passage",
                                     superseded_by="V2"))
        self.write("docs/V2.md", doc("Version two", "an unrelated revision", superseded_by="V3"))
        self.write("docs/V3.md", doc("Version three", "the quantum lattice, revised"))
        result = retrieve.retrieve(self.request("C2", constraints={"keywords": ["quantum"]}),
                                   self.root, self.registry())
        self.assertEqual(result["provenance"]["resolved_stage"], "lexical")
        self.assert_current_cited(result, "V3", ["V1", "V2"])
        self.assertEqual(result["evidence_relationship"], "LEXICAL_SUPPORT")
        self.assertIsNone(failures.check_citation_support(retrieve.citations(result)[0], self.root))

    def test_chain_leaving_the_corpus_after_two_hops_abstains(self):
        self.write("docs/V1.md", doc("Version one", "first", superseded_by="V2"))
        self.write("docs/V2.md", doc("Version two", "second", superseded_by="V9"))
        result = retrieve.retrieve(self.request("C3", constraints={"document_id": "V1"}),
                                   self.root, self.registry())
        self.assert_wrong_version(result, ["V1", "V2"], "OUTSIDE_CORPUS")

    def test_self_reference_abstains(self):
        self.write("docs/SELF-001.md", doc("Self", "the quantum passage", superseded_by="SELF-001"))
        self.write("docs/BETA-001.md", doc("Beta", "neutral filler text"))
        for request_id, constraints in (("C4a", {"document_id": "SELF-001"}),
                                        ("C4b", {"keywords": ["quantum"]})):
            result = retrieve.retrieve(self.request(request_id, constraints=constraints),
                                       self.root, self.registry())
            self.assert_wrong_version(result, ["SELF-001"], "SELF_REFERENCE")

    def test_two_document_cycle_abstains(self):
        self.write("docs/A-001.md", doc("A", "the quantum passage", superseded_by="B-001"))
        self.write("docs/B-001.md", doc("B", "another passage", superseded_by="A-001"))
        self.write("docs/BETA-001.md", doc("Beta", "neutral filler text"))
        for request_id, constraints in (("C5a", {"document_id": "A-001"}),
                                        ("C5b", {"keywords": ["quantum"]})):
            result = retrieve.retrieve(self.request(request_id, constraints=constraints),
                                       self.root, self.registry())
            self.assert_wrong_version(result, ["A-001", "B-001"], "CYCLE")

    def test_audit_flags_a_superseded_primary_whatever_the_contradiction_state(self):
        self.write("docs/V1.md", doc("Version one", "first", superseded_by="V2"))
        self.write("docs/V2.md", doc("Version two", "current"))
        result = retrieve.retrieve(self.request("C6", constraints={"document_id": "V1"}),
                                   self.root, self.registry())
        self.assertEqual(result["contradiction_state"], "SUPERSEDES")
        self.assertNotIn("WRONG_DOCUMENT_VERSION", retrieve.audit(result, self.root))
        # the cited source becomes superseded itself: a stale primary citation
        self.write("docs/V2.md", doc("Version two", "current", superseded_by="V3"))
        self.write("docs/V3.md", doc("Version three", "newer"))
        self.assertIn("WRONG_DOCUMENT_VERSION", retrieve.audit(result, self.root))
        self.assertIn("WRONG_DOCUMENT_VERSION", failures.audit_result(result, self.root))


class SemanticHardeningTests(RetrievalCase):
    """A backend hit goes through the same ACL, span and supersession rules as stages 1-5."""

    miss = {"keywords": ["zzzmissing"]}

    def test_semantic_hit_on_superseded_document_cites_the_successor(self):
        self.write("docs/OLD-001.md", doc("Old policy", "stale", status="SUPERSEDED",
                                          superseded_by="NEW-001"))
        self.write("docs/NEW-001.md", doc("New policy", "current body"))
        stub = StubBackend("docs/OLD-001.md", 1, 1)
        result = retrieve.retrieve(self.request("S1", constraints=self.miss),
                                   self.root, self.registry(), semantic_backend=stub)
        self.assertEqual(result["provenance"]["resolved_stage"], "semantic")
        self.assertEqual(result["source_id"], "NEW-001")
        self.assertEqual(result["contradiction_state"], "SUPERSEDES")
        self.assertEqual(result["evidence_relationship"], "UNVERIFIED")
        superseded = result["provenance"]["superseded"]
        self.assertEqual([c["source_id"] for c in superseded], ["OLD-001"])
        self.assertEqual(superseded[0]["contradiction_state"], "SUPERSEDED")
        cites = retrieve.citations(result)
        self.assertEqual(cites[0]["source_id"], "NEW-001")
        self.assertNotIn("CONTRADICTION_MISSED", retrieve.audit(result, self.root))

    def test_semantic_hit_on_superseded_document_without_successor_abstains(self):
        self.write("docs/OLD-001.md", doc("Old policy", "stale", status="SUPERSEDED",
                                          superseded_by="NEW-001"))
        result = retrieve.retrieve(self.request("S2", constraints=self.miss),
                                   self.root, self.registry(),
                                   semantic_backend=StubBackend("docs/OLD-001.md"))
        self.assertIsNone(result["source_id"])
        self.assertEqual(result["stop_reason"], "WRONG_DOCUMENT_VERSION")
        self.assertEqual(retrieve.citations(result)[0]["contradiction_state"], "SUPERSEDED")
        self.assertNotIn("recovery", [s["stage"] for s in result["provenance"]["stages"]])

    def test_semantic_out_of_range_span_is_no_match(self):
        self.write("docs/ALPHA-001.md", doc("Alpha", "ordinary body"))
        n_lines = len((self.root / "docs/ALPHA-001.md").read_text(encoding="utf-8").splitlines())
        for i, (start, end) in enumerate([(0, 1), (-3, 1), (2, 1), (1, n_lines + 1), (True, 1)]):
            stub = StubBackend("docs/ALPHA-001.md", start, end)
            result = retrieve.retrieve(self.request(f"S3-{i}", constraints=self.miss),
                                       self.root, self.registry(), semantic_backend=stub)
            outcomes = {s["stage"]: s["outcome"] for s in result["provenance"]["stages"]}
            self.assertEqual(outcomes["semantic"], "NO_MATCH", (start, end))
            self.assertEqual(outcomes["recovery"], "LOOP_EXHAUSTED")
            self.assertIsNone(result["source_id"])
            self.assertEqual(result["stop_reason"], "MISSING_REQUIRED_SOURCE")

    def test_semantic_in_range_span_rehashes(self):
        self.write("docs/ALPHA-001.md", doc("Alpha", "ordinary body"))
        stub = StubBackend("docs/ALPHA-001.md", 1, 3)
        result = retrieve.retrieve(self.request("S4", constraints=self.miss),
                                   self.root, self.registry(), semantic_backend=stub)
        self.assertEqual(result["evidence_span"]["end_line"], 3)
        self.assertIsNone(failures.check_citation_support(retrieve.citations(result)[0], self.root))

    def test_semantic_traversal_or_denied_hit_is_acl_scope_failure(self):
        self.write("docs/ALPHA-001.md", doc("Alpha", "ordinary body"))
        self.write("docs/API-TOKEN.md", doc("Token", "sensitive"))
        self.write("outside/other.md", doc("Outside", "not in any root"))
        for i, path in enumerate(["docs/../outside/other.md", "outside/other.md",
                                  "docs/API-TOKEN.md", str(self.root / "docs/ALPHA-001.md")]):
            result = retrieve.retrieve(self.request(f"S5-{i}", constraints=self.miss),
                                       self.root, self.registry(),
                                       semantic_backend=StubBackend(path))
            self.assertEqual(result["stop_reason"], "ACL_SCOPE_FAILURE", path)
            self.assertIsNone(result["source_id"])
            self.assertEqual(retrieve.citations(result), [])
            self.assertEqual(result["provenance"]["stages"][-1]["stage"], "semantic")


class RetrievalMethodTests(RetrievalCase):
    def test_methods_are_the_seven_stage_names(self):
        self.assertEqual(records.RETRIEVAL_METHODS, stages.ALL_STAGE_NAMES)

    def test_unknown_method_is_a_schema_failure(self):
        for bad in ("foo", "", "EXACT", 3, ["exact"]):
            with self.assertRaises(records.RecordError):
                self.request("M1", constraints={"document_id": "X"}, retrieval_method=bad)
            raw = {"request_id": "M1", "mission_id": None, "query_intent": "",
                   "constraints": {}, "corpus_scope": [], "retrieval_method": bad}
            self.assertIsNotNone(records.request_problem(raw))
            with self.assertRaises(records.RecordError):
                retrieve.retrieve(raw, self.root, self.registry())

    def test_pinned_recovery_runs_recovery(self):
        self.write("docs/ALPHA-001.md", doc("Alpha", "body"))
        result = retrieve.retrieve(
            self.request("M2", constraints={"path": "docs/MISSING.md", "document_id": "ALPHA-001"},
                         retrieval_method="recovery"),
            self.root, self.registry())
        self.assertEqual([s["stage"] for s in result["provenance"]["stages"]], ["recovery"])
        self.assertEqual(result["provenance"]["resolved_stage"], "recovery")
        self.assertEqual(result["source_id"], "ALPHA-001")
        self.assertEqual(result["provenance"]["stages"][0]["detail"], {"relaxations": ["path"]})

    def test_pinned_recovery_exhausts_honestly(self):
        self.write("docs/ALPHA-001.md", doc("Alpha", "body"))
        result = retrieve.retrieve(
            self.request("M3", constraints={"document_id": "NOPE-1"}, retrieval_method="recovery"),
            self.root, self.registry())
        last = result["provenance"]["stages"][-1]
        self.assertEqual((last["stage"], last["outcome"]), ("recovery", "LOOP_EXHAUSTED"))
        self.assertEqual(last["detail"]["iterations"], 1)
        self.assertEqual(result["confidence_state"], "ABSTAINED")

    def test_pinned_core_stage_runs_only_that_stage(self):
        self.write("docs/ALPHA-001.md", doc("Alpha", "body"))
        result = retrieve.retrieve(
            self.request("M4", constraints={"document_id": "ALPHA-001"}, retrieval_method="lexical"),
            self.root, self.registry())
        self.assertEqual([s["stage"] for s in result["provenance"]["stages"]], ["lexical"])
        self.assertEqual(result["stop_reason"], "MISSING_REQUIRED_SOURCE")


class StubBackend:
    """A deterministic semantic backend supplied by a test; no model is called."""

    def __init__(self, source_path, start_line=1, end_line=1):
        self.source_path = source_path
        self.start_line = start_line
        self.end_line = end_line
        self.calls = 0

    def retrieve(self, request, context):
        self.calls += 1
        return {"source_path": self.source_path,
                "start_line": self.start_line, "end_line": self.end_line}


class RecordTests(RetrievalCase):
    def test_request_schema_is_strict(self):
        good = self.request("R1", constraints={"document_id": "X"})
        self.assertIsNone(records.request_problem(good))
        with self.assertRaises(records.RecordError):
            records.validate_request({**good, "extra": 1})
        broken = dict(good)
        del broken["constraints"]
        with self.assertRaises(records.RecordError):
            records.validate_request(broken)

    def test_result_and_citation_schemas_are_strict(self):
        self.write("docs/ALPHA-001.md", doc("Alpha", "body"))
        result = retrieve.retrieve(self.request("R2", constraints={"document_id": "ALPHA-001"}),
                                   self.root, self.registry())
        self.assertIsNone(records.result_problem(result))
        self.assertIsNotNone(records.result_problem({**result, "surprise": 1}))
        citation = retrieve.citations(result)[0]
        self.assertIsNone(records.citation_problem(citation))
        with self.assertRaises(records.RecordError):
            records.validate_citation({**citation, "source_path": "/abs/path.md"})

    def test_fields_are_exactly_the_section_8_set(self):
        self.assertEqual(records.REQUEST_FIELDS | records.RESULT_FIELDS, {
            "request_id", "mission_id", "query_intent", "constraints", "corpus_scope",
            "retrieval_method", "source_id", "source_authority", "source_version",
            "source_date", "claim_id", "claim_text", "evidence_span", "evidence_relationship",
            "confidence_state", "contradiction_state", "missing_evidence", "validation_state",
            "provenance", "stop_reason"})
        self.assertEqual(records.REQUEST_FIELDS & records.RESULT_FIELDS, set())


class CorpusTests(RetrievalCase):
    def test_registry_validation_rejects_bad_schema_and_class(self):
        with self.assertRaises(corpus_mod.CorpusError):
            corpus_mod.parse_registry({"schema": "wrong", "registry_version": "x", "corpora": []})
        with self.assertRaises(corpus_mod.CorpusError):
            corpus_mod.parse_registry({
                "schema": "retrieval-corpus-v1", "registry_version": "x",
                "corpora": [{"id": "corpus:a", "roots": ["docs/*.md"], "deny_patterns": [],
                             "authority": {"docs/": "not-a-class"}, "vocabulary": {}}]})

    def test_resolve_excludes_deny_patterns_and_symlinks(self):
        self.write("docs/ALPHA-001.md", doc("Alpha", "body"))
        self.write("docs/api-token.md", doc("Token", "sensitive"))
        reg = self.registry()
        corpus = reg.get("corpus:docs")
        files = corpus_mod.resolve_files(corpus, self.root)
        self.assertIn("docs/ALPHA-001.md", files)
        self.assertNotIn("docs/api-token.md", files)  # matches *token*
        try:
            os.symlink(self.root / "docs/ALPHA-001.md", self.root / "docs/link.md")
        except (OSError, NotImplementedError):
            self.skipTest("symlinks not supported here")
        self.assertNotIn("docs/link.md", corpus_mod.resolve_files(corpus, self.root))

    def test_default_shipped_registry_loads(self):
        reg = corpus_mod.load_registry(corpus_mod.default_registry_path())
        self.assertIn("corpus:governance-doctrine", reg.corpora)


class FailureTests(RetrievalCase):
    def test_seventeen_classes_with_detection_and_severity(self):
        self.assertEqual(len(failures.FAILURE_CLASSES), 17)
        for name, spec in failures.FAILURE_CLASSES.items():
            self.assertIn("severity", spec)
            self.assertIn("evidence_retained", spec)
            if spec["detection"] == failures.NOT_DETECTABLE:
                self.assertIn("reason", spec)

    def test_audit_detects_schema_failure(self):
        self.assertEqual(failures.audit_result({"not": "a result"}, self.root), ["SCHEMA_FAILURE"])

    def test_audit_detects_loop_exhaustion_misrepresented(self):
        self.write("docs/ALPHA-001.md", doc("Alpha", "body"))
        result = retrieve.retrieve(self.request("F1", constraints={"document_id": "ALPHA-001"}),
                                   self.root, self.registry())
        tampered = json.loads(signing.canonical_bytes(result).decode("utf-8"))
        tampered["provenance"]["stages"].append(
            {"stage": "recovery", "outcome": "LOOP_EXHAUSTED", "detail": {"iterations": 1}})
        self.assertIn("LOOP_EXHAUSTION_MISREPRESENTED",
                      failures.audit_result(tampered, self.root, retrieve.citations(tampered)))


class CliTests(RetrievalCase):
    def test_cli_prints_canonical_json(self):
        self.write("docs/ALPHA-001.md", doc("Alpha", "body"))
        reg_path = self.root / "corpus.json"
        reg_path.write_text(json.dumps({
            "schema": "retrieval-corpus-v1", "registry_version": "cli-1",
            "corpora": [{"id": "corpus:docs", "roots": ["docs/**/*.md"],
                         "deny_patterns": DEFAULT_DENY, "authority": {"docs/": "doctrine"},
                         "vocabulary": {}}]}), encoding="utf-8")
        req_path = self.root / "req.json"
        req_path.write_text(json.dumps(self.request("C1", constraints={"document_id": "ALPHA-001"},
                                                     corpus_scope=["corpus:docs"])),
                            encoding="utf-8")
        # point the default registry path by monkeypatching is avoided; use retrieve() directly
        # for the registry, and only exercise the CLI formatting here.
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = _cli_with_registry(str(self.root), str(req_path), reg_path)
        self.assertEqual(code, 0)
        parsed = json.loads(buf.getvalue())
        self.assertEqual(parsed["source_id"], "ALPHA-001")
        self.assertEqual(buf.getvalue(), signing.canonical_bytes(parsed).decode("utf-8") + "\n")


def _cli_with_registry(root, request_file, registry_path):
    request = json.loads(Path(request_file).read_text(encoding="utf-8"))
    result = retrieve.retrieve(request, root, corpus_registry=registry_path)
    sys.stdout.write(signing.canonical_bytes(result).decode("utf-8") + "\n")
    return 0


if __name__ == "__main__":
    unittest.main()
