"""Ring 6 part 1 (MISSION-DISPATCH-001 §3m, Amendment 020): the evidence record, the chain, the seal, the verifier
and the mode. Vectors 102, 104, 105, 107, 110 and 111; router vector 119. Producers (the router, the dispatcher,
the gateway, the checks job) come in part 2, the seal job and the store in part 3."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import evidence
from epap import ed25519
from evidence import EvidenceError
from evidence import __main__ as cli
from evidence import chain, record, seal, verify
from mission_router.router import load_config
from router_spec002.policy import load_tables, normalize_path

AW = Path(__file__).resolve().parents[1]
RUN = "run-0001"
BOT = "example-router[bot]"


def entry(action="router.decision", **extra):
    fields = dict(actor=BOT, account_id=1001, action=action, result="done", authority_kind="spec_rule",
                  authority_ref="MISSION-ROUTER-001 section 2", mission="M-DEMO-001", round_n=1, pr=7,
                  commit="a" * 40, inputs={"head": "b" * 64}, outputs={"decision": "c" * 64})
    fields.update(extra)
    return fields


class Store:
    """A throwaway evidence store with one run of three records."""

    def __init__(self, test: unittest.TestCase):
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.seed = ed25519.generate_seed()
        public = ed25519.public_key(self.seed)
        self.keys = {seal.keyid(public): public.hex()}
        self.chain = self.run(RUN)

    def run(self, name, n=3):
        c = chain.Chain(self.root / verify.RUNS / name, name)
        for action in ("router.decision", "router.merge", "router.landing")[:n]:
            extra = {"reason": "merge: every routing check passed"} if action == "router.decision" else {}
            c.append(time="2026-11-07T12:00:00Z", **entry(action, **extra))
        return c

    def seal(self, c, seed=None):
        doc = seal.make(c.run, c.head, c.seq, {"agent-log": "d" * 64}, "2026-11-07T12:01:00Z", seed or self.seed)
        (c.path.parent / seal.SEAL).write_text(json.dumps(doc), encoding="utf-8")

    def lines(self, name=RUN):
        return (self.root / verify.RUNS / name / chain.RECORDS).read_bytes().split(b"\n")[:-1]

    def write(self, lines, name=RUN):
        (self.root / verify.RUNS / name / chain.RECORDS).write_bytes(b"".join(x + b"\n" for x in lines))

    def verify(self, **kw):
        return verify.verify_store(self.root, self.keys, **kw)


class RecordTests(unittest.TestCase):  # vector 102
    def make(self, **kw):
        return record.make(run=RUN, seq=0, prev=record.genesis(RUN), time="2026-11-07T12:00:00Z", **entry(**kw))

    def test_a_record_has_the_closed_fields(self):
        rec = self.make()
        self.assertEqual(set(rec), record.FIELDS - {"withdraws"})
        self.assertEqual(rec["class"], "decide")
        self.assertEqual(rec["id"], f"{RUN}/0")
        self.assertEqual(record.problems(rec), [])

    def test_the_action_list_is_closed(self):
        with self.assertRaisesRegex(EvidenceError, "not in the closed list"):
            self.make(action="router.something_new")
        rec = self.make()
        rec["class"] = "write"
        self.assertTrue(any("has class decide" in p for p in record.problems(rec)))

    def test_every_action_has_a_known_class(self):
        self.assertTrue(set(record.ACTIONS.values()) <= set(record.CLASSES))

    def test_inputs_and_outputs_are_digests_never_content(self):
        with self.assertRaisesRegex(EvidenceError, "digests only"):
            self.make(inputs={"message": "the agent's text"})

    def test_the_reason_passes_the_quarantine(self):
        rec = self.make(reason="held for @example-user\n/mission retry ‮")
        self.assertNotIn("@example-user", rec["reason"])
        self.assertNotIn("\n", rec["reason"])
        self.assertNotIn("‮", rec["reason"])
        raw = dict(rec, reason="for @example-user")
        self.assertTrue(any("quarantined line" in p for p in record.problems(raw)))

    def test_unknown_or_missing_fields_are_refused(self):
        rec = self.make()
        self.assertTrue(record.problems(dict(rec, content="x")))
        less = dict(rec)
        del less["prev"]
        self.assertTrue(record.problems(less))

    def test_a_withdrawal_names_its_record_and_is_hitl_only(self):
        target = {"id": f"{RUN}/1", "digest": "e" * 64}
        rec = self.make(action="evidence.withdraw", authority_kind="hitl_command", authority_ref="issue 12 comment",
                        withdraws=target)
        self.assertEqual(rec["class"], "withdraw")
        with self.assertRaisesRegex(EvidenceError, "HITL direction only"):
            self.make(action="evidence.withdraw", withdraws=target)
        with self.assertRaisesRegex(EvidenceError, "must name the record"):
            self.make(action="evidence.withdraw", authority_kind="hitl_command")
        with self.assertRaisesRegex(EvidenceError, "only a withdrawal"):
            self.make(withdraws=target)


class ChainTests(unittest.TestCase):
    def test_each_record_carries_the_digest_of_the_one_before(self):
        s = Store(self)
        recs = chain.read(s.chain.path)
        self.assertEqual(recs[0]["prev"], record.genesis(RUN))
        for before, rec in zip(recs, recs[1:]):
            self.assertEqual(rec["prev"], record.digest(before))
        self.assertEqual(s.chain.head, record.digest(recs[-1]))

    def test_a_reopened_chain_continues(self):
        s = Store(self)
        again = chain.Chain(s.chain.path.parent, RUN)
        self.assertEqual((again.seq, again.head), (3, s.chain.head))
        again.append(**entry("router.halt"))
        self.assertTrue(s.verify().ok)

    def test_a_line_must_be_canonical(self):
        s = Store(self)
        lines = s.lines()
        lines[0] = json.dumps(json.loads(lines[0]), indent=1).replace("\n", "").encode()
        s.write(lines)
        self.assertIn("canonical bytes", s.verify().failure)

    def test_the_first_record_is_bound_to_its_run(self):
        self.assertNotEqual(record.genesis("run-a"), record.genesis("run-b"))


class VerifierTests(unittest.TestCase):
    def test_a_sealed_run_verifies(self):
        s = Store(self)
        s.seal(s.chain)
        report = s.verify(require_seal=True)
        self.assertTrue(report.ok, report.failure)
        self.assertEqual((report.runs, report.records, report.unsealed), (1, 3, []))

    def test_v104_an_edited_record_breaks_the_chain(self):  # AST-6.1's check
        s = Store(self)
        lines = s.lines()
        lines[1] = lines[1].replace(b'"result":"done"', b'"result":"failed"')
        s.write(lines)
        failure = s.verify().failure
        self.assertIn(f"broken at record {RUN}/2", failure)
        self.assertIn(f"{RUN}/1 was changed or removed", failure)

    def test_v104_a_removed_record_is_a_gap(self):  # AST-6.2's check
        s = Store(self)
        lines = s.lines()
        s.write([lines[0], lines[2]])
        self.assertIn(f"a gap in the chain: record {RUN}/1 is missing", s.verify().failure)

    def test_an_edited_last_record_is_caught_by_the_seal(self):
        s = Store(self)
        s.seal(s.chain)
        lines = s.lines()
        lines[2] = lines[2].replace(b'"result":"done"', b'"result":"failed"')
        s.write(lines)
        self.assertIn("the seal's head does not match", s.verify().failure)

    def test_a_removed_last_record_is_caught_by_the_seal(self):
        s = Store(self)
        s.seal(s.chain)
        s.write(s.lines()[:2])
        self.assertIn("the seal covers 3 records, the chain has 2", s.verify().failure)

    def test_v105_a_seal_by_another_key_is_refused(self):  # AST-6.3's check
        s = Store(self)
        s.seal(s.chain, seed=ed25519.generate_seed())
        self.assertIn("not a pinned evidence key", s.verify().failure)

    def test_a_tampered_seal_is_refused(self):
        s = Store(self)
        s.seal(s.chain)
        path = s.chain.path.parent / seal.SEAL
        doc = json.loads(path.read_text())
        doc["signed"]["artifacts"]["agent-log"] = "f" * 64
        path.write_text(json.dumps(doc))
        self.assertIn("does not verify", s.verify().failure)

    def test_a_seal_for_another_run_is_refused(self):
        s = Store(self)
        other = s.run("run-0002")
        s.seal(other)
        (other.path.parent / seal.SEAL).rename(s.chain.path.parent / seal.SEAL)
        self.assertIn("the seal is for run run-0002", s.verify().failure)

    def test_a_record_moved_into_another_run_is_refused(self):
        s = Store(self)
        s.run("run-0002", n=1)
        s.write([s.lines()[0]], name="run-0002")
        self.assertIn("belongs to run", s.verify().failure)

    def test_v110_unsealed_runs_are_listed_under_observe_refused_when_sealed_is_required(self):
        s = Store(self)
        report = s.verify()
        self.assertTrue(report.ok)
        self.assertEqual(report.unsealed, [RUN])
        self.assertIn("not sealed", s.verify(require_seal=True).failure)

    def test_v107_a_withdrawal_keeps_the_chain_and_marks_the_record(self):  # AST-6.5's check
        s = Store(self)
        target = chain.read(s.chain.path)[1]
        w = s.run("run-0002", n=0)
        w.append(**entry("evidence.withdraw", authority_kind="hitl_command", authority_ref="issue 12 comment",
                         reason="recorded against the wrong PR",
                         withdraws={"id": target["id"], "digest": record.digest(target)}))
        report = s.verify()
        self.assertTrue(report.ok, report.failure)
        self.assertEqual(report.withdrawn, {f"{RUN}/1": "run-0002/0"})
        self.assertEqual(len(s.lines()), 3, "nothing is deleted")
        one = s.verify(run="run-0002")
        self.assertTrue(one.ok, one.failure)

    def test_a_withdrawal_of_a_record_not_in_the_store_is_refused(self):
        s = Store(self)
        w = s.run("run-0002", n=0)
        w.append(**entry("evidence.withdraw", authority_kind="hitl_command", authority_ref="issue 12 comment",
                         withdraws={"id": f"{RUN}/1", "digest": "0" * 64}))
        self.assertIn("not in the store as recorded", s.verify().failure)


class KeyPinTests(unittest.TestCase):
    def test_the_pinned_keys_load(self):
        keys = seal.load_keys()
        self.assertIsInstance(keys, dict)  # empty until the seal job's key is created (part 3)

    def test_a_pin_must_match_its_key_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "key.json"
            path.write_text(json.dumps({"schema": seal.KEYS_SCHEMA, "keys": [{"keyid": "0" * 64,
                                                                                 "public": "1" * 64}]}))
            with self.assertRaisesRegex(EvidenceError, "its key id"):
                seal.load_keys(path)


class CliTests(unittest.TestCase):
    def run_cli(self, *argv):
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli.main(list(argv))
        return code, out.getvalue()

    def test_verify_reports_and_refuses(self):
        s = Store(self)
        with tempfile.TemporaryDirectory() as tmp:
            keys = Path(tmp) / "key.json"
            kid, public = next(iter(s.keys.items()))
            keys.write_text(json.dumps({"schema": seal.KEYS_SCHEMA, "keys": [{"keyid": kid, "public": public}]}))
            code, out = self.run_cli("verify", "--store", str(s.root), "--keys", str(keys))
            self.assertEqual((code, out), (0, f"verified: 1 runs, 3 records\nunsealed: {RUN}\n"))
            self.assertEqual(self.run_cli("verify", "--store", str(s.root), "--keys", str(keys), "--sealed")[0], 1)
            s.seal(s.chain)
            self.assertEqual(self.run_cli("verify", "--store", str(s.root), "--keys", str(keys), "--sealed")[0], 0)
            s.write(s.lines()[:1] + s.lines()[2:])
            code, out = self.run_cli("verify", "--store", str(s.root), "--keys", str(keys))
            self.assertEqual(code, 1)
            self.assertTrue(out.startswith("REFUSED: "))


class ModeTests(unittest.TestCase):
    def test_the_mode(self):
        self.assertEqual(evidence.mode({}), "observe")
        self.assertEqual(evidence.mode({"evidence": "enforce"}), "enforce")
        with self.assertRaisesRegex(EvidenceError, "evidence must be one of"):
            evidence.mode({"evidence": "on"})  # vector 111

    def test_an_unknown_mode_stops_the_router(self):  # router vector 119
        config = json.loads((AW / "mission_router" / "config.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({**config, "evidence": "bogus"}))
            with self.assertRaisesRegex(ValueError, "evidence must be one of"):
                load_config(path)

    def test_this_repository_enforces_exactly_when_it_names_a_store(self):  # switched on 2026-11-09
        config = json.loads((AW / "mission_router" / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(evidence.mode(config), "enforce" if config.get("evidence_store") else "observe")

    def test_enforce_without_a_store_stops_the_router(self):
        config = json.loads((AW / "mission_router" / "config.json").read_text(encoding="utf-8"))
        config.pop("evidence_store", None)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({**config, "evidence": "enforce"}))
            with self.assertRaisesRegex(ValueError, "needs an evidence_store"):
                load_config(path)


class AuthorityTests(unittest.TestCase):
    def test_the_evidence_package_and_key_pin_are_authority(self):  # SPEC-002 amendment 2026-11-07
        tables = load_tables()
        for path in ("tools/agent_workflow/evidence/record.py", "tools/agent_workflow/evidence/key.json",
                     "tools/agent_workflow/evidence/verify.py"):
            with self.subTest(path):
                self.assertEqual(tables.classify(normalize_path(path)), "AUTHORITY")


if __name__ == "__main__":
    unittest.main()
