from __future__ import annotations

import ast
import contextlib
import io
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import graph_contracts.validate as V
import graph_engine.checkpoint as CK
import graph_engine.engine as E
import graph_engine.handlers as H
import graph_engine.state as ST

AGENT_WORKFLOW = Path(__file__).resolve().parents[1]
PKG = AGENT_WORKFLOW / "graph_engine"
NOW = "2026-10-29T00:00:00Z"

STR = {"type": "string"}
BOOL = {"type": "boolean"}
ROUTE = {"type": "string", "enum": ["FAST", "SLOW"]}

LINEAR = "GE-TEST-LINEAR-001"
GATED = "GE-TEST-GATED-001"
ROUTED = "GE-TEST-ROUTED-001"
PARENT = "GE-TEST-PARENT-001"
CHILD = "GE-TEST-CHILD-001"

APPROVAL = {"gate": "approve", "boundary": "MERGE", "decided_by": "HITL", "decision": "APPROVED"}


class Interrupt(BaseException):
    """Stands in for a process dying mid-run: no handler failure, nothing catches it."""


def obj(**props):
    """An object io schema whose properties are all required."""
    return {"type": "object", "properties": props, "required": list(props)}


def task(node_id, inp, out, kind="DETERMINISTIC_TASK"):
    return {"id": node_id, "kind": kind, "input_schema": inp, "output_schema": out}


def chain(*ids):
    return [{"kind": "static", "from": a, "to": b} for a, b in zip(ids, ids[1:])]


def contract(graph_id, nodes, edges, keys, writes, artifacts=()):
    return {
        "schema": "ge-graph-contract-v1", "graph_id": graph_id, "version": "1", "entry": nodes[0]["id"],
        "nodes": nodes, "edges": edges,
        "state": {"scope": "GRAPH_RUN", "store": "CONTROL_PLANE", "keys": keys,
                  "transitions": [{"id": f"t_{node}_{key}", "node": node, "writes": [key]} for node, key in writes]},
        "artifacts": [{"id": a, "version": 1, "media_type": "text/plain", "produced_by": p, "role": "EVIDENCE"}
                      for a, p in artifacts],
    }


def linear():
    """plan -> build (agent task) -> finish."""
    return contract(LINEAR,
                    [task("plan", obj(request=STR), obj(request=STR, plan=STR)),
                     task("build", obj(plan=STR), obj(plan=STR, head=STR, summary=STR), "AGENT_TASK"),
                     task("finish", obj(head=STR), obj(head=STR, receipt=STR))],
                    chain("plan", "build", "finish"),
                    {"plan": STR, "head": STR, "receipt": STR},
                    [("plan", "plan"), ("build", "head"), ("finish", "receipt")],
                    [("build_summary", "build")])


def gated(verification=True, hitl=True):
    """plan -> build -> [review (verification gate)] -> [approve (HITL gate)] -> publish."""
    nodes = [task("plan", obj(request=STR), obj(request=STR, plan=STR)),
             task("build", obj(plan=STR), obj(head=STR, approved=BOOL), "AGENT_TASK")]
    if verification:
        nodes.append(dict(task("review", obj(head=STR), obj(head=STR), "VERIFICATION_GATE"),
                          gate={"guards": ["build"], "satisfied_by": "INDEPENDENT_REVIEW", "exact_head": True,
                                "session_independent": True, "completion_state": "REVIEW_COMPLETED"}))
    if hitl:
        nodes.append(dict(task("approve", obj(head=STR), obj(head=STR), "HITL_GATE"),
                          gate={"guards": ["build"], "satisfied_by": "HITL", "boundary": "MERGE"}))
    nodes.append(task("publish", obj(head=STR), obj(receipt=STR)))
    return contract(GATED, nodes, chain(*[n["id"] for n in nodes]),
                    {"head": STR, "approved": BOOL, "receipt": STR},
                    [("build", "head"), ("build", "approved"), ("publish", "receipt")],
                    [("approval_note", "build")])


def routed(route_in_state=True):
    """plan (writes route) -> mid (carries the opposite route) -> check (router) -> fast | slow."""
    keys = {"route": ROUTE, "lane": STR} if route_in_state else {"lane": STR}
    writes = [("plan", "route")] if route_in_state else []
    return contract(ROUTED,
                    [task("plan", obj(request=STR), obj(head=STR, route=ROUTE)),
                     task("mid", obj(head=STR), obj(head=STR, route=ROUTE)),
                     task("check", obj(head=STR), obj(head=STR, route=ROUTE), "ROUTER"),
                     task("fast", obj(head=STR), obj(lane=STR)),
                     task("slow", obj(head=STR), obj(lane=STR))],
                    chain("plan", "mid", "check") + [{"kind": "conditional", "from": "check", "route_key": "route",
                                                      "routes": {"FAST": "fast", "SLOW": "slow"}}],
                    keys, writes + [("fast", "lane"), ("slow", "lane")])


def parent():
    """prep -> pub (SUBGRAPH of the child contract)."""
    return contract(PARENT,
                    [task("prep", obj(request=STR), obj(head=STR)),
                     dict(task("pub", obj(head=STR), obj(receipt=STR), "SUBGRAPH"),
                          subgraph={"graph_id": CHILD, "version": "1"})],
                    chain("prep", "pub"), {"head": STR, "receipt": STR}, [("prep", "head"), ("pub", "receipt")])


def child(gate=False):
    """sign -> [approve (HITL gate)]."""
    nodes = [task("sign", obj(head=STR), obj(receipt=STR))]
    if gate:
        nodes.append(dict(task("approve", obj(receipt=STR), obj(receipt=STR), "HITL_GATE"),
                          gate={"guards": ["sign"], "satisfied_by": "HITL", "boundary": "RELIANCE"}))
    return contract(CHILD, nodes, chain(*[n["id"] for n in nodes]), {"receipt": STR}, [("sign", "receipt")])


class Calls(list):
    """The node ids whose handlers ran, in order."""

    def wrap(self, node_id, fn):
        def handler(value, state):
            self.append(node_id)
            return fn(value, state)
        return handler


def registry(calls, graphs, actors=None, retries=None):
    reg = H.Registry()
    for graph_id, fns in graphs.items():
        for node_id, fn in fns.items():
            reg.register(graph_id, node_id, calls.wrap(node_id, fn), actor=(actors or {}).get(node_id, f"{node_id}-actor"),
                         retries=(retries or {}).get(node_id, 0))
    return reg


def linear_fns(**override):
    fns = {
        "plan": lambda v, s: {"request": v["request"], "plan": "plan:" + v["request"]},
        "build": lambda v, s: H.Result({"plan": v["plan"], "head": "h1", "summary": "built"},
                                       artifacts={"build_summary": "summary of h1\n"}),
        "finish": lambda v, s: {"head": v["head"], "receipt": "receipt:" + s["head"]},
    }
    fns.update(override)
    return fns


def gated_fns():
    # build's output, the state it writes and the artifact it produces all claim approval.
    return {
        "plan": lambda v, s: {"request": v["request"], "plan": "p"},
        "build": lambda v, s: H.Result({"head": "h1", "approved": True},
                                       artifacts={"approval_note": "APPROVED by HITL for MERGE"}),
        "publish": lambda v, s: {"receipt": "published:" + v["head"]},
    }


def routed_fns(choice):
    opposite = {"FAST": "SLOW", "SLOW": "FAST"}[choice]
    return {
        "plan": lambda v, s: {"head": "h", "route": choice},
        "mid": lambda v, s: {"head": v["head"], "route": opposite},
        "fast": lambda v, s: {"lane": "fast"},
        "slow": lambda v, s: {"lane": "slow"},
    }


def tree(root):
    root = Path(root)
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


class EngineCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.store = self.tmp / "store"

    def tearDown(self):
        self._tmp.cleanup()

    def events(self, run_id="run-1", store=None):
        path = Path(store or self.store) / run_id / "events.jsonl"
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

    def last_checkpoint(self, run_id="run-1", store=None):
        path = sorted((Path(store or self.store) / run_id / "checkpoints").iterdir())[-1]
        return json.loads(path.read_bytes())

    def start_linear(self, calls=None, store=None, run_id="run-1", **kwargs):
        calls = Calls() if calls is None else calls
        fns = kwargs.pop("fns", None) or linear_fns()
        reg = registry(calls, {LINEAR: fns}, retries=kwargs.pop("retries", None))
        out = E.start(linear(), reg, store or self.store, run_id, NOW, inputs={"request": "r"}, **kwargs)
        return out, reg, calls

    def start_gated(self, store=None, **flags):
        calls = Calls()
        reg = registry(calls, {GATED: gated_fns()}, actors={"build": "builder"})
        out = E.start(gated(**flags), reg, store or self.store, "run-1", NOW, inputs={"request": "r"})
        return out, reg, calls


class SpecVectorTests(EngineCase):
    """The plan's predicted vectors (P1-P9)."""

    def test_vector1_valid_linear_contract_runs_to_completed_with_checked_outputs(self):
        with mock.patch.object(H, "io_problem", wraps=H.io_problem) as check:
            out, _, calls = self.start_linear()
        self.assertEqual(out.status, E.COMPLETED, out.detail)
        self.assertEqual(calls, ["plan", "build", "finish"])
        self.assertEqual(out.state, {"plan": "plan:r", "head": "h1", "receipt": "receipt:h1"})
        self.assertEqual(out.output, {"head": "h1", "receipt": "receipt:h1"})
        checked = {c.args[2] for c in check.call_args_list if len(c.args) > 2}
        for node_id in calls:
            self.assertIn(f"output of {node_id}", checked)
        accepted = [e["node"] for e in self.events() if e["type"] == E.NODE_ACCEPTED]
        self.assertEqual(accepted, ["plan", "build", "finish"])
        self.assertEqual(self.events()[-1]["type"], E.RUN_COMPLETED)

    def test_vector2_rejected_contract_never_starts(self):
        doc = linear()
        doc["edges"][0]["to"] = "ghost"
        self.assertEqual(V.validate(doc).rule, "NO_DANGLING_ROUTES")
        calls = Calls()
        out = E.start(doc, registry(calls, {LINEAR: linear_fns()}), self.store, "run-1", NOW, inputs={"request": "r"})
        self.assertEqual(out.status, E.REFUSED)
        self.assertEqual(out.rule, "NO_DANGLING_ROUTES")
        self.assertEqual(calls, [])
        self.assertEqual([p.name for p in self.store.iterdir()], ["run-1"])
        self.assertEqual([p.name for p in (self.store / "run-1").iterdir()], ["refusal.json"])
        record = json.loads((self.store / "run-1" / "refusal.json").read_bytes())
        self.assertEqual((record["status"], record["rule"]), ("REFUSED", "NO_DANGLING_ROUTES"))
        self.assertEqual(E.status("run-1", self.store)["status"], E.REFUSED)
        again = E.resume("run-1", registry(calls, {LINEAR: linear_fns()}), self.store, NOW)
        self.assertEqual((again.status, again.rule), (E.REFUSED, "NO_DANGLING_ROUTES"))
        self.assertEqual(calls, [])

    def test_vector3_only_an_external_approval_passes_a_hitl_gate(self):
        out, reg, calls = self.start_gated(verification=False)
        self.assertEqual((out.status, out.position), (E.AWAITING_HITL, "approve"))
        self.assertEqual(calls, ["plan", "build"])
        # The run holds a node output, a state value and an artifact that each claim approval.
        self.assertIs(out.state["approved"], True)
        self.assertEqual([e["id"] for e in self.last_checkpoint()["evidence"]], ["approval_note"])
        before = tree(self.store)
        out = E.resume("run-1", reg, self.store, NOW)
        self.assertEqual((out.status, out.rule), (E.AWAITING_HITL, "HITL_APPROVAL_REQUIRED"))
        claims = [{"head": "h1", "approved": True}, {"approved": True}, dict(out.state), "APPROVED by HITL for MERGE",
                  {**APPROVAL, "decided_by": "build"}, {**APPROVAL, "decided_by": "builder"},
                  {**APPROVAL, "decided_by": "ENGINE"}, {**APPROVAL, "gate": "build"},
                  {**APPROVAL, "boundary": "ACTIVATION"}, {**APPROVAL, "decision": "REJECTED"},
                  {**APPROVAL, "approved": True}]
        for claim in claims:
            with self.subTest(claim=claim):
                out = E.resume("run-1", reg, self.store, NOW, approval=claim)
                self.assertEqual((out.status, out.rule), (E.AWAITING_HITL, "HITL_APPROVAL_INVALID"))
        out = E.resume("run-1", reg, self.store, NOW, verification={"gate": "approve", "actor": "someone",
                                                                    "completion_state": "REVIEW_COMPLETED"})
        self.assertEqual((out.status, out.rule), (E.AWAITING_HITL, "GATE_RECORD_UNEXPECTED"))
        self.assertEqual(tree(self.store), before)
        self.assertNotIn("publish", calls)
        out = E.resume("run-1", reg, self.store, NOW, approval=dict(APPROVAL))
        self.assertEqual(out.status, E.COMPLETED, out.detail)
        self.assertEqual(calls[-1], "publish")
        passed = [e for e in self.events() if e["type"] == E.GATE_PASSED]
        self.assertEqual([(e["node"], e["record"]) for e in passed], [("approve", APPROVAL)])

    def test_vector4_interrupted_run_resumes_at_next_node_byte_identical(self):
        reference = self.tmp / "reference"
        self.assertEqual(self.start_linear(store=reference)[0].status, E.COMPLETED)
        nodes = ["plan", "build", "finish"]
        write = CK.write
        for k in (1, 2):
            with self.subTest(k=k):
                store = self.tmp / f"interrupted-{k}"

                def interrupting(run_dir, body, k=k):
                    doc = write(run_dir, body)
                    if doc["seq"] == k + 1:  # checkpoint 1 is the start; checkpoint k + 1 follows node k
                        raise Interrupt()
                    return doc

                calls = Calls()
                with mock.patch.object(CK, "write", interrupting), self.assertRaises(Interrupt):
                    self.start_linear(calls, store=store)
                self.assertEqual(calls, nodes[:k])
                self.assertEqual(E.status("run-1", store)["position"], nodes[k])
                calls.clear()
                out = E.resume("run-1", registry(calls, {LINEAR: linear_fns()}), store, NOW)
                self.assertEqual(out.status, E.COMPLETED, out.detail)
                self.assertEqual(calls, nodes[k:])
                self.assertEqual(tree(store), tree(reference))

    def test_vector5_tampered_checkpoint_or_event_log_refuses_resume(self):
        def replace(path, old, new):
            data = path.read_bytes()
            self.assertIn(old, data)
            path.write_bytes(data.replace(old, new))

        def reseal(run):
            path = sorted((run / "checkpoints").iterdir())[-1]
            doc = json.loads(path.read_bytes())
            body = {k: doc[k] for k in CK.BODY_FIELDS}
            body.update(status="RUNNING", position="publish")
            path.write_bytes(ST.canonical(CK.seal(body)) + b"\n")

        def drop_event(run, number):
            path = run / "events.jsonl"
            lines = path.read_bytes().split(b"\n")
            del lines[number - 1]
            path.write_bytes(b"\n".join(lines))

        tampers = {
            "checkpoint value edited": lambda run: replace(run / "checkpoints" / "000004.json", b'"h1"', b'"h2"'),
            "checkpoint resealed past the gate": reseal,
            "checkpoint removed": lambda run: (run / "checkpoints" / "000002.json").unlink(),
            "event edited": lambda run: replace(run / "events.jsonl", b'"node":"plan"', b'"node":"build"'),
            "event removed": lambda run: drop_event(run, 2),
            "contracts edited": lambda run: replace(run / "contracts.json", b'"MERGE"', b'"RELIANCE"'),
        }
        for name, tamper in tampers.items():
            with self.subTest(tamper=name):
                store = self.tmp / name.replace(" ", "-")
                out, reg, calls = self.start_gated(store=store, verification=False)
                self.assertEqual(out.status, E.AWAITING_HITL)
                tamper(store / "run-1")
                before = tree(store)
                out = E.resume("run-1", reg, store, NOW, approval=dict(APPROVAL))
                self.assertEqual((out.status, out.rule), (E.REFUSED, E.CHECKPOINT_INTEGRITY))
                self.assertEqual(calls, ["plan", "build"])
                self.assertEqual(tree(store), before)
                self.assertEqual(E.status("run-1", store)["integrity"], "FAILED")

    def test_vector6_router_follows_declared_state_and_undeclared_writes_are_refused(self):
        for choice, lane in (("FAST", "fast"), ("SLOW", "slow")):
            with self.subTest(choice=choice):
                calls = Calls()
                out = E.start(routed(), registry(calls, {ROUTED: routed_fns(choice)}), self.store, f"run-{lane}", NOW,
                              inputs={"request": "r"})
                self.assertEqual(out.status, E.COMPLETED, out.detail)
                # mid carried the opposite label into the router; the router read only the declared state.
                self.assertEqual(calls, ["plan", "mid", lane])
                self.assertEqual(out.state, {"route": choice, "lane": lane})
                routes = [e.get("route") for e in self.events(f"run-{lane}") if e["type"] == E.NODE_ACCEPTED]
                self.assertEqual(routes, [None, None, choice, None])
        for writes in ({"receipt": "forged"}, {"bogus": 1}, {"head": "not-the-output"}):
            with self.subTest(writes=writes):
                calls = Calls()
                build = lambda v, s, w=writes: H.Result({"plan": v["plan"], "head": "h1", "summary": "s"}, writes=w)
                out, _, _ = self.start_linear(calls, run_id=f"run-{len(writes)}-{sorted(writes)[0]}",
                                              fns=linear_fns(build=build))
                self.assertEqual((out.status, out.rule), (E.REFUSED, "STATE_TRANSITION_UNDECLARED"))
                self.assertEqual(out.state, {"plan": "plan:r"})
                self.assertNotIn("finish", calls)
        build = lambda v, s: H.Result({"plan": v["plan"], "head": "h1", "summary": "s"}, writes={"head": "h1"})
        out, _, _ = self.start_linear(run_id="run-declared", fns=linear_fns(build=build))
        self.assertEqual(out.status, E.COMPLETED, out.detail)

    def test_vector7_failing_handler_is_retried_exactly_its_bound_then_fails(self):
        def broken(v, s):
            raise RuntimeError("tool unavailable")

        for bound in (0, 2):
            with self.subTest(bound=bound):
                run_id = f"run-{bound}"
                out, reg, calls = self.start_linear(run_id=run_id, fns=linear_fns(build=broken),
                                                    retries={"build": bound})
                self.assertEqual(out.status, E.FAILED)
                self.assertEqual(calls, ["plan"] + ["build"] * (bound + 1))
                recovery = E.status(run_id, self.store)["recovery"]
                self.assertEqual((recovery["node"], recovery["reason"], recovery["bound"], recovery["attempts"]),
                                 ("build", CK.RETRY_BOUND, bound, bound + 1))
                self.assertEqual(recovery["errors"], ["RuntimeError"] * (bound + 1))
                failed = [e for e in self.events(run_id) if e["type"] == E.NODE_ATTEMPT_FAILED]
                self.assertEqual([e["attempt"] for e in failed], list(range(1, bound + 2)))
                again = E.resume(run_id, reg, self.store, NOW)
                self.assertEqual((again.status, again.rule), (E.FAILED, "RUN_TERMINAL"))
                self.assertEqual(calls.count("build"), bound + 1)
        attempts = []

        def flaky(v, s):
            attempts.append(1)
            if len(attempts) == 1:
                raise RuntimeError("transient")
            return linear_fns()["build"](v, s)

        out, _, _ = self.start_linear(run_id="run-flaky", fns=linear_fns(build=flaky), retries={"build": 1})
        self.assertEqual(out.status, E.COMPLETED, out.detail)
        self.assertEqual(len(attempts), 2)

    def test_vector8_verification_by_the_producing_actor_is_refused(self):
        out, reg, calls = self.start_gated(hitl=False)
        self.assertEqual((out.status, out.position), (E.AWAITING_VERIFICATION, "review"))
        record = {"gate": "review", "actor": "builder", "completion_state": "REVIEW_COMPLETED"}
        before = tree(self.store)
        out = E.resume("run-1", reg, self.store, NOW, verification=record)
        self.assertEqual((out.status, out.rule), (E.AWAITING_VERIFICATION, "SELF_CHECK_NEVER_EQUALS_INDEPENDENT_REVIEW"))
        for bad in ({**record, "actor": "reviewer", "completion_state": "REVIEW_REQUESTED"},
                    {**record, "actor": "reviewer", "gate": "build"}, {**record, "actor": ""},
                    {"gate": "review", "actor": "reviewer"}):
            with self.subTest(record=bad):
                out = E.resume("run-1", reg, self.store, NOW, verification=bad)
                self.assertEqual((out.status, out.rule), (E.AWAITING_VERIFICATION, "VERIFICATION_INVALID"))
        out = E.resume("run-1", reg, self.store, NOW)
        self.assertEqual(out.rule, "VERIFICATION_REQUIRED")
        out = E.resume("run-1", reg, self.store, NOW, approval=dict(APPROVAL, gate="review"))
        self.assertEqual(out.rule, "GATE_RECORD_UNEXPECTED")
        self.assertEqual(tree(self.store), before)
        self.assertNotIn("publish", calls)
        out = E.resume("run-1", reg, self.store, NOW, verification={**record, "actor": "reviewer"})
        self.assertEqual(out.status, E.COMPLETED, out.detail)
        self.assertEqual(calls[-1], "publish")

    def test_vector9_subgraph_runs_in_its_own_state_scope(self):
        seen = []

        def sign(v, s):
            seen.append(s)
            return {"receipt": "signed:" + v["head"]}

        calls = Calls()
        reg = registry(calls, {PARENT: {"prep": lambda v, s: {"head": "h-" + v["request"]}}, CHILD: {"sign": sign}})
        out = E.start(parent(), reg, self.store, "run-1", NOW, contracts=[child()], inputs={"request": "r"})
        self.assertEqual(out.status, E.COMPLETED, out.detail)
        self.assertEqual(out.state, {"head": "h-r", "receipt": "signed:h-r"})
        self.assertEqual(seen, [{}])  # the child sees its own scope, never the parent's state
        children = self.store / "run-1" / "children"
        self.assertEqual([p.name for p in children.iterdir()], ["000002-pub"])
        sub = E.status("000002-pub", children)
        self.assertEqual((sub["status"], sub["state"]), (E.COMPLETED, {"receipt": "signed:h-r"}))
        accepted = [e for e in self.events() if e["type"] == E.NODE_ACCEPTED]
        self.assertEqual(accepted[-1]["child"], "000002-pub")

        hijack = lambda v, s: H.Result({"receipt": "x"}, writes={"head": "hijacked"})
        calls = Calls()
        reg = registry(calls, {PARENT: {"prep": lambda v, s: {"head": "h-" + v["request"]}}, CHILD: {"sign": hijack}})
        out = E.start(parent(), reg, self.store, "run-2", NOW, contracts=[child()], inputs={"request": "r"})
        self.assertEqual((out.status, out.rule), (E.REFUSED, "STATE_TRANSITION_UNDECLARED"))
        self.assertEqual(out.state, {"head": "h-r"})


class GateHardeningTests(EngineCase):
    def test_hitl_gate_inside_a_subgraph_suspends_the_parent(self):
        calls = Calls()
        reg = registry(calls, {PARENT: {"prep": lambda v, s: {"head": "h"}},
                               CHILD: {"sign": lambda v, s: {"receipt": "signed"}}})
        out = E.start(parent(), reg, self.store, "run-1", NOW, contracts=[child(gate=True)], inputs={"request": "r"})
        self.assertEqual((out.status, out.position), (E.AWAITING_HITL, "pub"))
        self.assertEqual(E.status("run-1", self.store)["child"], "000002-pub")
        self.assertEqual(E.resume("run-1", reg, self.store, NOW).rule, "HITL_APPROVAL_REQUIRED")
        wrong = {**APPROVAL, "boundary": "RELIANCE", "gate": "pub"}
        self.assertEqual(E.resume("run-1", reg, self.store, NOW, approval=wrong).rule, "HITL_APPROVAL_INVALID")
        out = E.resume("run-1", reg, self.store, NOW, approval={**APPROVAL, "boundary": "RELIANCE"})
        self.assertEqual(out.status, E.COMPLETED, out.detail)
        self.assertEqual(out.state, {"head": "h", "receipt": "signed"})

    def test_both_gates_in_sequence(self):
        out, reg, calls = self.start_gated()
        self.assertEqual(out.status, E.AWAITING_VERIFICATION)
        out = E.resume("run-1", reg, self.store, NOW,
                       verification={"gate": "review", "actor": "reviewer", "completion_state": "REVIEW_COMPLETED"})
        self.assertEqual((out.status, out.position), (E.AWAITING_HITL, "approve"))
        out = E.resume("run-1", reg, self.store, NOW, approval=dict(APPROVAL))
        self.assertEqual(out.status, E.COMPLETED, out.detail)

    def test_gate_records_are_not_preapprovals(self):
        out, reg, _ = self.start_linear()
        out = E.resume("run-1", reg, self.store, NOW, approval=dict(APPROVAL))
        self.assertEqual((out.status, out.rule), (E.COMPLETED, "RUN_TERMINAL"))


class RecoveryHardeningTests(EngineCase):
    def test_interrupt_inside_a_handler_reruns_that_node(self):
        reference = self.tmp / "reference"
        self.start_linear(store=reference)
        hits = []

        def build(v, s):
            hits.append(1)
            if len(hits) == 1:
                raise Interrupt()
            return linear_fns()["build"](v, s)

        with self.assertRaises(Interrupt):
            self.start_linear(fns=linear_fns(build=build))
        calls = Calls()
        out = E.resume("run-1", registry(calls, {LINEAR: linear_fns(build=build)}), self.store, NOW)
        self.assertEqual(out.status, E.COMPLETED, out.detail)
        self.assertEqual(calls, ["build", "finish"])
        self.assertEqual(tree(self.store), tree(reference))

    def test_uncommitted_event_tail_is_dropped_on_resume(self):
        reference = self.tmp / "reference"
        self.start_linear(store=reference)
        write = CK.write

        def crash_before(run_dir, body):
            if body["seq"] == 3:
                raise Interrupt()
            return write(run_dir, body)

        with mock.patch.object(CK, "write", crash_before), self.assertRaises(Interrupt):
            self.start_linear()
        self.assertEqual(self.events()[-1]["node"], "build")  # logged, never checkpointed
        calls = Calls()
        out = E.resume("run-1", registry(calls, {LINEAR: linear_fns()}), self.store, NOW)
        self.assertEqual(out.status, E.COMPLETED, out.detail)
        self.assertEqual(calls, ["build", "finish"])
        self.assertEqual(tree(self.store), tree(reference))

    def test_step_bound_ends_the_run_failed(self):
        out, _, calls = self.start_linear(max_steps=2)
        self.assertEqual(out.status, E.FAILED)
        self.assertEqual(calls, ["plan", "build"])
        self.assertEqual(E.status("run-1", self.store)["recovery"]["reason"], CK.STEP_BOUND)

    def test_same_inputs_give_byte_identical_runs(self):
        for store in ("a", "b"):
            out, reg, _ = self.start_gated(store=self.tmp / store)
            E.resume("run-1", reg, self.tmp / store, NOW,
                     verification={"gate": "review", "actor": "reviewer", "completion_state": "REVIEW_COMPLETED"})
            self.assertEqual(E.resume("run-1", reg, self.tmp / store, NOW, approval=dict(APPROVAL)).status, E.COMPLETED)
        self.assertEqual(tree(self.tmp / "a"), tree(self.tmp / "b"))


class StateHardeningTests(EngineCase):
    def test_refusals_before_start_write_only_the_refusal_record(self):
        cases = {
            "HANDLER_MISSING": dict(graphs={LINEAR: {k: v for k, v in linear_fns().items() if k != "finish"}}),
            "HANDLER_UNEXPECTED": dict(graphs={LINEAR: dict(linear_fns(), ghost=lambda v, s: v)}),
            "TYPED_INPUT": dict(inputs={"request": 1}),
            "SUBGRAPH_UNRESOLVED": dict(doc=parent(), graphs={PARENT: {"prep": lambda v, s: v},
                                                              CHILD: {"sign": lambda v, s: v}}),
            "ROUTE_STATE_UNDECLARED": dict(doc=routed(route_in_state=False), graphs={ROUTED: routed_fns("FAST")}),
        }
        for rule, case in cases.items():
            with self.subTest(rule=rule):
                calls = Calls()
                reg = registry(calls, case.get("graphs", {LINEAR: linear_fns()}))
                out = E.start(case.get("doc", linear()), reg, self.store, rule.lower(), NOW,
                              inputs=case.get("inputs", {"request": "r"}))
                self.assertEqual((out.status, out.rule), (E.REFUSED, rule), out.detail)
                self.assertEqual([p.name for p in (self.store / rule.lower()).iterdir()], ["refusal.json"])
                self.assertEqual(calls, [])

    def test_existing_run_is_never_overwritten(self):
        self.start_linear()
        before = tree(self.store)
        out, _, calls = self.start_linear()
        self.assertEqual((out.status, out.rule), (E.REFUSED, "RUN_EXISTS"))
        self.assertEqual(calls, [])
        self.assertEqual(tree(self.store), before)

    def test_output_outside_its_schema_is_refused(self):
        for name, build in (("missing", lambda v, s: {"plan": v["plan"]}),
                            ("mistyped", lambda v, s: {"plan": v["plan"], "head": 1, "summary": "s"}),
                            ("not-json", lambda v, s: {"plan": v["plan"], "head": "h", "summary": {"s"}})):
            with self.subTest(output=name):
                out, _, calls = self.start_linear(run_id=name, fns=linear_fns(build=build))
                self.assertEqual((out.status, out.rule), (E.REFUSED, "TYPED_OUTPUT"))
                self.assertNotIn("finish", calls)
                self.assertEqual(out.state, {"plan": "plan:r"})

    def test_artifacts_are_evidence_never_state(self):
        out, _, _ = self.start_linear()
        evidence = self.last_checkpoint()["evidence"]
        content = b"summary of h1\n"
        self.assertEqual(evidence, [{"id": "build_summary", "version": 1, "media_type": "text/plain", "node": "build",
                                     "step": 2, "digest": ST.sha256_hex(content), "size": len(content)}])
        self.assertEqual((self.store / "run-1" / "artifacts" / ST.sha256_hex(content)).read_bytes(), content)
        self.assertNotIn("build_summary", out.state)
        for name, fns in (("undeclared", linear_fns(build=lambda v, s: H.Result(
                              {"plan": "p", "head": "h", "summary": "s"}, artifacts={"ghost": "x"}))),
                          ("wrong-producer", linear_fns(plan=lambda v, s: H.Result(
                              {"request": "r", "plan": "p"}, artifacts={"build_summary": "x"})))):
            with self.subTest(case=name):
                out, _, _ = self.start_linear(run_id=name, fns=fns)
                self.assertEqual((out.status, out.rule), (E.REFUSED, "ARTIFACT_UNDECLARED"))

    def test_handlers_cannot_change_state_by_mutation(self):
        def finish(v, s):
            s["head"] = "mutated"
            v["head"] = "mutated"
            return {"head": "h1", "receipt": "r"}

        out, _, _ = self.start_linear(fns=linear_fns(finish=finish))
        self.assertEqual(out.status, E.COMPLETED, out.detail)
        self.assertEqual(out.state["head"], "h1")

    def test_event_chain_links_every_event(self):
        self.start_linear()
        lines = (self.store / "run-1" / "events.jsonl").read_bytes().split(b"\n")[:-1]
        prev = ST.ZERO
        for number, line in enumerate(lines, start=1):
            event = json.loads(line)
            self.assertEqual((event["seq"], event["prev"], event["at"]), (number, prev, NOW))
            prev = ST.sha256_hex(line)
        self.assertEqual(E.status("run-1", self.store)["chain_head"], prev)

    def test_accepted_events_record_the_node_kind(self):
        out, _, _ = self.start_linear()
        self.assertEqual(out.status, E.COMPLETED, out.detail)
        kinds = [(e["node"], e["kind"]) for e in self.events() if e["type"] == E.NODE_ACCEPTED]
        self.assertEqual(kinds, [("plan", "DETERMINISTIC_TASK"), ("build", "AGENT_TASK"),
                                 ("finish", "DETERMINISTIC_TASK")])

    def test_event_payload_cannot_set_the_chain_fields(self):
        log = ST.EventLog.create(self.tmp / "events.jsonl")
        event = log.append(NOW, "PROBE", kind="any", node="n")
        self.assertEqual((event["type"], event["kind"]), ("PROBE", "any"))
        for name in ST.EVENT_FIELDS:
            with self.subTest(field=name), self.assertRaises(ValueError):
                log.append(NOW, "PROBE", **{name: "forged"})
        self.assertEqual(ST.EventLog.load(self.tmp / "events.jsonl").count, 1)

    def test_registry_rejects_bad_registrations(self):
        fn = lambda v, s: v
        for kwargs in (dict(actor=""), dict(actor="a", retries=-1), dict(actor="a", retries=True),
                       dict(actor="a", retries=H.MAX_RETRIES + 1)):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(H.RegistrationError):
                    H.Registry().register(LINEAR, "plan", fn, **kwargs)
        with self.assertRaises(H.RegistrationError):
            H.Registry().register(LINEAR, "plan", fn, actor="a").register(LINEAR, "plan", fn, actor="a")
        with self.assertRaises(H.RegistrationError):
            H.Registry().register("../x", "plan", fn, actor="a")
        with self.assertRaises(ValueError):
            self.start_linear(run_id="../escape")

    def test_io_check(self):
        schema = {"type": "object", "properties": {"n": {"type": "integer"}, "tags": {"type": "array", "items": STR},
                                                  "mode": {"type": "string", "enum": ["A"]}},
                  "required": ["n"], "additionalProperties": False}
        self.assertIsNone(H.io_problem({"n": 1, "tags": ["x"], "mode": "A"}, schema))
        for value in ({"n": True}, {"n": 1.0}, {}, {"n": 1, "extra": 1}, {"n": 1, "tags": [1]}, {"n": 1, "mode": "B"},
                      [], None):
            with self.subTest(value=value):
                self.assertIsNotNone(H.io_problem(value, schema))


class SurfaceTests(EngineCase):
    def test_status_reports_state_position_chain_head_and_event_count(self):
        out, _, _ = self.start_gated(verification=False)
        doc = E.status("run-1", self.store)
        self.assertEqual((doc["status"], doc["position"], doc["integrity"]), (E.AWAITING_HITL, "approve", "VERIFIED"))
        self.assertEqual(doc["state"], out.state)
        self.assertEqual((doc["chain_head"], doc["event_count"]), (out.chain_head, out.event_count))
        self.assertEqual(doc["event_count"], len(self.events()))
        self.assertIn("non-equivalence", doc["scope"])
        self.assertIn("non-equivalence", out.scope)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = E.main(["status", "--store", str(self.store), "--run-id", "run-1"])
        self.assertEqual(code, 0)
        self.assertEqual(buffer.getvalue(), ST.canonical(doc).decode("utf-8") + "\n")
        self.assertEqual(E.status("ghost", self.store)["rule"], "RUN_UNKNOWN")

    def test_cli_run_and_resume(self):
        modules = self.tmp / "modules"
        modules.mkdir()
        (modules / "ge_engine_cli_handlers.py").write_text(
            "from graph_engine import handlers as H\n"
            "REGISTRY = H.Registry()\n"
            f"REGISTRY.register({GATED!r}, 'plan', lambda v, s: {{'request': v['request'], 'plan': 'p'}}, actor='planner')\n"
            f"REGISTRY.register({GATED!r}, 'build', lambda v, s: {{'head': 'h1', 'approved': False}}, actor='builder')\n"
            f"REGISTRY.register({GATED!r}, 'publish', lambda v, s: {{'receipt': 'r'}}, actor='publisher')\n",
            encoding="utf-8")
        files = {"contract.json": gated(verification=False), "input.json": {"request": "r"}, "approval.json": APPROVAL}
        for name, doc in files.items():
            (self.tmp / name).write_text(json.dumps(doc), encoding="utf-8")
        common = ["--store", str(self.store), "--run-id", "cli-1", "--now", NOW,
                  "--handlers", "ge_engine_cli_handlers:REGISTRY"]
        sys.path.insert(0, str(modules))
        try:
            outputs = []
            for argv in (["run", *common, "--contract", str(self.tmp / "contract.json"),
                          "--input", str(self.tmp / "input.json")],
                         ["resume", *common, "--approval", str(self.tmp / "approval.json")]):
                buffer = io.StringIO()
                with contextlib.redirect_stdout(buffer):
                    self.assertEqual(E.main(argv), 0)
                outputs.append(json.loads(buffer.getvalue()))
        finally:
            sys.path.remove(str(modules))
            sys.modules.pop("ge_engine_cli_handlers", None)
        self.assertEqual([o["status"] for o in outputs], [E.AWAITING_HITL, E.COMPLETED])
        self.assertEqual(outputs[1]["state"]["receipt"], "r")


class PackageTests(unittest.TestCase):
    def test_package_holds_exactly_the_planned_files(self):
        names = sorted(p.name for p in PKG.iterdir() if p.name != "__pycache__")
        self.assertEqual(names, ["IMPLEMENTATION-DECISIONS.md", "checkpoint.py", "engine.py", "handlers.py", "state.py"])

    def test_namespace_package_has_no_init(self):
        self.assertEqual(list(PKG.rglob("__init__.py")), [])

    def test_package_is_standard_library_only(self):
        allowed = {"__future__", "argparse", "dataclasses", "functools", "hashlib", "importlib", "json", "math", "os",
                   "pathlib", "re", "shutil", "sys", "typing", "graph_contracts", "graph_engine"}
        for path in sorted(PKG.glob("*.py")):
            tree_ = ast.parse(path.read_text(encoding="utf-8"))
            for stmt in ast.walk(tree_):
                if isinstance(stmt, ast.Import):
                    names = [a.name for a in stmt.names]
                elif isinstance(stmt, ast.ImportFrom):
                    names = [stmt.module or ""]
                else:
                    continue
                for name in names:
                    with self.subTest(file=path.name, module=name):
                        self.assertIn(name.split(".")[0], allowed)

    def test_no_release_deny_term_matches_a_delivered_file(self):
        manifests = sorted(AGENT_WORKFLOW.glob("*/manifest-gcs.json"))
        if not manifests:
            self.skipTest("no release manifest in this tree; the source repository runs this check")
        self.assertEqual(len(manifests), 1)
        terms = [re.compile(t) for t in json.loads(manifests[0].read_text(encoding="utf-8"))["deny_terms"]]
        self.assertTrue(terms)
        files = [p for p in sorted(PKG.iterdir()) if p.is_file()] + [Path(__file__).resolve()]
        hits = [(path.name, number, term.pattern) for path in files
                for number, line in enumerate(path.read_text(encoding="utf-8").split("\n"), start=1)
                for term in terms if term.search(line)]
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
