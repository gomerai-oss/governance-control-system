"""Ring 4 part 2 (MISSION-DISPATCH-001 §3l item 4): proof checked against GitHub's own record.

fetch takes policy CI's newest verified evidence graph from a push to the default branch, and nothing else; the
artifact link is followed without the token; record gives each checkout landing GitHub's result from that graph, or
from a direct check within its budget, or "not checked"; prepare writes it and never fails on it."""

from __future__ import annotations

import http.server
import io
import json
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_evidence_graph as EG  # noqa: E402

from evidence_graph import graph, history as H  # noqa: E402
from mission_dispatch import provenance as pv  # noqa: E402

REPO = "owner/repo"


def graph_doc(head, landings, findings=()):
    doc = {"schema": graph.SCHEMA, "ref": "HEAD", "head": head,
           "nodes": [{"id": f"commit:{sha}", "kind": "landing"} for sha in landings],
           "edges": [], "findings": list(findings), "counts": {}}
    doc["digest"] = graph.digest(doc)
    return doc


def zipped(doc):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr(pv.GRAPH_FILE, json.dumps(doc))
    return buf.getvalue()


class FakeGitHub:
    repo = REPO

    def __init__(self, runs, artifacts):
        self.runs, self.artifacts, self.calls = runs, artifacts, []

    def get(self, path):
        self.calls.append(path)
        if path.startswith("/actions/workflows/"):
            return {"workflow_runs": self.runs}
        run_id = int(path.split("/")[3])
        return {"artifacts": self.artifacts.get(run_id, [])}


def run(run_id, head, **over):
    doc = {"id": run_id, "head_sha": head, "path": pv.POLICY_PATH, "event": "push", "head_branch": "main",
           "repository": {"full_name": REPO}, "conclusion": "success", "html_url": f"https://x/{run_id}"}
    doc.update(over)
    return doc


class FetchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name) / "out"

    def test_the_newest_good_graph_from_a_push_to_main_is_handed_over(self):
        good = zipped(graph_doc("b" * 40, ["1" * 40]))
        gh = FakeGitHub(
            [run(9, "a" * 40, path=".github/workflows/other.yml"),  # another workflow
             run(8, "a" * 40, head_branch="feature"),  # another branch
             run(7, "a" * 40, event="pull_request"),  # not a push
             run(6, "a" * 40, repository={"full_name": "fork/repo"}),  # another repository
             run(5, "c" * 40),  # its graph is for another head
             run(4, "b" * 40)],
            {5: [{"id": 50, "name": pv.GRAPH_ARTIFACT, "archive_download_url": "u5"}],
             4: [{"id": 40, "name": pv.GRAPH_ARTIFACT, "archive_download_url": "u4"}]})
        downloads = {"u5": good, "u4": good}
        source = pv.fetch(gh, "tok", "main", self.out, download=lambda url, token: downloads[url])
        self.assertEqual((source["run_id"], source["run_head"], source["artifact_id"]), (4, "b" * 40, 40))
        self.assertEqual(pv.handed_graph(self.out)[1]["graph_digest"], source["graph_digest"])
        self.assertEqual([c for c in gh.calls if "artifacts" in c], ["/actions/runs/5/artifacts?name=evidence-graph",
                                                                     "/actions/runs/4/artifacts?name=evidence-graph"])

    def test_a_tampered_or_missing_graph_is_never_handed_over(self):
        tampered = graph_doc("b" * 40, ["1" * 40])
        tampered["findings"] = []
        tampered["nodes"].append({"id": "commit:" + "2" * 40, "kind": "landing"})  # digest no longer holds
        cases = {"tampered": zipped(tampered), "not a zip": b"PK not really", "no graph": zipped({})}
        for name, data in cases.items():
            with self.subTest(name):
                gh = FakeGitHub([run(4, "b" * 40)], {4: [{"id": 1, "name": pv.GRAPH_ARTIFACT,
                                                          "archive_download_url": "u"}]})
                with self.assertRaises(pv.ProvenanceError):
                    pv.fetch(gh, "tok", "main", self.out, download=lambda url, token, d=data: d)
        gh = FakeGitHub([run(4, "b" * 40)], {4: [{"id": 1, "name": pv.GRAPH_ARTIFACT, "expired": True,
                                                  "archive_download_url": "u"}]})
        with self.assertRaisesRegex(pv.ProvenanceError, "no evidence-graph artifact"):
            pv.fetch(gh, "tok", "main", self.out, download=lambda url, token: b"")


class DownloadTests(unittest.TestCase):
    """The API's redirect is followed without the token, so the token never leaves the GitHub API."""

    def test_a_plain_http_redirect_is_refused_and_not_followed(self):
        seen = {}

        class Api(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen["api_auth"] = self.headers.get("Authorization")
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:9/signed")
                self.end_headers()

            def log_message(self, *a):
                pass

        api = http.server.HTTPServer(("127.0.0.1", 0), Api)
        threading.Thread(target=api.serve_forever, daemon=True).start()
        self.addCleanup(api.shutdown)
        with self.assertRaisesRegex(pv.ProvenanceError, "non-https"):
            pv._download(f"http://127.0.0.1:{api.server_address[1]}/zip", "secret-token")
        self.assertEqual(seen["api_auth"], "Bearer secret-token")

    def test_the_signed_url_is_fetched_without_the_token(self):
        captured = {}

        def fake_open(self, req, timeout):
            captured["api"] = dict(req.header_items())
            raise pv.urllib.error.HTTPError(req.full_url, 302, "Found", {"Location": "https://blob.example/x"}, None)

        def fake_urlopen(req, timeout):
            captured["blob"] = (req.full_url, dict(req.header_items()))
            return _Reply()

        with mock.patch.object(pv.urllib.request.OpenerDirector, "open", fake_open), \
                mock.patch.object(pv.urllib.request, "urlopen", fake_urlopen):
            self.assertEqual(pv._download("https://api.github.com/repos/o/r/actions/artifacts/1/zip", "tok"),
                             b"zip bytes")
        self.assertEqual(captured["api"]["Authorization"], "Bearer tok")
        self.assertEqual(captured["blob"][0], "https://blob.example/x")
        self.assertNotIn("Authorization", captured["blob"][1])


class _Reply:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n=-1):
        return b"zip bytes"


class RecordTests(unittest.TestCase):
    """record over a real repository with one mission landing (the evidence-graph fixture)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        (base / "fixture").mkdir()
        self.fx = EG.Fixture(base / "fixture")
        self.mission = self.fx.mission(self.fx.seed())
        self.fx.set_main(self.mission["landing"])
        ids = H.load_identities(str(self.fx.config))
        for patcher in (mock.patch.object(H, "load_identities", lambda path=None: ids),
                        mock.patch.dict("os.environ", {k: self.fx.env[k] for k in ("GIT_CONFIG_GLOBAL",
                                                                                     "GIT_CONFIG_SYSTEM")})):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.root = base / "job"
        self.handed = base / "handed"
        self.landing = self.mission["landing"]

    def hand(self, doc):
        self.handed.mkdir(exist_ok=True)
        (self.handed / pv.HANDED_GRAPH).write_text(json.dumps(doc))
        (self.handed / pv.HANDED_SOURCE).write_text(json.dumps({"run_id": 1, "run_head": doc["head"],
                                                                 "graph_digest": doc["digest"]}))

    def record(self, verify=None, folder=True):
        return pv.record(self.root, self.fx.root, self.fx.root / ".git", "enforce",
                         self.handed if folder else None, verify, log=lambda line: None)

    def test_a_landing_the_graph_passed(self):
        self.hand(graph_doc("f" * 40, [self.landing]))
        doc = self.record()
        self.assertEqual(doc["landings"], {self.landing: "passed"})
        path = self.root / "binding" / pv.RECORD_FILE
        self.assertEqual(oct(path.stat().st_mode & 0o777), "0o444")
        self.assertEqual(pv.read_record(self.root / "binding" / "session.json")["landings"], doc["landings"])

    def test_a_landing_the_graph_found_against(self):
        self.hand(graph_doc("f" * 40, [self.landing], [{"mission": EG.MID, "landing": self.landing, "rule": "G1",
                                                        "detail": "not the merge commit of any merged pull request"}]))
        self.assertTrue(self.record()["landings"][self.landing].startswith("finding: G1 not the merge commit"))

    def test_a_landing_the_graph_lacks_is_checked_directly_within_the_budget(self):
        calls = []

        def verify(proof, repo, ids):
            calls.append(proof.commit.sha)
            proof.find("G3", "a build commit changes a file outside build_scope")

        self.hand(graph_doc("f" * 40, []))
        doc = self.record(verify)
        self.assertEqual((calls, doc["checked_directly"]), ([self.landing], 1))
        self.assertTrue(doc["landings"][self.landing].startswith("finding: G3"))
        with mock.patch.object(pv, "MAX_DIRECT", 0):
            self.assertEqual(self.record(verify)["landings"][self.landing], "not checked")
        self.assertEqual(self.record(None, folder=False)["landings"][self.landing], "not checked")

    def test_a_direct_check_that_cannot_read_github_is_not_a_pass(self):
        def verify(proof, repo, ids):
            raise OSError("no network")

        self.assertEqual(self.record(verify, folder=False)["landings"][self.landing], "not checked (OSError)")

    def test_a_graph_that_does_not_check_is_ignored(self):
        doc = graph_doc("f" * 40, [self.landing])
        self.hand(doc)
        source = json.loads((self.handed / pv.HANDED_SOURCE).read_text())
        source["graph_digest"] = "0" * 64  # the source names another graph
        (self.handed / pv.HANDED_SOURCE).write_text(json.dumps(source))
        self.assertEqual(self.record()["landings"][self.landing], "not checked")


class PrepareTests(unittest.TestCase):
    """prepare writes the record for a bound job, and a record that cannot be written is a warning, never a failure."""

    def setUp(self):
        from tests import test_mission_dispatch as flow
        self.flow = flow
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.remote = flow.Remote(self.root)

    def prepare(self, record):
        from mission_dispatch import dispatch
        from mission_router.state import AWAIT_A2
        job = dispatch.plan(self.flow.survey_for(AWAIT_A2, head=self.remote.head, m=self.flow.manifest()))[0][0]
        notes = []
        with mock.patch.object(dispatch.binding, "bind", return_value=object()), \
                mock.patch.object(dispatch.provenance, "record", side_effect=record) as called:
            dispatch.prepare(job, self.root / "work", self.remote.url, "", {"PATH": "/usr/bin:/bin",
                             "HOME": str(self.root)}, self.root, "main", binding_mode="enforce",
                             supply_mode="enforce", log=notes.append)
        return called, notes

    def test_a_bound_job_gets_its_record(self):
        called, notes = self.prepare(lambda *a, **k: {})
        self.assertEqual(called.call_count, 1)
        self.assertEqual(called.call_args.args[3], "enforce")
        self.assertEqual(notes, [])

    def test_a_record_that_cannot_be_written_is_a_warning(self):
        called, notes = self.prepare(RuntimeError("boom"))
        self.assertEqual(called.call_count, 1)
        self.assertTrue(any("could not be written (RuntimeError: boom)" in n for n in notes), notes)


if __name__ == "__main__":
    unittest.main()
