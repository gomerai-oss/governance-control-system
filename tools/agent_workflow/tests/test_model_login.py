"""Ring 1 amendment (MISSION-DISPATCH-001 §3i item 6, Amendment 017): the model login stays outside the agent.

Covers the mode, the encodings check, the proxy's model endpoint (against a fake TLS model host on loopback), the
login file, the dispatcher's placement and readiness, and collect's refusals. Vectors 81 to 88; router vector 114.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import http.server
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from egress import proxy
from mission_dispatch import blast, login
from mission_dispatch.dispatch import DispatchError, Job, collect, model_login_plan, plan, prepare, run_agent
from mission_router.router import load_config
from mission_router.state import AWAIT_A2

from tests import test_mission_dispatch as flow
from tests.test_mission_dispatch import A2B, MID, fake_runtime

STANDIN = login.STANDIN_PREFIX + "0" * 48
REAL = "sk-ant-api03-" + "R" * 40
OK = {"ok": True, "status": 200, "reason": "accepted"}


class ModeTests(unittest.TestCase):
    def test_the_mode(self):
        self.assertEqual(login.mode({}), "observe")
        self.assertEqual(login.mode({"model_login": "enforce"}), "enforce")
        with self.assertRaisesRegex(login.LoginError, "model_login must be one of"):
            login.mode({"model_login": "on"})  # vector 88

    def test_an_unknown_mode_stops_the_router(self):  # MISSION-ROUTER-001 vector 114
        shipped = Path(__file__).resolve().parents[1] / "mission_router" / "config.json"
        config = json.loads(shipped.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({**config, "model_login": "bogus"}))
            with self.assertRaisesRegex(ValueError, "model_login must be one of"):
                load_config(path)

    def test_this_repository_enforces(self):  # switched on after AST-1.6 to 1.8 (2026-11-06)
        shipped = Path(__file__).resolve().parents[1] / "mission_router" / "config.json"
        config = json.loads(shipped.read_text(encoding="utf-8"))
        self.assertEqual((config.get("model_login"), config.get("blast_radius")), ("enforce", "enforce"))

    def test_the_login_the_runtime_prefers(self):
        self.assertEqual(login.credential({"ANTHROPIC_API_KEY": REAL, "CLAUDE_CODE_OAUTH_TOKEN": "o" * 40}),
                         ("api_key", REAL))
        self.assertEqual(login.credential({"CLAUDE_CODE_OAUTH_TOKEN": "o" * 40}), ("oauth", "o" * 40))
        self.assertIsNone(login.credential({"ANTHROPIC_API_KEY": "short"}))

    def test_a_stand_in_is_fresh(self):
        a, b = login.new_standin(), login.new_standin()
        self.assertNotEqual(a, b)
        self.assertTrue(a.startswith(login.STANDIN_PREFIX) and len(a) >= 40)


class EncodingTests(unittest.TestCase):  # vector 84; AST-1.7
    VALUE = "sk-ant-api03-Zq9x" + "A1b2C3d4E5f6G7h8"

    def found(self, text):
        return login.encodings_found(text, [self.VALUE])

    def test_each_encoding_is_named(self):
        raw = self.VALUE.encode()
        cases = {
            "as written": f"x = '{self.VALUE}'",
            "reversed": f"note: {self.VALUE[::-1]}",
            "hex": f"0x{raw.hex()}",
            "base32": base64.b32encode(raw).decode(),
            "base64url": base64.urlsafe_b64encode(b"\xfb\xff" + raw).decode(),
            "split by separators": "\n".join(self.VALUE),
        }
        for name, text in cases.items():
            with self.subTest(name):
                self.assertIn(name, self.found(text))
        self.assertIn("hex", self.found(raw.hex().upper()), "either case")

    def test_base64_is_found_inside_longer_text_from_any_offset(self):
        for prefix in (b"", b"a", b"ab", b"abc", b"token="):
            with self.subTest(prefix):
                text = "data: " + base64.b64encode(prefix + self.VALUE.encode() + b"!tail").decode()
                self.assertIn("base64", self.found(text))
        wrapped = base64.encodebytes(b"header " + self.VALUE.encode()).decode()  # 76-column lines
        self.assertIn("base64", self.found(wrapped))

    def test_clean_text_is_clean(self):
        self.assertEqual(self.found("def f():\n    return 'sk-ant-api03-' + 'redacted'\n"), [])
        self.assertEqual(self.found(self.VALUE[:10]), [], "a fragment is not the login")
        self.assertEqual(login.encodings_found("anything", ["short"]), [], "values under 16 characters are ignored")


class _ModelHost(http.server.BaseHTTPRequestHandler):
    """A fake TLS model host: records what reaches it, answers 200."""
    protocol_version = "HTTP/1.1"
    seen: list = []

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(n)
        _ModelHost.seen.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()},
                                "body": body})
        out = b'{"input_tokens": 3}'
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(out)))
        self.send_header("connection", "close")
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *args):
        pass


class ModelEndpointTests(unittest.TestCase):
    """The proxy's model route (§3i item 6b, 6c), against a fake model host on loopback."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        d = Path(cls.tmp.name)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(d / "k.pem"),
                        "-out", str(d / "c.pem"), "-days", "1", "-subj", "/CN=api.anthropic.com",
                        "-addext", "subjectAltName=DNS:api.anthropic.com"], check=True, capture_output=True)
        cls.host = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _ModelHost)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(d / "c.pem"), str(d / "k.pem"))
        cls.host.socket = ctx.wrap_socket(cls.host.socket, server_side=True)
        threading.Thread(target=cls.host.serve_forever, daemon=True).start()
        cls.ca = str(d / "c.pem")
        shipped = Path(__file__).resolve().parents[1] / "mission_dispatch" / "egress-policy.json"
        cls.endpoint = proxy.load_model_endpoints(shipped.read_text(encoding="utf-8"))["claude-code"]

    @classmethod
    def tearDownClass(cls):
        cls.host.shutdown()
        cls.tmp.cleanup()

    def setUp(self):
        _ModelHost.seen = []
        # Registered first, so it runs last: after every server this test started has stopped. A handler thread can
        # still be appending its log line, so a late write does not fail the cleanup.
        self.dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.dir.cleanup)
        self.log = Path(self.dir.name) / "egress.jsonl"
        patches = [mock.patch.object(proxy, "PORT", self.host.server_address[1]),  # the fake host's port
                   mock.patch.object(proxy, "address_problem", lambda addresses: None)]  # it is on loopback
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def serve(self, kind="api_key", exclusive=True, mode=proxy.ENFORCE):
        egress = proxy.Egress(["api.anthropic.com"], mode, self.log, resolver=lambda h, p: ["127.0.0.1"],
                              model=self.endpoint, login=proxy.ModelLogin(kind, REAL, STANDIN), exclusive=exclusive,
                              tls=ssl.create_default_context(cafile=self.ca))
        server = proxy.Server(egress)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        return server.port

    def post(self, port, path="/model/v1/messages?beta=true", token=STANDIN, host=None, extra=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
        headers = {"Authorization": f"Bearer {token}", "content-type": "application/json",
                   "anthropic-beta": "claude-code-20250219", "Host": host or f"127.0.0.1:{port}", **(extra or {})}
        conn.request("POST", path, body=b'{"model":"m","messages":[]}', headers=headers)
        reply = conn.getresponse()
        reply.read()
        return reply.status

    def lines(self, want=0):
        """The log's lines; a forwarded request's line is written once the model host closes, just after the
        client has its answer, so wait for ``want`` lines."""
        deadline = time.monotonic() + 5
        while True:
            found = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
            if len(found) >= want or time.monotonic() > deadline:
                return found
            time.sleep(0.02)

    def test_the_login_is_added_and_the_stand_in_never_leaves(self):  # vector 81
        port = self.serve()
        self.assertEqual(self.post(port), 200)
        (seen,) = _ModelHost.seen
        self.assertEqual(seen["path"], "/v1/messages?beta=true")
        self.assertEqual(seen["headers"]["x-api-key"], REAL)
        self.assertEqual(seen["headers"]["host"], "api.anthropic.com")
        self.assertNotIn("authorization", seen["headers"])
        self.assertNotIn(STANDIN, json.dumps(seen["headers"]))
        self.assertEqual(seen["headers"]["anthropic-beta"], "claude-code-20250219")
        (line,) = self.lines(want=1)
        self.assertEqual((line["route"], line["decision"], line["status"], line["path"]),
                         ("model", "allowed", 200, "/v1/messages"))
        text = self.log.read_text()
        self.assertNotIn(REAL, text)
        self.assertNotIn(STANDIN, text)

    def test_an_oauth_login_goes_as_a_bearer_with_its_beta(self):
        port = self.serve(kind="oauth")
        self.assertEqual(self.post(port), 200)
        (seen,) = _ModelHost.seen
        self.assertEqual(seen["headers"]["authorization"], f"Bearer {REAL}")
        self.assertNotIn("x-api-key", seen["headers"])
        self.assertEqual(seen["headers"]["anthropic-beta"], f"claude-code-20250219,{proxy.OAUTH_BETA}")
        self.assertEqual(len(self.lines(want=1)), 1)

    def test_what_the_endpoint_refuses(self):  # vector 82; AST-1.8
        port = self.serve()
        cases = {
            "no stand-in": dict(token=""),
            "another value": dict(token=REAL),
            "a path not on the list": dict(path="/model/v1/files"),
            "a query not on the list": dict(path="/model/v1/messages?debug=1"),
            "another host": dict(host="evil.example.com"),
            "an absolute URL": dict(path="http://evil.example.com/v1/messages"),
            "a traversal": dict(path="/model/v1/messages/../files"),
        }
        for name, kw in cases.items():
            with self.subTest(name):
                self.assertIn(self.post(port, **kw), (403, 405))
        self.assertEqual(_ModelHost.seen, [], "nothing was forwarded")
        self.assertTrue(all(line["decision"] == "refused" for line in self.lines()))
        self.assertIn("/v1/files", [line.get("path") for line in self.lines()], "logged without the /model prefix")
        text = self.log.read_text()
        self.assertNotIn(REAL, text)
        self.assertNotIn(STANDIN, text)

    def test_a_header_cannot_smuggle_a_second_request(self):
        port = self.serve()
        with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
            s.sendall(f"POST /model/v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                      f"Authorization: Bearer {STANDIN}\r\nX-A: b\rInjected: 1\r\nContent-Length: 0\r\n\r\n".encode())
            self.assertIn(b" 400 ", s.recv(200))
        self.assertEqual(_ModelHost.seen, [])

    def test_exclusive_closes_the_tunnel_to_the_model_host(self):  # vector 83
        for exclusive, mode in ((True, proxy.ENFORCE), (True, proxy.OBSERVE)):
            egress = proxy.Egress(["api.anthropic.com"], mode, self.log, resolver=lambda h, p: ["8.8.8.8"],
                                  model=self.endpoint, login=proxy.ModelLogin("api_key", REAL, STANDIN),
                                  exclusive=exclusive)
            _, _, decision = egress.decide("CONNECT", f"api.anthropic.com:{proxy.PORT}")
            self.assertFalse(decision.allowed, f"{mode}: the endpoint is the only way to the model host")
        egress = proxy.Egress(["api.anthropic.com"], proxy.ENFORCE, self.log, resolver=lambda h, p: ["8.8.8.8"],
                              model=self.endpoint, login=proxy.ModelLogin("api_key", REAL, STANDIN), exclusive=False)
        self.assertTrue(egress.decide("CONNECT", f"api.anthropic.com:{proxy.PORT}")[2].allowed,
                        "not exclusive (observe): the tunnel stays")

    def test_the_login_file_is_read_once_and_deleted(self):
        path = Path(self.dir.name) / "login.json"
        path.write_text(json.dumps({"kind": "api_key", "login": REAL, "standin": STANDIN}))
        self.assertEqual(proxy.read_login_file(path), proxy.ModelLogin("api_key", REAL, STANDIN))
        self.assertFalse(path.exists())
        for bad in ({"kind": "password", "login": REAL, "standin": STANDIN},
                    {"kind": "api_key", "login": REAL, "standin": REAL},
                    {"kind": "api_key", "login": "short", "standin": STANDIN}):
            path.write_text(json.dumps(bad))
            with self.assertRaises(proxy.PolicyError):
                proxy.read_login_file(path)
            self.assertFalse(path.exists(), "deleted even when refused")

    def test_the_shipped_endpoint_is_what_the_pinned_runtime_sends(self):
        """Recorded from Claude Code 2.1.305 against a local endpoint (part 1): POST /v1/messages?beta=true only,
        with Authorization: Bearer <ANTHROPIC_AUTH_TOKEN>; the token count is the readiness request."""
        self.assertEqual(self.endpoint.host, "api.anthropic.com")
        self.assertEqual(set(self.endpoint.routes), {("POST", "/v1/messages"), ("POST", "/v1/messages/count_tokens")})
        self.assertEqual(set(self.endpoint.queries), {"", "beta=true"})
        self.assertEqual(self.endpoint.readiness_route, ("POST", "/v1/messages/count_tokens"))

    def test_the_policy_section_is_strict(self):
        good = json.loads((Path(__file__).resolve().parents[1] / "mission_dispatch" / "egress-policy.json").read_text())
        entry = good["model_endpoints"]["claude-code"]
        for bad in ({**entry, "host": "*.anthropic.com"}, {**entry, "routes": ["POST /v1/../x"]},
                    {**entry, "routes": []}, {**entry, "extra": 1},
                    {**entry, "readiness": {"route": "POST /v1/other", "model": "m1"}}):
            with self.assertRaises(proxy.PolicyError):
                proxy.load_policy(json.dumps({**good, "model_endpoints": {"claude-code": bad}}))
        with self.assertRaises(proxy.PolicyError):
            proxy.load_policy(json.dumps({**good, "model_endpoints": {"no-such-runtime": entry}}))

    def test_readiness_through_the_endpoint(self):  # item 6e
        port = self.serve()
        self.assertEqual(login.readiness(port, STANDIN, self.endpoint.readiness_route, "claude-opus-5-5"), OK)
        self.lines(want=1)
        (seen,) = _ModelHost.seen
        self.assertEqual(seen["path"], "/v1/messages/count_tokens")
        self.assertEqual(json.loads(seen["body"])["model"], "claude-opus-5-5")
        refused = login.readiness(port, "standin-wrong" + "0" * 40, self.endpoint.readiness_route, "m")
        self.assertEqual((refused["ok"], refused["status"]), (False, 403))


class FakeModelEgress:
    """Stands in for blast.AgentEgress with a model endpoint: records what it was given."""

    def __init__(self, model_login=None, exclusive=False):
        self.model_login, self.exclusive, self.port, self.stopped, self.calls = model_login, exclusive, 4321, False, []

    def start(self):
        return {name: f"http://127.0.0.1:{self.port}" for name in blast.PROXY_ENV}

    def stop(self):
        self.stopped = True

    def run(self, argv):
        self.calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0 if argv[0] != "pgrep" else 1, "", "")


class PlacementTests(unittest.TestCase):
    """Where the login goes (§3i item 6a, 6e, 6f); vectors 81, 85, 86."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.work = self.root / "work"
        for sub in ("checkout", "git", "empty"):
            (self.work / sub).mkdir(parents=True)
        self.env = {"PATH": os.environ["PATH"], "HOME": "/home/runner", "ANTHROPIC_API_KEY": REAL}
        self.job = Job(MID, "A2", 1, "a2", A2B, "claude-code", "0" * 40, ("tools/demo/**",), "t")

    def tearDown(self):
        self.tmp.cleanup()

    def run_agent(self, body, ready=OK, job=None, **kw):
        made = {}

        def egress_for(runtime, mode, root, account=None, model_login=None, exclusive=False):
            made["egress"] = FakeModelEgress(model_login, exclusive)
            return made["egress"]

        with mock.patch("mission_dispatch.dispatch.Checkout") as checkout, \
                mock.patch("mission_dispatch.login.readiness", return_value=ready) as readiness, \
                mock.patch("mission_dispatch.blast.AgentEgress", side_effect=egress_for):
            checkout.return_value = SimpleNamespace(tree=self.work / "checkout", git_dir=self.work / "git",
                                                    empty=self.work / "empty")
            try:
                log = run_agent(job or self.job, self.work, self.env, self.root, timeout=60,
                                binaries=fake_runtime(self.root, body), log=lambda line: None, **kw)
            finally:
                self.readiness_calls = readiness.call_args_list
        return log, made["egress"]

    SHOW = ('print("KEY", os.environ.get("ANTHROPIC_API_KEY"))\n'
            'print("BASE", os.environ.get("ANTHROPIC_BASE_URL"))\n'
            'print("TOKEN", os.environ.get("ANTHROPIC_AUTH_TOKEN"))')

    def enforce(self, **kw):
        with mock.patch("mission_dispatch.blast.account_env", side_effect=lambda env, *a: dict(env)), \
                mock.patch("mission_dispatch.blast.run_as_argv", return_value=[]), \
                mock.patch("mission_dispatch.blast.hand_over"), \
                mock.patch("mission_dispatch.blast.take_back", return_value=[]), \
                mock.patch("mission_dispatch.blast.limits_argv", return_value=[]):
            return self.run_agent(self.SHOW, login_mode=login.ENFORCE, blast_mode=blast.ENFORCE,
                                  run_as="mission-agent", **kw)

    def test_enforced_the_runtime_holds_only_a_stand_in(self):  # vector 81; AST-1.6
        log, egress = self.enforce()
        text = log.read_text()
        state = login.read_state(self.work)
        self.assertEqual((state["placement"], state["kind"]), ("proxy", "api_key"))
        self.assertIn("KEY None", text, "the login is not in the runtime's environment")
        self.assertIn("BASE http://127.0.0.1:4321/model", text)
        self.assertIn(f"TOKEN {state['standin']}", text.replace("***", state["standin"]),
                      "the runtime is given the stand-in (scrubbed from the uploaded log)")
        self.assertNotIn(state["standin"], text, "the stand-in is scrubbed from the log like a login")
        self.assertEqual(egress.model_login, {"kind": "api_key", "login": REAL, "standin": state["standin"]})
        self.assertTrue(egress.exclusive)
        self.assertEqual(oct((self.work / login.STATE_FILE).stat().st_mode & 0o777), "0o600")

    def test_observed_the_runtime_keeps_its_login_and_readiness_is_recorded(self):
        log, egress = self.run_agent(self.SHOW)
        state = login.read_state(self.work)
        self.assertEqual((state["placement"], state["readiness"]), ("runtime", OK))
        self.assertIn("KEY ***", log.read_text(), "the runtime keeps its login (scrubbed from the log)")
        self.assertIn("BASE None", log.read_text())
        self.assertFalse(egress.exclusive)
        self.assertEqual(len(self.readiness_calls), 1)

    def test_enforced_a_failed_readiness_fails_before_the_agent(self):  # vector 85
        with self.assertRaisesRegex(DispatchError, "not accepted through the endpoint .HTTP 401."):
            self.enforce(ready={"ok": False, "status": 401, "reason": "HTTP 401"})
        self.assertFalse((self.work / "agent.log").exists(), "no agent ran")
        self.assertEqual(login.read_state(self.work)["readiness"]["status"], 401)

    def test_observed_a_failed_readiness_is_recorded_only(self):  # vector 87
        log, _ = self.run_agent("print('RAN')", ready={"ok": False, "status": 401, "reason": "HTTP 401"})
        self.assertIn("RAN", log.read_text())
        self.assertEqual(login.read_state(self.work)["readiness"]["status"], 401)

    def test_enforced_needs_blast_radius_enforced(self):  # vector 86
        with self.assertRaisesRegex(DispatchError, "blast_radius is not"):
            self.run_agent("print('RAN')", login_mode=login.ENFORCE)
        self.assertFalse((self.work / "agent.log").exists())

    def test_a_cursor_job_keeps_its_login(self):  # known limit 19
        cursor = Job(MID, "A3", 1, "a3", A2B, "cursor-cli", "0" * 40, ("tools/demo/**",), "t")
        plan = model_login_plan(cursor, {**self.env, "CURSOR_API_KEY": "c" * 40}, login.ENFORCE, blast.ENFORCE)
        self.assertEqual((plan["state"]["placement"], plan["proxy_login"]), ("runtime", None))

    def test_unknown_mode(self):
        with self.assertRaisesRegex(DispatchError, "unknown model-login mode"):
            model_login_plan(self.job, self.env, "on", blast.ENFORCE)


class CollectTests(unittest.TestCase):
    """collect refuses a login or stand-in in any listed encoding (§3c, §3i item 6d); vectors 84, 87."""

    KEY = "sk-ant-api03-" + "0123456789abcdefABCDEF"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.remote = flow.Remote(self.root)
        self.base = self.remote.head
        patcher = mock.patch("mission_dispatch.login.readiness", return_value=OK)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.env = {"PATH": os.environ["PATH"], "HOME": str(self.root), "ANTHROPIC_API_KEY": self.KEY}

    def job(self):
        return plan(flow.survey_for(AWAIT_A2, head=self.base, m=flow.manifest()))[0][0]

    def agent(self, job, body, name="work"):
        work = self.root / name
        prepare(job, work, self.remote.url, "", self.env, self.root, "main")
        run_agent(job, work, self.env, self.root, timeout=60, binaries=fake_runtime(self.root, body),
                  log=lambda line: None)
        return work

    def test_base64_and_hex_were_already_refused_by_the_secrets_boundary(self):
        """The boundary's known-value forms (as written, base64 at every offset, hex, percent-encoded) refuse in
        both modes, before and after this amendment; the encodings check names them too."""
        bodies = {
            "base64": 'import base64\npathlib.Path("tools/demo/k.py").write_text("K = %r" % base64.b64encode(os.environ["ANTHROPIC_API_KEY"].encode()).decode())',
            "hex": 'pathlib.Path("tools/demo/k.py").write_text(os.environ["ANTHROPIC_API_KEY"].encode().hex())',
        }
        for name, body in bodies.items():
            with self.subTest(name):
                job = self.job()
                work = self.agent(job, body, name=f"bnd-{name}")
                with self.assertRaisesRegex(DispatchError, f"encoded .*{name}"):
                    collect(job, work, self.root / f"out-e-{name}", self.env, login_mode=login.ENFORCE)
                with self.assertRaisesRegex(DispatchError, "secrets boundary refused"):
                    collect(job, work, self.root / f"out-o-{name}", self.env, login_mode=login.OBSERVE,
                            log=lambda line: None)

    def test_an_encoded_login_is_refused_under_enforce_and_recorded_under_observe(self):
        """The forms the boundary does not find: reversed, base32, split by separators, base64 in wrapped lines."""
        bodies = {
            "reversed": 'pathlib.Path("tools/demo/k.py").write_text(os.environ["ANTHROPIC_API_KEY"][::-1])',
            "base32": 'import base64\npathlib.Path("tools/demo/k.py").write_text(base64.b32encode(os.environ["ANTHROPIC_API_KEY"].encode()).decode())',
            "split by separators": 'pathlib.Path("tools/demo/a.py").write_text("x")\npathlib.Path(".mission-dispatch/COMMIT_MSG").write_text("\\n".join(os.environ["ANTHROPIC_API_KEY"]))',
            "base64": 'import base64\npathlib.Path("tools/demo/k.py").write_text("\\n".join(base64.b64encode(os.environ["ANTHROPIC_API_KEY"].encode()).decode()[i:i+8] for i in range(0, 64, 8)))',
        }
        for name, body in bodies.items():
            with self.subTest(name):
                job = self.job()
                work = self.agent(job, body, name=f"enc-{name.replace(' ', '-')}")
                with self.assertRaisesRegex(DispatchError, f"encoded .*{name}"):
                    collect(job, work, self.root / f"out-e-{name}", self.env, login_mode=login.ENFORCE)
                warnings = []
                result = collect(job, work, self.root / f"out-o-{name}", self.env, login_mode=login.OBSERVE,
                                 log=warnings.append)
                self.assertIn(name, result["login"]["encodings_found"])
                self.assertTrue(any("observe: not refused" in w for w in warnings))

    def test_the_stand_in_as_written_is_refused_in_both_modes(self):
        job = self.job()
        work = self.root / "work"
        prepare(job, work, self.remote.url, "", self.env, self.root, "main")
        login.write_state(work, {"mode": "enforce", "placement": "proxy", "kind": "api_key", "standin": STANDIN,
                                 "readiness": OK})
        (work / "checkout" / "tools" / "demo").mkdir(parents=True, exist_ok=True)
        (work / "checkout" / "tools" / "demo" / "s.py").write_text(f"S = '{STANDIN}'\n")
        for mode in login.MODES:
            with self.subTest(mode), self.assertRaisesRegex(DispatchError, "model login"):
                collect(job, work, self.root / f"out-s-{mode}", self.env, login_mode=mode)

    def test_the_run_record_says_where_the_login_was(self):  # item 6f
        job = self.job()
        work = self.agent(job, 'pathlib.Path("tools/demo/a.py").write_text("x")')
        result = collect(job, work, self.root / "out", self.env, login_mode=login.OBSERVE)
        self.assertEqual(result["login"]["placement"], "runtime")
        self.assertEqual(result["login"]["encodings_found"], [])
        self.assertNotIn("standin", result["login"])
        self.assertNotIn(login.read_state(work)["standin"], (self.root / "out" / "result.json").read_text())


class LoginFileTests(unittest.TestCase):
    """AgentEgress hands the login to the real proxy in a file, which the proxy deletes (§3i item 6a)."""

    def test_the_proxy_gets_the_login_by_file_and_deletes_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seen = {}
            real_popen = subprocess.Popen

            def popen(argv, **kw):
                path = Path(argv[argv.index("--login-file") + 1])
                seen["mode"] = oct(path.stat().st_mode & 0o777)
                seen["parent"] = oct(path.parent.stat().st_mode & 0o777)
                seen["argv"] = " ".join(argv)
                seen["env"] = json.dumps(kw.get("env", {}))
                seen["path"] = path
                return real_popen(argv, **kw)

            egress = blast.AgentEgress("claude-code", blast.OBSERVE, root, popen=popen,
                                       model_login={"kind": "api_key", "login": REAL, "standin": STANDIN},
                                       exclusive=True)
            try:
                egress.start()
                self.assertTrue(egress.port)
            finally:
                egress.stop()
            self.assertEqual((seen["mode"], seen["parent"]), ("0o600", "0o700"))
            self.assertNotIn(REAL, seen["argv"] + seen["env"], "never on a command line or in the environment")
            self.assertIn("--exclusive", seen["argv"])
            self.assertFalse(seen["path"].exists() or seen["path"].parent.exists(), "file and folder are gone")


if __name__ == "__main__":
    unittest.main()
