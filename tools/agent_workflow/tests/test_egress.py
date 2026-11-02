"""Attack tests for the egress proxy (ring 5, MISSION-DISPATCH-001 §3h item 3)."""

from __future__ import annotations

import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from egress import proxy
from egress.proxy import ENFORCE, OBSERVE, Egress, PolicyError, Server, load_policy

HOSTS = ("api.example.com", "*.models.example.net")
PUBLIC = "93.184.215.14"


def fixed(*addresses):
    return lambda host, port: list(addresses)


class DecisionTests(unittest.TestCase):
    """Attack: an agent asks the proxy for somewhere it should not go."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = Path(self.tmp.name) / "egress.jsonl"

    def tearDown(self):
        self.tmp.cleanup()

    def decide(self, target, method="CONNECT", mode=ENFORCE, resolver=fixed(PUBLIC)):
        return Egress(HOSTS, mode, self.log, resolver).decide(method, target)[2]

    def test_a_listed_host_on_443_is_admitted(self):
        for target in ("api.example.com:443", "API.Example.com:443", "eu.models.example.net:443",
                       "a.b.models.example.net:443"):
            self.assertTrue(self.decide(target).allowed, target)

    def test_unlisted_hosts_and_lookalikes_are_refused(self):
        for target in ("evil.com:443", "api.example.com.evil.com:443", "xapi.example.com:443",
                       "models.example.net:443", "evilmodels.example.net:443"):
            decision = self.decide(target)
            self.assertFalse(decision.allowed, target)
            self.assertEqual(decision.reason, "not listed for this runtime")

    def test_ip_literals_in_any_spelling_are_refused(self):
        for target in ("93.184.215.14:443", "[2606:2800:220:1::]:443", "2130706433:443", "0x7f000001:443",
                       "127.1:443", "localhost:443", "api.example.com.:443", "-x.example.com:443"):
            self.assertFalse(self.decide(target).allowed, target)

    def test_other_ports_and_methods_are_refused(self):
        self.assertIn("is not 443", self.decide("api.example.com:22").reason)
        self.assertIn("is not 443", self.decide("api.example.com").reason)
        self.assertIn("is not 443", self.decide("api.example.com:0443x").reason)
        self.assertEqual(self.decide("http://api.example.com/", method="GET").reason, "GET is not CONNECT")

    def test_a_listed_name_that_resolves_to_a_private_address_is_refused(self):
        """Attack: DNS for a listed name points at the runner's own services or the cloud metadata address."""
        for address in ("10.0.0.5", "127.0.0.1", "169.254.169.254", "100.64.0.1", "::1", "fd00::1",
                        "::ffff:127.0.0.1", "0.0.0.0"):
            decision = self.decide("api.example.com:443", resolver=fixed(PUBLIC, address))
            self.assertFalse(decision.allowed, address)
            self.assertIn("non-global", decision.reason)
        self.assertEqual(self.decide("api.example.com:443", resolver=fixed()).reason, "it does not resolve")

    def test_observing_admits_everything_and_says_what_it_would_refuse(self):
        decision = self.decide("evil.com:443", mode=OBSERVE)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, "observe: would refuse (not listed for this runtime)")
        self.assertFalse(decision.listed)
        self.assertTrue(self.decide("api.example.com:22", mode=OBSERVE).allowed)
        self.assertFalse(self.decide("x", method="GET", mode=OBSERVE).allowed, "only CONNECT is a tunnel")

    def test_the_policy_file_is_strict(self):
        good = {"schema": "egress-policy-v1", "runtimes": {"claude-code": ["api.example.com"], "cursor-cli": []}}
        self.assertEqual(load_policy(json.dumps(good))["claude-code"], ("api.example.com",))
        for bad in ({**good, "extra": 1}, {**good, "schema": "v0"}, {**good, "runtimes": {}},
                    {**good, "runtimes": {"claude-code": ["10.0.0.1"]}},
                    {**good, "runtimes": {"claude-code": ["*"]}},
                    {**good, "runtimes": {"claude-code": ["API.example.com"]}},
                    {**good, "runtimes": {"claude-code": "api.example.com"}}):
            with self.assertRaises(PolicyError):
                load_policy(json.dumps(bad))
        with self.assertRaises(PolicyError):
            load_policy("{")

    def test_the_shipped_policy_is_the_switch_on_list(self):
        """The hosts AST-5.4 saw each runtime need, and nothing else (HITL, ring 5 part 4)."""
        shipped = Path(__file__).resolve().parents[1] / "mission_dispatch" / "egress-policy.json"
        policy = load_policy(shipped.read_text(encoding="utf-8"))
        self.assertEqual(policy, {"claude-code": ("api.anthropic.com",), "cursor-cli": ("*.cursor.sh",)})
        for host in ("api2.cursor.sh", "agentn.global.api5.cursor.sh", "repo42.cursor.sh"):
            self.assertTrue(proxy.listed(host, policy["cursor-cli"]), host)
        for host in ("downloads.cursor.com", "cursor.sh", "cursor.sh.evil.com", "evilcursor.sh"):
            self.assertFalse(proxy.listed(host, policy["cursor-cli"]), f"{host}: the CLI must not fetch another build of itself")
        self.assertFalse(proxy.listed("http-intake.logs.us5.datadoghq.com", policy["claude-code"]), "no telemetry")


class Upstream:
    """A local TCP server standing in for a listed host: echoes what it gets, with a prefix."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                data = conn.recv(65536)
                if data:
                    conn.sendall(b"ECHO " + data)

    def close(self):
        self.sock.close()


class ProxyTests(unittest.TestCase):
    """The proxy over real sockets on loopback."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = Path(self.tmp.name) / "egress.jsonl"
        self.upstream = Upstream()

    def tearDown(self):
        self.upstream.close()
        self.tmp.cleanup()

    def start(self, mode, max_total=proxy.MAX_TOTAL_BYTES):
        server = Server(Egress(HOSTS, mode, self.log, fixed("127.0.0.1"), max_total))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def ask(self, server, request, then=b""):
        with socket.create_connection(("127.0.0.1", server.port), timeout=10) as sock:
            sock.sendall(request)
            reply = sock.recv(4096)
            if then and reply.startswith(b"HTTP/1.1 200"):
                sock.sendall(then)
                reply += sock.recv(4096)
            return reply

    def lines(self, at_least=1):
        """The log, once it has ``at_least`` lines: a tunnel is logged when it closes, just after the reply."""
        deadline = time.monotonic() + 10
        while True:
            text = self.log.read_text() if self.log.exists() else ""
            if len(text.splitlines()) >= at_least or time.monotonic() > deadline:
                return [json.loads(line) for line in text.splitlines()]
            time.sleep(0.02)

    def tunnel(self, server, host="api.example.com"):
        with mock.patch.object(proxy, "PORT", self.upstream.port):
            return self.ask(server, f"CONNECT {host}:{self.upstream.port} HTTP/1.1\r\nHost: x\r\n\r\n".encode(),
                            then=b"hello")

    def test_enforcing_refuses_unlisted_hosts_and_plain_requests_and_logs_them(self):
        server = self.start(ENFORCE)
        self.assertTrue(self.ask(server, b"CONNECT evil.com:443 HTTP/1.1\r\n\r\n").startswith(b"HTTP/1.1 403"))
        self.assertTrue(self.ask(server, b"GET http://evil.com/ HTTP/1.1\r\n\r\n").startswith(b"HTTP/1.1 405"))
        self.assertTrue(self.ask(server, b"garbage\r\n\r\n").startswith(b"HTTP/1.1 400"))
        self.assertEqual([(l["host"], l["decision"]) for l in self.lines()],
                         [("evil.com", "refused"), ("http://evil.com/", "refused"), ("", "refused")])

    def test_enforcing_refuses_a_listed_name_on_a_private_address(self):
        """The upstream is on loopback, so even the listed name is refused: the check is on the address."""
        reply = self.tunnel(self.start(ENFORCE))
        self.assertTrue(reply.startswith(b"HTTP/1.1 403"), reply)
        self.assertIn("non-global", self.lines()[0]["reason"])

    def test_a_tunnel_relays_both_ways_and_counts_the_bytes(self):
        with mock.patch.object(proxy, "address_problem", lambda addresses: None):
            reply = self.tunnel(self.start(ENFORCE))
        self.assertTrue(reply.startswith(b"HTTP/1.1 200 Connection established\r\n\r\n"), reply)
        self.assertTrue(reply.endswith(b"ECHO hello"))
        (line,) = self.lines()
        self.assertEqual((line["decision"], line["listed"], line["bytes_up"], line["bytes_down"]),
                         ("allowed", True, 5, 10))

    def test_the_byte_cap_refuses_new_tunnels(self):
        """Found by A3 (M-METHOD-003): bytes were forwarded before they were counted, so a second tunnel could be
        admitted on an out-of-date total. Counted first, the cap is exact and the second tunnel is always refused."""
        for _ in range(20):  # the race showed up only now and then
            if self.log.exists():
                self.log.unlink()
            server = self.start(ENFORCE, max_total=8)
            with mock.patch.object(proxy, "address_problem", lambda addresses: None):
                first = self.tunnel(server)
                reply = self.tunnel(server)
            self.assertNotIn(b"ECHO", first, "the echo (10 bytes) would pass the 8-byte cap, so it is not forwarded")
            self.assertTrue(reply.startswith(b"HTTP/1.1 403"), reply)
            self.assertTrue(any("used its 8 bytes" in l["reason"] for l in self.lines(2)))

    def test_the_cap_is_never_passed(self):
        """Every byte forwarded either way is counted first, so what the tunnels carried never exceeds the cap."""
        server = self.start(ENFORCE, max_total=12)
        with mock.patch.object(proxy, "address_problem", lambda addresses: None):
            reply = self.tunnel(server)
        self.assertNotIn(b"ECHO", reply, "5 bytes up fit; 10 more down would make 15")
        (line,) = self.lines()
        self.assertLessEqual(line["bytes_up"] + line["bytes_down"], 12)
        self.assertEqual((line["bytes_up"], line["bytes_down"]), (5, 0))

    def test_observing_tunnels_to_an_unlisted_host_and_records_it(self):
        reply = self.tunnel(self.start(OBSERVE), host="evil.example.org")
        self.assertTrue(reply.endswith(b"ECHO hello"), reply)
        (line,) = self.lines()
        self.assertEqual((line["decision"], line["listed"]), ("allowed", False))
        self.assertTrue(line["reason"].startswith("observe: would refuse (not listed"))

    def test_serve_writes_its_port_and_refuses_an_unknown_runtime(self):
        with self.assertRaises(PolicyError):
            proxy.serve({"claude-code": ()}, "other", ENFORCE, self.log, Path(self.tmp.name) / "port")


if __name__ == "__main__":
    unittest.main()
