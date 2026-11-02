"""Egress proxy (ring 5): the agent account's only way out. MISSION-DISPATCH-001 §3h item 3, Amendment 012.

It listens on loopback and accepts only ``CONNECT host:443``. Under ``enforce`` it refuses:

- a request that is not CONNECT, or a port other than 443;
- a host that is not a DNS name (an IP literal in any spelling, a bare number, a bracketed IPv6 address);
- a host not listed for the job's runtime in the egress policy (exact names, or ``*.suffix`` for any subdomain);
- a name that resolves to any address that is not global (private, loopback, link-local, shared, reserved);
- anything once 256 MiB have passed in total, and it cuts the open tunnels at that point. Every chunk is counted
  before it is forwarded, and a chunk that would reach the cap is not forwarded, so the cap is never passed.

It connects to the address it checked, never re-resolving, so a name cannot change between the check and the
connection. Under ``observe`` it admits every CONNECT and records what enforcement would have refused. Each
decision is one JSON line in the log: time, host, port, decision, reason, listed, and bytes each way.
"""

from __future__ import annotations

import ipaddress
import json
import re
import select
import socket
import socketserver
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple

OBSERVE, ENFORCE = "observe", "enforce"
MODES = (OBSERVE, ENFORCE)
SCHEMA = "egress-policy-v1"
PORT = 443
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_REQUEST_BYTES = 8 * 1024
REQUEST_TIMEOUT = 10.0
CONNECT_TIMEOUT = 10.0
IDLE_TIMEOUT = 600.0
CHUNK = 64 * 1024

# A DNS name whose last label starts with a letter: no IPv4 literal, no bare number, no IPv6 literal.
_NAME = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?")
_ENTRY = re.compile(r"(?:\*\.)?" + _NAME.pattern)
_REQUEST = re.compile(rb"\A([A-Z]{3,10}) (\S{1,300}) HTTP/1\.[01]\r\n")

Resolver = Callable[[str, int], Sequence[str]]


class PolicyError(ValueError):
    """The egress policy file is malformed; the proxy does not start."""


def load_policy(text: str) -> Dict[str, Tuple[str, ...]]:
    """``{"schema": "egress-policy-v1", "runtimes": {<runtime>: [<host or *.suffix>, ...]}}``"""
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise PolicyError(f"the egress policy is not JSON: {exc}") from None
    runtimes = data.get("runtimes") if isinstance(data, dict) else None
    if not (isinstance(data, dict) and set(data) == {"schema", "runtimes"} and data["schema"] == SCHEMA
            and isinstance(runtimes, dict) and runtimes):
        raise PolicyError(f"the egress policy must be {{\"schema\": \"{SCHEMA}\", \"runtimes\": {{...}}}}")
    policy = {}
    for runtime, hosts in runtimes.items():
        if not (isinstance(runtime, str) and isinstance(hosts, list)
                and all(isinstance(h, str) and _ENTRY.fullmatch(h) for h in hosts)):
            raise PolicyError(f"runtime {runtime!r}: hosts must be lower-case DNS names or *.suffix")
        policy[runtime] = tuple(hosts)
    return policy


def listed(host: str, hosts: Sequence[str]) -> bool:
    return any(host == h or (h.startswith("*.") and host.endswith(h[1:])) for h in hosts)


def host_problem(host: str) -> Optional[str]:
    """Why ``host`` is not a usable name, or None."""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return "an IP address, not a name"
    except ValueError:
        pass
    if not _NAME.fullmatch(host):
        return "not a DNS name"
    return None


def address_problem(addresses: Sequence[str]) -> Optional[str]:
    """Why the resolved ``addresses`` must not be reached, or None. Every one must be global."""
    if not addresses:
        return "it does not resolve"
    for text in addresses:
        address = ipaddress.ip_address(text.split("%", 1)[0])
        mapped = getattr(address, "ipv4_mapped", None)
        if not (mapped or address).is_global:
            return f"it resolves to a non-global address ({address})"
    return None


def resolve(host: str, port: int) -> List[str]:
    found = []
    for *_, sockaddr in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
        if sockaddr[0] not in found:
            found.append(sockaddr[0])
    return found


@dataclass
class Decision:
    allowed: bool
    reason: str
    listed: bool
    addresses: Tuple[str, ...] = ()


class Egress:
    """The decisions and the log of one proxy. Thread-safe."""

    def __init__(self, hosts: Sequence[str], mode: str, log: Path, resolver: Resolver = resolve,
                 max_total: int = MAX_TOTAL_BYTES) -> None:
        if mode not in MODES:
            raise PolicyError(f"unknown egress mode {mode!r}")
        self.hosts, self.mode, self.log_path, self.resolver, self.max_total = tuple(hosts), mode, log, resolver, max_total
        self.total = 0
        self.lock = threading.Lock()

    def decide(self, method: str, target: str) -> Tuple[str, int, Decision]:
        host, port = target, 0
        if method == "CONNECT":
            host, sep, raw = target.rpartition(":")
            host = host.lower()
            port = int(raw) if sep and raw.isdigit() and len(raw) <= 5 else 0
        on_list = listed(host, self.hosts)
        problem = None
        addresses: Tuple[str, ...] = ()
        if method != "CONNECT":
            problem = f"{method} is not CONNECT"
        elif port != PORT:
            problem = f"port {port or raw!r} is not {PORT}"
        else:
            problem = host_problem(host)
            if problem is None and not on_list:
                problem = "not listed for this runtime"
            if problem is None or self.mode == OBSERVE:
                try:
                    addresses = tuple(self.resolver(host, port))
                except (OSError, UnicodeError):
                    addresses = ()
                problem = problem or address_problem(addresses)
        if problem is None and self.spent():
            problem = f"the run has used its {self.max_total} bytes"
        if problem is None:
            return host, port, Decision(True, "listed", on_list, addresses)
        if self.mode == OBSERVE and method == "CONNECT" and port:
            return host, port, Decision(True, f"observe: would refuse ({problem})", on_list, addresses)
        return host, port, Decision(False, problem, on_list, addresses)

    def spent(self) -> bool:
        with self.lock:
            return self.mode == ENFORCE and self.total >= self.max_total

    def count(self, n: int) -> bool:
        """Add ``n`` bytes; False once the cap is reached (enforce only)."""
        with self.lock:
            self.total += n
            return self.mode == OBSERVE or self.total < self.max_total

    def record(self, host: str, port: int, decision: Decision, up: int = 0, down: int = 0) -> None:
        line = json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "host": host[:300],
                           "port": port, "decision": "allowed" if decision.allowed else "refused",
                           "reason": decision.reason, "listed": decision.listed, "bytes_up": up, "bytes_down": down},
                          sort_keys=True)
        with self.lock, open(self.log_path, "a", encoding="utf-8") as log:
            log.write(line + "\n")


class _Handler(socketserver.BaseRequestHandler):
    server: "Server"

    def handle(self) -> None:
        egress = self.server.egress
        client = self.request
        client.settimeout(REQUEST_TIMEOUT)
        head = b""
        try:
            while b"\r\n\r\n" not in head and len(head) <= MAX_REQUEST_BYTES:
                part = client.recv(4096)
                if not part:
                    return
                head += part
        except OSError:
            return
        found = _REQUEST.match(head)
        if not found or b"\r\n\r\n" not in head:
            egress.record("", 0, Decision(False, "a malformed request", False))  # logged before the reply
            self._refuse(400, "a malformed request")
            return
        method, target = found.group(1).decode("ascii"), found.group(2).decode("ascii", "replace")
        host, port, decision = egress.decide(method, target)
        if not decision.allowed:
            egress.record(host, port, decision)
            self._refuse(403 if method == "CONNECT" else 405, decision.reason)
            return
        upstream = self._connect(decision.addresses, port)
        if upstream is None:
            egress.record(host, port, Decision(False, "the host could not be reached", decision.listed))
            self._refuse(502, "the host could not be reached")
            return
        up = down = 0
        try:
            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            rest = head.split(b"\r\n\r\n", 1)[1]
            if rest and egress.count(len(rest)):  # counted before it is forwarded, like every chunk
                upstream.sendall(rest)
                up += len(rest)
                up, down = self._relay(client, upstream, up, down)
            elif not rest:
                up, down = self._relay(client, upstream, up, down)
        except OSError:
            pass
        finally:
            upstream.close()
            egress.record(host, port, decision, up, down)

    def _connect(self, addresses: Sequence[str], port: int) -> Optional[socket.socket]:
        for address in addresses:  # the addresses decide() checked, never a fresh lookup
            try:
                return socket.create_connection((address, port), timeout=CONNECT_TIMEOUT)
            except OSError:
                continue
        return None

    def _relay(self, client: socket.socket, upstream: socket.socket, up: int, down: int) -> Tuple[int, int]:
        egress = self.server.egress
        client.settimeout(None)
        upstream.settimeout(None)
        while True:
            ready, _, _ = select.select([client, upstream], [], [], IDLE_TIMEOUT)
            if not ready:
                return up, down
            for sock in ready:
                data = sock.recv(CHUNK)
                if not data:
                    return up, down
                # Counted before it is forwarded: a chunk that would reach the cap is dropped and the tunnel cut,
                # so the cap is never passed and no later tunnel is decided on an out-of-date total.
                if not egress.count(len(data)):
                    return up, down
                other = upstream if sock is client else client
                other.sendall(data)
                if sock is client:
                    up += len(data)
                else:
                    down += len(data)

    def _refuse(self, status: int, reason: str) -> None:
        body = f"egress refused: {reason}\n".encode("utf-8", "replace")
        try:
            self.request.sendall(f"HTTP/1.1 {status} Refused\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                                 .encode("ascii") + body)
        except OSError:
            pass


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, egress: Egress) -> None:
        self.egress = egress
        super().__init__(("127.0.0.1", 0), _Handler)

    @property
    def port(self) -> int:
        return self.server_address[1]


def serve(policy: Mapping[str, Sequence[str]], runtime: str, mode: str, log: Path, ready: Path) -> None:
    """Run until killed. Writes the port to ``ready`` once listening."""
    if runtime not in policy:
        raise PolicyError(f"the egress policy lists no hosts for runtime {runtime!r}")
    server = Server(Egress(policy[runtime], mode, log))
    tmp = ready.with_name(ready.name + ".tmp")
    tmp.write_text(str(server.port), encoding="utf-8")
    tmp.replace(ready)
    server.serve_forever()
