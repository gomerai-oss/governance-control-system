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

Model endpoint (ring 1 amendment, MISSION-DISPATCH-001 §3i item 6, Amendment 017). Started with a login file, the
proxy also serves plain HTTP under ``/model/`` for the runtime's model API, so the runtime holds only a stand-in and
never the login. The file (``{"kind", "login", "standin"}``) is read once and deleted. A request is forwarded only
when it carries the stand-in exactly, names loopback as its host, and has a method, path and query listed for the
runtime under ``model_endpoints`` in the egress policy. Every authentication header the runtime sent is dropped, the
login is added in the form its kind needs, and the request goes over TLS, certificate checked, to the listed model
host at an address that passed the same global-address check as a tunnel. The answer comes back unchanged. These
checks hold in both modes; they are what the route is. Each request is one log line (``"route": "model"``: time,
method, path, decision, reason, status, bytes each way), never a header. With ``exclusive`` (``"model_login":
"enforce"``) a CONNECT to the model host is refused: the endpoint is the only way to it.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import re
import select
import socket
import socketserver
import ssl
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
MODEL_PREFIX = "/model"
MAX_MODEL_BODY = 32 * 1024 * 1024  # one model request's body
MODEL_TIMEOUT = 600.0  # a streamed answer can be long
LOGIN_KINDS = ("api_key", "oauth")
OAUTH_BETA = "oauth-2025-04-20"  # sent with an OAuth login, as the runtime itself does (checked by AST-1.6)
# Request headers never forwarded: the runtime's own credentials, and what the proxy sets itself.
DROPPED_HEADERS = frozenset({"authorization", "x-api-key", "proxy-authorization", "cookie", "host", "content-length",
                             "connection", "keep-alive", "proxy-connection", "transfer-encoding", "te", "upgrade",
                             "trailer", "expect"})

# A DNS name whose last label starts with a letter: no IPv4 literal, no bare number, no IPv6 literal.
_NAME = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?")
_ENTRY = re.compile(r"(?:\*\.)?" + _NAME.pattern)
_REQUEST = re.compile(rb"\A([A-Z]{3,10}) (\S{1,300}) HTTP/1\.[01]\r\n")

Resolver = Callable[[str, int], Sequence[str]]


class PolicyError(ValueError):
    """The egress policy file is malformed; the proxy does not start."""


def _policy_doc(text: str) -> dict:
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise PolicyError(f"the egress policy is not JSON: {exc}") from None
    runtimes = data.get("runtimes") if isinstance(data, dict) else None
    if not (isinstance(data, dict) and {"schema", "runtimes"} <= set(data) <= {"schema", "runtimes", "model_endpoints"}
            and data["schema"] == SCHEMA and isinstance(runtimes, dict) and runtimes):
        raise PolicyError(f"the egress policy must be {{\"schema\": \"{SCHEMA}\", \"runtimes\": {{...}}}}, "
                          "optionally with \"model_endpoints\"")
    return data


def load_policy(text: str) -> Dict[str, Tuple[str, ...]]:
    """``{"schema": "egress-policy-v1", "runtimes": {<runtime>: [<host or *.suffix>, ...]}, "model_endpoints": ...}``"""
    data = _policy_doc(text)
    load_model_endpoints(text)  # a malformed model section refuses the whole policy
    runtimes = data["runtimes"]
    policy = {}
    for runtime, hosts in runtimes.items():
        if not (isinstance(runtime, str) and isinstance(hosts, list)
                and all(isinstance(h, str) and _ENTRY.fullmatch(h) for h in hosts)):
            raise PolicyError(f"runtime {runtime!r}: hosts must be lower-case DNS names or *.suffix")
        policy[runtime] = tuple(hosts)
    return policy


@dataclass(frozen=True)
class ModelEndpoint:
    """What one runtime's model route may forward: its host, and the exact method, path and query of each request."""
    host: str
    routes: Tuple[Tuple[str, str], ...]
    queries: Tuple[str, ...]
    readiness_route: Tuple[str, str]
    readiness_model: str


_ROUTE = re.compile(r"([A-Z]{3,7}) (/[A-Za-z0-9_/.-]{1,200})")
_QUERY = re.compile(r"[A-Za-z0-9_=&.-]{0,200}")


def load_model_endpoints(text: str) -> Dict[str, ModelEndpoint]:
    """``"model_endpoints": {<runtime>: {"host", "routes": ["POST /v1/messages", ...], "queries": ["", ...],
    "readiness": {"route", "model"}}}``; absent means no runtime has one."""
    data = _policy_doc(text)
    section = data.get("model_endpoints", {})
    if not isinstance(section, dict):
        raise PolicyError("model_endpoints must map runtimes to endpoints")
    found = {}
    for runtime, doc in section.items():
        where = f"model_endpoints {runtime!r}"
        if runtime not in data["runtimes"]:
            raise PolicyError(f"{where}: not a runtime of the policy")
        if not (isinstance(doc, dict) and set(doc) == {"host", "routes", "queries", "readiness"}):
            raise PolicyError(f"{where} must have exactly host, routes, queries and readiness")
        host, routes, queries, ready = doc["host"], doc["routes"], doc["queries"], doc["readiness"]
        if not (isinstance(host, str) and _NAME.fullmatch(host)):
            raise PolicyError(f"{where}: host must be one lower-case DNS name")
        if not (isinstance(routes, list) and routes and all(isinstance(r, str) and _ROUTE.fullmatch(r) for r in routes)
                and all(".." not in r for r in routes)):
            raise PolicyError(f"{where}: routes must be \"METHOD /path\" entries")
        if not (isinstance(queries, list) and all(isinstance(q, str) and _QUERY.fullmatch(q) for q in queries)):
            raise PolicyError(f"{where}: queries must be exact query strings")
        if not (isinstance(ready, dict) and set(ready) == {"route", "model"} and ready["route"] in routes
                and isinstance(ready["model"], str) and re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,80}", ready["model"])):
            raise PolicyError(f"{where}: readiness must name one of its routes and a model")
        split = tuple(tuple(r.split(" ", 1)) for r in routes)
        found[runtime] = ModelEndpoint(host, split, tuple(queries), tuple(ready["route"].split(" ", 1)), ready["model"])
    return found


@dataclass(frozen=True)
class ModelLogin:
    kind: str
    login: str
    standin: str


def read_login_file(path: Path) -> ModelLogin:
    """The login file the dispatcher wrote for this run, read once and deleted."""
    try:
        if path.is_symlink():
            raise PolicyError("the login file is a symlink")
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PolicyError(f"the login file cannot be read: {exc}") from None
    finally:
        try:
            path.unlink()
        except OSError:
            pass
    if not (isinstance(doc, dict) and set(doc) == {"kind", "login", "standin"} and doc["kind"] in LOGIN_KINDS
            and all(isinstance(doc[k], str) and len(doc[k]) >= 16 and doc[k].isprintable() and " " not in doc[k]
                    for k in ("login", "standin")) and doc["login"] != doc["standin"]):
        raise PolicyError("the login file must hold kind, login and standin")
    return ModelLogin(doc["kind"], doc["login"], doc["standin"])


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
                 max_total: int = MAX_TOTAL_BYTES, model: Optional[ModelEndpoint] = None,
                 login: Optional[ModelLogin] = None, exclusive: bool = False,
                 tls: Optional[ssl.SSLContext] = None) -> None:
        if mode not in MODES:
            raise PolicyError(f"unknown egress mode {mode!r}")
        if (model is None) != (login is None):
            raise PolicyError("the model endpoint needs both its policy entry and a login")
        if exclusive and model is None:
            raise PolicyError("an exclusive model endpoint needs a login")
        self.hosts, self.mode, self.log_path, self.resolver, self.max_total = tuple(hosts), mode, log, resolver, max_total
        self.model, self.login, self.exclusive = model, login, exclusive
        self.tls = tls if tls is not None else ssl.create_default_context()
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
        elif self.exclusive and self.model is not None and host == self.model.host:
            problem = "the model host is reached through the model endpoint only"
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
        if self.mode == OBSERVE and method == "CONNECT" and port and not problem.startswith("the model host"):
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

    def model_decide(self, method: str, target: str, headers: Mapping[str, str], port: int) -> Tuple[str, Decision]:
        """Whether the model route forwards this request; returns the upstream path (with its query)."""
        model, login = self.model, self.login
        if model is None or login is None:
            return "", Decision(False, "no model endpoint in this run", False)
        path, _, query = target[len(MODEL_PREFIX):].partition("?")
        given = headers.get("authorization", "")
        bearer = given[7:] if given[:7].lower() == "bearer " else ""
        offered = bearer or headers.get("x-api-key", "")
        if not hmac.compare_digest(offered.encode("utf-8", "replace"), login.standin.encode("utf-8")):
            return "", Decision(False, "the request does not carry this run's stand-in", False)
        if headers.get("host", "") not in (f"127.0.0.1:{port}", f"localhost:{port}"):
            return "", Decision(False, "the request names a host other than this endpoint", False)
        if (method, path) not in model.routes:
            return "", Decision(False, f"{method} {path[:120]} is not a listed model route", False)
        if query not in model.queries:
            return "", Decision(False, "the query is not listed for this route", False)
        if "transfer-encoding" in headers or not headers.get("content-length", "0").isdigit():
            return "", Decision(False, "a model request must give its length", False)
        if int(headers.get("content-length", "0")) > MAX_MODEL_BODY:
            return "", Decision(False, f"the request is larger than {MAX_MODEL_BODY} bytes", False)
        if self.spent():
            return "", Decision(False, f"the run has used its {self.max_total} bytes", False)
        return path + (f"?{query}" if query else ""), Decision(True, "listed model route", True)

    def upstream_head(self, method: str, path: str, headers: Mapping[str, str], length: int) -> bytes:
        """The request line and headers sent to the model host: the runtime's own, minus its credentials, plus the
        login in the form its kind needs."""
        assert self.model is not None and self.login is not None
        lines = [f"{method} {path} HTTP/1.1", f"Host: {self.model.host}", f"Content-Length: {length}",
                 "Connection: close"]
        beta = headers.get("anthropic-beta", "")
        for name, value in headers.items():
            if name in DROPPED_HEADERS or name == "anthropic-beta":
                continue
            lines.append(f"{name}: {value}")
        if self.login.kind == "api_key":
            lines.append(f"x-api-key: {self.login.login}")
        else:
            lines.append(f"Authorization: Bearer {self.login.login}")
            betas = [b.strip() for b in beta.split(",") if b.strip()]
            if OAUTH_BETA not in betas:
                betas.append(OAUTH_BETA)
            beta = ",".join(betas)
        if beta:
            lines.append(f"anthropic-beta: {beta}")
        return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")

    def record_model(self, method: str, path: str, decision: Decision, status: int = 0, up: int = 0,
                     down: int = 0) -> None:
        line = json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "route": "model",
                           "method": method[:10], "path": path.partition("?")[0][:200],
                           "decision": "allowed" if decision.allowed else "refused", "reason": decision.reason,
                           "status": status, "bytes_up": up, "bytes_down": down}, sort_keys=True)
        with self.lock, open(self.log_path, "a", encoding="utf-8") as log:
            log.write(line + "\n")

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
        if method != "CONNECT" and egress.model is not None and (target == MODEL_PREFIX
                                                                   or target.startswith(MODEL_PREFIX + "/")):
            self._model(method, target, head)
            return
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

    def _model(self, method: str, target: str, head: bytes) -> None:
        egress = self.server.egress
        assert egress.model is not None
        raw_head, _, rest = head.partition(b"\r\n\r\n")
        headers: Dict[str, str] = {}
        for raw in raw_head.split(b"\r\n")[1:]:
            name, sep, value = raw.decode("latin-1").partition(":")
            if (not sep or not name.strip() or name != name.strip() or not re.fullmatch(r"[A-Za-z0-9-]{1,64}", name)
                    or any(c in value for c in "\r\n\0")):
                egress.record_model(method, target, Decision(False, "a malformed header", False))
                self._refuse(400, "a malformed header")
                return
            key = name.strip().lower()
            if key in headers:
                egress.record_model(method, target, Decision(False, f"header {key} given twice", False))
                self._refuse(400, "a repeated header")
                return
            headers[key] = value.strip()
        path, decision = egress.model_decide(method, target, headers, self.server.port)
        if not decision.allowed:
            egress.record_model(method, target, decision)
            self._refuse(403, decision.reason)
            return
        length = int(headers.get("content-length", "0"))
        body = rest
        try:
            while len(body) < length:
                part = self.request.recv(min(CHUNK, length - len(body)))
                if not part:
                    break
                body += part
        except OSError:
            pass
        if len(body) != length:
            egress.record_model(method, path, Decision(False, "the request body ended early", True))
            self._refuse(400, "the request body ended early")
            return
        try:
            addresses = tuple(egress.resolver(egress.model.host, PORT))
        except (OSError, UnicodeError):
            addresses = ()
        problem = address_problem(addresses)
        out = egress.upstream_head(method, path, headers, length) + body
        if problem is None and not egress.count(len(out)):
            problem = f"the run has used its {egress.max_total} bytes"
        if problem is not None:
            egress.record_model(method, path, Decision(False, f"the model host: {problem}", True))
            self._refuse(502, "the model host cannot be reached")
            return
        upstream = self._connect(addresses, PORT)
        if upstream is None:
            egress.record_model(method, path, Decision(False, "the model host could not be reached", True))
            self._refuse(502, "the model host could not be reached")
            return
        status, down = 0, 0
        try:
            tls = egress.tls.wrap_socket(upstream, server_hostname=egress.model.host)
        except (OSError, ssl.SSLError) as exc:
            upstream.close()
            egress.record_model(method, path, Decision(False, f"TLS to the model host failed ({type(exc).__name__})",
                                                       True))
            self._refuse(502, "TLS to the model host failed")
            return
        try:
            tls.settimeout(MODEL_TIMEOUT)
            tls.sendall(out)
            first = True
            while True:
                data = tls.recv(CHUNK)
                if not data:
                    break
                if first:
                    found = re.match(rb"HTTP/1\.[01] (\d{3})", data)
                    status = int(found.group(1)) if found else 0
                    first = False
                if not egress.count(len(data)):
                    break
                self.request.sendall(data)
                down += len(data)
        except (OSError, ssl.SSLError):
            pass
        finally:
            tls.close()
            egress.record_model(method, path, decision, status, len(out), down)

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

    def verify_request(self, request, client_address) -> bool:  # loopback only, for tunnels and the model route
        return ipaddress.ip_address(client_address[0]).is_loopback

    @property
    def port(self) -> int:
        return self.server_address[1]


def serve(policy: Mapping[str, Sequence[str]], runtime: str, mode: str, log: Path, ready: Path,
          models: Optional[Mapping[str, ModelEndpoint]] = None, login_file: Optional[Path] = None,
          exclusive: bool = False) -> None:
    """Run until killed. Writes the port to ``ready`` once listening. With ``login_file`` the model endpoint is
    served for ``runtime`` (its file is read and deleted before the port is written)."""
    if runtime not in policy:
        raise PolicyError(f"the egress policy lists no hosts for runtime {runtime!r}")
    model = login = None
    if login_file is not None:
        login = read_login_file(login_file)
        model = (models or {}).get(runtime)
        if model is None:
            raise PolicyError(f"the egress policy lists no model endpoint for runtime {runtime!r}")
    server = Server(Egress(policy[runtime], mode, log, model=model, login=login, exclusive=exclusive))
    tmp = ready.with_name(ready.name + ".tmp")
    tmp.write_text(str(server.port), encoding="utf-8")
    tmp.replace(ready)
    server.serve_forever()
