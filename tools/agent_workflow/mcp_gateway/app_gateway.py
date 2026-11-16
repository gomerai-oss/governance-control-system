"""The app gateway (APP-CONTROL-HARNESS-SPEC-001 §4.1 Proposal A, MISSION-DISPATCH-001 §3p, Amendment 027).

The second governed MCP server: an agent reaches a harness only as one of its tools, never through a shell. It is a
module of its own beside the retrieval gateway (``server.py``), which it does not change. The two share the MCP
framing (``protocol.py``'s ``decode``, ``encode``, ``result`` and ``error``, through ``protocol.Endpoint``), the
fabric (``mcp_auth.decide``) and the session module.

``AppGateway(root, session_path, evidence_dir)`` loads, at start, from the gateway's own tree, never from the
agent-writable checkout:

- the shipped fabric policy (``mcp_auth/policy.json``) and the app register (``tool_selection/apps.json``). A
  resource the register lists as restricted must be restricted in the policy, and the other way round, or the
  gateway refuses to start: it never under-declares a resource to get a call through;
- the app catalog (``app_tools.json``, schema ``mcp-app-gateway-tools-v1``), which may be empty. Each tool names its
  app, one ``app`` class action of kind ``read`` or ``write`` and one resource of that app. A ``send`` or ``delete``
  action is refused: no agent sends or deletes (Proposal C). So is a ``write`` action for an app whose writes are
  ``drafted``, and any action of a class the app's register entry does not list;
- the launcher's session (kind ``agent``, unless the perform step asks for ``service``), and from it the overlay
  with the register's approvals for the session's apps (``session.overlay``). An invalid session does not stop the
  gateway; it makes every call DENY with stop 13. A session that pins the app catalog (``app_catalog``) and a
  different catalog: under ``"enforce"`` the gateway refuses to start; under ``"observe"`` the difference is logged.

Every call is decided by the fabric with the truth about it: the connector holds no credential (the egress proxy
holds each app's key, §4.2), and every call implicates ``external_exposure``, because it reaches a service outside
the pipeline. A call over the run's bounds (the register's ``bounds``, or the app's own lower ones) is refused before
the fabric is asked. On ALLOW the tool's harness runs. A harness's result passes ``quarantine.quarantine``, labelled
with the app and the tool, and then the secrets boundary, before the agent reads it (§4.4).

**Harnesses** (§3p, Amendment 029). A harness is pinned before its tools enter the catalog: the gateway refuses to
start if a catalog tool's app has no harness in the ``harnesses`` section of ``credentials_check/pins.json``
(``mission_dispatch.supply_chain``), read from the gateway's own tree. At start it reads each such harness's file,
``mcp_gateway/harnesses/<name>.py`` in the same tree, once. The file must match its pin's SHA-256 and import only
``HARNESS_IMPORTS``. The gateway then runs exactly the bytes it checked, never a fresh import of the path. A harness
that fails any of these is not run: its tools' calls are refused, and each refusal is logged as ``harness``. A
harness defines ``run(tool, arguments, request) -> str``. ``request(method, host, path, query="", body=None)`` is
its only way to its app: the gateway lets through only a request the app register lists for the app, of the
calling tool's own class, to one of the app's hosts, at most ``MAX_HARNESS_REQUESTS`` per call, and sends it to the
app endpoint (Amendment 028) with the run's stand-in, which the harness is not given. The import list catches a plain
mistake, not a hostile harness: the harness runs in the gateway's process, so the independent review its pin
records is what admits it (APP-CONTROL-HARNESS-SPEC-001 §4.5).

Each line of ``app-decisions.jsonl`` in the evidence directory is one JSON object with an ``entry`` field:
``decision``, ``refusal`` (a tool not in the catalog), ``bound`` (a call over the run's bounds), ``harness`` (a
harness that is not run), ``result`` and ``result_error`` (after an ALLOW), ``draft`` and ``draft_refused`` (a
draft tool's call, Amendment 031), ``boundary``, and ``catalog_pin`` (``"observe"`` only). The directory is the
app gateway's own, never the retrieval gateway's, so ``collect`` never records a harness call as a retrieval call.

Drafting (Amendment 031, Proposal C): no agent sends, deletes or makes a drafted write. Such a catalog tool is served
as a draft tool, decided by the fabric as ``app.draft`` on the tool's resource; on ALLOW the gateway checks the
arguments and adds the exact call to the run's drafted list, ``app-drafts.json`` beside the log, at most
``MAX_DRAFTS`` calls, and sends nothing. The harness does not run.

Performing (Amendment 032): only the perform step builds the gateway with ``kind="service"``, in its own process,
never as an MCP server (``main`` serves agents only). It loads a ``service`` session and is served exactly the tools
an agent drafts, each as itself (``app.send``, ``app.delete`` or a drafted ``app.write``), and no other tool.
``perform(call)`` makes one call of HITL's performed list after checking that it names its tool exactly as the
catalog has it; the call is then bounded, decided by the fabric as the ``service`` principal, and run, like any
other.

A ``decision`` and a ``bound`` entry name the tool's ``kind``, and a ``decision`` the digest of the call's arguments
(``arguments_sha256``), never the arguments: ``collect`` records each call as one ``harness.<kind>`` record from them
(Amendment 030).
"""

from __future__ import annotations

import argparse
import ast
import http.client
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, List, Mapping, Optional, Tuple

from egress import proxy as egress_proxy
from epap import signing
from mcp_auth import decide
from mcp_auth import policy as P
from mcp_auth import records as auth_records
from mcp_gateway import protocol
from mcp_gateway import session as session_mod
from mission_dispatch import quarantine
from mission_dispatch import supply_chain
from secrets_boundary import detector as boundary_detector
from secrets_boundary import gate as boundary
from secrets_boundary import records as boundary_records
from tool_selection import apps as apps_mod

SERVER_NAME = "governed-apps"
SERVER_VERSION = "APP-CONTROL-HARNESS-SPEC-001"
CATALOG_SCHEMA = "mcp-app-gateway-tools-v1"
DEFAULT_CATALOG = Path(__file__).resolve().with_name("app_tools.json")
TOOLING = Path(__file__).resolve().parents[1]  # the gateway's own tree: its pins table and harness files
DEFAULT_PINS = TOOLING / supply_chain.PINS_TABLE
DECISIONS_FILE = "app-decisions.jsonl"
CONNECTOR_ID = SERVER_NAME
CAN_PRODUCE = ("audit_record",)
IMPLICATES = ("external_exposure",)  # every harness call reaches a service outside the pipeline
APP_CLASS = "app"
SERVED_KINDS = ("read", "write")  # the agent's gateway: never send or delete (Proposal C)
SERVICE_KIND = "service"  # the perform step's session (Amendment 032): it is served only the tools agents draft
# Drafting (Amendment 031): a send, a delete or a drafted write is served to an agent as a draft tool, decided by the
# fabric as DRAFT_ACTION. Its call is added to the run's drafted list, DRAFTS_FILE, and nothing is sent.
DRAFT_ACTION = "app.draft"
DRAFTS_FILE = "app-drafts.json"
DRAFTS_SCHEMA = "app-drafts-v1"
DRAFT_FIELDS = frozenset({"schema", "mission", "session", "calls"})
CALL_FIELDS = frozenset({"app", "tool", "kind", "action", "resource", "arguments"})
MAX_DRAFTS = 20  # per run
MAX_DRAFT_ARGUMENTS = 2000  # characters of a drafted call's arguments as JSON, so HITL reads every call whole
DRAFT_NOTE = "Drafts this call for HITL; it is not made, and nothing is sent until HITL performs the run's list. "
SESSION_STOP = 13
KNOWN_SECRET_ENV = ("MISSION_RUN_CANARY", "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "CURSOR_API_KEY")

CATALOG_FIELDS = frozenset({"schema", "catalog_version", "tools"})
TOOL_FIELDS = frozenset({"name", "description", "app", "action", "resource", "input_schema"})
SCHEMA_FIELDS = frozenset({"type", "properties", "required", "additionalProperties"})
_TOOL_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")
MAX_ARGUMENT_BYTES = 64 * 1024
MAX_RESULT_CHARS = 64 * 1024  # the most of one result the quarantine passes on

# The modules a harness may import (Amendment 029): none reaches the network, a file or a process.
HARNESS_IMPORTS = frozenset({"__future__", "json", "re", "typing", "dataclasses", "datetime", "urllib.parse", "html",
                             "string"})
MAX_HARNESS_REQUESTS = 20  # per tool call
MAX_HARNESS_BODY = 1024 * 1024  # the proxy's own cap (egress/proxy.py MAX_APP_BODY)
MAX_HARNESS_ANSWER = 1024 * 1024
HARNESS_TIMEOUT = 60

Runner = Callable[["AppTool", Mapping[str, str]], str]  # a test's stand-in for a pinned harness


class GatewayError(RuntimeError):
    """The app gateway refuses to start."""


class HarnessError(RuntimeError):
    """A harness's request the gateway does not send, or an endpoint that did not answer."""


@dataclass(frozen=True)
class AppTool:
    name: str
    description: str
    app: str
    action: str
    kind: str
    resource: str
    input_schema: dict
    performs: str = ""  # a draft tool's own action (app.send, app.delete or app.write); "" for a served tool

    def listing(self) -> dict:
        return {"name": self.name, "description": (DRAFT_NOTE if self.performs else "") + self.description,
                "inputSchema": json.loads(json.dumps(self.input_schema))}


# -- catalog -------------------------------------------------------------


def _check_input_schema(schema: Any, where: str) -> dict:
    if not isinstance(schema, dict) or not set(schema) <= SCHEMA_FIELDS or schema.get("type") != "object":
        raise GatewayError(f"{where}: input_schema must be an object schema using only {sorted(SCHEMA_FIELDS)}")
    if schema.get("additionalProperties") is not False:
        raise GatewayError(f"{where}: input_schema must set additionalProperties to false")
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise GatewayError(f"{where}: input_schema must declare its properties")
    for name, prop in properties.items():
        if not (isinstance(name, str) and _TOOL_NAME.fullmatch(name) and isinstance(prop, dict)
                and prop.get("type") == "string" and set(prop) <= {"type", "description"}):
            raise GatewayError(f"{where}: input_schema property {name!r} must be a plain string argument")
    required = schema.get("required", [])
    if not isinstance(required, list) or not all(r in properties for r in required):
        raise GatewayError(f"{where}: input_schema required names an undeclared property")
    return schema


def check_register(policy: Mapping, register: Mapping) -> None:
    """Each app resource the policy knows is restricted there exactly when the register lists it as restricted."""
    for name, app in register["apps"].items():
        for rid in app["resources"]:
            entry = policy["resources"].get(rid)
            if entry is None:
                continue  # a resource the policy does not know: no tool can name it (load_catalog)
            if entry["class"] != APP_CLASS:
                raise GatewayError(f"app {name!r}: resource {rid!r} is of class {entry['class']!r} in the policy")
            if entry["restricted"] != (rid in app["approvals"]["restricted"]):
                raise GatewayError(f"app {name!r}: resource {rid!r} is restricted in only one of the policy and "
                                   "the app register")


def load_catalog(path: Any, policy: Mapping, register: Mapping,
                 session_kind: str = session_mod.PRINCIPAL_KIND) -> List[AppTool]:
    """The validated app catalog (it may be empty); any defect refuses to start. For an agent's session (``kind``
    ``"agent"``) each send, delete and drafted write is a draft tool; for the perform step's ``service`` session
    (Amendment 032) exactly those tools are served as themselves, and no other tool is served."""
    if session_kind not in session_mod.SESSION_KINDS:
        raise GatewayError(f"a session kind is one of {list(session_mod.SESSION_KINDS)}")
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise GatewayError(f"app catalog is unreadable or not JSON: {exc}") from None
    if not isinstance(doc, dict) or set(doc) != CATALOG_FIELDS or doc["schema"] != CATALOG_SCHEMA:
        raise GatewayError(f"app catalog must be {CATALOG_SCHEMA!r} with exactly {sorted(CATALOG_FIELDS)}")
    if not P.is_name(doc["catalog_version"]):
        raise GatewayError("app catalog catalog_version must be a non-empty string")
    entries = doc["tools"]
    if not isinstance(entries, list):
        raise GatewayError("app catalog tools must be a list")
    app_class = policy["classes"][APP_CLASS]
    tools: List[AppTool] = []
    for i, entry in enumerate(entries):
        where = f"tools[{i}]"
        if not isinstance(entry, dict) or set(entry) != TOOL_FIELDS:
            raise GatewayError(f"{where} must have exactly {sorted(TOOL_FIELDS)}")
        name = entry["name"]
        if not isinstance(name, str) or not _TOOL_NAME.fullmatch(name) or any(t.name == name for t in tools):
            raise GatewayError(f"{where}: tool name must be a distinct lowercase identifier")
        if not P.is_name(entry["description"]):
            raise GatewayError(f"{where}: description must be a non-empty string")
        app = register["apps"].get(entry["app"]) if isinstance(entry["app"], str) else None
        if app is None:
            raise GatewayError(f"{where}: app {entry['app']!r} is not in the app register")
        if name not in app["tools"]:
            raise GatewayError(f"{where}: the app register does not list {name!r} as a tool of {entry['app']!r}")
        action = entry["action"]
        if not isinstance(action, str) or action not in app_class["read"] + app_class["mutation"]:
            raise GatewayError(f"{where}: action {action!r} is not an action of the fabric's app class")
        if action == DRAFT_ACTION:
            raise GatewayError(f"{where}: {DRAFT_ACTION} is the drafting action, not a tool's own")
        kind = policy["actions"][action]["kind"]
        if kind not in app["classes"]:
            raise GatewayError(f"{where}: app {entry['app']!r} does not list the {kind!r} class")
        # Proposal C: no agent sends, deletes or makes a drafted write. Such a tool is served as a draft tool.
        drafted = kind not in SERVED_KINDS or (kind == "write" and app["writes"] != "direct")
        if drafted and DRAFT_ACTION not in app_class["mutation"]:
            raise GatewayError(f"{where}: the fabric has no {DRAFT_ACTION!r} action to draft {action!r} with")
        resource = entry["resource"]
        res = policy["resources"].get(resource) if isinstance(resource, str) else None
        if res is None or res["class"] != APP_CLASS:
            raise GatewayError(f"{where}: resource {resource!r} is not an app resource known to policy")
        if resource not in app["resources"]:
            raise GatewayError(f"{where}: resource {resource!r} is not one of app {entry['app']!r}'s")
        schema = _check_input_schema(entry["input_schema"], where)
        if session_kind == SERVICE_KIND:
            if drafted:  # the perform step makes only the calls an agent can draft, each as itself
                tools.append(AppTool(name=name, description=entry["description"], app=entry["app"], action=action,
                                     kind=kind, resource=resource, input_schema=schema))
            continue
        tools.append(AppTool(name=name, description=entry["description"], app=entry["app"],
                             action=DRAFT_ACTION if drafted else action, kind=kind, resource=resource,
                             input_schema=schema, performs=action if drafted else ""))
    return tools


def catalog_digest(path: Any) -> str:
    """SHA-256 of the app catalog file's canonical JSON: the value the runtime binding pins as ``app_catalog``."""
    try:
        return signing.sha256_hex(signing.canonical_bytes(json.loads(Path(path).read_text(encoding="utf-8"))))
    except (OSError, UnicodeDecodeError, ValueError, TypeError, RecursionError, signing.CanonicalError) as exc:
        raise GatewayError(f"app catalog has no canonical form: {exc}") from None


def drafts_digest(doc: Mapping) -> str:
    """The digest of a drafted list: the SHA-256 of its canonical JSON. HITL's command names it (Amendment 031)."""
    return signing.sha256_hex(signing.canonical_bytes(doc))


def check_drafts(doc: object) -> List[str]:
    """What makes ``doc`` not a well-formed drafted list; empty when it is one."""
    if not (isinstance(doc, dict) and set(doc) == DRAFT_FIELDS and doc["schema"] == DRAFTS_SCHEMA):
        return [f"a drafted list must be {DRAFTS_SCHEMA!r} with exactly {sorted(DRAFT_FIELDS)}"]
    out = []
    if not (isinstance(doc["mission"], str) and doc["mission"] and isinstance(doc["session"], str) and doc["session"]):
        out.append("a drafted list names its mission and session")
    calls = doc["calls"]
    if not (isinstance(calls, list) and 0 < len(calls) <= MAX_DRAFTS):
        return out + [f"a drafted list holds 1 to {MAX_DRAFTS} calls"]
    for n, call in enumerate(calls, 1):
        if not (isinstance(call, dict) and set(call) == CALL_FIELDS
                and all(isinstance(call[k], str) and call[k] for k in CALL_FIELDS - {"arguments"})
                and isinstance(call["arguments"], dict)
                and all(isinstance(k, str) and isinstance(v, str) for k, v in call["arguments"].items())):
            out.append(f"call {n} must have exactly {sorted(CALL_FIELDS)}, its arguments plain strings")
        elif call["action"] not in ("app.send", "app.delete", "app.write") or call["kind"] != call["action"][4:]:
            out.append(f"call {n}: a drafted call is a send, a delete or a write, of its action's kind")
        elif len(json.dumps(call["arguments"], sort_keys=True, ensure_ascii=False)) > MAX_DRAFT_ARGUMENTS:
            out.append(f"call {n}: its arguments are longer than {MAX_DRAFT_ARGUMENTS} characters")
    return out


def read_drafts(path: Any) -> Tuple[dict, str]:
    """A drafted list file and its digest; ``GatewayError`` when it is a link, unreadable or malformed."""
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise GatewayError("the drafted list is not a regular file")
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise GatewayError(f"the drafted list is unreadable or not JSON: {exc}") from None
    found = check_drafts(doc)
    if found:
        raise GatewayError("; ".join(found))
    return doc, drafts_digest(doc)


def arguments_digest(arguments: object) -> str:
    """The SHA-256 of a call's arguments as canonical JSON (sorted keys, no spaces): its record's input (Amendment
    030). The log keeps the digest, never the arguments."""
    text = json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=repr)
    return signing.sha256_hex(text.encode("utf-8"))


def argument_problem(schema: Mapping, arguments: Any) -> Optional[str]:
    """Why ``arguments`` do not satisfy a catalog input schema, or None."""
    if not isinstance(arguments, dict):
        return "arguments must be an object"
    try:
        size = len(json.dumps(arguments, ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError):
        return "arguments must be JSON"
    if size > MAX_ARGUMENT_BYTES:
        return f"arguments are {size} bytes; at most {MAX_ARGUMENT_BYTES} are accepted"
    unknown = sorted(k for k in arguments if k not in schema["properties"])
    if unknown:
        return f"unknown arguments {unknown}"
    missing = sorted(r for r in schema.get("required", []) if r not in arguments)
    if missing:
        return f"missing arguments {missing}"
    bad = sorted(k for k, v in arguments.items() if not isinstance(v, str))
    if bad:
        return f"arguments {bad} must be strings"
    return None


# -- harnesses ------------------------------------------------------------


def harness_import_problem(tree: ast.AST) -> Optional[str]:
    """Why a harness's imports are refused, or None: only ``HARNESS_IMPORTS``, never a relative import."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                return "it makes a relative import"
            names = [node.module or ""]
        else:
            continue
        for name in names:
            if name not in HARNESS_IMPORTS:
                return f"it imports {name!r}"
    return None


def load_harness(tooling: Path, name: str, row: Mapping) -> Tuple[Optional[Callable], Optional[str]]:
    """``(run, None)`` for the pinned harness ``name``, or ``(None, why it is not run)``. The file is read once; what
    runs is the bytes whose digest matched the pin."""
    path = supply_chain.harness_path(tooling, name)
    try:
        if path.is_symlink() or not path.is_file():
            return None, f"harness {name!r} has no file"
        data = path.read_bytes()
    except OSError as exc:
        return None, f"harness {name!r} is unreadable ({type(exc).__name__})"
    if supply_chain.file_sha256(data) != row["sha256"]:
        return None, f"harness {name!r} does not match its pin"
    try:
        tree = ast.parse(data, filename=str(path))
    except (SyntaxError, ValueError):
        return None, f"harness {name!r} does not parse"
    problem = harness_import_problem(tree)
    if problem:
        return None, f"harness {name!r} is refused: {problem}"
    namespace: dict = {"__name__": f"mcp_gateway.harnesses.{name}", "__file__": str(path)}
    try:
        exec(compile(tree, str(path), "exec"), namespace)  # noqa: S102 -- the pinned, reviewed bytes only
    except (Exception, SystemExit) as exc:  # fail closed: a harness that cannot load is not run
        return None, f"harness {name!r} failed to load ({type(exc).__name__})"
    run = namespace.get("run")
    if not callable(run):
        return None, f"harness {name!r} defines no run(tool, arguments, request)"
    return run, None


# -- the gateway ---------------------------------------------------------


def _timestamp(now: int) -> Optional[str]:
    if not P.is_int(now) or not 0 <= now <= decide.MAX_EPOCH:
        return None
    return datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _tool_result(structured: dict, text: str, is_error: bool) -> dict:
    return {"content": [{"type": "text", "text": text}], "structuredContent": structured, "isError": is_error}


def _refused(request_id: str, tool: str, reason: str) -> dict:
    return _tool_result({"disposition": "REFUSED", "request_id": request_id, "tool": tool, "reason": reason},
                        f"{reason}; nothing was run", True)


class AppGateway:
    def __init__(self, root: Any, session_path: Any, evidence_dir: Any, *,
                 policy_path: Any = P.DEFAULT_PATH, catalog_path: Any = DEFAULT_CATALOG,
                 register_path: Any = apps_mod.DEFAULT_PATH, clock: Optional[Callable[[], int]] = None,
                 runner: Optional[Runner] = None, endpoint_path: Any = None, pins_path: Any = DEFAULT_PINS,
                 tooling: Any = TOOLING, kind: str = session_mod.PRINCIPAL_KIND):
        if kind not in session_mod.SESSION_KINDS:
            raise GatewayError(f"a session kind is one of {list(session_mod.SESSION_KINDS)}")
        self.kind = kind  # "agent" for the MCP server (main), "service" only for the perform step (Amendment 032)
        self.root = Path(root)
        if not self.root.is_dir():
            raise GatewayError("--root is not a directory")
        evidence = Path(evidence_dir)
        if not evidence.is_dir() or evidence.is_symlink():
            raise GatewayError("--evidence-dir is not a directory")
        if any(_inside(e, r) for e in (evidence.absolute(), evidence.resolve())
               for r in (self.root.absolute(), self.root.resolve())):
            raise GatewayError("--evidence-dir lies inside the checkout")
        self.log_path = evidence / DECISIONS_FILE
        self.known = tuple(v for v in (os.environ.get(k, "") for k in KNOWN_SECRET_ENV)
                           if len(v) >= boundary_detector.MIN_KNOWN)
        self.clock = clock or (lambda: int(time.time()))
        self.started = self.clock()
        self.runner = runner  # tests only: stands in for every pinned harness
        try:
            self.shipped_policy = P.load_file(Path(policy_path))
        except P.PolicyError as exc:
            raise GatewayError(f"fabric policy is unavailable or malformed: {exc}") from None
        try:
            self.register = apps_mod.load_file(Path(register_path))
        except apps_mod.AppsError as exc:
            raise GatewayError(f"app register is unavailable or malformed: {exc}") from None
        check_register(self.shipped_policy, self.register)
        self.tools = load_catalog(catalog_path, self.shipped_policy, self.register, kind)
        self._by_name = {t.name: t for t in self.tools}
        try:
            pinned = supply_chain.read_pins(Path(pins_path))["harnesses"]
        except (OSError, supply_chain.SupplyChainError) as exc:
            raise GatewayError(f"the pins table is unavailable or malformed: {exc}") from None
        by_app = {row["app"]: (name, row) for name, row in pinned.items()}
        for t in self.tools:
            if t.app not in by_app:
                raise GatewayError(f"tool {t.name!r}: app {t.app!r} has no pinned harness; a harness is pinned before "
                                   "its tools enter the catalog")
        self.routes = egress_proxy.load_app_routes(self.register)
        # app -> (harness name, its pinned SHA-256, run or None, why it is not run)
        self.harnesses: dict = {}
        for app in sorted({t.app for t in self.tools}):
            name, row = by_app[app]
            run, problem = load_harness(Path(tooling), name, row)
            self.harnesses[app] = (name, row["sha256"], run, problem)
        self.session: Optional[session_mod.Session] = None
        self.policy: Optional[dict] = None
        self.session_problem: Optional[str] = None
        try:
            session = session_mod.load(session_path, self.root, kind=kind)
            self.policy = session_mod.overlay(self.shipped_policy, session, self.register)
            self.session = session
        except session_mod.SessionError as exc:
            self.session_problem = str(exc)
        self._calls = 0
        self._app_calls: dict = {}
        # The run's drafted list (Amendment 031), beside the log. A gateway started again in the same session keeps
        # the list it finds; any other list there, or a malformed one, refuses every draft.
        self.drafts_path = evidence / DRAFTS_FILE
        self._drafts: List[dict] = []
        self.drafts_problem: Optional[str] = None
        if self.drafts_path.exists() or self.drafts_path.is_symlink():
            try:
                found, _ = read_drafts(self.drafts_path)
                if self.session is None or found["session"] != self.session.session_id:
                    raise GatewayError("the drafted list there is another session's")
                self._drafts = list(found["calls"])
            except GatewayError as exc:
                self.drafts_problem = str(exc)
        # The app endpoint (Amendment 028): its port and this run's stand-in, written by run_agent before the runtime
        # started. A harness reaches its app only through it (_harness_request); while it is missing or malformed,
        # the gateway still starts, and no harness request could leave.
        self.endpoint, self.endpoint_problem = read_endpoint(endpoint_path, self.root)
        if self.session is not None and self.session.app_catalog_sha256:
            loaded = catalog_digest(catalog_path)
            if loaded != self.session.app_catalog_sha256:
                if self.session.app_catalog_mode == "enforce":
                    raise GatewayError(f"the app catalog is not the one this session was bound against "
                                       f"(bound {self.session.app_catalog_sha256}, loaded {loaded})")
                self._append({"entry": "catalog_pin", "expected": self.session.app_catalog_sha256,
                              "loaded": loaded, "mode": self.session.app_catalog_mode})

    # -- decisions ---------------------------------------------------------

    def _request_id(self, label: str) -> str:
        if self.session is None:
            return f"app-gateway.{label}"
        return f"{self.session.mission_id}.r{self.session.round}.app.{label}"

    def build_request(self, request_id: str, tool: AppTool, capabilities: Iterable[str]) -> dict:
        """The full fabric request for one harness tool under this session, stating what is true of it."""
        s = self.session
        return {
            "request_id": request_id,
            "principal": {"id": s.principal, "kind": s.kind},
            "acting_identity": s.acting_identity,
            "session": {"id": s.session_id, "principal": s.principal, "acting_identity": s.acting_identity,
                        "mission": s.mission_id, "issued_at": s.issued_at, "expires_at": s.expires_at},
            "role": s.role,
            "mission": {"id": s.mission_id, "authority_ref": s.authority_ref},
            "resource": {"class": APP_CLASS, "id": tool.resource},
            "action": tool.action,
            "connector": {"id": CONNECTOR_ID, "capabilities": sorted(set(capabilities)), "credential_bearing": False},
            "evidence": {"can_produce": list(CAN_PRODUCE)},
            "implicates": list(IMPLICATES),
        }

    def _session_denial(self, request: Optional[dict], request_id: str, now: int, reason: str) -> decide.Decision:
        policy = self.policy or self.shipped_policy
        answers = auth_records.blank_answers()
        answers["stop_conditions"] = {"cleared": [12], "triggered": SESSION_STOP}
        record = auth_records.make_record(
            request_id=request_id,
            request_digest=auth_records.digest(request) if request is not None else None,
            policy_version=policy["policy_version"], policy_digest=auth_records.digest(policy),
            timestamp=_timestamp(now), disposition=decide.DENY, failed_step="identity",
            stop_condition={"number": SESSION_STOP, "text": decide.STOP_CONDITIONS[SESSION_STOP]},
            reason=reason, answers=answers)
        return decide.Decision(decide.DENY, "identity", SESSION_STOP, reason, record)

    def evaluate(self, tool: AppTool, capabilities: Iterable[str] = (), now: Optional[int] = None,
                 request_id: str = "probe") -> Tuple[Optional[dict], decide.Decision]:
        """Decide one harness tool for this session; nothing is run or logged."""
        now = self.clock() if now is None else now
        if self.session is None:
            return None, self._session_denial(None, request_id, now,
                                              f"session context cannot be validated: {self.session_problem}")
        request = self.build_request(request_id, tool, capabilities)
        if not self.session.live_at(now):
            return request, self._session_denial(request, request_id, now, "session is outside its time bounds")
        return request, decide.evaluate(request, self.policy, now)

    def listed_tools(self, now: Optional[int] = None) -> List[AppTool]:
        """The catalog tools the fabric allows for this session, each probed with only its own action."""
        now = self.clock() if now is None else now
        if self.session is None or not self.session.live_at(now):
            return []
        return [t for t in self.tools
                if self.evaluate(t, [t.action], now, self._request_id(f"list.{t.name}"))[1].allowed]

    def bound_problem(self, tool: AppTool, now: int) -> Optional[str]:
        """Why one more call of ``tool`` would pass the run's bounds (the register's, or the app's lower ones)."""
        limits = [self.register["bounds"]]
        own = self.register["apps"][tool.app]["bounds"]
        if own is not None:
            limits.append(own)
        minutes = min(b["minutes"] for b in limits)
        if now - self.started >= minutes * 60:
            return f"the run's {minutes} minutes for harness calls have passed"
        if self._calls >= self.register["bounds"]["calls"]:
            return f"the run's {self.register['bounds']['calls']} harness calls are spent"
        if own is not None and self._app_calls.get(tool.app, 0) >= own["calls"]:
            return f"app {tool.app!r}'s {own['calls']} calls for this run are spent"
        return None

    # -- evidence ----------------------------------------------------------

    def _append(self, entry: Mapping) -> None:
        """Append one entry, secrets redacted: the log leaves the run with its artifact. Unwritable is OSError."""
        admitted = boundary.admit_context(json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
                                          self.known)
        if not admitted.allow:
            raise OSError("the secrets boundary failed on an evidence entry")
        with open(self.log_path, "a", encoding="utf-8") as handle:
            handle.write(admitted.text + "\n")
            handle.flush()

    def _mission(self) -> Optional[dict]:
        return self.session.mission_evidence() if self.session else None

    # -- MCP surface -------------------------------------------------------

    def list_tools(self) -> List[dict]:
        return [t.listing() for t in self.listed_tools()]

    def call_tool(self, name: str, arguments: Mapping) -> dict:
        now = self.clock()
        request_id = self._request_id(f"call-{self._calls + 1}")
        tool = self._by_name.get(name)
        try:
            if tool is None:
                self._append({"entry": "refusal", "request_id": request_id, "tool": name, "mission": self._mission(),
                              "timestamp": _timestamp(now), "reason": "tool is not in the app catalog"})
                return _refused(request_id, name, f"tool {name!r} is not served by this gateway")
            over = self.bound_problem(tool, now)
            if over:
                self._append({"entry": "bound", "request_id": request_id, "tool": tool.name, "app": tool.app,
                              "kind": tool.kind, "mission": self._mission(), "timestamp": _timestamp(now),
                              "reason": over})
                return _refused(request_id, tool.name, over)
            self._calls += 1
            self._app_calls[tool.app] = self._app_calls.get(tool.app, 0) + 1
            listed = self.listed_tools(now)
            capabilities = {t.action for t in listed if t.resource == tool.resource} | {tool.action}
            request, decision = self.evaluate(tool, capabilities, now, request_id)
            self._append({"entry": "decision", "request_id": request_id, "tool": tool.name, "app": tool.app,
                          "kind": tool.kind, "arguments_sha256": arguments_digest(arguments),
                          "draft": bool(tool.performs), "mission": self._mission(),
                          "session": self.session.session_id if self.session else None,
                          "request": request, "record": decision.record,
                          "link": auth_records.link_material(decision.record)})
        except OSError:
            return _refused(request_id, name, "the evidence log cannot be written")
        if not decision.allowed:
            return self._denied(request_id, tool, decision)
        problem = argument_problem(tool.input_schema, arguments)
        if problem:
            raise protocol.RpcError(protocol.INVALID_PARAMS, f"invalid params: {problem}")
        if tool.performs:
            return self._draft(request_id, tool, arguments, decision, now)
        harness, harness_sha, run, problem = (None, None, None, None) if self.runner else self.harnesses[tool.app]
        if problem:
            try:
                self._append({"entry": "harness", "request_id": request_id, "tool": tool.name, "app": tool.app,
                              "mission": self._mission(), "harness": harness, "reason": problem})
            except OSError:
                pass
            return _refused(request_id, tool.name, problem)
        sent = [0]
        try:
            if self.runner is not None:
                text = self.runner(tool, dict(arguments))
            else:
                text = run(tool.name, dict(arguments), self._harness_request(tool, sent))
            if not isinstance(text, str):
                raise TypeError("a harness result must be text")
        except (Exception, SystemExit) as exc:  # fail closed: a harness defect returns nothing
            entry = {"entry": "result_error", "request_id": request_id, "tool": tool.name, "app": tool.app,
                     "mission": self._mission(), "harness": harness, "requests": sent[0],
                     "reason": type(exc).__name__}
            if isinstance(exc, HarnessError):
                entry["detail"] = str(exc)  # the gateway's own words, never the app's
            try:
                self._append(entry)
            except OSError:
                pass
            return _refused(request_id, tool.name, f"the harness failed ({type(exc).__name__})")
        held = quarantine.quarantine(text, f"app {tool.app}", f"harness tool {tool.name}", MAX_RESULT_CHARS)
        try:
            self._append({"entry": "result", "request_id": request_id, "tool": tool.name, "app": tool.app,
                          "mission": self._mission(), "harness": harness, "harness_sha256": harness_sha,
                          "requests": sent[0], "result_sha256": signing.sha256_hex(text.encode("utf-8")),
                          "steering_lines": len(held.hits), "hidden_removed": held.removed, "cut": held.cut})
        except OSError:
            return _refused(request_id, tool.name, "the evidence log cannot be written; the result is withheld")
        grant = decision.record["answers"]["sot_authority"]["grant"]
        structured = {"disposition": decide.ALLOW, "request_id": request_id, "tool": tool.name, "app": tool.app,
                      "grant": grant["id"], "result": held.text}
        return self._admitted(request_id, tool, structured, now)

    def _draft(self, request_id: str, tool: AppTool, arguments: Mapping, decision: decide.Decision, now: int) -> dict:
        """Add the exact call to the run's drafted list (Amendment 031). Nothing is sent and the harness does not
        run: the perform step makes the call only after HITL's command names the list's digest."""
        call = {"app": tool.app, "tool": tool.name, "kind": tool.kind, "action": tool.performs,
                "resource": tool.resource, "arguments": dict(arguments)}
        text = json.dumps(call["arguments"], sort_keys=True, ensure_ascii=False)
        problem = self.drafts_problem
        if problem is None and len(self._drafts) >= MAX_DRAFTS:
            problem = f"a run drafts at most {MAX_DRAFTS} calls"
        if problem is None and len(text) > MAX_DRAFT_ARGUMENTS:
            problem = f"a drafted call's arguments are at most {MAX_DRAFT_ARGUMENTS} characters"
        if problem is None:
            admitted = boundary.admit_context(text, self.known)
            if not admitted.allow or admitted.text != text:
                problem = "the secrets boundary found a secret in the arguments; nothing is drafted"
        if problem is None and self.session is None:
            problem = "no session"
        if problem is None:
            doc = {"schema": DRAFTS_SCHEMA, "mission": self.session.mission_id, "session": self.session.session_id,
                   "calls": self._drafts + [call]}
            try:
                partial = self.drafts_path.with_name(DRAFTS_FILE + ".part")
                partial.write_text(json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n",
                                   encoding="utf-8")
                os.replace(partial, self.drafts_path)
            except OSError:
                problem = "the drafted list cannot be written"
        try:
            if problem is not None:
                self._append({"entry": "draft_refused", "request_id": request_id, "tool": tool.name,
                              "app": tool.app, "mission": self._mission(), "reason": problem})
                return _refused(request_id, tool.name, problem)
            self._drafts.append(call)
            self._append({"entry": "draft", "request_id": request_id, "tool": tool.name, "app": tool.app,
                          "mission": self._mission(), "index": len(self._drafts),
                          "drafts_sha256": drafts_digest(doc)})
        except OSError:
            return _refused(request_id, tool.name, "the evidence log cannot be written")
        grant = decision.record["answers"]["sot_authority"]["grant"]
        note = (f"Drafted as call {len(self._drafts)} of this run's list. Nothing was sent: HITL performs the "
                "list only by a command naming its digest.")
        structured = {"disposition": decide.ALLOW, "request_id": request_id, "tool": tool.name, "app": tool.app,
                      "grant": grant["id"], "drafted": len(self._drafts), "result": note}
        return self._admitted(request_id, tool, structured, now)

    def perform(self, call: Mapping) -> dict:
        """Make one call of a drafted list, in a ``service`` session only (Amendment 032). The call must name a
        served tool exactly as the catalog has it now (its app, class, action and resource); it is then made as
        any call is: bounds, the fabric's decision as its own action, the pinned harness, the quarantine and the
        secrets boundary. A call that names anything else is refused and logged as a ``refusal``."""
        if self.kind != SERVICE_KIND:
            raise GatewayError("only the perform step's service session makes a drafted call")
        name = str(call.get("tool", "")) if isinstance(call, Mapping) else ""
        tool = self._by_name.get(name)
        if tool is None or (tool.app, tool.kind, tool.action, tool.resource) != tuple(
                call.get(k) for k in ("app", "kind", "action", "resource")):
            now = self.clock()
            request_id = self._request_id(f"call-{self._calls + 1}")
            reason = ("the drafted call names no tool this gateway performs" if tool is None
                      else "the drafted call does not match its tool in the app catalog")
            try:
                self._append({"entry": "refusal", "request_id": request_id, "tool": name, "mission": self._mission(),
                              "timestamp": _timestamp(now), "reason": reason})
            except OSError:
                pass
            return _refused(request_id, name, reason)
        arguments = call.get("arguments")
        try:
            return self.call_tool(tool.name, arguments if isinstance(arguments, Mapping) else {})
        except protocol.RpcError as exc:
            return _refused(self._request_id(f"call-{self._calls}"), tool.name, str(exc))

    def _harness_request(self, tool: AppTool, sent: List[int]) -> Callable[..., Tuple[int, str]]:
        """The one way a harness reaches its app, for one call of ``tool``: ``request(method, host, path, query="",
        body=None) -> (status, text)``. Only a request the register lists for the tool's app, of the tool's own
        class, to one of the app's hosts, is sent, to the app endpoint with the run's stand-in."""
        route = self.routes[tool.app]

        def request(method: str, host: str, path: str, query: str = "", body: Optional[str] = None) -> Tuple[int, str]:
            if sent[0] >= MAX_HARNESS_REQUESTS:
                raise HarnessError(f"a call makes at most {MAX_HARNESS_REQUESTS} requests")
            if not (all(isinstance(v, str) for v in (method, host, path, query))
                    and (body is None or isinstance(body, str)) and path.startswith("/")):
                raise HarnessError("method, host, path and query must be text, the path starting with /")
            if host not in route.hosts:
                raise HarnessError("that host is not listed for the app")
            found = route.match(method, path)
            if found is None:
                raise HarnessError(f"{method} is not a listed request of the app")
            if found[1] != tool.kind:
                raise HarnessError(f"a {tool.kind} tool makes only {tool.kind} requests, not {found[1]}")
            if self.endpoint is None:
                raise HarnessError(f"no app endpoint in this run ({self.endpoint_problem})")
            payload = b"" if body is None else body.encode("utf-8")
            if len(payload) > MAX_HARNESS_BODY:
                raise HarnessError(f"the request is larger than {MAX_HARNESS_BODY} bytes")
            port, standin = self.endpoint
            headers = {"Host": f"127.0.0.1:{port}", "Authorization": f"Bearer {standin}",
                       "Content-Length": str(len(payload))}
            if body is not None:
                headers["Content-Type"] = "application/json; charset=utf-8"
            sent[0] += 1
            target = f"{egress_proxy.APP_PREFIX}/{tool.app}/{host}{path}" + (f"?{query}" if query else "")
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=HARNESS_TIMEOUT)
            try:
                connection.request(method, target, body=payload, headers=headers)
                answer = connection.getresponse()
                data = answer.read(MAX_HARNESS_ANSWER + 1)
                status = answer.status
            except (OSError, http.client.HTTPException) as exc:
                raise HarnessError(f"the app endpoint did not answer ({type(exc).__name__})") from None
            finally:
                connection.close()
            if len(data) > MAX_HARNESS_ANSWER:
                raise HarnessError(f"the answer is larger than {MAX_HARNESS_ANSWER} bytes")
            return status, data.decode("utf-8", "replace")

        return request

    def _admitted(self, request_id: str, tool: AppTool, structured: dict, now: int) -> dict:
        """The secrets boundary's context check: every secret in a result is redacted before the agent sees it."""
        admitted = boundary.admit_context(json.dumps(structured, sort_keys=True), self.known)
        try:
            self._append({"entry": "boundary", "request_id": request_id, "tool": tool.name,
                          "mission": self._mission(), "record": boundary_records.record(admitted, now)})
        except OSError:
            return _refused(request_id, tool.name, "the evidence log cannot be written; the result is withheld")
        if not admitted.allow:
            return _refused(request_id, tool.name, "the secrets boundary failed; the result is withheld")
        try:
            redacted = json.loads(admitted.text)
        except ValueError:
            return _refused(request_id, tool.name, "the redacted result is not JSON; the result is withheld")
        return _tool_result(redacted, redacted["result"], False)

    @staticmethod
    def _denied(request_id: str, tool: AppTool, decision: decide.Decision) -> dict:
        stop = decision.stop_condition
        why = (f"stop condition {stop}: {decide.STOP_CONDITIONS[stop]}" if stop
               else "no stop condition applies")
        structured = {"disposition": decide.DENY, "request_id": request_id, "tool": tool.name, "app": tool.app,
                      "failed_step": decision.step, "stop_condition": decision.record["stop_condition"],
                      "reason": decision.reason}
        text = f"DENY at step {decision.step!r}, {why} ({decision.reason}); nothing was run"
        return _tool_result(structured, text, True)


class AppEndpoint(protocol.Endpoint):
    """The shared framing, with the app gateway's own name: ``initialize`` reports ``governed-apps``."""

    def _initialize(self, params: dict) -> dict:
        answer = super()._initialize(params)
        answer["serverInfo"] = {"name": SERVER_NAME, "version": SERVER_VERSION}
        return answer


ENDPOINT_FIELDS = frozenset({"port", "standin"})
MAX_ENDPOINT_BYTES = 4096


def read_endpoint(path: Any, root: Path) -> Tuple[Optional[Tuple[int, str]], Optional[str]]:
    """``((port, standin), None)`` from the app endpoint file at ``path``, or ``(None, why)``. The file must lie
    outside the checkout, be a regular file, and hold exactly a loopback port and a stand-in (Amendment 028)."""
    if path is None:
        return None, "no app endpoint was given"
    path = Path(path)
    try:
        if any(_inside(c, r) for c in (path.absolute(), path.resolve()) for r in (root.absolute(), root.resolve())):
            return None, "the app endpoint file lies inside the checkout"
        if path.is_symlink() or not path.is_file():
            return None, "the app endpoint file is missing or not a regular file"
        data = path.read_bytes()
        if len(data) > MAX_ENDPOINT_BYTES:
            return None, "the app endpoint file is too large"
        doc = json.loads(data.decode("utf-8"))
    except (OSError, ValueError) as exc:
        return None, f"the app endpoint file is unreadable ({type(exc).__name__})"
    if not (isinstance(doc, dict) and set(doc) == ENDPOINT_FIELDS and isinstance(doc["port"], int)
            and not isinstance(doc["port"], bool) and 0 < doc["port"] < 65536 and isinstance(doc["standin"], str)
            and 16 <= len(doc["standin"]) <= 200 and doc["standin"].isprintable() and " " not in doc["standin"]):
        return None, "the app endpoint file must hold exactly a port and a stand-in"
    return (doc["port"], doc["standin"]), None


def main(argv=None) -> int:
    """``python3 -m mcp_gateway.app_gateway --root CHECKOUT --session FILE --evidence-dir DIR [--endpoint FILE]``;
    exit 2 when the
    app gateway refuses to start (the reason on stderr), 0 at end of input."""
    parser = argparse.ArgumentParser(prog="mcp_gateway.app_gateway", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", required=True)
    parser.add_argument("--session", required=True)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--endpoint", default=None, help="the app endpoint file run_agent writes (Amendment 028)")
    args = parser.parse_args(argv)
    try:
        gateway = AppGateway(args.root, args.session, args.evidence_dir, endpoint_path=args.endpoint)
    except GatewayError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    protocol.serve(AppEndpoint(gateway), sys.stdin.buffer, sys.stdout.buffer)
    return 0


if __name__ == "__main__":
    sys.exit(main())
