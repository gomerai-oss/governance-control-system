"""The governed-retrieval gateway: every tool call decided by the authorization fabric.

``Gateway(root, session_path, evidence_dir)`` loads, at start:

- the shipped fabric policy (``mcp_auth/policy.json``) and corpus registry
  (``retrieval/corpus.json``) from the gateway's own tree, never from the
  agent-writable checkout;
- the tool catalog (``tools.json``), which refuses to start when a tool names
  an action of kind ``write`` or ``execute``, an action outside its resource's
  read set, or a corpus scope the registry does not resolve;
- the launcher's session file, and from it the per-session policy overlay
  (``session.py``). An invalid session does not stop the server; it makes every
  call DENY with stop 13.

``list_tools()`` returns only the catalog tools the fabric would allow for this
session, so the connector surface is never broader than the session's grants
(stop 1 by construction). ``call_tool(name, arguments)`` builds the full fabric
request, evaluates it with ``mcp_auth.decide.evaluate`` at the server's clock,
appends the decision to ``decisions.jsonl`` in the evidence directory, and only
on ``ALLOW`` runs ``retrieval.retrieve`` over the tool's corpus scope, or, for
the ``trace`` tool (action ``epap.artifact_lookup``), asks the evidence graph which
first-parent changes made one file what it is at the checkout's ``HEAD``. A DENY
runs nothing and is never turned into a narrower ALLOW.

``Gateway(..., git_dir=DIR)`` names the checkout's git dir when it lies outside the
work tree (the dispatcher's layout); without it, ``trace`` reads ``root`` itself.

Each line of ``decisions.jsonl`` is one JSON object with an ``entry`` field:

``decision``         ``request_id``, ``tool``, ``mission`` (id, authority_ref,
                     base_sha, round; null without a valid session), ``session``,
                     ``request`` (the fabric request, or null), ``record`` (the
                     ``mcp-auth-decision-v1`` record) and ``link`` (its
                     ``MCP_AUTH_DECISION`` link material)
``retrieval``        after an ALLOW: ``request_id``, ``tool``, ``mission``,
                     ``retrieval_request`` and ``link`` (the ``RETRIEVAL`` link material)
``retrieval_error``  after an ALLOW whose retrieval failed: nothing was returned
``trace``            after an ALLOW of ``trace``: ``request_id``, ``tool``, ``mission``,
                     ``path``, ``head`` and ``changes`` (how many were returned)
``trace_error``      after an ALLOW whose trace failed: nothing was returned
``refusal``          a call naming no catalog tool: no action to decide, nothing run
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, List, Mapping, Optional, Tuple

from evidence_graph import __main__ as evidence_cli
from evidence_graph import graph as evidence_graph
from evidence_graph import history as evidence_history
from mcp_auth import decide
from mcp_auth import policy as P
from mcp_auth import records as auth_records
from retrieval import corpus as corpus_mod
from retrieval import records as retrieval_records
from retrieval import retrieve

from secrets_boundary import gate as boundary
from secrets_boundary import records as boundary_records

from mcp_gateway import protocol
from mcp_gateway import session as session_mod

CATALOG_SCHEMA = "mcp-gateway-tools-v1"
DEFAULT_CATALOG = Path(__file__).resolve().with_name("tools.json")
DECISIONS_FILE = "decisions.jsonl"
CONNECTOR_ID = protocol.SERVER_NAME
CAN_PRODUCE = ("audit_record",)
SESSION_STOP = 13
TRACE_ACTION = "epap.artifact_lookup"
TRACE_SCHEMA = "evidence-trace-v1"

CATALOG_FIELDS = frozenset({"schema", "catalog_version", "tools"})
TOOL_FIELDS = frozenset({"name", "description", "action", "resource", "corpus_scope", "retrieval_method",
                         "input_schema"})
SCHEMA_FIELDS = frozenset({"type", "properties", "required", "additionalProperties", "minProperties"})
# Tool arguments: ``query`` is the claim text; every other argument is a retrieval constraint.
QUERY_ARGUMENT = "query"
STRING_ARGUMENTS = ("query", "document_id", "path", "location", "status", "title", "date", "alias")
LIST_ARGUMENTS = ("keywords",)
_TOOL_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")


class GatewayError(RuntimeError):
    """The gateway refuses to start."""


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    action: str
    resource: str
    corpus_scope: Tuple[str, ...]
    retrieval_method: Optional[str]
    input_schema: dict

    def listing(self) -> dict:
        return {"name": self.name, "description": self.description,
                "inputSchema": json.loads(json.dumps(self.input_schema))}


# -- catalog -------------------------------------------------------------


def _check_input_schema(schema: Any, where: str) -> dict:
    if not isinstance(schema, dict) or not set(schema) <= SCHEMA_FIELDS or schema.get("type") != "object":
        raise GatewayError(f"{where}: input_schema must be an object schema using only {sorted(SCHEMA_FIELDS)}")
    if schema.get("additionalProperties") is not False:
        raise GatewayError(f"{where}: input_schema must set additionalProperties to false")
    properties = schema.get("properties")
    if not isinstance(properties, dict) or not properties:
        raise GatewayError(f"{where}: input_schema must declare its properties")
    for name, prop in properties.items():
        if name in STRING_ARGUMENTS:
            ok = isinstance(prop, dict) and prop.get("type") == "string" and set(prop) <= {"type", "description"}
        elif name in LIST_ARGUMENTS:
            ok = (isinstance(prop, dict) and prop.get("type") == "array" and prop.get("items") == {"type": "string"}
                  and set(prop) <= {"type", "items", "minItems", "description"}
                  and P.is_int(prop.get("minItems", 1)) and prop.get("minItems", 1) >= 1)
        else:
            ok = False
        if not ok:
            raise GatewayError(f"{where}: input_schema property {name!r} is not a known argument of its type")
    required = schema.get("required", [])
    if not isinstance(required, list) or not all(r in properties for r in required):
        raise GatewayError(f"{where}: input_schema required names an undeclared property")
    minimum = schema.get("minProperties", 0)
    if not P.is_int(minimum) or minimum < 0:
        raise GatewayError(f"{where}: input_schema minProperties must be a non-negative integer")
    return schema


def load_catalog(path: Any, policy: Mapping, registry: corpus_mod.CorpusRegistry) -> List[Tool]:
    """The validated tool catalog; any defect, or any non-read action, refuses to start."""
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise GatewayError(f"tool catalog is unreadable or not JSON: {exc}") from None
    if not isinstance(doc, dict) or set(doc) != CATALOG_FIELDS or doc["schema"] != CATALOG_SCHEMA:
        raise GatewayError(f"tool catalog must be {CATALOG_SCHEMA!r} with exactly {sorted(CATALOG_FIELDS)}")
    if not P.is_name(doc["catalog_version"]):
        raise GatewayError("tool catalog catalog_version must be a non-empty string")
    entries = doc["tools"]
    if not isinstance(entries, list) or not entries:
        raise GatewayError("tool catalog must list at least one tool")
    tools: List[Tool] = []
    for i, entry in enumerate(entries):
        where = f"tools[{i}]"
        if not isinstance(entry, dict) or set(entry) != TOOL_FIELDS:
            raise GatewayError(f"{where} must have exactly {sorted(TOOL_FIELDS)}")
        name = entry["name"]
        if not isinstance(name, str) or not _TOOL_NAME.fullmatch(name) or any(t.name == name for t in tools):
            raise GatewayError(f"{where}: tool name must be a distinct lowercase identifier")
        if not P.is_name(entry["description"]):
            raise GatewayError(f"{where}: description must be a non-empty string")
        action = entry["action"]
        kind = policy["actions"].get(action, {}).get("kind") if isinstance(action, str) else None
        if kind is None:
            raise GatewayError(f"{where}: action {action!r} is not in the fabric's action catalog")
        if kind != "read":
            raise GatewayError(f"{where}: action {action!r} is of kind {kind!r}; the gateway serves read actions only")
        resource = entry["resource"]
        res = policy["resources"].get(resource) if isinstance(resource, str) else None
        if res is None:
            raise GatewayError(f"{where}: resource {resource!r} is not known to policy")
        if action not in policy["classes"][res["class"]]["read"]:
            raise GatewayError(f"{where}: action {action!r} is not a read action of class {res['class']!r}")
        scope = entry["corpus_scope"]
        if not isinstance(scope, list) or not scope or not all(isinstance(c, str) and c for c in scope):
            raise GatewayError(f"{where}: corpus_scope must be a non-empty list of corpus ids")
        try:
            registry.resolve_scope(scope)
        except corpus_mod.CorpusError as exc:
            raise GatewayError(f"{where}: corpus scope does not resolve: {exc}") from None
        method = entry["retrieval_method"]
        if method is not None and method not in retrieval_records.RETRIEVAL_METHODS:
            raise GatewayError(f"{where}: retrieval_method must be null or a retrieval stage name")
        tools.append(Tool(name=name, description=entry["description"], action=action, resource=resource,
                          corpus_scope=tuple(scope), retrieval_method=method,
                          input_schema=_check_input_schema(entry["input_schema"], where)))
    return tools


def argument_problem(schema: Mapping, arguments: Any) -> Optional[str]:
    """Why ``arguments`` do not satisfy a catalog input schema, or None."""
    if not isinstance(arguments, dict):
        return "arguments must be an object"
    properties = schema["properties"]
    unknown = sorted(k for k in arguments if k not in properties)
    if unknown:
        return f"unknown arguments {unknown}"
    missing = sorted(r for r in schema.get("required", []) if r not in arguments)
    if missing:
        return f"missing arguments {missing}"
    if len(arguments) < schema.get("minProperties", 0):
        return f"at least {schema['minProperties']} argument(s) required"
    for key, value in arguments.items():
        prop = properties[key]
        if prop["type"] == "string" and not isinstance(value, str):
            return f"argument {key!r} must be a string"
        if prop["type"] == "array" and (not isinstance(value, list) or not all(isinstance(v, str) for v in value)
                                        or len(value) < prop.get("minItems", 1)):
            return f"argument {key!r} must be a non-empty list of strings"
    return None


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


def _load_registry(corpus_registry: Any) -> corpus_mod.CorpusRegistry:
    try:
        if corpus_registry is None:
            return corpus_mod.load_registry(corpus_mod.default_registry_path())
        if isinstance(corpus_registry, corpus_mod.CorpusRegistry):
            return corpus_registry
        return corpus_mod.load_registry(Path(corpus_registry))
    except (OSError, UnicodeDecodeError, corpus_mod.CorpusError) as exc:
        raise GatewayError(f"corpus registry is unavailable or malformed: {exc}") from None


def _tool_result(structured: dict, text: str, is_error: bool) -> dict:
    return {"content": [{"type": "text", "text": text}], "structuredContent": structured, "isError": is_error}


def _refused(request_id: str, tool: str, reason: str) -> dict:
    return _tool_result({"disposition": "REFUSED", "request_id": request_id, "tool": tool, "reason": reason},
                        f"{reason}; nothing was run", True)


class Gateway:
    def __init__(self, root: Any, session_path: Any, evidence_dir: Any, *,
                 policy_path: Any = P.DEFAULT_PATH, catalog_path: Any = DEFAULT_CATALOG,
                 corpus_registry: Any = None, clock: Optional[Callable[[], int]] = None, git_dir: Any = None):
        self.root = Path(root)
        if not self.root.is_dir():
            raise GatewayError("--root is not a directory")
        self.git_dir = Path(git_dir) if git_dir is not None else None
        if self.git_dir is not None and not self.git_dir.is_dir():
            raise GatewayError("--git-dir is not a directory")
        self._history: Optional[Tuple[str, Any, list]] = None
        evidence = Path(evidence_dir)
        if not evidence.is_dir() or evidence.is_symlink():
            raise GatewayError("--evidence-dir is not a directory")
        if any(_inside(e, r) for e in (evidence.absolute(), evidence.resolve())
               for r in (self.root.absolute(), self.root.resolve())):
            raise GatewayError("--evidence-dir lies inside the checkout")
        self.log_path = evidence / DECISIONS_FILE
        self.clock = clock or (lambda: int(time.time()))
        try:
            self.shipped_policy = P.load_file(Path(policy_path))
        except P.PolicyError as exc:
            raise GatewayError(f"fabric policy is unavailable or malformed: {exc}") from None
        self.registry = _load_registry(corpus_registry)
        self.tools = load_catalog(catalog_path, self.shipped_policy, self.registry)
        self._by_name = {t.name: t for t in self.tools}
        self.session: Optional[session_mod.Session] = None
        self.policy: Optional[dict] = None
        self.session_problem: Optional[str] = None
        try:
            session = session_mod.load(session_path, self.root)
            self.policy = session_mod.overlay(self.shipped_policy, session)
            self.session = session
        except session_mod.SessionError as exc:
            self.session_problem = str(exc)
        self._calls = 0

    # -- decisions ---------------------------------------------------------

    def _request_id(self, label: str) -> str:
        if self.session is None:
            return f"gateway.{label}"
        return f"{self.session.mission_id}.r{self.session.round}.{label}"

    def build_request(self, request_id: str, action: Any, resource_id: Any, capabilities: Iterable[str]) -> dict:
        """The full fabric request for one action on one resource under this session."""
        s = self.session
        entry = self.policy["resources"].get(resource_id) if isinstance(resource_id, str) else None
        return {
            "request_id": request_id,
            "principal": {"id": s.principal, "kind": session_mod.PRINCIPAL_KIND},
            "acting_identity": s.acting_identity,
            "session": {"id": s.session_id, "principal": s.principal, "acting_identity": s.acting_identity,
                        "mission": s.mission_id, "issued_at": s.issued_at, "expires_at": s.expires_at},
            "role": s.role,
            "mission": {"id": s.mission_id, "authority_ref": s.authority_ref},
            "resource": {"class": entry["class"] if entry else None, "id": resource_id},
            "action": action,
            "connector": {"id": CONNECTOR_ID, "capabilities": sorted(set(capabilities)), "credential_bearing": False},
            "evidence": {"can_produce": list(CAN_PRODUCE)},
            "implicates": [],
        }

    def _session_denial(self, request: Optional[dict], request_id: str, now: int, reason: str) -> decide.Decision:
        """A DENY with stop 13, in the fabric's record format, for a session the gateway cannot bind."""
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

    def evaluate(self, action: Any, resource_id: Any, capabilities: Iterable[str] = (),
                 now: Optional[int] = None, request_id: str = "probe") -> Tuple[Optional[dict], decide.Decision]:
        """Decide one action on one resource for this session; nothing is run or logged."""
        now = self.clock() if now is None else now
        if self.session is None:
            return None, self._session_denial(None, request_id, now,
                                              f"session context cannot be validated: {self.session_problem}")
        request = self.build_request(request_id, action, resource_id, capabilities)
        if not self.session.live_at(now):
            return request, self._session_denial(request, request_id, now, "session is outside its time bounds")
        return request, decide.evaluate(request, self.policy, now)

    def listed_tools(self, now: Optional[int] = None) -> List[Tool]:
        """The catalog tools the fabric allows for this session, each probed with only its own action."""
        now = self.clock() if now is None else now
        if self.session is None or not self.session.live_at(now):
            return []
        return [t for t in self.tools
                if self.evaluate(t.action, t.resource, [t.action], now, self._request_id(f"list.{t.name}"))[1].allowed]

    # -- evidence ----------------------------------------------------------

    def _append(self, entry: Mapping) -> None:
        """Append one entry, secrets redacted: the log leaves the run with its artifact. Unwritable is OSError."""
        admitted = boundary.admit_context(json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
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
        self._calls += 1
        request_id = self._request_id(f"call-{self._calls}")
        tool = self._by_name.get(name)
        try:
            if tool is None:
                self._append({"entry": "refusal", "request_id": request_id, "tool": name, "mission": self._mission(),
                              "timestamp": _timestamp(now), "reason": "tool is not in the catalog"})
                return _refused(request_id, name, f"tool {name!r} is not served by this gateway")

            listed = self.listed_tools(now)
            capabilities = {t.action for t in listed if t.resource == tool.resource} | {tool.action}
            request, decision = self.evaluate(tool.action, tool.resource, capabilities, now, request_id)
            self._append({"entry": "decision", "request_id": request_id, "tool": tool.name,
                          "mission": self._mission(),
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
        if tool.action == TRACE_ACTION:
            return self._trace(request_id, tool, arguments["path"], decision, now)
        try:
            retrieval_request = retrieval_records.make_request(
                request_id,
                query_intent=arguments.get(QUERY_ARGUMENT, ""),
                constraints={k: v for k, v in arguments.items() if k != QUERY_ARGUMENT},
                corpus_scope=list(tool.corpus_scope),
                mission_id=self.session.mission_id,
                retrieval_method=tool.retrieval_method)
            result = retrieve.retrieve(retrieval_request, self.root, self.registry)
            cites = retrieve.citations(result)
            link = retrieve.evidence_link(result)
        except Exception as exc:  # fail closed: a retrieval defect returns nothing
            try:
                self._append({"entry": "retrieval_error", "request_id": request_id, "tool": tool.name,
                              "mission": self._mission(), "reason": type(exc).__name__})
            except OSError:
                pass
            return _refused(request_id, tool.name, f"retrieval failed ({type(exc).__name__})")
        try:
            self._append({"entry": "retrieval", "request_id": request_id, "tool": tool.name,
                          "mission": self._mission(), "retrieval_request": retrieval_request, "link": link})
        except OSError:
            return _refused(request_id, tool.name, "the evidence log cannot be written; the result is withheld")
        grant = decision.record["answers"]["sot_authority"]["grant"]
        structured = {"disposition": decide.ALLOW, "request_id": request_id, "tool": tool.name,
                      "grant": grant["id"], "result": result, "citations": cites}
        return self._admitted(request_id, tool, structured, now)

    def _walk(self) -> Tuple[str, Any, list]:
        """The checkout's first-parent history at ``HEAD``, every landing proved; read once per gateway."""
        if self._history is None:
            if self.git_dir is None and not (self.root / ".git").exists():
                # Never let git search upward from the checkout into some enclosing repository.
                raise evidence_history.GitError("the checkout has no git history of its own")
            repo = evidence_history.Repo(str(self.root), str(self.git_dir) if self.git_dir else None)
            repo.ensure_full_history()
            ids = evidence_history.load_identities()  # the tooling tree's router config, never the checkout's
            head = repo.resolve("HEAD")
            self._history = (head, repo, evidence_graph.walk(repo, ids, head))
        return self._history

    @staticmethod
    def _change(entry: Any) -> dict:
        commit = entry.commit.sha
        if entry.kind == evidence_history.LANDING:
            proof = entry.proof
            final = proof.reviews.get(proof.round)
            return {"kind": "mission", "commit": commit, "mission": proof.mission, "plan": proof.plan_sha,
                    "approval": proof.approval_kind, "round": proof.round,
                    "verdict": final.verdict if final else None,
                    "reviewed_sha": final.reviewed_sha if final else None,
                    "specs": list(proof.specs), "proven": proof.proven, "rules": proof.rules}
        if entry.kind == evidence_history.HAND_MERGE:
            return {"kind": "hand_merge", "commit": commit, "pr": entry.pr, "independent_review": "none"}
        return {"kind": "direct", "commit": commit, "independent_review": "none"}

    def _trace(self, request_id: str, tool: Tool, path: str, decision: decide.Decision, now: int) -> dict:
        """Which first-parent changes made ``path`` what it is, newest first; any defect returns nothing."""
        try:
            head, repo, entries = self._walk()
            repo.prefetch_files([e.commit for e in entries])
            touched = [e for e in reversed(entries) if path in repo.files(e.commit)]
            changes = [self._change(e) for e in touched]
            lines = [evidence_cli.trace_line(e) for e in touched]
        except Exception as exc:  # fail closed, as retrieval does
            try:
                self._append({"entry": "trace_error", "request_id": request_id, "tool": tool.name,
                              "mission": self._mission(), "reason": type(exc).__name__})
            except OSError:
                pass
            return _refused(request_id, tool.name, f"trace failed ({type(exc).__name__})")
        try:
            self._append({"entry": "trace", "request_id": request_id, "tool": tool.name, "mission": self._mission(),
                          "path": path, "head": head, "changes": len(changes)})
        except OSError:
            return _refused(request_id, tool.name, "the evidence log cannot be written; the result is withheld")
        grant = decision.record["answers"]["sot_authority"]["grant"]
        structured = {"disposition": decide.ALLOW, "request_id": request_id, "tool": tool.name,
                      "grant": grant["id"],
                      "result": {"schema": TRACE_SCHEMA, "path": path, "head": head, "changes": changes},
                      "lines": lines}
        return self._admitted(request_id, tool, structured, now)

    def _admitted(self, request_id: str, tool: Tool, structured: dict, now: int) -> dict:
        """The secrets boundary's context check: every secret in a result is redacted before the agent sees it."""
        admitted = boundary.admit_context(json.dumps(structured, sort_keys=True))
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
        return _tool_result(redacted, admitted.text, False)

    @staticmethod
    def _denied(request_id: str, tool: Tool, decision: decide.Decision) -> dict:
        stop = decision.stop_condition
        why = (f"stop condition {stop}: {decide.STOP_CONDITIONS[stop]}" if stop
               else "no stop condition applies")
        structured = {"disposition": decide.DENY, "request_id": request_id, "tool": tool.name,
                      "failed_step": decision.step, "stop_condition": decision.record["stop_condition"],
                      "reason": decision.reason}
        text = f"DENY at step {decision.step!r}, {why} ({decision.reason}); nothing was run"
        return _tool_result(structured, text, True)
