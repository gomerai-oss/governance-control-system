"""MCP stdio framing and JSON-RPC 2.0 for the governed-retrieval gateway.

The transport is newline-delimited JSON-RPC 2.0 over stdin and stdout: one
message per line, UTF-8, no embedded newline. The server answers exactly these
methods and nothing else (no resources, prompts, sampling or roots)::

    initialize                  protocol version 2025-06-18, server governed-retrieval,
                                capability ``tools`` only
    notifications/initialized   notification; never answered
    ping                        empty result
    tools/list                  the tools the fabric would allow for this session
    tools/call                  one tool call, decided by the fabric

Errors are the JSON-RPC codes ``-32700`` (parse), ``-32600`` (invalid request),
``-32601`` (method not found) and ``-32602`` (invalid params); ``-32603`` is
kept for a defect in the server itself. A bad line never stops the loop: the
server answers it and keeps serving until end of input.
"""

from __future__ import annotations

import json
from typing import Any, BinaryIO, Mapping, Optional

PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "governed-retrieval"
SERVER_VERSION = "MCP-GATEWAY-SPEC-001"

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

INITIALIZED = "notifications/initialized"
METHODS = ("initialize", "ping", "tools/list", "tools/call")


class RpcError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code, self.message = code, message


def _no_constant(text: str) -> Any:
    raise ValueError(f"non-finite number {text}")


def decode(raw: bytes) -> Any:
    """One line as a JSON value; anything that is not UTF-8 JSON is a parse error."""
    try:
        return json.loads(raw.decode("utf-8"), parse_constant=_no_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise RpcError(PARSE_ERROR, "parse error: the line is not a JSON value") from None


def encode(message: Mapping) -> bytes:
    return (json.dumps(message, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def result(rid: Any, value: Any) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "result": value}


def error(rid: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def _is_id(value: Any) -> bool:
    return isinstance(value, str) or (isinstance(value, int) and not isinstance(value, bool))


class Endpoint:
    """Routes JSON-RPC messages to a tool provider.

    The provider has ``list_tools() -> [tool, ...]`` and
    ``call_tool(name, arguments) -> tool result``; it may raise ``RpcError``.
    """

    def __init__(self, provider: Any):
        self.provider = provider
        self.initialized = False

    def handle(self, raw: bytes) -> Optional[dict]:
        """The response to one line, or None when nothing is answered."""
        try:
            message = decode(raw)
        except RpcError as exc:
            return error(None, exc.code, exc.message)
        if not isinstance(message, dict):
            return error(None, INVALID_REQUEST, "invalid request: not a JSON-RPC object")
        has_id = "id" in message
        rid = message.get("id")
        reply_id = rid if _is_id(rid) else None
        if message.get("jsonrpc") != "2.0":
            return error(reply_id, INVALID_REQUEST, "invalid request: jsonrpc must be \"2.0\"")
        if "method" not in message:
            if has_id and ("result" in message or "error" in message):
                return None  # a response; this server sends no requests, so there is nothing to match
            return error(reply_id, INVALID_REQUEST, "invalid request: no method")
        method = message["method"]
        if not isinstance(method, str) or not method:
            return error(reply_id, INVALID_REQUEST, "invalid request: method must be a non-empty string")
        if has_id and not _is_id(rid):
            return error(None, INVALID_REQUEST, "invalid request: id must be a string or an integer")
        params = message.get("params")
        if not has_id:
            if method == INITIALIZED and (params is None or isinstance(params, dict)):
                self.initialized = True
            return None  # notifications are never answered
        if "params" in message and not isinstance(params, dict):
            return error(rid, INVALID_PARAMS, "invalid params: params must be an object")
        try:
            return result(rid, self.dispatch(method, params or {}))
        except RpcError as exc:
            return error(rid, exc.code, exc.message)
        except Exception as exc:  # a defect in the server is an error, never a partial result
            return error(rid, INTERNAL_ERROR, f"internal error: {type(exc).__name__}")

    def dispatch(self, method: str, params: dict) -> Any:
        if method == "initialize":
            return self._initialize(params)
        if method == "ping":
            return {}
        if method == "tools/list":
            if "cursor" in params:
                raise RpcError(INVALID_PARAMS, "invalid params: this server issues no cursors")
            return {"tools": self.provider.list_tools()}
        if method == "tools/call":
            name = params.get("name")
            if not isinstance(name, str) or not name:
                raise RpcError(INVALID_PARAMS, "invalid params: name must be a non-empty string")
            arguments = params.get("arguments", {})
            if not isinstance(arguments, dict):
                raise RpcError(INVALID_PARAMS, "invalid params: arguments must be an object")
            return self.provider.call_tool(name, arguments)
        raise RpcError(METHOD_NOT_FOUND, f"method not found: {method}")

    def _initialize(self, params: dict) -> dict:
        if not isinstance(params.get("protocolVersion"), str):
            raise RpcError(INVALID_PARAMS, "invalid params: protocolVersion must be a string")
        for key in ("capabilities", "clientInfo"):
            if key in params and not isinstance(params[key], dict):
                raise RpcError(INVALID_PARAMS, f"invalid params: {key} must be an object")
        return {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        }


def serve(endpoint: Endpoint, instream: BinaryIO, outstream: BinaryIO) -> None:
    """Answer each line of ``instream`` on ``outstream`` until end of input."""
    for raw in iter(instream.readline, b""):
        if not raw.strip():
            continue
        response = endpoint.handle(raw)
        if response is not None:
            outstream.write(encode(response))
            outstream.flush()
