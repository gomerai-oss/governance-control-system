"""The Slack harness, read-only (APP-CONTROL-HARNESS-SPEC-001 build part 6; MISSION-DISPATCH-001 §3p, Amendment 033).

Two tools, both of class ``read``, each one request to the Slack Web API through the app gateway's ``request``:

``slack_list_channels``  ``GET https://slack.com/api/conversations.list``: the workspace's public channels, not
                         archived, with whether the bot is a member. Argument: ``cursor`` (optional).
``slack_read_channel``   ``GET https://slack.com/api/conversations.history``: one public channel's messages, newest
                         first. The bot must be a member. Arguments: ``channel`` (required, a channel id), ``oldest``
                         and ``latest`` (optional, Slack timestamps), ``cursor`` (optional).

Slack takes the arguments in the query string and the token in the ``Authorization`` header; the harness never sees
the token: the egress proxy adds it. Every argument is checked against a fixed pattern before any request, and a page
is at most ``PAGE`` items. The result is compact JSON of only the fields listed below, each message's text cut at
``MAX_TEXT`` characters. Slack's own error code is passed on as ``error``; an HTTP 429 as ``ratelimited``. The app
gateway quarantines the result before the agent reads it.

The harness may import only the app gateway's ``HARNESS_IMPORTS``; this one imports ``json``, ``re`` and
``urllib.parse``.
"""

from __future__ import annotations

import json
import re
import urllib.parse

HOST = "slack.com"
LIST_PATH = "/api/conversations.list"
HISTORY_PATH = "/api/conversations.history"
PAGE = 100  # Slack's default page; it recommends no more than 200
MAX_TEXT = 4000  # characters of one message's text
CHANNEL_FIELDS = ("id", "name", "is_member", "is_archived", "num_members")
MESSAGE_FIELDS = ("ts", "user", "bot_id", "subtype", "thread_ts", "reply_count", "text")
TOOLS = ("slack_list_channels", "slack_read_channel")

_CHANNEL = re.compile(r"C[A-Z0-9]{8,20}")  # a public channel's id
_TS = re.compile(r"[0-9]{1,10}(\.[0-9]{1,6})?")  # a Slack timestamp
# Slack's opaque next_cursor, short enough that its query form stays within the proxy's 1,000 characters
_CURSOR = re.compile(r"[A-Za-z0-9+/=_-]{1,250}")


class ArgumentError(ValueError):
    """An argument the harness does not send."""


def _arg(arguments, name, pattern, required=False):
    value = arguments.get(name, "")
    if not isinstance(value, str):
        raise ArgumentError(f"{name} must be text")
    if not value:
        if required:
            raise ArgumentError(f"{name} is required")
        return ""
    if not pattern.fullmatch(value):
        raise ArgumentError(f"{name} is not a valid Slack {name.replace('_', ' ')}")
    return value


def _query(pairs):
    return urllib.parse.urlencode([(k, v) for k, v in pairs if v != ""], quote_via=urllib.parse.quote, safe="")


def _keep(item, fields):
    out = {}
    for name in fields:
        value = item.get(name)
        if value is None:
            continue
        if isinstance(value, bool) or isinstance(value, int):
            out[name] = value
        elif isinstance(value, str):
            out[name] = value[:MAX_TEXT] if name == "text" else value[:200]
    return out


def _answer(status, text):
    """Slack's answer as a dict with ``ok``; a failure as ``{"ok": False, "error": ...}``. Only an HTTP 200 answer is
    read: any other status is a failure, whatever its body says (the independent review, M-HREVIEW-001)."""
    if status == 429:
        return {"ok": False, "error": "ratelimited"}
    if status != 200:
        return {"ok": False, "error": f"HTTP {status}"}
    try:
        doc = json.loads(text)
    except ValueError:
        return {"ok": False, "error": f"not JSON (HTTP {status})"}
    if not isinstance(doc, dict) or not isinstance(doc.get("ok"), bool):
        return {"ok": False, "error": f"no ok field (HTTP {status})"}
    if not doc["ok"]:
        error = doc.get("error")
        return {"ok": False, "error": error[:100] if isinstance(error, str) else f"HTTP {status}"}
    return doc


def _cursor(doc):
    meta = doc.get("response_metadata")
    value = meta.get("next_cursor") if isinstance(meta, dict) else None
    return value if isinstance(value, str) and _CURSOR.fullmatch(value) else ""


def run(tool, arguments, request):
    """One harness call: ``tool`` with its ``arguments`` (all text), through ``request``. Returns JSON text."""
    try:
        if tool == "slack_list_channels":
            query = _query([("types", "public_channel"), ("exclude_archived", "true"), ("limit", str(PAGE)),
                            ("cursor", _arg(arguments, "cursor", _CURSOR))])
            doc = _answer(*request("GET", HOST, LIST_PATH, query))
            if not doc["ok"]:
                return json.dumps(doc, sort_keys=True)
            channels = doc.get("channels") if isinstance(doc.get("channels"), list) else []
            return json.dumps({"ok": True, "channels": [_keep(c, CHANNEL_FIELDS) for c in channels[:PAGE]
                                                         if isinstance(c, dict)],
                               "next_cursor": _cursor(doc)}, sort_keys=True)
        if tool == "slack_read_channel":
            query = _query([("channel", _arg(arguments, "channel", _CHANNEL, required=True)),
                            ("oldest", _arg(arguments, "oldest", _TS)), ("latest", _arg(arguments, "latest", _TS)),
                            ("limit", str(PAGE)), ("cursor", _arg(arguments, "cursor", _CURSOR))])
            doc = _answer(*request("GET", HOST, HISTORY_PATH, query))
            if not doc["ok"]:
                return json.dumps(doc, sort_keys=True)
            messages = doc.get("messages") if isinstance(doc.get("messages"), list) else []
            return json.dumps({"ok": True, "messages": [_keep(m, MESSAGE_FIELDS) for m in messages[:PAGE]
                                                         if isinstance(m, dict)],
                               "has_more": doc.get("has_more") is True, "next_cursor": _cursor(doc)},
                              sort_keys=True)
    except ArgumentError as exc:
        return json.dumps({"ok": False, "error": f"argument: {exc}"}, sort_keys=True)
    return json.dumps({"ok": False, "error": f"unknown tool {str(tool)[:64]}"}, sort_keys=True)
