"""The app register (APP-CONTROL-HARNESS-SPEC-001 §4.3, MISSION-DISPATCH-001 §3p, Amendment 026): loading and strict
validation.

The register ships as data (``apps.json`` next to this module). It is ``AUTHORITY`` under SPEC-002's prefix rule for
this folder, so only a hand-merged PR changes it. It lists each app a harness may reach, and nothing reaches an app
that it does not list. Build part 1 ships it empty; nothing reads it at run time until part 2.

A register document has exactly these fields:

``schema``            ``"app-register-v1"``
``spec``              ``"APP-CONTROL-HARNESS-SPEC-001"``
``register_version``  non-empty string
``bounds``            ``{"calls", "minutes"}``: the most any harness run may make or take, positive integers
``apps``              app name -> app entry (may be empty)

An app's name is lowercase letters, digits and ``-``, starting with a letter, at most 32 characters. Its entry has
exactly:

``classes``     the classes its calls may ever use: a non-empty subset of ``CLASSES``
``writes``      ``"direct"`` or ``"drafted"`` when ``write`` is in ``classes``, else ``null``
``tools``       its harness's app-gateway tool names, non-empty; no tool belongs to two apps
``hosts``       its hosts: exact DNS names, non-empty; no wildcard and no address
``requests``    the requests its harness makes, non-empty: ``{"method", "path", "class"}``, each class one of the app's
                ``classes``; a path segment is literal or one ``{name}`` placeholder
``resources``   its fabric resource ids, non-empty: ``app:<name>`` or ``app:<name>:<part>``
``approvals``   ``{"restricted", "runtime"}``: the resources of its own that are restricted, and the runtime
                implications its calls declare (``mcp_auth.policy.IMPLICATIONS``)
``key_slot``    the secret holding its key, ``APP_KEY_<n>`` with ``n`` from 1 to 99; no slot belongs to two apps
``bounds``      ``null``, or ``{"calls", "minutes"}`` no higher than the register's

Every class an app lists must have at least one request of that class, and every request's class must be listed.

Any defect is an ``AppsError``; a reader then stops fail-closed. There is no partial register.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from mcp_auth.policy import IMPLICATIONS
from tool_selection.matrix import read_file

SCHEMA = "app-register-v1"
SPEC_ID = "APP-CONTROL-HARNESS-SPEC-001"
DEFAULT_PATH = Path(__file__).resolve().parent / "apps.json"

# The classes of the matrix's four app capabilities (app_read, app_write, app_send, app_delete).
CLASSES = ("read", "write", "send", "delete")
WRITES = ("direct", "drafted")
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
MAX_SLOT = 99

TOP_FIELDS = frozenset({"schema", "spec", "register_version", "bounds", "apps"})
APP_FIELDS = frozenset({"classes", "writes", "tools", "hosts", "requests", "resources", "approvals", "key_slot",
                        "bounds"})
REQUEST_FIELDS = frozenset({"method", "path", "class"})
APPROVAL_FIELDS = frozenset({"restricted", "runtime"})
BOUND_FIELDS = frozenset({"calls", "minutes"})

_APP_NAME = re.compile(r"[a-z][a-z0-9-]{0,31}")
_TOOL_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")  # the gateway's own tool-name rule (mcp_gateway/server.py)
_HOST = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?")
_SEGMENT = re.compile(r"[A-Za-z0-9_.~-]{1,100}|\{[a-z][a-z0-9_]{0,31}\}")
_RESOURCE_PART = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
_SLOT = re.compile(r"APP_KEY_([1-9][0-9]?)")
MAX_PATH = 300


class AppsError(ValueError):
    pass


def _fields(value: Any, fields: Iterable[str], where: str) -> dict:
    fields = frozenset(fields)
    if not isinstance(value, dict) or set(value) != fields:
        raise AppsError(f"{where} must have exactly the fields {sorted(fields)}")
    return value


def _list(value: Any, where: str, nonempty: bool = True) -> list:
    if not isinstance(value, list) or (nonempty and not value):
        raise AppsError(f"{where} must be a {'non-empty ' if nonempty else ''}list")
    if not all(isinstance(v, str) for v in value):
        raise AppsError(f"{where} must hold strings only")
    if len(set(value)) != len(value):
        raise AppsError(f"{where} has duplicate entries")
    return value


def _positive(value: Any, where: str) -> int:
    if type(value) is not int or value < 1:
        raise AppsError(f"{where} must be a positive integer")
    return value


def _bounds(value: Any, where: str) -> dict:
    doc = _fields(value, BOUND_FIELDS, where)
    for key in sorted(BOUND_FIELDS):
        _positive(doc[key], f"{where}.{key}")
    return doc


def _path(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value.startswith("/") or len(value) > MAX_PATH:
        raise AppsError(f"{where} must be a path starting with '/', at most {MAX_PATH} characters")
    segments = value[1:].split("/")
    if not all(_SEGMENT.fullmatch(s) for s in segments) or any(s in (".", "..") for s in segments):
        raise AppsError(f"{where}: each segment must be literal or one {{name}} placeholder")
    return value


def _app(name: str, entry: Any, register_bounds: dict) -> dict:
    where = f"apps.{name}"
    app = _fields(entry, APP_FIELDS, where)

    classes = _list(app["classes"], f"{where}.classes")
    unknown = [c for c in classes if c not in CLASSES]
    if unknown:
        raise AppsError(f"{where}.classes: unknown {unknown}")
    if ("write" in classes) != (app["writes"] is not None):
        raise AppsError(f"{where}.writes must be one of {list(WRITES)} when 'write' is listed, else null")
    if app["writes"] is not None and app["writes"] not in WRITES:
        raise AppsError(f"{where}.writes must be one of {list(WRITES)}")

    for tool in _list(app["tools"], f"{where}.tools"):
        if not _TOOL_NAME.fullmatch(tool):
            raise AppsError(f"{where}.tools: {tool!r} is not a gateway tool name")
    for host in _list(app["hosts"], f"{where}.hosts"):
        if not _HOST.fullmatch(host):
            raise AppsError(f"{where}.hosts: {host!r} is not an exact lowercase DNS name")

    requests = app["requests"]
    if not isinstance(requests, list) or not requests:
        raise AppsError(f"{where}.requests must be a non-empty list")
    seen, used = set(), set()
    for i, request in enumerate(requests):
        rwhere = f"{where}.requests[{i}]"
        req = _fields(request, REQUEST_FIELDS, rwhere)
        if req["method"] not in METHODS:
            raise AppsError(f"{rwhere}.method must be one of {list(METHODS)}")
        _path(req["path"], f"{rwhere}.path")
        if req["class"] not in classes:
            raise AppsError(f"{rwhere}.class must be one of the app's classes {classes}")
        key = (req["method"], req["path"])
        if key in seen:
            raise AppsError(f"{rwhere}: {req['method']} {req['path']} is listed twice")
        seen.add(key)
        used.add(req["class"])
    unused = [c for c in classes if c not in used]
    if unused:
        raise AppsError(f"{where}.classes: {unused} listed with no request of that class")

    resources = _list(app["resources"], f"{where}.resources")
    own = re.compile(rf"app:{re.escape(name)}(?::{_RESOURCE_PART.pattern})?")
    for rid in resources:
        if not own.fullmatch(rid):
            raise AppsError(f"{where}.resources: {rid!r} must be 'app:{name}' or 'app:{name}:<part>'")

    approvals = _fields(app["approvals"], APPROVAL_FIELDS, f"{where}.approvals")
    for rid in _list(approvals["restricted"], f"{where}.approvals.restricted", nonempty=False):
        if rid not in resources:
            raise AppsError(f"{where}.approvals.restricted: {rid!r} is not one of the app's resources")
    for imp in _list(approvals["runtime"], f"{where}.approvals.runtime", nonempty=False):
        if imp not in IMPLICATIONS:
            raise AppsError(f"{where}.approvals.runtime: {imp!r} is not a known implication {list(IMPLICATIONS)}")

    slot = app["key_slot"]
    if not isinstance(slot, str) or not _SLOT.fullmatch(slot):
        raise AppsError(f"{where}.key_slot must be APP_KEY_<n>, n from 1 to {MAX_SLOT}")

    if app["bounds"] is not None:
        own = _bounds(app["bounds"], f"{where}.bounds")
        for key in sorted(BOUND_FIELDS):
            if own[key] > register_bounds[key]:
                raise AppsError(f"{where}.bounds.{key} is higher than the register's {register_bounds[key]}")
    return app


def validate(doc: Any) -> dict:
    """A validated copy of ``doc``; raises ``AppsError`` naming the first defect."""
    _fields(doc, TOP_FIELDS, "register")
    if doc["schema"] != SCHEMA:
        raise AppsError(f"schema must be {SCHEMA!r}")
    if doc["spec"] != SPEC_ID:
        raise AppsError(f"spec must be {SPEC_ID!r}")
    version = doc["register_version"]
    if not isinstance(version, str) or not version or version != version.strip():
        raise AppsError("register_version must be a non-empty string without surrounding whitespace")
    register_bounds = _bounds(doc["bounds"], "bounds")

    apps = doc["apps"]
    if not isinstance(apps, dict):
        raise AppsError("apps must be an object")
    tools, slots = {}, {}
    for name, entry in apps.items():
        if not isinstance(name, str) or not _APP_NAME.fullmatch(name):
            raise AppsError(f"apps: {name!r} is not an app name")
        app = _app(name, entry, register_bounds)
        for tool in app["tools"]:
            if tool in tools:
                raise AppsError(f"apps.{name}.tools: {tool!r} already belongs to {tools[tool]!r}")
            tools[tool] = name
        if app["key_slot"] in slots:
            raise AppsError(f"apps.{name}.key_slot: {app['key_slot']} already belongs to {slots[app['key_slot']]!r}")
        slots[app["key_slot"]] = name
    return json.loads(json.dumps(doc))


def load_file(path: Path = DEFAULT_PATH) -> dict:
    """Load and validate the register at ``path`` (default: the shipped register)."""
    try:
        doc = read_file(path, "app register")
    except ValueError as exc:
        raise AppsError(str(exc)) from None
    return validate(doc)
