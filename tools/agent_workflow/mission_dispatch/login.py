"""The model login stays outside the agent (ring 1 amendment, MISSION-DISPATCH-001 §3i item 6, Amendment 017).

``"model_login"`` in ``config.json``: ``"observe"`` (the default) or ``"enforce"``; any other value fails the job and
stops the router.

- **Where the login is.** For a Claude Code job the egress proxy is given the login in a file it reads once and
  deletes, and serves the runtime's model endpoint on loopback (``egress.proxy``). Under ``"enforce"`` the runtime gets
  only a fresh **stand-in** (``ANTHROPIC_AUTH_TOKEN``) and ``ANTHROPIC_BASE_URL`` pointing at that endpoint, and the
  proxy refuses tunnels to the model host. Under ``"observe"`` the runtime keeps its login as before; the endpoint runs
  only for the readiness request. A Cursor job keeps its login in both modes (known limit 19).
- **Readiness.** Before the agent starts, one minimal request (a token count) goes through the endpoint. Under
  ``"enforce"`` anything but HTTP 200 fails the job before any agent runs; under ``"observe"`` it is recorded.
- **Encodings.** ``encodings_found`` lists the ways a patch or message carries a login or stand-in: as written,
  reversed, hex, base32, base64 (both alphabets, from each byte offset) or split by separators. ``collect`` refuses the
  login as written in both modes (as before); the other encodings refuse under ``"enforce"`` and are recorded under
  ``"observe"``.
- **The record.** ``login.json`` in the job root (the runner account's, mode 0600) holds the mode, where the login
  was (``proxy`` or ``runtime``), its kind, the stand-in and the readiness result; ``collect`` copies all but the
  stand-in into the run record.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import re
import secrets
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

OBSERVE, ENFORCE = "observe", "enforce"
MODES = (OBSERVE, ENFORCE)
CONFIG_KEY = "model_login"
STATE_FILE = "login.json"
STANDIN_PREFIX = "standin-"
READINESS_TIMEOUT = 30.0
ANTHROPIC_VERSION = "2023-06-01"
# The login forms a Claude Code runtime is given, in the order the runtime itself prefers them.
CLAUDE_LOGINS = (("ANTHROPIC_API_KEY", "api_key"), ("CLAUDE_CODE_OAUTH_TOKEN", "oauth"))
CLAUDE_LOGIN_ENV = tuple(name for name, _ in CLAUDE_LOGINS)
BASE_URL_ENV, STANDIN_ENV = "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN"
MIN_CHARS = 16
# Characters a login may be split by and still be read back: whitespace, commas, quotes, plus signs, backslashes.
_SEPARATORS = re.compile(r"[\s,\"'+\\]")


class LoginError(ValueError):
    """The model-login mode is unknown, or the login cannot be kept outside the agent."""


def mode(config: Mapping[str, object]) -> str:
    value = config.get(CONFIG_KEY, OBSERVE)
    if value not in MODES:
        raise LoginError(f"config.json: {CONFIG_KEY} must be one of {list(MODES)}, not {value!r}")
    return str(value)


def credential(environ: Mapping[str, str]) -> Optional[Tuple[str, str]]:
    """The Claude Code login the job was given, as ``(kind, value)``, or None."""
    for name, kind in CLAUDE_LOGINS:
        value = environ.get(name, "")
        if len(value) >= MIN_CHARS:
            return kind, value
    return None


def new_standin() -> str:
    """A fresh value for one run; the provider would reject it, and nothing outside the job knows it."""
    return STANDIN_PREFIX + secrets.token_hex(24)


# ------------------------------------------------------------------ encodings (item 6d)
def _b64_cores(raw: bytes, alphabet: str) -> List[str]:
    """The part of ``raw``'s base64 that is the same wherever ``raw`` starts in a longer text: from each of the three
    byte offsets, the characters that depend only on ``raw``."""
    cores = []
    for offset in range(3):
        encoded = base64.b64encode(bytes(offset) + raw).decode("ascii").rstrip("=")
        start = (offset * 8 + 5) // 6  # characters carrying any of the offset's padding bits
        end = len(encoded) - (1 if (offset + len(raw)) % 3 else 0)  # the last one may carry bits from what follows
        core = encoded[start:end]
        if alphabet == "url":
            core = core.translate(str.maketrans("+/", "-_"))
        if len(core) >= MIN_CHARS:
            cores.append(core)
    return cores


def encodings_found(text: str, values: Sequence[str]) -> List[str]:
    """Each way ``text`` carries one of ``values``, as ``"<encoding>"`` names (no value is ever named)."""
    found: List[str] = []
    flat = _SEPARATORS.sub("", text)
    lower, flat_lower = text.lower(), flat.lower()
    for value in values:
        if len(value) < MIN_CHARS:
            continue
        raw = value.encode("utf-8")
        checks = [
            ("as written", value in text),
            ("reversed", value[::-1] in text or value[::-1] in flat),
            ("hex", raw.hex() in lower or raw.hex() in flat_lower),
            ("base32", base64.b32encode(raw).decode("ascii").rstrip("=")[:-1] in flat.upper()),
            ("base64", any(core in flat for core in _b64_cores(raw, "std"))),
            ("base64url", any(core in flat for core in _b64_cores(raw, "url"))),
            ("split by separators", _SEPARATORS.sub("", value) in flat and value not in text),
        ]
        for name, hit in checks:
            if hit and name not in found:
                found.append(name)
    return found


# ------------------------------------------------------------------ readiness (item 6e)
def readiness(port: int, standin: str, route: Tuple[str, str], model: str,
              timeout: float = READINESS_TIMEOUT) -> Dict[str, Any]:
    """One token-count request through the endpoint. ``{"ok", "status", "reason"}``; the body is never kept."""
    method, path = route
    body = json.dumps({"model": model, "messages": [{"role": "user", "content": "ready"}]}).encode("utf-8")
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        conn.request(method, "/model" + path, body=body, headers={
            "Authorization": f"Bearer {standin}", "content-type": "application/json",
            "anthropic-version": ANTHROPIC_VERSION, "Host": f"127.0.0.1:{port}"})
        reply = conn.getresponse()
        reply.read()
        conn.close()
    except (OSError, http.client.HTTPException) as exc:
        return {"ok": False, "status": 0, "reason": f"no answer from the endpoint ({type(exc).__name__})"}
    ok = reply.status == 200
    return {"ok": ok, "status": reply.status, "reason": "accepted" if ok else f"HTTP {reply.status}"}


# ------------------------------------------------------------------ the record (item 6f)
def write_state(root: Path, state: Mapping[str, Any]) -> None:
    path = root / STATE_FILE
    if path.exists() or path.is_symlink():
        path.unlink()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        out.write(json.dumps(dict(state), indent=2, sort_keys=True) + "\n")


def read_state(root: Path) -> Dict[str, Any]:
    path = root / STATE_FILE
    if path.is_symlink() or not path.is_file():
        return {}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return {}
    return doc if isinstance(doc, dict) else {}


def standin_of(root: Path) -> str:
    value = read_state(root).get("standin", "")
    return value if isinstance(value, str) and value.startswith(STANDIN_PREFIX) else ""


def summary(state: Mapping[str, Any]) -> Dict[str, Any]:
    """The run record's view of ``login.json``: everything but the stand-in."""
    return {k: v for k, v in state.items() if k != "standin"}
