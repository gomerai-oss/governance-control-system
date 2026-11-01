"""Live tool binding (Amendment 011): each agent run gets its seat's admitted tool surface and the governed MCP gateway.

Off by default. With ``"runtime_binding": "enforce"`` in the repository's ``config.json``, ``prepare`` asks
``tool_selection.runtime_binding`` for the seat's admitted surface, writes the gateway's session file and MCP
config under ``<job root>/binding/`` (beside the checkout, never in it), and refuses to start the agent when the
surface cannot be bound. ``run_agent`` then narrows the runtime to that surface.

The binding library only says which tools are admitted. This module keeps the dispatcher's own ceiling and
writes the gateway command itself: a binding can narrow the built-in tools, add read rules inside the checkout,
add denials, and admit gateway tools, and nothing else. The gateway runs from the dispatcher's own tooling tree,
never from the checkout the agent is editing.
"""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Optional, Tuple

OFF, ENFORCE = "off", "enforce"
MODES = (OFF, ENFORCE)
CONFIG_KEY = "runtime_binding"

BINDING_DIR = "binding"  # under the job root, beside checkout/ and git/
GIT_DIR = "git"  # the checkout's git dir under the job root (workspace.Checkout.git_dir)
SESSION_FILE, MCP_FILE, BINDING_FILE, EVIDENCE_DIR = "session.json", "mcp.json", "binding.json", "evidence"
CURSOR_MCP = ".cursor/mcp.json"
GATEWAY_SERVER = "governed-retrieval"
GATEWAY_MODULE = "mcp_gateway"
BUILTIN_CEILING: Tuple[str, ...] = ("Read", "Edit", "Write", "Glob", "Grep")
EVIDENCE_MAX_BYTES = 4 * 1024 * 1024
OUT_DIR = "binding"  # in collect's output, beside the patch: kept with the run's artifact, never read by publish

_TOOL_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")
_RULE = re.compile(r"(Read|Edit)\(([A-Za-z0-9_.*+-][A-Za-z0-9_.*+/-]*)\)")  # relative to the checkout


class BindingError(ValueError):
    """The run cannot be bound to an admitted surface; the agent does not start."""


@dataclass(frozen=True)
class Bound:
    tools: Tuple[str, ...]  # built-in tools, in ceiling order
    allowed: Tuple[str, ...]  # "Read(<glob>)" / "Edit(<glob>)", relative to the checkout
    denied: Tuple[str, ...]  # extra denials, added to the dispatcher's own
    mcp_tools: Tuple[str, ...]  # admitted gateway tools, bare names
    mcp_config: str  # path of the dispatcher-written MCP config, or "" when no gateway tool is admitted

    def mcp_rules(self) -> Tuple[str, ...]:
        return tuple(f"mcp__{GATEWAY_SERVER}__{name}" for name in self.mcp_tools)

    def path_rules(self, workspace_rule: str) -> Tuple[str, ...]:
        """The allowed rules as Claude Code rules; ``workspace_rule`` is the checkout as a path rule."""
        return tuple(f"{m.group(1)}({workspace_rule}/{m.group(2)})" for m in map(_RULE.fullmatch, self.allowed))


def mode(config: Mapping[str, Any]) -> str:
    value = config.get(CONFIG_KEY, OFF)
    if value not in MODES:
        raise BindingError(f"config {CONFIG_KEY} must be one of {', '.join(MODES)}, not {value!r}")
    return value


def gateway_root() -> Path:
    """``tools/agent_workflow`` of the tree this dispatcher runs from (the default branch's tooling)."""
    return Path(__file__).resolve().parents[1]


def binding_dir(root: Path) -> Path:
    return root / BINDING_DIR


def _strings(value: Any, what: str) -> Tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not all(isinstance(v, str) and v and "\n" not in v for v in value):
        raise BindingError(f"the binding's {what} is not a list of strings")
    return tuple(value)


def check(tools: Any, allowed: Any, denied: Any, mcp_tools: Any) -> Tuple[tuple, tuple, tuple, tuple]:
    """Hold a binding to the dispatcher's ceiling."""
    tools, allowed, denied, mcp_tools = (_strings(tools, "tools"), _strings(allowed, "allowed rules"),
                                         _strings(denied, "denied rules"), _strings(mcp_tools, "gateway tools"))
    extra = sorted(set(tools) - set(BUILTIN_CEILING))
    if extra:
        raise BindingError(f"the binding admits tools beyond the dispatcher's ceiling: {', '.join(extra)}")
    for text in allowed:
        match = _RULE.fullmatch(text)
        if not match or ".." in match.group(2).split("/"):
            raise BindingError(f"the binding allows {text!r}, which is not a read or edit rule inside the checkout")
    for name in mcp_tools:
        if not _TOOL_NAME.fullmatch(name):
            raise BindingError(f"the binding admits gateway tool {name!r}, which is not a plain tool name")
    ordered = tuple(t for t in BUILTIN_CEILING if t in tools)
    return ordered, allowed, denied, tuple(dict.fromkeys(mcp_tools))


def mcp_config(checkout: Path, session: Path, evidence: Path, git_dir: Optional[Path] = None) -> dict:
    """The one MCP server an agent may use, as the dispatcher writes it: the gateway from the tooling tree.

    ``git_dir`` is the checkout's git dir, kept outside the work tree; the gateway's ``trace`` reads history there.
    """
    args = ["-m", GATEWAY_MODULE, "--root", str(checkout.resolve()), "--session", str(session.resolve()),
            "--evidence-dir", str(evidence.resolve())]
    if git_dir is not None:
        args += ["--git-dir", str(git_dir.resolve())]
    return {"mcpServers": {GATEWAY_SERVER: {
        "command": "python3",
        "args": args,
        "env": {"PYTHONPATH": str(gateway_root())},
    }}}


def _write_readonly(path: Path, doc: Any) -> None:
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o444)


def bind(job: Any, root: Path, checkout: Path, home: Path, now: int, binder: Any = None) -> Bound:
    """Bind ``job``'s seat; write the session, the MCP config and the record. Any failure is a BindingError."""
    if binder is None:
        try:
            from tool_selection import runtime_binding as binder  # the tooling tree's copy, never the checkout's
        except ImportError as exc:
            raise BindingError(f"runtime binding is enforced but tool_selection.runtime_binding is missing: {exc}") \
                from None
    out = binding_dir(root)
    if out.exists():
        raise BindingError(f"{out} already exists; refusing to reuse another run's binding")
    evidence = out / EVIDENCE_DIR
    evidence.mkdir(parents=True)
    session_path = out / SESSION_FILE
    mission = {"id": job.mission_id, "round": job.round, "agent": job.agent, "base_sha": job.base_sha,
               "build_scope": list(job.build_scope)}
    refused = getattr(binder, "BindingRefused", None)
    try:
        result = binder.bind(job.role, job.runtime, mission, checkout.resolve(), session_path, evidence,
                             gateway_root(), now)
        tools, allowed, denied, mcp_tools = check(result.tools, result.allowed_rules, result.denied_rules,
                                                  result.mcp_tools)
        session, audit = result.session, result.audit
    except BindingError:
        raise
    except Exception as exc:  # a refusal, or anything unexpected: the agent does not start
        kind = "refused" if refused is not None and isinstance(exc, refused) else "failed"
        raise BindingError(f"the tool surface for {job.role} could not be bound ({kind}): {exc}") from None
    if not isinstance(session, dict):
        raise BindingError("the binding produced no session")
    if job.runtime == "cursor-cli" and mcp_tools and (home / ".cursor" / "mcp.json").exists():
        raise BindingError("~/.cursor/mcp.json exists; --approve-mcps would approve its servers too")
    _write_readonly(session_path, session)
    config = ""
    if mcp_tools:
        git_dir = Path(root) / GIT_DIR
        _write_readonly(out / MCP_FILE, mcp_config(checkout, session_path, evidence,
                                                   git_dir if git_dir.is_dir() else None))
        config = str((out / MCP_FILE).resolve())
    bound = Bound(tools, allowed, denied, mcp_tools, config)
    try:
        audit_text = json.dumps(audit, sort_keys=True)
    except (TypeError, ValueError):
        raise BindingError("the binding's audit record is not JSON") from None
    _write_readonly(out / BINDING_FILE, {"bound": asdict(bound), "audit": json.loads(audit_text)})
    return bound


def load(root: Path) -> Bound:
    """The binding ``prepare`` wrote for this run, held to the ceiling again."""
    path = binding_dir(root) / BINDING_FILE
    if path.is_symlink() or not path.is_file():
        raise BindingError("runtime binding is enforced but prepare left no binding; refusing to start the agent")
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))["bound"]
        tools, allowed, denied, mcp_tools = check(doc["tools"], doc["allowed"], doc["denied"], doc["mcp_tools"])
        config = doc["mcp_config"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise BindingError(f"the run's binding cannot be read: {exc}") from None
    expected = str((binding_dir(root) / MCP_FILE).resolve()) if mcp_tools else ""
    if config != expected:
        raise BindingError("the run's binding names an MCP config the dispatcher did not write")
    return Bound(tools, allowed, denied, mcp_tools, config)


def write_cursor_mcp(checkout: Path, bound: Bound) -> Optional[Path]:
    """Copy the dispatcher's MCP config to ``.cursor/mcp.json`` (read-only) when a gateway tool is admitted."""
    if not bound.mcp_config:
        return None
    path = checkout / CURSOR_MCP
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(Path(bound.mcp_config).read_text(encoding="utf-8"), encoding="utf-8")
    path.chmod(0o444)
    return path


def remove_cursor_mcp(checkout: Path) -> None:
    path = checkout / CURSOR_MCP
    try:
        path.chmod(0o644)
        path.unlink()
    except FileNotFoundError:
        pass


def keep_evidence(root: Path, out_dir: Path) -> dict:
    """Copy the binding record and the gateway's evidence log next to collect's output. Returns a summary."""
    src = binding_dir(root)
    if not src.is_dir():
        return {}
    dest = out_dir / OUT_DIR
    dest.mkdir(parents=True, exist_ok=True)
    record = src / BINDING_FILE
    if record.is_file() and not record.is_symlink():
        shutil.copyfile(record, dest / BINDING_FILE)
    lines, size = 0, 0
    with open(dest / "gateway-evidence.jsonl", "w", encoding="utf-8") as log:
        for part in sorted((src / EVIDENCE_DIR).glob("*.jsonl")):
            if part.is_symlink() or not part.is_file():
                continue
            for line in part.read_text(encoding="utf-8", errors="replace").splitlines():
                size += len(line.encode("utf-8")) + 1
                if size > EVIDENCE_MAX_BYTES:
                    return {"evidence_lines": lines, "evidence_truncated": True}
                log.write(line + "\n")
                lines += 1
    return {"evidence_lines": lines, "evidence_truncated": False}
