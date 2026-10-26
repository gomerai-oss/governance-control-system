"""How the dispatcher starts each runtime, and the sandbox each one runs in.

The agent never holds a GitHub credential. It edits files in a fresh checkout and
writes a commit message; the dispatcher then checks the change, commits it, pushes
it and opens the PR with the agent's GitHub App token. So a runtime only needs to
read the checkout and write inside it.

Rule syntax was observed live (governance/orchestrator/WAKE-INVOCATIONS-001.md):

Claude Code: path rules are ``~/rel`` under home and ``//abs`` elsewhere; ``Edit()``
governs the Write tool. Here it gets no Bash, web or MCP tools at all (``--tools``),
and ``--setting-sources user`` keeps a checkout's own .claude/ settings and hooks
from loading.

Cursor agent: ``{workspace}/.cursor/cli.json`` with ``--trust``. Deny is checked
before allow; only Read *deny* rules bound reads; writes outside the workspace need
an approval that ``-p`` without ``--force`` refuses. Its shell is read-only git.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Tuple

CLAUDE_CODE = "claude-code"
CURSOR_CLI = "cursor-cli"
BINARIES = {CLAUDE_CODE: "claude", CURSOR_CLI: "agent"}

# Inside the checkout, excluded from git: the task (and checks report) the agent reads and the message it writes.
INBOX_DIR = ".mission-dispatch"
TASK_FILE = f"{INBOX_DIR}/TASK.md"
MESSAGE_FILE = f"{INBOX_DIR}/COMMIT_MSG"
DELETIONS_FILE = f"{INBOX_DIR}/DELETE"  # A2: files to delete, one path per line (Amendment 010)
CURSOR_CONFIG = ".cursor/cli.json"

# Key material and credentials on this laptop, relative to home. Denied to every runtime.
HOME_SECRET_PATHS: Tuple[str, ...] = (
    "campus-keys/**",
    "token-broker/**",
    "mint-*.sh",
    ".git-credentials",
    ".gitconfig",
    ".config/gh/**",
    ".config/git/**",
    ".ssh/**",
    ".gnupg/**",
    ".claude/**",
    ".claude.json",
    ".cursor/**",
    ".config/cursor/**",
    ".local/state/mission-dispatch/jobs/**",
)
SHELL_SECRET_SUBSTRINGS: Tuple[str, ...] = (
    "campus-keys", "token-broker", "mint-", ".git-credentials", ".config/gh", ".ssh", ".gnupg", "credentials",
)

# A checkout that holds any of these could configure the runtime itself (hooks, MCP
# servers, permissions). The dispatcher refuses to start an agent in it.
RUNTIME_CONFIG_PATHS: Tuple[str, ...] = (
    ".claude", ".mcp.json", ".cursor/cli.json", ".cursor/hooks.json", ".cursor/hooks", ".cursor/mcp.json",
    ".cursor/environment.json", ".cursor/sandbox.json", ".vscode/settings.json",
)

GIT_READONLY_COMMANDS: Tuple[str, ...] = ("git status", "git diff", "git log", "git show", "git rev-parse")
GIT_WRITE_COMMANDS: Tuple[str, ...] = (
    "git add", "git commit", "git push", "git fetch", "git pull", "git clone", "git branch", "git checkout",
    "git switch", "git reset", "git restore", "git config", "git remote", "git tag", "git rebase", "git merge",
    "git cherry-pick", "git stash", "git update-ref", "git worktree", "git submodule", "git gc", "git notes",
)
# git rejects abbreviations of these options, so a substring deny covers every spelling.
GIT_READONLY_DENY_SUBSTRINGS: Tuple[str, ...] = (
    "--output", "--no-index", "--ext-diff", "--textconv", "core.pager", "difftool", "--exec", "-c ",
)
# Cursor allows writes under these roots by default.
CURSOR_DEFAULT_WRITABLE_ROOTS: Tuple[str, ...] = ("/tmp", "/var/tmp", "/var/folders", "/private", "/dev/shm")

# Vendor logins the runtime needs to start (unset ones are dropped, so an empty secret
# never shadows a real login). Every other credential-looking variable is dropped.
KEEP_ENV = frozenset({"ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "CURSOR_API_KEY"})
_SECRET_ENV = re.compile(r"TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE|_PAT$|_KEY$|^SSH_AUTH_SOCK$|^GPG_", re.I)


class SandboxError(ValueError):
    """A path or value cannot be placed in a permission rule safely."""


def _safe(path: Path) -> str:
    text = path.resolve().as_posix()
    if not re.fullmatch(r"[A-Za-z0-9_./+-]+", text) or ".." in text.split("/"):
        raise SandboxError(f"path {text!r} cannot be placed in a permission rule")
    return text


def claude_path(path: Path, home: Path) -> str:
    """Claude Code path rule: ``~/rel`` under home, ``//abs`` elsewhere."""
    resolved = Path(_safe(path))
    try:
        rel = resolved.relative_to(home.resolve())
    except ValueError:
        return "/" + resolved.as_posix()
    return "~" if rel == Path(".") else "~/" + rel.as_posix()


def claude_argv(checkout: Path, prompt: str, home: Path, binary: str = "claude", model: str = "") -> List[str]:
    ws = claude_path(checkout, home)
    allowed = [f"Read({ws}/**)", f"Edit({ws}/**)"]
    denied = [
        *(f"Read(~/{rel})" for rel in HOME_SECRET_PATHS),
        *(f"Edit(~/{rel})" for rel in HOME_SECRET_PATHS),
        f"Edit({ws}/.git)",
        f"Edit({ws}/.git/**)",
        "Bash", "WebFetch", "WebSearch", "Task", "NotebookEdit",
    ]
    return [
        binary, "-p",
        "--output-format", "text",
        "--permission-mode", "dontAsk",
        "--permission-prompts", "none",
        "--setting-sources", "user",
        "--strict-mcp-config",
        "--tools", "Read,Edit,Write,Glob,Grep",
        f"--allowedTools={','.join(allowed)}",
        *(f"--disallowedTools={rule}" for rule in denied),
        *(("--model", model) if model else ()),
        prompt,
    ]


def cursor_permissions(checkout: Path, home: Path) -> Dict[str, List[str]]:
    ws = _safe(checkout)
    home_s = _safe(home)
    allow = [f"Read({ws}/**)", *(f"Shell({cmd})" for cmd in GIT_READONLY_COMMANDS)]
    deny = [
        *(f"Shell({cmd})" for cmd in GIT_WRITE_COMMANDS),
        *(f"Shell(git *{needle}*)" for needle in GIT_READONLY_DENY_SUBSTRINGS),
        "Shell(gh)",
        *(f"Shell(*{needle}*)" for needle in SHELL_SECRET_SUBSTRINGS),
        f"Write({ws}/.git)",
        f"Write({ws}/.git/**)",
        "Write(**/.cursor/**)",
        f"Write({ws}/{INBOX_DIR}/TASK.md)",
        *(f"Write({root}/**)" for root in CURSOR_DEFAULT_WRITABLE_ROOTS if not ws.startswith(root + "/")),
        *(f"Read({home_s}/{rel})" for rel in HOME_SECRET_PATHS),
        *(f"Write({home_s}/{rel})" for rel in HOME_SECRET_PATHS),
    ]
    for rule in allow + deny:
        if rule.startswith("Shell(") and ":" in rule:
            raise SandboxError(f"Cursor would split {rule!r} at ':'")
    return {"allow": allow, "deny": deny}


def cursor_argv(checkout: Path, prompt: str, binary: str = "agent", model: str = "") -> List[str]:
    return [binary, "-p", "--trust", "--workspace", _safe(checkout), *(("--model", model) if model else ()), prompt]


def write_cursor_config(checkout: Path, home: Path) -> Path:
    """Write the run's permissions to {checkout}/.cursor/cli.json and make it read-only."""
    path = checkout / CURSOR_CONFIG
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"permissions": cursor_permissions(checkout, home)}, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    path.chmod(0o444)
    return path


def remove_cursor_config(checkout: Path) -> None:
    path = checkout / CURSOR_CONFIG
    try:
        path.chmod(0o644)
        path.unlink()
    except FileNotFoundError:
        pass


def argv_for(runtime: str, checkout: Path, prompt: str, home: Path, binaries: Mapping[str, str] = BINARIES,
             model: str = "") -> List[str]:
    if model and model.startswith("-"):  # the plan parser never allows it; a flag must not reach the runtime
        raise SandboxError(f"model {model!r} would read as a flag")
    if runtime == CLAUDE_CODE:
        return claude_argv(checkout, prompt, home, binaries[CLAUDE_CODE], model)
    if runtime == CURSOR_CLI:
        return cursor_argv(checkout, prompt, binaries[CURSOR_CLI], model)
    raise SandboxError(f"unknown runtime {runtime!r}")


def agent_env(base: Mapping[str, str], checkout: Path, git_dir: Path, empty_dir: Path) -> Dict[str, str]:
    """The runtime's environment: no GitHub or other credentials, git pinned to the job's own git dir."""
    env = {k: v for k, v in base.items() if (k in KEEP_ENV and v) or not _SECRET_ENV.search(k)}
    env.update({
        "GIT_DIR": str(git_dir.resolve()),
        "GIT_WORK_TREE": str(checkout.resolve()),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GH_CONFIG_DIR": str(empty_dir.resolve()),
    })
    return env


def config_hazards(checkout: Path) -> List[str]:
    return [rel for rel in RUNTIME_CONFIG_PATHS if (checkout / rel).exists() or (checkout / rel).is_symlink()]
