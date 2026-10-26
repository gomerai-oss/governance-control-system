"""The job's git checkout: clone, branch, list changes, commit, push.

Every git call names the job's git dir and work tree explicitly and runs with no
global or system config, so nothing the agent leaves in the work tree (a ``.git``
file, hooks, attributes that need config) and no stored login on the machine can
take part. Credentials come only from the token handed to ``clone`` or ``push``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Mapping, Optional, Tuple

from .runtimes import CURSOR_CONFIG, INBOX_DIR

TOKEN_ENV = "MISSION_DISPATCH_GIT_TOKEN"
GIT_TIMEOUT = 600


class GitError(RuntimeError):
    pass


def git_env(base: Mapping[str, str], token: str = "") -> dict:
    """git environment with only the given token as a credential (none when empty)."""
    env = {k: v for k, v in base.items() if k in ("PATH", "HOME", "LANG", "LC_ALL", "TZ", "TMPDIR")}
    env.update({
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false",
        "SSH_ASKPASS": "/bin/false",
        "GIT_CONFIG_COUNT": "5",
        "GIT_CONFIG_KEY_0": "credential.helper",
        "GIT_CONFIG_VALUE_0": "",
        "GIT_CONFIG_KEY_1": "credential.helper",
        "GIT_CONFIG_VALUE_1": f'!f() {{ echo username=x-access-token; echo "password=${TOKEN_ENV}"; }}; f' if token else "",
        # Checkouts are thrown away: no background gc or maintenance may outlive the git call that started it.
        "GIT_CONFIG_KEY_2": "gc.auto",
        "GIT_CONFIG_VALUE_2": "0",
        "GIT_CONFIG_KEY_3": "maintenance.auto",
        "GIT_CONFIG_VALUE_3": "false",
        "GIT_CONFIG_KEY_4": "receive.autogc",
        "GIT_CONFIG_VALUE_4": "false",
    })
    if token:
        env[TOKEN_ENV] = token
    return env


@dataclass(frozen=True)
class Change:
    status: str  # porcelain XY
    path: str


class Checkout:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.tree = root / "checkout"
        self.git_dir = root / "git"
        self.empty = root / "empty"

    def _git(self, *args: str, env: Mapping[str, str], check: bool = True, stdin: Optional[str] = None,
             cwd: Optional[Path] = None) -> str:
        argv = ["git", "--git-dir", str(self.git_dir), "--work-tree", str(self.tree),
                "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "protocol.file.allow=user", *args]
        done = subprocess.run(argv, env=dict(env), capture_output=True, text=True, timeout=GIT_TIMEOUT, input=stdin,
                              cwd=str(cwd or self.root))
        if check and done.returncode != 0:
            raise GitError(f"git {args[0]} failed: {(done.stderr or done.stdout).strip()[:300]}")
        return done.stdout

    def prepare(self, clone_url: str, branch: str, base_sha: str, author: Tuple[str, str], env: Mapping[str, str]) -> None:
        """Fresh clone with ``branch`` created at ``base_sha``; the git dir is kept outside the work tree."""
        if self.root.exists():
            _make_writable(self.root)
            shutil.rmtree(self.root)
        self.root.mkdir(parents=True)
        self.empty.mkdir()
        done = subprocess.run(["git", "-c", "protocol.file.allow=user", "clone", "--quiet", "--no-checkout",
                               "--separate-git-dir", str(self.git_dir), "--", clone_url, str(self.tree)],
                              env=dict(env), capture_output=True, text=True, timeout=GIT_TIMEOUT, cwd=str(self.root))
        if done.returncode != 0:
            raise GitError(f"git clone failed: {done.stderr.strip()[:300]}")
        (self.tree / ".git").unlink()  # the pointer file; every call names the git dir itself
        self._git("checkout", "--quiet", "-b", branch, base_sha, env=env)
        head = self._git("rev-parse", "HEAD", env=env).strip()
        if head != base_sha:
            raise GitError(f"checkout is at {head}, expected {base_sha}")
        for key, value in (("user.name", author[0]), ("user.email", author[1]), ("core.hooksPath", "/dev/null"),
                           ("core.fsmonitor", "false"), ("commit.gpgsign", "false")):
            self._git("config", key, value, env=env)
        exclude = self.git_dir / "info" / "exclude"
        exclude.parent.mkdir(parents=True, exist_ok=True)
        with exclude.open("a", encoding="utf-8") as handle:
            handle.write(f"\n/{INBOX_DIR}/\n/{CURSOR_CONFIG}\n")
        (self.tree / INBOX_DIR).mkdir(exist_ok=True)

    def message(self, rev: str, env: Mapping[str, str]) -> str:
        """The commit message of ``rev``, or "" when there is no such commit."""
        return self._git("log", "-1", "--format=%B", rev, "--", env=env, check=False)

    def changes(self, env: Mapping[str, str]) -> List[Change]:
        out = self._git("status", "--porcelain=v1", "-z", "--untracked-files=all", "--no-renames", "--ignored=no", env=env)
        return [Change(entry[:2], entry[3:]) for entry in out.split("\0") if entry]

    def stage(self, env: Mapping[str, str]) -> None:
        self._git("add", "--all", env=env)

    def staged_patch(self, base: str, env: Mapping[str, str]) -> str:
        """Everything staged since ``base`` as a binary patch (paths are always relative to the tree)."""
        return self._git("diff", "--cached", "--binary", "--no-renames", "--no-ext-diff", "--no-textconv", base, "--", env=env)

    def staged_modes(self, base: str, env: Mapping[str, str]) -> List[Tuple[str, str]]:
        """(path, new mode) for every staged change since ``base``; a deletion has mode 000000."""
        out = self._git("diff", "--cached", "--raw", "-z", "--no-renames", "--no-abbrev", base, "--", env=env)
        fields = out.split("\0")
        modes = []
        for meta, path in zip(fields[0::2], fields[1::2]):
            if meta.startswith(":"):
                modes.append((path, meta[1:].split(" ")[1]))
        return modes

    def apply(self, patch: str, env: Mapping[str, str]) -> None:
        """Apply and stage ``patch``. git refuses paths outside the tree and paths behind a symbolic link."""
        # Run from the top of the work tree: git apply resolves paths against the working directory.
        self._git("apply", "--index", "--binary", "--whitespace=nowarn", "-", env=env, stdin=patch, cwd=self.tree)

    def commit(self, message: str, env: Mapping[str, str], allow_empty: bool = False) -> str:
        self._git("add", "--all", env=env)
        self._git("commit", "--quiet", "--no-verify", *(["--allow-empty"] if allow_empty else []), "--file", "-",
                  env=env, stdin=message)
        return self._git("rev-parse", "HEAD", env=env).strip()

    def head(self, env: Mapping[str, str]) -> str:
        return self._git("rev-parse", "HEAD", env=env).strip()

    def push(self, branch: str, env: Mapping[str, str]) -> None:
        """Create ``branch`` on the remote. Never forced: an existing branch makes this fail."""
        self._git("push", "--quiet", "--no-verify", "origin", f"HEAD:refs/heads/{branch}", env=env)


def _make_writable(root: Path) -> None:
    for path in (root, *root.rglob("*")):
        if path.is_dir() and not path.is_symlink():
            try:
                path.chmod(0o755)
            except OSError:
                pass
        elif path.is_file() and not path.is_symlink():
            try:
                path.chmod(0o644)
            except OSError:
                pass
