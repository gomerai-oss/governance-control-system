"""Reading a repository's git history, and the identities its commits are checked against.

``git`` runs as ``git -C <root> ...`` (or ``git --git-dir <dir> ...`` when the git dir lies
outside the work tree) with a list argv, never a shell, and only the
read-only subcommands in ``READ_ONLY``. File-name lists use ``-z`` so any path is read
exactly. Every git failure, a missing ref and a shallow clone raise ``GitError``, which the
command line turns into exit 2.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from mission_router.router import load_config

READ_ONLY = ("rev-parse", "log", "show", "diff-tree", "ls-tree", "cat-file")
LANDING_RE = re.compile(r"^Mission (M-[A-Z0-9-]+): merge A3 round ([1-9][0-9]*) \(PASS\)$")
HAND_MERGE_RE = re.compile(r"^Merge pull request #([0-9]+) from ")
LANDING, HAND_MERGE, DIRECT = "landing", "hand_merge", "direct"
SHALLOW_MESSAGE = "shallow clone: full history required"
# GitHub writes a login's commits as <login>@ or <id>+<login>@ this domain.
NOREPLY_DOMAIN = "users.noreply.github.com"
# One commit per record: fields split by US, records split by NUL (-z). The subject is last,
# so a stray US inside it stays in the subject.
_FORMAT = "%H%x1f%P%x1f%an%x1f%ae%x1f%s"


class GitError(Exception):
    """git failed, the ref is missing, or the clone is shallow. Exit 2."""


def text(raw: bytes) -> str:
    """Git output as text. Undecodable bytes survive as surrogates, so a path is never altered."""
    return raw.decode("utf-8", "surrogateescape")


@dataclass(frozen=True)
class Commit:
    sha: str
    parents: Tuple[str, ...]
    author_name: str
    author_email: str
    subject: str

    @property
    def is_merge(self) -> bool:
        return len(self.parents) >= 2


@dataclass(frozen=True)
class Identities:
    """The logins the rules check against, all from ``mission_router/config.json``."""

    bot: str
    hitl: Tuple[str, ...]
    a2: str
    a3: str


def load_identities(path: Optional[str] = None) -> Identities:
    """``bot_login``, ``hitl_logins``, ``agents["a2"]`` and ``agents["a3"]`` via ``load_config``."""
    config = load_config(Path(path)) if path else load_config()
    agents = config["agents"]
    if not all(isinstance(agents.get(name), str) for name in ("a2", "a3")):
        raise ValueError("config.json: agents must name a2 and a3")
    return Identities(config["bot_login"], tuple(config["hitl_logins"]), agents["a2"], agents["a3"])


def authored_by(commit: Commit, login: str) -> bool:
    """Whether ``login`` wrote ``commit``: its author name is the login, or its author email is
    the login's GitHub no-reply address (``<login>@`` or ``<id>+<login>@users.noreply.github.com``).
    GitHub logins are case-insensitive, so the comparison is too."""
    want = login.casefold()
    if commit.author_name.casefold() == want:
        return True
    local, _, domain = commit.author_email.casefold().rpartition("@")
    if domain != NOREPLY_DOMAIN:
        return False
    return local == want or ("+" in local and local.split("+", 1)[1] == want)


def classify(commit: Commit) -> Tuple[str, Optional[re.Match]]:
    """A first-parent commit is exactly one of landing, hand_merge or direct."""
    match = LANDING_RE.match(commit.subject)
    if match:
        return LANDING, match
    match = HAND_MERGE_RE.match(commit.subject)
    if match:
        return HAND_MERGE, match
    return DIRECT, None


class Repo:
    """Read-only access to one repository, with every answer cached for the run."""

    def __init__(self, root: str, git_dir: Optional[str] = None) -> None:
        self.root = str(root)
        # A checkout whose git dir is kept outside its work tree (the dispatcher's layout) names it here.
        self._where = ["--git-dir", str(git_dir)] if git_dir else ["-C", self.root]
        self._commits: Dict[str, Commit] = {}
        self._files: Dict[str, Tuple[str, ...]] = {}
        self._trees: Dict[str, Tuple[str, ...]] = {}
        self._blobs: Dict[Tuple[str, str], Optional[str]] = {}

    def _run(self, *args: str, check: bool = True, data: Optional[bytes] = None) -> Optional[bytes]:
        if not args or args[0] not in READ_ONLY:
            raise GitError(f"refusing git subcommand {args[0] if args else '(none)'}")
        try:
            if data is None:
                done = subprocess.run(["git", *self._where, *args], capture_output=True, stdin=subprocess.DEVNULL)
            else:
                done = subprocess.run(["git", *self._where, *args], capture_output=True, input=data)
        except OSError as exc:
            raise GitError(f"git could not run: {exc}") from exc
        if done.returncode:
            if not check:
                return None
            lines = text(done.stderr).strip().splitlines()
            raise GitError(f"git {args[0]} failed: {lines[0] if lines else f'exit {done.returncode}'}")
        return done.stdout

    def ensure_full_history(self) -> None:
        if text(self._run("rev-parse", "--is-shallow-repository")).strip() == "true":
            raise GitError(SHALLOW_MESSAGE)

    def resolve(self, ref: str) -> str:
        """The sha40 of the commit ``ref`` names."""
        if not ref or ref.startswith("-"):
            raise GitError(f"unknown ref: {ref}")
        out = self._run("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}", check=False)
        sha = text(out).strip() if out is not None else ""
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise GitError(f"unknown ref: {ref}")
        return sha

    def _log(self, *args: str) -> List[Commit]:
        raw = self._run("log", "--no-show-signature", "-z", f"--format={_FORMAT}", *args)
        commits = []
        for record in raw.split(b"\0"):
            record = record.strip(b"\n")
            if not record:
                continue
            sha, parents, name, email, subject = text(record).split("\x1f", 4)
            commit = Commit(sha, tuple(parents.split()), name, email, subject)
            self._commits[sha] = commit
            commits.append(commit)
        return commits

    def first_parent(self, head: str) -> List[Commit]:
        """The first-parent history of ``head``, oldest first."""
        return self._log("--first-parent", "--reverse", head)

    def range(self, base: str, top: str) -> List[Commit]:
        """``git log base..top``: the commits reachable from ``top`` and not from ``base``."""
        return self._log(f"{base}..{top}")

    def commit(self, sha: str) -> Commit:
        if sha not in self._commits:
            found = self._log("-1", sha)
            if not found:
                raise GitError(f"unknown commit: {sha}")
        return self._commits[sha]

    def files(self, commit: Commit) -> Tuple[str, ...]:
        """The commit's changes against its first parent; a root commit's whole tree."""
        if commit.sha not in self._files:
            if commit.parents:
                raw = self._run("diff-tree", "-r", "--no-commit-id", "--no-renames", "--name-only", "-z",
                                commit.parents[0], commit.sha)
                self._files[commit.sha] = tuple(sorted({text(p) for p in raw.split(b"\0") if p}))
            else:
                self._files[commit.sha] = self.tree(commit.sha)
        return self._files[commit.sha]

    def prefetch_files(self, commits: List[Commit]) -> None:
        """``files`` for many commits in one ``git diff-tree --stdin`` call, the same answers as one call each.

        Each input line names a commit and its first parent; ``--always`` prints every commit's id, even with
        no changes, so the output splits at exactly the ids fed, in order."""
        todo = [c for c in commits if c.parents and c.sha not in self._files]
        if not todo:
            return
        feed = "".join(f"{c.sha} {c.parents[0]}\n" for c in todo).encode()
        raw = self._run("diff-tree", "--stdin", "--always", "-r", "--no-renames", "--name-only", "-z", data=feed)
        found: Dict[str, set] = {}
        index, current = 0, None
        for token in (text(t) for t in raw.split(b"\0") if t):
            if index < len(todo) and token == todo[index].sha:
                current = token
                found[current] = set()
                index += 1
            elif current is None:
                raise GitError("git diff-tree --stdin: output does not start with a commit id")
            else:
                found[current].add(token)
        if index != len(todo):
            raise GitError("git diff-tree --stdin: not every commit was answered")
        for sha, paths in found.items():
            self._files[sha] = tuple(sorted(paths))

    def tree(self, sha: str) -> Tuple[str, ...]:
        """Every path in the commit's tree."""
        if sha not in self._trees:
            raw = self._run("ls-tree", "-r", "--name-only", "-z", sha)
            self._trees[sha] = tuple(sorted({text(p) for p in raw.split(b"\0") if p}))
        return self._trees[sha]

    def show(self, sha: str, path: str) -> Optional[str]:
        """The file's text at the commit, or None when it is not there."""
        key = (sha, path)
        if key not in self._blobs:
            raw = self._run("cat-file", "blob", f"{sha}:{path}", check=False)
            self._blobs[key] = None if raw is None else raw.decode("utf-8", "replace")
        return self._blobs[key]
