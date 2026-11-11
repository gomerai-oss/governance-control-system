"""The evidence store (§3m item 3; part 4): a repository of its own, written by its own App, that only ever gains files.

A sealed run is stored as ``runs/<run>/records.jsonl`` and ``runs/<run>/seal.json``. Files are added through the
contents API without a ``sha``, which GitHub refuses when the file exists: a stored file is never replaced. A re-run
that would store the same bytes again is a no-op; different bytes are refused. The store's branch protection
(no force-push, no deletion) keeps its history, and ``evidence verify --store-history`` checks every stored file was
added once and never changed.
"""

from __future__ import annotations

import base64
import subprocess
from pathlib import Path
from typing import Callable, Dict, List, Optional

from evidence import EvidenceError

RUNS = "runs"
PACKS = "packs"  # the landing attestations (§3m item 2): kept like runs, added once and never changed


class Store:
    """Adds files to the store through ``request(method, path, body)`` (``mission_router.github.GitHub.request``)."""

    def __init__(self, request: Callable, branch: str = "main"):
        self.request = request
        self.branch = branch

    def _existing(self, path: str):
        from mission_router.github import GitHubError
        try:
            return self.request("GET", f"/contents/{path}?ref={self.branch}")
        except GitHubError as exc:
            if exc.status == 404:
                return None
            raise

    def holds(self, path: str) -> bool:
        return self._existing(path) is not None

    def add(self, path: str, data: bytes, message: str) -> str:
        """``"added"``, or ``"same"`` when the store already holds these bytes. Raises when it holds others."""
        from mission_router.github import GitHubError
        existing = self._existing(path)
        if existing is not None:
            held = base64.b64decode(existing.get("content") or "")
            if held == data:
                return "same"
            raise EvidenceError(f"{path} is already stored with different content; a stored file is never replaced")
        try:
            self.request("PUT", f"/contents/{path}", {"message": message, "branch": self.branch,
                                                      "content": base64.b64encode(data).decode("ascii")})
        except GitHubError as exc:
            raise EvidenceError(f"the store refused {path}: {exc.status}") from None
        return "added"


def history_problems(clone: Path) -> List[str]:
    """For a clone of the store: every file under ``runs/`` and ``packs/`` must have been added in one commit and never changed,
    renamed or deleted since (§3m item 3)."""
    done = subprocess.run(["git", "-C", str(clone), "log", "--format=%x00%H", "--name-status", "--no-renames", "--",
                           RUNS, PACKS], capture_output=True, text=True)
    if done.returncode != 0:
        return [f"the store's history cannot be read: {done.stderr.strip()[:200]}"]
    touched: Dict[str, List[str]] = {}
    for block in done.stdout.split("\x00")[1:]:
        lines = [l for l in block.splitlines() if l.strip()]
        sha = lines[0] if lines else ""
        for line in lines[1:]:
            status, _, path = line.partition("\t")
            touched.setdefault(path, []).append(f"{status[:1]}@{sha[:12]}")
    out = []
    for path, changes in sorted(touched.items()):
        if changes != [c for c in changes if c.startswith("A@")] or len(changes) != 1:
            out.append(f"{path} was changed after it was stored: {', '.join(reversed(changes))}")
    return out
