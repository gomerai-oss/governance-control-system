"""Pull request source backed by the GitHub REST API through the ``gh`` CLI.

Any API failure raises, which the evaluator converts to ``DIFF_UNKNOWN``.

The file list is read from ``compare/{base_sha}...{head_sha}`` using the SHAs from
the same PR read, not from ``pulls/{n}/files``. The PR files endpoint always
lists the *current* head, so a head that moves A -> B -> A between the two SHA
reads would bind B's file list to commit A. The compare endpoint is pinned to
the exact SHA the decision binds to.
"""

from __future__ import annotations

import json
import re
import subprocess
from typing import Callable, List, Optional, Sequence, Tuple

from .evaluator import FileChange, FileListing

# GitHub's compare endpoint returns at most 300 changed files. A listing that
# reaches the cap cannot be shown complete, so it is never treated as complete.
GITHUB_COMPARE_FILES_CAP = 300
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")

Runner = Callable[[Sequence[str]], str]


def _run_gh(args: Sequence[str]) -> str:
    result = subprocess.run(["gh", "api", *args], capture_output=True, text=True, timeout=60, check=True)
    return result.stdout


class GitHubPullRequestSource:
    def __init__(self, repo: str, pr_number: int, runner: Runner = _run_gh) -> None:
        if not _REPO_RE.match(repo) or not isinstance(pr_number, int) or pr_number <= 0:
            raise ValueError("invalid repo or PR number")
        self._repo = repo
        self._base = f"repos/{repo}/pulls/{pr_number}"
        self._runner = runner
        self._snapshot: Optional[Tuple[str, str, int]] = None

    def read_head_sha(self) -> str:
        pr = json.loads(self._runner([self._base]))
        changed = pr["changed_files"]
        if not isinstance(changed, int) or changed < 0:
            raise ValueError("changed_files missing")
        head_sha = pr["head"]["sha"]
        base_sha = pr["base"]["sha"]
        if not all(isinstance(s, str) and _SHA_RE.match(s) for s in (head_sha, base_sha)):
            raise ValueError("head or base sha malformed")
        if self._snapshot is None:
            self._snapshot = (head_sha, base_sha, changed)
        return head_sha

    def list_files(self) -> FileListing:
        if self._snapshot is None:
            raise RuntimeError("read_head_sha must run before list_files")
        head_sha, base_sha, changed = self._snapshot
        comparison = json.loads(self._runner([f"repos/{self._repo}/compare/{base_sha}...{head_sha}"]))
        batch = comparison["files"]
        if not isinstance(batch, list):
            raise ValueError("unexpected compare payload")
        files: List[FileChange] = [
            FileChange(path=item["filename"], status=item["status"], previous_path=item.get("previous_filename"))
            for item in batch
        ]
        complete = len(files) == changed and changed < GITHUB_COMPARE_FILES_CAP
        return FileListing(files=tuple(files), complete=complete)
