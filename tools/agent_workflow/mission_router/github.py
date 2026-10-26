"""Minimal GitHub REST client for the mission router (stdlib only).

Every path segment that comes from GitHub data or agent input is quoted, and
callers only pass values that already passed the model's validators.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Iterator, Optional

API = "https://api.github.com"


class GitHubError(RuntimeError):
    def __init__(self, status: int, message: str, path: str) -> None:
        super().__init__(f"GitHub {status} on {path}: {message}")
        self.status = status
        self.message = message


def q(segment: str) -> str:
    """Quote one URL path segment (branch names keep their slashes)."""
    return urllib.parse.quote(segment, safe="/")


class GitHub:
    def __init__(self, token: str, repo: str, api: str = API, timeout: int = 30) -> None:
        if not token:
            raise ValueError("GITHUB_TOKEN is required")
        owner, _, name = repo.partition("/")
        if not owner or not name or "/" in name:
            raise ValueError("repo must be OWNER/NAME")
        self._token = token
        self.repo = repo
        self._api = api
        self._timeout = timeout

    def request(self, method: str, path: str, body: Optional[Dict[str, Any]] = None, raw: bool = False) -> Any:
        url = path if path.startswith("https://") else f"{self._api}/repos/{self.repo}{path}"
        if not url.startswith(self._api + "/"):
            raise ValueError("refusing a request outside the GitHub API")
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self._token}")
        req.add_header("Accept", "application/vnd.github.raw" if raw else "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                payload = resp.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")
            try:
                detail = json.loads(detail).get("message", detail)
            except ValueError:
                pass
            raise GitHubError(exc.code, str(detail)[:500], path) from None
        if raw:
            return payload.decode("utf-8")
        return json.loads(payload) if payload else None

    def get(self, path: str, raw: bool = False) -> Any:
        return self.request("GET", path, raw=raw)

    def paginate(self, path: str, limit: int = 2000) -> Iterator[Any]:
        sep = "&" if "?" in path else "?"
        page, seen = 1, 0
        while True:
            batch = self.get(f"{path}{sep}per_page=100&page={page}")
            if not isinstance(batch, list):
                raise GitHubError(0, "expected a list", path)
            for item in batch:
                yield item
                seen += 1
                if seen >= limit:
                    return
            if len(batch) < 100:
                return
            page += 1

    # -- reads -----------------------------------------------------------
    def file_at(self, path: str, ref: str) -> Optional[str]:
        try:
            return self.get(f"/contents/{q(path)}?ref={q(ref)}", raw=True)
        except GitHubError as exc:
            if exc.status == 404:
                return None
            raise

    def list_dir(self, path: str, ref: str) -> list:
        try:
            items = self.get(f"/contents/{q(path)}?ref={q(ref)}")
        except GitHubError as exc:
            if exc.status == 404:
                return []
            raise
        return items if isinstance(items, list) else []

    def branch_head(self, branch: str) -> Optional[str]:
        try:
            return self.get(f"/git/ref/heads/{q(branch)}")["object"]["sha"]
        except GitHubError as exc:
            if exc.status == 404:
                return None
            raise

    def compare(self, base: str, head: str) -> dict:
        return self.get(f"/compare/{q(base)}...{q(head)}")

    def activity(self, branch: str, limit: int) -> list:
        """GitHub's own record of every update to a branch: who pushed, created or force-pushed it, and the SHAs."""
        return list(self.paginate(f"/activity?ref={urllib.parse.quote('refs/heads/' + branch, safe='')}", limit=limit))

    def pulls_from(self, branch: str) -> list:
        """Every PR (open or closed) whose head is ``branch`` in this repository."""
        owner = self.repo.partition("/")[0]
        head = urllib.parse.quote(f"{owner}:{branch}", safe="")
        return list(self.paginate(f"/pulls?state=all&head={head}", limit=100))

    def check_runs(self, sha: str, name: str) -> list:
        data = self.get(f"/commits/{q(sha)}/check-runs?check_name={urllib.parse.quote(name, safe='')}&filter=latest")
        return list((data or {}).get("check_runs") or [])

    # -- writes ----------------------------------------------------------
    def create_branch(self, branch: str, sha: str) -> None:
        self.request("POST", "/git/refs", {"ref": f"refs/heads/{branch}", "sha": sha})

    def update_ref(self, branch: str, sha: str) -> None:
        """Fast-forward only: GitHub refuses the update if it would drop commits."""
        self.request("PATCH", f"/git/refs/heads/{q(branch)}", {"sha": sha, "force": False})

    def delete_branch(self, branch: str) -> None:
        """Delete ``branch``; GitHub closes any open PR from it. Already gone counts as done."""
        try:
            self.request("DELETE", f"/git/refs/heads/{q(branch)}")
        except GitHubError as exc:
            if exc.status not in (404, 422):
                raise

    def retarget(self, number: int, base: str) -> None:
        self.request("PATCH", f"/pulls/{number}", {"base": base})

    def approve(self, number: int, sha: str, body: str) -> None:
        self.request("POST", f"/pulls/{number}/reviews", {"commit_id": sha, "event": "APPROVE", "body": body})

    def merge(self, number: int, sha: str, title: str) -> dict:
        return self.request("PUT", f"/pulls/{number}/merge", {"sha": sha, "merge_method": "merge", "commit_title": title})

    def create_check_run(self, name: str, sha: str, status: str, conclusion: Optional[str], title: str, summary: str) -> None:
        body: Dict[str, Any] = {"name": name, "head_sha": sha, "status": status,
                                "output": {"title": title[:255], "summary": summary[:60000]}}
        if conclusion:
            body["conclusion"] = conclusion
        self.request("POST", "/check-runs", body)

    def create_pull(self, head: str, base: str, title: str, body: str) -> dict:
        return self.request("POST", "/pulls", {"head": head, "base": base, "title": title, "body": body,
                                               "maintainer_can_modify": False})

    def dispatch_workflow(self, workflow: str, ref: str) -> None:
        """Start ``workflow`` (a file name under .github/workflows) on ``ref``. No inputs are passed."""
        self.request("POST", f"/actions/workflows/{q(workflow)}/dispatches", {"ref": ref})

    def comment(self, number: int, body: str) -> None:
        self.request("POST", f"/issues/{number}/comments", {"body": body})

    def ensure_label(self, name: str, color: str, description: str) -> None:
        try:
            self.request("POST", "/labels", {"name": name, "color": color, "description": description})
        except GitHubError as exc:
            if exc.status != 422:  # already exists
                raise
