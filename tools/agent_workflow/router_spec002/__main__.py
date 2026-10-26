"""CLI for the ROUTER-POLICY-SPEC-002 decision point.

Live PR:
    python3 -m tools.agent_workflow.router_spec002 --repo OWNER/REPO --pr N \
        (--handoff-block-json JSON | --no-handoff-block) --waiver-state true|false

Offline request file (head_sha, files, complete, handoff_block, waiver_state):
    python3 -m tools.agent_workflow.router_spec002 --request-file request.json

Prints the decision as JSON. The process exit code is the decision exit_code.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Optional, Sequence

from .evaluator import Decision, FileChange, FileListing, evaluate
from .github_source import GitHubPullRequestSource


class StaticSource:
    def __init__(self, head_sha: Any, files: Any, complete: Any) -> None:
        self._head_sha = head_sha
        self._listing = FileListing(
            files=tuple(
                FileChange(path=f["path"], status=f["status"], previous_path=f.get("previous_path")) for f in files
            ),
            complete=complete,
        )

    def read_head_sha(self) -> Any:
        return self._head_sha

    def list_files(self) -> FileListing:
        return self._listing


_MISSING = object()


def _from_request_file(path: str) -> Decision:
    with open(path, encoding="utf-8") as handle:
        request = json.load(handle)
    required = ("head_sha", "files", "complete", "handoff_block", "waiver_state")
    if not isinstance(request, dict) or any(key not in request for key in required):
        raise ValueError(f"request file must define {', '.join(required)}")
    source = StaticSource(request["head_sha"], request["files"], request["complete"])
    return evaluate(source, request["handoff_block"], request["waiver_state"])


def _parse_waiver(text: str) -> Any:
    return {"true": True, "false": False}.get(text, _MISSING)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--request-file")
    parser.add_argument("--repo")
    parser.add_argument("--pr", type=int)
    block = parser.add_mutually_exclusive_group()
    block.add_argument("--handoff-block-json")
    block.add_argument("--no-handoff-block", action="store_true")
    parser.add_argument("--waiver-state")
    args = parser.parse_args(argv)

    try:
        if args.request_file:
            decision = _from_request_file(args.request_file)
        else:
            if not (args.repo and args.pr and args.waiver_state):
                parser.error("--repo, --pr and --waiver-state are required without --request-file")
            if args.handoff_block_json is None and not args.no_handoff_block:
                parser.error("state the handoff block explicitly: --handoff-block-json or --no-handoff-block")
            handoff_block = None if args.no_handoff_block else json.loads(args.handoff_block_json)
            if handoff_block is None and not args.no_handoff_block:
                handoff_block = {}
            source = GitHubPullRequestSource(args.repo, args.pr)
            decision = evaluate(source, handoff_block, _parse_waiver(args.waiver_state))
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc), "exit_code": 1, "merge_allowed": False}))
        return 1

    print(json.dumps(decision.to_dict(), indent=2, sort_keys=True))
    return decision.exit_code


if __name__ == "__main__":
    sys.exit(main())
