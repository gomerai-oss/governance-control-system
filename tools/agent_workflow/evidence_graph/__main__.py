"""``python3 -m evidence_graph build|check|trace``: prove every mission landing from git history.

Exit codes: ``build`` and ``check`` 0 with no findings, 1 with findings; ``trace`` 0 when the
path appears, 2 when it never does. Usage errors, shallow clones, missing refs and git
failures exit 2 with one line on stderr.
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from .graph import Entry, build_graph, canonical, counts, sorted_findings, walk
from .history import HAND_MERGE, LANDING, GitError, Repo, load_identities


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # one line on stderr, exit 2
        print(f"{self.prog}: {message}", file=sys.stderr)
        sys.exit(2)


def _parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--root", default=".", help="the repository (default .)")
    common.add_argument("--ref", default="HEAD", help="the ref whose first-parent history is walked (default HEAD)")
    common.add_argument("--config", default=None, help="mission_router config.json (default: the router's own)")
    parser = _Parser(prog="python3 -m evidence_graph", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build", parents=[common], help="write the evidence graph")
    build.add_argument("--out", required=True, help="the file the graph is written to")
    sub.add_parser("check", parents=[common], help="report every landing that cannot be proven")
    trace = sub.add_parser("trace", parents=[common], help="list the first-parent changes to a path, newest first")
    trace.add_argument("path")
    return parser


def _one_line(text: str) -> str:
    return " ".join(str(text).split())


def _sha12(sha: Optional[str]) -> str:
    return sha[:12] if sha else "-"


def trace_line(entry: Entry) -> str:
    if entry.kind == LANDING:
        proof = entry.proof
        final = proof.reviews.get(proof.round)
        line = (f"mission {proof.mission} landing {_sha12(entry.commit.sha)} plan {_sha12(proof.plan_sha)} "
                f"approval {proof.approval_kind or '-'} review round {proof.round} "
                f"{(final.verdict if final and final.verdict else '-')} on {_sha12(final.reviewed_sha if final else None)} "
                f"specs {','.join(proof.specs) or '-'}")
        if proof.findings:
            line += f" UNPROVEN {','.join(proof.rules)}"
        return line
    if entry.kind == HAND_MERGE:
        return f"hand-merge #{entry.pr} {_sha12(entry.commit.sha)} independent-review none"
    return f"direct {_sha12(entry.commit.sha)} independent-review none"


def main(argv: Optional[List[str]] = None) -> int:
    args = _parser().parse_args(argv)
    try:
        ids = load_identities(args.config)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        print(_one_line(f"config: {exc}"), file=sys.stderr)
        return 2
    repo = Repo(args.root)
    try:
        if args.command == "build":
            doc, _ = build_graph(repo, ids, args.ref)
            try:
                with open(args.out, "wb") as handle:
                    handle.write(canonical(doc))
            except OSError as exc:
                print(_one_line(f"cannot write {args.out}: {exc}"), file=sys.stderr)
                return 2
            return 0 if not doc["findings"] else 1

        repo.ensure_full_history()
        head = repo.resolve(args.ref)
        entries = walk(repo, ids, head)
        if args.command == "check":
            for finding in sorted_findings(entries):
                print(f"FINDING {finding['mission']} {finding['rule']} {finding['landing'][:12]} "
                      f"{_one_line(finding['detail'])}")
            total = counts(entries)
            print(" ".join(f"{key}={total[key]}" for key in ("landings", "proven", "findings", "hand_merges", "direct")))
            return 0 if not total["findings"] else 1

        repo.prefetch_files([e.commit for e in entries])
        lines = [trace_line(e) for e in reversed(entries) if args.path in repo.files(e.commit)]
    except GitError as exc:
        print(_one_line(str(exc)), file=sys.stderr)
        return 2
    if not lines:
        print(_one_line(f"{args.path} never changed on the first-parent history of {args.ref}"), file=sys.stderr)
        return 2
    for line in lines:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
