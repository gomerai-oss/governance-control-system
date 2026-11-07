"""``python3 -m evidence verify --store DIR [--run RUN] [--keys key.json] [--sealed] [--files DIR] [--git DIR]``
(§3m item 5).

Exit 0: verified. Exit 1: refused, naming the first problem. Exit 2: the key pin cannot be read. ``--sealed`` refuses a
run with no seal; without it, unsealed runs are listed (``"evidence": "observe"``).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from evidence import EvidenceError
from evidence import seal as seal_mod
from evidence import verify


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m evidence")
    sub = parser.add_subparsers(dest="command", required=True)
    v = sub.add_parser("verify", help="replay and check a store's chains and seals")
    v.add_argument("--store", required=True)
    v.add_argument("--run")
    v.add_argument("--keys", default=str(seal_mod.KEYS_FILE))
    v.add_argument("--sealed", action="store_true", help="refuse a run with no seal")
    v.add_argument("--files", help="a run's downloaded artifacts: each recorded file there must match its digest")
    v.add_argument("--git", help="a clone: each record's commit must be in it")
    args = parser.parse_args(argv)
    try:
        keys = seal_mod.load_keys(Path(args.keys))
    except EvidenceError as exc:
        print(f"evidence: {exc}", file=sys.stderr)
        return 2
    report = verify.verify_store(Path(args.store), keys, args.run, args.sealed,
                                 Path(args.files) if args.files else None, Path(args.git) if args.git else None)
    if not report.ok:
        print(f"REFUSED: {report.failure}")
        return 1
    print(f"verified: {report.runs} runs, {report.records} records"
          + (f", {report.files_checked} files" if args.files else "")
          + (f", {report.commits_checked} commits" if args.git else ""))
    for name in report.ambiguous_files:
        print(f"not checked (found twice under --files): {name}")
    for name in report.unsealed:
        print(f"unsealed: {name}")
    for target, by in sorted(report.withdrawn.items()):
        print(f"withdrawn: {target} (by {by})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
