"""``python3 -m evidence``:

- ``verify --store DIR [--run RUN] [--keys key.json] [--sealed] [--files DIR] [--git DIR] [--store-history]``
  (§3m item 5);
- ``seal --chains DIR --store-repo OWNER/NAME --out FILE``: the seal job (item 2), with ``EVIDENCE_SEAL_KEY`` and
  ``STORE_TOKEN``;
- ``mark --repo OWNER/NAME --result FILE --store-repo OWNER/NAME``: the ``evidence-sealed`` checks, with
  ``GITHUB_TOKEN``;
- ``check --store DIR --git DIR --out FILE`` and ``report --repo OWNER/NAME --result FILE --sha SHA --store-repo
  OWNER/NAME``: the checker (item 7);
- ``store-name``: ``config.json``'s ``evidence_store``, for the seal workflow;
- ``keygen --repo OWNER/NAME --env ENV``: a new evidence key, its seed set as the environment secret by ``gh``, its
  public half printed to pin in ``key.json``.

Exit 0: verified. Exit 1: refused, naming the first problem. Exit 2: the key pin cannot be read. ``--sealed`` refuses a
run with no seal; without it, unsealed runs are listed (``"evidence": "observe"``).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from evidence import EvidenceError
from evidence import chain as chain_mod
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
    v.add_argument("--store-history", action="store_true",
                   help="the store is a clone: each stored file was added once and never changed")
    s = sub.add_parser("seal", help="seal and store a workflow run's chains (the seal job)")
    s.add_argument("--chains", required=True)
    s.add_argument("--store-repo", required=True)
    s.add_argument("--out", required=True)
    m = sub.add_parser("mark", help="set evidence-sealed on the PRs a sealed run published")
    m.add_argument("--repo", required=True)
    m.add_argument("--result", required=True)
    m.add_argument("--store-repo", required=True)
    c = sub.add_parser("check", help="the checker: verify the whole store and record the result (item 7)")
    c.add_argument("--store", required=True)
    c.add_argument("--git", help="this repository's clone, with full history")
    c.add_argument("--out", required=True)
    r = sub.add_parser("report", help="the checker's evidence-verified check and, on a failure, the HITL issue")
    r.add_argument("--repo", required=True)
    r.add_argument("--result", required=True)
    r.add_argument("--sha", required=True)
    r.add_argument("--store-repo", required=True)
    sub.add_parser("store-name", help="print full=<owner/name> and name=<name> of config.json's evidence_store")
    k = sub.add_parser("keygen", help="make an evidence key; the seed goes to the environment secret only")
    k.add_argument("--repo", required=True)
    k.add_argument("--env", required=True)
    k.add_argument("--dry-run", action="store_true", help="print a public half, set nothing (the seed is discarded)")
    args = parser.parse_args(argv)
    if args.command != "verify":
        return _other(args)
    try:
        keys = seal_mod.load_keys(Path(args.keys))
    except EvidenceError as exc:
        print(f"evidence: {exc}", file=sys.stderr)
        return 2
    report = verify.verify_store(Path(args.store), keys, args.run, args.sealed,
                                 Path(args.files) if args.files else None, Path(args.git) if args.git else None)
    problems = []
    if args.store_history:  # checked whether or not the chains verify: only it sees a run deleted whole (AST-6.2)
        from evidence import store as store_mod
        problems = store_mod.history_problems(Path(args.store))
    if not report.ok or problems:
        for line in ([report.failure] if not report.ok else []) + problems:
            print(f"REFUSED: {line}")
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


def _other(args) -> int:
    import os
    from evidence import sealer
    try:
        if args.command == "keygen":
            entry = sealer.keygen(args.repo, args.env, dry_run=args.dry_run)
            print("Pin this public half in tools/agent_workflow/evidence/key.json (the seed was "
                  + ("discarded" if args.dry_run else f"set as {sealer.SEAL_KEY_ENV} in environment {args.env}") + "):")
            print(json.dumps(entry, indent=2))
            return 0
        if args.command == "check":
            from evidence import checker, producer
            result = checker.check(Path(args.store), seal_mod.load_keys(), Path(args.git) if args.git else None,
                                   producer.Recorder.from_env(os.environ))
            sealer.write_json(args.out, result)
            print("verified" if result["ok"] else f"REFUSED: {result['failures'][0]}")
            return 0  # the report job turns a refusal into a failed check and an issue
        if args.command == "report":
            from evidence import checker
            from mission_router.github import GitHub
            result = json.loads(Path(args.result).read_text(encoding="utf-8"))
            done = checker.report(result, GitHub(os.environ["GITHUB_TOKEN"], args.repo), args.sha, args.store_repo,
                                  os.environ.get("RUN_URL", ""))
            print(done)
            return 0 if result["ok"] else 1
        if args.command == "store-name":
            from mission_router.router import load_config
            full = load_config().get("evidence_store") or ""
            if full:
                print(f"full={full}\nname={full.split('/', 1)[1]}")
            return 0
        from mission_router.github import GitHub
        if args.command == "seal":
            seed = sealer.seed_from(os.environ.get(sealer.SEAL_KEY_ENV, ""))
            from evidence import store as store_mod
            store = store_mod.Store(GitHub(os.environ["STORE_TOKEN"], args.store_repo).request)
            result = sealer.seal_runs(Path(args.chains), seed, seal_mod.load_keys(), store, chain_mod.now())
            sealer.write_json(args.out, result)
            for run in result["sealed"]:
                print(f"sealed: {run}")
            for r in result["refused"]:
                print(f"REFUSED: {r['run']}: {r['reason']}")
            return 1 if result["refused"] else 0
        if args.command == "mark":
            result = json.loads(Path(args.result).read_text(encoding="utf-8"))
            marked = sealer.mark(result, GitHub(os.environ["GITHUB_TOKEN"], args.repo), args.store_repo)
            print(f"marked: {', '.join(f'#{n}' for n in marked) or 'none'}")
            return 0
    except (EvidenceError, KeyError, OSError, ValueError) as exc:
        print(f"evidence {args.command}: {str(exc)[:500]}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
