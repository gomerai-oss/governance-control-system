"""CLI: one idempotent sweep over every mission.

    PYTHONPATH=tools/agent_workflow python3 -m mission_router --repo OWNER/REPO [--dry-run]

Needs GITHUB_TOKEN. Exit 0 when the sweep ran (per-mission blocks are reported, not errors).
"""

from __future__ import annotations

import argparse
import os
import sys

from router_spec002.policy import load_tables, normalize_path

from .gate import classify_or_raise
from .github import GitHub
from .router import MissionRouter, load_config


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--dry-run", action="store_true", help="read and decide, but write nothing to GitHub")
    args = parser.parse_args(argv)
    gh = GitHub(os.environ.get("GITHUB_TOKEN", ""), args.repo)
    router = MissionRouter(gh, load_config(), classify_or_raise(load_tables(), normalize_path), dry_run=args.dry_run)
    states = router.sweep()
    print(f"swept {len(states)} mission(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
