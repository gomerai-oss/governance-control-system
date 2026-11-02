"""CLI for the egress proxy (MISSION-DISPATCH-001 §3h item 3).

    PYTHONPATH=tools/agent_workflow python3 -m egress serve --policy FILE --runtime NAME --mode observe|enforce
        --log FILE --ready FILE

Runs until killed. Writes the port it listens on (127.0.0.1) to --ready once it accepts connections; exit 2 on a
malformed policy or an unknown runtime.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from egress.proxy import MODES, PolicyError, load_policy, serve


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="step", required=True)
    run = sub.add_parser("serve")
    run.add_argument("--policy", required=True)
    run.add_argument("--runtime", required=True)
    run.add_argument("--mode", required=True, choices=MODES)
    run.add_argument("--log", required=True)
    run.add_argument("--ready", required=True)
    args = parser.parse_args(argv)
    try:
        serve(load_policy(Path(args.policy).read_text(encoding="utf-8")), args.runtime, args.mode, Path(args.log),
              Path(args.ready))
    except (OSError, PolicyError) as exc:
        print(f"egress: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
