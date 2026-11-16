"""CLI for the egress proxy (MISSION-DISPATCH-001 §3h item 3).

    PYTHONPATH=tools/agent_workflow python3 -m egress serve --policy FILE --runtime NAME --mode observe|enforce
        --log FILE --ready FILE [--login-file FILE [--exclusive]] [--apps FILE [--app-keys-file FILE]]

Runs until killed. Writes the port it listens on (127.0.0.1) to --ready once it accepts connections; exit 2 on a
malformed policy or an unknown runtime. With --login-file it also serves the runtime's model endpoint under /model/
(MISSION-DISPATCH-001 §3i item 6): the file is read and deleted at start, and --exclusive refuses tunnels to the model
host. With --apps (the tooling tree's app register) it refuses a tunnel to any host the register lists, and with
--app-keys-file too it serves the app endpoint under /app/ (§3p, Amendment 028): that file is read and deleted at
start, like the login file.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from egress.proxy import MODES, PolicyError, load_model_endpoints, load_policy, serve


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="step", required=True)
    run = sub.add_parser("serve")
    run.add_argument("--policy", required=True)
    run.add_argument("--runtime", required=True)
    run.add_argument("--mode", required=True, choices=MODES)
    run.add_argument("--log", required=True)
    run.add_argument("--ready", required=True)
    run.add_argument("--login-file", default=None)
    run.add_argument("--exclusive", action="store_true")
    run.add_argument("--apps", default=None)
    run.add_argument("--app-keys-file", default=None)
    args = parser.parse_args(argv)
    try:
        text = Path(args.policy).read_text(encoding="utf-8")
        if args.exclusive and not args.login_file:
            raise PolicyError("--exclusive needs --login-file")
        if args.app_keys_file and not args.apps:
            raise PolicyError("--app-keys-file needs --apps")
        serve(load_policy(text), args.runtime, args.mode, Path(args.log), Path(args.ready),
              models=load_model_endpoints(text), login_file=Path(args.login_file) if args.login_file else None,
              exclusive=args.exclusive, apps_file=Path(args.apps) if args.apps else None,
              app_keys_file=Path(args.app_keys_file) if args.app_keys_file else None)
    except (OSError, PolicyError) as exc:
        print(f"egress: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
