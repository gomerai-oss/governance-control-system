"""CLI: serve governed retrieval as an MCP server on stdio.

    PYTHONPATH=tools/agent_workflow python3 -m mcp_gateway --root CHECKOUT --session FILE --evidence-dir DIR [--git-dir DIR]

--root          the agent's checkout; the only tree retrieval reads
--session       the launcher's session file, outside the checkout
--evidence-dir  where decisions.jsonl is appended, outside the checkout
--git-dir       the checkout's git dir, when it lies outside the work tree (read by ``trace``)

Exit 0 at end of input; 2 when the gateway refuses to start (the reason on stderr).
"""

from __future__ import annotations

import argparse
import sys

from mcp_gateway import protocol, server


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="mcp_gateway", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", required=True)
    parser.add_argument("--session", required=True)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--git-dir", default=None)
    args = parser.parse_args(argv)
    try:
        gateway = server.Gateway(args.root, args.session, args.evidence_dir, git_dir=args.git_dir)
    except server.GatewayError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    protocol.serve(protocol.Endpoint(gateway), sys.stdin.buffer, sys.stdout.buffer)
    return 0


if __name__ == "__main__":
    sys.exit(main())
