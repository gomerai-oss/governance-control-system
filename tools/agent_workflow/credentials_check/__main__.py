"""CLI: check the credentials register against the workflows (MISSION-DISPATCH-001 §3i item 3).

    PYTHONPATH=tools/agent_workflow python3 -m credentials_check --root <repo root> [--config <config.json>]
        [--workflows <dir>]

Prints one ``FINDING <text>`` line per finding, then ``findings=<count> mode=<mode>``. Exit 0 when there are none, or
under ``"identity": "observe"`` whatever they are; 1 on findings under ``"enforce"``; 2 when the config, the register
or a workflow cannot be read.

It also runs the substrate check before merge (MISSION-DISPATCH-001 §3h item 6): one ``SUBSTRATE <text>`` line per
mission-workflow job whose runner is not a GitHub-hosted ``ubuntu-*`` label, unless ``config.json`` names a substrate
declaration, then ``substrate_findings=<count> mode=<mode> declared=<file|none>`` before the last line. Those
findings fail the check only under ``"substrate": "enforce"``; a declaration that is named but unusable exits 2.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from mission_router.accounts import identity_mode
from mission_router.router import load_config
from mission_router import substrate

from .check import RegisterError, check, read_workflows


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="credentials_check", description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=".", help="the repository (default .)")
    parser.add_argument("--config", default=None, help="mission_router config.json (default: the router's own)")
    parser.add_argument("--workflows", default=None,
                        help="the workflow folder, relative to --root (default .github/workflows); a release that ships "
                             "its workflows to be installed checks them where they are, as packaging/workflows")
    args = parser.parse_args(argv)
    root = Path(args.root)
    try:
        config = load_config(Path(args.config)) if args.config else load_config()
        mode = identity_mode(config)
        path = config.get("credentials_register")
        if not isinstance(path, str) or not path:
            raise ValueError("config.json: credentials_register is required")
        register = (root / path).read_text(encoding="utf-8")
        workflows = read_workflows(root / (args.workflows or ".github/workflows"))
        substrate_mode = substrate.mode(config)
        declared = substrate.declaration(config, root)
    except (OSError, ValueError, RegisterError, UnicodeDecodeError) as exc:
        print(f"credentials_check: {exc}", file=sys.stderr)
        return 2
    findings = check(register, workflows)
    on_substrate = [] if declared else substrate.static_findings(workflows)
    for finding in on_substrate:
        print(f"SUBSTRATE {finding}")
    print(f"substrate_findings={len(on_substrate)} mode={substrate_mode} declared={declared or 'none'}")
    for finding in findings:
        print(f"FINDING {finding}")
    print(f"findings={len(findings)} mode={mode}")
    return 1 if (findings and mode == "enforce") or (on_substrate and substrate_mode == "enforce") else 0


if __name__ == "__main__":
    sys.exit(main())
