"""CLI: check the credentials register against the workflows (MISSION-DISPATCH-001 §3i item 3).

    PYTHONPATH=tools/agent_workflow python3 -m credentials_check --root <repo root> [--config <config.json>]
        [--workflows <dir>] [--tooling <dir>] [--base <dir>]

Prints one ``FINDING <text>`` line per finding, then ``findings=<count> mode=<mode>``. Exit 0 when there are none, or
under ``"identity": "observe"`` whatever they are; 1 on findings under ``"enforce"``; 2 when the config, the register
or a workflow cannot be read.

It also runs the substrate check before merge (MISSION-DISPATCH-001 §3h item 6): one ``SUBSTRATE <text>`` line per
mission-workflow job whose runner is not a GitHub-hosted ``ubuntu-*`` label, unless ``config.json`` names a substrate
declaration, then ``substrate_findings=<count> mode=<mode> declared=<file|none>`` before the last line. Those
findings fail the check only under ``"substrate": "enforce"``; a declaration that is named but unusable exits 2.

And it runs ring 2's checks (MISSION-DISPATCH-001 §3k): one ``DESCRIPTION <text>`` line per gateway tool description
that fails item 1, then ``description_findings=<count> mode=<mode>``, failing the check only under
``"permissions": "enforce"``; and, with ``--base`` (the PR's base, checked out beside the head), one ``GRANT <text>``
line per widening from the base (item 3), then ``grants=<count>``. Grant lines never fail the check. Both lists are
also written to the step summary when ``GITHUB_STEP_SUMMARY`` is set.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import List, Optional

from mission_router.accounts import identity_mode
from mission_router.router import load_config
from mission_router import substrate
from mission_dispatch import permissions

from .check import RegisterError, check, read_workflows


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="credentials_check", description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=".", help="the repository (default .)")
    parser.add_argument("--config", default=None, help="mission_router config.json (default: the router's own)")
    parser.add_argument("--workflows", default=None,
                        help="the workflow folder, relative to --root (default .github/workflows); a release that ships "
                             "its workflows to be installed checks them where they are, as packaging/workflows")
    parser.add_argument("--tooling", default=permissions.TOOLING,
                        help=f"the tooling tree, relative to --root (default {permissions.TOOLING})")
    parser.add_argument("--base", default=None,
                        help="the PR's base tree; with it, every widening from the base is listed as a GRANT line")
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
        permissions_mode = permissions.mode(config)
        catalog_path = root / args.tooling / permissions.CATALOG
        on_descriptions = (permissions.description_findings(permissions.read_catalog(catalog_path))
                           if catalog_path.is_file() else [f"no gateway catalog at {args.tooling}/{permissions.CATALOG}"])
        grants = (permissions.grant_lines(Path(args.base), root, args.tooling, args.workflows or ".github/workflows")
                  if args.base else [])
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
    for finding in on_descriptions:
        print(f"DESCRIPTION {finding}")
    print(f"description_findings={len(on_descriptions)} mode={permissions_mode}")
    for line in grants:
        print(f"GRANT {line}")
    print(f"grants={len(grants)} base={'given' if args.base else 'none'}")
    for finding in findings:
        print(f"FINDING {finding}")
    print(f"findings={len(findings)} mode={mode}")
    _summary(on_descriptions, permissions_mode, grants, bool(args.base))
    return 1 if ((findings and mode == "enforce") or (on_substrate and substrate_mode == "enforce")
                 or (on_descriptions and permissions_mode == "enforce")) else 0


def _summary(descriptions: List[str], permissions_mode: str, grants: List[str], based: bool) -> None:
    """Ring 2's two lists in the check run's summary (MISSION-DISPATCH-001 §3k items 1 and 3)."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    out = [f"### Tool descriptions ({permissions_mode})", ""]
    out += [f"- {d}" for d in descriptions] or ["Every gateway tool description passes."]
    out += ["", "### Grant changes", ""]
    if not based:
        out.append("No base tree was given, so widenings were not compared.")
    else:
        out += [f"- {g}" for g in grants] or ["This change widens no grant."]
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("\n".join(out) + "\n")
    except OSError:
        pass


if __name__ == "__main__":
    sys.exit(main())
