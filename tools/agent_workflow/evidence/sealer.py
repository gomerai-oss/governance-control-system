"""The seal job (§3m item 2; part 4): seal each job's chain from one workflow run and add it to the store.

It is handed the run's ``evidence-*`` artifacts. For each chain it checks the chain (``verify.verify_run``), signs
its head with the evidence key, and adds the records and the seal to the store. A chain that does not verify is
not sealed or stored, and the run's PRs are not marked. The key must be one of the pinned evidence keys
(``key.json``): a seal no verifier would accept is never made.

``mark`` then sets the ``evidence-sealed`` check on the head of each PR the run published, which the router
requires under ``"evidence": "enforce"`` (item 6).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Mapping

from epap import ed25519
from epap.signing import dump
from evidence import EvidenceError
from evidence import chain as chain_mod
from evidence import record as rec_mod
from evidence import seal as seal_mod
from evidence import store as store_mod
from evidence import verify

SEAL_KEY_ENV = "EVIDENCE_SEAL_KEY"
CHECK_NAME = "evidence-sealed"


def find_runs(chains: Path) -> Dict[str, Path]:
    """Each chain under ``chains`` (downloaded artifacts), by run id. A run found twice is refused."""
    found: Dict[str, Path] = {}
    for path in sorted(Path(chains).rglob(chain_mod.RECORDS)):
        if path.is_symlink() or not path.is_file():
            continue
        run = path.parent.name
        if run in found:
            raise EvidenceError(f"chain {run} was handed over twice")
        found[run] = path.parent
    return found


def seed_from(text: str) -> bytes:
    text = (text or "").strip()
    if len(text) != 64 or any(c not in "0123456789abcdef" for c in text):
        raise EvidenceError(f"{SEAL_KEY_ENV} must be the 32-byte seed in lowercase hex")
    return bytes.fromhex(text)


def seal_runs(chains: Path, seed: bytes, keys: Mapping[str, str], store: "store_mod.Store", time: str) -> dict:
    """``{"sealed": [run], "refused": [{run, reason}], "prs": [{pr, run}]}``."""
    kid = seal_mod.keyid(ed25519.public_key(seed))
    if kid not in keys:
        raise EvidenceError("the seal key is not a pinned evidence key (evidence/key.json); nothing was sealed")
    out: dict = {"sealed": [], "refused": [], "prs": []}
    for run, directory in find_runs(chains).items():
        try:
            records, _ = verify.verify_run(directory, run, {})
        except verify.Refused as exc:
            out["refused"].append({"run": run, "reason": str(exc)})
            continue
        head = rec_mod.digest(records[-1]) if records else rec_mod.genesis(run)
        doc = seal_mod.make(run, head, len(records), {}, time, seed)
        message = f"Seal {run}: {len(records)} records"
        store.add(f"{store_mod.RUNS}/{run}/{chain_mod.RECORDS}", (directory / chain_mod.RECORDS).read_bytes(), message)
        store.add(f"{store_mod.RUNS}/{run}/{seal_mod.SEAL}", dump(doc), message)
        out["sealed"].append(run)
        for rec in records:
            if rec["action"] == "dispatch.publish" and rec["result"] == "done" and rec["subject"]["pr"]:
                out["prs"].append({"pr": rec["subject"]["pr"], "run": run})
    return out


def mark(result: Mapping, gh, store_repo: str) -> List[int]:
    """Set ``evidence-sealed`` on the head of each PR the run published, when every chain of the run was sealed.
    Returns the PRs marked."""
    if result.get("refused") or not result.get("sealed"):
        return []
    marked = []
    for entry in result.get("prs", []):
        pr = gh.request("GET", f"/pulls/{int(entry['pr'])}")
        sha = (pr.get("head") or {}).get("sha")
        if not sha:
            continue
        runs = "\n".join(f"- `{r}`" for r in result["sealed"])
        gh.create_check_run(CHECK_NAME, sha, "completed", "success", "Evidence sealed and stored",
                            f"Every chain of the run that published this PR is sealed and stored in `{store_repo}`:"
                            f"\n\n{runs}")
        marked.append(int(entry["pr"]))
    return marked


def keygen(repo: str, env: str, secret: str = SEAL_KEY_ENV, dry_run: bool = False, run=subprocess.run) -> dict:
    """Make an evidence key. The seed goes straight to the environment secret through ``gh secret set`` on stdin, and
    is never printed or written. Returns the ``key.json`` entry (the public half) to pin."""
    seed = ed25519.generate_seed()
    public = ed25519.public_key(seed)
    entry = {"keyid": seal_mod.keyid(public), "public": public.hex()}
    if not dry_run:
        done = run(["gh", "secret", "set", secret, "--env", env, "-R", repo], input=seed.hex(), text=True,
                   capture_output=True)
        if done.returncode != 0:
            raise EvidenceError(f"gh secret set failed: {(done.stderr or '').strip()[:300]}")
    del seed
    return entry


def write_json(path: str, doc) -> None:
    if path == "-":
        print(json.dumps(doc, indent=2, sort_keys=True))
        return
    Path(path).write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def warn(message: str) -> None:
    print(f"::warning::{message}", file=sys.stderr)
