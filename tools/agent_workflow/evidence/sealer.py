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
from evidence import pack as pack_mod
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


# Runs that never hold a mission's records: the credentials check's and the checker's.
_NO_MISSION = ("-credentials", "-verify")


def _stored_records(store: "store_mod.Store") -> List[dict]:
    """The records of every run that can hold a mission's records, read back from the store (the landing attestation
    cites a mission's records across all its runs). Listed through the git trees API, which says when its listing is
    truncated, never through the contents API, which stops at 1,000 entries without saying so."""
    import base64
    import json
    tree = store.request("GET", f"/git/trees/{store.branch}?recursive=1")
    if tree.get("truncated"):
        raise EvidenceError("the store's tree is too large to list in one call; the landing attestation needs all of it")
    out: List[dict] = []
    for entry in tree.get("tree", []):
        path = entry.get("path", "")
        parts = path.split("/")
        if entry.get("type") != "blob" or len(parts) != 3 or parts[0] != store_mod.RUNS \
                or parts[2] != chain_mod.RECORDS or parts[1].endswith(_NO_MISSION):
            continue
        data = base64.b64decode(store.request("GET", f"/git/blobs/{entry['sha']}").get("content") or "")
        out += [json.loads(line) for line in data.decode("utf-8").splitlines() if line]
    return out


def seal_runs(chains: Path, seed: bytes, keys: Mapping[str, str], store: "store_mod.Store", time: str,
              worm=None, repository: str = "", resume: bool = False) -> dict:
    """``{"sealed": [run], "refused": [{run, reason}], "prs": [{pr, run}]}``. With ``worm`` (a declared WORM bucket),
    each run's records and seal are also copied there once they are in the store; a copy the bucket refuses fails the
    job, so the run's PRs are not marked. With ``resume`` (the sweep, Amendment 022), a chain the store already holds
    a seal for is not sealed again: its records must be the stored ones, and it counts as sealed for marking, with no
    second seal and no second landing attestation."""
    kid = seal_mod.keyid(ed25519.public_key(seed))
    if kid not in keys:
        raise EvidenceError("the seal key is not a pinned evidence key (evidence/key.json); nothing was sealed")
    out: dict = {"sealed": [], "refused": [], "prs": [], "packs": []}
    landed: List[dict] = []
    for run, directory in find_runs(chains).items():
        try:
            records, _ = verify.verify_run(directory, run, {})
        except verify.Refused as exc:
            out["refused"].append({"run": run, "reason": str(exc)})
            continue
        head = rec_mod.digest(records[-1]) if records else rec_mod.genesis(run)
        doc = seal_mod.make(run, head, len(records), {}, time, seed)
        message = f"Seal {run}: {len(records)} records"
        records_bytes, seal_bytes = (directory / chain_mod.RECORDS).read_bytes(), dump(doc)
        store.add(f"{store_mod.RUNS}/{run}/{chain_mod.RECORDS}", records_bytes, message)
        if resume and store.holds(f"{store_mod.RUNS}/{run}/{seal_mod.SEAL}"):
            out["sealed"].append(run)  # sealed by an earlier sweep that stopped part way; its records are the stored ones
            out["prs"] += _published(records, run)
            continue
        store.add(f"{store_mod.RUNS}/{run}/{seal_mod.SEAL}", seal_bytes, message)
        if worm is not None:
            worm.put(f"{store_mod.RUNS}/{run}/{chain_mod.RECORDS}", records_bytes)
            worm.put(f"{store_mod.RUNS}/{run}/{seal_mod.SEAL}", seal_bytes)
        out["sealed"].append(run)
        out["prs"] += _published(records, run)
        landed += pack_mod.landings(records)
    if landed and repository:  # each landing's attestation, once its run is in the store (§3m item 2)
        everything = _stored_records(store)
        for landing in landed:
            name = pack_mod.name_for(landing)
            data = pack_mod.sign(pack_mod.statement(landing, everything, repository), seed)
            store.add(name, data, f"Landing provenance for {landing['subject']['mission']} ({landing['id']})")
            if worm is not None:
                worm.put(name, data)
            out["packs"].append(name)
    return out


def _published(records: List[dict], run: str) -> List[dict]:
    return [{"pr": rec["subject"]["pr"], "run": run} for rec in records
            if rec["action"] == "dispatch.publish" and rec["result"] == "done" and rec["subject"]["pr"]]


def backfill(request, bucket) -> Dict[str, int]:
    """Copy every file the store already holds under ``runs/`` to the WORM bucket (§3m item 3): runs sealed before the
    bucket was declared. ``request`` is the store's GitHub client (the evidence App's token can read the store). A copy
    already there is left as it is. Returns ``{"added": n, "present": n}``."""
    import base64
    tree = request("GET", f"/git/trees/{store_mod.Store(request).branch}?recursive=1")
    if tree.get("truncated"):
        raise EvidenceError("the store's tree is too large to list in one call; backfill in parts")
    counts = {"added": 0, "present": 0}
    for entry in tree.get("tree", []):
        path = entry.get("path", "")
        if entry.get("type") != "blob" or not path.startswith(f"{store_mod.RUNS}/"):
            continue
        blob = request("GET", f"/git/blobs/{entry['sha']}")
        data = base64.b64decode(blob.get("content") or "")
        counts[bucket.put(path, data)] += 1
    return counts


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
