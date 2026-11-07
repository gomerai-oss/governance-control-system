"""Producers' side of the record (§3m item 1; part 2): how a pipeline job writes its records.

A job that records sets two variables before its first recording step:
- ``EVIDENCE_DIR``: where the job's chains are kept (``$RUNNER_TEMP/evidence``), created ``0700``;
- ``EVIDENCE_RUN``: the job's chain id, ``gh-<run id>-<attempt>-<job>[-<lane>]``.

Without both, nothing is recorded. The chain is the job's: a workflow run's jobs run on different machines, so each
writes its own, and the seal (part 4) covers each one. The agent never sees either variable
(``runtimes.agent_env``), and under the blast radius (§3h) it runs as an account that cannot open the directory.

Under ``"evidence": "observe"`` a record that cannot be written is a warning: the step's own result stands.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Tuple

from evidence import EvidenceError
from evidence import chain as chain_mod
from evidence import verify

DIR_ENV, RUN_ENV = "EVIDENCE_DIR", "EVIDENCE_RUN"
ENV_PREFIX = "EVIDENCE_"
# Records written from one log (the gateway's decisions, the egress log) are bounded; past the bound one record says
# how many lines were left out, with the whole log's digest (it is kept with the run's artifact).
LOG_RECORDS_MAX = 2000
_RUN = re.compile(r"[^A-Za-z0-9_.-]+")


def chain_id(*parts: object) -> str:
    """A chain id from its parts, with anything outside the id's characters replaced."""
    return _RUN.sub("-", "-".join(str(p) for p in parts if p not in (None, ""))).strip("-.")[:128]


def file_digest(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 16), b""):
            h.update(block)
    return h.hexdigest()


def text_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def file_digests(directory: Path, names: Iterable[str]) -> Dict[str, str]:
    """``{basename: sha256}`` for each of ``names`` (relative to ``directory``) that is a regular file."""
    out: Dict[str, str] = {}
    for name in names:
        path = Path(directory) / name
        if path.is_file() and not path.is_symlink():
            out[Path(name).name] = file_digest(path)
    return out


def log_lines(path: Path) -> Iterator[Tuple[int, str, Optional[dict]]]:
    """``(line number, line, parsed object or None)`` for a JSON-lines log; nothing when the log is absent."""
    if not (path.is_file() and not path.is_symlink()):
        return
    with open(path, encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            line = line.rstrip("\n")
            try:
                value = json.loads(line)
            except ValueError:
                value = None
            yield n, line, value if isinstance(value, dict) else None


class Recorder:
    """Appends records to this job's chain. Disabled (records nothing) when the job set no chain."""

    def __init__(self, directory: Optional[Path], run: str, warn=None):
        self.enabled = directory is not None and bool(run)
        self.warn = warn or (lambda m: print(f"::warning::{m}", file=sys.stderr))
        self.chain: Optional[chain_mod.Chain] = None
        self.failed = False
        if self.enabled:
            try:
                base = Path(directory)
                base.mkdir(mode=0o700, parents=True, exist_ok=True)
                (base / verify.RUNS).mkdir(mode=0o700, exist_ok=True)
                self.chain = chain_mod.Chain(base / verify.RUNS / run, run)
            except (OSError, EvidenceError) as exc:
                self._fail(exc)

    @classmethod
    def from_env(cls, environ: Mapping[str, str] = os.environ, warn=None) -> "Recorder":
        directory, run = environ.get(DIR_ENV, ""), environ.get(RUN_ENV, "")
        return cls(Path(directory) if directory and run else None, run, warn)

    def _fail(self, exc: Exception) -> None:
        self.failed = True
        self.chain = None
        self.warn(f"evidence: not recorded: {str(exc)[:300]}")

    def record(self, **fields: Any) -> Optional[dict]:
        """One record (see ``record.make`` for the fields; ``run``, ``seq``, ``prev`` and ``time`` are the chain's).
        Returns it, or None when disabled or when it could not be written."""
        if self.chain is None:
            return None
        try:
            return self.chain.append(**fields)
        except (OSError, EvidenceError) as exc:
            self._fail(exc)
            return None

    def from_log(self, path: Path, action: str, actor: str, result_of, base: Mapping[str, Any]) -> int:
        """One record per line of a JSON-lines log, each with the line's digest as its output. ``result_of(obj)`` gives
        ``(result, reason)`` for a parsed line (``None`` to skip it). Returns how many were written."""
        if self.chain is None:
            return 0
        written = skipped = 0
        for n, line, value in log_lines(path):
            if value is None:
                continue
            outcome = result_of(value)
            if outcome is None:
                continue
            if written >= LOG_RECORDS_MAX:
                skipped += 1
                continue
            result, reason = outcome
            if self.record(actor=actor, account_id=None, action=action, result=result, reason=reason,
                           outputs={"line": text_digest(line)}, **base) is None:
                return written
            written += 1
        if skipped:
            self.record(actor=actor, account_id=None, action=action, result="done",
                        reason=f"{skipped} more lines of {path.name} not recorded one by one (limit {LOG_RECORDS_MAX})",
                        outputs={path.name: file_digest(path)}, **base)
        return written


def gateway_result(entry: dict):
    """The gateway's decisions log (``decisions.jsonl``): a decision or a refusal is one record."""
    kind = entry.get("entry")
    if kind == "decision":
        record = entry.get("record") if isinstance(entry.get("record"), dict) else {}
        allowed = record.get("disposition") == "ALLOW"
        return ("done" if allowed else "refused"), f"{entry.get('tool', '')}: {record.get('disposition', '?')}"
    if kind == "refusal":
        return "refused", f"{entry.get('tool', '')}: not in the catalog"
    return None


def egress_result(entry: dict):
    """The egress log (``egress.jsonl``): every line is one decision."""
    allowed = entry.get("decision") == "allowed"
    where = entry.get("path", "") if entry.get("route") == "model" else f"{entry.get('host', '')}:{entry.get('port', '')}"
    return ("done" if allowed else "refused"), f"{where}: {entry.get('decision', '?')}"


