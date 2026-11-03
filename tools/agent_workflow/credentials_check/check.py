"""The credentials register checked against the workflows (MISSION-DISPATCH-001 Amendment 013, §3i items 2-3).

Every ``secrets.<NAME>`` and ``vars.<NAME>`` a workflow uses must have a register row naming that workflow and job,
held where the job runs; a row naming a job that no longer uses it is stale; a workflow that hands over every secret
at once or picks one by a computed name is refused, since no row can describe it. Stdlib only: workflows are read
line by line, and a shape this reader does not know is refused rather than guessed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from secrets_boundary.detector import scan

HEADER = ("Credential", "Kind", "Held in", "Used by", "Can do", "Revoke", "Rotated")
KINDS = ("secret", "variable", "app-key", "model-login", "user-login", "token")
EXEMPT = frozenset({"GITHUB_TOKEN"})  # minted per run, scoped by each workflow's permissions
MAX_FILE = 1 << 20

_NAME = r"[A-Za-z_][A-Za-z0-9_]*"
_REF_RE = re.compile(rf"\b(secrets|vars)\.({_NAME})")
_EXPR_RE = re.compile(r"\$\{\{.*?\}\}")
_JOB_RE = re.compile(r"^  ([A-Za-z_][A-Za-z0-9_-]*):\s*(#.*)?$")
_ENV_RE = re.compile(r"^    environment:\s*(.*?)\s*(#.*)?$")
_ENV_NAME_RE = re.compile(r"^      name:\s*(.*?)\s*(#.*)?$")
_WHOLESALE = (
    (re.compile(r"\bsecrets:\s*inherit\b"), "passes every secret at once (`secrets: inherit`)"),
    (re.compile(r"\btoJSON\(\s*secrets\s*\)", re.I), "passes every secret at once (`toJSON(secrets)`)"),
    (re.compile(r"\bsecrets\s*\["), "picks a secret by a computed name (`secrets[...]`)"),
)
_HELD_RE = re.compile(r"^(environment:[A-Za-z0-9_.*-]+|repository|organization|outside:.+)$")
_USE_RE = re.compile(r"^[A-Za-z0-9_.-]+\.ya?ml:[A-Za-z_][A-Za-z0-9_-]*$")


class RegisterError(ValueError):
    """The register cannot be read as a register: nothing it says can be trusted."""


@dataclass(frozen=True)
class Row:
    name: str
    kind: str
    held_in: str
    used_by: Tuple[str, ...]


@dataclass(frozen=True)
class Use:
    name: str
    kind: str  # "secret" or "variable"
    workflow: str
    job: str
    held_in: Tuple[str, ...]  # where the job may hold it: its environment, or repository / organization
    line: int


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1]
    return value


def parse_register(text: str) -> List[Row]:
    """The register's rows. A missing header, a malformed row, a duplicate or a value-shaped string raises."""
    if not isinstance(text, str) or len(text) > MAX_FILE:
        raise RegisterError("missing or too large")
    if scan(text):
        raise RegisterError("it contains something shaped like a credential value; the register never holds values")
    rows: List[Row] = []
    seen: Set[Tuple[str, str]] = set()
    in_table = False
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped.startswith("|"):
            in_table = False
            continue
        cells = tuple(c.strip() for c in stripped.strip("|").split("|"))
        if cells == HEADER:
            in_table = True
            continue
        if not in_table or set("".join(cells)) <= set("-: "):
            continue
        if len(cells) != len(HEADER):
            raise RegisterError(f"line {number}: a row needs {len(HEADER)} cells, not {len(cells)}")
        name = cells[0].split()[0] if cells[0] else ""
        kind, held_in, used = cells[1], cells[2], cells[3]
        if not name or kind not in KINDS:
            raise RegisterError(f"line {number}: needs a credential name and a kind ({', '.join(KINDS)})")
        if not _HELD_RE.match(held_in):
            raise RegisterError(f"line {number}: 'Held in' must be environment:<name>, repository, organization or "
                                f"outside:<where>, not {held_in!r}")
        used_by = () if used == "-" else tuple(u.strip() for u in used.split(","))
        if not all(_USE_RE.match(u) for u in used_by):
            raise RegisterError(f"line {number}: 'Used by' must be '-' or <workflow file>:<job>, comma-separated")
        if kind in ("secret", "variable") and not re.fullmatch(_NAME, name):
            raise RegisterError(f"line {number}: {name!r} is not a workflow {kind} name")
        if (name, held_in) in seen:
            raise RegisterError(f"line {number}: {name} held in {held_in} is listed twice")
        seen.add((name, held_in))
        rows.append(Row(name, kind, held_in, used_by))
    if not rows:
        raise RegisterError(f"no rows under the header | {' | '.join(HEADER)} |")
    return rows


def _environment(value: str) -> str:
    """An environment name with each ``${{ ... }}`` filled in at run time written as ``*``."""
    return _EXPR_RE.sub("*", _unquote(value))


def scan_workflow(name: str, text: str) -> Tuple[List[Use], List[str]]:
    """Every credential use in one workflow file, and every problem that keeps it from being checked."""
    uses: List[Use] = []
    problems: List[str] = []
    if "\t" in text:
        problems.append(f"{name}: contains a tab; it cannot be read reliably")
    lines = text.splitlines()
    in_jobs, job, env = False, None, None
    job_uses: List[Tuple[str, str, int]] = []

    def close() -> None:
        held = (f"environment:{env}",) if env else ("repository", "organization")
        uses.extend(Use(n, "secret" if k == "secrets" else "variable", name, job, held, ln) for k, n, ln in job_uses)

    for number, line in enumerate(lines, 1):
        if line.startswith("jobs:"):
            in_jobs = True
            continue
        if line and not line[0].isspace() and not line.startswith("#"):
            if job is not None:
                close()
            in_jobs, job, env, job_uses = False, None, None, []
        match = _JOB_RE.match(line) if in_jobs else None
        if match:
            if job is not None:
                close()
            job, env, job_uses = match.group(1), None, []
            continue
        if job is not None:
            env_match = _ENV_RE.match(line)
            if env_match:
                value = env_match.group(1)
                if value:
                    env = _environment(value)
                else:  # environment given as a mapping: its name is on a following line
                    following = next((_ENV_NAME_RE.match(l) for l in lines[number:number + 3] if _ENV_NAME_RE.match(l)), None)
                    if following is None:
                        problems.append(f"{name}:{number}: job {job}'s environment has no name this check can read")
                    else:
                        env = _environment(following.group(1))
        # A whole-line comment is not code. A trailing one is still read: a '#' can sit inside a quoted string, and
        # reading too much can only raise a finding, never hide a use.
        code = "" if line.lstrip().startswith("#") else line
        problems.extend(f"{name}:{number}: {why}" for pattern, why in _WHOLESALE if pattern.search(code))
        for ref in _REF_RE.finditer(code):
            kind, cred = ref.group(1), ref.group(2)
            if kind == "secrets" and cred in EXEMPT:
                continue
            if job is None:
                problems.append(f"{name}:{number}: {kind}.{cred} is used outside any job, so no row can name its job")
            else:
                job_uses.append((kind, cred, number))
    if job is not None:
        close()
    return uses, problems


def check(register: str, workflows: Dict[str, str]) -> List[str]:
    """Every finding for ``register`` against ``workflows`` (file name -> text). Empty when they agree."""
    try:
        rows = parse_register(register)
    except RegisterError as exc:
        return [f"the credentials register is unusable: {exc}"]
    findings: List[str] = []
    uses: List[Use] = []
    for name in sorted(workflows):
        found, problems = scan_workflow(name, workflows[name])
        uses += found
        findings += problems
    for use in uses:
        candidates = [r for r in rows if r.name == use.name and r.kind == use.kind]
        where = f"{use.workflow}:{use.line}"
        if not candidates:
            findings.append(f"{where}: {use.kind} {use.name} has no row in the credentials register")
            continue
        if not any(f"{use.workflow}:{use.job}" in r.used_by for r in candidates):
            findings.append(f"{where}: {use.kind} {use.name} is used by job {use.job}, which no row's 'Used by' names")
            continue
        if not any(f"{use.workflow}:{use.job}" in r.used_by and r.held_in in use.held_in for r in candidates):
            findings.append(f"{where}: job {use.job} holds {use.name} in {' or '.join(use.held_in)}, "
                            f"not where its row says")
    used = {(u.name, u.kind, f"{u.workflow}:{u.job}") for u in uses}
    for row in rows:
        for entry in row.used_by:
            if (row.name, row.kind, entry) not in used:
                findings.append(f"stale row: {row.name} ({row.kind}) names {entry}, which does not use it")
    return findings


def read_workflows(folder: Path) -> Dict[str, str]:
    """Every ``*.yml`` and ``*.yaml`` in ``folder``. An unreadable file raises."""
    found: Dict[str, str] = {}
    if not folder.is_dir():
        return found
    for path in sorted(folder.iterdir()):
        if path.suffix in (".yml", ".yaml") and path.is_file():
            if path.stat().st_size > MAX_FILE:
                raise RegisterError(f"{path.name} is too large to check")
            found[path.name] = path.read_text(encoding="utf-8")
    return found
