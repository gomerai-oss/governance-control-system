"""Reads the identity registry file.

The registry is a Markdown table with at least the columns Role, App ID and
Status. Only ``ACTIVE`` identities verify. Anything the reader cannot parse
without guessing (no table, a missing column, a role listed twice) is an error.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

ACTIVE = "ACTIVE"
REQUIRED_COLUMNS = ("Role", "App ID", "Status")


class RegistryError(ValueError):
    pass


@dataclass(frozen=True)
class Identity:
    role: str
    app_id: str
    status: str

    @property
    def active(self) -> bool:
        return self.status == ACTIVE


def _cells(line: str) -> List[str]:
    return [c.strip().strip("`").strip() for c in line.strip().strip("|").split("|")]


def parse_registry(text: str) -> Dict[str, Identity]:
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if not line.strip().startswith("|"):
            continue
        header = _cells(line)
        if not all(col in header for col in REQUIRED_COLUMNS):
            continue
        if i + 1 >= len(lines) or set(lines[i + 1].replace("|", "").strip()) - set("-: "):
            raise RegistryError("registry table header is not followed by a separator row")
        idx = {col: header.index(col) for col in REQUIRED_COLUMNS}
        out: Dict[str, Identity] = {}
        for row in lines[i + 2:]:
            if not row.strip().startswith("|"):
                break
            cells = _cells(row)
            if len(cells) != len(header):
                raise RegistryError(f"registry row has {len(cells)} cells, header has {len(header)}: {row.strip()}")
            ident = Identity(cells[idx["Role"]], cells[idx["App ID"]], cells[idx["Status"]])
            if not ident.role:
                raise RegistryError("registry row with an empty role")
            if ident.role in out:
                raise RegistryError(f"role {ident.role!r} is listed twice")
            out[ident.role] = ident
        if not out:
            raise RegistryError("registry table has no rows")
        return out
    raise RegistryError("no identity table with columns " + ", ".join(REQUIRED_COLUMNS))


def load_registry(path: Path) -> Dict[str, Identity]:
    return parse_registry(Path(path).read_text(encoding="utf-8"))
