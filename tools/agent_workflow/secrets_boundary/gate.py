"""The two fail-closed checkpoints of the agent-pipeline boundary.

``admit_context(text, known)`` (checkpoint ``context``) returns text about to enter an agent's context with every
secret replaced by ``[REDACTED:<rule>:<digest>]``; overlapping finding spans are merged first and the merged span
takes the marker of its earliest finding (the longest, on a tie). It always allows when it completes.

``admit_output(files, texts, known)`` (checkpoint ``output``) refuses what a run wants to publish, as a whole, if
any file path is a credential path (``paths.denied``) or any file content or text value holds a secret. File
content that is not valid UTF-8 is scanned as Latin-1. Paths are checked in sorted order, then texts by sorted
label; ``reason`` names the first offender as ``<path or label>: <rule>`` and never the value.

Any exception inside either function returns a refusal with ``reason="boundary-error"`` (and ``text=None`` for
context): an error is never an admission.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Mapping, Optional, Sequence, Tuple

from secrets_boundary import detector, paths

CONTEXT = "context"
OUTPUT = "output"
CLEAN = "clean"
REDACTED = "redacted"
BOUNDARY_ERROR = "boundary-error"
PATH_KIND = "path"


@dataclass(frozen=True)
class Decision:
    """One checkpoint decision. ``findings`` holds ``detector.Finding`` items for ``context`` and
    ``(location, finding)`` pairs for ``output``; ``text`` is the redacted text, for ``context`` only."""

    allow: bool
    checkpoint: str
    findings: tuple
    reason: str
    text: Optional[str] = None


@dataclass(frozen=True)
class PathDenial:
    """An output file path that is a credential path: the ``paths`` rule and the path's digest."""

    kind: str
    rule: str
    digest: str


def marker(finding) -> str:
    return f"[REDACTED:{finding.rule}:{finding.digest}]"


def _merged(findings: Sequence[detector.Finding]) -> List[Tuple[int, int, detector.Finding]]:
    """Merge overlapping spans; each merged span keeps its earliest finding, the longest on a tie."""
    spans: List[Tuple[int, int, detector.Finding]] = []
    for finding in sorted(findings, key=lambda f: (f.start, -f.end, f.rule)):
        if spans and finding.start < spans[-1][1]:
            start, end, first = spans[-1]
            spans[-1] = (start, max(end, finding.end), first)
        else:
            spans.append((finding.start, finding.end, finding))
    return spans


def redact(text: str, findings: Sequence[detector.Finding]) -> str:
    parts: List[str] = []
    at = 0
    for start, end, first in _merged(findings):
        parts.append(text[at:start])
        parts.append(marker(first))
        at = end
    parts.append(text[at:])
    return "".join(parts)


def admit_context(text: str, known: Sequence[str] = ()) -> Decision:
    """``text`` with every secret redacted, for an agent's context; a refusal only on a boundary error."""
    try:
        findings = tuple(detector.scan(text, known))
        return Decision(True, CONTEXT, findings, REDACTED if findings else CLEAN, redact(text, findings))
    except Exception:
        return Decision(False, CONTEXT, (), BOUNDARY_ERROR, None)


def _content_text(content: bytes) -> str:
    if not isinstance(content, (bytes, bytearray)):
        raise TypeError("file content must be bytes")
    try:
        return bytes(content).decode("utf-8")
    except UnicodeDecodeError:
        return bytes(content).decode("latin-1")


def _output_findings(files: Mapping[str, bytes], texts: Mapping[str, str], known: Sequence[str]) -> List[tuple]:
    found: List[tuple] = []
    for path in sorted(files):
        if not isinstance(path, str):
            raise TypeError("file paths must be strings")
        in_name = detector.scan(path, known)  # the name is output too
        # A name that holds a secret is never repeated: every finding for that file is located by its redacted name.
        where = redact(path, in_name) if in_name else path
        rule = paths.denied(path)
        if rule:
            found.append((where, PathDenial(PATH_KIND, rule, detector.digest(path))))
        found.extend((where, finding) for finding in in_name)
        found.extend((where, finding) for finding in detector.scan(_content_text(files[path]), known))
    for label in sorted(texts):
        if not isinstance(label, str) or not isinstance(texts[label], str):
            raise TypeError("text labels and values must be strings")
        found.extend((label, finding) for finding in detector.scan(texts[label], known))
    return found


def admit_output(files: Mapping[str, bytes], texts: Mapping[str, str], known: Sequence[str] = ()) -> Decision:
    """Allow what a run publishes only if no path is a credential path and nothing in it holds a secret."""
    try:
        found = tuple(_output_findings(files, texts, known))
        if not found:
            return Decision(True, OUTPUT, (), CLEAN)
        location, first = found[0]
        return Decision(False, OUTPUT, found, f"{location}: {first.rule}")
    except Exception:
        return Decision(False, OUTPUT, (), BOUNDARY_ERROR)
