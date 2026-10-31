"""The secrets detector of the agent-pipeline boundary: known values, secret shapes and one level of base64.

``scan(text, known)`` returns every ``Finding`` in ``text``, sorted by ``start``. A finding names where a secret
is (``start``, ``end``), what found it (``kind``, ``rule``) and a short digest of it; it never holds the secret.

* **Known values** (``kind="known"``): each ``known`` string of at least ``MIN_KNOWN`` characters, verbatim
  (``known``), in standard or URL-safe base64 with or without padding and at each of the three byte alignments
  inside a longer base64 run (``known-base64``), in lowercase or uppercase hex (``known-hex``) and
  percent-encoded (``known-url``).
* **Patterns** (``kind="pattern"``): the shapes in ``PATTERNS``.
* **One level of decoding**: every base64 run of ``MIN_BASE64_RUN`` or more characters that decodes to valid
  UTF-8 is decoded and scanned again for the patterns; a match there has its rule id suffixed ``-base64`` and
  spans the whole run.

The digest is the first 16 hex characters of the SHA-256 of the secret value matched: the known string for a
known value in any encoding, the matched text for a pattern, and the decoded match for a ``-base64`` pattern
(see IMPLEMENTATION-DECISIONS). Standard library only; nothing here reads a file or the network.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass
from typing import Dict, Iterator, List, Sequence, Set, Tuple
from urllib.parse import quote, quote_plus

KNOWN = "known"
PATTERN = "pattern"
MIN_KNOWN = 16
MIN_BASE64_RUN = 24
DIGEST_CHARS = 16

# Each shape is assembled from pieces so that no line of this file is itself secret-shaped.
_PEM = "-----" + "BEGIN " + r"(?:[A-Z0-9]+ )*" + "PRIVATE" + " KEY" + "-----"

PATTERNS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("github-token", re.compile("gh" + r"[pousr]_[A-Za-z0-9]{36,}")),
    ("github-pat", re.compile("github" + r"_pat_[A-Za-z0-9_]{22,}")),
    ("anthropic-key", re.compile("sk-" + r"ant-[A-Za-z0-9_-]{20,}")),
    ("openai-key", re.compile("sk-" + r"proj-[A-Za-z0-9_-]{20,}")),
    ("aws-access-key", re.compile("AK" + r"IA[0-9A-Z]{16}(?![0-9A-Z])")),
    ("google-api-key", re.compile("AI" + r"za[0-9A-Za-z_-]{35}")),
    ("slack-token", re.compile("xo" + r"x[abprs]-[A-Za-z0-9-]{10,}")),
    ("private-key-block", re.compile(_PEM)),
    ("canary", re.compile("SBX-" + r"CANARY-[0-9a-f]{32}")),
)
RULES = tuple(rule for rule, _ in PATTERNS)

BASE64_RUN_RE = re.compile(r"[A-Za-z0-9+/_-]{%d,}={0,2}" % MIN_BASE64_RUN)
_TO_STANDARD = str.maketrans("-_", "+/")
_ESCAPE_RE = re.compile(r"%[0-9A-F]{2}")


@dataclass(frozen=True)
class Finding:
    """One secret in a scanned text: what found it and where. Never the matched text."""

    kind: str
    rule: str
    digest: str
    start: int
    end: int


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:DIGEST_CHARS]


def _base64_forms(data: bytes) -> Iterator[str]:
    """Every base64 spelling of ``data``: whole (padded and not) and the part fixed by ``data`` alone at each
    of the three byte alignments inside a longer run, in the standard and URL-safe alphabets."""
    whole = base64.b64encode(data).decode("ascii")
    forms = [whole, whole.rstrip("=")]
    for lead in range(3):
        encoded = base64.b64encode(b"\0" * lead + data).decode("ascii").rstrip("=")
        first = (lead * 8 + 5) // 6
        last = ((lead + len(data)) * 8) // 6
        forms.append(encoded[first:last])
    for form in forms:
        yield form
        yield form.replace("+", "-").replace("/", "_")


def _percent_forms(value: str) -> Iterator[str]:
    """``value`` percent-encoded: reserved characters only (``%20`` or ``+`` for a space) and every byte, each
    with uppercase and lowercase escapes."""
    raw = value.encode("utf-8")
    for form in (quote(value, safe=""), quote_plus(value, safe=""), "".join("%%%02X" % b for b in raw)):
        yield form
        yield _ESCAPE_RE.sub(lambda m: m.group(0).lower(), form)


def _needles(value: str) -> Dict[str, str]:
    """Each spelling of known ``value`` mapped to the rule that finds it; the first rule for a spelling wins."""
    raw = value.encode("utf-8")
    out: Dict[str, str] = {value: "known"}
    for form in _base64_forms(raw):
        out.setdefault(form, "known-base64")
    out.setdefault(raw.hex(), "known-hex")
    out.setdefault(raw.hex().upper(), "known-hex")
    for form in _percent_forms(value):
        out.setdefault(form, "known-url")
    return {needle: rule for needle, rule in out.items() if needle}


def _occurrences(text: str, needle: str) -> Iterator[int]:
    at = text.find(needle)
    while at != -1:
        yield at
        at = text.find(needle, at + 1)


def _known(text: str, known: Sequence[str]) -> List[Finding]:
    out: List[Finding] = []
    for value in known:
        if not isinstance(value, str):
            raise TypeError("known values must be strings")
        if len(value) < MIN_KNOWN:
            continue
        mark = digest(value)
        for needle, rule in _needles(value).items():
            for at in _occurrences(text, needle):
                out.append(Finding(KNOWN, rule, mark, at, at + len(needle)))
    return out


def _patterns(text: str) -> List[Finding]:
    return [Finding(PATTERN, rule, digest(m.group(0)), m.start(), m.end())
            for rule, pattern in PATTERNS for m in pattern.finditer(text)]


def _decodings(run: str) -> Iterator[str]:
    """Each UTF-8 text the base64 ``run`` decodes to, read from each of its first four characters."""
    body = run.rstrip("=").translate(_TO_STANDARD)
    for skip in range(4):
        part = body[skip:]
        part = part[:len(part) - len(part) % 4] if len(part) % 4 == 1 else part
        if len(part) < MIN_BASE64_RUN - 3:
            continue
        try:
            yield base64.b64decode(part + "=" * (-len(part) % 4), validate=True).decode("utf-8")
        except (binascii.Error, ValueError):
            continue


def _decoded(text: str) -> List[Finding]:
    out: List[Finding] = []
    for run in BASE64_RUN_RE.finditer(text):
        for decoded in _decodings(run.group(0)):
            for rule, pattern in PATTERNS:
                for m in pattern.finditer(decoded):
                    out.append(Finding(PATTERN, rule + "-base64", digest(m.group(0)), run.start(), run.end()))
    return out


def _dedupe(findings: List[Finding]) -> List[Finding]:
    """One finding per rule and digest over any span, dropping one that lies inside another of the same rule
    and digest (the padded and unpadded spellings of one base64 value, say). Findings of different rules are
    all kept, overlapping or not."""
    unique: Set[Finding] = set(findings)
    kept = [f for f in unique
            if not any(o is not f and o.rule == f.rule and o.digest == f.digest and o.start <= f.start
                       and f.end <= o.end and (o.start, o.end) != (f.start, f.end) for o in unique)]
    return sorted(kept, key=lambda f: (f.start, f.end, f.kind, f.rule, f.digest))


def scan(text: str, known: Sequence[str] = ()) -> List[Finding]:
    """Every secret in ``text``: known values, pattern matches and base64-wrapped pattern matches."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if isinstance(known, str):
        raise TypeError("known must be a sequence of strings, not a string")
    return _dedupe(_known(text, known) + _patterns(text) + _decoded(text))
