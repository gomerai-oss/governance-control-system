"""Loads and strictly validates the corpus registry (``corpus.json``).

The registry (``retrieval-corpus-v1``) is data: each corpus declares an ``id``
(the fabric resource id), ``roots`` (repo-relative include globs — an allow-list
only; nothing outside a root is ever read), ``deny_patterns`` (generic
credential patterns), ``authority`` (path-prefix to authority class), and
``vocabulary`` (alias to canonical document id).

Resolving a corpus walks its roots under a repository root and returns a
deterministically sorted list of repo-relative POSIX paths. A symlink, a path
that escapes the repository root, any requested path that is not a plain
relative path (absolute, backslash, or an empty, ``.`` or ``..`` segment), and
any path that matches a deny pattern (case-insensitively) are all refused: no
bytes are read from them, and they never enter a file set.
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from retrieval.records import AUTHORITY_CLASSES


@lru_cache(maxsize=None)
def _glob_regex(pattern: str) -> "re.Pattern":
    """A regex for a path glob supporting ``**`` (any depth), ``*`` and ``?``."""
    parts: List[str] = []
    i = 0
    while i < len(pattern):
        if pattern[i:i + 3] == "**/":
            parts.append("(?:.*/)?")
            i += 3
        elif pattern[i:i + 2] == "**":
            parts.append(".*")
            i += 2
        elif pattern[i] == "*":
            parts.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            parts.append("[^/]")
            i += 1
        else:
            parts.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(parts) + "$")


def glob_match(path: str, pattern: str) -> bool:
    return _glob_regex(pattern).match(path) is not None

REGISTRY_SCHEMA = "retrieval-corpus-v1"
CORPUS_FIELDS = frozenset({"id", "roots", "deny_patterns", "authority", "vocabulary"})

# How a requested path relates to a corpus.
PATH_ALLOWED = "ALLOWED"      # inside a root, not denied, a real file
PATH_DENIED = "DENIED"        # outside every root, or matches a deny pattern
PATH_ABSENT = "ABSENT"        # inside a root, not denied, but no such file


class CorpusError(ValueError):
    pass


def is_clean_relpath(relpath: object) -> bool:
    """True for a plain repo-relative POSIX path.

    A path that is not a string, is empty or absolute, holds a backslash or a NUL,
    or has an empty, ``.`` or ``..`` segment is not clean. Glob matching is
    lexical, so an unclean path could match a root while naming a file outside
    it; such a path is refused before any root is consulted.
    """
    if not isinstance(relpath, str) or not relpath:
        return False
    if relpath.startswith("/") or "\\" in relpath or "\x00" in relpath:
        return False
    return not any(seg in ("", ".", "..") for seg in relpath.split("/"))


@dataclass(frozen=True)
class Corpus:
    id: str
    roots: Tuple[str, ...]
    deny_patterns: Tuple[str, ...]
    authority: Tuple[Tuple[str, str], ...]  # (prefix, class), longest prefix first
    vocabulary: Dict[str, str]

    def authority_of(self, relpath: str) -> str:
        for prefix, klass in self.authority:
            if relpath.startswith(prefix):
                return klass
        return "reference"

    def is_denied(self, relpath: str) -> bool:
        # Case-insensitive on every platform: 'API-TOKEN.md' is as much a
        # credential file as 'api-token.md'.
        segments = [seg.lower() for seg in relpath.split("/")]
        for pattern in self.deny_patterns:
            lowered = pattern.lower()
            if any(fnmatch.fnmatchcase(seg, lowered) for seg in segments):
                return True
        return False

    def within_roots(self, relpath: str) -> bool:
        if not is_clean_relpath(relpath):
            return False
        return any(glob_match(relpath, root) for root in self.roots)


@dataclass(frozen=True)
class CorpusRegistry:
    version: str
    corpora: Dict[str, Corpus]

    def get(self, corpus_id: str) -> Corpus:
        if corpus_id not in self.corpora:
            raise CorpusError(f"unknown corpus id: {corpus_id!r}")
        return self.corpora[corpus_id]

    def resolve_scope(self, corpus_scope: Sequence[str]) -> List[Corpus]:
        """The corpora a request names, or every corpus when the scope is empty."""
        if not corpus_scope:
            return [self.corpora[cid] for cid in sorted(self.corpora)]
        return [self.get(cid) for cid in corpus_scope]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CorpusError(message)


def parse_registry(data: object) -> CorpusRegistry:
    """Validate a decoded ``corpus.json`` and build a :class:`CorpusRegistry`."""
    _require(isinstance(data, dict), "registry must be an object")
    _require(data.get("schema") == REGISTRY_SCHEMA, f"registry schema must be {REGISTRY_SCHEMA!r}")
    _require(set(data) == {"schema", "registry_version", "corpora"},
             "registry must have exactly schema, registry_version, corpora")
    version = data["registry_version"]
    _require(isinstance(version, str) and version, "registry_version must be a non-empty string")
    raw = data["corpora"]
    _require(isinstance(raw, list) and raw, "corpora must be a non-empty list")
    corpora: Dict[str, Corpus] = {}
    for entry in raw:
        corpus = _parse_corpus(entry)
        _require(corpus.id not in corpora, f"corpus id {corpus.id!r} is listed twice")
        corpora[corpus.id] = corpus
    return CorpusRegistry(version=version, corpora=corpora)


def _parse_corpus(entry: object) -> Corpus:
    _require(isinstance(entry, dict) and set(entry) == CORPUS_FIELDS,
             f"each corpus must have exactly {sorted(CORPUS_FIELDS)}")
    cid = entry["id"]
    _require(isinstance(cid, str) and cid.startswith("corpus:"), "corpus id must be a 'corpus:' string")
    roots = entry["roots"]
    _require(isinstance(roots, list) and roots and all(isinstance(r, str) and r for r in roots),
             f"corpus {cid}: roots must be a non-empty list of globs")
    for root in roots:
        _require(not root.startswith("/") and ".." not in root.split("/"),
                 f"corpus {cid}: root {root!r} must be a clean relative glob")
    deny = entry["deny_patterns"]
    _require(isinstance(deny, list) and all(isinstance(d, str) and d for d in deny),
             f"corpus {cid}: deny_patterns must be a list of strings")
    authority = entry["authority"]
    _require(isinstance(authority, dict), f"corpus {cid}: authority must be an object")
    for prefix, klass in authority.items():
        _require(isinstance(prefix, str) and prefix, f"corpus {cid}: authority prefix must be a string")
        _require(klass in AUTHORITY_CLASSES, f"corpus {cid}: authority class {klass!r} is not known")
    # Longest prefix first so authority_of picks the most specific.
    ordered = tuple(sorted(authority.items(), key=lambda kv: len(kv[0]), reverse=True))
    vocab = entry["vocabulary"]
    _require(isinstance(vocab, dict)
             and all(isinstance(k, str) and isinstance(v, str) and k and v for k, v in vocab.items()),
             f"corpus {cid}: vocabulary must map alias strings to document id strings")
    return Corpus(id=cid, roots=tuple(roots), deny_patterns=tuple(deny),
                  authority=ordered, vocabulary=dict(vocab))


def load_registry(path: Path) -> CorpusRegistry:
    text = Path(path).read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CorpusError(f"{path}: not valid JSON: {exc}") from exc
    return parse_registry(data)


def default_registry_path() -> Path:
    return Path(__file__).resolve().with_name("corpus.json")


def _is_safe(root: Path, target: Path) -> bool:
    """True when ``target`` is a real file under ``root`` with no symlink in the way.

    Only path components at or below ``root`` are checked for symlinks; symlinks in
    the ancestry of ``root`` itself (for example a ``/tmp`` that is a symlink) are
    the environment's, not the corpus's, and do not disqualify a file.
    """
    root = Path(root)
    try:
        rel = target.relative_to(root)
    except ValueError:
        return False
    probe = root
    for part in rel.parts:
        probe = probe / part
        if probe.is_symlink():
            return False
    if not target.is_file():
        return False
    try:
        target.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def resolve_files(corpus: Corpus, root: Path) -> List[str]:
    """The deterministically sorted repo-relative files a corpus admits under ``root``."""
    root = Path(root)
    found = set()
    for pattern in corpus.roots:
        for path in root.glob(pattern):
            if not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            if corpus.is_denied(rel):
                continue
            if not _is_safe(root, path):
                continue
            found.add(rel)
    return sorted(found)


def classify_path(corpus: Corpus, root: Path, relpath: object) -> str:
    """Whether a requested path is allowed, denied by ACL, or simply absent.

    An unclean path (see :func:`is_clean_relpath`) is denied outright, so a
    ``..`` segment can never carry a request out of a root.
    """
    if not is_clean_relpath(relpath):
        return PATH_DENIED
    if not corpus.within_roots(relpath) or corpus.is_denied(relpath):
        return PATH_DENIED
    candidate = Path(root) / relpath
    if _is_safe(Path(root), candidate):
        return PATH_ALLOWED
    return PATH_ABSENT


def canonical_for_alias(corpus: Corpus, alias: str) -> Optional[str]:
    return corpus.vocabulary.get(alias)
