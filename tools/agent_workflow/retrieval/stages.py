"""The retrieval stages of doctrine section 2, in their fixed order.

The hierarchy runs structure-first, probabilistic-last:

1. ``exact``      - exact document id, path, or known location.
2. ``metadata``   - fielded filters over extracted metadata.
3. ``structure``  - hierarchy, version and lifecycle constraints, including
                    supersession (a document whose metadata says it is superseded,
                    and by which document).
4. ``vocabulary`` - alias / controlled-term resolution from the corpus registry.
5. ``lexical``    - deterministic fielded keyword search (BM25, k1=1.2, b=0.75,
                    ties broken by path).
6. ``semantic``   - a pluggable backend interface; no backend ships in this build,
                    and with none configured the stage records ``SEMANTIC_UNAVAILABLE``
                    and never substitutes another method under its name.
7. ``recovery``   - a bounded loop (max iterations is data, default 3) that relaxes
                    one declared constraint per iteration and records each relaxation.

A later stage runs only when every earlier stage left the request unresolved.
Nothing a stage produces is phrased or typed as permission to act.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from retrieval import corpus as corpus_mod
from retrieval.records import make_span

# Stage names.
EXACT = "exact"
METADATA = "metadata"
STRUCTURE = "structure"
VOCABULARY = "vocabulary"
LEXICAL = "lexical"
SEMANTIC = "semantic"
RECOVERY = "recovery"

CORE_STAGE_NAMES = (EXACT, METADATA, STRUCTURE, VOCABULARY, LEXICAL)
ALL_STAGE_NAMES = CORE_STAGE_NAMES + (SEMANTIC, RECOVERY)

# Stage outcome labels.
RESOLVED = "RESOLVED"
NO_MATCH = "NO_MATCH"
NOT_APPLICABLE = "NOT_APPLICABLE"
DEFERRED_SUPERSEDED = "DEFERRED_SUPERSEDED"
SEMANTIC_UNAVAILABLE = "SEMANTIC_UNAVAILABLE"
LOOP_EXHAUSTED = "LOOP_EXHAUSTED"
ACL_SCOPE_FAILURE = "ACL_SCOPE_FAILURE"
WRONG_DOCUMENT_VERSION = "WRONG_DOCUMENT_VERSION"

# Constraint keys the recovery loop may relax, in a deterministic order.
RELAXABLE_KEYS = ("location", "path", "document_id", "status", "title", "date",
                  "version", "lifecycle", "require_current", "alias", "keywords")
LIFECYCLE_KEYS = ("version", "lifecycle", "require_current")
METADATA_KEYS = ("status", "title", "date")

DEFAULT_RECOVERY_ITERATIONS = 3

_TOKEN = re.compile(r"[a-z0-9]+")
_STATUS = re.compile(r"^\*\*Status:\*\*\s*(.+?)\s*$", re.MULTILINE)
_TITLE = re.compile(r"^\*\*Title:\*\*\s*(.+?)\s*$", re.MULTILINE)
_SUPERSEDED_BY = re.compile(r"^\*\*Superseded-By:\*\*\s*(.+?)\s*$", re.MULTILINE)
_H1 = re.compile(r"^#\s+(.+?)\s*$", re.MULTILINE)
_DATE_LINE = re.compile(r"^\*\*[^*]*Date[^*]*:\*\*\s*(.+?)\s*$", re.MULTILINE | re.IGNORECASE)
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def _clean(value: str) -> str:
    return value.strip().strip("`").strip()


@dataclass
class Document:
    relpath: str
    corpus_id: str
    authority: str
    data: bytes
    text: str
    lines: List[str]
    sha256: str
    metadata: Dict[str, Optional[str]]

    @property
    def document_id(self) -> str:
        return self.metadata["document_id"]

    def full_span(self) -> dict:
        return make_span(1, max(1, len(self.lines)), self.sha256)

    def line_span(self, line_no: int) -> dict:
        line_no = max(1, min(line_no, len(self.lines)))
        span_bytes = self.lines[line_no - 1].encode("utf-8")
        return make_span(line_no, line_no, hashlib.sha256(span_bytes).hexdigest())


def extract_metadata(relpath: str, text: str) -> Dict[str, Optional[str]]:
    document_id = Path(relpath).stem
    status = _STATUS.search(text)
    title = _TITLE.search(text)
    if title is None:
        title = _H1.search(text)
    superseded_by = _SUPERSEDED_BY.search(text)
    date_value = None
    date_line = _DATE_LINE.search(text)
    if date_line:
        hit = _DATE.search(date_line.group(1))
        if hit:
            date_value = hit.group(0)
    status_value = _clean(status.group(1)) if status else None
    return {
        "document_id": document_id,
        "status": status_value,
        "title": _clean(title.group(1)) if title else None,
        "date": date_value,
        "superseded_by": _clean(superseded_by.group(1)) if superseded_by else None,
        "superseded": (superseded_by is not None)
        or (status_value is not None and status_value.upper() == "SUPERSEDED"),
    }


def tokenize(text: str) -> List[str]:
    return _TOKEN.findall(text.lower())


@dataclass
class StageContext:
    root: Path
    request: Mapping[str, Any]
    constraints: Mapping[str, Any]
    corpora: Sequence["corpus_mod.Corpus"]
    semantic_backend: Any = None
    registry_version: str = ""
    _cache: Dict[str, Document] = field(default_factory=dict)
    _file_index: Optional[List[Tuple[str, "corpus_mod.Corpus"]]] = None

    def file_index(self) -> List[Tuple[str, "corpus_mod.Corpus"]]:
        if self._file_index is None:
            seen: Dict[str, "corpus_mod.Corpus"] = {}
            for corpus in self.corpora:
                for rel in corpus_mod.resolve_files(corpus, self.root):
                    seen.setdefault(rel, corpus)
            self._file_index = sorted(seen.items(), key=lambda kv: kv[0])
        return self._file_index

    def all_files(self) -> List[str]:
        return [rel for rel, _ in self.file_index()]

    def load(self, relpath: str, corpus: "corpus_mod.Corpus") -> Document:
        if relpath not in self._cache:
            data = (self.root / relpath).read_bytes()
            text = data.decode("utf-8", errors="replace")
            self._cache[relpath] = Document(
                relpath=relpath,
                corpus_id=corpus.id,
                authority=corpus.authority_of(relpath),
                data=data,
                text=text,
                lines=text.splitlines(keepends=True) or [""],
                sha256=hashlib.sha256(data).hexdigest(),
                metadata=extract_metadata(relpath, text),
            )
        return self._cache[relpath]

    def corpus_of(self, relpath: str) -> "corpus_mod.Corpus":
        for rel, corpus in self.file_index():
            if rel == relpath:
                return corpus
        raise KeyError(relpath)

    def documents(self) -> List[Document]:
        return [self.load(rel, corpus) for rel, corpus in self.file_index()]

    def find_by_document_id(self, document_id: str) -> Optional[Document]:
        for doc in self.documents():
            if doc.document_id == document_id:
                return doc
        return None


@dataclass
class StageOutcome:
    name: str
    outcome: str
    resolved: bool = False
    abstain: bool = False
    failure_class: Optional[str] = None
    doc: Optional[Document] = None
    relationship: Optional[str] = None
    span: Optional[dict] = None
    contradiction_state: str = "NONE"
    superseded: List[Document] = field(default_factory=list)
    detail: Any = None

    def record(self) -> dict:
        return {"stage": self.name, "outcome": self.outcome, "detail": self.detail}


def _na(name: str) -> StageOutcome:
    return StageOutcome(name=name, outcome=NOT_APPLICABLE)


def _no_match(name: str) -> StageOutcome:
    return StageOutcome(name=name, outcome=NO_MATCH)


def _follow_supersession(ctx: StageContext, doc: Document
                         ) -> Tuple[Optional[Document], List[Document], Optional[str], Optional[str]]:
    """Follow ``Superseded-By`` from a superseded ``doc`` to a document that is not superseded.

    Returns ``(current, chain, successor_id, reason)``. ``chain`` lists every
    superseded document on the way, in order, starting with ``doc``. ``current``
    is None, and ``reason`` names why, when the chain leaves the corpus
    (``OUTSIDE_CORPUS``, or ``NO_SUCCESSOR_NAMED`` for a superseded document that
    names none), names the document itself (``SELF_REFERENCE``) or returns to a
    document already on it (``CYCLE``); ``successor_id`` is then the last
    successor named. The walk is bounded by the corpus size.
    """
    chain = [doc]
    visited = {doc.relpath}
    successor_id: Optional[str] = None
    for _ in range(len(ctx.all_files()) + 1):
        cur = chain[-1]
        successor_id = cur.metadata["superseded_by"]
        if not successor_id:
            return None, chain, successor_id, "NO_SUCCESSOR_NAMED"
        if successor_id == cur.document_id:
            return None, chain, successor_id, "SELF_REFERENCE"
        successor = ctx.find_by_document_id(successor_id)
        if successor is None:
            return None, chain, successor_id, "OUTSIDE_CORPUS"
        if successor.relpath in visited:
            return None, chain, successor_id, "CYCLE"
        if not successor.metadata["superseded"]:
            return successor, chain, successor_id, None
        visited.add(successor.relpath)
        chain.append(successor)
    return None, chain, successor_id, "CYCLE"


def _wrong_version(stage: str, chain: List[Document], successor_id: Optional[str],
                   reason: str) -> StageOutcome:
    return StageOutcome(name=stage, outcome=WRONG_DOCUMENT_VERSION, abstain=True,
                        failure_class="WRONG_DOCUMENT_VERSION", superseded=list(chain),
                        detail={"superseded_document": chain[0].document_id,
                                "superseding_document": successor_id,
                                "supersession_chain": [d.document_id for d in chain],
                                "reason": reason})


def _apply_supersession(ctx: StageContext, stage: str, doc: Document,
                        successor_relationship: str = "EXACT_MATCH") -> StageOutcome:
    """Resolve a (possibly superseded) candidate to the current document.

    If the candidate is superseded, ``Superseded-By`` is followed through the
    corpus to a document that is not superseded; that document is cited and every
    superseded one on the way is listed with ``contradiction_state: SUPERSEDED``.
    If the chain leaves the corpus, cycles or names the document itself, the
    result abstains with ``WRONG_DOCUMENT_VERSION`` rather than citing a stale one.
    """
    if not doc.metadata["superseded"]:
        return StageOutcome(name=stage, outcome=RESOLVED, resolved=True, doc=doc,
                            relationship=successor_relationship, span=doc.full_span())
    current, chain, successor_id, reason = _follow_supersession(ctx, doc)
    if current is None:
        return _wrong_version(stage, chain, successor_id, reason)
    return StageOutcome(name=stage, outcome=RESOLVED, resolved=True, doc=current,
                        relationship=successor_relationship, span=current.full_span(),
                        contradiction_state="SUPERSEDES", superseded=chain,
                        detail={"superseded_document": doc.document_id,
                                "superseding_document": current.document_id,
                                "supersession_chain": [d.document_id for d in chain]})


def _classify_requested(ctx: StageContext, relpath: Any) -> Tuple[str, Optional["corpus_mod.Corpus"]]:
    """How a requested path relates to the request's corpora, and the corpus that admits it.

    The path is taken exactly as given, never normalised: an unclean path
    (absolute, backslash, or an empty, ``.`` or ``..`` segment) is denied by
    :func:`corpus_mod.classify_path` before any root is consulted.
    """
    state = corpus_mod.PATH_DENIED
    owning = None
    for cand in ctx.corpora:
        s = corpus_mod.classify_path(cand, ctx.root, relpath)
        if s == corpus_mod.PATH_ALLOWED:
            return s, cand
        if s == corpus_mod.PATH_ABSENT:
            state, owning = corpus_mod.PATH_ABSENT, cand
    return state, owning


def _acl_failure(stage: str, relpath: Any) -> StageOutcome:
    return StageOutcome(name=stage, outcome=ACL_SCOPE_FAILURE, abstain=True,
                        failure_class="ACL_SCOPE_FAILURE",
                        detail={"path": relpath if isinstance(relpath, str) else None,
                                "reason": "not a clean relative path, outside every corpus root, "
                                          "or deny-pattern match"})


def stage_exact(ctx: StageContext, constraints: Mapping[str, Any]) -> StageOutcome:
    target = constraints["path"] if "path" in constraints else constraints.get("location")
    document_id = constraints.get("document_id")
    if target is None and document_id is None:
        return _na(EXACT)
    # A version/lifecycle constraint is a structural concern; defer to structure.
    if any(k in constraints for k in LIFECYCLE_KEYS):
        return _na(EXACT)
    if target is not None:
        state, owning = _classify_requested(ctx, target)
        if state == corpus_mod.PATH_DENIED:
            return _acl_failure(EXACT, target)
        if state == corpus_mod.PATH_ABSENT or owning is None:
            return _no_match(EXACT)
        doc = ctx.load(target, owning)
        if doc.metadata["superseded"]:
            return StageOutcome(name=EXACT, outcome=DEFERRED_SUPERSEDED, doc=doc,
                                detail={"candidate": doc.document_id})
        return StageOutcome(name=EXACT, outcome=RESOLVED, resolved=True, doc=doc,
                            relationship="EXACT_MATCH", span=doc.full_span())
    doc = ctx.find_by_document_id(str(document_id))
    if doc is None:
        return _no_match(EXACT)
    if doc.metadata["superseded"]:
        return StageOutcome(name=EXACT, outcome=DEFERRED_SUPERSEDED, doc=doc,
                            detail={"candidate": doc.document_id})
    return StageOutcome(name=EXACT, outcome=RESOLVED, resolved=True, doc=doc,
                        relationship="EXACT_MATCH", span=doc.full_span())


def stage_metadata(ctx: StageContext, constraints: Mapping[str, Any]) -> StageOutcome:
    filters = {k: constraints[k] for k in METADATA_KEYS if k in constraints}
    if not filters:
        return _na(METADATA)
    if any(k in constraints for k in LIFECYCLE_KEYS):
        return _na(METADATA)
    matches = []
    for doc in ctx.documents():
        if _matches_filters(doc, filters):
            matches.append(doc)
    if not matches:
        return _no_match(METADATA)
    doc = sorted(matches, key=lambda d: d.relpath)[0]
    if doc.metadata["superseded"]:
        return StageOutcome(name=METADATA, outcome=DEFERRED_SUPERSEDED, doc=doc,
                            detail={"candidate": doc.document_id})
    return StageOutcome(name=METADATA, outcome=RESOLVED, resolved=True, doc=doc,
                        relationship="EXACT_MATCH", span=doc.full_span())


def _matches_filters(doc: Document, filters: Mapping[str, Any]) -> bool:
    for key, want in filters.items():
        have = doc.metadata.get(key)
        if have is None:
            return False
        if str(have).strip().lower() != str(want).strip().lower():
            return False
    return True


def stage_structure(ctx: StageContext, constraints: Mapping[str, Any],
                    deferred: Optional[Document] = None) -> StageOutcome:
    candidate = deferred
    if candidate is None and any(k in constraints for k in LIFECYCLE_KEYS):
        document_id = constraints.get("document_id")
        if document_id is not None:
            candidate = ctx.find_by_document_id(str(document_id))
        elif any(k in constraints for k in METADATA_KEYS):
            filters = {k: constraints[k] for k in METADATA_KEYS if k in constraints}
            matches = sorted((d for d in ctx.documents() if _matches_filters(d, filters)),
                             key=lambda d: d.relpath)
            candidate = matches[0] if matches else None
    if candidate is None:
        return _na(STRUCTURE)
    outcome = _apply_supersession(ctx, STRUCTURE, candidate)
    return outcome


def stage_vocabulary(ctx: StageContext, constraints: Mapping[str, Any]) -> StageOutcome:
    alias = constraints.get("alias")
    if alias is None:
        return _na(VOCABULARY)
    for corpus in ctx.corpora:
        canonical = corpus.vocabulary.get(str(alias))
        if canonical is None:
            continue
        doc = ctx.find_by_document_id(canonical)
        if doc is None:
            continue
        return _apply_supersession(ctx, VOCABULARY, doc)
    return _no_match(VOCABULARY)


def stage_lexical(ctx: StageContext, constraints: Mapping[str, Any]) -> StageOutcome:
    keywords = constraints.get("keywords")
    if not keywords:
        return _na(LEXICAL)
    terms: List[str] = []
    for kw in keywords:
        terms.extend(tokenize(str(kw)))
    if not terms:
        return _na(LEXICAL)
    docs = ctx.documents()
    if not docs:
        return _no_match(LEXICAL)
    best_doc, best_score = _bm25_best(docs, terms)
    if best_doc is None or best_score <= 0.0:
        return _no_match(LEXICAL)
    span = _best_line_span(best_doc, terms)
    if best_doc.metadata["superseded"]:
        return _supersede_lexical(ctx, best_doc, terms)
    return StageOutcome(name=LEXICAL, outcome=RESOLVED, resolved=True, doc=best_doc,
                        relationship="LEXICAL_SUPPORT", span=span)


def _supersede_lexical(ctx: StageContext, doc: Document, terms: Sequence[str]) -> StageOutcome:
    """Redirect a superseded lexical hit to its successor without overclaiming.

    BM25 matched the superseded document, not the successor, so the successor's
    evidence is only as strong as the successor itself supports: ``LEXICAL_SUPPORT``
    with a matching line span when the successor scores for the terms, otherwise
    ``UNVERIFIED`` with its whole-file span. If the successor is outside the corpus
    the result abstains with ``WRONG_DOCUMENT_VERSION`` rather than cite the stale one.
    The successor is the end of the ``Superseded-By`` chain, as in
    :func:`_apply_supersession`: a chain that leaves the corpus, cycles or names
    the document itself also abstains.
    """
    successor, chain, successor_id, reason = _follow_supersession(ctx, doc)
    if successor is None:
        return _wrong_version(LEXICAL, chain, successor_id, reason)
    term_set = set(terms)
    if any(tok in term_set for tok in tokenize(successor.text)):
        relationship, span = "LEXICAL_SUPPORT", _best_line_span(successor, terms)
    else:
        relationship, span = "UNVERIFIED", successor.full_span()
    return StageOutcome(name=LEXICAL, outcome=RESOLVED, resolved=True, doc=successor,
                        relationship=relationship, span=span,
                        contradiction_state="SUPERSEDES", superseded=chain,
                        detail={"superseded_document": doc.document_id,
                                "superseding_document": successor.document_id,
                                "supersession_chain": [d.document_id for d in chain]})


def _bm25_best(docs: Sequence[Document], terms: Sequence[str],
               k1: float = 1.2, b: float = 0.75) -> Tuple[Optional[Document], float]:
    tokenized = {doc.relpath: tokenize(doc.text) for doc in docs}
    lengths = {rel: len(toks) for rel, toks in tokenized.items()}
    n = len(docs)
    avgdl = (sum(lengths.values()) / n) if n else 0.0
    df: Dict[str, int] = {}
    for term in set(terms):
        df[term] = sum(1 for toks in tokenized.values() if term in toks)
    best_doc: Optional[Document] = None
    best_score = 0.0
    for doc in sorted(docs, key=lambda d: d.relpath):
        toks = tokenized[doc.relpath]
        dl = lengths[doc.relpath]
        score = 0.0
        for term in terms:
            f = toks.count(term)
            if f == 0 or df.get(term, 0) == 0:
                continue
            idf = math.log(1 + (n - df[term] + 0.5) / (df[term] + 0.5))
            denom = f + k1 * (1 - b + b * (dl / avgdl if avgdl else 0.0))
            score += idf * (f * (k1 + 1)) / denom
        if score > best_score:
            best_score = score
            best_doc = doc
    return best_doc, best_score


def _best_line_span(doc: Document, terms: Sequence[str]) -> dict:
    term_set = set(terms)
    best_line = 1
    best_hits = -1
    for i, line in enumerate(doc.lines, start=1):
        hits = sum(1 for tok in tokenize(line) if tok in term_set)
        if hits > best_hits:
            best_hits = hits
            best_line = i
    return doc.line_span(best_line)


def stage_semantic(ctx: StageContext, constraints: Mapping[str, Any]) -> StageOutcome:
    if ctx.semantic_backend is None:
        return StageOutcome(name=SEMANTIC, outcome=SEMANTIC_UNAVAILABLE,
                            detail="no semantic backend configured in this build")
    hit = ctx.semantic_backend.retrieve(ctx.request, ctx)
    if not hit or not isinstance(hit, Mapping) or "source_path" not in hit:
        return _no_match(SEMANTIC)
    # A backend hit is a requested path like any other: same ACL, no normalisation.
    relpath = hit["source_path"]
    state, owning = _classify_requested(ctx, relpath)
    if state == corpus_mod.PATH_DENIED:
        return _acl_failure(SEMANTIC, relpath)
    if state == corpus_mod.PATH_ABSENT or owning is None:
        return _no_match(SEMANTIC)
    try:
        corpus = ctx.corpus_of(relpath)
    except KeyError:
        return _no_match(SEMANTIC)
    doc = ctx.load(relpath, corpus)
    start = hit.get("start_line", 1)
    end = hit.get("end_line", start)
    if (not isinstance(start, int) or isinstance(start, bool)
            or not isinstance(end, int) or isinstance(end, bool)
            or not 1 <= start <= end <= len(doc.lines)):
        return StageOutcome(name=SEMANTIC, outcome=NO_MATCH,
                            detail={"path": relpath, "reason": "backend span out of range"})
    if doc.metadata["superseded"]:
        # The successor was not what the backend matched, so nothing stronger
        # than UNVERIFIED is claimed for it.
        return _apply_supersession(ctx, SEMANTIC, doc, successor_relationship="UNVERIFIED")
    span_bytes = "".join(doc.lines[start - 1:end]).encode("utf-8")
    span = make_span(start, end, hashlib.sha256(span_bytes).hexdigest())
    return StageOutcome(name=SEMANTIC, outcome=RESOLVED, resolved=True, doc=doc,
                        relationship="UNVERIFIED", span=span)
