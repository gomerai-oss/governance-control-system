"""Router Policy Decision Point (ROUTER-POLICY-SPEC-002 section 4).

Six steps run in fixed order; the first step that reaches a decision stops
evaluation. ``_decide`` is the only constructor of ``Decision`` and the only
place ``merge_allowed`` is computed, and it computes it solely from the
section 3d allowlist table.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any, List, Mapping, Optional, Protocol, Tuple

from .policy import (
    ACKNOWLEDGED,
    AGENT_POLICY,
    AUTHORITY,
    CLASS_REQUIRED,
    DENIED,
    HITL_REQUIRED,
    WAIVED,
    BlockPolicy,
    PathRejected,
    PolicyTables,
    load_tables,
    normalize_path,
)

UNKNOWN_PR_TYPE = "UNKNOWN"

REASON_PASS = "POLICY_PASS"
REASON_WAIVED = "OPERATOR_WAIVER"
REASON_DIFF_UNKNOWN = "DIFF_UNKNOWN"
REASON_INVALID_INPUT = "INVALID_INPUT"
REASON_UNKNOWN_BLOCK = "UNKNOWN_BLOCK"
REASON_AUTHORITY = "AUTHORITY_VIOLATION"
REASON_AGENT_POLICY = "AGENT_POLICY_CHANGE"
REASON_UNKNOWN_CLASS = "UNKNOWN_CLASS"
REASON_EVALUATION_ERROR = "EVALUATION_ERROR"

STEP_INPUT_INTEGRITY = 1
STEP_AUTHORITY = 2
STEP_AGENT_POLICY = 3
STEP_CLASS_DIFF = 4
STEP_OUTPUT = 6

_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SINGLE_PATH_STATUSES = frozenset({"added", "removed", "modified", "changed", "unchanged"})
_TWO_PATH_STATUSES = frozenset({"renamed", "copied"})


@dataclass(frozen=True)
class FileChange:
    path: str
    status: str
    previous_path: Optional[str] = None


@dataclass(frozen=True)
class FileListing:
    files: Tuple[FileChange, ...]
    complete: bool


class PullRequestSource(Protocol):
    def read_head_sha(self) -> str: ...

    def list_files(self) -> FileListing: ...


@dataclass(frozen=True)
class Decision:
    pr_type: str
    disposition: str
    reason: str
    exit_code: int
    merge_allowed: bool
    head_sha: Optional[str]
    file_list_digest: Optional[str]
    decided_at_step: int
    offending_paths: Tuple[str, ...] = ()

    def to_dict(self) -> dict:
        data = asdict(self)
        data["offending_paths"] = list(self.offending_paths)
        return data


def evaluate(
    source: PullRequestSource,
    handoff_block: Optional[Mapping[str, Any]],
    waiver_state: Any,
    tables: Optional[PolicyTables] = None,
) -> Decision:
    """Evaluate one PR event.

    ``handoff_block`` is ``None`` only when the PR body has no handoff block at
    all; a block that was found but could not be parsed must be passed as a
    mapping (for example ``{}``) so it is denied as invalid, not treated as absent.
    """
    try:
        active = tables if tables is not None else load_tables()
        return _evaluate(source, handoff_block, waiver_state, active)
    except Exception:
        return _decide(
            None,
            pr_type=UNKNOWN_PR_TYPE,
            disposition=DENIED,
            reason=REASON_EVALUATION_ERROR,
            step=STEP_INPUT_INTEGRITY,
            head_sha=None,
            digest=None,
        )


def _evaluate(
    source: PullRequestSource,
    handoff_block: Optional[Mapping[str, Any]],
    waiver_state: Any,
    tables: PolicyTables,
) -> Decision:
    # Step 1: input integrity. The decision binds to the SHA read on both sides of the listing.
    verified = _verified_snapshot(source)
    if verified is None:
        return _decide(tables, UNKNOWN_PR_TYPE, DENIED, REASON_DIFF_UNKNOWN, STEP_INPUT_INTEGRITY, None, None)
    head_sha, digest, paths = verified

    def decide(pr_type: str, disposition: str, reason: str, step: int, offending=()) -> Decision:
        return _decide(tables, pr_type, disposition, reason, step, head_sha, digest, tuple(offending))

    if waiver_state is not True and waiver_state is not False:
        return decide(UNKNOWN_PR_TYPE, DENIED, REASON_INVALID_INPUT, STEP_INPUT_INTEGRITY)
    block, pr_class, failure = _resolve_block(handoff_block, tables)
    if block is None:
        return decide(UNKNOWN_PR_TYPE, DENIED, failure, STEP_INPUT_INTEGRITY)
    pr_type = block.resolve_pr_type(pr_class)

    families = [(raw, tables.classify(key)) for raw, key in paths]

    # Step 2: authority. Not overridable by class or waiver.
    touched = [raw for raw, family in families if family == AUTHORITY]
    if touched:
        return decide(pr_type, DENIED, REASON_AUTHORITY, STEP_AUTHORITY, touched)

    # Step 3: agent policy routes to HITL. Not a breach, never mergeable.
    touched = [raw for raw, family in families if family == AGENT_POLICY]
    if touched:
        return decide(pr_type, HITL_REQUIRED, REASON_AGENT_POLICY, STEP_AGENT_POLICY, touched)

    # Step 4: class-diff. Unknown or missing class permits nothing, unless the block type implies one.
    class_missing = pr_class is None or pr_class == ""
    class_policy = None
    if class_missing:
        if block.implicit_class is not None:
            class_policy = tables.classes[block.implicit_class]
        elif block.class_policy == CLASS_REQUIRED:
            return decide(pr_type, DENIED, REASON_UNKNOWN_CLASS, STEP_CLASS_DIFF)
    else:
        class_policy = tables.classes.get(pr_class) if isinstance(pr_class, str) else None
        if class_policy is None:
            return decide(pr_type, DENIED, REASON_UNKNOWN_CLASS, STEP_CLASS_DIFF)

    permitted = _permitted_families(block, class_policy)
    outside = [raw for raw, family in families if family not in permitted]
    if outside:
        return decide(pr_type, DENIED, block.mismatch_reason, STEP_CLASS_DIFF, outside)

    # Step 5: waiver, consulted only after steps 1-4 passed.
    waived = (
        waiver_state is True
        and block.waiver_applies
        and class_policy is not None
        and class_policy.waiver_eligible
    )

    # Step 6: output.
    if waived:
        return decide(pr_type, WAIVED, REASON_WAIVED, STEP_OUTPUT)
    return decide(pr_type, ACKNOWLEDGED, REASON_PASS, STEP_OUTPUT)


def _verified_snapshot(source: PullRequestSource) -> Optional[Tuple[str, str, List[Tuple[str, str]]]]:
    try:
        sha_before = source.read_head_sha()
        listing = source.list_files()
        sha_after = source.read_head_sha()
    except Exception:
        return None
    if not isinstance(sha_before, str) or not _SHA_RE.match(sha_before) or sha_after != sha_before:
        return None
    if not isinstance(listing, FileListing) or listing.complete is not True:
        return None
    if not isinstance(listing.files, tuple) or not listing.files:
        return None

    paths: List[Tuple[str, str]] = []
    records = []
    try:
        for change in listing.files:
            if not isinstance(change, FileChange):
                return None
            if change.status in _TWO_PATH_STATUSES:
                if change.previous_path is None:
                    return None
            elif change.status not in _SINGLE_PATH_STATUSES:
                return None
            for raw in (change.path, change.previous_path):
                if raw is not None:
                    paths.append((raw, normalize_path(raw)))
            records.append([change.path, change.status, change.previous_path])
    except PathRejected:
        return None

    canonical = json.dumps(sorted(records, key=lambda r: json.dumps(r)), separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return sha_before, digest, paths


def _resolve_block(
    handoff_block: Optional[Mapping[str, Any]], tables: PolicyTables
) -> Tuple[Optional[BlockPolicy], Any, str]:
    if handoff_block is None:
        return tables.absent_block, None, ""
    if not isinstance(handoff_block, Mapping):
        return None, None, REASON_INVALID_INPUT
    block_id = handoff_block.get("handoff_block_id")
    if not isinstance(block_id, str) or not block_id:
        return None, None, REASON_INVALID_INPUT
    block = tables.block_types.get(block_id)
    if block is None:
        return None, None, REASON_UNKNOWN_BLOCK
    return block, handoff_block.get("pr_class"), ""


def _permitted_families(block: BlockPolicy, class_policy) -> frozenset:
    if block.permitted_families is None:
        return class_policy.permitted_families
    if class_policy is None:
        return block.permitted_families
    return block.permitted_families & class_policy.permitted_families


def _decide(
    tables: Optional[PolicyTables],
    pr_type: str,
    disposition: str,
    reason: str,
    step: int,
    head_sha: Optional[str],
    digest: Optional[str],
    offending: Tuple[str, ...] = (),
) -> Decision:
    exit_code = 1 if disposition == DENIED else 0
    merge_allowed = (
        tables is not None
        and exit_code == 0
        and head_sha is not None
        and tables.merge_permitted(pr_type, disposition)
    )
    return Decision(
        pr_type=pr_type,
        disposition=disposition,
        reason=reason,
        exit_code=exit_code,
        merge_allowed=merge_allowed,
        head_sha=head_sha,
        file_list_digest=digest,
        decided_at_step=step,
        offending_paths=offending,
    )
