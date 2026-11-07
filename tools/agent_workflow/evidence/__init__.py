"""Durable evidence (ring 6, MISSION-DISPATCH-001 §3m, Amendment 020). Standard library only.

- ``record``: the one record every pipeline action writes (``evidence-record-v1``), with its closed list of actions.
- ``chain``: a run's records, each carrying the digest of the one before it (§3m item 2).
- ``seal``: the signed seal over a run's chain head, and the pinned evidence keys it is checked against.
- ``verify``: the verifier (§3m item 5), ``python3 -m evidence verify``.

``"evidence"`` in ``config.json``: ``"observe"`` (the default when absent) or ``"enforce"``; any other value fails the
job and stops the router (vectors 111, router 119).
"""

from __future__ import annotations

from typing import Mapping

OBSERVE, ENFORCE = "observe", "enforce"
MODES = (OBSERVE, ENFORCE)
CONFIG_KEY = "evidence"


class EvidenceError(ValueError):
    """The evidence mode is unknown, or a record, chain, seal or key pin is malformed."""


def mode(config: Mapping[str, object]) -> str:
    """``config.json`` ``"evidence"``; ``"observe"`` when absent. Any other value raises."""
    value = config.get(CONFIG_KEY, OBSERVE)
    if value not in MODES:
        raise EvidenceError(f"config {CONFIG_KEY} must be one of {', '.join(MODES)}, not {value!r}")
    return str(value)
