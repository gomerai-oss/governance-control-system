"""The challenge loop on a plan (MISSION-DISPATCH-001 Amendment 021 §3n, MISSION-ROUTER-001 Amendment 019 §6a).

Before HITL approves a plan, the Adversarial Reviewer (AR, its own App) challenges it, round by round:

- AR writes ``missions/<ID>/challenges/round-<N>.json`` (``mission-challenge-v1``) and ``round-<N>.md``, through its
  own PR into the plan branch;
- the A1 seat answers with ``round-<N>-response.md``, opening ``Position: DEFEND`` or ``Position: ACCEPT`` and then
  ``Drafted-with: <agent>`` or ``Drafted-with: HITL`` (HITL, 2026-11-11);
- AR answers that in round N+1, and a change to the plan's own files makes a new round due.

Everything here is pure: the router reads GitHub and hands the facts in. Agent text is untrusted, so each parser
returns a fully validated value or raises ``MissionInputError``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Mapping, Optional, Sequence, Tuple

from .model import SHA_RE, MissionInputError, _load_json, _require

CONFIG_KEY = "challenge"
OBSERVE, ENFORCE = "observe", "enforce"
MODES = (OBSERVE, ENFORCE)

CHALLENGE_SCHEMA = "mission-challenge-v1"
CHALLENGE_VERDICTS = ("CHALLENGE", "NO_CHALLENGE")
POSITIONS = ("DEFEND", "ACCEPT")
MAX_ROUNDS = 99  # the most the stage branch name (ar-r<N>) can carry; the loop itself has no cap
MAX_POINTS = 50
POINT_ID_MAX_CHARS = 40
POINT_ON_MAX_CHARS = 300
POINT_TEXT_MAX_CHARS = 4000
SUMMARY_MAX_CHARS = 4000
DRAFTED_WITH_MAX_CHARS = 64
RESPONSE_MAX_CHARS = 65536

_POSITION_RE = re.compile(r"Position:[ \t]*(DEFEND|ACCEPT)[ \t]*")
_DRAFTED_RE = re.compile(r"Drafted-with:[ \t]*(\S(?:[^\r\n]*\S)?)[ \t]*")
_POINT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0," + str(POINT_ID_MAX_CHARS - 1) + r"}")
# A3's line on one open AR point, in its verdict's summary (Amendment 024 of MISSION-DISPATCH-001).
AR_STATUSES = ("handled", "still present", "out of reach")
AR_LINE_RE = re.compile(r"(?m)^[ \t]*(AR [A-Za-z0-9][A-Za-z0-9._-]{0," + str(POINT_ID_MAX_CHARS - 1)
                        + r"}: (?:" + "|".join(AR_STATUSES) + r")\b[^\r\n]*)$")


class ChallengeError(ValueError):
    """``"challenge"`` in config.json is not a known mode: the job fails and the router stops (vectors 120, 126)."""


def mode(config: Mapping[str, object]) -> str:
    """``config.json`` ``"challenge"``; ``"observe"`` when absent. Any other value raises."""
    value = config.get(CONFIG_KEY, OBSERVE)
    if value not in MODES:
        raise ChallengeError(f"config {CONFIG_KEY} must be one of {', '.join(MODES)}, not {value!r}")
    return str(value)


def challenges_dir(mission_id: str) -> str:
    return f"missions/{mission_id}/challenges/"


def round_json(mission_id: str, round_no: int) -> str:
    return f"{challenges_dir(mission_id)}round-{round_no}.json"


def round_md(mission_id: str, round_no: int) -> str:
    return f"{challenges_dir(mission_id)}round-{round_no}.md"


def response_path(mission_id: str, round_no: int) -> str:
    return f"{challenges_dir(mission_id)}round-{round_no}-response.md"


def plan_branch(mission_id: str) -> str:
    return f"mission/{mission_id}/a1"


def is_plan_file(path: str, mission_id: str) -> bool:
    """A file of the plan itself: everything under ``missions/<ID>/`` except ``challenges/`` (§3n item 3)."""
    return path.startswith(f"missions/{mission_id}/") and not path.startswith(challenges_dir(mission_id))


@dataclass(frozen=True)
class Point:
    id: str
    on: str  # the plan file and section it is about
    claim: str
    why: str


@dataclass(frozen=True)
class Challenge:
    mission_id: str
    round: int
    challenged_sha: str  # the plan head AR read
    verdict: str  # CHALLENGE or NO_CHALLENGE
    summary: str
    points: Tuple[Point, ...]


def parse_challenge(text, mission_id: str, round_no: int) -> Challenge:
    """``round-<N>.json`` as AR wrote it, checked against the mission and round it must be for (vector 116)."""
    data = _load_json(text, "challenge")
    allowed = {"schema", "mission_id", "round", "challenged_sha", "verdict", "summary", "points"}
    _require(set(data) <= allowed, f"challenge: unknown keys {sorted(set(data) - allowed)}")
    _require(data.get("schema") == CHALLENGE_SCHEMA, f"challenge: schema must be {CHALLENGE_SCHEMA}")
    _require(data.get("mission_id") == mission_id, "challenge: mission_id does not match the branch")
    _require(data.get("round") == round_no and not isinstance(data.get("round"), bool),
             "challenge: round does not match the branch")
    sha = data.get("challenged_sha")
    _require(isinstance(sha, str) and bool(SHA_RE.fullmatch(sha)),
             "challenge: challenged_sha must be a full 40-character commit SHA")
    _require(data.get("verdict") in CHALLENGE_VERDICTS, "challenge: verdict must be CHALLENGE or NO_CHALLENGE")
    summary = data.get("summary", "")
    _require(isinstance(summary, str) and len(summary) <= SUMMARY_MAX_CHARS,
             f"challenge: summary must be text of at most {SUMMARY_MAX_CHARS} characters")
    raw_points = data.get("points", [])
    _require(isinstance(raw_points, list) and len(raw_points) <= MAX_POINTS,
             f"challenge: points must list at most {MAX_POINTS} points")
    points = []
    for entry in raw_points:
        _require(isinstance(entry, dict) and set(entry) == {"id", "on", "claim", "why"},
                 "challenge: each point has exactly id, on, claim and why")
        _require(isinstance(entry["id"], str) and bool(_POINT_ID_RE.fullmatch(entry["id"])),
                 "challenge: a point id is a short name of letters, digits, '.', '_' or '-'")
        _require(isinstance(entry["on"], str) and 0 < len(entry["on"]) <= POINT_ON_MAX_CHARS,
                 f"challenge: a point's on names the plan file and section in 1-{POINT_ON_MAX_CHARS} characters")
        for key in ("claim", "why"):
            _require(isinstance(entry[key], str) and entry[key].strip() and len(entry[key]) <= POINT_TEXT_MAX_CHARS,
                     f"challenge: a point's {key} is text of 1-{POINT_TEXT_MAX_CHARS} characters")
        points.append(Point(entry["id"], entry["on"], entry["claim"], entry["why"]))
    _require(len({p.id for p in points}) == len(points), "challenge: point ids must be distinct")
    if data["verdict"] == "CHALLENGE":
        _require(bool(points), "challenge: a CHALLENGE lists at least one point")
    else:
        _require(not points, "challenge: NO_CHALLENGE lists no points")
    return Challenge(mission_id, round_no, sha, data["verdict"], summary, tuple(points))


@dataclass(frozen=True)
class Response:
    position: str  # DEFEND or ACCEPT
    drafted_with: str  # the agent HITL drafted it with, or "HITL"; declared, not proven (dispatch limit 36)


def parse_response(text) -> Response:
    """``round-<N>-response.md``: line 1 ``Position: DEFEND|ACCEPT``, line 2 ``Drafted-with: <agent>|HITL``.

    The error names the line that is missing (router vector 127)."""
    _require(isinstance(text, str) and len(text) <= RESPONSE_MAX_CHARS,
             f"the response is missing or longer than {RESPONSE_MAX_CHARS} characters")
    lines = text.lstrip("﻿").splitlines()
    first = lines[0] if lines else ""
    second = lines[1] if len(lines) > 1 else ""
    position = _POSITION_RE.fullmatch(first)
    _require(position is not None, "its first line must be `Position: DEFEND` or `Position: ACCEPT`")
    drafted = _DRAFTED_RE.fullmatch(second)
    _require(drafted is not None and len(drafted.group(1)) <= DRAFTED_WITH_MAX_CHARS,
             "its second line must be `Drafted-with: <agent>` (the agent HITL drafted it with) or "
             f"`Drafted-with: HITL`, of at most {DRAFTED_WITH_MAX_CHARS} characters")
    return Response(position.group(1), drafted.group(1))


@dataclass(frozen=True)
class RoundFacts:
    """What the router read about one round at the plan head."""
    challenge: Optional[Challenge]  # None: round-<N>.json is there but does not parse
    error: str = ""  # why it does not parse
    authentic: bool = False  # it came in through a merged PR of AR's own App, unchanged since (router §6a)
    response: Optional[str] = None  # the text of round-<N>-response.md, when there is one


@dataclass(frozen=True)
class LoopStatus:
    rounds: int  # the latest round on the plan head (0: none)
    due_round: Optional[int]  # the round AR is due for now, or None
    due_reason: str  # why that round is due
    complete: bool  # the loop is complete for this head (§6a): HITL's approval of it counts under enforce
    missing: str  # when not complete, what is missing, for HITL
    response_error: str = ""  # A1's latest response is there but malformed: AR is not started (vector 127)
    latest: Optional[Challenge] = None
    ended: bool = False  # HITL ended the loop for this head with /mission end-challenge (router Amendment 020)


def loop_status(mission_id: str, rounds: Sequence[RoundFacts], plan_changed: bool,
                stray_responses: Sequence[int] = (), ended: bool = False) -> LoopStatus:
    """Where the loop stands for one plan head (§3n item 3, §6a).

    ``rounds`` are rounds 1..L in order, as found at the head. ``plan_changed`` says whether the plan's own files at
    the head differ from those at the latest round's ``challenged_sha``. ``stray_responses`` are responses found for a
    round that does not exist. ``ended`` says HITL ended the loop for this head (router Amendment 020): the loop is
    then complete, with no round due, as long as at least one round exists and every round is valid and AR's own.
    """
    if not rounds:
        return LoopStatus(0, 1, "the plan has no challenge round yet", False, "no challenge round exists yet")
    latest_no = len(rounds)
    for n, facts in enumerate(rounds, 1):
        if facts.challenge is None:
            return LoopStatus(latest_no, None, "", False,
                              f"challenge round {n} is not a valid {CHALLENGE_SCHEMA} file: {facts.error}")
        if not facts.authentic:
            return LoopStatus(latest_no, None, "", False,
                              f"challenge round {n} was not added by a merged PR of AR's own App, or changed since")
    if stray_responses:
        return LoopStatus(latest_no, None, "", False,
                          "a response exists for a round AR has not written: round "
                          + ", ".join(str(n) for n in stray_responses))
    latest = rounds[-1]
    if ended:  # HITL's decision: no rebuttal and no fresh round for this head, whatever A1 wrote since
        return LoopStatus(latest_no, None, "", True, "", latest=latest.challenge, ended=True)
    if latest.response is not None:
        try:
            parse_response(latest.response)
        except MissionInputError as exc:
            return LoopStatus(latest_no, None, "", False,
                              f"A1's response to round {latest_no} is not complete: {exc}",
                              response_error=f"A1's response to round {latest_no}: {exc}", latest=latest.challenge)
        if latest_no >= MAX_ROUNDS:
            return LoopStatus(latest_no, None, "", False,
                              f"round {latest_no} is the last round the branch names can carry; HITL decides")
        return LoopStatus(latest_no, latest_no + 1, f"A1 answered round {latest_no}", False,
                          f"A1's response to round {latest_no} has no answer from AR yet (the rebuttal is pending)",
                          latest=latest.challenge)
    if plan_changed:
        if latest_no >= MAX_ROUNDS:
            return LoopStatus(latest_no, None, "", False,
                              f"round {latest_no} is the last round the branch names can carry; HITL decides")
        return LoopStatus(latest_no, latest_no + 1, f"the plan changed since AR read it in round {latest_no}", False,
                          f"the plan changed since AR read it in round {latest_no}", latest=latest.challenge)
    return LoopStatus(latest_no, None, "", True, "", latest=latest.challenge)


@dataclass(frozen=True)
class OpenPoints:
    """AR's latest round, when it is a CHALLENGE: the points HITL approved the plan over (dispatch Amendment 024)."""
    round: int
    challenge: Challenge
    response: Optional[str]  # A1's response to it, when HITL ended the loop after one; AR never read it


def open_points(read: Callable[[str], Optional[str]], mission_id: str) -> Optional[OpenPoints]:
    """The open points in an approved plan, from its challenge files. ``read`` returns a file's text at the approved
    head, or None. None when there is no round, or the latest round is ``NO_CHALLENGE``. A latest round that does not
    parse raises ``MissionInputError``: it cannot be in an approved plan, as the router never counts the approval."""
    latest = 0
    while latest < MAX_ROUNDS and read(round_json(mission_id, latest + 1)) is not None:
        latest += 1
    if not latest:
        return None
    found = parse_challenge(read(round_json(mission_id, latest)), mission_id, latest)
    if found.verdict != "CHALLENGE":
        return None
    return OpenPoints(latest, found, read(response_path(mission_id, latest)))


def ar_lines(summary: str) -> Tuple[str, ...]:
    """A3's ``AR <id>: handled|still present|out of reach ...`` lines in its verdict's summary."""
    return tuple(m.group(1).strip() for m in AR_LINE_RE.finditer(summary or ""))
