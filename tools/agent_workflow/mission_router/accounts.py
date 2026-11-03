"""Account IDs (MISSION-ROUTER-001 Amendment 011, ring 1): every login is checked with its GitHub account ID.

A login is a name GitHub lets an account change, and a deleted App's name can be taken again by a new App. The account
ID never changes and is never reused. ``AccountGuard`` sits where GitHub's records enter the router: every account
object (``user``, ``merged_by``, ``actor``, ...) whose login is one the pipeline trusts is compared with the ID it
should carry. Under ``"enforce"`` a mismatch gets a login no rule accepts, so every check downstream sees a foreign
identity; under ``"observe"`` it is logged and left as it was.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, Callable, Dict, Iterable, Optional, Set

IDENTITY_MODES = ("observe", "enforce")


def identity_mode(config: dict) -> str:
    """``config.json`` ``"identity"``; ``"observe"`` when absent. Any other value raises: no agent may act."""
    value = config.get("identity", "observe")
    if value not in IDENTITY_MODES:
        raise ValueError(f"config.json: identity must be one of {', '.join(IDENTITY_MODES)}, not {value!r}")
    return value


def account_id(value: Any) -> Optional[int]:
    """A GitHub account ID: a positive int, never a bool."""
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def config_accounts(config: dict) -> Dict[str, int]:
    """Login (casefolded) -> account ID for ``hitl_logins`` (``hitl_account_ids``, same order) and ``bot_login``
    (``bot_account_id``). A list of the wrong length or a non-numeric ID raises."""
    accounts: Dict[str, int] = {}
    hitl_ids = config.get("hitl_account_ids")
    if hitl_ids is not None:
        hitl = config["hitl_logins"]
        if not (isinstance(hitl_ids, list) and len(hitl_ids) == len(hitl) and all(account_id(x) for x in hitl_ids)):
            raise ValueError("config.json: hitl_account_ids must give one account ID per hitl_logins entry, in order")
        accounts.update({login.casefold(): ident for login, ident in zip(hitl, hitl_ids)})
    if config.get("bot_account_id") is not None:
        if not account_id(config["bot_account_id"]):
            raise ValueError("config.json: bot_account_id must be an account ID")
        accounts[config["bot_login"].casefold()] = config["bot_account_id"]
    return accounts


def expected_accounts(config: dict, registry: Optional[str]) -> Dict[str, int]:
    """Every login the pipeline trusts -> its account ID: ``config_accounts`` plus each agent's bot from the
    identity registry's ``Account ID`` column. An agent without one is left out, so nothing vouches for it."""
    from .model import MissionInputError, parse_identity_accounts  # model imports nothing from here

    accounts = config_accounts(config)
    try:
        registered = parse_identity_accounts(registry)
    except MissionInputError:
        registered = {}
    for agent, login in (config.get("agents") or {}).items():
        if registered.get(agent):
            accounts[login.casefold()] = registered[agent]
    return accounts


class AccountGuard:
    """Checks every account object in GitHub's records against the IDs the pipeline expects."""

    def __init__(self, mode: str, log: Callable[[str], None]) -> None:
        self.mode = mode
        self.log = log
        self.expected: Dict[str, int] = {}  # casefolded login -> account ID
        self._logged: Set[tuple] = set()

    def expect(self, accounts: Dict[str, int]) -> None:
        self.expected = {login.casefold(): ident for login, ident in accounts.items()}
        self._logged = set()

    def mismatch(self, login: str, found: Any) -> Optional[str]:
        """Why ``login`` with account ID ``found`` is not the account the pipeline trusts, or None."""
        want = self.expected.get(login.casefold())
        if want is None or account_id(found) == want:
            return None
        return f"{login} has account ID {found if account_id(found) else 'none'}, not {want}"

    def check(self, payload: Any) -> Any:
        """``payload`` with every mismatched account relabelled (enforce) or logged (observe). Mutates in place."""
        stack = [payload]
        while stack:
            item = stack.pop()
            if isinstance(item, list):
                stack.extend(item)
            elif isinstance(item, dict):
                login = item.get("login")
                if isinstance(login, str):
                    why = self.mismatch(login, item.get("id"))
                    if why:
                        self._report(why)
                        if self.mode == "enforce":
                            item["login"] = f"{login} (account ID mismatch)"  # matches no login any rule accepts
                stack.extend(v for v in item.values() if isinstance(v, (dict, list)))
        return payload

    def _report(self, why: str) -> None:
        if why not in self._logged:
            self._logged.add(why)
            self.log(f"identity ({self.mode}): {why}" + ("; treated as a foreign identity" if self.mode == "enforce" else ""))

    def confirm(self, read_account: Callable[[str], Optional[dict]], logins: Iterable[str]) -> Set[str]:
        """The logins whose GitHub account record has the expected ID and type ``Bot``. Each failure is logged."""
        confirmed = set()
        for login in logins:
            want = self.expected.get(login.casefold())
            try:
                record = read_account(login) or {}
            except Exception as exc:  # an unreadable record confirms nothing
                self._report(f"{login}: GitHub's account record is unreadable ({exc})")
                continue
            if want is not None and account_id(record.get("id")) == want and record.get("type") == "Bot":
                confirmed.add(login)
            else:
                self._report(f"{login}: GitHub's account record has ID {record.get('id')} and type "
                             f"{record.get('type')}, not {want} and Bot")
        return confirmed


class GuardedGitHub:
    """A GitHub client whose every record passes through an ``AccountGuard`` before the router reads it."""

    def __init__(self, gh: Any, guard: AccountGuard) -> None:
        self._gh = gh
        self.guard = guard

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._gh, name)
        if not callable(attr):
            return attr
        guard = self.guard

        def guarded(*args, **kwargs):
            result = attr(*args, **kwargs)
            if isinstance(result, Iterator):  # a paginated read: every item is checked as it is read
                return (guard.check(item) for item in result)
            return result if isinstance(result, (str, bytes)) or result is None else guard.check(result)
        return guarded
