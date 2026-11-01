"""Blast radius (ring 5): the checks run with no network, and every check and agent run is capped.

MISSION-DISPATCH-001 §3h, Amendment 012. The mode is ``"blast_radius"`` in ``config.json``:

observe  (the default when the key is absent) the caps apply; the network rules only count what the checks
         account sends, and the probe's result is recorded
enforce  the network rules reject everything the checks account sends except on loopback, and loopback DNS too;
         a probe that gets through fails the job before any check runs

The rules match the checks account's user id, so the runner's own processes keep their network. Loopback DNS is
refused because the runner's local resolver forwards queries to the internet, which would carry data out.
"""

from __future__ import annotations

import json
import re
import socket
import subprocess
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

OBSERVE, ENFORCE = "observe", "enforce"
MODES = (OBSERVE, ENFORCE)
CONFIG_KEY = "blast_radius"

# Caps on every check and agent run (§3h item 4), applied by prlimit to the process and everything it starts.
MAX_PROCESSES = 512
MAX_FILE_BYTES = 1024 * 1024 * 1024
MAX_OPEN_FILES = 4096
MAX_CHANGED_FILES = 300
LOG_MAX_BYTES = 8 * 1024 * 1024
CLAUDE_MAX_TURNS = 200

CHAIN = "MISSION-NET"
TAG = "mission-net-out"  # comment on the rules whose counters say what the account sent
FIREWALLS = ("iptables", "ip6tables")
PROBE_HOST, PROBE_DNS = "api.github.com", "1.1.1.1"
PROBE_FALLBACK = "1.1.1.1"  # when the runner cannot resolve PROBE_HOST, a TCP probe to a fixed address instead
PROBE_TIMEOUT = 5

# Run as the checks account. Each probe is "open" when it got through, "closed" when it did not.
PROBE_SCRIPT = r"""
import json, socket, sys
host, dns, timeout = sys.argv[1], sys.argv[2], float(sys.argv[3])
out = {}
try:
    socket.create_connection((host, 443), timeout=timeout).close()
    out["tcp"] = "open"
except OSError:
    out["tcp"] = "closed"
query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(timeout)
try:
    s.connect((dns, 53))
    s.send(query)
    out["dns"] = "open" if s.recv(512) else "closed"
except OSError:
    out["dns"] = "closed"
finally:
    s.close()
try:
    socket.getaddrinfo("example.com", 443)
    out["resolver"] = "open"
except OSError:
    out["resolver"] = "closed"
print(json.dumps(out))
"""

_COUNTER = re.compile(r"-c (\d+) (\d+)")
_ACCOUNT = re.compile(r"[a-z_][a-z0-9_-]{0,31}")

Runner = Callable[[Sequence[str]], subprocess.CompletedProcess]


class BlastError(ValueError):
    """The blast-radius controls cannot be applied as configured; the job does not go on."""


def mode(config: Mapping[str, Any]) -> str:
    value = config.get(CONFIG_KEY, OBSERVE)
    if value not in MODES:
        raise BlastError(f"config {CONFIG_KEY} must be one of {', '.join(MODES)}, not {value!r}")
    return value


def limits_argv() -> List[str]:
    """prlimit prefix for one capped command: processes, size of any file written, open files."""
    return ["prlimit", f"--nproc={MAX_PROCESSES}", f"--fsize={MAX_FILE_BYTES}", f"--nofile={MAX_OPEN_FILES}", "--"]


def keep_tail(path: Path, limit: int = LOG_MAX_BYTES) -> None:
    """Cut a log to its last ``limit`` bytes, in place."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size <= limit:
        return
    with open(path, "rb") as handle:
        handle.seek(-limit, 2)
        tail = handle.read()
    path.write_bytes(b"[... earlier output cut: the log keeps its last %d bytes]\n" % limit + tail)


def chain_rules(enforce: bool) -> List[List[str]]:
    """The rules of the checks account's chain, for one firewall. Without ``enforce`` they only count."""
    target = ["-j", "REJECT"] if enforce else []
    tag = ["-m", "comment", "--comment", TAG]
    return [
        ["-A", CHAIN, "-o", "lo", "-p", "udp", "--dport", "53", *tag, *target],
        ["-A", CHAIN, "-o", "lo", "-p", "tcp", "--dport", "53", *tag, *target],
        ["-A", CHAIN, "-o", "lo", "-j", "ACCEPT"],
        ["-A", CHAIN, *tag, *target],
    ]


def firewall_argv(account: str, enforce: bool) -> List[List[str]]:
    """Every command that closes (or, observing, counts) the network of ``account``, in order."""
    if not _ACCOUNT.fullmatch(account):
        raise BlastError(f"{account!r} is not a usable account name")
    commands = []
    for tool in FIREWALLS:
        base = ["sudo", "-n", tool, "-w"]
        commands.append([*base, "-N", CHAIN])
        commands += [[*base, *rule] for rule in chain_rules(enforce)]
        commands.append([*base, "-I", "OUTPUT", "1", "-m", "owner", "--uid-owner", account, "-j", CHAIN])
    return commands


def probe_argv(account: str, host: str, path: str) -> List[str]:
    return ["sudo", "-n", "-u", account, "--", "env", "-i", f"PATH={path}", "LANG=C.UTF-8",
            "python3", "-I", "-c", PROBE_SCRIPT, host, PROBE_DNS, str(PROBE_TIMEOUT)]


def _run(argv: Sequence[str]) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), capture_output=True, text=True, errors="replace", stdin=subprocess.DEVNULL,
                          timeout=60)


def _probe_host() -> str:
    try:
        return socket.gethostbyname(PROBE_HOST)
    except OSError:
        return PROBE_FALLBACK


class CheckNetwork:
    """The checks account's network for one checks job: closed (or counted) before the first check."""

    def __init__(self, account: str, blast_mode: str, run: Runner = _run, path: str = "/usr/local/bin:/usr/bin:/bin",
                 probe_host: Optional[Callable[[], str]] = None) -> None:
        if blast_mode not in MODES:
            raise BlastError(f"unknown blast-radius mode {blast_mode!r}")
        self.account, self.mode, self.run, self.path = account, blast_mode, run, path
        self.probe_host = probe_host or _probe_host
        self.record: Dict[str, Any] = {"mode": blast_mode}

    def close(self) -> Dict[str, Any]:
        """Install the rules, then prove them. Enforcing, a failure here stops the job before any check runs."""
        enforce = self.mode == ENFORCE
        for argv in firewall_argv(self.account, enforce):
            done = self.run(argv)
            if done.returncode != 0:
                problem = f"{' '.join(argv[2:5])} failed: {(done.stderr or done.stdout or '').strip()[:200]}"
                if enforce:
                    raise BlastError(f"the checks' network could not be closed ({problem})")
                self.record["rules"] = f"not installed ({problem})"
                break
        else:
            self.record["rules"] = "reject" if enforce else "count"
        host = self.probe_host()
        done = self.run(probe_argv(self.account, host, self.path))
        try:
            probe = json.loads((done.stdout or "").strip().splitlines()[-1])
            if not (isinstance(probe, dict) and set(probe) == {"tcp", "dns", "resolver"}
                    and set(probe.values()) <= {"open", "closed"}):
                raise ValueError
        except (ValueError, IndexError):
            if enforce:
                raise BlastError("the network probe gave no result, so the checks' network is not proven closed")
            probe = {}
        self.record["probe"] = {"host": host, **probe}
        if not enforce and self.record["rules"] == "count":
            for tool in FIREWALLS:  # count only what the checks send, not the probe
                self.run(["sudo", "-n", tool, "-w", "-Z", CHAIN])
        opened = sorted(k for k, v in probe.items() if v == "open")
        self.record["network"] = "open" if opened or not probe else "closed"
        if enforce and opened:
            raise BlastError("the checks' network is still open after the rules (" + ", ".join(opened) + ")")
        return self.record

    def report(self) -> Dict[str, Any]:
        """The record, with what the account sent past the rules while the checks ran (observing)."""
        if self.record.get("rules") == "count":
            sent = 0
            for tool in FIREWALLS:
                done = self.run(["sudo", "-n", tool, "-w", "-S", CHAIN, "-v"])
                for line in (done.stdout or "").splitlines():
                    found = _COUNTER.search(line) if TAG in line else None
                    if found:
                        sent += int(found.group(1))
            self.record["packets_sent"] = sent
        return dict(self.record)
