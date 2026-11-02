"""Blast radius (ring 5): checks and agents with no open network, and every check and agent run capped.

MISSION-DISPATCH-001 §3h, Amendment 012. The mode is ``"blast_radius"`` in ``config.json``:

observe  (the default when the key is absent) the caps apply; the checks' network rules only count, and the
         probe's result is recorded; the agent runs as before, as the runner, pointed at the egress proxy, which
         admits everything and records it
enforce  the checks' network rules reject everything except loopback, and loopback DNS too; a probe that gets
         through fails the job before any check runs. The agent runs as its own account, whose only way out is
         the egress proxy, which admits only the hosts listed for its runtime

The rules match one account's user id, so the runner's own processes keep their network. Loopback DNS is refused
because the runner's local resolver forwards queries to the internet, which would carry data out.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time
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


def limits_argv(own_account: bool = True) -> List[str]:
    """prlimit prefix for one capped command: size of any file written, open files, and processes.

    The process cap counts every process of the account, so it applies only to a run with an account of its own
    (``own_account``): on a shared account it would count the runner's own processes, or a laptop user's.
    """
    nproc = [f"--nproc={MAX_PROCESSES}"] if own_account else []
    return ["prlimit", *nproc, f"--fsize={MAX_FILE_BYTES}", f"--nofile={MAX_OPEN_FILES}", "--"]


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


# ------------------------------------------------------------------ the agent (§3h items 2 and 3)
AGENT_ACCOUNT = "mission-agent"
AGENT_CHAIN = "MISSION-AGENT-NET"
POLICY_FILE = Path(__file__).resolve().parent / "egress-policy.json"
EGRESS_LOG, EGRESS_READY, EGRESS_ERR = "egress.jsonl", "egress.port", "egress.err"
EGRESS_START_TIMEOUT = 15.0
EGRESS_MAX_BYTES = 4 * 1024 * 1024  # of egress.jsonl kept with the run's artifact
PROXY_ENV = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy")
NO_PROXY_ENV = ("NO_PROXY", "no_proxy")


def agent_home(account: str) -> Path:
    return Path("/home") / account


def agent_firewall_argv(account: str, port: int) -> List[List[str]]:
    """Every command that closes ``account``'s network except a TCP connection to the proxy on 127.0.0.1."""
    if not _ACCOUNT.fullmatch(account):
        raise BlastError(f"{account!r} is not a usable account name")
    if not (isinstance(port, int) and 0 < port < 65536):
        raise BlastError(f"{port!r} is not a port")
    tag = ["-m", "comment", "--comment", TAG]
    commands = []
    for tool in FIREWALLS:
        base = ["sudo", "-n", tool, "-w"]
        commands.append([*base, "-N", AGENT_CHAIN])
        if tool == "iptables":
            commands.append([*base, "-A", AGENT_CHAIN, "-o", "lo", "-p", "tcp", "-d", "127.0.0.1",
                             "--dport", str(port), "-j", "ACCEPT"])
        commands.append([*base, "-A", AGENT_CHAIN, *tag, "-j", "REJECT"])
        commands.append([*base, "-I", "OUTPUT", "1", "-m", "owner", "--uid-owner", account, "-j", AGENT_CHAIN])
    return commands


def run_as_argv(account: str, env_names: Sequence[str]) -> List[str]:
    """sudo prefix that runs as ``account`` keeping exactly ``env_names`` (values never on a command line)."""
    if not _ACCOUNT.fullmatch(account):
        raise BlastError(f"{account!r} is not a usable account name")
    names = sorted(n for n in env_names if n != "PATH")  # sudo's secure_path sets PATH
    if any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", n) for n in names):
        raise BlastError("an environment name cannot be passed through sudo")
    return ["sudo", "-n", "-u", account, f"--preserve-env={','.join(names)}", "--"]


def account_env(env: Mapping[str, str], account: str, runner_home: str) -> Dict[str, str]:
    """``env`` for a run as ``account``: its own HOME, and nothing pointing into the runner's home."""
    home = str(agent_home(account))
    kept = {k: v for k, v in env.items() if not (runner_home and runner_home.rstrip("/") + "/" in v + "/")}
    kept["HOME"] = home
    return kept


class AgentEgress:
    """The agent's way out for one run: the proxy, and under enforce the account's firewall and probe."""

    def __init__(self, runtime: str, blast_mode: str, root: Path, account: Optional[str] = None,
                 run: Runner = _run, popen: Callable[..., Any] = subprocess.Popen, policy: Path = POLICY_FILE,
                 probe_host: Optional[Callable[[], str]] = None, log: Callable[[str], None] = print) -> None:
        if blast_mode not in MODES:
            raise BlastError(f"unknown blast-radius mode {blast_mode!r}")
        if blast_mode == ENFORCE and not account:
            raise BlastError("blast radius is enforced but the agent has no account of its own to run as")
        self.runtime, self.mode, self.root, self.account = runtime, blast_mode, root, account
        self.run, self.popen, self.policy, self.log = run, popen, policy, log
        self.probe_host = probe_host or _probe_host
        self.proc: Any = None
        self.port = 0

    def start(self) -> Dict[str, str]:
        """Start the proxy (and close the account's network). Returns the variables that point the runtime at it."""
        try:
            self._start_proxy()
            if self.account and self.mode == ENFORCE:
                self._close_network()
        except BlastError as exc:
            if self.mode == ENFORCE:
                self.stop()
                raise
            self.log(f"::warning::egress proxy not used in observe mode: {exc}")
            self.stop()
            return {}
        url = f"http://127.0.0.1:{self.port}"
        return {name: url for name in PROXY_ENV}

    def _start_proxy(self) -> None:
        ready = self.root / EGRESS_READY
        if ready.exists() or ready.is_symlink():
            ready.unlink()
        tooling = str(Path(__file__).resolve().parents[1])
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONPATH": tooling, "LANG": "C.UTF-8"}
        err_path = self.root / EGRESS_ERR  # a file, not a pipe: nothing reads it while the agent runs
        with open(err_path, "wb") as err:
            self.proc = self.popen([sys.executable, "-B", "-m", "egress", "serve", "--policy", str(self.policy),
                                    "--runtime", self.runtime, "--mode", self.mode,
                                    "--log", str(self.root / EGRESS_LOG), "--ready", str(ready)],
                                   env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=err)
        deadline = time.monotonic() + EGRESS_START_TIMEOUT
        while not ready.is_file():
            if self.proc.poll() is not None:
                why = err_path.read_bytes()[-300:].decode("utf-8", "replace").strip()
                raise BlastError(f"the egress proxy did not start: {why}")
            if time.monotonic() > deadline:
                raise BlastError("the egress proxy did not start in time")
            time.sleep(0.05)
        self.port = int(ready.read_text(encoding="utf-8").strip())

    def _close_network(self) -> None:
        for argv in agent_firewall_argv(self.account, self.port):
            done = self.run(argv)
            if done.returncode != 0:
                raise BlastError(f"the agent's network could not be closed ({' '.join(argv[2:5])}: "
                                 f"{(done.stderr or done.stdout or '').strip()[:200]})")
        done = self.run(probe_argv(self.account, self.probe_host(), "/usr/local/bin:/usr/bin:/bin"))
        try:
            probe = json.loads((done.stdout or "").strip().splitlines()[-1])
            opened = sorted(k for k, v in probe.items() if v != "closed")
        except (ValueError, IndexError, AttributeError):
            raise BlastError("the network probe gave no result, so the agent's network is not proven closed") from None
        if opened or set(probe) != {"tcp", "dns", "resolver"}:
            raise BlastError("the agent's network is still open past the proxy (" + ", ".join(opened) + ")")

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None


def hand_over(root: Path, account: str, paths: Sequence[Path], run: Runner = _run) -> None:
    """Give ``account`` the paths it works in for the run; everything else under ``root`` stays the runner's."""
    for path in paths:
        done = run(["sudo", "-n", "chown", "-R", "--no-dereference", f"{account}:{account}", str(path)])
        if done.returncode != 0:
            raise BlastError(f"cannot hand {path.name} to {account}: {(done.stderr or '').strip()[:200]}")


def take_back(root: Path, account: str, run: Runner = _run) -> List[str]:
    """Kill everything ``account`` runs, then give ``root`` back to the runner. Returns the problems found."""
    problems = []
    run(["sudo", "-n", "pkill", "-KILL", "-u", account])
    if run(["pgrep", "-u", account]).returncode == 0:
        problems.append(f"processes of {account} survived the run")
    done = run(["sudo", "-n", "chown", "-R", "--no-dereference", f"{os.getuid()}:{os.getgid()}", str(root)])
    if done.returncode != 0:
        problems.append(f"cannot take {root} back from {account}")
    return problems


def keep_egress(root: Path, out_dir: Path) -> Dict[str, Any]:
    """Copy the proxy's log next to collect's output (capped) and summarize it."""
    src = root / EGRESS_LOG
    if src.is_symlink() or not src.is_file():
        return {}
    data = src.read_bytes()
    cut = len(data) > EGRESS_MAX_BYTES
    data = data[:EGRESS_MAX_BYTES]
    lines = []
    for line in data.decode("utf-8", "replace").splitlines():
        try:
            lines.append(json.loads(line))
        except ValueError:
            continue
    (out_dir / EGRESS_LOG).write_bytes(data)
    hosts = sorted({str(l.get("host", "")) for l in lines if not l.get("listed")})
    return {"lines": len(lines), "refused": sum(l.get("decision") == "refused" for l in lines),
            "off_list": hosts[:50], "truncated": cut}
