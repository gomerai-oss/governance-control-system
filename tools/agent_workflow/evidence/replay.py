"""EPAP replay (MISSION-DISPATCH-001 Amendment 062): rerun an evidence pack in a sandbox, as an outside auditor would.

A pack (``evidence summon``, Amendment 061) holds what was recorded. The replay takes nothing it says on trust: from
the pack's own files, its git bundle and the auditor's copy of this tooling, with no network and no access to the
repository, its evidence store or GitHub, it does again every step of the mission that is not an AI agent's own work,
and compares each result with what was sealed:

1. **the pack**: every file matches the SHA-256 the manifest gives it, and nothing is added;
2. **git**: the bundle unbundles (git checks every object's id), and holds every commit the pack names;
3. **the keys**: the seals are checked against the evidence keys the repository itself pins in its history
   (``tools/agent_workflow/evidence/key.json`` at the pack's commits), or the auditor's own (``--keys``), never
   against the pack's ``key.json`` alone;
4. **the chains**: each chain is replayed record by record and its seal checked; only sealed, verified records are
   facts below, less any HITL withdrew;
5. **the attestations**: each landing attestation's signature, and that it cites the records as sealed;
6. **the authority**: the plan the router merged is the exact commit a HITL account (``config.json`` at that commit)
   approved, and the approved plan is read there as the router read it;
7. **each stage**: its sealed change, applied with the dispatcher's own ``publish`` code to the commit the sealed
   ``dispatch.collect`` record names, rebuilds the PR head's tree exactly, and the head is the commit the sealed
   ``dispatch.publish`` record names; the dispatcher's own gates (scope, instruction files, the verdict or challenge,
   the secrets boundary's patterns) run again on it and accept it;
8. **the router**: its own gate (``gate.evaluate``) decides again, from the sealed facts, on each PR it merged, and its
   own state machine (``state.derive_state``), replayed over the sealed merges, ends where the mission did;
9. **the result**: from the integration branch's start, the plan and the rebuilt changes, each recorded merge is made
   again and gives the recorded merge's tree, up to the commit that landed;
10. **the checks**: the plan's checks and the landing checks run again on the commit A3 reviewed, in a sandbox with no
    network, and each result is compared with the sealed ``checks.check`` record (recorded from Amendment 060 on).

What an AI agent produced (A2's build, A3's review, AR's challenge) cannot be generated again byte for byte. Each is
reported ``output verified, not re-generated``: it is proven to be exactly what was sealed and what landed, and the
gates accept it, but the agent's run is not repeated.

The report names each step's result: ``reproduced``, ``diverged`` (with what differs), ``not replayable`` (with why), and
the first divergence. A replay never writes outside its work directory and never uses the network.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from evidence import EvidenceError
from evidence import pack as pack_mod
from evidence import record as rec_mod
from evidence import seal as seal_mod
from evidence import summon
from evidence import verify

SCHEMA = "evidence-replay-v1"
REPRODUCED = "reproduced"
DIVERGED = "diverged"
NOT_REPLAYABLE = "not replayable"
OUTPUT_VERIFIED = "output verified, not re-generated"
CONFIG = "tools/agent_workflow/mission_router/config.json"
KEY_PIN = "tools/agent_workflow/evidence/key.json"
CHECK_TIMEOUT = 1800.0
OUTPUT_CHARS = 2000
CHECKS = ("none", "last", "all")
SANDBOXES = ("auto", "unshare", "offline")
# Public addresses a machine with a network reaches; a sandbox reaches none of them.
PROBES = (("1.1.1.1", 443), ("8.8.8.8", 53), ("140.82.112.3", 443))
UNSHARE = ("unshare", "--user", "--map-root-user", "--net", "--mount", "--")
# Inside the namespaces: bring up the namespace's own loopback (the checks' local servers use it; it reaches nothing
# outside), and unless the home is kept, hide the replaying account's home under an empty tmpfs, the work directory
# kept reachable.
_SETUP = ('set -e; w=$1; h=$2; shift 2; ip link set lo up 2>/dev/null || ifconfig lo up 2>/dev/null || true; '
          'if [ -n "$h" ]; then d=$PWD; m=$(mktemp -d); mount --bind "$w" "$m"; '
          'mount -t tmpfs -o mode=0700 tmpfs "$h"; mkdir -p "$w"; mount --bind "$m" "$w"; cd "$d" 2>/dev/null || cd "$w"; '
          'fi; exec "$@"')
_PROBE = ("import socket, sys\n"
          "for host, port in {probes!r}:\n"
          "    try:\n"
          "        socket.create_connection((host, port), timeout=3).close()\n"
          "        sys.exit(0)\n"
          "    except OSError:\n"
          "        pass\n"
          "sys.exit(1)\n")
_BRANCH = re.compile(r"create mission/([A-Z0-9][A-Z0-9-]{2,63})/integration at ([0-9a-f]{40})")
_CHECK = re.compile(r"check (\d+): exit (-?\d+|not run)")
_LANDING = re.compile(r"landing check (\d+) on (\S+) at ([0-9a-f]{0,12}): exit (-?\d+|not run)")
_STATUS = {"A": "added", "M": "modified", "D": "removed", "T": "changed"}
IDENTITY = {"GIT_AUTHOR_NAME": "epap-replay", "GIT_AUTHOR_EMAIL": "epap-replay@localhost",
            "GIT_COMMITTER_NAME": "epap-replay", "GIT_COMMITTER_EMAIL": "epap-replay@localhost",
            "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z"}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _Git:
    """git on the replay's own repository (a bare one), hooks off, no global or system configuration."""

    def __init__(self, repo: Path, environ: Mapping[str, str]) -> None:
        from mission_dispatch.workspace import git_env
        self.repo = repo
        self.env = {**git_env(environ), **IDENTITY}

    def run(self, *args: str, cwd: Optional[Path] = None, check: bool = True, binary: bool = False,
            stdin: Optional[bytes] = None):
        argv = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "protocol.file.allow=user"]
        argv += ["-C", str(cwd)] if cwd else ["--git-dir", str(self.repo)]
        done = subprocess.run([*argv, *args], env=self.env, capture_output=True, input=stdin)
        if check and done.returncode != 0:
            raise EvidenceError(f"git {' '.join(args[:2])}: {done.stderr.decode('utf-8', 'replace').strip()[:300]}")
        return done.stdout if binary else done.stdout.decode("utf-8", "replace").strip()

    def commit(self, ref: str) -> Optional[str]:
        out = self.run("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}", check=False)
        return out if re.fullmatch(r"[0-9a-f]{40}", out or "") else None

    def show(self, commit: str, path: str) -> Optional[str]:
        """The file ``path`` at ``commit``, or None when there is none."""
        if not path:
            return None
        done = subprocess.run(["git", "--git-dir", str(self.repo), "cat-file", "blob", f"{commit}:{path}"],
                              env=self.env, capture_output=True)
        return done.stdout.decode("utf-8", "replace") if done.returncode == 0 else None

    def parents(self, commit: str) -> List[str]:
        return self.run("rev-list", "--parents", "-n", "1", commit).split()[1:]

    def tree(self, commit: str) -> str:
        return self.run("rev-parse", f"{commit}^{{tree}}")

    def files(self, base: str, head: str) -> List[Tuple[str, str]]:
        """(GitHub status, path) of each file changed from the merge base of ``base`` and ``head`` to ``head``."""
        fork = self.run("merge-base", base, head)
        out = self.run("diff", "--name-status", "--no-renames", "-z", fork, head, "--")
        fields = [f for f in out.split("\0") if f]
        return [(_STATUS.get(s[:1], "changed"), p) for s, p in zip(fields[0::2], fields[1::2])]

    def behind(self, head: str, base: str) -> int:
        return int(self.run("rev-list", "--count", f"{head}..{base}") or 0)

    def ancestor(self, older: str, newer: str) -> bool:
        return subprocess.run(["git", "--git-dir", str(self.repo), "merge-base", "--is-ancestor", older, newer],
                              env=self.env, capture_output=True).returncode == 0


class _Report:
    def __init__(self) -> None:
        self.steps: List[dict] = []

    def add(self, step: str, result: str, detail: str) -> None:
        self.steps.append({"step": step, "result": result, "detail": detail})


# ---------------------------------------------------------------------------------------------------- the sandbox

def network_reachable(prefix: Sequence[str]) -> bool:
    """Whether a process started with ``prefix`` reaches any public address in ``PROBES``."""
    try:
        done = subprocess.run([*prefix, sys.executable, "-I", "-c", _PROBE.format(probes=PROBES)],
                              capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return True  # it could not be shown to be cut off
    return done.returncode == 0


def sandbox(mode: str, work: Path, keep_home: bool = False,
            probe: Callable[[Sequence[str]], bool] = network_reachable) -> Tuple[Optional[List[str]], str]:
    """``(prefix, description)`` for running a check with no network, or ``(None, why there is none)``. ``unshare``:
    a private network namespace (no interface but a loopback that is down) and mount namespace, the account
    unprivileged outside it, its home hidden under an empty tmpfs unless ``keep_home``. ``offline``: this machine has no
    network at all (a container started with ``--network none``, a disconnected VM). Either is probed: a sandbox that
    reaches the network is refused."""
    if mode not in SANDBOXES:
        raise EvidenceError(f"the sandbox must be one of {', '.join(SANDBOXES)}")
    home = os.environ.get("HOME", "")
    if mode in ("auto", "unshare"):
        hide = not keep_home and home and Path(home).is_dir() and Path(home).resolve() != Path("/")
        prefix = [*UNSHARE, "sh", "-c", _SETUP, "epap-sandbox", str(work.resolve()),
                  str(Path(home).resolve()) if hide else ""]
        try:
            usable = subprocess.run([*prefix, "true"], capture_output=True, timeout=30).returncode == 0
        except (OSError, subprocess.SubprocessError):
            usable = False
        if usable and not probe(prefix):
            return prefix, ("unshare: a network namespace of its own with no network but its own loopback (probed: "
                            "no public address reachable), a mount namespace, the replaying account unprivileged "
                            "outside them" + (", its home hidden under an empty tmpfs" if hide else ""))
        if mode == "unshare":
            return None, ("unshare cannot make a sandbox here (unprivileged user namespaces are not allowed, or the "
                          "namespace still reached the network)")
    if not probe([]):
        return [], "offline: this machine reaches no public address (probed), so nothing a check runs can either"
    return None, ("the network is reachable and no sandbox could be made: replay in a container started with "
                  "--network none, or on Linux with unprivileged user namespaces allowed, or pass --checks none")


# ---------------------------------------------------------------------------------------------------- the replay

def replay(pack: Path, work: Path, keys_path: Optional[Path] = None, checks: str = "last", sandbox_mode: str = "auto",
           keep_home: bool = False, timeout: float = CHECK_TIMEOUT, environ: Optional[Mapping[str, str]] = None,
           probe: Callable[[Sequence[str]], bool] = network_reachable, now: Optional[str] = None) -> dict:
    """Replay the pack in ``pack`` in ``work`` (a new directory) and return the report, also written there as
    ``replay-report.json`` and ``replay-report.md``."""
    pack, work = Path(pack), Path(work)
    if checks not in CHECKS:
        raise EvidenceError(f"--checks must be one of {', '.join(CHECKS)}")
    if work.exists():
        raise EvidenceError(f"{work} exists; a replay works in a new directory")
    try:
        manifest = json.loads((pack / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise EvidenceError(f"{pack} is not an evidence pack: manifest.json: {exc}") from None
    if not isinstance(manifest, dict) or manifest.get("schema") != summon.SCHEMA:
        raise EvidenceError(f"{pack}/manifest.json is not {summon.SCHEMA}")
    work.mkdir(parents=True)
    environ = dict(os.environ if environ is None else environ)
    r = _Report()
    report = {"schema": SCHEMA, "replayed_at": now or datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"), "pack": {k: manifest.get(k) for k in ("repository", "pr", "mission", "summoned_at",
                                                                    "summoned_by")},
              "tooling": _tooling(), "environment": _environment(), "sandbox": None, "steps": r.steps}
    _pack_files(pack, manifest, r)
    git = _unbundle(pack, manifest, work, r, environ)
    keys = _keys(pack, keys_path, git, manifest, r)
    chains = _chains(pack, keys, r) if keys else {}
    mission = manifest.get("mission")
    if keys:
        _attestations(pack, keys, chains, mission, r)
    if not mission:
        r.add("mission", NOT_REPLAYABLE, f"PR #{manifest.get('pr')} went outside the mission flow: no mission step "
                                         "was recorded, so there is nothing to replay beyond the pack itself")
    elif git is None or not keys:
        r.add("mission", NOT_REPLAYABLE, "without the git bundle and a pinned key the mission cannot be replayed")
    else:
        try:
            _mission(pack, manifest, mission, git, chains, work, r, environ, checks, sandbox_mode, keep_home,
                     timeout, probe, report)
        except EvidenceError as exc:
            r.add("mission", DIVERGED, f"the replay could not go on: {exc}")
    diverged = [s for s in r.steps if s["result"] == DIVERGED]
    report["result"] = ("DIVERGED" if diverged else "NOTHING TO REPLAY" if not mission else "REPRODUCED")
    report["first_divergence"] = diverged[0] if diverged else None
    report["not_replayable"] = [s for s in r.steps if s["result"] == NOT_REPLAYABLE]
    (work / "replay-report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (work / "replay-report.md").write_text(text(report), encoding="utf-8")
    return report


def _tooling() -> str:
    here = Path(__file__).resolve().parent
    try:
        done = subprocess.run(["git", "-C", str(here), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        done = None
    commit = done.stdout.strip() if done is not None and done.returncode == 0 else ""
    return f"the replaying tooling at commit {commit}" if commit else "the replaying tooling (not in a git checkout)"


def _environment() -> str:
    try:
        git = subprocess.run(["git", "--version"], capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        git = "git unknown"
    return f"{platform.system()} {platform.machine()}; python {platform.python_version()}; " \
           + git.replace("git version ", "git ")


def _inside(pack: Path, rel: object) -> Optional[Path]:
    """``pack / rel`` when ``rel`` is a plain relative path inside the pack; None otherwise. The manifest is data from
    whoever handed the pack on, so none of its paths is followed out of the pack."""
    if not isinstance(rel, str) or not rel or rel.startswith("/") or "\\" in rel or "\0" in rel:
        return None
    parts = Path(rel).parts
    if ".." in parts or any(Path(pack, *parts[:i + 1]).is_symlink() for i in range(len(parts))):
        return None
    return Path(pack, *parts)


def _pack_files(pack: Path, manifest: Mapping, r: _Report) -> None:
    listed = manifest.get("files") or {}
    if not isinstance(listed, dict):
        listed = {}
    bad = [str(name) for name, digest in sorted(listed.items())
           if (where := _inside(pack, name)) is None or not where.is_file() or _sha256(where.read_bytes()) != digest]
    extra = sorted(p.relative_to(pack).as_posix() for p in pack.rglob("*")
                   if (p.is_file() or p.is_symlink()) and p.relative_to(pack).as_posix() not in listed
                   and p.relative_to(pack).as_posix() != "manifest.json")
    if bad or extra:
        r.add("pack files", DIVERGED, "; ".join(
            ([f"{len(bad)} file(s) do not match the manifest: {', '.join(bad[:10])}"] if bad else [])
            + ([f"{len(extra)} file(s) are not in the manifest: {', '.join(extra[:10])}"] if extra else [])))
    else:
        r.add("pack files", REPRODUCED, f"all {len(listed)} files match the SHA-256 the manifest gives them; nothing "
                                        "is added (the manifest is an index: what proves the evidence is the seals)")


def _unbundle(pack: Path, manifest: Mapping, work: Path, r: _Report, environ: Mapping[str, str]) -> Optional[_Git]:
    bundle = manifest.get("bundle") or {}
    path = pack / "repo.bundle"
    if not bundle.get("path") or not path.is_file():
        r.add("git", NOT_REPLAYABLE, "the pack holds no git bundle")
        return None
    repo = work / "repo.git"
    git = _Git(repo, environ)
    subprocess.run(["git", "init", "-q", "--bare", str(repo)], env=git.env, check=True, capture_output=True)
    try:
        git.run("bundle", "verify", str(path.resolve()))
        # Every commit by name: packs carry them as epap-pack branches; packs summoned before Amendment 063 under
        # refs/epap-pack/, which a plain clone does not fetch.
        git.run("fetch", "-q", "--no-tags", str(path.resolve()), f"+{summon.BUNDLE_REFS}*:refs/heads/epap-pack/*",
                "+refs/epap-pack/*:refs/heads/epap-pack/*")
    except EvidenceError as exc:
        r.add("git", DIVERGED, f"the bundle does not unbundle: {exc}")
        return None
    missing = [c for c in bundle.get("commits") or [] if git.commit(c) != c]
    if missing:
        r.add("git", DIVERGED, f"{len(missing)} commit(s) the pack names are not in its bundle: "
                               + ", ".join(c[:12] for c in missing[:10]))
        return git
    r.add("git", REPRODUCED, f"the bundle unbundles (git checks each object's id) and holds all "
                             f"{len(bundle.get('commits') or [])} commits the pack names, with their history"
          + (f"; {len(bundle['missing'])} named commit(s) were not in the repository when it was summoned"
             if bundle.get("missing") else ""))
    return git


def _keys_of(text: Optional[str], where: Path) -> Dict[str, str]:
    if text is None:
        return {}
    where.write_text(text, encoding="utf-8")
    try:
        return seal_mod.load_keys(where)
    except EvidenceError:
        return {}


def _keys(pack: Path, keys_path: Optional[Path], git: Optional[_Git], manifest: Mapping,
          r: _Report) -> Dict[str, str]:
    try:
        own = seal_mod.load_keys(pack / "evidence" / "key.json")
    except EvidenceError as exc:
        own = {}
        r.add("keys", DIVERGED, f"the pack's evidence/key.json cannot be read: {exc}")
    if keys_path is not None:
        trusted = seal_mod.load_keys(Path(keys_path))  # the auditor's own pin; a bad one is an error, not a result
        source = f"the auditor's own pin ({Path(keys_path).name})"
    elif git is not None:
        trusted = {}
        scratch = git.repo.parent / "key-pin.json"
        for commit in (manifest.get("bundle") or {}).get("commits") or []:
            trusted.update(_keys_of(git.show(commit, KEY_PIN), scratch))
        source = f"the keys the repository pins in {KEY_PIN} at the pack's commits"
    else:
        trusted = {}
        source = ""
    if not trusted:
        if own:
            r.add("keys", NOT_REPLAYABLE, "no key pin outside the pack could be read, so the seals are checked against "
                                          "the pack's own key.json only: pass --keys with a pin you hold yourself")
        return own
    unknown = sorted(set(own) - set(trusted))
    if unknown:
        r.add("keys", DIVERGED, f"the pack's key.json holds {len(unknown)} key(s) that {source} does not: "
                                + ", ".join(k[:16] for k in unknown))
    elif own:
        r.add("keys", REPRODUCED, f"the seals are checked against {source} ({len(trusted)} key(s)); the pack's "
                                  "key.json holds none other")
    return trusted


def _chains(pack: Path, keys: Mapping[str, str], r: _Report) -> Dict[str, List[dict]]:
    """Every sealed chain that verifies, by name; the others are named and none of their records is a fact."""
    base = pack / "evidence" / verify.RUNS
    sealed: Dict[str, List[dict]] = {}
    unsealed, refused = [], []
    for run_dir in sorted(p for p in base.iterdir() if p.is_dir()) if base.is_dir() else []:
        try:
            records, ok = verify.verify_run(run_dir, run_dir.name, keys)
        except verify.Refused as exc:
            refused.append(str(exc))
            continue
        if ok:
            sealed[run_dir.name] = records
        else:
            unsealed.append(run_dir.name)
    count = sum(len(v) for v in sealed.values())
    if refused:
        r.add("chains", DIVERGED, f"{len(refused)} chain(s) do not verify: " + "; ".join(refused[:5]))
    if sealed:
        r.add("chains", REPRODUCED, f"{len(sealed)} chain(s), {count} records: each record's link to the one before "
                                    "and each seal's signature verify")
    if unsealed:
        r.add("chains", NOT_REPLAYABLE, f"{len(unsealed)} chain(s) carry no seal, so none of their records is used: "
                                        + ", ".join(unsealed[:10]))
    return sealed


def _attestations(pack: Path, keys: Mapping[str, str], chains: Mapping[str, List[dict]], mission: Optional[str],
                  r: _Report) -> None:
    """This mission's landing attestations. One of another mission (a pack summoned before Amendment 062 could carry
    one, as a router chain holds several missions' records) cites chains the pack does not hold: it is named, not
    checked."""
    folder = pack / "evidence" / pack_mod.PACKS
    found = sorted(folder.glob(f"*{pack_mod.SUFFIX}")) if folder.is_dir() else []
    if not found:
        return
    by_id = {rec["id"]: rec for rs in chains.values() for rec in rs}
    index = {rid: rec_mod.digest(rec) for rid, rec in by_id.items()}
    withdrawn = {rec["withdraws"]["id"] for rec in by_id.values() if rec["class"] == "withdraw"}
    own, other, gone = [], [], []
    for path in found:
        lid = pack_mod.landing_of(path.read_bytes()) or ""
        landing = by_id.get(lid)
        (gone if lid in withdrawn else own if landing is None or landing["subject"]["mission"] == mission
         else other).append(path)
    problems = [p for path in own for p in pack_mod.problems(path.read_bytes(), keys, index, path.name)]
    if problems:
        r.add("attestations", DIVERGED, "; ".join(problems[:5]))
    elif own:
        r.add("attestations", REPRODUCED, f"{len(own)} landing attestation(s) of this mission: each signature verifies "
                                          "and each cites the records exactly as sealed")
    if gone:
        r.add("attestations", REPRODUCED, f"{len(gone)} attestation(s) of a landing HITL withdrew (GitHub refused "
                                          "that landing, Amendment 055) are not counted: "
                                          + ", ".join(p.name for p in gone))
    if other:
        r.add("attestations", NOT_REPLAYABLE, f"{len(other)} attestation(s) of other missions are in the pack (a "
                                              "router chain holds several missions' records); the records they cite "
                                              "are not, so they are not checked: " + ", ".join(p.name for p in other))


# ---------------------------------------------------------------------------------------------------- the mission

def _mission(pack: Path, manifest: Mapping, mission: str, git: _Git, chains: Mapping[str, List[dict]], work: Path,
             r: _Report, environ: Mapping[str, str], checks: str, sandbox_mode: str, keep_home: bool,
             timeout: float, probe, report: dict) -> None:
    records = sorted((rec for rs in chains.values() for rec in rs), key=lambda x: (x["time"], x["id"]))
    withdrawn = {rec["withdraws"]["id"] for rec in records if rec["class"] == "withdraw"}
    live = {n: [rec for rec in rs if rec["id"] not in withdrawn] for n, rs in chains.items()}
    by_id = {rec["id"]: rec for rs in live.values() for rec in rs}
    lanes = {n: rs for n, rs in live.items() if (m := summon._LANE.fullmatch(n)) and m.group(4) == mission}
    stages = summon._stages(lanes)
    mine = [rec for rs in live.values() for rec in rs if rec["subject"]["mission"] == mission]
    approvals = summon._approvals(sorted(mine, key=lambda x: (x["time"], x["id"])))
    merges = summon._merges({n: rs for n, rs in live.items()}, mission)
    starts = [m.group(2) for rec in mine if rec["action"] == "router.branch" and rec["result"] == "done"
              and (m := _BRANCH.search(rec["reason"])) and m.group(1) == mission]
    gone = withdrawn & {rec["id"] for rec in records}
    if gone:
        r.add("withdrawals", REPRODUCED, f"{len(gone)} record(s) HITL withdrew are left out of every step below")
    commits = list((manifest.get("bundle") or {}).get("commits") or [])
    snapshot = _github(pack, manifest)
    plan = _authority(git, mission, approvals, merges, starts, snapshot, r)
    built = []
    for index, s in enumerate(stages):
        entry = _stage(pack, manifest, git, work, index, s, plan, mission, commits, r, environ)
        if entry:
            built.append(entry)
    if plan is not None:
        history = _router(git, mission, plan, merges, built, by_id, snapshot, r)
        if history is not None:
            _rebuild(git, work, mission, plan, history, r)
        if checks != "none":
            _checks(git, work, mission, plan, built, checks, sandbox_mode, keep_home, timeout, probe, environ, r,
                    report, live, history)
    for b in built:
        r.add(f"{b['role']} round {b['round']}: the agent's work", OUTPUT_VERIFIED,
              f"{b['agent'] or 'the agent'} ({b['runtime'] or 'runtime not named'}) made PR #{b['pr']}: an AI agent's run "
              "cannot be repeated byte for byte, so it is not; what it produced is proven above to be exactly what "
              "was sealed and published, and the gates accept it")


def _github(pack: Path, manifest: Mapping) -> Dict[int, dict]:
    """GitHub's word on each PR at summon time (unsealed), reduced to the fields a replay reads, each of its type."""
    out: Dict[int, dict] = {}
    listed = manifest.get("github") if isinstance(manifest.get("github"), dict) else {}
    for n, rel in listed.items():
        where = _inside(pack, rel)
        try:
            number, raw = int(n), json.loads(where.read_text(encoding="utf-8")) if where is not None else None
        except (OSError, ValueError, TypeError):
            continue
        if not isinstance(raw, dict):
            continue
        base = raw.get("base") if isinstance(raw.get("base"), dict) else {}
        out[number] = {"user": raw.get("user") if isinstance(raw.get("user"), str) else "",
                       "merge_commit_sha": raw.get("merge_commit_sha") if isinstance(raw.get("merge_commit_sha"), str)
                       else None,
                       "base": {"ref": base.get("ref") if isinstance(base.get("ref"), str) else None}}
    return out


class _Plan:
    def __init__(self, **kw) -> None:
        self.__dict__.update(kw)


def _config(git: _Git, commit: str) -> dict:
    text = git.show(commit, CONFIG)
    try:
        data = json.loads(text) if text else None
    except ValueError:
        data = None
    if not isinstance(data, dict):
        raise EvidenceError(f"{CONFIG} cannot be read at {commit[:12]}")
    return data


def _identities(git: _Git, commit: str, config: Mapping) -> Dict[str, str]:
    """Agent -> App login, for agents ACTIVE with an account ID in the identity registry at ``commit``, as the
    router reads it (``MissionRouter.identities``)."""
    from mission_router.model import MissionInputError, parse_identity_accounts, parse_identity_registry
    text = git.show(commit, str(config.get("identity_registry") or ""))
    try:
        statuses, accounts = parse_identity_registry(text), parse_identity_accounts(text)
    except MissionInputError:
        return {}
    return {agent: login for agent, login in (config.get("agents") or {}).items()
            if statuses.get(agent) == "ACTIVE" and accounts.get(agent) is not None}


def _merge_commit(git: _Git, head: str, first_parent: Optional[str], hint: Optional[str] = None) -> Optional[str]:
    """The merge commit that brought ``head`` in: its second parent is ``head``, and its first ``first_parent`` when
    that is known. ``hint`` (GitHub's word) is taken only when git agrees."""
    if hint and git.commit(hint) == hint:
        parents = git.parents(hint)
        if len(parents) == 2 and parents[1] == head and (first_parent is None or parents[0] == first_parent):
            return hint
    out = git.run("rev-list", "--parents", "--all")
    found = [line.split()[0] for line in out.splitlines()
             if len(line.split()) == 3 and line.split()[2] == head
             and (first_parent is None or line.split()[1] == first_parent)]
    return found[0] if len(found) == 1 else None


def _authority(git: _Git, mission: str, approvals: List[dict], merges: List[dict], starts: List[str],
               snapshot: Mapping[int, dict], r: _Report) -> Optional[_Plan]:
    from mission_router.model import MissionInputError, manifest_path, parse_manifest
    plan_merges = [m for m in merges if m["round"] == 0 and m["kind"] == "merge"]
    if not plan_merges:
        r.add("authority", NOT_REPLAYABLE, "no sealed record shows the plan (A1) merged: the mission had not started")
        return None
    a1 = plan_merges[0]
    head, pr = a1["commit"], a1["pr"]
    if not starts:
        r.add("authority", DIVERGED, "no sealed record names the commit the integration branch was created at")
        return None
    start = starts[0]
    if git.commit(head) != head:
        r.add("authority", DIVERGED, f"the plan commit {head[:12]} the router merged is not in the bundle")
        return None
    config = _config(git, head)
    hitl = {str(x).casefold() for x in config.get("hitl_logins") or []}
    hitl_ids = set(config.get("hitl_account_ids") or [])
    by_hitl = [a for a in approvals if a["login"].casefold() in hitl and a["account_id"] in hitl_ids]
    others = [a for a in approvals if a not in by_hitl]
    approved = {a["approved"] for a in by_hitl}
    for a in by_hitl:  # an approval carried to a later plan head (MISSION-ROUTER-001 Amendment 025)
        if a["carried_to"] and head.startswith(a["carried_to"]) and git.ancestor(a["approved"], head):
            approved.add(head)
    plan_pr = snapshot.get(pr) or {}
    merge = _merge_commit(git, head, start, plan_pr.get("merge_commit_sha"))
    if merge is None:
        r.add("authority", DIVERGED, f"no commit in the bundle merges the plan {head[:12]} onto the integration "
                                     f"branch's start {start[:12]}")
        return None
    try:
        manifest = parse_manifest(git.show(merge, manifest_path(mission)), mission)
    except MissionInputError as exc:
        r.add("authority", DIVERGED, f"the approved plan cannot be read at {merge[:12]}: {exc}")
        return None
    landing = manifest.branch or config.get("default_branch") or "main"
    plan = _Plan(head=head, pr=pr, merge=merge, start=start, config=config, hitl=hitl, approved=approved,
                 manifest=manifest, landing=landing, author=(plan_pr.get("user") or ""))
    who = ", ".join(sorted({f"{a['login']} (account {a['account_id']})" for a in by_hitl})) or "no HITL account"
    if head not in approved:
        r.add("authority", DIVERGED, f"the router merged the plan at {head[:12]} (PR #{pr}), which {who} did not "
                                     "approve" + (f"; approvals by accounts that are not HITL's are not counted: "
                                                  + ", ".join(a["login"] for a in others) if others else ""))
        return plan
    r.add("authority", REPRODUCED,
          f"{who}, HITL in {CONFIG} at {head[:12]}, approved the plan at that exact commit (sealed "
          f"router.hitl_command); the router merged exactly it as PR #{pr} (merge {merge[:12]}), where the approved "
          f"plan is read: \"{manifest.title}\", build_scope {list(manifest.build_scope)}, {len(manifest.checks)} "
          f"check(s), max_rounds {manifest.max_rounds}, landing on {landing}"
          + (f"; approvals by accounts that are not HITL's were not counted: "
             + ", ".join(a["login"] for a in others) if others else ""))
    return plan


def _stage(pack: Path, manifest: Mapping, git: _Git, work: Path, index: int, s: dict, plan: Optional[_Plan],
           mission: str, commits: Sequence[str], r: _Report, environ: Mapping[str, str]) -> Optional[dict]:
    """Rebuild one agent stage's PR from its sealed change with the dispatcher's own publish path, and run the
    dispatcher's gates on it again."""
    from mission_dispatch import dispatch
    from mission_dispatch.workspace import Checkout, GitError, git_env
    from mission_router.model import MissionInputError, manifest_path, parse_manifest, stage_branch
    from secrets_boundary import gate as boundary
    name = f"{s['role']} round {s['round']} ({s['run']})"
    collect, publish = s["collect"], s["publish"]
    if publish is None:
        r.add(name, NOT_REPLAYABLE, "this run collected a change but published no PR, so nothing of it reached "
                                    "a PR")
        return None
    if collect is None:
        r.add(name, DIVERGED, f"PR #{s['pr']} was published, but no sealed dispatch.collect record holds its change")
        return None
    base = collect["subject"]["commit"]
    sealed_patch = (collect.get("outputs") or {}).get(summon.PATCH)
    sealed_head = (publish.get("outputs") or {}).get("commit")
    heads = [c for c in commits if _sha256(c.encode()) == sealed_head]
    if not heads:
        r.add(name, DIVERGED, f"no commit in the bundle is the one the sealed dispatch.publish record names for "
                              f"PR #{s['pr']}")
        return None
    head = heads[0]
    stored = next((x for x in manifest.get("stages") or [] if (x["role"], x["round"], x["run"]) ==
                   (s["role"], s["round"], s["run"]) and x.get("change")), None)
    path = _inside(pack, stored["change"].get("path")) if stored else None
    patch = path.read_bytes() if path is not None and path.is_file() else \
        git.run(*summon.DIFF, base, head, "--", binary=True)
    if _sha256(patch) != sealed_patch:
        r.add(name, DIVERGED, f"the change in the pack is not the one sealed for PR #{s['pr']} (SHA-256 "
                              f"{_sha256(patch)[:16]}..., sealed {str(sealed_patch)[:16]}...)")
        return None
    if s["role"] == "AR":
        try:
            spec = parse_manifest(git.show(base, manifest_path(mission)), mission)
        except MissionInputError as exc:
            r.add(name, DIVERGED, f"the plan AR was handed cannot be read at {base[:12]}: {exc}")
            return None
    elif plan is None:
        r.add(name, DIVERGED, f"PR #{s['pr']} was published for a mission whose plan no sealed record shows merged")
        return None
    else:
        spec = plan.manifest
    role = spec.roles.get(s["role"])
    job = dispatch.Job(mission, s["role"], s["round"], role.agent if role else "", publish["actor"]["name"],
                       (role.runtime if role else "") or "", base, tuple(spec.build_scope), spec.title,
                       tuple(spec.checks), plan.landing if plan else "main")
    checkout = Checkout(work / "stages" / str(index))
    genv = git_env(environ)
    try:
        checkout.prepare(str(git.repo), stage_branch(mission, s["role"], s["round"]), base,
                         (IDENTITY["GIT_AUTHOR_NAME"], IDENTITY["GIT_AUTHOR_EMAIL"]), genv)
        text_patch = patch.decode("utf-8")
        if text_patch:
            checkout.apply(text_patch, genv)
        changes, modes = dispatch._staged(checkout, base, genv)
        tree = checkout._git("write-tree", env=genv).strip()
    except (GitError, UnicodeDecodeError) as exc:
        r.add(name, DIVERGED, f"the sealed change does not apply to {base[:12]} as the dispatcher applies it: {exc}")
        return None
    rebuilt = git.run("commit-tree", tree, "-p", base, stdin=b"epap replay\n")
    parents = git.parents(head)
    if tree != git.tree(head) or parents != [base]:
        r.add(name, DIVERGED, f"the sealed change applied to {base[:12]} does not rebuild PR #{s['pr']}'s head "
                              f"{head[:12]}" + ("" if parents == [base] else f" (its parent is not {base[:12]})"))
        return None
    message = git.run("log", "-1", "--format=%B", head)
    problems, verdict = dispatch.check_changes(job, checkout.tree, changes, modes, message)
    instruction = dispatch.instruction_files(job, changes)
    refused = []
    if instruction and (plan.config if plan else {}).get("quarantine") == "enforce":
        refused += instruction
    admitted = boundary.admit_output(dispatch.added_content(checkout, base, genv), {"message": message}, [])
    if not admitted.allow:
        refused.append(f"the secrets boundary refuses it ({admitted.reason})")
    if len(patch) > dispatch.PATCH_MAX_BYTES:
        refused.append(f"the change is larger than {dispatch.PATCH_MAX_BYTES} bytes")
    r.add(name, REPRODUCED, f"PR #{s['pr']}: its sealed change, applied by the dispatcher's own code to the commit the "
                            f"sealed dispatch.collect record names ({base[:12]}), rebuilds its head {head[:12]} tree "
                            "for tree, and that head is the commit the sealed dispatch.publish record names")
    gates = f"{name}: the dispatcher's gates"
    if problems or refused:
        r.add(gates, DIVERGED, "rerun on the rebuilt change, they refuse it: " + "; ".join(problems + refused))
    else:
        r.add(gates, REPRODUCED, f"rerun on the rebuilt change ({len(changes)} file(s)), they accept it"
              + (f": the {'verdict' if s['role'] == 'A3' else 'challenge'} is {verdict}" if verdict else "")
              + (f"; under observe they would list {len(instruction)} instruction file(s)" if instruction else "")
              + "; the secrets boundary's patterns find nothing (the run's own secret values are never in a pack)")
    return {"role": s["role"], "round": s["round"], "pr": s["pr"], "base": base, "head": head, "rebuilt": rebuilt,
            "verdict": verdict, "author": publish["actor"]["name"], "agent": job.agent, "runtime": job.runtime,
            "run": s["run"], "checks": s["checks"], "spec": spec}


def _router(git: _Git, mission: str, plan: _Plan, merges: List[dict], built: List[dict], by_id: Mapping[str, dict],
            snapshot: Mapping[int, dict], r: _Report) -> Optional[List[dict]]:
    """The router's own gate and state machine, on the sealed facts: each PR it merged is decided again, and the
    mission's state is derived again from the merges."""
    from mission_dispatch import dispatch
    from mission_router import gate
    from mission_router.model import MissionInputError, StageRef, integration_branch, parse_verdict, verdict_path
    from mission_router.state import DONE, HALTED, MergedStage, derive_state
    stages = {b["pr"]: b for b in built}
    bot = str(plan.config.get("bot_login") or "")
    trusted = plan.hitl | {bot.casefold()}
    landing = plan.landing
    merged: List[MergedStage] = []
    history: List[dict] = []
    state = derive_state(mission, (), plan.manifest, trusted, landing)
    refuse = plan.config.get("quarantine") == "enforce"
    for m in merges:
        if m["kind"] not in ("merge", "landing"):
            continue
        b = stages.get(m["pr"])
        if b is not None and b["role"] == "AR":
            ok = git.ancestor(b["head"], plan.head)
            r.add(f"router: PR #{m['pr']} (AR round {b['round']})", REPRODUCED if ok else DIVERGED,
                  f"AR's challenge was merged into the plan branch, and the plan HITL approved "
                  + ("carries it" if ok else f"({plan.head[:12]}) does not contain it"))
            continue
        if m["pr"] == plan.pr and m["round"] == 0:
            ref, head, author = StageRef(mission, "A1", 0), plan.head, plan.author
        elif b is not None:
            ref, head, author = StageRef(mission, b["role"], b["round"]), b["head"], b["author"]
        else:
            r.add(f"router: PR #{m['pr']}", DIVERGED, f"the router merged PR #{m['pr']}, which no sealed stage "
                                                     "record published")
            return None
        if head != m["commit"]:
            r.add(f"router: PR #{m['pr']}", DIVERGED, f"the router merged PR #{m['pr']} at {m['commit'][:12]}, not "
                                                     f"at its published head {head[:12]}")
            return None
        name = f"router: PR #{m['pr']} ({ref.role}{'' if ref.role == 'A1' else f' round {ref.round}'})"
        verdict = verdict_error = None
        if ref.role == "A3":
            try:
                verdict = parse_verdict(git.show(head, verdict_path(mission, ref.round)), mission, ref.round)
            except MissionInputError as exc:
                verdict_error = str(exc)
        into_landing = m["kind"] == "landing"
        first = None if into_landing else (plan.start if ref.role == "A1" else state.integration_head)
        commit = _merge_commit(git, head, first, (snapshot.get(m["pr"]) or {}).get("merge_commit_sha"))
        if commit is None:
            r.add(name, DIVERGED, f"no commit in the bundle merges {head[:12]}"
                                  + (f" onto {first[:12]}, where the router had the integration branch" if first else ""))
            return None
        onto = git.parents(commit)[0]
        base_ref = landing if into_landing else integration_branch(mission)
        # As the router compares (MissionRouter.decide): A1 with the integration branch, A2 with the integration head
        # it expects, A3 with the head it handed A3; a PASS's promotion with the landing branch it merges onto.
        compare = plan.start if ref.role == "A1" else state.review_sha if ref.role == "A3" else state.integration_head
        if compare is None:
            r.add(name, DIVERGED, f"the router merged PR #{m['pr']} while the mission was {state.stage}, so it had no "
                                  "head to compare it with")
            return None
        if not author:
            r.add(name, NOT_REPLAYABLE, "who opened the plan's PR is GitHub's word, and the pack holds no GitHub "
                                        "snapshot of it")
        files = tuple(gate.FileChange(p, st) for st, p in git.files(compare, head))
        promotion = tuple(gate.FileChange(p, st) for st, p in git.files(onto, head)) if into_landing else ()
        identities = _identities(git, plan.head if ref.role == "A1" else onto, plan.config)
        github_base = ((snapshot.get(m["pr"]) or {}).get("base") or {}).get("ref") or base_ref
        pr = gate.OpenStagePR(number=m["pr"], ref=ref, head_sha=head, base_ref=github_base, author=author,
                              same_repo=True, draft=False, files=files, files_complete=True,
                              behind_by=git.behind(head, compare),
                              author_type="Bot" if author.endswith("[bot]") else "User", pushers=(author,),
                              head_pushed=True)
        rejects = []
        if ref.role == "A1" and plan.config.get("challenge") == "enforce" and "AR" not in plan.manifest.roles:
            rejects.append("under \"challenge\": \"enforce\" a plan assigns an AR seat (MISSION-DISPATCH-001 §3n item 1)")
        decision = gate.evaluate(pr, state, plan.manifest, dispatch.classify, plan.approved,
                                 plan.start if ref.role == "A1" else state.integration_head, verdict, verdict_error,
                                 promotion, True, landing, rejects, (), True, identities, hitl_logins=plan.hitl,
                                 refuse_instruction_files=refuse, plan_mergers={bot})
        if decision.action != gate.MERGE:
            r.add(name, DIVERGED, f"the router's gate, given the sealed facts, decides {decision.action}, not the "
                                  f"merge the router recorded: {decision.summary}")
            return None
        actor = (by_id.get(m["record"]) or {}).get("actor", {}).get("name", "")
        merged.append(MergedStage(ref, m["pr"], base_ref, actor, commit,
                                  verdict.verdict if verdict else None, verdict.reviewed_sha if verdict else None,
                                  head, m["time"], verdict.findings if verdict else ()))
        history.append({"pr": m["pr"], "role": ref.role, "round": ref.round, "head": head, "commit": commit,
                        "onto": onto, "rebuilt": b["rebuilt"] if b else head, "expected_onto": first,
                        "landing": into_landing})
        state = derive_state(mission, tuple(merged), plan.manifest, trusted, landing)
        r.add(name, REPRODUCED, f"the router's gate, rerun on the sealed facts, decides MERGE"
              + (f" ({decision.verdict})" if decision.verdict else "") + f", as the router did (merge {commit[:12]} "
              f"onto {base_ref}); the mission is then {state.stage}"
              + (f" round {state.round}" if state.stage not in (DONE, HALTED) else ""))
        if state.stage == HALTED:
            r.add("router: mission state", DIVERGED, f"the router's state machine halts: {state.reason}")
            return None
    detail = f"the router's state machine, replayed over the {len(merged)} sealed merge(s), ends {state.stage}"
    if state.stage == DONE:
        detail += f": landed on {landing} as {state.landed_sha[:12]}"
    r.add("router: mission state", REPRODUCED, detail + " (who could push to each branch is the sealed publish "
                                                       "record's agent; the integration branch is taken to be where "
                                                       "the router recorded it, as its sealed merges show)")
    return history


def _rebuild(git: _Git, work: Path, mission: str, plan: _Plan, history: List[dict], r: _Report) -> None:
    """Every recorded merge made again, from the integration branch's start, the plan and the rebuilt changes."""
    tree_dir = work / "rebuild"
    git.run("worktree", "add", "-q", "--detach", str(tree_dir), plan.start)
    landed = None
    for h in history:
        if h["expected_onto"] and h["onto"] != h["expected_onto"]:
            r.add("result", DIVERGED, f"PR #{h['pr']} was merged onto {h['onto'][:12]}, not the integration head "
                                      f"{h['expected_onto'][:12]} the router had")
            return
        git.run("checkout", "-q", "--detach", h["onto"], cwd=tree_dir)
        done = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-C", str(tree_dir), "merge", "-q", "--no-ff",
                               "--no-edit", "-m", f"epap replay: PR #{h['pr']}", h["rebuilt"]], env=git.env,
                              capture_output=True, text=True)
        if done.returncode != 0:
            r.add("result", DIVERGED, f"merging the rebuilt PR #{h['pr']} onto {h['onto'][:12]} conflicts: "
                                      + " ".join((done.stdout + done.stderr).split())[-300:])
            return
        if git.run("rev-parse", "HEAD^{tree}", cwd=tree_dir) != git.tree(h["commit"]):
            r.add("result", DIVERGED, f"merging the rebuilt PR #{h['pr']} onto {h['onto'][:12]} does not give the "
                                      f"recorded merge {h['commit'][:12]}'s tree")
            return
        if h["landing"]:
            landed = h
    what = f"; the landed commit {landed['commit'][:12]} on {plan.landing} is rebuilt tree for tree" if landed else ""
    r.add("result", REPRODUCED, f"from the integration branch's start {plan.start[:12]}, HITL's plan and the rebuilt "
                                f"changes, each of the {len(history)} recorded merge(s) is made again and gives the "
                                f"recorded merge's tree{what}")


# ---------------------------------------------------------------------------------------------------- the checks

def _check_records(records: Sequence[dict]) -> Tuple[Dict[int, dict], Dict[int, dict], Optional[str]]:
    plain, landing, env = {}, {}, None
    for rec in records:
        if rec["action"] == "checks.environment":
            env = rec["reason"]
            continue
        m = _CHECK.fullmatch(rec["reason"])
        if m:
            plain[int(m.group(1))] = rec
            continue
        m = _LANDING.fullmatch(rec["reason"])
        if m:
            landing[int(m.group(1))] = {**rec, "_branch": m.group(2), "_head": m.group(3)}
    return plain, landing, env


def _checks(git: _Git, work: Path, mission: str, plan: _Plan, built: List[dict], which: str, sandbox_mode: str,
            keep_home: bool, timeout: float, probe, environ: Mapping[str, str], r: _Report, report: dict,
            live: Mapping[str, List[dict]], history: Optional[List[dict]]) -> None:
    """The plan's checks on the commit A3 reviewed, and the landing checks on it merged onto the landing branch's head
    they ran on, rerun in a sandbox and compared with each sealed ``checks.check`` record. A review whose results were
    not recorded (before Amendment 060) is rerun too, and said to have nothing to compare with; its landing checks are
    then run on the commit that landed."""
    from evidence.producer import text_digest
    reviews = [b for b in built if b["role"] == "A3"]
    if not reviews:
        r.add("checks", NOT_REPLAYABLE, "no A3 stage was published, so no commit was reviewed with checks")
        return
    prefix, how = sandbox(sandbox_mode, work, keep_home, probe)
    report["sandbox"] = how
    if prefix is None:
        r.add("checks", NOT_REPLAYABLE, f"the checks run the repository's own code, and they are run only in a "
                                        f"sandbox with no network: {how}")
        return
    landed = {h["pr"]: h for h in history or [] if h["landing"]}
    for b in reviews if which == "all" else reviews[-1:]:
        lane = [rec for n, rs in live.items() if (m := summon._LANE.fullmatch(n)) and m.group(4) == mission
                and m.group(5) == "A3" and int(m.group(6)) == b["round"] and f"gh-{m.group(1)}-{m.group(2)}" == b["run"]
                for rec in rs if rec["action"] in ("checks.check", "checks.environment")]
        plain, landing, recorded_env = _check_records(lane)
        note = f" (the sealed results were recorded on: {recorded_env})" if recorded_env else ""
        # The dispatcher's checkout is a full clone: origin/<landing branch> is that branch's head when the checks
        # ran. It is the head the landing records name, or else the commit the mission landed onto.
        head = _landing_head(git, landing)
        head = head or (landed[b["pr"]]["onto"] if b["pr"] in landed else None)
        ref = f"refs/remotes/origin/{plan.landing}"
        if head:
            git.run("update-ref", ref, head)
        else:
            git.run("update-ref", "-d", ref, check=False)
        name = f"checks: A3 round {b['round']}"
        commands = list(plan.manifest.checks)
        if commands:
            tree = work / "checks" / f"r{b['round']}" / "tree"
            git.run("worktree", "add", "-q", "--detach", str(tree), b["base"])
            _run_and_compare(name, commands, tree, prefix, environ, timeout, work, plain, text_digest(b["base"]),
                             "commit", r, f"{b['base'][:12]}, the commit A3 reviewed", note)
        else:
            r.add(name, REPRODUCED, "the approved plan names no checks")
        _landing_checks(git, work, b, landing, landed.get(b["pr"]), prefix, environ, timeout, r, note)


def _landing_head(git: _Git, landing: Mapping[int, dict]) -> Optional[str]:
    """The landing branch's head the sealed landing check records name: the commit whose first 12 digits they quote
    and whose SHA-256 they hold."""
    from evidence.producer import text_digest
    if not landing:
        return None
    first = landing[min(landing)]
    found = git.commit(first["_head"]) if first["_head"] else None
    return found if found and text_digest(found) == (first.get("inputs") or {}).get("head") else None


def _landing_checks(git: _Git, work: Path, b: dict, landing: Mapping[int, dict], landed: Optional[dict], prefix,
                    environ, timeout, r: _Report, note: str) -> None:
    from evidence.producer import text_digest
    name = f"landing checks: A3 round {b['round']}"
    tree = work / "checks" / f"r{b['round']}" / "landing"
    if not landing:
        if landed is None:
            r.add(name, NOT_REPLAYABLE, "no sealed landing check result for this review (they were recorded from "
                                        "MISSION-DISPATCH-001 Amendment 060 on), and it did not land")
            return
        commands = [c for c in _config(git, landed["onto"]).get("landing_checks") or [] if isinstance(c, str)]
        if not commands:
            r.add(name, REPRODUCED, f"{CONFIG} named no landing checks on {landed['onto'][:12]}, where the mission "
                                    "landed, so none ran")
            return
        git.run("worktree", "add", "-q", "--detach", str(tree), landed["commit"])
        _run_and_compare(name, commands, tree, prefix, environ, timeout, work, {}, "", "head", r,
                         f"{landed['commit'][:12]}, the commit that landed", note)
        return
    first = landing[min(landing)]
    found = _landing_head(git, landing)
    if found is None:
        r.add(name, NOT_REPLAYABLE, f"the landing branch's head the checks ran on ({first['_head']}) is not in the "
                                    "pack's bundle")
        return
    commands = [c for c in _config(git, found).get("landing_checks") or [] if isinstance(c, str)]
    git.run("worktree", "add", "-q", "--detach", str(tree), b["base"])
    done = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-C", str(tree), "merge", "-q", "--no-ff",
                           "--no-edit", "-m", f"landing checks: merge {first['_branch']}", found], env=git.env,
                          capture_output=True, text=True)
    if done.returncode != 0:
        r.add(name, DIVERGED, f"{b['base'][:12]} does not merge onto {first['_branch']} at {found[:12]} here, though "
                              "the landing checks were recorded as run on that merge")
        return
    _run_and_compare(name, commands, tree, prefix, environ, timeout, work, landing, text_digest(found), "head", r,
                     f"{b['base'][:12]} merged onto {first['_branch']} at {found[:12]}", note)


def _run_and_compare(name: str, commands: Sequence[str], tree: Path, prefix: Sequence[str],
                     environ: Mapping[str, str], timeout: float, work: Path, recorded: Mapping[int, dict],
                     where_digest: str, where_key: str, r: _Report, where: str, note: str) -> None:
    """Run each command in ``tree`` as the dispatcher runs a check (``dispatch.check_argv``: capped, a clean
    environment), inside ``prefix`` (the sandbox), and compare its result with its sealed record, which must be for
    this very command (its SHA-256) at this very commit."""
    from evidence.producer import text_digest
    from mission_dispatch import dispatch
    env = {k: v for k, v in environ.items() if k in ("PATH", "HOME", "LANG", "LC_ALL", "TZ")}
    env.update(dispatch.CHECK_GIT_ENV)
    (work / "tmp").mkdir(exist_ok=True)
    env["TMPDIR"] = str((work / "tmp").resolve())
    path = env.get("PATH", "/usr/local/bin:/usr/bin:/bin")
    same, differ, alone = [], [], []
    for index, command in enumerate(commands, 1):
        rec = recorded.get(index)
        if rec is not None and ((rec.get("outputs") or {}).get("command") != text_digest(command)
                                or (rec.get("inputs") or {}).get(where_key) != where_digest):
            differ.append(f"{index}. the sealed result is for another command or commit than `{command}` at {where}")
            continue
        try:
            done = subprocess.run([*prefix, *dispatch.check_argv(command, None, path)], cwd=str(tree), env=env,
                                  stdin=subprocess.DEVNULL, capture_output=True, text=True, errors="replace",
                                  timeout=timeout)
            code, output = done.returncode, (done.stdout or "") + (done.stderr or "")
        except subprocess.TimeoutExpired:
            code, output = None, f"timed out after {int(timeout)} seconds"
        tail = " ".join(output.split())[-OUTPUT_CHARS:]
        if rec is None:
            alone.append(f"{index}. `{command}`: exit {code}" + ("" if code == 0 else f"; last output: {tail}"))
            continue
        passed, was = code == 0, rec["result"] == "done"
        line = f"{index}. `{command}`: exit {code}, sealed {rec['reason'].rsplit('exit ', 1)[-1]}"
        (same if passed == was else differ).append(line + ("" if passed == was else
                                                          f"; last output here: {tail}"))
    alone_text = ("rerun here, with nothing sealed to compare them with (check results were recorded from "
                  "MISSION-DISPATCH-001 Amendment 060 on): " + "; ".join(alone)) if alone else ""
    if differ:
        r.add(name, DIVERGED, f"rerun at {where} with no network, they do not give the sealed results: "
              + "; ".join(differ) + (f"; {alone_text}" if alone_text else "") + note)
    elif same:
        r.add(name, REPRODUCED, f"rerun at {where} with no network, each gives the result sealed for it: "
              + "; ".join(same) + (f"; {alone_text}" if alone_text else "") + note)
    else:
        r.add(name, NOT_REPLAYABLE, f"at {where}, {alone_text}")


# ---------------------------------------------------------------------------------------------------- the report

def text(report: Mapping) -> str:
    pack = report["pack"]
    lines = [f"# EPAP replay: {pack.get('repository')} PR #{pack.get('pr')}", "",
             f"**{report['result']}**. Mission {pack.get('mission') or 'none'}; pack summoned {pack.get('summoned_at')}"
             + (f" by {pack['summoned_by']}" if pack.get("summoned_by") else "") + f"; replayed {report['replayed_at']} "
             f"with {report['tooling']} on {report['environment']}.", ""]
    if report.get("first_divergence"):
        d = report["first_divergence"]
        lines += [f"First divergence: **{d['step']}**: {d['detail']}", ""]
    if report.get("sandbox"):
        lines += [f"Sandbox: {report['sandbox']}.", ""]
    lines += ["## Steps", ""]
    lines += [f"- **{s['step']}**: {s['result']}. {s['detail']}" for s in report["steps"]]
    lines += ["", "`reproduced`: done again here from the pack alone, with the same result as sealed. `diverged`: done "
              "again, with a different result. `not replayable`: the pack does not hold what it would take, and why. "
              "`output verified, not re-generated`: an AI agent's own work, proven to be exactly what was sealed and "
              "published, not repeated.", ""]
    return "\n".join(lines)
