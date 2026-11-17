"""Pinned tools and package trees (ring 4, MISSION-DISPATCH-001 §3l, Amendment 034; SECURITY-SCAN-SPEC-001 §3).

A runtime is one tarball (§3l item 2). The security scanner is not: ``@openai/codex-security`` pulls in a tree of
packages, the Codex runtime among them, and needs a newer Node than the runner has. HITL decided to pin the whole tree
(2026-11-16). ``pins.json`` therefore gains two sections:

``tools``  a tool fetched outside npm, each ``{"version", "sha256", "url", "provenance"}``; today ``node``.
``trees``  a package tree, each ``{"root", "version", "platform", "registry", "packages", "provenance"}``:
           ``registry`` is ``{"keys": {<keyid>: {"key", "expires"}}}``, the npm registry's public keys as it publishes
           them (``https://registry.npmjs.org/-/npm/v1/keys``), and ``packages`` lists every package of the tree for
           ``platform``, each ``{"path", "name", "version", "sha512", "keyid", "sig", "published"}``.

``sha512`` (the package's digest) and ``sig`` (the registry's DER signature) are written as decimal numbers, not
base64. The public GCS release scans every shipped line for internal names, and random base64 contains letters that
match them by chance (a pinned signature did); decimal digits cannot. The installer turns them back into npm's
own ``sha512-<base64>`` and DER bytes before it checks them.

npm rotated its signing key: the old one expired on 2025-01-29, and versions published before then carry only its
signature. As ``npm audit signatures`` does, a signature by a key with an ``expires`` counts only for a version
``published`` before that time; a key with ``expires`` null counts for every version.

Installing a tree (``install_tree``) never runs ``npm``, ``npx`` or any install script. For each package, in the
listed order, it:

1. builds the tarball's URL from the pinned name and version (``https://registry.npmjs.org/<name>/-/<base>-<version>.tgz``),
   never from data the registry returns;
2. checks the bytes against the pinned ``integrity`` (``sha512-<base64>``);
3. checks the pinned ``sig`` with ``openssl`` as the pinned ``keyid``'s ECDSA P-256 signature over
   ``<name>@<version>:<integrity>``, the registry's own message (``registry.py``), and that the key had not expired
   when the version was ``published``, so a pin typed wrong is caught;
4. unpacks the tarball's ``package/`` into ``<dest>/<path>``, refusing any entry that is not a regular file or a
   directory, any absolute name, and any name that would leave its folder.

A mismatch stops the install, and nothing it wrote is used. ``make_tree_pin`` builds a tree's pin from an npm
lockfile and the registry's records; a maintainer runs it, and HITL's hand merge of ``pins.json`` is the review.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import shutil
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Dict, List, Mapping, Optional

from mission_dispatch import registry as registry_mod

REGISTRY = registry_mod.REGISTRY
TOOL_FIELDS = frozenset({"version", "sha256", "url", "provenance"})
TREE_FIELDS = frozenset({"root", "version", "platform", "registry", "packages", "provenance"})
PACKAGE_FIELDS = frozenset({"path", "name", "version", "sha512", "keyid", "sig", "published"})
KEY_FIELDS = frozenset({"key", "expires"})
PROVENANCE_FIELDS = frozenset({"version", "checked", "how", "by"})
PLATFORMS = ("linux-x64",)
MAX_PACKAGES = 400
MAX_TARBALL_BYTES = 256 * 1024 * 1024  # the largest is the Codex runtime's native build
MAX_UNPACKED_BYTES = 1024 * 1024 * 1024

_NAME = re.compile(r"(?:@[a-z0-9][a-z0-9._-]{0,213}/)?[a-z0-9][a-z0-9._-]{0,213}")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]{1,64})?")
_PATH = re.compile(r"node_modules/(?:(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*/node_modules/)*"
                   r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*")
_INTEGRITY = re.compile(r"sha512-[A-Za-z0-9+/]{86}==")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_B64 = re.compile(r"[A-Za-z0-9+/]+={0,2}")
_DECIMAL = re.compile(r"[1-9][0-9]{0,400}")
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z")
_KEYID = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")

Fetch = Callable[[str], bytes]
Check = Callable[[bytes, bytes, bytes], bool]


class TreeError(ValueError):
    pass


def _provenance(value: Any, where: str) -> None:
    if not (isinstance(value, dict) and set(value) == PROVENANCE_FIELDS and all(isinstance(v, str) for v in value.values())):
        raise TreeError(f"{where}: provenance must be exactly {sorted(PROVENANCE_FIELDS)}, as text")


def check_tools(tools: Any) -> None:
    """``pins.json``'s ``tools`` section; raises ``TreeError``."""
    if not isinstance(tools, dict):
        raise TreeError("tools must be an object")
    for name, row in tools.items():
        where = f"tool {name!r}"
        if not (isinstance(name, str) and re.fullmatch(r"[a-z][a-z0-9-]{0,31}", name) and isinstance(row, dict)
                and set(row) == TOOL_FIELDS and isinstance(row["version"], str) and row["version"]
                and isinstance(row["sha256"], str) and _SHA256.fullmatch(row["sha256"])
                and isinstance(row["url"], str) and row["url"].startswith("https://")):
            raise TreeError(f"{where} must have exactly {sorted(TOOL_FIELDS)}: a version, a SHA-256 and an https URL")
        _provenance(row["provenance"], where)
        if row["provenance"]["version"] != row["version"]:
            raise TreeError(f"{where} is pinned at {row['version']!r} but its provenance is for "
                            f"{row['provenance']['version']!r}")


def check_trees(trees: Any) -> None:
    """``pins.json``'s ``trees`` section; raises ``TreeError``."""
    if not isinstance(trees, dict):
        raise TreeError("trees must be an object")
    for name, row in trees.items():
        where = f"tree {name!r}"
        if not (isinstance(name, str) and re.fullmatch(r"[a-z][a-z0-9-]{0,31}", name) and isinstance(row, dict)
                and set(row) == TREE_FIELDS):
            raise TreeError(f"{where} must have exactly {sorted(TREE_FIELDS)}")
        if not (isinstance(row["root"], str) and _NAME.fullmatch(row["root"]) and isinstance(row["version"], str)
                and _VERSION.fullmatch(row["version"]) and row["platform"] in PLATFORMS):
            raise TreeError(f"{where}: root must be a package name, version a version, platform one of {list(PLATFORMS)}")
        reg = row["registry"]
        keys = reg.get("keys") if isinstance(reg, dict) and set(reg) == {"keys"} else None
        if not (isinstance(keys, dict) and keys and all(
                isinstance(k, str) and _KEYID.fullmatch(k) and isinstance(v, dict) and set(v) == KEY_FIELDS
                and isinstance(v["key"], str) and _B64.fullmatch(v["key"])
                and (v["expires"] is None or (isinstance(v["expires"], str) and _TIME.fullmatch(v["expires"])))
                for k, v in keys.items())):
            raise TreeError(f"{where}: registry must be {{keys: {{<keyid>: {{key, expires}}}}}}, keys in base64")
        _provenance(row["provenance"], where)
        if row["provenance"]["version"] != row["version"]:
            raise TreeError(f"{where} is pinned at {row['version']!r} but its provenance is for "
                            f"{row['provenance']['version']!r}")
        packages = row["packages"]
        if not (isinstance(packages, list) and 0 < len(packages) <= MAX_PACKAGES):
            raise TreeError(f"{where}: packages must list 1 to {MAX_PACKAGES} packages")
        paths = set()
        for i, pkg in enumerate(packages):
            at = f"{where} package {i}"
            if not (isinstance(pkg, dict) and set(pkg) == PACKAGE_FIELDS):
                raise TreeError(f"{at} must have exactly {sorted(PACKAGE_FIELDS)}")
            if not (isinstance(pkg["path"], str) and _PATH.fullmatch(pkg["path"])
                    and isinstance(pkg["name"], str) and _NAME.fullmatch(pkg["name"])
                    and isinstance(pkg["version"], str) and _VERSION.fullmatch(pkg["version"])
                    and isinstance(pkg["sha512"], str) and _DECIMAL.fullmatch(pkg["sha512"])
                    and isinstance(pkg["sig"], str) and _DECIMAL.fullmatch(pkg["sig"])
                    and isinstance(pkg["published"], str) and _TIME.fullmatch(pkg["published"])):
                raise TreeError(f"{at}: path, name, version, sha512, sig or published is malformed")
            key = keys.get(pkg["keyid"])
            if key is None:
                raise TreeError(f"{at}: signed by {pkg['keyid']!r}, which the tree's registry keys do not hold")
            if key["expires"] is not None and pkg["published"] >= key["expires"]:
                raise TreeError(f"{at}: published {pkg['published']}, after its key expired ({key['expires']})")
            if pkg["path"] in paths:
                raise TreeError(f"{at}: {pkg['path']} is listed twice")
            paths.add(pkg["path"])
        root_path = f"node_modules/{row['root']}"
        if not any(p["path"] == root_path and p["name"] == row["root"] and p["version"] == row["version"]
                   for p in packages):
            raise TreeError(f"{where}: its root {row['root']}@{row['version']} is not in its packages")


def to_decimal(data: bytes) -> str:
    """Bytes as a decimal number; a leading zero byte is kept by a 1 in front (``from_decimal`` drops it)."""
    return str(int.from_bytes(b"\x01" + data, "big"))


def from_decimal(text: str) -> bytes:
    raw = int(text).to_bytes((int(text).bit_length() + 7) // 8, "big")
    if not raw or raw[0] != 1:
        raise TreeError("a decimal field is malformed")
    return raw[1:]


def integrity_of(pkg: Mapping) -> str:
    """npm's ``sha512-<base64>`` for a pinned package, from its decimal ``sha512``."""
    digest = from_decimal(pkg["sha512"])
    if len(digest) != 64:
        raise TreeError(f"{pkg.get('name')}: its sha512 is not 64 bytes")
    return "sha512-" + base64.b64encode(digest).decode("ascii")


def tarball_url(name: str, version: str) -> str:
    """The registry's tarball URL for ``name@version``, built from the pin alone."""
    base = name.rsplit("/", 1)[-1]
    return f"{REGISTRY}/{name}/-/{base}-{version}.tgz"


def _fetch(url: str) -> bytes:
    import urllib.request  # standard library; the job's own network, before the agent's account is closed off
    with urllib.request.urlopen(url, timeout=120) as reply:  # noqa: S310 - https only, URL built from the pin
        data = reply.read(MAX_TARBALL_BYTES + 1)
    if len(data) > MAX_TARBALL_BYTES:
        raise TreeError(f"{url} is larger than {MAX_TARBALL_BYTES} bytes")
    return data


def _integrity(data: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode("ascii")


def _safe_members(tar: tarfile.TarFile) -> List[tarfile.TarInfo]:
    members = []
    for member in tar.getmembers():
        name = PurePosixPath(member.name)
        if name.is_absolute() or ".." in name.parts or not name.parts or name.parts[0] != "package":
            raise TreeError(f"the tarball holds an entry outside package/: {member.name!r}")
        if not (member.isfile() or member.isdir()):
            raise TreeError(f"the tarball holds {member.name!r}, which is not a regular file or a directory")
        members.append(member)
    return members


def unpack(data: bytes, target: Path) -> int:
    """Unpack an npm tarball's ``package/`` into ``target``; returns the bytes written. Raises ``TreeError``."""
    try:
        tar = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise TreeError(f"the tarball cannot be read ({type(exc).__name__})") from None
    written = 0
    with tar:
        for member in _safe_members(tar):
            rel = PurePosixPath(*PurePosixPath(member.name).parts[1:])
            out = target.joinpath(*rel.parts) if rel.parts else target
            if member.isdir():
                out.mkdir(parents=True, exist_ok=True)
                continue
            written += member.size
            if written > MAX_UNPACKED_BYTES:
                raise TreeError(f"the tree unpacks to more than {MAX_UNPACKED_BYTES} bytes")
            out.parent.mkdir(parents=True, exist_ok=True)
            source = tar.extractfile(member)
            if source is None:
                raise TreeError(f"{member.name!r} cannot be read")
            with source, open(out, "wb") as dest:
                shutil.copyfileobj(source, dest)
            out.chmod(0o755 if member.mode & 0o111 else 0o644)
    return written


def install_tree(tree: Mapping, dest: Path, fetch: Fetch = _fetch, check: Check = registry_mod.openssl_verify,
                 log: Callable[[str], None] = lambda message: None) -> Dict[str, int]:
    """Install a checked ``trees`` row of ``pins.json`` into ``dest``; raises ``TreeError`` on any mismatch."""
    check_trees({"tree": dict(tree)})
    dest = Path(dest)
    if dest.exists() and any(dest.iterdir()):
        raise TreeError(f"{dest} is not empty")
    keys = tree["registry"]["keys"]
    total = 0
    for pkg in tree["packages"]:
        label = f"{pkg['name']}@{pkg['version']}"
        data = fetch(tarball_url(pkg["name"], pkg["version"]))
        integrity = integrity_of(pkg)
        if _integrity(data) != integrity:
            raise TreeError(f"{label} does not match its pinned integrity")
        message = f"{pkg['name']}@{pkg['version']}:{integrity}".encode("utf-8")
        try:
            signed = check(base64.b64decode(keys[pkg["keyid"]]["key"]), from_decimal(pkg["sig"]), message)
        except (ValueError, OSError) as exc:
            raise TreeError(f"{label}: its signature cannot be checked ({type(exc).__name__})") from None
        if not signed:
            raise TreeError(f"{label}: its pinned signature does not verify against the pinned registry key")
        total += unpack(data, dest.joinpath(*pkg["path"].split("/")))
    log(f"tree {tree['root']}@{tree['version']}: {len(tree['packages'])} packages, {total} bytes, every one checked")
    return {"packages": len(tree["packages"]), "bytes": total}


def _link_stays_inside(name: PurePosixPath, link: str, top: str) -> bool:
    """Whether a symbolic link at ``name`` pointing to ``link`` resolves inside the archive's ``top`` folder."""
    target = PurePosixPath(link)
    if target.is_absolute():
        return False
    parts: List[str] = list(name.parent.parts)
    for part in target.parts:
        if part == "..":
            if not parts:
                return False
            parts.pop()
        elif part != ".":
            parts.append(part)
    return bool(parts) and parts[0] == top


def install_tool(tool: Mapping, dest: Path, fetch: Fetch = _fetch) -> Path:
    """Fetch a ``tools`` row's archive and check its SHA-256, then unpack it into ``dest``. Returns the archive's one
    top folder. Every entry is checked first, independent of the Python version's own tar filter: its name stays
    inside the top folder, it is a regular file, a directory or a symbolic link that resolves inside the top folder,
    and never a hard link, a device or a FIFO."""
    check_tools({"tool": dict(tool)})
    data = fetch(tool["url"])
    if hashlib.sha256(data).hexdigest() != tool["sha256"]:
        raise TreeError(f"{tool['url']} does not match its pinned SHA-256")
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
            members = tar.getmembers()
            tops = {PurePosixPath(m.name).parts[0] for m in members if PurePosixPath(m.name).parts}
            if len(tops) != 1:
                raise TreeError("the archive does not have exactly one top folder")
            top = tops.pop()
            for member in members:
                name = PurePosixPath(member.name)
                if name.is_absolute() or ".." in name.parts or not name.parts or name.parts[0] != top:
                    raise TreeError(f"the archive holds {member.name!r}, outside its folder")
                if member.issym():
                    if not _link_stays_inside(name, member.linkname, top):
                        raise TreeError(f"the archive's link {member.name!r} points outside it")
                elif not (member.isfile() or member.isdir()):
                    raise TreeError(f"the archive holds {member.name!r}, which is not a file, folder or link")
            tar.extractall(dest, members=members, filter="tar")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise TreeError(f"the archive cannot be unpacked safely ({type(exc).__name__}: {exc})") from None
    return dest / top


def _published(name: str, version: str) -> str:
    """When the registry says ``name@version`` was published (its full record's ``time``)."""
    import urllib.request
    with urllib.request.urlopen(f"{REGISTRY}/{name}", timeout=60) as reply:  # noqa: S310 - the registry, https
        doc = json.loads(reply.read(64 * 1024 * 1024))
    when = (doc.get("time") or {}).get(version)
    if not isinstance(when, str) or not _TIME.fullmatch(when):
        raise TreeError(f"{name}@{version}: the registry gives no publish time")
    return when


def make_tree_pin(lockfile: Mapping, root: str, platform: str, keys: Mapping[str, Mapping], checked: str, by: str,
                  fetch_record: Callable[[str, str], Mapping] = registry_mod.version_record,
                  fetch_published: Callable[[str, str], str] = _published) -> dict:
    """A ``trees`` row from an npm lockfile (``npm install --package-lock-only --ignore-scripts``) and the registry's
    signature for each package. Packages for other platforms are left out. A maintainer runs this; the row is
    reviewed in the hand-merged ``pins.json`` change."""
    if platform != "linux-x64":
        raise TreeError(f"platform must be one of {list(PLATFORMS)}")
    packages = []
    for path, entry in sorted((lockfile.get("packages") or {}).items()):
        if not path:
            continue
        if entry.get("os") and "linux" not in entry["os"]:
            continue
        if entry.get("cpu") and "x64" not in entry["cpu"]:
            continue
        if entry.get("libc") and "glibc" not in entry["libc"]:
            continue
        if path.endswith("-musl"):  # a musl build left unlabelled by its publisher
            continue
        if entry.get("hasInstallScript"):
            raise TreeError(f"{path} has an install script, which this installer never runs")
        name = entry.get("name") or path.rsplit("node_modules/", 1)[-1]
        version, integrity = entry.get("version"), entry.get("integrity")
        record = fetch_record(name, version)
        dist = record.get("dist") if isinstance(record.get("dist"), dict) else {}
        if record.get("name") != name or record.get("version") != version or dist.get("integrity") != integrity:
            raise TreeError(f"{path}: the registry's record does not match the lockfile")
        sigs = sorted((s for s in dist.get("signatures") or [] if isinstance(s, dict) and s.get("keyid") in keys),
                      key=lambda s: keys[s["keyid"]]["expires"] is not None)  # an unexpiring key first
        if not sigs:
            raise TreeError(f"{path}: no registry signature by any of the keys {sorted(keys)}")
        if not (isinstance(integrity, str) and _INTEGRITY.fullmatch(integrity)):
            raise TreeError(f"{path}: its integrity is not sha512")
        packages.append({"path": path, "name": name, "version": version,
                         "sha512": to_decimal(base64.b64decode(integrity[len("sha512-"):])),
                         "keyid": sigs[0]["keyid"], "sig": to_decimal(base64.b64decode(sigs[0]["sig"])),
                         "published": fetch_published(name, version)})
    root_entry = (lockfile.get("packages") or {}).get(f"node_modules/{root}") or {}
    row = {"root": root, "version": root_entry.get("version", ""), "platform": platform,
           "registry": {"keys": {k: {"key": v["key"], "expires": v["expires"]} for k, v in keys.items()}},
           "packages": packages,
           "provenance": {"version": root_entry.get("version", ""), "checked": checked,
                          "how": "npm lockfile (scripts disabled) and each version's registry record and signature",
                          "by": by}}
    check_trees({"tree": row})
    return row
