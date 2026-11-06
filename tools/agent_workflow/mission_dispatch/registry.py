"""A runtime's package against its registry's signature (ring 4, MISSION-DISPATCH-001 §3l item 2, Amendment 018).

The SHA-256 pin fixes the bytes; this checks that those bytes are what the registry published under the package's
name and version, so a wrong value typed into a pin change is caught. For an npm package (Claude Code):

1. the version's record is read from the registry: ``https://registry.npmjs.org/<package>/<version>``;
2. its ``name`` and ``version`` must be the pinned ones;
3. the downloaded package must match its ``dist.integrity`` (``sha512-<base64>``);
4. one of its ``dist.signatures`` must carry the pinned key id, and verify, with ``openssl``, as the pinned key's ECDSA
   P-256 signature over ``<name>@<version>:<integrity>``.

The key comes from ``credentials_check/pins.json``, never from the registry, so a compromised registry endpoint cannot
supply a key of its own. Standard library plus the runner's ``openssl``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from typing import Callable, Dict, Mapping, Tuple

REGISTRY = "https://registry.npmjs.org"
FETCH_TIMEOUT = 30
MAX_RECORD_BYTES = 4 * 1024 * 1024

Fetch = Callable[[str], bytes]


class RegistryError(RuntimeError):
    """The package does not verify against its registry's signature."""


def _fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=FETCH_TIMEOUT) as reply:  # https only: the URL is built here
        return reply.read(MAX_RECORD_BYTES + 1)


def version_record(package: str, version: str, fetch: Fetch = _fetch) -> dict:
    raw = fetch(f"{REGISTRY}/{package}/{version}")
    if len(raw) > MAX_RECORD_BYTES:
        raise RegistryError("the registry's version record is too large")
    try:
        doc = json.loads(raw)
    except ValueError:
        raise RegistryError("the registry's version record is not JSON") from None
    if not isinstance(doc, dict):
        raise RegistryError("the registry's version record is not an object")
    return doc


def openssl_verify(public_key_der: bytes, signature_der: bytes, message: bytes, openssl: str = "openssl") -> bool:
    with tempfile.TemporaryDirectory(prefix="registry-check-") as tmp:
        d = Path(tmp)
        (d / "key.der").write_bytes(public_key_der)
        (d / "sig.der").write_bytes(signature_der)
        (d / "msg").write_bytes(message)
        done = subprocess.run([openssl, "dgst", "-sha256", "-verify", str(d / "key.der"), "-keyform", "DER",
                               "-signature", str(d / "sig.der"), str(d / "msg")],
                              capture_output=True, text=True, timeout=30)
    return done.returncode == 0 and "Verified OK" in done.stdout


def verify(package_file: Path, row: Mapping, fetch: Fetch = _fetch,
           check: Callable[[bytes, bytes, bytes], bool] = openssl_verify) -> Dict[str, str]:
    """Check ``package_file`` (a runtime ``row`` of pins.json) against its registry; raises RegistryError."""
    registry = row.get("registry")
    if not registry:
        raise RegistryError("the runtime has no registry signature to check (its row's registry is null)")
    package, version = registry["package"], row["version"]
    doc = version_record(package, version, fetch)
    if doc.get("name") != package or doc.get("version") != version:
        raise RegistryError(f"the registry's record is for {doc.get('name')}@{doc.get('version')}, "
                            f"not {package}@{version}")
    dist = doc.get("dist") if isinstance(doc.get("dist"), dict) else {}
    integrity = dist.get("integrity", "")
    algo, _, want = integrity.partition("-") if isinstance(integrity, str) else ("", "", "")
    if algo not in ("sha512", "sha384", "sha256") or not want:
        raise RegistryError("the registry's record has no usable dist.integrity")
    got = base64.b64encode(hashlib.new(algo, package_file.read_bytes()).digest()).decode("ascii")
    if got != want:
        raise RegistryError(f"the package does not match the registry's dist.integrity ({algo})")
    signatures = [s for s in dist.get("signatures") or [] if isinstance(s, dict) and s.get("keyid") == registry["keyid"]]
    if not signatures:
        raise RegistryError(f"the registry's record carries no signature by the pinned key {registry['keyid']}")
    message = f"{package}@{version}:{integrity}".encode("utf-8")
    key = base64.b64decode(registry["key"])
    for signature in signatures:
        try:
            if check(key, base64.b64decode(signature.get("sig", "")), message):
                return {"package": package, "version": version, "keyid": registry["keyid"], "integrity": algo}
        except (ValueError, OSError, subprocess.SubprocessError):
            continue
    raise RegistryError(f"no signature verifies against the pinned key {registry['keyid']}")


def pins_row(runtime: str, table_path: Path) -> Tuple[dict, dict]:
    from mission_dispatch import supply_chain
    table = supply_chain.read_pins(table_path)
    if runtime not in table["runtimes"]:
        raise RegistryError(f"no runtime {runtime!r} in the pins table")
    return table, table["runtimes"][runtime]
