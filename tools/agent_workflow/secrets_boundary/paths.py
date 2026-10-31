"""Credential paths of the agent-pipeline boundary: a path an agent may never read and a patch may never add.

``denied(path)`` names the rule a POSIX path (relative or absolute) falls under, or returns ``None``. Rules are
tried in ``RULES`` order and the first match wins. The final component is compared case-insensitively; the
components before it exactly.

``read_denials()`` gives the same rules, except ``proc``, as path globs relative to a checkout, for a runtime's
read-deny list.
"""

from __future__ import annotations

import posixpath
from typing import List, Optional, Tuple

ENV_FILE = "env-file"
SSH = "ssh"
KEY_FILE = "key-file"
NETRC = "netrc"
GIT_CREDENTIALS = "git-credentials"
CLOUD_CREDENTIALS = "cloud-credentials"
GH_CONFIG = "gh-config"
PACKAGE_AUTH = "package-auth"
PROC = "proc"

RULES = (ENV_FILE, SSH, KEY_FILE, NETRC, GIT_CREDENTIALS, CLOUD_CREDENTIALS, GH_CONFIG, PACKAGE_AUTH, PROC)

SSH_DIR = ".ssh"
SSH_KEY_PREFIXES = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")
KEY_SUFFIXES = (".pem", ".key", ".p12", ".pfx")
NETRC_NAMES = (".netrc", "_netrc")
CLOUD_DIRS = (".aws", ".azure", "gcloud")
PACKAGE_AUTH_NAMES = (".npmrc", ".pypirc")

READ_DENIALS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    (ENV_FILE, ("**/.env", "**/.env.*")),
    (SSH, ("**/.ssh/**",) + tuple(f"**/{prefix}*" for prefix in SSH_KEY_PREFIXES)),
    (KEY_FILE, tuple(f"**/*{suffix}" for suffix in KEY_SUFFIXES)),
    (NETRC, tuple(f"**/{name}" for name in NETRC_NAMES)),
    (GIT_CREDENTIALS, ("**/.git-credentials",)),
    (CLOUD_CREDENTIALS, tuple(f"**/{name}/**" for name in CLOUD_DIRS)),
    (GH_CONFIG, ("**/gh/hosts.yml",)),
    (PACKAGE_AUTH, tuple(f"**/{name}" for name in PACKAGE_AUTH_NAMES) + ("**/.docker/config.json",)),
)


def _components(path: str) -> List[str]:
    return [part for part in path.split("/") if part not in ("", ".")]


def _under_proc(path: str) -> bool:
    if not path.startswith("/"):
        return False
    for candidate in (path, posixpath.normpath(path)):
        parts = _components(candidate)
        if len(parts) > 1 and parts[0] == "proc":
            return True
    return False


def denied(path: str) -> Optional[str]:
    """The rule id of credential path ``path``, or None."""
    if not isinstance(path, str):
        raise TypeError("path must be a string")
    parts = _components(path)
    if not parts:
        return None
    parents, final = parts[:-1], parts[-1].lower()
    parent = parents[-1] if parents else None
    if final == ".env" or final.startswith(".env."):
        return ENV_FILE
    if SSH_DIR in parents or final == SSH_DIR or final.startswith(SSH_KEY_PREFIXES):
        return SSH
    if final.endswith(KEY_SUFFIXES):
        return KEY_FILE
    if final in NETRC_NAMES:
        return NETRC
    if final == ".git-credentials":
        return GIT_CREDENTIALS
    if any(name in parents for name in CLOUD_DIRS) or final in CLOUD_DIRS:
        return CLOUD_CREDENTIALS
    if parent == "gh" and final == "hosts.yml":
        return GH_CONFIG
    if final in PACKAGE_AUTH_NAMES or (parent == ".docker" and final == "config.json"):
        return PACKAGE_AUTH
    if _under_proc(path):
        return PROC
    return None


def read_denials() -> Tuple[str, ...]:
    """The denial rules as checkout-relative path globs, in ``RULES`` order (``proc`` has none)."""
    return tuple(glob for _, globs in READ_DENIALS for glob in globs)
