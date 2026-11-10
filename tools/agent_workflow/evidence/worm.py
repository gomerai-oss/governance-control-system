"""The WORM copy (§3m item 3; Amendment 020, the WORM part): a second copy of every sealed run in object storage whose
retention policy forbids deleting or replacing an object before it expires. Standard library only.

Provider: Google Cloud Storage with a bucket retention policy (``config.json`` ``evidence_worm``). The policy is first
set unlocked (it can still be removed by a project administrator: "governance" mode), then locked by HITL (it can only
be lengthened, by anyone: "compliance" mode, the write-once media of SEC 17a-4).

No credential is stored. A job asks GitHub for its OIDC token (``id-token: write``) and exchanges it at Google's
Security Token Service for a short-lived access token, through a Workload Identity Federation provider that trusts
this repository on the default branch only, and grants each workflow file one role on the bucket: the seal workflow
``roles/storage.objectCreator`` (create only), the checker ``roles/storage.objectViewer`` (read only).

An object is created with ``ifGenerationMatch=0``: Google refuses it when the object exists, so a copy is never
replaced. The writer cannot read, so a re-run that finds an object there reports it as present; the checker
compares every copy with the store, byte for byte, and checks its retention.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional

from evidence import EvidenceError

CONFIG_KEY = "evidence_worm"
FIELDS = frozenset({"provider", "bucket", "workload_identity_provider", "retention_years"})
_BUCKET = re.compile(r"[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]")
_PROVIDER = re.compile(r"projects/[0-9]+/locations/global/workloadIdentityPools/[a-z0-9-]{4,32}/providers/[a-z0-9-]{4,32}")
STS = "https://sts.googleapis.com/v1/token"
API = "https://storage.googleapis.com/storage/v1"
UPLOAD = "https://storage.googleapis.com/upload/storage/v1"
SCOPE = "https://www.googleapis.com/auth/devstorage.read_write"
YEAR_SECONDS = 365.25 * 24 * 3600
SLACK_SECONDS = 24 * 3600  # clocks and rounding: a retention a day short of the years is still accepted


def config(cfg: Mapping) -> Optional[dict]:
    """The WORM declaration, or None. Raises ``EvidenceError`` on a malformed one."""
    worm = cfg.get(CONFIG_KEY)
    if worm is None:
        return None
    if not (isinstance(worm, dict) and set(worm) == FIELDS and worm["provider"] == "gcs"
            and isinstance(worm["bucket"], str) and _BUCKET.fullmatch(worm["bucket"])
            and isinstance(worm["workload_identity_provider"], str)
            and _PROVIDER.fullmatch(worm["workload_identity_provider"])
            and isinstance(worm["retention_years"], int) and not isinstance(worm["retention_years"], bool)
            and worm["retention_years"] >= 1):
        raise EvidenceError(f"config {CONFIG_KEY} must be {{provider: gcs, bucket, workload_identity_provider: "
                            "projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>, "
                            "retention_years >= 1}")
    return dict(worm)


def _call(urlopen, req) -> bytes:
    try:
        with urlopen(req, timeout=60) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        raise _Status(exc.code, exc.read()[:300].decode("utf-8", "replace")) from None


class _Status(Exception):
    def __init__(self, status: int, text: str):
        super().__init__(f"HTTP {status}: {text}")
        self.status = status


def access_token(provider: str, environ: Mapping[str, str] = os.environ, urlopen: Callable = urllib.request.urlopen) -> str:
    """GitHub's OIDC token for this job, exchanged at Google's STS for a short-lived access token."""
    url, bearer = environ.get("ACTIONS_ID_TOKEN_REQUEST_URL"), environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not (url and bearer):
        raise EvidenceError("no GitHub OIDC token: the job needs permissions id-token: write")
    audience = f"https://iam.googleapis.com/{provider}"
    req = urllib.request.Request(f"{url}&audience={urllib.parse.quote(audience, safe='')}",
                                 headers={"Authorization": f"Bearer {bearer}"})
    try:
        oidc = json.loads(_call(urlopen, req))["value"]
        body = json.dumps({"grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
                           "audience": f"//iam.googleapis.com/{provider}", "scope": SCOPE,
                           "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
                           "subjectTokenType": "urn:ietf:params:oauth:token-type:jwt",
                           "subjectToken": oidc}).encode()
        req = urllib.request.Request(STS, data=body, method="POST", headers={"Content-Type": "application/json"})
        return json.loads(_call(urlopen, req))["access_token"]
    except (_Status, KeyError, ValueError) as exc:
        raise EvidenceError(f"the WORM token exchange failed: {str(exc)[:300]}") from None


class Bucket:
    """A GCS bucket through its JSON API with a short-lived bearer token."""

    def __init__(self, bucket: str, token: str, urlopen: Callable = urllib.request.urlopen):
        self.bucket, self.token, self.urlopen = bucket, token, urlopen

    def _req(self, url: str, data: Optional[bytes] = None, method: str = "GET", ctype: str = "") -> urllib.request.Request:
        headers = {"Authorization": f"Bearer {self.token}"}
        if ctype:
            headers["Content-Type"] = ctype
        return urllib.request.Request(url, data=data, method=method, headers=headers)

    def put(self, name: str, data: bytes) -> str:
        """``"added"``, or ``"present"`` when an object of that name exists (it is never replaced)."""
        url = (f"{UPLOAD}/b/{self.bucket}/o?uploadType=media&ifGenerationMatch=0"
               f"&name={urllib.parse.quote(name, safe='')}")
        try:
            _call(self.urlopen, self._req(url, data, "POST", "application/octet-stream"))
        except _Status as exc:
            if exc.status == 412:
                return "present"
            raise EvidenceError(f"the WORM bucket refused {name}: {exc}") from None
        return "added"

    def meta(self, name: str) -> Optional[dict]:
        try:
            return json.loads(_call(self.urlopen, self._req(f"{API}/b/{self.bucket}/o/{urllib.parse.quote(name, safe='')}")))
        except _Status as exc:
            if exc.status == 404:
                return None
            raise EvidenceError(f"the WORM bucket refused to show {name}: {exc}") from None

    def get(self, name: str) -> bytes:
        url = f"{API}/b/{self.bucket}/o/{urllib.parse.quote(name, safe='')}?alt=media"
        try:
            return _call(self.urlopen, self._req(url))
        except _Status as exc:
            raise EvidenceError(f"the WORM bucket refused to read {name}: {exc}") from None


def _when(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)


def check_copies(store: Path, bucket: Bucket, retention_years: int) -> List[str]:
    """For a clone of the store: every file under ``runs/`` has its copy in the bucket, byte-identical, retained for
    at least ``retention_years`` from when the copy was made. One line per problem."""
    problems: List[str] = []
    base = Path(store)
    for path in sorted((base / "runs").rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        name = path.relative_to(base).as_posix()
        meta = bucket.meta(name)
        if meta is None:
            problems.append(f"{name} has no WORM copy")
            continue
        data = path.read_bytes()
        md5 = base64.b64encode(hashlib.md5(data).digest()).decode()  # noqa: S324 - GCS's own content check
        if meta.get("md5Hash") != md5 or bucket.get(name) != data:
            problems.append(f"{name}: the WORM copy differs from the store")
            continue
        expiry = meta.get("retentionExpirationTime")
        if not expiry:
            problems.append(f"{name}: the WORM copy has no retention")
            continue
        held = (_when(expiry) - _when(meta["timeCreated"])).total_seconds()
        if held + SLACK_SECONDS < retention_years * YEAR_SECONDS:
            problems.append(f"{name}: the WORM copy is retained {held / YEAR_SECONDS:.2f} years, "
                            f"not {retention_years}")
    return problems


def from_config(cfg: Mapping, environ: Mapping[str, str] = os.environ,
                urlopen: Callable = urllib.request.urlopen) -> Optional[Bucket]:
    worm = config(cfg)
    if worm is None:
        return None
    return Bucket(worm["bucket"], access_token(worm["workload_identity_provider"], environ, urlopen), urlopen)
