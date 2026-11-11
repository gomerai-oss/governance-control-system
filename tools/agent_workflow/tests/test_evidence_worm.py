"""Ring 6, the WORM copy (MISSION-DISPATCH-001 §3m item 3; limit 29): every sealed run is also copied, write-once, to
a Google Cloud Storage bucket under a retention policy; no key is stored (GitHub OIDC -> Google STS); the checker
confirms each copy is there, identical, and retained. Against a fake GitHub OIDC endpoint, a fake STS and a fake
bucket that keeps Google's rules: no replacement (ifGenerationMatch=0), and the retention it was given."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tempfile
import unittest
import urllib.error
import urllib.parse
from pathlib import Path

from epap import ed25519
from evidence import EvidenceError, chain, checker, producer, seal, sealer, store, worm
from mission_router.router import load_config

from tests.test_evidence_seal import FakeStore

PROVIDER = "projects/123456789/locations/global/workloadIdentityPools/github-pool/providers/governance"
CONFIG = {"provider": "gcs", "bucket": "example-evidence-worm", "workload_identity_provider": PROVIDER,
          "retention_years": 6}
ENV = {"ACTIONS_ID_TOKEN_REQUEST_URL": "https://oidc.example.invalid/token?api-version=2.0",
       "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "placeholder-request-token"}
AW = Path(__file__).resolve().parents[1]


class Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeCloud:
    """GitHub's OIDC endpoint, Google's STS and one bucket."""

    def __init__(self, retention_seconds=int(6 * 365.25 * 86400), sts_ok=True):
        self.objects = {}
        self.retention = retention_seconds
        self.sts_ok = sts_ok
        self.calls = []

    def fail(self, req, status):
        raise urllib.error.HTTPError(req.full_url, status, "x", {}, io.BytesIO(b'{"error": "x"}'))

    def __call__(self, req, timeout=60):
        url, method = req.full_url, req.get_method()
        self.calls.append((method, url.split("?")[0]))
        if url.startswith("https://oidc.example.invalid/"):
            assert req.get_header("Authorization") == "Bearer placeholder-request-token"
            assert "audience=" + urllib.parse.quote(f"https://iam.googleapis.com/{PROVIDER}", safe="") in url
            return Resp(json.dumps({"value": "placeholder-oidc-jwt"}).encode())
        if url == worm.STS:
            body = json.loads(req.data)
            assert body["subjectToken"] == "placeholder-oidc-jwt" and body["audience"] == f"//iam.googleapis.com/{PROVIDER}"
            if not self.sts_ok:
                self.fail(req, 403)
            return Resp(json.dumps({"access_token": "placeholder-access-token"}).encode())
        assert req.get_header("Authorization") == "Bearer placeholder-access-token"
        if url.startswith(worm.UPLOAD):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            assert q["ifGenerationMatch"] == ["0"], "a copy is only ever created"
            name = q["name"][0]
            if name in self.objects:
                self.fail(req, 412)
            self.objects[name] = req.data
            return Resp(b"{}")
        name = urllib.parse.unquote(urllib.parse.urlparse(url).path.split("/o/", 1)[1])
        if name not in self.objects:
            self.fail(req, 404)
        if "alt=media" in url:
            return Resp(self.objects[name])
        data = self.objects[name]
        return Resp(json.dumps({"md5Hash": base64.b64encode(hashlib.md5(data).digest()).decode(),
                                "timeCreated": "2026-11-09T12:00:00Z",
                                "retentionExpirationTime": f"{2026 + int(self.retention // (365.25 * 86400))}-11-09T"
                                                           f"12:00:00Z" if self.retention else None}).encode())


class Setup:
    def __init__(self, test, cloud=None):
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.seed = ed25519.generate_seed()
        pub = ed25519.public_key(self.seed)
        self.keys = {seal.keyid(pub): pub.hex()}
        self.chains = self.root / "chains"
        rec = producer.Recorder(self.chains, "gh-1-1-agent-M-DEMO-001-A2-r1")
        for action in ("dispatch.prepare", "dispatch.run"):
            rec.record(actor="mission-dispatch", account_id=None, action=action, result="done",
                       authority_kind="plan", authority_ref="M-DEMO-001 A2 round 1")
        self.fake_store = FakeStore()
        self.cloud = cloud or FakeCloud()
        self.bucket = worm.from_config({"evidence_worm": CONFIG}, ENV, self.cloud)

    def seal(self):
        return sealer.seal_runs(self.chains, self.seed, self.keys, store.Store(self.fake_store.request),
                                "2026-11-09T12:00:00Z", self.bucket)

    def clone(self):
        path = self.root / "store"
        self.fake_store.copy_to(path)
        return path


class ConfigTests(unittest.TestCase):
    def test_a_declaration_is_checked(self):
        self.assertEqual(worm.config({"evidence_worm": CONFIG}), CONFIG)
        self.assertIsNone(worm.config({}))
        for bad in ({**CONFIG, "provider": "s3"}, {**CONFIG, "bucket": "Has Spaces"},
                    {**CONFIG, "workload_identity_provider": "a key file"}, {**CONFIG, "retention_years": 0},
                    {**CONFIG, "extra": 1}):
            with self.subTest(bad), self.assertRaises(EvidenceError):
                worm.config({"evidence_worm": bad})

    def test_a_malformed_declaration_stops_the_router(self):
        config = json.loads((AW / "mission_router" / "config.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({**config, "evidence_worm": {**CONFIG, "provider": "s3"}}))
            with self.assertRaisesRegex(ValueError, "evidence_worm"):
                load_config(path)


class TokenTests(unittest.TestCase):
    def test_no_key_is_stored_the_oidc_token_is_exchanged(self):
        cloud = FakeCloud()
        self.assertEqual(worm.access_token(PROVIDER, ENV, cloud), "placeholder-access-token")
        self.assertEqual([c[1] for c in cloud.calls], ["https://oidc.example.invalid/token", worm.STS])

    def test_without_id_token_write_it_says_so(self):
        with self.assertRaisesRegex(EvidenceError, "id-token: write"):
            worm.access_token(PROVIDER, {}, FakeCloud())

    def test_a_refused_exchange_is_an_error(self):
        with self.assertRaisesRegex(EvidenceError, "token exchange failed"):
            worm.access_token(PROVIDER, ENV, FakeCloud(sts_ok=False))


class CopyTests(unittest.TestCase):
    def test_each_sealed_run_is_copied_and_the_copies_check(self):
        s = Setup(self)
        result = s.seal()
        self.assertEqual(len(result["sealed"]), 1)
        self.assertEqual(set(s.cloud.objects), set(s.fake_store.files), "the same paths as the store")
        self.assertEqual(worm.check_copies(s.clone(), s.bucket, 6), [])

    def test_a_copy_is_never_replaced(self):
        s = Setup(self)
        s.seal()
        name = next(iter(s.cloud.objects))
        before = s.cloud.objects[name]
        self.assertEqual(s.bucket.put(name, b"other bytes\n"), "present")
        self.assertEqual(s.cloud.objects[name], before)

    def test_the_checker_names_a_missing_a_different_or_a_short_lived_copy(self):
        s = Setup(self)
        s.seal()
        clone = s.clone()
        names = sorted(s.cloud.objects)
        del s.cloud.objects[names[0]]
        s.cloud.objects[names[1]] = b"tampered\n"
        problems = worm.check_copies(clone, s.bucket, 6)
        self.assertIn(f"{names[0]} has no WORM copy", problems)
        self.assertIn(f"{names[1]}: the WORM copy differs from the store", problems)
        short = Setup(self, FakeCloud(retention_seconds=int(1 * 365.25 * 86400)))
        short.seal()
        self.assertTrue(all("retained 1.00 years, not 6" in p for p in worm.check_copies(short.clone(), short.bucket, 6)))
        none = Setup(self, FakeCloud(retention_seconds=0))
        none.seal()
        self.assertTrue(all("has no retention" in p for p in worm.check_copies(none.clone(), none.bucket, 6)))

    def test_the_checker_reports_the_worm_copy(self):
        s = Setup(self)
        s.seal()
        clone = s.clone()
        import subprocess
        for args in (["init", "-q"], ["add", "-A"], ["-c", "user.name=t", "-c", "user.email=t@example.invalid",
                                                     "commit", "-q", "-m", "stored"]):
            subprocess.run(["git", *args], cwd=clone, check=True, capture_output=True)
        good = checker.check(clone, s.keys, None, None, s.bucket, 6)
        self.assertTrue(good["ok"], good["failures"])
        self.assertIn("WORM copy identical and retained", checker.summary(good, "example-org/evidence-store"))
        unreachable = checker.check(clone, s.keys, None, None, None, 6, "the WORM token exchange failed: HTTP 403")
        self.assertFalse(unreachable["ok"])
        self.assertIn("the WORM copy could not be checked", unreachable["failures"][0])


class BackfillTests(unittest.TestCase):
    """Runs sealed before the bucket was declared are copied once, by hand (the seal workflow's workflow_dispatch)."""

    def store_request(self, fake_store, truncated=False):
        def request(method, path, body=None):
            if path.startswith("/git/trees/"):
                return {"truncated": truncated, "tree": [
                    {"type": "blob", "path": name, "sha": f"sha-{name}"} for name in fake_store.files] + [
                    {"type": "blob", "path": "README.md", "sha": "sha-readme"}, {"type": "tree", "path": "runs"}]}
            if path.startswith("/git/blobs/sha-"):
                return {"content": base64.b64encode(fake_store.files[path[len("/git/blobs/sha-"):]]).decode()}
            raise AssertionError(path)
        return request

    def test_every_stored_run_is_copied_once(self):
        s = Setup(self)
        s.bucket = None
        s.seal()  # sealed while no bucket was declared: the store has it, the bucket does not
        s.bucket = worm.from_config({"evidence_worm": CONFIG}, ENV, s.cloud)
        self.assertEqual(s.cloud.objects, {})
        self.assertEqual(sealer.backfill(self.store_request(s.fake_store), s.bucket), {"added": 2, "present": 0})
        self.assertEqual(set(s.cloud.objects), set(s.fake_store.files), "README.md is not a run")
        self.assertEqual(sealer.backfill(self.store_request(s.fake_store), s.bucket), {"added": 0, "present": 2})
        self.assertEqual(worm.check_copies(s.clone(), s.bucket, 6), [])

    def test_a_truncated_listing_is_refused(self):
        s = Setup(self)
        with self.assertRaisesRegex(EvidenceError, "too large"):
            sealer.backfill(self.store_request(s.fake_store, truncated=True), s.bucket)


class WorkflowTests(unittest.TestCase):
    def test_by_hand_the_seal_workflow_only_backfills(self):
        root = AW.parents[1]
        live = root / ".github" / "workflows" / "evidence-seal.yml"
        text = (live if live.is_file() else root / "packaging" / "workflows" / "evidence-seal.yml").read_text()
        self.assertIn("workflow_dispatch:", text[:text.index("\npermissions:")])
        backfill = text.index("python3 -B -m evidence backfill")
        self.assertIn("github.event_name == 'workflow_dispatch'", text[backfill - 400:backfill])
        for step in ("python3 -B -m evidence seal", "name: sealed\n"):  # workflow_run or the sweep (Amendment 022)
            at = text.index(step)
            self.assertIn("github.event_name != 'workflow_dispatch'", text[at - 700:at], step)
        mark = text[text.index("\n  mark:\n"):]
        self.assertIn("github.event_name != 'workflow_dispatch'", mark[:mark.index("\n    steps:")], "the mark job")

    def test_both_jobs_ask_for_an_oidc_token_and_hold_no_cloud_key(self):
        root = AW.parents[1]
        for name, job in (("evidence-seal.yml", "seal"), ("evidence-verify.yml", "verify")):
            live = root / ".github" / "workflows" / name
            text = (live if live.is_file() else root / "packaging" / "workflows" / name).read_text()
            block = text[text.index(f"\n  {job}:\n"):]
            block = block[:block.index("\n    steps:")]
            with self.subTest(name):
                self.assertIn("id-token: write", block)
                self.assertNotRegex(text, r"secrets\.(GOOGLE|GCP|GCS)", "no cloud key is stored")


if __name__ == "__main__":
    unittest.main()
