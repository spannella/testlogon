"""Offline regression tests for GAP-0286 and GAP-0287 (KYC-021).

Both gaps live in ``app/routers/kyc_partner_api.py`` (with their service-layer
implementations in ``app/services/kyc_partner_api.py`` and the shared limiter in
``app/services/rate_limit.py``).

GAP-0286 — per-API-key rate limiting was completely absent from the KYC Partner
API. The ticket (§4.7) specifies hourly caps per category (100 applications,
200 documents, 1000 reads, 10 webhook-tests). The fix adds
``rate_limit_kyc_partner_api(api_key_id, category)`` (keyed on
``apikey:{api_key_id}``) at the top of every handler. FAILS BEFORE: the
(N+1)-th call in the same hour still returns 200. PASSES AFTER: it raises
HTTP 429 with ``code=kyc_api_rate_limited``.

GAP-0287 — document file bytes were read from the multipart upload and then
discarded; nothing was ever written to S3. The fix uploads the bytes to S3 under
``{prefix}{partner_id}/{application_id}/{document_id}/{filename}``, records the
``s3_key``/``bucket`` on the document dict, and exposes a download endpoint.
FAILS BEFORE: ``put_object`` is never called and the document has no ``s3_key``.
PASSES AFTER: the bytes land in S3 and the download endpoint returns a URL.

Hermetic / offline (TEST ISOLATION):
* Real in-memory DynamoDB tables via moto are created and bound to the exact
  frozen ``T.kyc_cases`` / ``T.sessions`` handles through ``object.__setattr__``
  (``T`` is a frozen dataclass), restored on cleanup. We do NOT rely on global
  ``@mock_aws`` interception leaking into business code beyond these handles.
* The S3 client is monkeypatched to an in-memory fake so NO real AWS (and no
  moto S3 global interception) is touched.
* Async route handlers are invoked directly with ``asyncio.run`` on a fresh
  event loop — never ``asyncio.get_event_loop()``.
* The frozen ``Settings`` singleton ``S`` is mutated via ``object.__setattr__``.
"""
from __future__ import annotations

import asyncio
import unittest
from contextlib import ExitStack
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


# ── helpers ──────────────────────────────────────────────────────────

def _run(coro):
    """Run a coroutine on a fresh event loop (never get_event_loop())."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _make_kyc_cases_table(ddb):
    return ddb.create_table(
        TableName="kyc_cases_test",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_sessions_table(ddb):
    return ddb.create_table(
        TableName="sessions_test",
        KeySchema=[
            {"AttributeName": "user_sub", "KeyType": "HASH"},
            {"AttributeName": "session_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_sub", "AttributeType": "S"},
            {"AttributeName": "session_id", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


class _FakeS3:
    """In-memory stand-in for the boto3 S3 client (no real AWS / no moto S3)."""

    def __init__(self):
        self.objects = {}
        self.put_calls = []

    def put_object(self, *, Bucket, Key, Body, ContentType=None):  # noqa: N803
        self.objects[(Bucket, Key)] = Body
        self.put_calls.append({"Bucket": Bucket, "Key": Key, "ContentType": ContentType})
        return {}

    def generate_presigned_url(self, op, *, Params, ExpiresIn):  # noqa: N803
        return f"https://s3.example/{Params['Bucket']}/{Params['Key']}?sig=test"


class _UploadFile:
    """Minimal async-readable stand-in for starlette's UploadFile."""

    def __init__(self, content: bytes, filename: str, content_type: str):
        self._content = content
        self.filename = filename
        self.content_type = content_type

    async def read(self):
        return self._content


@unittest.skipIf(mock_aws is None, "moto is not installed")
class _KycPartnerApiTestBase(unittest.TestCase):
    PARTNER_ID = "partner_user_sub_001"
    API_KEY_ID = "ak_test_gap_0286_0287"
    APPLICATION_ID = "app_test_0001"

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.kyc_table = _make_kyc_cases_table(ddb)
        self.sessions_table = _make_sessions_table(ddb)

        from app.core.tables import T
        from app.core.settings import S
        from app.services import kyc_partner_api as svc
        from app.services import rate_limit

        self.T = T
        self.S = S
        self.svc = svc
        self.rate_limit = rate_limit

        # Bind the exact frozen table handles to our in-memory tables.
        self._patch_frozen(T, "kyc_cases", self.kyc_table)
        self._patch_frozen(T, "sessions", self.sessions_table)
        # Ensure the rate-limiter engages (it no-ops when no sessions table name).
        self._patch_frozen(S, "ddb_sessions_table", "sessions_test")
        self._patch_frozen(S, "dev_mode", True)

        self.principal = {
            "user_sub": self.PARTNER_ID,
            "api_key_id": self.API_KEY_ID,
            "capabilities": ["kyc:admin"],  # implies all kyc:* scopes
        }

    def _patch_frozen(self, obj, attr, value):
        original = getattr(obj, attr)
        object.__setattr__(obj, attr, value)
        self.addCleanup(lambda: object.__setattr__(obj, attr, original))

    def _seed_submission(self, application_id=None):
        application_id = application_id or self.APPLICATION_ID
        self.kyc_table.put_item(
            Item={
                "pk": self.svc._partner_pk(self.PARTNER_ID),
                "sk": self.svc._sub_sk(application_id),
                "entity_type": "kyc_partner_submission",
                "application_id": application_id,
                "external_id": "ext-1",
                "kyc_case_id": "",  # empty -> _refresh_status_from_case is a no-op
                "status": "draft",
                "documents": [],
                "applicant": {},
                "tier": "tier_1",
                "created_at": 1,
                "updated_at": 1,
                "sandbox": False,
            }
        )
        return application_id


# ── GAP-0286: per-API-key rate limiting ──────────────────────────────

@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestRateLimitGap0286(_KycPartnerApiTestBase):
    def _call_count(self, category):
        """Number of allowed calls before 429 for a category."""
        from fastapi import HTTPException

        n = 0
        while True:
            try:
                self.rate_limit.rate_limit_kyc_partner_api(self.API_KEY_ID, category)
                n += 1
            except HTTPException as exc:
                self.assertEqual(exc.status_code, 429)
                self.assertEqual(exc.detail.get("code"), "kyc_api_rate_limited")
                return n
            if n > 5000:  # safety
                self.fail("rate limit never triggered")

    def test_applications_cap_enforced(self):
        # Lower the cap so the test is fast & deterministic.
        self._patch_frozen(self.S, "kyc_partner_api_rl_applications_per_hour", 3)
        allowed = self._call_count("applications")
        self.assertEqual(
            allowed,
            3,
            "GAP-0286: POST /applications must be capped per API key (was unlimited)",
        )

    def test_documents_cap_enforced(self):
        self._patch_frozen(self.S, "kyc_partner_api_rl_documents_per_hour", 2)
        self.assertEqual(self._call_count("documents"), 2)

    def test_read_cap_enforced(self):
        self._patch_frozen(self.S, "kyc_partner_api_rl_read_per_hour", 4)
        self.assertEqual(self._call_count("read"), 4)

    def test_webhook_test_cap_enforced(self):
        self._patch_frozen(self.S, "kyc_partner_api_rl_webhook_test_per_hour", 1)
        self.assertEqual(self._call_count("webhook_test"), 1)

    def test_separate_keys_have_separate_budgets(self):
        self._patch_frozen(self.S, "kyc_partner_api_rl_applications_per_hour", 1)
        # First key exhausts its budget.
        self.rate_limit.rate_limit_kyc_partner_api("key_A", "applications")
        from fastapi import HTTPException

        with self.assertRaises(HTTPException):
            self.rate_limit.rate_limit_kyc_partner_api("key_A", "applications")
        # A different key still has its full budget.
        self.rate_limit.rate_limit_kyc_partner_api("key_B", "applications")  # must NOT raise

    def test_router_create_application_returns_429_after_cap(self):
        """End-to-end through the router handler (GAP-0286)."""
        from fastapi import HTTPException, Request
        from app.routers import kyc_partner_api as router
        from app.models import KycPartnerApplicationCreateIn

        self._patch_frozen(self.S, "kyc_partner_api_rl_applications_per_hour", 1)

        # Stub create_application so the test doesn't depend on kyc_cases STORE.
        created = {
            "application_id": "app_made_1",
            "status": "draft",
            "created_at": 1,
            "sandbox": False,
        }
        request = Request({"type": "http", "headers": []})
        body = KycPartnerApplicationCreateIn(
            external_id="ext-router-1",
            applicant={
                "first_name": "A",
                "last_name": "B",
                "date_of_birth": "1990-01-01",
                "email": "a@example.com",
            },
        )

        with patch.object(router.svc, "create_application", return_value=created):
            # 1st call: allowed (idempotency key required).
            resp = _run(
                router.create_application(
                    body=body,
                    request=request,
                    principal=self.principal,
                    idempotency_key="idem-1",
                )
            )
            self.assertEqual(resp["application_id"], "app_made_1")

            # 2nd call (fresh idempotency key) must hit the per-key cap -> 429.
            with self.assertRaises(HTTPException) as ctx:
                _run(
                    router.create_application(
                        body=body,
                        request=request,
                        principal=self.principal,
                        idempotency_key="idem-2",
                    )
                )
            self.assertEqual(ctx.exception.status_code, 429)
            self.assertEqual(ctx.exception.detail.get("code"), "kyc_api_rate_limited")


# ── GAP-0287: document bytes stored in S3 ────────────────────────────

@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestDocumentStorageGap0287(_KycPartnerApiTestBase):
    def setUp(self):
        super().setUp()
        self.fake_s3 = _FakeS3()
        # Patch the centralized S3 factory used by the service.
        import app.core.aws_clients as aws_clients

        self.stack.enter_context(
            patch.object(aws_clients, "s3_client", return_value=self.fake_s3)
        )

    def test_upload_persists_bytes_to_s3(self):
        """GAP-0287: uploaded bytes must be written to S3 with the right key."""
        self._seed_submission()
        contents = b"\x89PNG fake-id-front-bytes"

        result = self.svc.upload_document(
            self.principal,
            self.APPLICATION_ID,
            document_type="id_front",
            file_type="image/png",
            filename="id front.png",
            size_bytes=len(contents),
            contents=contents,
        )

        # Exactly one S3 put with our bytes.
        self.assertEqual(len(self.fake_s3.put_calls), 1)
        ((bucket, key), body), = self.fake_s3.objects.items()
        self.assertEqual(body, contents)
        # Key format: {prefix}{partner_id}/{application_id}/{document_id}/{safe_name}
        self.assertIn(self.PARTNER_ID, key)
        self.assertIn(self.APPLICATION_ID, key)
        self.assertIn(result["document_id"], key)
        self.assertTrue(key.endswith("id_front.png"), key)

        # The s3_key/bucket must be recorded on the persisted document.
        item = self.kyc_table.get_item(
            Key={
                "pk": self.svc._partner_pk(self.PARTNER_ID),
                "sk": self.svc._sub_sk(self.APPLICATION_ID),
            }
        )["Item"]
        docs = item["documents"]
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]["s3_key"], key)
        self.assertEqual(docs[0]["bucket"], bucket)

    def test_download_endpoint_returns_url(self):
        """GAP-0287: the new download endpoint returns a URL for a stored doc."""
        self._seed_submission()
        contents = b"selfie-bytes"
        up = self.svc.upload_document(
            self.principal,
            self.APPLICATION_ID,
            document_type="selfie",
            file_type="image/jpeg",
            filename="selfie.jpg",
            size_bytes=len(contents),
            contents=contents,
        )
        dl = self.svc.get_document_download(
            self.principal, self.APPLICATION_ID, up["document_id"]
        )
        self.assertEqual(dl["document_id"], up["document_id"])
        self.assertTrue(dl["url"])  # dev-mode /mock/s3/... URL

    def test_download_unknown_document_404(self):
        from fastapi import HTTPException

        self._seed_submission()
        with self.assertRaises(HTTPException) as ctx:
            self.svc.get_document_download(self.principal, self.APPLICATION_ID, "doc_missing")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_partner_isolation_on_download(self):
        """A different partner cannot download another partner's document."""
        from fastapi import HTTPException

        self._seed_submission()
        self.svc.upload_document(
            self.principal,
            self.APPLICATION_ID,
            document_type="id_back",
            file_type="image/png",
            filename="back.png",
            size_bytes=4,
            contents=b"abcd",
        )
        other_principal = {
            "user_sub": "other_partner_999",
            "api_key_id": "ak_other",
            "capabilities": ["kyc:admin"],
        }
        # Other partner's partition has no such submission -> 404 (isolation).
        with self.assertRaises(HTTPException) as ctx:
            self.svc.get_document_download(other_principal, self.APPLICATION_ID, "doc_any")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_router_upload_passes_bytes_through(self):
        """End-to-end through the router upload handler (GAP-0287)."""
        from app.routers import kyc_partner_api as router

        self._seed_submission()
        contents = b"router-upload-bytes"
        upload = _UploadFile(contents, "router.png", "image/png")

        result = _run(
            router.upload_document(
                application_id=self.APPLICATION_ID,
                principal=self.principal,
                document_type="id_front",
                file=upload,
                idempotency_key="doc-idem-1",
            )
        )
        self.assertIn("document_id", result)
        self.assertEqual(len(self.fake_s3.put_calls), 1)
        ((_, _), body), = self.fake_s3.objects.items()
        self.assertEqual(body, contents)


if __name__ == "__main__":
    unittest.main()
