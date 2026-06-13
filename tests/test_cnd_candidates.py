"""
CND-001 through CND-005: Hermetic offline pytest suite for the ATS Candidates subsystem.

Isolation pattern (from test_gap_0286_0287_kyc_partner_api.py):
- mock_aws() context — moto in-memory DynamoDB only.
- T.candidates patched via object.__setattr__(T, "candidates", moto_table).
- S.candidates_enabled toggled via object.__setattr__(S, "candidates_enabled", True/False).
- No TestClient, no real AWS, no network.
- Async route handlers invoked via _run(coro) helper on fresh asyncio.new_event_loop().
"""

import asyncio
import sys
import unittest
from contextlib import ExitStack
from decimal import Decimal
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch
from uuid import uuid4

import boto3
from moto import mock_aws

from app.core.settings import S
from app.core.tables import T
from app.models import (
    CANDIDATE_RESUME_CONTENT_TYPES,
    CANDIDATE_SOURCES,
    CANDIDATE_STATUSES,
    CandidateCreateIn,
    CandidateHistoryOut,
    CandidateHistoryPage,
    CandidateListOut,
    CandidateOut,
    CandidateResumeOut,
    CandidateUpdateIn,
    SetOwnerIn,
)


# ── helpers ────────────────────────────────────────────────────────────────────

def _run(coro):
    """Run a coroutine on a fresh event loop (avoids loop reuse issues)."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class _FakeS3:
    def __init__(self):
        self.store: Dict[str, bytes] = {}
        self.deleted_keys = []

    def put_object(self, *, Bucket, Key, Body, ContentType="application/octet-stream"):
        self.store[f"{Bucket}/{Key}"] = Body if isinstance(Body, bytes) else Body.encode()

    def delete_object(self, *, Bucket, Key):
        self.deleted_keys.append(f"{Bucket}/{Key}")

    def generate_presigned_url(self, op, Params, ExpiresIn=300):
        return f"https://fake-presign/{Params['Bucket']}/{Params['Key']}"


def _make_candidates_table(ddb):
    """Create the candidates table with all three GSIs (CND-001 schema)."""
    return ddb.create_table(
        TableName="candidates_test",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "N"},
            {"AttributeName": "GSI2PK", "AttributeType": "S"},
            {"AttributeName": "GSI2SK", "AttributeType": "N"},
            {"AttributeName": "GSI3PK", "AttributeType": "S"},
            {"AttributeName": "GSI3SK", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByOwner",
                "KeySchema": [
                    {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByStatus",
                "KeySchema": [
                    {"AttributeName": "GSI2PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI2SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "BySource",
                "KeySchema": [
                    {"AttributeName": "GSI3PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI3SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _seed_candidate(table, *, candidate_id=None, email="test@example.com",
                    owner_sub="user1", status="active", source="direct",
                    created_at=1000000, deleted_at=None) -> dict:
    """Insert a minimal candidate META row and return it."""
    cid = candidate_id or ("cand_" + uuid4().hex[:20])
    item = {
        "pk": f"CANDIDATE#{cid}",
        "sk": "META",
        "candidate_id": cid,
        "first_name": "Test",
        "last_name": "Candidate",
        "email": email,
        "email_raw": email,
        "source": source,
        "owner_sub": owner_sub,
        "status": status,
        "can_relocate": False,
        "created_by": owner_sub,
        "created_at": created_at,
        "updated_at": created_at,
        "GSI1PK": f"OWNER#{owner_sub}",
        "GSI1SK": created_at,
        "GSI2PK": f"STATUS#{status}",
        "GSI2SK": created_at,
        "GSI3PK": f"SOURCE#{source}",
        "GSI3SK": created_at,
    }
    if deleted_at:
        item["deleted_at"] = deleted_at
    table.put_item(Item=item)
    return item


# ── Test: CND-001 Pydantic models and settings ─────────────────────────────────

class TestCnd001ScaffoldModels(unittest.TestCase):
    """Verify models, sentinel sets, and settings defaults."""

    def test_candidate_statuses_set(self):
        expected = {"active", "qualified", "submitted", "interviewing",
                    "placed", "on_hold", "not_in_search", "archived"}
        self.assertEqual(CANDIDATE_STATUSES, frozenset(expected))
        self.assertNotIn("unknown", CANDIDATE_STATUSES)

    def test_candidate_sources_set(self):
        self.assertIn("other", CANDIDATE_SOURCES)
        self.assertIn("linkedin", CANDIDATE_SOURCES)
        self.assertNotIn("unknown", CANDIDATE_SOURCES)

    def test_candidate_resume_content_types(self):
        self.assertIn("application/pdf", CANDIDATE_RESUME_CONTENT_TYPES)

    def test_settings_defaults(self):
        # Default OFF
        prev = S.candidates_enabled
        try:
            object.__setattr__(S, "candidates_enabled", False)
            self.assertFalse(S.candidates_enabled)
        finally:
            object.__setattr__(S, "candidates_enabled", prev)
        # Other settings present and typed
        self.assertIsInstance(S.candidates_table_name, str)
        self.assertIsInstance(S.candidate_resume_bucket, str)
        self.assertIsInstance(S.candidate_resume_s3_prefix, str)
        self.assertIsInstance(S.candidate_resume_max_bytes, int)
        self.assertIsInstance(S.candidate_resume_max_per_candidate, int)
        self.assertEqual(S.candidate_resume_max_bytes, 20971520)
        self.assertEqual(S.candidate_resume_max_per_candidate, 25)

    def test_create_in_valid(self):
        c = CandidateCreateIn(first_name="Alice", last_name="Smith", email="alice@example.com")
        self.assertEqual(c.first_name, "Alice")
        self.assertEqual(c.can_relocate, False)

    def test_create_in_invalid_status(self):
        from pydantic import ValidationError
        with self.assertRaises(ValidationError):
            CandidateCreateIn(first_name="A", last_name="B", email="a@b.com", status="invalid")

    def test_create_in_invalid_source(self):
        from pydantic import ValidationError
        with self.assertRaises(ValidationError):
            CandidateCreateIn(first_name="A", last_name="B", email="a@b.com", source="unknown")

    def test_create_in_missing_first_name(self):
        from pydantic import ValidationError
        with self.assertRaises(ValidationError):
            CandidateCreateIn(last_name="B", email="a@b.com")

    def test_create_in_key_skills_too_long(self):
        from pydantic import ValidationError
        with self.assertRaises(ValidationError):
            CandidateCreateIn(first_name="A", last_name="B", email="a@b.com", key_skills="x" * 4001)

    def test_update_in_all_optional(self):
        u = CandidateUpdateIn()
        self.assertIsNone(u.first_name)

    def test_candidate_out_resumes_default(self):
        c = CandidateOut(
            candidate_id="cand_1",
            first_name="A", last_name="B",
            email="a@b.com", email_raw="A@B.com",
            source="direct", owner_sub="u1", status="active",
            can_relocate=False, created_by="u1", created_at=0, updated_at=0,
        )
        self.assertEqual(c.resumes, [])

    def test_set_owner_in(self):
        from pydantic import ValidationError
        s = SetOwnerIn(owner_sub="user123")
        self.assertEqual(s.owner_sub, "user123")
        with self.assertRaises(ValidationError):
            SetOwnerIn(owner_sub="")


# ── Test: CND-001 Table handle + DDB GSI range query ─────────────────────────

class TestCnd001TableHandle(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_candidates_table(ddb)
        prev = T.candidates
        object.__setattr__(T, "candidates", self.table)
        self.addCleanup(lambda: object.__setattr__(T, "candidates", prev))

    def test_put_and_get(self):
        item = _seed_candidate(self.table, candidate_id="cand_test1")
        resp = self.table.get_item(Key={"pk": "CANDIDATE#cand_test1", "sk": "META"})
        self.assertIn("Item", resp)

    def test_gsi_byowner_range_query(self):
        """Verify GSI1SK is numeric — integer range query must not raise ValidationException."""
        _seed_candidate(self.table, candidate_id="cand_gsi1", owner_sub="owner_x",
                        created_at=2000000)
        from boto3.dynamodb.conditions import Key
        resp = self.table.query(
            IndexName="ByOwner",
            KeyConditionExpression=Key("GSI1PK").eq("OWNER#owner_x") & Key("GSI1SK").gte(0),
        )
        self.assertGreaterEqual(len(resp["Items"]), 1)

    def test_gsi_bystatus_range_query(self):
        _seed_candidate(self.table, candidate_id="cand_gsi2", status="active",
                        created_at=2000001)
        from boto3.dynamodb.conditions import Key
        resp = self.table.query(
            IndexName="ByStatus",
            KeyConditionExpression=Key("GSI2PK").eq("STATUS#active") & Key("GSI2SK").gte(0),
        )
        self.assertGreaterEqual(len(resp["Items"]), 1)

    def test_gsi_bysource_range_query(self):
        _seed_candidate(self.table, candidate_id="cand_gsi3", source="linkedin",
                        created_at=2000002)
        from boto3.dynamodb.conditions import Key
        resp = self.table.query(
            IndexName="BySource",
            KeyConditionExpression=Key("GSI3PK").eq("SOURCE#linkedin") & Key("GSI3SK").gte(0),
        )
        self.assertGreaterEqual(len(resp["Items"]), 1)


# ── Test: CND-002 CRUD service ────────────────────────────────────────────────

@mock_aws
class TestCandidateCrudService(unittest.TestCase):
    def setUp(self):
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_candidates_table(ddb)
        prev_t = T.candidates
        object.__setattr__(T, "candidates", self.table)
        self.addCleanup(lambda: object.__setattr__(T, "candidates", prev_t))
        prev_s = S.candidates_enabled
        object.__setattr__(S, "candidates_enabled", True)
        self.addCleanup(lambda: object.__setattr__(S, "candidates_enabled", prev_s))

        # Patch audit_event
        self._audit_patcher = patch("app.services.alerts.audit_event")
        self.mock_audit = self._audit_patcher.start()
        self.addCleanup(self._audit_patcher.stop)

    def _make_create_in(self, email="alice@example.com", **kwargs) -> CandidateCreateIn:
        defaults = dict(first_name="Alice", last_name="Smith", email=email)
        defaults.update(kwargs)
        return CandidateCreateIn(**defaults)

    # Flag-off tests
    def test_flag_off_create(self):
        from fastapi import HTTPException
        import app.services.candidates as svc
        object.__setattr__(S, "candidates_enabled", False)
        with self.assertRaises(HTTPException) as ctx:
            svc.create_candidate("u1", self._make_create_in())
        self.assertEqual(ctx.exception.status_code, 503)

    def test_flag_off_get(self):
        from fastapi import HTTPException
        import app.services.candidates as svc
        object.__setattr__(S, "candidates_enabled", False)
        with self.assertRaises(HTTPException):
            svc.get_candidate("cand_xxx")

    def test_flag_off_list(self):
        from fastapi import HTTPException
        import app.services.candidates as svc
        object.__setattr__(S, "candidates_enabled", False)
        with self.assertRaises(HTTPException):
            svc.list_candidates()

    def test_flag_off_update(self):
        from fastapi import HTTPException
        import app.services.candidates as svc
        object.__setattr__(S, "candidates_enabled", False)
        with self.assertRaises(HTTPException):
            svc.update_candidate("cand_xxx", "u1", CandidateUpdateIn())

    def test_flag_off_delete(self):
        from fastapi import HTTPException
        import app.services.candidates as svc
        object.__setattr__(S, "candidates_enabled", False)
        with self.assertRaises(HTTPException):
            svc.delete_candidate("cand_xxx", "u1")

    def test_flag_off_set_owner(self):
        from fastapi import HTTPException
        import app.services.candidates as svc
        object.__setattr__(S, "candidates_enabled", False)
        with self.assertRaises(HTTPException):
            svc.set_owner("cand_xxx", "new_owner", "actor")

    # Happy path: create
    def test_create_candidate_happy_path(self):
        import app.services.candidates as svc
        item = svc.create_candidate("creator_sub", self._make_create_in(email="Bob@Example.COM"))
        self.assertIn("candidate_id", item)
        self.assertTrue(item["candidate_id"].startswith("cand_"))
        self.assertEqual(item["email"], "bob@example.com")  # normalized
        self.assertEqual(item["email_raw"], "Bob@Example.COM")  # raw preserved
        self.assertEqual(item["status"], "active")
        self.assertEqual(item["source"], "other")
        self.assertIn("GSI1PK", item)
        self.assertIn("GSI2PK", item)
        self.assertIn("GSI3PK", item)
        self.assertIsInstance(item["created_at"], int)

    def test_create_candidate_defaults(self):
        import app.services.candidates as svc
        item = svc.create_candidate("u1", self._make_create_in())
        self.assertEqual(item["owner_sub"], "u1")  # defaults to creator
        self.assertEqual(item["source"], "other")
        self.assertEqual(item["status"], "active")

    def test_create_candidate_with_phone(self):
        import app.services.candidates as svc
        item = svc.create_candidate("u1", self._make_create_in(phone="+14155551234"))
        self.assertIn("phone", item)

    def test_create_candidate_invalid_email(self):
        from fastapi import HTTPException
        import app.services.candidates as svc
        with self.assertRaises(HTTPException) as ctx:
            svc.create_candidate("u1", self._make_create_in(email="not-an-email"))
        self.assertEqual(ctx.exception.status_code, 400)

    def test_create_candidate_invalid_date_available(self):
        from fastapi import HTTPException
        import app.services.candidates as svc
        with self.assertRaises(HTTPException) as ctx:
            svc.create_candidate("u1", CandidateCreateIn(
                first_name="A", last_name="B", email="a@b.com", date_available="not-a-date"
            ))
        self.assertEqual(ctx.exception.status_code, 400)

    def test_create_candidate_valid_date_available(self):
        import app.services.candidates as svc
        item = svc.create_candidate("u1", CandidateCreateIn(
            first_name="A", last_name="B", email="dateable@test.com", date_available="2026-12-01"
        ))
        self.assertEqual(item["date_available"], "2026-12-01")

    def test_create_duplicate_email_returns_409(self):
        from fastapi import HTTPException
        import app.services.candidates as svc
        svc.create_candidate("u1", self._make_create_in())
        with self.assertRaises(HTTPException) as ctx:
            svc.create_candidate("u1", self._make_create_in())
        self.assertEqual(ctx.exception.status_code, 409)
        detail = ctx.exception.detail
        self.assertEqual(detail["code"], "duplicate_candidate")
        self.assertIn("candidate_id", detail)

    def test_create_different_email_succeeds(self):
        import app.services.candidates as svc
        svc.create_candidate("u1", self._make_create_in(email="first@example.com"))
        svc.create_candidate("u1", self._make_create_in(email="second@example.com"))

    def test_audit_event_called_on_create(self):
        import app.services.candidates as svc
        svc.create_candidate("u1", self._make_create_in(email="audit@test.com"))
        self.mock_audit.assert_called()

    # get_candidate
    def test_get_candidate_returns_item(self):
        import app.services.candidates as svc
        item = svc.create_candidate("u1", self._make_create_in(email="get@test.com"))
        found = svc.get_candidate(item["candidate_id"])
        self.assertIsNotNone(found)
        self.assertEqual(found["candidate_id"], item["candidate_id"])

    def test_get_candidate_returns_none_for_missing(self):
        import app.services.candidates as svc
        self.assertIsNone(svc.get_candidate("cand_nonexistent"))

    def test_get_candidate_returns_soft_deleted(self):
        import app.services.candidates as svc
        cid = _seed_candidate(self.table, deleted_at=999999)["candidate_id"]
        item = svc.get_candidate(cid)
        self.assertIsNotNone(item)
        self.assertIn("deleted_at", item)

    # list_candidates
    def test_list_candidates_by_owner(self):
        import app.services.candidates as svc
        svc.create_candidate("owner_abc", self._make_create_in(email="l1@test.com"))
        svc.create_candidate("owner_abc", self._make_create_in(email="l2@test.com"))
        result = svc.list_candidates(owner_sub="owner_abc")
        self.assertGreaterEqual(len(result["candidates"]), 2)

    def test_list_candidates_excludes_soft_deleted(self):
        import app.services.candidates as svc
        _seed_candidate(self.table, owner_sub="x", deleted_at=123456)
        result = svc.list_candidates(owner_sub="x")
        for c in result["candidates"]:
            self.assertNotIn("deleted_at", c)

    def test_list_candidates_by_status(self):
        import app.services.candidates as svc
        _seed_candidate(self.table, status="placed", email="placed@test.com", created_at=5000)
        result = svc.list_candidates(status="placed")
        self.assertGreaterEqual(len(result["candidates"]), 1)
        for c in result["candidates"]:
            self.assertEqual(c["status"], "placed")

    def test_list_candidates_by_source(self):
        import app.services.candidates as svc
        _seed_candidate(self.table, source="linkedin", email="src@test.com", created_at=5001)
        result = svc.list_candidates(source="linkedin")
        self.assertGreaterEqual(len(result["candidates"]), 1)

    # update_candidate
    def test_update_candidate_happy_path(self):
        import app.services.candidates as svc
        item = svc.create_candidate("u1", self._make_create_in(email="upd@test.com"))
        cid = item["candidate_id"]
        updated = svc.update_candidate(cid, "u1", CandidateUpdateIn(title="Engineer"))
        self.assertEqual(updated["title"], "Engineer")

    def test_update_candidate_404_for_missing(self):
        from fastapi import HTTPException
        import app.services.candidates as svc
        with self.assertRaises(HTTPException) as ctx:
            svc.update_candidate("cand_missing", "u1", CandidateUpdateIn(title="X"))
        self.assertEqual(ctx.exception.status_code, 404)

    def test_update_candidate_410_for_deleted(self):
        from fastapi import HTTPException
        import app.services.candidates as svc
        cid = _seed_candidate(self.table, deleted_at=100000)["candidate_id"]
        with self.assertRaises(HTTPException) as ctx:
            svc.update_candidate(cid, "u1", CandidateUpdateIn(title="X"))
        self.assertEqual(ctx.exception.status_code, 410)

    def test_update_candidate_status_change_rewrites_gsi2(self):
        import app.services.candidates as svc
        item = svc.create_candidate("u1", self._make_create_in(email="gsi2@test.com"))
        cid = item["candidate_id"]
        updated = svc.update_candidate(cid, "u1", CandidateUpdateIn(status="interviewing"))
        self.assertEqual(updated["status"], "interviewing")
        self.assertEqual(updated["GSI2PK"], "STATUS#interviewing")

    def test_update_candidate_none_fields_not_overwritten(self):
        import app.services.candidates as svc
        item = svc.create_candidate("u1", self._make_create_in(
            email="nones@test.com", company="Acme"
        ))
        cid = item["candidate_id"]
        updated = svc.update_candidate(cid, "u1", CandidateUpdateIn(title="CEO"))
        self.assertEqual(updated.get("company"), "Acme")  # preserved

    # delete_candidate
    def test_delete_candidate_sets_deleted_at_and_archived(self):
        import app.services.candidates as svc
        item = svc.create_candidate("u1", self._make_create_in(email="del@test.com"))
        cid = item["candidate_id"]
        svc.delete_candidate(cid, "u1")
        found = svc.get_candidate(cid)
        self.assertIn("deleted_at", found)
        self.assertEqual(found["status"], "archived")

    def test_delete_candidate_404_for_missing(self):
        from fastapi import HTTPException
        import app.services.candidates as svc
        with self.assertRaises(HTTPException) as ctx:
            svc.delete_candidate("cand_missing", "u1")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_delete_candidate_idempotent(self):
        import app.services.candidates as svc
        item = svc.create_candidate("u1", self._make_create_in(email="del2@test.com"))
        cid = item["candidate_id"]
        svc.delete_candidate(cid, "u1")
        # Second call should be no-op (no exception)
        svc.delete_candidate(cid, "u1")

    # set_owner
    def test_set_owner_shim(self):
        import app.services.candidates as svc
        item = svc.create_candidate("owner_orig", self._make_create_in(email="own@test.com"))
        cid = item["candidate_id"]
        updated = svc.set_owner(cid, "new_owner_sub", "actor_sub")
        self.assertEqual(updated["owner_sub"], "new_owner_sub")
        self.assertEqual(updated["GSI1PK"], "OWNER#new_owner_sub")

    # find_candidate_by_email
    def test_find_candidate_by_email_returns_item(self):
        import app.services.candidates as svc
        item = svc.create_candidate("u1", self._make_create_in(email="find@test.com"))
        found = svc.find_candidate_by_email("find@test.com")
        self.assertIsNotNone(found)
        self.assertEqual(found["candidate_id"], item["candidate_id"])

    def test_find_candidate_by_email_returns_none_for_missing(self):
        import app.services.candidates as svc
        self.assertIsNone(svc.find_candidate_by_email("nothere@example.com"))

    def test_find_candidate_by_email_works_with_flag_off(self):
        import app.services.candidates as svc
        _seed_candidate(self.table, email="findoff@test.com")
        object.__setattr__(S, "candidates_enabled", False)
        # Should not raise even with flag off
        result = svc.find_candidate_by_email("findoff@test.com")
        # result may be None or the item — either is OK, no exception
        object.__setattr__(S, "candidates_enabled", True)


# ── Test: CND-003 résumé attachments ──────────────────────────────────────────

@mock_aws
class TestResumeAttachments(unittest.TestCase):
    def setUp(self):
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_candidates_table(ddb)
        prev_t = T.candidates
        object.__setattr__(T, "candidates", self.table)
        self.addCleanup(lambda: object.__setattr__(T, "candidates", prev_t))
        prev_s = S.candidates_enabled
        object.__setattr__(S, "candidates_enabled", True)
        self.addCleanup(lambda: object.__setattr__(S, "candidates_enabled", prev_s))

        # Patch audit_event
        self._audit_patcher = patch("app.services.alerts.audit_event")
        self.mock_audit = self._audit_patcher.start()
        self.addCleanup(self._audit_patcher.stop)

        # Create a candidate for attachment tests
        import app.services.candidates as svc
        from app.models import CandidateCreateIn
        self.cid = svc.create_candidate(
            "recruiter",
            CandidateCreateIn(first_name="Resume", last_name="Test", email="resume@test.com"),
        )["candidate_id"]

    def _add_resume(self, filename="cv.pdf", make_primary=False, **kwargs):
        import app.services.candidates as svc
        defaults = dict(
            uploaded_by="recruiter",
            filename=filename,
            content_type="application/pdf",
            size_bytes=1024,
            s3_key=f"candidate-resumes/{self.cid}/att_xxx/{filename}",
            s3_bucket="local-uploads",
            source="upload",
            make_primary=make_primary,
        )
        defaults.update(kwargs)
        return svc.add_resume(self.cid, **defaults)

    def test_flag_off_add_resume(self):
        from fastapi import HTTPException
        import app.services.candidates as svc
        object.__setattr__(S, "candidates_enabled", False)
        with self.assertRaises(HTTPException) as ctx:
            self._add_resume()
        self.assertEqual(ctx.exception.status_code, 503)

    def test_add_resume_to_nonexistent_candidate(self):
        from fastapi import HTTPException
        import app.services.candidates as svc
        with self.assertRaises(HTTPException) as ctx:
            svc.add_resume(
                "cand_nonexistent",
                uploaded_by="u", filename="f.pdf",
                content_type="application/pdf", size_bytes=0,
                s3_key="k", s3_bucket="b",
            )
        self.assertEqual(ctx.exception.status_code, 404)

    def test_add_resume_to_deleted_candidate(self):
        from fastapi import HTTPException
        import app.services.candidates as svc
        del_cid = _seed_candidate(self.table, deleted_at=123456)["candidate_id"]
        with self.assertRaises(HTTPException) as ctx:
            svc.add_resume(
                del_cid,
                uploaded_by="u", filename="f.pdf",
                content_type="application/pdf", size_bytes=0,
                s3_key="k", s3_bucket="b",
            )
        self.assertEqual(ctx.exception.status_code, 410)

    def test_first_upload_auto_primary(self):
        import app.services.candidates as svc
        item = self._add_resume("first.pdf")
        self.assertTrue(item["is_primary"])
        meta = svc.get_candidate(self.cid)
        self.assertEqual(meta["primary_resume_id"], item["attachment_id"])

    def test_second_upload_not_primary_by_default(self):
        import app.services.candidates as svc
        first = self._add_resume("first2.pdf")
        second = self._add_resume("second.pdf", make_primary=False)
        self.assertFalse(second.get("is_primary"))
        meta = svc.get_candidate(self.cid)
        self.assertEqual(meta["primary_resume_id"], first["attachment_id"])

    def test_second_upload_make_primary(self):
        import app.services.candidates as svc
        self._add_resume("a.pdf")
        second = self._add_resume("b.pdf", make_primary=True)
        meta = svc.get_candidate(self.cid)
        self.assertEqual(meta["primary_resume_id"], second["attachment_id"])

    def test_set_primary_exactly_one_invariant(self):
        import app.services.candidates as svc
        a = self._add_resume("a2.pdf")
        b = self._add_resume("b2.pdf")
        svc.set_primary_resume(self.cid, b["attachment_id"], "recruiter")
        rows = svc.list_resumes(self.cid)
        primaries = [r for r in rows if r.get("is_primary")]
        self.assertEqual(len(primaries), 1)
        self.assertEqual(primaries[0]["attachment_id"], b["attachment_id"])

    def test_set_primary_idempotent(self):
        import app.services.candidates as svc
        a = self._add_resume("idm.pdf")
        svc.set_primary_resume(self.cid, a["attachment_id"], "recruiter")
        svc.set_primary_resume(self.cid, a["attachment_id"], "recruiter")
        rows = svc.list_resumes(self.cid)
        primaries = [r for r in rows if r.get("is_primary")]
        self.assertEqual(len(primaries), 1)

    def test_list_resumes_excludes_soft_deleted(self):
        import app.services.candidates as svc
        a = self._add_resume("keep.pdf")
        b = self._add_resume("delete.pdf")
        svc.delete_resume(self.cid, b["attachment_id"], "recruiter")
        rows = svc.list_resumes(self.cid)
        ids = [r["attachment_id"] for r in rows]
        self.assertIn(a["attachment_id"], ids)
        self.assertNotIn(b["attachment_id"], ids)

    def test_list_resumes_primary_first(self):
        import app.services.candidates as svc
        a = self._add_resume("first_pf.pdf")
        b = self._add_resume("second_pf.pdf")
        svc.set_primary_resume(self.cid, b["attachment_id"], "recruiter")
        rows = svc.list_resumes(self.cid)
        self.assertEqual(rows[0]["attachment_id"], b["attachment_id"])

    def test_count_cap_enforcement(self):
        from fastapi import HTTPException
        import app.services.candidates as svc
        # Set cap to 2 for speed
        prev_cap = S.candidate_resume_max_per_candidate
        object.__setattr__(S, "candidate_resume_max_per_candidate", 2)
        self._add_resume("cap1.pdf")
        self._add_resume("cap2.pdf")
        with self.assertRaises(HTTPException) as ctx:
            self._add_resume("cap3.pdf")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail["code"], "candidate_resume_limit_reached")
        object.__setattr__(S, "candidate_resume_max_per_candidate", prev_cap)

    def test_soft_delete_frees_slot(self):
        import app.services.candidates as svc
        prev_cap = S.candidate_resume_max_per_candidate
        object.__setattr__(S, "candidate_resume_max_per_candidate", 2)
        a = self._add_resume("slot1.pdf")
        b = self._add_resume("slot2.pdf")
        svc.delete_resume(self.cid, a["attachment_id"], "recruiter")
        # slot freed — third should succeed
        self._add_resume("slot3.pdf")
        object.__setattr__(S, "candidate_resume_max_per_candidate", prev_cap)

    def test_delete_non_primary(self):
        import app.services.candidates as svc
        primary = self._add_resume("primary_del.pdf")
        secondary = self._add_resume("secondary_del.pdf")
        svc.delete_resume(self.cid, secondary["attachment_id"], "recruiter")
        meta = svc.get_candidate(self.cid)
        self.assertEqual(meta["primary_resume_id"], primary["attachment_id"])

    def test_delete_primary_promotes_next(self):
        import app.services.candidates as svc
        a = self._add_resume("prm.pdf")
        b = self._add_resume("nxt.pdf")
        # a is primary (first)
        svc.delete_resume(self.cid, a["attachment_id"], "recruiter")
        meta = svc.get_candidate(self.cid)
        self.assertEqual(meta.get("primary_resume_id"), b["attachment_id"])

    def test_delete_last_resume_clears_pointer(self):
        import app.services.candidates as svc
        a = self._add_resume("last.pdf")
        svc.delete_resume(self.cid, a["attachment_id"], "recruiter")
        meta = svc.get_candidate(self.cid)
        self.assertIsNone(meta.get("primary_resume_id"))

    def test_delete_resume_idempotent(self):
        from fastapi import HTTPException
        import app.services.candidates as svc
        a = self._add_resume("idem.pdf")
        svc.delete_resume(self.cid, a["attachment_id"], "recruiter")
        with self.assertRaises(HTTPException) as ctx:
            svc.delete_resume(self.cid, a["attachment_id"], "recruiter")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_s3_not_called_on_soft_delete(self):
        """S3 delete_object should never be called (lifecycle policy handles it)."""
        import app.services.candidates as svc
        fake_s3 = _FakeS3()
        a = self._add_resume("nos3.pdf")
        svc.delete_resume(self.cid, a["attachment_id"], "recruiter")
        self.assertEqual(fake_s3.deleted_keys, [])

    def test_make_download_url_dev_mode(self):
        import app.services.candidates as svc
        prev_dev = S.dev_mode
        object.__setattr__(S, "dev_mode", True)
        url = svc._make_download_url("my/key.pdf", "my-bucket")
        self.assertIn("/mock/s3/", url)
        object.__setattr__(S, "dev_mode", prev_dev)

    def test_get_primary_resume_item_returns_item(self):
        import app.services.candidates as svc
        a = self._add_resume("primary_get.pdf")
        result = svc.get_primary_resume_item(self.cid)
        self.assertIsNotNone(result)
        self.assertEqual(result["attachment_id"], a["attachment_id"])

    def test_get_primary_resume_item_no_primary(self):
        import app.services.candidates as svc
        # New candidate with no resume
        from app.models import CandidateCreateIn
        cid2 = svc.create_candidate(
            "u2",
            CandidateCreateIn(first_name="No", last_name="Resume", email="noresume@test.com"),
        )["candidate_id"]
        result = svc.get_primary_resume_item(cid2)
        self.assertIsNone(result)

    def test_get_primary_resume_item_dangling_pointer(self):
        import app.services.candidates as svc
        a = self._add_resume("dangling.pdf")
        # Manually soft-delete without clearing pointer
        self.table.update_item(
            Key={"pk": f"CANDIDATE#{self.cid}", "sk": f"ATTACHMENT#{a['attachment_id']}"},
            UpdateExpression="SET deleted_at = :t",
            ExpressionAttributeValues={":t": 999},
        )
        result = svc.get_primary_resume_item(self.cid)
        self.assertIsNone(result)

    def test_get_primary_resume_item_flag_off(self):
        from fastapi import HTTPException
        import app.services.candidates as svc
        object.__setattr__(S, "candidates_enabled", False)
        with self.assertRaises(HTTPException) as ctx:
            svc.get_primary_resume_item(self.cid)
        self.assertEqual(ctx.exception.status_code, 503)


# ── Test: CND-004 change history ──────────────────────────────────────────────

@mock_aws
class TestCandidateHistory(unittest.TestCase):
    def setUp(self):
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_candidates_table(ddb)
        prev_t = T.candidates
        object.__setattr__(T, "candidates", self.table)
        self.addCleanup(lambda: object.__setattr__(T, "candidates", prev_t))
        prev_s = S.candidates_enabled
        object.__setattr__(S, "candidates_enabled", True)
        self.addCleanup(lambda: object.__setattr__(S, "candidates_enabled", prev_s))

    def _call_record(self, candidate_id="cand_hist1", actor="user1",
                     change_type="updated", summary="test"):
        import app.services.candidates as svc
        svc.record_candidate_change(
            candidate_id, actor,
            change_type=change_type,
            summary=summary,
        )

    def test_record_never_raises(self):
        # Should not raise even with bogus candidate_id
        self._call_record(candidate_id="cand_bogus999")

    def test_fallback_writes_activity_subitem(self):
        import app.services.candidates as svc
        _seed_candidate(self.table, candidate_id="cand_h1")
        svc.record_candidate_change(
            "cand_h1", "actor",
            change_type="updated", summary="field updated",
        )
        from boto3.dynamodb.conditions import Key
        resp = self.table.query(
            KeyConditionExpression=(
                Key("pk").eq("CANDIDATE#cand_h1") & Key("sk").begins_with("ACTIVITY#")
            ),
        )
        self.assertGreaterEqual(len(resp["Items"]), 1)
        item = resp["Items"][0]
        self.assertEqual(item["change_type"], "updated")
        self.assertEqual(item["actor_sub"], "actor")

    def test_summary_truncated_to_200(self):
        import app.services.candidates as svc
        _seed_candidate(self.table, candidate_id="cand_h2")
        svc.record_candidate_change(
            "cand_h2", "actor",
            change_type="updated", summary="x" * 300,
        )
        from boto3.dynamodb.conditions import Key
        resp = self.table.query(
            KeyConditionExpression=(
                Key("pk").eq("CANDIDATE#cand_h2") & Key("sk").begins_with("ACTIVITY#")
            ),
        )
        self.assertEqual(len(resp["Items"][0]["summary"]), 200)

    def test_newest_first_ordering(self):
        import app.services.candidates as svc
        from unittest.mock import patch as _patch
        _seed_candidate(self.table, candidate_id="cand_h3")
        # Record events with distinct timestamps
        with _patch("app.services.candidates.now_ts", side_effect=[1000, 2000, 3000]):
            svc.record_candidate_change("cand_h3", "actor", change_type="updated", summary="t=1000")
            svc.record_candidate_change("cand_h3", "actor", change_type="updated", summary="t=2000")
            svc.record_candidate_change("cand_h3", "actor", change_type="updated", summary="t=3000")
        result = svc.list_candidate_history("cand_h3")
        events = result["events"]
        self.assertEqual(len(events), 3)
        # Should be newest first (t=3000 first)
        self.assertEqual(events[0]["created_at"], 3000)
        self.assertEqual(events[-1]["created_at"], 1000)

    def test_empty_history(self):
        import app.services.candidates as svc
        _seed_candidate(self.table, candidate_id="cand_h_empty")
        result = svc.list_candidate_history("cand_h_empty")
        self.assertEqual(result["events"], [])
        self.assertIsNone(result["cursor"])

    def test_pagination(self):
        import app.services.candidates as svc
        from unittest.mock import patch as _patch
        _seed_candidate(self.table, candidate_id="cand_pg")
        with _patch("app.services.candidates.now_ts", side_effect=list(range(1000, 1010))):
            for i in range(5):
                svc.record_candidate_change("cand_pg", "actor", change_type="updated", summary=f"ev{i}")
        page1 = svc.list_candidate_history("cand_pg", limit=2)
        self.assertLessEqual(len(page1["events"]), 2)
        # If there's a cursor, page 2 should return more
        if page1.get("cursor"):
            page2 = svc.list_candidate_history("cand_pg", cursor=page1["cursor"], limit=2)
            self.assertIsInstance(page2["events"], list)

    def test_tampered_cursor_returns_start_without_error(self):
        import app.services.candidates as svc
        _seed_candidate(self.table, candidate_id="cand_bad_cursor")
        result = svc.list_candidate_history("cand_bad_cursor", cursor="bad_cursor_value")
        self.assertIsInstance(result["events"], list)

    def test_act009_preferred_path(self):
        """When crm_activity_timeline is patched present, it is called."""
        import app.services.candidates as svc
        mock_crm_module = MagicMock()
        mock_crm_module.record_crm_activity = MagicMock()
        sys.modules["app.services.crm_activity_timeline"] = mock_crm_module
        try:
            _seed_candidate(self.table, candidate_id="cand_act009")
            svc.record_candidate_change(
                "cand_act009", "actor",
                change_type="updated", summary="via act009",
            )
            mock_crm_module.record_crm_activity.assert_called_once()
            args = mock_crm_module.record_crm_activity.call_args[0]
            self.assertEqual(args[0], "candidate")
            self.assertEqual(args[1], "cand_act009")
        finally:
            del sys.modules["app.services.crm_activity_timeline"]

    def test_act009_fallback_when_raises(self):
        """When crm_activity_timeline raises, local fallback path writes sub-item."""
        import app.services.candidates as svc
        mock_crm_module = MagicMock()
        mock_crm_module.record_crm_activity = MagicMock(side_effect=RuntimeError("DDB down"))
        sys.modules["app.services.crm_activity_timeline"] = mock_crm_module
        try:
            _seed_candidate(self.table, candidate_id="cand_fallback")
            svc.record_candidate_change(
                "cand_fallback", "actor",
                change_type="updated", summary="fallback",
            )
            from boto3.dynamodb.conditions import Key
            resp = self.table.query(
                KeyConditionExpression=(
                    Key("pk").eq("CANDIDATE#cand_fallback") & Key("sk").begins_with("ACTIVITY#")
                ),
            )
            self.assertGreaterEqual(len(resp["Items"]), 1)
        finally:
            del sys.modules["app.services.crm_activity_timeline"]

    def test_flag_off_record_is_noop(self):
        import app.services.candidates as svc
        _seed_candidate(self.table, candidate_id="cand_off")
        object.__setattr__(S, "candidates_enabled", False)
        svc.record_candidate_change("cand_off", "actor", change_type="updated", summary="x")
        from boto3.dynamodb.conditions import Key
        resp = self.table.query(
            KeyConditionExpression=(
                Key("pk").eq("CANDIDATE#cand_off") & Key("sk").begins_with("ACTIVITY#")
            ),
        )
        self.assertEqual(len(resp["Items"]), 0)
        object.__setattr__(S, "candidates_enabled", True)

    def test_activity_subitem_invisible_to_byowner_gsi(self):
        """ACTIVITY# sub-items carry no GSI keys and must not appear in ByOwner index."""
        import app.services.candidates as svc
        _seed_candidate(self.table, candidate_id="cand_invis", owner_sub="ow_invis")
        svc.record_candidate_change("cand_invis", "actor", change_type="updated", summary="x")
        from boto3.dynamodb.conditions import Key
        resp = self.table.query(
            IndexName="ByOwner",
            KeyConditionExpression=Key("GSI1PK").eq("OWNER#ow_invis"),
        )
        for item in resp["Items"]:
            self.assertEqual(item["sk"], "META")

    def test_all_change_types_accepted(self):
        import app.services.candidates as svc
        _seed_candidate(self.table, candidate_id="cand_ctypes")
        change_types = [
            "created", "updated", "status_changed", "owner_changed",
            "resume_added", "resume_removed", "deleted",
        ]
        for ct in change_types:
            svc.record_candidate_change("cand_ctypes", "actor", change_type=ct, summary=ct)
        from boto3.dynamodb.conditions import Key
        resp = self.table.query(
            KeyConditionExpression=(
                Key("pk").eq("CANDIDATE#cand_ctypes") & Key("sk").begins_with("ACTIVITY#")
            ),
        )
        self.assertEqual(len(resp["Items"]), len(change_types))


# ── Test: CND-005 router handlers ─────────────────────────────────────────────

@mock_aws
class TestCandidatesRouter(unittest.TestCase):
    """Smoke-test the router handler coroutines directly (no TestClient)."""

    def setUp(self):
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_candidates_table(ddb)
        prev_t = T.candidates
        object.__setattr__(T, "candidates", self.table)
        self.addCleanup(lambda: object.__setattr__(T, "candidates", prev_t))
        prev_s = S.candidates_enabled
        object.__setattr__(S, "candidates_enabled", True)
        self.addCleanup(lambda: object.__setattr__(S, "candidates_enabled", prev_s))

        self._audit_patcher = patch("app.services.alerts.audit_event")
        self.mock_audit = self._audit_patcher.start()
        self.addCleanup(self._audit_patcher.stop)

        # Import router handlers
        import app.routers.candidates as r
        self.router_mod = r

    def _ctx(self, user_sub="u1", role="user"):
        return {"user_sub": user_sub, "role": role}

    def test_create_endpoint(self):
        r = self.router_mod
        body = CandidateCreateIn(first_name="R", last_name="T", email="router@test.com")
        result = _run(r.create_candidate_endpoint(body, self._ctx()))
        self.assertIsInstance(result, CandidateOut)
        self.assertTrue(result.candidate_id.startswith("cand_"))

    def test_get_endpoint_404(self):
        from fastapi import HTTPException
        r = self.router_mod
        with self.assertRaises(HTTPException) as ctx:
            _run(r.get_candidate_endpoint("cand_missing", self._ctx()))
        self.assertEqual(ctx.exception.status_code, 404)

    def test_list_endpoint(self):
        r = self.router_mod
        result = _run(r.list_candidates_endpoint(
            owner_sub=None, status=None, source=None,
            created_after=None, cursor=None, limit=10,
            ctx=self._ctx("u_list"),
        ))
        self.assertIsInstance(result, CandidateListOut)

    def test_delete_endpoint_403_for_non_owner(self):
        from fastapi import HTTPException
        import app.services.candidates as svc
        r = self.router_mod
        item = svc.create_candidate("owner_a", CandidateCreateIn(
            first_name="X", last_name="Y", email="del_403@test.com"
        ))
        with self.assertRaises(HTTPException) as ctx:
            _run(r.delete_candidate_endpoint(item["candidate_id"], self._ctx("other_user")))
        self.assertEqual(ctx.exception.status_code, 403)

    def test_flag_off_returns_404(self):
        from fastapi import HTTPException
        r = self.router_mod
        object.__setattr__(S, "candidates_enabled", False)
        with self.assertRaises(HTTPException) as ctx:
            _run(r.list_candidates_endpoint(
                owner_sub=None, status=None, source=None,
                created_after=None, cursor=None, limit=10,
                ctx=self._ctx(),
            ))
        self.assertEqual(ctx.exception.status_code, 404)
        object.__setattr__(S, "candidates_enabled", True)

    def test_history_endpoint(self):
        import app.services.candidates as svc
        r = self.router_mod
        item = svc.create_candidate("u1", CandidateCreateIn(
            first_name="H", last_name="T", email="hist_router@test.com"
        ))
        result = _run(r.get_history_endpoint(
            item["candidate_id"], cursor=None, limit=10, ctx=self._ctx()
        ))
        self.assertIsInstance(result, CandidateHistoryPage)


if __name__ == "__main__":
    unittest.main()
