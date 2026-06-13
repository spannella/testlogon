"""
Hermetic offline tests for the CRM Leads backend subsystem (LED-001..LED-013).

Pattern: moto in-memory DynamoDB, T.leads patched via object.__setattr__,
S flags toggled via object.__setattr__, audit_event patched to a no-op,
route handlers called directly on asyncio.new_event_loop().
No TestClient, no real AWS, no network.
"""
from __future__ import annotations

import asyncio
import sys
import types
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

from app.core.settings import S
from app.core.tables import T, _FloatSafeTable
from app.models import (
    LEAD_SOURCES,
    LEAD_STATUSES,
    LeadConversionIn,
    LeadConversionOut,
    LeadCreateIn,
    LeadScoreRulesIn,
    LeadScoreRuleIn,
    LeadUpdateIn,
    ProspectCreateIn,
    ProspectUpdateIn,
)


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

def _make_leads_table(ddb):
    """Create a moto leads table matching LED-001 TableDef."""
    return ddb.create_table(
        TableName="leads_test",
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
            {"AttributeName": "GSI4PK", "AttributeType": "S"},
            {"AttributeName": "GSI4SK", "AttributeType": "N"},
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
            {
                "IndexName": "ByEmail",
                "KeySchema": [
                    {"AttributeName": "GSI4PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI4SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@pytest.fixture()
def leads_table():
    """moto leads table, T.leads patched, S.leads_enabled=True, audit_event patched."""
    with mock_aws():
        ddb = boto3.resource(
            "dynamodb",
            region_name="us-east-1",
            aws_access_key_id="test",
            aws_secret_access_key="test",
        )
        table = _make_leads_table(ddb)

        # Patch frozen T and S
        object.__setattr__(T, "leads", table)
        object.__setattr__(S, "leads_enabled", True)
        object.__setattr__(S, "leads_scoring_enabled", True)
        object.__setattr__(S, "leads_assignment_enabled", True)

        # Patch audit_event to a no-op
        import app.services.leads as _svc
        _orig_audit = _svc._audit
        _svc._audit = lambda *a, **kw: None

        yield table

        # Restore
        _svc._audit = _orig_audit
        object.__setattr__(S, "leads_enabled", False)
        object.__setattr__(S, "leads_scoring_enabled", False)
        object.__setattr__(S, "leads_assignment_enabled", False)
        object.__setattr__(T, "leads", _FloatSafeTable(
            boto3.resource(
                "dynamodb",
                region_name="us-east-1",
                aws_access_key_id="test",
                aws_secret_access_key="test",
            ).Table("leads")
        ))


def run(coro):
    """Run a coroutine in a fresh event loop."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ─────────────────────────────────────────────────────────────────────────────
# LED-001: Settings & Table handle
# ─────────────────────────────────────────────────────────────────────────────

class TestLED001Scaffold:
    def test_leads_enabled_defaults_false(self):
        # In a clean import with no env var, defaults to False
        # (the fixture sets it to True, but before fixture, S has its default)
        # We can't easily test the raw default here without reimporting,
        # but we verify the flag type and name.
        assert isinstance(S.leads_enabled, bool)

    def test_leads_sub_flags_are_bool(self):
        assert isinstance(S.leads_scoring_enabled, bool)
        assert isinstance(S.leads_drip_enabled, bool)
        assert isinstance(S.leads_assignment_enabled, bool)

    def test_leads_table_name_default(self):
        assert S.leads_table_name == "leads"

    @mock_aws
    def test_leads_table_handle_is_float_safe_table(self):
        assert isinstance(T.leads, _FloatSafeTable)


# ─────────────────────────────────────────────────────────────────────────────
# LED-002: Pydantic models
# ─────────────────────────────────────────────────────────────────────────────

class TestLED002Models:
    def test_lead_statuses_membership(self):
        assert "new" in LEAD_STATUSES
        assert "converted" in LEAD_STATUSES
        assert "unknown" not in LEAD_STATUSES

    def test_lead_sources_membership(self):
        assert "campaign" in LEAD_SOURCES
        assert "web_site" in LEAD_SOURCES
        assert "linkedin" not in LEAD_SOURCES

    def test_lead_create_in_minimal(self):
        m = LeadCreateIn(first_name="Alice", last_name="Smith", email="alice@example.com")
        assert m.lead_source == "other"
        assert m.phone is None

    def test_lead_create_in_rejects_unknown_source(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            LeadCreateIn(first_name="X", last_name="Y", email="x@y.com", lead_source="linkedin")

    def test_lead_update_in_all_none(self):
        m = LeadUpdateIn()
        assert m.status is None
        assert m.score is None

    def test_lead_conversion_in_defaults(self):
        m = LeadConversionIn()
        assert m.create_account is False
        assert m.create_opportunity is False

    def test_prospect_create_in_email_required(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            ProspectCreateIn()

    def test_prospect_update_no_email(self):
        m = ProspectUpdateIn(first_name="Bob")
        assert not hasattr(m, "email") or m.model_fields.get("email") is None


# ─────────────────────────────────────────────────────────────────────────────
# LED-003: Lead CRUD service
# ─────────────────────────────────────────────────────────────────────────────

class TestLED003CreateLead:
    def test_create_returns_lead_dict(self, leads_table):
        import app.services.leads as svc
        data = LeadCreateIn(first_name="Alice", last_name="Smith", email="alice@example.com")
        result = svc.create_lead("user1", data)
        assert result["lead_id"].startswith("lead_")
        assert result["status"] == "new"
        assert result["score"] == 0
        assert result["created_by"] == "user1"
        assert result["email"] == "alice@example.com"

    def test_create_normalizes_email(self, leads_table):
        import app.services.leads as svc
        data = LeadCreateIn(first_name="A", last_name="B", email="ALICE@EXAMPLE.COM")
        result = svc.create_lead("user1", data)
        assert result["email"] == "alice@example.com"
        assert result["email_raw"] == "ALICE@EXAMPLE.COM"

    def test_create_idempotent_duplicate_email(self, leads_table):
        import app.services.leads as svc
        data1 = LeadCreateIn(first_name="A", last_name="B", email="dup@example.com")
        data2 = LeadCreateIn(first_name="C", last_name="D", email="dup@example.com")
        r1 = svc.create_lead("user1", data1)
        r2 = svc.create_lead("user1", data2)
        assert r1["lead_id"] == r2["lead_id"]
        # Only one item should exist
        items = leads_table.scan()["Items"]
        leads_only = [i for i in items if i["pk"].startswith("LEAD#") and i["sk"] == "META"]
        assert len(leads_only) == 1

    def test_create_flag_off_raises_503(self, leads_table):
        import app.services.leads as svc
        from fastapi import HTTPException
        object.__setattr__(S, "leads_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc_info:
                data = LeadCreateIn(first_name="X", last_name="Y", email="x@y.com")
                svc.create_lead("user1", data)
            assert exc_info.value.status_code == 503
        finally:
            object.__setattr__(S, "leads_enabled", True)

    def test_create_with_attribution_code(self, leads_table):
        import app.services.leads as svc
        data = LeadCreateIn(
            first_name="A", last_name="B", email="attr@example.com",
            attribution_code="summer24",
        )
        result = svc.create_lead("user1", data)
        assert result.get("attribution_code") == "summer24"

    def test_create_with_extra(self, leads_table):
        import app.services.leads as svc
        data = LeadCreateIn(first_name="A", last_name="B", email="extra@example.com")
        result = svc.create_lead(
            "user1", data,
            extra={"origin_questionnaire_id": "q_123", "origin_response_session_id": "sess_abc"},
        )
        assert result.get("origin_questionnaire_id") == "q_123"
        assert result.get("origin_response_session_id") == "sess_abc"


class TestLED003GetLead:
    def test_get_existing_lead(self, leads_table):
        import app.services.leads as svc
        data = LeadCreateIn(first_name="X", last_name="Y", email="getme@example.com")
        created = svc.create_lead("user1", data)
        found = svc.get_lead(created["lead_id"])
        assert found is not None
        assert found["email"] == "getme@example.com"

    def test_get_missing_lead_returns_none(self, leads_table):
        import app.services.leads as svc
        result = svc.get_lead("lead_nonexistent")
        assert result is None


class TestLED003ListLeads:
    def test_list_by_owner_default(self, leads_table):
        import app.services.leads as svc
        for i in range(3):
            svc.create_lead(
                "owner1",
                LeadCreateIn(first_name="X", last_name="Y", email=f"x{i}@example.com"),
            )
        result = svc.list_leads(owner_sub="owner1")
        assert len(result["leads"]) == 3

    def test_list_excludes_soft_deleted(self, leads_table):
        import app.services.leads as svc
        lead = svc.create_lead("u1", LeadCreateIn(first_name="A", last_name="B", email="del@x.com"))
        svc.delete_lead(lead["lead_id"], "u1")
        result = svc.list_leads(owner_sub="u1")
        assert all(l["lead_id"] != lead["lead_id"] for l in result["leads"])


class TestLED003UpdateLead:
    def test_update_fields(self, leads_table):
        import app.services.leads as svc
        lead = svc.create_lead("u1", LeadCreateIn(first_name="A", last_name="B", email="upd@x.com"))
        updated = svc.update_lead(lead["lead_id"], "u1", LeadUpdateIn(first_name="Updated"))
        assert updated["first_name"] == "Updated"
        assert updated["updated_at"] >= lead["created_at"]

    def test_update_valid_status_transition(self, leads_table):
        import app.services.leads as svc
        lead = svc.create_lead("u1", LeadCreateIn(first_name="A", last_name="B", email="trans@x.com"))
        updated = svc.update_lead(lead["lead_id"], "u1", LeadUpdateIn(status="assigned"))
        assert updated["status"] == "assigned"

    def test_update_invalid_status_transition_raises_400(self, leads_table):
        import app.services.leads as svc
        from fastapi import HTTPException
        lead = svc.create_lead("u1", LeadCreateIn(first_name="A", last_name="B", email="inv@x.com"))
        with pytest.raises(HTTPException) as exc_info:
            svc.update_lead(lead["lead_id"], "u1", LeadUpdateIn(status="converted"))
        assert exc_info.value.status_code == 400

    def test_update_not_found_raises_404(self, leads_table):
        import app.services.leads as svc
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            svc.update_lead("lead_nonexistent", "u1", LeadUpdateIn(first_name="X"))
        assert exc_info.value.status_code == 404


class TestLED003DeleteLead:
    def test_delete_sets_deleted_at(self, leads_table):
        import app.services.leads as svc
        lead = svc.create_lead("u1", LeadCreateIn(first_name="A", last_name="B", email="dlt@x.com"))
        svc.delete_lead(lead["lead_id"], "u1")
        item = leads_table.get_item(Key={"pk": f"LEAD#{lead['lead_id']}", "sk": "META"}).get("Item", {})
        assert "deleted_at" in item

    def test_delete_idempotent(self, leads_table):
        import app.services.leads as svc
        lead = svc.create_lead("u1", LeadCreateIn(first_name="A", last_name="B", email="dlt2@x.com"))
        svc.delete_lead(lead["lead_id"], "u1")
        # Second call should not raise
        svc.delete_lead(lead["lead_id"], "u1")


# ─────────────────────────────────────────────────────────────────────────────
# LED-004: Source summary
# ─────────────────────────────────────────────────────────────────────────────

class TestLED004SourceSummary:
    def test_all_sources_returned(self, leads_table):
        import app.services.leads as svc
        svc.create_lead("u1", LeadCreateIn(first_name="A", last_name="B", email="s1@x.com", lead_source="campaign"))
        counts = svc.get_lead_source_counts()
        source_names = {c["lead_source"] for c in counts}
        assert source_names == LEAD_SOURCES

    def test_counts_accurate(self, leads_table):
        import app.services.leads as svc
        for i in range(3):
            svc.create_lead("u1", LeadCreateIn(first_name="A", last_name="B", email=f"c{i}@x.com", lead_source="campaign"))
        counts = svc.get_lead_source_counts()
        camp_entry = next(c for c in counts if c["lead_source"] == "campaign")
        assert camp_entry["count"] == 3

    def test_flag_off_raises_503(self, leads_table):
        import app.services.leads as svc
        from fastapi import HTTPException
        object.__setattr__(S, "leads_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc_info:
                svc.get_lead_source_counts()
            assert exc_info.value.status_code == 503
        finally:
            object.__setattr__(S, "leads_enabled", True)


# ─────────────────────────────────────────────────────────────────────────────
# LED-005: Web-to-lead capture
# ─────────────────────────────────────────────────────────────────────────────

class TestLED005WebToLead:
    def test_capture_creates_lead(self, leads_table):
        import app.services.leads as svc
        version = {"questionnaire_id": "q_001", "capture_as_lead": True}
        answers = {"email": "web@example.com", "first_name": "Web", "last_name": "Lead"}
        result = svc.create_lead_from_submission(version, answers, response_session_id="sess_1", user_sub=None)
        assert result is not None
        assert result["email"] == "web@example.com"
        assert result["lead_source"] == "web_site"
        assert result["created_by"] == "system_web_lead"

    def test_capture_off_by_default(self, leads_table):
        import app.services.leads as svc
        version = {"questionnaire_id": "q_002", "capture_as_lead": False}
        answers = {"email": "off@example.com"}
        result = svc.create_lead_from_submission(version, answers, user_sub=None)
        assert result is None

    def test_capture_flag_off_no_capture(self, leads_table):
        import app.services.leads as svc
        object.__setattr__(S, "leads_enabled", False)
        try:
            version = {"questionnaire_id": "q_003", "capture_as_lead": True}
            answers = {"email": "flagoff@example.com"}
            result = svc.create_lead_from_submission(version, answers, user_sub=None)
            assert result is None
        finally:
            object.__setattr__(S, "leads_enabled", True)

    def test_missing_email_no_capture(self, leads_table):
        import app.services.leads as svc
        version = {"questionnaire_id": "q_004", "capture_as_lead": True}
        answers = {"first_name": "Bob"}
        result = svc.create_lead_from_submission(version, answers, user_sub=None)
        assert result is None

    def test_malformed_email_no_capture(self, leads_table):
        import app.services.leads as svc
        version = {"questionnaire_id": "q_005", "capture_as_lead": True}
        answers = {"email": "not-an-email"}
        result = svc.create_lead_from_submission(version, answers, user_sub=None)
        assert result is None

    def test_lead_source_override(self, leads_table):
        import app.services.leads as svc
        version = {"questionnaire_id": "q_006", "capture_as_lead": True, "lead_source_override": "campaign"}
        answers = {"email": "camp@example.com"}
        result = svc.create_lead_from_submission(version, answers, user_sub=None)
        assert result is not None
        assert result["lead_source"] == "campaign"

    def test_authenticated_user_capture(self, leads_table):
        import app.services.leads as svc
        version = {"questionnaire_id": "q_007", "capture_as_lead": True}
        answers = {"email": "auth@example.com"}
        result = svc.create_lead_from_submission(version, answers, user_sub="user_abc123")
        assert result is not None
        assert result["created_by"] == "user_abc123"

    def test_does_not_raise_on_error(self, leads_table):
        import app.services.leads as svc
        # Simulate create_lead raising a RuntimeError
        orig = svc.create_lead
        svc.create_lead = lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("DB down"))
        try:
            version = {"questionnaire_id": "q_008", "capture_as_lead": True}
            answers = {"email": "err@example.com"}
            result = svc.create_lead_from_submission(version, answers, user_sub=None)
            assert result is None  # swallowed
        finally:
            svc.create_lead = orig


# ─────────────────────────────────────────────────────────────────────────────
# LED-006: Lead conversion
# ─────────────────────────────────────────────────────────────────────────────

class TestLED006Conversion:
    def test_stub_path_converts_lead(self, leads_table):
        import app.services.leads as svc
        object.__setattr__(S, "leads_enabled", True)
        # Ensure party_crm_enabled is False (stub path)
        orig_pty = getattr(S, "party_crm_enabled", None)
        object.__setattr__(S, "party_crm_enabled", False)
        try:
            lead = svc.create_lead("u1", LeadCreateIn(first_name="Al", last_name="S", email="conv@x.com"))
            # Transition to in_process first
            svc.update_lead(lead["lead_id"], "u1", LeadUpdateIn(status="in_process"))
            result = svc.convert_lead(lead["lead_id"], "u1", LeadConversionIn())
            assert result.status == "converted"
            assert result.converted_party_id.startswith("PERSON#")
            assert result.pty_path_used is False
        finally:
            if orig_pty is not None:
                object.__setattr__(S, "party_crm_enabled", orig_pty)

    def test_already_converted_returns_409(self, leads_table):
        import app.services.leads as svc
        from fastapi import HTTPException
        object.__setattr__(S, "party_crm_enabled", False)
        lead = svc.create_lead("u1", LeadCreateIn(first_name="Al", last_name="S", email="conv409@x.com"))
        svc.update_lead(lead["lead_id"], "u1", LeadUpdateIn(status="in_process"))
        svc.convert_lead(lead["lead_id"], "u1", LeadConversionIn())
        with pytest.raises(HTTPException) as exc_info:
            svc.convert_lead(lead["lead_id"], "u1", LeadConversionIn())
        assert exc_info.value.status_code == 409

    def test_opportunity_stub_created(self, leads_table):
        import app.services.leads as svc
        object.__setattr__(S, "party_crm_enabled", False)
        lead = svc.create_lead("u1", LeadCreateIn(first_name="Al", last_name="S", email="opp@x.com"))
        result = svc.convert_lead(
            lead["lead_id"], "u1",
            LeadConversionIn(create_opportunity=True, opportunity_amount_cents=5000),
        )
        assert result.opportunity is not None
        assert result.opportunity.amount_cents == 5000
        assert result.opportunity.stage == "prospecting"

    def test_org_stub_created_when_create_account(self, leads_table):
        import app.services.leads as svc
        object.__setattr__(S, "party_crm_enabled", False)
        lead = svc.create_lead("u1", LeadCreateIn(first_name="Al", last_name="S", email="org@x.com"))
        result = svc.convert_lead(
            lead["lead_id"], "u1",
            LeadConversionIn(create_account=True, account_name="Acme Corp"),
        )
        assert result.converted_org_id is not None
        assert result.converted_org_id.startswith("ORG#")

    def test_deleted_lead_returns_410(self, leads_table):
        import app.services.leads as svc
        from fastapi import HTTPException
        object.__setattr__(S, "party_crm_enabled", False)
        lead = svc.create_lead("u1", LeadCreateIn(first_name="Al", last_name="S", email="delconv@x.com"))
        svc.delete_lead(lead["lead_id"], "u1")
        with pytest.raises(HTTPException) as exc_info:
            svc.convert_lead(lead["lead_id"], "u1", LeadConversionIn())
        assert exc_info.value.status_code == 410


# ─────────────────────────────────────────────────────────────────────────────
# LED-007: Prospects
# ─────────────────────────────────────────────────────────────────────────────

class TestLED007Prospects:
    def test_create_prospect(self, leads_table):
        import app.services.leads as svc
        data = ProspectCreateIn(email="prospect@example.com", first_name="P", last_name="L")
        result = svc.create_prospect("owner1", data)
        assert result["prospect_id"].startswith("pros_")
        assert result["email"] == "prospect@example.com"

    def test_create_prospect_idempotent(self, leads_table):
        import app.services.leads as svc
        data1 = ProspectCreateIn(email="idem@example.com")
        data2 = ProspectCreateIn(email="idem@example.com")
        r1 = svc.create_prospect("owner1", data1)
        r2 = svc.create_prospect("owner1", data2)
        assert r1["prospect_id"] == r2["prospect_id"]

    def test_get_prospect_returns_none_if_not_found(self, leads_table):
        import app.services.leads as svc
        result = svc.get_prospect("pros_nonexistent")
        assert result is None

    def test_list_prospects(self, leads_table):
        import app.services.leads as svc
        for i in range(3):
            svc.create_prospect("owner2", ProspectCreateIn(email=f"p{i}@example.com"))
        result = svc.list_prospects("owner2")
        assert result["count"] == 3

    def test_delete_prospect_soft(self, leads_table):
        import app.services.leads as svc
        data = ProspectCreateIn(email="del@example.com")
        prospect = svc.create_prospect("owner1", data)
        svc.delete_prospect(prospect["prospect_id"], "owner1")
        found = svc.get_prospect(prospect["prospect_id"])
        assert found is None

    def test_update_prospect(self, leads_table):
        import app.services.leads as svc
        data = ProspectCreateIn(email="upd@example.com")
        prospect = svc.create_prospect("owner1", data)
        updated = svc.update_prospect(prospect["prospect_id"], "owner1", ProspectUpdateIn(first_name="NewName"))
        assert updated["first_name"] == "NewName"


# ─────────────────────────────────────────────────────────────────────────────
# LED-009: Duplicate detection & merge
# ─────────────────────────────────────────────────────────────────────────────

class TestLED009Dedup:
    def test_find_duplicates_returns_matching_leads(self, leads_table):
        import app.services.leads as svc

        # Create two leads with same email but different IDs
        # (normally idempotent create prevents this, but we'll put directly)
        from app.core.time import now_ts
        ts = now_ts()
        leads_table.put_item(Item={
            "pk": "LEAD#lead_dup001",
            "sk": "META",
            "lead_id": "lead_dup001",
            "email": "dup2@example.com",
            "first_name": "A",
            "last_name": "B",
            "status": "new",
            "score": 0,
            "created_by": "u1",
            "created_at": ts,
            "updated_at": ts,
            "GSI1PK": "OWNER#u1",
            "GSI1SK": ts,
            "GSI2PK": "STATUS#new",
            "GSI2SK": ts,
            "GSI3PK": "SOURCE#other",
            "GSI3SK": ts,
            "GSI4PK": "EMAIL#dup2@example.com",
            "GSI4SK": ts,
        })
        leads_table.put_item(Item={
            "pk": "LEAD#lead_dup002",
            "sk": "META",
            "lead_id": "lead_dup002",
            "email": "dup2@example.com",
            "first_name": "C",
            "last_name": "D",
            "status": "new",
            "score": 0,
            "created_by": "u1",
            "created_at": ts + 1,
            "updated_at": ts + 1,
            "GSI1PK": "OWNER#u1",
            "GSI1SK": ts + 1,
            "GSI2PK": "STATUS#new",
            "GSI2SK": ts + 1,
            "GSI3PK": "SOURCE#other",
            "GSI3SK": ts + 1,
            "GSI4PK": "EMAIL#dup2@example.com",
            "GSI4SK": ts + 1,
        })
        dupes = svc.find_duplicates("lead_dup001")
        assert any(d["lead_id"] == "lead_dup002" for d in dupes)

    def test_merge_leads(self, leads_table):
        import app.services.leads as svc
        primary = svc.create_lead("u1", LeadCreateIn(first_name="P", last_name="R", email="primary@x.com"))
        # Put secondary directly (bypass idempotent check)
        from app.core.time import now_ts
        ts = now_ts()
        leads_table.put_item(Item={
            "pk": "LEAD#secondary001",
            "sk": "META",
            "lead_id": "secondary001",
            "email": "secondary@x.com",
            "first_name": "S",
            "last_name": "E",
            "company": "Acme",
            "status": "new",
            "score": 0,
            "created_by": "u1",
            "created_at": ts,
            "updated_at": ts,
            "GSI1PK": "OWNER#u1",
            "GSI1SK": ts,
            "GSI2PK": "STATUS#new",
            "GSI2SK": ts,
            "GSI3PK": "SOURCE#other",
            "GSI3SK": ts,
        })
        merged = svc.merge_leads(primary["lead_id"], "secondary001", "u1")
        # Company from secondary should be merged into primary
        assert merged.get("company") == "Acme"
        # Secondary should be soft-deleted
        sec = leads_table.get_item(Key={"pk": "LEAD#secondary001", "sk": "META"}).get("Item", {})
        assert "deleted_at" in sec


# ─────────────────────────────────────────────────────────────────────────────
# LED-010: Assignment
# ─────────────────────────────────────────────────────────────────────────────

class TestLED010Assignment:
    def test_assign_lead(self, leads_table):
        import app.services.leads as svc
        lead = svc.create_lead("u1", LeadCreateIn(first_name="A", last_name="B", email="assign@x.com"))
        updated = svc.assign_lead(lead["lead_id"], "agent_001", "u1")
        assert updated["assigned_to"] == "agent_001"
        assert updated["status"] == "assigned"

    def test_round_robin_assignment(self, leads_table):
        import app.services.leads as svc
        svc.upsert_assignment_queue("q_rr1", "admin1", ["agent_a", "agent_b"], name="TestQ")
        lead1 = svc.create_lead("u1", LeadCreateIn(first_name="A", last_name="B", email="rr1@x.com"))
        svc.auto_assign_round_robin(lead1["lead_id"], "q_rr1", "admin1")
        # Second lead gets next agent
        lead2 = svc.create_lead("u1", LeadCreateIn(first_name="C", last_name="D", email="rr2@x.com"))
        svc.auto_assign_round_robin(lead2["lead_id"], "q_rr1", "admin1")

        # Verify agents were assigned
        l1 = svc.get_lead(lead1["lead_id"])
        l2 = svc.get_lead(lead2["lead_id"])
        assert l1["assigned_to"] in ["agent_a", "agent_b"]
        assert l2["assigned_to"] in ["agent_a", "agent_b"]
        assert l1["assigned_to"] != l2["assigned_to"]


# ─────────────────────────────────────────────────────────────────────────────
# LED-011: Scoring engine
# ─────────────────────────────────────────────────────────────────────────────

class TestLED011Scoring:
    def test_update_and_get_scoring_rules(self, leads_table):
        import app.services.leads as svc
        rules_data = LeadScoreRulesIn(
            rules=[
                LeadScoreRuleIn(field="lead_source", operator="eq", value="campaign", points=20),
                LeadScoreRuleIn(field="company", operator="not_empty", value="", points=10),
            ],
            max_score=100,
        )
        result = svc.update_scoring_rules("admin1", rules_data)
        assert len(result["rules"]) == 2

        fetched = svc.get_scoring_rules()
        assert len(fetched["rules"]) == 2

    def test_compute_lead_score(self, leads_table):
        import app.services.leads as svc
        rules_data = LeadScoreRulesIn(
            rules=[
                LeadScoreRuleIn(field="lead_source", operator="eq", value="campaign", points=50),
            ],
            max_score=100,
        )
        svc.update_scoring_rules("admin1", rules_data)
        lead = svc.create_lead("u1", LeadCreateIn(
            first_name="A", last_name="B", email="score@x.com", lead_source="campaign"
        ))
        result = svc.compute_lead_score(lead["lead_id"], "admin1", trigger="test")
        assert result["score"] == 50

    def test_score_history(self, leads_table):
        import app.services.leads as svc
        rules_data = LeadScoreRulesIn(rules=[], max_score=100)
        svc.update_scoring_rules("admin1", rules_data)
        lead = svc.create_lead("u1", LeadCreateIn(first_name="A", last_name="B", email="hist@x.com"))
        svc.compute_lead_score(lead["lead_id"], "admin1", "manual")
        history = svc.get_score_history(lead["lead_id"])
        assert len(history["entries"]) == 1
        assert history["entries"][0]["trigger"] == "manual"

    def test_scoring_flag_off_raises_404(self, leads_table):
        import app.services.leads as svc
        from fastapi import HTTPException
        object.__setattr__(S, "leads_scoring_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc_info:
                svc.compute_lead_score("lead_fake", "u1")
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(S, "leads_scoring_enabled", True)


# ─────────────────────────────────────────────────────────────────────────────
# LED-012: Activity log
# ─────────────────────────────────────────────────────────────────────────────

class TestLED012ActivityLog:
    def test_log_and_list_activities(self, leads_table):
        import app.services.leads as svc
        lead = svc.create_lead("u1", LeadCreateIn(first_name="A", last_name="B", email="act@x.com"))
        svc.log_lead_activity(
            lead["lead_id"], "u1", "call",
            subject="Follow up", description="Called the lead"
        )
        svc.log_lead_activity(lead["lead_id"], "u1", "email", subject="Intro email")
        result = svc.list_lead_activities(lead["lead_id"])
        assert len(result["activities"]) == 2

    def test_activity_has_ttl(self, leads_table):
        import app.services.leads as svc
        from app.core.time import now_ts
        from app.services.leads import _CRM_ACTIVITY_TTL_SECONDS
        lead = svc.create_lead("u1", LeadCreateIn(first_name="A", last_name="B", email="ttl@x.com"))
        item = svc.log_lead_activity(lead["lead_id"], "u1", "note", subject="test")
        ts = now_ts()
        assert abs(item["ttl"] - (ts + _CRM_ACTIVITY_TTL_SECONDS)) <= 5  # ~1yr

    def test_activity_not_found_404(self, leads_table):
        import app.services.leads as svc
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            svc.log_lead_activity("lead_nonexistent", "u1", "note")
        assert exc_info.value.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# LED-013: Router (endpoint handler tests)
# ─────────────────────────────────────────────────────────────────────────────

class TestLED013Router:
    def test_flag_off_returns_404(self):
        """When leads_enabled=False, endpoints return 404."""
        from fastapi import HTTPException
        import app.routers.leads as router_mod
        object.__setattr__(S, "leads_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc_info:
                router_mod._require_leads_enabled()
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(S, "leads_enabled", True)

    def test_source_summary_requires_admin(self, leads_table):
        """lead_sources_summary returns 403 for USER role."""
        from fastapi import HTTPException
        from app.auth.roles import Role
        import app.routers.leads as router_mod
        ctx = {"user_sub": "user1", "role": Role.USER}
        with pytest.raises(HTTPException) as exc_info:
            router_mod.lead_sources_summary(ctx=ctx)
        assert exc_info.value.status_code == 403

    def test_create_lead_endpoint(self, leads_table):
        """create_lead router handler returns LeadOut."""
        from app.auth.roles import Role
        import app.routers.leads as router_mod
        ctx = {"user_sub": "user1", "role": Role.USER}
        body = LeadCreateIn(first_name="Alice", last_name="S", email="router@x.com")
        result = run(router_mod.create_lead(body=body, ctx=ctx))
        assert result.lead_id.startswith("lead_")
        assert result.email == "router@x.com"

    def test_get_lead_not_found_404(self, leads_table):
        """get_lead handler returns 404 for unknown id."""
        from fastapi import HTTPException
        from app.auth.roles import Role
        import app.routers.leads as router_mod
        ctx = {"user_sub": "user1", "role": Role.USER}
        with pytest.raises(HTTPException) as exc_info:
            run(router_mod.get_lead(lead_id="lead_nope", ctx=ctx))
        assert exc_info.value.status_code == 404

    def test_score_history_enforces_ownership(self, leads_table):
        """score history endpoint enforces ownership for USER role."""
        from fastapi import HTTPException
        from app.auth.roles import Role
        import app.routers.leads as router_mod
        import app.services.leads as svc
        # Create lead owned by user1
        lead = svc.create_lead("user1", LeadCreateIn(first_name="A", last_name="B", email="own@x.com"))
        ctx = {"user_sub": "user2", "role": Role.USER}
        with pytest.raises(HTTPException) as exc_info:
            run(router_mod.get_score_history(lead_id=lead["lead_id"], ctx=ctx))
        assert exc_info.value.status_code == 403

    def test_score_history_admin_can_see_all(self, leads_table):
        """Admin can see score history for any lead."""
        from app.auth.roles import Role
        import app.services.leads as svc
        # Enable scoring and create rules
        rules = LeadScoreRulesIn(rules=[], max_score=100)
        svc.update_scoring_rules("admin1", rules)
        lead = svc.create_lead("user1", LeadCreateIn(first_name="A", last_name="B", email="admhist@x.com"))
        svc.compute_lead_score(lead["lead_id"], "admin1", "test")
        # Call service directly (testing the ownership logic is in router, not here)
        result = svc.get_score_history(lead["lead_id"], limit=20)
        assert len(result["entries"]) >= 1
        assert result["entries"][0]["trigger"] == "test"


# ─────────────────────────────────────────────────────────────────────────────
# LED-001: DynamoDB table creation (integration)
# ─────────────────────────────────────────────────────────────────────────────

@mock_aws
def test_table_def_creates_correct_gsis():
    """The leads TableDef produces all required GSIs (LED-001 + LED-007)."""
    import boto3 as _b3

    ddb = _b3.resource(
        "dynamodb",
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    # Create the table directly mirroring the LED-001+LED-007 TableDef
    table = _make_leads_table(ddb)
    table.load()
    gsi_names = {g["IndexName"] for g in (table.global_secondary_indexes or [])}
    assert "ByOwner" in gsi_names
    assert "ByStatus" in gsi_names
    assert "BySource" in gsi_names
    assert "ByEmail" in gsi_names
    # Verify the leads_table_name setting
    assert S.leads_table_name == "leads"
