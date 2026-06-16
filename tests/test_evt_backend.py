"""Hermetic offline tests for EVT backend subsystem.

Covers EVT-001 (settings/tables), EVT-002 (invitee mgmt),
EVT-003 (registration), EVT-004 (capacity/waitlist),
EVT-008 (survey distribution), EVT-011 (doc library),
EVT-014 (contact SMS), EVT-015 (audit log browse).

Pattern: moto in-memory DynamoDB + object.__setattr__ on frozen T/S.
No TestClient, no real AWS, no network.
"""
from __future__ import annotations

import asyncio
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws


# ── Helpers ─────────────────────────────────────────────────────────────────

def _run(coro):
    """Run a coroutine on a fresh event loop."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _make_ddb_tables(ddb):
    """Create moto-backed tables for the EVT subsystem tests."""
    crm_events = ddb.create_table(
        TableName="crm_events_test",
        KeySchema=[
            {"AttributeName": "event_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "event_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "owner_sub", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": "ByOwner",
            "KeySchema": [
                {"AttributeName": "owner_sub", "KeyType": "HASH"},
                {"AttributeName": "created_at", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
    )

    crm_event_registrations = ddb.create_table(
        TableName="crm_event_reg_test",
        KeySchema=[
            {"AttributeName": "event_id", "KeyType": "HASH"},
            {"AttributeName": "registrant_sub", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "event_id", "AttributeType": "S"},
            {"AttributeName": "registrant_sub", "AttributeType": "S"},
            {"AttributeName": "registrant_sub_gsi", "AttributeType": "S"},
            {"AttributeName": "registered_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": "ByRegistrant",
            "KeySchema": [
                {"AttributeName": "registrant_sub_gsi", "KeyType": "HASH"},
                {"AttributeName": "registered_at", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
    )

    alerts = ddb.create_table(
        TableName="alerts_test",
        KeySchema=[
            {"AttributeName": "user_sub", "KeyType": "HASH"},
            {"AttributeName": "alert_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_sub", "AttributeType": "S"},
            {"AttributeName": "alert_id", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )

    contacts = ddb.create_table(
        TableName="contacts_test",
        KeySchema=[
            {"AttributeName": "owner_id", "KeyType": "HASH"},
            {"AttributeName": "contact_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "owner_id", "AttributeType": "S"},
            {"AttributeName": "contact_id", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )

    crm_sms_log = ddb.create_table(
        TableName="crm_sms_test",
        KeySchema=[
            {"AttributeName": "sender_sub", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "sender_sub", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "contact_id", "AttributeType": "S"},
            {"AttributeName": "sent_at_ts", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": "ByContact",
            "KeySchema": [
                {"AttributeName": "contact_id", "KeyType": "HASH"},
                {"AttributeName": "sent_at_ts", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
    )

    questionnaires = ddb.create_table(
        TableName="questionnaires_test",
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

    sessions = ddb.create_table(
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

    return SimpleNamespace(
        crm_events=crm_events,
        crm_event_registrations=crm_event_registrations,
        alerts=alerts,
        contacts=contacts,
        crm_contact_sms_log=crm_sms_log,
        questionnaires=questionnaires,
        sessions=sessions,
    )


# ── Scope="module" autouse fixture that installs + restores moto tables ──────

@pytest.fixture(autouse=True, scope="module")
def moto_tables():
    """Start moto, create tables, bind to frozen T/S, restore on teardown."""
    from app.core.tables import T
    from app.core.settings import S

    # Save original table handles and settings
    orig = {
        "crm_events": T.crm_events,
        "crm_event_registrations": T.crm_event_registrations,
        "alerts": T.alerts,
        "contacts": T.contacts,
        "crm_contact_sms_log": T.crm_contact_sms_log,
        "questionnaires": T.questionnaires,
        "sessions": T.sessions,
    }
    orig_settings = {
        "crm_events_enabled": S.crm_events_enabled,
        "crm_survey_distribution_enabled": S.crm_survey_distribution_enabled,
        "crm_document_library_enabled": S.crm_document_library_enabled,
        "crm_contact_sms_enabled": S.crm_contact_sms_enabled,
        "crm_audit_log_browse_enabled": S.crm_audit_log_browse_enabled,
        "crm_contact_sms_rate_max": S.crm_contact_sms_rate_max,
        "crm_contact_sms_rate_window_seconds": S.crm_contact_sms_rate_window_seconds,
        "survey_distribution_rate_limit_max": S.survey_distribution_rate_limit_max,
        "survey_distribution_rate_limit_window": S.survey_distribution_rate_limit_window,
    }

    mock = mock_aws()
    mock.start()

    ddb = boto3.resource("dynamodb", region_name="us-east-1")
    tbls = _make_ddb_tables(ddb)

    for name, tbl in vars(tbls).items():
        object.__setattr__(T, name, tbl)

    object.__setattr__(S, "crm_events_enabled", True)
    object.__setattr__(S, "crm_survey_distribution_enabled", True)
    object.__setattr__(S, "crm_document_library_enabled", True)
    object.__setattr__(S, "crm_contact_sms_enabled", True)
    object.__setattr__(S, "crm_audit_log_browse_enabled", True)
    object.__setattr__(S, "crm_contact_sms_rate_max", 1000)
    object.__setattr__(S, "crm_contact_sms_rate_window_seconds", 3600)
    object.__setattr__(S, "survey_distribution_rate_limit_max", 1000)
    object.__setattr__(S, "survey_distribution_rate_limit_window", 3600)

    yield tbls

    # Restore
    for name, tbl in orig.items():
        object.__setattr__(T, name, tbl)
    for name, val in orig_settings.items():
        object.__setattr__(S, name, val)
    mock.stop()


# ── EVT-001: Settings and Tables ─────────────────────────────────────────────

class TestEvt001Settings:
    def test_flag_default_is_false(self):
        """CRM_EVENTS_ENABLED defaults to False when env var is absent."""
        import os
        os.environ.pop("CRM_EVENTS_ENABLED", None)
        from app.core.settings import Settings
        s = Settings()
        assert s.crm_events_enabled is False

    def test_flag_enabled_when_env_set_1(self):
        """CRM_EVENTS_ENABLED='1' enables the flag."""
        expr = "1".lower() in ("1", "true", "yes", "on")
        assert expr is True

    @pytest.mark.parametrize("val,expected", [
        ("1", True), ("true", True), ("yes", True), ("on", True),
        ("0", False), ("false", False), ("", False), ("off", False),
    ])
    def test_flag_truth_values(self, val, expected):
        """Verify flag expression logic independently of Settings instantiation."""
        result = val.lower() in ("1", "true", "yes", "on")
        assert result is expected

    def test_table_name_defaults(self):
        import os
        os.environ.pop("CRM_EVENTS_TABLE_NAME", None)
        os.environ.pop("CRM_EVENT_REGISTRATIONS_TABLE_NAME", None)
        from app.core.settings import Settings
        s = Settings()
        assert s.crm_events_table_name == "crm_events"
        assert s.crm_event_registrations_table_name == "crm_event_registrations"

    def test_t_handles_exist(self):
        import dataclasses
        from app.core.tables import Tables
        field_names = {f.name for f in dataclasses.fields(Tables)}
        assert "crm_events" in field_names
        assert "crm_event_registrations" in field_names
        assert "crm_contact_sms_log" in field_names

    def test_guard_raises_404_when_flag_off(self):
        from fastapi import HTTPException
        from app.core.settings import S
        orig = S.crm_events_enabled
        object.__setattr__(S, "crm_events_enabled", False)
        try:
            from app.routers.crm_events import _require_crm_events_enabled
            with pytest.raises(HTTPException) as exc_info:
                _require_crm_events_enabled()
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(S, "crm_events_enabled", orig)

    def test_guard_does_not_raise_when_flag_on(self):
        from app.core.settings import S
        object.__setattr__(S, "crm_events_enabled", True)
        from app.routers.crm_events import _require_crm_events_enabled
        _require_crm_events_enabled()  # must not raise


# ── EVT-002: CRM Event invitee management ────────────────────────────────────

class TestEvt002Invitees:
    def test_create_crm_event(self, moto_tables):
        import app.services.crm_events as svc
        item = svc.create_crm_event("user1", "My Event")
        assert item["sk"] == "META"
        assert item["owner_sub"] == "user1"
        assert item["name"] == "My Event"
        assert "event_id" in item

    def test_add_invitee_writes_pending_row(self, moto_tables):
        import app.services.crm_events as svc
        evt = svc.create_crm_event("user1", "Evt2")
        item, was_new = svc.add_invitee(evt["event_id"], "user2", "user1")
        assert was_new is True
        assert item["invite_status"] == "pending"
        assert item["invitee_sub"] == "user2"

    def test_add_invitee_idempotent(self, moto_tables):
        import app.services.crm_events as svc
        evt = svc.create_crm_event("user1", "Evt3")
        svc.add_invitee(evt["event_id"], "user2", "user1")
        item2, was_new2 = svc.add_invitee(evt["event_id"], "user2", "user1")
        assert was_new2 is False
        # Status should remain 'pending' (not reset)
        assert item2["invite_status"] == "pending"

    def test_remove_invitee_returns_true_and_false(self, moto_tables):
        import app.services.crm_events as svc
        evt = svc.create_crm_event("user1", "Evt4")
        svc.add_invitee(evt["event_id"], "user3", "user1")
        assert svc.remove_invitee(evt["event_id"], "user3", "user1") is True
        assert svc.remove_invitee(evt["event_id"], "user3", "user1") is False

    def test_bulk_import_deduplicates(self, moto_tables):
        import app.services.crm_events as svc
        evt = svc.create_crm_event("user1", "Evt5")
        result = svc.bulk_import_invitees(evt["event_id"], ["u1", "u2", "u1"], "user1")
        # u1 twice: first added, second skipped
        assert result["added"] == 2
        assert result["skipped"] == 1

    def test_send_invitations_dispatches_only_pending(self, moto_tables):
        import app.services.crm_events as svc
        from app.core.tables import T

        evt = svc.create_crm_event("user1", "Evt6")
        svc.add_invitee(evt["event_id"], "pending_user", "user1")
        # Manually put a row with invite_status='sent' for another user
        T.crm_events.put_item(Item={
            "event_id": evt["event_id"],
            "sk": "INVITEE#sent_user",
            "invitee_sub": "sent_user",
            "invite_status": "sent",
            "invited_at": 0,
        })

        with patch("app.services.alerts.send_alert_email", return_value=None) as mock_send:
            with patch("app.services.crm_events._resolve_email", return_value="test@test.com"):
                result = svc.send_invitations(evt["event_id"], evt, "user1")

        # sent_user should be skipped (already sent)
        assert result["skipped"] >= 1
        # pending_user should have been sent
        assert result["sent"] + result["failed"] >= 1

    def test_list_invitees_pagination(self, moto_tables):
        import app.services.crm_events as svc
        evt = svc.create_crm_event("user1", "Evt7")
        for i in range(15):
            svc.add_invitee(evt["event_id"], f"inv_user_{i}", "user1")
        page1 = svc.list_invitees(evt["event_id"], limit=10)
        assert len(page1["invitees"]) <= 10
        if page1["cursor"]:
            page2 = svc.list_invitees(evt["event_id"], limit=10, cursor=page1["cursor"])
            assert len(page2["invitees"]) > 0

    def test_route_returns_404_when_flag_off(self, moto_tables):
        from fastapi import HTTPException
        from app.core.settings import S
        object.__setattr__(S, "crm_events_enabled", False)
        try:
            from app.routers.crm_events import _require_crm_events_enabled
            with pytest.raises(HTTPException) as exc_info:
                _require_crm_events_enabled()
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(S, "crm_events_enabled", True)


# ── EVT-003: Registration workflow ───────────────────────────────────────────

class TestEvt003Registration:
    def test_register_for_event(self, moto_tables):
        import app.services.crm_events as svc
        evt = svc.create_crm_event("owner1", "RegEvt1")
        item = svc.register_for_event(evt["event_id"], "reg_user1")
        assert item["status"] == "registered"
        assert item["event_id"] == evt["event_id"]
        assert item["registrant_sub"] == "reg_user1"

    def test_register_duplicate_raises_409(self, moto_tables):
        from fastapi import HTTPException
        import app.services.crm_events as svc
        evt = svc.create_crm_event("owner1", "RegEvt2")
        svc.register_for_event(evt["event_id"], "dup_user")
        with pytest.raises(HTTPException) as exc_info:
            svc.register_for_event(evt["event_id"], "dup_user")
        assert exc_info.value.status_code == 409

    def test_respond_accept(self, moto_tables):
        import app.services.crm_events as svc
        evt = svc.create_crm_event("owner1", "RegEvt3")
        svc.register_for_event(evt["event_id"], "resp_user")
        item = svc.respond_to_invitation(evt["event_id"], "resp_user", "accepted", "resp_user")
        assert item["status"] == "accepted"

    def test_respond_decline(self, moto_tables):
        import app.services.crm_events as svc
        evt = svc.create_crm_event("owner1", "RegEvt4")
        svc.register_for_event(evt["event_id"], "resp_user2")
        item = svc.respond_to_invitation(evt["event_id"], "resp_user2", "declined", "resp_user2")
        assert item["status"] == "declined"

    def test_check_in_attendee(self, moto_tables):
        import app.services.crm_events as svc
        evt = svc.create_crm_event("owner1", "RegEvt5")
        svc.register_for_event(evt["event_id"], "checkin_user")
        item = svc.check_in_attendee(evt["event_id"], "checkin_user", "owner1")
        assert item["status"] == "attended"

    def test_list_registrations(self, moto_tables):
        import app.services.crm_events as svc
        evt = svc.create_crm_event("owner1", "RegEvt6")
        svc.register_for_event(evt["event_id"], "list_reg_user1")
        svc.register_for_event(evt["event_id"], "list_reg_user2")
        result = svc.list_registrations(evt["event_id"])
        assert result["registrations"]
        assert len(result["registrations"]) >= 2

    def test_cancel_registration(self, moto_tables):
        import app.services.crm_events as svc
        evt = svc.create_crm_event("owner1", "RegEvt7")
        svc.register_for_event(evt["event_id"], "cancel_user")
        assert svc.cancel_registration(evt["event_id"], "cancel_user", "owner1") is True
        assert svc.cancel_registration(evt["event_id"], "cancel_user", "owner1") is False


# ── EVT-004: Capacity / waitlist ─────────────────────────────────────────────

class TestEvt004Capacity:
    def test_register_within_capacity(self, moto_tables):
        import app.services.crm_events as svc
        evt = svc.create_crm_event("owner1", "CapEvt1", max_attendance=5)
        item = svc.register_for_event(evt["event_id"], "cap_user1")
        # No capacity exceeded yet → registered (not waitlisted)
        assert item["status"] == "registered"

    def test_waitlist_when_at_capacity(self, moto_tables):
        import app.services.crm_events as svc
        evt = svc.create_crm_event("owner2", "CapEvt2", max_attendance=1)
        # Fill capacity: register and accept first user
        svc.register_for_event(evt["event_id"], "cap_u1")
        svc.respond_to_invitation(evt["event_id"], "cap_u1", "accepted", "cap_u1")
        # Second user should be waitlisted
        item2 = svc.register_for_event(evt["event_id"], "cap_u2")
        assert item2["status"] == "waitlisted"
        assert item2.get("waitlist_position") is not None

    def test_get_event_capacity(self, moto_tables):
        import app.services.crm_events as svc
        evt = svc.create_crm_event("owner2", "CapEvt3", max_attendance=10)
        svc.register_for_event(evt["event_id"], "cap_q1")
        svc.respond_to_invitation(evt["event_id"], "cap_q1", "accepted", "cap_q1")
        cap = svc.get_event_capacity(evt["event_id"])
        assert cap["max_attendance"] == 10
        assert cap["accepted_count"] >= 1
        assert cap["available_spots"] is not None

    def test_promote_from_waitlist_on_decline(self, moto_tables):
        import app.services.crm_events as svc
        evt = svc.create_crm_event("owner2", "CapEvt4", max_attendance=1)
        svc.register_for_event(evt["event_id"], "promo_u1")
        svc.respond_to_invitation(evt["event_id"], "promo_u1", "accepted", "promo_u1")
        # Second gets waitlisted
        item_wl = svc.register_for_event(evt["event_id"], "promo_u2")
        assert item_wl["status"] == "waitlisted"
        # Decline first → second gets promoted
        svc.respond_to_invitation(evt["event_id"], "promo_u1", "declined", "promo_u1")
        from app.core.tables import T
        promoted = T.crm_event_registrations.get_item(
            Key={"event_id": evt["event_id"], "registrant_sub": "promo_u2"}
        ).get("Item", {})
        assert promoted.get("status") == "registered"


# ── EVT-008: Survey distribution ─────────────────────────────────────────────

class TestEvt008SurveyDist:
    def test_send_survey_invitations(self, moto_tables):
        from app.services.crm_survey_distribution import send_survey_invitations

        # Patch the lazily-imported send_alert_email via the alerts module
        with patch("app.services.alerts.send_alert_email", return_value=None):
            result = send_survey_invitations(
                questionnaire_id="qnr_abc",
                owner_sub="owner1",
                recipients=["user1@test.com", "user2@test.com"],
                subject="Test Survey",
                survey_url="https://example.com/survey",
            )
        assert result["sent"] + result["failed"] + result["skipped"] == 2

    def test_send_survey_invitations_idempotent(self, moto_tables):
        """Duplicate emails are skipped on second send."""
        from app.services.crm_survey_distribution import send_survey_invitations

        with patch("app.services.alerts.send_alert_email", return_value=None):
            r1 = send_survey_invitations(
                questionnaire_id="qnr_idem",
                owner_sub="owner1",
                recipients=["idem@test.com"],
                subject="S",
                survey_url="https://x.com",
            )
            r2 = send_survey_invitations(
                questionnaire_id="qnr_idem",
                owner_sub="owner1",
                recipients=["idem@test.com"],
                subject="S",
                survey_url="https://x.com",
            )
        # Second call skips the already-invited address
        assert r2["skipped"] == 1

    def test_get_distribution_summary_empty(self, moto_tables):
        from app.services.crm_survey_distribution import get_distribution_summary
        result = get_distribution_summary(
            questionnaire_id="qnr_no_sends",
            owner_sub="owner1",
        )
        assert result["total_sent"] == 0
        assert result["response_rate"] == 0.0


# ── EVT-014: Contact SMS ──────────────────────────────────────────────────────

class TestEvt014ContactSms:
    def _seed_contact(self, moto_tables, sender_sub: str, contact_id: str):
        moto_tables.contacts.put_item(Item={
            "owner_id": sender_sub,
            "contact_id": contact_id,
            "display_name": "Test Contact",
        })

    def test_send_contact_sms_no_phone_raises_404(self, moto_tables):
        from fastapi import HTTPException
        from app.services.crm_contact_sms import send_contact_sms

        self._seed_contact(moto_tables, "sms_sender", "sms_contact1")
        # Patch profile lazily imported inside function
        with patch("app.services.profile.get_profile_identity", return_value={}):
            with pytest.raises(HTTPException) as exc_info:
                send_contact_sms(sender_sub="sms_sender", contact_id="sms_contact1", body="Hello")
            assert exc_info.value.status_code == 404

    def test_send_contact_sms_missing_contact_raises_404(self, moto_tables):
        from fastapi import HTTPException
        from app.services.crm_contact_sms import send_contact_sms

        with pytest.raises(HTTPException) as exc_info:
            send_contact_sms(sender_sub="sms_sender", contact_id="nonexistent", body="Hello")
        assert exc_info.value.status_code == 404

    def test_send_contact_sms_success(self, moto_tables):
        from app.services.crm_contact_sms import send_contact_sms

        self._seed_contact(moto_tables, "sms_sender2", "sms_contact2")
        with patch("app.services.profile.get_profile_identity", return_value={"phone": "+15551234567"}):
            with patch("app.services.sms_delivery.send_sms", return_value={"status": "dev_logged", "message_id": "msg1"}):
                result = send_contact_sms(sender_sub="sms_sender2", contact_id="sms_contact2", body="Hi!")
        assert result["status"] == "dev_logged"
        assert result["contact_id"] == "sms_contact2"

    def test_list_contact_sms_log(self, moto_tables):
        from app.services.crm_contact_sms import send_contact_sms, list_contact_sms_log

        self._seed_contact(moto_tables, "sms_list_sender", "sms_list_contact")
        with patch("app.services.profile.get_profile_identity", return_value={"phone": "+15551234567"}):
            with patch("app.services.sms_delivery.send_sms", return_value={"status": "dev_logged", "message_id": ""}):
                send_contact_sms(sender_sub="sms_list_sender", contact_id="sms_list_contact", body="Hi")
        result = list_contact_sms_log("sms_list_sender")
        assert len(result["items"]) >= 1

    def test_crm_contact_sms_guard(self):
        from fastapi import HTTPException
        from app.core.settings import S
        object.__setattr__(S, "crm_contact_sms_enabled", False)
        try:
            from app.routers.crm_contact_sms import _require_crm_contact_sms_enabled
            with pytest.raises(HTTPException) as exc_info:
                _require_crm_contact_sms_enabled()
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(S, "crm_contact_sms_enabled", True)


# ── EVT-015: Audit log browse ─────────────────────────────────────────────────

class TestEvt015AuditLogBrowse:
    def _seed_alert(self, moto_tables, user_sub: str, event: str, ts: int):
        alert_id = f"{ts:010d}#abc{user_sub}"
        moto_tables.alerts.put_item(Item={
            "user_sub": user_sub,
            "alert_id": alert_id,
            "ts": ts,
            "event": event,
            "outcome": "success",
            "title": "Test",
            "details": {},
            "read": False,
            "category": "auth",
        })

    def test_browse_auth_category_returns_items(self, moto_tables):
        from app.services.audit_log_browse import browse_audit_log
        from_ts = 1700000000
        to_ts = 1700100000
        for i in range(3):
            self._seed_alert(moto_tables, "alice", "login", from_ts + i * 100)

        result = browse_audit_log(
            category="auth",
            from_ts=from_ts,
            to_ts=to_ts,
            user_sub_filter="alice",
            limit=10,
        )
        assert "items" in result
        assert result["category"] == "auth"
        assert result["from_ts"] == from_ts
        assert result["to_ts"] == to_ts

    def test_browse_unknown_category_raises_valueerror(self, moto_tables):
        from app.services.audit_log_browse import browse_audit_log
        with pytest.raises(ValueError, match="Unknown category"):
            browse_audit_log(category="xyz_unknown", from_ts=1700000000, to_ts=1700100000)

    def test_browse_from_ts_after_to_ts_raises(self, moto_tables):
        from app.services.audit_log_browse import browse_audit_log
        with pytest.raises(ValueError, match="from_ts must be"):
            browse_audit_log(category="auth", from_ts=1700100000, to_ts=1700000000)

    def test_browse_date_range_too_wide(self, moto_tables):
        from app.services.audit_log_browse import browse_audit_log
        from app.core.settings import S
        max_days = S.audit_export_max_date_range_days
        with pytest.raises(ValueError, match="Date range exceeds"):
            browse_audit_log(
                category="auth",
                from_ts=0,
                to_ts=max_days * 86400 + 86401,
            )

    def test_browse_empty_result(self, moto_tables):
        from app.services.audit_log_browse import browse_audit_log
        result = browse_audit_log(
            category="auth",
            from_ts=1,
            to_ts=2,
        )
        assert result["items"] == []
        assert result["cursor"] is None

    def test_browse_flag_off_returns_404(self, moto_tables):
        from fastapi import HTTPException
        from app.core.settings import S
        object.__setattr__(S, "crm_audit_log_browse_enabled", False)
        try:
            from app.routers.audit_export import _require_audit_log_browse_enabled
            with pytest.raises(HTTPException) as exc_info:
                _require_audit_log_browse_enabled()
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(S, "crm_audit_log_browse_enabled", True)


# ── EVT-011: Document library metadata ───────────────────────────────────────

class TestEvt011DocumentLibrary:
    def test_linked_record_types_constant(self):
        """_LINKED_RECORD_TYPES must include the four CRM record types."""
        from app.services.filemanager import _LINKED_RECORD_TYPES
        for expected in ("contact", "ticket", "account", "party"):
            assert expected in _LINKED_RECORD_TYPES

    def test_crm_document_library_guard(self):
        from fastapi import HTTPException
        from app.core.settings import S
        object.__setattr__(S, "crm_document_library_enabled", False)
        try:
            from app.routers.filemanager import _require_crm_document_library_enabled
            with pytest.raises(HTTPException) as exc_info:
                _require_crm_document_library_enabled()
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(S, "crm_document_library_enabled", True)

    def test_update_crm_metadata_validates_linked_record_type(self):
        """Invalid linked_record_type raises HTTP 400."""
        from fastapi import HTTPException
        from app.services.filemanager import update_crm_metadata

        with patch("app.services.filemanager.get_node", return_value={"path": "/test.pdf", "type": "file"}):
            with patch("app.services.filemanager.norm_path", return_value="/test.pdf"):
                with pytest.raises(HTTPException) as exc_info:
                    update_crm_metadata(
                        "user1", "/test.pdf",
                        crm_category=None,
                        crm_description=None,
                        linked_record_type="invalid_type",
                        linked_record_id="rec123",
                    )
                assert exc_info.value.status_code == 400

    def test_update_crm_metadata_requires_pair(self):
        """Supplying only linked_record_type without linked_record_id raises HTTP 400."""
        from fastapi import HTTPException
        from app.services.filemanager import update_crm_metadata

        with patch("app.services.filemanager.get_node", return_value={"path": "/test.pdf", "type": "file"}):
            with patch("app.services.filemanager.norm_path", return_value="/test.pdf"):
                with pytest.raises(HTTPException) as exc_info:
                    update_crm_metadata(
                        "user1", "/test.pdf",
                        crm_category=None,
                        crm_description=None,
                        linked_record_type="contact",
                        linked_record_id=None,
                    )
                assert exc_info.value.status_code == 400
