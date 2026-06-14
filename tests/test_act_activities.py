"""
Hermetic offline pytest covering ACT-001 through ACT-010 backend subsystem.

Follows the module-scoped autouse fixture pattern from CLAUDE.md:
- Saves prior T/S values before patching via object.__setattr__
- Restores on teardown (autouse, scope="module")
- Uses moto in-memory DynamoDB
- Calls async route handlers on asyncio.new_event_loop()
- No TestClient, no real AWS/network
"""
from __future__ import annotations

import asyncio
import sys
import types
import uuid
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws


# ─── Module-level DynamoDB fixture ────────────────────────────────────────────

@pytest.fixture(scope="module", autouse=True)
def crm_moto_setup():
    """
    Start moto mock_aws, create all 5 CRM tables plus calendar and call_history,
    wire frozen T handles and S flags, restore on teardown.
    """
    mock = mock_aws()
    mock.start()

    ddb = boto3.resource("dynamodb", region_name="us-east-1")

    def mk(name, hash_key, range_key=None, gsis=None, attr_types=None):
        attr_defs = [{"AttributeName": hash_key, "AttributeType": "S"}]
        key_schema = [{"AttributeName": hash_key, "KeyType": "HASH"}]
        if range_key:
            attr_defs.append({"AttributeName": range_key, "AttributeType": "S"})
            key_schema.append({"AttributeName": range_key, "KeyType": "RANGE"})
        gsi_defs = []
        if gsis:
            for g in gsis:
                pk = g["pk"]; sk = g.get("sk"); iname = g["name"]
                pk_type = (attr_types or {}).get(pk, "S")
                if pk not in [a["AttributeName"] for a in attr_defs]:
                    attr_defs.append({"AttributeName": pk, "AttributeType": pk_type})
                gsi_ks = [{"AttributeName": pk, "KeyType": "HASH"}]
                if sk:
                    sk_type = (attr_types or {}).get(sk, "S")
                    if sk not in [a["AttributeName"] for a in attr_defs]:
                        attr_defs.append({"AttributeName": sk, "AttributeType": sk_type})
                    gsi_ks.append({"AttributeName": sk, "KeyType": "RANGE"})
                gsi_defs.append({
                    "IndexName": iname,
                    "KeySchema": gsi_ks,
                    "Projection": {"ProjectionType": "ALL"},
                })
        kwargs: Dict[str, Any] = dict(
            TableName=name,
            KeySchema=key_schema,
            AttributeDefinitions=attr_defs,
            BillingMode="PAY_PER_REQUEST",
        )
        if gsi_defs:
            kwargs["GlobalSecondaryIndexes"] = gsi_defs
        return ddb.create_table(**kwargs)

    cal_tbl = mk("calendar", "calendar_id", "sk")
    call_tbl = mk("call_history", "user_id", "sk")
    tasks_tbl = mk(
        "crm_tasks", "user_sub", "sk",
        gsis=[
            {"name": "ByStatus",   "pk": "GSI1PK", "sk": "GSI1SK"},
            {"name": "ByAssignee", "pk": "GSI2PK", "sk": "GSI2SK"},
        ],
        attr_types={"GSI1SK": "N", "GSI2SK": "N"},
    )
    notes_tbl = mk(
        "crm_notes", "user_sub", "sk",
        gsis=[{"name": "ByEntity", "pk": "GSI1PK", "sk": "GSI1SK"}],
        attr_types={"GSI1SK": "N"},
    )
    timeline_tbl = mk(
        "crm_activity_timeline", "entity_key", "sk",
        gsis=[{"name": "ByType", "pk": "GSI1PK", "sk": "GSI1SK"}],
        attr_types={"GSI1SK": "N"},
    )
    rsvp_tbl = mk(
        "crm_event_rsvp", "event_key", "attendee_sub",
        gsis=[{"name": "ByUser", "pk": "GSI1PK", "sk": "GSI1SK"}],
        attr_types={"GSI1SK": "N"},
    )
    reminders_tbl = mk(
        "crm_event_reminders", "reminder_key", "reminder_id",
        gsis=[{"name": "DueReminders", "pk": "GSI1PK", "sk": "GSI1SK"}],
        attr_types={"GSI1SK": "N"},
    )

    # Patch T handles
    from app.core import tables as tables_mod
    T = tables_mod.T

    _saved_T = {
        "calendar": T.calendar,
        "call_history": T.call_history,
        "crm_tasks": T.crm_tasks,
        "crm_notes": T.crm_notes,
        "crm_activity_timeline": T.crm_activity_timeline,
        "crm_event_rsvp": T.crm_event_rsvp,
        "crm_event_reminders": T.crm_event_reminders,
    }
    object.__setattr__(T, "calendar", cal_tbl)
    object.__setattr__(T, "call_history", call_tbl)
    object.__setattr__(T, "crm_tasks", tasks_tbl)
    object.__setattr__(T, "crm_notes", notes_tbl)
    object.__setattr__(T, "crm_activity_timeline", timeline_tbl)
    object.__setattr__(T, "crm_event_rsvp", rsvp_tbl)
    object.__setattr__(T, "crm_event_reminders", reminders_tbl)

    # Patch S flags ON
    from app.core import settings as settings_mod
    S = settings_mod.S
    _flag_names = [
        "crm_activities_enabled",
        "crm_tasks_enabled",
        "crm_notes_enabled",
        "crm_activity_timeline_enabled",
        "crm_event_rsvp_enabled",
        "crm_event_reminders_enabled",
        "dev_mode",
    ]
    _saved_S = {n: getattr(S, n) for n in _flag_names}
    for n in _flag_names:
        object.__setattr__(S, n, True)

    yield {
        "T": T,
        "S": S,
        "cal_tbl": cal_tbl,
        "call_tbl": call_tbl,
        "tasks_tbl": tasks_tbl,
        "notes_tbl": notes_tbl,
        "timeline_tbl": timeline_tbl,
        "rsvp_tbl": rsvp_tbl,
        "reminders_tbl": reminders_tbl,
    }

    # Restore
    for k, v in _saved_T.items():
        object.__setattr__(T, k, v)
    for k, v in _saved_S.items():
        object.__setattr__(S, k, v)

    mock.stop()


def run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ─── ACT-001: Settings and table handles ────────────────────────────────────

class TestAct001Scaffold:
    def test_flags_default_false(self):
        """Without env override, all CRM flags default to false."""
        import os
        from app.core.settings import Settings
        # Create fresh Settings without env override
        old = {k: os.environ.pop(k) for k in [
            "CRM_ACTIVITIES_ENABLED", "CRM_TASKS_ENABLED", "CRM_NOTES_ENABLED",
            "CRM_ACTIVITY_TIMELINE_ENABLED", "CRM_EVENT_RSVP_ENABLED", "CRM_EVENT_REMINDERS_ENABLED",
        ] if k in os.environ}
        try:
            s = Settings()
            assert s.crm_activities_enabled is False
            assert s.crm_tasks_enabled is False
            assert s.crm_notes_enabled is False
            assert s.crm_activity_timeline_enabled is False
            assert s.crm_event_rsvp_enabled is False
            assert s.crm_event_reminders_enabled is False
        finally:
            os.environ.update(old)

    def test_table_name_defaults(self):
        from app.core.settings import Settings
        import os
        for k in ["DDB_CRM_TASKS_TABLE", "DDB_CRM_NOTES_TABLE", "DDB_CRM_ACTIVITY_TIMELINE_TABLE",
                  "DDB_CRM_EVENT_RSVP_TABLE", "DDB_CRM_EVENT_REMINDERS_TABLE"]:
            os.environ.pop(k, None)
        s = Settings()
        assert s.crm_tasks_table_name == "crm_tasks"
        assert s.crm_notes_table_name == "crm_notes"
        assert s.crm_activity_timeline_table_name == "crm_activity_timeline"
        assert s.crm_event_rsvp_table_name == "crm_event_rsvp"
        assert s.crm_event_reminders_table_name == "crm_event_reminders"

    def test_table_handles_exist(self, crm_moto_setup):
        T = crm_moto_setup["T"]
        # Verify handles resolve (moto-backed tables are actual boto3 Table objects)
        assert T.crm_tasks is not None
        assert T.crm_notes is not None
        assert T.crm_activity_timeline is not None
        assert T.crm_event_rsvp is not None
        assert T.crm_event_reminders is not None

    def test_gsi_numeric_sort_keys_tasks(self, crm_moto_setup):
        """Write + query via ByStatus GSI with numeric GSI1SK — no ValidationException."""
        T = crm_moto_setup["T"]
        ts = 1750000000
        T.crm_tasks.put_item(Item={
            "user_sub": "u1",
            "sk": f"TASK#9998249999999#t1",
            "task_id": "t1",
            "GSI1PK": "STATUS#open",
            "GSI1SK": ts,
            "GSI2PK": "ASSIGNEE#u2",
            "GSI2SK": ts,
        })
        from boto3.dynamodb.conditions import Key
        resp = T.crm_tasks.query(
            IndexName="ByStatus",
            KeyConditionExpression=Key("GSI1PK").eq("STATUS#open") & Key("GSI1SK").gte(0),
        )
        assert any(i["task_id"] == "t1" for i in resp["Items"])


# ─── ACT-002: Calendar RSVP ────────────────────────────────────────────────

class TestAct002Rsvp:
    _CAL_ID = "cal_act002"
    _EVT_ID = "evt_act002"
    _ALICE = "alice_rsvp"
    _BOB = "bob_rsvp"

    def setup_method(self):
        # Seed a calendar event with Alice and Bob as attendees
        from app.core.tables import T
        T.calendar.put_item(Item={
            "calendar_id": self._CAL_ID,
            "sk": f"event#{self._EVT_ID}",
            "name": "Test Meeting",
            "attendees": [self._ALICE, self._BOB],
            "start_utc": "2099-01-01T10:00:00Z",
            "end_utc": "2099-01-01T11:00:00Z",
            "owner_user_sub": "organizer_rsvp",
        })
        T.calendar.put_item(Item={
            "calendar_id": self._CAL_ID,
            "sk": "meta",
            "owner_user_sub": "organizer_rsvp",
            "timezone": "UTC",
        })

    def test_upsert_rsvp_accepted(self, crm_moto_setup):
        from app.routers.calendar import _upsert_rsvp, _get_rsvp
        with patch("app.routers.calendar.audit_event"):
            row = _upsert_rsvp(self._CAL_ID, self._EVT_ID, self._ALICE, "accepted")
        assert row["status"] == "accepted"
        assert isinstance(row["responded_at"], int)
        stored = _get_rsvp(self._CAL_ID, self._EVT_ID, self._ALICE)
        assert stored["status"] == "accepted"

    def test_upsert_rsvp_updates_status(self, crm_moto_setup):
        from app.routers.calendar import _upsert_rsvp, _get_rsvp
        with patch("app.routers.calendar.audit_event"):
            _upsert_rsvp(self._CAL_ID, self._EVT_ID, self._ALICE, "accepted")
            _upsert_rsvp(self._CAL_ID, self._EVT_ID, self._ALICE, "declined")
        stored = _get_rsvp(self._CAL_ID, self._EVT_ID, self._ALICE)
        assert stored["status"] == "declined"

    def test_enrich_attendees(self, crm_moto_setup):
        from app.routers.calendar import _upsert_rsvp, _enrich_attendees
        with patch("app.routers.calendar.audit_event"):
            _upsert_rsvp(self._CAL_ID, self._EVT_ID, self._ALICE, "tentative")
        enriched = _enrich_attendees(self._CAL_ID, self._EVT_ID, [self._ALICE, self._BOB])
        alice_e = next(e for e in enriched if e.user_sub == self._ALICE)
        bob_e = next(e for e in enriched if e.user_sub == self._BOB)
        assert alice_e.rsvp_status.value == "tentative"
        assert bob_e.rsvp_status.value == "no_response"

    def test_enrich_ignores_stale_rsvp(self, crm_moto_setup):
        from app.routers.calendar import _upsert_rsvp, _enrich_attendees
        with patch("app.routers.calendar.audit_event"):
            _upsert_rsvp(self._CAL_ID, self._EVT_ID, "stranger_sub", "accepted")
        enriched = _enrich_attendees(self._CAL_ID, self._EVT_ID, [self._ALICE])
        assert len(enriched) == 1

    def test_put_rsvp_non_attendee_403(self, crm_moto_setup):
        from fastapi import HTTPException
        from app.routers.calendar import update_event_rsvp
        from app.models import EventRsvpUpdateIn, EventAttendeeRsvpStatus
        ctx = {"user_sub": "stranger_sub_2"}
        body = EventRsvpUpdateIn(status=EventAttendeeRsvpStatus.accepted)
        with pytest.raises(HTTPException) as exc_info:
            run_async(update_event_rsvp(self._CAL_ID, self._EVT_ID, body, ctx))
        assert exc_info.value.status_code == 403

    def test_flag_off_returns_404(self, crm_moto_setup):
        from fastapi import HTTPException
        from app.routers.calendar import update_event_rsvp
        from app.models import EventRsvpUpdateIn, EventAttendeeRsvpStatus
        from app.core.settings import S as _S
        object.__setattr__(_S, "crm_event_rsvp_enabled", False)
        try:
            ctx = {"user_sub": self._ALICE}
            body = EventRsvpUpdateIn(status=EventAttendeeRsvpStatus.accepted)
            with pytest.raises(HTTPException) as exc_info:
                run_async(update_event_rsvp(self._CAL_ID, self._EVT_ID, body, ctx))
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(_S, "crm_event_rsvp_enabled", True)


# ─── ACT-003 / ACT-005: _build_ics + invite dispatch ────────────────────────

class TestAct003And005Ics:
    def test_build_ics_method_request(self):
        from app.routers.calendar import _build_ics
        evt = {"name": "Meeting", "start_utc": "2099-01-01T10:00:00Z", "end_utc": "2099-01-01T11:00:00Z"}
        ics = _build_ics(evt, "abc123", method="REQUEST")
        assert "METHOD:REQUEST" in ics
        assert "CALSCALE:GREGORIAN" in ics
        # METHOD comes AFTER CALSCALE and before BEGIN:VEVENT
        cal_pos = ics.index("CALSCALE:GREGORIAN")
        method_pos = ics.index("METHOD:REQUEST")
        vevent_pos = ics.index("BEGIN:VEVENT")
        assert cal_pos < method_pos < vevent_pos

    def test_build_ics_method_cancel(self):
        from app.routers.calendar import _build_ics
        evt = {"name": "Meeting", "all_day": True, "all_day_date": "2099-01-01"}
        ics = _build_ics(evt, "abc456", method="CANCEL")
        assert "METHOD:CANCEL" in ics

    def test_build_ics_no_method_backward_compat(self):
        from app.routers.calendar import _build_ics
        evt = {"name": "Evt", "start_utc": "2099-01-01T10:00:00Z"}
        ics = _build_ics(evt, "abc789")
        assert "METHOD:" not in ics

    def test_build_ics_yearly_rrule(self):
        from app.routers.calendar import _build_ics
        evt = {
            "name": "Birthday",
            "start_utc": "2099-01-01T10:00:00Z",
            "recurrence_rule": {"freq": "YEARLY", "interval": 1},
        }
        ics = _build_ics(evt, "annual1")
        assert "RRULE:FREQ=YEARLY" in ics

    def test_dispatch_flag_off_skips(self):
        from app.routers.calendar import _dispatch_invite_emails
        from app.core.settings import S as _S
        object.__setattr__(_S, "crm_event_reminders_enabled", False)
        try:
            with patch("app.routers.calendar.send_calendar_invite_email") as mock_send:
                _dispatch_invite_emails(
                    {"attendees": ["alice_test"], "name": "Test",
                     "start_utc": "2099-01-01T10:00:00Z", "end_utc": "2099-01-01T11:00:00Z"},
                    "evt1", "organizer_sub", "REQUEST"
                )
                mock_send.assert_not_called()
        finally:
            object.__setattr__(_S, "crm_event_reminders_enabled", True)

    def test_dispatch_skips_no_email(self, crm_moto_setup):
        from app.routers.calendar import _dispatch_invite_emails
        with patch("app.routers.calendar.get_profile_identity", return_value={"email": None, "display_name": "X"}):
            with patch("app.routers.calendar.send_calendar_invite_email") as mock_send:
                with patch("app.routers.calendar.audit_event"):
                    _dispatch_invite_emails(
                        {"attendees": ["attendee_no_email"], "name": "Evt",
                         "start_utc": "2099-01-01T10:00:00Z", "end_utc": "2099-01-01T11:00:00Z"},
                        "evt2", "organizer_sub", "REQUEST"
                    )
                    mock_send.assert_not_called()

    def test_dispatch_skips_organizer(self, crm_moto_setup):
        from app.routers.calendar import _dispatch_invite_emails
        def fake_identity(sub):
            return {"email": f"{sub}@test.local", "display_name": sub}
        with patch("app.routers.calendar.get_profile_identity", side_effect=fake_identity):
            with patch("app.routers.calendar.send_calendar_invite_email") as mock_send:
                with patch("app.routers.calendar.audit_event"):
                    _dispatch_invite_emails(
                        {"attendees": ["organizer_sub", "attendee1"], "name": "Evt",
                         "start_utc": "2099-01-01T10:00:00Z", "end_utc": "2099-01-01T11:00:00Z"},
                        "evt3", "organizer_sub", "REQUEST"
                    )
                    # Only attendee1 should get email, not organizer
                    assert mock_send.call_count == 1

    def test_dispatch_never_raises(self, crm_moto_setup):
        from app.routers.calendar import _dispatch_invite_emails
        with patch("app.routers.calendar.get_profile_identity", side_effect=Exception("boom")):
            # Should not raise
            _dispatch_invite_emails(
                {"attendees": ["a1"], "name": "X",
                 "start_utc": "2099-01-01T10:00:00Z", "end_utc": "2099-01-01T11:00:00Z"},
                "evt4", "org", "REQUEST"
            )


# ─── ACT-004: Event reminders ────────────────────────────────────────────────

class TestAct004Reminders:
    _CAL_ID = "cal_rem"
    _EVT_ID = "evt_rem"

    def setup_method(self):
        from app.core.tables import T
        T.calendar.put_item(Item={
            "calendar_id": self._CAL_ID,
            "sk": f"event#{self._EVT_ID}",
            "name": "Reminder Test",
            "attendees": ["alice_rem"],
            "start_utc": "2099-06-01T10:00:00Z",
            "end_utc": "2099-06-01T11:00:00Z",
        })
        T.calendar.put_item(Item={
            "calendar_id": self._CAL_ID,
            "sk": "meta",
            "owner_user_sub": "alice_rem",
            "timezone": "UTC",
        })

    def test_set_and_get_reminders(self, crm_moto_setup):
        from app.routers.calendar import _set_reminders, _get_reminders
        from app.models import EventReminderIn, EventReminderMethod
        with patch("app.routers.calendar.audit_event"):
            reminders_in = [
                EventReminderIn(minutes_before=15, method=EventReminderMethod.in_app),
                EventReminderIn(minutes_before=60, method=EventReminderMethod.email),
            ]
            written = _set_reminders(
                self._CAL_ID, self._EVT_ID, "alice_rem",
                reminders_in,
                4070908800,  # far future event start ts
                "Reminder Test", "2099-06-01T10:00:00Z",
            )
        assert len(written) == 2
        rows = _get_reminders(self._CAL_ID, self._EVT_ID, "alice_rem")
        assert len(rows) == 2
        # Ordered by fire_at ascending
        assert rows[0]["fire_at"] < rows[1]["fire_at"]

    def test_set_replaces_existing(self, crm_moto_setup):
        from app.routers.calendar import _set_reminders, _get_reminders
        from app.models import EventReminderIn, EventReminderMethod
        with patch("app.routers.calendar.audit_event"):
            _set_reminders(self._CAL_ID, self._EVT_ID, "alice_rem",
                [EventReminderIn(minutes_before=10, method=EventReminderMethod.in_app),
                 EventReminderIn(minutes_before=30, method=EventReminderMethod.in_app)],
                4070908800, "T", "U")
            _set_reminders(self._CAL_ID, self._EVT_ID, "alice_rem",
                [EventReminderIn(minutes_before=5, method=EventReminderMethod.in_app)],
                4070908800, "T", "U")
        rows = _get_reminders(self._CAL_ID, self._EVT_ID, "alice_rem")
        assert len(rows) == 1
        assert rows[0]["minutes_before"] == 5

    def test_set_empty_clears_all(self, crm_moto_setup):
        from app.routers.calendar import _set_reminders, _get_reminders
        with patch("app.routers.calendar.audit_event"):
            _set_reminders(self._CAL_ID, self._EVT_ID, "alice_rem", [], 4070908800, "T", "U")
        assert _get_reminders(self._CAL_ID, self._EVT_ID, "alice_rem") == []

    def test_past_fire_at_skipped(self, crm_moto_setup):
        from app.routers.calendar import _set_reminders, _get_reminders
        from app.models import EventReminderIn, EventReminderMethod
        with patch("app.routers.calendar.audit_event"):
            # event started 1 second ago → fire_at in the past
            import time
            past_ts = int(time.time()) - 60
            written = _set_reminders(
                self._CAL_ID, self._EVT_ID, "alice_rem",
                [EventReminderIn(minutes_before=1, method=EventReminderMethod.in_app)],
                past_ts, "T", "U",
            )
        assert len(written) == 0

    def test_mark_fired_idempotent(self, crm_moto_setup):
        from app.services.crm_event_reminders import mark_reminder_fired
        from app.core.tables import T
        # audit_event is called via lazy import inside mark_reminder_fired
        with patch("app.services.alerts.audit_event"):
            reminder_key = "cal1#evt1#usr1"
            reminder_id = f"REM#{uuid.uuid4().hex}"
            T.crm_event_reminders.put_item(Item={
                "reminder_key": reminder_key,
                "reminder_id": reminder_id,
                "fired": False,
                "GSI1PK": "DUE",
                "GSI1SK": 1,
            })
            mark_reminder_fired(reminder_key, reminder_id)
            mark_reminder_fired(reminder_key, reminder_id)  # idempotent
        item = T.crm_event_reminders.get_item(
            Key={"reminder_key": reminder_key, "reminder_id": reminder_id}
        ).get("Item")
        assert item["fired"] is True
        assert "GSI1PK" not in item

    def test_list_due_reminders(self, crm_moto_setup):
        from app.services.crm_event_reminders import list_due_reminders
        from app.core.tables import T
        now_ts = 1750000000
        T.crm_event_reminders.put_item(Item={
            "reminder_key": "kdue#evt#u",
            "reminder_id": "REM#due1",
            "fired": False,
            "GSI1PK": "DUE",
            "GSI1SK": now_ts - 10,
        })
        due = list_due_reminders(now=now_ts)
        assert any(i["reminder_id"] == "REM#due1" for i in due)

    def test_dispatch_in_app_reminder(self, crm_moto_setup):
        from app.services.crm_event_reminders import _dispatch_reminder
        # write_alert is imported lazily inside _dispatch_reminder
        with patch("app.services.alerts.write_alert") as mock_wa:
            _dispatch_reminder({
                "user_sub": "alice_rem",
                "event_name": "Stand-up",
                "event_start_utc": "2099-06-01T10:00:00Z",
                "minutes_before": 5,
                "method": "in_app",
                "calendar_id": "cal1",
                "event_id": "evt1",
            })
            mock_wa.assert_called_once()

    def test_dispatch_email_reminder(self, crm_moto_setup):
        from app.services.crm_event_reminders import _dispatch_reminder
        with patch("app.services.profile.get_profile_identity",
                   return_value={"email": "alice@test.local"}):
            with patch("app.services.alerts.send_alert_email") as mock_email:
                _dispatch_reminder({
                    "user_sub": "alice_rem",
                    "event_name": "Stand-up",
                    "event_start_utc": "2099-06-01T10:00:00Z",
                    "minutes_before": 5,
                    "method": "email",
                    "calendar_id": "cal1",
                    "event_id": "evt1",
                })
                mock_email.assert_called_once()

    def test_flag_off_reminder_endpoint_404(self, crm_moto_setup):
        from fastapi import HTTPException
        from app.routers.calendar import set_event_reminders
        from app.models import EventRemindersSetIn
        from app.core.settings import S as _S
        object.__setattr__(_S, "crm_event_reminders_enabled", False)
        try:
            ctx = {"user_sub": "alice_rem"}
            body = EventRemindersSetIn(reminders=[])
            with pytest.raises(HTTPException) as ei:
                run_async(set_event_reminders(self._CAL_ID, self._EVT_ID, body, ctx))
            assert ei.value.status_code == 404
        finally:
            object.__setattr__(_S, "crm_event_reminders_enabled", True)


# ─── ACT-005: YEARLY recurrence ────────────────────────────────────────────

class TestAct005Yearly:
    def test_yearly_basic_expansion(self):
        from datetime import datetime, timezone
        from app.routers.calendar import _expand_rrule
        from app.models import RecurrenceRule
        start = datetime(2020, 3, 15, 10, 0, tzinfo=timezone.utc)
        end = datetime(2020, 3, 15, 11, 0, tzinfo=timezone.utc)
        rr = RecurrenceRule(freq="YEARLY", interval=1, count=3)
        window_s = datetime(2020, 1, 1, tzinfo=timezone.utc)
        window_e = datetime(2025, 12, 31, tzinfo=timezone.utc)
        occs = _expand_rrule(start, end, rr, window_s, window_e)
        assert len(occs) == 3
        years = [o[0].year for o in occs]
        assert years == [2020, 2021, 2022]

    def test_yearly_feb29_clamps_to_feb28(self):
        """Feb-29 annual event → Feb-28 in non-leap years."""
        from datetime import datetime, timezone
        from app.routers.calendar import _expand_rrule
        from app.models import RecurrenceRule
        start = datetime(2020, 2, 29, 12, 0, tzinfo=timezone.utc)
        end = datetime(2020, 2, 29, 13, 0, tzinfo=timezone.utc)
        rr = RecurrenceRule(freq="YEARLY", interval=1, count=5)
        window_s = datetime(2020, 1, 1, tzinfo=timezone.utc)
        window_e = datetime(2027, 12, 31, tzinfo=timezone.utc)
        occs = _expand_rrule(start, end, rr, window_s, window_e)
        assert len(occs) == 5
        # 2021 is not leap → Feb-28
        non_leap = [o for o in occs if o[0].year == 2021]
        assert len(non_leap) == 1
        assert non_leap[0][0].month == 2
        assert non_leap[0][0].day == 28
        # 2024 is leap → Feb-29
        leap = [o for o in occs if o[0].year == 2024]
        assert len(leap) == 1
        assert leap[0][0].day == 29

    def test_rrule_in_ics(self):
        from app.routers.calendar import _build_ics
        evt = {
            "name": "Annual Review",
            "start_utc": "2025-01-01T09:00:00Z",
            "recurrence_rule": {"freq": "YEARLY", "interval": 2, "count": 5},
        }
        ics = _build_ics(evt, "yr1")
        assert "RRULE:FREQ=YEARLY" in ics
        assert "INTERVAL=2" in ics
        assert "COUNT=5" in ics


# ─── ACT-006 / ACT-007: CRM Call Logging ────────────────────────────────────

class TestAct006And007CallLog:
    def test_create_and_list_call_log(self, crm_moto_setup):
        from app.services.call_history import create_crm_call_log, list_crm_call_logs
        result = create_crm_call_log(
            user_sub="calluser1",
            subject="Follow-up call",
            description="Discussed Q4 targets",
            direction="outbound",
            duration_seconds=300,
            outcome="connected",
        )
        assert result["subject"] == "Follow-up call"
        assert result["outcome"] == "connected"
        listing = list_crm_call_logs("calluser1", limit=10)
        assert any(i["call_id"] == result["call_id"] for i in listing["items"])

    def test_update_call_log(self, crm_moto_setup):
        from app.services.call_history import create_crm_call_log, update_crm_call_log
        original = create_crm_call_log(
            user_sub="calluser2",
            subject="Init", description="", direction="inbound",
            duration_seconds=60, outcome="connected",
        )
        updated = update_crm_call_log("calluser2", original["call_id"], outcome="left_message")
        assert updated["outcome"] == "left_message"

    def test_delete_call_log(self, crm_moto_setup):
        from app.services.call_history import create_crm_call_log, delete_crm_call_log, get_crm_call_log
        log = create_crm_call_log(
            user_sub="calluser3",
            subject="To delete", description="", direction="outbound",
            duration_seconds=0, outcome="busy",
        )
        assert delete_crm_call_log("calluser3", log["call_id"]) is True
        assert get_crm_call_log("calluser3", log["call_id"]) is None

    def test_entity_link_fires_timeline(self, crm_moto_setup):
        """ACT-007: creating a linked call fires record_crm_activity."""
        # The call service imports crm_activity_timeline lazily; the actual
        # write will succeed (timeline table is live in moto), just assert the
        # call log itself is created and has entity link fields.
        from app.services.call_history import create_crm_call_log
        result = create_crm_call_log(
            user_sub="calluser4",
            subject="Entity call",
            description="",
            direction="outbound",
            duration_seconds=90,
            outcome="connected",
            linked_entity_type="contact",
            linked_entity_id="contact_123",
        )
        assert result["linked_entity_type"] == "contact"
        assert result["linked_entity_id"] == "contact_123"
        # Verify timeline entry was written
        from app.services.crm_activity_timeline import list_entity_activities
        tl = list_entity_activities("contact", "contact_123")
        assert any(i["activity_id"] == result["call_id"] for i in tl["items"])

    def test_flag_off_returns_404(self, crm_moto_setup):
        from fastapi import HTTPException
        from app.routers.call_history import ui_create_crm_call_log
        from app.models import CallLogCreateIn, CallOutcome
        from app.core.settings import S as _S
        object.__setattr__(_S, "crm_activities_enabled", False)
        try:
            ctx = {"user_sub": "calluser5"}
            body = CallLogCreateIn(
                subject="Test", direction="outbound",
                duration_seconds=0, outcome=CallOutcome.connected,
            )
            with pytest.raises(HTTPException) as ei:
                run_async(ui_create_crm_call_log(body, ctx))
            assert ei.value.status_code == 404
        finally:
            object.__setattr__(_S, "crm_activities_enabled", True)


# ─── ACT-009: CRM Activity Timeline ─────────────────────────────────────────

class TestAct009Timeline:
    def test_record_and_list_activity(self, crm_moto_setup):
        from app.services.crm_activity_timeline import record_crm_activity, list_entity_activities
        record_crm_activity(
            entity_type="contact",
            entity_id="contact_abc",
            activity_type="call",
            activity_id="call_xyz",
            user_sub="usr1",
            summary="Sales call",
            metadata={"outcome": "connected"},
        )
        result = list_entity_activities("contact", "contact_abc")
        assert any(i["activity_id"] == "call_xyz" for i in result["items"])

    def test_record_noop_when_disabled(self, crm_moto_setup):
        from app.services.crm_activity_timeline import record_crm_activity
        from app.core.settings import S as _S
        from app.core.tables import T
        object.__setattr__(_S, "crm_activity_timeline_enabled", False)
        try:
            before = T.crm_activity_timeline.scan()["Count"]
            record_crm_activity("contact", "c2", "task", "t2", "usr1", summary="X")
            after = T.crm_activity_timeline.scan()["Count"]
            assert after == before
        finally:
            object.__setattr__(_S, "crm_activity_timeline_enabled", True)

    def test_delete_activity(self, crm_moto_setup):
        from app.services.crm_activity_timeline import record_crm_activity, delete_entity_activity, list_entity_activities
        from app.core.tables import T
        from boto3.dynamodb.conditions import Key
        # Use unique IDs to avoid cross-test pollution
        entity_id = f"del_contact_{uuid.uuid4().hex[:8]}"
        act_id = f"act_{uuid.uuid4().hex[:8]}"
        record_crm_activity("contact", entity_id, "note", act_id, "usr1", summary="Test note")
        # Find the actual SK from the table
        rows = T.crm_activity_timeline.query(
            KeyConditionExpression=Key("entity_key").eq(f"contact#{entity_id}")
        )["Items"]
        assert len(rows) == 1
        actual_sk = rows[0]["sk"]
        with patch("app.services.alerts.audit_event"):
            deleted = delete_entity_activity("contact", entity_id, actual_sk, "usr1")
        assert deleted is True
        items_after = list_entity_activities("contact", entity_id)["items"]
        assert len(items_after) == 0


# ─── ACT-008: CRM Tasks ──────────────────────────────────────────────────────

class TestAct008Tasks:
    def test_create_and_get_task(self, crm_moto_setup):
        from app.services.crm_tasks import create_task, get_task
        result = create_task(
            user_sub="task_user1",
            subject="Setup demo",
            description="Prepare demo environment",
            status="not_started",
            priority="high",
        )
        assert result["subject"] == "Setup demo"
        assert result["status"] == "not_started"
        fetched = get_task("task_user1", result["task_id"])
        assert fetched is not None
        assert fetched["task_id"] == result["task_id"]

    def test_update_task_status(self, crm_moto_setup):
        from app.services.crm_tasks import create_task, update_task
        task = create_task("task_user2", "Do it", status="not_started", priority="medium")
        updated = update_task("task_user2", task["task_id"], status="in_progress")
        assert updated["status"] == "in_progress"

    def test_delete_task(self, crm_moto_setup):
        from app.services.crm_tasks import create_task, delete_task, get_task
        task = create_task("task_user3", "Temp task", status="not_started", priority="low")
        assert delete_task("task_user3", task["task_id"]) is True
        assert get_task("task_user3", task["task_id"]) is None

    def test_list_tasks(self, crm_moto_setup):
        from app.services.crm_tasks import create_task, list_tasks
        user = f"task_list_user_{uuid.uuid4().hex[:6]}"
        create_task(user, "Task A", status="not_started", priority="low")
        create_task(user, "Task B", status="in_progress", priority="medium")
        result = list_tasks(user, limit=10)
        assert result["count"] >= 2

    def test_task_routes_flag_off_404(self, crm_moto_setup):
        from fastapi import HTTPException
        from app.routers.crm_tasks import create_crm_task
        from app.models import CrmTaskCreateIn
        from app.core.settings import S as _S
        object.__setattr__(_S, "crm_tasks_enabled", False)
        try:
            ctx = {"user_sub": "task_user4"}
            body = CrmTaskCreateIn(subject="X", status="not_started", priority="low")
            with pytest.raises(HTTPException) as ei:
                run_async(create_crm_task(body, ctx))
            assert ei.value.status_code == 404
        finally:
            object.__setattr__(_S, "crm_tasks_enabled", True)


# ─── ACT-010: CRM Notes ──────────────────────────────────────────────────────

class TestAct010Notes:
    def test_create_and_list_note(self, crm_moto_setup):
        from app.services.crm_notes import create_note, list_notes
        result = create_note(
            user_sub="note_user1",
            body="This is my note",
        )
        assert result["body"] == "This is my note"
        assert result["note_id"].startswith("note_")
        listing = list_notes("note_user1")
        assert any(n["note_id"] == result["note_id"] for n in listing["notes"])

    def test_create_note_with_entity_link(self, crm_moto_setup):
        from app.services.crm_notes import create_note, list_notes_by_entity
        result = create_note(
            user_sub="note_user2",
            body="Linked note",
            linked_entity_type="lead",
            linked_entity_id="lead_001",
        )
        assert result["linked_entity_type"] == "lead"
        by_entity = list_notes_by_entity("lead", "lead_001")
        assert any(n["note_id"] == result["note_id"] for n in by_entity["notes"])

    def test_update_note(self, crm_moto_setup):
        from app.services.crm_notes import create_note, update_note
        note = create_note("note_user3", body="Original body")
        updated = update_note("note_user3", note["note_id"], body="Updated body")
        assert updated["body"] == "Updated body"

    def test_delete_note(self, crm_moto_setup):
        from app.services.crm_notes import create_note, delete_note, get_note
        note = create_note("note_user4", body="To be deleted")
        assert delete_note("note_user4", note["note_id"]) is True
        assert get_note("note_user4", note["note_id"]) is None

    def test_note_flag_off_404(self, crm_moto_setup):
        from fastapi import HTTPException
        from app.routers.crm_notes import create_crm_note
        from app.models import CrmNoteCreateIn
        from app.core.settings import S as _S
        object.__setattr__(_S, "crm_notes_enabled", False)
        try:
            ctx = {"user_sub": "note_user5"}
            body = CrmNoteCreateIn(body="X")
            with pytest.raises(HTTPException) as ei:
                run_async(create_crm_note(body, ctx))
            assert ei.value.status_code == 404
        finally:
            object.__setattr__(_S, "crm_notes_enabled", True)

    def test_note_timeline_fired(self, crm_moto_setup):
        """ACT-010: linked note triggers record_crm_activity."""
        from app.services import crm_activity_timeline as tm
        with patch.object(tm, "record_crm_activity") as mock_rca:
            from app.services.crm_notes import create_note
            create_note("note_user6", body="With link",
                        linked_entity_type="account", linked_entity_id="acc_001")
            mock_rca.assert_called_once()
