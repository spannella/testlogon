"""Unit tests for broadcast scheduling (BCAST-009)."""
from __future__ import annotations

import time
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

import pytest
from fastapi import HTTPException

from app.services import broadcast_store
from app.services.broadcast_state_machine import validate_transition
from app.services.broadcast_reminders import generate_ical


# ─── Fake DDB Tables ────────────────────────────────────────────


class _FakeTable:
    """Fake DDB table that stores items keyed by a composite of their primary keys."""

    def __init__(self) -> None:
        self.items: dict = {}

    # Subclasses or instances should set this to determine key extraction mode
    key_mode: str = "auto"  # "auto", "pk_sk", or "single"

    def _make_key(self, item_or_key: dict) -> str:
        """Build a lookup key from an item or a Key dict."""
        if self.key_mode == "pk_sk":
            pk = item_or_key.get("pk", "")
            sk = item_or_key.get("sk", "")
            return f"{pk}|{sk}" if sk else pk

        # Default: use session_id/transition_id/profile_id if present and no sk
        for single in ("session_id", "transition_id", "profile_id"):
            if single in item_or_key and "sk" not in item_or_key:
                return item_or_key[single]
        pk = item_or_key.get("pk", "")
        sk = item_or_key.get("sk", "")
        if pk:
            return f"{pk}|{sk}" if sk else pk
        for single in ("session_id", "transition_id", "profile_id"):
            if single in item_or_key:
                return item_or_key[single]
        return str(id(item_or_key))

    def put_item(self, *, Item, ConditionExpression=None):  # noqa: N803
        key = self._make_key(Item)
        if ConditionExpression and "attribute_not_exists" in str(ConditionExpression):
            if key in self.items:
                raise AssertionError("duplicate insert")
        self.items[key] = Item

    def get_item(self, *, Key, ConsistentRead=False):  # noqa: N803
        key = self._make_key(Key)
        item = self.items.get(key)
        return {"Item": item} if item else {}

    def delete_item(self, *, Key):  # noqa: N803
        key = self._make_key(Key)
        self.items.pop(key, None)

    def update_item(self, *, Key, UpdateExpression="", ExpressionAttributeValues=None):  # noqa: N803
        key = self._make_key(Key)
        item = self.items.get(key)
        if not item:
            return
        if ExpressionAttributeValues:
            for k, v in ExpressionAttributeValues.items():
                clean_k = k.lstrip(":")
                item[clean_k] = v
        # Handle "REMOVE attr1, attr2" in UpdateExpression
        if "REMOVE" in UpdateExpression:
            remove_part = UpdateExpression.split("REMOVE")[1].strip()
            for attr in remove_part.split(","):
                item.pop(attr.strip(), None)

    def query(self, **kwargs):
        index = kwargs.get("IndexName")
        limit = kwargs.get("Limit", 100)

        if index == "ByScheduledAt":
            kce = kwargs.get("KeyConditionExpression")
            threshold = None
            if hasattr(kce, "_values") and len(kce._values) >= 2:
                rhs = kce._values[1]
                if hasattr(rhs, "_values") and len(rhs._values) >= 2:
                    threshold = rhs._values[1]
            all_items = list(self.items.values())
            result = []
            for item in all_items:
                if item.get("schedule_status") == "scheduled":
                    sa = item.get("scheduled_at")
                    if sa is not None:
                        if threshold is None or sa <= threshold:
                            result.append(item)
            result.sort(key=lambda x: x.get("scheduled_at", 0))
            return {"Items": result[:limit]}

        elif index == "ByCreatorCreatedAt":
            all_items = list(self.items.values())
            result = [i for i in all_items if i.get("created_by")]
            fe = kwargs.get("FilterExpression")
            if fe:
                result = [i for i in result if i.get("schedule_status") == "scheduled"]
            return {"Items": result[:limit]}

        elif index == "ByRemindAt":
            all_items = list(self.items.values())
            result = [i for i in all_items if i.get("remind_status") == "pending"]
            return {"Items": result[:limit]}

        else:
            # Default: filter by pk from KeyConditionExpression if present
            kce = kwargs.get("KeyConditionExpression")
            all_items = list(self.items.values())
            if kce:
                try:
                    pk_val = kce._values[1]
                    if isinstance(pk_val, str):
                        all_items = [i for i in all_items if i.get("pk") == pk_val]
                except (AttributeError, IndexError):
                    pass
            return {"Items": all_items[:limit]}

    def batch_writer(self):
        return _FakeBatchWriter(self)


class _FakeBatchWriter:
    def __init__(self, table: _FakeTable):
        self.table = table

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def delete_item(self, *, Key):  # noqa: N803
        self.table.delete_item(Key=Key)


def _make_tables():
    reminders = _FakeTable()
    reminders.key_mode = "pk_sk"
    return SimpleNamespace(
        broadcast_profiles=_FakeTable(),
        broadcast_sessions=_FakeTable(),
        broadcast_outputs=_FakeTable(),
        broadcast_session_transitions=_FakeTable(),
        broadcast_reminders=reminders,
    )


def _create_session(tables, session_id: str, created_by: str = "user-1", **overrides):
    """Create a session directly in the fake table."""
    item = {
        "session_id": session_id,
        "profile_id": "prof-1",
        "status": overrides.pop("status", "draft"),
        "created_by": created_by,
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
        "stream_key_rotation_interval_seconds": 86400,
        "pk": f"SESSION#{session_id}",
    }
    item.update(overrides)
    tables.broadcast_sessions.items[session_id] = item
    return item


# ─── State Machine Tests ────────────────────────────────────────


def test_state_machine_draft_to_scheduled():
    assert validate_transition("draft", "scheduled").legal is True


def test_state_machine_scheduled_to_provisioning():
    assert validate_transition("scheduled", "provisioning").legal is True


def test_state_machine_scheduled_to_cancelled():
    assert validate_transition("scheduled", "cancelled").legal is True


def test_state_machine_scheduled_to_error():
    assert validate_transition("scheduled", "error").legal is True


def test_state_machine_scheduled_to_live_illegal():
    assert validate_transition("scheduled", "live").legal is False


def test_state_machine_scheduled_to_stopped_illegal():
    assert validate_transition("scheduled", "stopped").legal is False


def test_state_machine_live_to_scheduled_illegal():
    assert validate_transition("live", "scheduled").legal is False


# ─── Session Store Scheduling Tests ────────────────────────────────


def test_session_to_item_includes_scheduling_fields():
    from app.models_broadcast import BroadcastSessionModel
    session = BroadcastSessionModel(
        id="s1",
        profile_id="p1",
        status="scheduled",
        created_by="user-1",
        scheduled_at=1700000000,
        schedule_status="scheduled",
        name="Test Broadcast",
        description="A test stream",
    )
    item = broadcast_store.session_to_item(session)
    assert item["scheduled_at"] == 1700000000
    assert item["schedule_status"] == "scheduled"
    assert item["name"] == "Test Broadcast"
    assert item["description"] == "A test stream"


def test_session_from_item_reads_scheduling_fields():
    item = {
        "session_id": "s1",
        "profile_id": "p1",
        "status": "scheduled",
        "created_by": "user-1",
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
        "stream_key_rotation_interval_seconds": 86400,
        "scheduled_at": 1700000000,
        "schedule_status": "scheduled",
        "name": "My Stream",
        "description": "Hello",
        "pk": "SESSION#s1",
    }
    session = broadcast_store.session_from_item(item)
    assert session.scheduled_at == 1700000000
    assert session.schedule_status == "scheduled"
    assert session.name == "My Stream"


def test_session_from_item_no_scheduling_fields():
    """Existing sessions without scheduling fields still load fine."""
    item = {
        "session_id": "s2",
        "profile_id": "p1",
        "status": "draft",
        "created_by": "user-1",
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
        "stream_key_rotation_interval_seconds": 86400,
        "pk": "SESSION#s2",
    }
    session = broadcast_store.session_from_item(item)
    assert session.scheduled_at is None
    assert session.schedule_status is None
    assert session.name is None


def test_list_due_scheduled_sessions():
    tables = _make_tables()
    now = 1700000000

    _create_session(tables, "s1", status="scheduled", schedule_status="scheduled", scheduled_at=now - 60)
    _create_session(tables, "s2", status="scheduled", schedule_status="scheduled", scheduled_at=now - 3600)
    _create_session(tables, "s3", status="scheduled", schedule_status="scheduled", scheduled_at=now + 3600)
    _create_session(tables, "s4", status="draft")

    with patch.object(broadcast_store, "T", tables):
        due = broadcast_store.list_due_scheduled_sessions(now=now, limit=10)

    assert len(due) == 2
    ids = {s.id for s in due}
    assert "s1" in ids
    assert "s2" in ids
    assert "s3" not in ids


def test_list_due_ordered_oldest_first():
    tables = _make_tables()
    now = 1700000000

    _create_session(tables, "s_old", status="scheduled", schedule_status="scheduled", scheduled_at=now - 7200)
    _create_session(tables, "s_new", status="scheduled", schedule_status="scheduled", scheduled_at=now - 60)

    with patch.object(broadcast_store, "T", tables):
        due = broadcast_store.list_due_scheduled_sessions(now=now, limit=10)

    assert due[0].id == "s_old"
    assert due[1].id == "s_new"


def test_transition_preserves_scheduling_fields():
    tables = _make_tables()
    _create_session(
        tables, "s1",
        status="draft",
        schedule_status=None,
        scheduled_at=1700000000,
        name="My Broadcast",
    )

    with patch.object(broadcast_store, "T", tables):
        updated = broadcast_store.transition_session_status(
            session_id="s1",
            to_status="scheduled",
            reason="schedule-requested",
            actor="user-1",
            extra_fields={"schedule_status": "scheduled"},
        )

    assert updated.status == "scheduled"
    assert updated.scheduled_at == 1700000000
    assert updated.name == "My Broadcast"
    assert updated.schedule_status == "scheduled"


# ─── Reminder Tests ──────────────────────────────────────────────


def test_register_and_cancel_reminder():
    tables = _make_tables()

    with patch("app.services.broadcast_reminders.T", tables):
        from app.services.broadcast_reminders import register_reminder, cancel_reminder

        result = register_reminder(
            session_id="s1",
            user_id="user-1",
            remind_at_ts=1700000000,
            session_name="Test",
        )
        assert result["ok"] is True

        # Verify item exists
        items = list(tables.broadcast_reminders.items.values())
        assert len(items) == 1
        assert items[0]["remind_status"] == "pending"

        # Cancel
        cancel_reminder("s1", "user-1")
        items_after = list(tables.broadcast_reminders.items.values())
        assert len(items_after) == 0


def test_cancel_reminders_for_session():
    tables = _make_tables()

    with patch("app.services.broadcast_reminders.T", tables):
        from app.services.broadcast_reminders import register_reminder, cancel_reminders_for_session

        register_reminder(session_id="s1", user_id="u1", remind_at_ts=1700000000)
        register_reminder(session_id="s1", user_id="u2", remind_at_ts=1700000000)
        register_reminder(session_id="s2", user_id="u1", remind_at_ts=1700000000)

        deleted = cancel_reminders_for_session("s1")
        assert deleted == 2

        # s2 reminder should still exist
        remaining = list(tables.broadcast_reminders.items.values())
        assert len(remaining) == 1
        assert remaining[0]["session_id"] == "s2"


def test_dispatch_due_reminders():
    tables = _make_tables()

    with patch("app.services.broadcast_reminders.T", tables):
        from app.services.broadcast_reminders import register_reminder, dispatch_due_reminders

        register_reminder(
            session_id="s1",
            user_id="user-1",
            remind_at_ts=1700000000,
            session_name="Big Show",
            interval=900,
        )

        with patch("app.services.alerts.write_alert") as mock_alert:
            dispatched = dispatch_due_reminders(now=1700000001, limit=50)
            assert dispatched == 1
            mock_alert.assert_called_once()
            call_args = mock_alert.call_args
            assert call_args[0][0] == "user-1"
            assert "15 minutes" in call_args[1]["title"]


# ─── iCal Tests ──────────────────────────────────────────────────


def test_generate_ical_valid_format():
    ical = generate_ical(
        session_id="s1",
        name="Test Stream",
        description="A test broadcast",
        scheduled_at=1700000000,
        frontend_base_url="https://example.com",
    )
    assert "BEGIN:VCALENDAR" in ical
    assert "BEGIN:VEVENT" in ical
    assert "SUMMARY:Test Stream" in ical
    assert "DTSTART:" in ical
    assert "DTEND:" in ical
    assert "URL:https://example.com/broadcast/s1" in ical
    assert "BEGIN:VALARM" in ical
    assert "END:VCALENDAR" in ical


def test_generate_ical_escapes_special_chars():
    ical = generate_ical(
        session_id="s1",
        name="Live, Stream; Now",
        description="Don't miss\nthis event",
        scheduled_at=1700000000,
        frontend_base_url="https://example.com",
    )
    assert "SUMMARY:Live\\, Stream\\; Now" in ical
    assert "DESCRIPTION:Don't miss\\nthis event" in ical
