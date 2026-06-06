"""Unit tests for CALL-012 / GAP-0150: Group Call Service.

Covers: create_group_call, get_call, get_active_call_for_conversation,
        list_call_history, join_call, leave_call, end_call,
        list_participants, get_participant, update_media_state, relay_signal,
        and their error paths.

Runs FULLY OFFLINE:
  - moto in-process for the GroupCallSessions DynamoDB table.
  - _get_conversation_participant_ids is patched to return a fixed member set
    (the real impl queries a separate Participants table via GSI1).
  - _emit_timeline is patched to a no-op (real impl writes to the Messages table).
  - Settings `S` is a frozen dataclass, so feature flags are toggled with
    object.__setattr__ (NOT monkeypatch.setenv, which would require a reload).

The service is exercised by calling its functions directly (no TestClient).
"""
from __future__ import annotations

import os
import sys

import boto3
import pytest
from moto import mock_aws

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

TABLE_NAME = "GroupCallSessions"
CONV_ID = "conv_test_001"
PARTICIPANTS = {"alice", "bob", "charlie"}  # 3-person group


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture()
def ddb_table():
    """Create GroupCallSessions table with the correct GSI schema via moto.

    Mirrors scripts/local-ddb-init.py: pk/sk string keys, plus
    ByConversationCreatedAt (conversation_id HASH, created_at N RANGE) and
    ByStateCreatedAt (state HASH, created_at N RANGE).
    """
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        table = ddb.create_table(
            TableName=TABLE_NAME,
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "conversation_id", "AttributeType": "S"},
                {"AttributeName": "created_at", "AttributeType": "N"},
                {"AttributeName": "state", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "ByConversationCreatedAt",
                    "KeySchema": [
                        {"AttributeName": "conversation_id", "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "ByStateCreatedAt",
                    "KeySchema": [
                        {"AttributeName": "state", "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        yield table


@pytest.fixture(autouse=True)
def _patch_table(ddb_table, monkeypatch):
    """Wire the service's _table() to the moto table handle."""
    import app.services.group_call_service as svc

    monkeypatch.setattr(svc, "_table", lambda: ddb_table)


@pytest.fixture(autouse=True)
def _patch_participants(monkeypatch):
    """Patch _get_conversation_participant_ids to a fixed 3-member set."""
    import app.services.group_call_service as svc

    monkeypatch.setattr(
        svc, "_get_conversation_participant_ids", lambda _conv_id: set(PARTICIPANTS)
    )


@pytest.fixture(autouse=True)
def _patch_timeline(monkeypatch):
    """Patch _emit_timeline to a no-op (avoids touching the Messages table)."""
    import app.services.group_call_service as svc

    monkeypatch.setattr(svc, "_emit_timeline", lambda *a, **k: None)


@pytest.fixture(autouse=True)
def _enable_group_calls():
    """Force feature flags via object.__setattr__ (S is a frozen dataclass)."""
    from app.core.settings import S

    prev_enabled = S.group_calls_enabled
    prev_cap = S.group_call_max_participants
    object.__setattr__(S, "group_calls_enabled", True)
    object.__setattr__(S, "group_call_max_participants", 8)
    try:
        yield
    finally:
        object.__setattr__(S, "group_calls_enabled", prev_enabled)
        object.__setattr__(S, "group_call_max_participants", prev_cap)


def _make_call(creator="alice"):
    from app.services.group_call_service import create_group_call

    return create_group_call(conversation_id=CONV_ID, creator_user_id=creator)


# ---------------------------------------------------------------------------
# create_group_call
# ---------------------------------------------------------------------------


def test_create_group_call_success():
    meta = _make_call()
    assert meta["call_id"].startswith("gc_")
    assert meta["state"] == "created"
    assert meta["conversation_id"] == CONV_ID
    assert meta["creator_user_id"] == "alice"
    assert meta["current_participant_count"] == 0
    assert meta["start_ts"] == 0
    assert meta["max_participants"] == 8


def test_create_group_call_non_member_rejected():
    from app.services.group_call_service import create_group_call, GroupCallError

    with pytest.raises(GroupCallError) as exc:
        create_group_call(conversation_id=CONV_ID, creator_user_id="mallory")
    assert exc.value.status_code == 403


def test_create_group_call_requires_three_participants(monkeypatch):
    import app.services.group_call_service as svc

    monkeypatch.setattr(svc, "_get_conversation_participant_ids", lambda _: {"alice", "bob"})
    with pytest.raises(svc.GroupCallError) as exc:
        svc.create_group_call(conversation_id=CONV_ID, creator_user_id="alice")
    assert exc.value.status_code == 400


def test_create_group_call_duplicate_rejected():
    from app.services.group_call_service import GroupCallError

    _make_call()
    with pytest.raises(GroupCallError) as exc:
        _make_call()
    assert exc.value.status_code == 409


def test_create_group_call_disabled_raises():
    from app.core.settings import S
    from app.services.group_call_service import create_group_call, GroupCallError

    object.__setattr__(S, "group_calls_enabled", False)
    with pytest.raises(GroupCallError) as exc:
        create_group_call(conversation_id=CONV_ID, creator_user_id="alice")
    assert exc.value.status_code == 403


def test_create_group_call_clamps_max_participants():
    from app.core.settings import S
    from app.services.group_call_service import create_group_call

    object.__setattr__(S, "group_call_max_participants", 4)
    # Request 100; clamped to settings cap of 4.
    meta = create_group_call(
        conversation_id=CONV_ID, creator_user_id="alice", max_participants=100
    )
    assert meta["max_participants"] == 4


# ---------------------------------------------------------------------------
# get_call / get_active_call_for_conversation / list_call_history
# ---------------------------------------------------------------------------


def test_get_call_missing_returns_none():
    from app.services.group_call_service import get_call

    assert get_call("gc_does_not_exist") is None


def test_get_active_call_for_conversation():
    from app.services.group_call_service import get_active_call_for_conversation

    assert get_active_call_for_conversation(CONV_ID) is None
    meta = _make_call()
    active = get_active_call_for_conversation(CONV_ID)
    assert active is not None
    assert active["call_id"] == meta["call_id"]


def test_get_active_call_excludes_ended():
    from app.services.group_call_service import (
        join_call,
        end_call,
        get_active_call_for_conversation,
    )

    meta = _make_call()
    join_call(meta["call_id"], "alice", "Alice")
    end_call(meta["call_id"], "alice")
    assert get_active_call_for_conversation(CONV_ID) is None


def test_list_call_history():
    from app.services.group_call_service import (
        join_call,
        end_call,
        list_call_history,
    )

    meta1 = _make_call()
    join_call(meta1["call_id"], "alice", "Alice")
    end_call(meta1["call_id"], "alice")
    meta2 = _make_call()  # allowed now that the first call ended

    history = list_call_history(CONV_ID)
    ids = {h["call_id"] for h in history}
    assert {meta1["call_id"], meta2["call_id"]} <= ids
    assert all(h["sk"] == "META" for h in history)


# ---------------------------------------------------------------------------
# join_call / leave_call
# ---------------------------------------------------------------------------


def test_join_increments_participant_count():
    from app.services.group_call_service import join_call, get_call

    meta = _make_call()
    join_call(meta["call_id"], "alice", "Alice")
    updated = get_call(meta["call_id"])
    assert updated["current_participant_count"] == 1
    assert updated["state"] == "active"
    assert int(updated.get("start_ts") or 0) > 0


def test_join_writes_participant_row():
    from app.services.group_call_service import join_call, get_participant

    meta = _make_call()
    join_call(meta["call_id"], "alice", "Alice")
    part = get_participant(meta["call_id"], "alice")
    assert part is not None
    assert part["state"] == "active"
    assert part["display_name"] == "Alice"
    assert part["media_status"]["audio"] is True
    assert part["media_status"]["video"] is True  # mode == "video"


def test_join_is_idempotent():
    from app.services.group_call_service import join_call, get_call

    meta = _make_call()
    join_call(meta["call_id"], "alice", "Alice")
    join_call(meta["call_id"], "alice", "Alice")  # rejoin must not double-count
    updated = get_call(meta["call_id"])
    assert updated["current_participant_count"] == 1


def test_join_missing_call_raises():
    from app.services.group_call_service import join_call, GroupCallError

    with pytest.raises(GroupCallError) as exc:
        join_call("gc_missing", "alice", "Alice")
    assert exc.value.status_code == 404


def test_join_non_member_raises():
    from app.services.group_call_service import join_call, GroupCallError

    meta = _make_call()
    with pytest.raises(GroupCallError) as exc:
        join_call(meta["call_id"], "mallory", "Mallory")
    assert exc.value.status_code == 403


def test_join_ended_call_raises():
    from app.services.group_call_service import join_call, end_call, GroupCallError

    meta = _make_call()
    join_call(meta["call_id"], "alice", "Alice")
    end_call(meta["call_id"], "alice")
    with pytest.raises(GroupCallError) as exc:
        join_call(meta["call_id"], "bob", "Bob")
    assert exc.value.status_code == 410


def test_join_at_capacity_raises():
    from app.core.settings import S
    from app.services.group_call_service import join_call, GroupCallError

    # The service floors max_participants at 2 (max(2, min(req, cap))), so the
    # smallest achievable capacity is 2. Fill it, then a third member fails.
    object.__setattr__(S, "group_call_max_participants", 2)
    meta = _make_call()  # max_participants clamped to 2
    assert meta["max_participants"] == 2
    join_call(meta["call_id"], "alice", "Alice")
    join_call(meta["call_id"], "bob", "Bob")
    with pytest.raises(GroupCallError) as exc:
        join_call(meta["call_id"], "charlie", "Charlie")
    assert exc.value.status_code == 409


def test_two_participants_join():
    from app.services.group_call_service import join_call, get_call, list_participants

    meta = _make_call()
    join_call(meta["call_id"], "alice", "Alice")
    join_call(meta["call_id"], "bob", "Bob")
    assert get_call(meta["call_id"])["current_participant_count"] == 2
    active = [p for p in list_participants(meta["call_id"]) if p["state"] == "active"]
    assert {p["user_id"] for p in active} == {"alice", "bob"}


def test_leave_decrements_count():
    from app.services.group_call_service import join_call, leave_call, get_call

    meta = _make_call()
    join_call(meta["call_id"], "alice", "Alice")
    join_call(meta["call_id"], "bob", "Bob")
    result = leave_call(meta["call_id"], "bob")
    assert result["ok"] is True
    assert result["call_ended"] is False
    assert result["remaining_participants"] == 1
    assert get_call(meta["call_id"])["current_participant_count"] == 1


def test_leave_auto_ends_when_last_participant():
    from app.services.group_call_service import join_call, leave_call, get_call

    meta = _make_call()
    join_call(meta["call_id"], "alice", "Alice")
    result = leave_call(meta["call_id"], "alice")
    assert result["call_ended"] is True
    updated = get_call(meta["call_id"])
    assert updated["state"] == "ended"
    assert updated["end_reason"] == "all_left"


def test_leave_not_in_call_raises():
    from app.services.group_call_service import join_call, leave_call, GroupCallError

    meta = _make_call()
    join_call(meta["call_id"], "alice", "Alice")
    with pytest.raises(GroupCallError) as exc:
        leave_call(meta["call_id"], "bob")  # bob never joined
    assert exc.value.status_code == 400


def test_leave_missing_call_raises():
    from app.services.group_call_service import leave_call, GroupCallError

    with pytest.raises(GroupCallError) as exc:
        leave_call("gc_missing", "alice")
    assert exc.value.status_code == 404


# ---------------------------------------------------------------------------
# end_call authorization
# ---------------------------------------------------------------------------


def test_end_call_by_creator():
    from app.services.group_call_service import join_call, end_call, get_call

    meta = _make_call()
    join_call(meta["call_id"], "alice", "Alice")
    join_call(meta["call_id"], "bob", "Bob")
    result = end_call(meta["call_id"], "alice")
    assert result["ok"] is True
    assert result["call_id"] == meta["call_id"]
    assert result["duration_seconds"] >= 0
    assert result["total_participants"] == 2
    assert get_call(meta["call_id"])["state"] == "ended"


def test_end_call_marks_participants_left():
    from app.services.group_call_service import join_call, end_call, list_participants

    meta = _make_call()
    join_call(meta["call_id"], "alice", "Alice")
    join_call(meta["call_id"], "bob", "Bob")
    end_call(meta["call_id"], "alice")
    parts = list_participants(meta["call_id"])
    assert all(p["state"] == "left" for p in parts)


def test_end_call_by_non_creator_raises():
    from app.services.group_call_service import join_call, end_call, GroupCallError

    meta = _make_call()
    join_call(meta["call_id"], "alice", "Alice")
    join_call(meta["call_id"], "bob", "Bob")
    with pytest.raises(GroupCallError) as exc:
        end_call(meta["call_id"], "bob", role="USER")
    assert exc.value.status_code == 403


def test_end_call_by_admin_succeeds():
    from app.services.group_call_service import join_call, end_call, get_call

    meta = _make_call()
    join_call(meta["call_id"], "alice", "Alice")
    end_call(meta["call_id"], "charlie", role="ADMIN")
    assert get_call(meta["call_id"])["state"] == "ended"


def test_end_call_by_root_succeeds():
    from app.services.group_call_service import join_call, end_call, get_call

    meta = _make_call()
    join_call(meta["call_id"], "alice", "Alice")
    end_call(meta["call_id"], "root_user", role="ROOT")
    assert get_call(meta["call_id"])["state"] == "ended"


def test_end_call_already_ended_raises():
    from app.services.group_call_service import join_call, end_call, GroupCallError

    meta = _make_call()
    join_call(meta["call_id"], "alice", "Alice")
    end_call(meta["call_id"], "alice")
    with pytest.raises(GroupCallError) as exc:
        end_call(meta["call_id"], "alice")
    assert exc.value.status_code == 410


def test_end_call_missing_raises():
    from app.services.group_call_service import end_call, GroupCallError

    with pytest.raises(GroupCallError) as exc:
        end_call("gc_missing", "alice")
    assert exc.value.status_code == 404


# ---------------------------------------------------------------------------
# update_media_state
# ---------------------------------------------------------------------------


def test_update_media_mute_audio():
    from app.services.group_call_service import join_call, update_media_state

    meta = _make_call()
    join_call(meta["call_id"], "alice", "Alice")
    new_media = update_media_state(meta["call_id"], "alice", audio=False)
    assert new_media["audio"] is False
    assert new_media["video"] is True  # unchanged


def test_update_media_partial_only_changes_specified():
    from app.services.group_call_service import (
        join_call,
        update_media_state,
        get_participant,
    )

    meta = _make_call()
    join_call(meta["call_id"], "alice", "Alice")
    update_media_state(meta["call_id"], "alice", video=False)
    media = get_participant(meta["call_id"], "alice")["media_status"]
    assert media["video"] is False
    assert media["audio"] is True  # left untouched
    assert media["screen"] is False


def test_update_media_not_active_participant_raises():
    from app.services.group_call_service import update_media_state, GroupCallError

    meta = _make_call()  # alice has not joined
    with pytest.raises(GroupCallError) as exc:
        update_media_state(meta["call_id"], "alice", audio=False)
    assert exc.value.status_code == 400


def test_screen_share_allowed_when_no_conflict():
    from app.services.group_call_service import join_call, update_media_state

    meta = _make_call()
    join_call(meta["call_id"], "alice", "Alice")
    new_media = update_media_state(meta["call_id"], "alice", screen=True)
    assert new_media["screen"] is True


def test_screen_share_conflict():
    from app.services.group_call_service import join_call, update_media_state, GroupCallError

    meta = _make_call()
    join_call(meta["call_id"], "alice", "Alice")
    join_call(meta["call_id"], "bob", "Bob")
    update_media_state(meta["call_id"], "alice", screen=True)
    with pytest.raises(GroupCallError) as exc:
        update_media_state(meta["call_id"], "bob", screen=True)
    assert exc.value.status_code == 409


# ---------------------------------------------------------------------------
# relay_signal (dev mesh mode — in-memory only)
# ---------------------------------------------------------------------------


def test_relay_signal_success():
    from app.services.group_call_service import join_call, relay_signal

    meta = _make_call()
    join_call(meta["call_id"], "alice", "Alice")
    join_call(meta["call_id"], "bob", "Bob")
    result = relay_signal(meta["call_id"], "alice", "bob", "offer", {"sdp": "x"})
    assert result["ok"] is True
    assert result["relayed_to"] == "bob"


def test_relay_signal_inactive_target_raises():
    from app.services.group_call_service import join_call, relay_signal, GroupCallError

    meta = _make_call()
    join_call(meta["call_id"], "alice", "Alice")
    # bob has not joined
    with pytest.raises(GroupCallError) as exc:
        relay_signal(meta["call_id"], "alice", "bob", "offer", {})
    assert exc.value.status_code == 400


def test_relay_signal_inactive_sender_raises():
    from app.services.group_call_service import join_call, relay_signal, GroupCallError

    meta = _make_call()
    join_call(meta["call_id"], "bob", "Bob")
    # alice (sender) has not joined
    with pytest.raises(GroupCallError) as exc:
        relay_signal(meta["call_id"], "alice", "bob", "offer", {})
    assert exc.value.status_code == 403


def test_relay_signal_missing_call_raises():
    from app.services.group_call_service import relay_signal, GroupCallError

    with pytest.raises(GroupCallError) as exc:
        relay_signal("gc_missing", "alice", "bob", "offer", {})
    assert exc.value.status_code == 404
