from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.services import broadcast_store


class _FakeTable:
    def __init__(self) -> None:
        self.items = {}

    @staticmethod
    def _primary_key(item: dict) -> str | None:
        return item.get("transition_id") or item.get("session_id") or item.get("profile_id")

    def put_item(self, *, Item, ConditionExpression=None):  # noqa: N803
        if ConditionExpression and "attribute_not_exists" in ConditionExpression:
            key = self._primary_key(Item)
            if key in self.items:
                raise AssertionError("duplicate insert")
        key = self._primary_key(Item)
        self.items[key] = Item

    def get_item(self, *, Key, ConsistentRead=False):  # noqa: N803
        key = Key.get("transition_id") or Key.get("session_id") or Key.get("profile_id")
        item = self.items.get(key)
        return {"Item": item} if item else {}

    def query(self, **kwargs):
        index = kwargs.get("IndexName")
        if index == "ByStatusCreatedAt":
            status = kwargs["KeyConditionExpression"]._values[1]
            items = [i for i in self.items.values() if i.get("status") == status]
        elif index == "ByCreatorCreatedAt":
            creator = kwargs["KeyConditionExpression"]._values[1]
            items = [i for i in self.items.values() if i.get("created_by") == creator]
        else:
            items = list(self.items.values())
        return {"Items": items, "LastEvaluatedKey": None}


def test_create_and_get_profile_roundtrip() -> None:
    profiles = _FakeTable()
    with patch.object(
        broadcast_store,
        "T",
        SimpleNamespace(broadcast_profiles=profiles, broadcast_sessions=_FakeTable(), broadcast_outputs=_FakeTable(), broadcast_session_transitions=_FakeTable()),
    ):
        profile = broadcast_store.create_profile(
            name="Main",
            region="us-east-1",
            rendition_preset="1080p",
            created_by="user-1",
        )
        loaded = broadcast_store.get_profile(profile.id)

    assert loaded.id == profile.id
    assert loaded.region == "us-east-1"


def test_get_session_missing_raises_404() -> None:
    with patch.object(
        broadcast_store,
        "T",
        SimpleNamespace(broadcast_profiles=_FakeTable(), broadcast_sessions=_FakeTable(), broadcast_outputs=_FakeTable(), broadcast_session_transitions=_FakeTable()),
    ):
        with pytest.raises(HTTPException) as exc:
            broadcast_store.get_session("missing")

    assert exc.value.status_code == 404


def test_list_sessions_by_status_uses_status_index() -> None:
    sessions = _FakeTable()
    sessions.put_item(
        Item={
            "session_id": "s1",
            "profile_id": "p1",
            "status": "live",
            "created_by": "user-1",
            "created_at": "2026-03-25T00:00:00+00:00",
            "updated_at": "2026-03-25T00:00:00+00:00",
        }
    )
    with patch.object(
        broadcast_store,
        "T",
        SimpleNamespace(broadcast_profiles=_FakeTable(), broadcast_sessions=sessions, broadcast_outputs=_FakeTable(), broadcast_session_transitions=_FakeTable()),
    ):
        out = broadcast_store.list_sessions_by_status("live")
    assert len(out["items"]) == 1
    assert out["items"][0].status == "live"


def test_transition_session_status_persists_audit_record() -> None:
    sessions = _FakeTable()
    audits = _FakeTable()
    sessions.put_item(
        Item={
            "session_id": "s2",
            "profile_id": "p1",
            "status": "ready",
            "created_by": "user-1",
            "created_at": "2026-03-25T00:00:00+00:00",
            "updated_at": "2026-03-25T00:00:00+00:00",
        }
    )
    with patch.object(
        broadcast_store,
        "T",
        SimpleNamespace(
            broadcast_profiles=_FakeTable(),
            broadcast_sessions=sessions,
            broadcast_outputs=_FakeTable(),
            broadcast_session_transitions=audits,
        ),
    ):
        out = broadcast_store.transition_session_status(
            session_id="s2",
            to_status="live",
            reason="start requested",
            actor="ops-user",
        )
    assert out.status == "live"
    assert len(audits.items) == 1


def test_transition_session_status_rejects_illegal_transition() -> None:
    sessions = _FakeTable()
    sessions.put_item(
        Item={
            "session_id": "s3",
            "profile_id": "p1",
            "status": "draft",
            "created_by": "user-1",
            "created_at": "2026-03-25T00:00:00+00:00",
            "updated_at": "2026-03-25T00:00:00+00:00",
        }
    )
    with patch.object(
        broadcast_store,
        "T",
        SimpleNamespace(
            broadcast_profiles=_FakeTable(),
            broadcast_sessions=sessions,
            broadcast_outputs=_FakeTable(),
            broadcast_session_transitions=_FakeTable(),
        ),
    ):
        with pytest.raises(HTTPException) as exc:
            broadcast_store.transition_session_status(
                session_id="s3",
                to_status="live",
                reason="skip provisioning",
                actor="ops-user",
            )
    assert exc.value.status_code == 409
    assert exc.value.detail["code"] == "BROADCAST_INVALID_STATE_TRANSITION"


def test_create_session_rejects_raw_stream_key_value() -> None:
    with patch.object(
        broadcast_store,
        "T",
        SimpleNamespace(
            broadcast_profiles=_FakeTable(),
            broadcast_sessions=_FakeTable(),
            broadcast_outputs=_FakeTable(),
            broadcast_session_transitions=_FakeTable(),
        ),
    ):
        with pytest.raises(HTTPException) as exc:
            broadcast_store.create_session(
                profile_id="p1",
                created_by="user-1",
                stream_key_ref="raw-secret-value",
            )
    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "BROADCAST_SECRET_REFERENCE_REQUIRED"
