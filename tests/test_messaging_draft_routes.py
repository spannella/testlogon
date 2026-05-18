from __future__ import annotations

import pytest
from pydantic import ValidationError

import sys
import types

sys.modules.setdefault("zipstream", types.ModuleType("zipstream"))

from app.routers import messaging
from app.services.messaging_drafts import DraftNotFoundError, DraftValidationError


def test_draft_route_happy_path_functions(monkeypatch):
    monkeypatch.setattr(messaging, "_is_messaging_drafts_enabled_for", lambda **kwargs: True)
    monkeypatch.setattr(messaging, "require_participant_active", lambda user_id, conversation_id: {"status": "active"})
    monkeypatch.setattr(
        messaging,
        "create_draft",
        lambda **kwargs: {
            "draft_id": "d1",
            "conversation_id": kwargs["conversation_id"],
            "owner_user_id": kwargs["owner_user_id"],
            "text": kwargs["text"],
            "version": 1,
            "created_at": 100,
            "updated_at": 100,
        },
    )
    monkeypatch.setattr(
        messaging,
        "list_drafts",
        lambda **kwargs: {
            "items": [
                {
                    "draft_id": "d1",
                    "conversation_id": kwargs["conversation_id"],
                    "owner_user_id": kwargs["owner_user_id"],
                    "text": "hello",
                    "version": 1,
                    "created_at": 100,
                    "updated_at": 101,
                }
            ],
            "next_cursor": None,
        },
    )
    monkeypatch.setattr(
        messaging,
        "get_draft",
        lambda **kwargs: {
            "draft_id": kwargs["draft_id"],
            "conversation_id": kwargs["conversation_id"],
            "owner_user_id": kwargs["owner_user_id"],
            "text": "hello",
            "version": 1,
            "created_at": 100,
            "updated_at": 101,
        },
    )
    monkeypatch.setattr(
        messaging,
        "update_draft",
        lambda **kwargs: {
            "draft_id": kwargs["draft_id"],
            "conversation_id": kwargs["conversation_id"],
            "owner_user_id": kwargs["owner_user_id"],
            "text": kwargs["text"],
            "version": 2,
            "created_at": 100,
            "updated_at": 102,
        },
    )
    deleted = {"called": False}
    monkeypatch.setattr(messaging, "delete_draft", lambda **kwargs: deleted.__setitem__("called", True))

    created = messaging.create_conversation_draft(
        "c1",
        messaging.DraftCreateIn(text="hello"),
        idempotency_key="idem-1",
        user_id="u1",
    )
    assert created.draft.draft_id == "d1"

    listed = messaging.list_conversation_drafts("c1", user_id="u1")
    assert listed.items[0].draft_id == "d1"

    fetched = messaging.get_conversation_draft("c1", "d1", user_id="u1")
    assert fetched.draft.draft_id == "d1"

    patched = messaging.patch_conversation_draft("c1", "d1", messaging.DraftPatchIn(text="updated"), user_id="u1")
    assert patched.draft.version == 2

    messaging.delete_conversation_draft("c1", "d1", user_id="u1")
    assert deleted["called"] is True


def test_draft_route_error_parity_and_validation(monkeypatch):
    monkeypatch.setattr(messaging, "_is_messaging_drafts_enabled_for", lambda **kwargs: True)
    # schema validation via pydantic models
    with pytest.raises(ValidationError):
        messaging.DraftCreateIn(text="")

    with pytest.raises(ValidationError):
        messaging.DraftPatchIn(text="x" * (messaging.MESSAGE_TEXT_MAX_CHARS + 1))

    # authz failure path
    monkeypatch.setattr(
        messaging,
        "require_participant_active",
        lambda _user_id, _conversation_id: (_ for _ in ()).throw(
            messaging.HTTPException(status_code=403, detail="Not an active participant")
        ),
    )
    with pytest.raises(messaging.HTTPException) as denied:
        messaging.list_conversation_drafts("c1", user_id="u1")
    assert denied.value.status_code == 403

    # restore active participant and test service -> http parity
    monkeypatch.setattr(messaging, "require_participant_active", lambda _u, _c: {"status": "active"})

    monkeypatch.setattr(
        messaging,
        "list_drafts",
        lambda **kwargs: (_ for _ in ()).throw(DraftValidationError("bad limit")),
    )
    with pytest.raises(messaging.HTTPException) as invalid:
        messaging.list_conversation_drafts("c1", user_id="u1")
    assert invalid.value.status_code == 422

    monkeypatch.setattr(
        messaging,
        "get_draft",
        lambda **kwargs: (_ for _ in ()).throw(DraftNotFoundError("missing")),
    )
    with pytest.raises(messaging.HTTPException) as missing:
        messaging.get_conversation_draft("c1", "d404", user_id="u1")
    assert missing.value.status_code == 404


def test_draft_route_feature_flag_gate(monkeypatch):
    monkeypatch.setattr(messaging, "_is_messaging_drafts_enabled_for", lambda **kwargs: False)
    with pytest.raises(messaging.HTTPException) as blocked:
        messaging.list_conversation_drafts("c1", user_id="u1")
    assert blocked.value.status_code == 403
    assert "not enabled" in blocked.value.detail.lower()
