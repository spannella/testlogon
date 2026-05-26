"""Unit tests for video share messaging (FEED-002 / video_share message kind).

Tests the create_video_share_message endpoint logic using mocked DDB tables
and mocked video_metadata_store, following the same patterns as test_messaging_routes.py.

The endpoint does `from app.services.video_metadata_store import get_video as _get_vod_video`
inside the function body, so the correct patch target is the source module:
  patch("app.services.video_metadata_store.get_video", ...)
"""
from __future__ import annotations

import os
import sys
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


# ─── Env fixture ──────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _mock_env(monkeypatch):
    monkeypatch.setenv("DEV_MODE", "1")
    monkeypatch.setenv("DDB_ENDPOINT_URL", "http://localhost:8001")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("UI_ACCESS_TOKEN_SECRET", "test-secret")
    monkeypatch.setenv("API_KEY_PEPPER", "test-pepper")
    monkeypatch.setenv("DDB_CONVERSATIONS", "Conversations")
    monkeypatch.setenv("DDB_PARTICIPANTS", "Participants")
    monkeypatch.setenv("DDB_MESSAGES", "Messages")


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _make_video(
    *,
    video_id: str = "v_" + "a" * 32,
    owner: str = "alice",
    status: str = "published",
    visibility: str = "public",
    title: str = "My Video",
    hls_manifest_url: str = "https://cdn.example.com/hls/index.m3u8",
    thumbnail_url: str = "https://cdn.example.com/thumb.jpg",
    duration_seconds: float = 90.0,
    width: int = 1280,
    height: int = 720,
):
    from app.models_video import VideoMetadataModel
    ts = int(time.time())
    return VideoMetadataModel(
        id=video_id,
        owner_user_id=owner,
        title=title,
        status=status,
        visibility=visibility,
        created_at=ts,
        updated_at=ts,
        hls_manifest_url=hls_manifest_url,
        thumbnail_url=thumbnail_url,
        duration_seconds=duration_seconds,
        width=width,
        height=height,
    )


def _make_convo(conversation_id: str = "c_conv001", *, retention_days: int = 0) -> dict:
    return {
        "conversation_id": conversation_id,
        "type": "dm",
        "created_at": int(time.time()),
        "retention_days": retention_days,
    }


def _invoke_share(
    *,
    user_id: str = "alice",
    conversation_id: str = "c_conv001",
    video: object,
    text: str | None = None,
    send_at: int | None = None,
    video_side_effect=None,
):
    """Call create_video_share_message with full mocking of infrastructure."""
    from app.routers import messaging

    vid = video
    video_id = vid.id if video_side_effect is None else ("v_" + "z" * 32)

    inp_data: dict = {"video_id": video_id}
    if text is not None:
        inp_data["text"] = text
    if send_at is not None:
        inp_data["send_at"] = send_at

    inp = messaging.CreateVideoShareMessageIn(**inp_data)
    convo = _make_convo(conversation_id)
    participants = [{"user_id": user_id, "conversation_id": conversation_id}]

    tbl_convos_mock = MagicMock()
    tbl_msgs_mock = MagicMock()
    tbl_parts_mock = MagicMock()
    tbl_parts_mock.query.return_value = {"Items": participants}

    vod_get_kwargs = {}
    if video_side_effect is not None:
        vod_get_kwargs["side_effect"] = video_side_effect
    else:
        vod_get_kwargs["return_value"] = vid

    with (
        patch.object(messaging, "require_participant_active"),
        patch.object(messaging, "_get_conversation_or_404", return_value=convo),
        patch.object(messaging, "tbl_parts", tbl_parts_mock),
        patch.object(messaging, "tbl_msgs", tbl_msgs_mock),
        patch.object(messaging, "tbl_convos", tbl_convos_mock),
        patch("app.services.video_metadata_store.get_video", **vod_get_kwargs),
        patch.object(messaging, "_bump_unread_counts"),
        patch.object(messaging, "_record_delivery_receipts"),
        patch.object(messaging, "_fanout_new_message_event"),
        patch.object(messaging, "_emit_message_lifecycle_archive_event_or_503"),
        patch.object(messaging, "_meter_message_send"),
        patch.object(messaging, "_message_retention_ttl", return_value=None),
        patch.object(messaging, "audit_event"),
        patch.object(messaging, "now_ts", return_value=int(time.time())),
        patch.object(messaging, "new_id", return_value="deadbeef" * 4),
        patch.object(messaging, "S") as mock_s,
    ):
        mock_s.video_sharing_enabled = True
        mock_s.dev_mode = True
        return messaging.create_video_share_message(
            conversation_id=conversation_id,
            inp=inp,
            req=None,
            user_id=user_id,
        ), tbl_convos_mock


# ─── Tests ────────────────────────────────────────────────────────────────────


class TestVideoShareMessageEndpoint:

    def test_share_own_published_video(self):
        """Owner can share their own published video — 200 OK."""
        vid = _make_video(status="published", visibility="public", owner="alice")
        result, _ = _invoke_share(user_id="alice", video=vid)
        assert result.kind == "video_share"

    def test_share_own_private_video(self):
        """Owner CAN share their own private video."""
        vid = _make_video(status="published", visibility="private", owner="alice")
        result, _ = _invoke_share(user_id="alice", video=vid)
        assert result.kind == "video_share"

    def test_share_nonowner_public_video(self):
        """Non-owner CAN share a published public video."""
        vid = _make_video(status="published", visibility="public", owner="alice")
        result, _ = _invoke_share(user_id="bob", video=vid)
        assert result.kind == "video_share"

    def test_share_nonowner_private_video_403(self):
        """Non-owner cannot share a private video."""
        vid = _make_video(status="published", visibility="private", owner="alice")
        with pytest.raises(HTTPException) as exc_info:
            _invoke_share(user_id="bob", video=vid)
        assert exc_info.value.status_code == 403

    def test_share_nonowner_unpublished_403(self):
        """Non-owner cannot share an unpublished video."""
        vid = _make_video(status="encoding", visibility="public", owner="alice")
        with pytest.raises(HTTPException) as exc_info:
            _invoke_share(user_id="bob", video=vid)
        assert exc_info.value.status_code == 403

    def test_share_nonexistent_video_404(self):
        """Sharing a non-existent video returns 404."""
        vid = _make_video()  # used for video_id only; get_video raises 404
        with pytest.raises(HTTPException) as exc_info:
            _invoke_share(
                user_id="alice",
                video=vid,
                video_side_effect=HTTPException(404, "video not found"),
            )
        assert exc_info.value.status_code == 404

    def test_share_encoding_video_400(self):
        """Owner cannot share their own video if it's still encoding."""
        vid = _make_video(status="encoding", visibility="public", owner="alice")
        with pytest.raises(HTTPException) as exc_info:
            _invoke_share(user_id="alice", video=vid)
        assert exc_info.value.status_code == 400

    def test_share_with_caption(self):
        """Video share with text sets the text field on the returned message."""
        vid = _make_video(status="published", visibility="public", owner="alice")
        result, _ = _invoke_share(user_id="alice", video=vid, text="Check this out!")
        assert result.text == "Check this out!"

    def test_share_scheduled(self):
        """Sharing with send_at in the future marks the message as scheduled."""
        vid = _make_video(status="published", visibility="public", owner="alice")
        future_ts = int(time.time()) + 300
        result, _ = _invoke_share(user_id="alice", video=vid, send_at=future_ts)
        assert result.scheduled is True
        assert result.deliver_at == future_ts

    def test_non_participant_403(self):
        """Non-participant trying to share returns 403."""
        from app.routers import messaging

        vid = _make_video(status="published", visibility="public", owner="carol")
        inp = messaging.CreateVideoShareMessageIn(video_id=vid.id)

        with (
            patch.object(messaging, "require_participant_active", side_effect=HTTPException(403, "not a participant")),
            patch.object(messaging, "S") as mock_s,
        ):
            mock_s.video_sharing_enabled = True
            with pytest.raises(HTTPException) as exc_info:
                messaging.create_video_share_message(
                    conversation_id="c_conv001",
                    inp=inp,
                    req=None,
                    user_id="nobody",
                )
        assert exc_info.value.status_code == 403

    def test_message_out_has_video_share(self):
        """MessageOut returned from share endpoint includes video_share dict."""
        vid = _make_video(status="published", visibility="public", owner="alice", title="Epic Clip")
        result, _ = _invoke_share(user_id="alice", video=vid)
        assert result.video_share is not None
        assert result.video_share["video_id"] == vid.id
        assert result.video_share["title"] == "Epic Clip"

    def test_video_share_in_searchable_kinds(self):
        """video_share kind is included in the searchable message kinds."""
        from app.routers.messaging import _is_searchable_kind
        assert _is_searchable_kind("video_share") is True

    def test_conversation_preview_contains_video_title(self):
        """The last_message_preview stored on the conversation includes the video title."""
        vid = _make_video(status="published", visibility="public", owner="alice", title="Epic Clip")
        _, tbl_convos_mock = _invoke_share(user_id="alice", video=vid)

        # tbl_convos.update_item should have been called with a preview containing "Epic Clip"
        tbl_convos_mock.update_item.assert_called_once()
        call_kwargs = tbl_convos_mock.update_item.call_args.kwargs
        preview_value = call_kwargs["ExpressionAttributeValues"].get(":p", "")
        assert "Epic Clip" in preview_value

    def test_video_sharing_disabled_403(self):
        """When video_sharing_enabled is False the endpoint raises 403."""
        from app.routers import messaging

        vid = _make_video(status="published", visibility="public", owner="alice")
        inp = messaging.CreateVideoShareMessageIn(video_id=vid.id)

        with patch.object(messaging, "S") as mock_s:
            mock_s.video_sharing_enabled = False
            with pytest.raises(HTTPException) as exc_info:
                messaging.create_video_share_message(
                    conversation_id="c_conv001",
                    inp=inp,
                    req=None,
                    user_id="alice",
                )
        assert exc_info.value.status_code == 403
