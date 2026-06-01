"""Unit tests for CALL-014 voicemail.

Covers:
  - voicemail presign endpoint (validation + s3_key/upload_url shape)
  - voicemail create endpoint (message item, voicemail_message_id linkage, alert)
  - MessageOut voicemail projection in _message_out_from_item
  - call-timeline preview text for voicemail events

Follows the direct-endpoint-invocation + infrastructure-mocking pattern from
test_video_share_message.py. No dev stack required; DDB is mocked via MagicMock.
"""
from __future__ import annotations

import os
import sys
import time
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

_MID = "m_" + "a" * 32
_CALL_ID = "call_a1b2c3d4e5f6"
_CONV_ID = "c_conv001"
_CALLER = "alice"
_CALLEE = "bob"


def _make_call(
    *,
    state: str = "declined",
    caller: str = _CALLER,
    callee: str = _CALLEE,
    conversation_id: str = _CONV_ID,
    paid: bool = False,
    voicemail_message_id=None,
):
    from app.services.messaging_call_sessions import CallSessionRecord

    return CallSessionRecord(
        call_id=_CALL_ID,
        conversation_id=conversation_id,
        caller_user_id=caller,
        callee_user_id=callee,
        initial_mode="audio",
        state=state,
        start_ts=int(time.time()),
        paid=paid,
        voicemail_message_id=voicemail_message_id,
    )


def _make_convo(conversation_id: str = _CONV_ID) -> dict:
    return {
        "conversation_id": conversation_id,
        "type": "dm",
        "created_at": int(time.time()),
        "retention_days": 0,
    }


def _waveform(n: int = 30) -> list[float]:
    return [round((i % 10) / 10.0, 2) for i in range(n)]


def _invoke_presign(
    *,
    user_id: str = _CALLER,
    conversation_id: str = _CONV_ID,
    call,
    body_kwargs=None,
    voicemail_enabled: bool = True,
):
    from app.routers import messaging

    data = {
        "call_id": _CALL_ID,
        "content_type": "audio/webm",
        "size_bytes": 245760,
        "mode": "audio",
    }
    if body_kwargs:
        data.update(body_kwargs)
    body = messaging.PresignVoicemailRequest(**data)

    with (
        patch.object(messaging, "require_participant_active"),
        patch("app.services.messaging_call_sessions.get_call_session", return_value=call),
        patch.object(messaging, "S") as mock_s,
    ):
        mock_s.voicemail_enabled = voicemail_enabled
        mock_s.dev_mode = True
        return messaging.presign_voicemail(
            conversation_id=conversation_id,
            body=body,
            user_id=user_id,
        )


def _invoke_create(
    *,
    user_id: str = _CALLER,
    conversation_id: str = _CONV_ID,
    call,
    body_kwargs=None,
    voicemail_enabled: bool = True,
):
    from app.routers import messaging

    data = {
        "message_id": _MID,
        "call_id": _CALL_ID,
        "s3_key": f"voicemails/{conversation_id}/{_MID}.webm",
        "content_type": "audio/webm",
        "size_bytes": 245760,
        "duration_seconds": 28.5,
        "waveform_data": _waveform(),
        "mode": "audio",
    }
    if body_kwargs:
        data.update(body_kwargs)
    body = messaging.CreateVoicemailRequest(**data)

    convo = _make_convo(conversation_id)
    participants = [
        {"user_id": _CALLER, "conversation_id": conversation_id},
        {"user_id": _CALLEE, "conversation_id": conversation_id},
    ]

    tbl_msgs_mock = MagicMock()
    tbl_parts_mock = MagicMock()
    tbl_parts_mock.query.return_value = {"Items": participants}

    set_vm_mock = MagicMock()
    write_alert_mock = MagicMock()

    with (
        patch.object(messaging, "require_participant_active"),
        patch.object(messaging, "_get_conversation_or_404", return_value=convo),
        patch.object(messaging, "tbl_msgs", tbl_msgs_mock),
        patch.object(messaging, "tbl_parts", tbl_parts_mock),
        patch("app.services.messaging_call_sessions.get_call_session", return_value=call),
        patch("app.services.messaging_call_sessions.set_voicemail_message_id", set_vm_mock),
        patch("app.services.alerts.write_alert", write_alert_mock),
        patch.object(messaging, "_send_single_destination_message"),
        patch.object(messaging, "_message_retention_ttl", return_value=None),
        patch.object(messaging, "S") as mock_s,
    ):
        mock_s.voicemail_enabled = voicemail_enabled
        mock_s.dev_mode = True
        mock_s.voice_message_waveform_samples = 100
        result = messaging.create_voicemail(
            conversation_id=conversation_id,
            body=body,
            req=None,
            user_id=user_id,
        )
    return result, tbl_msgs_mock, set_vm_mock, write_alert_mock


# ─── Presign endpoint ─────────────────────────────────────────────────────────


class TestPresignVoicemail:
    def test_presign_success_returns_keys(self):
        result = _invoke_presign(call=_make_call())
        assert result["message_id"].startswith("m_")
        assert result["s3_key"].startswith(f"voicemails/{_CONV_ID}/")
        assert result["s3_key"].endswith(".webm")
        assert result["upload_url"].startswith("/mock/s3/")
        assert result["s3_key"] in result["upload_url"]

    def test_presign_video_mode_extension(self):
        result = _invoke_presign(
            call=_make_call(),
            body_kwargs={"content_type": "video/mp4", "mode": "video"},
        )
        assert result["s3_key"].endswith(".mp4")

    def test_presign_disabled_404(self):
        with pytest.raises(HTTPException) as exc:
            _invoke_presign(call=_make_call(), voicemail_enabled=False)
        assert exc.value.status_code == 404

    def test_presign_call_not_found_404(self):
        with pytest.raises(HTTPException) as exc:
            _invoke_presign(call=None)
        assert exc.value.status_code == 404

    def test_presign_wrong_conversation_400(self):
        with pytest.raises(HTTPException) as exc:
            _invoke_presign(call=_make_call(conversation_id="other_conv"))
        assert exc.value.status_code == 400

    def test_presign_not_caller_403(self):
        with pytest.raises(HTTPException) as exc:
            _invoke_presign(user_id=_CALLEE, call=_make_call())
        assert exc.value.status_code == 403

    def test_presign_ineligible_state_400(self):
        with pytest.raises(HTTPException) as exc:
            _invoke_presign(call=_make_call(state="ended"))
        assert exc.value.status_code == 400

    def test_presign_paid_call_400(self):
        with pytest.raises(HTTPException) as exc:
            _invoke_presign(call=_make_call(paid=True))
        assert exc.value.status_code == 400

    def test_presign_duplicate_voicemail_409(self):
        with pytest.raises(HTTPException) as exc:
            _invoke_presign(call=_make_call(voicemail_message_id="m_existing"))
        assert exc.value.status_code == 409

    @pytest.mark.parametrize("state", ["declined", "missed", "busy"])
    def test_presign_all_eligible_states(self, state):
        result = _invoke_presign(call=_make_call(state=state))
        assert "s3_key" in result


# ─── Create endpoint ──────────────────────────────────────────────────────────


class TestCreateVoicemail:
    def test_create_returns_voicemail_message(self):
        result, _, _, _ = _invoke_create(call=_make_call())
        assert result.kind == "voicemail"
        assert result.voicemail is not None
        assert result.voicemail["call_id"] == _CALL_ID
        assert result.voicemail["mode"] == "audio"
        assert result.voicemail["audio_url"]
        assert result.voicemail["video_url"] is None
        assert result.voicemail["call_state"] == "declined"
        assert result.voicemail["caller_user_id"] == _CALLER
        assert result.voicemail["callee_user_id"] == _CALLEE

    def test_create_writes_message_item(self):
        _, tbl_msgs_mock, _, _ = _invoke_create(call=_make_call())
        tbl_msgs_mock.put_item.assert_called_once()
        item = tbl_msgs_mock.put_item.call_args.kwargs["Item"]
        assert item["kind"] == "voicemail"
        assert item["message_id"] == _MID
        assert item["call_id"] == _CALL_ID
        assert item["sender_id"] == _CALLER
        assert item["voicemail_mode"] == "audio"
        assert item["audio_url"].startswith("voicemails/")

    def test_create_links_voicemail_to_call(self):
        _, _, set_vm_mock, _ = _invoke_create(call=_make_call())
        set_vm_mock.assert_called_once()
        kwargs = set_vm_mock.call_args.kwargs
        assert kwargs["call_id"] == _CALL_ID
        assert kwargs["voicemail_message_id"] == _MID

    def test_create_alerts_callee(self):
        _, _, _, write_alert_mock = _invoke_create(call=_make_call())
        write_alert_mock.assert_called_once()
        kwargs = write_alert_mock.call_args.kwargs
        assert kwargs["user_sub"] == _CALLEE
        assert kwargs["event"] == "voicemail_received"
        assert kwargs["details"]["call_id"] == _CALL_ID

    def test_create_video_mode(self):
        result, tbl_msgs_mock, _, _ = _invoke_create(
            call=_make_call(),
            body_kwargs={"content_type": "video/webm", "mode": "video"},
        )
        assert result.voicemail["mode"] == "video"
        assert result.voicemail["video_url"]
        assert result.voicemail["audio_url"] is None
        item = tbl_msgs_mock.put_item.call_args.kwargs["Item"]
        assert "video_url" in item
        assert "audio_url" not in item

    def test_create_disabled_404(self):
        with pytest.raises(HTTPException) as exc:
            _invoke_create(call=_make_call(), voicemail_enabled=False)
        assert exc.value.status_code == 404

    def test_create_not_caller_403(self):
        with pytest.raises(HTTPException) as exc:
            _invoke_create(user_id=_CALLEE, call=_make_call())
        assert exc.value.status_code == 403

    def test_create_duplicate_voicemail_409(self):
        with pytest.raises(HTTPException) as exc:
            _invoke_create(call=_make_call(voicemail_message_id="m_existing"))
        assert exc.value.status_code == 409

    def test_create_paid_call_400(self):
        with pytest.raises(HTTPException) as exc:
            _invoke_create(call=_make_call(paid=True))
        assert exc.value.status_code == 400


# ─── MessageOut projection ────────────────────────────────────────────────────


class TestVoicemailProjection:
    def _project(self, item):
        from app.routers import messaging

        with patch.object(messaging, "S") as mock_s:
            mock_s.dev_mode = True
            return messaging._message_out_from_item(item, _CALLEE)

    def _base_item(self, **overrides):
        item = {
            "conversation_id": _CONV_ID,
            "message_id": _MID,
            "sender_id": _CALLER,
            "created_at": int(time.time()),
            "kind": "voicemail",
            "text": None,
            "call_id": _CALL_ID,
            "voicemail_mode": "audio",
            "audio_url": f"voicemails/{_CONV_ID}/{_MID}.webm",
            "audio_content_type": "audio/webm",
            "audio_size_bytes": 245760,
            "duration_seconds": 28.5,
            "waveform_data": _waveform(),
            "call_state": "declined",
            "caller_user_id": _CALLER,
            "callee_user_id": _CALLEE,
            "reactions": {},
        }
        item.update(overrides)
        return item

    def test_projection_audio(self):
        out = self._project(self._base_item())
        assert out.kind == "voicemail"
        assert out.voicemail is not None
        assert out.voicemail["mode"] == "audio"
        assert out.voicemail["audio_url"].startswith("/mock/s3/")
        assert out.voicemail["video_url"] is None
        assert out.voicemail["call_id"] == _CALL_ID
        assert out.voicemail["duration_seconds"] == 28.5
        assert len(out.voicemail["waveform_data"]) == len(_waveform())

    def test_projection_video(self):
        item = self._base_item(
            voicemail_mode="video",
            video_url=f"voicemails/{_CONV_ID}/{_MID}.webm",
            video_content_type="video/webm",
            video_size_bytes=1048576,
        )
        item.pop("audio_url", None)
        item.pop("audio_content_type", None)
        item.pop("audio_size_bytes", None)
        out = self._project(item)
        assert out.voicemail["mode"] == "video"
        assert out.voicemail["video_url"].startswith("/mock/s3/")
        assert out.voicemail["audio_url"] is None
        assert out.voicemail["size_bytes"] == 1048576


# ─── Call-timeline preview text ───────────────────────────────────────────────


class TestTimelinePreview:
    def test_voicemail_complete_preview(self):
        from app.services.messaging_call_timeline import _preview_for_event

        text = _preview_for_event(
            event_type="call.voicemail_complete", call_state="declined", reason=None
        )
        assert text == "Left a voicemail"

    def test_voicemail_start_preview(self):
        from app.services.messaging_call_timeline import _preview_for_event

        text = _preview_for_event(
            event_type="call.voicemail_start", call_state="declined", reason=None
        )
        assert text == "Recording a voicemail"

    def test_voicemail_state_preview(self):
        from app.services.messaging_call_timeline import _preview_for_event

        text = _preview_for_event(
            event_type="voicemail", call_state="voicemail", reason=None
        )
        assert text == "Voicemail"

    def test_existing_previews_unchanged(self):
        from app.services.messaging_call_timeline import _preview_for_event

        assert _preview_for_event(
            event_type="call.missed", call_state="missed", reason=None
        ) == "Missed call"
        assert _preview_for_event(
            event_type="call.decline", call_state="busy", reason="busy"
        ) == "Call unavailable (busy)"
