"""Regression test for GAP-0145.

When a call recording upload completes (recording transitions to ``ready``),
``complete_recording_upload`` must:

  1. emit a ``call.recording_available`` timeline system message into the
     conversation (via ``emit_call_timeline_event``), so both participants can
     discover the recording from the conversation view, and
  2. fan out a ``call.recording_available`` SSE event (via
     ``fanout_event_to_conversation``) so the remote peer refreshes its UI.

Additionally, ``_preview_for_event`` must return a descriptive preview for the
new ``call.recording_available`` event type instead of the generic fallback.

Fails-before: the endpoint emitted neither a timeline event nor a fanout, and
``_preview_for_event`` returned ``"Call event: ready"``.
Passes-after: both call sites fire and the preview reads
``"Call recording available"``.

Fully offline: the call-session store, the recording store, the download-URL
helper, ``emit_call_timeline_event`` and ``fanout_event_to_conversation`` are
all replaced with in-memory fakes/recorders, so no real AWS / DynamoDB access
occurs. The endpoint coroutine is invoked directly (TestClient is broken in
this env), exactly like ``tests/test_gap_0142_call_missed_fanout.py``.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from app.routers import call_recording as cr


CALL_ID = "call_rec_test"
CONV_ID = "conv_rec_test"
REC_ID = "rec_test_001"
UPLOADER = "user_uploader"
PEER = "user_peer"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


@dataclass
class _FakeCallSession:
    call_id: str = CALL_ID
    caller_user_id: str = UPLOADER
    callee_user_id: str = PEER


@dataclass
class _FakeRecording:
    recording_id: str = REC_ID
    call_id: str = CALL_ID
    conversation_id: str = CONV_ID
    initiated_by: str = UPLOADER
    participants: list[str] = field(default_factory=lambda: [UPLOADER, PEER])
    status: str = "uploading"
    mime_type: str = "video/webm"
    file_size_bytes: int = 1024
    duration_seconds: float = 45.0


def _patch_handler_deps(monkeypatch):
    """Wire up the in-memory fakes; return (timeline_calls, fanout_calls)."""
    timeline_calls: list[dict] = []
    fanout_calls: list[dict] = []

    # Feature flag (S.call_recording_enabled) and S.dev_mode both default to
    # True in the test settings, so no override is needed; Settings is frozen.

    # Call-session lookup (used by _get_call_session helper).
    from app.services import messaging_call_sessions as sessions_mod

    monkeypatch.setattr(
        sessions_mod, "get_call_session", lambda cid: _FakeCallSession()
    )

    # Recording store: get + complete (imported inside the handler).
    from app.services import call_recording_store as store_mod

    monkeypatch.setattr(store_mod, "get_recording", lambda rid: _FakeRecording())

    def fake_complete_upload(rid, **kwargs):
        return _FakeRecording(status="ready")

    monkeypatch.setattr(store_mod, "complete_upload", fake_complete_upload)

    # Download URL helper (module-level in call_recording).
    monkeypatch.setattr(
        cr, "_make_download_url", lambda rec: ("/mock/s3/download", 9999999999)
    )

    # Timeline emitter (imported inside the handler from its source module).
    from app.services import messaging_call_timeline as timeline_mod

    def fake_emit(**kwargs):
        timeline_calls.append(dict(kwargs))
        return dict(kwargs)

    monkeypatch.setattr(timeline_mod, "emit_call_timeline_event", fake_emit)

    # Fanout (imported inside the handler from app.routers.messaging).
    from app.routers import messaging as msg_mod

    def fake_fanout(**kwargs):
        fanout_calls.append(dict(kwargs))

    monkeypatch.setattr(msg_mod, "fanout_event_to_conversation", fake_fanout)

    return timeline_calls, fanout_calls


def _run_complete():
    return asyncio.run(
        cr.complete_recording_upload(
            call_id=CALL_ID,
            body=cr.RecordingUploadCompleteIn(
                recording_id=REC_ID, duration_seconds=45.0
            ),
            request=None,  # unused once user_id is supplied directly
            user_id=UPLOADER,
        )
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_preview_for_event_recording_available():
    """_preview_for_event must describe the recording_available event."""
    from app.services.messaging_call_timeline import _preview_for_event

    preview = _preview_for_event(
        event_type="call.recording_available", call_state="ready", reason=None
    )
    # FAILS-BEFORE: falls through to f"Call event: ready".
    assert preview == "Call recording available"


def test_complete_recording_upload_emits_timeline_event(monkeypatch):
    timeline_calls, _fanout_calls = _patch_handler_deps(monkeypatch)

    result = _run_complete()
    assert result.status == "ready"
    assert result.recording_id == REC_ID

    # FAILS-BEFORE: no timeline event emitted.
    rec_events = [
        c for c in timeline_calls if c.get("event_type") == "call.recording_available"
    ]
    assert len(rec_events) == 1, "exactly one call.recording_available timeline event"
    ev = rec_events[0]
    assert ev["conversation_id"] == CONV_ID
    assert ev["call_id"] == CALL_ID
    assert ev["call_state"] == "ready"
    assert ev["extra_payload"]["recording_id"] == REC_ID


def test_complete_recording_upload_fans_out_sse(monkeypatch):
    _timeline_calls, fanout_calls = _patch_handler_deps(monkeypatch)

    _run_complete()

    # FAILS-BEFORE: no fanout recorded.
    rec_fanouts = [
        f for f in fanout_calls if f.get("event_type") == "call.recording_available"
    ]
    assert len(rec_fanouts) == 1
    f = rec_fanouts[0]
    assert f["conversation_id"] == CONV_ID
    assert f["sender_id"] == UPLOADER
    assert f["respect_mute"] is False
    assert f["payload"]["recording_id"] == REC_ID
    assert f["payload"]["call_id"] == CALL_ID
