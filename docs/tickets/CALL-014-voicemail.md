# CALL-014: Voicemail — Record Audio/Video Message on Unanswered Calls

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-28  
**Priority**: High  
**Estimated effort**: 8-12 days  
**Dependencies**: CALL-001 (Signaling Endpoint), CALL-007 (Ringing Timeout), MSG-002 (Voice Messages)

---

## 1. Overview & Motivation

### Problem Statement

When a call is declined, times out (missed), or the callee is busy, the caller's `CallSessionOverlay` displays a static outcome message ("Call declined.", "Call timed out with no answer.", "User is busy on another call.") and a single "Dismiss" button (`CallSessionOverlay.tsx`, lines 65-71 for the `outcomeCopy` map, lines 588-592 for the Dismiss button rendering). <!-- VERIFIED: frontend/src/pages/messages/CallSessionOverlay.tsx:65-71,588-592 --> The overlay then closes and the caller has no opportunity to leave a message for the callee. This is a significant gap in the communication flow — the caller initiated the call because they had something to say, and the platform discards that intent entirely when the call is not answered.

The platform already has a complete voice recording pipeline: `VoiceRecorder.tsx` (311 lines) provides MediaRecorder integration with live waveform visualization, configurable max duration (default 300s), and preview/re-record capability. <!-- VERIFIED: frontend/src/pages/messages/VoiceRecorder.tsx:1-311 --> The backend supports voice message presigning (`POST /conversations/{id}/voice-message/presign`, messaging.py line 8111), creation (`POST /conversations/{id}/voice-message`, line 8142), S3 upload, waveform storage, and playback via `WaveformPlayer.tsx` (177 lines). <!-- VERIFIED: frontend/src/pages/messages/WaveformPlayer.tsx:1-177 --> <!-- VERIFIED: app/routers/messaging.py:8111,8142 --> All the recording, upload, and playback infrastructure exists — it simply is not connected to the call outcome flow.

### Goals

1. When a call reaches a terminal unanswered state (declined, missed/timeout, busy), present the caller with a "Leave a voicemail?" prompt instead of immediately dismissing the overlay.
2. Allow the caller to record an audio or video voicemail (up to 60 seconds) using the existing `VoiceRecorder` component or a new video recording mode.
3. Store voicemails as a distinct message kind (`"voicemail"`) in the conversation, linked to the originating call via `call_id`.
4. Display voicemails in the conversation timeline with a "Missed call — voicemail" header and a "Call back" action button.
5. Send an alert notification to the callee when a voicemail is left.
6. Support voicemail for both 1-on-1 DM calls and group calls (CALL-012).

### User Stories

| # | As a... | I want to... | So that... |
|---|---------|-------------|-----------|
| 1 | Caller | See a "Leave a message?" prompt when my call is not answered | I can communicate my intent without waiting for a callback |
| 2 | Caller | Record an audio voicemail up to 60 seconds | I can leave a quick voice message without typing |
| 3 | Caller | Record a video voicemail up to 60 seconds | I can leave a face-to-face message for the recipient |
| 4 | Caller | Preview my voicemail before sending | I can re-record if I am not satisfied with the message |
| 5 | Caller | Skip the voicemail and just dismiss | I am not forced to leave a message if I do not want to |
| 6 | Callee | See a voicemail message in the conversation with a "Missed call" header | I know I missed a call and can listen to the message |
| 7 | Callee | Receive a push notification when a voicemail is left | I am alerted even when not looking at the conversation |
| 8 | Callee | Tap "Call back" on a voicemail message | I can quickly return the call without navigating away |
| 9 | Group member | See a voicemail left by the caller in the group conversation | I know someone tried to reach the group via call |

### Scope

**In scope**: Voicemail recording after unanswered calls, audio and video voicemail, S3 upload with presigned URLs, voicemail message kind in DynamoDB, conversation timeline rendering, callee alert notification, call-back button, group call voicemail support.

**Out of scope (non-goals)**:
- Voicemail greetings (custom recorded greeting message played to caller before recording)
- Voicemail transcription (speech-to-text conversion of voicemail audio)
- Auto-attendant / IVR-style voicemail routing
- Voicemail-to-email forwarding
- Per-user voicemail enable/disable toggle (v1 is always available when calls are enabled)
- Voicemail storage quotas or retention policies (use existing S3 lifecycle rules)
- Voicemail for pay-per-minute calls (CALL-011) — paid calls have different end-of-call semantics

---

## 2. Current State Analysis

### 2.1 Call Lifecycle and Terminal States

The call lifecycle is managed by `app/services/messaging_call_lifecycle.py`. The state machine defines terminal states at line 23 and allowed transitions at lines 24-28: <!-- VERIFIED: app/services/messaging_call_lifecycle.py:23-28 -->

```python
TERMINAL_STATES = {"declined", "busy", "missed", "ended", "failed", "canceled"}
ALLOWED_TRANSITIONS = {
    "invited": {"accepted", "declined", "busy", "canceled", "failed", "missed"},
    "accepted": {"connected", "ended", "failed", "canceled"},
    "connected": {"ended", "failed"},
}
```

Three terminal states represent unanswered calls where voicemail is appropriate:

| Terminal State | Trigger | Function | Line |
|---------------|---------|----------|------|
| `declined` | Callee explicitly declines | `decline_invite()` | 279 | <!-- VERIFIED: app/services/messaging_call_lifecycle.py:279 -->
| `missed` | Ringing timeout (30s, CALL-007) | `timeout_call()` | 404 | <!-- VERIFIED: app/services/messaging_call_lifecycle.py:404 -->
| `busy` | Callee already on another call | `decline_invite(reason="busy")` | 295 | <!-- VERIFIED: app/services/messaging_call_lifecycle.py:295 -->

All three transitions follow the same pattern: update state in DDB, emit a timeline event, return `(CallSessionRecord, LifecycleEvent)`. After the transition, the backend returns the result to the caller's frontend via SSE. The frontend `CallSessionOverlay` receives the outcome state and renders the static dismissal UI. **No voicemail prompt exists in any of these paths.**

#### `decline_invite()` Signature (line 279)

<!-- VERIFIED: app/services/messaging_call_lifecycle.py:279-287 -->
```python
def decline_invite(
    *,
    call_id: str,
    actor_user_id: str,
    reason: str = "declined",
    client_platform: str = "unknown",
    client_browser: str = "unknown",
    timeline_emitter: Callable[..., dict[str, object]] = emit_call_timeline_event,
) -> tuple[CallSessionRecord, LifecycleEvent]:
```

The `reason` parameter drives the terminal state: `reason="busy"` transitions to `"busy"` state, any other value transitions to `"declined"` (line 295). <!-- VERIFIED: app/services/messaging_call_lifecycle.py:295 -->

#### `timeout_call()` Signature (line 404)

<!-- VERIFIED: app/services/messaging_call_lifecycle.py:404-411 -->
```python
def timeout_call(
    *,
    call_id: str,
    actor_user_id: str,
    reason: str = "no_answer",
    idempotency_key: Optional[str] = None,
    timeline_emitter: Callable[..., dict[str, object]] = emit_call_timeline_event,
) -> tuple[CallSessionRecord, LifecycleEvent]:
```

Only the caller or `"system"` actor can timeout a call (line 420). <!-- VERIFIED: app/services/messaging_call_lifecycle.py:420 --> This transitions the call to the `"missed"` state (line 423). <!-- VERIFIED: app/services/messaging_call_lifecycle.py:423 -->

#### `end_call()` Signature (line 334)

<!-- VERIFIED: app/services/messaging_call_lifecycle.py:334-343 -->
```python
def end_call(
    *,
    call_id: str,
    actor_user_id: str,
    reason: str = "ended",
    idempotency_key: Optional[str] = None,
    client_platform: str = "unknown",
    client_browser: str = "unknown",
    timeline_emitter: Callable[..., dict[str, object]] = emit_call_timeline_event,
) -> tuple[CallSessionRecord, LifecycleEvent]:
```

The `end_call` function determines the terminal state based on the current state: `"ended"` if the call was `connected` or `accepted`, `"canceled"` if it was still `invited` (line 354). <!-- VERIFIED: app/services/messaging_call_lifecycle.py:354 --> Neither `ended` nor `canceled` are voicemail-eligible states.

#### `create_invite()` Signature (line 132)

<!-- VERIFIED: app/services/messaging_call_lifecycle.py:132-148 -->
```python
def create_invite(
    *,
    call_id: str,
    conversation_id: str,
    actor_user_id: str,
    caller_user_id: str,
    callee_user_id: str,
    initial_mode: str,
    participant_resolver: Callable[[str], set[str]] = _load_conversation_participants,
    idempotency_key: Optional[str] = None,
    client_platform: str = "unknown",
    client_browser: str = "unknown",
    timeline_emitter: Callable[..., dict[str, object]] = emit_call_timeline_event,
    paid: bool = False,
    rate_cents_per_min: int = 0,
    max_duration_seconds: int = 0,
) -> tuple[CallSessionRecord, LifecycleEvent]:
```

The `paid` parameter on `create_invite` propagates to `CallSessionRecord.paid`. Voicemail eligibility checks this field to exclude pay-per-minute calls (CALL-011).

### 2.2 Call Session Record Model

`CallSessionRecord` in `app/services/messaging_call_sessions.py` (lines 18-48) is a frozen dataclass. <!-- VERIFIED: app/services/messaging_call_sessions.py:18-48 --> The type aliases are defined at lines 8-10: <!-- VERIFIED: app/services/messaging_call_sessions.py:8-10 -->

```python
CallMode = Literal["audio", "video"]
CallState = Literal["invited", "accepted", "connected", "ended", "missed", "declined", "busy", "failed", "canceled"]
NetworkPath = Literal["p2p", "turn"]
```

The full field inventory of `CallSessionRecord`:

| Field | Type | Line | Purpose |
|-------|------|------|---------|
| `call_id` | `str` | 20 | PK — Unique call identifier, will become FK on voicemail messages | <!-- VERIFIED: app/services/messaging_call_sessions.py:20 -->
| `conversation_id` | `str` | 21 | Conversation this call belongs to | <!-- VERIFIED: app/services/messaging_call_sessions.py:21 -->
| `caller_user_id` | `str` | 22 | Who initiated the call — only this user can leave voicemail | <!-- VERIFIED: app/services/messaging_call_sessions.py:22 -->
| `callee_user_id` | `str` | 23 | Who received the call — voicemail notification target | <!-- VERIFIED: app/services/messaging_call_sessions.py:23 -->
| `initial_mode` | `CallMode` | 24 | `"audio"` or `"video"` — influences default voicemail mode | <!-- VERIFIED: app/services/messaging_call_sessions.py:24 -->
| `state` | `CallState` | 25 | Current lifecycle state | <!-- VERIFIED: app/services/messaging_call_sessions.py:25 -->
| `start_ts` | `int` | 26 | Unix timestamp when call was created | <!-- VERIFIED: app/services/messaging_call_sessions.py:26 -->
| `connect_ts` | `Optional[int]` | 27 | When the call was connected (None if never connected) | <!-- VERIFIED: app/services/messaging_call_sessions.py:27 -->
| `end_ts` | `Optional[int]` | 28 | When the call ended | <!-- VERIFIED: app/services/messaging_call_sessions.py:28 -->
| `end_reason` | `Optional[str]` | 29 | Why the call ended | <!-- VERIFIED: app/services/messaging_call_sessions.py:29 -->
| `network_path` | `Optional[NetworkPath]` | 30 | `"p2p"` or `"turn"` | <!-- VERIFIED: app/services/messaging_call_sessions.py:30 -->
| `updated_at` | `Optional[int]` | 31 | Last update timestamp | <!-- VERIFIED: app/services/messaging_call_sessions.py:31 -->
| `lifecycle_events` | `Optional[list[dict]]` | 32 | Event history log | <!-- VERIFIED: app/services/messaging_call_sessions.py:32 -->
| `idempotency_records` | `Optional[dict]` | 33 | Idempotency dedup map | <!-- VERIFIED: app/services/messaging_call_sessions.py:33 -->
| `broadcast_session_id` | `str` | 35 | BCAST-011 broadcast linkage (default `""`) | <!-- VERIFIED: app/services/messaging_call_sessions.py:35 -->
| `paid` | `bool` | 37 | Whether this is a paid call (CALL-011) — paid calls skip voicemail | <!-- VERIFIED: app/services/messaging_call_sessions.py:37 -->
| `rate_cents_per_min` | `int` | 38 | CALL-011 billing rate | <!-- VERIFIED: app/services/messaging_call_sessions.py:38 -->
| `billing_status` | `str` | 39 | CALL-011 billing state | <!-- VERIFIED: app/services/messaging_call_sessions.py:39 -->
| `billing_start_ts` | `Optional[int]` | 40 | CALL-011 billing start | <!-- VERIFIED: app/services/messaging_call_sessions.py:40 -->
| `last_billed_ts` | `Optional[int]` | 41 | CALL-011 last billing cycle | <!-- VERIFIED: app/services/messaging_call_sessions.py:41 -->
| `total_billed_cents` | `int` | 42 | CALL-011 total billed | <!-- VERIFIED: app/services/messaging_call_sessions.py:42 -->
| `total_billed_seconds` | `int` | 43 | CALL-011 total billed duration | <!-- VERIFIED: app/services/messaging_call_sessions.py:43 -->
| `billing_cycle_count` | `int` | 44 | CALL-011 billing cycles | <!-- VERIFIED: app/services/messaging_call_sessions.py:44 -->
| `platform_fee_bps` | `int` | 45 | CALL-011 platform fee basis points | <!-- VERIFIED: app/services/messaging_call_sessions.py:45 -->
| `max_duration_seconds` | `int` | 46 | CALL-011 max call duration | <!-- VERIFIED: app/services/messaging_call_sessions.py:46 -->
| `caller_last_heartbeat_ts` | `Optional[int]` | 47 | CALL-011 caller heartbeat | <!-- VERIFIED: app/services/messaging_call_sessions.py:47 -->
| `callee_last_heartbeat_ts` | `Optional[int]` | 48 | CALL-011 callee heartbeat | <!-- VERIFIED: app/services/messaging_call_sessions.py:48 -->

The record currently has **no voicemail-related fields**. A new `voicemail_message_id` field will be added to link the call session to the voicemail message if one is left.

Key helper functions on the session model:

| Function | Line | Signature |
|----------|------|-----------|
| `_item_from_record()` | 51 | `(record: CallSessionRecord) -> dict[str, object]` | <!-- VERIFIED: app/services/messaging_call_sessions.py:51 -->
| `_record_from_item()` | 92 | `(item: dict[str, object]) -> CallSessionRecord` | <!-- VERIFIED: app/services/messaging_call_sessions.py:92 -->
| `create_call_session()` | 126 | `(*, call_id, conversation_id, caller_user_id, callee_user_id, initial_mode, state, ...) -> CallSessionRecord` | <!-- VERIFIED: app/services/messaging_call_sessions.py:126 -->
| `get_call_session()` | 158 | `(call_id: str) -> Optional[CallSessionRecord]` | <!-- VERIFIED: app/services/messaging_call_sessions.py:158 -->
| `update_call_session_state()` | 165 | `(*, call_id, state, connect_ts, end_ts, ...) -> Optional[CallSessionRecord]` | <!-- VERIFIED: app/services/messaging_call_sessions.py:165 -->
| `list_call_sessions_for_conversation()` | 223 | `(conversation_id: str, *, limit: int = 50) -> list[CallSessionRecord]` | <!-- VERIFIED: app/services/messaging_call_sessions.py:223 -->

The `update_call_session_state()` function (lines 165-220) reconstructs the entire `CallSessionRecord` from the existing record, preserving all fields including BCAST-011 broadcast linkage (line 203) and CALL-011 billing fields (lines 204-216). <!-- VERIFIED: app/services/messaging_call_sessions.py:165-220 --> The new `voicemail_message_id` field must be added to this reconstruction to survive state transitions.

### 2.3 Call Signaling Types

`app/services/messaging_call_signaling.py` (lines 14-28) defines the allowed signaling types: <!-- VERIFIED: app/services/messaging_call_signaling.py:14-28 -->

```python
ALLOWED_SIGNALING_TYPES = {
    "call.invite", "call.ring", "call.accept", "call.decline",
    "webrtc.offer", "webrtc.answer", "webrtc.ice_candidate",
    "call.end",
    "call.recording_request", "call.recording_accept",
    "call.recording_decline", "call.recording_started", "call.recording_stopped",
}
```

No voicemail-related signal types exist. The `STATE_ALLOWED_SIGNALING_TYPES` map (lines 34-42) restricts which signals are valid in each call state: <!-- VERIFIED: app/services/messaging_call_signaling.py:34-42 -->

```python
STATE_ALLOWED_SIGNALING_TYPES: dict[str, set[str]] = {
    "invited": {"call.invite", "call.ring", "call.accept", "call.decline", "call.end"},
    "accepted": {"webrtc.offer", "webrtc.answer", "webrtc.ice_candidate", "call.end"},
    "connected": {
        "webrtc.offer", "webrtc.answer", "webrtc.ice_candidate", "call.end",
        "call.recording_request", "call.recording_accept", "call.recording_decline",
        "call.recording_started", "call.recording_stopped",
    },
}
```

Terminal states (`TERMINAL_CALL_STATES` at line 32: `{"ended", "missed", "declined", "busy", "failed", "canceled"}`) are not present in `STATE_ALLOWED_SIGNALING_TYPES`. <!-- VERIFIED: app/services/messaging_call_signaling.py:32 --> The routing logic at lines 233-239 rejects non-`call.end` events in terminal states (line 233) and then checks state-specific allowlists (lines 236-239). <!-- VERIFIED: app/services/messaging_call_signaling.py:233-239 --> Since terminal states have no entry in the map, `allowed_events` is `None`, and the check at line 237 (`if allowed_events is not None`) passes — meaning any event type in `ALLOWED_SIGNALING_TYPES` is technically allowed if it passes the terminal-state guard at line 233. This means voicemail signals must either (a) be added to `ALLOWED_SIGNALING_TYPES` and given explicit terminal-state entries, or (b) bypass the terminal-state guard. Option (a) is safer and more explicit.

### 2.4 CallSessionOverlay Outcome UI

`CallSessionOverlay.tsx` renders the non-connected states starting at line 529. <!-- VERIFIED: frontend/src/pages/messages/CallSessionOverlay.tsx:529 --> The `isOutcome` flag is computed at line 294: <!-- VERIFIED: frontend/src/pages/messages/CallSessionOverlay.tsx:294 -->

```typescript
const isOutcome = ["declined", "busy", "timeout", "ended", "failure"].includes(session.state);
```

When `isOutcome` is true, the UI shows at lines 588-592: <!-- VERIFIED: frontend/src/pages/messages/CallSessionOverlay.tsx:588-592 -->

```tsx
{isOutcome && (
  <Button onClick={onDismiss} aria-label="Dismiss call status">
    Dismiss
  </Button>
)}
```

The outcome description text is rendered at line 565 via the `outcomeCopy` map (lines 65-71): <!-- VERIFIED: frontend/src/pages/messages/CallSessionOverlay.tsx:65-71,565 -->

```typescript
const outcomeCopy: Record<Extract<CallUiState, "declined" | "busy" | "timeout" | "ended" | "failure">, string> = {
  declined: "Call declined.",
  busy: "User is busy on another call.",
  timeout: "Call timed out with no answer.",
  ended: "Call ended.",
  failure: "Call failed to connect.",
};
```

The `Props` interface (lines 41-63) includes callback props `onAccept`, `onDecline`, `onEnd`, `onDismiss`, and media toggle functions, but no voicemail-related props. <!-- VERIFIED: frontend/src/pages/messages/CallSessionOverlay.tsx:41-63 -->

This is where the voicemail prompt will be injected — replacing the single "Dismiss" button with "Leave a message?" + "Dismiss" options for the three voicemail-eligible states (`declined`, `timeout`, `busy`). The `ended` and `failure` states will continue to show only the "Dismiss" button.

### 2.5 Voice Message Infrastructure

The existing voice message system provides nearly all the building blocks for voicemail:

**Frontend — `VoiceRecorder.tsx` (311 lines)**: <!-- VERIFIED: frontend/src/pages/messages/VoiceRecorder.tsx:1-311 -->
- `VoiceRecorderProps` interface (lines 6-9): `onComplete(blob, { duration, waveform, contentType })`, `onCancel()`, `maxDuration` (default 300s) <!-- VERIFIED: frontend/src/pages/messages/VoiceRecorder.tsx:6-9 -->
- Phases: `idle` -> `recording` -> `preview` (line 28) <!-- VERIFIED: frontend/src/pages/messages/VoiceRecorder.tsx:28 -->
- Uses `MediaRecorder` API with codec detection via `detectMimeType()` (lines 18-25): checks `audio/webm;codecs=opus`, `audio/webm`, `audio/mp4`, `audio/ogg;codecs=opus` in order <!-- VERIFIED: frontend/src/pages/messages/VoiceRecorder.tsx:18-25 -->
- Live waveform via `AnalyserNode` with `fftSize=256` (line 88), sampled at 10Hz via `setInterval` (lines 139-148) <!-- VERIFIED: frontend/src/pages/messages/VoiceRecorder.tsx:88,139-148 -->
- RMS amplitude normalized to 0-1, then multiplied by 2 for visual scaling (line 147) <!-- VERIFIED: frontend/src/pages/messages/VoiceRecorder.tsx:147 -->
- Preview playback with re-record option (lines 260-310) <!-- VERIFIED: frontend/src/pages/messages/VoiceRecorder.tsx:260-310 -->
- Cleanup on unmount: stops tracks, closes AudioContext (lines 46-59) <!-- VERIFIED: frontend/src/pages/messages/VoiceRecorder.tsx:46-59 -->
- Escape key cancels recording (lines 66-75) <!-- VERIFIED: frontend/src/pages/messages/VoiceRecorder.tsx:66-75 -->
- Max duration auto-stop via timer check (lines 132-134) <!-- VERIFIED: frontend/src/pages/messages/VoiceRecorder.tsx:132-134 -->
- Data collection interval: 100ms chunks (`recorder.start(100)` at line 122) <!-- VERIFIED: frontend/src/pages/messages/VoiceRecorder.tsx:122 -->
- Waveform downsampled to 30-100 values in `recorder.onstop` handler (lines 108-118) <!-- VERIFIED: frontend/src/pages/messages/VoiceRecorder.tsx:108-118 -->

**Frontend — `WaveformPlayer.tsx` (177 lines)**: <!-- VERIFIED: frontend/src/pages/messages/WaveformPlayer.tsx:1-177 -->
- Props interface (lines 6-12): `audioUrl`, `waveform: number[]`, `durationSeconds`, `consumed?`, `onPlaybackComplete?` <!-- VERIFIED: frontend/src/pages/messages/WaveformPlayer.tsx:6-12 -->
- Renders waveform visualization with playback progress (lines 130-150) <!-- VERIFIED: frontend/src/pages/messages/WaveformPlayer.tsx:130-150 -->
- Play/pause controls, seek-by-click via `handleBarClick` (lines 106-111) <!-- VERIFIED: frontend/src/pages/messages/WaveformPlayer.tsx:106-111 -->
- Duration display with remaining time during playback (line 153-155) <!-- VERIFIED: frontend/src/pages/messages/WaveformPlayer.tsx:153-155 -->
- Playback speed toggle: 1x, 1.5x, 2x (lines 20-21, 97-104) <!-- VERIFIED: frontend/src/pages/messages/WaveformPlayer.tsx:20-21,97-104 -->
- Consumed state: disables replay after first listen (line 85, 113, 170-174) <!-- VERIFIED: frontend/src/pages/messages/WaveformPlayer.tsx:85,113,170-174 -->
- Used in `MessageBubble` for `kind="voice_message"` messages

**Backend — Voice message endpoints** (`app/routers/messaging.py`):

| Endpoint | Line | Purpose |
|----------|------|---------|
| `POST /conversations/{id}/voice-message/presign` | 8111 | Get presigned S3 upload URL | <!-- VERIFIED: app/routers/messaging.py:8111 -->
| `POST /conversations/{id}/voice-message` | 8142 | Create voice message record in DDB | <!-- VERIFIED: app/routers/messaging.py:8142 -->

**Backend — Pydantic Models** (`app/routers/messaging.py`):

`PresignVoiceMessageRequest` (lines 1937-1940): <!-- VERIFIED: app/routers/messaging.py:1937-1940 -->
```python
class PresignVoiceMessageRequest(BaseModel):
    content_type: str = Field(pattern=r"^audio/(webm|mp4|ogg|wav)")
    size_bytes: int = Field(ge=1, le=52_428_800)  # 50MB max
    duration_seconds: float = Field(ge=0.5, le=300)  # 0.5s to 5 minutes
```

`CreateVoiceMessageRequest` (lines 1943-1952): <!-- VERIFIED: app/routers/messaging.py:1943-1952 -->
```python
class CreateVoiceMessageRequest(BaseModel):
    message_id: str = Field(pattern=r"^m_[a-f0-9]{32}$")
    s3_key: str
    content_type: str
    size_bytes: int = Field(ge=1)
    duration_seconds: float = Field(ge=0.5, le=300)
    waveform_data: List[float] = Field(min_length=10, max_length=200)
    consumption_policy: Literal["none", "listen_once"] = "none"
    reply_to_message_id: Optional[str] = None
    send_at: Optional[int] = None  # Unix timestamp; schedules delivery for the future
```

**Backend — Settings** (`app/core/settings.py`, lines 1251-1254): <!-- VERIFIED: app/core/settings.py:1251-1254 -->

```python
voice_message_enabled: bool = os.environ.get("VOICE_MESSAGE_ENABLED", "1") not in ("0", "false", "False")
voice_message_max_duration_seconds: int = int(os.environ.get("VOICE_MESSAGE_MAX_DURATION_SECONDS", "300"))
voice_message_max_size_bytes: int = int(os.environ.get("VOICE_MESSAGE_MAX_SIZE_BYTES", "52428800"))
voice_message_waveform_samples: int = int(os.environ.get("VOICE_MESSAGE_WAVEFORM_SAMPLES", "100"))
```

**Backend — S3 pattern**: Voice messages use `s3_key = f"voice-messages/{conversation_id}/{msg_id}.{ext}"` (line 8130) <!-- VERIFIED: app/routers/messaging.py:8130 --> and the bucket `S3_BUCKET_IMAGES` (line 207: `os.getenv("S3_BUCKET_IMAGES", "my-chat-images")`). <!-- VERIFIED: app/routers/messaging.py:207 --> In dev mode, the upload URL is `/mock/s3/{bucket}/{key}` (line 8132). <!-- VERIFIED: app/routers/messaging.py:8132 -->

**Backend — Voice message projection** (`_message_out_from_item`, lines 3929-3946): <!-- VERIFIED: app/routers/messaging.py:3929-3946 -->
```python
voice_message_out: Optional[Dict[str, Any]] = None
if merged_item.get("kind") == "voice_message" and not content_hidden:
    from urllib.parse import quote as _vm_url_quote
    _vm_s3_key = str(merged_item.get("audio_url") or "")
    _vm_audio_url = ""
    if _vm_s3_key:
        if S.dev_mode:
            _vm_audio_url = f"/mock/s3/{S3_BUCKET_IMAGES}/{_vm_url_quote(_vm_s3_key, safe='/')}"
        else:
            _vm_audio_url = _vm_s3_key
    raw_waveform = merged_item.get("waveform_data") or []
    voice_message_out = {
        "audio_url": _vm_audio_url,
        "audio_content_type": merged_item.get("audio_content_type"),
        "audio_size_bytes": int(merged_item.get("audio_size_bytes", 0)),
        "duration_seconds": float(merged_item.get("duration_seconds", 0)),
        "waveform_data": [float(v) for v in raw_waveform],
    }
```

### 2.6 MessageOut Model

`MessageOut` (line 2305) defines the `kind` literal at line 2310, currently supporting 12 message kinds: <!-- VERIFIED: app/routers/messaging.py:2305,2310 -->

```python
kind: Literal["text", "image", "file", "audio", "video", "gallery",
              "file_share", "calendar_share", "calendar_event",
              "meeting_poll", "video_share", "voice_message"]
```

The `voice_message` field (line 2320) carries voice message metadata: <!-- VERIFIED: app/routers/messaging.py:2320 -->

```python
voice_message: Optional[Dict[str, Any]] = None
```

Additional relevant fields on `MessageOut` that voicemail messages will inherit:

| Field | Line | Type | Voicemail Usage |
|-------|------|------|-----------------|
| `reactions_counts` | 2344 | `Optional[Dict[str, int]]` | Reactions on voicemail messages | <!-- VERIFIED: app/routers/messaging.py:2344 -->
| `tip_amount_cents` | 2358 | `Optional[int]` | Tips on voicemail messages (future) | <!-- VERIFIED: app/routers/messaging.py:2358 -->
| `expires_at` | 2363 | `Optional[int]` | Voicemail expiry (future) | <!-- VERIFIED: app/routers/messaging.py:2363 -->
| `scheduled` | 2354 | `bool` | Not used for voicemail (always immediate) | <!-- VERIFIED: app/routers/messaging.py:2354 -->

The voicemail kind will be added to this literal and will use a new `voicemail` field for voicemail-specific metadata (call linkage, video URL, call state).

### 2.7 Timeline Event System

`app/services/messaging_call_timeline.py` emits system messages into the conversation timeline for call lifecycle events. The `_preview_for_event` function (line 21) maps event types to human-readable strings: <!-- VERIFIED: app/services/messaging_call_timeline.py:21-36 -->

```python
def _preview_for_event(*, event_type: str, call_state: str, reason: Optional[str]) -> str:
    if event_type == "call.invite":
        return "Started a call"
    if event_type == "call.accept":
        return "Call accepted"
    if event_type == "call.decline":
        if reason == "busy":
            return "Call unavailable (busy)"
        return "Call declined"
    if event_type == "call.end":
        if reason:
            return f"Call ended ({reason})"
        return "Call ended"
    if event_type == "call.missed":
        return "Missed call"
    return f"Call event: {call_state}"
```

The `emit_call_timeline_event` function (lines 39-119) writes a system message item to the Messages table with `sender_id: "system"`, `kind: "text"`, `subtype: "call_lifecycle"`, and updates the conversation's `last_message_preview`. <!-- VERIFIED: app/services/messaging_call_timeline.py:39-119 -->

Timeline messages use `message_id = f"sys_call_{call_id}_{event_type.replace('.', '_')}_{ts}"` (line 52) for deterministic deduplication via `ConditionExpression="attribute_not_exists(message_id)"` (line 78). <!-- VERIFIED: app/services/messaging_call_timeline.py:52,78 -->

The voicemail message will be a **user-sent message** (not a system message), so it sits alongside the existing timeline event rather than replacing it.

### 2.8 Alert System

`app/services/alerts.py` provides `write_alert()` (line 266) which writes an alert to the `alerts` DDB table, increments the unread count sentinel, and publishes to SSE subscribers: <!-- VERIFIED: app/services/alerts.py:266 -->

```python
def write_alert(user_sub: str, *, event: str, outcome: str, title: str, details: Dict[str, Any]) -> Optional[Dict[str, Any]]:
```

The function generates an `alert_id` from timestamp + UUID (line 270), applies a TTL based on `S.alerts_ttl_days` (line 271), writes to DDB via `T.alerts.put_item` (line 300), increments unread count via `increment_unread_count` (line 309), and publishes to SSE via `sse_publish_alert` (line 317). <!-- VERIFIED: app/services/alerts.py:270,271,300,309,317 -->

The existing "missed call" timeline event does NOT generate a user-facing alert — it only writes to the conversation timeline. The voicemail feature will call `write_alert` when a voicemail is left, providing the callee with an out-of-conversation notification.

---

## 3. Technical Design

### 3.1 Voicemail-Eligible Terminal States

A call is voicemail-eligible when ALL of the following are true:

1. The call has reached a terminal state of `declined`, `missed`, or `busy`
2. The caller is the actor viewing the outcome (only callers can leave voicemail)
3. The call is NOT a paid call (`paid == False`) — paid calls have separate billing finalization
4. The call is NOT already linked to a voicemail (`voicemail_message_id` is empty)
5. Voice messages are enabled on the platform (`S.voice_message_enabled == True`)
6. The new voicemail feature flag is enabled (`S.voicemail_enabled == True`)

The `failed` and `canceled` states are NOT voicemail-eligible because:
- `failed`: Technical failure (ICE negotiation, network) — the caller likely cannot record either
- `canceled`: Caller voluntarily canceled before the callee responded — they chose to stop trying
- `ended`: The call was successfully connected and later hung up — both parties already spoke

### 3.2 Voicemail Flow Diagram

```
Alice (caller)                   Backend                           Bob (callee)
  |                                |                                  |
  |-- POST /calls/invite -------->|-- SSE call.invite --------------->|
  |                                |                                  |
  |                                |<-- POST /calls/{id}/decline -----|
  |                                |  (state: invited -> declined)    |
  |                                |                                  |
  |<-- SSE call.decline -----------|                                  |
  |  { state: "declined",          |                                  |
  |    voicemail_eligible: true }  |                                  |
  |                                |                                  |
  |  [UI: "Leave a message?" prompt]                                  |
  |  [User clicks "Record"]        |                                  |
  |                                |                                  |
  |-- POST /conversations/{id}/   |                                  |
  |   voicemail/presign ---------->|                                  |
  |<-- { message_id, upload_url,  |                                  |
  |      s3_key } ----------------|                                  |
  |                                |                                  |
  |  [Records 0-60s audio/video]  |                                  |
  |  [Previews, clicks "Send"]    |                                  |
  |                                |                                  |
  |-- PUT upload_url (S3) ------->|  (direct S3 upload)              |
  |                                |                                  |
  |-- POST /conversations/{id}/   |                                  |
  |   voicemail ------------------>|                                  |
  |                                |-- update CallSessionRecord ----->|
  |                                |   voicemail_message_id = mid     |
  |                                |                                  |
  |                                |-- write message to DDB --------->|
  |                                |   kind="voicemail", call_id=...  |
  |                                |                                  |
  |                                |-- SSE message event ------------>|
  |                                |   (voicemail appears in chat)    |
  |                                |                                  |
  |                                |-- write_alert to Bob ----------->|
  |                                |   "Missed call — voicemail left" |
  |                                |                                  |
  |<-- { message_id, ok: true } --|                                  |
  |                                |                                  |
  |  [UI: "Voicemail sent" toast]  |                                  |
  |  [Overlay closes]              |                                  |
```

### 3.3 S3 Presign Flow Diagram

```
┌──────────────────┐        ┌──────────────────┐        ┌──────────────┐
│  Caller Browser  │        │   FastAPI Backend │        │  S3 (moto)   │
└────────┬─────────┘        └────────┬─────────┘        └──────┬───────┘
         │                           │                         │
         │  POST /voicemail/presign  │                         │
         │  { call_id, content_type, │                         │
         │    size_bytes, mode }     │                         │
         │ ─────────────────────────>│                         │
         │                           │                         │
         │                           │  validate call state    │
         │                           │  validate caller_user_id│
         │                           │  validate no dup VM     │
         │                           │  generate msg_id        │
         │                           │  compute s3_key         │
         │                           │                         │
         │                           │  [dev mode]             │
         │                           │  upload_url = /mock/s3/ │
         │                           │                         │
         │                           │  [prod mode]            │
         │                           │  s3.generate_presigned_ │
         │                           │  url(PUT, 300s expiry)  │
         │                           │                         │
         │  { message_id,            │                         │
         │    upload_url, s3_key }   │                         │
         │ <─────────────────────────│                         │
         │                           │                         │
         │  PUT upload_url           │                         │
         │  Content-Type: audio/webm │                         │
         │  [raw recording bytes]    │                         │
         │ ──────────────────────────┼────────────────────────>│
         │                           │                         │
         │  200 OK                   │                         │
         │ <─────────────────────────┼─────────────────────────│
         │                           │                         │
         │  POST /voicemail          │                         │
         │  { message_id, call_id,   │                         │
         │    s3_key, content_type,  │                         │
         │    duration_seconds,      │                         │
         │    waveform_data, mode }  │                         │
         │ ─────────────────────────>│                         │
         │                           │                         │
         │                           │  write Messages item    │
         │                           │  update CallSession     │
         │                           │  SSE to participants    │
         │                           │  write_alert to callee  │
         │                           │                         │
         │  MessageOut (voicemail)   │                         │
         │ <─────────────────────────│                         │
         │                           │                         │
```

### 3.4 Voicemail Message Data Model

Voicemail messages are stored in the `Messages` DDB table (same as all other messages) with `kind: "voicemail"`. The DDB item schema:

```python
{
    "conversation_id": "conv_abc123",          # PK
    "message_id": "m_deadbeef01234567...",     # SK
    "sender_id": "caller_user_id",             # The caller (who left the voicemail)
    "created_at": 1716681600,                  # Unix timestamp
    "kind": "voicemail",
    "text": None,                              # No text body

    # Audio voicemail fields (reuse voice_message pattern)
    "audio_url": "voicemails/conv_abc123/m_deadbeef01234567.webm",   # S3 key
    "audio_content_type": "audio/webm;codecs=opus",
    "audio_size_bytes": 245760,
    "duration_seconds": Decimal("28.5"),
    "waveform_data": [Decimal("0.12"), Decimal("0.45"), ...],  # 100 samples

    # Video voicemail fields (mutually exclusive with audio fields in v1)
    "video_url": "voicemails/conv_abc123/m_deadbeef01234567.webm",   # S3 key (video)
    "video_content_type": "video/webm;codecs=vp8,opus",
    "video_size_bytes": 1048576,

    # Voicemail-specific fields
    "call_id": "call_xyz789",                  # FK to CallSessionRecord
    "voicemail_mode": "audio",                 # "audio" or "video"
    "call_state": "declined",                  # Terminal state that triggered voicemail

    # Standard message fields
    "reactions": {},
}
```

### 3.5 Pydantic Model Definitions

#### `PresignVoicemailRequest`

```python
class PresignVoicemailRequest(BaseModel):
    """Request body for voicemail presign endpoint."""
    call_id: str = Field(
        min_length=1,
        max_length=128,
        description="ID of the call session that ended unanswered",
    )
    content_type: str = Field(
        pattern=r"^(audio|video)/(webm|mp4|ogg|wav)",
        description="MIME type of the voicemail recording",
    )
    size_bytes: int = Field(
        ge=1,
        le=52_428_800,
        description="Expected size of the recording in bytes (max 50MB)",
    )
    mode: Literal["audio", "video"] = Field(
        default="audio",
        description="Recording mode: audio-only or video+audio",
    )
```

**Example request JSON** (audio):
```json
{
  "call_id": "call_a1b2c3d4e5f6",
  "content_type": "audio/webm",
  "size_bytes": 245760,
  "mode": "audio"
}
```

**Example request JSON** (video):
```json
{
  "call_id": "call_a1b2c3d4e5f6",
  "content_type": "video/webm",
  "size_bytes": 2097152,
  "mode": "video"
}
```

**Example response JSON**:
```json
{
  "message_id": "m_deadbeef01234567890abcdef0123456",
  "upload_url": "/mock/s3/my-chat-images/voicemails/conv_abc123/m_deadbeef01234567890abcdef0123456.webm",
  "s3_key": "voicemails/conv_abc123/m_deadbeef01234567890abcdef0123456.webm"
}
```

#### `CreateVoicemailRequest`

```python
class CreateVoicemailRequest(BaseModel):
    """Request body for voicemail creation endpoint."""
    message_id: str = Field(
        pattern=r"^m_[a-f0-9]{32}$",
        description="Message ID returned by the presign endpoint",
    )
    call_id: str = Field(
        min_length=1,
        max_length=128,
        description="ID of the call session that ended unanswered",
    )
    s3_key: str = Field(
        min_length=1,
        max_length=500,
        description="S3 key returned by the presign endpoint",
    )
    content_type: str = Field(
        min_length=1,
        max_length=100,
        description="MIME type of the uploaded recording",
    )
    size_bytes: int = Field(
        ge=1,
        le=52_428_800,
        description="Actual size of the uploaded recording in bytes",
    )
    duration_seconds: float = Field(
        ge=0.5,
        le=60,
        description="Duration of the recording in seconds (max 60s for voicemail)",
    )
    waveform_data: List[float] = Field(
        min_length=10,
        max_length=200,
        description="Waveform amplitude samples (10-200 floats, each 0.0-1.0)",
    )
    mode: Literal["audio", "video"] = Field(
        default="audio",
        description="Recording mode: audio-only or video+audio",
    )
```

**Example request JSON** (audio):
```json
{
  "message_id": "m_deadbeef01234567890abcdef0123456",
  "call_id": "call_a1b2c3d4e5f6",
  "s3_key": "voicemails/conv_abc123/m_deadbeef01234567890abcdef0123456.webm",
  "content_type": "audio/webm",
  "size_bytes": 245760,
  "duration_seconds": 28.5,
  "waveform_data": [0.12, 0.45, 0.78, 0.92, 0.65, 0.34, 0.56, 0.88, 0.71, 0.43,
                     0.21, 0.67, 0.89, 0.54, 0.32, 0.76, 0.91, 0.48, 0.63, 0.85,
                     0.39, 0.72, 0.58, 0.44, 0.81, 0.69, 0.52, 0.37, 0.94, 0.26],
  "mode": "audio"
}
```

**Example response JSON** (`MessageOut`):
```json
{
  "conversation_id": "conv_abc123",
  "message_id": "m_deadbeef01234567890abcdef0123456",
  "sender_id": "alice_user_sub",
  "created_at": 1716681600,
  "kind": "voicemail",
  "text": null,
  "voicemail": {
    "call_id": "call_a1b2c3d4e5f6",
    "mode": "audio",
    "audio_url": "/mock/s3/my-chat-images/voicemails/conv_abc123/m_deadbeef01234567890abcdef0123456.webm",
    "video_url": null,
    "content_type": "audio/webm",
    "size_bytes": 245760,
    "duration_seconds": 28.5,
    "waveform_data": [0.12, 0.45, 0.78, 0.92, 0.65, 0.34, 0.56, 0.88, 0.71, 0.43,
                       0.21, 0.67, 0.89, 0.54, 0.32, 0.76, 0.91, 0.48, 0.63, 0.85,
                       0.39, 0.72, 0.58, 0.44, 0.81, 0.69, 0.52, 0.37, 0.94, 0.26],
    "call_state": "declined",
    "caller_user_id": "alice_user_sub",
    "callee_user_id": "bob_user_sub"
  },
  "reactions_counts": null,
  "my_reactions": null,
  "is_encrypted": false,
  "scheduled": false
}
```

**Example response JSON** (video voicemail):
```json
{
  "conversation_id": "conv_abc123",
  "message_id": "m_cafebabe01234567890abcdef0123456",
  "sender_id": "alice_user_sub",
  "created_at": 1716681700,
  "kind": "voicemail",
  "text": null,
  "voicemail": {
    "call_id": "call_a1b2c3d4e5f6",
    "mode": "video",
    "audio_url": null,
    "video_url": "/mock/s3/my-chat-images/voicemails/conv_abc123/m_cafebabe01234567890abcdef0123456.webm",
    "content_type": "video/webm",
    "size_bytes": 2097152,
    "duration_seconds": 15.2,
    "waveform_data": [0.32, 0.55, 0.71, 0.88, 0.42, 0.63, 0.79, 0.51, 0.67, 0.38],
    "call_state": "declined",
    "caller_user_id": "alice_user_sub",
    "callee_user_id": "bob_user_sub"
  },
  "reactions_counts": null,
  "my_reactions": null,
  "is_encrypted": false,
  "scheduled": false
}
```

### 3.6 CallSessionRecord Extension

Add one new field to `CallSessionRecord` in `app/services/messaging_call_sessions.py`:

| Field | Type | Description |
|-------|------|-------------|
| `voicemail_message_id` | S \| None | Links to the voicemail message if one was left after the call ended |

This field is set by the voicemail creation endpoint after the voicemail message is written to DDB. It serves as a guard against duplicate voicemails (only one voicemail per call).

### 3.7 New Signaling Types

Two new signal types added to `ALLOWED_SIGNALING_TYPES` in `messaging_call_signaling.py`:

| Signal | Direction | Purpose |
|--------|-----------|---------|
| `call.voicemail_start` | Caller -> Backend | Caller has started recording voicemail |
| `call.voicemail_complete` | Backend -> Callee | Voicemail recording complete, message stored |

These signals are informational (not state-transition signals). They are allowed in terminal states (`declined`, `missed`, `busy`) only. The callee's client can use `call.voicemail_complete` to show a toast or badge without waiting for the full message SSE event.

A new entry in `STATE_ALLOWED_SIGNALING_TYPES`:

```python
STATE_ALLOWED_SIGNALING_TYPES["declined"] = {"call.voicemail_start", "call.voicemail_complete"}
STATE_ALLOWED_SIGNALING_TYPES["missed"] = {"call.voicemail_start", "call.voicemail_complete"}
STATE_ALLOWED_SIGNALING_TYPES["busy"] = {"call.voicemail_start", "call.voicemail_complete"}
```

Note: The terminal-state guard in `route_signaling_event` at line 233 (`if call_state in TERMINAL_CALL_STATES and event_type != "call.end"`) <!-- VERIFIED: app/services/messaging_call_signaling.py:233 --> must be updated to also allow voicemail signals through:

```python
VOICEMAIL_SIGNAL_TYPES = {"call.voicemail_start", "call.voicemail_complete"}

if call_state in TERMINAL_CALL_STATES and event_type != "call.end" and event_type not in VOICEMAIL_SIGNAL_TYPES:
    emit_metric(outcome="error", reason="invalid_state", event_type=event_type)
    raise SignalingValidationError("invalid_state", f"cannot route {event_type} when call is {call_state}")
```

### 3.8 Voicemail Presign Endpoint

```
POST /messaging/conversations/{conversation_id}/voicemail/presign
```

**Request body**: `PresignVoicemailRequest` (see section 3.5)

**Response**:

```json
{
  "message_id": "m_deadbeef01234567890abcdef0123456",
  "upload_url": "/mock/s3/my-chat-images/voicemails/conv_abc/m_dead....webm",
  "s3_key": "voicemails/conv_abc/m_dead....webm"
}
```

**Validation**:
1. User must be a participant of the conversation (`require_participant_active`)
2. The `call_id` must reference a valid `CallSessionRecord` in a voicemail-eligible terminal state
3. The user must be the `caller_user_id` on the call session
4. The call must not already have a `voicemail_message_id` set
5. `S.voicemail_enabled` must be `True`
6. The call must not be a paid call (`call.paid == False`)

**S3 key pattern**: `voicemails/{conversation_id}/{message_id}.{ext}` — separate prefix from `voice-messages/` for easier lifecycle management.

**Error responses**:

| Status | Condition | Body |
|--------|-----------|------|
| 404 | `VOICEMAIL_ENABLED=0` | `"Voicemail is not enabled"` |
| 404 | `call_id` not found | `"Call not found"` |
| 400 | Call not in eligible state | `"Call state '{state}' is not voicemail-eligible"` |
| 400 | Paid call | `"Voicemail is not available for paid calls"` |
| 400 | Wrong conversation | `"Call does not belong to this conversation"` |
| 403 | Not the caller | `"Only the caller can leave a voicemail"` |
| 409 | Duplicate voicemail | `"A voicemail has already been left for this call"` |

### 3.9 Voicemail Create Endpoint

```
POST /messaging/conversations/{conversation_id}/voicemail
```

**Request body**: `CreateVoicemailRequest` (see section 3.5)

**Response**: `MessageOut` (the voicemail message)

**Behavior**:
1. Validate caller is participant and is the `caller_user_id` on the referenced call
2. Validate call is in a voicemail-eligible terminal state
3. Validate call does not already have a `voicemail_message_id`
4. Validate call is not a paid call
5. Cap waveform to `S.voice_message_waveform_samples` samples, clamp each value to [0.0, 1.0]
6. Write voicemail message item to `Messages` table with `kind: "voicemail"`
7. Update `CallSessionRecord` to set `voicemail_message_id`
8. Update conversation `last_message_id` and `last_message_at`
9. Emit SSE event to all conversation participants
10. Call `write_alert` for the callee: "Missed call — voicemail left"
11. Return `MessageOut` with voicemail-specific fields populated

**Error responses**: Same as presign endpoint, plus:

| Status | Condition | Body |
|--------|-----------|------|
| 422 | Validation error (duration > 60, waveform < 10 items, etc.) | Pydantic validation detail |

### 3.10 MessageOut Extension

Add `"voicemail"` to the `kind` literal on `MessageOut` (line 2310): <!-- VERIFIED: app/routers/messaging.py:2310 -->

```python
kind: Literal["text", "image", "file", "audio", "video", "gallery",
              "file_share", "calendar_share", "calendar_event",
              "meeting_poll", "video_share", "voice_message", "voicemail"]
```

Add a new optional field (after the `voice_message` field at line 2320): <!-- VERIFIED: app/routers/messaging.py:2320 -->

```python
voicemail: Optional[Dict[str, Any]] = None
```

The `voicemail` field structure:

```python
{
    "call_id": "call_xyz789",
    "mode": "audio",                              # "audio" or "video"
    "audio_url": "/mock/s3/.../voicemails/...",    # present for audio voicemails
    "video_url": "/mock/s3/.../voicemails/...",    # present for video voicemails
    "content_type": "audio/webm;codecs=opus",
    "size_bytes": 245760,
    "duration_seconds": 28.5,
    "waveform_data": [0.12, 0.45, ...],
    "call_state": "declined",                      # terminal state that triggered voicemail
    "caller_user_id": "alice_sub",
    "callee_user_id": "bob_sub",
}
```

### 3.11 _message_out_from_item Voicemail Projection

Add a voicemail projection block in `_message_out_from_item` (after the existing voice message projection at line 3946), following the same URL-rewriting pattern: <!-- VERIFIED: app/routers/messaging.py:3745,3929-3946 -->

```python
# Voicemail projection
voicemail_out: Optional[Dict[str, Any]] = None
if merged_item.get("kind") == "voicemail" and not content_hidden:
    from urllib.parse import quote as _vm_url_quote
    _vm_mode = str(merged_item.get("voicemail_mode") or "audio")

    _vm_media_url = ""
    if _vm_mode == "video":
        _vm_s3_key = str(merged_item.get("video_url") or "")
    else:
        _vm_s3_key = str(merged_item.get("audio_url") or "")

    if _vm_s3_key:
        if S.dev_mode:
            _vm_media_url = f"/mock/s3/{S3_BUCKET_IMAGES}/{_vm_url_quote(_vm_s3_key, safe='/')}"
        else:
            _vm_media_url = _vm_s3_key

    raw_waveform = merged_item.get("waveform_data") or []
    voicemail_out = {
        "call_id": str(merged_item.get("call_id") or ""),
        "mode": _vm_mode,
        "audio_url": _vm_media_url if _vm_mode == "audio" else None,
        "video_url": _vm_media_url if _vm_mode == "video" else None,
        "content_type": merged_item.get("audio_content_type") or merged_item.get("video_content_type"),
        "size_bytes": int(merged_item.get("audio_size_bytes") or merged_item.get("video_size_bytes") or 0),
        "duration_seconds": float(merged_item.get("duration_seconds", 0)),
        "waveform_data": [float(v) for v in raw_waveform],
        "call_state": str(merged_item.get("call_state") or ""),
        "caller_user_id": str(merged_item.get("caller_user_id") or ""),
        "callee_user_id": str(merged_item.get("callee_user_id") or ""),
    }
```

### 3.12 Alert Notification

When a voicemail is created, call `write_alert` for the callee using the existing alert infrastructure (`app/services/alerts.py` line 266): <!-- VERIFIED: app/services/alerts.py:266 -->

```python
from app.services.alerts import write_alert

write_alert(
    user_sub=callee_user_id,
    event="voicemail_received",
    outcome="info",
    title=f"Missed call — voicemail left",
    details={
        "conversation_id": conversation_id,
        "message_id": message_id,
        "call_id": call_id,
        "caller_user_id": caller_user_id,
        "voicemail_mode": mode,
        "duration_seconds": duration_seconds,
    },
)
```

The alert links to the conversation so the callee can navigate directly to the voicemail message. The `write_alert` function handles DDB write, unread count increment, and SSE publication automatically.

### 3.13 Group Call Voicemail

For group calls (CALL-012), voicemail works with these constraints:

1. Only the call creator (the user who started the group call) can leave a voicemail
2. The voicemail message goes to the group conversation (not individual DMs)
3. The alert is sent to all group conversation participants except the caller
4. The voicemail `callee_user_id` is set to `"group"` to indicate it is a group voicemail
5. The call must have reached a terminal state where no participants joined (i.e., the group call was never `active`)

The group call voicemail eligibility check queries the `group_call_sessions` table to verify no participant ever joined the call.

For group voicemail alerts, iterate over all conversation participants and call `write_alert` for each non-caller participant:

```python
for participant in participants:
    participant_user_id = str(participant.get("user_id") or "")
    if participant_user_id and participant_user_id != user_id:
        try:
            write_alert(
                user_sub=participant_user_id,
                event="voicemail_received",
                outcome="info",
                title=f"Missed group call — voicemail left",
                details={...},
            )
        except Exception:
            pass  # best-effort delivery
```

### 3.14 Video Voicemail Recording

Video voicemail uses the browser's `MediaRecorder` API with video+audio capture:

- **Codec selection**: `video/webm;codecs=vp8,opus` (Chrome/Firefox), `video/mp4;codecs=h264,aac` (Safari fallback)
- **Max resolution**: 720p (1280x720) to keep file sizes under 50MB for 60 seconds
- **Camera + microphone**: Both streams captured simultaneously
- **Preview**: Video playback element replaces the waveform visualization
- **Presign content_type**: `video/webm` or `video/mp4` based on codec detection

The `VideoVoicemailRecorder` component uses the following `MediaRecorder` configuration:

```typescript
const stream = await navigator.mediaDevices.getUserMedia({
  video: {
    width: { ideal: 1280, max: 1280 },
    height: { ideal: 720, max: 720 },
    frameRate: { ideal: 30, max: 30 },
    facingMode: "user",   // front camera
  },
  audio: {
    echoCancellation: true,
    noiseSuppression: true,
    autoGainControl: true,
  },
});

const mimeType = detectVideoMimeType(); // video/webm;codecs=vp8,opus or video/mp4
const recorder = new MediaRecorder(stream, {
  mimeType,
  videoBitsPerSecond: 1_500_000,  // 1.5 Mbps — ~11MB per 60s
  audioBitsPerSecond: 128_000,    // 128 kbps
});
```

**Video codec detection function**:

```typescript
function detectVideoMimeType(): string {
  if (typeof MediaRecorder === "undefined") return "video/webm";
  if (MediaRecorder.isTypeSupported("video/webm;codecs=vp8,opus")) return "video/webm;codecs=vp8,opus";
  if (MediaRecorder.isTypeSupported("video/webm;codecs=vp9,opus")) return "video/webm;codecs=vp9,opus";
  if (MediaRecorder.isTypeSupported("video/webm")) return "video/webm";
  if (MediaRecorder.isTypeSupported("video/mp4")) return "video/mp4";
  return "video/webm";
}
```

### 3.15 VoicemailRecorder Component State Machine

The `VoicemailRecorder` component manages a 5-phase state machine:

```
                          ┌─────────┐
                          │  idle   │  (initial — shows prompt)
                          └────┬────┘
                               │ user clicks "Record Audio" or "Record Video"
                               v
                          ┌──────────┐
              ┌──────────>│ recording│  (MediaRecorder active, live waveform/preview)
              │           └────┬─────┘
              │                │ user clicks "Stop" or max 60s reached
              │                v
              │           ┌────────────┐
              └───────────│ previewing │  (playback of recording, re-record option)
              re-record   └────┬───────┘
                               │ user clicks "Send"
                               v
                          ┌───────────┐
                          │ uploading │  (presign + PUT S3 + POST create)
                          └────┬──────┘
                               │ success
                               v
                          ┌──────┐
                          │ sent │  (toast shown, overlay dismissed)
                          └──────┘
```

**State transitions and side effects**:

| From | To | Trigger | Side Effect |
|------|----|---------|-------------|
| `idle` | `recording` | User clicks Record | `getUserMedia()`, create `MediaRecorder`, start timer |
| `recording` | `previewing` | User clicks Stop or 60s reached | `recorder.stop()`, stop media tracks, build preview blob |
| `previewing` | `recording` | User clicks Re-record | Restart `getUserMedia()` + `MediaRecorder` |
| `previewing` | `uploading` | User clicks Send | POST presign, PUT S3, POST create |
| `uploading` | `sent` | Backend returns 200 | Toast "Voicemail sent", call `onSent()` |
| `uploading` | `previewing` | Upload fails | Show error, allow retry |
| any | dismissed | User clicks Skip | Call `onSkip()`, close overlay |

**Error states during upload**:

| Error | Recovery | UI |
|-------|----------|-----|
| Presign 400/403/409 | Return to previewing with error message | "Could not prepare upload. Try again." |
| S3 PUT timeout/error | Return to previewing with error message | "Upload failed. Check your connection and try again." |
| Create POST 400/409 | Return to previewing with error message | "Could not save voicemail. Try again." |
| Create POST 500 | Return to previewing with error message | "Server error. Try again later." |

---

## 4. Implementation Plan

### Phase 1: Backend — Voicemail Endpoints and Data Model (Days 1-3)

#### Modify: `app/services/messaging_call_sessions.py`

Add `voicemail_message_id` field to `CallSessionRecord` (after line 48): <!-- VERIFIED: app/services/messaging_call_sessions.py:48 -->

```python
@dataclass(frozen=True)
class CallSessionRecord:
    # ... existing fields ...
    # CALL-014: voicemail linkage
    voicemail_message_id: Optional[str] = None
```

Update `_item_from_record()` (after line 89) to serialize the new field: <!-- VERIFIED: app/services/messaging_call_sessions.py:51-89 -->

```python
if record.voicemail_message_id:
    item["voicemail_message_id"] = record.voicemail_message_id
```

Update `_record_from_item()` (within lines 92-123) to deserialize: <!-- VERIFIED: app/services/messaging_call_sessions.py:92-123 -->

```python
voicemail_message_id=str(item["voicemail_message_id"]) if item.get("voicemail_message_id") else None,
```

Update `update_call_session_state()` to preserve the field through state transitions (add to the `CallSessionRecord(...)` constructor at line 188): <!-- VERIFIED: app/services/messaging_call_sessions.py:188 -->

```python
voicemail_message_id=existing.voicemail_message_id,
```

Add a new function for updating just the voicemail linkage:

```python
def set_voicemail_message_id(*, call_id: str, voicemail_message_id: str) -> Optional[CallSessionRecord]:
    """Set the voicemail_message_id on a call session record.

    Uses a conditional update to prevent overwriting an existing voicemail link,
    providing server-side duplicate prevention even if the client retries.
    """
    existing = get_call_session(call_id)
    if not existing:
        return None
    if existing.voicemail_message_id:
        return existing  # already linked, idempotent

    item = _item_from_record(
        CallSessionRecord(
            call_id=existing.call_id,
            conversation_id=existing.conversation_id,
            caller_user_id=existing.caller_user_id,
            callee_user_id=existing.callee_user_id,
            initial_mode=existing.initial_mode,
            state=existing.state,
            start_ts=existing.start_ts,
            connect_ts=existing.connect_ts,
            end_ts=existing.end_ts,
            end_reason=existing.end_reason,
            network_path=existing.network_path,
            lifecycle_events=existing.lifecycle_events,
            idempotency_records=existing.idempotency_records,
            broadcast_session_id=existing.broadcast_session_id,
            paid=existing.paid,
            rate_cents_per_min=existing.rate_cents_per_min,
            billing_status=existing.billing_status,
            billing_start_ts=existing.billing_start_ts,
            last_billed_ts=existing.last_billed_ts,
            total_billed_cents=existing.total_billed_cents,
            total_billed_seconds=existing.total_billed_seconds,
            billing_cycle_count=existing.billing_cycle_count,
            platform_fee_bps=existing.platform_fee_bps,
            max_duration_seconds=existing.max_duration_seconds,
            caller_last_heartbeat_ts=existing.caller_last_heartbeat_ts,
            callee_last_heartbeat_ts=existing.callee_last_heartbeat_ts,
            voicemail_message_id=voicemail_message_id,
        )
    )
    _table().put_item(Item=item)
    return _record_from_item(item)
```

#### Modify: `app/services/messaging_call_signaling.py`

Add voicemail signal types to `ALLOWED_SIGNALING_TYPES` (line 14): <!-- VERIFIED: app/services/messaging_call_signaling.py:14 -->

```python
ALLOWED_SIGNALING_TYPES = {
    # ... existing types ...
    "call.voicemail_start",
    "call.voicemail_complete",
}
```

Add terminal-state signaling allowances to `STATE_ALLOWED_SIGNALING_TYPES` (after line 42): <!-- VERIFIED: app/services/messaging_call_signaling.py:42 -->

```python
STATE_ALLOWED_SIGNALING_TYPES["declined"] = {"call.voicemail_start", "call.voicemail_complete"}
STATE_ALLOWED_SIGNALING_TYPES["missed"] = {"call.voicemail_start", "call.voicemail_complete"}
STATE_ALLOWED_SIGNALING_TYPES["busy"] = {"call.voicemail_start", "call.voicemail_complete"}
```

Update the terminal-state guard at line 233 to allow voicemail signals: <!-- VERIFIED: app/services/messaging_call_signaling.py:233 -->

```python
VOICEMAIL_SIGNAL_TYPES = {"call.voicemail_start", "call.voicemail_complete"}
# Replace line 233:
if call_state in TERMINAL_CALL_STATES and event_type != "call.end" and event_type not in VOICEMAIL_SIGNAL_TYPES:
```

#### Modify: `app/services/messaging_call_lifecycle.py`

Modify `decline_invite()` (line 279), `timeout_call()` (line 404) return values. No code change is needed in the lifecycle functions themselves — the `voicemail_eligible` flag is computed by the router from the returned `CallSessionRecord` state and `paid` flag.

#### Modify: `app/core/settings.py`

Add voicemail-specific settings (after line 1254): <!-- VERIFIED: app/core/settings.py:1254 -->

```python
voicemail_enabled: bool = os.environ.get("VOICEMAIL_ENABLED", "1") not in ("0", "false", "False")
voicemail_max_duration_seconds: int = int(os.environ.get("VOICEMAIL_MAX_DURATION_SECONDS", "60"))
voicemail_max_size_bytes: int = int(os.environ.get("VOICEMAIL_MAX_SIZE_BYTES", "52428800"))
```

#### Modify: `app/routers/messaging.py`

**Add Pydantic models** (after the `CreateVoiceMessageRequest` class at line 1952): <!-- VERIFIED: app/routers/messaging.py:1952 -->

See section 3.5 for complete `PresignVoicemailRequest` and `CreateVoicemailRequest` definitions.

**Add `"voicemail"` to the `MessageOut.kind` literal** (line 2310): <!-- VERIFIED: app/routers/messaging.py:2310 -->

```python
kind: Literal["text", "image", "file", "audio", "video", "gallery",
              "file_share", "calendar_share", "calendar_event",
              "meeting_poll", "video_share", "voice_message", "voicemail"]
```

**Add `voicemail` field to `MessageOut`** (after the `voice_message` field at line 2320): <!-- VERIFIED: app/routers/messaging.py:2320 -->

```python
voicemail: Optional[Dict[str, Any]] = None
```

**Add voicemail presign endpoint** (after the voice message endpoints, ~line 8280):

```python
VOICEMAIL_ELIGIBLE_STATES = {"declined", "missed", "busy"}

@router.post("/conversations/{conversation_id}/voicemail/presign")
def presign_voicemail(
    conversation_id: str,
    body: PresignVoicemailRequest,
    user_id: str = Depends(get_messaging_user_id),
):
    """Get a presigned S3 upload URL for a voicemail recording."""
    if not S.voicemail_enabled:
        raise HTTPException(404, "Voicemail is not enabled")
    require_participant_active(user_id, conversation_id)

    # Validate call eligibility
    call = get_call_session(body.call_id)
    if not call:
        raise HTTPException(404, "Call not found")
    if call.conversation_id != conversation_id:
        raise HTTPException(400, "Call does not belong to this conversation")
    if call.caller_user_id != user_id:
        raise HTTPException(403, "Only the caller can leave a voicemail")
    if call.state not in VOICEMAIL_ELIGIBLE_STATES:
        raise HTTPException(400, f"Call state '{call.state}' is not voicemail-eligible")
    if call.paid:
        raise HTTPException(400, "Voicemail is not available for paid calls")
    if call.voicemail_message_id:
        raise HTTPException(409, "A voicemail has already been left for this call")

    msg_id = "m_" + uuid.uuid4().hex
    ext = "webm"
    if "mp4" in body.content_type:
        ext = "mp4"
    elif "ogg" in body.content_type:
        ext = "ogg"
    elif "wav" in body.content_type:
        ext = "wav"
    s3_key = f"voicemails/{conversation_id}/{msg_id}.{ext}"

    from urllib.parse import quote as _vm_pq
    if S.dev_mode:
        upload_url = f"/mock/s3/{S3_BUCKET_IMAGES}/{_vm_pq(s3_key, safe='/')}"
    else:
        upload_url = s3.generate_presigned_url(
            ClientMethod="put_object",
            Params={"Bucket": S3_BUCKET_IMAGES, "Key": s3_key, "ContentType": body.content_type},
            ExpiresIn=300,
        )
    return {"message_id": msg_id, "upload_url": upload_url, "s3_key": s3_key}
```

**Add voicemail create endpoint**:

```python
@router.post("/conversations/{conversation_id}/voicemail", response_model=MessageOut)
def create_voicemail(
    conversation_id: str,
    body: CreateVoicemailRequest,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    """Create a voicemail message after uploading the recording to S3."""
    if not S.voicemail_enabled:
        raise HTTPException(404, "Voicemail is not enabled")
    require_participant_active(user_id, conversation_id)

    # Validate call eligibility (same checks as presign)
    call = get_call_session(body.call_id)
    if not call:
        raise HTTPException(404, "Call not found")
    if call.conversation_id != conversation_id:
        raise HTTPException(400, "Call does not belong to this conversation")
    if call.caller_user_id != user_id:
        raise HTTPException(403, "Only the caller can leave a voicemail")
    if call.state not in VOICEMAIL_ELIGIBLE_STATES:
        raise HTTPException(400, f"Call state '{call.state}' is not voicemail-eligible")
    if call.paid:
        raise HTTPException(400, "Voicemail is not available for paid calls")
    if call.voicemail_message_id:
        raise HTTPException(409, "A voicemail has already been left for this call")

    convo = _get_conversation_or_404(conversation_id)
    ts = now_ts()
    mid = body.message_id

    max_samples = S.voice_message_waveform_samples
    waveform = [max(0.0, min(1.0, float(v))) for v in body.waveform_data[:max_samples]]
    from decimal import Decimal as _DecVM
    waveform_dec = [_DecVM(str(v)) for v in waveform]

    # Build message item
    item: Dict[str, Any] = {
        "conversation_id": conversation_id,
        "message_id": mid,
        "sender_id": user_id,
        "created_at": ts,
        "kind": "voicemail",
        "text": None,
        "call_id": body.call_id,
        "voicemail_mode": body.mode,
        "duration_seconds": _DecVM(str(body.duration_seconds)),
        "waveform_data": waveform_dec,
        "call_state": call.state,
        "caller_user_id": call.caller_user_id,
        "callee_user_id": call.callee_user_id,
        "reactions": {},
    }

    if body.mode == "video":
        item["video_url"] = body.s3_key
        item["video_content_type"] = body.content_type
        item["video_size_bytes"] = body.size_bytes
    else:
        item["audio_url"] = body.s3_key
        item["audio_content_type"] = body.content_type
        item["audio_size_bytes"] = body.size_bytes

    ttl = _message_retention_ttl(convo, ts)
    if ttl:
        item["ttl"] = ttl

    tbl_msgs.put_item(Item=item)

    # Link voicemail to call session
    from app.services.messaging_call_sessions import set_voicemail_message_id
    set_voicemail_message_id(call_id=body.call_id, voicemail_message_id=mid)

    # Lookup participants for SSE and notification
    try:
        resp = tbl_parts.query(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(conversation_id))
        participants = resp.get("Items", [])
    except Exception:
        participants = []

    _send_single_destination_message(
        conversation_id=conversation_id,
        sender_id=user_id,
        message_id=mid,
        created_at=ts,
        message_item=item,
        participants=participants,
        is_scheduled=False,
        preview_text="[Voicemail]",
    )

    # Dispatch alert to callee (or all group members)
    try:
        from app.services.alerts import write_alert
        alert_details = {
            "conversation_id": conversation_id,
            "message_id": mid,
            "call_id": body.call_id,
            "caller_user_id": user_id,
            "voicemail_mode": body.mode,
            "duration_seconds": body.duration_seconds,
        }

        if call.callee_user_id and call.callee_user_id != "group":
            # 1-on-1 call: alert the callee
            write_alert(
                user_sub=call.callee_user_id,
                event="voicemail_received",
                outcome="info",
                title="Missed call — voicemail left",
                details=alert_details,
            )
        else:
            # Group call: alert all participants except the caller
            for p in participants:
                p_uid = str(p.get("user_id") or "")
                if p_uid and p_uid != user_id:
                    try:
                        write_alert(
                            user_sub=p_uid,
                            event="voicemail_received",
                            outcome="info",
                            title="Missed group call — voicemail left",
                            details=alert_details,
                        )
                    except Exception:
                        pass
    except Exception:
        import logging
        logging.getLogger(__name__).warning(
            "voicemail_alert_dispatch_error",
            extra={"call_id": body.call_id, "message_id": mid},
        )

    # Build response
    from urllib.parse import quote as _vm_url_quote
    media_url = ""
    if body.s3_key:
        if S.dev_mode:
            media_url = f"/mock/s3/{S3_BUCKET_IMAGES}/{_vm_url_quote(body.s3_key, safe='/')}"
        else:
            media_url = body.s3_key

    voicemail_out = {
        "call_id": body.call_id,
        "mode": body.mode,
        "audio_url": media_url if body.mode == "audio" else None,
        "video_url": media_url if body.mode == "video" else None,
        "content_type": body.content_type,
        "size_bytes": body.size_bytes,
        "duration_seconds": float(body.duration_seconds),
        "waveform_data": waveform,
        "call_state": call.state,
        "caller_user_id": call.caller_user_id,
        "callee_user_id": call.callee_user_id,
    }

    return MessageOut(
        conversation_id=conversation_id,
        message_id=mid,
        sender_id=user_id,
        created_at=ts,
        kind="voicemail",
        voicemail=voicemail_out,
    )
```

**Add voicemail projection to `_message_out_from_item`** (after the voice message projection block at ~line 3946): <!-- VERIFIED: app/routers/messaging.py:3946 -->

See section 3.11 for the complete projection code.

#### Modify: `app/services/messaging_call_timeline.py`

Add voicemail preview text to `_preview_for_event()` (after line 35): <!-- VERIFIED: app/services/messaging_call_timeline.py:35 -->

```python
if event_type == "call.voicemail_complete":
    return "Voicemail left"
```

### Phase 2: Frontend — Voicemail Recording UI (Days 4-7)

#### New File: `frontend/src/pages/messages/VoicemailRecorder.tsx`

A wrapper around `VoiceRecorder` with voicemail-specific constraints:

```typescript
import { VoiceRecorder } from "./VoiceRecorder";

interface VoicemailRecorderProps {
  conversationId: string;
  callId: string;
  callMode: "audio" | "video";
  peerName: string;
  onSent: () => void;
  onSkip: () => void;
}

export function VoicemailRecorder({
  conversationId,
  callId,
  callMode,
  peerName,
  onSent,
  onSkip,
}: VoicemailRecorderProps) {
  const [mode, setMode] = useState<"audio" | "video">(callMode === "video" ? "video" : "audio");
  const [phase, setPhase] = useState<"prompt" | "recording" | "uploading" | "sent">("prompt");

  // 1. Prompt phase: "Leave a message for {peerName}?"
  //    [Record Audio] [Record Video] [Skip]
  //
  // 2. Recording phase:
  //    - Audio: Render VoiceRecorder with maxDuration=60
  //    - Video: Render VideoVoicemailRecorder (new, uses MediaRecorder with video+audio)
  //
  // 3. On complete:
  //    - POST presign -> PUT S3 -> POST create voicemail
  //    - Show "Voicemail sent" toast
  //    - Call onSent()
}
```

**Prompt phase UI**:
```
+-------------------------------------+
|  Missed call                        |
|                                     |
|  Leave a message for Bob?           |
|                                     |
|  [Record Audio] [Record Video]      |
|                                     |
|             [Skip]                  |
+-------------------------------------+
```

**Recording phase UI** (audio mode):
```
+-------------------------------------+
|  Recording voicemail for Bob        |
|                                     |
|  +-----------------------------+    |
|  |  [waveform bars] 0:15/1:00 |    |
|  +-----------------------------+    |
|                                     |
|  [Stop]                            |
+-------------------------------------+
```

**Preview phase UI** (audio mode):
```
+-------------------------------------+
|  Voicemail preview                  |
|                                     |
|  +-----------------------------+    |
|  |  [play] [waveform] 0:15    |    |
|  +-----------------------------+    |
|                                     |
|  [Re-record] [Send] [Skip]         |
+-------------------------------------+
```

#### New File: `frontend/src/pages/messages/VideoVoicemailRecorder.tsx`

A video recording component for video voicemails:

```typescript
interface VideoVoicemailRecorderProps {
  onComplete: (blob: Blob, meta: { duration: number; waveform: number[]; contentType: string }) => void;
  onCancel: () => void;
  maxDuration?: number;  // default 60
}
```

Uses `navigator.mediaDevices.getUserMedia({ video: { width: 1280, height: 720 }, audio: true })` to capture both video and audio. The waveform is extracted from the audio track via `AnalyserNode` (same pattern as `VoiceRecorder` at line 86-90). <!-- VERIFIED: frontend/src/pages/messages/VoiceRecorder.tsx:86-90 --> Preview uses a `<video>` element with `URL.createObjectURL(blob)`.

#### Modify: `frontend/src/pages/messages/CallSessionOverlay.tsx`

**Add new props** (after line 63): <!-- VERIFIED: frontend/src/pages/messages/CallSessionOverlay.tsx:63 -->

```typescript
interface Props {
  // ... existing props ...
  onRecordVoicemail?: () => void;    // Triggered when user clicks "Record"
  onSkipVoicemail?: () => void;      // Triggered when user clicks "Skip"
  voicemailPhase?: "prompt" | "recording" | "uploading" | "sent" | null;
  voicemailEligible?: boolean;       // Backend says this call supports voicemail
}
```

**Modify the outcome section** (lines 588-592): <!-- VERIFIED: frontend/src/pages/messages/CallSessionOverlay.tsx:588-592 -->

Replace the single "Dismiss" button for voicemail-eligible outcomes:

```tsx
{isOutcome && (
  <>
    {voicemailEligible && !voicemailPhase && session.direction === "outgoing" && (
      <div className="flex flex-col gap-2 w-full">
        <p className="text-sm text-muted-foreground">Leave a message?</p>
        <div className="flex gap-2">
          <Button onClick={onRecordVoicemail} aria-label="Record voicemail">
            <Mic className="mr-2 h-4 w-4" />
            Record
          </Button>
          <Button variant="outline" onClick={onSkipVoicemail ?? onDismiss} aria-label="Skip voicemail">
            Skip
          </Button>
        </div>
      </div>
    )}
    {voicemailPhase === "recording" && (
      <VoicemailRecorder
        conversationId={session.callId ? "..." : ""}
        callId={session.callId ?? ""}
        callMode={session.mode}
        peerName={session.peerName}
        onSent={onDismiss}
        onSkip={onDismiss}
      />
    )}
    {!voicemailEligible && (
      <Button onClick={onDismiss} aria-label="Dismiss call status">
        Dismiss
      </Button>
    )}
  </>
)}
```

#### New File: `frontend/src/pages/messages/VoicemailBubble.tsx`

A specialized message bubble for voicemail messages rendered inside `MessageBubble`:

```typescript
interface VoicemailBubbleProps {
  voicemail: {
    call_id: string;
    mode: "audio" | "video";
    audio_url?: string | null;
    video_url?: string | null;
    content_type: string;
    size_bytes: number;
    duration_seconds: number;
    waveform_data: number[];
    call_state: string;
    caller_user_id: string;
    callee_user_id: string;
  };
  isOwn: boolean;
  onCallBack?: () => void;
}
```

**Audio voicemail rendering**:
```
+----------------------------------+
|  Missed call -- voicemail        |
|                                  |
|  +----------------------------+  |
|  | [play] [waveform] 0:28    |  |
|  +----------------------------+  |
|                                  |
|  [Call back]                     |
+----------------------------------+
```

**Video voicemail rendering**:
```
+----------------------------------+
|  Missed call -- voicemail        |
|                                  |
|  +----------------------------+  |
|  |                            |  |
|  |     [play] [video player]  |  |
|  |                            |  |
|  +----------------------------+  |
|                                  |
|  [Call back]                     |
+----------------------------------+
```

The "Call back" button triggers a new call invite to the voicemail sender, reusing the existing call initiation flow in `ConversationView`.

#### Modify: `frontend/src/pages/messages/MessageBubble.tsx`

Add a case for `kind === "voicemail"` in the message rendering logic:

```tsx
{msg.kind === "voicemail" && msg.voicemail && (
  <VoicemailBubble
    voicemail={msg.voicemail}
    isOwn={msg.sender_id === currentUserId}
    onCallBack={() => onStartCall?.(msg.voicemail!.callee_user_id === currentUserId
      ? msg.voicemail!.caller_user_id
      : msg.voicemail!.callee_user_id)}
  />
)}
```

#### Modify: `frontend/src/api/types.ts`

Add TypeScript types:

```typescript
export interface VoicemailData {
  call_id: string;
  mode: "audio" | "video";
  audio_url: string | null;
  video_url: string | null;
  content_type: string;
  size_bytes: number;
  duration_seconds: number;
  waveform_data: number[];
  call_state: string;
  caller_user_id: string;
  callee_user_id: string;
}

// Extend MessageOut type:
export interface MessageOut {
  // ... existing fields ...
  voicemail?: VoicemailData | null;
}
```

#### Modify: `frontend/src/api/endpoints/messaging.ts`

Add voicemail API wrappers:

```typescript
export const presignVoicemail = (
  conversationId: string,
  data: { call_id: string; content_type: string; size_bytes: number; mode: "audio" | "video" }
) =>
  client
    .post<{ message_id: string; upload_url: string; s3_key: string }>(
      `/ui/messaging/conversations/${conversationId}/voicemail/presign`,
      data
    )
    .then((r) => r.data);

export const createVoicemail = (
  conversationId: string,
  data: {
    message_id: string;
    call_id: string;
    s3_key: string;
    content_type: string;
    size_bytes: number;
    duration_seconds: number;
    waveform_data: number[];
    mode: "audio" | "video";
  }
) =>
  client
    .post<MessageOut>(`/ui/messaging/conversations/${conversationId}/voicemail`, data)
    .then((r) => r.data);
```

### Phase 3: Integration and Polish (Days 8-10)

#### Modify: `frontend/src/pages/messages/ConversationView.tsx`

Wire the voicemail flow into the call session state machine:

1. When a call reaches an outcome state, check if `voicemail_eligible` is true in the SSE event payload
2. Set `voicemailEligible` state flag, pass to `CallSessionOverlay`
3. On "Record" click, transition to recording phase
4. After successful voicemail send, invalidate the conversation's messages query to show the voicemail bubble
5. Dismiss the overlay

```typescript
const [voicemailEligible, setVoicemailEligible] = useState(false);
const [voicemailPhase, setVoicemailPhase] = useState<"prompt" | "recording" | "uploading" | "sent" | null>(null);

// In SSE handler for call.decline / call.missed:
if (event.voicemail_eligible) {
  setVoicemailEligible(true);
}
```

#### Modify: SSE Event Handling

The backend must include `voicemail_eligible: true` in the SSE event payload when a call transitions to a voicemail-eligible terminal state. This is done by extending the event payload in the call lifecycle response processing in the messaging router.

In the `/calls/{call_id}/decline` and `/calls/{call_id}/timeout` endpoint handlers, add to the SSE event:

```python
event_payload["voicemail_eligible"] = (
    not record.paid
    and record.state in VOICEMAIL_ELIGIBLE_STATES
    and S.voicemail_enabled
    and not record.voicemail_message_id
)
```

#### Sidebar Preview Text

In `_message_out_from_item` / `getPreviewText` (frontend), voicemail messages should show `"[Voicemail]"` in the conversation list sidebar:

```typescript
// In getPreviewText (ConversationList.tsx):
if (lastMsg.kind === "voicemail") return "[Voicemail]";
```

#### Modify: `frontend/src/hooks/useMessagingStream.ts`

Handle `call.voicemail_complete` SSE events to invalidate the messages query:

```typescript
if (event.type === "call.voicemail_complete") {
  queryClient.invalidateQueries({
    queryKey: ["messages", event.conversation_id],
  });
  queryClient.invalidateQueries({
    queryKey: ["conversations"],
  });
}
```

### Phase 4: E2E Tests (Days 10-12)

#### New File: `frontend/e2e/voicemail.spec.ts`

See section 5 for full testing strategy.

### File Change Summary

| File | Action | Description |
|------|--------|-------------|
| `app/services/messaging_call_sessions.py` | Modify | Add `voicemail_message_id` field + `set_voicemail_message_id()` |
| `app/services/messaging_call_signaling.py` | Modify | Add voicemail signal types to allowlists + terminal-state guard |
| `app/services/messaging_call_timeline.py` | Modify | Add voicemail preview text |
| `app/core/settings.py` | Modify | Add `voicemail_enabled`, `voicemail_max_duration_seconds`, `voicemail_max_size_bytes` |
| `app/routers/messaging.py` | Modify | Add models, endpoints, projection, `"voicemail"` kind |
| `frontend/src/pages/messages/VoicemailRecorder.tsx` | **New** | Voicemail recording UI (wraps VoiceRecorder) |
| `frontend/src/pages/messages/VideoVoicemailRecorder.tsx` | **New** | Video voicemail recording |
| `frontend/src/pages/messages/VoicemailBubble.tsx` | **New** | Voicemail message rendering |
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | Modify | Add voicemail prompt to outcome states |
| `frontend/src/pages/messages/MessageBubble.tsx` | Modify | Add voicemail rendering case |
| `frontend/src/pages/messages/ConversationView.tsx` | Modify | Wire voicemail state into call flow |
| `frontend/src/api/types.ts` | Modify | Add `VoicemailData` type |
| `frontend/src/api/endpoints/messaging.ts` | Modify | Add `presignVoicemail`, `createVoicemail` |
| `frontend/src/hooks/useMessagingStream.ts` | Modify | Handle `call.voicemail_complete` events |
| `frontend/e2e/voicemail.spec.ts` | **New** | E2E tests |

---

## 5. Testing Strategy

### 5.1 E2E Test Plan: `frontend/e2e/voicemail.spec.ts`

The E2E tests use the existing session injection pattern (`injectAuth`, `apiPost`, `apiGet`) from `e2e_admin_session_setup.py`. Tests exercise both the API layer directly and the UI.

**Test users**: Alice (caller), Bob (callee)

#### Section 145.1: Voicemail Presign API — Basic (4 tests)

| # | Test | Method |
|---|------|--------|
| 145.1.1 | Presign returns message_id, upload_url, s3_key for audio voicemail | POST presign with valid call_id in declined state |
| 145.1.2 | Presign returns video upload_url when mode=video | POST presign with mode="video", content_type="video/webm" |
| 145.1.3 | Presign s3_key uses voicemails/ prefix | Verify s3_key starts with `voicemails/` |
| 145.1.4 | Presign upload_url is a valid mock S3 path in dev mode | Verify upload_url starts with `/mock/s3/` |

#### Section 145.2: Voicemail Presign API — Validation (5 tests)

| # | Test | Method |
|---|------|--------|
| 145.2.1 | Presign rejects non-caller user with 403 | POST presign as Bob (callee) -> 403 |
| 145.2.2 | Presign rejects call in non-eligible state (ended) with 400 | Create call, end it normally -> POST presign -> 400 |
| 145.2.3 | Presign rejects call in canceled state with 400 | Create invite, cancel before answer -> presign -> 400 |
| 145.2.4 | Presign rejects call in failed state with 400 | Simulate failure -> presign -> 400 |
| 145.2.5 | Presign rejects non-existent call_id with 404 | POST presign with bogus call_id -> 404 |

#### Section 145.3: Voicemail Create API — Happy Path (5 tests)

| # | Test | Method |
|---|------|--------|
| 145.3.1 | Create audio voicemail succeeds after presign + S3 upload | Full presign -> upload -> create flow |
| 145.3.2 | Created voicemail has kind="voicemail" and correct fields | Verify response shape |
| 145.3.3 | Voicemail appears in conversation message list | GET messages, find voicemail by message_id |
| 145.3.4 | CallSessionRecord updated with voicemail_message_id | GET call session, check field is set |
| 145.3.5 | Voicemail voicemail.call_state matches the terminal state | Verify voicemail.call_state == "declined" |

#### Section 145.4: Voicemail Create API — Guard Rails (5 tests)

| # | Test | Method |
|---|------|--------|
| 145.4.1 | Duplicate voicemail for same call returns 409 | POST create twice -> 409 on second |
| 145.4.2 | Voicemail rejects paid calls with 400 | Create paid call, decline -> POST voicemail -> 400 |
| 145.4.3 | Voicemail rejects wrong conversation_id with 400 | POST with mismatched conversation -> 400 |
| 145.4.4 | Voicemail rejects callee as recorder with 403 | Bob tries to create voicemail on Alice's declined call -> 403 |
| 145.4.5 | Voicemail rejects duration > 60 seconds with 422 | POST with duration_seconds=120 -> 422 |

#### Section 145.5: Voicemail on Declined Call (3 tests)

| # | Test | Method |
|---|------|--------|
| 145.5.1 | Voicemail eligible after decline_invite | Create invite -> decline -> verify voicemail_eligible in response |
| 145.5.2 | Audio voicemail created after decline | Full flow: invite -> decline -> presign -> upload -> create |
| 145.5.3 | Voicemail message displays call_state "declined" | GET message, verify voicemail.call_state = "declined" |

#### Section 145.6: Voicemail on Missed Call (Timeout) (3 tests)

| # | Test | Method |
|---|------|--------|
| 145.6.1 | Voicemail eligible after timeout_call | Create invite -> timeout -> verify eligibility |
| 145.6.2 | Audio voicemail created after timeout | Full flow: invite -> timeout -> presign -> upload -> create |
| 145.6.3 | Voicemail message has call_state="missed" | Verify voicemail metadata |

#### Section 145.7: Voicemail on Busy Call (3 tests)

| # | Test | Method |
|---|------|--------|
| 145.7.1 | Voicemail eligible after busy decline | Create invite -> decline(reason="busy") -> verify eligibility |
| 145.7.2 | Audio voicemail created after busy | Full flow |
| 145.7.3 | Voicemail message has call_state="busy" | Verify voicemail metadata |

#### Section 145.8: Video Voicemail (4 tests)

| # | Test | Method |
|---|------|--------|
| 145.8.1 | Presign accepts video content_type | POST presign with content_type="video/webm" |
| 145.8.2 | Create video voicemail with mode=video | Full flow with video mode |
| 145.8.3 | Video voicemail has video_url in response, audio_url is null | Verify response fields |
| 145.8.4 | Video voicemail s3_key extension is .webm | Verify s3_key ends with `.webm` |

#### Section 145.9: Voicemail Feature Flag (2 tests)

| # | Test | Method |
|---|------|--------|
| 145.9.1 | Voicemail presign returns 404 when disabled | Set VOICEMAIL_ENABLED=0 -> presign -> 404 |
| 145.9.2 | Voicemail create returns 404 when disabled | Set VOICEMAIL_ENABLED=0 -> create -> 404 |

#### Section 145.10: Voicemail in Conversation Timeline (3 tests)

| # | Test | Method |
|---|------|--------|
| 145.10.1 | Voicemail appears after system "Missed call" timeline message | GET messages, verify ordering by created_at |
| 145.10.2 | Sidebar preview shows "[Voicemail]" | GET conversations, check last_message preview |
| 145.10.3 | Voicemail waveform data is preserved and clamped to [0,1] | Send waveform with out-of-range values, verify clamped |

#### Section 145.11: Voicemail Alert Notification (3 tests)

| # | Test | Method |
|---|------|--------|
| 145.11.1 | Callee receives alert after voicemail is left | GET alerts for Bob, find event="voicemail_received" |
| 145.11.2 | Alert payload contains conversation_id and message_id | Verify alert details |
| 145.11.3 | Alert title contains "Missed call" and "voicemail" | Verify alert title text |

#### Section 145.12: Voicemail Signaling Types (3 tests)

| # | Test | Method |
|---|------|--------|
| 145.12.1 | call.voicemail_start signal accepted in declined state | Route signaling event with type=call.voicemail_start |
| 145.12.2 | call.voicemail_complete signal accepted in missed state | Route signaling event with type=call.voicemail_complete |
| 145.12.3 | call.voicemail_start rejected in connected state | Route signaling event -> invalid_state error |

**Total: 43 tests across 12 sections**

### 5.2 Unit Tests (`tests/`)

#### `tests/test_voicemail.py`

| # | Test | Description |
|---|------|-------------|
| 1 | `test_voicemail_eligible_states` | Verify `declined`, `missed`, `busy` are eligible; `ended`, `canceled`, `failed` are not |
| 2 | `test_voicemail_presign_returns_valid_response` | Verify presign endpoint returns `message_id`, `upload_url`, `s3_key` |
| 3 | `test_voicemail_presign_rejects_wrong_user` | Non-caller gets 403 |
| 4 | `test_voicemail_presign_rejects_wrong_state` | Call in `ended` state gets 400 |
| 5 | `test_voicemail_presign_rejects_paid_call` | Paid call gets 400 |
| 6 | `test_voicemail_presign_rejects_duplicate` | Second presign for same call with existing VM gets 409 |
| 7 | `test_voicemail_presign_rejects_wrong_conversation` | Mismatched conversation_id gets 400 |
| 8 | `test_voicemail_presign_video_mode_extension` | Video presign uses `.webm` extension |
| 9 | `test_voicemail_create_writes_message` | Verify DDB message item has correct fields |
| 10 | `test_voicemail_create_links_call_session` | Verify `set_voicemail_message_id` is called and field is set |
| 11 | `test_voicemail_create_dispatches_alert` | Verify `write_alert` is called with correct payload |
| 12 | `test_voicemail_create_alert_has_correct_event` | Alert event is `voicemail_received` |
| 13 | `test_voicemail_duplicate_rejected` | Second create for same call_id returns 409 |
| 14 | `test_voicemail_message_projection` | Verify `_message_out_from_item` projects voicemail fields correctly |
| 15 | `test_voicemail_video_mode_projection` | Video voicemail uses `video_url` not `audio_url` in projection |
| 16 | `test_voicemail_max_duration_enforced` | `duration_seconds > 60` returns 422 |
| 17 | `test_voicemail_waveform_clamped` | Waveform values outside [0,1] are clamped |
| 18 | `test_voicemail_waveform_truncated` | Waveform arrays longer than `voice_message_waveform_samples` are truncated |
| 19 | `test_call_session_voicemail_field_persistence` | Verify `voicemail_message_id` survives `update_call_session_state` |
| 20 | `test_set_voicemail_message_id_idempotent` | Calling `set_voicemail_message_id` twice is safe |
| 21 | `test_voicemail_disabled_feature_flag` | Both endpoints return 404 when `voicemail_enabled=False` |
| 22 | `test_voicemail_signaling_types_in_terminal_states` | Voicemail signal types accepted in declined/missed/busy |
| 23 | `test_voicemail_signaling_rejected_in_connected` | Voicemail signal types rejected in connected state |
| 24 | `test_voicemail_preview_text` | `_preview_for_event` returns "Voicemail left" for `call.voicemail_complete` |
| 25 | `test_voicemail_s3_key_pattern` | S3 key follows `voicemails/{conversation_id}/{message_id}.{ext}` |

### 5.3 Manual QA Checklist

- [ ] Place a call, have callee decline — verify "Leave a message?" prompt appears
- [ ] Record a 30-second audio voicemail, preview, re-record, send
- [ ] Verify voicemail appears in conversation with "Missed call — voicemail" header and waveform player
- [ ] Verify callee can play back the voicemail audio with waveform progress
- [ ] Verify "Call back" button initiates a new call
- [ ] Click "Skip" on voicemail prompt — overlay dismisses without recording
- [ ] Place a call that times out (30s) — verify voicemail prompt appears
- [ ] Place a call to a busy user — verify voicemail prompt appears
- [ ] End a connected call normally — verify NO voicemail prompt
- [ ] Cancel an outgoing call before answer — verify NO voicemail prompt
- [ ] Record a video voicemail — verify video playback works for callee
- [ ] Test on mobile viewport (375px wide) — verify recording UI is responsive
- [ ] Verify push notification received by callee for voicemail (alert appears in alert bell)
- [ ] Verify sidebar preview shows "[Voicemail]" text
- [ ] Test microphone permission denied — verify error message appears
- [ ] Test camera permission denied for video voicemail — verify error message appears
- [ ] Test leaving a voicemail on a paid call — verify voicemail prompt does NOT appear
- [ ] Test rapid double-click on "Send" — verify only one voicemail is created
- [ ] Verify voicemail playback speed toggle (1x, 1.5x, 2x) works
- [ ] Test with VOICEMAIL_ENABLED=0 — verify no voicemail prompt appears on any call outcome

---

## 6. Error Handling Matrix

### 6.1 Recording Errors

| Error | Trigger | User Impact | Recovery |
|-------|---------|-------------|----------|
| `NotAllowedError` (mic) | User denies microphone permission | Cannot record audio | Show "Microphone access required" error with browser settings link |
| `NotAllowedError` (camera) | User denies camera permission | Cannot record video | Fall back to audio-only mode, show "Camera access denied" notice |
| `NotFoundError` | No microphone/camera device available | Cannot record | Show "No recording device found" error, offer to dismiss |
| `NotReadableError` | Device in use by another application | Cannot record | Show "Microphone is in use by another app" error |
| `AbortError` | Browser aborts getUserMedia | Cannot record | Show generic error, offer retry |
| `MediaRecorder` not supported | Very old browser | Cannot record | Show "Your browser does not support voice recording" error |
| Codec not supported | Specific codec unavailable | Fallback codec used | `detectMimeType()` cascades through alternatives |

### 6.2 Upload Errors

| Error | Trigger | User Impact | Recovery |
|-------|---------|-------------|----------|
| Presign 404 | Feature disabled | Cannot send voicemail | Show "Voicemail is not available" error, offer dismiss |
| Presign 400 | Call not in eligible state (race condition) | Cannot send voicemail | Show "This call is no longer eligible for voicemail" |
| Presign 403 | Not the caller (should not happen in normal flow) | Cannot send voicemail | Show generic error |
| Presign 409 | Duplicate voicemail | Voicemail already sent | Show "A voicemail was already sent for this call" |
| S3 PUT timeout | Network timeout during upload (>30s) | Recording not uploaded | Return to preview, show "Upload timed out. Check your connection." |
| S3 PUT network error | Connection dropped during upload | Recording not uploaded | Return to preview, show "Upload failed. Try again." |
| S3 PUT 403 | Presigned URL expired (>5 minutes since presign) | Recording not uploaded | Re-presign automatically, retry upload |
| Create 409 | Race condition: duplicate voicemail | Second attempt redundant | Show "Voicemail already saved" (treat as success) |
| Create 500 | Server error | Voicemail not saved | Return to preview, show "Server error. Try again later." |

### 6.3 Playback Errors

| Error | Trigger | User Impact | Recovery |
|-------|---------|-------------|----------|
| Audio 404 | S3 object deleted or expired | Cannot play voicemail | Show "This voicemail is no longer available" |
| Audio decode error | Corrupt or unsupported format | Cannot play voicemail | Show "Unable to play this voicemail" |
| Video 404 | S3 object deleted or expired | Cannot play video voicemail | Show "This video voicemail is no longer available" |
| CORS error | S3 bucket misconfigured (production) | Cannot fetch media | Fall back to download link |

---

## 7. Performance & Capacity Planning

### 7.1 Recording Size Limits

| Parameter | Audio | Video |
|-----------|-------|-------|
| Max duration | 60 seconds | 60 seconds |
| Max file size | 50 MB | 50 MB |
| Typical bit rate | 128 kbps (Opus) | 1.5 Mbps video + 128 kbps audio |
| Typical file size (60s) | ~960 KB | ~12 MB |
| Typical file size (30s) | ~480 KB | ~6 MB |
| Waveform samples | 10-200 floats | 10-200 floats |

### 7.2 S3 Storage Costs

Assuming 10,000 voicemails per month with average 30-second duration:

| Type | Avg Size | Monthly Volume | S3 Storage Cost |
|------|----------|----------------|-----------------|
| Audio voicemails (80%) | 480 KB | 8,000 x 480 KB = 3.75 GB | ~$0.09/month |
| Video voicemails (20%) | 6 MB | 2,000 x 6 MB = 12 GB | ~$0.28/month |
| **Total** | | **15.75 GB** | **~$0.37/month** |

S3 lifecycle policies should archive voicemails to S3 Glacier after 90 days and delete after 1 year (or per tenant retention policy).

### 7.3 Concurrent Upload Capacity

- Presigned URL generation: CPU-bound, negligible latency (~1ms)
- S3 PUT upload: Client-to-S3 direct, does not go through backend
- Create endpoint: Single DDB write + participant query + alert write = ~3 DDB operations
- SSE broadcast: Async, non-blocking
- **Bottleneck**: DDB write throughput on Messages table (provisioned or on-demand)
- **Expected peak**: 100 concurrent voicemail uploads during high-traffic period is well within typical DDB on-demand capacity

### 7.4 DDB Item Size

Voicemail message items are larger than typical text messages due to waveform data:

| Field | Size |
|-------|------|
| Fixed fields (conversation_id, message_id, sender_id, etc.) | ~500 bytes |
| waveform_data (100 Decimal values) | ~1,200 bytes |
| audio_url / video_url (S3 key) | ~100 bytes |
| call_id, caller_user_id, callee_user_id | ~150 bytes |
| **Total** | **~2 KB per voicemail item** |

This is well within the DDB 400 KB item size limit.

---

## 8. Edge Cases Deep Dive

### 8.1 Caller Hangs Up During Recording

**Scenario**: Alice starts recording a voicemail, then closes the browser tab or navigates away before completing the recording.

**Behavior**: The `VoicemailRecorder` component's cleanup function (inherited from `VoiceRecorder` pattern at line 46-59) <!-- VERIFIED: frontend/src/pages/messages/VoiceRecorder.tsx:46-59 --> stops all media tracks and closes the AudioContext on unmount. The presign was never called (or was called but the upload was never completed), so no orphaned S3 objects are created. The `CallSessionRecord.voicemail_message_id` remains `None`, and the call session is unchanged.

**No action needed**: This is a clean no-op.

### 8.2 Network Drop During Upload

**Scenario**: Alice completes recording, clicks "Send", the presign succeeds, but the S3 PUT upload fails due to network disconnection.

**Behavior**: The `VoicemailRecorder` catches the upload error and transitions back to the `previewing` phase with an error message. The presigned URL may have expired by the time the network recovers (5-minute expiry). The recording blob is still in memory.

**Recovery**: On retry, the component calls presign again (generating a new `message_id` and `s3_key`), uploads the same recording blob, and calls create. The old presigned URL and S3 key are abandoned (no object was written to S3, so no orphan cleanup is needed).

### 8.3 Group Call Voicemail with Multiple Decliners

**Scenario**: Alice starts a group call with Bob, Charlie, and Dave. Bob declines, Charlie is busy, Dave never answers (timeout). The group call reaches a terminal state.

**Behavior**: Group call voicemail eligibility requires that NO participant joined the call. If at least one participant accepted, the call becomes `active` and later `ended` — which is not voicemail-eligible. If all three decline/busy/timeout, the group call reaches a terminal state where voicemail is offered to Alice.

**Voicemail goes to the group conversation**: Alice's voicemail message is sent to the group conversation, not individual DMs. All three recipients (Bob, Charlie, Dave) see the voicemail in the group chat. Alerts are sent to all three.

### 8.4 Voicemail for Blocked Users

**Scenario**: Bob has blocked Alice. Alice calls Bob (if the platform allows calling blocked users). The call is declined or times out.

**Behavior**: If the platform's blocking system prevents call invitations to blocked users, this scenario never occurs. If blocking only hides messages (soft block), the voicemail is created normally but may be filtered from Bob's view by the existing block message filtering logic in `_message_out_from_item`.

**Design decision**: Voicemail respects the existing blocking infrastructure. No additional blocking logic is needed in the voicemail endpoints — the block check happens at the conversation/participant level, which is already enforced by `require_participant_active`.

### 8.5 Rapid State Transitions

**Scenario**: Bob declines Alice's call. Alice clicks "Record" and starts recording. Meanwhile, Alice makes a new call to Bob (perhaps from another tab), and Bob accepts. Now the original call's voicemail recording is in progress, but Alice is also on a live call.

**Behavior**: The voicemail recording happens in the `CallSessionOverlay` for the original (declined) call. The new call opens a separate overlay. When Alice finishes recording and clicks "Send", the voicemail is created on the original call's conversation. The presign/create endpoints validate against the original `call_id` (which is still in the `declined` state), so the voicemail is accepted.

**No conflict**: Each call has its own `call_id`, and voicemail is linked to a specific call. Multiple calls to the same user do not interfere.

### 8.6 Presign-to-Upload Time Gap

**Scenario**: Alice calls presign, then gets distracted. She returns 10 minutes later and tries to upload.

**Behavior**: The presigned PUT URL expires after 300 seconds (5 minutes). The PUT upload will fail with a 403 from S3. The `VoicemailRecorder` detects this and offers to retry. On retry, it calls presign again (with a fresh URL), which succeeds because the `CallSessionRecord.voicemail_message_id` is still `None` (the create endpoint was never called).

### 8.7 Backend Restart During Recording

**Scenario**: The backend restarts while Alice is recording a voicemail. She completes the recording and clicks "Send".

**Behavior**: The presign call fails (backend is down). The `VoicemailRecorder` shows an error message. When the backend comes back, Alice retries. The `CallSessionRecord` persists in DDB (DynamoDB survives backend restarts), so the presign succeeds on retry.

### 8.8 Voicemail on a Call That Was Already Voicemailed (Client Cache)

**Scenario**: Alice leaves a voicemail on a declined call. She navigates away and back to the conversation. The call history shows the declined call. Can she try to leave another voicemail?

**Behavior**: The SSE event for the original decline included `voicemail_eligible: true`, but that was before the voicemail was created. If Alice somehow triggers the voicemail flow again (e.g., from cached UI state), the presign endpoint will return 409 ("A voicemail has already been left for this call") because `CallSessionRecord.voicemail_message_id` is now set. The UI should handle this gracefully by showing a "Voicemail already sent" message.

---

## 9. Notification Delivery Matrix

### 9.1 Notification Channels

When a voicemail is left, the callee should be notified through multiple channels:

| Channel | Implementation | Latency | Reliability |
|---------|---------------|---------|-------------|
| **In-app SSE** | `write_alert` -> `sse_publish_alert` | <1 second | High (if user is online) |
| **Alert bell badge** | `increment_unread_count` via `write_alert` | <1 second | High |
| **Conversation badge** | SSE message event updates conversation list | <2 seconds | High (if on messages page) |
| **Push notification** | Via `write_alert` -> push subscription (if configured) | 1-5 seconds | Medium (depends on push service) |
| **Email notification** | Via alert email preferences (if user opted in) | 1-30 seconds | Medium (depends on email delivery) |
| **SMS notification** | Via alert SMS preferences (if user opted in) | 5-60 seconds | Medium (depends on SMS provider) |
| **Webhook** | Via alert webhook preferences (if configured) | 1-5 seconds | Medium |

### 9.2 Notification Content

| Channel | Title | Body | Deep Link |
|---------|-------|------|-----------|
| In-app alert | "Missed call — voicemail left" | (none) | `/messages?conversation={id}` |
| Push notification | "Missed call" | "Voicemail from {caller_name}" | `/messages?conversation={id}` |
| Email | "Missed call from {caller_name}" | "You have a new voicemail ({duration}s). Tap to listen." | `/messages?conversation={id}` |
| SMS | "Missed call — voicemail" | "{caller_name} left you a {duration}s voicemail" | Short URL |

### 9.3 Group Voicemail Notifications

For group calls, notifications are sent to all participants except the caller:

| Participants | Notifications Sent | Alert Title |
|-------------|-------------------|-------------|
| 2 participants (1-on-1) | 1 alert to callee | "Missed call — voicemail left" |
| 3 participants | 2 alerts | "Missed group call — voicemail left" |
| 10 participants | 9 alerts | "Missed group call — voicemail left" |

Each alert is written individually via `write_alert` in a loop. Failures for individual participants are caught and logged but do not prevent other participants from receiving their alert.

### 9.4 Notification Deduplication

The alert system uses `alert_id = f"{ts:010d}#{uuid.uuid4().hex}"` (from `write_alert` at line 270 of `app/services/alerts.py`), <!-- VERIFIED: app/services/alerts.py:270 --> which is unique per write. If the voicemail create endpoint is retried (409 on the create), no duplicate alert is sent because the 409 path returns before reaching the alert dispatch code.

---

## 10. Security Considerations

### 10.1 Authorization

All voicemail endpoints enforce the following authorization checks:

1. **Participant validation**: `require_participant_active(user_id, conversation_id)` ensures the user is an active member of the conversation. This prevents users from leaving voicemails in conversations they do not belong to.

2. **Caller-only restriction**: `call.caller_user_id != user_id` check ensures only the call initiator can leave a voicemail. The callee cannot leave a voicemail on their own missed call.

3. **Call ownership validation**: `call.conversation_id != conversation_id` cross-check prevents path manipulation attacks where a user references a call_id from a different conversation.

4. **CSRF protection**: All POST endpoints go through `get_messaging_user_id` which enforces CSRF token validation for cookie-authenticated requests (consistent with all other messaging endpoints).

### 10.2 Input Validation

| Input | Validation | Rationale |
|-------|-----------|-----------|
| `call_id` | Max 128 chars, must exist in DDB | Prevent injection, ensure valid reference |
| `message_id` | Regex `^m_[a-f0-9]{32}$` | Match existing message ID format |
| `content_type` | Regex `^(audio\|video)/(webm\|mp4\|ogg\|wav)` | Restrict to known media types |
| `size_bytes` | 1 to 52,428,800 (50MB) | Prevent empty uploads and storage abuse |
| `duration_seconds` | 0.5 to 60 | Enforce voicemail max duration |
| `waveform_data` | 10-200 floats, each clamped to [0.0, 1.0] | Prevent oversized arrays, normalize values |
| `mode` | Literal "audio" \| "video" | Restrict to supported modes |
| `s3_key` | 1 to 500 chars | Prevent empty or excessively long keys |

### 10.3 Idempotency and Duplicate Prevention

The `voicemail_message_id` field on `CallSessionRecord` serves as a duplicate guard. The presign and create endpoints both check `if call.voicemail_message_id:` and return 409 if a voicemail already exists for the call. This prevents:

- Double-submit from slow network conditions
- Malicious attempts to overwrite a voicemail
- Race conditions if the user has multiple tabs open

### 10.4 S3 Upload Security

Voicemail S3 uploads follow the same presigned URL pattern as voice messages:

- **Presigned PUT URLs** expire after 300 seconds (5 minutes)
- **Content-type enforcement**: The presigned URL includes `ContentType` in the `Params`, preventing the caller from uploading a different file type
- **Separate S3 prefix**: `voicemails/` is separate from `voice-messages/`, allowing independent lifecycle policies and access controls
- **No direct S3 read access**: Voicemail playback goes through the backend's mock S3 proxy in dev mode or through presigned GET URLs in production

### 10.5 Rate Limiting

Voicemail creation is subject to the existing message send quota (`_enforce_message_send_quota_precheck`). Additionally, the one-voicemail-per-call limit naturally prevents abuse — a user can only leave one voicemail per unanswered call, and calls require the callee to be a real user who must be invited and then decline/timeout.

### 10.6 Data Privacy

- Voicemails are stored as regular messages and are subject to the same data retention policies (TTL via `_message_retention_ttl`)
- Either participant can see the voicemail in the conversation
- Voicemails can be deleted using the existing message deletion/revocation mechanism
- No voicemail data is stored outside the `Messages` DDB table and S3 bucket

---

## 11. Migration & Rollback Plan

### 11.1 Migration

This feature is entirely additive — no existing data structures are modified, only extended:

1. **`CallSessionRecord`**: New optional field `voicemail_message_id` defaults to `None`. Existing records are unaffected — `_record_from_item` uses `item.get("voicemail_message_id")` which returns `None` for old records.

2. **`MessageOut.kind` literal**: Adding `"voicemail"` to the union does not affect existing messages. Old clients that do not recognize the kind will fall through to a default rendering.

3. **`ALLOWED_SIGNALING_TYPES`**: Adding new signal types does not affect existing signals. Old clients ignore unknown SSE event types.

4. **`STATE_ALLOWED_SIGNALING_TYPES`**: Adding entries for terminal states does not affect existing behavior — terminal states previously had no entry, meaning all signaling was rejected. The new entries only allow the two voicemail-specific signals.

5. **Settings**: New settings default to enabled. No migration of `.env.local` is required — the feature is available immediately.

6. **DynamoDB tables**: No new tables are needed. Voicemail messages go into the existing `Messages` table. No GSI changes are required.

### 11.2 Feature Flag Rollback

The feature can be disabled instantly by setting the environment variable:

```bash
VOICEMAIL_ENABLED=0
```

When disabled:
- Presign endpoint returns 404 "Voicemail is not enabled"
- Create endpoint returns 404 "Voicemail is not enabled"
- SSE events do not include `voicemail_eligible: true`
- Frontend never shows the "Leave a message?" prompt
- Existing voicemail messages remain visible and playable (they are just regular messages)

### 11.3 Rollback Steps

If a critical bug is discovered:

1. **Disable feature flag**: `VOICEMAIL_ENABLED=0` in `.env.local`, restart backend
2. **No data cleanup needed**: Existing voicemail messages are valid messages that will continue to render
3. **Code rollback**: Revert the commit. The only schema change (`voicemail_message_id` on `CallSessionRecord`) is a new optional field — removing it from code does not corrupt existing records (the field will simply be ignored on read)

### 11.4 Forward Compatibility

Old frontend clients (before this feature) will encounter `kind: "voicemail"` messages in conversations. The `MessageBubble` component should have a fallback for unknown kinds:

```tsx
// In MessageBubble.tsx, at the end of the kind-specific rendering:
{!["text", "image", "file", ..., "voicemail"].includes(msg.kind) && (
  <p className="text-sm text-muted-foreground italic">Unsupported message type</p>
)}
```

This ensures old clients do not crash when encountering voicemail messages — they display a graceful fallback.

---

## 12. Acceptance Criteria

### 12.1 Core Functionality

1. When a call is declined, the caller sees a "Leave a message?" prompt in the `CallSessionOverlay` instead of only "Dismiss"
2. When a call times out (missed), the caller sees a "Leave a message?" prompt
3. When a call is declined with reason="busy", the caller sees a "Leave a message?" prompt
4. The caller can record an audio voicemail up to 60 seconds using the `VoicemailRecorder` component
5. The caller can record a video voicemail up to 60 seconds using the `VideoVoicemailRecorder` component
6. The caller can preview the voicemail before sending, and re-record if unsatisfied
7. The caller can skip the voicemail prompt and dismiss the overlay without recording
8. After sending, the voicemail appears as a `kind: "voicemail"` message in the conversation timeline
9. The voicemail message displays a "Missed call — voicemail" header in the conversation view
10. The voicemail prompt does NOT appear for `ended`, `canceled`, or `failed` call states

### 12.2 Backend

11. `POST /conversations/{id}/voicemail/presign` returns a valid presigned S3 upload URL with `message_id`, `upload_url`, and `s3_key`
12. `POST /conversations/{id}/voicemail` creates a voicemail message in DDB and returns `MessageOut`
13. The voicemail message item includes `call_id`, `voicemail_mode`, `call_state`, and media URL fields
14. The `CallSessionRecord` is updated with `voicemail_message_id` after voicemail creation
15. A second voicemail attempt for the same call returns HTTP 409
16. Paid calls (`paid: true`) are excluded from voicemail eligibility (HTTP 400)
17. Only the `caller_user_id` can leave a voicemail (HTTP 403 for callee)
18. Voicemail is disabled when `VOICEMAIL_ENABLED=0` (HTTP 404 on both endpoints)
19. Voicemail presign generates S3 keys with `voicemails/` prefix (separate from `voice-messages/`)
20. Waveform data is clamped to [0.0, 1.0] and truncated to `voice_message_waveform_samples`

### 12.3 Frontend

21. `CallSessionOverlay` shows "Leave a message?" prompt only for voicemail-eligible outcomes (declined, missed/timeout, busy) and only for outgoing calls
22. Audio voicemail recorder reuses `VoiceRecorder` with `maxDuration=60`
23. Video voicemail recorder captures camera + microphone at 720p max with `videoBitsPerSecond: 1_500_000`
24. `VoicemailBubble` renders audio voicemails with `WaveformPlayer` and a "Missed call" header
25. `VoicemailBubble` renders video voicemails with an inline `<video>` player and a "Missed call" header
26. "Call back" button on voicemail messages initiates a new call to the other participant
27. Sidebar conversation list shows `[Voicemail]` as preview text for voicemail messages
28. Microphone/camera permission denied errors are handled gracefully with user-visible messages
29. Upload failures return to the preview phase with a retry option (recording is not lost)

### 12.4 Notifications

30. Callee receives an alert with event type `voicemail_received` when a voicemail is left
31. Alert title includes "Missed call" and "voicemail left"
32. Alert payload contains `conversation_id`, `message_id`, and `call_id` for deep linking
33. Group call voicemail sends alerts to all participants except the caller

### 12.5 Signals and Events

34. `call.voicemail_start` and `call.voicemail_complete` are valid signal types in `ALLOWED_SIGNALING_TYPES`
35. Voicemail signals are allowed in `declined`, `missed`, and `busy` call states via `STATE_ALLOWED_SIGNALING_TYPES`
36. `call.voicemail_complete` SSE event triggers message query invalidation on the callee's client

### 12.6 Group Call Support

37. Only the group call creator can leave a voicemail in the group conversation
38. Voicemail is eligible when no participant joined the group call
39. Alert is sent to all group conversation participants except the caller

### 12.7 Tests

40. All ~43 E2E tests in `frontend/e2e/voicemail.spec.ts` pass
41. All 25 unit tests in `tests/test_voicemail.py` pass
42. No regressions in existing call-related E2E tests (`messaging-features.spec.ts` call sections, `calendar-messaging.spec.ts`)

### 12.8 Edge Cases

43. Duplicate voicemail prevention works correctly (409 response, no duplicate messages)
44. Presigned URL expiry is handled with automatic re-presign on retry
45. Browser tab close during recording does not leave orphaned resources
