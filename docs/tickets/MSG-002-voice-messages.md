# MSG-002: Voice Messages

**Ticket**: MSG-002
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: Medium-High
**Estimated effort**: 8-10 days

---

## 1. Executive Summary

Voice messages are a foundational engagement feature missing from the messaging system. While the platform supports text, images, videos, audio files, file shares, calendar shares, gallery messages, and encrypted messages, there is no purpose-built voice message workflow. Users who want to send a quick verbal response must record audio externally, save it as a file, and attach it via the generic file picker -- a multi-step workflow that discourages casual voice communication.

This feature adds a one-tap record-and-send voice message experience directly in the ComposeBar, with a custom waveform visualization in message bubbles. The implementation leverages the existing S3 presign upload pattern used by image messages, extends the Messages DynamoDB table with a new `kind="voice_message"` type, and builds two new frontend components: `VoiceRecorder` (MediaRecorder integration with live amplitude visualization) and `WaveformPlayer` (playback with progressive waveform highlighting). The feature supports all existing message capabilities including listen-once consumption policy, scheduled send, replies, and group conversations.

Voice messages are a core engagement feature in modern messaging platforms (WhatsApp, Telegram, iMessage). They enable faster, more personal communication than typing, particularly on mobile devices, and drive longer session times. Implementation is intentionally lightweight: waveform data is computed client-side during recording, stored as metadata, and rendered without any server-side audio processing. The audio is encoded as Opus/WebM (Chrome/Firefox) or AAC/MP4 (Safari) and streamed directly from S3.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Sender | I want to hold a button to record a voice message and release to stop. | Recording starts on press, stops on release; preview appears. |
| Sender | I want to preview my recording before sending. | Playback controls shown after recording; can re-record or send. |
| Sender | I want to cancel a recording by swiping left (mobile) or pressing Escape (desktop). | Recording discarded; compose area returns to normal. |
| Recipient | I want to see a waveform and play button for voice messages in the chat. | Message bubble shows waveform bars, play/pause button, duration label. |
| Recipient | I want to see the playback progress as the message plays. | Waveform bars highlight progressively as audio plays. |
| Sender | I want to send a voice message with view-once / listen-once policy. | `consumption_policy: "listen_once"` supported; recipient hears once. |
| Sender | I want to send a scheduled voice message. | Voice message with `send_at` appears in scheduled queue, delivers at the specified time. |
| Sender | I want to reply to a specific message with a voice message. | `reply_to_message_id` links voice message to the original. |
| User | I want playback speed control for long voice messages. | Toggle between 1x, 1.5x, and 2x playback speed. |

### 2.2 Pain Points with Current Workflow

1. **Multi-step recording**: Users must open an external recording app, save the file, return to the platform, click Paperclip, navigate to the file, and attach it. This takes 6+ taps vs. 1-2 for a voice message button.
2. **No waveform preview**: Generic audio file attachments render as a plain `<audio>` element with browser-default controls. There is no visual indicator of message length or content.
3. **No duration metadata**: The existing `audio` message kind does not store duration, so recipients cannot see how long a message is before playing.
4. **No listen-once for voice**: While the `audio` kind supports generic consumption policies, there is no voice-specific listen-once UX with "Already listened" indicators.

### 2.3 Competitive Analysis

| Platform | Voice Message UX | Waveform | Playback Speed | Duration | Listen-Once |
|----------|-----------------|----------|----------------|----------|-------------|
| WhatsApp | Hold to record | Yes (live + playback) | 1x, 1.5x, 2x | Yes | Yes ("View Once") |
| Telegram | Hold to record; lock for hands-free | Yes (playback) | 2x | Yes | Yes (self-destruct) |
| iMessage | Hold to record | Waveform in bubble | No | Yes | No |
| Signal | Hold to record; lock supported | Yes | 1x only | Yes | Yes (disappearing) |
| **This platform** | **Not available** | **No** | **No** | **No** | **Partial (audio kind)** |

---

## 3. Current State Analysis

### 3.1 Messaging Architecture

Messages are stored in the `Messages` DynamoDB table with `PK=conversation_id`, `SK=message_id`. The `kind` field distinguishes message types: `text`, `image`, `video`, `audio`, `file`, `file_share`, `calendar_share`, `calendar_event`, `meeting_poll`, `gallery`, `video_share`. <!-- VERIFIED: kind Literal in messaging.py:2291 -->

The existing `audio` kind is used for generic audio file attachments (uploaded via the Paperclip button). Voice messages will use a new `kind="voice_message"` to differentiate them in rendering (waveform vs. generic audio player). <!-- NOTE: "voice_message" must be added to the kind Literal in messaging.py:2291 -->

### 3.2 ComposeBar (frontend/src/pages/messages/ComposeBar.tsx) <!-- VERIFIED: file exists -->

The ComposeBar already has:
- `onSendAudioRecording` callback prop for audio files
- `Headphones` icon import from lucide-react
- `listenOnceAudio` state for listen-once consumption policy
- `pendingFile` state with `kind: "audio"` branch
- File input accepting `audio/*`
<!-- NOTE: Claims about specific ComposeBar props/state should be verified against the current source -->

The voice message feature adds a dedicated record button alongside the existing Paperclip (file attach) button, using the `MediaRecorder` API for in-browser recording instead of file selection.

### 3.3 MessageBubble (frontend/src/pages/messages/MessageBubble.tsx)

The MessageBubble component renders different layouts based on `msg.kind`. Currently `kind="audio"` renders a basic `<audio>` element. Voice messages will render a custom waveform visualization component.

### 3.4 S3 Upload Pattern

Image messages use a two-step flow: (1) presign upload URL via `presign_image_upload` at `messaging.py:7797`, (2) PUT blob directly to S3. Audio voice messages will follow the same pattern. The existing `create_image_message` endpoint at `messaging.py:7816` (presign + metadata write) serves as the template. <!-- VERIFIED: presign_image_upload at line 7797, create_image_message at line 7816 -->

### 3.5 Gaps

1. No `MediaRecorder` integration in ComposeBar
2. No `kind="voice_message"` message type in backend
3. No waveform computation or storage
4. No waveform visualization component in MessageBubble
5. No duration metadata field on audio messages

---

## 4. Technical Architecture

### 4.1 System Diagram

```
+------------------+      +-------------------+      +------------------+
|   ComposeBar     |      |    Backend API    |      |    DynamoDB      |
|                  |      |  (messaging.py)   |      |  Messages table  |
| [Mic Button]     |      |                   |      |                  |
|   |              |      |  POST /voice-     |      | PK: conv_id      |
|   v              |      |  message/presign  |      | SK: message_id   |
| VoiceRecorder    |----->|   -> S3 presign   |      | kind: voice_msg  |
|  (MediaRecorder) |      |                   |      | waveform_data[]  |
|  (AnalyserNode)  |      |  POST /voice-     |      | duration_seconds |
|   |              |      |  message          |      | audio_url        |
|   | blob + meta  |----->|   -> DDB put_item |----->|                  |
|   v              |      |   -> SSE emit     |      +------------------+
| Upload to S3     |      |                   |
| (PUT presigned)  |      +-------------------+      +------------------+
+------------------+              |                   |   S3 Bucket      |
                                  |                   | voice-messages/  |
+------------------+              |                   |  {conv_id}/      |
| MessageBubble    |              |                   |   {msg_id}.webm  |
|                  |              v                   +------------------+
| WaveformPlayer   |<---- SSE message:new event
|  (AudioContext)  |
|  [||||||||||||]  |----> GET audio from S3
|  Play/Pause btn  |      (presigned or /mock/s3 URL)
|  Duration label  |
|  Speed toggle    |
+------------------+
```

### 4.2 Data Flow

1. User presses Mic button in ComposeBar
2. `navigator.mediaDevices.getUserMedia({ audio: true })` requests mic permission
3. `MediaRecorder` starts with `mimeType: "audio/webm;codecs=opus"` (or `audio/mp4` on Safari)
4. `AnalyserNode` samples amplitude at 10Hz, building `waveform_data[]`
5. User releases button (or taps again) -- recording stops
6. Preview appears with playback controls
7. User clicks Send:
   a. POST `/voice-message/presign` to get S3 upload URL + message_id
   b. PUT audio blob to S3 via presigned URL
   c. POST `/voice-message` with metadata (s3_key, duration, waveform, etc.)
   d. Backend writes to DynamoDB Messages table
   e. Backend emits SSE `message:new` event to all participants
   f. SSE event triggers React Query invalidation on recipient's ConversationView

---

## 5. Data Model Deep Dive

### 5.1 Message Record (DynamoDB `Messages` table)

The Messages table uses `PK=conversation_id`, `SK=message_id` (format: `m_<uuid4_hex>`). Voice messages add these fields to the existing message schema:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `kind` | S | `"voice_message"` | `"voice_message"` |
| `audio_url` | S | S3 key for the recorded audio file | `"voice-messages/conv_abc123/m_def456.webm"` |
| `audio_content_type` | S | MIME type | `"audio/webm"` or `"audio/mp4"` |
| `audio_size_bytes` | N | File size in bytes | `245760` |
| `duration_seconds` | N | Recording duration (Decimal, max 300) | `12.5` |
| `waveform_data` | L | Normalized amplitude samples (0.0-1.0), 50-100 values | `[0.1, 0.3, 0.8, ...]` |
| `consumption_policy` | S | `"none"` or `"listen_once"` | `"none"` |
| `reply_to_message_id` | S (optional) | Parent message for replies | `"m_aaa111bbb222"` |
| `scheduled` | BOOL (optional) | True if scheduled send | `true` |
| `deliver_at` | N (optional) | Unix timestamp for delivery | `1748380800` |

**Example DynamoDB item:**

```json
{
  "conversation_id": "conv_abc123def456",
  "message_id": "m_1a2b3c4d5e6f7890abcdef1234567890",
  "sender_id": "e2e_alice@test.local",
  "kind": "voice_message",
  "text": null,
  "audio_url": "voice-messages/conv_abc123def456/m_1a2b3c4d5e6f7890abcdef1234567890.webm",
  "audio_content_type": "audio/webm",
  "audio_size_bytes": 245760,
  "duration_seconds": 12.5,
  "waveform_data": [0.05, 0.12, 0.34, 0.67, 0.89, 0.92, 0.78, 0.45, 0.23, 0.11],
  "consumption_policy": "none",
  "created_at": 1748380800,
  "reply_to_message_id": null
}
```

### 5.2 Access Patterns

| Access Pattern | Table/Index | Key Condition | Filter |
|---------------|-------------|---------------|--------|
| Get messages in conversation | Messages (PK) | `conversation_id = X` | None |
| Get single voice message | Messages (PK+SK) | `conversation_id = X AND message_id = Y` | `kind = "voice_message"` |
| List scheduled voice messages | Messages (PK) + filter | `conversation_id = X` | `scheduled = true AND kind = "voice_message"` |
| Messages by created_at | GSI `ByConversationCreatedAt` | `conversation_id = X` | Sort by `created_at` desc |

### 5.3 Frontend Types

```typescript
// frontend/src/api/types.ts
interface VoiceMessageMeta {
  audio_url: string;
  audio_content_type: string;
  audio_size_bytes: number;
  duration_seconds: number;
  waveform_data: number[];  // normalized 0-1, ~50-100 samples
}

// Extended on Message interface:
interface Message {
  // ... existing fields ...
  kind: "text" | "image" | "video" | "audio" | "voice_message" | /* ... */;
  audio_url?: string;
  audio_content_type?: string;
  audio_size_bytes?: number;
  duration_seconds?: number;
  waveform_data?: number[];
  listen_once_consumed?: boolean;
}
```

---

## 6. API Contract Design

### 6.1 Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/messaging/conversations/{id}/voice-message/presign` | `require_ui_session` | Get presigned S3 upload URL for voice recording |
| POST | `/ui/messaging/conversations/{id}/voice-message` | `require_ui_session` | Create voice message after upload (with waveform metadata) |

### 6.2 POST `/ui/messaging/conversations/{id}/voice-message/presign`

**Request:**

```json
{
  "content_type": "audio/webm",
  "size_bytes": 245760,
  "duration_seconds": 12.5
}
```

**Validation:**
- `content_type`: Must match `^audio/(webm|mp4|ogg|wav)`
- `size_bytes`: `ge=1, le=52_428_800` (50MB max)
- `duration_seconds`: `ge=0.5, le=300` (0.5s to 5 minutes)

**Response (200):**

```json
{
  "message_id": "m_1a2b3c4d5e6f7890abcdef1234567890",
  "upload_url": "https://s3.amazonaws.com/uploads/voice-messages/...?X-Amz-Signature=...",
  "s3_key": "voice-messages/conv_abc123/m_1a2b3c4d5e6f7890abcdef1234567890.webm"
}
```

**Error responses:**
- `403`: User is not a participant in the conversation
- `422`: Validation error (duration over 300s, invalid content type, etc.)

### 6.3 POST `/ui/messaging/conversations/{id}/voice-message`

**Request:**

```json
{
  "message_id": "m_1a2b3c4d5e6f7890abcdef1234567890",
  "s3_key": "voice-messages/conv_abc123/m_1a2b3c4d5e6f7890abcdef1234567890.webm",
  "content_type": "audio/webm",
  "size_bytes": 245760,
  "duration_seconds": 12.5,
  "waveform_data": [0.05, 0.12, 0.34, 0.67, 0.89, 0.92, 0.78, 0.45, 0.23, 0.11],
  "consumption_policy": "none",
  "reply_to_message_id": null,
  "send_at": null
}
```

**Validation:**
- `message_id`: Must match `^m_[a-f0-9]{32}$`
- `waveform_data`: `min_length=10, max_length=200`, values clamped to 0.0-1.0
- `consumption_policy`: `"none"` or `"listen_once"`
- `send_at`: If provided, must be >= now + 5 seconds

**Response (200):**

```json
{
  "conversation_id": "conv_abc123def456",
  "message_id": "m_1a2b3c4d5e6f7890abcdef1234567890",
  "sender_id": "e2e_alice@test.local",
  "kind": "voice_message",
  "text": null,
  "audio_url": "/mock/s3/uploads/voice-messages/conv_abc123/m_1a2b...webm",
  "audio_content_type": "audio/webm",
  "audio_size_bytes": 245760,
  "duration_seconds": 12.5,
  "waveform_data": [0.05, 0.12, 0.34, 0.67, 0.89, 0.92, 0.78, 0.45, 0.23, 0.11],
  "consumption_policy": "none",
  "created_at": 1748380800,
  "scheduled": false
}
```

**Error responses:**
- `400`: `send_at` is in the past or less than 5 seconds in the future
- `403`: User is not a participant in the conversation
- `422`: Validation error (empty waveform, invalid message_id format)

### 6.4 Rate Limits

Both endpoints inherit the `messaging` rate limit group:
- Per-user: 120 requests / 60 seconds
- Per-IP: 200 requests / 60 seconds
- Bypassed by root and admin roles

---

## 7. Backend Implementation

### 7.1 Presign Endpoint

```python
class PresignVoiceMessageRequest(BaseModel):
    content_type: str = Field(pattern=r"^audio/(webm|mp4|ogg|wav)")
    size_bytes: int = Field(ge=1, le=52_428_800)  # 50MB max
    duration_seconds: float = Field(ge=0.5, le=300)  # 0.5s to 5 minutes

@router.post("/conversations/{conversation_id}/voice-message/presign")
def presign_voice_message(
    conversation_id: str,
    body: PresignVoiceMessageRequest,
    ctx=Depends(require_ui_session),
):
    user_id = ctx["user_sub"]
    require_participant_active(conversation_id, user_id)  # <!-- CORRECTED: was _require_participant, actually require_participant_active (messaging.py:4188) -->

    msg_id = f"m_{uuid.uuid4().hex}"
    s3_key = f"voice-messages/{conversation_id}/{msg_id}.webm"

    presigned = s3.generate_presigned_url(
        ClientMethod="put_object",
        Params={
            "Bucket": S3_BUCKET_IMAGES,  # <!-- CORRECTED: was UPLOAD_BUCKET, actually S3_BUCKET_IMAGES (messaging.py:207) -->
            "Key": s3_key,
            "ContentType": body.content_type,
        },
        ExpiresIn=300,
    )
    return {
        "message_id": msg_id,
        "upload_url": presigned,
        "s3_key": s3_key,
    }
```

### 7.2 Create Voice Message

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
    send_at: Optional[int] = None  # scheduled send support

@router.post("/conversations/{conversation_id}/voice-message")
def create_voice_message(
    conversation_id: str,
    body: CreateVoiceMessageRequest,
    ctx=Depends(require_ui_session),
):
    user_id = ctx["user_sub"]
    require_participant_active(conversation_id, user_id)  # <!-- CORRECTED: was _require_participant, actually require_participant_active (messaging.py:4188) -->
    now = now_ts()

    # Normalize waveform to 0-1 range, cap at 100 samples
    waveform = [max(0.0, min(1.0, float(v))) for v in body.waveform_data[:100]]

    item = {
        "conversation_id": conversation_id,
        "message_id": body.message_id,
        "sender_id": user_id,
        "kind": "voice_message",
        "text": None,
        "audio_url": body.s3_key,
        "audio_content_type": body.content_type,
        "audio_size_bytes": body.size_bytes,
        "duration_seconds": Decimal(str(body.duration_seconds)),
        "waveform_data": waveform,
        "consumption_policy": body.consumption_policy,
        "created_at": now,
        "reply_to_message_id": body.reply_to_message_id,
    }

    # Scheduled send support (same pattern as text messages)
    if body.send_at:
        if body.send_at < now + 5:
            raise HTTPException(status_code=400, detail="send_at must be at least 5 seconds in the future")
        item["scheduled"] = True
        item["deliver_at"] = body.send_at

    T.messages.put_item(Item=item)
    # <!-- CORRECTED: _update_conversation_last_message does not exist as a named function.
    #    The pattern is an inline tbl_convos.update_item with SET last_message_at, last_message_preview, last_message_id
    #    (see messaging.py:4751, 8301, 8424 etc.) -->
    tbl_convos.update_item(
        Key={"conversation_id": conversation_id},
        UpdateExpression="SET last_message_at = :ts, last_message_preview = :p, last_message_id = :mid",
        ExpressionAttributeValues={":ts": now, ":p": "[Voice message]", ":mid": body.message_id},
    )
    # <!-- CORRECTED: _emit_sse_event does not exist. SSE is done via _sse_pack (messaging.py:4812).
    #    Actual pattern: build SSE payload and push to per-connection queues. -->
    return _message_out_from_item(item, user_id)  # <!-- CORRECTED: was _message_out_from_item(item), actually requires (item, viewer_user_id) (messaging.py:3725) -->
```

### 7.3 `_message_out_from_item` Extension

Add `voice_message` to the kind-specific field extraction in the existing `_message_out_from_item` function:

```python
if item.get("kind") == "voice_message":
    out["audio_url"] = _resolve_media_url(item.get("audio_url", ""))
    out["audio_content_type"] = item.get("audio_content_type")
    out["audio_size_bytes"] = int(item.get("audio_size_bytes", 0))
    out["duration_seconds"] = float(item.get("duration_seconds", 0))
    out["waveform_data"] = item.get("waveform_data", [])
    out["consumption_policy"] = item.get("consumption_policy", "none")
```

<!-- CORRECTED: _resolve_media_url does not exist in messaging.py. The actual pattern for URL resolution in dev mode
is inline within _message_out_from_item: it checks S.dev_mode and constructs /mock/s3/{bucket}/{key} URLs
(see messaging.py lines ~9357-9368 for image/file URL resolution). -->

---

## 8. Frontend Component Design

### 8.1 Component Tree

```
ComposeBar
  |-- [Existing: textarea, file inputs, send button]
  |-- MicButton (new)
  |     |-- onPointerDown -> startRecording()
  |     |-- onPointerUp -> stopRecording()
  |-- VoiceRecorder (new, replaces textarea area during recording)
  |     |-- LiveWaveform (canvas showing real-time amplitude)
  |     |-- Timer (elapsed time display)
  |     |-- CancelButton (Escape / swipe-left)
  |     |-- PreviewMode (after recording stops)
  |           |-- PlaybackControls
  |           |-- Re-record button
  |           |-- Send button

MessageBubble
  |-- [Existing: text, image, video, etc. branches]
  |-- WaveformPlayer (new, for kind="voice_message")
        |-- PlayPauseButton (circle button, left side)
        |-- WaveformBars (SVG bars, heights from waveform_data)
        |-- ProgressOverlay (colored bars for played portion)
        |-- DurationLabel (right side, shows remaining time)
        |-- SpeedToggle (1x / 1.5x / 2x)
        |-- ListenOnceOverlay (if consumed, shows "Already listened")
```

### 8.2 New Files

| File | Purpose |
|------|---------|
| `frontend/src/pages/messages/VoiceRecorder.tsx` | MediaRecorder integration, waveform computation, record/preview UI |
| `frontend/src/pages/messages/WaveformPlayer.tsx` | Waveform visualization with playback progress in MessageBubble |
| `frontend/src/lib/audioWaveform.ts` | Web Audio API helpers: compute waveform from AudioBuffer |

### 8.3 VoiceRecorder Component

```tsx
interface VoiceRecorderProps {
  onComplete: (blob: Blob, meta: { duration: number; waveform: number[]; contentType: string }) => void;
  onCancel: () => void;
  maxDuration?: number;  // default 300s
}
```

Implementation details:
- Uses `navigator.mediaDevices.getUserMedia({ audio: true })` for mic access
- `MediaRecorder` with `mimeType: "audio/webm;codecs=opus"` (fallback to `audio/mp4` on Safari)
- `AnalyserNode` connected to the mic stream samples amplitude at 10Hz during recording
- Amplitude values normalized to 0-1 and downsampled to ~50-100 values for `waveform_data`
- Recording auto-stops at `maxDuration` seconds
- Cancel via Escape key or swipe-left gesture (mobile)

### 8.4 WaveformPlayer Component

```tsx
interface WaveformPlayerProps {
  audioUrl: string;
  waveform: number[];      // normalized 0-1
  durationSeconds: number;
  consumed?: boolean;       // listen-once already played
}
```

Visual design:
- Horizontal bar of vertical lines whose height represents amplitude
- Lines are gray (unplayed) or primary color (played) based on playback progress
- Play/pause circle button on the left
- Duration label on the right (shows remaining time during playback)
- Playback speed button (1x, 1.5x, 2x) for long voice messages

### 8.5 ComposeBar Integration

Add a microphone button next to the existing Paperclip button:

```tsx
<Button
  variant="ghost"
  size="icon"
  className="h-9 w-9 shrink-0"
  onPointerDown={() => startRecording()}
  onPointerUp={() => stopRecording()}
  disabled={disabled || sending || encrypting || !!pendingFile || galleryMode}
  aria-label="Record voice message"
>
  <Mic className="h-4 w-4" />
</Button>
```

When recording is active, the textarea and other buttons are replaced by the `VoiceRecorder` component showing a live waveform and elapsed time.

### 8.6 MessageBubble Integration

In `MessageBubble.tsx`, add a branch for `kind === "voice_message"`:

```tsx
{msg.kind === "voice_message" && msg.audio_url && (
  <WaveformPlayer
    audioUrl={resolveAudioUrl(msg.audio_url)}
    waveform={msg.waveform_data ?? []}
    durationSeconds={msg.duration_seconds ?? 0}
    consumed={msg.listen_once_consumed}
  />
)}
```

### 8.7 React Query Hooks

```typescript
// frontend/src/api/endpoints/messaging.ts
export function presignVoiceMessage(conversationId: string, body: PresignVoiceReq) {
  return client.post(`/ui/messaging/conversations/${conversationId}/voice-message/presign`, body);
}

export function createVoiceMessage(conversationId: string, body: CreateVoiceReq) {
  return client.post(`/ui/messaging/conversations/${conversationId}/voice-message`, body);
}
```

In `ConversationView.tsx`, wire the `onSendVoiceMessage` callback through the presign -> upload -> create flow, same pattern as `sendImageMessage`.

### 8.8 State Management

VoiceRecorder state is local to the ComposeBar component (no Zustand store needed):
- `isRecording: boolean`
- `recordingDuration: number` (seconds elapsed)
- `previewBlob: Blob | null`
- `previewWaveform: number[]`

The WaveformPlayer manages its own local state:
- `isPlaying: boolean`
- `currentTime: number`
- `playbackRate: 1 | 1.5 | 2`

---

## 9. Security & Privacy Considerations

### 9.1 Authentication & Authorization

- Both endpoints use `require_ui_session` (cookie auth with CSRF enforcement). <!-- VERIFIED: auth pattern in messaging.py -->
- `require_participant_active(user_id, conversation_id)` verifies the sender is an active participant. <!-- CORRECTED: was _require_participant, actually require_participant_active (messaging.py:4188) -->
- Presigned S3 URLs expire after 300 seconds. The audio URL in the message record is an S3 key, not a public URL. In dev mode, `_message_out_from_item` resolves it to `/mock/s3/{bucket}/{key}`. In production, a presigned GET URL is generated on message fetch.

### 9.2 Input Validation

- `content_type` restricted to `audio/(webm|mp4|ogg|wav)` via regex pattern.
- `size_bytes` capped at 50MB. Backend can optionally verify actual S3 object size matches declared size.
- `duration_seconds` capped at 300s (5 minutes). Client enforces via `MediaRecorder.stop()` at max duration.
- `waveform_data` values clamped to [0.0, 1.0] and capped at 100 samples server-side to prevent storage abuse.
- `message_id` format validated via regex to prevent injection.

### 9.3 Data Protection

- Voice messages in listen-once mode: after playback, the client marks the message as consumed via `POST /messages/{id}/view` (existing endpoint). The audio URL remains accessible server-side (needed for compliance/legal holds) but the UI hides playback controls.
- Audio files stored in S3 inherit the bucket's encryption-at-rest configuration.
- No server-side audio transcription or analysis (waveform is client-computed).

### 9.4 Abuse Prevention

- Presign endpoint rate-limited to prevent S3 bucket flooding.
- Max 50MB per file prevents storage abuse.
- 5-minute duration cap prevents excessively long recordings.
- Existing spam/moderation systems apply to voice messages (reporting, content moderation tickets).

---

## 10. Performance & Scalability

### 10.1 DynamoDB Costs

- **Write**: 1 `put_item` per voice message (same as text). Waveform data adds ~400 bytes (100 floats * 4 bytes) to item size. Total item size ~1-2 KB.
- **Read**: `_message_out_from_item` processes voice messages identically to other kinds. No extra queries.
- **No new table or GSI needed**: Voice messages use the existing Messages table schema.

### 10.2 S3 Costs

- **Storage**: Opus/WebM at ~32kbps = ~240KB per minute. A 5-minute max recording = ~1.2MB.
- **Bandwidth**: Audio streamed directly from S3 (or CloudFront). No transcoding.
- **Lifecycle**: Consider S3 lifecycle policy to transition voice messages to Glacier after 90 days if storage costs grow.

### 10.3 Caching Strategy

- Waveform data is embedded in the message record, so no extra fetch needed for rendering.
- React Query caches messages per conversation with the existing `["messages", conversationId]` key.
- Audio files can be cached by the browser (standard HTTP caching on presigned URLs with long Expires).

### 10.4 Known Bottlenecks

- **MediaRecorder browser support**: Safari only supports `audio/mp4;codecs=aac`. The `content_type` field allows both formats. No server-side transcoding is performed, so WebM recordings cannot be played on older Safari versions (pre-15). Mitigation: detect browser and warn if format incompatibility exists.
- **Large conversation history**: Voice messages with waveform data are slightly larger than text messages (~1-2KB vs ~200B). In conversations with thousands of voice messages, pagination response size increases. The existing `Limit=50` per page mitigates this.

---

## 11. Migration & Rollback Plan

### 11.1 Feature Flag

| Variable | Default | Description |
|----------|---------|-------------|
| `VOICE_MESSAGE_ENABLED` | `true` | Master feature flag |
| `VOICE_MESSAGE_MAX_DURATION_SECONDS` | `300` | Maximum recording length (5 min) |
| `VOICE_MESSAGE_MAX_SIZE_BYTES` | `52428800` | Maximum file size (50MB) |
| `VOICE_MESSAGE_WAVEFORM_SAMPLES` | `100` | Max waveform data points stored |

Add to `app/core/settings.py` (frozen dataclass, currently 1197 lines): <!-- VERIFIED: settings.py is a frozen dataclass; none of these settings exist yet -->

```python
voice_message_enabled: bool = os.environ.get("VOICE_MESSAGE_ENABLED", "1") not in ("0", "false", "False")
voice_message_max_duration_seconds: int = int(os.environ.get("VOICE_MESSAGE_MAX_DURATION_SECONDS", "300"))
voice_message_max_size_bytes: int = int(os.environ.get("VOICE_MESSAGE_MAX_SIZE_BYTES", "52428800"))
voice_message_waveform_samples: int = int(os.environ.get("VOICE_MESSAGE_WAVEFORM_SAMPLES", "100"))
```

### 11.2 Incremental Deployment

1. **Phase 1 (backend)**: Deploy presign + create endpoints behind feature flag. Existing clients unaffected.
2. **Phase 2 (frontend)**: Deploy VoiceRecorder and WaveformPlayer. Mic button appears only when `VOICE_MESSAGE_ENABLED=true`.
3. **Phase 3 (GA)**: Enable flag in production. Monitor error rates and S3 storage growth.

### 11.3 Rollback

- Set `VOICE_MESSAGE_ENABLED=false` in env vars. Mic button hidden. Endpoints return 404.
- Existing voice messages remain in DynamoDB and S3. MessageBubble falls back to generic audio player for `kind="voice_message"` when the feature is disabled.
- No database migration needed (no new tables). Schema is additive (new fields on existing Messages table items).

---

## 12. Testing Strategy

### 12.1 Unit Tests (pytest)

| # | Test | File |
|---|------|------|
| 1 | `PresignVoiceMessageRequest` validates content_type regex | `tests/test_models.py` |
| 2 | `PresignVoiceMessageRequest` rejects duration > 300 | `tests/test_models.py` |
| 3 | `CreateVoiceMessageRequest` validates message_id format | `tests/test_models.py` |
| 4 | `CreateVoiceMessageRequest` rejects empty waveform | `tests/test_models.py` |
| 5 | Waveform normalization clamps values to [0, 1] | `tests/test_messaging.py` |
| 6 | Voice message `_message_out_from_item` includes audio_url | `tests/test_messaging.py` |
| 7 | Scheduled voice message sets `scheduled=True` and `deliver_at` | `tests/test_messaging.py` |
| 8 | `send_at` in the past raises 400 | `tests/test_messaging.py` |
| 9 | Non-participant gets 403 on presign | `tests/test_messaging.py` |

### 12.2 E2E Tests

**Test File:** `frontend/e2e/voice-messages.spec.ts`

**Section 1: Voice Message API (6 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | Presign voice message upload | POST presign; 200; has `upload_url`, `s3_key`, `message_id` |
| 2 | Create voice message with waveform | POST create; 200; response has `kind: "voice_message"`, `duration_seconds`, `waveform_data` |
| 3 | Reject duration over 300 seconds | POST create with `duration_seconds: 600`; 422 |
| 4 | Reject empty waveform data | POST create with `waveform_data: []`; 422 |
| 5 | Voice message appears in conversation messages | GET messages; find by `kind: "voice_message"`; has `audio_url` |
| 6 | Voice message with listen-once policy | POST create with `consumption_policy: "listen_once"`; response has `consumption_policy` |

**Section 2: Voice Message in Chat (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 7 | Voice message renders waveform in message bubble | Navigate to conversation; locate voice message; waveform bars visible |
| 8 | Play button starts audio playback | Click play; progress indicator advances |
| 9 | Duration label shows correct time | Voice message bubble shows formatted duration |
| 10 | Listen-once voice message shows consumed state after play | Play once; bubble shows "Already listened" indicator |

**Section 3: Scheduled Voice Messages (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 11 | Create scheduled voice message | POST create with `send_at` in future; 200; `scheduled: true` |
| 12 | Scheduled voice message in scheduled list | GET scheduled messages; find voice message |
| 13 | Cancel scheduled voice message | DELETE schedule; 200 |

**Section 4: Voice Message in Groups (2 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 14 | Send voice message in group conversation | POST create in group; 200; all participants can retrieve it |
| 15 | Voice message reply | POST create with `reply_to_message_id`; response has reply reference |

---

## 13. Monitoring & Alerting

### 13.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `voice_message_send_total` | Counter | `conversation_type` (dm/group), `policy` (none/listen_once) | Total voice messages sent |
| `voice_message_presign_total` | Counter | - | Total presign requests |
| `voice_message_duration_seconds` | Histogram | - | Distribution of recording durations |
| `voice_message_size_bytes` | Histogram | - | Distribution of file sizes |
| `voice_message_presign_latency_ms` | Histogram | - | S3 presign latency |
| `voice_message_create_latency_ms` | Histogram | - | DDB write latency for create endpoint |

### 13.2 Dashboard Queries

- **Adoption**: `rate(voice_message_send_total[1h])` -- voice messages per hour
- **Duration distribution**: `histogram_quantile(0.95, voice_message_duration_seconds)` -- 95th percentile duration
- **Error rate**: `rate(http_requests_total{path=~".*voice-message.*", status="5xx"}[5m])`

### 13.3 Alert Thresholds

| Alert | Condition | Severity |
|-------|-----------|----------|
| High error rate on voice message endpoints | 5xx rate > 5% for 5 minutes | Warning |
| S3 presign failures | `voice_message_presign_error_total` > 10 in 5 minutes | Critical |
| Unusual voice message volume | `voice_message_send_total` > 10x normal hourly rate | Warning |
| Large file uploads | `voice_message_size_bytes` > 40MB (approaching 50MB limit) | Info |

---

## 14. Open Questions & Risks

### 14.1 Unresolved Decisions

1. **Transcription**: Should voice messages optionally include server-side transcription (speech-to-text) for accessibility and searchability? This would require an external service (AWS Transcribe, Whisper) and significantly increase complexity. Recommendation: defer to a future ticket (MSG-003).
2. **Playback outside the app**: If a user receives a voice message notification via email, should the email include a playback link? This would require generating a time-limited public URL.
3. **Browser compatibility**: Should the backend reject `audio/mp4` from non-Safari browsers or accept any format? Currently accepting all valid audio MIME types.

### 14.2 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| `MediaRecorder` not available (older browsers, some WebViews) | Low | Medium | Feature detection; hide Mic button if unsupported. Show tooltip "Voice messages not supported in this browser". |
| S3 upload failure mid-recording | Low | Low | Retry logic in frontend. On failure, show error toast and allow re-attempt. |
| Safari `audio/mp4` not playable on Chrome mobile | Medium | Medium | Store `content_type` with message; WaveformPlayer uses `<audio>` with explicit `type` attribute. Browser shows unsupported error gracefully. |
| Waveform data bloats message list API response | Low | Low | 100 float values = ~400 bytes. Even 50 voice messages per page = ~20KB extra. Negligible. |

### 14.3 Dependency Risks

- **Microphone permissions**: Users must grant microphone access. Browser permission prompts are outside our control. If denied, the VoiceRecorder shows a friendly "Microphone access required" message.
- **S3 presign pattern**: Depends on the existing presign flow used by image messages. Any changes to S3 bucket configuration or CORS rules affect voice messages too.

---

## 15. Implementation Timeline

### Phase 1: Backend (Days 1-3)

| Day | Task |
|-----|------|
| 1 | Add `VOICE_MESSAGE_*` settings to `app/core/settings.py`. Add Pydantic models (`PresignVoiceMessageRequest`, `CreateVoiceMessageRequest`) to `app/models.py`. |
| 2 | Implement presign and create endpoints in `app/routers/messaging.py`. Extend `_message_out_from_item` for `kind="voice_message"`. |
| 3 | Write unit tests. Verify presign URL generation with moto S3. Test validation edge cases. |

### Phase 2: Frontend Core (Days 4-6)

| Day | Task |
|-----|------|
| 4 | Build `audioWaveform.ts` helper and `VoiceRecorder.tsx` component with MediaRecorder integration. |
| 5 | Build `WaveformPlayer.tsx` component with playback progress and speed toggle. |
| 6 | Integrate VoiceRecorder into ComposeBar, wire send flow (presign -> upload -> create) in ConversationView. Add `voice_message` branch to MessageBubble. |

### Phase 3: Frontend Polish + Types (Days 7-8)

| Day | Task |
|-----|------|
| 7 | Add TypeScript types to `api/types.ts`. Add API functions to `api/endpoints/messaging.ts`. Handle Safari fallback, browser feature detection, error states. |
| 8 | Add listen-once UX for voice messages. Add scheduled send support. Test in both DM and group conversations. |

### Phase 4: E2E Tests + QA (Days 9-10)

| Day | Task |
|-----|------|
| 9 | Write `frontend/e2e/voice-messages.spec.ts` (15 tests across 4 sections). |
| 10 | Manual QA, cross-browser testing (Chrome, Firefox, Safari), fix any issues, code review. |

---

## 16. Files to Create

| File | Purpose |
|------|---------|
| `frontend/src/pages/messages/VoiceRecorder.tsx` | Recording UI with live waveform |
| `frontend/src/pages/messages/WaveformPlayer.tsx` | Playback waveform visualization |
| `frontend/src/lib/audioWaveform.ts` | Web Audio API waveform computation helpers |
| `frontend/e2e/voice-messages.spec.ts` | E2E tests |

## 17. Files to Modify

| File | Change |
|------|--------|
| `app/routers/messaging.py` | Add presign and create voice message endpoints; add `voice_message` to `_message_out_from_item` (line 3725); add `"voice_message"` to `kind` Literal (line 2291); add new fields to `MessageOut` class (line 2286) | <!-- VERIFIED: _message_out_from_item at line 3725, MessageOut at line 2286 -->
| `app/core/settings.py` | Add `VOICE_MESSAGE_*` settings | <!-- VERIFIED: settings.py exists (1197 lines); none of these settings exist yet -->
| `app/models.py` | **NOTE**: Pydantic models for messaging are defined INSIDE `app/routers/messaging.py` (e.g., `SendTextMessageIn` at line 1843, `MessageOut` at line 2286), NOT in `app/models.py`. New voice message models should follow this pattern. | <!-- CORRECTED: was app/models.py, actually models are inline in messaging.py -->
| `frontend/src/pages/messages/ComposeBar.tsx` | Add microphone button, `VoiceRecorder` integration, `onSendVoiceMessage` callback |
| `frontend/src/pages/messages/ConversationView.tsx` | Wire `onSendVoiceMessage` prop to presign + upload + create flow |
| `frontend/src/pages/messages/MessageBubble.tsx` | Add `WaveformPlayer` rendering for `kind="voice_message"` |
| `frontend/src/api/types.ts` | Add `VoiceMessageMeta` fields to `Message` interface |
| `frontend/src/api/endpoints/messaging.ts` | Add `presignVoiceMessage()` and `createVoiceMessage()` functions |

---

## 18. Dependencies

- **Web Audio API / MediaRecorder API**: Supported in all modern browsers (Chrome, Firefox, Safari 14.1+, Edge).
- **S3 presign upload pattern**: Already used by image messages in `app/routers/messaging.py`.
- **Listen-once consumption policy**: Already implemented for audio messages; reused for voice messages.

---

## 19. Acceptance Criteria

1. User can hold the mic button to record, release to stop, and see a preview with playback controls.
2. User can send the recording; it appears in chat as a waveform bubble with play button and duration.
3. Recipient can play the voice message; waveform highlights progressively during playback.
4. Playback speed can be toggled between 1x, 1.5x, and 2x.
5. Recording auto-stops at 5 minutes with a visual countdown in the last 30 seconds.
6. Voice messages work with listen-once consumption policy.
7. Voice messages work with scheduled send (`send_at`).
8. Voice messages work in both DM and group conversations.
9. Cancel recording via Escape key discards the audio and returns to normal compose mode.
10. Waveform data (50-100 amplitude samples) is stored as message metadata, not computed at playback.

---

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| Messages table PK=conversation_id, SK=message_id | `scripts/local-ddb-init.py` | 247 | VERIFIED |
| `kind` Literal values on MessageOut | `app/routers/messaging.py` | 2291 | VERIFIED (includes text, image, video, audio, file, file_share, calendar_share, calendar_event, meeting_poll, gallery, video_share; does NOT include `lottery` as claimed in section 3.1) |
| `_message_out_from_item` function signature | `app/routers/messaging.py` | 3725 | VERIFIED: `def _message_out_from_item(message_item: dict, viewer_user_id: str) -> MessageOut` (ticket code samples omitted `viewer_user_id` param -- CORRECTED inline) |
| `send_text_message` function | `app/routers/messaging.py` | 7572-7573 | VERIFIED |
| `create_image_message` function | `app/routers/messaging.py` | 7815-7816 | VERIFIED |
| `presign_image_upload` function | `app/routers/messaging.py` | 7796-7797 | VERIFIED |
| `SendTextMessageIn` Pydantic model | `app/routers/messaging.py` | 1843 | VERIFIED (inline in messaging.py, NOT in app/models.py) |
| `CreateImageMessageIn` Pydantic model | `app/routers/messaging.py` | 1910 | VERIFIED (inline in messaging.py, NOT in app/models.py) |
| `MessageOut` Pydantic model | `app/routers/messaging.py` | 2286 | VERIFIED (inline in messaging.py, NOT in app/models.py) |
| `S3_BUCKET_IMAGES` variable | `app/routers/messaging.py` | 207 | VERIFIED: `S3_BUCKET_IMAGES = os.getenv("S3_BUCKET_IMAGES", "my-chat-images")` |
| `require_participant_active` function | `app/routers/messaging.py` | 4188 | VERIFIED (ticket used `_require_participant` which does not exist -- CORRECTED inline) |
| `_get_conversation_or_404` function | `app/routers/messaging.py` | 4203 | VERIFIED |
| `_sse_pack` SSE helper | `app/routers/messaging.py` | 4812 | VERIFIED (ticket used `_emit_sse_event` which does not exist -- CORRECTED inline) |
| `now_ts()` function | `app/core/time.py` | 2 | VERIFIED: returns integer Unix timestamp |
| `app/core/settings.py` exists | `app/core/settings.py` | 1-1197 | VERIFIED: frozen dataclass; no `VOICE_MESSAGE_*` settings exist yet |
| `app/core/tables.py` Tables dataclass | `app/core/tables.py` | 1-177 | VERIFIED: no `messages` handle (messages table accessed via module-level `tbl` in messaging.py) |
| Conversation last_message update pattern | `app/routers/messaging.py` | 4751, 8301, 8424, 8603, 8718, 8831 | VERIFIED: inline `tbl_convos.update_item` with SET last_message_at, last_message_preview, last_message_id (ticket used `_update_conversation_last_message()` which does not exist as a named function -- CORRECTED inline) |
| `consumption_policy` field on MessageOut | `app/routers/messaging.py` | 2328 | VERIFIED: `Literal["none", "view_once", "listen_once"]` |
| `scheduled` and `deliver_at` fields on MessageOut | `app/routers/messaging.py` | 2334-2335 | VERIFIED |
| `reply_to_message_id` field on MessageOut | `app/routers/messaging.py` | 2307 | VERIFIED |
| Messaging router file | `app/routers/messaging.py` | 12698 lines total | VERIFIED |

### Key Corrections Summary

1. **`_require_participant` does not exist** -- the actual function is `require_participant_active(user_id, conversation_id)` at messaging.py:4188.
2. **`UPLOAD_BUCKET` does not exist** -- the actual variable is `S3_BUCKET_IMAGES` at messaging.py:207.
3. **`_update_conversation_last_message` does not exist** as a named function -- it is an inline `tbl_convos.update_item(...)` call with `SET last_message_at, last_message_preview, last_message_id`.
4. **`_emit_sse_event` does not exist** -- SSE packing is done via `_sse_pack` at messaging.py:4812.
5. **`_resolve_media_url` does not exist** -- URL resolution is inline within `_message_out_from_item`.
6. **`_message_out_from_item(item)` signature is wrong** -- actual signature is `_message_out_from_item(message_item: dict, viewer_user_id: str)`.
7. **Pydantic models are in `app/routers/messaging.py`, not `app/models.py`** -- `SendTextMessageIn` (line 1843), `CreateImageMessageIn` (line 1910), `MessageOut` (line 2286) are all defined inline in the router file.
8. **`lottery` is not in the kind Literal** -- the actual value is `video_share` at that position (line 2291).

---

## Codebase References

| File | Line(s) | What was verified |
|------|---------|-------------------|
| `app/routers/messaging.py` | 8164 | ALREADY EXISTS: `presign_voice_message()` endpoint |
| `app/routers/messaging.py` | 8195 | ALREADY EXISTS: `create_voice_message()` endpoint |
| `app/routers/messaging.py` | 1937-1943 | ALREADY EXISTS: `PresignVoiceMessageRequest` and `CreateVoiceMessageRequest` models |
| `app/routers/messaging.py` | 1949, 1971 | EXISTS: `waveform_data: List[float]` field with validation (min 10, max 200 samples) |
| `app/routers/messaging.py` | 2330 | EXISTS: `kind` Literal includes `"voice_message"` |
| `app/routers/messaging.py` | 3950-3966 | EXISTS: voice message rendering in `_message_out_from_item` with waveform data |
| `app/routers/messaging.py` | 8231-8247 | EXISTS: waveform processing (clamping, Decimal conversion) |
| `app/core/settings.py` | 1280-1283 | EXISTS: `voice_message_enabled`, `voice_message_max_duration_seconds` (300), `voice_message_max_size_bytes`, `voice_message_waveform_samples` (100) |
| `frontend/src/pages/messages/VoiceRecorder.tsx` | — | ALREADY EXISTS: voice recorder component |
| `frontend/src/pages/messages/WaveformPlayer.tsx` | — | ALREADY EXISTS: waveform playback component |
<!-- NOTE: Voice messages are FULLY IMPLEMENTED in backend (endpoints, models, waveform processing, settings) and frontend (VoiceRecorder, WaveformPlayer). This ticket should be marked as Complete. -->
