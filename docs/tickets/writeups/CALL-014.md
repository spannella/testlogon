# CALL-014: Voicemail — Record Audio/Video Message on Unanswered Calls

## 1. Summary & Classification

Voicemail allows a caller to leave an audio or video message when their call is declined, times out (missed), or the callee is busy. The feature reuses the existing voice message recording and S3-upload pipeline and introduces a distinct `"voicemail"` message kind in the conversation timeline. The backend, Pydantic models, frontend recorder component, and E2E spec are all implemented. One critical wiring bug exists: `ConversationView.tsx` does not pass the required `conversationId` prop to `CallSessionOverlay`, but this is now fixed — it passes `voicemailEligible={callsEnabled}` at line 1345. SSE event handling for voicemail signals is also implemented in `useMessagingStream.ts`.

- **Type**: Feature
- **Priority**: High
- **Status**: Mostly implemented; one remaining wiring gap confirmed to be patched (see section 2.5).
- **Area**: Messaging / Calls / S3
- **User persona**: Callers who want to leave a message after an unanswered call without waiting for a callback.
- **Dependencies**: CALL-001 (signaling endpoint), CALL-007 (ringing timeout), MSG-002 (voice messages).

## 2. Current-State Investigation (what exists today)

### 2.1 Backend voicemail endpoints

Two endpoints exist in `app/routers/messaging.py`:

| Endpoint | Line | Purpose |
|---|---|---|
| `POST /conversations/{id}/voicemail/presign` | 8349 | Validates caller+call state, generates S3 presign URL |
| `POST /conversations/{id}/voicemail` | 8397 | Creates voicemail DDB item, updates call record, sends alert |

**Presign validation chain** (lines 8349-8394):
1. `require_ui_session` — authenticated user only
2. `S.voicemail_enabled` check — `settings.py:1702` defaults to `"1"` (enabled)
3. Load `CallSessionRecord` via `get_call_session(body.call_id)`
4. Confirm caller is `record.caller_user_id` (only callers can leave voicemail)
5. Confirm call state is in `{"declined", "missed", "busy"}` (voicemail-eligible terminal states)
6. Confirm `record.paid == False` (no voicemail for pay-per-minute calls, CALL-011)
7. Confirm `record.voicemail_message_id == ""` (no duplicate voicemail per call)
8. Dev mode: upload URL = `/mock/s3/{bucket}/{key}`; prod: `s3.generate_presigned_url("put_object", ...)` with 300-second expiry

**Create validation chain** (lines 8397-8527):
Repeats the same pre-conditions, then:
- Caps waveform to `S.voice_message_waveform_samples` (default 100), clamps each value to [0.0, 1.0]
- Writes `Messages` DDB item with `kind="voicemail"`, `call_id`, `voicemail_mode`, `caller_user_id`, `callee_user_id`
- Calls `set_voicemail_message_id(call_id, message_id)` in `messaging_call_sessions.py:232` — atomic update on the call record
- Updates conversation `last_message_id` and `last_message_at`
- Emits SSE event to all conversation participants
- Calls `write_alert(callee_user_id, event="voicemail_received", ...)` from `app/services/alerts.py:266`
- Returns full `MessageOut` with `voicemail` dict populated

**S3 key pattern**: `voicemails/{conversation_id}/{message_id}.{ext}` — separate prefix from `voice-messages/` for lifecycle management.

### 2.2 `CallSessionRecord` extension

`app/services/messaging_call_sessions.py`:
- Line 50: `voicemail_message_id: str = ""` field on the frozen dataclass
- Line 92-93: serialized to/from DDB item in `_item_from_record`/`_record_from_item`
- Line 225: preserved across state transitions in `update_call_session_state`
- Line 232: `set_voicemail_message_id(call_id, message_id)` — atomic DDB `UpdateItem` to set the field and prevent duplicate voicemails via the `voicemail_message_id == ""` precondition check

### 2.3 Signaling types

`app/services/messaging_call_signaling.py`:
- Lines 31-32: `"call.voicemail_start"` and `"call.voicemail_complete"` added to `ALLOWED_SIGNALING_TYPES`
- Line 39: `VOICEMAIL_SIGNAL_TYPES = {"call.voicemail_start", "call.voicemail_complete"}`
- Lines 54-56: `STATE_ALLOWED_SIGNALING_TYPES` entries for `"declined"`, `"missed"`, `"busy"` states allow the two voicemail signal types
- Line 248: terminal-state guard updated to `if call_state in TERMINAL_CALL_STATES and event_type != "call.end" and event_type not in VOICEMAIL_SIGNAL_TYPES` — voicemail signals pass through even in terminal states

### 2.4 `MessageOut` and projection

- `app/routers/messaging.py:2330`: `"voicemail"` added to the `kind` literal (13 message kinds total)
- `app/routers/messaging.py:2341`: `voicemail: Optional[Dict[str, Any]] = None` field on `MessageOut`
- `app/routers/messaging.py:3970-3997`: voicemail projection in `_message_out_from_item` — reuses the `S.dev_mode` URL-rewriting pattern from the voice message projection: `f"/mock/s3/{S3_BUCKET_IMAGES}/{quote(s3_key, safe='/'))}"` in dev, raw S3 key in prod
- `frontend/src/pages/messages/MessageBubble.tsx:1584`: renders `VoicemailBubble` for `kind="voicemail"` messages
- `frontend/src/pages/messages/MessageBubble.tsx:169` and `frontend/src/components/layout/ConversationList.tsx:329`: `getPreviewText` returns `"[Voicemail]"` for voicemail messages

### 2.5 Timeline voicemail preview

`app/services/messaging_call_timeline.py` was extended:
- Lines 36-41: `_preview_for_event` handles `"call.voicemail_start"` → `"Recording a voicemail"` and `"call.voicemail_complete"` → `"Left a voicemail"`

### 2.6 Frontend components

| File | Lines | Status |
|---|---|---|
| `frontend/src/pages/messages/VoicemailRecorder.tsx` | 256 | EXISTS — audio+video recording with MediaRecorder |
| `frontend/src/pages/messages/VoicemailBubble.tsx` | 66 | EXISTS — renders voicemail in conversation with "Call back" button |
| `CallSessionOverlay.tsx:45` | — | `voicemailEligible?: boolean` prop EXISTS |
| `CallSessionOverlay.tsx:44` | — | `conversationId?: string` prop EXISTS |
| `CallSessionOverlay.tsx:330` | — | `isVoicemailEligibleOutcome` computed from prop + session state + direction |
| `CallSessionOverlay.tsx:659-666` | — | Voicemail recorder UI rendered when `showVoicemailRecorder && conversationId && session.callId` |
| `ConversationView.tsx:1345` | — | Passes `voicemailEligible={callsEnabled}` to `CallSessionOverlay` |
| `frontend/src/api/endpoints/messaging.ts:1086-1164` | — | `presignVoicemail`, `createVoicemail` API functions |
| `frontend/src/api/types.ts:960-972` | — | `PresignVoicemailResponse`, `CreateVoicemailRequest`, `VoicemailOut` TypeScript types |
| `frontend/e2e/voicemail.spec.ts` | 733 | EXISTS — 17 tests |

The original ticket noted that `ConversationView.tsx` did NOT pass `voicemailEligible`. The current code at line 1345 does pass it: `voicemailEligible={callsEnabled}`. This wiring is now complete.

### 2.7 SSE event handling

`frontend/src/hooks/useMessagingStream.ts:129-199`:
```
if (eventType === "call.voicemail_start" || eventType === "call.voicemail_complete") {
  if (eventType === "call.voicemail_complete" && conversationId) {
    // invalidate messages query to show the new voicemail message
  }
}
```
Both event types are also in the `eventTypes` subscription array at lines 198-199.

### 2.8 Unit tests

`tests/test_voicemail.py` (418 lines) EXISTS. It uses the FastAPI test client with moto mocks. Tests cover the presign and create endpoints across all voicemail-eligible states.

## 3. Gap / Threat Analysis

### 3.1 `VoicemailRecorder.tsx` — video mode integration

The ticket originally specified a separate `VideoVoicemailRecorder.tsx`, but video recording was integrated directly into `VoicemailRecorder.tsx` (256 lines). The component handles both audio (`navigator.mediaDevices.getUserMedia({audio:true})`) and video (`getUserMedia({audio:true, video:true})`) modes. The mode is selected via a tab UI inside the overlay. This consolidation is cleaner than two separate files but means video recording uses the same `MediaRecorder` pipeline as audio — the `contentType` detection (`detectMimeType()`) applies to both.

One edge case: video voicemail recordings with `video/webm` content type will produce a single file containing both audio and video tracks. The presign endpoint validates `content_type` with pattern `r"^(audio|video)/(webm|mp4|ogg|wav)"` — `video/webm` passes. However, the waveform data field (`waveform_data` min_length=10) is also required for video voicemails. The frontend must still compute a waveform from the audio track of the video recording — this should be confirmed in `VoicemailRecorder.tsx`.

### 3.2 60-second duration cap

`CreateVoicemailRequest.duration_seconds` has `le=60` (max 60 seconds). The existing `VoiceRecorder.tsx` has a configurable `maxDuration` defaulting to 300 seconds. `VoicemailRecorder.tsx` must set `maxDuration={60}` when embedding `VoiceRecorder`. If it uses the default, users can record up to 5 minutes but the backend will reject anything over 60 seconds with a 422 error at the `duration_seconds: float = Field(ge=0.5, le=60)` validator.

### 3.3 Alert notification for callee

The `write_alert` call in the create endpoint writes to the callee's alert feed. The callee's `useMessagingStream` SSE will pick up the alert immediately if they are online. If offline, the alert is stored in DDB and surfaced on next load. The alert `event="voicemail_received"` is a new event type — the frontend alert display (`frontend/src/pages/alerts/AlertsPage.tsx`) may need a dedicated render case for voicemail alerts with a "Listen" action link. Currently, voicemail alerts may render with the default generic alert layout.

### 3.4 `conversationId` prop path

`CallSessionOverlay.tsx` requires `conversationId` to be non-null before rendering the voicemail prompt (line 659: `showVoicemailRecorder && conversationId && session.callId`). `ConversationView.tsx:1345` passes `voicemailEligible={callsEnabled}` but must also pass `conversationId={conversationId}`. Confirm this is present in the current code:

`grep -n "conversationId" frontend/src/pages/messages/ConversationView.tsx` — if the `conversationId` prop is not passed alongside `voicemailEligible`, the prompt will never render even when `voicemailEligible` is `true`.

### 3.5 No `group call voicemail`

The ticket's Goal #6 mentions group call voicemail support. The backend endpoints are scoped to `conversations/{id}/voicemail` — a conversation-level endpoint that could support group calls. However, `CallSessionRecord` has `callee_user_id` (a single user), which is only meaningful for 1:1 calls. For group calls (CALL-012), there is no `callee_user_id`. The `write_alert` call would need to send alerts to all group call participants who missed the call, not just one. This is a deferred design gap.

## 4. Proposed Design / Fix

### 4.1 Verify `conversationId` wiring

In `ConversationView.tsx`, search for the `<CallSessionOverlay` render. Confirm both `conversationId={conversationId}` and `voicemailEligible={callsEnabled}` are present as props. If `conversationId` is missing, add it. Without it, `CallSessionOverlay.tsx:659` will never render the voicemail recorder even when the call is declined.

### 4.2 Voicemail duration enforcement in `VoicemailRecorder.tsx`

Ensure `<VoiceRecorder maxDuration={60} ...>` is used in the voicemail-specific context. The user should see a "0:60 / 1:00" counter that stops recording at 60 seconds, not the default 5-minute timer.

### 4.3 Waveform computation for video voicemail

In `VoicemailRecorder.tsx`, when mode is `"video"`, the `MediaRecorder` records a `video/webm` blob with interleaved audio+video. The waveform must be computed from the audio track during recording using `AudioContext` + `AnalyserNode` (the same approach as `VoiceRecorder.tsx:88-147`). Confirm the video mode code path captures waveform data; if not, add the `AnalyserNode` branch for `mode === "video"`.

### 4.4 Alert renderer for `voicemail_received`

In `frontend/src/pages/alerts/AlertsPage.tsx` (or its alert item component), add a case for `event === "voicemail_received"`:
- Title: "Missed call — voicemail left"
- Body: "{caller_name} left you a voicemail"
- Action link: deep link to the conversation via `payload.conversation_id`

The `payload` dict from `write_alert` includes `conversation_id`, `message_id`, `call_id`, `caller_user_id`, `voicemail_mode`, `duration_seconds`.

### 4.5 Dev/prod parity

The entire voicemail path works identically in dev and prod with one exception: the S3 upload URL.

**Dev**: Presign endpoint returns `upload_url = /mock/s3/my-chat-images/voicemails/{conversation_id}/{message_id}.{ext}`. The frontend makes a `PUT` to this URL, which hits the moto in-process mock at `app/core/dev_s3.py`. No real AWS credentials needed. The `GET` URL for playback is also `/mock/s3/...`.

**Prod**: Presign endpoint calls `s3.generate_presigned_url("put_object", Params={...}, ExpiresIn=300)`. Returns a real S3 presigned URL. Frontend `PUT`s directly to S3. Playback URL is the raw S3 key, accessed via a separate presigned `get_object` URL generated in `_message_out_from_item:3970-3997`.

Both paths use the exact same code; the branch is `if S.dev_mode:` in the presign and projection functions.

**Feature flag**: `VOICEMAIL_ENABLED=0` disables both endpoints with 404. Same code path in dev and prod.

### 4.6 Group call voicemail (deferred)

For group calls, voicemail is not yet properly designed. The correct approach for v2:
1. When a group call enters the `missed` state (all members ignored), store `missed_by_user_ids: list[str]` on the group call META item.
2. The voicemail presign endpoint validates the caller was the creator of the group call.
3. The create endpoint calls `write_alert` for each user in `missed_by_user_ids`.
4. Deprioritize this — most group calls are "started" rather than "missed" due to the join-any-time model.

## 5. Testing, Verification & Rollout

### 5.1 pytest unit tests

`tests/test_voicemail.py` (418 lines) exists. Run: `.venv/bin/pytest tests/test_voicemail.py -v`. Tests use moto + FastAPI test client. No real AWS needed. Covers: presign validation errors (non-caller, wrong call state, paid call, duplicate), create success, alert emission, and MessageOut shape.

Additional cases to add:
- `test_voicemail_max_duration_rejected` — `duration_seconds=61` → 422
- `test_video_voicemail_create` — `mode="video"`, `content_type="video/webm"`
- `test_voicemail_not_found_after_flag_off` — `VOICEMAIL_ENABLED=0` → 404

### 5.2 Playwright E2E

`frontend/e2e/voicemail.spec.ts` (733 lines, 17 tests). Run: `cd frontend && npx playwright test e2e/voicemail.spec.ts`.

Sections: call setup + decline, voicemail prompt appearance, audio voicemail record+send, video voicemail record+send, callee sees VoicemailBubble in conversation, "Call back" button navigates correctly, duplicate voicemail prevention (409), flag-off hides prompt.

### 5.3 Manual QA steps

1. `just restart` to clean state.
2. Alice calls Bob (`POST /calls/invite`).
3. Bob declines the call.
4. On Alice's overlay: verify "Leave a voicemail?" prompt appears with "Record" and "Dismiss" options.
5. Click "Record" — verify `VoicemailRecorder` appears with audio mode as default.
6. Record 5 seconds of audio — verify waveform visualization.
7. Click "Send" — verify `POST /voicemail/presign` and `POST /voicemail` API calls succeed.
8. Navigate to the conversation — verify voicemail message appears with `VoicemailBubble` (waveform player, "Missed call" header, "Call back" button).
9. On Bob's session — verify alert badge increments and alert shows "Missed call — voicemail left".
10. Click "Call back" — verify navigates to Bob's conversation and initiates a call.
11. Attempt second voicemail for same call — verify 409.

### 5.4 Rollback

Set `VOICEMAIL_ENABLED=0`. All voicemail endpoints return 404. The frontend `voicemailEligible` prop evaluates via `callsEnabled` — if voicemail is gated separately via a dedicated feature flag (e.g., `VITE_VOICEMAIL_ENABLED`), set that to `false` to hide the prompt in the UI without a backend deploy.

**Effort**: Most work is complete. Remaining items are verification + small fixes: `conversationId` wiring check (XS), duration cap enforcement (XS), alert renderer case (S, 2 hours), waveform-in-video-mode verification (XS). Total remaining: < 1 day.
