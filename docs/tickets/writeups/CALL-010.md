# CALL-010: Wire Call Recording into Messenger ConversationView — Investigation & Implementation Write-up

## 1. Summary & Classification

CALL-009 delivered a complete call recording stack — backend endpoints, DynamoDB store, frontend `useCallRecording` hook, state machine events, SSE event types, and overlay UI props — but the hook was never instantiated, making the entire recording feature invisible to users. This ticket is integration glue: import and wire `useCallRecording` inside `ConversationView.tsx`, synchronize its state to the call state machine, pass recording-derived props to `<CallSessionOverlay>`, handle edge cases (call ends mid-recording, page refresh mid-recording, upload progress toasts), and add a frontend feature flag. One gap remains: no `RecordingsPanel` component exists for post-call recording discovery within the conversation view.

**Type**: Feature integration / glue
**Priority**: High (P0 — CALL-009 is dead without this ticket)
**Status**: Core wiring fully implemented; `RecordingsPanel.tsx` frontend component not implemented; `tests/test_call_recording_integration.py` exists (571 lines)
**Owning area**: Messaging / Calls / Frontend
**Cross-references**: CALL-009 (provides all building blocks), CALL-011 (billing overlay also not yet wired — same pattern), SECOPS-007 (feature-flag gating via `VITE_CALL_RECORDING_ENABLED`; same code path dev and prod)
**Affected users**: All users in active WebRTC calls with `VITE_CALL_RECORDING_ENABLED=true`.

---

## 2. Current-State Investigation

### 2.1 Hook Import and Instantiation

`frontend/src/pages/messages/ConversationView.tsx:53-54`:
```typescript
import { useCallRecording } from "@/hooks/useCallRecording";
import { isCallRecordingEnabled, isGroupCallsEnabled } from "@/lib/featureFlags";
```

`ConversationView.tsx:696-704`:
```typescript
const callRecordingEnabled = callsEnabled && isCallRecordingEnabled();
const callRecording = useCallRecording({
  callId: callMachine.callId,
  userId: userId ?? "",
  localStream: rtcLocalStream ?? mediaCapture.stream ?? null,
  remoteStream: rtcRemoteStream ?? null,
  isConnected: callMachine.phase === "connected",
  enabled: callRecordingEnabled,
});
```

The `enabled` guard means the hook registers no event listeners and makes no API calls when recording is disabled or calls are not active. `localStream` uses the same fallback chain as the overlay (`rtcLocalStream ?? mediaCapture.stream ?? null`), ensuring the hook sees whatever stream the camera is using.

### 2.2 State Machine Sync Effect

`ConversationView.tsx:706-720` (approximately) contains a `useEffect` that watches `callRecording.recordingState`, `callRecording.recordingId`, `callRecording.consentPendingFrom`, and `callRecording.isInitiator`. It dispatches to `callStateReducer`:
- `recordingState === "recording"` → dispatches `RECORDING_STARTED` with `recordingId`.
- `recordingState === "consent_pending"` with `consentPendingFrom` → dispatches `RECORDING_REQUEST_RECEIVED`.
- `recordingState === "consent_pending"` with `isInitiator` → dispatches `RECORDING_REQUEST_SENT`.
- `recordingState === "idle"` while `callMachine.recordingState !== "idle"` → dispatches `RECORDING_DECLINED`.
- `recordingState` in `["stopping", "uploading", "complete"]` → dispatches `RECORDING_STOPPED`.

This is a one-way sync: the hook is the source of truth; the state machine mirrors for derived state consumers. No duplicate SSE event handling occurs in the `onCallEvent` listener — the hook's internal listener (`:105-136` of `useCallRecording.ts`) handles all five `call.recording_*` event types before `ConversationView`'s `onCallEvent` would see them.

### 2.3 `beforeunload` Warning

`ConversationView.tsx:722-726` registers a `beforeunload` handler when `callRecording.recordingState === "recording"`, warning users with "A recording is in progress..." This prevents silent data loss on accidental navigation.

### 2.4 Upload Progress Toast

`ConversationView.tsx:728-735` (approximately) uses a `useEffect` on `callRecording.recordingState` to show:
- `toast.loading("Uploading call recording...", { id: "recording-upload" })` when `uploading`.
- `toast.success("Call recording saved.", { id: "recording-upload" })` when `complete`.
- `toast.error(...)` when `error`.

### 2.5 Recording Props Passed to Overlay

`ConversationView.tsx:1443` and surrounding lines pass all eight recording props to `<CallSessionOverlay>`:
- `isRecording={callRecording.recordingState === "recording"}`
- `recordingDuration={callRecording.duration}`
- `onRequestRecording={() => callRecording.requestRecording()}`
- `onStopRecording={() => callRecording.stopRecording()}`
- `recordingEnabled={callRecordingEnabled}`
- `showRecordingConsent={callRecording.recordingState === "consent_pending" && !!callRecording.consentPendingFrom}`
- `recordingConsentFrom={callRecording.consentPendingFrom}`
- `onConsentRecording={(accept) => callRecording.respondToRequest(accept)}`

### 2.6 Stop Recording Before Teardown

`ConversationView.tsx:1414` (in `onEnd` handler) and `:1430` (in `onDismiss` handler): `callRecording.stopRecording()` is called before `teardownCallResources()`. This ensures `MediaRecorder.stop()` fires and collects the final data chunk before stream tracks are stopped.

The `useCallRecording` hook's `stopRecording()` is synchronous (transitions state immediately, fires `recorder.stop()`). The `ondataavailable` handler fires asynchronously, and the resulting Blob is assembled before the `uploading` state is entered. Because the Blob is already collected before `teardownCallResources` stops the stream, the upload can proceed in the background even after the call overlay is dismissed.

### 2.7 Feature Flag

`frontend/src/lib/featureFlags.ts:126-127`:
```typescript
export const callRecordingEnabled = toBool(env.VITE_CALL_RECORDING_ENABLED, false);
export const isCallRecordingEnabled = () => callRecordingEnabled;
```

The backend independently gates recording via `S.call_recording_enabled` (`:1468`). Both flags must be true for recording to function end-to-end.

### 2.8 Post-Call Recording Access — `GET /messages/recordings`

`app/routers/call_recording.py:439-465` implements `GET /messages/recordings` with an optional `conversation_id` query parameter (`:443`). When supplied, it queries the `ByConversationCreatedAt` GSI via `get_recordings_for_conversation()` from `call_recording_store.py:172`. This endpoint is the backend API for the unimplemented `RecordingsPanel.tsx`.

### 2.9 What Is Not Implemented

`frontend/src/pages/messages/RecordingsPanel.tsx` does **not exist**. The CALL-010 spec (section 3.7) describes this as a "Recordings" section in the conversation info panel showing past recordings with download links. There is no frontend component that queries `GET /messages/recordings?conversation_id={id}` or displays recording metadata in the conversation UI. Users can only access recordings via the raw API or the upload-complete toast.

`tests/test_call_recording_integration.py` exists (571 lines), so Python integration test coverage is present. The E2E spec `frontend/e2e/call-recording-integration.spec.ts` (601 lines) covers the consent flow, REC indicator, and upload, but cannot cover the `RecordingsPanel` since it does not exist.

---

## 3. Gap / Threat Analysis

### 3.1 `RecordingsPanel.tsx` Not Implemented

The primary gap. Post-call recording discovery relies entirely on the upload-complete toast, which is ephemeral. A user who missed the toast has no way to find their recording within the conversation UI. They could navigate to `GET /messages/recordings` directly, but there is no UI for this.

**Impact**: Feature is functional but hard to discover. Affects user retention for the recording feature.

### 3.2 No Recording System Message in Timeline

`complete_recording_upload` (`:322`) does not insert a system message into the conversation timeline (see CALL-009, gap 3.1). Without it, there is no `call_recording_available` event in the message list to anchor a download button. The `RecordingsPanel` can still show recordings, but the in-line timeline anchor is missing.

**Impact**: Compound with 3.1 — two separate gaps both reduce discoverability.

### 3.3 Upload May Proceed After Call Teardown but `useCallRecording` Is Still Mounted

The hook is mounted inside `ConversationView.tsx`, which is the message thread component. After a call ends and the overlay is dismissed, `ConversationView` remains mounted (the user is still in the conversation). The hook continues through `uploading → complete` without issues. However, if the user navigates away from the conversation during the upload (to another conversation or page), `ConversationView` unmounts and the hook's cleanup (`useEffect` cleanup function) is called. This cancels the in-progress `fetch` upload via the hook's `AbortController` (if one is used).

**Action needed**: Confirm `useCallRecording.ts` uses an `AbortController` for the presigned PUT call (`:270-302`). If it does not, the `fetch` will continue in the background after the component unmounts — which is actually correct behavior for a fire-and-forget upload, but will log React warnings about state updates after unmount.

### 3.4 Recordings List Endpoint Has a 50-Item Cap

`list_user_recordings` at `call_recording.py:467` slices to `recordings[:50]`. A user with more than 50 recordings in a single conversation will silently lose older recordings from the listing. No pagination is implemented.

**Impact**: Low risk for v1; calls generate at most one recording each, and 50 conversations with recordings is unlikely in the near term.

### 3.5 Double-Consent Race Condition

Both Alice and Bob could press Record simultaneously. Each creates a `CallRecordingRecord` via `/recording/request`. The `get_active_recording_for_call()` check at presign time (`:273`) returns the first non-deleted, non-failed recording — but between the two simultaneous requests, `get_active_recording_for_call()` may return `None` for both (before either has been written) or either record. If both requests succeed, two `pending_consent` records exist for the same call. Both will wait for the other party's consent, and both may eventually transition to `recording` — resulting in two simultaneous recordings.

**Impact**: Edge case; unlikely in practice since only one party typically presses Record. The second recording upload creates a second DDB record and a second S3 object. No data corruption occurs, but storage is doubled.

**Fix**: Add a `ConditionExpression` to `create_recording()` in `call_recording_store.py:117` that fails if any `pending_consent` or `recording` record already exists for the `call_id`, using the `ByCallIdCreatedAt` GSI.

---

## 4. Proposed Design / Fix

### 4.1 Implement `RecordingsPanel.tsx`

Create `frontend/src/pages/messages/RecordingsPanel.tsx`:

```typescript
function RecordingsPanel({ conversationId }: { conversationId: string }) {
  const { data } = useQuery({
    queryKey: ["recordings", conversationId],
    queryFn: () => api.get(`/messages/recordings?conversation_id=${conversationId}`).then(r => r.data),
    enabled: isCallRecordingEnabled(),
  });

  if (!data?.recordings?.length) return <p className="text-sm text-muted-foreground">No recordings.</p>;

  return (
    <ul className="space-y-2">
      {data.recordings.map((rec: RecordingMetadataOut) => (
        <li key={rec.recording_id} className="flex items-center justify-between p-2 rounded border">
          <div>
            <p className="text-sm font-medium">{new Date(rec.created_at * 1000).toLocaleString()}</p>
            <p className="text-xs text-muted-foreground">
              {rec.duration_seconds ? `${Math.floor(rec.duration_seconds / 60)}m ${rec.duration_seconds % 60}s` : "—"}
              {" · "}
              {rec.file_size_bytes ? `${(rec.file_size_bytes / 1024 / 1024).toFixed(1)} MB` : "—"}
            </p>
          </div>
          {rec.download_url && (
            <Button size="sm" variant="outline" asChild>
              <a href={rec.download_url} download>Download</a>
            </Button>
          )}
        </li>
      ))}
    </ul>
  );
}
```

Add `RecordingMetadataOut` TypeScript interface to `frontend/src/api/types.ts` mirroring `app/routers/call_recording.py`'s response model. Render `RecordingsPanel` in the conversation info / detail panel — the same dropdown or side panel that shows conversation metadata, participants, and pinned messages.

### 4.2 Add `call_recording_available` Timeline Message

See CALL-009 section 4.1. Once implemented, add a `MessageBubble` render case for `system_event === "call_recording_available"` that shows a "Call Recording Available" card with a "Download" link pointing to `GET /messages/recordings/{recording_id}/download`. Invalidate the `["recordings", conversationId]` query key on receiving a `call_recording_available` timeline message to refresh `RecordingsPanel` automatically.

### 4.3 Fix Concurrent Recording Creation Race

In `app/services/call_recording_store.py:117`, add:

```python
from boto3.dynamodb.conditions import Attr
# Check for existing active recording first
existing = get_active_recording_for_call(call_id)
if existing:
    raise ValueError(f"Active recording already exists for call {call_id}")
```

Or use a conditional put with a DDB `ConditionExpression` on the `ByCallIdCreatedAt` GSI to enforce at-most-one `pending_consent` record per call.

### 4.4 Verify `AbortController` in Upload Path

Review `useCallRecording.ts:270-302` to confirm the presigned PUT uses an `AbortController` tied to the hook's `useEffect` cleanup. If not, add one. On component unmount, if the upload is in progress, the upload should be allowed to complete (do not abort) but state updates should be guarded by `if (mounted)` to avoid React unmount warnings.

### 4.5 Dev/Prod Parity (SECOPS-007)

The `VITE_CALL_RECORDING_ENABLED` frontend flag and `CALL_RECORDING_ENABLED` backend flag are both configurable env vars. In dev, both default to `"1"` (enabled). The feature-flag pattern follows SECOPS-007: same code path, flag-selected behavior. The S3 upload path uses `S.dev_mode` to select the `/mock/s3/` URL (CALL-009, section 2.2). No `dev_mode`-only branching exists in the `ConversationView` integration code — all the flag checks are done once at the `callRecordingEnabled` computed variable (`:696`), which is passed as the `enabled` prop to the hook.

---

## 5. Testing, Verification & Rollout

### 5.1 Pytest Unit Tests

**File**: `tests/test_call_recording_integration.py` (571 lines, exists)

Verify presence of:
- `test_full_recording_lifecycle`: Create call session, create recording, consent, presign, complete upload, download — all via HTTP test client with moto S3+DDB mocks.
- `test_recording_disabled_returns_503`: Set `S.call_recording_enabled = False`; verify all recording endpoints return 503.
- `test_list_recordings_by_conversation_filters_correctly`: Two recordings in different conversations; `conversation_id` filter returns only the right one.
- `test_download_returns_403_for_non_participant`: Third party cannot download.

Add:
- `test_concurrent_recording_request_returns_409`: Two simultaneous `/recording/request` calls for the same call; second returns conflict (once gap 4.3 is implemented).

### 5.2 Playwright E2E Tests

**File**: `frontend/e2e/call-recording-integration.spec.ts` (601 lines, exists)

Key scenarios to verify coverage:
1. Alice and Bob in connected call; Alice clicks Record; Bob sees consent dialog; Bob clicks "Allow Recording"; REC badge appears in both overlays.
2. Alice ends call; toast "Uploading call recording..." appears; then "Call recording saved."
3. After upload, `GET /messages/recordings?conversation_id={id}` returns a recording with `status=ready`.
4. `RecordingsPanel` (once implemented): panel shows recording with download link; download link navigates to a file.
5. `VITE_CALL_RECORDING_ENABLED=false` → Record button hidden from controls.
6. Bob declines consent → toast "Recording declined" shown to Alice; no REC badge.
7. Feature flag `CALL_RECORDING_ENABLED=0` (backend) → `/recording/request` returns 503.

### 5.3 Manual QA

1. With two Chrome windows, start a video call.
2. Click Record in one window; accept in the other; verify REC badge and duration counter.
3. End the call after 30 seconds; verify upload toast sequence.
4. Hard-refresh the page while recording is active; verify "Recording in progress" browser dialog appears.
5. Navigate to the conversation info panel (once `RecordingsPanel` is implemented); verify the recording appears with correct duration, file size, and a working Download link.
6. In an incognito window (third party), attempt `GET /messages/recordings/{id}/download` with Alice's recording ID; verify 403.

### 5.4 Rollback

Set `VITE_CALL_RECORDING_ENABLED=false` and redeploy frontend to hide the Record button. Existing recordings and DDB records are unaffected. The backend endpoints remain live (for API access) but the UI hides all entry points.

**Effort for remaining gaps**:
- Gap 4.1 (`RecordingsPanel`): **M** (2 days — component, query integration, types).
- Gap 4.2 (timeline message): handled by CALL-009 gap 4.1.
- Gap 4.3 (race condition fix): **S** (0.5 day).
- Gap 4.4 (AbortController audit): **S** (0.5 day).

Implement in order: race condition fix first (data integrity), then `RecordingsPanel` for discoverability.
