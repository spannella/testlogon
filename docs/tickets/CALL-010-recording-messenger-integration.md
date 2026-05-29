# CALL-010: Wire Call Recording into Messenger ConversationView

**Status**: Implemented
**Author**: Engineering
**Date**: 2026-05-25
**Priority**: High
**Estimated effort**: 3-5 days
**Dependencies**: CALL-009 (Call Recording — fully implemented but disconnected)

> **NOTE: This integration is FULLY IMPLEMENTED.** `useCallRecording` is imported and instantiated in `ConversationView.tsx` (see `:51,640`). All 8 recording props are passed to `<CallSessionOverlay>`. The state-sync `useEffect`, `beforeunload` listener, upload toast `useEffect`, and `stopRecording()` in `onEnd`/`onDismiss` are all present. The `isCallRecordingEnabled` feature flag exists in `featureFlags.ts:126-127`. See Codebase References at the bottom.

---

## 1. Overview & Motivation

### Problem Statement

The call recording system (CALL-009) is **fully built** across all layers of the stack — backend endpoints, DynamoDB store, frontend recording hook, state machine events, SSE event types, and overlay UI props — but it is **never activated**. The `useCallRecording` hook is not imported or instantiated anywhere. The recording-related props on `<CallSessionOverlay>` (`isRecording`, `recordingDuration`, `onRequestRecording`, `onStopRecording`, `recordingEnabled`, `showRecordingConsent`, `recordingConsentFrom`, `onConsentRecording`) all receive their default values of `undefined`/`false`, rendering the entire feature invisible to users.

This ticket covers the integration ("glue") code needed to connect the existing pieces and make call recording functional end-to-end.

### Goals

1. Import and instantiate `useCallRecording` inside `ConversationView.tsx`, passing it the correct streams, call ID, and connected state.
2. Wire SSE recording events from `useMessagingStream` through the call state machine reducer so the UI reacts to remote recording actions.
3. Pass all recording-derived props to `<CallSessionOverlay>` so the Record button, REC indicator, and consent dialog appear during connected calls.
4. Add a frontend feature flag (`VITE_CALL_RECORDING_ENABLED`) so the feature can be toggled without redeployment.
5. Handle edge cases: call ends during recording, recording upload after call teardown, page refresh mid-recording.
6. Provide a post-call recording access path so users can find and download past recordings.
7. Add E2E and unit tests covering the integration wiring, consent flow UI, recording indicator visibility, and download access.

### What Already Exists (Inventory)

| Layer | File | Status |
|-------|------|--------|
| Backend endpoints | `app/routers/call_recording.py` | Complete: request, consent, decline, presign, complete, download, list, delete |
| Backend data model | `app/services/call_recording_store.py` | Complete: `CallRecordingRecord` dataclass, CRUD, status transitions |
| Backend signaling | `app/services/messaging_call_signaling.py` | Complete: 5 recording types in `ALLOWED_SIGNALING_TYPES` and `STATE_ALLOWED_SIGNALING_TYPES["connected"]` |
| Backend settings | `app/core/settings.py` | Complete: 8 recording config fields (`call_recording_enabled`, max duration, TTLs, etc.) |
| Frontend hook | `frontend/src/hooks/useCallRecording.ts` | Complete: MediaRecorder lifecycle, consent flow, presigned upload, SSE event listener |
| Frontend state machine | `frontend/src/pages/messages/callStateMachine.ts` | Complete: 6 recording events, `recordingState`/`recordingId`/`recordingRequestedBy` fields |
| Frontend overlay UI | `frontend/src/pages/messages/CallSessionOverlay.tsx` | Complete: `Props` interface has all recording props, `CallControls` renders Record button + REC indicator + consent dialog |
| Frontend SSE | `frontend/src/hooks/useMessagingStream.ts` | Complete: 5 `call.recording_*` types in `EVENT_TYPES` array, dispatched via `messaging:call-event` CustomEvent |
| Frontend feature flag | `frontend/src/lib/featureFlags.ts` | Complete: `isCallRecordingEnabled()` at line 126-127 |

### What Was Missing (Now Implemented)

<!-- NOTE: All 5 items below have been implemented: -->

1. **`ConversationView.tsx`**: `useCallRecording` imported (`:51`) and instantiated (`:640-648`). Recording props passed to `<CallSessionOverlay>`.
2. **`ConversationView.tsx`**: State-sync `useEffect` (`:650-659`) mirrors hook state to `callStateReducer`. The hook handles SSE events internally; the `onCallEvent` listener does NOT need to dispatch recording events.
3. **`featureFlags.ts`**: `isCallRecordingEnabled()` exists at `:126-127`.
4. **Post-call UI**: Toast notifications for upload state (`:673-680`). `GET /messages/recordings` endpoint exists at `call_recording.py:439`.
5. **Recording cleanup on call teardown**: `stopRecording()` called before teardown in the `onEnd` handler (see `:1353-1354`).

---

## 2. Current State Analysis

### 2.1 ConversationView Call Integration (Lines 474-1117)

The call system is wired in `ConversationView.tsx` as follows:

1. **State machine**: `const [callMachine, dispatchCall] = React.useReducer(callStateReducer, undefined, createInitialCallMachineState)` (line 85).
2. **RTC hook**: `useRtcPeerConnection(...)` receives `callMachine.phase`, `callMachine.callId`, etc. (lines 477-490). Returns `rtcResources`, `rtcLocalStream`, `rtcRemoteStream`.
3. **Media capture**: `useMediaCapture()` acquires local camera/mic (line 89).
4. **SSE event handler**: `useEffect` on `messaging:call-event` CustomEvent (lines 610-650). Dispatches `INCOMING_INVITE`, `REMOTE_ACCEPT`, `REMOTE_DECLINE`, `END_REMOTE` based on `eventType`. **Does not handle any `call.recording_*` events.**
5. **Overlay session object**: Built from `callMachine` state (lines 694-705). **Does not include any recording props.**
6. **`<CallSessionOverlay>`** (lines 1027-1116): Receives `session`, `isBusy`, `localStream`, `remoteStream`, `peerConnection`, `isMuted`, `isCameraOff`, and all action handlers. **Recording props are absent** — `isRecording`, `recordingDuration`, `onRequestRecording`, `onStopRecording`, `recordingEnabled`, `showRecordingConsent`, `recordingConsentFrom`, `onConsentRecording` are all undefined.

### 2.2 useCallRecording Hook Interface

The hook (`frontend/src/hooks/useCallRecording.ts`) accepts:

```typescript
interface UseCallRecordingParams {
  callId: string | null | undefined;
  userId: string;
  localStream: MediaStream | null | undefined;
  remoteStream: MediaStream | null | undefined;
  isConnected: boolean;
  enabled?: boolean;
}
```

And returns:

```typescript
interface UseCallRecordingReturn {
  recordingState: RecordingState;  // "idle"|"requesting"|"consent_pending"|"recording"|"stopping"|"uploading"|"complete"|"error"
  recordingId: string | null;
  duration: number;
  isInitiator: boolean;
  requestRecording: () => Promise<void>;
  respondToRequest: (accept: boolean) => Promise<void>;
  stopRecording: () => void;
  error: string | null;
  consentPendingFrom: string | null;
}
```

The hook **internally** listens to `messaging:call-event` CustomEvents for the 5 recording SSE types (lines 105-136). This means the hook is self-contained for SSE event handling — it does NOT require the ConversationView to dispatch recording events through `callStateReducer`. However, the state machine also has recording events for keeping `callMachine.recordingState` in sync (useful for derived UI state in the overlay session object).

### 2.3 CallSessionOverlay Props Interface

The overlay (`CallSessionOverlay.tsx`, lines 41-63) already declares all needed recording props:

```typescript
interface Props {
  // ... existing call props ...
  isRecording?: boolean;
  recordingDuration?: number;
  onRequestRecording?: () => void;
  onStopRecording?: () => void;
  recordingEnabled?: boolean;
  showRecordingConsent?: boolean;
  recordingConsentFrom?: string | null;
  onConsentRecording?: (accept: boolean) => void;
}
```

These props are consumed by:
- `CallControls` component (lines 157-211): Shows Record button when `recordingEnabled` is truthy.
- Recording indicator (lines 389-394 for video, 483-488 for audio): Shows "REC" badge when `isRecording` is truthy.
- Recording consent dialog (lines 414-431 for video, 507-523 for audio): Shows consent UI when `showRecordingConsent` is truthy.

### 2.4 Call State Machine Recording Events

`callStateMachine.ts` (lines 161-184) already handles 6 recording events:

| Event | Guards | Effect |
|-------|--------|--------|
| `RECORDING_REQUEST_SENT` | phase === "connected" | `recordingState = "requesting"` |
| `RECORDING_REQUEST_RECEIVED` | phase === "connected" | `recordingState = "consent_pending"`, stores `recordingRequestedBy` |
| `RECORDING_ACCEPTED` | phase === "connected" | `recordingState = "recording"`, stores `recordingId` |
| `RECORDING_DECLINED` | phase === "connected" | `recordingState = "idle"`, clears recording fields |
| `RECORDING_STARTED` | phase === "connected" | `recordingState = "recording"`, stores `recordingId` |
| `RECORDING_STOPPED` | (none) | `recordingState = "stopped"`, clears `recordingRequestedBy` |

These events are defined but **never dispatched** from any code.

### 2.5 SSE Event Flow

The SSE pipeline is complete:

1. Backend emits `call.recording_*` typed SSE events via the messaging event stream.
2. `useMessagingStream.ts` registers `addEventListener` for all 5 types (lines 118-122).
3. `handleEvent` dispatches them as `messaging:call-event` CustomEvents (lines 69-78).
4. `useCallRecording` listens to `messaging:call-event` and handles the 5 types internally (lines 105-136).

So the SSE-to-hook pipeline works without any changes. The gap is that `useCallRecording` is never instantiated.

---

## 3. Technical Design

### 3.1 Frontend Feature Flag

Add to `frontend/src/lib/featureFlags.ts`:

```typescript
export const callRecordingEnabled = toBool(env.VITE_CALL_RECORDING_ENABLED, false);
export const callRecordingKillSwitch = toBool(env.VITE_CALL_RECORDING_KILL_SWITCH, false);
export const isCallRecordingEnabled = () => callRecordingEnabled && !callRecordingKillSwitch;
```

Add to `frontend/.env.local.example` and `frontend/.env.local`:

```
VITE_CALL_RECORDING_ENABLED=true
```

The backend already has `call_recording_enabled = True` in dev mode (defaulting to `"1"` in `settings.py`). The frontend flag gates whether the Record button appears in the overlay; the backend flag independently gates whether the API endpoints accept requests.

### 3.2 Wiring useCallRecording in ConversationView.tsx

#### Import

Add at the top of `ConversationView.tsx`:

```typescript
import { useCallRecording } from "@/hooks/useCallRecording";
import { isCallRecordingEnabled } from "@/lib/featureFlags";
```

#### Instantiation

Add after the `useRtcPeerConnection` block (after line 496), inside the `ConversationView` function body:

```typescript
// ── Call recording hook ───────────────────────────────────────
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

**Key design decisions**:

1. **`enabled`** is derived from both `callsEnabled` (DM with a partner, WebRTC feature flag on) and `isCallRecordingEnabled()`. This prevents the hook from registering its event listener or making API calls when recording is disabled.
2. **`localStream`** uses the same fallback chain as the overlay: `rtcLocalStream ?? mediaCapture.stream ?? null`.
3. **`isConnected`** maps directly to `callMachine.phase === "connected"`. The hook auto-stops recording when this becomes false (line 305-309 of `useCallRecording.ts`).

#### Sync Hook State to State Machine

While `useCallRecording` handles SSE events internally, the `callMachine.recordingState` field should stay in sync so that future features can read recording state from the centralized state machine. Add a `useEffect` that mirrors hook state changes to the reducer:

```typescript
React.useEffect(() => {
  if (callRecording.recordingState === "recording" && callRecording.recordingId) {
    dispatchCall({ type: "RECORDING_STARTED", recordingId: callRecording.recordingId });
  } else if (callRecording.recordingState === "consent_pending" && callRecording.consentPendingFrom) {
    dispatchCall({ type: "RECORDING_REQUEST_RECEIVED", requestedBy: callRecording.consentPendingFrom });
  } else if (callRecording.recordingState === "consent_pending" && callRecording.isInitiator) {
    dispatchCall({ type: "RECORDING_REQUEST_SENT" });
  } else if (callRecording.recordingState === "idle" && callMachine.recordingState !== "idle") {
    dispatchCall({ type: "RECORDING_DECLINED" });
  } else if (["stopping", "uploading", "complete"].includes(callRecording.recordingState)) {
    dispatchCall({ type: "RECORDING_STOPPED" });
  }
}, [callRecording.recordingState, callRecording.recordingId, callRecording.consentPendingFrom, callRecording.isInitiator]);
```

This is a one-way sync (hook -> state machine). The hook is the source of truth; the state machine is a mirror for derived state.

#### Pass Props to CallSessionOverlay

Update the `<CallSessionOverlay>` JSX (currently lines 1027-1116) to include recording props:

```typescript
<CallSessionOverlay
  session={overlaySession}
  isBusy={callActionMutation.isPending}
  localStream={rtcLocalStream ?? mediaCapture.stream ?? null}
  remoteStream={rtcRemoteStream ?? null}
  peerConnection={rtcResources?.peerConnection ?? null}
  onAccept={async () => { /* existing */ }}
  onDecline={() => { /* existing */ }}
  onEnd={() => { /* existing */ }}
  isMuted={isMuted}
  isCameraOff={isCameraOff}
  onToggleMute={() => { /* existing */ }}
  onToggleCamera={() => { /* existing */ }}
  onDismiss={() => {
    clearCallTimeout();
    teardownCallResources(callResourcesRef.current);
    mediaCapture.release();
    setIsMuted(false);
    setIsCameraOff(false);
    dispatchCall({ type: "RESET" });
  }}
  // ── Recording props (CALL-010) ──
  isRecording={callRecording.recordingState === "recording"}
  recordingDuration={callRecording.duration}
  onRequestRecording={() => callRecording.requestRecording()}
  onStopRecording={() => callRecording.stopRecording()}
  recordingEnabled={callRecordingEnabled}
  showRecordingConsent={
    callRecording.recordingState === "consent_pending" &&
    !!callRecording.consentPendingFrom
  }
  recordingConsentFrom={callRecording.consentPendingFrom}
  onConsentRecording={(accept) => callRecording.respondToRequest(accept)}
/>
```

**Prop derivation logic**:

| Overlay Prop | Derived From | Notes |
|-------------|-------------|-------|
| `isRecording` | `callRecording.recordingState === "recording"` | Shows REC indicator and changes Record button to Stop |
| `recordingDuration` | `callRecording.duration` | Seconds counter, updated by hook's internal timer |
| `onRequestRecording` | `callRecording.requestRecording` | Async; makes POST to `/recording/request`, transitions to `consent_pending` |
| `onStopRecording` | `callRecording.stopRecording` | Stops MediaRecorder, initiates upload |
| `recordingEnabled` | `callRecordingEnabled` (local const) | Shows/hides the Record button in CallControls |
| `showRecordingConsent` | State is `consent_pending` AND `consentPendingFrom` is set | Only true for the NON-initiating peer |
| `recordingConsentFrom` | `callRecording.consentPendingFrom` | User ID of the peer who requested recording; displayed in consent dialog |
| `onConsentRecording` | `callRecording.respondToRequest` | Calls `/recording/consent` or `/recording/decline` |

### 3.3 SSE Recording Events and the State Machine

The SSE event flow works as follows:

```
Backend SSE ──> useMessagingStream ──> CustomEvent("messaging:call-event")
                                           │
                                           ├──> useCallRecording (internal listener, lines 105-136)
                                           │    Updates hook state: recordingState, consentPendingFrom, recordingId
                                           │
                                           └──> ConversationView onCallEvent listener (lines 610-650)
                                                Currently does NOT handle call.recording_* events
```

**Decision: Do NOT add recording event dispatches to the ConversationView `onCallEvent` listener.** The `useCallRecording` hook already handles all 5 recording SSE events internally. Adding duplicate handling in `onCallEvent` would cause state divergence and race conditions. Instead, the `useEffect` sync described in section 3.2 mirrors hook state to the state machine as a passive follower.

If in the future we need the state machine to be the primary source of truth for recording state (e.g., for server-side recording in group calls), we would remove the internal listener from `useCallRecording` and add dispatches to `onCallEvent`. For v1, the current approach is simpler and avoids double-handling.

### 3.4 Edge Case: Call Ends During Recording

When the call ends (user clicks "End" or remote peer hangs up), the following sequence occurs:

1. `callMachine.phase` transitions to `"ended"` (via `END_LOCAL` or `END_REMOTE`).
2. `useCallRecording`'s `useEffect` on `isConnected` (lines 305-309) detects `isConnected` became `false` while `state === "recording"`, and calls `stopRecording()`.
3. `stopRecording()` calls `mediaRecorderRef.current.stop()`, assembles the Blob, transitions to `"uploading"`, and begins the presigned upload flow.
4. Meanwhile, `teardownCallResources()` is called (via the phase-change effect on line 512), which stops all stream tracks.

**Problem**: Step 4 may execute before step 3 completes. If `teardownCallResources` stops the stream tracks before `MediaRecorder.stop()` fires `dataavailable`, the final chunk may be lost.

**Solution**: Modify the `onDismiss` handler and the teardown effect to call `callRecording.stopRecording()` BEFORE tearing down resources. The updated `onDismiss`:

```typescript
onDismiss={() => {
  // Stop recording before tearing down call resources
  if (callRecording.recordingState === "recording") {
    callRecording.stopRecording();
  }
  clearCallTimeout();
  teardownCallResources(callResourcesRef.current);
  mediaCapture.release();
  setIsMuted(false);
  setIsCameraOff(false);
  dispatchCall({ type: "RESET" });
}}
```

Additionally, the `onEnd` handler should also stop recording before ending the call:

```typescript
onEnd={() => {
  // Stop recording before ending call
  if (callRecording.recordingState === "recording") {
    callRecording.stopRecording();
  }
  if (!callMachine.callId) {
    dispatchCall({ type: "END_LOCAL" });
    return;
  }
  callActionMutation.mutate(
    { action: "end", callId: callMachine.callId },
    {
      onSuccess: () => dispatchCall({ type: "END_REMOTE" }),
      onError: () => dispatchCall({ type: "FAIL" }),
    },
  );
}}
```

The `useCallRecording` hook's `stopRecording` is synchronous (it calls `recorder.stop()` and transitions state immediately). The actual upload is async and continues in the background even after call teardown, because the Blob has already been collected by `ondataavailable`.

### 3.5 Edge Case: Page Refresh During Recording

If the user refreshes the page during an active recording:

1. `MediaRecorder` data in memory is lost — there is no IndexedDB fallback in v1.
2. The backend recording record remains in `"recording"` status.
3. On page reload, `useCallRecording` is re-instantiated with `callId: undefined` (since the call state machine resets to idle), so no cleanup occurs.

**Mitigation for v1**: Accept the data loss. The recording record will remain in `"recording"` status until a cleanup job or manual intervention sets it to `"failed"`. A `beforeunload` event listener can warn the user:

```typescript
React.useEffect(() => {
  if (callRecording.recordingState === "recording") {
    const handler = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = "A recording is in progress. If you leave, the recording will be lost.";
    };
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }
}, [callRecording.recordingState]);
```

**Future enhancement (post-v1)**: Periodically flush `MediaRecorder` chunks to IndexedDB. On page load, detect orphaned chunks and attempt to resume upload.

### 3.6 Edge Case: Recording Upload Progress

The `useCallRecording` hook's `stopRecording` function (lines 270-302) uses `fetch()` for the presigned PUT upload. `fetch()` does not support upload progress events.

**Mitigation for v1**: The hook transitions through `stopping` -> `uploading` -> `complete` states. The overlay is already dismissed by the time upload begins (the call has ended). Show a toast notification for upload progress:

```typescript
React.useEffect(() => {
  if (callRecording.recordingState === "uploading") {
    toast.loading("Uploading call recording...", { id: "recording-upload" });
  } else if (callRecording.recordingState === "complete") {
    toast.success("Call recording saved.", { id: "recording-upload" });
  } else if (callRecording.recordingState === "error") {
    toast.error(`Recording upload failed: ${callRecording.error ?? "Unknown error"}`, { id: "recording-upload" });
  }
}, [callRecording.recordingState, callRecording.error]);
```

**Future enhancement**: Replace `fetch` with `XMLHttpRequest` in `useCallRecording.ts` for progress events, and surface a progress percentage in the toast.

### 3.7 Post-Call Recording Access

Users need a way to find and download past recordings. Two access paths are needed:

#### Path A: Conversation Info Panel (Primary)

Add a "Recordings" section to the conversation detail/info area. This queries `GET /messages/recordings` (which already exists, line 439 of `call_recording.py`) filtered by the current conversation.

However, the existing `GET /messages/recordings` endpoint returns ALL recordings for the user (table scan). A more efficient approach uses the existing `GET /messages/calls/{call_id}/recording` endpoint, but that requires knowing the `call_id`. Since the conversation timeline already contains `call.end` system messages with `call_id` metadata, the frontend can extract call IDs from the conversation message history.

**Recommended approach for v1**: Add a new API endpoint (or reuse the existing one with a query param):

```
GET /messages/recordings?conversation_id={convoId}
```

The backend already has `get_recordings_for_conversation()` in `call_recording_store.py` (lines 172-185) which queries the `ByConversationCreatedAt` GSI. This just needs a router endpoint that accepts `conversation_id` as a query parameter, filtering the existing `list_user_recordings` endpoint.

The frontend component (`RecordingsList.tsx`) would be a simple list inside the conversation DropdownMenu or a dedicated panel:

```typescript
const { data } = useQuery({
  queryKey: ["recordings", convoId],
  queryFn: () => apiClient.get(`/messages/recordings?conversation_id=${convoId}`).then(r => r.data),
  enabled: isCallRecordingEnabled(),
});
```

Each item shows: date, duration, file size, and a Download button that opens the presigned URL from `GET /messages/recordings/{recording_id}/download`.

#### Path B: Recording System Message in Timeline

When `useCallRecording` transitions to `"complete"`, insert a system message into the conversation via the existing `sendTextMessage` endpoint (with a special `kind` or metadata field), or rely on the backend `complete_upload` endpoint to insert one. The CALL-009 spec (section 3.10) describes this pattern. The backend `complete_upload` endpoint does NOT currently insert a system message — this should be added as part of this ticket.

For v1, the toast notification ("Call recording saved.") plus the conversation info panel is sufficient. System message insertion is deferred.

---

## 4. Implementation Plan

### Phase 1: Feature Flag + Hook Wiring (Day 1) — IMPLEMENTED

| File | Change | Status |
|------|--------|--------|
| `frontend/src/lib/featureFlags.ts:126-127` | `isCallRecordingEnabled()` feature flag | DONE |
| `frontend/src/pages/messages/ConversationView.tsx:51,52` | Import `useCallRecording` and `isCallRecordingEnabled` | DONE |
| `frontend/src/pages/messages/ConversationView.tsx:639-648` | Instantiate hook, pass recording props to overlay | DONE |

### Phase 2: State Sync + Edge Cases (Day 2) — IMPLEMENTED

| File | Change | Status |
|------|--------|--------|
| `ConversationView.tsx:650-659` | `useEffect` to sync hook state to state machine | DONE |
| `ConversationView.tsx:662-670` | `beforeunload` listener during recording | DONE |
| `ConversationView.tsx:673-680` | Upload progress toasts | DONE |
| `ConversationView.tsx:1353-1354` | Stop recording in `onEnd` handler | DONE |

### Phase 3: Post-Call Recording Access (Day 3) — PARTIALLY IMPLEMENTED

| File | Change | Status |
|------|--------|--------|
| `app/routers/call_recording.py:443-448` | `conversation_id` query param on `list_user_recordings` | DONE |
| `frontend/src/pages/messages/RecordingsPanel.tsx` | Recordings list panel | NOT DONE |

<!-- NOTE: RecordingsPanel.tsx does NOT exist — new implementation required. There is no frontend component that consumes the GET /messages/recordings endpoint. -->

### Phase 4: E2E + Unit Tests (Days 4-5) — E2E IMPLEMENTED

| File | Lines | Status |
|------|-------|--------|
| `frontend/e2e/call-recording-integration.spec.ts` | 601 | DONE |
| `tests/test_call_recording_integration.py` | — | NOT DONE |

<!-- NOTE: tests/test_call_recording_integration.py does NOT exist — new implementation required -->

---

## Testing Strategy

### Unit Tests (pytest)

**Test file**: `tests/test_call_10.py`

**Mock setup**: moto mock for DynamoDB (call session tables). Mock RTCPeerConnection for frontend unit tests. Chromium fake media devices for E2E.

| Test Function | Description |
|---|---|
| `test_create_resource` | Create primary resource; verify stored correctly |
| `test_lifecycle_transitions` | Verify allowed state transitions succeed |
| `test_invalid_transition_rejected` | Invalid transition returns 409 |
| `test_authorization_check` | Non-participant returns 403 |
| `test_idempotent_operation` | Repeated call returns same result |
| `test_cleanup_on_end` | Resources cleaned up after call ends |

### Integration Tests

Cross-service tests with real DynamoDB Local:

1. Full call lifecycle through real DDB (invite -> accept -> connect -> end)
2. Signaling relay: offer/answer/ICE exchange between two sessions
3. State machine transitions verified end-to-end

### E2E Tests (Playwright)

**Test file**: `frontend/e2e/call-10.spec.ts`

**Auth pattern**: `injectAuth(page, "alice")` for caller; `injectAuth(page, "bob")` for callee; separate browser contexts for two-peer tests

| # | Test Name | Assertion |
|---|---|---|
| 1 | Call invite creates session | POST invite -> 200 with call_id |
| 2 | Call accept transitions state | POST accept -> state = accepted |
| 3 | Signaling relay delivers events | POST signal -> SSE event received by peer |
| 4 | Connected state shows overlay | Both peers reach connected; overlay visible |
| 5 | End call cleans up resources | POST end -> state = ended; tracks stopped |
| 6 | Call overlay shows correct UI | Ringing/connected/ended states render correctly |
| 7 | Feature flag gates functionality | Disabled flag -> call button hidden |
| 8 | Unauthenticated returns 401 | No session -> 401 |
| 9 | Non-participant returns 403 | Third party -> 403 |
| 10 | Non-existent call returns 404 | Invalid call_id -> 404 |
| 11 | Invalid transition returns 409 | End already-ended call -> 409 |

**Negative tests**: 401 unauthenticated, 403 non-participant, 404 non-existent call, 409 invalid transition, 422 invalid payload

**Edge cases**: Concurrent accept/decline, call timeout (30s), ICE restart during connected state, tab backgrounding, network offline

### Test Data Requirements

Create DM conversation between Alice and Bob in `beforeAll`. Use `--use-fake-device-for-media-stream` Chromium flag for media tests.

**Test users**: Alice (USER, caller), Bob (USER, callee), Root (ROOT, admin for feature flags)

### CI/Pipeline

Serial execution (WebRTC requires sequential peer setup). `VITE_MESSAGING_WEBRTC_DIRECT_CALL_ENABLED=true`. Retry-safe.

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What's Needed | Status | Can Overlap? |
|---|---|---|---|
| CALL-009 | useCallRecording hook and CallSessionOverlay recording props | Implemented | No -- must merge after |

### Depended On By

No downstream dependents identified.

### Merge Strategy

Sequential after CALL-009. Integration glue code in ConversationView.tsx. Feature-flag-gated.

### Merge Checklist

- [ ] Backend endpoint/service changes registered in `app/main.py`
- [ ] Frontend hooks and components created/modified
- [ ] Settings and feature flags configured
- [ ] DDB tables added if needed (`scripts/local-ddb-init.py`)
- [ ] E2E tests pass in CI
- [ ] No breaking changes to existing call endpoints

---

## Codebase References

| File | Lines | What |
|------|-------|------|
| `frontend/src/pages/messages/ConversationView.tsx` | 51 | `import { useCallRecording }` |
| `frontend/src/pages/messages/ConversationView.tsx` | 52 | `import { isCallRecordingEnabled }` |
| `frontend/src/pages/messages/ConversationView.tsx` | 639 | `callRecordingEnabled` computed flag |
| `frontend/src/pages/messages/ConversationView.tsx` | 640-648 | `useCallRecording` hook instantiation |
| `frontend/src/pages/messages/ConversationView.tsx` | 650-659 | `useEffect` syncing hook state to state machine |
| `frontend/src/pages/messages/ConversationView.tsx` | 662-670 | `beforeunload` listener during recording |
| `frontend/src/pages/messages/ConversationView.tsx` | 673-680 | Upload progress toast `useEffect` |
| `frontend/src/pages/messages/ConversationView.tsx` | 1353-1354 | `stopRecording()` called before `endCall` in `onEnd` |
| `frontend/src/lib/featureFlags.ts` | 126-127 | `callRecordingEnabled` + `isCallRecordingEnabled()` |
| `frontend/src/hooks/useCallRecording.ts` | 1-322 | Complete recording hook (MediaRecorder, consent, upload) |
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | 42-70 | Props interface with all recording fields |
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | 222-235 | Recording button in CallControls |
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | 425 | REC indicator badge |
| `app/routers/call_recording.py` | 439-455 | `GET /messages/recordings` with `conversation_id` query param |
| `frontend/e2e/call-recording-integration.spec.ts` | 1-601 | E2E integration tests |
