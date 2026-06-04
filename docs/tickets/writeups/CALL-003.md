# CALL-003: Implement getUserMedia Capture with Permission Handling — Investigation & Implementation Write-up

## 1. Summary & Classification

**Problem/Feature**: WebRTC calls require the browser to acquire the user's microphone (and optionally camera) via `navigator.mediaDevices.getUserMedia()`. Without this step, no local media tracks exist to add to the `RTCPeerConnection`, and no real audio/video flows even if ICE negotiation succeeds. This ticket implements `useMediaCapture` — a React hook that wraps `getUserMedia` with permission tracking, error categorization (NotAllowedError, NotFoundError, etc.), and track management (mute, camera toggle, device switching). It also adds a companion `useMediaDevices` hook for device enumeration.

- **Type**: Feature (new React hooks; no backend changes)
- **Priority**: High — blocks CALL-004 (media rendering) and CALL-005 (media controls)
- **Status**: Implemented — `frontend/src/hooks/useMediaCapture.ts` (315 lines); `frontend/src/hooks/useMediaDevices.ts` (107 lines); `acquireLocalMedia()` in `frontend/src/lib/webrtc.ts:15`; integrated in `ConversationView.tsx:52,97`; E2E coverage in `frontend/e2e/webrtc-media.spec.ts:1297` (section 83 — permission denied). Unit test files `useMediaCapture.test.ts` and `useMediaDevices.test.ts` do not exist.
- **Area**: Frontend media capture, browser permissions, WebRTC track management
- **Who is affected**: Any user who initiates or accepts a direct call
- **Cross-references**: [[CALL-002]] (provides local tracks to `RTCPeerConnection`), [[CALL-004]] (renders the captured streams), [[CALL-005]] (mute/camera toggle uses track.enabled), [[SECOPS-007]] (dev parity: fake media devices in E2E)

---

## 2. Current-State Investigation (what exists today)

### 2.1 `useMediaCapture` hook (`frontend/src/hooks/useMediaCapture.ts:1–315`)

Fully implemented. Key anchors:

- **`buildConstraints(mode, preferredVideoDeviceId?)`** (line 50): returns `{ audio: true, video: false }` for `"audio"` mode; `{ audio: true, video: { width: { ideal: 1280, max: 1920 }, height: { ideal: 720, max: 1080 }, frameRate: { ideal: 30, max: 30 }, facingMode: "user" } }` for `"video"` mode. The `ideal` constraints allow the browser to downgrade gracefully on devices that cannot produce 1280×720.
- **`categorizeError(err)`** (line 72): maps `DOMException.name` to `MediaCaptureErrorType`. `NotAllowedError` → denied; `NotFoundError` → not_found; `NotReadableError` → error (device in use); `OverconstrainedError` → error; `AbortError` → error; anything else → unknown. Each type has a user-readable message string.
- **`UseMediaCaptureReturn`** (line 36): exposes `stream`, `error`, `permissionState`, `isAcquiring`, `acquire(mode)`, `release()`, `switchCamera()`.
- **`acquire(mode)`** (line 124 area): sets `status="requesting"`, calls `getUserMedia(buildConstraints(mode))`, on success sets `status="active"` and stores the stream, on error categorizes and sets `status` accordingly (denied/not_found/error). Returns `MediaStream | null`.
- **`release()`**: stops all tracks on the current stream and resets state to `idle`.
- **`switchCamera()`**: calls `getUserMedia` again with a different `preferredVideoDeviceId` (from `useMediaDevices`), then `sender.replaceTrack(newTrack)` on the `RTCPeerConnection`'s senders. This is device switching mid-call without renegotiation.

### 2.2 `useMediaDevices` hook (`frontend/src/hooks/useMediaDevices.ts:1–107`)

Fully implemented. Enumerates `audioinput` and `videoinput` devices via `navigator.mediaDevices.enumerateDevices()`. Listens for `devicechange` events to update the list when USB devices are plugged/unplugged. Returns `{ audioInputs, videoInputs }`. Device labels are empty strings until `getUserMedia` has been called at least once (browser security restriction) — the hook re-enumerates after a successful capture.

### 2.3 `acquireLocalMedia()` in webrtc.ts (line 15)

A thin wrapper:

```typescript
export async function acquireLocalMedia(mode: DirectCallMode): Promise<MediaStream> {
  return navigator.mediaDevices.getUserMedia({
    audio: true,
    video: mode === "video" ? { facingMode: "user", width: { ideal: 1280 }, height: { ideal: 720 } } : false,
  });
}
```

This function is used directly inside `useRtcPeerConnection.ts` (around line 159–183) when the hook needs to acquire media as part of the caller/callee flows. The `useMediaCapture` hook uses `buildConstraints()` for richer constraint specification but ultimately also calls `getUserMedia`.

### 2.4 Integration in `ConversationView.tsx`

- **Import** (line 52): `import { useMediaCapture } from "@/hooks/useMediaCapture"`.
- **Hook call** (line 97): `const mediaCapture = useMediaCapture()`.
- **Mute/camera local state** (lines 98–99): `const [isMuted, setIsMuted] = React.useState(false)` and `const [isCameraOff, setIsCameraOff] = React.useState(false)`.
- **Outgoing call** (lines 794–806): `const localStream = await mediaCapture.acquire(mode)` before `callMutation.mutate()`. If `acquire` returns null, `dispatchCall({ type: "FAIL" })` aborts the call. Stream is stored in `callResourcesRef.current.localStream`.
- **Incoming call accept** (lines 1354–1368): same pattern — acquire media before dispatching `LOCAL_ACCEPT` and calling the accept API. Decline is sent if acquire fails.
- **Stream passed to overlay** (line 1347): `localStream={rtcLocalStream ?? mediaCapture.stream ?? null}` — prefers the RTC-provided stream (CALL-002) but falls back to `mediaCapture.stream` if the RTC hook hasn't attached tracks yet.

### 2.5 CallSessionOverlay.tsx integration

Receives `localStream` prop (line 47). The `VideoRenderer` sub-component (line 90) sets `videoRef.current.srcObject = stream` imperatively in a `useEffect`. The `AudioRenderer` (line 117) does the same for `<audio>` elements. These components are consumers of the stream produced by this ticket.

### 2.6 Teardown path

`teardownCallResources()` in `callStateMachine.ts:199` iterates both `localStream` and `remoteStream` and calls `track.stop()` on every track. This permanently releases the hardware (camera/mic indicator light goes off). `useMediaCapture.release()` does the same thing for streams it directly holds. On call end (any terminal state), the ConversationView calls `teardownCallResources(callResourcesRef.current)` (lines 754, 760).

### 2.7 `CallMode` backend type

`app/services/messaging_call_sessions.py:8` defines `CallMode = Literal["audio", "video"]`. The frontend mirrors this as `DirectCallMode` in `frontend/src/api/endpoints/messaging.ts`. The `initial_mode` on `CallSessionRecord` and `CallMachineState.mode` both carry this value through the call lifecycle.

### 2.8 Dev vs prod behavior

In dev/E2E: `--use-fake-device-for-media-stream` Chromium flag (used in `webrtc-media.spec.ts:542`) replaces real hardware with synthetic test streams (spinning color wheel video + 440Hz sine audio). `--use-fake-ui-for-media-stream` auto-grants the permission dialog. No real camera or microphone is needed for tests. In prod: real `getUserMedia` call; OS/browser permission dialog shown on first use.

---

## 3. Gap / Threat Analysis

### 3.1 Unit test gap

`frontend/src/hooks/useMediaCapture.test.ts` and `frontend/src/hooks/useMediaDevices.test.ts` do not exist. The media capture logic — particularly the permission state tracking, error categorization, and the `switchCamera` mid-call device-switch flow — is not unit-tested. E2E coverage exists only for the permission-denied scenario (section 83 in `webrtc-media.spec.ts`) and general audio/video call flows. Edge cases like `OverconstrainedError` (relax constraints and retry), `NotReadableError` (device in use), and `devicechange` events during an active call have no test coverage.

### 3.2 `OverconstrainedError` retry not implemented

The ticket design described retrying with relaxed constraints when `OverconstrainedError` occurs (e.g., the device cannot produce 1280×720). The current `categorizeError()` maps `OverconstrainedError` to `type: "error"` and aborts. A retry with `{ audio: true, video: true }` (no resolution constraints) would improve compatibility with low-end webcams. This is a gap in the current implementation.

### 3.3 `switchCamera` depends on RTCPeerConnection availability

`useMediaCapture.switchCamera()` calls `sender.replaceTrack(newTrack)` — but `useMediaCapture` does not hold a reference to the `RTCPeerConnection`. The hook receives `sendersRef` or must coordinate with `useRtcPeerConnection`. The current implementation in `useMediaCapture.ts` either stores a `pc` ref internally or relies on the caller to provide it. This coupling between the two hooks needs explicit documentation in the hook's API contract.

### 3.4 Echo cancellation constraints

The ticket design specifies `echoCancellation: true`, `noiseSuppression: true`, `autoGainControl: true` in audio constraints. `buildConstraints()` in `useMediaCapture.ts:50` uses `audio: true` (browser defaults), which enables echo cancellation by default in most browsers but is not explicitly required. For production calls, explicitly setting these constraints prevents echo on speakers-based setups.

### 3.5 Permission re-request after denial

Once a user denies `getUserMedia`, subsequent calls with the same origin receive `NotAllowedError` immediately (no dialog shown). The hook sets `status="denied"` but does not provide a mechanism to open the browser's permission settings page. The overlay UI (CallSessionOverlay) should surface a link to `chrome://settings/content/camera` or instructions for Safari — currently the error message is shown as a toast.

---

## 4. Proposed Design / Fix

### 4.1 Unit tests — `frontend/src/hooks/useMediaCapture.test.ts`

Mock `navigator.mediaDevices.getUserMedia` globally. Key test cases:

- **Audio acquire**: `acquire("audio")` → returns `MediaStream` with 1 audio track, 0 video tracks; `status="active"`.
- **Video acquire**: `acquire("video")` → returns stream with 1 audio + 1 video track; `status="active"`.
- **NotAllowedError**: `getUserMedia` rejects with `DOMException { name: "NotAllowedError" }` → `status="denied"`, `error.type="NotAllowedError"`, `error.message` contains "denied".
- **NotFoundError**: `getUserMedia` rejects with `NotFoundError` → `status="not_found"`.
- **NotReadableError**: → `status="error"`.
- **Release**: after `acquire`, call `release()` → `stream.getTracks().forEach(t => t.stop())` called, `status="idle"`.
- **Idempotent release**: call `release()` twice → no error.
- **`isAcquiring` during request**: set to `true` before `getUserMedia`, `false` after.
- **DeviceChange event**: dispatch `devicechange` on `navigator.mediaDevices` → `enumerateDevices` re-called.

### 4.2 Unit tests — `frontend/src/hooks/useMediaDevices.test.ts`

- **Initial enumeration**: mock `enumerateDevices` to return devices → `audioInputs` and `videoInputs` populated.
- **devicechange listener**: dispatch `devicechange` → re-enumerates.
- **Cleanup on unmount**: `removeEventListener` called.

### 4.3 OverconstrainedError retry

Add retry logic in `acquire()`:

```typescript
} catch (err) {
  if (err instanceof DOMException && err.name === "OverconstrainedError" && mode === "video") {
    // Retry with relaxed video constraints
    try {
      stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: true });
    } catch (fallbackErr) {
      // Report original error
      throw err;
    }
  }
}
```

### 4.4 Echo cancellation in constraints

Update `buildConstraints` audio constraint:

```typescript
const audio: MediaTrackConstraints = {
  echoCancellation: true,
  noiseSuppression: true,
  autoGainControl: true,
};
```

This is backward-compatible (browsers already default to enabled but explicit declaration improves cross-browser reliability).

### 4.5 Dev/Prod parity (SECOPS-007)

No backend changes. E2E tests use Chromium fake device flags (`--use-fake-device-for-media-stream`, `--use-fake-ui-for-media-stream`) in `webrtc-media.spec.ts:542`. This provides a deterministic synthetic stream that works identically in CI and local dev. The same test code runs in prod CI — just with real credential secrets stripped.

For section 83 (permission denied, `webrtc-media.spec.ts:1297`): a second browser context launched **without** `--use-fake-ui-for-media-stream` is used; the permission dialog auto-denies in headless mode.

---

## 5. Testing, Verification & Rollout

### Unit tests

Files to create: `frontend/src/hooks/useMediaCapture.test.ts`, `frontend/src/hooks/useMediaDevices.test.ts`. Use `@testing-library/react`'s `renderHook`. Mock `navigator.mediaDevices` globally in a `beforeEach`. ~200 lines each.

Run: `cd frontend && npx vitest src/hooks/useMediaCapture`

### Playwright E2E

`frontend/e2e/webrtc-media.spec.ts` covers:

- Section 78 (lines 529–640): Audio call — local audio track present, remote track live.
- Section 79 (lines 648–820): Video call — local video track, remote `<video>` element has non-zero dimensions.
- Section 83 (lines 1297–1375): Permission denied — `useMediaCapture` sets `status="denied"`, call transitions to `"failure"`, overlay shows appropriate error.

Each section launches a custom Chromium browser with `--use-fake-device-for-media-stream` and `--use-fake-ui-for-media-stream` flags (lines 542–543, 661–662) to avoid needing real hardware. Sections use `browser.newContext({ permissions: ["camera", "microphone"] })` for context-level permission grants.

### Manual QA steps

1. `just up`; set `MESSAGING_WEBRTC_DIRECT_CALL_ENABLED=true`.
2. Open Chrome DevTools → Privacy and Security → Site Settings → Microphone: confirm the site has permission.
3. Alice initiates audio call to Bob. During the call, check DevTools → Sensors → Camera/Microphone indicator: should show active.
4. In a private window (permission not yet granted): Alice initiates call → browser permission dialog appears → deny → toast shows "Microphone/camera access denied." → call transitions to failure state.
5. Video call: confirm local PiP video appears in the call overlay after CALL-004 is merged.

### Observability

No direct backend metrics for `getUserMedia` (it is a pure browser API). The `FAIL` event dispatched on media acquisition failure flows to the call state machine; the resulting call state transition (to `"failure"`) triggers `timeout_call` on the backend which records an end event in `messaging_call_timeline.py`. Frontend: log `console.warn` in `categorizeError` with `error.type` and `error.message`.

### Rollback

Feature-flagged via `MESSAGING_WEBRTC_DIRECT_CALL_ENABLED`. If getUserMedia failures spike after rollout, disable the flag to hide call buttons. No DDB migration required.

### 5.1 Echo cancellation and audio quality constraints

The `buildConstraints()` function (useMediaCapture.ts:50) currently uses `audio: true` (browser-default constraints). Modern browsers enable `echoCancellation`, `noiseSuppression`, and `autoGainControl` by default when `audio: true` is specified, but this is implementation-defined — Safari on macOS may apply different defaults than Chrome. For consistent audio quality across browsers and platforms, the constraints should be explicit:

```typescript
const audio: MediaTrackConstraints = {
  echoCancellation: { ideal: true },
  noiseSuppression: { ideal: true },
  autoGainControl: { ideal: true },
};
```

Using `{ ideal: true }` instead of `true` (boolean) allows the browser to honour the constraint without failing if the device does not support it — `ideal` is a "best effort" modifier in the MediaStream constraints API.

### 5.2 Permission state integration with `navigator.permissions`

The `PermissionState` type (`useMediaCapture.ts:34`) has four values: `"prompt" | "granted" | "denied" | "unknown"`. The current `acquire()` implementation sets `permissionState` based on the `getUserMedia` outcome. A more proactive pattern is to query `navigator.permissions.query({ name: "microphone" })` (and `"camera"` for video) before calling `getUserMedia`, so that the UI can show "Requesting permissions..." text only when the state is `"prompt"` (first use) versus silently calling `getUserMedia` when state is already `"granted"`. This avoids showing permission UI language when the user has already granted access.

The `useMediaCapture` hook currently does not query `navigator.permissions` proactively. This is a minor UX gap — the hook always shows `"requesting"` status during `getUserMedia`, even for repeat calls.

### 5.3 Track stopping vs. track disabling

Two distinct operations exist on a `MediaStreamTrack`:

- `track.stop()`: permanently stops the track and releases the hardware. The camera/mic light goes off. The track cannot be re-enabled — a new `getUserMedia` call is required. Called by `teardownCallResources()` (callStateMachine.ts:214–218) on call end.
- `track.enabled = false`: silences/blacks the track without releasing hardware. The camera light stays on (indicating an active session). The RTP stream continues sending silence/black frames. Called by the mute/camera toggle handlers in ConversationView.

This distinction is critical for `useMediaCapture.release()` vs. the mute/camera toggles in CALL-005. `release()` calls `track.stop()` (permanent); toggles use `track.enabled` (reversible). The teardown path via `teardownCallResources()` is the only place `stop()` should be called during a call lifecycle.

**Effort estimate**: S — hooks are implemented. Remaining work is unit test files (~400 lines total). One day.
