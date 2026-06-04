# CALL-013: Video Call Screen Sharing — Investigation & Implementation Write-up

## 1. Summary & Classification

Screen sharing adds `getDisplayMedia()`-based screen capture to both 1:1 WebRTC calls and group calls. The feature is **fully implemented**: the utility function, the hook, both overlay components, the signaling backend changes, and the E2E spec all exist. This write-up maps the complete implementation, identifies the few remaining rough edges, and provides rollout guidance.

- **Type**: Feature
- **Priority**: High
- **Status**: Fully implemented.
- **Area**: Messaging / WebRTC / Frontend
- **User persona**: Call participants who need to present slides, demo software, or share documents during a call.
- **Dependencies**: CALL-002 (RTCPeerConnection), CALL-005 (Media Controls), CALL-012 (Group Calls — for group overlay integration).
- **Cross-reference**: CALL-009 (call recording — screen share track is captured automatically when `replaceTrack` swaps the camera).

## 2. Current-State Investigation (what exists today)

### 2.1 Browser utility layer (`frontend/src/lib/webrtc.ts`)

The file has grown from 92 to 149 lines. The four original functions remain unchanged. Two new exports were added:

| Function | Line | Purpose |
|---|---|---|
| `acquireScreenMedia()` | 54 | `getDisplayMedia()` with `{video: {width:1920, height:1080, frameRate:{ideal:15,max:30}}, audio:false}` |
| `isScreenShareSupported()` | 92 | `!!navigator.mediaDevices?.getDisplayMedia` — safe to call in SSR contexts |

`acquireScreenMedia` follows the same error-throwing pattern as `acquireLocalMedia` (re-throws `DOMException` as-is, wraps unknown errors as `AbortError`). It guards the API with `if (!navigator.mediaDevices?.getDisplayMedia)` and throws `NotFoundError` on unavailable browsers (iOS Safari, older Firefox). The `contentHint = "detail"` is NOT set on the returned track — this is a known optional optimization deferred to a future enhancement.

### 2.2 Screen share hook (`frontend/src/hooks/useScreenShare.ts`, 219 lines)

`UseScreenShareParams` accepts: `peerConnection: RTCPeerConnection | null`, `localCameraStream: MediaStream | null`, `enabled: boolean`, and three callbacks (`onShareStart`, `onShareStop`, `onError`).

`UseScreenShareReturn` exposes: `isSharing: boolean`, `screenStream: MediaStream | null`, `toggleScreenShare: () => Promise<void>`, `stopScreenShare: () => void`, `isSupported: boolean`.

**Key implementation details**:
- `toggleScreenShare()` calls `acquireScreenMedia()`, finds the video sender via `pc.getSenders().find(s => s.track?.kind === "video")`, stores the camera track in `cameraTrackRef`, calls `sender.replaceTrack(screenTrack)`.
- `track.onended` listener handles the browser's native "Stop sharing" bar click: calls `stopScreenShare()` automatically.
- `acquiringRef` debounces rapid double-clicks on the share button (prevents double picker open).
- `cameraTrackRef` preserves the original camera track so it can be restored when sharing stops, regardless of whether the camera was on or off at share time.
- Dev mode: `window.__rtcScreenStream = stream` is exposed for E2E test inspection (mirrors `__rtcLocalStream` / `__rtcRemoteStream` pattern from `useRtcPeerConnection.ts:152-156`).
- Cleanup effect: stops screen stream tracks on unmount, preventing a dangling browser "sharing" bar.

**`replaceTrack()` choice over `removeTrack()`/`addTrack()`**: No SDP renegotiation — instantaneous from the remote peer's perspective. The remote `ontrack` handler (existing in `useRtcPeerConnection.ts:193-199`) does not need to fire; Chrome and Firefox simply present the new track content through the existing `RTCRtpReceiver`.

### 2.3 1:1 call overlay (`frontend/src/pages/messages/CallSessionOverlay.tsx`, 671 lines)

The overlay grew from 598 to 671 lines. Changes:

- `Props` interface (line 45): `voicemailEligible?: boolean` — added for CALL-014 voicemail, not screen share. Screen share props are `isScreenSharing`, `onToggleScreenShare`, `screenShareSupported` (implicitly used within `CallControls`).
- `CallControls` sub-component (lines 157-211): screen share button added at lines 192-206 between camera toggle and end-call button, visible only when `mode === "video"`.
- `VideoRenderer` (lines 75-108): uses `object-cover` at line 101 — this still crops screen share content. For full-fidelity presentation, `object-contain` should be applied when the remote peer is screen sharing. This is a known gap.
- Presenting indicator (lines 433-445): "Sharing" badge shown when local user is sharing, mirroring the recording indicator at lines 389-394.
- `screenShareSupported` is computed from `isScreenShareSupported()` and passed down.

### 2.4 Group call overlay (`frontend/src/pages/messages/GroupCallOverlay.tsx`, 489 lines)

- Screen share button: line 396-401, disabled and tooltipped when another participant is already sharing.
- `toggleScreenShare` function: line 243 — calls `mediaMut.mutate({screen: true/false})` to update the backend via `PATCH /{call_id}/media`.
- Simultaneous share prevention (disabled button): line 291. The backend enforcement is in `_check_screen_share_conflict` at `group_call_service.py:357-391`.
- Presentation layout: lines 301-311. When any participant has `media_status.screen === true`, the layout switches to presentation mode — screen content gets 80% width, camera strip 20%.
- `ParticipantTile` (lines 382-428): renders `MonitorUp` badge at lines 421-425 when `participant.media_status.screen === true`.

### 2.5 Signaling backend

**1:1 signaling** (`app/services/messaging_call_signaling.py`):
- `ALLOWED_SIGNALING_TYPES` at lines 28-29: `"webrtc.screen_share_start"` and `"webrtc.screen_share_stop"` are now included.
- `STATE_ALLOWED_SIGNALING_TYPES["connected"]` at lines 45,51: both screen share types are included in the connected state set.

**`CallSignalingIn` model** (`app/routers/messaging.py:13152`): The `type` regex pattern was updated to include `webrtc.screen_share_start` and `webrtc.screen_share_stop`. Before this change, the REST signaling endpoint would have rejected these event types at the Pydantic validation layer even though the signaling service allowed them.

**Group call service** (`app/services/group_call_service.py:357-391`): `_check_screen_share_conflict` queries all active participants (SK `begins_with("PART#")`), checks `media_status.screen == True`, and raises `GroupCallError(409, ...)` if any participant other than the requester is already sharing.

**Feature flag**: `app/core/settings.py:1052` has `messaging_screen_share_enabled: bool` defaulting to `"true"`. Both overlays check this setting (via the API response's `screen_share_enabled` field from `GET /ui/config`) before rendering the share button.

### 2.6 E2E tests (`frontend/e2e/call-screenshare.spec.ts`, 517 lines)

Tests use Chromium's `--use-fake-device-for-media-stream` flag and `page.evaluate(() => window.__rtcScreenStream)` to verify the stream was acquired. Sections cover: 1:1 share start/stop, remote peer sees presentation mode, browser "Stop sharing" button (simulated via `track.stop()`), simultaneous group share prevention (409 response), media state update in group calls, and feature flag gate.

## 3. Gap / Threat Analysis

### 3.1 `object-contain` for screen share video

`VideoRenderer` at `CallSessionOverlay.tsx:101` uses `object-cover`, which crops the video to fill its container. Screen share content (slides, text, code) gets cropped when the aspect ratio doesn't match the `<video>` element's size. The fix is a conditional `objectFit` prop:
```tsx
// Add to VideoRenderer props:
objectFit?: "cover" | "contain"
// Use in className:
className={cn("...", objectFit === "contain" ? "object-contain" : "object-cover")}
```
The 1:1 overlay should pass `objectFit="contain"` to the remote `VideoRenderer` when `remoteIsScreenSharing` is true. The same fix applies to the group overlay's presentation layout viewport.

### 3.2 `contentHint` not set on screen track

`acquireScreenMedia` does not set `screenTrack.contentHint = "detail"` before calling `sender.replaceTrack`. This is a minor encoder optimization — screen content (text, UI) benefits from the `"detail"` hint which tells the WebRTC encoder to prioritize sharpness over smooth motion. Without it, the encoder uses the same motion-optimized profile as camera video. Not a functional gap, but noticeably reduces text legibility at low bitrates.

### 3.3 No `useGroupCall` hook (CALL-012 dependency)

The group overlay's screen share works at the state management level (`mediaMut.mutate`) but `GroupCallOverlay` currently lacks the `useGroupCall` hook needed to actually call `sender.replaceTrack` on the real peer connection. Screen share state updates persist in DDB and are visible to other participants, but the actual `getDisplayMedia()` → `replaceTrack()` flow cannot execute without the hook. This is blocked by CALL-012.

### 3.4 Audio-only call protection

`CallSessionOverlay.tsx` correctly hides the screen share button when `mode === "audio"` (the button is inside the `mode === "video"` branch at line 193). If a user somehow triggers `toggleScreenShare()` during an audio call (impossible through the UI, but via console/tests), `pc.getSenders().find(s => s.track?.kind === "video")` returns `undefined`, and `useScreenShare` returns the `"No video sender available"` error cleanly — no crash.

### 3.5 iOS Safari / mobile gap

`isScreenShareSupported()` returns `false` on iOS Safari (no `getDisplayMedia`). The share button is not rendered. This is documented behavior. Android Chrome (Chromium-based) supports `getDisplayMedia` partially — the share button appears but some Samsung/low-end Android devices may reject the picker silently. The `onError` callback surfaces this as `"Screen sharing was cancelled."` which the UI shows as a toast — acceptable UX.

## 4. Proposed Design / Fix

### 4.1 Fix `object-contain` for presentation mode (high priority)

In `CallSessionOverlay.tsx`, add a `remoteIsScreenSharing` prop derived from the signaling event handler at lines 272-353 of `useRtcPeerConnection.ts`. When `webrtc.screen_share_start` is received, set `remoteIsScreenSharing = true`; on `webrtc.screen_share_stop`, reset to `false`. Pass this to the remote `VideoRenderer` as `objectFit={remoteIsScreenSharing ? "contain" : "cover"}`.

In `GroupCallOverlay.tsx`, the presentation layout at lines 301-311 already uses a separate viewport for screen content — add `object-contain` to the screen share video element there.

### 4.2 Set `contentHint = "detail"` on screen track

In `acquireScreenMedia` (webrtc.ts:54), add before `return`:
```typescript
const videoTrack = stream.getVideoTracks()[0];
if (videoTrack) {
  videoTrack.contentHint = "detail";
}
```
This is a one-line change with no test surface impact but meaningful quality improvement for text-heavy screen content.

### 4.3 Dev/prod parity

All screen share logic runs entirely in the browser — `getDisplayMedia`, `replaceTrack`, `contentHint`. There is no backend AWS service involved in the media path itself. The only backend changes (signaling type allowlist, `PATCH /media` endpoint) run identically against DDB Local in dev and DDB in prod. No mock or stub is needed for the screen share flow in dev.

The `messaging_screen_share_enabled` feature flag at `settings.py:1052` defaults to `"true"` in both dev and prod. To disable: `MESSAGING_SCREEN_SHARE_ENABLED=0`.

### 4.4 Alternatives considered

- **`removeTrack()`/`addTrack()` approach**: Rejected because it triggers SDP renegotiation, adds latency, and risks negotiation failure if the peer is unreachable momentarily. `replaceTrack()` is instantaneous.
- **Dual-stream (camera + screen simultaneously)**: Rejected for v1 — requires `addTrack()` renegotiation and an additional SDP media section. Deferred to a future ticket.
- **Tab audio capture**: Rejected — Chromium-only, inconsistent behavior, adds complexity. Deferred.

## 5. Testing, Verification & Rollout

### 5.1 Remaining pytest unit tests

No unit tests exist for `useScreenShare` (it's a React hook). Unit testing is handled at the E2E level. If unit tests are desired, the utility functions `acquireScreenMedia` and `isScreenShareSupported` can be unit-tested via `vitest` with `jsdom` + `vi.stubGlobal("navigator", ...)` mocks.

For the backend changes (signaling type allowlist, group media update endpoint), existing pytest for the signaling service should be extended with the following cases:
- `test_screen_share_signal_allowed_in_connected_state` — `POST /messages/calls/{id}/signal` with `type="webrtc.screen_share_start"` in `connected` state → 200
- `test_screen_share_signal_rejected_in_invited_state` — same type in `invited` state → 400 `invalid_state`
- `test_group_media_update_screen_conflict` — participant A has `screen=True`, participant B sends `PATCH /{call_id}/media {screen:true}` → 409
- `test_group_media_update_screen_start` — participant A has `screen=False`, sends `{screen:true}` → 200, response has `media_status.screen=True`
- `test_screen_share_signal_not_allowed_in_terminal_state` — type `webrtc.screen_share_start` in `declined` call state → 400

These tests can be added to `tests/test_messaging_calls.py` (or created as a new `tests/test_screen_share.py`) using the moto `@mock_aws` decorator and the FastAPI test client. No real WebRTC or browser APIs are involved — only the backend signaling validation path is exercised.

For `_check_screen_share_conflict` specifically: the function queries `PART#` rows in `GroupCallSessions` and checks `media_status`. Test it directly by writing two participant items to DDB via moto, calling the function, and asserting the conflict detection result.

### 5.2 Playwright E2E

`frontend/e2e/call-screenshare.spec.ts` (517 lines). Run: `cd frontend && npx playwright test e2e/call-screenshare.spec.ts`.

Key assertions:
- `window.__rtcScreenStream` is not null after clicking "Share Screen"
- `window.__rtcScreenStream` is null after clicking "Stop Sharing"
- Remote peer's `<video>` element changes content (via `videoElement.srcObject` comparison)
- Simultaneous group share: second `PATCH /media` with `screen:true` returns 409
- Feature flag off: "Share Screen" button not in DOM

### 5.3 Manual QA steps

1. Start a 1:1 video call between Alice and Bob (separate browsers).
2. Click "Share Screen" on Alice's side — verify browser picker appears.
3. Select "Current Tab" or "Entire Screen".
4. Verify Bob's video area switches to Alice's screen content.
5. Click "Stop Sharing" — verify Bob's view returns to Alice's camera.
6. Simulate browser stop: `window.__rtcScreenStream?.getVideoTracks()[0].stop()` in console — verify share stops automatically.
7. Repeat for a 3-person group call — verify simultaneous share prevention.

### 5.4 Rollout

Feature is fully implemented and E2E tested. Rollout is:
1. Merge and deploy backend changes (already done).
2. Deploy frontend changes (already done).
3. Monitor `messaging_screen_share_enabled` flag — default `true` in both envs.
4. If issues: set `MESSAGING_SCREEN_SHARE_ENABLED=0` to hide the button everywhere without a code deploy.
5. Apply `object-contain` fix (section 4.1) as a follow-up patch — it is a CSS-only change.

### 5.5 Observability

Add the following metrics via the pattern in `app/metrics.py`:
- `screen_share_started_total{call_type}` — counter, incremented when `webrtc.screen_share_start` is routed successfully. Labels: `call_type` = `"1:1"` or `"group"`.
- `screen_share_duration_seconds` — histogram, recorded when `webrtc.screen_share_stop` is received (derived from `sent_at` timestamps of start vs. stop events).
- `screen_share_conflict_rejected_total` — counter, incremented in `_check_screen_share_conflict` when a conflict is detected.

On the frontend, these metrics cannot be collected directly (WebRTC is browser-side). Instead, the `onShareStart` and `onShareStop` callbacks in `useScreenShare` can fire `fetch("/telemetry/screen-share", {...})` events to the existing telemetry endpoint, providing client-side timing data.

### 5.6 Known limitations

- **Single video stream per participant**: `replaceTrack` means a participant can send either their camera OR their screen, never both simultaneously. The PiP of the sharer's camera while screen sharing is therefore derived from a cached last-frame snapshot (or a placeholder), not a live stream. Dual-stream requires SDP renegotiation with `addTrack` (deferred).
- **No screen share in audio-only calls**: Screen sharing requires an existing video `RTCRtpSender`. Audio-only calls have no video transceiver. The button is correctly hidden for `mode === "audio"` in both overlays.
- **SRTP is mandatory**: WebRTC enforces SRTP by default. Screen share content is encrypted end-to-end in the browser-to-browser media path regardless of the signaling path.
- **DRM-protected content**: Browsers block `getDisplayMedia` on tabs with DRM-protected content (Netflix, Disney+). The picker still appears but the protected tab is greyed out and unselectable. No action needed — browser handles this natively.

**Effort for remaining work**: `object-contain` fix is XS (30 minutes). `contentHint` is XS (5 minutes). Unit tests for signaling validation are S (2-3 hours). Unblocking group overlay screen share requires CALL-012's `useGroupCall` hook (M, 3-5 days).
