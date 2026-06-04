# CALL-004: Render Local and Remote Media Streams in Call Overlay — Investigation & Implementation Write-up

## 1. Summary & Classification

**Problem/Feature**: Once a WebRTC call reaches the `"connected"` phase, both peers hold live `MediaStream` objects from CALL-002 (RTCPeerConnection) and CALL-003 (getUserMedia). Without rendering, the user hears and sees nothing — the overlay only shows a text string "Connected with {peerName}". This ticket adds `<video>`/`<audio>` elements to `CallSessionOverlay.tsx` for both audio and video call modes, manages `srcObject` assignment via React refs, adds a call duration timer, and provides mute/camera toggle controls. The `DialogContent` layout is also reworked: video calls expand to near-fullscreen (95vw) while audio calls keep the compact modal.

- **Type**: Feature (frontend UI component changes only; no backend changes)
- **Priority**: High — without this, media flows silently/blindly
- **Status**: Implemented — `frontend/src/pages/messages/CallSessionOverlay.tsx` (671 lines) contains `VideoRenderer` (line 90), `AudioRenderer` (line 117), `CallTimer` (line 131), `CallControls` (line 167), full video + audio connected-state layouts (lines 362–477, 478–563). Dedicated E2E spec (`frontend/e2e/webrtc-call-media.spec.ts`) does not exist; related coverage is in `webrtc-media.spec.ts` and `webrtc-calls.spec.ts`.
- **Area**: Frontend UI (`CallSessionOverlay.tsx`, `ConversationView.tsx`)
- **Who is affected**: Any user in a connected call
- **Cross-references**: [[CALL-002]] (provides `remoteStream`), [[CALL-003]] (provides `localStream`), [[CALL-005]] (media controls build on this rendering foundation), [[SECOPS-007]] (fake media devices in dev/CI)

---

## 2. Current-State Investigation (what exists today)

### 2.1 `CallSessionOverlay.tsx` structure (671 lines)

The component is a Radix UI `<Dialog>` gated by `session.state !== "idle"`. The Props interface (line 42) includes all media fields:

```typescript
interface Props {
  session: CallSessionUi;
  conversationId?: string;
  voicemailEligible?: boolean;
  isBusy?: boolean;
  localStream?: MediaStream | null;      // from CALL-003
  remoteStream?: MediaStream | null;     // from CALL-002
  peerConnection?: RTCPeerConnection | null;  // for quality indicator (CALL-005)
  isMuted?: boolean;
  isCameraOff?: boolean;
  onAccept, onDecline, onEnd, onDismiss: () => void;
  onToggleMute, onToggleCamera?: () => void;
  isRecording?: boolean;
  recordingDuration?: number;
  onRequestRecording, onStopRecording?: () => void;
  recordingEnabled?: boolean;
  showRecordingConsent?: boolean;
  recordingConsentFrom?: string | null;
  onConsentRecording?: (accept: boolean) => void;
  isScreenSharing?: boolean;
  onToggleScreenShare?: () => void;
  screenShareSupported?: boolean;
  peerIsScreenSharing?: boolean;
}
```

Recording and screen-share props are already included here (anticipating CALL-009 and CALL-013), though those tickets are not yet implemented. The `onConsentRecording` callback handles the consent dialog that appears when the remote peer requests recording.

### 2.2 Sub-components (lines 80–237)

All rendering sub-components are defined as local functions within `CallSessionOverlay.tsx`:

- **`VideoRenderer`** (line 90): `<video autoPlay playsInline muted={muted} ref={videoRef}>`. Sets `videoRef.current.srcObject = stream ?? null` in a `useEffect` with `[stream]` dependency. On cleanup, sets `srcObject = null`. Accepts `mirror` prop for local preview (`[transform:scaleX(-1)]` Tailwind arbitrary). This is the correct pattern because React does not support `srcObject` as a JSX attribute.
- **`AudioRenderer`** (line 117): `<audio autoPlay className="hidden" ref={audioRef}>`. Same `srcObject` management pattern. Hidden from view — audio plays without visual element.
- **`CallTimer`** (line 131): increments `elapsed` via `setInterval` when `running=true`. Format: `MM:SS`. Resets to `00:00` when `running` becomes false. Renders as `<span className="font-mono text-sm tabular-nums text-muted-foreground">`.
- **`CallControls`** (line 167): accepts `mode`, `isMuted`, `isCameraOff`, `onToggleMute`, `onToggleCamera`, `onEnd`, `isBusy`, plus recording and screen-share props. Renders Mic/MicOff, Video/VideoOff (video mode only), recording button (if `recordingEnabled`), screen-share button (if `screenShareSupported`), and PhoneOff end button. All buttons are circular `size="icon"` shadcn/ui `Button` components.

### 2.3 Connected-state layouts (lines 362–563)

The component uses `isConnected = phase === "connected"` and `session.mode` to select the layout.

**Video connected layout** (around line 362–477):
- `DialogContent` with `sm:max-w-[95vw] md:max-w-4xl max-h-[90vh] p-0 overflow-hidden` — near-fullscreen override of the default `sm:max-w-md`.
- Remote video area: `relative w-full aspect-video bg-black` containing `VideoRenderer` (or avatar fallback when `hasRemoteVideo=false`).
- Local PiP: `absolute bottom-4 right-4 w-28 h-20 sm:w-40 sm:h-28 rounded-xl` containing `VideoRenderer` with `mirror` and `muted` (local preview must be muted to avoid feedback). When `isCameraOff=true`, shows a `VideoOff` icon placeholder instead.
- Peer name + `CallTimer` overlay in top-left corner with `bg-black/50 backdrop-blur-sm`.
- Controls bar below the video: `CallControls` component.
- `AudioRenderer` also present (for remote audio even in video calls).

**Audio connected layout** (around line 478–563):
- `DialogContent` with standard `sm:max-w-md` (unchanged from non-connected states).
- Avatar + peer name + "Connected" text + `CallTimer`.
- `AudioRenderer` for remote audio playback.
- `CallControls` (audio mode — no camera button).

### 2.4 `hasRemoteVideo` state (line 340)

Tracks whether the remote stream has enabled video tracks:

```typescript
const [hasRemoteVideo, setHasRemoteVideo] = React.useState(false);

React.useEffect(() => {
  if (!remoteStream) { setHasRemoteVideo(false); return; }
  const videoTracks = remoteStream.getVideoTracks();
  setHasRemoteVideo(videoTracks.length > 0 && videoTracks[0].enabled);
  // Event listeners for mute/unmute/ended on each track
  ...
}, [remoteStream]);
```

When `hasRemoteVideo=false`, a centered avatar fallback (initials of peer name) is shown inside the video container.

### 2.5 `useConnectionQuality` import (line 17)

`CallSessionOverlay.tsx` imports `useConnectionQuality` from `"@/hooks/useConnectionQuality"` (106 lines). This hook (`frontend/src/hooks/useConnectionQuality.ts`) polls `RTCPeerConnection.getStats()` every 3 seconds (when `isConnected=true`) and returns `"good" | "fair" | "poor" | "unknown"` based on RTT and packet loss thresholds. Used in the control bar with a colored `Signal` icon.

### 2.6 Stream prop flow in ConversationView.tsx

Streams reach the overlay via (line 1347–1348):

```typescript
localStream={rtcLocalStream ?? mediaCapture.stream ?? null}
remoteStream={rtcRemoteStream ?? null}
```

`rtcLocalStream` and `rtcRemoteStream` come from `useRtcPeerConnection` (line 675). `mediaCapture.stream` is the fallback from `useMediaCapture` (set before the RTC hook attaches tracks). Mute/camera toggle handlers (lines 1397–1413) manipulate `callResourcesRef.current?.localStream ?? mediaCapture.stream` tracks directly.

### 2.7 Dev vs prod behavior

There is no backend-side distinction for media rendering. In dev/E2E, Chromium fake device streams produce a synthetic spinning color wheel video and 440Hz sine audio — `VideoRenderer` renders the synthetic video the same way it would render a real webcam. The `srcObject` assignment and `autoPlay` behavior is identical. The fake streams also trigger `ontrack` events on the remote `RTCPeerConnection`, so `remoteStream` is populated in the same way.

---

## 3. Gap / Threat Analysis

### 3.1 Missing dedicated E2E spec

`frontend/e2e/webrtc-call-media.spec.ts` does not exist. The connected-state media rendering (video element dimensions, `srcObject` assignment, PiP layout) is not directly tested. `webrtc-media.spec.ts` sections 78–79 do test media track presence and `connectionState="connected"`, but they do not assert DOM-level video element rendering (e.g., that `videoWidth > 0`).

### 3.2 autoPlay policy in some browsers

Mobile browsers (iOS Safari, Chrome for Android) block `autoPlay` for audio elements unless the play is user-initiated. The `AudioRenderer` uses `autoPlay` without any `play()` fallback. This means remote audio may not start on iOS unless the user interacts with the page after the call connects. A `useEffect` calling `audioRef.current.play().catch(...)` would handle this gracefully.

### 3.3 PiP camera-off placeholder covers the `<video>` but the track is still sending black frames

When `isCameraOff=true`, the PiP shows a `VideoOff` icon overlay, but the underlying `<video>` element is still rendered (just hidden). The video track's `enabled=false` (set by the toggle handler) causes the peer connection to send black frames, not blank — the remote sees a black frame. This is the correct WebRTC behavior (no renegotiation needed) but the comment in the component should clarify this for future maintainers.

### 3.4 `aria-label` on `<Dialog>` for screen readers

`DialogContent` for the full-screen video layout uses `aria-label="Video call"` but has a visually-hidden `<DialogHeader>` with `className="sr-only"`. Screen reader announces "Video call" from the `aria-label` and then the hidden title "Video call with {peerName}" — this double announcement should be simplified (only the `DialogTitle` text is needed).

### 3.5 `CallControls` recording/screen-share props always passed but features not implemented

`CallControls` (line 167) accepts `recordingEnabled`, `isRecording`, `onRequestRecording`, `onStopRecording`, `isScreenSharing`, `onToggleScreenShare`, `screenShareSupported`. These are passed from ConversationView. The recording and screen-share backend services (CALL-009, CALL-013) are not yet implemented, so these buttons are either hidden or no-op. The prop plumbing is correct and will activate when those tickets land.

---

## 4. Proposed Design / Fix

### 4.1 Add dedicated E2E spec — `frontend/e2e/webrtc-call-media.spec.ts`

This spec focuses on DOM-level media rendering assertions distinct from the API-level tests in `webrtc.spec.ts` and the track-level tests in `webrtc-media.spec.ts`. Key test scenarios:

- **Video element has non-zero dimensions**: after call reaches `"connected"`, assert `remoteVideoEl.videoWidth > 0` and `remoteVideoEl.videoHeight > 0` (using `page.evaluate`).
- **Local PiP visible**: local `<video>` element in PiP position is visible and has non-zero dimensions.
- **Audio call: no video element**: in audio mode, no `<video>` elements are in the DOM (only a hidden `<audio>`).
- **AudioRenderer plays**: cannot directly assert audio output, but can assert `audioEl.paused === false` via `page.evaluate`.
- **Camera-off placeholder**: after `onToggleCamera()`, PiP shows `VideoOff` icon, underlying `<video>` still in DOM.
- **Dialog expands for video**: `DialogContent` has width `>= 0.9 * viewport.width` in video call mode.

Use the `--use-fake-device-for-media-stream` custom browser per `webrtc-media.spec.ts` pattern.

### 4.2 autoPlay fallback for iOS

In `AudioRenderer` and `VideoRenderer`:

```typescript
React.useEffect(() => {
  if (!ref.current) return;
  ref.current.srcObject = stream ?? null;
  if (stream) {
    ref.current.play().catch(() => {
      // autoplay blocked — user interaction required. Not an error in strict mode.
    });
  }
  return () => { if (ref.current) ref.current.srcObject = null; };
}, [stream]);
```

This is safe on desktop (where `autoPlay` already works) and fixes iOS.

### 4.3 Dev/Prod parity (SECOPS-007)

No backend changes needed. The rendering components are purely client-side. E2E fake media devices (`--use-fake-device-for-media-stream`) provide a deterministic video stream (animated color pattern at 640×480) that allows `videoWidth > 0` assertions to pass reliably in CI. Prod uses real webcam/mic; the same `srcObject` assignment code path runs.

### 4.4 Screen reader cleanup

Simplify the video call `DialogContent`: remove the `aria-label="Video call"` attribute from `DialogContent` and rely solely on the `sr-only` `<DialogTitle>` for screen reader announcement. One announcement is sufficient.

---

## 5. Testing, Verification & Rollout

### Playwright E2E

**Existing coverage** (indirect):
- `webrtc-media.spec.ts` sections 78–83 cover track presence, `connectionState`, and teardown.
- `webrtc-calls.spec.ts` covers UI state transitions including "Connected with..." text.

**New spec needed**: `frontend/e2e/webrtc-call-media.spec.ts` — DOM-level video/audio element assertions. ~150 lines, custom browser with fake media flags.

Key assertions:
```typescript
// Remote video element has rendered frames
const videoInfo = await bobPage.evaluate(() => {
  const v = document.querySelector('video[aria-label="Remote video"]') as HTMLVideoElement;
  return v ? { width: v.videoWidth, height: v.videoHeight, paused: v.paused } : null;
});
expect(videoInfo?.width).toBeGreaterThan(0);
expect(videoInfo?.paused).toBe(false);
```

### Manual QA

1. `just up`; set `MESSAGING_WEBRTC_DIRECT_CALL_ENABLED=true`.
2. Alice and Bob each navigate to their DM conversation.
3. Alice starts a **video call** → Bob accepts → both peers reach "Connected".
4. Verify: remote video fills the expanded dialog; local PiP shows Alice's camera feed (mirrored).
5. Alice clicks the camera-off button → local PiP shows `VideoOff` icon; remote (Bob) sees black frames.
6. Alice clicks the mute button → button turns red; microphone indicator in OS turns off.
7. Both click "End call" → dialog shows "Call ended." → all video/audio elements removed.
8. Start an **audio call** → verify compact dialog layout, peer name, timer, mute button, no video elements.

### Observability

Call duration is tracked by `CallTimer` in the frontend (displayed as `MM:SS`). The `connect_ts` and `end_ts` fields on `CallSessionRecord` (backend, `messaging_call_sessions.py:26–29`) record server-side timestamps. Duration can be computed as `end_ts - connect_ts` and emitted as `webrtc_call_duration_seconds` histogram (metrics.py:1432).

### Rollback

Feature-flagged. No DDB or backend changes. Disabling `MESSAGING_WEBRTC_DIRECT_CALL_ENABLED` hides call buttons entirely. The UI changes are contained within `CallSessionOverlay.tsx` and are only visible during a connected call.

### 5.1 `srcObject` lifecycle edge cases

The imperative `srcObject` assignment pattern has several edge cases that must be handled correctly:

**Stream replacement during a connected call**: If `remoteStream` changes (e.g., during an ICE restart that creates a new `RTCPeerConnection`), the `useEffect` in `VideoRenderer` (line 90) will re-fire with the new stream. `videoRef.current.srcObject = null` is set in the cleanup function before the new stream is assigned. This prevents the video element from briefly showing a frozen frame from the old stream. The cleanup runs synchronously (React's effect cleanup mechanism), so there is no flicker window.

**Multiple track `ontrack` events**: `RTCPeerConnection.ontrack` fires once per incoming track. If the remote peer has both audio and video tracks, two `ontrack` events fire. The `useRtcPeerConnection` hook (line ~259 in the hook file) uses `remoteStream.addTrack(track)` for each incoming track, and the `remoteStream` state is updated after each addition. Because React batches state updates within a single event loop tick, the `VideoRenderer` effect may fire once (after both tracks are added) or twice (once per track). The `srcObject` assignment is idempotent (assigning the same stream reference is a no-op) so either behavior is correct.

**Null stream on disconnect**: When the call enters the `"reconnecting"` phase, `remoteStream` may become null (if the peer connection is torn down during reconnect). `VideoRenderer`'s `useEffect` will set `videoRef.current.srcObject = null`, showing either a black video element or the `hasRemoteVideo=false` avatar fallback. This is the correct UX — show the avatar while reconnecting, restore video when the new stream arrives.

### 5.2 Video call dialog size and mobile responsiveness

The `DialogContent` class override for video calls (`sm:max-w-[95vw] md:max-w-4xl max-h-[90vh] p-0 overflow-hidden`) expands the modal to near-fullscreen on desktop. On mobile (viewport < 640px), the Tailwind `sm:` prefix doesn't apply, so the dialog reverts to `max-w-full` (the default Radix UI Dialog behavior on small screens). This is acceptable — mobile users see a full-width dialog.

The PiP container (`absolute bottom-4 right-4 w-28 h-20 sm:w-40 sm:h-28`) is smaller on mobile (`w-28 h-20`, approximately 112×80px) to leave room for controls. On desktop it is `w-40 h-28` (160×112px). The `object-cover` class on the local PiP video ensures the feed is cropped to fill the container without distortion regardless of the camera's native aspect ratio.

### 5.3 Accessibility considerations for media elements

- `<video>` elements with `autoPlay` that are not muted can fail `aria-hidden` checks in automated accessibility scans. The `VideoRenderer`'s remote `<video>` is not muted (remote audio plays through it) — this is necessary for audio-only loopback when the device has no speakers. The `aria-label="Remote video"` attribute satisfies screen reader requirements for non-decorative media elements.
- `<audio>` elements with `className="hidden"` and no `aria-label` are decorative and should have `aria-hidden="true"` to prevent screen readers from announcing them. The current `AudioRenderer` (line 117) does not set this attribute.

**Effort estimate**: S — rendering components are fully implemented. Remaining work is the dedicated E2E spec, autoPlay fallback fix, and `aria-hidden` on AudioRenderer. One day.
