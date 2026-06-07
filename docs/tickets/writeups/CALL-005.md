# CALL-005: Add In-Call Media Controls (Mute, Camera, End) with Duration Timer and Quality Indicator — Investigation & Implementation Write-up

## 1. Summary & Classification

**Problem/Feature**: Once a call is visually rendering (CALL-004), the user needs interactive controls: mute microphone, toggle camera, see call duration, and monitor connection quality. Without these, a user cannot mute themselves during a call and has no feedback on call health. This ticket adds the full control bar to `CallSessionOverlay.tsx` — mute/camera toggles that manipulate `track.enabled`, a duration timer using `Date.now()` delta, and a connection quality indicator from `RTCPeerConnection.getStats()`.

- **Type**: Feature (frontend only; no backend changes)
- **Priority**: Medium-High — table-stakes UX for any voice/video call product
- **Status**: Implemented — `CallSessionOverlay.tsx:167` (`CallControls` component), `CallSessionOverlay.tsx:131` (`CallTimer`), `useConnectionQuality` hook at `frontend/src/hooks/useConnectionQuality.ts` (106 lines) imported at `CallSessionOverlay.tsx:17`. Mute/camera state managed in `ConversationView.tsx:98–99`. No dedicated unit test file for `useConnectionQuality`.
- **Area**: Frontend UI (`CallSessionOverlay.tsx`, `ConversationView.tsx`); WebRTC stats API
- **Who is affected**: All connected-call participants
- **Cross-references**: [[CALL-003]] (local stream for track.enabled), [[CALL-004]] (rendering foundation), [[CALL-002]] (peer connection for getStats), [[SECOPS-007]] (quality indicator behavior in dev vs prod)

---

## 2. Current-State Investigation (what exists today)

### 2.1 `CallControls` component (`CallSessionOverlay.tsx:150–237`)

`CallControls` is a local function component that renders the full in-call control bar. Its props:

```typescript
interface CallControlsProps {
  mode: DirectCallMode;
  isMuted: boolean;
  isCameraOff: boolean;
  onToggleMute: () => void;
  onToggleCamera: () => void;
  onEnd: () => void;
  isBusy: boolean;
  isRecording?: boolean;
  onRequestRecording?: () => void;
  onStopRecording?: () => void;
  recordingEnabled?: boolean;
  isScreenSharing?: boolean;
  onToggleScreenShare?: () => void;
  screenShareSupported?: boolean;
}
```

Buttons rendered (lines ~171–237):
- **Mic/MicOff** (lines 171–178): `variant={isMuted ? "destructive" : "secondary"}`, circular `size="icon"`, `aria-label={isMuted ? "Unmute microphone" : "Mute microphone"}`.
- **Video/VideoOff** (lines 182–190): only rendered when `mode === "video"`, same variant pattern.
- **Screen share** (lines 192–203): Monitor/MonitorOff icon, only when `screenShareSupported=true`. Currently no-op (CALL-013 not yet implemented).
- **Recording** (lines 204–227): Circle/red dot icons when `recordingEnabled=true`. Includes consent flow handling (CALL-009).
- **PhoneOff end button** (lines 230–237): `variant="destructive"`, larger (`h-12 w-12`), disabled when `isBusy`.

### 2.2 `CallTimer` component (`CallSessionOverlay.tsx:131–147`)

```typescript
function CallTimer({ running }: { running: boolean }) {
  const [elapsed, setElapsed] = React.useState(0);
  React.useEffect(() => {
    if (!running) { setElapsed(0); return; }
    const interval = window.setInterval(() => setElapsed((e) => e + 1), 1000);
    return () => window.clearInterval(interval);
  }, [running]);
  const minutes = Math.floor(elapsed / 60).toString().padStart(2, "0");
  const seconds = (elapsed % 60).toString().padStart(2, "0");
  return <span className="font-mono text-sm tabular-nums text-muted-foreground" ...>{minutes}:{seconds}</span>;
}
```

Uses `setInterval` with a counter increment (not `Date.now()` delta). The design in the ticket specified `Date.now()` delta to avoid drift — the current implementation is simpler but may drift slightly (±1 second per minute under CPU load). For call durations under 60 minutes this is acceptable.

### 2.3 `useConnectionQuality` hook (`frontend/src/hooks/useConnectionQuality.ts:1–106`)

Exported function `useConnectionQuality(peerConnection, isConnected)` (line 20). Polls `peerConnection.getStats()` every 3 seconds when `isConnected=true`. Extracts `currentRoundTripTime` from `candidate-pair` reports and `packetsLost/packetsReceived` from `inbound-rtp` reports.

Quality thresholds:
- **good**: RTT < 150ms AND loss rate < 2%
- **fair**: RTT < 400ms AND loss rate < 5%
- **poor**: anything worse

Returns `"good" | "fair" | "poor" | "unknown"`. `"unknown"` is returned when `peerConnection` is null, `isConnected=false`, or `getStats()` throws.

Used in `CallSessionOverlay.tsx:334`: `const connectionQuality = useConnectionQuality(peerConnection, isConnected)`. Rendered as a colored `Signal` icon in the overlay header/controls area.

### 2.4 Mute/camera state management in ConversationView.tsx

- **State** (lines 98–99): `const [isMuted, setIsMuted] = React.useState(false)` and `const [isCameraOff, setIsCameraOff] = React.useState(false)`.
- **Toggle handlers** (lines 1397–1413):
  ```typescript
  onToggleMute={() => {
    const stream = callResourcesRef.current?.localStream ?? mediaCapture.stream;
    stream?.getAudioTracks().forEach((t) => { t.enabled = !t.enabled; });
    setIsMuted((m) => !m);
  }}
  onToggleCamera={() => {
    const stream = callResourcesRef.current?.localStream ?? mediaCapture.stream;
    stream?.getVideoTracks().forEach((t) => { t.enabled = !t.enabled; });
    setIsCameraOff((c) => !c);
  }}
  ```
  Both toggle `track.enabled` (not `track.stop()`). `track.enabled=false` sends silence/black frames — the peer connection remains established, no renegotiation.
- **Props passed to overlay** (lines 1394–1395): `isMuted={isMuted}`, `isCameraOff={isCameraOff}`.

### 2.5 `peerConnection` prop flow

`ConversationView.tsx` passes `peerConnection` to the overlay (line ~1350):
```typescript
peerConnection={callResourcesRef.current?.peerConnection ?? null}
```

`CallRuntimeResources.peerConnection` is typed as `RTCPeerConnection | null` (callStateMachine.ts:191) — not a minimal interface, so `getStats()` is available.

### 2.6 Keyboard shortcuts

`callStateMachine.test.ts` does not cover keyboard shortcuts. The ticket design specified `M` for mute and `V` for camera. These are not yet implemented in `CallSessionOverlay.tsx` — there is no `keydown` event listener in the component. The controls have `aria-label` for accessibility but no keyboard shortcut bindings.

### 2.7 Dev vs prod behavior

`RTCPeerConnection.getStats()` is a browser API available in dev and prod identically. In E2E with fake media devices, the synthetic stream generates ICE candidate pairs and stats reports. The `candidate-pair` report with `state: "succeeded"` will be present once Chromium's loopback ICE completes. RTT for loopback connections will be near zero (< 1ms), so `connectionQuality` will always be `"good"` in dev. In prod, real-world RTT varies. There is no dev mock needed for this feature.

---

## 3. Gap / Threat Analysis

### 3.1 `CallTimer` drift

The `setInterval` timer increments `elapsed` by 1 second on each tick. `setInterval` is not precise — it can fire late under CPU load or browser throttling (inactive tabs). Over a 30-minute call, the displayed timer might diverge from wall-clock time by several seconds. The `Date.now()` delta approach (measure elapsed = `Date.now() - startTime`) is more accurate. The current implementation is acceptable for UX (users don't need millisecond precision) but the design intent was higher accuracy.

### 3.2 `isMuted`/`isCameraOff` state can drift from track state

`setIsMuted` uses a React state flip (`!m`). If the track is manipulated externally (e.g., by `useRtcPeerConnection` during reconnect), the React state may desync from `track.enabled`. The design specified reading the current track state at toggle time: `const newEnabled = !audioTracks[0]?.enabled`. The current implementation does this correctly via `t.enabled = !t.enabled` (reading then toggling), but the React state is a flip (`!m`) which could diverge if multiple sources modify tracks. A `useEffect` that syncs `isMuted` to `stream?.getAudioTracks()[0]?.enabled` when `localStream` changes would prevent drift.

### 3.3 No unit tests for `useConnectionQuality`

`frontend/src/hooks/useConnectionQuality.ts` (106 lines) has no test file. The polling logic, quality threshold comparisons, and cleanup on unmount are not tested. Edge cases: `peerConnection.getStats()` rejects (should set quality to `"unknown"`); `isConnected` becomes false mid-poll (should clear the interval and reset quality); multiple rapid state changes.

### 3.4 Keyboard shortcuts not implemented

Keyboard shortcuts (`M` for mute, `V` for camera, `Escape` for end) described in the ticket design are absent from `CallSessionOverlay.tsx`. This is a UX gap for power users and accessibility users who rely on keyboard navigation.

### 3.5 Recording/screen-share buttons rendered but not functional

`CallControls` renders recording and screen-share buttons conditionally on `recordingEnabled` and `screenShareSupported` props. In the current state of the codebase, these features (CALL-009, CALL-013) are not implemented. The buttons are wired but the handlers are no-ops. There is a risk that `recordingEnabled` evaluates to `true` via `isCallRecordingEnabled()` in `featureFlags.ts:127` and the button renders but does nothing, confusing users. The feature flag should default to `false` until CALL-009 lands.

---

## 4. Proposed Design / Fix

### 4.1 Unit tests for `useConnectionQuality`

File: `frontend/src/hooks/useConnectionQuality.test.ts`. Use `renderHook`. Mock `RTCPeerConnection` with `getStats` returning a `Map` of stats reports.

Key test cases:
- **Good quality**: RTT 0.05s, loss rate 0% → `"good"`.
- **Fair quality**: RTT 0.25s, loss rate 3% → `"fair"`.
- **Poor quality**: RTT 0.5s, loss rate 8% → `"poor"`.
- **getStats rejects**: mock rejects → `"unknown"`.
- **Not connected**: `isConnected=false` → quality stays `"unknown"`, no polling.
- **Poll interval**: verify polling fires at 3-second intervals (use `vi.useFakeTimers()`).
- **Cleanup**: unmount during poll → `clearInterval` called.

### 4.2 `CallTimer` accuracy improvement

Replace the counter with a `Date.now()` delta:

```typescript
function CallTimer({ running }: { running: boolean }) {
  const [elapsed, setElapsed] = React.useState(0);
  const startRef = React.useRef<number | null>(null);

  React.useEffect(() => {
    if (!running) { setElapsed(0); startRef.current = null; return; }
    startRef.current = Date.now();
    const interval = window.setInterval(() => {
      setElapsed(startRef.current ? Math.floor((Date.now() - startRef.current) / 1000) : 0);
    }, 1000);
    return () => window.clearInterval(interval);
  }, [running]);
  ...
}
```

This eliminates drift from `setInterval` jitter. Backward-compatible change.

### 4.3 Keyboard shortcuts

Add a `useEffect` to `CallSessionOverlay.tsx` for keyboard handling in the connected state:

```typescript
React.useEffect(() => {
  if (!isConnected) return;
  const handler = (e: KeyboardEvent) => {
    if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
    if (e.key === "m" || e.key === "M") { e.preventDefault(); onToggleMute?.(); }
    if ((e.key === "v" || e.key === "V") && session.mode === "video") { e.preventDefault(); onToggleCamera?.(); }
  };
  document.addEventListener("keydown", handler);
  return () => document.removeEventListener("keydown", handler);
}, [isConnected, onToggleMute, onToggleCamera, session.mode]);
```

Add `aria-keyshortcuts="m"` and `aria-keyshortcuts="v"` to the respective buttons.

### 4.4 `isMuted` sync with track state

Add a sync effect in ConversationView:

```typescript
React.useEffect(() => {
  const stream = callResourcesRef.current?.localStream ?? mediaCapture.stream;
  if (!stream) return;
  const audioTrack = stream.getAudioTracks()[0];
  if (audioTrack) setIsMuted(!audioTrack.enabled);
}, [rtcLocalStream, mediaCapture.stream]);
```

This prevents the React state from diverging from the actual track state when streams are replaced during reconnection.

### 4.5 Dev/Prod parity (SECOPS-007)

`useConnectionQuality` uses `RTCPeerConnection.getStats()` — a browser API. No backend dependency. In E2E (loopback Chromium), the quality will always be `"good"` (near-zero RTT). In prod with real TURN relay, RTT will vary. The thresholds (150ms/400ms) are reasonable for real-world use. No mock needed.

Recording and screen-share feature flags (`isCallRecordingEnabled`, `screenShareSupported`) should default to `false` in `.env.local.example` until those features are implemented, to prevent UI confusion.

---

## 5. Testing, Verification & Rollout

### Unit tests

Files to create:
- `frontend/src/hooks/useConnectionQuality.test.ts` — ~120 lines, uses `vi.useFakeTimers()` for interval testing.

Run: `cd frontend && npx vitest src/hooks/useConnectionQuality`

### Playwright E2E

Existing coverage:
- `webrtc-media.spec.ts` section 81 (lines 998–1140): Media teardown — after end call, tracks have `readyState="ended"`. This implicitly tests that the mute toggle (track.enabled) does not stop tracks.
- `webrtc-calls.spec.ts`: covers full call lifecycle including connected state UI.

New E2E tests to add to `webrtc-call-media.spec.ts` (see CALL-004):
- **Mute via button**: connected → click Mic button → verify `aria-label="Unmute microphone"` (button toggled) + local audio track `enabled=false`.
- **Camera toggle in video call**: click camera button → verify PiP shows VideoOff icon.
- **Timer increments**: connected → wait 3 seconds → timer reads `"00:03"` (or higher).
- **Quality indicator visible**: `Signal` icon is present in the connected overlay; color class is `text-green-500` for loopback (should be "good").

### Manual QA

1. Video call (both peers) → click Mic button → button turns red → ask peer "can you hear me?" (should hear silence). Click again → unmuted.
2. Camera toggle → local PiP shows black (VideoOff placeholder) → peer sees black frame.
3. Watch timer for 60 seconds → confirm it shows `"01:00"` (not `"00:59"` or `"01:01"`).
4. Signal indicator: on localhost → green Signal icon; simulate poor network by throttling Chrome DevTools → indicator should turn yellow/red (cannot easily test without real degradation).

### Observability

Connection quality is client-side only. No backend metric. Could add a frontend event to log quality transitions: `console.warn("WebRTC quality degraded:", quality)` in the `useConnectionQuality` hook when quality drops from good to fair or poor. Tie to a future SECOPS-001 telemetry event if call quality metrics are required.

### Rollback

Feature-flagged. No backend changes. The mute/camera track manipulation is entirely client-side and reversible. If a bug in the toggle handler stops tracks permanently, the user ends the call and re-dials.

### 5.1 `RTCPeerConnection.getStats()` stats report structure

The `useConnectionQuality` hook extracts two metrics from the `RTCStatsReport`:

**Round-trip time**: From `candidate-pair` reports with `state: "succeeded"`, reads `report.currentRoundTripTime` (in seconds). Only the active/nominated candidate pair has this field populated. The hook averages across all succeeded pairs, but in practice only one pair is nominated per connection.

**Packet loss rate**: From `inbound-rtp` reports, reads `report.packetsLost` and `report.packetsReceived`. Loss rate = `packetsLost / (packetsLost + packetsReceived)`. Note: `packetsLost` is cumulative (total lost since connection start), not a rate. Comparing consecutive samples to compute a rolling loss rate would be more accurate for detecting short bursts. The current implementation uses the cumulative lifetime loss rate, which dampens short-term fluctuations.

The `getStats()` API shape is standardized in W3C WebRTC Statistics but individual browser implementations vary. `currentRoundTripTime` may be `undefined` on some `candidate-pair` reports (only the nominated pair reports RTT). The `packetsLost` field on `inbound-rtp` may be negative in some edge cases (e.g., when RTCP reports arrive out of order). The hook must guard against these: `if (typeof report.currentRoundTripTime === "number")` and `packetsLost = Math.max(0, report.packetsLost ?? 0)`.

### 5.2 Mute indicator on remote peer

When Alice mutes herself (sets `audioTrack.enabled = false`), she sends silence frames to Bob. Bob's `useConnectionQuality` still shows the connection as "good" (RTT and packet loss are unaffected by silent audio). Bob has no visual indicator that Alice is muted — the track continues flowing. This is standard WebRTC behavior. A future improvement (out of scope for CALL-005) would be to send a `webrtc.*` signaling event (e.g., `webrtc.mute_audio`) to notify the peer, allowing the peer's overlay to show "Alice is muted". This would require a new event type in `ALLOWED_SIGNALING_TYPES` (signaling.py:14) and a handler in the `useRtcPeerConnection` hook.

### 5.3 Control bar layout in audio vs video mode

For audio calls, the `CallControls` component is rendered inside `DialogFooter` (compact modal). For video calls, it appears inside the expanded video container at the bottom. In both cases, the same `CallControls` component is used — the `mode` prop selects which buttons to render. The layout differences (footer vs. overlay bar with `bg-background`) are handled in the parent JSX of `CallSessionOverlay.tsx` (lines ~448–477 for video, ~545–563 for audio), not inside `CallControls` itself. This keeps the control component layout-agnostic and reusable.

**Effort estimate**: S — controls are implemented. Remaining work: `useConnectionQuality.test.ts` (~120 lines), keyboard shortcut implementation (~20 lines), CallTimer accuracy improvement (~5 lines), `packetsLost` defensive guard (~3 lines). Half a day.
