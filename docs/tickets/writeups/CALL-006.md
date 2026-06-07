# CALL-006: E2E Tests for WebRTC Media Establishment — Investigation & Implementation Write-up

## 1. Summary & Classification

**Problem/Feature**: The WebRTC call feature (CALL-001 through CALL-005) requires end-to-end verification that two real browser contexts can negotiate a peer connection through the backend signaling relay, exchange ICE candidates, establish media tracks, and tear down cleanly. Unit tests mock `RTCPeerConnection` and `getUserMedia` entirely — they cannot confirm that Chromium's real WebRTC stack completes ICE negotiation, that the backend SSE relay delivers signaling events in the right order, or that `<video>` elements actually render received streams. This ticket creates the E2E test infrastructure and test cases using Chromium's fake media device flags.

- **Type**: Feature (test-only; no production code changes)
- **Priority**: Medium-High — without these tests, regressions in the ICE negotiation or media rendering path would be silent
- **Status**: Implemented — `frontend/e2e/webrtc-media.spec.ts` (1375 lines) covers sections 78–83; `frontend/e2e/webrtc-calls.spec.ts` (661 lines) covers call lifecycle UI. The originally proposed `frontend/e2e/webrtc-signaling.spec.ts` (pure signaling relay tests from CALL-001) does not exist. Unit test files for `useRtcPeerConnection`, `useMediaCapture`, and `useMediaDevices` do not exist.
- **Area**: Playwright E2E test infrastructure; Chromium fake media devices; two-browser-context patterns
- **Who is affected**: QA, CI pipeline, developers debugging WebRTC regressions
- **Cross-references**: [[CALL-001]] (signaling relay), [[CALL-002]] (RTCPeerConnection hook), [[CALL-003]] (getUserMedia), [[CALL-004]] (media rendering), [[CALL-005]] (media controls), [[SECOPS-007]] (dev/prod parity — offline CI tests, no real AWS)

---

## 2. Current-State Investigation (what exists today)

### 2.1 `webrtc-media.spec.ts` (1375 lines) — sections 78–83

The file is fully implemented. Structure:

- **Sections 78 (audio) and 79 (video) — Media Establishment** (lines 526–820): Each section launches a custom Chromium browser per `beforeAll` with `--use-fake-device-for-media-stream` and `--use-fake-ui-for-media-stream` (lines 539–545, 658–664). Creates Alice and Bob contexts with `permissions: ["camera", "microphone"]`. Alice and Bob navigate to a shared DM conversation seeded in DDB. Alice initiates the call via the UI call button; Bob accepts via the overlay; both contexts poll `waitForConnectionState` (using `window.__rtcPeerConnection?.connectionState`). Tests assert local/remote track presence, `readyState="live"`, and overlay text "Connected with...".
- **Section 80 — ICE Candidate Exchange** (lines 826–990): Verifies that at least one ICE candidate pair with `state="succeeded"` exists in `RTCPeerConnection.getStats()`. Queries signaling events from DDB using inline Python `execSync` to confirm `webrtc.ice_candidate` items were written for both directions.
- **Section 81 — Media Teardown** (lines 995–1140): After call end (click "End call" button), asserts all local tracks have `readyState="ended"` and `RTCPeerConnection.connectionState === "closed"`. Also asserts that calling `getUserMedia` again succeeds after teardown (hardware released).
- **Section 82 — Reconnection** (lines 1144–1290): Uses `page.route` to block STUN/ICE traffic, triggering `iceConnectionState="failed"`. Verifies the overlay transitions to `"reconnecting"`. Removes the route block, verifies `connectionState` returns to `"connected"`.
- **Section 83 — Permission Denied** (lines 1294–1375): Launches a context **without** `--use-fake-ui-for-media-stream`. In headless mode, the permission dialog auto-denies. Verifies `useMediaCapture` sets `status="denied"` and the call transitions to the `"failure"` phase.

### 2.2 `webrtc-calls.spec.ts` (661 lines)

Covers the call lifecycle from a UI/state-machine perspective (not pure media). Key sections:
- Invite creation, accept, decline, end via UI clicks.
- Overlay state transitions (ringing → connecting → connected → ended).
- Feature flag gating (call button hidden when disabled).
- Timeout flow (30-second no-answer → "Call timed out" overlay).

### 2.3 `webrtc.spec.ts` (871 lines) — sections 73–77

Pure HTTP API tests (no browser WebRTC). Tests TURN credential issuance, call invite/accept/decline/end lifecycle via `page.request.post`. No fake media flags or RTCPeerConnection.

### 2.4 Supporting helper patterns

From `webrtc.spec.ts` and reused in `webrtc-media.spec.ts`:

- **`getSessions()`** (line 40): `execSync` call to `e2e_admin_session_setup.py` to seed Alice, Bob, Charlie sessions. Cached in module-level `_sessions`.
- **`injectAuth(page, identity)`**: Sets `ui_session`, `ui_csrf`, `ui_access_token` cookies.
- **DDB helpers** (`seedCallSession`, `deleteCallSession`, `seedConversation`, `deleteConversation`): inline Python via `execSync`. Write directly to DynamoDB Local port 8001 with `boto3`.
- **`apiPost(page, identity, path, body)`**: sends CSRF-authenticated POST using `page.request.post` with `x-csrf-token` header from seeded session.

### 2.5 `window.__rtcPeerConnection` testability hook

`useRtcPeerConnection.ts` exposes the `RTCPeerConnection` instance on `window.__rtcPeerConnection` in dev mode (`import.meta.env.DEV`). E2E tests use `page.waitForFunction(() => window.__rtcPeerConnection?.connectionState === "connected")` to poll ICE state without relying on fragile UI text assertions.

### 2.6 Playwright configuration

`frontend/playwright.config.ts`: 1 worker, 1 retry, 30 s default timeout, headless Chromium. No global `launchOptions.args` — fake media flags are set per-browser-launch within the test files (custom `chromium.launch(...)` instances). The `permissions: ["camera", "microphone"]` array is set per browser context, not globally, to avoid affecting other spec files.

### 2.7 Dev/prod parity (SECOPS-007)

The entire E2E suite runs offline (no AWS, no real TURN). Key behaviors:

- **TURN disabled** (`MESSAGING_WEBRTC_TURN_ENABLED=false` default in dev): ICE uses host/srflx candidates only — works for loopback on localhost.
- **Fake media streams**: Chromium generates a 640×480 animated color pattern for video and a 440Hz sine wave for audio. The same `ontrack` event fires on the remote `RTCPeerConnection` as with a real webcam.
- **DynamoDB Local**: all signaling nonce and event writes go to port 8001. The `querySignalingEvents` helper queries this local DDB to verify backend delivery.
- **No internet required**: `--disable-features=WebRtcHideLocalIpsWithMdns` flag (used in some browser launches in the spec) prevents mDNS ICE candidate obfuscation, allowing direct loopback candidate exchange without DNS resolution.

---

## 3. Gap / Threat Analysis

### 3.1 No unit tests for core hooks

Despite the E2E coverage, there are no unit test files for:
- `frontend/src/hooks/useRtcPeerConnection.test.ts`
- `frontend/src/hooks/useMediaCapture.test.ts`
- `frontend/src/hooks/useMediaDevices.test.ts`

The E2E tests verify end-to-end behavior but are slow (each test requires ICE negotiation, ~10–15 s) and flaky under CPU pressure. Unit tests would catch regressions in the hook logic (ICE buffer, error handling, teardown idempotency) much faster.

### 3.2 No isolated signaling relay spec

`frontend/e2e/webrtc-signaling.spec.ts` does not exist. The HTTP-level signaling relay (IDOR check, replay protection, state-gate enforcement, rate limiting) is only tested in the service-layer unit tests (`test_messaging_call_signaling.py`) and indirectly through the full call flow in `webrtc-media.spec.ts`. There is no E2E test that explicitly:
- Submits a signaling event as a non-participant and verifies 403.
- Submits a duplicate nonce and verifies 409.
- Submits `webrtc.offer` while call is in `"invited"` state and verifies 409 (`invalid_state`).

### 3.3 Reconnection test reliability (section 82)

Section 82 uses `page.route` to block ICE traffic. The ICE failure detection depends on the browser's ICE disconnect timer (~5 s). This makes the test slow and flaky — the exact timing when `iceConnectionState` transitions to `"disconnected"` or `"failed"` varies under CI load. A per-test `test.setTimeout(60_000)` is needed, and the test should poll with retries rather than using a fixed wait.

### 3.4 `window.__rtcPeerConnection` in prod builds

The testability hook `window.__rtcPeerConnection` is gated on `import.meta.env.DEV`. In production builds (where `DEV=false`), this global is not set. E2E tests that use `waitForFunction` targeting this global will timeout in a production build. The alternative — polling UI text assertions — is less reliable (overlay text can change before ICE is fully stable). The DEV gate is correct behavior but must be documented.

### 3.5 Video element rendering not directly asserted

The existing sections 78 and 79 assert that `getReceivers()` returns audio/video tracks with `readyState="live"` via `page.evaluate`. They do not assert that the `<video>` element's `srcObject` is set and `videoWidth > 0` — i.e., that the DOM-level rendering (from CALL-004) is actually working. This gap means a regression in `VideoRenderer.srcObject` assignment would not be caught by these tests.

---

## 4. Proposed Design / Fix

### 4.1 Unit tests for `useRtcPeerConnection` (see CALL-002 write-up §4.1)

Mock `RTCPeerConnection`, `sendSignalingEvent`, and `fetchTurnCredentials`. Test caller path, callee path, ICE buffer, teardown, and TURN failure fallback. ~200 lines.

### 4.2 Unit tests for `useMediaCapture` and `useMediaDevices` (see CALL-003 write-up §4.1/4.2)

Mock `navigator.mediaDevices.getUserMedia` and `enumerateDevices`. Test all error types, `release()` idempotency, and `devicechange` event handling. ~400 lines total.

### 4.3 `frontend/e2e/webrtc-signaling.spec.ts` — isolated signaling relay tests

Complement to `webrtc-media.spec.ts`. Does not need fake media devices (pure API tests). Uses `apiPost(page, identity, path, body)` to submit signaling envelopes directly after seeding a call session in `"accepted"` state.

Scenarios:
- **IDOR attempt**: Charlie (not a participant) submits signaling event for Alice/Bob call → assert 403 `forbidden`.
- **Replay detection**: Alice submits the same `{ event_id, nonce }` twice → first returns 200 `delivered`, second returns 409 `replay_detected`.
- **Wrong state**: `webrtc.offer` submitted while call is in `"invited"` state → 409 `invalid_state`.
- **Stale timestamp**: `sent_at` 200 seconds in the past → 400 `stale_timestamp`.
- **Rate limit**: submit 65 events within 10 seconds → 429 after the 60th.

These tests should run fast (pure HTTP, no WebRTC) and be deterministic. Add to CI via `just e2e` (all spec files run together).

### 4.4 DOM-level video rendering assertion

Extend sections 78/79 in `webrtc-media.spec.ts` to assert `<video>` element dimensions after call connects:

```typescript
// After waitForConnectionState("connected")
const remoteVideoInfo = await bobPage.evaluate(() => {
  const v = document.querySelector('video[aria-label="Remote video"]') as HTMLVideoElement;
  return v ? { w: v.videoWidth, h: v.videoHeight, paused: v.paused } : null;
});
expect(remoteVideoInfo?.w).toBeGreaterThan(0);
expect(remoteVideoInfo?.paused).toBe(false);
```

Chromium fake device produces a 640×480 stream, so `videoWidth` will be 640 when rendering correctly.

### 4.5 Reconnection test stabilization

In section 82, replace fixed-wait polling with `page.waitForFunction`:

```typescript
// Block STUN by intercepting connections
await alicePage.route("**/stun.*/**", (route) => route.abort());

// Wait for ICE failure (may take up to 30s)
await alicePage.waitForFunction(
  () => (window as any).__rtcPeerConnection?.iceConnectionState === "failed",
  { timeout: 35_000 }
);

// Restore
await alicePage.unroute("**/stun.*/**");

// Wait for recovery
await waitForConnectionState(alicePage, "connected", 30_000);
```

Use `test.setTimeout(90_000)` for this section only.

### 4.6 Dev/Prod parity summary (SECOPS-007)

All E2E tests run offline. No real AWS, no real TURN, no network egress required:
- DynamoDB: DDB Local (port 8001)
- Signaling: backend writes to DDB Local, SSE reads from same
- Media: Chromium fake device (deterministic synthetic stream)
- TURN: disabled (`MESSAGING_WEBRTC_TURN_ENABLED=false`) — ICE uses loopback host candidates
- Auth: seeded sessions via `execSync` DDB writes from `e2e_admin_session_setup.py`

The prod E2E environment (if ever created) would need `MESSAGING_WEBRTC_TURN_ENABLED=true` with a real coturn server, but the test code itself would be identical.

---

## 5. Testing, Verification & Rollout

### Current E2E coverage summary

| File | Lines | Sections | What it tests |
|---|---|---|---|
| `webrtc-media.spec.ts` | 1375 | 78–83 | Audio/video media, ICE, teardown, reconnect, permission denied |
| `webrtc-calls.spec.ts` | 661 | (unnumbered) | Call lifecycle UI (invite/accept/decline/end/timeout/feature flag) |
| `webrtc.spec.ts` | 871 | 73–77 | TURN credentials, call HTTP API (pure API, no media) |

### Remaining test gaps and effort

| Gap | File | Effort |
|---|---|---|
| HTTP-layer signaling relay IDOR/replay/state checks | `webrtc-signaling.spec.ts` | S (1 day, ~120 lines) |
| `useRtcPeerConnection` unit tests | `useRtcPeerConnection.test.ts` | S (1 day, ~200 lines) |
| `useMediaCapture` unit tests | `useMediaCapture.test.ts` | S (half day, ~150 lines) |
| `useMediaDevices` unit tests | `useMediaDevices.test.ts` | S (half day, ~100 lines) |
| DOM-level `<video>` rendering assertions | `webrtc-media.spec.ts` additions | XS (2 hours, ~20 lines) |
| Reconnection test stabilization | `webrtc-media.spec.ts` section 82 | XS (1 hour) |

### Running the tests

```bash
# All E2E tests (including WebRTC)
cd frontend && npx playwright test e2e/webrtc-media.spec.ts e2e/webrtc-calls.spec.ts e2e/webrtc.spec.ts

# With TURN enabled (if testing TURN integration)
MESSAGING_WEBRTC_TURN_ENABLED=true npx playwright test e2e/webrtc-media.spec.ts

# Unit tests (when created)
npx vitest src/hooks/useRtcPeerConnection src/hooks/useMediaCapture src/hooks/useMediaDevices
```

Prerequisites: `just up` (starts dev stack), `MESSAGING_WEBRTC_DIRECT_CALL_ENABLED=true` in backend env.

### CI configuration

`frontend/playwright.config.ts` current: 1 worker, 1 retry, 30 s timeout, headless Chromium. WebRTC media tests need longer per-test timeouts — `test.setTimeout(45_000)` is set inside individual tests (e.g., line ~580 of `webrtc-media.spec.ts`). The `webrtc-signaling.spec.ts` can run with the default 30 s timeout.

The `VITE_MESSAGING_WEBRTC_DIRECT_CALL_ENABLED=true` env var must be set in the Vite build used for E2E (this controls frontend feature gate checks in `featureFlags.ts`).

### Rollback

Test-only ticket — no production code changes. Tests can be skipped in CI by excluding the spec files. No rollback required beyond reverting the spec file additions.

### 5.1 DDB seeding pattern used in WebRTC specs

All WebRTC specs use the same DDB seeding approach established in `webrtc.spec.ts:96–155`. Inline Python via `execSync` writes directly to DynamoDB Local:

```typescript
function seedCallSession(callId: string, conversationId: string, callerId: string, calleeId: string): void {
  const py = `
import boto3
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001",
                     region_name="us-east-1", aws_access_key_id="test",
                     aws_secret_access_key="test")
ddb.Table("CallSessions").put_item(Item={
    "call_id": "${callId}", "conversation_id": "${conversationId}",
    "caller_user_id": "${callerId}", "callee_user_id": "${calleeId}",
    "initial_mode": "audio", "state": "accepted",
    "start_ts": int(__import__('time').time()),
})`;
  execSync(`python3 -c '${py}'`, { cwd: "/home/ubuntu/testlogon" });
}
```

This pattern avoids going through the call invite/accept HTTP flow for sections that only need to test signaling or media (not lifecycle). It allows tests to start with a call already in `"accepted"` state without waiting for the full invite/accept SSE round-trip.

`afterAll` in each section deletes seeded records using the same pattern. If a test fails mid-run, the cleanup in `afterAll` still runs (Playwright runs `afterAll` even on failure). DDB Local is wiped by `just restart` between full suite runs.

### 5.2 Fake media stream characteristics

Chromium's `--use-fake-device-for-media-stream` flag produces:

- **Video**: 640×480 animated color wheel, 30fps. `videoWidth=640`, `videoHeight=480`. The pattern changes over time, so the `<video>` element's `currentTime` advances.
- **Audio**: 440Hz (A4 note) sine wave at a fixed amplitude. The audio stream is a single mono channel. This is audible if played through speakers during development — turn down volume.

Both streams trigger `ontrack` events on the remote `RTCPeerConnection` and set `readyState="live"` on the tracks. This allows the assertions `expect(remoteTrackInfo).toContainEqual({ kind: "audio", readyState: "live" })` in sections 78–79 to pass reliably.

The `--disable-features=WebRtcHideLocalIpsWithMdns` flag (used in some `chromium.launch` calls in `webrtc-media.spec.ts`) prevents mDNS address obfuscation for ICE candidates. Without this flag, Chromium generates mDNS hostnames like `abc123.local` instead of `127.0.0.1` for host candidates. mDNS resolution fails in headless CI (no multicast DNS resolver), causing ICE failure. The flag forces plain IP address ICE candidates, ensuring loopback connectivity works in headless environments.

### 5.3 Signaling relay correctness properties

The key correctness property the E2E tests verify is that a signaling event submitted to `POST /messaging/messages/calls/{call_id}/signal` by Alice is delivered to Bob's SSE stream without modification. The relay is a store-and-forward mechanism: the event is written to `UserEvents` with `user_id=recipient_user_id` (bob's user_id), and the SSE poll on Bob's connection fetches it within `poll_ms` milliseconds.

The `_project_event_for_user()` function in `messaging.py` (referenced in the SSE stream handler) may strip fields from the event before sending to the client. For signaling events, the full `payload` (SDP or ICE candidate) must be preserved — partial projection would break WebRTC negotiation. Section 80's DDB inspection (`querySignalingEvents`) confirms the raw event was written correctly, but only a full two-browser test confirms the end-to-end delivery chain including SSE projection.

**Effort estimate**: M — the main spec (`webrtc-media.spec.ts`) is implemented. Remaining work: `webrtc-signaling.spec.ts` (1 day), unit test files for 3 hooks (2 days), DOM-level rendering assertions + section 82 stabilization (half day). Total ~3.5 days.
