# CALL-006: E2E Tests for WebRTC Media Establishment

**Status**: Implemented

## 1. Overview & Motivation

### Purpose

This ticket defines the end-to-end testing strategy for verifying that WebRTC media actually flows between two browser contexts during a direct call. The existing E2E test suite (`frontend/e2e/webrtc.spec.ts`, sections 73-77) validates the **call lifecycle API** (invite, accept, decline, end, TURN credential issuance) but never exercises the browser's `RTCPeerConnection`, `getUserMedia`, ICE negotiation, or media track rendering. Those tests are pure HTTP-level assertions against the FastAPI backend.

<!-- NOTE: CALL-002 (useRtcPeerConnection at frontend/src/hooks/useRtcPeerConnection.ts, 518 lines) and CALL-003 (useMediaCapture at frontend/src/hooks/useMediaCapture.ts, 315 lines) are now IMPLEMENTED. E2E test files exist: webrtc-calls.spec.ts (661 lines), webrtc-media.spec.ts (1375 lines). The original webrtc.spec.ts (871 lines) also exists for call lifecycle HTTP tests. The proposed webrtc-media.spec.ts file name was used for the implementation. -->
CALL-006 ensures that:

1. Two browser contexts can establish a peer connection through the signaling server.
2. ICE candidates are exchanged and the connection reaches the `connected` state.
3. Audio/video `MediaStreamTrack` objects flow from one peer to the other.
4. The call overlay UI correctly reflects the connected state with active media.
5. Teardown (call end) properly stops all tracks and closes the peer connection.

### Why E2E (Not Unit Tests)

Unit tests (like `ConversationView.call_flows.test.tsx` and `callStateMachine.test.ts`) mock out `RTCPeerConnection` and `getUserMedia` entirely. They verify state transitions but cannot confirm that:

- Chromium's real WebRTC stack completes ICE negotiation in the local network topology.
- The signaling relay (SSE stream + `POST /messaging/signaling`) correctly delivers SDP offers, answers, and ICE candidates between two isolated sessions.
- Media tracks are actually attached to `<video>` or `<audio>` elements and the browser renders them.
- The teardown path truly releases hardware resources (camera/mic handles).

These properties require two real browser contexts communicating through the real backend.

### Scope

| In scope | Out of scope |
|----------|--------------|
| Loopback peer connection (both peers on localhost) | NAT traversal through a real TURN relay |
| Fake media device streams (Chromium flags) | Real camera/microphone hardware |
| ICE connection state verification | Network partition simulation |
| Media track presence on remote `<video>` element | Actual audio/video quality measurement |
| Call lifecycle integration (invite -> accept -> media -> end) | Performance benchmarks |
| Audio-only and video call modes | Screen sharing |

---

## 2. Current State Analysis

### Existing `webrtc.spec.ts` (Sections 73-77)

The file at `frontend/e2e/webrtc.spec.ts` (871 lines) tests five sections (see `frontend/e2e/webrtc.spec.ts`):

| Section | What it tests | Technique |
|---------|--------------|-----------|
| 73 | TURN credential issuance | HTTP POST assertions (200/403/404/503) |
| 74 | Call invite creation | HTTP POST with DDB-seeded conversations |
| 75 | Accept/decline flow | Two browser contexts, HTTP POST only |
| 76 | End call | State transition assertions (ended/canceled/409) |
| 77 | Full happy path | invite -> accept -> end via HTTP, no media |

**Key patterns from the existing file:**

1. **Session bootstrap** (lines 40-73): `getSessions()` calls `e2e_admin_session_setup.py` synchronously via `execSync`, caches the result in `_sessions`. `injectAuth(page, identity)` sets session cookies on the page context.

2. **DynamoDB seeding** (lines 96-155): `seedCallSession()` and `deleteCallSession()` use inline Python scripts executed via `execSync` to write/delete items directly in DynamoDB Local (port 8001). Similarly, `seedConversation()` and `deleteConversation()` manage conversation records.

3. **Two-context pattern** (lines 502-519): Each describe block creates separate browser contexts for Alice and Bob:
   ```typescript
   const aliceCtx = await browser.newContext();
   alicePage = await aliceCtx.newPage();
   await injectAuth(alicePage, "alice");
   await alicePage.goto(BASE);

   const bobCtx = await browser.newContext();
   bobPage = await bobCtx.newPage();
   await injectAuth(bobPage, "bob");
   await bobPage.goto(BASE);
   ```

4. **API helpers** (lines 75-89): `apiPost(page, identity, path, body)` sends CSRF-authenticated POST requests; `apiGet(page, path)` for GETs.

5. **Cleanup in afterAll** (lines 516-519): Contexts are closed, DDB records deleted.

### Playwright Configuration (`frontend/playwright.config.ts`)

```typescript
export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  expect: { timeout: 8_000 },
  retries: 1,
  workers: 1,
  use: {
    baseURL: "http://localhost:3000",
    headless: true,
    viewport: { width: 1280, height: 800 },
    actionTimeout: 10_000,
    navigationTimeout: 15_000,
    screenshot: "only-on-failure",
    video: "off",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
```

**Notable limitations for media tests:**

- No `launchOptions.args` are configured -- Chromium launches without fake media device flags.
- No `permissions` array is set -- `getUserMedia` will trigger a permission prompt (which blocks in headless mode unless auto-granted).
- `video: "off"` means we cannot use Playwright's video recording to debug media flow; we will rely on `RTCPeerConnection` state and DOM assertions instead.
- `workers: 1` is ideal for media tests (no parallel interference).
- `timeout: 30_000` may need per-test overrides for ICE negotiation which can take 2-5 seconds.

### Frontend Call Architecture (Post CALL-002/003)

After CALL-002 and CALL-003 land, the flow will be:

1. `ConversationView` calls `useRtcPeerConnection(callState, callResources)` hook.
2. On `phase === "outgoing_connecting"` (after remote accept), the hook:
   - Fetches TURN credentials from `POST /messages/calls/{call_id}/turn-credentials`.
   - Calls `navigator.mediaDevices.getUserMedia({ audio: true, video: mode === "video" })`.
   - Creates `RTCPeerConnection` with ICE servers.
   - Adds local tracks, creates offer, sends via signaling.
3. The callee receives `webrtc.offer` via SSE, sets remote description, creates answer.
4. Both peers trickle ICE candidates via `webrtc.ice_candidate` signaling events.
5. When `RTCPeerConnection.connectionState === "connected"`, dispatches `CONNECT` to state machine.
6. `CallSessionOverlay` renders `<video>` elements with `srcObject = localStream / remoteStream`.

### Backend Signaling Infrastructure

`app/services/messaging_call_signaling.py` implements `route_signaling_event()` which:
- Validates envelope structure (type, version, event_id, call_id, conversation_id, nonces).
- Checks sender is a call participant.
- Enforces state-based signaling type restrictions (e.g., `webrtc.offer` only allowed in `accepted`/`connected` states).
- Writes the event to the `Events` DDB table addressed to `recipient_user_id`.
- Returns a `SignalingAck` with delivery status.

The allowed signaling types are: `call.invite`, `call.ring`, `call.accept`, `call.decline`, `webrtc.offer`, `webrtc.answer`, `webrtc.ice_candidate`, `call.end`.

---

## 3. Technical Design

### 3.1 Chromium Fake Media Device Flags

Chromium provides command-line flags that replace real hardware media devices with synthetic test streams:

| Flag | Purpose |
|------|---------|
| `--use-fake-device-for-media-stream` | Replaces camera/mic with a generated pattern (spinning color wheel for video, 440Hz sine wave for audio) |
| `--use-fake-ui-for-media-stream` | Auto-grants `getUserMedia` permission without showing a dialog |

These flags must be passed via Playwright's `launchOptions.args` on the browser context or globally in the config. For CALL-006 tests we will configure them **per-context** rather than globally, to avoid affecting other test files:

```typescript
const aliceCtx = await browser.newContext({
  permissions: ["camera", "microphone"],
});
// Note: permissions grant is insufficient alone in headless mode;
// chromium args must be set at the browser level.
```

**Browser-level approach** (preferred for reliability): Since Playwright's `browser` fixture is launched once per worker, and `webrtc.spec.ts` already owns the worker (workers: 1), we can use a **project-level config override** or launch a dedicated browser instance:

```typescript
// Option A: Use browser.newContext with permissions
const ctx = await browser.newContext({
  permissions: ["camera", "microphone"],
});

// Option B: Launch a separate browser with args (more reliable for headless)
const customBrowser = await chromium.launch({
  args: [
    "--use-fake-device-for-media-stream",
    "--use-fake-ui-for-media-stream",
    "--allow-file-access",
  ],
});
```

**Recommended approach**: Use a dedicated Playwright project in `playwright.config.ts` for media tests, or launch a custom browser within the test file. Given that the existing config has only one project (`chromium`) with no args, and modifying it would affect all 1070+ tests, we will **launch a custom Chromium browser within the media test file**:

```typescript
import { chromium, type Browser, type BrowserContext, type Page } from "@playwright/test";

let mediaBrowser: Browser;

test.beforeAll(async () => {
  mediaBrowser = await chromium.launch({
    headless: true,
    args: [
      "--use-fake-device-for-media-stream",
      "--use-fake-ui-for-media-stream",
      "--disable-web-security",           // allow cross-origin for local TURN
      "--disable-features=WebRtcHideLocalIpsWithMdns",  // expose local IPs for ICE
    ],
  });
});
```

### 3.2 Two-Browser-Context Test Architecture

Each media test requires two independent browser contexts (Alice and Bob) that:
1. Share the same custom-launched Chromium browser (so they inherit fake device flags).
2. Have independent cookie jars (session isolation).
3. Can independently call `getUserMedia` and get fake streams.
4. Communicate only through the backend signaling relay (no direct page-to-page channel).

```
+-------------------+        +-------------------+
|   Alice Context   |        |    Bob Context    |
|  (Browser Tab 1)  |        |  (Browser Tab 2)  |
+--------+----------+        +---------+---------+
         |                              |
         | POST /calls/invite           |
         +----------------------------->|
         |                              |
         |    SSE: call.invite event    |
         |<-----------------------------+
         |                              |
         | POST /calls/{id}/accept      |
         |<-----------------------------+
         |                              |
         | webrtc.offer (signaling)     |
         +----------------------------->|
         |                              |
         | webrtc.answer (signaling)    |
         |<-----------------------------+
         |                              |
         | webrtc.ice_candidate (both)  |
         |<---------------------------->|
         |                              |
         |  [RTCPeerConnection: connected]
         |                              |
         | Media tracks flowing         |
         |<===========================>|
```

### 3.3 Verifying ICE Connection State

After offer/answer exchange, the `RTCPeerConnection.connectionState` progresses through: `new` -> `connecting` -> `connected`. We verify this by evaluating JavaScript in the page context:

```typescript
// Wait for connection state to reach "connected"
await alicePage.waitForFunction(() => {
  // Access the peer connection exposed by the hook on window (for testability)
  const pc = (window as any).__rtcPeerConnection;
  return pc && pc.connectionState === "connected";
}, { timeout: 15_000 });
```

**Testability hook**: The `useRtcPeerConnection` hook should expose the `RTCPeerConnection` instance on `window.__rtcPeerConnection` in dev mode (`import.meta.env.DEV`) for E2E test inspection. This avoids brittle DOM-based detection.

Alternatively, if the hook does not expose the PC globally, we can observe the **UI state** as a proxy:

```typescript
// The CallSessionOverlay shows "Connected with <peerName>." when state = "connected"
await alicePage.getByText(/Connected with/).waitFor({ state: "visible", timeout: 15_000 });
```

**ICE candidate verification**: Check that at least one ICE candidate was gathered:

```typescript
const candidateCount = await alicePage.evaluate(() => {
  const pc = (window as any).__rtcPeerConnection;
  // Get stats to verify candidates
  return pc?.getStats().then((stats: RTCStatsReport) => {
    let count = 0;
    stats.forEach((report) => {
      if (report.type === "local-candidate") count++;
    });
    return count;
  });
});
expect(candidateCount).toBeGreaterThan(0);
```

### 3.4 Verifying Media Tracks

Once the connection is established, verify that media tracks are flowing:

**Local stream verification** (the page that called getUserMedia):

```typescript
const localTrackInfo = await alicePage.evaluate(() => {
  const pc = (window as any).__rtcPeerConnection;
  const senders = pc?.getSenders() ?? [];
  return senders.map((s: RTCRtpSender) => ({
    kind: s.track?.kind,
    enabled: s.track?.enabled,
    readyState: s.track?.readyState,
  }));
});
// Audio call: expect at least 1 audio track
expect(localTrackInfo).toContainEqual(
  expect.objectContaining({ kind: "audio", enabled: true, readyState: "live" })
);
```

**Remote stream verification** (the peer that receives media):

```typescript
const remoteTrackInfo = await bobPage.evaluate(() => {
  const pc = (window as any).__rtcPeerConnection;
  const receivers = pc?.getReceivers() ?? [];
  return receivers.map((r: RTCRtpReceiver) => ({
    kind: r.track?.kind,
    enabled: r.track?.enabled,
    readyState: r.track?.readyState,
  }));
});
expect(remoteTrackInfo).toContainEqual(
  expect.objectContaining({ kind: "audio", enabled: true, readyState: "live" })
);
```

**Video element verification** (for video calls):

```typescript
// Verify the remote video element has a non-zero video dimension
const videoReady = await bobPage.evaluate(() => {
  const video = document.querySelector("video[data-testid='remote-video']") as HTMLVideoElement;
  return video && video.videoWidth > 0 && video.videoHeight > 0;
});
expect(videoReady).toBe(true);
```

### 3.5 Signaling Relay Verification

Rather than intercepting raw SSE streams (complex in Playwright), verify signaling delivery via:

1. **HTTP-level**: After Alice sends `webrtc.offer` via `POST /messaging/signaling`, the response should be a `SignalingAck` with `status: "delivered"`.
2. **Effect-level**: Bob's page enters `connected` state (proves the offer was received, answer was sent back, and ICE completed).

For deeper signaling inspection, query the Events DDB table directly:

```typescript
function querySignalingEvents(callId: string, recipientId: string): any[] {
  const py = `
import json, boto3
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001",
                     region_name="us-east-1", aws_access_key_id="test",
                     aws_secret_access_key="test")
table = ddb.Table("Events")
resp = table.query(
    KeyConditionExpression="user_id = :uid",
    FilterExpression="call_id = :cid",
    ExpressionAttributeValues={":uid": "${recipientId}", ":cid": "${callId}"}
)
print(json.dumps(resp.get("Items", []), default=str))
`;
  const raw = execSync(`python3 -c '${py}'`, { ... }).toString();
  return JSON.parse(raw);
}
```

---

## 4. Implementation Plan

### 4.1 New Spec File Structure

Create `frontend/e2e/webrtc-media.spec.ts` as a separate file (not appended to `webrtc.spec.ts`) because:
- It requires a custom browser launch with fake media flags.
- It will have longer timeouts (ICE negotiation).
- It can be run independently or skipped in CI if WebRTC features are disabled.

```
frontend/e2e/webrtc-media.spec.ts
├── Constants + Imports
├── Session bootstrap (same pattern as webrtc.spec.ts)
├── DDB helpers (reuse seedCallSession, seedConversation, etc.)
├── Custom browser launch (fake media flags)
├── Helper: waitForConnectionState(page, state, timeout)
├── Helper: getTrackInfo(page, direction: "local" | "remote")
├── Helper: sendSignalingEvent(page, identity, envelope)
├── Section 78: Audio Call Media Establishment
├── Section 79: Video Call Media Establishment
├── Section 80: ICE Candidate Exchange Verification
├── Section 81: Media Teardown on Call End
├── Section 82: Reconnection After Brief Disconnection
└── Section 83: getUserMedia Permission Denied Handling
```

### 4.2 Test Scenarios

#### Section 78 -- Audio Call Media Establishment (4 tests)

```typescript
test.describe("78 -- Audio Call Media Establishment", () => {
  // 78.1: Alice invites Bob for audio, Bob accepts, both reach "connected"
  // 78.2: Alice's local stream has exactly 1 audio track (no video)
  // 78.3: Bob receives 1 remote audio track with readyState "live"
  // 78.4: RTCPeerConnection.connectionState === "connected" on both sides
});
```

#### Section 79 -- Video Call Media Establishment (5 tests)

```typescript
test.describe("79 -- Video Call Media Establishment", () => {
  // 79.1: Alice invites Bob for video, Bob accepts, both reach "connected"
  // 79.2: Alice's local stream has 1 audio + 1 video track
  // 79.3: Bob receives remote video track, <video> element has non-zero dimensions
  // 79.4: Alice receives Bob's remote video track
  // 79.5: CallSessionOverlay shows "Connected with Bob" text
});
```

#### Section 80 -- ICE Candidate Exchange (3 tests)

```typescript
test.describe("80 -- ICE Candidate Exchange Verification", () => {
  // 80.1: At least one local ICE candidate is gathered by each peer
  // 80.2: Signaling events table contains webrtc.ice_candidate entries for both directions
  // 80.3: RTCStatsReport shows "succeeded" candidate pair
});
```

#### Section 81 -- Media Teardown on Call End (4 tests)

```typescript
test.describe("81 -- Media Teardown on Call End", () => {
  // 81.1: After end call, all local tracks have readyState "ended"
  // 81.2: After end call, RTCPeerConnection.connectionState is "closed"
  // 81.3: After end call, CallSessionOverlay shows "Call ended."
  // 81.4: Calling getUserMedia again succeeds (hardware released)
});
```

#### Section 82 -- Reconnection (3 tests)

```typescript
test.describe("82 -- Reconnection After ICE Restart", () => {
  // 82.1: Simulate network interruption via page.route (block STUN), verify state -> "reconnecting"
  // 82.2: Remove block, verify state returns to "connected"
  // 82.3: If reconnection fails after maxRetries, state -> "failure"
});
```

#### Section 83 -- Permission Denied (2 tests)

```typescript
test.describe("83 -- getUserMedia Permission Denied", () => {
  // 83.1: Launch context WITHOUT fake-device flags, deny permission, verify state -> "failure"
  // 83.2: CallSessionOverlay shows appropriate error message
});
```

### 4.3 Helper Functions

```typescript
// ---------- Custom browser launch ----------
async function launchMediaBrowser(): Promise<Browser> {
  return chromium.launch({
    headless: true,
    args: [
      "--use-fake-device-for-media-stream",
      "--use-fake-ui-for-media-stream",
      "--disable-features=WebRtcHideLocalIpsWithMdns",
      "--no-sandbox",
    ],
  });
}

// ---------- Create context with media permissions ----------
async function createMediaContext(browser: Browser, identity: string): Promise<{ ctx: BrowserContext; page: Page }> {
  const ctx = await browser.newContext({
    permissions: ["camera", "microphone"],
    baseURL: BASE,
  });
  const page = await ctx.newPage();
  await injectAuth(page, identity);
  await page.goto(BASE);
  return { ctx, page };
}

// ---------- Wait for WebRTC connection state ----------
async function waitForConnectionState(
  page: Page,
  expectedState: string,
  timeout = 15_000,
): Promise<void> {
  await page.waitForFunction(
    (state) => {
      const pc = (window as any).__rtcPeerConnection;
      return pc && pc.connectionState === state;
    },
    expectedState,
    { timeout },
  );
}

// ---------- Get track information ----------
async function getTrackInfo(
  page: Page,
  direction: "senders" | "receivers",
): Promise<Array<{ kind: string; enabled: boolean; readyState: string }>> {
  return page.evaluate((dir) => {
    const pc = (window as any).__rtcPeerConnection;
    if (!pc) return [];
    const items = dir === "senders" ? pc.getSenders() : pc.getReceivers();
    return items
      .filter((item: any) => item.track)
      .map((item: any) => ({
        kind: item.track.kind,
        enabled: item.track.enabled,
        readyState: item.track.readyState,
      }));
  }, direction);
}

// ---------- Get ICE candidate pair stats ----------
async function getSucceededCandidatePair(
  page: Page,
): Promise<{ localType: string; remoteType: string } | null> {
  return page.evaluate(async () => {
    const pc = (window as any).__rtcPeerConnection;
    if (!pc) return null;
    const stats: RTCStatsReport = await pc.getStats();
    for (const [, report] of stats) {
      if (report.type === "candidate-pair" && report.state === "succeeded") {
        return {
          localType: report.localCandidateId,
          remoteType: report.remoteCandidateId,
        };
      }
    }
    return null;
  });
}

// ---------- Initiate full call flow (invite + accept) ----------
async function establishCall(
  alicePage: Page,
  bobPage: Page,
  opts: { conversationId: string; mode: "audio" | "video" },
): Promise<string> {
  const callId = `e2e_media_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

  // Alice sends invite
  const invResp = await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
    call_id: callId,
    conversation_id: opts.conversationId,
    callee_user_id: BOB_ID,
    initial_mode: opts.mode,
  });
  expect(invResp.status()).toBe(200);

  // Bob accepts
  const accResp = await apiPost(bobPage, "bob", `/messaging/messages/calls/${callId}/accept`);
  expect(accResp.status()).toBe(200);

  return callId;
}

// ---------- Navigate to conversation (triggers hook mount) ----------
async function openConversation(page: Page, conversationId: string): Promise<void> {
  await page.goto(`${BASE}/messages/${conversationId}`);
  await page.waitForLoadState("domcontentloaded");
}
```

### 4.4 Full Test Flow Example (Section 78.1)

```typescript
test("78.1 -- Alice invites Bob for audio, both reach connected state", async () => {
  test.setTimeout(45_000);

  // Both pages navigate to the conversation
  await openConversation(alicePage, CONVO_ID);
  await openConversation(bobPage, CONVO_ID);

  // Alice initiates call via UI (click audio call button)
  await alicePage.getByRole("button", { name: /audio call/i }).click();

  // Wait for invite to appear on Bob's side (CallSessionOverlay)
  await bobPage.getByText(/is calling you/i).waitFor({ state: "visible", timeout: 10_000 });

  // Bob accepts
  await bobPage.getByRole("button", { name: /accept/i }).click();

  // Wait for both to reach connected state
  await waitForConnectionState(alicePage, "connected", 15_000);
  await waitForConnectionState(bobPage, "connected", 15_000);

  // Verify UI shows connected
  await expect(alicePage.getByText(/Connected with/)).toBeVisible();
  await expect(bobPage.getByText(/Connected with/)).toBeVisible();

  // Clean up
  await alicePage.getByRole("button", { name: /end call/i }).click();
});
```

---

## Testing Strategy

### Unit Tests (pytest)

**Test file**: `tests/test_call_6.py`

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

**Test file**: `frontend/e2e/webrtc-media.spec.ts`

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
| CALL-002 | RTCPeerConnection for peer connection tests | Implemented | No -- must merge after |
| CALL-003 | getUserMedia for media track tests | Implemented | No -- must merge after |

### Depended On By

No downstream dependents identified.

### Merge Strategy

Sequential after CALL-002/003. E2E test file only. No production code changes.

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
| `frontend/e2e/webrtc.spec.ts` | 1-871 | Existing call lifecycle E2E tests (sections 73-77) |
| `frontend/e2e/webrtc-calls.spec.ts` | 1-661 | WebRTC call E2E tests (IMPLEMENTED) |
| `frontend/e2e/webrtc-media.spec.ts` | 1-1375 | WebRTC media E2E tests (IMPLEMENTED) |
| `frontend/src/hooks/useRtcPeerConnection.ts` | 1-518 | RTCPeerConnection lifecycle hook |
| `frontend/src/hooks/useMediaCapture.ts` | 1-315 | Media capture hook |
| `frontend/src/lib/webrtc.ts` | 1-149 | WebRTC utilities |
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | 1-671 | Call UI overlay with media rendering |
| `frontend/src/pages/messages/callStateMachine.ts` | 1-222 | Call state machine + teardown |
| `frontend/src/hooks/useMessagingStream.ts` | 148-184 | EVENT_TYPES including webrtc events |
| `app/services/messaging_call_signaling.py` | 1-359 | Backend signaling service |
| `app/routers/messaging.py` | 13244-13288 | Signaling HTTP endpoint |
