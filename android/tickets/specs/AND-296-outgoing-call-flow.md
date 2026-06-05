---
id: AND-296
title: Outgoing call flow
milestone: M7
epic: E40
priority: P0
size: L
status: draft
depends_on: [AND-295, AND-290]
blocks: [AND-297, AND-298]
---

# AND-296 — Outgoing call flow

## 1. Overview & Goal

Implement the **outgoing 1:1 call flow** for the TestLogon native Android app: the
client-side state machine and orchestration that takes a user from "tap call" on a
thread or profile screen, through **invite → ringing → connecting → connected →
ended**, wiring together the call REST API (AND-295), the signaling transport
(AND-290), and the WebRTC PeerConnection lifecycle (AND-289). This ticket owns the
**caller side** of the negotiation: it sends the SDP offer, fetches TURN/STUN
credentials, drives ICE, posts heartbeats while connected, and tears the call down
cleanly on end/timeout/failure.

This ticket does **not** own the rich in-call control surface (mute/cam/speaker/flip
— that is AND-298) nor the incoming/answer side (AND-297). It provides a minimal
caller UI scaffold (entry points, an "outgoing call" screen showing peer + state +
hang-up) sufficient to satisfy the acceptance criterion: **an outgoing 1:1 call
connects and ends.** The richer surface composes on top of the `CallManager` and
`CallUiState` defined here.

Success = from a thread or profile, the local user can place a 1:1 call to a peer who
is online and accepts; the two peers reach WebRTC `CONNECTED`/media-flowing state; and
either party ending the call returns both clients to an idle state with all resources
released.

## 2. Context & References

- **Epic E40** (call UX) — caller-side flow. Sibling tickets: AND-297 (incoming),
  AND-298 (in-call UI), AND-299 (group).
- **Epic E39** (WebRTC foundation): AND-289 PeerConnection wrapper, AND-290 signaling
  transport, AND-291 TURN/STUN credentials, AND-292 media capture, AND-293 renderers.
- **Direct deps**:
  - **AND-295 — Call API + DTOs**: provides `CallApi` Retrofit interface and Moshi
    DTOs for `/messaging/messages/calls/*`. This ticket consumes them; it must not
    redefine them.
  - **AND-290 — Signaling transport**: provides the `SignalingTransport` that POSTs
    local SDP/ICE to `/messaging/messages/calls/{call_id}/signal` and surfaces remote
    SDP/ICE via SSE/poll as a `Flow<SignalingEvent>`.
  - Transitively: **AND-289** (`PeerConnectionWrapper`), **AND-291** (TURN creds),
    **AND-018** (`ApiResult`), **AND-013** (401 refresh), **AND-011** (cookie jar),
    **AND-012** (CSRF).
- **Backend**: FastAPI + DynamoDB. Call endpoints under
  `/messaging/messages/calls/*` (verified against `/openapi.json`). Dev host
  `http://18.222.237.167:8000` is plaintext + unreliable; treat all signaling /
  control posts with ~20s timeouts.
- **Web reference**: `frontend/src/api/endpoints/*` call layer for parity of state
  names and reason codes; `frontend/src/api/types.ts` for DTO shapes.
- **Package**: all code under `com.testlogon.android`. New module:
  `feature-call` (depends on `core-network`, `core-model`, `core-ui`, `core-data`,
  and the E39 WebRTC modules).

## 3. Functional Requirements

FR-1. **Entry points.** A "Call" affordance is exposed from (a) the conversation/thread
top bar and (b) the peer profile screen. Both resolve a `conversationId` +
`calleeUserId` and navigate to the outgoing-call route. If `conversationId` is unknown
from a profile, a 1:1 conversation is resolved/created upstream and passed in (out of
scope to create here — callers must supply both ids).

FR-2. **Place call (invite).** On entry the flow generates a client `call_id` (UUIDv4)
and an `idempotency_key`, then POSTs `CallInviteIn` to
`/messaging/messages/calls/invite` with `initial_mode = "audio"` (default for this
ticket; video toggled later by AND-298/AND-292).

FR-3. **Negotiate.** After a successful invite the flow: (a) fetches TURN credentials
(AND-291); (b) creates the `PeerConnectionWrapper`, adds the local audio track
(AND-292 capture, audio-only baseline); (c) creates the SDP **offer**, sets local
description, and sends it via the signaling transport (`type = "offer"`); (d) relays
local ICE candidates as `type = "ice"` signaling events; (e) applies remote
answer/ICE received from the signaling `Flow`.

FR-4. **State machine.** The flow exposes a single source of truth `CallPhase`:
`Idle → Inviting → Ringing → Connecting → Connected → Ending → Ended(reason)` plus a
terminal `Failed(reason)`. Transitions are driven by REST responses, signaling events,
and `PeerConnection.PeerConnectionState`. `Ringing` is entered on a successful invite
(callee not yet accepted); `Connecting` on receipt of the remote answer; `Connected`
when PeerConnectionState reaches `CONNECTED`.

FR-5. **Heartbeat.** While in `Connected`, PATCH
`/messaging/messages/calls/{call_id}/heartbeat` every **15s** with `client_ts`. Surface
`elapsed_seconds`, `warn_low_balance`, `minutes_remaining`, and `action` to UI state.
If `action == "terminate"` or `minutes_remaining <= 0`, transition to `Ending` with
reason `"insufficient_balance"`.

FR-6. **Ringing timeout.** If no remote answer within **45s** of `Ringing`, POST
`/messaging/messages/calls/{call_id}/timeout` with `reason = "no_answer"` and move to
`Ended(no_answer)`.

FR-7. **End call.** User taps Hang Up at any non-idle phase → POST
`/messaging/messages/calls/{call_id}/end` with `reason = "hangup"`, tear down the
PeerConnection and signaling subscription, release capture, and transition to
`Ended(hangup)`. Remote-initiated end (signaling event or call-state notification)
produces `Ended(remote_hangup)`.

FR-8. **Decline handling.** If a `call.declined` signaling/state event arrives during
`Ringing`, transition to `Ended(declined)` and tear down (no `end` POST needed).

FR-9. **Outgoing-call screen.** Minimal Compose screen: callee display name/avatar
(from `core-model`), current phase label ("Calling…", "Ringing…", "Connecting…",
"00:42" once connected), and a single **End** button. No mute/video controls here
(AND-298). Audio routing uses the default earpiece/speaker per platform default.

FR-10. **Single active call.** Placing a call while one is active is rejected at the
entry point (toast + no navigation). The `CallManager` is a process singleton.

## 4. Technical Design

New module `feature-call` (Hilt). Core orchestrator is a `@Singleton` `CallManager`
that owns the call lifecycle independent of any composable, so the call survives
config changes and screen recomposition.

```kotlin
package com.testlogon.android.feature.call.domain

sealed interface CallPhase {
    data object Idle : CallPhase
    data object Inviting : CallPhase
    data object Ringing : CallPhase
    data object Connecting : CallPhase
    data class  Connected(val sinceElapsedMs: Long) : CallPhase
    data object Ending : CallPhase
    data class  Ended(val reason: CallEndReason) : CallPhase
    data class  Failed(val reason: CallEndReason) : CallPhase
}

enum class CallEndReason {
    HANGUP, REMOTE_HANGUP, DECLINED, NO_ANSWER,
    INSUFFICIENT_BALANCE, NEGOTIATION_FAILED, NETWORK, UNKNOWN
}

data class ActiveCall(
    val callId: String,
    val conversationId: String,
    val calleeUserId: String,
    val initialMode: String,          // "audio" | "video"
    val idempotencyKey: String,
)

@Singleton
class CallManager @Inject constructor(
    private val callApi: CallApi,                 // AND-295
    private val signaling: SignalingTransport,    // AND-290
    private val pcFactory: PeerConnectionFactoryProvider, // AND-289
    private val turnRepo: TurnCredentialsRepository,      // AND-291
    private val capture: MediaCaptureController,          // AND-292
    @ApplicationScope private val scope: CoroutineScope,
    private val clock: Clock,
) {
    val state: StateFlow<CallSessionState>

    suspend fun placeCall(conversationId: String, calleeUserId: String,
                          mode: String = "audio"): ApiResult<Unit>
    fun endCall(reason: CallEndReason = CallEndReason.HANGUP)
    fun isBusy(): Boolean
}

data class CallSessionState(
    val phase: CallPhase = CallPhase.Idle,
    val call: ActiveCall? = null,
    val peerName: String? = null,
    val elapsedSeconds: Int = 0,
    val warnLowBalance: Boolean = false,
    val minutesRemaining: Double? = null,
)
```

`placeCall` runs the orchestration as a single supervised coroutine job on
`ApplicationScope`; `endCall` cancels that job after issuing the `end` POST.
Internally the manager subscribes to `signaling.events(callId)` and to
`pcWrapper.connectionState` and folds both into `state`.

ViewModel is a thin adapter mapping `CallSessionState` → `CallUiState`:

```kotlin
package com.testlogon.android.feature.call.ui

@HiltViewModel
class OutgoingCallViewModel @Inject constructor(
    private val callManager: CallManager,
    savedState: SavedStateHandle,
) : ViewModel() {
    val uiState: StateFlow<CallUiState> =
        callManager.state.map(::toUi)
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), CallUiState.Connecting)
    fun onHangUp() = callManager.endCall(CallEndReason.HANGUP)
}
```

Navigation (extends AND-022 host):
`com.testlogon.android.feature.call.ui.OutgoingCallRoute` =
`"call/outgoing/{conversationId}/{calleeUserId}?mode={mode}"`. Entry points call
`callManager.isBusy()` then `navController.navigate(...)`.

Negotiation sequencing (caller):
1. `POST invite` → `CallInviteOut` (state `"ringing"`/`"initiated"`).
2. `POST {call_id}/turn-credentials` → configure `RTCConfiguration.iceServers`.
3. `pc.createOffer()` → `setLocalDescription` → `signaling.send(offer)`.
4. Collect remote `answer` from signaling `Flow` → `setRemoteDescription`.
5. Trickle ICE both directions (`onIceCandidate` → `signaling.send(ice)`; remote ice →
   `pc.addIceCandidate`).
6. `PeerConnectionState.CONNECTED` → phase `Connected`; start heartbeat ticker.

## 5. API Contract

DTOs are defined by **AND-295**; this ticket consumes them. Endpoints used (verified
against `/openapi.json`), all on the cookie-authenticated session with
`X-CSRF-Token` header (AND-012):

**POST `/messaging/messages/calls/invite`** — request `CallInviteIn`:
```json
{
  "call_id": "8f3c…",
  "conversation_id": "conv_123",
  "callee_user_id": "user_456",
  "initial_mode": "audio",
  "idempotency_key": "8f3c…-inv",
  "paid": false,
  "rate_cents_per_min": null
}
```
Response `CallInviteOut`:
```json
{ "call_id":"8f3c…","conversation_id":"conv_123","caller_user_id":"user_001",
  "callee_user_id":"user_456","state":"ringing","initial_mode":"audio",
  "start_ts":1733400000,"paid":false,"rate_cents_per_minute":null }
```

**POST `/messaging/messages/calls/{call_id}/turn-credentials`** → `TurnCredentialsOut`:
`{ "ttl_seconds":..., "expires_at":..., "ice_servers":[TurnIceServerOut...] }`.

**POST `/messaging/messages/calls/{call_id}/signal`** — request `CallSignalingIn`:
```json
{ "type":"offer","event_id":"<uuid>","conversation_id":"conv_123",
  "recipient_user_id":"user_456","nonce":"<uuid>","sent_at":1733400001,
  "payload":{ "sdp":"v=0…","sdpType":"offer" } }
```
`type ∈ {offer, answer, ice}`; for ice the payload carries `candidate`, `sdpMid`,
`sdpMLineIndex`. Response `CallSignalingOut` `{ event_id, call_id, conversation_id,
event_type, delivered_to, status }`.

**PATCH `/messaging/messages/calls/{call_id}/heartbeat`** — `{ "client_ts": 1733400060 }`
→ `HeartbeatOut { call_id, elapsed_seconds, total_cost_cents, balance_remaining_cents,
rate_cents_per_minute, next_bill_in_seconds, warn_low_balance, minutes_remaining,
max_duration_warning, action }`.

**POST `/messaging/messages/calls/{call_id}/end`** — `CallEndIn { reason, idempotency_key }`
→ `CallActionOut { call_id, conversation_id, state, from_state, reason, event_ts,
voicemail_eligible }`. Same `CallActionOut` returned by `timeout` and `decline`.

**POST `/messaging/messages/calls/{call_id}/timeout`** — `CallTimeoutIn { reason:"no_answer",
idempotency_key }`.

Remote answer/ICE/decline/remote-end are received via the AND-290 transport (SSE/poll),
not by polling these endpoints directly.

## 6. Data & State Management

- **Single source of truth**: `CallManager.state: StateFlow<CallSessionState>`, hot,
  application-scoped. Survives navigation and config changes; the screen merely renders.
- **No Room persistence of live call state.** A call is ephemeral; persisting it
  across process death is explicitly out of scope (a killed caller process tears the
  call down via signaling/heartbeat timeout on the peer/server).
- **DataStore**: none new for this ticket. (Audio-route and default-video prefs belong
  to AND-298.)
- **Idempotency**: `idempotency_key` generated once per `ActiveCall` and reused for
  invite; a distinct derived key (`"${idk}-end"`) for end, so a retried `end` is safe.
- **Timers**: heartbeat ticker (15s) and ringing-timeout (45s) are coroutine
  `delay`-loop jobs children of the orchestration job; cancelled on any terminal phase.
- **Elapsed time** is derived from `HeartbeatOut.elapsed_seconds` when available,
  otherwise from a local monotonic timer seeded at `Connected` (clock injected for
  testability).

## 7. Error Handling & Resilience

- All control posts (`invite`, `turn-credentials`, `signal`, `end`, `timeout`) use the
  shared OkHttp client (AND-009) with ~20s timeouts. These are **non-idempotent**
  POST/PATCH; **no automatic retry** except the single 401→refresh→retry from AND-013.
  The retry-backoff policy (AND-016) applies only to idempotent GETs and is **not**
  used here.
- **Invite failure** (network/5xx/4xx) → `Failed(NETWORK)` (or mapped error message via
  AND-015 `detail` mapping) and the screen shows an inline error + Retry/Close. No
  PeerConnection is created on invite failure.
- **TURN fetch failure** → fall back to STUN-only ICE config and continue; surface a
  non-fatal warning. If ICE then fails, → `Failed(NEGOTIATION_FAILED)`.
- **Signaling send failure** for offer/ice → one manual retry after 2s; persistent
  failure → `Failed(NETWORK)`.
- **PeerConnection** `FAILED`/`CLOSED` before `Connected` → `Failed(NEGOTIATION_FAILED)`;
  `DISCONNECTED` after `Connected` is tolerated for 10s (ICE restart attempt) before
  `Failed(NETWORK)`.
- **No answer in 45s** → `timeout` POST → `Ended(NO_ANSWER)`.
- **Heartbeat failure**: a single failed heartbeat is logged and ignored; **three
  consecutive** failures → `Ending(NETWORK)` (server-side call likely gone).
- **Teardown is idempotent and always runs** in a `finally` block: close PC, stop
  capture, cancel signaling subscription, cancel timers — even if the `end` POST throws.
- **Offline at entry** (connectivity probe AND-017 says no network) → block placing the
  call with an offline message rather than entering `Inviting`.

## 8. Security & Privacy

- All calls ride the existing **cookie-based session** with persistent cookie jar
  (AND-011) and `X-CSRF-Token` echo (AND-012); 401 triggers the single refresh+retry
  (AND-013). No bearer tokens are introduced.
- **TURN credentials are short-lived** (`ttl_seconds`); never logged, never persisted to
  disk, held only in memory for the call duration and re-fetched per call.
- **SDP/ICE payloads** may contain host IP candidates; they are transmitted only to the
  backend signaling endpoint over the session and are **never written to logs** (redact
  in any debug logging — log only `type`, `event_id`, `status`).
- **RECORD_AUDIO** runtime permission must be granted before capture; if denied, the
  flow aborts pre-invite with a rationale (no call placed). `CAMERA` is not requested in
  this audio-baseline ticket.
- No PII (peer name/avatar) is included in telemetry events.

## 9. Accessibility & i18n

- Outgoing-call screen: End button has a `contentDescription` ("End call"); phase text
  is announced via `liveRegion = LiveRegionMode.Polite` so screen readers hear
  "Ringing", "Connected", and the running duration is **not** spammed (announce phase
  changes only, not each tick).
- All strings (`Calling…`, `Ringing…`, `Connecting…`, `Call failed`, end reasons) live
  in `feature-call` `strings.xml`; no hardcoded UI text. Duration formatted with a
  locale-aware `mm:ss` formatter.
- Touch targets ≥48dp; End button meets contrast on the call background. Supports
  dynamic font scaling and dark theme via Material 3 (AND-019).

## 10. Telemetry & Logging

Structured, redacted events emitted through the shared logger (AND-052 conventions),
tagged `feature-call`:
- `call_outgoing_initiated` { call_id, conversation_id, initial_mode }
- `call_phase_changed` { call_id, from, to }
- `call_negotiation` { call_id, step: invite|turn|offer|answer|ice|connected, ok, latency_ms }
- `call_ended` { call_id, reason, duration_seconds }
- `call_heartbeat_warn` { call_id, warn_low_balance, minutes_remaining }
- `call_error` { call_id, stage, http_status?, error_code? }

No SDP, ICE candidate strings, TURN credentials, cookies, or peer identifiers beyond
opaque user ids are ever logged. Verbose WebRTC native logging is gated behind the
`debug`/internal flavor only.

## 11. Testing Strategy

**Unit (JVM, core-testing + MockWebServer AND-046):**
- `CallManagerTest` with a fake `SignalingTransport` (emits scripted answer/ice/decline/
  remote-end) and a fake `PeerConnectionWrapper` (drives `connectionState`):
  - happy path: `placeCall` → invite POST asserted → offer sent → answer applied →
    `CONNECTED` → phase `Connected`; `endCall` → end POST asserted → `Ended(HANGUP)`.
  - no-answer: no answer within (test) timeout → `timeout` POST → `Ended(NO_ANSWER)`.
  - decline event during Ringing → `Ended(DECLINED)`, **no** end POST.
  - remote-end event during Connected → `Ended(REMOTE_HANGUP)`.
  - invite 5xx → `Failed(NETWORK)`, no PC created.
  - TURN failure → STUN-only path still reaches `Connected`.
  - heartbeat `action="terminate"` → `Ending(INSUFFICIENT_BALANCE)`.
  - teardown always closes PC + stops capture (verified on every terminal branch).
- `CallStateMachineTest`: exhaustive legal/illegal transition table.
- Idempotency-key reuse asserted across invite + end retry.

**Compose UI tests (AND-048 patterns):** `OutgoingCallScreen` renders correct label per
phase; End button invokes `onHangUp`; error state shows Retry/Close.

**Instrumented / staged (CI emulator, AND-051):** end-to-end two-peer connect+end using
the staged signaling harness from AND-294 (loopback offer/answer) to satisfy the
acceptance criterion in an automated lane where a real second device is unavailable.

## 12. Dependencies & Sequencing

**Hard deps (must merge first):**
- **AND-295** — `CallApi` + DTOs (this ticket calls them; do not duplicate).
- **AND-290** — `SignalingTransport` (offer/answer/ice exchange + remote event Flow).
- Transitive: **AND-289** PeerConnection wrapper, **AND-291** TURN creds,
  **AND-292** audio capture, **AND-018** ApiResult, **AND-013/012/011** auth/session.

**Blocks:**
- **AND-297** (incoming call) reuses `CallManager`/`CallPhase` for the answer side.
- **AND-298** (in-call UI) composes its controls over `CallManager.state`.

**Sequencing:** land after E39 foundation (AND-289…294) and AND-295/AND-290 are green;
ship audio-only baseline first, then AND-298 adds video/controls and AND-292 video
capture.

## 13. Risks & Open Questions

- **Unreliable dev backend**: signaling latency over plaintext HTTP + SSE/poll may make
  the 45s ringing timeout flaky; timeout is configurable to allow tuning in staging.
- **Q**: Does the backend emit a distinct `call.declined`/`call.ended` event over the
  AND-290 transport, or must the caller infer end from `CallActionOut.state`? Assumed
  the transport surfaces both; confirm event taxonomy with AND-290 owner.
- **Q**: Is `initial_mode` server-authoritative (can backend downgrade video→audio)?
  Spec assumes client choice is honored for 1:1.
- **Risk**: process death mid-call leaves a dangling server call; mitigated by
  server-side heartbeat/timeout, not by this client.
- **Risk**: audio focus/route handling is minimal here; full audio-manager integration
  deferred to AND-298. May cause earpiece-vs-speaker UX gaps in this baseline.
- **Q**: `paid`/`rate_cents_per_min` — default `paid=false`; confirm whether 1:1 calls
  can be paid in current product config.

## 14. Acceptance Criteria

AC-1. From a thread top bar **and** from a profile screen, tapping Call navigates to the
outgoing-call screen with the correct `conversationId` + `calleeUserId`.
AC-2. Placing a call sends `POST /messaging/messages/calls/invite` with a generated
`call_id`, `idempotency_key`, and `initial_mode="audio"`, and enters `Ringing`.
AC-3. The caller fetches TURN creds, sends an SDP **offer** via signaling, applies the
remote **answer** and ICE, and reaches `Connected` when PeerConnectionState is
`CONNECTED` — **an outgoing 1:1 call connects** (verified in the staged two-peer test).
AC-4. While connected, heartbeat PATCH fires every 15s and updates elapsed time;
`action="terminate"` ends the call with `INSUFFICIENT_BALANCE`.
AC-5. Tapping End sends `POST …/end {reason:"hangup"}`, tears down PC + capture +
signaling, and reaches `Ended(HANGUP)` — **the call ends** and resources are released.
AC-6. No answer within 45s → `POST …/timeout {reason:"no_answer"}` → `Ended(NO_ANSWER)`.
AC-7. Remote decline/end during the flow yields `Ended(DECLINED)` /
`Ended(REMOTE_HANGUP)` and full teardown.
AC-8. Invite failure surfaces a mapped error with Retry/Close and creates no
PeerConnection; placing a second call while one is active is blocked.
AC-9. No SDP/ICE/TURN/cookie material appears in logs (verified by log inspection test).

## 15. Definition of Done

- `feature-call` module created under `com.testlogon.android`, wired into the nav host
  (AND-022) with the outgoing-call route and both entry points.
- `CallManager`, `CallPhase`/`CallSessionState`, `OutgoingCallViewModel`, and
  `OutgoingCallScreen` implemented per §4, consuming AND-295 DTOs and AND-290 transport
  with no duplication.
- All §14 acceptance criteria pass, including the staged two-peer connect+end test.
- Unit + Compose + instrumented tests from §11 added and green in CI (AND-050/051).
- Telemetry events (§10) emitted with redaction; lint/detekt/ktlint clean (AND-005).
- No new lint/strings-hardcoding violations; a11y checks (§9) pass.
- Code reviewed and merged to `android-port`; ticket linked to AND-297/AND-298 as
  blocked-by.
