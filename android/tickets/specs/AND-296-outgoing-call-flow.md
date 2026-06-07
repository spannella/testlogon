---
id: AND-296
title: Outgoing call flow
milestone: M7
epic: E40
priority: P0
size: L
status: reviewed
reviewed_on: 2026-06-06
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
description, and sends it via the signaling transport (`type = "webrtc.offer"`); (d) relays
local ICE candidates as `type = "webrtc.ice_candidate"` signaling events; (e) applies remote
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
(Required: `call_id`, `conversation_id`, `callee_user_id`. `initial_mode` defaults to
`"audio"`, `paid` to `false`. `rate_cents_per_min` is a nullable **integer** — note the
request field is `rate_cents_per_min` while the response field is `rate_cents_per_minute`.)
Response `CallInviteOut`:
```json
{ "call_id":"8f3c…","conversation_id":"conv_123","caller_user_id":"user_001",
  "callee_user_id":"user_456","state":"ringing","initial_mode":"audio",
  "start_ts":1733400000,"paid":false,"rate_cents_per_minute":null }
```

**POST `/messaging/messages/calls/{call_id}/turn-credentials`** (no request body) →
`TurnCredentialsOut`:
`{ "ttl_seconds":int, "expires_at":int, "ice_servers":[TurnIceServerOut{urls[],username,credential}...] }`.
Error responses use `TurnCredentialErrorOut { detail }` for 400/403/404/409/503.

**POST `/messaging/messages/calls/{call_id}/signal`** — request `CallSignalingIn`
(`call_id` is a path param, not a body field):
```json
{ "type":"webrtc.offer","event_id":"<uuid>","conversation_id":"conv_123",
  "recipient_user_id":"user_456","nonce":"<uuid (min 8 chars)>","sent_at":1733400001,
  "payload":{ "sdp":"v=0…","type":"offer" } }
```
**Corrected:** the `type` field is regex-constrained server-side to
`type ∈ {webrtc.offer, webrtc.answer, webrtc.ice_candidate, webrtc.screen_share_start,
webrtc.screen_share_stop}` — NOT the bare `offer/answer/ice` an earlier draft claimed.
The offer/answer `payload` carries `{ sdp, type }` where the inner `type` is the
RTCSdpType (`"offer"`/`"answer"`) — the field is `type`, NOT `sdpType`. For ICE the
payload carries `candidate`, `sdpMid`, `sdpMLineIndex`, `usernameFragment`. Response
`CallSignalingOut` `{ event_id, call_id, conversation_id, event_type, delivered_to,
status }` (web client narrows `status` to `"delivered" | "duplicate"`). Error responses
use `CallSignalingErrorOut { code, message }` for 400/403/404/409/429/503.

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
  (AND-011) and `X-CSRF-Token` echo (AND-012) — verified: web client reads the `ui_csrf`
  cookie and sets header `X-CSRF-Token`, with credentialed (cookie) requests; 401 triggers the single refresh+retry
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.

1. **POST `/messaging/messages/calls/invite` with request `CallInviteIn` → `CallInviteOut`.**
   VERDICT: Verified. SOURCE: OpenAPI `POST /messaging/messages/calls/invite`
   (op=create_call_invite…, req=CallInviteIn, resp=200:CallInviteOut); schemas
   `components.schemas.CallInviteIn`, `CallInviteOut`.
2. **`CallInviteIn` required fields = `call_id`, `conversation_id`, `callee_user_id`;
   `initial_mode` defaults `"audio"`, `paid` defaults `false`.** VERDICT: Verified.
   SOURCE: schema `CallInviteIn` (required[], defaults).
3. **Invite request rate field is `rate_cents_per_min` (nullable integer); response
   field is `rate_cents_per_minute` (nullable integer).** VERDICT: Verified (asymmetric
   naming). SOURCE: schemas `CallInviteIn.rate_cents_per_min`,
   `CallInviteOut.rate_cents_per_minute`.
4. **POST `/messaging/messages/calls/{call_id}/turn-credentials` (no body) →
   `TurnCredentialsOut { ttl_seconds, expires_at, ice_servers[] }`, each
   `TurnIceServerOut { urls[], username, credential }`.** VERDICT: Verified. SOURCE:
   OpenAPI `POST …/turn-credentials` (req empty, resp=200:TurnCredentialsOut); schemas
   `TurnCredentialsOut`, `TurnIceServerOut`; frontend
   `src/api/endpoints/messaging.ts: fetchTurnCredentials` (posts empty `{}` body).
5. **TURN error responses use `TurnCredentialErrorOut { detail }` (400/403/404/409/503).**
   VERDICT: Verified. SOURCE: OpenAPI `POST …/turn-credentials` resp list; schema
   `TurnCredentialErrorOut`.
6. **POST `/messaging/messages/calls/{call_id}/signal` request `CallSignalingIn`,
   `call_id` is a PATH param (not a body field).** VERDICT: Verified. SOURCE: OpenAPI
   `POST …/{call_id}/signal` (params=call_id…); schema `CallSignalingIn` has no
   `call_id` property.
7. **Signaling `type` values are `webrtc.offer | webrtc.answer | webrtc.ice_candidate`
   (plus screen-share variants), NOT bare `offer/answer/ice`.** VERDICT: Corrected
   (spec draft was wrong). SOURCE: schema `CallSignalingIn.type` regex
   `^(webrtc\.offer|webrtc\.answer|webrtc\.ice_candidate|webrtc\.screen_share_start|webrtc\.screen_share_stop)$`;
   frontend `src/api/endpoints/messaging.ts: SignalingPayload.type`;
   `src/hooks/useRtcPeerConnection.ts` (lines ~252, 304, 371, 441).
8. **Offer/answer signaling payload field is `type` (RTCSdpType), NOT `sdpType`; payload
   shape is `{ sdp, type }`.** VERDICT: Corrected (spec draft said `sdpType`). SOURCE:
   `src/hooks/useRtcPeerConnection.ts` offer payload (`payload:{ sdp, type }`, lines
   ~377-380, 447-450) and answer payload (~310-313).
9. **ICE candidate payload carries `candidate`, `sdpMid`, `sdpMLineIndex`,
   `usernameFragment`.** VERDICT: Verified (added `usernameFragment`). SOURCE:
   `src/hooks/useRtcPeerConnection.ts` ICE onicecandidate (lines ~258-263).
10. **`CallSignalingIn` constraints: `nonce` minLength 8; `event_id`/`conversation_id`/
    `recipient_user_id` maxLength 128.** VERDICT: Verified. SOURCE: schema
    `CallSignalingIn` field constraints.
11. **Response `CallSignalingOut { event_id, call_id, conversation_id, event_type,
    delivered_to, status }`; web client narrows `status` to `"delivered" | "duplicate"`.**
    VERDICT: Verified. SOURCE: schema `CallSignalingOut`; frontend
    `src/api/endpoints/messaging.ts: SignalingAck`.
12. **Signal error responses `CallSignalingErrorOut { code, message }` for
    400/403/404/409/429/503.** VERDICT: Verified. SOURCE: OpenAPI `POST …/signal` resp
    list; schema `CallSignalingErrorOut`.
13. **PATCH `/messaging/messages/calls/{call_id}/heartbeat` with `{ client_ts }` →
    `HeartbeatOut`.** VERDICT: Verified (method is PATCH). SOURCE: OpenAPI
    `PATCH …/heartbeat` (req=HeartbeatIn, resp=200:HeartbeatOut); frontend
    `src/api/endpoints/callBilling.ts: sendCallHeartbeat` (uses `api.patch`,
    `{ client_ts }`).
14. **`HeartbeatOut` fields: `call_id, elapsed_seconds, total_cost_cents,
    balance_remaining_cents, rate_cents_per_minute, next_bill_in_seconds,
    warn_low_balance, minutes_remaining, max_duration_warning, action`.** VERDICT:
    Verified. SOURCE: schema `HeartbeatOut`. Note `action` default is `"ok"` and
    `minutes_remaining` is a `number` (float); only `call_id` is required.
15. **Heartbeat `action == "terminate"` drives `Ending(INSUFFICIENT_BALANCE)`.**
    VERDICT: Unverified-assumption. SOURCE: schema `HeartbeatOut.action` documents only
    the default `"ok"`; the enum of action values (incl. `"terminate"`) is not specified
    in OpenAPI. Treat the exact action string as a contract assumption to confirm with
    backend/AND-295 owner.
16. **POST `/messaging/messages/calls/{call_id}/end` request `CallEndIn { reason,
    idempotency_key }` → `CallActionOut`.** VERDICT: Verified. SOURCE: OpenAPI
    `POST …/end`; schema `CallEndIn`. Note `CallEndIn.reason` default is `"ended"`; the
    spec's `reason:"hangup"` is a valid free-string client choice (not server-enforced).
17. **POST `/messaging/messages/calls/{call_id}/timeout` request `CallTimeoutIn
    { reason:"no_answer", idempotency_key }` → `CallActionOut`.** VERDICT: Verified.
    SOURCE: OpenAPI `POST …/timeout`; schema `CallTimeoutIn` (reason default
    `"no_answer"`).
18. **`CallActionOut { call_id, conversation_id, state, from_state, reason, event_ts,
    voicemail_eligible }`, also returned by `timeout`/`decline`.** VERDICT: Verified.
    SOURCE: schema `CallActionOut`; OpenAPI resp on end/timeout/decline all =
    200:CallActionOut.
19. **Cookie session + CSRF: requests are credentialed and echo `X-CSRF-Token` from the
    `ui_csrf` cookie; 401→refresh+retry.** VERDICT: Verified (CSRF transport). SOURCE:
    frontend `src/api/client.ts` (`credentials:"include"`, reads cookie `ui_csrf`, sets
    header `X-CSRF-Token`). The 401-refresh single-retry itself is an Android-side
    cross-ticket behavior (AND-013).
20. **A `decline` event exists server-side: POST `…/decline` request `CallDeclineIn`
    (reason default `"declined"`) → `CallActionOut`.** VERDICT: Verified. SOURCE: OpenAPI
    `POST …/decline`; schema `CallDeclineIn`.
21. **Remote answer/ICE/decline/remote-end are delivered via the AND-290 transport
    (SSE), not by polling.** VERDICT: Verified (mechanism in web reference). SOURCE:
    frontend `src/hooks/useRtcPeerConnection.ts` listens to `messaging:webrtc-signal`
    events; `src/hooks/useMessagingStream.ts` enumerates
    `webrtc.offer/webrtc.answer/webrtc.ice_candidate` stream event types. The exact
    Android transport shape and the discrete `call.declined`/`call.ended` event taxonomy
    are owned by AND-290 (see Open assumptions).
22. **CallManager / CallPhase / Hilt singleton / Compose screen design.** VERDICT:
    Unverified-assumption (Android-side design, no backend source). Framework choices —
    Jetpack Compose StateFlow/ViewModel (framework ref:
    https://developer.android.com/develop/ui/compose/state),
    Hilt `@Singleton` (framework ref:
    https://developer.android.com/training/dependency-injection/hilt-android),
    WebRTC `PeerConnection.PeerConnectionState` (framework ref:
    https://webrtc.github.io/webrtc-org/native-code/android/). These are internal
    implementation decisions, not contract claims.
23. **RECORD_AUDIO runtime permission required before audio capture.** VERDICT: Verified
    (Android platform requirement). SOURCE: framework ref
    https://developer.android.com/reference/android/Manifest.permission#RECORD_AUDIO
    (dangerous permission, runtime grant required).

### Corrections made

- **§5 / FR-3 — signaling `type` values.** Changed `offer/answer/ice` →
  `webrtc.offer/webrtc.answer/webrtc.ice_candidate`; documented the full server-enforced
  regex set and that bare values are rejected. (Claim 7.)
- **§5 — signaling offer/answer payload field.** Changed `sdpType` → `type`; documented
  payload shape `{ sdp, type }`. (Claim 8.)
- **§5 — signal request.** Noted `call_id` is a path param (not a body field); added
  `nonce` min-length 8 and the `usernameFragment` ICE field. (Claims 6, 9, 10.)
- **§5 — signal/turn error shapes.** Added `CallSignalingErrorOut { code, message }` and
  `TurnCredentialErrorOut { detail }` with their HTTP statuses. (Claims 5, 12.)
- **§5 — invite request/response naming.** Documented the `rate_cents_per_min` (req,
  integer) vs `rate_cents_per_minute` (resp) asymmetry and the required-field set.
  (Claims 2, 3.)
- **§5 — `CallSignalingOut.status`.** Noted web client narrows to
  `"delivered" | "duplicate"`. (Claim 11.)
- **§8 — CSRF.** Cited the exact cookie name `ui_csrf` and credentialed transport.
  (Claim 19.)

No endpoint path or HTTP method in the original draft was wrong — all paths/methods
matched the OpenAPI index. Corrections were confined to signaling field names/values and
added error-shape detail.

### Open assumptions

- **Heartbeat `action` enum.** OpenAPI documents only the default `"ok"`; the exact
  string used to force termination (spec assumes `"terminate"`) and the
  `minutes_remaining <= 0` trigger are not enumerated in the contract. Confirm with the
  AND-295/backend owner. (Claim 15.)
- **Discrete remote end/decline event taxonomy over AND-290.** The web reference handles
  `webrtc.*` signaling and infers call lifecycle, but a backend-emitted distinct
  `call.declined` / `call.ended` event over the Android SSE/poll transport is not visible
  in the available sources; ownership is AND-290. The spec already flags this in §13.
  (Claim 21.)
- **`initial_mode` server authority.** Whether the backend may downgrade `video→audio` is
  not expressed in the schema (it is a free string with default `"audio"`). Assumed
  client choice honored for 1:1; confirm with backend.
- **Paid 1:1 calls in current product config.** `paid`/`rate_cents_per_min` are accepted
  by `CallInviteIn`, but whether 1:1 paid calls are enabled is product config, not
  determinable from the schema. Default `paid=false` is safe.
- **All `feature-call` Android types/classes (`CallManager`, `CallPhase`,
  `OutgoingCallViewModel`, etc.)** are new design with no upstream source to verify
  against; they are validated only against framework references (Claim 22).

## 17. Test Plan

Test target legend — JVM: local JVM/Robolectric unit, no device; MWS: contract test
against MockWebServer; EMU: headless emulator AVD `test35` (x86_64, API 35); DEVICE:
physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a) reachable via adb.

- **TC-AND-296-01** — Type: contract/MockWebServer (MWS, JVM). Target: `CallManager` +
  `CallApi` (AND-295) against MockWebServer. Preconditions: MWS enqueues
  `200 CallInviteOut {state:"ringing"}`. Steps: call `placeCall(conv, callee)`; capture
  the recorded request. Expected: exactly one `POST /messaging/messages/calls/invite`;
  body has generated `call_id` (UUIDv4), `idempotency_key`, `callee_user_id`,
  `conversation_id`, `initial_mode:"audio"`; `X-CSRF-Token` header present; phase →
  `Ringing`. Traces: AC-2.
- **TC-AND-296-02** — Type: unit (JVM). Target: `CallManager` orchestration with fake
  `SignalingTransport` + fake `PeerConnectionWrapper`. Preconditions: invite succeeds;
  fake signaling will emit a `webrtc.answer` then drive PC to `CONNECTED`. Steps: run
  happy path: invite → fetch TURN → create offer → send offer signal → apply remote
  answer → ICE exchange → PC `CONNECTED`. Expected: an offer is sent with
  `type:"webrtc.offer"` and payload `{ sdp, type:"offer" }`; remote answer applied;
  phase → `Connected`; heartbeat ticker starts. Traces: AC-3.
- **TC-AND-296-03** — Type: contract/MockWebServer (MWS, JVM). Target: signaling send
  via the AND-290 transport / `CallApi`. Preconditions: MWS enqueues
  `200 CallSignalingOut {status:"delivered"}`. Steps: trigger an offer send and an ICE
  send. Expected: `POST /messaging/messages/calls/{call_id}/signal`; offer body
  `type:"webrtc.offer"`, payload `{sdp,type}`; ICE body `type:"webrtc.ice_candidate"`,
  payload `{candidate,sdpMid,sdpMLineIndex,usernameFragment}`; `nonce` length ≥ 8; no
  `call_id` in the JSON body. Traces: AC-3.
- **TC-AND-296-04** — Type: contract/MockWebServer (MWS, JVM). Target: heartbeat loop.
  Preconditions: call in `Connected`; MWS enqueues sequential
  `200 HeartbeatOut` responses (with advancing `elapsed_seconds`). Steps: advance the
  injected `Clock` by 15s twice. Expected: two `PATCH …/heartbeat` requests with
  `{client_ts}`; `elapsedSeconds` in `CallSessionState` updates from
  `HeartbeatOut.elapsed_seconds`; `warn_low_balance`/`minutes_remaining` surfaced.
  Traces: AC-4.
- **TC-AND-296-05** — Type: unit (JVM). Target: `CallManager` balance handling.
  Preconditions: connected; MWS/fake returns `HeartbeatOut {action:"terminate"}` (and a
  variant with `minutes_remaining:0`). Steps: deliver that heartbeat. Expected: phase →
  `Ending` then `Ended`/`Failed` with reason `INSUFFICIENT_BALANCE`; PC + capture torn
  down. (Note: `action` string is an unverified assumption — see §16 Open assumptions;
  test pins the assumed contract.) Traces: AC-4.
- **TC-AND-296-06** — Type: contract/MockWebServer (MWS, JVM). Target: end flow.
  Preconditions: connected; MWS enqueues `200 CallActionOut {state:"ended"}`. Steps:
  call `endCall(HANGUP)`. Expected: `POST …/end` with `{reason:"hangup",
  idempotency_key:"<idk>-end"}`; PC closed, capture stopped, signaling subscription and
  timers cancelled (assert in `finally`); phase → `Ended(HANGUP)`. Traces: AC-5.
- **TC-AND-296-07** — Type: unit (JVM). Target: ringing-timeout path. Preconditions:
  phase `Ringing`; no answer emitted; ringing timeout shortened via injected config.
  Steps: advance `Clock` past the timeout (45s prod). Expected: `POST …/timeout` with
  `{reason:"no_answer"}`; phase → `Ended(NO_ANSWER)`; full teardown. Traces: AC-6.
- **TC-AND-296-08** — Type: unit (JVM). Target: remote decline + remote end handling.
  Preconditions: (a) `Ringing`, fake signaling emits a decline event; (b) `Connected`,
  fake signaling emits a remote-end event. Steps: emit each event. Expected: (a) phase →
  `Ended(DECLINED)` with **no** `…/end` POST issued; (b) phase → `Ended(REMOTE_HANGUP)`;
  both fully tear down. Traces: AC-7.
- **TC-AND-296-09** — Type: unit (JVM). Target: invite failure + single-active-call
  guard. Preconditions: MWS/fake returns `500` (and a 4xx variant) on invite; separately,
  a call already active. Steps: call `placeCall` on failure; then attempt a second
  `placeCall`/entry while busy. Expected: invite failure → `Failed(NETWORK)` with a
  mapped error message and **no** PeerConnection created; second placement is blocked
  (`isBusy()` true, no navigation, toast). Traces: AC-8.
- **TC-AND-296-10** — Type: unit (JVM). Target: TURN fallback + offline-at-entry.
  Preconditions: (a) `turn-credentials` returns `503 TurnCredentialErrorOut`; (b)
  connectivity probe (AND-017) reports offline. Steps: (a) place call and let fake PC
  still reach `CONNECTED` via STUN-only config; (b) attempt to place a call while
  offline. Expected: (a) call proceeds with STUN-only iceServers, non-fatal warning
  surfaced, reaches `Connected`; (b) placement blocked with offline message, phase never
  leaves `Idle`. Traces: AC-3, AC-8.
- **TC-AND-296-11** — Type: unit/log-inspection (JVM). Target: redaction in telemetry +
  logger. Preconditions: run a full happy-path call with a capturing log appender. Steps:
  exercise invite→offer→ice→connected→end. Expected: captured logs/telemetry contain no
  SDP strings, ICE candidate strings, TURN `credential`/`username`, cookies, or
  `X-CSRF-Token`; signaling logs include only `type`, `event_id`, `status`. Traces: AC-9.
- **TC-AND-296-12** — Type: Compose-UI (EMU). Target: `OutgoingCallScreen` rendering.
  Preconditions: ViewModel fed scripted `CallUiState` for each phase. Steps: render
  Calling/Ringing/Connecting/Connected(00:42)/error states; tap End. Expected: correct
  per-phase label; duration shown when connected; End invokes `onHangUp`; error state
  shows Retry/Close. Traces: AC-1, AC-5, AC-8.
- **TC-AND-296-13** — Type: Compose-UI / accessibility (EMU). Target:
  `OutgoingCallScreen` a11y. Preconditions: rendered call screen. Steps: assert
  semantics. Expected: End button has `contentDescription` "End call" and target ≥ 48dp;
  phase text node uses `liveRegion = Polite` and announces on phase change only (not per
  duration tick); no hardcoded strings (all from `strings.xml`); passes contrast/dynamic
  font checks. Traces: AC-1, AC-5.
- **TC-AND-296-14** — Type: instrumented/e2e (EMU, staged loopback). Target: two-peer
  connect+end via the AND-294 staged signaling harness (loopback offer/answer). Steps:
  place a call; harness answers and trickles ICE; reach `Connected`; end from caller.
  Expected: PeerConnectionState reaches `CONNECTED`, phase `Connected`, then `…/end` →
  `Ended(HANGUP)` with both sides released — automated proof of the acceptance criterion
  where a second real device is unavailable. Traces: AC-3, AC-5.
- **TC-AND-296-15** — Type: instrumented/e2e + security permission (DEVICE — MUST run on
  the physical Galaxy A15). Target: real RECORD_AUDIO grant/deny + real audio capture and
  end-to-end 1:1 audio call against a second peer/staging. Preconditions: app installed
  on SM-A156U via adb; mic available. Steps: (a) deny RECORD_AUDIO → attempt to place a
  call; (b) grant RECORD_AUDIO → place a 1:1 call, confirm mic capture + media flow,
  then End. Expected: (a) flow aborts pre-invite with rationale, no invite POST, no PC;
  (b) call reaches `Connected` with real audio, End tears everything down to `Idle`.
  MUST be on the physical device: real microphone capture, runtime permission dialog, and
  arm64-v8a/API-34 audio behavior cannot be validated on the x86_64 emulator. Traces:
  AC-2, AC-3, AC-5, plus the §8 RECORD_AUDIO security requirement.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
|---|---|
| AC-1 (entry points → screen with correct ids) | TC-12, TC-13 |
| AC-2 (invite POST + Ringing) | TC-01, TC-15 |
| AC-3 (TURN/offer/answer/ICE → Connected) | TC-02, TC-03, TC-10, TC-14, TC-15 |
| AC-4 (heartbeat 15s + terminate→INSUFFICIENT_BALANCE) | TC-04, TC-05 |
| AC-5 (End → teardown → Ended(HANGUP)) | TC-06, TC-12, TC-13, TC-14, TC-15 |
| AC-6 (no answer 45s → timeout → Ended(NO_ANSWER)) | TC-07 |
| AC-7 (remote decline/end → teardown) | TC-08 |
| AC-8 (invite failure Retry/Close + single-active guard) | TC-09, TC-10, TC-12 |
| AC-9 (no SDP/ICE/TURN/cookie in logs) | TC-11 |
