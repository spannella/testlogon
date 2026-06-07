---
id: AND-305
title: Calls ViewModels + state machine
milestone: M7
epic: E40
priority: P0
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-296, AND-295]
blocks: [AND-297, AND-298, AND-299, AND-301, AND-302, AND-304, AND-306]
---

# AND-305 — Calls ViewModels + state machine

## 1. Overview & Goal

AND-296 wired the happy-path outgoing 1:1 call flow (invite → ringing → connect → end) directly inside a screen-bound ViewModel. That is sufficient to demonstrate a single connect/end cycle but does not survive the reality of telephony: invites time out, the callee declines, the network drops mid-call, the app is backgrounded and the process is killed, ICE/SDP signaling races the user pressing "End", and a second incoming invite arrives while one call is already active. AND-305 extracts the **authoritative call lifecycle into a single, process-scoped, deterministic finite state machine (FSM)** and the ViewModels that drive it.

The goal is a `CallStateMachine` in `core-data` (technology- and UI-agnostic) plus a `CallViewModel` (and a thin `IncomingCallViewModel`) in `feature-calls` that own a `StateFlow<CallUiState>`. Every UI surface built by sibling tickets — outgoing (AND-296), incoming full-screen (AND-297), in-call controls (AND-298), group (AND-299), telecom (AND-304) — renders from this one state and dispatches typed `CallIntent`s back into it. The FSM has exactly one source of truth for "what state is this call in," makes all transitions explicit and total (no implicit fall-throughs), and is **unit-tested** (the sole acceptance bullet for this ticket) to ~100% transition coverage with a virtual-time `TestDispatcher`.

This ticket delivers no new pixels and no new endpoints; it consumes the DTOs from AND-295 and the signaling calls already exercised by AND-296, and hardens their orchestration. The in-call rendering, ConnectionService binding, and signaling integration tests are owned downstream (AND-298, AND-304, AND-306 respectively).

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, `android/` subfolder, branch `android-port`. State machine lands in `core-data`; ViewModels in `feature-calls`. Namespace base `com.testlogon.android`.
- **Stack:** Kotlin 2.0.21, Coroutines/Flow, Hilt (KSP). FSM is pure Kotlin (no Android imports) so it can run on the JVM `test` source set without Robolectric.
- **Upstream deps:**
  - **AND-295 — Call API + DTOs** (`com.testlogon.android.core.network.calls`): DTOs and Retrofit `CallApi` for `/messaging/messages/calls/*` — invite/accept/decline/end/signal/timeout/heartbeat.
  - **AND-296 — Outgoing call flow:** existing `CallRepository` and the call-entry navigation from thread/profile; AND-305 refactors AND-296's inline orchestration into the FSM and leaves the entry points intact.
- **Downstream consumers (blocked by this ticket):** AND-297 (incoming push + full-screen), AND-298 (in-call UI), AND-299/AND-300 (group), AND-301 (billing), AND-302 (recording consent), AND-304 (ConnectionService/Telecom), AND-306 (state-machine + signaling tests).
- **Web reference:** `frontend/src/api/endpoints/calls*.ts` and signaling state handling in the web call hook; `frontend/src/api/types.ts` for the `CallStatus` enum mirrored here.
- **Backend:** FastAPI dev host `http://18.222.237.167:8000` (plaintext, unreliable). The web client uses a hybrid transport (verified against `src/api/client.ts`): a `Bearer` `Authorization` header from the auth store **plus** `credentials: "include"` for the cookie session **plus** an `X-CSRF-Token` header read from the `ui_csrf` cookie. The call HTTP transport is shared with the rest of the app and is not re-specified here. (The earlier "cookie-based session only" phrasing was incomplete — corrected; see §16.)

## 3. Functional Requirements

FR-1. Model the complete 1:1 call lifecycle as an explicit FSM with these states: `Idle`, `Dialing` (outgoing invite sent, awaiting acceptance), `IncomingRinging` (invite received, awaiting local accept/decline), `Connecting` (accepted by both sides; SDP/ICE negotiation in flight), `Active` (media flowing; tracks duration), `Reconnecting` (transient ICE/network loss during Active), `Ending` (local or remote teardown in progress), and `Ended` (terminal, with a typed `EndReason`).

FR-2. Accept exactly one input type, `CallEvent`, covering user intents (`StartOutgoing`, `Accept`, `Decline`, `HangUp`, `ToggleMute`, etc. — control toggles are passed through without changing FSM state), remote signaling (`RemoteAccepted`, `RemoteDeclined`, `RemoteEnded`, `RemoteSignal`, `IceConnected`, `IceDisconnected`, `IceFailed`), and timers (`InviteTimeout`, `ReconnectTimeout`, `HeartbeatTick`).

FR-3. All transitions are total: every (state, event) pair either maps to a defined transition or is an explicit, logged no-op. No event may throw or leave the machine in an undefined state.

FR-4. Outgoing timeout: `Dialing` auto-transitions to `Ended(reason = TIMED_OUT)` after **30s** with no remote acceptance, firing the `timeout` call (`reason="no_answer"`). **Correction:** the original 45s contradicted the web reference, which uses a `30_000`ms ring timeout and posts `timeoutCall(callId, { reason: "no_answer" })` (`ConversationView.tsx` ~L821-829); aligned to 30s. Incoming ring timeout: `IncomingRinging` → `Ended(MISSED)` after 30s (mirrors the outgoing budget; the web app has no separate verified incoming-side constant — see §16 Open assumptions). The exact budget is centralized in one config constant so it can be retuned.

FR-5. Reconnect: from `Active`, an `IceDisconnected` enters `Reconnecting` with a 20s budget; `IceConnected` restores `Active` (duration timer continues, not reset); `ReconnectTimeout` or `IceFailed` → `Ended(NETWORK_LOST)`.

FR-6. Single-call invariant: while a call is non-terminal, a new `StartOutgoing` or incoming invite for a *different* call is rejected with a `CallBusy` one-shot effect; the active call is unaffected.

FR-7. Surface a serializable snapshot so the call survives process death (FR detailed in §6) and can be rehydrated into `IncomingRinging`/`Active` on relaunch.

FR-8. Expose a cold `Flow<CallEffect>` (one-shot side effects: navigation, ringtone start/stop, vibration, error toasts, telecom callbacks) distinct from the hot `StateFlow<CallUiState>`.

## 4. Technical Design

The FSM is a pure reducer plus an effect-executing host. `CallStateMachine` is `@Singleton` (process-scoped, not screen-scoped) so a single call outlives navigation and is shared by incoming/outgoing/in-call screens.

```kotlin
// core-data/src/main/kotlin/com/testlogon/android/core/data/calls/CallState.kt
sealed interface CallState {
    val callId: String?
    data object Idle : CallState { override val callId = null }
    data class Dialing(override val callId: String, val peer: PeerRef, val isVideo: Boolean) : CallState
    data class IncomingRinging(override val callId: String, val peer: PeerRef, val isVideo: Boolean) : CallState
    data class Connecting(override val callId: String, val peer: PeerRef, val isVideo: Boolean) : CallState
    data class Active(override val callId: String, val peer: PeerRef, val isVideo: Boolean, val startedAtMs: Long) : CallState
    data class Reconnecting(override val callId: String, val peer: PeerRef, val since: Long) : CallState
    data class Ending(override val callId: String, val reason: EndReason) : CallState
    data class Ended(override val callId: String?, val reason: EndReason, val durationMs: Long) : CallState
}

enum class EndReason { LOCAL_HANGUP, REMOTE_HANGUP, DECLINED, TIMED_OUT, MISSED, NETWORK_LOST, BUSY, ERROR }

sealed interface CallEvent { /* StartOutgoing, Accept, Decline, HangUp, control toggles,
    RemoteAccepted, RemoteDeclined, RemoteEnded, RemoteSignal, IceConnected, IceDisconnected,
    IceFailed, InviteTimeout, ReconnectTimeout, HeartbeatTick */ }

sealed interface CallEffect {
    data class SendInvite(val peer: PeerRef, val isVideo: Boolean) : CallEffect
    data class SendAccept(val callId: String) : CallEffect
    data class SendDecline(val callId: String) : CallEffect
    data class SendEnd(val callId: String, val reason: EndReason) : CallEffect
    data class SendTimeout(val callId: String) : CallEffect
    data class StartTimer(val key: TimerKey, val delayMs: Long) : CallEffect
    data class CancelTimer(val key: TimerKey) : CallEffect
    data object PlayRingback : CallEffect
    data object StopAudio : CallEffect
    data class TelecomReport(val callId: String, val state: CallState) : CallEffect
    data class Error(val message: UiText) : CallEffect
    data object CallBusy : CallEffect
}
```

The reducer is pure and synchronously testable:

```kotlin
// Pure: no coroutines, no IO. Returns next state + effects to run.
fun reduce(state: CallState, event: CallEvent): Pair<CallState, List<CallEffect>>
```

The host wires it to the world:

```kotlin
@Singleton
class CallStateMachine @Inject constructor(
    private val repo: CallRepository,            // AND-296/AND-295
    private val timers: CallTimerScheduler,      // wraps coroutine delay; injectable for tests
    @ApplicationScope private val scope: CoroutineScope,
    private val snapshotStore: CallSnapshotStore // DataStore-backed, §6
) {
    val state: StateFlow<CallState>          // hot, replays latest
    val effects: SharedFlow<CallEffect>      // extraBufferCapacity=16, no replay

    fun dispatch(event: CallEvent)           // serializes events via a Channel; reduces then runs effects
}
```

`dispatch` posts to an unbounded `Channel<CallEvent>` consumed by a single coroutine, guaranteeing serialized, ordered processing (no concurrent reduces, no locks in the reducer). Effects that produce events feed back via `dispatch(RemoteAccepted(...))`-style follow-ups from the repo callbacks. Note (verified against `CallInviteIn`): `call_id` is a **client-supplied required request field**, not server-minted on the invite response — so the FSM/repo generates the `call_id` (and `conversation_id`/`callee_user_id`) before `SendInvite` and uses it directly for subsequent `{call_id}`-path calls; the `Dialing` state already carries `callId`, which is consistent with this. The FSM's internal `isVideo: Boolean` maps to the API's `initial_mode` string (`"audio"`/`"video"`).

ViewModels are thin adapters that observe the singleton and map to UI:

```kotlin
// feature-calls
@HiltViewModel
class CallViewModel @Inject constructor(
    private val sm: CallStateMachine
) : ViewModel() {
    val uiState: StateFlow<CallUiState> =
        sm.state.map { it.toUiState(now = ::elapsedRealtime) }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), CallUiState.Idle)

    fun onIntent(intent: CallIntent) = sm.dispatch(intent.toEvent())
}
```

`CallUiState` carries display-ready fields (peer name/avatar, formatted duration via a 1Hz ticker derived from `Active.startedAtMs`, control toggle booleans, connection-quality label). `IncomingCallViewModel` exposes only the ringing slice plus `accept()`/`decline()`.

## 5. API Contract

This ticket defines no new endpoints; it orchestrates the AND-295 `CallApi` surface. The FSM emits effects that `CallRepository` translates to these calls under `/messaging/messages/calls/`. **The table below was corrected against the OpenAPI index and `src/api/endpoints/messaging.ts` / `callBilling.ts`** — the original draft had wrong paths (flat `…/accept` etc. instead of `…/{call_id}/accept`), a wrong method (heartbeat is `PATCH`, not `POST`), and wrong request/response shapes. Verified contract:

| Effect | Method + Endpoint (authoritative) | Request schema | Response schema | Maps event on success |
|---|---|---|---|---|
| `SendInvite` | `POST /messaging/messages/calls/invite` | `CallInviteIn` = `{ call_id, conversation_id, callee_user_id, initial_mode="audio", paid=false, rate_cents_per_min?, idempotency_key? }` | `CallInviteOut` = `{ call_id, conversation_id, caller_user_id, callee_user_id, state, initial_mode, start_ts, paid, rate_cents_per_minute? }` | `RemoteAccepted` / poll or push |
| `SendAccept` | `POST /messaging/messages/calls/{call_id}/accept` | `CallAcceptIn` = `{ idempotency_key? }` (call_id is a path param) | `CallActionOut` | `Connecting` |
| `SendDecline` | `POST /messaging/messages/calls/{call_id}/decline` | `CallDeclineIn` = `{ reason="declined" }` | `CallActionOut` | `Ended(DECLINED)` |
| `SendEnd` | `POST /messaging/messages/calls/{call_id}/end` | `CallEndIn` = `{ reason="ended", idempotency_key? }` | `CallActionOut` | `Ended` |
| `SendTimeout` | `POST /messaging/messages/calls/{call_id}/timeout` | `CallTimeoutIn` = `{ reason="no_answer", idempotency_key? }` | `CallActionOut` | `Ended(TIMED_OUT)` |
| (signal) | `POST /messaging/messages/calls/{call_id}/signal` | `CallSignalingIn` = `{ type, event_id, conversation_id, recipient_user_id, nonce(≥8), sent_at, payload{} }`; `type` ∈ `webrtc.offer\|answer\|ice_candidate\|screen_share_start\|screen_share_stop` | `CallSignalingOut` = `{ event_id, call_id, conversation_id, event_type, delivered_to, status }` | `RemoteSignal` |
| (heartbeat) | `PATCH /messaging/messages/calls/{call_id}/heartbeat` | `HeartbeatIn` = `{ client_ts? }` (epoch seconds) | `HeartbeatOut` = `{ call_id, action="ok", elapsed_seconds, minutes_remaining, balance_remaining_cents, warn_low_balance, max_duration_warning, … }` | `RemoteEnded` if `action` signals teardown |

`CallActionOut` carries `{ call_id, conversation_id, state, event_ts, from_state?, reason?, voicemail_eligible=false }` — the FSM should map remote teardown off the returned `state`/`reason`, not a literal `"ringing"`/`"status"` field (those did not exist in the draft's assumed shapes).

Inbound remote events (`RemoteAccepted`, `RemoteEnded`, `RemoteSignal`) arrive via the AND-297 FCM push path and/or the heartbeat poll; AND-305 only consumes them as `CallEvent`s. **Error shapes (corrected):** invite/accept/decline/end/timeout/heartbeat declare only `200` + `422:HTTPValidationError` in the OpenAPI; runtime failures surface app-wide as `ErrorEnvelope` = `{ error: { code, message, details? } }` (schema `ErrorDetail`). The web client, however, reads the call-busy/declined codes from `err.body.detail.code` (see `ConversationView.tsx: extractCallErrorCode`), and branches on the literal codes **`call_busy`** and **`call_declined`** — the Android error mapper must read the same `detail.code` and map `call_busy → CallBusy`, `call_declined → Ended(DECLINED)`. The `signal` endpoint additionally returns typed `CallSignalingErrorOut` = `{ code, message }` for `400/403/404/409/429/503`. These are mapped to `ApiResult.Error` by the shared layer and surface as `CallEffect.Error`. The full DTO/serialization contract is owned by AND-295; signaling integration testing by AND-306.

## 6. Data & State Management

- **Hot state:** `StateFlow<CallState>` (single source of truth). ViewModels never hold their own call state; they project.
- **Effects:** `SharedFlow<CallEffect>` collected by the host (executes IO/timers) and, for navigation/UX effects, by the active screen.
- **Persistence for process death:** a minimal snapshot persisted to DataStore via `CallSnapshotStore`:

```kotlin
@JsonClass(generateAdapter = true)
data class CallSnapshot(
    val callId: String, val state: String, val peerId: String,
    val peerName: String, val isVideo: Boolean, val startedAtMs: Long?
)
```

  Written on every transition into `Dialing`/`IncomingRinging`/`Connecting`/`Active`; cleared on `Ended`. On cold start the host reads the snapshot and, if non-null, rehydrates to the persisted state and issues a `heartbeat` to confirm the call is still live (else → `Ended(NETWORK_LOST)`). Duration is computed from `startedAtMs` against `SystemClock.elapsedRealtime()`-anchored wall time so it stays correct across rehydration.
- **Timers:** `CallTimerScheduler` launches `delay`-based jobs in the application scope keyed by `TimerKey`; `StartTimer`/`CancelTimer` effects manage them. Tests inject a fake backed by `TestScope` virtual time.
- **Lifecycle scope:** state machine is `@Singleton`; ViewModels are screen-scoped and use `WhileSubscribed(5_000)` so rotation does not tear down the call.

## 7. Error Handling & Resilience

- **Unreliable host:** signaling POSTs use the shared ~20s timeout. `invite`/`accept`/`end`/`timeout` failures transition deterministically: a failed `invite` → `Ended(ERROR)` + `Error` effect; a failed `end` still drives the local FSM to `Ended` (we never strand the user in a call because the teardown POST failed) and best-effort retries the `end` POST.
- **Retries:** only the **heartbeat poll** uses bounded backoff. (Correction: heartbeat is a `PATCH` with a `{client_ts}` body — not a GET — but it is effectively idempotent/safe to repeat for liveness/billing-tick purposes, so bounded retry is acceptable.) Mutating signaling POSTs are not auto-retried (except best-effort `end`) to avoid duplicate calls; where the server supports it, retries should carry the same `idempotency_key` (present on `CallAcceptIn`/`CallEndIn`/`CallTimeoutIn`, and `CallInviteIn`).
- **Races:** the serialized event channel resolves "user pressed End while RemoteAccepted is in flight" deterministically — whichever event is dequeued first wins; the loser becomes a logged no-op (e.g. `RemoteAccepted` in `Ending` is ignored).
- **Reconnect budget:** §FR-5; 20s, then `NETWORK_LOST`.
- **Busy:** a second call attempt yields `CallBusy` effect, no state change.
- **Crash safety:** reducer is total and pure; any unexpected exception in an *effect* is caught, logged, and converted to `Ended(ERROR)` rather than crashing the app.

## 8. Security & Privacy

- No new credentials or storage of secrets. The `CallSnapshot` persists only call metadata (ids, peer display name, flags) — never SDP, ICE candidates, or media keys. Snapshot is cleared on `Ended` and on logout (hook the existing session-clear path).
- All signaling rides the existing authenticated transport (Bearer `Authorization` + cookie session + `X-CSRF-Token` from the `ui_csrf` cookie — verified `src/api/client.ts`); on 401 the shared client performs the single `POST /ui/session/refresh` + retry, and on refresh failure it logs the user out (`logout("session_expired")`). The FSM treats a hard auth failure as `Ended(ERROR)`.
- Microphone/camera permission *requests* are owned by the in-call UI (AND-298); the FSM refuses to enter `Connecting` without a `mediaReady` precondition flag set by the UI, preventing signaling before consent.

## 9. Accessibility & i18n

No direct UI is shipped here, but the `CallUiState` is built to be a11y-ready: all user-facing strings (`EndReason` labels, connection-quality text, busy message) are `UiText` references to `strings.xml` resources, never hardcoded — so AND-297/AND-298 can render and translate them. Duration is exposed both as a formatted string and raw millis so screens can supply a `contentDescription` like "call active, 3 minutes 12 seconds." No locale-specific formatting is baked into the FSM.

## 10. Telemetry & Logging

- Structured, tag-`CallSM` logs on every transition: `callId`, `from`, `to`, `event`, `reason`. No PII beyond opaque ids in logs (peer display name is omitted from logs).
- Counters/timings (via the app's existing analytics facade, no new SDK): `call_invite`, `call_connected`, `call_ended{reason}`, `call_reconnect`, `time_to_connect_ms` (Dialing/Connecting → Active), `call_duration_ms`. Emitted as `CallEffect`-driven analytics calls so they remain testable.
- A debug-only transition history ring buffer (last 50 transitions) is exposed for bug reports; excluded from release via build config.

## 11. Testing Strategy

This is the acceptance bullet ("Unit-tested") and the bulk of the work. JVM unit tests in `core-data/src/test` (no Robolectric needed — FSM is pure).

- **Pure reducer table tests:** parameterized over the full (state × event) matrix asserting the next state and emitted effects; coverage gate ≥ 95% line / 100% of defined transitions. Verifies no-op cases are no-ops.
- **Timeout tests** (virtual time, `TestScope` + `StandardTestDispatcher`): `Dialing` → `TIMED_OUT` at 45s; `IncomingRinging` → `MISSED` at 45s; `Reconnecting` → `NETWORK_LOST` at 20s; verify `SendTimeout`/`SendEnd` effects fired exactly once.
- **Race tests:** enqueue `HangUp` then `RemoteAccepted` and assert terminal `Ended(LOCAL_HANGUP)`; reverse order asserts `Connecting`.
- **Busy test:** second `StartOutgoing` during `Active` yields `CallBusy`, state unchanged.
- **Persistence tests:** simulate process death by constructing a new host from a serialized `CallSnapshot`; assert rehydration to `Active` with correct duration and a heartbeat confirmation/teardown.
- **Host integration tests:** `CallStateMachine` with a fake `CallRepository` (records effect→event) and fake timer scheduler; assert end-to-end `StartOutgoing → … → Ended`.
- **ViewModel tests:** Turbine on `uiState`; assert duration ticker, control toggles, and intent→event mapping.
- **Tooling:** JUnit5, Turbine, MockK, `kotlinx-coroutines-test`, `core-testing` dispatcher rule. Signaling/E2E with a real backend is explicitly AND-306.

## 12. Dependencies & Sequencing

- **Depends on:** AND-296 (outgoing flow + `CallRepository`/entry points to refactor) and transitively AND-295 (DTOs / `CallApi`). AND-296 must be merged first; this ticket moves its inline orchestration behind the FSM without changing entry-point signatures.
- **Blocks:** AND-297 (incoming UI dispatches into and renders this FSM), AND-298 (in-call controls), AND-299/AND-300 (group reuses the FSM core), AND-301 (billing observes `Active`/`Ended`), AND-302 (recording consent gates on `Active`), AND-304 (Telecom `ConnectionService` mirrors FSM state via `TelecomReport` effects), AND-306 (its tests target this state machine).
- **Sequencing note:** land `CallState`/`reduce` (pure) + tests first, then the host, then ViewModels, so downstream tickets can integrate against the stable `state`/`dispatch`/`effects` surface early.

## 13. Risks & Open Questions

- **R1 — Group reuse:** the 1:1 FSM may not cleanly extend to N-party (per-participant sub-states). Mitigation: model `peer` as a list-capable `PeerRef` set now; AND-299 owns the multi-party state extension. Open question: one FSM with participant sub-machines vs. a separate group FSM.
- **R2 — Timeout values:** RESOLVED for the outgoing ring (web reference uses 30s, now adopted — `ConversationView.tsx` ~L821). The 20s reconnect budget and the incoming-ring budget remain unverified assumptions (no backend/web constant found); confirm/retune before GA. The backend has no exposed invite-timeout constant in the OpenAPI — the server only offers the `…/{call_id}/timeout` endpoint the client drives.
- **R3 — Push vs. poll ordering:** if FCM (AND-297) and heartbeat both deliver `RemoteEnded`, idempotency relies on the no-op-in-`Ended` rule — covered by race tests.
- **R4 — Process-death media:** rehydrating to `Active` is metadata-only; actual media/WebRTC peer connection cannot be restored, so rehydration to `Active` immediately probes via heartbeat and likely resolves to `NETWORK_LOST`. Decide whether to rehydrate `Active` at all or only `IncomingRinging`/`Dialing` (lean toward rehydrating only pre-`Active` states).

## 14. Acceptance Criteria

AC-1. A pure `reduce(state, event)` exists with a total, defined transition for every state, and unit tests cover 100% of defined transitions (≥95% line coverage on `core-data` calls package).
AC-2. `CallStateMachine` is a `@Singleton` exposing `StateFlow<CallState> state`, `SharedFlow<CallEffect> effects`, and `dispatch(CallEvent)`; events are processed serially and ordering is deterministic (verified by race tests).
AC-3. Outgoing invite times out to `Ended(TIMED_OUT)` and incoming ring to `Ended(MISSED)` at the configured budget; `Reconnecting` resolves to `Active` on `IceConnected` or `Ended(NETWORK_LOST)` on timeout — all verified under virtual time.
AC-4. Single-call invariant holds: a concurrent call attempt emits `CallBusy` without disturbing the active call (tested).
AC-5. A persisted `CallSnapshot` rehydrates the machine on cold start and clears on `Ended`/logout (tested).
AC-6. `CallViewModel.uiState` projects display-ready state including a live 1Hz duration ticker and control toggles; `onIntent` maps intents to events (Turbine tests pass).
AC-7. The full unit-test suite passes in CI (`./gradlew :core-data:test :feature-calls:test`).

## 15. Definition of Done

- All AC met; `CallState`, `CallEvent`, `CallEffect`, `reduce`, `CallStateMachine`, `CallViewModel`, `IncomingCallViewModel`, `CallSnapshotStore`, `CallTimerScheduler` merged under `com.testlogon.android.core.data.calls` and `…feature.calls`.
- AND-296's inline orchestration removed/refactored; outgoing call still connects + ends (no regression).
- Unit tests green in CI; coverage gate enforced; no new lint/detekt violations; ktlint clean.
- Public FSM surface (`state`/`effects`/`dispatch`) KDoc-documented so AND-297/298/304 can integrate without reading internals.
- No hardcoded user-facing strings; snapshot persists no media secrets; logout clears call state.
- PR reviewed and merged to `android-port`; downstream tickets unblocked.

## 16. Citations & Assumption Audit

Each key technical claim, its verification verdict, and the exact source pointer.

1. **Invite endpoint** = `POST /messaging/messages/calls/invite`. VERDICT: **Verified**. Source: OpenAPI `POST /messaging/messages/calls/invite` (op `create_call_invite…`); frontend `src/api/endpoints/messaging.ts: startDirectCall` (posts `/messages/calls/invite`, base-prefixed to `/messaging`).
2. **Invite request shape** = `CallInviteIn { call_id, conversation_id, callee_user_id, initial_mode, paid, rate_cents_per_min?, idempotency_key? }`, response `CallInviteOut { …, state, start_ts, … }`. VERDICT: **Corrected** (draft claimed `{ peer_id, is_video }` → `{ call_id, status:"ringing" }`). Source: OpenAPI `components.schemas.CallInviteIn` / `CallInviteOut`; frontend body uses `{ conversation_id, callee_user_id, mode, idempotency_key? }` (`messaging.ts` L285-294).
3. **`call_id` is a client-supplied required request field on invite** (not server-minted). VERDICT: **Verified/Corrected** (clarifies §4). Source: OpenAPI `CallInviteIn.required = [call_id, conversation_id, callee_user_id]`.
4. **Accept endpoint** = `POST /messaging/messages/calls/{call_id}/accept`, body `CallAcceptIn { idempotency_key? }`, resp `CallActionOut`. VERDICT: **Corrected** (draft used flat `/accept` with `{call_id}` in body). Source: OpenAPI line `…/{call_id}/accept`; frontend `messaging.ts: acceptCallInvite` (L296).
5. **Decline endpoint** = `POST /messaging/messages/calls/{call_id}/decline`, body `CallDeclineIn { reason="declined" }`, resp `CallActionOut`. VERDICT: **Corrected** (path). Source: OpenAPI `…/{call_id}/decline`; `messaging.ts: declineCallInvite` (L301-308); `CallDeclineIn` schema.
6. **End endpoint** = `POST /messaging/messages/calls/{call_id}/end`, body `CallEndIn { reason="ended", idempotency_key? }`, resp `CallActionOut`. VERDICT: **Corrected** (path; draft also assumed `{call_id, reason}` body). Source: OpenAPI `…/{call_id}/end`; `messaging.ts: endCall` (L310-314); `CallEndIn` schema.
7. **Timeout endpoint** = `POST /messaging/messages/calls/{call_id}/timeout`, body `CallTimeoutIn { reason="no_answer", idempotency_key? }`, resp `CallActionOut`. VERDICT: **Corrected** (path). Source: OpenAPI `…/{call_id}/timeout`; `messaging.ts: timeoutCall` (L316-320); web posts `reason:"no_answer"` (`ConversationView.tsx` L826).
8. **Signal endpoint** = `POST /messaging/messages/calls/{call_id}/signal`, body `CallSignalingIn { type, event_id, conversation_id, recipient_user_id, nonce, sent_at, payload }`; `type` restricted to `webrtc.offer|answer|ice_candidate|screen_share_start|screen_share_stop`; resp `CallSignalingOut`. VERDICT: **Corrected** (draft assumed `{ call_id, sdp?, ice? }`). Source: OpenAPI `CallSignalingIn`/`CallSignalingOut`; `messaging.ts: sendSignal` (L1047 posts `/messaging/messages/calls/${callId}/signal`).
9. **Heartbeat = `PATCH` (not POST) `/messaging/messages/calls/{call_id}/heartbeat`**, body `HeartbeatIn { client_ts? }`, resp `HeartbeatOut { call_id, action, elapsed_seconds, minutes_remaining, … }`. VERDICT: **Corrected** (method + shape; draft said POST `{call_id}` → `{status}`). Source: OpenAPI `PATCH …/{call_id}/heartbeat`; frontend `callBilling.ts: sendCallHeartbeat` uses `api.patch(..., { client_ts })` (L70-74); `HeartbeatIn`/`HeartbeatOut` schemas.
10. **`CallActionOut` shape** = `{ call_id, conversation_id, state, event_ts, from_state?, reason?, voicemail_eligible }`. VERDICT: **Verified** (and used to correct the "status:ringing" assumption). Source: OpenAPI `components.schemas.CallActionOut`.
11. **Auth/transport = Bearer `Authorization` + cookie session (`credentials: include`) + `X-CSRF-Token` from `ui_csrf` cookie**. VERDICT: **Corrected** (draft §2 said "cookie-based session + X-CSRF-Token" only, omitting the Bearer token). Source: `src/api/client.ts` L157-171, L183.
12. **401 handling = single `POST /ui/session/refresh` then retry; logout on refresh failure**. VERDICT: **Verified**. Source: `src/api/client.ts: refreshSession` L121-130 (`logout("session_expired")`).
13. **Call-mutation error codes read from `detail.code`; literal codes `call_busy`, `call_declined`**. VERDICT: **Verified/Corrected** (draft described generic FastAPI `detail` string/array; the real branch is `err.body.detail.code`). Source: `ConversationView.tsx: extractCallErrorCode` (L780-786) and L833/L837. App-wide error envelope schema = `ErrorEnvelope { error: ErrorDetail{code,message,details?} }` (OpenAPI). Signal-only typed error = `CallSignalingErrorOut { code, message }` (OpenAPI signal `400/403/404/409/429/503`).
14. **Outgoing ring timeout = 30s** firing `timeout(reason="no_answer")`. VERDICT: **Corrected** (draft said 45s). Source: `ConversationView.tsx` L821-829 (`window.setTimeout(..., 30_000)`).
15. **Remote events delivered to the web client via SSE**; Android plan is FCM push + heartbeat poll. VERDICT: **Verified (web) / Unverified-assumption (Android)**. Source: `ConversationView.tsx` L820 ("dispatched … via SSE"), L877. No FCM call-event contract exists in the OpenAPI; the Android FCM path is owned by AND-297 and is an assumption here.
16. **FSM as pure Kotlin reducer + `@Singleton` host on coroutines/Flow; ViewModels with `stateIn(WhileSubscribed(5_000))`**. VERDICT: **Unverified-assumption** (framework/architecture choice, not derivable from backend/frontend). framework ref: Android ViewModel + Kotlin Flow guidance — https://developer.android.com/topic/architecture/ui-layer/stateholders and https://developer.android.com/kotlin/flow/stateflow-and-sharedflow .
17. **`CallSnapshot` persisted via DataStore for process-death survival**. VERDICT: **Unverified-assumption** (Android-side design). framework ref: Jetpack DataStore — https://developer.android.com/topic/libraries/architecture/datastore .
18. **20s reconnect budget; incoming-ring budget**. VERDICT: **Unverified-assumption** (no backend/web constant found). Source: absence in OpenAPI + `reference/src` (grep for ring/reconnect timeouts found only the 30s outgoing value).

### Corrections made
- §2: transport corrected from "cookie session + CSRF" to Bearer + cookie + CSRF (citation 11).
- §5 table: corrected all five `{call_id}`-path endpoints (accept/decline/end/timeout/signal), the heartbeat **method (POST→PATCH)**, and every request/response schema (invite `peer_id/is_video`→`CallInviteIn`; bare responses→`CallActionOut`; signal `{sdp,ice}`→`CallSignalingIn`; heartbeat `{status}`→`HeartbeatOut`) (citations 2,4-9).
- §5: error model corrected to `detail.code` (`call_busy`/`call_declined`) + `ErrorEnvelope`/`CallSignalingErrorOut` (citation 13).
- §4: clarified `call_id` is client-supplied; `isVideo`↔`initial_mode` mapping (citation 3).
- §7: heartbeat re-described as idempotent **PATCH** (not GET); idempotency-key retry note (citation 9).
- §8: transport line aligned with citation 11/12.
- §3 FR-4 + §13 R2: outgoing ring timeout corrected 45s→30s (citation 14).

### Open assumptions
- **Android delivery of remote call events via FCM** — backend exposes no FCM/push contract for call signaling (web uses SSE); confirm with AND-297. (citation 15)
- **20s reconnect budget and incoming-ring timeout** — no authoritative source; engineering defaults pending tuning. (citation 18)
- **All Android-framework architecture choices** (pure-reducer FSM, `@Singleton` host, DataStore snapshot, `WhileSubscribed(5_000)`) — design decisions, not contract-derived. (citations 16,17)
- **`reason` enum values** sent on end/timeout/decline beyond the verified `ended`/`no_answer`/`declined` defaults are assumed free-form strings (schemas declare plain `string` defaults, no enum).

## 17. Test Plan

All cases trace to §14 Acceptance Criteria. Targets: **JVM** = JVM/Robolectric unit (no device); **emu test35** = headless x86_64 API-35 AVD; **device A15** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64). The FSM core is pure Kotlin, so the bulk runs on JVM; instrumented/e2e cases note their target and whether the physical device is mandatory.

- **TC-AND-305-01 — Happy-path outgoing transition chain (pure reducer).** Type: unit. Target: JVM. Preconditions: fresh `CallState.Idle`. Steps: `reduce(Idle, StartOutgoing)` → assert `Dialing` + `[SendInvite, StartTimer(invite), PlayRingback]`; feed `RemoteAccepted` → `Connecting` + `[SendAccept-or-no-op, CancelTimer(invite), StopAudio]`; `IceConnected` → `Active(startedAtMs set)`; `HangUp` → `Ending`/`Ended(LOCAL_HANGUP)` + `[SendEnd]`. Expected: each (state,event) yields the documented next state and exact effect list; `Active.startedAtMs` set once. Traces: AC-1, AC-2.
- **TC-AND-305-02 — Total transition matrix / no-op coverage.** Type: unit (parameterized). Target: JVM. Preconditions: enumerate all `CallState`×`CallEvent` pairs. Steps: invoke `reduce` for every pair. Expected: no exception thrown; undefined pairs return the same state with empty (or log-only) effects; ≥95% line coverage on the `core-data` calls package and 100% of defined transitions exercised. Traces: AC-1.
- **TC-AND-305-03 — Outgoing ring timeout = 30s → TIMED_OUT.** Type: unit (virtual time, `StandardTestDispatcher`/`TestScope`). Target: JVM. Preconditions: machine in `Dialing`; fake `CallTimerScheduler` on virtual clock. Steps: advance virtual time to 30_000ms with no `RemoteAccepted`. Expected: transitions to `Ended(TIMED_OUT)`; `SendTimeout` effect (mapping to `POST …/{call_id}/timeout`, `reason="no_answer"`) fired exactly once. Traces: AC-3. (Note: budget corrected to 30s per §16 citation 14.)
- **TC-AND-305-04 — Incoming ring timeout → MISSED.** Type: unit (virtual time). Target: JVM. Preconditions: `IncomingRinging`. Steps: advance to the configured incoming budget with no local Accept/Decline. Expected: `Ended(MISSED)`; ringtone `StopAudio` effect; no `SendAccept`. Traces: AC-3.
- **TC-AND-305-05 — Reconnect resolve and fail.** Type: unit (virtual time). Target: JVM. Preconditions: `Active`. Steps: (a) `IceDisconnected` → `Reconnecting`, then `IceConnected` before 20s → back to `Active` with **duration not reset**; (b) separate run: `IceDisconnected` then advance >20s (or `IceFailed`) → `Ended(NETWORK_LOST)`. Expected: both branches as described; `startedAtMs` preserved across (a). Traces: AC-3.
- **TC-AND-305-06 — Single-call (busy) invariant.** Type: unit. Target: JVM. Preconditions: machine in `Active(call A)`. Steps: dispatch `StartOutgoing(call B)`; separately dispatch an incoming-invite event for a different call. Expected: state stays `Active(call A)` unchanged; a single `CallBusy` effect emitted per attempt. Traces: AC-4.
- **TC-AND-305-07 — Event serialization / race determinism.** Type: unit (host integration on `TestScope`). Target: JVM. Preconditions: host with fake repo + timer; machine in `Dialing`. Steps: enqueue `HangUp` then `RemoteAccepted` back-to-back; assert terminal `Ended(LOCAL_HANGUP)` and that the later `RemoteAccepted` is a logged no-op in `Ending`. Reverse order → `Connecting`. Expected: deterministic by dequeue order; no concurrent reduce. Traces: AC-2.
- **TC-AND-305-08 — Repository contract mapping (MockWebServer).** Type: contract/MockWebServer. Target: JVM (Robolectric not required; OkHttp MockWebServer runs on JVM). Preconditions: `CallRepository` wired to MockWebServer. Steps: trigger each effect and assert the outgoing request: invite → `POST /messaging/messages/calls/invite` body matches `CallInviteIn`; accept/decline/end/timeout → `POST …/{call_id}/{action}`; **heartbeat → `PATCH …/{call_id}/heartbeat`** with `{client_ts}`; signal → `POST …/{call_id}/signal` with `CallSignalingIn` (`type` matches the allowed `webrtc.*` pattern). Assert `Authorization: Bearer`, `X-CSRF-Token`, and cookie are attached. Expected: method, path, and JSON body exactly match the §5 (corrected) contract. Traces: AC-2, AC-7.
- **TC-AND-305-09 — Error-response handling (real shapes).** Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer scripted responses. Steps: (a) invite returns body `{ "detail": { "code": "call_busy" } }` → assert `CallBusy` effect, no terminal transition beyond busy; (b) `{ "detail": { "code": "call_declined" } }` → `Ended(DECLINED)`; (c) signal returns 409 `CallSignalingErrorOut { code, message }` → `CallEffect.Error` with mapped message, FSM unaffected; (d) generic `ErrorEnvelope` 500 on `end` → FSM still reaches `Ended` locally (best-effort end). Expected: codes mapped per §16 citation 13; never strands user in-call. Traces: AC-2, AC-7.
- **TC-AND-305-10 — Process-death snapshot persistence & rehydration.** Type: unit/integration (Robolectric for DataStore, or JVM with in-memory store). Target: JVM (Robolectric) or emu test35. Preconditions: `Active` call; `CallSnapshotStore` populated. Steps: serialize `CallSnapshot`; construct a new host from it (simulating cold start); assert rehydration to the persisted state and a `heartbeat` confirmation issued; on heartbeat failure → `Ended(NETWORK_LOST)`. Then drive `Ended` and assert snapshot cleared; assert logout clears snapshot. Expected: rehydrated duration correct vs `elapsedRealtime` anchor; snapshot stores no SDP/ICE/keys. Traces: AC-5, AC-2.
- **TC-AND-305-11 — ViewModel projection (Turbine).** Type: unit (Turbine + `kotlinx-coroutines-test`). Target: JVM (Robolectric for `ViewModel`/`SavedState` if needed). Preconditions: `CallViewModel` over a fake `CallStateMachine`. Steps: emit states through the machine; collect `uiState`; advance virtual time to observe the 1Hz duration ticker increment in `Active`; toggle mute/speaker intents. Expected: `uiState` carries display-ready peer/duration/toggle fields; `onIntent` maps each `CallIntent` to the correct `CallEvent` (dispatched to the machine). Traces: AC-6.
- **TC-AND-305-12 — Snapshot stores no media secrets (security).** Type: unit. Target: JVM. Preconditions: drive a full call carrying SDP/ICE via `RemoteSignal` payloads. Steps: inspect every persisted `CallSnapshot`. Expected: snapshot fields limited to ids/peer display name/flags/`startedAtMs`; no SDP, ICE candidates, TURN creds, or auth tokens present; cleared on `Ended` and on the session-clear/logout hook. Traces: AC-5.
- **TC-AND-305-13 — Flaky-host / offline orchestration.** Type: contract/MockWebServer (offline + slow paths). Target: JVM; mandatory real-network confirmation on **device A15** for true cellular flakiness. Preconditions: MockWebServer with dispatcher returning timeouts/socket resets; for the device run, toggle airplane mode mid-call. Steps: (a) invite times out at the shared ~20s client timeout → `Ended(ERROR)` + `Error` effect; (b) `end` POST fails → FSM still `Ended(LOCAL_HANGUP)`, best-effort retry observed; (c) during `Active`, drop network → `Reconnecting` then `NETWORK_LOST`. Expected: no crash, no stuck non-terminal state, deterministic terminal reasons. Device A15 note: must run on the physical device for genuine arm64/API-34 radio-loss behavior (emulator network drops are simulated and do not exercise the real connectivity callbacks). Traces: AC-2, AC-3.
- **TC-AND-305-14 — Incoming full-screen accessibility smoke (Compose-UI).** Type: Compose-UI / instrumented. Target: emu test35 (sufficient — no hardware needed). Preconditions: a minimal harness screen binding `IncomingCallViewModel` (UI itself ships in AND-297; this validates the a11y-ready `CallUiState` contract). Steps: render `IncomingRinging` and `Active` states; run accessibility checks (TalkBack semantics) on duration/end-reason/busy strings. Expected: all user-facing strings resolve from `strings.xml` (`UiText`), not hardcoded; duration exposes a `contentDescription`-suitable raw-millis + formatted pair. Traces: AC-6, AC-1.

### Coverage matrix

| §14 AC | Covered by |
|---|---|
| AC-1 (total `reduce`, 100% transitions, ≥95% line) | TC-01, TC-02, TC-14 |
| AC-2 (`@Singleton` host, serial/deterministic dispatch) | TC-01, TC-07, TC-08, TC-09, TC-10, TC-13 |
| AC-3 (timeouts + reconnect under virtual time) | TC-03, TC-04, TC-05, TC-13 |
| AC-4 (single-call/busy invariant) | TC-06 |
| AC-5 (snapshot rehydrate + clear on Ended/logout) | TC-10, TC-12 |
| AC-6 (ViewModel projection, 1Hz ticker, intent→event) | TC-11, TC-14 |
| AC-7 (full unit suite green in CI) | TC-02, TC-08, TC-09 (run under `:core-data:test` / `:feature-calls:test`) |
