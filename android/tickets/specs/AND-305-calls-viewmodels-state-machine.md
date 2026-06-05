---
id: AND-305
title: Calls ViewModels + state machine
milestone: M7
epic: E40
priority: P0
size: L
status: draft
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
- **Backend:** FastAPI dev host `http://18.222.237.167:8000` (plaintext, unreliable). Cookie-based session + `X-CSRF-Token`; the call HTTP transport is shared with the rest of the app and is not re-specified here.

## 3. Functional Requirements

FR-1. Model the complete 1:1 call lifecycle as an explicit FSM with these states: `Idle`, `Dialing` (outgoing invite sent, awaiting acceptance), `IncomingRinging` (invite received, awaiting local accept/decline), `Connecting` (accepted by both sides; SDP/ICE negotiation in flight), `Active` (media flowing; tracks duration), `Reconnecting` (transient ICE/network loss during Active), `Ending` (local or remote teardown in progress), and `Ended` (terminal, with a typed `EndReason`).

FR-2. Accept exactly one input type, `CallEvent`, covering user intents (`StartOutgoing`, `Accept`, `Decline`, `HangUp`, `ToggleMute`, etc. — control toggles are passed through without changing FSM state), remote signaling (`RemoteAccepted`, `RemoteDeclined`, `RemoteEnded`, `RemoteSignal`, `IceConnected`, `IceDisconnected`, `IceFailed`), and timers (`InviteTimeout`, `ReconnectTimeout`, `HeartbeatTick`).

FR-3. All transitions are total: every (state, event) pair either maps to a defined transition or is an explicit, logged no-op. No event may throw or leave the machine in an undefined state.

FR-4. Outgoing timeout: `Dialing` auto-transitions to `Ended(reason = TIMED_OUT)` after 45s with no remote acceptance, firing the `timeout` signaling call. Incoming ring timeout: `IncomingRinging` → `Ended(MISSED)` after 45s.

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

`dispatch` posts to an unbounded `Channel<CallEvent>` consumed by a single coroutine, guaranteeing serialized, ordered processing (no concurrent reduces, no locks in the reducer). Effects that produce events (e.g. `SendInvite` returning a `callId`) feed back via `dispatch(RemoteAccepted(...))`-style follow-ups from the repo callbacks.

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

This ticket defines no new endpoints; it orchestrates the AND-295 `CallApi` surface. The FSM emits effects that `CallRepository` translates to these idempotent-where-possible POSTs under `/messaging/messages/calls/`:

| Effect | Endpoint | Request body (shape) | Maps event on success |
|---|---|---|---|
| `SendInvite` | `POST /messaging/messages/calls/invite` | `{ "peer_id": str, "is_video": bool }` → `{ "call_id": str, "status": "ringing" }` | `RemoteAccepted` / poll or push |
| `SendAccept` | `POST /messaging/messages/calls/accept` | `{ "call_id": str }` | `Connecting` |
| `SendDecline` | `POST /messaging/messages/calls/decline` | `{ "call_id": str }` | `Ended(DECLINED)` |
| `SendEnd` | `POST /messaging/messages/calls/end` | `{ "call_id": str, "reason": str }` | `Ended` |
| `SendTimeout` | `POST /messaging/messages/calls/timeout` | `{ "call_id": str }` | `Ended(TIMED_OUT)` |
| (signal) | `POST /messaging/messages/calls/signal` | `{ "call_id": str, "sdp": str?, "ice": obj? }` | `RemoteSignal` |
| (heartbeat) | `POST /messaging/messages/calls/heartbeat` | `{ "call_id": str }` → `{ "status": str }` | `RemoteEnded` if peer gone |

Inbound remote events (`RemoteAccepted`, `RemoteEnded`, `RemoteSignal`) arrive via the AND-297 FCM push path and/or the heartbeat poll; AND-305 only consumes them as `CallEvent`s. FastAPI `detail` errors (string | `[{msg}]` | `{code,...}`) are mapped to `ApiResult.Error` by the shared layer and surface as `CallEffect.Error`. The full DTO/serialization contract is owned by AND-295; signaling integration testing by AND-306.

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
- **Retries:** only the idempotent **heartbeat GET-equivalent poll** uses bounded backoff; mutating signaling POSTs are not auto-retried (except best-effort `end`) to avoid duplicate calls.
- **Races:** the serialized event channel resolves "user pressed End while RemoteAccepted is in flight" deterministically — whichever event is dequeued first wins; the loser becomes a logged no-op (e.g. `RemoteAccepted` in `Ending` is ignored).
- **Reconnect budget:** §FR-5; 20s, then `NETWORK_LOST`.
- **Busy:** a second call attempt yields `CallBusy` effect, no state change.
- **Crash safety:** reducer is total and pure; any unexpected exception in an *effect* is caught, logged, and converted to `Ended(ERROR)` rather than crashing the app.

## 8. Security & Privacy

- No new credentials or storage of secrets. The `CallSnapshot` persists only call metadata (ids, peer display name, flags) — never SDP, ICE candidates, or media keys. Snapshot is cleared on `Ended` and on logout (hook the existing session-clear path).
- All signaling rides the existing authenticated cookie session with `X-CSRF-Token`; on 401 the shared client performs the single `POST /ui/session/refresh` + retry. The FSM treats a hard auth failure as `Ended(ERROR)`.
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
- **R2 — Timeout values:** 45s invite / 20s reconnect are assumptions; must match backend `timeout` semantics. Confirm against `frontend` call hook and OpenAPI before merge.
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
