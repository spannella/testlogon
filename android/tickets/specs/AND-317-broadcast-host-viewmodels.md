---
id: AND-317
title: Broadcast host ViewModels
milestone: M7
epic: E41
priority: P1
size: L
status: draft
depends_on: [AND-308]
blocks: [AND-318]
---

# AND-317 — Broadcast host ViewModels

## 1. Overview & Goal

This ticket delivers the presentation-layer state machine for the broadcast *host* experience in the native Android app (`com.testlogon.android`). It introduces a single source of truth — `BroadcastHostViewModel` — plus the `HostSessionState` finite-state machine (FSM), `HostSessionEvent` intent set, and the supporting `HostSessionStateMachine` reducer that drive every host screen: pre-flight, scheduling confirmation, connecting, live, paused, ended, and error.

The goal is to centralize *all* host session lifecycle logic in deterministic, unit-testable Kotlin code that mediates between the host-facing Compose UI and the lower-level data/WebRTC layers built in AND-307 (session create/schedule) and AND-308 (WebRTC ingest). This ViewModel owns the canonical session status, the WebRTC ingest connection status, derived health, and the legal transition graph; it does **not** own UI rendering (downstream feature screens), low-level RTCPeerConnection wiring (AND-308), nor input toggling (AND-310) or control RPCs (AND-309) beyond invoking their use cases and folding their results into state.

Success is defined by AND-318: the FSM and the ViewModel are fully unit-tested with deterministic coroutine tests and a fake repository/ingest controller, with no Android framework or network dependency required to run.

## 2. Context & References

- **Architecture:** `app -> feature-broadcast -> core-*`. This ticket lives in `feature-broadcast` (host package) and consumes `core-data`, `core-network`, `core-model`, `core-testing`. ViewModels expose `StateFlow<UiState>`; data calls return typed `ApiResult<T>`.
- **Upstream (depends_on):**
  - **AND-308 — WebRTC ingest** (`webrtc-ingest`, P0). Provides `WebRtcIngestController` (`inputs` + `webrtc-offer` publish of camera/mic). AND-317 observes its connection state and surfaces it; it does not implement SDP/ICE handling.
  - **AND-307 — Host session create/schedule** (transitive). Provides `BroadcastHostRepository` create/schedule/cancel-schedule operations.
- **Peers in M7/E41 (consumers, not dependencies):**
  - **AND-309 — Host controls** (start/stop/resume/reschedule, health report) invokes events on this ViewModel.
  - **AND-310 — Inputs management** toggles inputs through state owned here.
  - **AND-318 — Broadcast host tests** (this ticket *blocks* it) verifies the FSM and control transitions.
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` (plaintext, unreliable). Cookie-based auth + `X-CSRF-Token`; 401 → single `POST /ui/session/refresh` then retry. OpenAPI at `/openapi.json`. Web reference: `frontend/src/api/endpoints/*.ts`, `frontend/src/api/types.ts`.
- **Stack:** Kotlin 2.0.21, Compose/Material 3, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6, DataStore. minSdk 24 / targetSdk 35, JDK 17.

## 3. Functional Requirements

FR-1. Provide a `HostSessionState` sealed FSM enumerating: `Idle`, `Scheduling`, `Scheduled`, `PreFlight`, `Connecting`, `Live`, `Paused`, `Reconnecting`, `Ending`, `Ended`, `Error`. Each carries the data needed to render that phase.

FR-2. Provide a `HostSessionEvent` sealed intent set covering every host action and external signal: load/restore, schedule, cancel schedule, go-live (start), pause, resume, reschedule, stop/end, ingest-status changed, health-tick, refresh, and dismiss-error.

FR-3. Implement `HostSessionStateMachine.reduce(state, event)` as a **pure function** producing `(nextState, effects)`. Illegal transitions (e.g., `Pause` while `Idle`) return the current state unchanged plus a `LogIllegalTransition` effect; they must never crash.

FR-4. `BroadcastHostViewModel` exposes `val uiState: StateFlow<HostSessionState>` and a single `fun onEvent(event: HostSessionEvent)`. It executes effects (repository/ingest calls) off the FSM output and re-dispatches resulting internal events.

FR-5. The ViewModel must reflect the WebRTC ingest connection status from AND-308 by collecting `WebRtcIngestController.status: StateFlow<IngestStatus>` and translating it into `IngestStatusChanged` events. While `Live`, an ingest drop transitions to `Reconnecting`; recovery returns to `Live`; exhausted retries transition to `Error`.

FR-6. The ViewModel derives a `HostHealth` snapshot (uptime, ingest state, dropped-frame/bitrate hints when supplied, last-error) on a periodic health tick while `Live`/`Paused`/`Reconnecting`, exposed within the state object for AND-309's health report UI.

FR-7. Session lifecycle must survive process death / config change: persist the active `sessionId` and last-known status to DataStore so a relaunch enters `PreFlight`/`Reconnecting` and rehydrates from `GET /broadcasts/host/sessions/{session_id}`.

FR-8. All long-running work runs in `viewModelScope` on an injected `CoroutineDispatcher` (default = `Dispatchers.Default`) so tests can substitute `StandardTestDispatcher`.

FR-9. The ViewModel must be idempotent against duplicate events (e.g., double-tap "Go Live" must not open two ingest connections) by gating on the current state and an in-flight guard.

## 4. Technical Design

Package: `com.testlogon.android.feature.broadcast.host`.

### 4.1 State model

```kotlin
sealed interface HostSessionState {
    val sessionId: String?

    data object Idle : HostSessionState { override val sessionId: String? get() = null }

    data class Scheduling(override val sessionId: String?, val draft: SessionDraft) : HostSessionState
    data class Scheduled(override val sessionId: String, val startsAt: Instant) : HostSessionState
    data class PreFlight(override val sessionId: String, val devices: DeviceSelection) : HostSessionState
    data class Connecting(override val sessionId: String, val attempt: Int) : HostSessionState
    data class Live(
        override val sessionId: String,
        val startedAt: Instant,
        val ingest: IngestStatus,
        val health: HostHealth,
    ) : HostSessionState
    data class Paused(override val sessionId: String, val since: Instant, val health: HostHealth) : HostSessionState
    data class Reconnecting(override val sessionId: String, val attempt: Int, val since: Instant) : HostSessionState
    data class Ending(override val sessionId: String) : HostSessionState
    data class Ended(override val sessionId: String, val endedAt: Instant) : HostSessionState
    data class Error(
        override val sessionId: String?,
        val cause: HostError,
        val recoverable: Boolean,
        val previous: HostSessionState? = null,
    ) : HostSessionState
}
```

### 4.2 Events & effects

```kotlin
sealed interface HostSessionEvent {
    data class Load(val sessionId: String?) : HostSessionEvent
    data class Schedule(val draft: SessionDraft) : HostSessionEvent
    data object CancelSchedule : HostSessionEvent
    data object GoLive : HostSessionEvent
    data object Pause : HostSessionEvent
    data object Resume : HostSessionEvent
    data class Reschedule(val startsAt: Instant) : HostSessionEvent
    data object Stop : HostSessionEvent
    data class IngestStatusChanged(val status: IngestStatus) : HostSessionEvent
    data object HealthTick : HostSessionEvent
    data object Refresh : HostSessionEvent
    data object DismissError : HostSessionEvent
    // internal results re-dispatched by the VM after effects complete
    data class SessionLoaded(val result: ApiResult<HostSession>) : HostSessionEvent
    data class ControlResult(val action: ControlAction, val result: ApiResult<HostSession>) : HostSessionEvent
}

sealed interface HostEffect {
    data class LoadSession(val sessionId: String) : HostEffect
    data class CallControl(val action: ControlAction) : HostEffect   // start/stop/pause/resume/reschedule
    data object OpenIngest : HostEffect
    data object CloseIngest : HostEffect
    data object StartHealthTicker : HostEffect
    data object StopHealthTicker : HostEffect
    data class Persist(val sessionId: String, val status: HostSessionStatus) : HostEffect
    data class LogIllegalTransition(val from: String, val event: String) : HostEffect
}
```

### 4.3 Reducer (pure)

```kotlin
object HostSessionStateMachine {
    data class Result(val state: HostSessionState, val effects: List<HostEffect>)
    fun reduce(state: HostSessionState, event: HostSessionEvent): Result
}
```

Transition matrix (primary edges):

| From | Event | To | Effects |
|---|---|---|---|
| Idle/Scheduled | Schedule | Scheduling | CallControl(Schedule) |
| Scheduling | ControlResult(ok) | Scheduled | Persist |
| Scheduled/PreFlight | GoLive | Connecting(attempt=1) | CallControl(Start), OpenIngest |
| Connecting | IngestStatusChanged(Connected) | Live | StartHealthTicker, Persist |
| Live | Pause | Paused | CallControl(Pause) |
| Paused | Resume | Live | CallControl(Resume) |
| Live | IngestStatusChanged(Disconnected) | Reconnecting | (none; AND-308 owns retry) |
| Reconnecting | IngestStatusChanged(Connected) | Live | StartHealthTicker |
| Reconnecting | IngestStatusChanged(Failed) | Error(recoverable) | CloseIngest, StopHealthTicker |
| Live/Paused/Reconnecting | Stop | Ending | CallControl(Stop), CloseIngest, StopHealthTicker |
| Ending | ControlResult(ok) | Ended | Persist |
| any | ControlResult(err) | Error(prev=state) | LogIllegalTransition is *not* used here |
| Error(recoverable) | Refresh | previous ?: Idle | LoadSession |

Any unmatched (state, event) pair returns `Result(state, listOf(LogIllegalTransition(state::class.simpleName, event::class.simpleName)))`.

### 4.4 ViewModel

```kotlin
@HiltViewModel
class BroadcastHostViewModel @Inject constructor(
    private val repository: BroadcastHostRepository,
    private val ingest: WebRtcIngestController,        // from AND-308
    private val prefs: HostSessionPrefs,               // DataStore-backed
    @DefaultDispatcher private val dispatcher: CoroutineDispatcher,
    savedState: SavedStateHandle,
) : ViewModel() {

    private val _uiState = MutableStateFlow<HostSessionState>(HostSessionState.Idle)
    val uiState: StateFlow<HostSessionState> = _uiState.asStateFlow()

    fun onEvent(event: HostSessionEvent)              // reduce -> setState -> runEffects
    private fun runEffects(effects: List<HostEffect>)
}
```

`onEvent` is single-threaded via a `Mutex`/single dispatched channel so reduction is serialized. `runEffects` launches effects in `viewModelScope`; each repository/ingest result is folded back as an internal `ControlResult`/`SessionLoaded`/`IngestStatusChanged` event, so the reducer remains the *only* place state mutates. On `init`, the VM collects `ingest.status` and starts the health ticker only when an effect requests it (cancellable `Job`).

## 5. API Contract

This ViewModel does not define new endpoints; it composes use cases from AND-307/AND-308/AND-309. The contracts it relies on (consumed via `BroadcastHostRepository` returning `ApiResult<T>`):

- `GET /broadcasts/host/sessions/{session_id}` → rehydrate (FR-7).
  ```json
  { "session_id": "bs_01H...", "status": "live",
    "scheduled_start": "2026-06-05T18:00:00Z", "started_at": "2026-06-05T18:01:12Z",
    "ingest": { "state": "connected", "bitrate_kbps": 2400, "dropped_frames": 3 } }
  ```
  `status ∈ {scheduled, preflight, live, paused, ended}`.
- `POST /broadcasts/host/sessions/{session_id}/start | /pause | /resume | /stop` (AND-309) → returns the updated `HostSession` body above.
- WebRTC ingest (`POST .../inputs`, `POST .../webrtc-offer`) is wholly owned by AND-308 and surfaced only as `IngestStatus`.

All mutating calls send `X-CSRF-Token` (from `ui_csrf` cookie) via the shared OkHttp auth/CSRF interceptor. FastAPI errors map `detail` (`string | [{msg}] | {code,...}`) to `HostError` through the shared `ErrorMapper` in `core-network`. Retry/backoff applies to the idempotent `GET` only; control POSTs are **not** auto-retried (non-idempotent — surfaced as `Error` for explicit re-tap). N/A for endpoint *definition*: owned by AND-307/308/309.

## 6. Data & State Management

- **In-memory:** `StateFlow<HostSessionState>` is the single UI source of truth; Compose host screens (downstream) `collectAsStateWithLifecycle`.
- **Persistence (DataStore Preferences):** `HostSessionPrefs` stores `active_session_id: String?` and `last_status: HostSessionStatus`. Written via the `Persist` effect on every committed status change; cleared on `Ended`/`CancelSchedule`. No PII stored.
- **Restore path:** `init` reads `active_session_id`; if present, seeds `Reconnecting`/`PreFlight` and dispatches `Load(id)` to rehydrate from the GET. Room is **not** used here (no list/cache need at this layer; broadcast catalog caching is a separate ticket).
- **Health:** `HostHealth(uptime: Duration, ingest: IngestStatus, bitrateKbps: Int?, droppedFrames: Int?, lastError: HostError?)` recomputed on each `HealthTick` (default 2s cadence, injected for tests) from `startedAt` + latest `IngestStatus`.
- **Derived flags** (computed properties, not stored): `canGoLive`, `canPause`, `canStop`, `isReconnecting` — drive button enablement in AND-309/AND-310 without leaking transition rules into UI.

## 7. Error Handling & Resilience

- `HostError` taxonomy: `Network`, `Timeout`, `Auth`, `Csrf`, `Conflict` (e.g., session already live), `IngestFailed`, `Validation(field)`, `Unknown`. Mapped from `ApiResult.Error` and `IngestStatus.Failed`.
- **Timeouts:** rely on the shared 20s OkHttp call timeout for the dev host. A control call timeout → `Error(recoverable=true)` preserving `previous` so `Refresh`/retry can resume.
- **401 handling:** delegated to the shared interceptor (single `POST /ui/session/refresh` then retry). A second 401 → `HostError.Auth` and `Error` state prompting re-login (no infinite loops).
- **Ingest loss while Live:** transition `Live → Reconnecting`; AND-308 owns ICE-restart/backoff. The VM bounds total reconnect time (default 30s, injected); on exhaustion → `Error(IngestFailed, recoverable=true)` with `CloseIngest`/`StopHealthTicker`.
- **Illegal transitions:** never throw — return unchanged state + `LogIllegalTransition` effect (telemetry only).
- **Idempotency:** in-flight guard prevents duplicate `GoLive`/`Stop` from opening/closing ingest twice (FR-9).
- **Offline/stale:** if rehydrate GET fails offline, stay in `Reconnecting` with a stale banner flag rather than dropping to `Idle`.

## 8. Security & Privacy

- No credentials handled here; session cookies and `ui_csrf` are managed by the persistent OkHttp `CookieJar` and CSRF interceptor (core-network). The VM never reads cookie values.
- DataStore persists only `active_session_id` (opaque server id) and a status enum — no usernames, tokens, or media. DataStore is app-private storage; no `allowBackup` of the prefs file (excluded via backup rules).
- Camera/mic permission state is owned by AND-308/the host screen; the VM treats absent permission as a `PreFlight` blocker (`HostError.Validation("permissions")`) and never requests permissions itself.
- No secrets, tokens, or PII in logs (see §10); `sessionId` is opaque and acceptable to log at debug level.

## 9. Accessibility & i18n

Largely deferred to the host Compose screens (AND-309/AND-310), but this ticket supports them:
- The state object exposes a stable `statusLabelKey: Int` (string resource id) per phase rather than hard-coded English, so all phase labels (Connecting, Live, Reconnecting, Paused, Ended) are localizable. No raw user-facing strings originate in the ViewModel.
- Error messages are produced as `@StringRes` keys + format args, not literals, enabling translation and `TalkBack`-friendly announcements downstream.
- Time/duration values (`uptime`, `startsAt`) are carried as `Instant`/`Duration` and formatted by the UI with locale-aware formatters — the VM stores no pre-formatted strings.

## 10. Telemetry & Logging

- Inject `HostAnalytics` (interface in core-data) and emit structured events on committed transitions: `host_session_state_changed { session_id, from, to }`, `host_control_invoked { action, result }`, `host_ingest_state { state, attempt }`, `host_reconnect_exhausted`, `host_illegal_transition { from, event }`.
- Logging via the shared `Logger` at: `debug` for every reduce (`from -> to`), `warn` for illegal transitions and recoverable errors, `error` for terminal `Error`. No PII; `session_id` only.
- Health snapshots are **not** spammed to analytics; only state changes and explicit health-report opens (AND-309) emit events.
- All analytics calls are fire-and-forget on `viewModelScope` and fully mockable for AND-318.

## 11. Testing Strategy

Acceptance is "Unit-tested"; tests proper land in AND-318, but this ticket must ship code that is unit-testable and includes the FSM's own table tests.

- **Reducer tests (pure, no coroutines):** parameterized table covering every legal edge in §4.3 plus a representative sample of illegal pairs asserting `state` unchanged + single `LogIllegalTransition`. Property-style check: from any state, every event yields a non-null `Result` and never throws.
- **ViewModel tests:** `kotlinx-coroutines-test` `StandardTestDispatcher` via the injected dispatcher; `MainDispatcherRule` from `core-testing`. Use `FakeBroadcastHostRepository` and `FakeWebRtcIngestController` (settable `status` flow) and an in-memory `HostSessionPrefs`.
  - `GoLive` happy path: `Idle/Scheduled → Connecting → (ingest Connected) → Live`, asserting `OpenIngest` + `StartHealthTicker` ran once.
  - Reconnect: drop while `Live → Reconnecting → Live` on recovery; exhaustion → `Error(IngestFailed)`.
  - Control failure: `Stop` returns `ApiResult.Error` → `Error(previous=Live)`; `Refresh` restores.
  - Idempotency: two rapid `GoLive` open ingest once.
  - Restore: pre-seeded prefs → `Load` rehydrates to correct phase.
  - 401: repository surfaces `Auth` after refresh-retry exhausted → `Error(Auth)`.
- **Turbine** for `StateFlow` assertions. Target ≥90% line coverage on `HostSessionStateMachine` and `BroadcastHostViewModel`. No Robolectric/instrumentation required (no Android framework deps in this layer).

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-308 (WebRTC ingest) must provide `WebRtcIngestController` + `IngestStatus`. AND-307 (transitively) provides `BroadcastHostRepository` create/schedule/cancel. If AND-308's controller interface is not final, define the consumed interface here and let AND-308 implement it (adapter to avoid blocking).
- **Blocks:** AND-318 (host tests) consumes the fakes/seams created here.
- **Coordinates with:** AND-309 (controls call `onEvent(Stop/Pause/Resume/Reschedule)`), AND-310 (inputs read derived flags). Their PRs should merge after this lands.
- **Sequencing:** land FSM (`HostSessionStateMachine` + sealed types) first as a self-contained PR (testable in isolation), then the ViewModel + DataStore + ingest wiring.

## 13. Risks & Open Questions

- **R1 — Ingest interface churn (AND-308):** controller status enum shape may shift. Mitigation: own the consumed `IngestStatus`/`WebRtcIngestController` interface in this module.
- **R2 — Reconnect ownership split:** unclear whether ICE-restart backoff lives in AND-308 or here. Assumption: AND-308 owns retry; this VM only bounds total reconnect window. *Open question for AND-308 owner.*
- **R3 — Server status vocabulary:** `status` enum values for host sessions are assumed from the web reference; confirm against `/openapi.json` (`HostSessionStatus`). If `preflight` is not a server status, treat it as client-only.
- **R4 — Dev host unreliability:** flaky control POSTs may strand state in `Ending`. Mitigation: rehydrate-on-resume + explicit `Refresh`. Non-idempotent POSTs are not auto-retried.
- **OQ1:** Does the backend emit health (bitrate/dropped frames) on the session GET, or must it come solely from local WebRTC stats? Affects `HostHealth` source.
- **OQ2:** Is `Reschedule` allowed while `Live`, or only `Scheduled`? Spec assumes `Scheduled`-only.

## 14. Acceptance Criteria

1. `HostSessionState`, `HostSessionEvent`, `HostEffect`, and `HostSessionStateMachine.reduce` exist in `com.testlogon.android.feature.broadcast.host` with signatures per §4.
2. `reduce` is a pure function: identical input always yields identical output, throws on no input, and returns the unchanged state + exactly one `LogIllegalTransition` for any illegal `(state, event)` pair.
3. Every transition in the §4.3 matrix is implemented and covered by a passing table test.
4. `BroadcastHostViewModel` exposes `StateFlow<HostSessionState>` and a single `onEvent`; all mutation flows through the reducer; effects re-dispatch internal events.
5. Collecting `WebRtcIngestController.status` drives `Live ↔ Reconnecting`, with reconnect-window exhaustion → `Error(IngestFailed, recoverable=true)`.
6. Double-`GoLive` opens ingest exactly once; double-`Stop` closes exactly once (idempotency tests pass).
7. Active `sessionId` + status persist to DataStore and rehydrate on relaunch via `GET /broadcasts/host/sessions/{session_id}`.
8. Control-call failures and exhausted 401-refresh produce `Error` states preserving `previous`, recoverable via `Refresh`.
9. All long-running work uses the injected dispatcher; tests run deterministically under `StandardTestDispatcher` with no real network/Android deps.
10. Unit tests for the FSM and ViewModel pass in CI with ≥90% line coverage on the two core classes.

## 15. Definition of Done

- Code merged to `android-port` under `android/feature-broadcast/.../host/`, builds with AGP 8.7.3 / Gradle 8.9 / JDK 17, passing `./gradlew :feature-broadcast:detekt :feature-broadcast:testDebugUnitTest`.
- No new public API leaks transition rules to UI; only `uiState`, `onEvent`, and derived flags are exposed.
- No PII/tokens in logs or DataStore; backup-excluded prefs verified.
- All §14 acceptance criteria verified by passing unit tests; coverage report attached to the PR.
- KDoc on `HostSessionStateMachine`, the sealed types, and `BroadcastHostViewModel`; transition matrix documented in code.
- Hilt module binds `BroadcastHostRepository`, `WebRtcIngestController` (or adapter), `HostSessionPrefs`, and `@DefaultDispatcher`; app compiles with DI graph resolved.
- PR description links AND-308 (dep) and AND-318 (blocked); reviewed and approved by an E41 owner.
