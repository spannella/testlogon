---
id: AND-149
title: Reconnect/backoff + lifecycle
milestone: M3
epic: E20
priority: P1
size: M
status: draft
depends_on: [AND-143]
blocks: []
---

# AND-149 — Reconnect/backoff + lifecycle

## 1. Overview & Goal

The SSE client core delivered in **AND-143** (`SseClient`, an OkHttp `EventSource`
wrapper that emits a cold `Flow<SseEvent>`) connects, streams server-sent events,
and performs a naive reconnect after a drop. This ticket hardens that client for
the realities of the TestLogon dev backend (`http://18.222.237.167:8000`), which
is a plaintext HTTP host that frequently stalls, returns transient 5xx, and
silently drops idle connections. It also wires the stream to the Android process
and UI lifecycle so streams subscribe only while a screen is actually observing
them, and tear down cleanly otherwise.

The goal of AND-149 is twofold:

1. **Resilient reconnection** — a deterministic, jittered exponential-backoff
   reconnect policy with a cap, "fresh-event" backoff reset, and explicit,
   observable connection states so the UI can render connecting / live / stale /
   offline affordances.
2. **Lifecycle correctness** — the SSE connection starts when a Compose screen
   (or `ViewModel`) begins collecting and the app is in the foreground, and is
   suspended/cancelled when the screen stops collecting or the app is
   backgrounded — with **zero leaked sockets, coroutines, or `EventSource`
   instances**.

Success is defined by the acceptance bullets: the stream **survives host blips**
(connection drops, transient 5xx, idle timeouts) without surfacing a hard error,
and there are **no leaks**, verified by instrumented and unit tests.

## 2. Context & References

- **Module:** `core-network` (the `SseClient` lives here; lifecycle helpers may
  expose a thin `core-ui` collector extension). Package root
  `com.testlogon.android.core.network.sse`.
- **Depends on AND-143** (`sse-client-core`) — provides `SseClient`,
  `SseEvent`, and the OkHttp `EventSource.Factory` wiring. AND-149 extends, it
  does not replace, that surface.
- **Transitively depends on AND-009** (network/OkHttp + cookie-jar foundation)
  via AND-143 — the persistent cookie jar and `X-CSRF-Token` interceptor are
  reused unchanged; SSE requests must carry the session cookies so the stream is
  authenticated.
- **Stack:** Kotlin 2.0.21, Coroutines/Flow, OkHttp 4.12 (`okhttp-sse`),
  AndroidX Lifecycle 2.8 (`lifecycle-runtime-compose`,
  `ProcessLifecycleOwner`), Hilt (KSP). minSdk 24 / targetSdk 35, JDK 17.
- **Reference:** the web app's `EventSource` reconnect behavior in
  `frontend/src/api/` (browser `EventSource` auto-reconnect with
  `Last-Event-ID`) is the functional baseline we are matching on native.
- **Backend constraint:** design for ~20 s connect/read timeouts on the SSE
  socket budget, bounded backoff, and offline/stale UI states (project context).

## 3. Functional Requirements

FR-1. **Exponential backoff with jitter.** After a non-deliberate disconnect
(socket close, IOException, timeout, retryable 5xx), the client reconnects after
`delay = min(cap, base * 2^attempt) ± jitter`. Defaults: `base = 1s`,
`multiplier = 2.0`, `cap = 30s`, full jitter in `[0.5, 1.0]` of computed delay.

FR-2. **Backoff reset on healthy stream.** When the stream has been connected and
delivering events continuously for `resetAfter = 60s` (or on the first event
after a successful `onOpen`, per configuration), the attempt counter resets to 0
so the next blip starts from `base` again.

FR-3. **Bounded, then steady-state.** There is no terminal "give up" for a
foreground subscriber; the client keeps retrying at the `cap` interval
indefinitely while subscribed, surfacing `Reconnecting`/`Offline` states rather
than throwing. (A configurable `maxAttempts` is supported but defaults to
unlimited for foreground use.)

FR-4. **`Last-Event-ID` resume.** Each event's `id` (when present) is retained;
on reconnect the client sends `Last-Event-ID: <id>` so the server can resume.

FR-5. **Explicit connection state.** The client exposes a hot
`StateFlow<SseConnectionState>` distinct from the event flow:
`Idle | Connecting | Connected | Reconnecting(attempt, nextRetryAt) | Stale | Offline`.

FR-6. **Foreground/background subscribe/unsubscribe.** While the process is
backgrounded (`ProcessLifecycleOwner` below `STARTED`), active streams are
paused: the underlying `EventSource` is cancelled and state moves to `Idle`. On
return to foreground, streams that still have collectors auto-resume.

FR-7. **Lifecycle-scoped collection.** A Compose-friendly collector starts the
stream when a screen reaches a given `Lifecycle.State` (default `STARTED`) and
cancels it when it falls below — with no double-subscription on config change.

FR-8. **Reference-counted single connection.** Multiple collectors of the *same*
stream key share one `EventSource`; the connection opens on the first collector
and closes when the last collector and the lifecycle both release it.

FR-9. **Flaky-host tolerance.** Idle-read timeouts and transient `502/503/504`
are treated as reconnectable (not fatal). Non-retryable conditions
(`401`, `403`, `404`, malformed-stream after auth) propagate distinctly: `401`
triggers exactly one `POST /ui/session/refresh` then a single retry (per project
auth rule); other 4xx surface as `Offline` with a non-retry reason.

FR-10. **No leaks.** On cancellation/teardown the `EventSource` is cancelled, its
`OkHttp` `Call` released back to the pool, and all child coroutines complete.

## 4. Technical Design

All new types live in `com.testlogon.android.core.network.sse`.

```kotlin
data class SseBackoffConfig(
    val base: Duration = 1.seconds,
    val multiplier: Double = 2.0,
    val cap: Duration = 30.seconds,
    val jitter: ClosedFloatingPointRange<Double> = 0.5..1.0,
    val resetAfter: Duration = 60.seconds,
    val maxAttempts: Int = Int.MAX_VALUE,
    val staleAfter: Duration = 45.seconds, // no events while "Connected" => Stale
)

sealed interface SseConnectionState {
    data object Idle : SseConnectionState
    data object Connecting : SseConnectionState
    data object Connected : SseConnectionState
    data class Reconnecting(val attempt: Int, val nextRetryAtMillis: Long) : SseConnectionState
    data object Stale : SseConnectionState
    data class Offline(val reason: OfflineReason) : SseConnectionState
}

enum class OfflineReason { NO_NETWORK, AUTH, NOT_FOUND, SERVER, UNKNOWN }
```

The backoff math is pure and unit-testable:

```kotlin
class SseBackoffPolicy(
    private val config: SseBackoffConfig,
    private val random: Random = Random.Default,
) {
    fun delayFor(attempt: Int): Duration {
        val raw = config.base * config.multiplier.pow(attempt)
        val capped = minOf(raw, config.cap)
        val factor = config.jitter.start +
            random.nextDouble() * (config.jitter.endInclusive - config.jitter.start)
        return capped * factor
    }
    fun shouldReset(connectedFor: Duration) = connectedFor >= config.resetAfter
}
```

The resilient stream is built as a Flow operator over the AND-143 `SseClient`,
keeping AND-143's surface intact:

```kotlin
class ResilientSseStream @Inject constructor(
    private val sseClient: SseClient,           // from AND-143
    private val policy: SseBackoffPolicy,
    private val sessionRefresher: SessionRefresher, // POST /ui/session/refresh (AND-009)
    private val clock: Clock = Clock.System,
) {
    val state: StateFlow<SseConnectionState>     // hot, per-stream instance

    fun events(request: SseRequest): Flow<SseEvent>
}
```

`events()` is a cold `Flow` implemented with `channelFlow` + `retryWhen`:

- On collect: emit `Connecting`, open the `EventSource` via `sseClient`.
- `onOpen` → `Connected`, record `connectedAt`, schedule a stale watchdog
  (`staleAfter`).
- Each event → re-arm the stale watchdog, store `lastEventId`, reset attempt if
  `policy.shouldReset(now - connectedAt)`.
- On failure classified as retryable → emit `Reconnecting(attempt, nextRetryAt)`,
  `delay(policy.delayFor(attempt))`, increment attempt, re-open with
  `Last-Event-ID`.
- On `401` → call `sessionRefresher.refreshOnce()`; success retries immediately
  (attempt unchanged), failure → `Offline(AUTH)`.
- Non-retryable failure → `Offline(reason)` and stop (no further retries until
  re-collected).

**Sharing & ref-counting.** A `SseStreamRegistry` keyed by `SseRequest` returns a
`shareIn`-backed `SharedFlow` with `SharingStarted.WhileSubscribed(
stopTimeout = 5.seconds, replayExpiration = 0)`, so the one connection lives
while ≥1 collector is active and tears down 5 s after the last leaves
(debouncing rapid recompositions/config changes).

**Process lifecycle gate.** A `ProcessLifecycleOwner`-driven `StateFlow<Boolean>`
(`isForeground`) is combined into the stream: when it flips false, `channelFlow`
cancels the `EventSource` and emits `Idle`; when true and collectors remain, the
upstream restarts. This is implemented with
`flatMapLatest` over `isForeground` so background simply yields an empty,
non-connecting branch.

**Compose collector** (in `core-ui`, thin wrapper over
`androidx.lifecycle.compose.collectAsStateWithLifecycle`):

```kotlin
@Composable
fun <T> Flow<T>.collectSseAsState(
    initial: T,
    minActiveState: Lifecycle.State = Lifecycle.State.STARTED,
): State<T>
```

ViewModels expose the connection state and events as `StateFlow<UiState>` per the
project's MVVM contract; AND-149 only provides the building blocks, not feature
screens.

## 5. API Contract

No new backend endpoints. AND-149 governs **how** the existing SSE endpoint
(owned by AND-143) is consumed under failure. Reused/expected wire behavior:

- **SSE GET** (path defined by AND-143, e.g. `GET /ui/events/stream`):
  request carries session cookies + `Accept: text/event-stream`,
  `Cache-Control: no-cache`, and on reconnect `Last-Event-ID: <id>`.
- **Event frame** parsed by AND-143's `SseEvent`:

  ```
  id: 1832
  event: status_changed
  data: {"id":"abc","status":"online","ts":"2026-06-05T12:00:00Z"}
  ```

- **Retryable HTTP statuses on stream open:** `502`, `503`, `504`, plus
  network/timeout `IOException` → backoff reconnect.
- **Auth refresh** (reused from AND-009): `POST /ui/session/refresh` with
  `X-CSRF-Token` header (echoing `ui_csrf` cookie), empty body; `200` → retry
  stream; non-200 → `Offline(AUTH)`.
- **FastAPI `detail` mapping** (`string | [{msg}] | {code,...}`) applies only to
  the refresh response error path; the SSE stream itself is line-protocol, not
  JSON envelope.

## 6. Data & State Management

- **In-memory only.** No Room/DataStore persistence is introduced. `lastEventId`,
  `attempt`, `connectedAt`, and `SseConnectionState` are held in the stream's
  coroutine scope and discarded on teardown.
- **State exposure.** `state: StateFlow<SseConnectionState>` is the single source
  of truth for UI connection chrome. It is `MutableStateFlow` internally,
  read-only outward.
- **Event delivery.** `events()` is a `SharedFlow` (replay = 0) so late
  subscribers do not receive stale buffered events; resume is handled by
  `Last-Event-ID`, not local buffering.
- **Threading.** All flow work runs on `Dispatchers.IO` for the socket and a
  default dispatcher for timer/backoff math; `state` updates are conflated.
- **DataStore note:** if a future ticket wants user-tunable backoff, it would add
  a `SseBackoffConfig` provider — explicitly out of scope here.

## 7. Error Handling & Resilience

This is the heart of the ticket.

- **Classification.** A single `fun classify(t: Throwable?, code: Int?):
  Retryability` maps failures to `Retryable | AuthRefresh | Fatal(reason)`.
  Timeouts, `IOException`, premature EOF, and `502/503/504` → `Retryable`.
  `401` → `AuthRefresh`. `403/404/410` and malformed-stream-after-auth →
  `Fatal`.
- **Backoff.** Jittered exponential per `SseBackoffPolicy` (§4), capped at 30 s,
  reset after 60 s healthy. Full jitter prevents thundering-herd reconnects when
  the flaky host recovers and many clients reconnect at once.
- **Idle/stale detection.** A watchdog timer (`staleAfter = 45s`) flips state to
  `Stale` if `Connected` but silent, and proactively recycles the connection
  (cancel + reconnect) since the dev host drops idle sockets without FIN.
- **Single refresh on 401.** Exactly one `refreshOnce()` per stream
  per failure event; a refresh loop is prevented by a guard flag that resets only
  after a subsequent successful `onOpen`.
- **No-network short-circuit.** If `ConnectivityManager` reports no validated
  network, skip dialing and emit `Offline(NO_NETWORK)`; resume on the next
  `onAvailable` callback rather than burning backoff attempts.
- **Cancellation safety.** All `delay()`s are cooperative; cancelling the
  collector mid-backoff cancels the timer and never opens a new socket.

## 8. Security & Privacy

- **Cookie-based auth preserved.** SSE requests reuse the persistent cookie jar
  and `X-CSRF-Token` header from AND-009; no token is logged.
- **Plaintext dev host.** The stream runs over `http://` only because the dev
  backend is plaintext; the `usesCleartextTraffic` network-security-config
  allowance is scoped to the dev host (owned by AND-009) and **must not** widen.
  Production/staging hosts must be `https://`; the client does not downgrade.
- **No PII in logs.** Event `data` payloads are never logged at INFO; only event
  `type`, `id`, and state transitions are logged (DEBUG gated).
- **Refresh safety.** On `401`, only one refresh is attempted; credentials are
  never embedded in the stream URL or `Last-Event-ID`.

## 9. Accessibility & i18n

No direct UI is shipped by this ticket (it provides `core` primitives), so screen
layout/contrast a11y is N/A here and is owned by the consuming feature screens.
The two cross-cutting obligations AND-149 must satisfy:

- **String externalization.** Any human-readable connection-state label helper
  provided for convenience (`SseConnectionState.toUserMessage()`) must resolve
  through `string` resources (`R.string.sse_state_reconnecting`, etc.), never
  hard-coded English, so consumers get localized/RTL-correct copy.
- **Non-visual signaling.** Connection state must be exposed as data
  (`StateFlow`) so consuming screens can attach `liveRegion`/`contentDescription`
  semantics; the spec mandates state be machine-readable, not color-only.

## 10. Telemetry & Logging

- **Structured logs** via the project logger (Timber-style facade): one DEBUG
  line per transition `sse.state attempt=<n> from=<a> to=<b> nextRetryMs=<ms>
  reason=<r>`. WARN on entering `Offline`, INFO on first successful `Connected`.
- **Metrics counters** (behind the app's analytics facade, no-op in debug if
  unconfigured): `sse_reconnect_total{reason}`, `sse_connect_duration_ms`,
  `sse_stale_recycle_total`, `sse_offline_total{reason}`. These let us quantify
  host-blip frequency.
- **No event-body logging.** Per §8.
- **Leak signal.** A debug-only `AtomicInteger activeEventSources` counter is
  logged on teardown to make leaks observable in instrumented runs and assertable
  in tests.

## 11. Testing Strategy

Unit (JVM, `core-network` / `core-testing`):

- `SseBackoffPolicyTest` — deterministic with a seeded `Random`: verifies
  geometric growth, `cap` clamp, jitter bounds, and `shouldReset` boundary at
  `resetAfter`.
- `ClassifyTest` — every status/throwable maps to the correct `Retryability`.
- `ResilientSseStreamTest` with `MockWebServer` + `runTest`/virtual time:
  1. **Survives a blip** — server sends 2 events, closes; client reconnects and
     receives a 3rd event; state sequence is
     `Connecting → Connected → Reconnecting → Connected`.
  2. **Backoff timing** — assert reconnect delays follow the seeded policy via
     `TestCoroutineScheduler.currentTime`.
  3. **`Last-Event-ID`** — second request carries the last `id` header.
  4. **401 refresh** — one `/ui/session/refresh`, then a single retry; second
     `401` without refresh success → `Offline(AUTH)`.
  5. **5xx retryable vs 404 fatal.**
  6. **Stale recycle** — no events for `staleAfter` triggers `Stale` + reconnect.

Lifecycle / leak (instrumented or Robolectric with `TestLifecycleOwner`):

- **Foreground/background** — backgrounding cancels the `EventSource` (assert
  `activeEventSources == 0` and `MockWebServer.takeRequest` shows the call
  closed); foregrounding with a live collector reopens exactly one connection.
- **Lifecycle collect** — `collectSseAsState` opens on `STARTED`, closes below;
  config-change recreation does **not** double-subscribe (ref count stays 1).
- **No-leak assertion** — after cancelling all collectors,
  `activeEventSources == 0`, OkHttp `connectionPool.connectionCount()` drains, and
  no coroutines remain (`TestScope` completes). This directly satisfies the
  acceptance bullet "no leaks (tested)".

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-143 (SSE client core) must be merged first; AND-149
  layers `ResilientSseStream`/registry/lifecycle on top of its `SseClient` and
  `SseEvent`. Transitively requires AND-009 (OkHttp + cookie jar + refresh).
- **Provides for downstream:** any M3/E20 feature that consumes the live event
  stream (status/notifications screens) depends on the `SseConnectionState` and
  the lifecycle-aware collector defined here.
- **Sequencing:** ship `SseBackoffPolicy` + `classify` (pure) first, then
  `ResilientSseStream`, then the registry/ref-count, then the lifecycle gate and
  Compose collector — each independently testable.
- **No DI conflicts:** new bindings (`SseBackoffConfig`, `SseBackoffPolicy`,
  `SseStreamRegistry`) go in a `@Module @InstallIn(SingletonComponent::class)`
  `SseModule` in `core-network`.

## 13. Risks & Open Questions

- **Server `Last-Event-ID` support unverified.** If the backend ignores it,
  reconnect causes a full replay or a gap. *Mitigation:* the client tolerates
  duplicates by event `id` de-dup at the consumer; confirm against
  `/openapi.json` / backend team. **Open question.**
- **Idle-drop without FIN.** The dev host may hold a half-open socket; the
  `staleAfter` watchdog is the guard, but its value (45 s) is a guess relative to
  the server's idle policy — needs tuning against observed behavior. **Open.**
- **Process vs UI lifecycle interaction.** Combining `ProcessLifecycleOwner` with
  per-screen `WhileSubscribed` could rarely race on rapid foreground/background
  flips; the 5 s `stopTimeout` debounce mitigates but should be load-tested.
- **Backoff cap for background-allowed streams.** If a future ticket needs a
  background SSE (e.g., FCM-substitute), `maxAttempts`/cap policy will differ;
  out of scope but flagged.

## 14. Acceptance Criteria

AC-1. With `MockWebServer` dropping the connection after N events, the stream
reconnects and continues delivering events without emitting a terminal error;
observed state sequence includes `Reconnecting` then `Connected`. *(Survives host
blips.)*

AC-2. Reconnect delays follow jittered exponential backoff capped at 30 s, and
the attempt counter resets after `resetAfter` of healthy connection — asserted
with a seeded `Random` and virtual time.

AC-3. Transient `502/503/504` and timeouts trigger reconnect; `401` triggers
exactly one `/ui/session/refresh` + retry; `403/404` → `Offline` without retry.

AC-4. Backgrounding the process cancels the underlying `EventSource`
(`activeEventSources == 0`); foregrounding with a live collector reopens exactly
one connection.

AC-5. After all collectors are cancelled, there are **no leaks**:
`activeEventSources == 0`, the OkHttp connection pool drains, and no coroutines
remain — asserted in test. *(No leaks, tested.)*

AC-6. Multiple collectors of the same `SseRequest` share a single connection
(ref count == 1); a configuration change does not create a second `EventSource`.

AC-7. On reconnect, the request carries the correct `Last-Event-ID` header.

## 15. Definition of Done

- `SseBackoffConfig`, `SseBackoffPolicy`, `SseConnectionState`,
  `ResilientSseStream`, `SseStreamRegistry`, the foreground gate, and the
  `collectSseAsState` collector are implemented in `core-network`/`core-ui` under
  `com.testlogon.android` and provided via Hilt.
- AND-143's public surface is unchanged (extended, not broken).
- All §11 unit, lifecycle, and leak tests pass in CI; AC-1…AC-7 demonstrably
  green, including the explicit no-leak assertions.
- No event payloads are logged; cleartext is confined to the dev host config.
- KtLint/Detekt clean; new public APIs have KDoc; PR merged to `android-port`
  with the test evidence (MockWebServer logs / leak counter) referenced in the
  description.
