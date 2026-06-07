---
id: AND-149
title: Reconnect/backoff + lifecycle
milestone: M3
epic: E20
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- **Reference:** the web app's `EventSource` reconnect behavior is the functional
  baseline we are matching on native. **[CORRECTED]** The reconnect logic lives in
  the SSE hooks (`src/hooks/useMessagingStream.ts`, `src/hooks/useAlertStream.ts`,
  `src/hooks/useBroadcastStream.ts`), **not** under `src/api/`. Each hook uses the
  browser `EventSource` (`withCredentials: true`) and on `onerror` reconnects with
  `delay = min(1000 * 2^retryCount, 30_000)` — exponential, 30 s cap, **no
  jitter** — resetting `retryCount` to 0 immediately on `onopen` (and the alert
  hook also resets on every `heartbeat` event). The native client deliberately
  **adds** full jitter (FR-1) and a 60 s healthy-duration reset window (FR-2) on
  top of this baseline; those refinements are not present in the web app and are
  Android design choices. App-level `Last-Event-ID` is handled by the browser
  automatically and is not set explicitly by the hooks.
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

- **SSE GET** (path defined by AND-143). **[CORRECTED]** There is no
  `/ui/events/stream` endpoint in the backend. The real SSE GET endpoints (all
  `resp=200` with an unschema'd `text/event-stream` body) are, e.g.:
  `GET /sse` (newsfeed; web `feedSseUrl = "/sse"`),
  `GET /messaging/events/stream`, `GET /ui/alerts/stream`,
  `GET /ui/dashboard/stream`, `GET /broadcast/sessions/{session_id}/stream`.
  AND-149 is endpoint-agnostic — the concrete path is injected via `SseRequest`
  by the consuming feature/AND-143. Each request carries session cookies +
  `Accept: text/event-stream`, `Cache-Control: no-cache`, and on reconnect
  `Last-Event-ID: <id>`. **[ASSUMPTION]** Web reference uses the browser
  `EventSource` (auto `Last-Event-ID`); some streams also accept an `after`
  cursor query param (e.g. `/messaging/events/stream` `params=after,limit,poll_ms`).
- **Event frame** parsed by AND-143's `SseEvent`:

  ```
  id: 1832
  event: status_changed
  data: {"id":"abc","status":"online","ts":"2026-06-05T12:00:00Z"}
  ```

- **Retryable HTTP statuses on stream open:** `502`, `503`, `504`, plus
  network/timeout `IOException` → backoff reconnect.
- **Auth refresh** (reused from AND-009): `POST /ui/session/refresh`, empty body;
  `200` → retry stream; non-200 → `Offline(AUTH)`. **[CORRECTED]** The endpoint is
  verified (`POST /ui/session/refresh`, no request body, `resp=200` empty schema),
  but the web reference's `refreshSession()` (`src/api/client.ts`) issues this as a
  raw `fetch(..., { method: "POST", credentials: "include" })` and does **not**
  attach an `X-CSRF-Token` header — only cookies. The earlier claim that refresh
  carries `X-CSRF-Token` was wrong for this call; `X-CSRF-Token` (echoing the
  `ui_csrf` cookie) is added by the general `api()` wrapper to other mutating
  requests, not to the refresh call. Android should match the web: cookie-only POST
  to refresh.
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
  never embedded in the stream URL or `Last-Event-ID`. **[ASSUMPTION]** In the web
  reference, SSE streams use the browser `EventSource` directly and do **not** pass
  through the `api()` wrapper, so the web app's one-shot 401→`/ui/session/refresh`
  logic (`src/api/client.ts`) does not run for SSE — the browser simply
  reconnects. FR-9's "401 on the stream → single refresh + retry" is therefore an
  Android-side hardening choice (consistent with the documented project auth rule),
  not an observed web SSE behavior; flagged as an assumption to confirm with the
  backend (whether the SSE endpoints actually emit `401` on session expiry vs.
  just closing the connection).

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **`POST /ui/session/refresh` exists, takes no request body, returns `200`.**
   VERDICT: **Verified.** SOURCE: OpenAPI `POST /ui/session/refresh`
   (op=`ui_session_refresh_ui_session_refresh_post`, `req=` empty, `resp=200:`
   empty schema) and `src/api/client.ts: refreshSession()`.

2. **On `401`, the client performs exactly one refresh then a single retry; a
   second failure logs out / surfaces auth error.** VERDICT: **Verified** (web
   contract). SOURCE: `src/api/client.ts: api()` 401 branch — single shared
   `refreshPromise`, one retry, `logout("session_expired")` on retry-`401`.

3. **The refresh call carries an `X-CSRF-Token` header.** VERDICT: **Corrected.**
   `refreshSession()` issues a raw `fetch(POST, { credentials: "include" })` with
   **no** `X-CSRF-Token`. The CSRF header (from the `ui_csrf` cookie) is added by
   the general `api()` wrapper to other mutating calls, not to refresh.
   SOURCE: `src/api/client.ts: refreshSession()` vs. `api()` (`getCookie("ui_csrf")`
   → `headers.set("X-CSRF-Token", csrf)`).

4. **CSRF transport is `X-CSRF-Token` echoing the `ui_csrf` cookie.** VERDICT:
   **Verified** for normal mutating requests. SOURCE: `src/api/client.ts: api()`.

5. **Auth is cookie/session based; SSE requests must carry session cookies.**
   VERDICT: **Verified.** SOURCE: all SSE hooks use
   `new EventSource(url, { withCredentials: true })` —
   `src/hooks/useMessagingStream.ts:209`, `src/hooks/useAlertStream.ts:45`,
   `src/hooks/useBroadcastStream.ts:49`.

6. **SSE endpoint path `GET /ui/events/stream`.** VERDICT: **Corrected.** No such
   path exists. Real SSE GET endpoints: `GET /sse`
   (`src/api/endpoints/newsfeed.ts:152 feedSseUrl = "/sse"`; OpenAPI
   `GET /sse` op=`sse_sse_get`), `GET /messaging/events/stream`
   (`src/hooks/useMessagingStream.ts:4`; OpenAPI
   op=`events_stream_messaging_events_stream_get`), `GET /ui/alerts/stream`
   (OpenAPI op=`alerts_stream_ui_alerts_stream_get`), `GET /ui/dashboard/stream`
   (op=`dashboard_stream_ui_dashboard_stream_get`),
   `GET /broadcast/sessions/{session_id}/stream`
   (op=`broadcast_event_stream_route_...`). All have `resp=200:` with no documented
   schema (`text/event-stream`). AND-149 stays endpoint-agnostic via `SseRequest`.

7. **Web reconnect = jittered exponential backoff, reset after 60 s healthy.**
   VERDICT: **Corrected** (as the web baseline). Web reconnect is
   `delay = min(1000 * 2^retryCount, 30_000)` — exponential, 30 s cap, **no
   jitter** — with `retryCount` reset to 0 *immediately* on `onopen` (and on
   `heartbeat` in the alert hook). SOURCE:
   `src/hooks/useMessagingStream.ts:5,226-228,211-213`,
   `src/hooks/useAlertStream.ts:6,150-152,47-49,141-144`. The native FR-1 jitter
   and FR-2 60 s reset window are deliberate Android refinements, not web behavior.

8. **30 s backoff cap.** VERDICT: **Verified** against web. SOURCE:
   `MAX_RETRY_DELAY = 30_000` in `src/hooks/useMessagingStream.ts:5` and
   `src/hooks/useAlertStream.ts:6`.

9. **`401` on the SSE stream triggers a refresh + retry (FR-9).** VERDICT:
   **Unverified-assumption.** Web SSE uses the browser `EventSource` directly and
   does **not** route through `api()`, so the web app never runs refresh-on-401 for
   streams — it just reconnects. Whether the backend even returns `401` on SSE
   session expiry (vs. closing the socket) is undocumented. SOURCE (negative):
   SSE hooks never call `api()`; `src/api/client.ts` 401 logic is `fetch`-scoped.

10. **`502/503/504` and timeouts are retryable.** VERDICT:
    **Unverified-assumption.** Reasonable transport-level policy, but the OpenAPI
    only documents `200`/`422` for the SSE endpoints and the web hooks treat *any*
    `onerror` as a uniform reconnect (no status-class branching). No source
    distinguishes 5xx-retryable from 4xx-fatal for streams. SOURCE (web is
    status-agnostic): `onerror` handlers in the SSE hooks.

11. **`403/404/410` are non-retryable / fatal.** VERDICT:
    **Unverified-assumption** for SSE. Same rationale as #10 — web SSE does not
    branch on status. For non-SSE calls, `403` is surfaced as a hard error
    (`src/api/client.ts` 403 branch), supporting the intent.

12. **FastAPI error `detail` shape is `string | [{msg}] | {code,...}`.** VERDICT:
    **Verified.** SOURCE: OpenAPI `HTTPValidationError.detail` = array of
    `ValidationError` (each with `msg`), and `src/api/client.ts:
    normalizeErrorDetail()` handles all three shapes incl. `{code}` via
    `mapAuthorizationError`.

13. **`Last-Event-ID` resume (FR-4) / server support.** VERDICT:
    **Unverified-assumption.** The web app never sets `Last-Event-ID` explicitly
    (browser does it implicitly); several stream endpoints instead expose an
    `after` cursor query param (OpenAPI `GET /messaging/events/stream`
    `params=after,limit,poll_ms`). Server honoring of `Last-Event-ID` is
    unconfirmed — already flagged in §13.

14. **Cleartext dev host `http://18.222.237.167:8000`.** VERDICT:
    **Unverified-assumption** (project/context value, not in OpenAPI or frontend
    sources; `VITE_API_BASE_URL` is env-injected in `src/api/client.ts`).

15. **Framework choices: AndroidX Lifecycle `collectAsStateWithLifecycle`,
    `ProcessLifecycleOwner`, `repeatOnLifecycle`/`WhileSubscribed`, OkHttp-SSE
    `EventSource`.** VERDICT: **Verified (framework ref).** SOURCES:
    Lifecycle-aware collection —
    https://developer.android.com/topic/libraries/architecture/coroutines#lifecycle-aware ;
    `ProcessLifecycleOwner` —
    https://developer.android.com/reference/androidx/lifecycle/ProcessLifecycleOwner ;
    `SharingStarted.WhileSubscribed` —
    https://kotlinlang.org/api/kotlinx.coroutines/kotlinx-coroutines-core/kotlinx.coroutines.flow/-sharing-started/ ;
    OkHttp SSE `EventSource` —
    https://square.github.io/okhttp/ .

### Corrections made

- **§5 SSE path:** replaced the non-existent `GET /ui/events/stream` with the real
  SSE endpoints (`/sse`, `/messaging/events/stream`, `/ui/alerts/stream`,
  `/ui/dashboard/stream`, `/broadcast/sessions/{session_id}/stream`) and clarified
  AND-149 is endpoint-agnostic.
- **§5 refresh header:** removed the incorrect claim that `POST /ui/session/refresh`
  carries `X-CSRF-Token`; the web refresh call is cookie-only.
- **§2 reference pointer:** corrected the reconnect-logic location (SSE hooks under
  `src/hooks/`, not `src/api/`) and the web baseline (exponential, 30 s cap, **no
  jitter**, immediate reset on `onopen`/`heartbeat`); noted FR-1 jitter and FR-2
  60 s reset are Android additions.
- **§8:** annotated that web SSE bypasses the `api()` 401-refresh path, so FR-9's
  401→refresh is an Android hardening choice, not observed web SSE behavior.

### Open assumptions

- **Server `Last-Event-ID` support** (claim 13) — not documented; some endpoints
  use an `after` cursor instead. Confirm with backend; consumer-side `id` de-dup is
  the mitigation (§13).
- **SSE `401` semantics** (claim 9) — unknown whether SSE endpoints emit `401` on
  expiry or just drop; refresh-on-401 for streams is unverified.
- **5xx-retryable vs 4xx-fatal status branching for SSE** (claims 10, 11) — not
  documented (only `200`/`422` in OpenAPI) and not present in web hooks; a
  pragmatic transport policy, to validate against live host behavior.
- **`staleAfter = 45s` watchdog value** (§13) — a guess vs. the dev host's idle
  policy; tune against observation.
- **Dev host URL / cleartext scope** (claim 14) — project context only, not in the
  verifiable sources.

## 17. Test Plan

Test target legend: **JVM** = local JVM unit/Robolectric (no device); **AVD35** =
headless emulator `test35` (x86_64, API 35); **A15** = physical Samsung Galaxy A15
5G (SM-A156U, serial R5CX821TA9R, Android 14 / API 34, arm64-v8a). Most cases are
device-independent (pure logic / MockWebServer / Robolectric); device targets are
called out only where ABI / API-level / real-network behavior matters.

- **TC-AND-149-01** — Type: unit (JVM). Target: `SseBackoffPolicy`.
  Preconditions: `SseBackoffConfig` defaults; seeded `Random`. Steps: call
  `delayFor(0..6)`; assert geometric growth `base*2^attempt` before jitter, `cap`
  clamp at 30 s for high attempts, and every result lies within
  `[0.5,1.0]*capped`. Also assert `shouldReset(59s)==false`, `shouldReset(60s)==true`.
  Expected: all assertions hold deterministically with the seed.
  Traces: AC-2.

- **TC-AND-149-02** — Type: unit (JVM). Target: `classify(throwable, code)`.
  Preconditions: none. Steps: feed `SocketTimeoutException`, generic `IOException`,
  premature-EOF, and codes `502/503/504` → expect `Retryable`; `401` →
  `AuthRefresh`; `403/404/410` and malformed-stream-after-auth → `Fatal(reason)`
  with correct `OfflineReason`. Expected: mapping table matches §7.
  Note: classification policy for SSE 5xx/4xx is an unverified assumption
  (audit #10/#11) — this test pins the chosen behavior. Traces: AC-3.

- **TC-AND-149-03** — Type: contract/MockWebServer (JVM, `runTest` virtual time).
  Target: `ResilientSseStream.events()`. Preconditions: MockWebServer enqueues an
  `text/event-stream` response with 2 events then closes; a second response with a
  3rd event. Steps: collect; let server drop after event 2. Expected: client
  reconnects and delivers event 3; observed `state` sequence is
  `Connecting → Connected → Reconnecting → Connected`; no terminal error emitted.
  Traces: AC-1.

- **TC-AND-149-04** — Type: contract/MockWebServer (JVM, virtual time). Target:
  backoff scheduling in `ResilientSseStream`. Preconditions: seeded `Random`,
  server drops repeatedly. Steps: force N consecutive failures; read
  `TestCoroutineScheduler.currentTime` deltas between reconnect attempts.
  Expected: deltas equal `policy.delayFor(attempt)` (jittered exponential, capped
  at 30 s); after `resetAfter=60s` of healthy connection the attempt counter
  resets to 0. Traces: AC-2.

- **TC-AND-149-05** — Type: contract/MockWebServer (JVM). Target: `Last-Event-ID`
  resume. Preconditions: first response emits events with `id: 1831`, `id: 1832`
  then closes. Steps: collect, allow reconnect, inspect the second request via
  `takeRequest()`. Expected: second request header `Last-Event-ID: 1832`.
  Note: server honoring of this header is an open assumption (audit #13); test
  asserts the client *sends* it. Traces: AC-7.

- **TC-AND-149-06** — Type: contract/MockWebServer (JVM). Target: 401 refresh
  path. Preconditions: stream returns `401`; `/ui/session/refresh` enqueued `200`;
  next stream response `200` with an event. Steps: collect. Expected: exactly one
  `POST /ui/session/refresh` (cookie-only, **no** `X-CSRF-Token` header — per
  correction #2/audit #3), then a single retry that connects and delivers the
  event; the refresh guard prevents a second refresh until a later `onOpen`.
  Traces: AC-3.

- **TC-AND-149-07** — Type: contract/MockWebServer (JVM). Target: refresh-failure
  and non-retryable terminal states. Preconditions: (a) stream `401` then
  `/ui/session/refresh` returns non-200; (b) separate run: stream returns `404`.
  Steps: collect each. Expected: (a) → `Offline(AUTH)`, no further dialing;
  (b) → `Offline(NOT_FOUND)` with no retry. Contrast with `503` which retries
  (covered by TC-03/04). Traces: AC-3.

- **TC-AND-149-08** — Type: contract/MockWebServer (JVM, virtual time). Target:
  stale watchdog. Preconditions: server holds the connection open, sends `onOpen`
  but no events for `> staleAfter (45s)`. Steps: advance virtual time past
  `staleAfter`. Expected: state flips `Connected → Stale`, the connection is
  proactively recycled (cancel + reconnect), and `activeEventSources` returns to
  its pre-recycle count (exactly one live source after reconnect). Traces: AC-1.

- **TC-AND-149-09** — Type: instrumented/Robolectric (JVM or AVD35) with
  `TestLifecycleOwner` + a fake `ProcessLifecycleOwner` foreground `StateFlow`.
  Target: foreground/background gate. Preconditions: one active collector, stream
  connected (MockWebServer). Steps: move process below `STARTED`; then back to
  foreground. Expected: on background, the `EventSource` is cancelled, state →
  `Idle`, `activeEventSources == 0`; on foreground with the collector still
  present, exactly one connection reopens (`activeEventSources == 1`, exactly one
  new `takeRequest`). Traces: AC-4.

- **TC-AND-149-10** — Type: Compose-UI (AVD35; Robolectric acceptable). Target:
  `collectSseAsState` lifecycle scoping. Preconditions: a test Composable
  collecting via `collectSseAsState(minActiveState = STARTED)`; MockWebServer.
  Steps: drive the host lifecycle `STARTED`→below→`STARTED`, then trigger a
  configuration change (recreation). Expected: stream opens at `STARTED`, closes
  when below; across config-change recreation the ref count stays `1` (no second
  `EventSource`). Traces: AC-6.

- **TC-AND-149-11** — Type: integration/MockWebServer (JVM). Target:
  `SseStreamRegistry` ref-counting. Preconditions: two collectors of the *same*
  `SseRequest`, one of a *different* key. Steps: subscribe both same-key
  collectors, then cancel one. Expected: a single shared connection serves both
  same-key collectors (one `takeRequest`); cancelling one keeps the connection
  alive; the connection tears down only ~5 s (`stopTimeout`) after the last
  collector leaves; the different-key collector opens its own connection.
  Traces: AC-6.

- **TC-AND-149-12** — Type: instrumented/leak (AVD35). Target: no-leak assertion.
  Preconditions: connected stream with collectors; debug `activeEventSources`
  counter wired. Steps: cancel all collectors and let `stopTimeout` elapse.
  Expected: `activeEventSources == 0`, OkHttp `connectionPool.connectionCount()`
  drains to 0, and the `TestScope` completes with no lingering child coroutines.
  Traces: AC-5.

- **TC-AND-149-13** — Type: integration (A15 — physical device, MUST). Target:
  no-network short-circuit + real `ConnectivityManager`/radio behavior.
  Preconditions: app on the A15; toggle airplane mode / disable Wi-Fi+cellular via
  adb. Steps: with a live collector, drop all networks, then restore.
  Expected: while offline the client emits `Offline(NO_NETWORK)` and does **not**
  dial (no backoff burn); on the real `onAvailable` callback it resumes and
  reconnects exactly once. Rationale for physical device: exercises the actual
  radio/`ConnectivityManager` validated-network transitions and arm64/API-34 path,
  which the emulator does not faithfully reproduce. Traces: AC-1.

- **TC-AND-149-14** — Type: manual + accessibility (A15 — physical device).
  Target: `SseConnectionState.toUserMessage()` localization + non-visual
  signaling. Preconditions: a thin host screen rendering connection chrome from
  the `StateFlow`, TalkBack enabled on the A15. Steps: drive the device through
  connecting → live → reconnecting → offline (use the flaky dev host or a proxy
  that drops the socket); with TalkBack on, observe announcements. Expected: every
  state label resolves through `R.string.*` resources (no hard-coded English;
  verify via a pseudolocale/RTL locale), and state is exposed as data so a
  `liveRegion`/`contentDescription` announces transitions (not color-only). Run on
  the physical device to validate real TalkBack output and the live dev-host flaky
  path. Traces: AC-1 (UI-surfaced affordances; supports §9).

### Coverage matrix

| Acceptance criterion | Covered by |
|---|---|
| AC-1 (survives blips; Reconnecting→Connected; no terminal error) | TC-03, TC-08, TC-13, TC-14 |
| AC-2 (jittered exp backoff, 30 s cap, reset after 60 s) | TC-01, TC-04 |
| AC-3 (5xx/timeout retry; one 401 refresh+retry; 403/404 → Offline) | TC-02, TC-06, TC-07 |
| AC-4 (background cancels EventSource; foreground reopens one) | TC-09 |
| AC-5 (no leaks: activeEventSources==0, pool drains, no coroutines) | TC-12 |
| AC-6 (shared single connection; config change ≠ second EventSource) | TC-10, TC-11 |
| AC-7 (correct `Last-Event-ID` on reconnect) | TC-05 |
