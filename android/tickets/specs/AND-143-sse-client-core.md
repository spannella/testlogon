---
id: AND-143
title: SSE client core
milestone: M3
epic: E20
priority: P0
size: M
status: draft
depends_on: [AND-009]
blocks: []
---

# AND-143 — SSE client core

## 1. Overview & Goal

This ticket delivers the reusable Server-Sent Events (SSE) transport core for the
TestLogon Android app (`com.testlogon.android`). It wraps OkHttp's `EventSource`
(from `okhttp-sse`) behind a Kotlin-idiomatic, lifecycle-aware `Flow<SseEvent>`
API so that feature modules can subscribe to a backend SSE stream without ever
touching `EventSource`, callbacks, threading, or reconnect bookkeeping.

The deliverable is narrow and infrastructural. It is the foundation of the E20
real-time epic: any screen that needs a live push channel (notifications, session
events, live status) consumes the `SseClient` defined here through a `repeatOnLifecycle`
collector. This ticket does NOT define which endpoint is streamed, how individual
event payloads are parsed into domain models, or any UI — those belong to the
downstream feature tickets that own a concrete stream.

Concretely, we deliver:

1. An `SseClient` interface plus a `DefaultSseClient` implementation, Hilt-provided
   from `core-network`, that converts an OkHttp `EventSource` into a cold
   `Flow<SseEvent>` via `callbackFlow`.
2. **Auth-correct connections:** the SSE request rides the same persistent cookie
   jar and `X-CSRF-Token` posture as the rest of the app, reusing the shared
   `OkHttpClient` from AND-009 (with an SSE-tuned `readTimeout` override).
3. **Lifecycle awareness:** the stream is a cold `Flow`; collection starts on
   subscribe and the underlying `EventSource` is cancelled on unsubscribe, so a
   standard `repeatOnLifecycle(STARTED)` collector connects/disconnects with the UI.
4. **Reconnect with bounded backoff:** on a transport drop or non-fatal failure,
   the client reconnects with exponential backoff + jitter, honoring the
   SSE `Last-Event-ID` and server `retry:` hint, surfacing connection lifecycle as
   typed events so consumers can render connecting/live/stale UI.

Success is a single, tested integration point: it connects, emits parsed events,
and transparently reconnects after a drop, all verified against `MockWebServer`.

## 2. Context & References

- **Module:** `core-network`, package `com.testlogon.android.core.network.sse`.
- **Stack:** Kotlin 2.0.21, OkHttp 4.12.0 + `okhttp-sse` 4.12.0, Coroutines/Flow,
  Hilt (KSP). minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Depends on AND-009 — OkHttp client + timeouts + logging:** the shared
  `@Singleton OkHttpClient` (20s connect, `retryOnConnectionFailure(true)`,
  debug-only redacting logger). The SSE client reuses that client but derives an
  SSE-specific variant with a long/disabled `readTimeout` (a streaming connection
  must not be killed by the 20s read budget).
- **Cookie + CSRF posture:** cookie-based auth (AND-011 cookie jar, AND-012 CSRF
  interceptor) is attached to the shared client; SSE inherits it automatically.
  The `ui_csrf` cookie is echoed as `X-CSRF-Token`. SSE streams are `GET`, so CSRF
  is not strictly required by the backend for the stream itself, but the header is
  carried for uniformity and gateway compatibility.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext, unreliable). FastAPI exposes SSE via `text/event-stream` responses
  (typically `sse-starlette`). OpenAPI at `/openapi.json` lists the concrete stream
  path; this core is endpoint-agnostic and is parameterized by a request URL.
- **Web reference:** the frontend uses the browser `EventSource` API with
  `withCredentials`; this ticket reproduces that behavior natively.
- **Repo:** `spannella/testlogon`, app under `android/`, branch `android-port`.

## 3. Functional Requirements

FR-1. `core-network` SHALL expose an `SseClient` interface whose single operation
returns a cold `Flow<SseEvent>` for a caller-supplied request (URL + optional
`Last-Event-ID`).

FR-2. Subscribing to the returned `Flow` SHALL open exactly one OkHttp `EventSource`;
cancelling collection SHALL cancel that `EventSource` and release its connection.
No `EventSource` SHALL outlive its collector.

FR-3. Each SSE message delivered by `EventSourceListener.onEvent(id, type, data)`
SHALL be emitted downstream as an `SseEvent.Message(id, event, data)`. The client
SHALL track the most recent non-null `id` as the current `Last-Event-ID`.

FR-4. The client SHALL emit typed connection-lifecycle events
(`SseEvent.Open`, `SseEvent.Reconnecting`, and terminal failure handling per FR-7)
so consumers can render connecting/live/stale states without parsing raw frames.

FR-5. On a non-fatal connection drop or `onFailure` (network error, `IOException`,
idle stream close without a fatal HTTP status), the client SHALL automatically
reconnect using exponential backoff with full jitter, starting at 1s, doubling to a
30s cap, sending the retained `Last-Event-ID` header on each reconnect, and resetting
the backoff to the base after any successful `onOpen`.

FR-6. The client SHALL respect a server-provided `retry:` field (delivered by OkHttp
as the default reconnection time) as a lower bound on the next reconnect delay when
present, never reconnecting faster than the server requests.

FR-7. The client SHALL treat the following as **fatal** (no reconnect; emit
`SseEvent.Closed(reason)` or throw into the flow): HTTP `401` after a single
in-band session refresh has already been attempted by the shared `Authenticator`
(AND-013), HTTP `403`, HTTP `404`, and any `4xx` other than `408`/`429`. `408` and
`429` are retriable (honoring `Retry-After` when present).

FR-8. Reconnect attempts SHALL be **bounded**: after `MAX_CONSECUTIVE_FAILURES`
(default 8) consecutive failures with no successful `onOpen` in between, the client
SHALL emit `SseEvent.Closed(STALE)` and stop, allowing the consumer to surface an
offline/stale UI and offer manual retry (re-collection).

FR-9. All emissions SHALL occur on a background dispatcher; the `Flow` SHALL be safe
to collect from the main thread and SHALL NOT block it. Reconnect timing SHALL use
`delay` (coroutine-cancellable), never `Thread.sleep`.

FR-10. The client SHALL be lifecycle-friendly by construction: because it is a cold
`Flow`, a `repeatOnLifecycle(Lifecycle.State.STARTED)` collector connects when the
screen is visible and disconnects when it is backgrounded, with no extra API.

## 4. Technical Design

All artifacts live in `core-network`, package
`com.testlogon.android.core.network.sse`.

### 4.1 Public types

```kotlin
package com.testlogon.android.core.network.sse

/** A single decoded SSE frame or a connection-lifecycle signal. */
sealed interface SseEvent {
    /** Connection established (after onOpen). */
    data object Open : SseEvent

    /** A data frame. `event` is the SSE event name ("message" if unnamed). */
    data class Message(
        val id: String?,
        val event: String,
        val data: String,
    ) : SseEvent

    /** A drop occurred; a reconnect is scheduled in `delayMillis`. */
    data class Reconnecting(
        val attempt: Int,
        val delayMillis: Long,
        val cause: Throwable?,
    ) : SseEvent

    /** Stream terminated and will not reconnect. */
    data class Closed(val reason: CloseReason) : SseEvent

    enum class CloseReason { SERVER_CLOSED, FATAL_HTTP, STALE, UNAUTHORIZED }
}

/** Caller-supplied connection parameters. */
data class SseRequest(
    val url: String,
    val lastEventId: String? = null,
    val extraHeaders: Map<String, String> = emptyMap(),
)
```

### 4.2 Interface

```kotlin
interface SseClient {
    /**
     * Cold flow. Each collection opens one EventSource and reconnects with
     * bounded backoff until cancelled or a fatal/stale terminal state.
     */
    fun events(request: SseRequest): Flow<SseEvent>
}
```

### 4.3 Implementation (callbackFlow bridge)

```kotlin
class DefaultSseClient @Inject constructor(
    @SseOkHttp private val client: OkHttpClient,   // SSE-tuned variant, §4.4
    private val backoff: BackoffPolicy = BackoffPolicy.Sse,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
) : SseClient {

    override fun events(request: SseRequest): Flow<SseEvent> = channelFlow {
        var lastEventId = request.lastEventId
        var attempt = 0

        while (isActive) {
            val outcome = connectOnce(request, lastEventId) { event ->
                if (event is SseEvent.Message && event.id != null) lastEventId = event.id
                trySend(event)
            }

            when (outcome) {
                is Outcome.Fatal -> {
                    send(SseEvent.Closed(outcome.reason)); break
                }
                is Outcome.ServerClosed -> {
                    send(SseEvent.Closed(SseEvent.CloseReason.SERVER_CLOSED)); break
                }
                is Outcome.Retriable -> {
                    attempt++
                    if (attempt >= backoff.maxConsecutiveFailures) {
                        send(SseEvent.Closed(SseEvent.CloseReason.STALE)); break
                    }
                    val delayMs = backoff.nextDelayMillis(attempt, outcome.serverRetryMillis)
                    send(SseEvent.Reconnecting(attempt, delayMs, outcome.cause))
                    delay(delayMs)
                }
                is Outcome.Opened -> attempt = 0   // reset after a clean onOpen
            }
        }
    }.flowOn(dispatcher)
}
```

`connectOnce` suspends until the current `EventSource` terminates, bridging the
callback API with `suspendCancellableCoroutine` so cancellation propagates to
`eventSource.cancel()`:

```kotlin
private suspend fun connectOnce(
    request: SseRequest,
    lastEventId: String?,
    onEvent: (SseEvent) -> Unit,
): Outcome = suspendCancellableCoroutine { cont ->
    val httpReq = Request.Builder()
        .url(request.url)
        .header("Accept", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .apply { lastEventId?.let { header("Last-Event-ID", it) } }
        .apply { request.extraHeaders.forEach { (k, v) -> header(k, v) } }
        .build()

    val listener = object : EventSourceListener() {
        override fun onOpen(es: EventSource, response: Response) {
            onEvent(SseEvent.Open)
            // First-open signalling handled by resuming with Opened only on close;
            // attempt reset is driven by the loop receiving Opened/Retriable.
        }
        override fun onEvent(es: EventSource, id: String?, type: String?, data: String) {
            onEvent(SseEvent.Message(id, type ?: "message", data))
        }
        override fun onClosed(es: EventSource) {
            if (cont.isActive) cont.resume(Outcome.ServerClosed)
        }
        override fun onFailure(es: EventSource, t: Throwable?, response: Response?) {
            if (cont.isActive) cont.resume(classifyFailure(t, response))
        }
    }

    val es = EventSources.createFactory(client).newEventSource(httpReq, listener)
    cont.invokeOnCancellation { es.cancel() }
}
```

> Implementation note: the simplified `Outcome.Opened` reset above is realized by
> emitting an internal opened-marker through the channel and tracking it in the loop,
> or equivalently by resetting `attempt` inside `onOpen`. The chosen mechanism MUST
> reset backoff on every successful open (FR-5) and is covered by T-3.

### 4.4 SSE-tuned OkHttpClient variant

The 20s `readTimeout` from AND-009 would kill an idle-but-healthy stream. We derive
an SSE variant from the shared client (reusing its cookie jar, CSRF interceptor,
authenticator, and connection pool — `newBuilder()` shares the pool/dispatcher):

```kotlin
@Module
@InstallIn(SingletonComponent::class)
object SseNetworkModule {

    @Provides @Singleton @SseOkHttp
    fun provideSseOkHttpClient(base: OkHttpClient): OkHttpClient =
        base.newBuilder()
            .readTimeout(0, TimeUnit.SECONDS)        // no read timeout for streams
            .callTimeout(0, TimeUnit.SECONDS)        // unbounded; loop owns lifecycle
            .pingInterval(25, TimeUnit.SECONDS)      // detect half-open connections
            .retryOnConnectionFailure(true)
            .build()

    @Provides @Singleton
    fun provideSseClient(impl: DefaultSseClient): SseClient = impl
}

@Qualifier @Retention(AnnotationRetention.BINARY) annotation class SseOkHttp
```

### 4.5 Backoff policy

```kotlin
data class BackoffPolicy(
    val baseMillis: Long,
    val maxMillis: Long,
    val maxConsecutiveFailures: Int,
) {
    /** Full-jitter exponential backoff, floored by any server retry hint. */
    fun nextDelayMillis(attempt: Int, serverRetryMillis: Long?): Long {
        val exp = (baseMillis shl (attempt - 1)).coerceAtMost(maxMillis)
        val jittered = Random.nextLong(baseMillis, exp.coerceAtLeast(baseMillis) + 1)
        return maxOf(jittered, serverRetryMillis ?: 0L)
    }
    companion object {
        val Sse = BackoffPolicy(baseMillis = 1_000, maxMillis = 30_000, maxConsecutiveFailures = 8)
    }
}
```

## 5. API Contract

This ticket defines no NEW app endpoint; it is a transport client parameterized by
URL. It DOES pin the wire contract the client speaks. The concrete stream path
(e.g. `GET /ui/events` or similar) is owned by the consuming feature ticket and read
from `/openapi.json`; this core works against any conformant `text/event-stream`.

**Request issued per connection:**
```
GET <SseRequest.url> HTTP/1.1
Host: 18.222.237.167:8000
Accept: text/event-stream
Cache-Control: no-cache
Cookie: <session cookies from persistent jar>        # added by AND-011
X-CSRF-Token: <ui_csrf>                               # added by AND-012
Last-Event-ID: <retained id>                          # only on reconnect
```

**Server response (streaming):**
```
HTTP/1.1 200 OK
Content-Type: text/event-stream
Cache-Control: no-cache
Connection: keep-alive

retry: 3000

id: 42
event: session.revoked
data: {"session_id":"abc123"}

: heartbeat

id: 43
event: notification
data: {"title":"Hello","body":"World"}
```

**Mapping to emitted events:**
- `onOpen` → `SseEvent.Open`
- frame `id:42 event:session.revoked data:{...}` →
  `SseEvent.Message(id="42", event="session.revoked", data="{\"session_id\":\"abc123\"}")`
- comment line `: heartbeat` → not emitted (OkHttp consumes comments; keeps the
  socket alive).
- `retry: 3000` → used as the lower bound for the next reconnect delay (FR-6).

**Error frames / statuses (from `onFailure`):**
- `200` then socket drop → `Outcome.Retriable` → reconnect with `Last-Event-ID`.
- `401` (after AND-013's single refresh failed) → `Outcome.Fatal(UNAUTHORIZED)`.
- `403/404/4xx` (except `408/429`) → `Outcome.Fatal(FATAL_HTTP)`.
- `429` with `Retry-After: N` → `Outcome.Retriable(serverRetryMillis = N*1000)`.
- `5xx` / `IOException` / `SocketTimeoutException` → `Outcome.Retriable`.

Payload (`data`) parsing into domain models is explicitly out of scope and owned
by the feature ticket that consumes a given `event` name.

## 6. Data & State Management

- **Scope:** `SseClient` is `@Singleton` (stateless factory). The shared OkHttp
  `ConnectionPool`/`Dispatcher` are reused via `newBuilder()`; no second pool.
- **Per-collection state (in-flow only):** `lastEventId`, consecutive `attempt`
  count, and the live `EventSource` reference are confined to one `channelFlow`
  scope and torn down on cancellation. Nothing is shared across collectors; two
  subscribers get two independent streams.
- **No persistence:** `Last-Event-ID` is retained only for the lifetime of a single
  collection (in-memory). Cross-process resumption (persisting the last id to
  DataStore so the app resumes a stream after restart) is intentionally deferred to
  the consuming feature ticket — see Open Question Q1.
- **No Room/DataStore writes** in this ticket.
- **ViewModel/UiState:** none here. The expected consumer pattern (documented for
  downstream tickets, not implemented):

```kotlin
viewLifecycleOwner.lifecycleScope.launch {
    repeatOnLifecycle(Lifecycle.State.STARTED) {
        sseClient.events(SseRequest(url = streamUrl))
            .collect { event -> viewModel.onSseEvent(event) }   // maps to StateFlow<UiState>
    }
}
```

- **Thread model:** emissions are `flowOn(Dispatchers.IO)`; OkHttp dispatches
  callbacks on its own threads; `delay` is cancellable and respects structured
  concurrency.

## 7. Error Handling & Resilience

- **Reconnect (transient):** drops, idle closes, `IOException`,
  `SocketTimeoutException`, `5xx`, `408`, `429` → exponential backoff with full
  jitter (1s base, 30s cap), `Last-Event-ID` replayed, server `retry:`/`Retry-After`
  honored as a floor (FR-5/6).
- **Bounded:** `MAX_CONSECUTIVE_FAILURES = 8`; exhaustion → `Closed(STALE)`,
  matching the project's offline/stale UI posture. The consumer re-collects to retry.
- **Fatal (no reconnect):** `401` (post-refresh), `403`, `404`, other `4xx` →
  `Closed(FATAL_HTTP)`/`Closed(UNAUTHORIZED)`. Distinguishing fatal from retriable is
  the core resilience decision and is unit-tested (T-5).
- **Auth interplay (AND-013):** the shared `Authenticator` already performs one
  `POST /ui/session/refresh` + retry on `401`. SSE inherits this on connect. If a
  `401` still surfaces to `onFailure`, the refresh failed and the stream is fatal —
  the consumer should route to re-authentication. The SSE core does NOT itself call
  refresh; it relies on the shared client.
- **Plaintext/unreliable dev host:** long-lived plaintext connections over a flaky
  host make drops the norm, not the exception; `pingInterval(25s)` detects half-open
  sockets and triggers `onFailure` → reconnect rather than a silent stall.
- **Backpressure:** `channelFlow` uses a small buffered channel; a slow collector
  applies suspension backpressure to `trySend`. SSE rates here are low; if a future
  high-rate stream needs `conflate()`/`buffer(DROP_OLDEST)`, the consumer applies it.
- **Cancellation:** cancelling the collector cancels the coroutine, runs
  `invokeOnCancellation { es.cancel() }`, and cancels any in-flight `delay` — no
  leaked connection or pending reconnect.

## 8. Security & Privacy

- **Auth material reuse:** SSE rides the existing persistent cookie jar (AND-011)
  and CSRF interceptor (AND-012) via the shared client; no credentials are handled
  in this module. The `Last-Event-ID` and stream URL contain no secrets.
- **Logging redaction:** the debug-only `HttpLoggingInterceptor` from AND-009
  redacts `Cookie`/`Set-Cookie`/`X-CSRF-Token` for the SSE request handshake too.
  Streamed `data:` bodies, however, will print in debug logs at `Level.BODY` — if a
  stream carries PII this is a debug-only exposure (never ships). Documented as a
  known limitation; consumers carrying sensitive payloads should request a body-level
  log filter (Q2).
- **Clear-text scoping:** unchanged from AND-009 — clear-text permitted only for the
  dev IP via `network_security_config.xml`; production hosts remain HTTPS-only.
- **No new permissions:** uses existing `INTERNET`; SSE adds no manifest permissions.
- **No secret storage:** this ticket persists nothing.

## 9. Accessibility & i18n

Not applicable at this layer — no UI, no Compose content, no user-visible strings.
Connection-state strings (e.g. "Connecting…", "Live", "Offline — tap to retry") and
their accessibility semantics are owned by the consuming feature tickets that map
`SseEvent.Open`/`Reconnecting`/`Closed` to a state composable (the state composables
from AND-021). No `strings.xml` entries are added here.

## 10. Telemetry & Logging

- **Logging:** reuses AND-009's debug-only redacting `HttpLoggingInterceptor` for the
  HTTP handshake. The SSE core adds lightweight structured `Log.d`/`Log.i` under tag
  `SseClient` for lifecycle transitions only — open, reconnect (attempt + delay), and
  terminal close (reason) — never raw `data:` payloads. No `println`.
- **No analytics SDK** is introduced. Reconnect-rate and time-to-first-event metrics
  are a documented future seam: attach an OkHttp `EventListener` to the SSE client
  builder, out of scope here (Q3).
- **Diagnostics:** the `SseEvent.Reconnecting`/`Closed` events are themselves the
  primary observability surface — consumers (and tests) can count attempts and reasons
  without instrumentation.

## 11. Testing Strategy

All tests are JVM unit tests in `core-network/src/test`, using `MockWebServer`,
JUnit4, Truth, and `kotlinx-coroutines-test` (`runTest`, `TestScope`, virtual time)
plus Turbine for `Flow` assertions. No instrumentation required.

**T-1 (Acceptance — connect + emit).** Enqueue a `MockResponse` with
`Content-Type: text/event-stream` and a body of two SSE frames
(`id:1 event:notification data:{"x":1}` …). Collect `events()` with Turbine; assert
the sequence `Open`, `Message(id="1", event="notification", data="{\"x\":1}")`,
`Message(id="2", …)`. Verifies connection and parsing.

**T-2 (Acceptance — reconnect after drop).** Enqueue response #1 that emits one frame
then closes the socket (`SocketPolicy.DISCONNECT_AFTER_REQUEST` / a body that ends),
and response #2 that emits a second frame. Assert the flow emits `Message(1)`,
`Reconnecting(attempt=1, …)`, `Open`, `Message(2)`. Assert the **second request
carried `Last-Event-ID: 1`** by inspecting `server.takeRequest().getHeader("Last-Event-ID")`.
This is the gating acceptance test (matches the source acceptance bullet).

**T-3 (Backoff reset + bounds).** Drive repeated drops with `runTest` virtual time;
assert delays follow the jittered exponential schedule (within `[base, cap]`), that a
successful `Open` resets `attempt` to 0, and that the server `retry:` hint floors the
delay (FR-6). Assert `delay` advances virtual time (no real sleep).

**T-4 (Stale termination).** Force `MAX_CONSECUTIVE_FAILURES` consecutive failures with
no `Open` between; assert the flow emits `Closed(STALE)` and completes.

**T-5 (Fatal classification).** Parameterized: enqueue `401`, `403`, `404`, `429`,
`500`. Assert `401/403/404` → `Closed(FATAL_HTTP|UNAUTHORIZED)` (no reconnect), while
`429` (with `Retry-After`) and `500` → `Reconnecting` then a retry request issued.

**T-6 (Cancellation / no leak).** Collect in a child job, then cancel it mid-stream;
assert the `EventSource` is cancelled (`server.requestCount` does not grow afterward)
and no further emissions occur. Confirms `invokeOnCancellation` wiring (FR-2).

**T-7 (SSE client config).** Assert the `@SseOkHttp` client has `readTimeout == 0`,
a configured `pingInterval`, and shares the base client's `connectionPool`/`cookieJar`
(verifies `newBuilder()` reuse, §4.4).

Coverage gate: T-1 and T-2 (connect + reconnect-with-Last-Event-ID) are the gating
acceptance assertions.

## 12. Dependencies & Sequencing

**Depends on:**
- **AND-009 — OkHttp client + timeouts + logging:** provides the shared
  `@Singleton OkHttpClient` this ticket derives the SSE variant from, and supplies
  `MockWebServer`/Truth test deps in `core-network`/`core-testing`.

**Transitively benefits from (already attached to the shared client, not direct
build deps of this ticket):** AND-011 (cookie jar), AND-012 (CSRF interceptor),
AND-013 (401 refresh authenticator). SSE inherits all three automatically; if they
land after this ticket, SSE auth simply begins working when they do — no edits here.

**Blocks (downstream consumers):** none enumerated in the source bullets. Any future
E20 feature ticket that streams a concrete endpoint (and owns payload parsing,
`Last-Event-ID` persistence, and the live/stale UI) will consume `SseClient`.

**Build dependencies to add to `core-network/build.gradle.kts`:**
```kotlin
implementation("com.squareup.okhttp3:okhttp-sse:4.12.0")
testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
testImplementation("app.cash.turbine:turbine:<catalog>")
testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:<catalog>")
```
(`okhttp` core, Hilt, and Coroutines are already present from AND-009/AND-004.)

Sequencing: implement `SseEvent`/`SseRequest`/`SseClient`, `DefaultSseClient`,
`BackoffPolicy`, and `SseNetworkModule`; T-1 and T-2 must pass before any E20 feature
ticket begins consuming the client.

## 13. Risks & Open Questions

- **R-1 (readTimeout(0) masks dead streams).** Disabling the read timeout means a
  silently half-open socket could stall indefinitely. *Mitigation:* `pingInterval(25s)`
  forces `onFailure` on a dead peer, converting a stall into a reconnect.
- **R-2 (Backoff churn against the flaky dev host).** Frequent drops could produce a
  reconnect storm. *Mitigation:* full jitter + 30s cap + `MAX_CONSECUTIVE_FAILURES`
  bound + honoring server `retry:`; consumer surfaces `Closed(STALE)` for manual retry.
- **R-3 (callbackFlow leak risk).** A mis-wired `invokeOnCancellation` would leak an
  `EventSource`. *Mitigation:* T-6 asserts cancellation cancels the source.
- **R-4 (Last-Event-ID semantics depend on backend).** If `sse-starlette` does not
  replay missed events on `Last-Event-ID`, reconnect resumes live-only (gap possible).
  *Mitigation:* this core sends the header correctly; gap handling is the consumer's
  concern. Verify backend replay behavior before relying on at-least-once delivery.
- **R-5 (Authenticator + streaming `401`).** AND-013's `Authenticator` was designed for
  unary calls; its interaction with a long-lived stream's initial `401` should be
  confirmed (does refresh+retry re-establish the stream cleanly?). *Mitigation:* T-5
  covers the post-refresh fatal `401` path; integration confirmed when AND-013 lands.
- **Q1.** Persist `Last-Event-ID` to DataStore for cross-process resume, or keep it
  in-memory per collection? (Default: in-memory; persistence owned by the consumer.)
- **Q2.** Add a body-redacting log filter so debug logs of `data:` frames omit PII, or
  rely on debug-only gating? (Default: rely on gating.)
- **Q3.** Attach an `EventListener` for reconnect/latency telemetry now, or defer to a
  later observability ticket? (Default: defer.)
- **Q4.** Confirm the concrete SSE endpoint path and event-name catalog from
  `/openapi.json` (owned by the consuming feature ticket).

## 14. Acceptance Criteria

AC-1. `core-network` exposes a Hilt-provided `@Singleton SseClient` whose
`events(SseRequest): Flow<SseEvent>` opens exactly one `EventSource` per collection
and cancels it on unsubscribe (FR-1/2; T-6).

AC-2. **Connects and emits events:** against `MockWebServer` serving
`text/event-stream`, the flow emits `Open` then `Message` events with correct
`id`/`event`/`data` mapping (T-1).

AC-3. **Reconnects after a drop:** after the socket is dropped, the flow emits
`Reconnecting` then `Open` then resumes, and the reconnect request carries
`Last-Event-ID` set to the last received id (T-2).

AC-4. Reconnect uses bounded exponential backoff with full jitter (1s→30s), resets on
a successful `Open`, honors server `retry:`/`Retry-After` as a floor, and terminates
with `Closed(STALE)` after `MAX_CONSECUTIVE_FAILURES` (T-3/T-4).

AC-5. Fatal statuses (`401` post-refresh, `403`, `404`) terminate without reconnect;
`408`/`429`/`5xx`/`IOException` reconnect (T-5).

AC-6. The `@SseOkHttp` client reuses the shared client (cookie jar, CSRF,
authenticator, connection pool) with `readTimeout = 0` and a configured
`pingInterval` (T-7).

AC-7. Collection is main-safe and lifecycle-friendly: a `repeatOnLifecycle(STARTED)`
collector connects/disconnects with the UI; no `Thread.sleep`; cancellation leaks no
connection (FR-9/10; T-6).

## 15. Definition of Done

- [ ] `SseEvent`, `SseRequest`, `SseClient`, `DefaultSseClient`, `BackoffPolicy`, and
      `SseNetworkModule` (+ `@SseOkHttp` qualifier) implemented in
      `com.testlogon.android.core.network.sse`.
- [ ] `okhttp-sse:4.12.0` added via the version catalog; Turbine +
      `kotlinx-coroutines-test` added as test deps.
- [ ] `@SseOkHttp` client derived via `newBuilder()` with `readTimeout(0)`,
      `pingInterval(25s)`, pool/cookie-jar reuse.
- [ ] `channelFlow` bridge with `EventSourceListener`, `invokeOnCancellation { es.cancel() }`,
      and `flowOn(Dispatchers.IO)`.
- [ ] Bounded jittered backoff with server-`retry:` floor, `Open`-reset, and
      `MAX_CONSECUTIVE_FAILURES` stale termination, all as named constants.
- [ ] Fatal-vs-retriable HTTP classification implemented per FR-7.
- [ ] Unit tests T-1 through T-7 written and passing in CI; T-1 + T-2 are gating.
- [ ] Lifecycle consumer pattern documented in the module README/KDoc (no UI shipped).
- [ ] No new lint/detekt warnings in `core-network`; KSP/Hilt build clean.
- [ ] PR reviewed and merged to `android-port`.
