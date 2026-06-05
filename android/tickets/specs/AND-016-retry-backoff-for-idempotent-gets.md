---
id: AND-016
title: Retry/backoff for idempotent GETs
milestone: M1
epic: E02
priority: P1
size: M
status: draft
depends_on: [AND-009]
blocks: [AND-017]
---

# AND-016 — Retry/backoff for idempotent GETs

## 1. Overview & Goal

The TestLogon dev backend (`http://18.222.237.167:8000`, FastAPI + DynamoDB) is an
explicitly **unreliable plaintext host**. Cold DynamoDB paths, ALB warm-up, and transient
gateway errors produce intermittent `503`/`502`/`504` responses and dropped connections that
recover on a second attempt seconds later. Without a retry policy every such blip becomes a
user-visible error state.

This ticket adds a **bounded exponential-backoff retry policy** to the `core-network`
layer that automatically re-issues **safe, idempotent GET requests** when they fail with a
retryable transport fault or a retryable 5xx status. The policy is **strictly GET-only**:
mutating requests (`POST`, `PUT`, `PATCH`, `DELETE`) are **never** retried by this layer,
because the backend's auth/session and MFA mutations (`POST /ui/session/start`,
`/ui/mfa/{totp|sms|email}/verify`, `POST /ui/session/finalize`) are not safe to replay.

The deliverable is an OkHttp **application interceptor** (`RetryBackoffInterceptor`)
contributed into the interceptor set defined by AND-009, plus its configuration
(`RetryPolicy`), a deterministic backoff calculator, and the Hilt wiring and tests. The
single gating acceptance scenario is: a transient `503` followed by a `200` on the retry
yields overall success, while a failing `POST` is surfaced after exactly one attempt.

This is transport-level plumbing. It owns *whether and when* a GET is replayed. It does
**not** own error-to-domain mapping (AND-015 / `ApiResult`), connectivity status
(AND-017), the cookie jar (AND-011), CSRF (AND-012), or 401 refresh (AND-013); it composes
cleanly with all of them.

## 2. Context & References

- **Module:** `core-network`, package `com.testlogon.android.core.network.retry`. All code
  ships here.
- **Depends on AND-009** — OkHttp client + timeouts + logging. AND-009 defines the single
  `@Singleton OkHttpClient` and the **ordered application-interceptor seam** this ticket
  plugs into. Timeouts (20s connect/read/write, 30s `callTimeout`) bound the total time a
  retried call may consume.
- **Blocks AND-017** — Connectivity & backend health probe. The health ping should issue a
  *single* unretried probe (or reuse this policy with attempts=1) so reachability flips
  promptly; AND-017 consumes this module's `RetryPolicy` type to opt out.
- **Related (not a hard dependency):** AND-013 (401 Authenticator) — OkHttp runs the
  `authenticator` independently of application interceptors; this ticket must not double the
  refresh attempts. AND-015 maps the *final* failure to a typed error.
- **Stack:** Kotlin 2.0.21, OkHttp 4.12.0, Hilt (KSP), Coroutines/Flow. minSdk 24,
  compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Backend:** FastAPI; OpenAPI at `/openapi.json`. Error body `detail` may be
  `string | [{msg}] | {code,...}` (mapping owned by AND-015). Idempotent GETs in scope
  include `GET /ui/me`, `GET /openapi.json`, and any future read endpoints.
- **Web reference:** `frontend/src/api/endpoints/*.ts` — the web client uses
  `credentials: include` and does not implement structured GET backoff; this is a
  native-only resilience improvement.
- **Repo:** `spannella/testlogon`, app under `android/`, branch `android-port`.

## 3. Functional Requirements

FR-1. The layer SHALL provide an OkHttp application `Interceptor`
(`RetryBackoffInterceptor`) contributed into the AND-009 interceptor set via Hilt
multibinding (`@IntoSet`).

FR-2. The interceptor SHALL retry a request **only if its HTTP method is `GET`** (case-
sensitive per OkHttp's normalized `request.method`). All other methods (`POST`, `PUT`,
`PATCH`, `DELETE`, `HEAD` notwithstanding — see Q1) SHALL be executed exactly once and their
result returned unmodified.

FR-3. For an in-scope GET, the interceptor SHALL retry when either:
(a) `proceed()` throws a **retryable IOException** — `SocketTimeoutException`,
`ConnectException`, `java.net.UnknownHostException` only when network is up (else fail fast,
see FR-9), or a generic connection-reset `IOException`; or
(b) `proceed()` returns a **retryable status code** in the set
`{502, 503, 504}` (and optionally `408 Request Timeout`, `429 Too Many Requests`).

FR-4. The interceptor SHALL NOT retry on non-retryable statuses: any `2xx`, `3xx`, `4xx`
(except the retryable subset in FR-3b), in particular `400/401/403/404/422`. A `401` is left
entirely to the AND-013 `Authenticator`.

FR-5. Backoff SHALL be **bounded exponential with full jitter**: attempt *n* (0-indexed)
waits `random(0, min(maxDelay, baseDelay * 2^n))`. Defaults: `baseDelay = 250 ms`,
`maxDelay = 4 s`, `maxAttempts = 3` (i.e. 1 initial + up to 2 retries).

FR-6. The total number of `proceed()` invocations for a single GET SHALL never exceed
`maxAttempts`. After the final failed attempt the **last** response/exception is returned/
re-thrown unchanged (so AND-015 sees the real terminal status).

FR-7. A retryable response that is **not** retried-into-success SHALL be returned with its
body intact; intermediate retryable responses SHALL have their body **closed** before the
next attempt to avoid connection-pool leaks.

FR-8. The interceptor SHALL respect a `Retry-After` response header (delta-seconds form)
when present on a `503`/`429`, using it as the delay for the next attempt **capped at
`maxDelay`** and only if it does not breach `callTimeout` headroom.

FR-9. If the device is **offline** (no active network), the interceptor SHALL NOT spend the
backoff budget retrying; it SHALL fail fast on the first transport error. (Connectivity
source is provided by AND-017 when available; until then, a `ConnectivityChecker` abstraction
with a default "assume online" implementation is used — see §4.4.)

FR-10. The policy SHALL be **per-call overridable**: a request carrying the tag
`RetryPolicy` (via `Request.tag(RetryPolicy::class.java)`) uses that policy instead of the
injected default, allowing AND-017 to request `maxAttempts = 1`.

FR-11. The interceptor SHALL be **coroutine-cancellation aware**: the inter-attempt sleep
SHALL abort promptly if the call is canceled (OkHttp `call.isCanceled()`), throwing an
`IOException` rather than continuing to wait.

## 4. Technical Design

All artifacts live in `core-network`, package `com.testlogon.android.core.network.retry`.

### 4.1 Policy & backoff types

```kotlin
package com.testlogon.android.core.network.retry

import java.util.concurrent.TimeUnit
import kotlin.random.Random

data class RetryPolicy(
    val maxAttempts: Int = 3,                 // 1 initial + up to 2 retries
    val baseDelayMs: Long = 250L,
    val maxDelayMs: Long = 4_000L,
    val retryableStatuses: Set<Int> = setOf(502, 503, 504, 408, 429),
    val honorRetryAfter: Boolean = true,
) {
    companion object {
        /** Single-shot policy for liveness/health probes (AND-017). */
        val NO_RETRY = RetryPolicy(maxAttempts = 1)
        val DEFAULT = RetryPolicy()
    }
}

/** Deterministic when seeded; full-jitter exponential backoff. */
class BackoffCalculator(
    private val policy: RetryPolicy,
    private val random: Random = Random.Default,
) {
    /** @param attemptIndex 0-based index of the *failed* attempt about to be retried. */
    fun delayMsFor(attemptIndex: Int, retryAfterMs: Long? = null): Long {
        val exp = policy.baseDelayMs shl attemptIndex          // baseDelay * 2^n
        val ceil = minOf(policy.maxDelayMs, exp.coerceAtLeast(policy.baseDelayMs))
        val jittered = random.nextLong(0, ceil + 1)            // full jitter [0, ceil]
        return if (retryAfterMs != null && policy.honorRetryAfter)
            minOf(retryAfterMs, policy.maxDelayMs)
        else jittered
    }
}
```

### 4.2 The interceptor

```kotlin
package com.testlogon.android.core.network.retry

import okhttp3.Interceptor
import okhttp3.Response
import java.io.IOException
import javax.inject.Inject

class RetryBackoffInterceptor @Inject constructor(
    private val defaultPolicy: RetryPolicy,
    private val connectivity: ConnectivityChecker,
    private val sleeper: Sleeper = Sleeper.RealTime,   // injectable for tests
    private val backoffFactory: (RetryPolicy) -> BackoffCalculator = { BackoffCalculator(it) },
) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        val policy = request.tag(RetryPolicy::class.java) ?: defaultPolicy

        // Hard guard: only safe, idempotent GETs are ever retried.
        if (request.method != "GET" || policy.maxAttempts <= 1) {
            return chain.proceed(request)
        }

        val backoff = backoffFactory(policy)
        var lastError: IOException? = null

        for (attempt in 0 until policy.maxAttempts) {
            if (chain.call().isCanceled()) throw IOException("canceled")
            try {
                val response = chain.proceed(request)
                if (!response.isRetryable(policy) || attempt == policy.maxAttempts - 1) {
                    return response
                }
                val retryAfter = response.retryAfterMs()
                response.close()                                  // FR-7: release body/conn
                if (!connectivity.isOnline()) return chain.proceed(request) // FR-9 fallback
                sleeper.sleep(backoff.delayMsFor(attempt, retryAfter), chain.call())
            } catch (e: IOException) {
                lastError = e
                if (!e.isRetryable() || attempt == policy.maxAttempts - 1 ||
                    !connectivity.isOnline()) {                    // FR-3a, FR-9
                    throw e
                }
                sleeper.sleep(backoff.delayMsFor(attempt), chain.call())
            }
        }
        throw lastError ?: IOException("retry exhausted")
    }
}

private fun Response.isRetryable(p: RetryPolicy) = code in p.retryableStatuses

private fun Response.retryAfterMs(): Long? =
    header("Retry-After")?.toLongOrNull()?.let { it * 1000L }

private fun IOException.isRetryable(): Boolean = when (this) {
    is java.net.SocketTimeoutException,
    is java.net.ConnectException -> true
    is java.net.UnknownHostException -> false   // DNS/offline -> fail fast (FR-9)
    else -> true                                // connection reset / generic transport
}
```

### 4.3 Cancellable sleeper

```kotlin
package com.testlogon.android.core.network.retry

import okhttp3.Call
import java.io.IOException

fun interface Sleeper {
    /** Sleep [ms], aborting early (throwing IOException) if [call] is canceled. */
    fun sleep(ms: Long, call: Call)

    companion object {
        val RealTime = Sleeper { ms, call ->
            val deadline = System.nanoTime() + ms * 1_000_000
            while (System.nanoTime() < deadline) {
                if (call.isCanceled()) throw IOException("canceled during backoff")
                Thread.sleep(minOf(50L, ms))      // poll cancellation
            }
        }
    }
}
```

The interceptor runs on OkHttp's `Dispatcher` worker thread, so a blocking sleep here is
acceptable and does not block the Coroutine `Main` dispatcher; Retrofit `suspend` calls
(AND-010) remain cancellable end-to-end because OkHttp call cancellation propagates.

### 4.4 Connectivity abstraction

```kotlin
package com.testlogon.android.core.network.retry

fun interface ConnectivityChecker {
    fun isOnline(): Boolean
    companion object { val AlwaysOnline = ConnectivityChecker { true } }
}
```

AND-017 supplies the real `ConnectivityManager`-backed implementation and `@Binds`-replaces
the default `AlwaysOnline` provided here.

### 4.5 Hilt wiring

```kotlin
@Module
@InstallIn(SingletonComponent::class)
object RetryModule {

    @Provides @Singleton
    fun provideRetryPolicy(): RetryPolicy = RetryPolicy.DEFAULT

    @Provides @Singleton
    fun provideDefaultConnectivity(): ConnectivityChecker = ConnectivityChecker.AlwaysOnline
}

@Module
@InstallIn(SingletonComponent::class)
interface RetryBindingModule {
    @Binds @IntoSet
    fun bindRetryInterceptor(impl: RetryBackoffInterceptor): Interceptor   // AND-009 seam
}
```

Per AND-009 FR-7, the logging interceptor is appended **after** the application set, so
retried attempts are individually logged. Within the set, ordering relative to CSRF
(AND-012) is irrelevant because each retry re-runs the full chain below this interceptor,
re-applying CSRF/auth headers freshly on every attempt.

## 5. API Contract

This ticket defines no new app-facing endpoint. It constrains behavior of existing
idempotent reads. Acceptance is validated against **MockWebServer**, not the live host.

Exercised happy-path exchange (transient 503 then 200):

```
# Attempt 1 (interceptor issues):
GET /ui/me HTTP/1.1
Host: localhost:<mock-port>

# MockWebServer response 1:
HTTP/1.1 503 Service Unavailable
Retry-After: 0
Content-Type: application/json

{"detail":"temporarily unavailable"}

# Attempt 2 (after backoff):
GET /ui/me HTTP/1.1

# MockWebServer response 2:
HTTP/1.1 200 OK
Content-Type: application/json

{"user_id":"u_123","username":"spannella"}
```

Caller observes a single `Response(code=200)`; the 503 is invisible above the interceptor.

Never-retried exchange (mutation):

```
POST /ui/session/start HTTP/1.1
Content-Type: application/json

{"challenge_context":{"username":"a","password":"b"}}

# MockWebServer response (single 503):
HTTP/1.1 503 Service Unavailable
```

Caller observes the `503` after **exactly one** `proceed()` — MockWebServer's request count
asserts `1`.

Affected real GETs: `GET /ui/me`, `GET /openapi.json`. Their payload contracts are owned by
the auth feature tickets; this layer is payload-agnostic.

## 6. Data & State Management

- **Stateless interceptor.** `RetryBackoffInterceptor`, `RetryPolicy`, `BackoffCalculator`,
  and `Sleeper` hold no cross-call mutable state. Retry counters are per-`intercept()` locals,
  so the interceptor is fully thread-safe across OkHttp's `Dispatcher` pool.
- **Scope:** `@Singleton` (one interceptor instance shared by the single client). The
  injected `RetryPolicy` is an immutable singleton; per-call overrides are passed via request
  tags, not shared state.
- **No persistence.** No Room/DataStore. No cookie/CSRF state touched (that flows through
  AND-011/012 on each re-issued attempt automatically).
- **No ViewModel/UiState.** Sits below the feature layer; emits no `StateFlow`. The eventual
  success/failure becomes an `ApiResult<T>` only in AND-015's mapping layer.
- **Randomness:** `BackoffCalculator` takes an injectable `Random` so tests can seed
  deterministic jitter.

## 7. Error Handling & Resilience

- **Retryable classification** is centralized: statuses `{502,503,504,408,429}` and the
  transport exceptions in `IOException.isRetryable()`. `UnknownHostException` is treated as
  offline/DNS and **not** retried (fail fast, FR-9) to avoid burning the budget on a dead host.
- **Terminal surfacing (FR-6):** after exhaustion the *real* last response (e.g. `503` with
  its `detail` body) or the last exception is propagated unchanged so AND-015 maps an accurate
  error and AND-017's status reflects true unreachability.
- **Body-leak safety (FR-7):** every intermediate retryable `Response` is `close()`d before
  the next attempt, preventing `ConnectionPool` exhaustion under repeated 503s.
- **Timeout interaction:** total retry time is bounded by AND-009's `callTimeout` (30s).
  `maxDelay`(4s) × up to 2 retries + per-attempt read time stays within budget; if
  `callTimeout` fires mid-backoff, OkHttp cancels the call and `Sleeper` aborts (FR-11). The
  policy never extends a call beyond `callTimeout`.
- **Authenticator non-interference:** OkHttp's `Authenticator` (AND-013) reacts to `401` and
  is orthogonal to this interceptor, which never retries `401`. The two cannot stack: a 401
  triggers refresh-then-retry once by the authenticator; a 503 triggers backoff-retry here.
- **Cancellation (FR-11):** the cancellable `Sleeper` ensures a user navigating away or a
  Coroutine cancellation does not leave a thread sleeping for seconds.
- **Offline (FR-9):** when `ConnectivityChecker.isOnline()` is false, we make one final
  unretried attempt / immediate failure rather than backoff-spinning.

## 8. Security & Privacy

- **No credential handling.** This layer reads only the request method and response status/
  `Retry-After` header; it does not read, log, or store auth material.
- **Replay-safety is the security-relevant invariant:** mutations are never replayed (FR-2).
  This specifically prevents accidental double-submission of `POST /ui/session/start`,
  `/ui/mfa/*/verify`, and `POST /ui/session/finalize`, which could otherwise consume MFA
  attempts, trigger lockouts, or create duplicate sessions. The hard method guard is unit-
  tested (T-3).
- **Re-issued requests carry fresh headers:** because each retry re-runs the chain below this
  interceptor, the CSRF token (`X-CSRF-Token`, AND-012) and cookies (AND-011) are recomputed
  per attempt, so a refreshed token after a 401 elsewhere is never stale on a GET retry.
- **No new logging of sensitive data.** Retry diagnostics (§10) log only method, host, path,
  status, and attempt number — never headers or bodies. Redaction remains AND-009's
  responsibility for the underlying HTTP dump.

## 9. Accessibility & i18n

Not applicable. This ticket has no UI surface, no Compose content, and no user-visible
strings; no `strings.xml` entries are added. User-facing messaging for the *terminal* failure
(after retries are exhausted) is owned by AND-015 (error mapping → strings) and the consuming
feature-* modules, where localization and accessible error presentation are handled.

## 10. Telemetry & Logging

- **Structured retry log (debug only):** on each retry the interceptor emits one Logcat line
  via the existing `OkHttp` tag pattern, e.g.
  `Log.d("OkHttp-Retry", "GET /ui/me attempt=2/3 cause=503 delayMs=312")`. Contains no
  headers/bodies (§8). Gated on `BuildConfig.DEBUG` to match AND-009's posture.
- **No analytics SDK introduced.** A future observability ticket may attach an
  `EventListener` (AND-009 Q3) or increment retry/exhaustion counters; the interceptor exposes
  the attempt index and cause at the log seam to make that drop-in trivial. Out of scope here.
- **Metrics seam:** `BackoffCalculator.delayMsFor` and the cause classification are the two
  hooks a future `RetryMetrics` collaborator would observe; documented as an inline TODO.

## 11. Testing Strategy

JVM unit tests in `core-network/src/test` using `MockWebServer`, JUnit4, Truth, and a fake
`Sleeper` (no real waiting) plus a seeded `Random` for deterministic jitter. The interceptor
is built directly (not through Hilt) for unit tests.

**T-1 (Acceptance — transient 503 then 200).** Enqueue `503` then
`200 {"user_id":"u_123"}`. Issue `GET /ui/me` through a client with
`RetryBackoffInterceptor(DEFAULT, AlwaysOnline, FakeSleeper)`. Assert final `code == 200`,
body round-trips, and `server.requestCount == 2`. **Gating acceptance test.**

**T-2 (Exhaustion).** Enqueue `503` three times with `maxAttempts = 3`. Assert the returned
response is `503` (terminal, FR-6) and `requestCount == 3` (no extra attempt).

**T-3 (Mutations never retried — gating).** Enqueue a single `503`. Issue
`POST /ui/session/start` with a JSON body. Assert the caller sees `503` and
`server.requestCount == 1`. Repeat parametrically for `PUT/PATCH/DELETE`.

**T-4 (Non-retryable statuses).** Enqueue `400`, `401`, `404`, `422` (separate cases) for a
GET; assert each returns after exactly one attempt (`requestCount == 1`) — confirms `401` is
left to AND-013 and 4xx is not retried.

**T-5 (Transport exception retry).** Use `MockResponse().socketPolicy =
DISCONNECT_AT_START` once, then `200`. Assert success after retry and request count `2`.
Then `UnknownHostException`-style/offline case: with `ConnectivityChecker { false }`, assert a
transport error fails fast (one attempt).

**T-6 (Backoff math).** Unit-test `BackoffCalculator` with a fixed-seed `Random`: assert
delays for attempts 0..n are within `[0, min(maxDelay, base*2^n)]`, monotonic ceiling growth,
and that `Retry-After` overrides jitter and is capped at `maxDelay`.

**T-7 (Cancellation).** Cancel the `Call` mid-backoff (fake `Sleeper` checks
`call.isCanceled()`); assert an `IOException` is thrown and no further `proceed()` occurs.

**T-8 (Per-call policy tag).** Issue a GET tagged `RetryPolicy.NO_RETRY` against a `503`;
assert `requestCount == 1`, proving FR-10 / AND-017's opt-out.

**T-9 (Body closed).** Assert intermediate responses are closed (no
`IllegalStateException`/leak warnings; verify via a counting `ResponseBody` or OkHttp's
connection-pool idle count).

CI gates on T-1 and T-3 passing; coverage requires `RetryBackoffInterceptor` and
`BackoffCalculator` exercised.

## 12. Dependencies & Sequencing

**Depends on:**
- **AND-009 — OkHttp client + timeouts + logging.** Provides the `@Singleton OkHttpClient`,
  the ordered application-interceptor seam (`Set<Interceptor>` / future `List`), and the
  `callTimeout` budget this policy must respect. This ticket contributes its interceptor via
  `@Binds @IntoSet` into that seam.

**Blocks:**
- **AND-017 — Connectivity & backend health probe.** Consumes `RetryPolicy.NO_RETRY` for its
  single-shot ping and supplies the real `ConnectivityChecker` that `@Binds`-replaces the
  `AlwaysOnline` default provided here.

**Soft-coupled (no ordering constraint):** AND-013 (Authenticator — independent path),
AND-015 (maps the terminal failure). AND-010 (Retrofit) sits above and is unaffected.

**Build dependencies** (already present from AND-009; none new required):
```kotlin
implementation("com.squareup.okhttp3:okhttp:4.12.0")
testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
```

**Sequencing:** implement `RetryPolicy`/`BackoffCalculator`/`Sleeper` →
`RetryBackoffInterceptor` → `RetryModule`/`RetryBindingModule` → tests T-1..T-9. T-1 and T-3
must pass before AND-017 begins (it relies on the opt-out tag and the `ConnectivityChecker`
seam). Coordinate removal of the `AlwaysOnline` default provider when AND-017 lands to avoid
a duplicate Hilt binding.

## 13. Risks & Open Questions

- **R-1 (Double retry vs. OkHttp `retryOnConnectionFailure`).** AND-009 sets
  `retryOnConnectionFailure(true)`; OkHttp may already reattempt some connection faults
  *within* a single `proceed()`. *Mitigation:* our retries count `proceed()` calls, so total
  attempts remain bounded by `maxAttempts`; the two compose without unbounded fan-out.
  Documented; verified by T-5 request counting.
- **R-2 (Blocking sleep on Dispatcher thread).** Backoff blocks an OkHttp worker. *Mitigation:*
  pool is sized for concurrent calls; sleeps are short (≤4s) and cancellation-aware (T-7).
  Revisit if call concurrency is high.
- **R-3 (callTimeout abort mid-retry).** A slow dev host plus backoff could hit the 30s
  `callTimeout`. *Mitigation:* `maxDelay`/`maxAttempts` chosen conservatively; `Sleeper`
  aborts on cancel. Revisit jointly with AND-013's refresh budget (AND-009 R-4).
- **R-4 (Idempotency assumption for future GETs).** Assumes all `GET`s are side-effect-free.
  *Mitigation:* true for current FastAPI reads; if a non-idempotent GET is ever added, tag it
  `RetryPolicy.NO_RETRY`.
- **Q1.** Should `HEAD` be retried like `GET` (it is idempotent)? *Default:* yes — extend the
  method guard to `{GET, HEAD}` if/when HEAD is used; currently GET-only per the ticket text.
- **Q2.** Honor `Retry-After` HTTP-date form in addition to delta-seconds? *Default:* delta-
  seconds only for M1; date form is rare from FastAPI.
- **Q3.** Should `429` be retried by default given the dev host has no rate limiter today?
  *Default:* include it (harmless) but with `Retry-After` respected.

## 14. Acceptance Criteria

AC-1. **Transient 503 then 200 yields success:** a `GET` returning `503` then `200` produces
a single `200` to the caller with `requestCount == 2` (T-1). *(Primary acceptance.)*

AC-2. **POSTs are never retried:** a `POST` (and `PUT/PATCH/DELETE`) failing with `503` is
surfaced after exactly one attempt; `requestCount == 1` (T-3). *(Primary acceptance.)*

AC-3. Retries are bounded: at most `maxAttempts` (default 3) `proceed()` invocations per
call; on exhaustion the terminal response/exception is returned unchanged (T-2).

AC-4. Only `{502,503,504,408,429}` and retryable transport exceptions trigger retry; `2xx`,
`3xx`, and other `4xx` (incl. `401`, `422`) are returned after one attempt (T-4).

AC-5. Backoff is bounded exponential with full jitter within `[0, min(maxDelay, base*2^n)]`,
deterministic under a seeded `Random`; `Retry-After` overrides and is capped (T-6).

AC-6. Offline (`ConnectivityChecker.isOnline()==false`) causes fail-fast with no backoff
spin (T-5); the interceptor is contributed via Hilt `@IntoSet` and the Hilt graph compiles.

AC-7. Per-call `RetryPolicy.NO_RETRY` tag disables retry for that request (T-8); intermediate
response bodies are closed (T-9); cancellation aborts backoff promptly (T-7).

## 15. Definition of Done

- [ ] `RetryPolicy`, `BackoffCalculator`, `Sleeper`, `ConnectivityChecker`, and
      `RetryBackoffInterceptor` implemented in `core-network` under
      `com.testlogon.android.core.network.retry`.
- [ ] Interceptor contributed via `@Binds @IntoSet Interceptor` into the AND-009 set; Hilt
      graph compiles and injects (`RetryModule`/`RetryBindingModule`).
- [ ] GET-only guard, retryable-status/exception classification, full-jitter backoff,
      `Retry-After` handling, offline fail-fast, per-call tag override, and cancellation-aware
      sleep all implemented per FRs.
- [ ] Default `ConnectivityChecker.AlwaysOnline` provided with an inline TODO naming AND-017
      as the replacer.
- [ ] Debug-only structured retry log line (no headers/bodies) added.
- [ ] Unit tests T-1..T-9 written and passing in CI; T-1 and T-3 are the gating tests.
- [ ] No new lint/detekt warnings in `core-network`; KSP/Hilt build clean.
- [ ] Risks R-1 (double-retry composition) and R-3 (callTimeout interaction) verified by
      request-count assertions and documented.
- [ ] PR reviewed and merged to `android-port`; downstream AND-017 unblocked.
