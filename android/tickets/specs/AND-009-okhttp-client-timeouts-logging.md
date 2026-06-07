---
id: AND-009
title: OkHttp client + timeouts + logging
milestone: M1
epic: E02
priority: P0
size: S
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-003, AND-004]
blocks: [AND-010, AND-011, AND-012, AND-013]
---

# AND-009 — OkHttp client + timeouts + logging

## 1. Overview & Goal

This ticket establishes the single, Hilt-provided `OkHttpClient` instance that every
network call in the TestLogon Android app (`com.testlogon.android`) flows through. It is
the foundation of the E02 networking epic: Retrofit (AND-010), the persistent cookie jar
(AND-011), the CSRF interceptor (AND-012), and the 401 refresh authenticator (AND-013)
all attach to or are configured against the client defined here.

The goal is narrow and deliberate. We deliver:

1. A correctly-tuned `OkHttpClient` configured for the **unreliable plaintext dev backend**
   (`http://18.222.237.167:8000`): connect/read/write timeouts of ~20s, sane connection-pool
   and retry-on-connection-failure settings, and an explicit clear-text-traffic posture.
2. An `HttpLoggingInterceptor` that is **active only in debug builds** and **redacts all
   sensitive headers** (Authorization, Cookie, Set-Cookie, X-CSRF-Token) so that auth
   material never reaches Logcat.
3. The Hilt wiring (`@Module`/`@Provides`) in `core-network` that exposes the client to the
   rest of the graph, plus the extension seams (an ordered interceptor list and a settable
   `CookieJar`/`Authenticator`) that downstream tickets plug into without modifying this code.

The client is intentionally *not* responsible for base-URL resolution, JSON
(de)serialization, cookies, CSRF, or refresh logic — those are owned by the dependent
tickets named above. This ticket's success is a single integration point that boots, times
out gracefully, and logs safely.

## 2. Context & References

- **Module:** `core-network` (created in AND-003). All code in this ticket lives there.
- **DI baseline:** AND-004 (`@HiltAndroidApp` Application, KSP-processed Hilt graph).
- **Stack:** Kotlin 2.0.21, OkHttp 4.12.0, `logging-interceptor` 4.12.0, Hilt (KSP),
  Coroutines/Flow. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` is **plaintext HTTP**
  and unreliable; OpenAPI at `/openapi.json`. Cookie-based auth with a `ui_csrf` cookie echoed
  as `X-CSRF-Token`. These constraints drive the timeout, retry, and redaction decisions here.
- **Web reference:** `frontend/src/api/endpoints/*.ts` (fetch wrapper, credentials: include).
- **Downstream consumers:** AND-010 (Retrofit), AND-011 (CookieJar), AND-012 (CSRF
  interceptor), AND-013 (401 Authenticator). AND-006 supplies `BuildConfig.API_BASE_URL`
  but is consumed by AND-010, not here.
- **Repo:** `spannella/testlogon`, Android app under `android/`, branch `android-port`.

## 3. Functional Requirements

FR-1. The app SHALL provide exactly one application-scoped `OkHttpClient` via Hilt
(`@Singleton`), constructed in `core-network`.

FR-2. The client SHALL set `connectTimeout`, `readTimeout`, and `writeTimeout` to **20
seconds** each, and `callTimeout` to **30 seconds** (an upper bound covering DNS + connect +
the full request/response including a single internal refresh-retry added later by AND-013).

FR-3. The client SHALL set `retryOnConnectionFailure(true)` (OkHttp's transport-level retry
for stale/broken connections only — distinct from application-level GET backoff, which is
owned elsewhere).

FR-4. In **debug builds only**, the client SHALL include an `HttpLoggingInterceptor` at
`Level.BODY`. In **release builds**, no logging interceptor SHALL be present (verified by
absence, not merely a lower level).

FR-5. The logging interceptor SHALL **redact** the following headers in all logged output:
`Authorization`, `Cookie`, `Set-Cookie`, `X-CSRF-Token`, `Proxy-Authorization`. Redacted
headers MUST appear as `<name>: ██` (OkHttp default), never with their value.

FR-6. The client construction SHALL accept an **ordered list of application interceptors**
and an **optional `CookieJar` and `Authenticator`** injected by Hilt, so that AND-011/012/013
contribute their components via multibindings/optional bindings **without editing this
module's provider**.

FR-7. The logging interceptor, when present, SHALL be added **last in the application
interceptor chain** so it observes headers added by CSRF/auth interceptors (and redacts them).

FR-8. The client SHALL be safe against the plaintext dev host: clear-text traffic to
`18.222.237.167` SHALL be permitted via network-security-config without globally disabling
TLS enforcement for production hosts.

## 4. Technical Design

All artifacts live in `core-network`, package `com.testlogon.android.core.network`.

### 4.1 Hilt module

```kotlin
package com.testlogon.android.core.network.di

import com.testlogon.android.core.network.BuildConfig
import com.testlogon.android.core.network.logging.RedactingLoggerFactory
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import okhttp3.Authenticator
import okhttp3.CookieJar
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import java.util.concurrent.TimeUnit
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object NetworkModule {

    private const val TIMEOUT_CONNECT_S = 20L
    private const val TIMEOUT_READ_S = 20L
    private const val TIMEOUT_WRITE_S = 20L
    private const val TIMEOUT_CALL_S = 30L

    @Provides
    @Singleton
    fun provideOkHttpClient(
        // Contributed via @ElementsIntoSet in AND-012/013; empty in this ticket.
        appInterceptors: Set<@JvmSuppressWildcards Interceptor>,
        // Optional bindings: Hilt supplies a no-op default until AND-011/013 land.
        cookieJar: CookieJar,
        authenticator: Authenticator,
    ): OkHttpClient {
        val builder = OkHttpClient.Builder()
            .connectTimeout(TIMEOUT_CONNECT_S, TimeUnit.SECONDS)
            .readTimeout(TIMEOUT_READ_S, TimeUnit.SECONDS)
            .writeTimeout(TIMEOUT_WRITE_S, TimeUnit.SECONDS)
            .callTimeout(TIMEOUT_CALL_S, TimeUnit.SECONDS)
            .retryOnConnectionFailure(true)
            .cookieJar(cookieJar)
            .authenticator(authenticator)

        // Deterministic ordering: CSRF/auth first, logging last so it redacts their headers.
        appInterceptors.forEach { builder.addInterceptor(it) }

        if (BuildConfig.DEBUG) {
            builder.addInterceptor(RedactingLoggerFactory.create())
        }
        return builder.build()
    }
}
```

> Ordering note: `Set<Interceptor>` is unordered. Until AND-012/013 introduce a need for
> strict ordering, this set is empty. When they land, this ticket's contract is upgraded to a
> `List<Interceptor>` qualified binding (`@Named("appInterceptors")`) populated in a defined
> order; the logging interceptor is appended after, in code, regardless. The seam is the key
> deliverable — the concrete set/list shape is finalized by the consuming ticket.

### 4.2 Default optional bindings

So this ticket compiles and runs standalone (before AND-011/013), `core-network` provides
no-op defaults that the later tickets `@Binds`-replace:

```kotlin
@Module
@InstallIn(SingletonComponent::class)
object NetworkDefaultsModule {
    @Provides @Singleton
    fun provideDefaultCookieJar(): CookieJar = CookieJar.NO_COOKIES   // replaced by AND-011

    @Provides @Singleton
    fun provideDefaultAuthenticator(): Authenticator = Authenticator.NONE // replaced by AND-013
}
```

When AND-011/013 add their `@Provides`, this defaults module is deleted (or its providers
removed) to avoid duplicate-binding errors. This is documented inline.

### 4.3 Redacting logger factory

```kotlin
package com.testlogon.android.core.network.logging

import android.util.Log
import okhttp3.logging.HttpLoggingInterceptor

object RedactingLoggerFactory {

    private val SENSITIVE_HEADERS = listOf(
        "Authorization",
        "Cookie",
        "Set-Cookie",
        "X-CSRF-Token",
        "Proxy-Authorization",
    )

    fun create(): HttpLoggingInterceptor {
        val logger = HttpLoggingInterceptor.Logger { message ->
            Log.d("OkHttp", message)
        }
        return HttpLoggingInterceptor(logger).apply {
            level = HttpLoggingInterceptor.Level.BODY
            SENSITIVE_HEADERS.forEach { redactHeader(it) }
        }
    }
}
```

`HttpLoggingInterceptor.redactHeader(name)` is case-insensitive and replaces the value with
`██` in both request and response header dumps. Body redaction of credential payloads carried inside the free-form
`challenge_context` object in `POST /ui/session/start` is **not** provided by OkHttp;
mitigated by FR-4 (logging is debug-only and never ships). (Note: per `UiSessionStartReq`,
`challenge_context` is an open object — `additionalProperties: true` — so the specific
field names of any credentials it carries are not fixed by the backend schema; see §16.)

### 4.4 Network security config

`core-network/src/main/res/xml/network_security_config.xml` (merged into the app manifest by
AND-005/006 manifest wiring) whitelists the dev host for clear-text while keeping
`cleartextTrafficPermitted="false"` as the global default:

```xml
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="false">18.222.237.167</domain>
    </domain-config>
</network-security-config>
```

## 5. API Contract

This ticket defines no app-facing API endpoints; it is transport plumbing. It does, however,
constrain how *all* endpoints behave. The contractual guarantees the client makes to
downstream tickets:

- Any call exceeding 20s at connect/read/write, or 30s end-to-end, fails with
  `java.net.SocketTimeoutException` (mapped to a domain error by AND-014/ApiResult, not here).
- Connection-level failures (stale keep-alive, broken pipe) are transparently retried once by
  OkHttp before surfacing.
- Validation target endpoint for the acceptance test is a **MockWebServer** local instance,
  not the real backend. Example exercised exchange:

Request issued by the test:
```
GET /ping HTTP/1.1
Host: localhost:<mock-port>
Authorization: Bearer secret-token-should-not-appear
Cookie: session=abc; ui_csrf=xyz
```

MockWebServer response:
```
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: session=def; Path=/; HttpOnly

{"status":"ok"}
```

Expected Logcat (assertion target): lines for `Authorization`, `Cookie`, and `Set-Cookie`
render as `Authorization: ██`, `Cookie: ██`, `Set-Cookie: ██`; the body `{"status":"ok"}` is
present; `secret-token-should-not-appear`, `abc`, `xyz`, and `def` are absent from all logs.

Real endpoints (`/ui/session/start`, `/ui/session/finalize`, `/ui/me`, `/ui/session/refresh`)
are listed only to identify which headers must be redacted; their contracts are owned by the
auth feature tickets (E03+).

## 6. Data & State Management

The client is **stateless application configuration** with one mutable concern delegated
away: the connection pool and (later) the cookie jar hold transport state.

- **Scope:** `@Singleton`. Exactly one `OkHttpClient` and its `Dispatcher`/`ConnectionPool`
  exist per process. Reuse is mandatory — never construct ad-hoc clients (each spawns its own
  pool/threads). A lint/CI rule (section 11) enforces single construction.
- **No persisted state** is introduced by this ticket. Cookie persistence (AND-011) and CSRF
  token derivation (AND-012) layer on later. No Room/DataStore usage here.
- **ViewModel/UiState:** none. The client sits below the feature layer; no
  `StateFlow<UiState>` is touched.
- **Thread model:** OkHttp manages its own `Dispatcher` thread pool; Retrofit `suspend`
  functions (AND-010) bridge to Coroutines. This ticket changes neither default.

## 7. Error Handling & Resilience

- **Timeouts:** the 20s/30s budget is tuned to the unreliable dev host — long enough for a
  cold FastAPI/DynamoDB path, short enough to fail fast for the UI's offline/stale states.
  Timeouts surface as `SocketTimeoutException`/`InterruptedIOException`; this ticket does not
  catch or map them — mapping to `ApiResult.Error` is owned by AND-014.
- **Connection failure retry:** `retryOnConnectionFailure(true)` handles transient transport
  faults. This is *not* the bounded GET backoff described in project context (that is
  application-level, in the repository/use-case layer, GET-only); the two compose cleanly.
- **No retry of non-idempotent requests** at the transport layer beyond OkHttp's own
  connection-reestablishment, which never replays a request whose body was already sent on a
  fully-established connection.
- **`callTimeout` headroom:** set to 30s (> 20s read) so AND-013's single internal
  refresh+retry fits inside one call budget without a spurious `callTimeout` abort.
- **Graceful degradation:** because the client never throws at construction (no network at
  build time), DI graph creation cannot fail due to backend availability.

## 8. Security & Privacy

- **Header redaction (primary control):** all credential-bearing headers (`Authorization`,
  `Cookie`, `Set-Cookie`, `X-CSRF-Token`, `Proxy-Authorization`) are redacted in logs. This
  is the central security requirement of the ticket and is acceptance-tested.
- **Debug-only logging:** the logging interceptor is gated on `BuildConfig.DEBUG`; release
  builds contain no body/header logging path at all, eliminating the risk of leaking the
  `ui_csrf` cookie or session cookies in production Logcat or crash logs.
- **Clear-text scoping:** clear-text HTTP is permitted *only* for the dev IP via
  `network_security_config.xml`; the global default remains `false`, so staging/prod hosts
  (HTTPS) cannot be downgraded.
- **Body credentials caveat:** OkHttp cannot redact JSON bodies, so the login body
  (a `{challenge_context: {...}}` envelope; `challenge_context` is a free-form object per the
  `UiSessionStartReq` schema — credential field names such as username/password are not fixed
  by the backend contract, see §16) would print in debug. Documented as a known
  limitation acceptable only because logging never ships; a follow-up may add a body-filtering
  logger if debug log sharing becomes a concern (Open Question Q2).
- **No secret storage:** this ticket stores no tokens; cookie persistence and its encryption
  (EncryptedSharedPreferences/DataStore) are AND-011's responsibility.

## 9. Accessibility & i18n

Not applicable. This ticket has no UI surface, no user-visible strings, and no Compose
content. Accessibility and localization for network-driven screens are owned by their
respective feature tickets (e.g., AND-014 error mapping → user-facing strings, and the
feature-* modules). No `strings.xml` entries are added here.

## 10. Telemetry & Logging

- **Logging:** the `HttpLoggingInterceptor` (debug only) is the sole logging output, under
  Logcat tag `OkHttp`, at `Level.BODY`, with redaction per section 8. No `println`/`System.out`.
- **No analytics/telemetry SDK** is introduced. If a structured network-event sink (latency,
  status-code histograms) is later desired, it attaches as an `EventListener` on the builder —
  an explicitly documented future seam, out of scope here (Open Question Q3).
- **Diagnostics:** consumers may read `response.networkResponse?.code` etc.; this ticket adds
  no custom metrics. Timeout/error counting is deferred to whatever observability ticket the
  team schedules.

## 11. Testing Strategy

All tests live in `core-network/src/test` (JVM unit tests; no instrumentation needed) using
`okhttp3.mockwebserver.MockWebServer`, JUnit4, and Truth (from `core-testing`, AND-003).

**T-1 (Acceptance — happy path).** Build a client via the production provider, point it at a
`MockWebServer` enqueuing `200 {"status":"ok"}`, issue a `GET /ping`, assert response code
`200` and body `ok`. Verifies the client is constructed and functional.

```kotlin
@Test fun request_against_mockwebserver_succeeds() {
    server.enqueue(MockResponse().setResponseCode(200).setBody("""{"status":"ok"}"""))
    val client = NetworkModule.provideOkHttpClient(emptySet(), CookieJar.NO_COOKIES, Authenticator.NONE)
    val resp = client.newCall(Request.Builder().url(server.url("/ping")).build()).execute()
    assertThat(resp.code).isEqualTo(200)
}
```

**T-2 (Acceptance — redaction).** Install a test `HttpLoggingInterceptor.Logger` capturing
messages into a list (instead of `Log.d`), send a request carrying `Authorization`, `Cookie`,
and receive a `Set-Cookie` response. Assert each sensitive header line contains `██` and that
none of the raw secret values appear in any captured line; assert the body *is* logged.

**T-3 (Timeouts).** Configure `MockWebServer` with a throttled/`NO_RESPONSE` body so the read
exceeds 20s using a `MockResponse().setBodyDelay(...)`; assert a `SocketTimeoutException` is
thrown. (Run with a shortened timeout-injected client variant to keep the test fast, asserting
the configured values via a builder-inspection helper rather than waiting 20s in CI.)

**T-4 (Debug gating).** A small `NetworkModuleTest` verifies that with `BuildConfig.DEBUG`
true the built client's `interceptors` contains an `HttpLoggingInterceptor`, and a release-
config variant (via a test seam exposing the predicate) contains none.

**T-5 (Single-instance / no ad-hoc clients).** A CI check (Konsist or a ripgrep-based Gradle
verification task) asserts `OkHttpClient.Builder()` appears only in `NetworkModule`.

Coverage gate: the `RedactingLoggerFactory` and provider are required to be exercised; redaction
(T-2) is the gating acceptance assertion.

## 12. Dependencies & Sequencing

**Depends on:**
- **AND-003 — Core module structure:** `core-network` module must exist with its namespace
  and build file, and `core-testing` must provide MockWebServer/Truth/JUnit test deps.
- **AND-004 — Hilt DI baseline:** `SingletonComponent` and the Hilt/KSP plugin must be wired
  so `@Module @InstallIn(SingletonComponent::class)` resolves.

**Blocks (downstream consumers):**
- **AND-010 — Retrofit + Moshi:** builds its `Retrofit` on this `OkHttpClient`.
- **AND-011 — Persistent cookie jar:** replaces the default `CookieJar` binding.
- **AND-012 — CSRF interceptor:** contributes an application interceptor into the set/list.
- **AND-013 — 401 refresh authenticator:** replaces the default `Authenticator` binding;
  relies on the 30s `callTimeout` headroom defined here.

**Build dependencies to add to `core-network/build.gradle.kts`:**
```kotlin
implementation("com.squareup.okhttp3:okhttp:4.12.0")
implementation("com.squareup.okhttp3:logging-interceptor:4.12.0")
implementation("com.google.dagger:hilt-android:<catalog>")
ksp("com.google.dagger:hilt-android-compiler:<catalog>")
testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
```

Sequencing: implement defaults module + provider + logger factory + network-security-config,
then T-1/T-2 must pass before AND-010 begins. Removal of `NetworkDefaultsModule` providers is
coordinated as AND-011/013 land.

## 13. Risks & Open Questions

- **R-1 (Interceptor ordering churn).** The empty `Set<Interceptor>` here becomes an ordered
  `List` when AND-012/013 land. *Mitigation:* document the seam now; freeze the ordered-list
  contract in AND-012 so logging stays last.
- **R-2 (Duplicate Hilt bindings).** `NetworkDefaultsModule` will collide with AND-011/013
  providers if not removed. *Mitigation:* inline TODO + a tracking note in those tickets.
- **R-3 (Body credential leakage in debug logs).** OkHttp cannot redact bodies; any
  credentials inside the `challenge_context` login envelope print in debug. *Mitigation:*
  debug-only gating; revisit per Q2.
- **R-4 (callTimeout vs. AND-013 refresh).** If AND-013's refresh+retry is slow on the dev
  host, 30s may abort it. *Mitigation:* revisit `callTimeout` when AND-013 is implemented;
  value is centralized as a constant.
- **Q1.** Should clear-text be limited further to the exact `:8000` host, or is IP-level
  scoping sufficient? (network-security-config matches host only, not port.)
- **Q2.** Do we need a custom body-redacting logger for shareable debug logs, or is debug-only
  gating enough? (Default: enough.)
- **Q3.** Do we want an `EventListener` for network telemetry in M1, or defer to a later
  observability ticket? (Default: defer.)

## 14. Acceptance Criteria

AC-1. A single `@Singleton OkHttpClient` is provided from `core-network` via Hilt and is the
only `OkHttpClient` constructed in the app (enforced by T-5).

AC-2. Connect, read, and write timeouts are 20s; `callTimeout` is 30s;
`retryOnConnectionFailure` is true. (Asserted via builder/inspection helper.)

AC-3. **A test request against MockWebServer succeeds** (T-1: `200`, body round-trips).

AC-4. **Logs redact sensitive headers:** with logging enabled, `Authorization`, `Cookie`,
`Set-Cookie`, and `X-CSRF-Token` render as `██`, and no raw secret value appears in any log
line, while the response body is still logged (T-2).

AC-5. The logging interceptor is present in debug builds and absent in release builds (T-4).

AC-6. Clear-text traffic is permitted to `18.222.237.167` while the global default remains
disabled (network-security-config present and scoped).

AC-7. The Hilt graph compiles and the client injects successfully with the no-op default
`CookieJar`/`Authenticator` (graph builds standalone, before AND-011/013).

## 15. Definition of Done

- [ ] `NetworkModule`, `NetworkDefaultsModule`, and `RedactingLoggerFactory` implemented in
      `core-network` under `com.testlogon.android.core.network`.
- [ ] `network_security_config.xml` added and referenced; manifest clear-text posture verified.
- [ ] OkHttp + logging-interceptor + MockWebServer dependencies added via the version catalog.
- [ ] Timeouts, `callTimeout`, and `retryOnConnectionFailure` set per AC-2; values as named
      constants.
- [ ] Logging interceptor debug-gated and added last in the chain.
- [ ] Header redaction list complete and applied via `redactHeader(...)`.
- [ ] Unit tests T-1 through T-5 written and passing in CI; T-2 (redaction) is the gating test.
- [ ] CI single-instance check (T-5) green.
- [ ] Interceptor-set and optional-binding seams documented with inline TODOs naming
      AND-011/012/013.
- [ ] No new lint/detekt warnings in `core-network`; KSP/Hilt build clean.
- [ ] PR reviewed and merged to `android-port`; downstream AND-010 unblocked.

## 16. Citations & Assumption Audit

Each key technical claim in this spec, with verdict and an exact source pointer. This ticket
is transport plumbing, so most claims are framework/library facts (labeled "framework ref")
rather than backend-contract facts; the few backend claims are verified against the OpenAPI
spec and the frontend reference client.

1. **CSRF: the `ui_csrf` cookie value is echoed back as the `X-CSRF-Token` header.**
   VERDICT: Verified. SOURCE: `src/api/client.ts` lines 167-171
   (`const csrf = getCookie("ui_csrf"); ... headers.set("X-CSRF-Token", csrf)`); also
   `src/api/endpoints/kycCompliance.ts:63-67`, `src/api/endpoints/profile.ts:157-159`.

2. **Auth is cookie-based with `credentials: include` on every request.**
   VERDICT: Verified. SOURCE: `src/api/client.ts:180-184` (`fetch(url, { ...init, headers,
   credentials: "include" })`); refresh path also uses `credentials: "include"`
   (`src/api/client.ts:122-125`).

3. **A bearer token may also be sent via the `Authorization` header.**
   VERDICT: Verified. SOURCE: `src/api/client.ts:157-160` (sets `Authorization: Bearer
   ${accessToken}` from the auth store when present). This confirms `Authorization` is a real
   credential-bearing header worth redacting.

4. **Real auth endpoints exist: `POST /ui/session/start`, `POST /ui/session/finalize`,
   `GET /ui/me`, `POST /ui/session/refresh`.**
   VERDICT: Verified. SOURCE: OpenAPI index —
   `POST /ui/session/start | op=ui_session_start_ui_session_start_post | req=UiSessionStartReq | resp=200:UiSessionStartResp`;
   `POST /ui/session/finalize | req=UiSessionFinalizeReq | resp=200:;422:HTTPValidationError`;
   `GET /ui/me | resp=200:;422:HTTPValidationError`;
   `POST /ui/session/refresh | req= | resp=200:`.

5. **The login request body is `{ challenge_context: { username, password } }`.**
   VERDICT: Corrected → Unverified-assumption (field names). SOURCE:
   `components.schemas.UiSessionStartReq` defines a single property `challenge_context` of
   `type: object` with `additionalProperties: true` and no declared sub-fields. The envelope
   key `challenge_context` is Verified; the specific `username`/`password` field names are NOT
   defined by the backend contract and were softened in §4.3 / §8 / §13 to "credentials
   inside the free-form `challenge_context`". OpenAPI `POST /ui/session/start`,
   schema `UiSessionStartReq`.

6. **`POST /ui/session/refresh` takes no request body and returns 200.**
   VERDICT: Verified. SOURCE: OpenAPI index `POST /ui/session/refresh | req= | resp=200:`;
   frontend `src/api/client.ts:121-130` calls it with `method: "POST"` and no body. (Supports
   the §7 claim that AND-013's refresh+retry fits in the 30s `callTimeout` budget — refresh is
   a single bodyless POST.)

7. **The web client refreshes the session once on a 401 and retries the original request.**
   VERDICT: Verified. SOURCE: `src/api/client.ts:191-221` (single in-flight `refreshPromise`,
   then retry with fresh session). This is the behavior AND-013 ports to an OkHttp
   `Authenticator`; it justifies the §7 `callTimeout` headroom rationale.

8. **Validation errors return `422` with an `HTTPValidationError` body
   (`{ "detail": ValidationError[] }`).**
   VERDICT: Verified. SOURCE: OpenAPI index `resp=...;422:HTTPValidationError` on the auth
   endpoints; `components.schemas.HTTPValidationError` = `{ detail: array<ValidationError> }`.
   (Used in §17 contract tests for realistic error shapes; note this ticket does not parse
   error bodies — mapping is AND-014.)

9. **Dev backend is plaintext HTTP at `http://18.222.237.167:8000` and unreliable.**
   VERDICT: Unverified-assumption. SOURCE: project/ticket context only (ticket scope + §2);
   not derivable from the OpenAPI spec or frontend source (which use a relative/configured
   base URL). Treated as a given environmental constraint that drives timeout/clear-text
   decisions.

10. **OkHttp `connectTimeout`/`readTimeout`/`writeTimeout` default to 10s and `callTimeout`
    defaults to 0 (no timeout) — hence all four must be set explicitly.**
    VERDICT: Verified (framework ref). SOURCE: OkHttp `OkHttpClient.Builder` docs —
    https://square.github.io/okhttp/4.x/okhttp/okhttp3/-ok-http-client/-builder/ .

11. **`retryOnConnectionFailure(true)` retries only transport-level connection problems
    (stale pooled connections, unreachable routes), never replaying a request already written
    to a healthy connection.**
    VERDICT: Verified (framework ref). SOURCE: OkHttp `OkHttpClient.Builder.retryOnConnectionFailure`
    docs — https://square.github.io/okhttp/4.x/okhttp/okhttp3/-ok-http-client/-builder/retry-on-connection-failure/ .

12. **`HttpLoggingInterceptor.redactHeader(name)` is case-insensitive and replaces the value
    with `██` in both request and response header dumps.**
    VERDICT: Verified (framework ref). SOURCE: OkHttp logging-interceptor
    `HttpLoggingInterceptor.redactHeader` docs —
    https://square.github.io/okhttp/4.x/logging-interceptor/okhttp3/logging/-http-logging-interceptor/redact-header/ .
    (OkHttp redacts only headers, not bodies — confirms the §8 body-leakage caveat.)

13. **Application interceptors run in the order added, and an interceptor added last observes
    headers injected by earlier interceptors.**
    VERDICT: Verified (framework ref). SOURCE: OkHttp interceptors guide —
    https://square.github.io/okhttp/features/interceptors/ . (Supports FR-7: logging added
    last so it sees & redacts CSRF/auth headers.)

14. **Android `network-security-config` `domain-config` matches by host only (not port), and a
    `base-config cleartextTrafficPermitted="false"` keeps other hosts HTTPS-only.**
    VERDICT: Verified (framework ref). SOURCE: Android Network security configuration docs —
    https://developer.android.com/privacy-and-security/security-config . (Confirms Q1: IP
    scoping cannot be narrowed to `:8000`.)

15. **`MockWebServer` (`com.squareup.okhttp3:mockwebserver`) supports `enqueue`,
    `setBodyDelay`, and `SocketPolicy.NO_RESPONSE` for timeout testing.**
    VERDICT: Verified (framework ref). SOURCE: OkHttp MockWebServer docs —
    https://github.com/square/okhttp/tree/master/mockwebserver .

### Corrections made

- **§4.3, §8, §13 (claim 5):** Removed the assertion that the login body is specifically
  `{ challenge_context: { username, password } }`. The `UiSessionStartReq` schema declares
  `challenge_context` as an open object (`additionalProperties: true`) with no fixed
  sub-fields, so the credential field names are not part of the backend contract. Reworded to
  "credentials inside the free-form `challenge_context`" and cross-referenced this audit. The
  security point (OkHttp cannot redact bodies) is unchanged and still valid.
- No other factual errors found. Endpoint paths/methods, the `ui_csrf`→`X-CSRF-Token` CSRF
  mechanism, cookie-based auth, the single-retry-on-401 behavior, and the 422/HTTPValidationError
  error shape are all confirmed against the sources and were already stated correctly.

### Open assumptions

- **Dev host identity & reliability** (`http://18.222.237.167:8000`, plaintext, flaky): from
  ticket/project context only; not present in OpenAPI or frontend source (claim 9). Drives the
  timeout and clear-text decisions; if the dev host/IP changes, §4.4 and the constants in §4.1
  must be revisited.
- **Exact credential field names inside `challenge_context`**: not defined by the backend
  schema (claim 5). Does not affect this ticket's deliverable (transport plumbing) but is
  flagged for the E03 auth tickets that actually build the request body.
- **20s/30s timeout values**: chosen heuristically for the unreliable dev host; not derived
  from any measured backend latency in the sources. Centralized as named constants (§4.1) so
  they can be tuned (R-4) without code churn.

## 17. Test Plan

Test IDs `TC-AND-009-NN`. All JVM-side tests live in `core-network/src/test` using
MockWebServer + JUnit4 + Truth. "Traces" link to the §14 Acceptance Criteria.

- **TC-AND-009-01** — Happy path (contract/MockWebServer).
  Preconditions: `MockWebServer` running; client built via `NetworkModule.provideOkHttpClient(
  emptySet(), CookieJar.NO_COOKIES, Authenticator.NONE)`.
  Steps: enqueue `200 {"status":"ok"}`; issue `GET /ping`.
  Expected: response code `200`; body deserializes to `{"status":"ok"}`; exactly one request
  recorded by the server.
  Traces: AC-3, AC-7.

- **TC-AND-009-02** — Header redaction (unit, gating).
  Preconditions: build the logging interceptor via `RedactingLoggerFactory.create()` but inject
  a test `HttpLoggingInterceptor.Logger` that captures messages into a `MutableList<String>`
  (instead of `Log.d`); attach to a MockWebServer-backed client.
  Steps: enqueue a `200` response that sets `Set-Cookie: session=def; ...`; send a request with
  `Authorization: Bearer secret-token-should-not-appear` and `Cookie: session=abc; ui_csrf=xyz`.
  Expected: captured log contains `Authorization: ██`, `Cookie: ██`, `Set-Cookie: ██`; none of
  `secret-token-should-not-appear`, `abc`, `xyz`, `def` appear in ANY captured line; the
  response body `{"status":"ok"}` IS present.
  Traces: AC-4. (Gating acceptance assertion.)

- **TC-AND-009-03** — `X-CSRF-Token` redaction (unit).
  Preconditions: same capturing-logger setup as TC-02.
  Steps: send a request carrying `X-CSRF-Token: csrf-secret-xyz`.
  Expected: log shows `X-CSRF-Token: ██`; `csrf-secret-xyz` absent from all captured lines.
  (Mirrors the web client's `ui_csrf`→`X-CSRF-Token` header per §16 claim 1.)
  Traces: AC-4.

- **TC-AND-009-04** — `Proxy-Authorization` redaction (unit).
  Preconditions: capturing-logger setup.
  Steps: send a request with `Proxy-Authorization: Basic c2VjcmV0`.
  Expected: `Proxy-Authorization: ██` in log; `c2VjcmV0` absent. (Confirms FR-5's full list,
  not just the four headers in AC-4.)
  Traces: AC-4.

- **TC-AND-009-05** — Timeout values applied / read timeout surfaces `SocketTimeoutException`
  (contract/MockWebServer).
  Preconditions: client built with shortened timeouts (test seam: timeout constants injected /
  small builder variant) so CI does not wait 20s; MockWebServer enqueues a response with
  `setBodyDelay` exceeding the read timeout (or `SocketPolicy.NO_RESPONSE`).
  Steps: issue a `GET`; await completion.
  Expected: a `SocketTimeoutException` (subtype of `InterruptedIOException`) is thrown; this
  ticket does not catch/map it. Additionally assert via a builder-inspection helper that the
  production client's `connectTimeoutMillis`/`readTimeoutMillis`/`writeTimeoutMillis` == 20000,
  `callTimeoutMillis` == 30000, and `retryOnConnectionFailure` == true.
  Traces: AC-2.

- **TC-AND-009-06** — Connection-failure retry does not replay sent request bodies (contract).
  Preconditions: client with `retryOnConnectionFailure(true)`; MockWebServer first response
  uses `SocketPolicy.DISCONNECT_AFTER_REQUEST` / a stale-connection scenario, second enqueued
  response is `200`.
  Steps: issue an idempotent `GET`; observe transparent reconnect.
  Expected: the call ultimately succeeds via OkHttp's connection re-establishment without the
  caller observing the transient failure; for a request whose body was already fully written on
  a healthy connection, no silent replay occurs (per §16 claim 11). 
  Traces: AC-2.

- **TC-AND-009-07** — Debug build includes the logging interceptor (unit).
  Preconditions: `BuildConfig.DEBUG == true` (or the debug branch via the test seam exposing the
  predicate).
  Steps: build the client through the provider; inspect `client.interceptors`.
  Expected: exactly one `HttpLoggingInterceptor` is present.
  Traces: AC-5.

- **TC-AND-009-08** — Release build excludes the logging interceptor (unit, security).
  Preconditions: release branch via the test seam (`BuildConfig.DEBUG == false`).
  Steps: build the client; inspect `client.interceptors`.
  Expected: NO `HttpLoggingInterceptor` instance present (verified by absence, per FR-4 — not a
  lowered level). Guards against credential/cookie leakage in production Logcat.
  Traces: AC-5.

- **TC-AND-009-09** — Logging interceptor is added LAST so it observes/redacts downstream
  headers (unit).
  Preconditions: provider invoked with a non-empty `appInterceptors` set containing a dummy
  interceptor that ADDS `X-CSRF-Token: injected` to the outbound request; debug build; capturing
  logger.
  Steps: issue a request that originally had no CSRF header.
  Expected: the injected `X-CSRF-Token` appears in the log AS `██` (proving the logger ran after
  the injecting interceptor and still redacted it). 
  Traces: AC-4, AC-5.

- **TC-AND-009-10** — Hilt graph builds standalone with no-op defaults (integration).
  Preconditions: a Hilt test component installing `NetworkModule` + `NetworkDefaultsModule`
  with an empty interceptor multibinding.
  Steps: trigger graph creation and inject `OkHttpClient`.
  Expected: graph compiles and the client injects successfully; injected `cookieJar` ==
  `CookieJar.NO_COOKIES` and `authenticator` == `Authenticator.NONE` (the AND-011/013
  placeholders). Construction never touches the network.
  Traces: AC-1, AC-7.

- **TC-AND-009-11** — Single `OkHttpClient` construction site (instrumented/CI static check).
  Preconditions: Konsist or a ripgrep-based Gradle verification task over the Android source set.
  Steps: scan for `OkHttpClient.Builder(`.
  Expected: it appears only in `NetworkModule`; the check fails the build on any other match.
  Traces: AC-1.

- **TC-AND-009-12** — Clear-text scoping (manual / instrumented).
  Preconditions: `network_security_config.xml` present and referenced by the merged manifest.
  Steps (manual or `androidTest`): attempt a plaintext `http://18.222.237.167/...` request
  (allowed) and a plaintext request to an arbitrary other host (expected blocked); confirm the
  `base-config` default is `cleartextTrafficPermitted="false"` and only `18.222.237.167` is
  whitelisted.
  Expected: cleartext to `18.222.237.167` succeeds at the TLS-policy layer; cleartext to any
  other host raises a cleartext-not-permitted error. (Host-only match per §16 claim 14 — port
  is not constrained.)
  Traces: AC-6.

- **TC-AND-009-13** — 422 validation error passes through untouched (contract/MockWebServer).
  Preconditions: MockWebServer-backed client.
  Steps: enqueue `422` with body
  `{"detail":[{"loc":["body","challenge_context"],"msg":"field required","type":"value_error"}]}`
  (real `HTTPValidationError` shape per §16 claim 8); issue a request.
  Expected: the client returns the `422` response verbatim with the body intact; this ticket
  performs NO error mapping (that is AND-014). Confirms the transport layer is contract-neutral.
  Traces: AC-3.

- **TC-AND-009-14** — Offline / flaky-dev-host failure surfaces as IOException (contract).
  Preconditions: client pointed at a MockWebServer that is shut down before the call (simulating
  the unreliable dev host / offline), or `SocketPolicy.NO_RESPONSE` with short timeouts.
  Steps: issue a `GET`.
  Expected: an `IOException` subtype (`ConnectException` / `SocketTimeoutException`) is thrown
  and propagates uncaught (mapping owned by AND-014); DI graph and client remain reusable for
  subsequent calls.
  Traces: AC-2, AC-3.

Note on accessibility (§9): this ticket has no UI surface, so no Compose-UI or accessibility
test cases apply. The "where there is UI" accessibility requirement is intentionally N/A here.

### Coverage matrix

| Acceptance criterion | Covered by |
|---|---|
| AC-1 (single @Singleton client, only construction site) | TC-AND-009-10, TC-AND-009-11 |
| AC-2 (timeouts 20s, callTimeout 30s, retryOnConnectionFailure true) | TC-AND-009-05, TC-AND-009-06, TC-AND-009-14 |
| AC-3 (request against MockWebServer succeeds) | TC-AND-009-01, TC-AND-009-13, TC-AND-009-14 |
| AC-4 (sensitive headers redacted, body still logged) | TC-AND-009-02, TC-AND-009-03, TC-AND-009-04, TC-AND-009-09 |
| AC-5 (logging present in debug, absent in release) | TC-AND-009-07, TC-AND-009-08, TC-AND-009-09 |
| AC-6 (clear-text scoped to 18.222.237.167, global default off) | TC-AND-009-12 |
| AC-7 (graph compiles & injects with no-op defaults) | TC-AND-009-01, TC-AND-009-10 |
