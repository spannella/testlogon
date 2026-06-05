---
id: AND-046
title: MockWebServer harness + fixtures
milestone: M1
epic: E07
priority: P0
size: M
status: draft
depends_on: [AND-010]
blocks: [AND-013, AND-014, AND-015, AND-016, AND-017, AND-018]
---

# AND-046 — MockWebServer harness + fixtures

## 1. Overview & Goal

This ticket delivers a reusable HTTP test harness and a curated set of JSON fixtures inside the `core-testing` module so that every networking, repository, and ViewModel test in the TestLogon Android port can exercise Retrofit/OkHttp against a deterministic, in-process server instead of the unreliable dev backend at `http://18.222.237.167:8000`.

The harness wraps OkHttp's `MockWebServer` (from `com.squareup.okhttp3:mockwebserver`) behind a small, ergonomic API: a JUnit4 `TestRule` / JUnit5 extension that starts and shuts the server down per test, fixture-loading helpers that read captured JSON from test resources, and a request-routing `Dispatcher` that can model the cookie-based auth flow (`/ui/session/start` → MFA → `/ui/session/finalize` → `/ui/me`), CSRF header echoing, `401 → /ui/session/refresh → retry`, and the dev backend's failure modes (timeouts, 5xx, malformed bodies).

The fixtures are *captured from the real backend's auth responses* so test assertions track live wire shapes rather than hand-invented ones. The goal: any feature ticket can write a hermetic test in three lines — start the harness, enqueue a fixture, assert on the parsed `ApiResult<T>` — with zero network flakiness and full coverage of error branches.

This is a **Chore** ticket; it ships no production code path and no user-visible behavior. It produces test infrastructure consumed by downstream auth/session/repository tickets.

## 2. Context & References

- **Module:** `core-testing` (test-only library module; consumed via `testImplementation`/`androidTestImplementation` by feature and core modules).
- **Layering:** `core-testing` sits beside the other `core-*` modules and depends only on `core-model` (for fixture-typed deserialization assertions) and `core-network` test surfaces. It must not depend on `app` or any `feature-*` module.
- **Upstream dependency AND-010 (Retrofit + Moshi setup):** establishes Retrofit 2.11 + Moshi 1.15 (Kotlin codegen) with `baseUrl` sourced from `BuildConfig`. The harness must expose a `baseUrl` (an `HttpUrl`) that AND-010's Retrofit factory can be pointed at in tests, so the same `Moshi` instance and converter config used in production are validated against fixtures.
- **Backend reference:** FastAPI + DynamoDB. Auth is cookie-based with a `ui_csrf` cookie echoed as `X-CSRF-Token`. OpenAPI at `/openapi.json`. Error envelope `detail` may be `string | [{msg, ...}] | {code, ...}`.
- **Web reference for shapes:** `frontend/src/api/endpoints/*.ts` and `frontend/src/api/types.ts` document the same request/response contracts; fixtures should be cross-checked against these and against live captures.
- **Stack:** Kotlin 2.0.21, OkHttp 4.12, Moshi 1.15, Coroutines/Flow, JUnit, Truth/AssertJ assertions, JDK 17, Gradle 8.9, AGP 8.7.3.
- **Namespace:** `com.testlogon.android.core.testing`.

## 3. Functional Requirements

FR-1. Provide a lifecycle-managed `MockWebServer` accessible from JUnit4 (as a `TestRule`) and from plain test setup (start/stop helpers), starting on an ephemeral port and shutting down deterministically.

FR-2. Expose the server's `baseUrl: HttpUrl` and a convenience `retrofit(moshi): Retrofit` builder so a test can construct the real API interfaces against the mock server.

FR-3. Load JSON fixtures by logical name from test resources (`core-testing/src/main/resources/fixtures/**`) and enqueue them as `MockResponse` with configurable status code, headers, and delay.

FR-4. Provide a request-aware `Dispatcher` (`AuthFlowDispatcher`) that responds based on path + method, models `Set-Cookie` issuance (session + `ui_csrf`), and asserts the `X-CSRF-Token` header on mutating requests.

FR-5. Model the full happy-path auth sequence: `POST /ui/session/start` → MFA begin/verify → `POST /ui/session/finalize` → `GET /ui/me`, each backed by a captured fixture.

FR-6. Model failure injection: per-route `enqueue` of `503`, `500` with `detail` envelopes, network timeout (via `MockResponse.socketPolicy`/`setBodyDelay`), malformed JSON, and the `401 → POST /ui/session/refresh → retry` cycle.

FR-7. Provide a `RecordedRequest` assertion helper to verify outgoing path, method, headers (CSRF, cookies), and JSON body equality against an expected fixture.

FR-8. Provide a fixture-currency check (`FixtureValidationTest`) that fails CI when a fixture no longer parses into its `core-model` type, catching schema drift.

FR-9. Ship a documented re-capture procedure so fixtures can be refreshed from the live backend.

## 4. Technical Design

The harness lives under `core-testing/src/main/kotlin/com/testlogon/android/core/testing/net/`. Because `core-testing` is consumed via `testImplementation`, its classes live in `main` (not `test`) so they are visible to dependents.

```kotlin
package com.testlogon.android.core.testing.net

/** JUnit4 rule: starts MockWebServer before each test, shuts it down after. */
class MockBackendRule(
    private val dispatcherFactory: (() -> Dispatcher)? = null,
) : TestRule {
    lateinit var server: MockWebServer
        private set
    val baseUrl: HttpUrl get() = server.url("/")

    override fun apply(base: Statement, description: Description): Statement = object : Statement() {
        override fun evaluate() {
            server = MockWebServer().also { s ->
                dispatcherFactory?.let { s.dispatcher = it() }
                s.start()
            }
            try { base.evaluate() } finally { server.shutdown() }
        }
    }

    fun enqueue(response: MockResponse) = server.enqueue(response)
    fun takeRequest(): RecordedRequest = server.takeRequest(5, TimeUnit.SECONDS)!!
}

/** Builds the production-config Retrofit pointed at the mock server. */
fun MockBackendRule.retrofit(moshi: Moshi, client: OkHttpClient = defaultTestClient()): Retrofit =
    Retrofit.Builder()
        .baseUrl(baseUrl)
        .client(client)
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()

/** Short timeouts so timeout tests run fast; matches prod retry semantics, not its 20s budget. */
fun defaultTestClient(): OkHttpClient = OkHttpClient.Builder()
    .connectTimeout(2, TimeUnit.SECONDS)
    .readTimeout(2, TimeUnit.SECONDS)
    .cookieJar(InMemoryCookieJar())
    .build()
```

Fixture loading reads classpath resources:

```kotlin
object Fixtures {
    /** Reads fixtures/<name>.json from the classpath; throws with a clear message if missing. */
    fun json(name: String): String =
        requireNotNull(javaClass.classLoader.getResourceAsStream("fixtures/$name.json")) {
            "Missing fixture: fixtures/$name.json"
        }.bufferedReader().use { it.readText() }

    fun ok(name: String, code: Int = 200): MockResponse =
        MockResponse().setResponseCode(code)
            .setHeader("Content-Type", "application/json")
            .setBody(json(name))

    fun error(detail: String, code: Int): MockResponse =
        MockResponse().setResponseCode(code)
            .setHeader("Content-Type", "application/json")
            .setBody("""{"detail":$detail}""")

    fun timeout(): MockResponse = MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE)
    fun malformed(): MockResponse = MockResponse().setResponseCode(200).setBody("{not json")
}
```

The routing dispatcher models auth state and CSRF/cookies:

```kotlin
class AuthFlowDispatcher(
    private val csrfToken: String = "csrf-test-token",
    private val requireCsrfOnMutations: Boolean = true,
) : Dispatcher() {
    override fun dispatch(req: RecordedRequest): MockResponse {
        val path = req.requestUrl?.encodedPath.orEmpty()
        if (requireCsrfOnMutations && req.method != "GET" &&
            req.getHeader("X-CSRF-Token") != csrfToken && path != "/ui/session/start"
        ) return Fixtures.error("\"csrf_failed\"", 403)

        return when (path to req.method) {
            "/ui/session/start" to "POST" -> Fixtures.ok("session_start_mfa_required")
                .addHeader("Set-Cookie", "tl_session=sess-1; Path=/; HttpOnly")
                .addHeader("Set-Cookie", "ui_csrf=$csrfToken; Path=/")
            "/ui/mfa/totp/begin" to "POST" -> Fixtures.ok("mfa_totp_begin")
            "/ui/mfa/totp/verify" to "POST" -> Fixtures.ok("mfa_totp_verify_ok")
            "/ui/session/finalize" to "POST" -> Fixtures.ok("session_finalize_ok")
            "/ui/session/refresh" to "POST" -> Fixtures.ok("session_refresh_ok")
                .addHeader("Set-Cookie", "ui_csrf=$csrfToken; Path=/")
            "/ui/me" to "GET" -> Fixtures.ok("me")
            else -> Fixtures.error("\"not_found\"", 404)
        }
    }
}
```

An `InMemoryCookieJar` (simple `MutableMap<String, List<Cookie>>` keyed by host) is provided so cookie-roundtrip tests don't require the production persistent jar; the persistent `SharedPrefsCookieJar` is owned by the auth/session tickets and validated separately.

A `JsonSubject`/`assertJsonEquals(expected, actual)` helper performs order-insensitive structural JSON comparison (parse both via Moshi to `Map<String, Any?>`) for `RecordedRequest` body assertions.

## 5. API Contract

This ticket defines no new production endpoints; it *mirrors* the backend contract. The fixtures encode the authoritative shapes the harness serves. Captured fixtures (`fixtures/*.json`):

`session_start_mfa_required.json` (response to `POST /ui/session/start` with body `{"challenge_context":{"username":"...","password":"..."}}`):
```json
{
  "auth_required": true,
  "challenge_id": "chal_01HZX...",
  "required_factors": ["totp"]
}
```

`mfa_totp_begin.json` (`POST /ui/mfa/totp/begin` body `{"challenge_id":"chal_..."}`):
```json
{ "challenge_id": "chal_01HZX...", "factor": "totp", "expires_at": "2026-06-05T12:00:00Z" }
```

`mfa_totp_verify_ok.json` (`POST /ui/mfa/totp/verify` body `{"challenge_id":"chal_...","code":"123456"}`):
```json
{ "verified": true, "remaining_factors": [] }
```

`session_finalize_ok.json` (`POST /ui/session/finalize`):
```json
{ "session_active": true, "user_id": "usr_42" }
```

`me.json` (`GET /ui/me`):
```json
{ "user_id": "usr_42", "username": "demo", "display_name": "Demo User", "mfa_enabled": true }
```

`session_refresh_ok.json` (`POST /ui/session/refresh`): `{ "refreshed": true }`.

Error envelope fixtures cover all three `detail` variants:
`error_detail_string.json` → `{"detail":"invalid_credentials"}`;
`error_detail_list.json` → `{"detail":[{"loc":["body","password"],"msg":"field required","type":"value_error.missing"}]}`;
`error_detail_object.json` → `{"detail":{"code":"mfa_locked","retry_after":30}}`.

Exact field names/types must be reconciled against `frontend/src/api/types.ts` and a live capture before merge (see Open Questions).

## 6. Data & State Management

No persistent app state. The harness manages transient test state only:

- **Server lifecycle** owned by `MockBackendRule` (one `MockWebServer` per test, ephemeral port).
- **Cookie state** held in `InMemoryCookieJar` for the duration of a test; reset by constructing a fresh jar per `defaultTestClient()` call.
- **Dispatcher state** (e.g., refresh-once semantics) kept in the `Dispatcher` instance and recreated per test.

Fixtures are static resources, immutable at runtime. A `FixturesIndex` constant object enumerates known fixture names as typed references to prevent stringly-typed drift:

```kotlin
object FixtureName {
    const val SESSION_START_MFA = "session_start_mfa_required"
    const val ME = "me"
    // ...
}
```

`StateFlow<UiState>` / `ApiResult<T>` belong to production code; here they appear only as assertion targets in example tests, not as harness state.

## 7. Error Handling & Resilience

The harness's primary purpose is exercising error paths, so it must *produce* faults reliably:

- **Timeouts:** `Fixtures.timeout()` uses `SocketPolicy.NO_RESPONSE`; with the 2s test `readTimeout` this surfaces as `SocketTimeoutException`, letting repository tests assert `ApiResult.Error` mapping. A separate `delayed(name, ms)` helper uses `setBodyDelay` for slow-but-eventual responses.
- **5xx / dev-host flakiness:** `Fixtures.error(detail, 503)` models the unreliable dev backend; combined with `server.enqueue(...)` sequencing, tests verify the production bounded-backoff retry for idempotent GETs (one failure then success).
- **Malformed JSON:** `Fixtures.malformed()` validates the Moshi/converter error path maps to a parse `ApiResult.Error`, not a crash.
- **401 refresh cycle:** the dispatcher (or an enqueue sequence) returns `401` then expects `POST /ui/session/refresh`, then serves the retried request; a helper `RefreshOnceDispatcher` returns `401` exactly once per protected path so tests can assert single-refresh behavior and CSRF cookie re-echo.
- **Harness robustness:** `Fixtures.json` fails loudly on missing files; `takeRequest` uses a bounded 5s wait and fails the test rather than hanging if an expected request never arrives. `server.shutdown()` runs in a `finally` block to avoid port leakage across tests.

## 8. Security & Privacy

- **No real credentials or PII.** Captured fixtures must be scrubbed: usernames/display names replaced with `demo`/`Demo User`, all `challenge_id`/`user_id`/token values replaced with stable synthetic placeholders, and any real `Set-Cookie` values replaced with `sess-1` / `csrf-test-token`. A capture script step strips `Authorization`, real cookies, and email/phone before committing.
- The harness binds `MockWebServer` to localhost on an ephemeral port; it never contacts the network and never embeds the dev host URL.
- CSRF enforcement is *modeled* (the dispatcher rejects mutations lacking `X-CSRF-Token`), giving security regression coverage for the production client without exposing secrets.
- No fixture may contain a valid TOTP secret, password, or session token from a real account; CI fixture validation includes a regex guard against committed secret-like patterns.

## 9. Accessibility & i18n

N/A for runtime UI — this is test infrastructure with no user-facing surface. Accessibility and i18n are owned by the feature UI tickets (e.g., AND-016/AND-017 login/MFA screens). Where i18n intersects testing, fixtures use locale-neutral, machine-readable fields (ISO-8601 timestamps, stable error `code` values), so downstream string-localization tests can map codes to resources without depending on backend-localized text.

## 10. Telemetry & Logging

No production telemetry. For test diagnostics the harness:

- Optionally installs OkHttp's `HttpLoggingInterceptor` at `BODY` level via `defaultTestClient(log = true)`, gated off by default to keep CI logs clean.
- Provides `MockBackendRule.dumpRequests()` that prints recorded request path/method/body on assertion failure to speed debugging.
- On `takeRequest` timeout, emits a descriptive failure naming the expected vs. received request sequence.

Analytics events are owned by the production telemetry ticket and are out of scope here.

## 11. Testing Strategy

This module *is* test code, so the deliverable includes self-tests proving the harness works:

- **`MockBackendRuleTest`** — start/stop lifecycle, `baseUrl` reachability, `enqueue`/`takeRequest` round-trip, port released after shutdown.
- **`FixturesTest`** — `Fixtures.json` loads each named fixture; missing fixture throws with clear message.
- **`AuthFlowDispatcherTest`** — drives a real Retrofit interface (built via `retrofit(moshi)`) through `start → totp begin/verify → finalize → me`, asserting each fixture deserializes into its `core-model` type and that cookies/CSRF are echoed.
- **`ErrorInjectionTest`** — timeout → `SocketTimeoutException`; `503` then `200` retry sequence; malformed JSON → parse error; each `detail` variant parses into the error mapper's model.
- **`RefreshCycleTest`** — `401` once → `/ui/session/refresh` observed → retried request succeeds; assert exactly one refresh.
- **`FixtureValidationTest`** — parameterized over every fixture: each parses into its declared `core-model` type with no unknown-field loss (Moshi `failOnUnknown` in strict mode) and contains no secret-like patterns.

Run on JVM unit test source set (no device needed). Targets: 100% of harness public API covered; all six error modes from §7 exercised.

## 12. Dependencies & Sequencing

- **Depends on AND-010** (Retrofit + Moshi setup) — the harness reuses the production `Moshi` instance and `MoshiConverterFactory` config; without it the `retrofit()` helper and fixture-validation tests cannot bind production deserialization.
- **Transitively benefits from AND-009/AND-006** (via AND-010) for the OkHttp/build configuration baseline.
- **Blocks** the auth/session and repository test work: AND-013–AND-018 (and any ViewModel test using `core-network`) consume this harness. Those tickets should not author bespoke MockWebServer setup; they import `core-testing`.
- New Gradle deps in `core-testing/build.gradle.kts`: `com.squareup.okhttp3:mockwebserver:4.12.0` (as `api`), plus `junit:junit`, `com.google.truth:truth`, `org.jetbrains.kotlinx:kotlinx-coroutines-test`, exposed as `api` so dependents inherit them. `core-testing` adds `implementation(project(":core-model"))` and `implementation(project(":core-network"))`.

## 13. Risks & Open Questions

- **Fixture drift vs. live backend:** the dev host is unreliable and may change shapes. Mitigation: `FixtureValidationTest` parses against `core-model`, and a documented re-capture script keeps fixtures current. Risk that captures are taken from a stale deploy — pin capture date in a `fixtures/CAPTURED.md`.
- **Exact auth field names unconfirmed:** the JSON in §5 is reconstructed from the project context and web reference; the real `/ui/session/start` and `/ui/me` payloads must be confirmed by a live capture and against `frontend/src/api/types.ts` before merge. **Open question:** does `required_factors` ever include `sms`/`email` simultaneously, and does `/ui/session/finalize` return the full user object or just a flag?
- **MockWebServer cookie handling:** `MockWebServer` does not implement a cookie store; cookie semantics are validated via the client's `CookieJar`, so the harness can only assert `Set-Cookie` emission and header echo, not server-side cookie persistence. Acceptable for client tests.
- **Open question:** should the persistent `SharedPrefsCookieJar` get its own Robolectric-backed test fixture here, or in the auth ticket? Current plan: auth ticket owns it; harness provides only `InMemoryCookieJar`.

## 14. Acceptance Criteria

AC-1. `core-testing` exposes `MockBackendRule` (JUnit4 `TestRule`) that starts/stops `MockWebServer` per test and provides `baseUrl`, `enqueue`, and `takeRequest`. *(Verified by `MockBackendRuleTest`.)*

AC-2. A `retrofit(moshi)` helper builds Retrofit against the mock server using AND-010's production converter config, and a sample typed endpoint round-trips a fixture into a `core-model` type in a unit test.

AC-3. `Fixtures` loads named JSON from `fixtures/**`, and helpers exist for success, error (all three `detail` variants), timeout, and malformed responses.

AC-4. `AuthFlowDispatcher` serves the full `start → totp → finalize → me` sequence from captured fixtures, echoing session + `ui_csrf` cookies and rejecting CSRF-missing mutations. *(Verified by `AuthFlowDispatcherTest`.)*

AC-5. Error injection produces real timeouts (`SocketTimeoutException`), `5xx`-then-success retry sequences, malformed-JSON parse errors, and a single `401 → refresh → retry` cycle. *(Verified by `ErrorInjectionTest`, `RefreshCycleTest`.)*

AC-6. Captured fixtures match live wire shapes: every fixture parses into its declared `core-model` type with no field loss, and contains no real PII/secrets. *(Verified by `FixtureValidationTest`.)*

AC-7. `RecordedRequest` assertion helper verifies path, method, headers, and order-insensitive JSON body equality.

AC-8. The harness is reusable: a downstream module can add a hermetic networking test using only `testImplementation(project(":core-testing"))` with no bespoke MockWebServer wiring.

## 15. Definition of Done

- All §14 acceptance criteria pass in CI on the JVM unit-test source set; harness public API has self-tests and full coverage.
- `com.testlogon.android.core.testing.net` classes (`MockBackendRule`, `Fixtures`, `AuthFlowDispatcher`/`RefreshOnceDispatcher`, `InMemoryCookieJar`, `FixtureName`, JSON assertion helpers) merged to branch `android-port` under `android/core-testing/`.
- Fixtures committed under `core-testing/src/main/resources/fixtures/` with a `CAPTURED.md` noting source backend, date, and the scrub procedure; a re-capture script is documented.
- `mockwebserver` and test deps declared as `api` in `core-testing/build.gradle.kts`; module depends only on `core-model`/`core-network` (no `app`/`feature-*`).
- Fixtures reconciled against `frontend/src/api/types.ts` and a live `/ui/...` capture; open questions in §13 resolved or explicitly deferred with owning ticket noted.
- Lint/Detekt clean; no committed secrets (CI guard passes); PR reviewed and approved.
