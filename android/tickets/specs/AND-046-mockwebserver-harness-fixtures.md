---
id: AND-046
title: MockWebServer harness + fixtures
milestone: M1
epic: E07
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- **Backend reference:** FastAPI + DynamoDB. Auth uses a server-set session cookie plus a `ui_csrf` cookie whose value the client echoes in the `X-CSRF-Token` header. **Correction (verified):** per `src/api/client.ts`, the web client reads the `ui_csrf` cookie and sets `X-CSRF-Token` on **every** request (GET included), not only mutations; it *additionally* sends an `Authorization: Bearer <accessToken>` header when an access token is present in the auth store, and an `X-IMPERSONATION-TOKEN` when impersonating — so auth is cookie-based **plus** an optional bearer token, not purely cookie-based. OpenAPI is at `/openapi.json`. The validation error envelope (HTTP 422) is `HTTPValidationError = {detail: [{loc, msg, type}]}` (verified: `components.schemas.HTTPValidationError` / `ValidationError`); the client's `normalizeErrorDetail` also tolerates `detail` as a plain `string` and as an object `{code, ...}` (e.g. `role_required`, `geo_blocked`), so the three `detail` variants the harness models are real client-handled shapes.
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
            // NOTE (corrected): there is NO `/ui/mfa/totp/begin` endpoint — TOTP is an
            // offline authenticator, so the login flow posts the code straight to
            // `/ui/mfa/totp/verify`. Only SMS (`/ui/mfa/sms/begin`) and email
            // (`/ui/mfa/email/begin`) have a "begin" step (each returns `ChallengeResp`).
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

`session_start_mfa_required.json` (response to `POST /ui/session/start`, req schema `UiSessionStartReq = {challenge_context?: object}`; the web client posts `{"challenge_context":{...}}`). **Corrected** to match `UiSessionStartResp` (verified schema fields: `auth_required` (required), `challenge_id?`, `required_factors[]`, `session_id?`):
```json
{
  "auth_required": true,
  "challenge_id": "chal_01HZX...",
  "required_factors": ["totp"],
  "session_id": null
}
```

> Removed `mfa_totp_begin.json`: **corrected** — no `/ui/mfa/totp/begin` endpoint exists (TOTP is offline; verify is posted directly). If a begin step is needed for the SMS/email factors, model `/ui/mfa/sms/begin` or `/ui/mfa/email/begin`, each returning `ChallengeResp = {challenge_id, sent_to?: string[]}` (verified: `src/api/types.ts: ChallengeResp`).

`mfa_totp_verify_ok.json` (`POST /ui/mfa/totp/verify`, req schema `TotpVerifyReq = {challenge_id, totp_code}` — **corrected**: the field is `totp_code`, not `code`). Response **corrected** to `MfaVerifyResp` (verified `src/api/types.ts: MfaVerifyResp`):
```json
{ "status": "ok", "session_id": "sess-1", "required_factors": ["totp"], "passed": { "totp": true }, "remaining_factors": [] }
```

`session_finalize_ok.json` (`POST /ui/session/finalize`, req schema `UiSessionFinalizeReq = {challenge_id, remember_device?: boolean}`). Response **corrected** to `SessionFinalizeResp` (verified `src/api/types.ts: SessionFinalizeResp`):
```json
{ "status": "ok", "session_id": "sess-1", "required_factors": [], "passed": { "totp": true } }
```

`me.json` (`GET /ui/me`) — **corrected**: `MeResp` is `{user_sub, session_id, ip}` (verified `src/api/types.ts: MeResp`), NOT `{user_id, username, display_name, mfa_enabled}`:
```json
{ "user_sub": "usr_42", "session_id": "sess-1", "ip": "203.0.113.7" }
```

`session_refresh_ok.json` (`POST /ui/session/refresh`) — **corrected**: the web client types this as `StatusResp = {status}` (verified `src/api/endpoints/auth.ts: refreshSession` → `StatusResp`; OpenAPI lists resp `200:` with no schema, so the body is best treated as opaque/`StatusResp`-shaped): `{ "status": "ok" }`.

Error envelope fixtures cover all three `detail` variants:
`error_detail_string.json` → `{"detail":"invalid_credentials"}`;
`error_detail_list.json` → `{"detail":[{"loc":["body","password"],"msg":"field required","type":"value_error.missing"}]}`;
`error_detail_object.json` → `{"detail":{"code":"mfa_locked","retry_after":30}}`.

The success-response field names/types above have now been reconciled against the backend OpenAPI (`components.schemas.UiSessionStartResp`, `UiSessionFinalizeReq`, `TotpVerifyReq`, `HTTPValidationError`) and `src/api/types.ts` (`SessionStartResp`, `SessionFinalizeResp`, `MeResp`, `MfaVerifyResp`, `StatusResp`, `ChallengeResp`); see §16 for the per-claim audit. The placeholder *values* (synthetic ids, timestamps) still require a live capture to confirm formats, but the *shapes* are verified.

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
- **401 refresh cycle:** the dispatcher (or an enqueue sequence) returns `401` then expects `POST /ui/session/refresh`, then serves the retried request; a helper `RefreshOnceDispatcher` returns `401` exactly once per protected path so tests can assert single-refresh behavior and CSRF cookie re-echo. **Verified-behavior caveats** (from `src/api/client.ts`): (1) the web client refreshes on `401` **only if the user was already authenticated** — an *unauthenticated* `401` (e.g. wrong password at `/ui/session/start`) propagates straight to the caller with **no** refresh attempt; the production-mirroring Android client must replicate this, and the harness must cover both branches. (2) The web client de-dupes concurrent refreshes via a single shared `refreshPromise`. (3) On retry the web client **re-uses the original request headers object**, so it does *not* re-read a freshly rotated `ui_csrf` cookie for the retried call — if the Android client instead re-derives CSRF from the cookie jar (recommended), that is a deliberate divergence to assert, not a faithful mirror. (4) A failed refresh triggers `logout("session_expired")`.
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
- **Exact auth field names — now confirmed (was unconfirmed):** the §5 shapes have been reconciled against OpenAPI and `src/api/types.ts` (see §16). Resolved corrections: `/ui/me` returns `{user_sub, session_id, ip}` (not a username/display-name object); `/ui/session/finalize` returns a `SessionFinalizeResp` *status object* `{status, session_id?, required_factors, passed}` (answering the old open question — it returns a status/flags object, **not** the full user object); `required_factors` is a free `string[]` and the schema does not constrain it, so it *can* in principle carry multiple factors (e.g. `["totp","sms"]`) — exact backend policy on simultaneous factors remains a backend-behavior question, but the harness should not assume single-element arrays. The `mfa_totp_begin` endpoint was removed (does not exist). The placeholder *values* still need a live capture; the *shapes* are verified.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **`POST /ui/session/start` exists, takes `UiSessionStartReq`, returns `UiSessionStartResp`.** VERIFIED. OpenAPI `POST /ui/session/start` (`op=ui_session_start`, `req=UiSessionStartReq`, `resp=200:UiSessionStartResp`); `src/api/endpoints/auth.ts: sessionStart`.
2. **`UiSessionStartReq` body is `{challenge_context?: object}`.** VERIFIED. OpenAPI `components.schemas.UiSessionStartReq` (single optional `challenge_context`, `additionalProperties: true`); `src/api/types.ts: SessionStartReq`.
3. **`session_start` response shape = `{auth_required, challenge_id?, required_factors[], session_id?}`.** CORRECTED (spec omitted `session_id`). OpenAPI `components.schemas.UiSessionStartResp` (only `auth_required` required); `src/api/types.ts: SessionStartResp`.
4. **`/ui/mfa/totp/begin` is part of the login flow.** CORRECTED — endpoint does not exist; removed from the dispatcher and §5 fixtures. OpenAPI has no `ui/mfa/totp/begin`; TOTP login goes straight to `POST /ui/mfa/totp/verify` (`op=ui_totp_verify`). Confirmed by `src/api/endpoints/auth.ts: verifyTotp` (posts directly to `/ui/mfa/totp/verify`). Only `POST /ui/mfa/sms/begin` and `POST /ui/mfa/email/begin` have a begin step.
5. **TOTP verify request body field is `code`.** CORRECTED to `totp_code`. OpenAPI `components.schemas.TotpVerifyReq = {challenge_id, totp_code}` (both required); `src/api/types.ts: TotpVerifyReq`.
6. **MFA-verify success response = `{verified, remaining_factors}`.** CORRECTED to `MfaVerifyResp = {status, session_id?, required_factors, passed, remaining_factors}`. Source: `src/api/types.ts: MfaVerifyResp` (web types `verifyTotp/verifySms/verifyEmail` → `MfaVerifyResp`). OpenAPI lists `resp=200:` with no inline schema, so the TS type is authoritative.
7. **`POST /ui/session/finalize` takes `UiSessionFinalizeReq` and returns `{session_active, user_id}`.** CORRECTED — request verified as `UiSessionFinalizeReq = {challenge_id, remember_device?}` (OpenAPI `components.schemas.UiSessionFinalizeReq`); response corrected to `SessionFinalizeResp = {status, session_id?, required_factors, passed}` (`src/api/types.ts: SessionFinalizeResp`). OpenAPI `resp=200:` has no inline schema → TS type authoritative.
8. **`GET /ui/me` returns `{user_id, username, display_name, mfa_enabled}`.** CORRECTED to `MeResp = {user_sub, session_id, ip}`. Source: `src/api/types.ts: MeResp` and `src/api/endpoints/auth.ts: getMe`. OpenAPI `GET /ui/me` (`op=ui_me`) lists `resp=200:` with no inline schema → TS type authoritative.
9. **`POST /ui/session/refresh` returns `{refreshed: true}`.** CORRECTED to a `StatusResp = {status}` shape. Source: `src/api/endpoints/auth.ts: refreshSession` → `StatusResp`; OpenAPI `POST /ui/session/refresh` (`op=ui_session_refresh`, empty req, `resp=200:` no schema). Body is effectively opaque; treat as `StatusResp`.
10. **Auth is purely cookie-based; `ui_csrf` echoed as `X-CSRF-Token`.** CORRECTED/REFINED. `src/api/client.ts` reads cookie `ui_csrf` and sets `X-CSRF-Token` on **every** request (not just mutations), AND additionally sets `Authorization: Bearer <accessToken>` when present plus `X-IMPERSONATION-TOKEN` when impersonating. So: cookie session + CSRF header + optional bearer token. Cookie name `ui_csrf` and header `X-CSRF-Token` VERIFIED (`src/api/client.ts:168-170`, `src/stores/offlineStore.ts`, `src/api/endpoints/profile.ts`, `kycCompliance.ts`).
11. **Error envelope `detail` may be `string | [{msg,...}] | {code,...}`.** VERIFIED. 422 shape is `HTTPValidationError = {detail: [{loc, msg, type}]}` (OpenAPI `components.schemas.HTTPValidationError` + `ValidationError`). The `string` and `{code,...}` variants are handled by `src/api/client.ts: normalizeErrorDetail` / `mapAuthorizationError` (codes e.g. `role_required`, `geo_blocked`).
12. **401 → refresh → retry cycle.** VERIFIED, with refinements. `src/api/client.ts:194-237`: refresh attempted **only if already authenticated**; unauthenticated 401 propagates without refresh; concurrent refreshes de-duped via shared `refreshPromise`; retry re-uses the original headers object; failed refresh → `logout("session_expired")`.
13. **403 CSRF-failure response modeled as `{"detail":"csrf_failed"}` with status 403.** UNVERIFIED-ASSUMPTION. The CSRF *mechanism* (cookie → header) is verified, but the exact backend rejection status/body for a missing/invalid CSRF token is not exposed in OpenAPI or the frontend. Reasonable model; flag for live-capture confirmation.
14. **Session cookie name `tl_session`.** UNVERIFIED-ASSUMPTION. The web client uses `credentials: "include"` and never references a session-cookie name; only `ui_csrf` is named in source. The harness only needs *a* `Set-Cookie`, so the exact name is non-load-bearing, but do not assert `tl_session` against the live backend without a capture.
15. **422 `type` value `value_error.missing` (in `error_detail_list.json`).** CORRECTED/FLAGGED. The envelope shape `{loc, msg, type}` is verified, but `value_error.missing` is Pydantic v1 wording; FastAPI on Pydantic v2 emits `type: "missing"`. Use `"missing"` (or confirm via live capture). Source: OpenAPI `ValidationError`.
16. **MockWebServer (`com.squareup.okhttp3:mockwebserver:4.12.0`) provides `Dispatcher`, `MockResponse`, `RecordedRequest`, `SocketPolicy`, `setBodyDelay`.** VERIFIED (framework ref): OkHttp MockWebServer 4.12 API — https://square.github.io/okhttp/4.x/okhttp/okhttp3/-handshake/ and https://github.com/square/okhttp/tree/master/mockwebserver . Note (framework ref): in MockWebServer 4.x, `MockResponse` is mutable-builder style (`setResponseCode`/`setBody`/`setSocketPolicy`) as the spec uses; the newer 5.x API renames to `MockResponse.Builder` — keep on 4.12 to match the code samples, consistent with OkHttp 4.12 in §2.
17. **JUnit4 `TestRule`/`Statement`/`Description` contract used by `MockBackendRule`.** VERIFIED (framework ref): JUnit4 rules — https://junit.org/junit4/javadoc/latest/org/junit/rules/TestRule.html .
18. **Harness lives in `src/main` (not `src/test`) so it is visible to `testImplementation` dependents.** VERIFIED (framework ref): Android/Gradle test-fixtures visibility — a `testImplementation`-consumed library exposes only its `main` source set; https://developer.android.com/studio/test/advanced-test-setup and Gradle test-fixtures docs https://docs.gradle.org/current/userguide/java_testing.html#sec:java_test_fixtures . (Alternatively `java-test-fixtures`; the spec's `main` approach is valid.)

### Corrections made

- **§5 `me.json`**: `{user_id, username, display_name, mfa_enabled}` → `MeResp = {user_sub, session_id, ip}`.
- **§5 `session_finalize_ok.json`**: `{session_active, user_id}` → `SessionFinalizeResp = {status, session_id?, required_factors, passed}`.
- **§5 `mfa_totp_verify_ok.json`**: `{verified, remaining_factors}` → `MfaVerifyResp = {status, session_id?, required_factors, passed, remaining_factors}`; verify request field `code` → `totp_code`.
- **§5 `session_refresh_ok.json`**: `{refreshed:true}` → `StatusResp` shape `{status:"ok"}`.
- **§5 `session_start_mfa_required.json`**: added nullable `session_id` to match `UiSessionStartResp`.
- **§4 dispatcher + §5**: removed the non-existent `/ui/mfa/totp/begin` route/fixture; documented that only SMS/email have a begin step (`ChallengeResp`).
- **§2**: refined "purely cookie-based" to cookie session + CSRF header + optional bearer; documented that the web client sends `X-CSRF-Token` on all requests; pinned the 422 envelope as `HTTPValidationError`.
- **§7**: added verified 401-refresh caveats (auth-gated refresh, shared-promise de-dupe, header re-use on retry, logout-on-failure).
- **§13**: marked the "auth field names unconfirmed" open question as resolved with the verified shapes; answered the finalize-payload question (status object, not full user).

### Open assumptions

- **CSRF-failure status/body** (`403 {"detail":"csrf_failed"}`): not exposed by OpenAPI or frontend; assumed for modeling. Confirm via live capture.
- **Session cookie name** (`tl_session`): not named anywhere in the frontend; assumed. Non-load-bearing for harness tests.
- **Synthetic placeholder value formats** (e.g. `chal_01HZX...` ULID-style ids, ISO-8601 timestamps, `usr_42`/`sess-1`): shapes verified, exact value formats require a live capture (`fixtures/CAPTURED.md`).
- **Backend retry/idempotency policy** for GET 5xx and **whether `required_factors` can contain multiple simultaneous factors**: not constrained by the schema (`required_factors` is a free `string[]`); harness should not assume single-element arrays, but exact backend behavior needs backend docs/capture.
- **MFA-verify / finalize / refresh / me response bodies**: OpenAPI declares these `resp=200:` with no inline schema; the field shapes are taken from `src/api/types.ts`, which is the web client's contract but may lag the live backend — re-confirm on capture.

## 17. Test Plan

All cases run on the **JVM unit-test source set (JVM unit/Robolectric — local, no device)** unless noted. This is a `core-testing` chore that ships only JVM test infrastructure: there is no production UI, no Android-hardware behavior, and no on-device surface, so **no case requires the emulator AVD `test35` or the physical Galaxy A15 (SM-A156U)**. That hardware is reserved for the downstream feature tickets (login/MFA Compose screens, biometrics, camera/KYC, FCM, WebRTC) that *consume* this harness; an explicit "not applicable here" note is recorded in the coverage discussion and in TC-AND-046-12. A few cases use **Robolectric** only because `InMemoryCookieJar`/resource loading may touch Android stubs when run from an `androidTest`-consuming module; they remain CI-local.

- **TC-AND-046-01** — Type: unit. Target: `MockBackendRule` (JVM unit). Preconditions: none. Steps: instantiate `MockBackendRule`, run a trivial test body via the rule, capture `baseUrl`, then let the rule complete. Expected: `server` starts on an ephemeral loopback port before the body, `baseUrl` is a reachable `http://127.0.0.1:<port>/` `HttpUrl`, and `server.shutdown()` runs in `finally` (port released — a second rule can bind a new port). Traces: AC-1.
- **TC-AND-046-02** — Type: unit. Target: `MockBackendRule.enqueue`/`takeRequest` (JVM unit). Preconditions: rule started. Steps: `enqueue(Fixtures.ok("me"))`; issue a `GET /ui/me` via an OkHttp call; `takeRequest()`. Expected: response body is the `me` fixture; `RecordedRequest` reports path `/ui/me`, method `GET`; `takeRequest` honors the bounded 5s wait. Traces: AC-1.
- **TC-AND-046-03** — Type: contract/MockWebServer. Target: `retrofit(moshi)` + a typed endpoint using AND-010's production `Moshi`/`MoshiConverterFactory` (JVM unit). Preconditions: rule started; production Moshi available. Steps: build Retrofit via `retrofit(moshi)`; enqueue `me` fixture; call typed `getMe()`. Expected: response deserializes into the `core-model` `MeResp`-equivalent type with fields `user_sub`, `session_id`, `ip` populated and **no field loss**; converter config matches production. Traces: AC-2, AC-6.
- **TC-AND-046-04** — Type: unit. Target: `Fixtures.json` loader (JVM unit). Preconditions: fixtures present on classpath. Steps: load each known `FixtureName` (`session_start_mfa_required`, `mfa_totp_verify_ok`, `session_finalize_ok`, `me`, `session_refresh_ok`, error variants); then request a missing fixture. Expected: each known fixture loads non-empty; missing fixture throws `IllegalArgumentException` with message `Missing fixture: fixtures/<name>.json`. Traces: AC-3.
- **TC-AND-046-05** — Type: contract/MockWebServer. Target: `AuthFlowDispatcher` happy path (JVM unit). Preconditions: rule started with `AuthFlowDispatcher`; client uses `InMemoryCookieJar`. Steps: drive the real typed sequence `POST /ui/session/start` → `POST /ui/mfa/totp/verify` → `POST /ui/session/finalize` → `GET /ui/me`. Expected: `start` sets `Set-Cookie` for the session and `ui_csrf=<token>` and returns `auth_required:true, required_factors:["totp"]`; subsequent mutations carry `X-CSRF-Token: <token>` (read from the cookie jar); each response deserializes into its corrected `core-model` type; `verify` returns `MfaVerifyResp` with `totp` in `passed`; `finalize` returns `SessionFinalizeResp{status:"ok"}`; `me` returns `MeResp`. Confirms NO `/ui/mfa/totp/begin` call is made. Traces: AC-4, AC-6.
- **TC-AND-046-06** — Type: contract/MockWebServer (security). Target: `AuthFlowDispatcher` CSRF enforcement (JVM unit). Preconditions: rule + dispatcher with `requireCsrfOnMutations=true`. Steps: issue a mutating `POST` (e.g. `/ui/session/finalize`) WITHOUT the `X-CSRF-Token` header. Expected: dispatcher responds `403` with `{"detail":"csrf_failed"}` (modeled — see §16 open assumption); a GET without CSRF is allowed; with the correct token the mutation succeeds. Traces: AC-4.
- **TC-AND-046-07** — Type: unit (security). Target: TOTP verify request contract (JVM unit). Preconditions: rule + dispatcher. Steps: call the typed `verifyTotp` and `takeRequest()`. Expected: request body JSON has keys `challenge_id` and **`totp_code`** (not `code`), validated by order-insensitive structural compare against an expected fixture; wrong field name would fail. Traces: AC-7, AC-6.
- **TC-AND-046-08** — Type: contract/MockWebServer (error). Target: `Fixtures.error` all three `detail` variants (JVM unit). Preconditions: rule started. Steps: enqueue `error_detail_string.json` (`{"detail":"invalid_credentials"}`, 401), `error_detail_list.json` (422 `HTTPValidationError`, `type:"missing"`), and `error_detail_object.json` (`{"detail":{"code":"mfa_locked","retry_after":30}}`, 423/403); call the endpoint for each. Expected: each parses into the production error mapper's model and `normalizeErrorDetail`-equivalent logic resolves a human message (string passthrough; list joins `msg`s; object maps `code`); maps to `ApiResult.Error`, never a crash. Traces: AC-3, AC-6.
- **TC-AND-046-09** — Type: contract/MockWebServer (offline/flaky-dev-host). Target: `Fixtures.timeout()` + `defaultTestClient()` 2s read timeout (JVM unit). Preconditions: rule started. Steps: enqueue `Fixtures.timeout()` (`SocketPolicy.NO_RESPONSE`); call an endpoint. Expected: client throws `SocketTimeoutException` within ~2s; repository mapping yields `ApiResult.Error` (network/timeout class), modeling the unreliable dev host `18.222.237.167:8000`. Also assert `delayed(name, ms)` returns a body after a sub-timeout delay (slow-but-eventual). Traces: AC-5.
- **TC-AND-046-10** — Type: contract/MockWebServer (flaky-dev-host). Target: 5xx-then-success retry for idempotent GET (JVM unit). Preconditions: rule started. Steps: `enqueue(Fixtures.error("\"unavailable\"", 503))` then `enqueue(Fixtures.ok("me"))`; perform a GET that uses the production bounded-backoff retry. Expected: first attempt sees 503, retry succeeds, exactly two requests recorded, final result is parsed `me`. (If retry is owned by the production client, this is asserted at the consuming ticket; harness proves the enqueue sequence works.) Traces: AC-5.
- **TC-AND-046-11** — Type: contract/MockWebServer (error). Target: `Fixtures.malformed()` parse path (JVM unit). Preconditions: rule started. Steps: enqueue malformed body `{not json` with 200; call a typed endpoint. Expected: Moshi/converter raises a parse failure that maps to `ApiResult.Error` (parse class), not an unhandled crash. Traces: AC-5.
- **TC-AND-046-12** — Type: contract/MockWebServer (auth-state branch). Target: `RefreshOnceDispatcher` 401→refresh→retry, mirroring `src/api/client.ts` (JVM unit). Preconditions: rule + `RefreshOnceDispatcher`; cookie jar holds session + `ui_csrf`. Steps: (a) authenticated case — call a protected endpoint; dispatcher returns `401` once, test asserts a `POST /ui/session/refresh` is observed exactly once (shared-promise de-dupe under concurrent calls), then the retried request succeeds and `ui_csrf` re-echo is observed; (b) unauthenticated case — a `401` from `/ui/session/start` (wrong password) propagates with NO refresh attempt. Expected: both branches behave as the verified web-client logic (§16 item 12). Note: this is JVM-local; **no physical device needed** — the device/emulator targets apply only to downstream feature tickets, not to this harness chore. Traces: AC-5.
- **TC-AND-046-13** — Type: unit (FixtureValidationTest, parameterized). Target: every fixture parses into its declared `core-model` type (JVM unit). Preconditions: production Moshi with strict `failOnUnknown`. Steps: for each fixture, parse into its declared type; scan raw bytes against a secret-like-pattern regex. Expected: every fixture parses with no unknown-field loss; NO fixture contains a real password/TOTP secret/session token/email/phone (only synthetic `demo`/`Demo User`/`csrf-test-token`/`sess-1` placeholders). Catches schema drift and committed-secret regressions. Traces: AC-6.
- **TC-AND-046-14** — Type: unit. Target: `RecordedRequest` assertion helper `assertJsonEquals` (JVM unit). Preconditions: none. Steps: compare two JSON bodies with reordered keys (should pass) and bodies with a differing field value/name (should fail with a clear diff); also assert path/method/header (CSRF, cookie) checks. Expected: order-insensitive structural equality (parsed via Moshi to `Map<String,Any?>`), accurate pass/fail. Traces: AC-7.
- **TC-AND-046-15** — Type: integration (consumer smoke). Target: harness reusability from a downstream module (JVM unit, separate Gradle module depending on `testImplementation(project(":core-testing"))`). Preconditions: a throwaway consumer test module. Steps: write a 3-line hermetic test (start rule, enqueue fixture, assert parsed `ApiResult<T>`) importing only `core-testing`, with NO bespoke MockWebServer wiring; confirm `mockwebserver`/Truth/coroutines-test are inherited via `api` exposure. Expected: compiles and passes; no `app`/`feature-*` leakage on the `core-testing` classpath (depends only on `core-model`/`core-network`). Traces: AC-8.

### Coverage matrix

| AC (§14) | Covered by |
|---|---|
| AC-1 (`MockBackendRule` lifecycle/baseUrl/enqueue/takeRequest) | TC-01, TC-02 |
| AC-2 (`retrofit(moshi)` round-trips a fixture into a `core-model` type) | TC-03 |
| AC-3 (`Fixtures` loads named JSON; success/error/timeout/malformed helpers) | TC-04, TC-08, (TC-09 timeout, TC-11 malformed) |
| AC-4 (`AuthFlowDispatcher` full `start→totp→finalize→me`, cookie/CSRF echo, reject CSRF-missing mutations) | TC-05, TC-06 |
| AC-5 (real timeouts, 5xx-then-success retry, malformed parse, single 401→refresh→retry) | TC-09, TC-10, TC-11, TC-12 |
| AC-6 (fixtures match live shapes, parse into `core-model`, no PII/secrets) | TC-03, TC-05, TC-07, TC-08, TC-13 |
| AC-7 (`RecordedRequest` assertion: path/method/headers/JSON body equality) | TC-07, TC-14 |
| AC-8 (reusable via `testImplementation(project(":core-testing"))`, no bespoke wiring) | TC-15 |
