---
id: AND-027
title: AuthApi (session endpoints)
milestone: M1
epic: E04
priority: P0
size: M
status: draft
depends_on: [AND-026]
blocks: [AND-028, AND-029, AND-030]
---

# AND-027 — AuthApi (session endpoints)

## 1. Overview & Goal

This ticket defines the Retrofit service interface `AuthApi` that exposes the
cookie-based session lifecycle of the TestLogon backend to the Android client:
starting a session, finalizing it after MFA, refreshing it on 401, logging out,
fetching the current principal, and listing/revoking sessions. It is the typed
HTTP seam through which the auth feature (`feature-auth`) and the session
repository (`core-data`) drive the entire login flow.

Scope, verbatim from the backlog: *Retrofit `AuthApi`:
`session/start|finalize|refresh|logout`, `me`, `sessions(+revoke)`.* The single
acceptance criterion is that every endpoint is callable and that its
path/verb/body exactly matches the backend contract, proven with `MockWebServer`.

This is a **transport-definition** ticket. It owns the interface declaration, the
`@Headers`/`@HTTP` annotations, the request/response DTO bindings (DTOs themselves
come from AND-026), and the Hilt provider that constructs the service from the
shared Retrofit. It deliberately does **not** own: the persistent cookie jar
(AND-011), the CSRF interceptor that injects `X-CSRF-Token` (AND-012), the
401-refresh `Authenticator` (AND-013), `ApiResult` wrapping (AND-018), the MFA
endpoints (`/ui/mfa/...`, owned by the MFA feature ticket), or any ViewModel/UI.
Those attach to the shared `OkHttpClient` or live in higher layers and take
effect for `AuthApi` calls without changes here.

The deliverable: a compiling `AuthApi`, its Hilt provider, and a `MockWebServer`
test suite asserting each endpoint's HTTP method, resolved path, request body
shape, and successful response decoding.

## 2. Context & References

- **Repo / location:** `spannella/testlogon`, monorepo subfolder `android/`,
  branch `android-port`. Production code lands in module **`core-network`** under
  package `com.testlogon.android.core.network.auth`.
- **Canonical package:** `com.testlogon.android` everywhere.
- **Stack pins relevant here:** Kotlin 2.0.21, Retrofit **2.11.0**, OkHttp
  **4.12.0**, Moshi **1.15.x** (codegen via KSP), Hilt (KSP), Coroutines, JDK 17,
  minSdk 24 / compileSdk 35.
- **Module layering:** `app -> feature-* -> core-*`. `AuthApi` lives in
  `core-network`, consumes DTOs from `core-model` (AND-026), and is consumed by
  `core-data` repositories. No `feature-*`/`app` symbols leak into `core-network`.
- **Upstream dependency — AND-026 (Auth DTOs + adapters):** supplies the Moshi
  `@JsonClass(generateAdapter = true)` DTOs this interface references
  (`SessionStartReq/Resp`, `SessionFinalizeReq/Resp`, `MeResp`, `SessionInfo`,
  `Challenge/Ok/StatusResp`, etc., per Appendix A). This ticket binds those types
  into method signatures; it must not redefine them.
- **Transitive upstream:** AND-010 (Retrofit + Moshi), AND-009 (shared
  `OkHttpClient`), AND-006 (`BuildConfig.API_BASE_URL`). The shared Retrofit's
  base URL for `dev` resolves to `http://18.222.237.167:8000/`.
- **Auth flow (authoritative):** `POST /ui/session/start` with
  `{challenge_context:{username,password}}` →
  `{auth_required, challenge_id, required_factors[]}`; MFA via
  `/ui/mfa/{totp|sms|email}/begin|verify` (separate ticket); `POST
  /ui/session/finalize`; `GET /ui/me`. Session rides on cookies + a `ui_csrf`
  cookie echoed as `X-CSRF-Token`; on 401 the client calls `POST
  /ui/session/refresh` once then retries (Authenticator, AND-013).
- **Backend:** FastAPI + DynamoDB; dev host is plaintext HTTP and unreliable
  (~20s timeouts, bounded backoff for idempotent GETs — owned by AND-009/AND-016).
  OpenAPI at `/openapi.json`. Web reference for shapes:
  `frontend/src/api/endpoints/*.ts`, types `frontend/src/api/types.ts`.

## 3. Functional Requirements

FR-1. Declare a single Retrofit interface `AuthApi` covering exactly these
operations: `sessionStart`, `sessionFinalize`, `sessionRefresh`, `sessionLogout`,
`me`, `listSessions`, `revokeSession`.

FR-2. Each method's HTTP verb and relative path match the backend contract
(Section 5). Paths are declared **without** a leading slash (per AND-010's
no-leading-slash convention) so they append to the normalized base URL.

FR-3. All methods are `suspend` functions returning the typed DTO body (Retrofit
native coroutine support). Methods that return no meaningful body return `Unit`
(Retrofit decodes empty/2xx to `Unit`).

FR-4. Request bodies use `@Body` with the AND-026 request DTOs; path parameters
use `@Path`. No raw `Map`/`JsonObject` bodies.

FR-5. POST methods that send JSON carry `@Headers("Content-Type:
application/json")` (Moshi converter also sets this; explicit header documents
intent and guards against converter changes).

FR-6. The CSRF header (`X-CSRF-Token`) is **not** declared per-method here; it is
injected globally by AND-012's interceptor for mutating verbs. `AuthApi` stays
header-agnostic for CSRF and cookies.

FR-7. A Hilt `@Provides @Singleton fun provideAuthApi(retrofit: Retrofit):
AuthApi` constructs the service from the shared Retrofit (AND-010). No new
Retrofit/OkHttp instance is created.

FR-8. `sessionRefresh` is declared so the AND-013 `Authenticator` can call it
out-of-band; it must be invocable without a request body
(`POST /ui/session/refresh`, no body) and tolerate an empty 200 response.

FR-9. `listSessions` returns the current principal's active sessions;
`revokeSession(sessionId)` revokes one by id (`DELETE`).

## 4. Technical Design

All production code lands in
`core-network/src/main/kotlin/com/testlogon/android/core/network/auth/`.

### 4.1 The `AuthApi` interface

```kotlin
package com.testlogon.android.core.network.auth

import com.testlogon.android.core.model.auth.MeResp
import com.testlogon.android.core.model.auth.OkResp
import com.testlogon.android.core.model.auth.SessionFinalizeReq
import com.testlogon.android.core.model.auth.SessionFinalizeResp
import com.testlogon.android.core.model.auth.SessionInfo
import com.testlogon.android.core.model.auth.SessionStartReq
import com.testlogon.android.core.model.auth.SessionStartResp
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path

interface AuthApi {

    /** Step 1 of login. Returns challenge metadata; never sets a finalized session. */
    @Headers("Content-Type: application/json")
    @POST("ui/session/start")
    suspend fun sessionStart(@Body body: SessionStartReq): SessionStartResp

    /** Step 3 of login (after MFA). Establishes the authenticated session cookies. */
    @Headers("Content-Type: application/json")
    @POST("ui/session/finalize")
    suspend fun sessionFinalize(@Body body: SessionFinalizeReq): SessionFinalizeResp

    /**
     * Refreshes the session. No request body. Called by the 401 Authenticator
     * (AND-013) at most once per failed call, and by the repository proactively.
     */
    @POST("ui/session/refresh")
    suspend fun sessionRefresh(): OkResp

    /** Ends the current session (clears server-side state; cookies cleared by jar). */
    @POST("ui/session/logout")
    suspend fun sessionLogout(): OkResp

    /** Current principal. Idempotent GET; used for auth-gating (AND-025). */
    @GET("ui/me")
    suspend fun me(): MeResp

    /** Active sessions for the current principal. Idempotent GET. */
    @GET("ui/sessions")
    suspend fun listSessions(): List<SessionInfo>

    /** Revoke a single session by id. */
    @DELETE("ui/sessions/{sessionId}")
    suspend fun revokeSession(@Path("sessionId") sessionId: String): OkResp
}
```

Notes:
- DTO types (`SessionStartReq`, `MeResp`, `OkResp`, etc.) are **owned by
  AND-026**. If a referenced type is not yet present, this ticket is blocked.
  `OkResp` is the generic `{ "ok": true }`-style acknowledgement DTO from
  Appendix A; if the backend returns a bare empty body for `refresh`/`logout`,
  the corresponding method type may be `Unit` instead — confirmed against
  `/openapi.json` during implementation (see Q-1).
- `listSessions` returns `List<SessionInfo>`; if the backend wraps it as
  `{ "sessions": [...] }`, a thin `SessionsResp(sessions: List<SessionInfo>)`
  wrapper DTO (AND-026) is used and the method returns that. This is resolved by
  inspecting `/openapi.json` and the web reference before coding (Q-2).

### 4.2 Hilt provider

```kotlin
package com.testlogon.android.core.network.auth.di

import com.testlogon.android.core.network.auth.AuthApi
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AuthApiModule {

    @Provides
    @Singleton
    fun provideAuthApi(retrofit: Retrofit): AuthApi =
        retrofit.create(AuthApi::class.java)
}
```

The injected `Retrofit` is the singleton from AND-010's `NetworkModule`, built on
AND-009's shared `OkHttpClient`. No client/Retrofit is constructed here.

### 4.3 Path & verb conventions

- Relative paths, no leading slash: `@POST("ui/session/start")` resolves against
  base `http://18.222.237.167:8000/` to
  `http://18.222.237.167:8000/ui/session/start`.
- Mutating verbs: `start`, `finalize`, `refresh`, `logout`, `revoke` are
  POST/DELETE — the CSRF interceptor (AND-012) attaches `X-CSRF-Token` to these.
- Idempotent GETs: `me`, `listSessions` — eligible for AND-016 bounded backoff.

### 4.4 Gradle wiring

No new dependencies. `core-network/build.gradle.kts` already has Retrofit, Moshi,
Hilt, and (test) MockWebServer from AND-010. This ticket adds source files only;
it depends on `:core-model` (AND-026 DTOs), which is already an `implementation`
dependency of `core-network`.

## 5. API Contract

Base path (`dev`): `http://18.222.237.167:8000/`. All bodies are JSON.

### POST `ui/session/start`
Request:
```json
{ "challenge_context": { "username": "alice@example.com", "password": "s3cret" } }
```
Response `200`:
```json
{
  "auth_required": true,
  "challenge_id": "chl_01HRX...",
  "required_factors": ["totp"]
}
```

### POST `ui/session/finalize`
Request (challenge id from start, after MFA verify succeeds):
```json
{ "challenge_id": "chl_01HRX..." }
```
Response `200` (session cookies set via `Set-Cookie`; `ui_csrf` cookie included):
```json
{ "ok": true, "user": { "username": "alice@example.com", "roles": ["user"] } }
```
(`SessionFinalizeResp` shape per AND-026 Appendix A.)

### POST `ui/session/refresh`
Request: no body. Mutating verb; carries cookies + `X-CSRF-Token`.
Response `200`:
```json
{ "ok": true }
```

### POST `ui/session/logout`
Request: no body. Response `200`: `{ "ok": true }`. Cookie jar clears session
cookies on success (jar behavior owned by AND-011).

### GET `ui/me`
Response `200`:
```json
{
  "username": "alice@example.com",
  "roles": ["user"],
  "mfa_enrolled": true,
  "session_id": "sess_01HRY..."
}
```
`401` when unauthenticated → triggers AND-013 refresh-then-retry once.

### GET `ui/sessions`
Response `200`:
```json
[
  {
    "session_id": "sess_01HRY...",
    "created_at": "2026-06-05T12:00:00Z",
    "last_seen_at": "2026-06-05T12:30:00Z",
    "user_agent": "TestLogon-Android/1.0 (Pixel 7; Android 14)",
    "ip": "203.0.113.7",
    "current": true
  }
]
```

### DELETE `ui/sessions/{sessionId}`
Path: `ui/sessions/sess_01HRY...`. Response `200`: `{ "ok": true }`.
`404` if the session id is unknown/already revoked.

**Error envelope (all endpoints):** FastAPI `detail` union
(`string | [{msg, type, loc}] | {code, ...}`). Mapping to a typed `ApiError` is
owned by **AND-015**; this ticket lets non-2xx surface as `HttpException` so
AND-015/AND-018 can map it.

## 6. Data & State Management

`AuthApi` is **stateless**; it is a singleton interface proxy with no fields.

- **Session state** lives entirely in cookies, persisted by the cookie jar
  (AND-011). `AuthApi` neither reads nor writes cookies directly — OkHttp's
  `CookieJar` does so transparently on every call.
- **CSRF token** (`ui_csrf` cookie → `X-CSRF-Token` header) is handled by the
  AND-012 interceptor reading the persisted cookie; `AuthApi` is unaware of it.
- **No Room / DataStore** in this ticket. Caching the principal (`MeResp`) or
  sessions list is a `core-data` / repository concern.
- **No `StateFlow`/`UiState`.** ViewModels (auth feature) expose UI state by
  consuming the session repository, which wraps these calls in `ApiResult<T>`
  (AND-018). This interface returns plain DTOs (happy path) and throws on failure.
- **Threading:** suspend methods must be invoked from a coroutine on an IO
  dispatcher (injected at the repository layer). This ticket imposes no dispatcher.
- **Serialization:** request/response (de)serialization uses the AND-026 Moshi
  codegen adapters via the shared converter; unknown JSON keys are ignored and
  absent optional fields fall back to Kotlin defaults (lenient).

## 7. Error Handling & Resilience

Responsibilities here are narrow: declare endpoints so failures propagate cleanly.

- **Non-2xx** surfaces as `retrofit2.HttpException` (carrying the raw error body
  for AND-015 to decode the FastAPI `detail`). `401` on any call is intercepted by
  the AND-013 `Authenticator`, which calls `sessionRefresh()` once and retries the
  original request; only a second `401` propagates.
- **`sessionRefresh` recursion guard:** the Authenticator must not invoke itself
  for the refresh call. AND-013 owns that guard; `AuthApi` simply exposes
  `sessionRefresh()`. A `401` from `refresh` itself is terminal → caller must
  treat the session as expired and route to login (AND-025).
- **Transport failures** (`SocketTimeoutException`, `UnknownHostException`,
  `IOException`) propagate unchanged; the ~20s timeouts and bounded backoff for
  idempotent GETs (`me`, `listSessions`) are owned by AND-009/AND-016 on the
  shared client.
- **Deserialization failures** surface as `JsonDataException` from the converter;
  lenient parsing minimizes these against the evolving dev backend.
- **Logout resilience:** `logout` should be treated as best-effort by callers —
  even if the network call fails, the client clears local session state. That
  policy lives in the repository, not here; `AuthApi.sessionLogout()` simply
  reports success/failure.
- This ticket maps **no** errors itself — that is AND-015 (`ApiError`) and
  AND-018 (`ApiResult`).

## 8. Security & Privacy

- **Credentials in transit:** `sessionStart` sends username/password in the JSON
  body. On `dev` this rides plaintext HTTP (`http://18.222.237.167:8000`) — a
  known dev-only risk permitted by the scoped cleartext config (AND-006);
  `staging`/`prod` are HTTPS-only.
- **No credential logging:** the request body of `sessionStart` (and any cookie /
  `Set-Cookie` / `X-CSRF-Token` headers) must be redacted by AND-009's logging
  interceptor. This ticket adds no logging and must not log bodies. A code-review
  check confirms `sessionStart` bodies never reach logcat in any build.
- **Cookie/CSRF handling** is delegated to AND-011/AND-012; `AuthApi` introduces
  no manual `Cookie`/`Authorization` headers.
- **No token storage:** the auth model is cookie-based; no bearer tokens are held
  by this layer.
- **Session enumeration:** `listSessions`/`revokeSession` operate only on the
  authenticated principal's own sessions (server-enforced); the client passes the
  cookie-scoped identity implicitly.

## 9. Accessibility & i18n

Not applicable — this is a headless transport interface with no UI surface and no
user-facing strings. Accessibility is owned by `core-ui` and the `feature-auth`
screens. Localization of any error text derived from these endpoints is owned by
AND-015 (error mapping) and the consuming feature.

## 10. Telemetry & Logging

- **HTTP logging** is inherited from AND-009's redacting `HttpLoggingInterceptor`
  (debug builds only). No new logging here. The `sessionStart` request body and
  all auth-related headers must be redacted (Section 8).
- **No analytics events** emitted by this layer. Login-success/failure and
  MFA-step events are emitted by the auth feature ViewModels (their own ticket),
  derived from `ApiResult` outcomes — not from `AuthApi` directly.
- **Build-time signal:** KSP must have generated Moshi adapters for every AND-026
  DTO referenced here; a missing adapter fails the build (no reflection fallback,
  per AND-010 policy).

## 11. Testing Strategy

All tests are JVM unit tests in `core-network/src/test/...` using `MockWebServer`
and the production Moshi/Retrofit configuration. One test per endpoint asserts the
**verb, resolved path, request body (where applicable), and decoded response**.

Test harness:
```kotlin
private fun api(server: MockWebServer): AuthApi {
    val moshi = Moshi.Builder().build() // mirrors provideMoshi(): codegen adapters
    val retrofit = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
    return retrofit.create(AuthApi::class.java)
}
```

**T-1 — `sessionStart` contract.**
```kotlin
@Test fun sessionStart_postsContextAndDecodes() = runTest {
    val server = MockWebServer().apply {
        enqueue(MockResponse().setBody(
            """{"auth_required":true,"challenge_id":"chl_1","required_factors":["totp"]}"""))
        start()
    }
    val resp = api(server).sessionStart(
        SessionStartReq(ChallengeContext("alice@example.com", "s3cret")))

    val req = server.takeRequest()
    assertEquals("POST", req.method)
    assertEquals("/ui/session/start", req.path)
    val body = req.body.readUtf8()
    assertTrue(body.contains("\"challenge_context\""))
    assertTrue(body.contains("\"username\":\"alice@example.com\""))
    assertEquals("chl_1", resp.challengeId)
    assertEquals(listOf("totp"), resp.requiredFactors)
    server.shutdown()
}
```

**T-2 — `sessionFinalize`** posts `{challenge_id}` to `/ui/session/finalize`
(verb POST) and decodes `SessionFinalizeResp`.

**T-3 — `sessionRefresh`** issues `POST /ui/session/refresh` with an **empty
body** and tolerates a `200 {"ok":true}` (and, per Q-1, an empty body if the type
is `Unit`).

**T-4 — `sessionLogout`** issues `POST /ui/session/logout`, decodes `OkResp`.

**T-5 — `me`** issues `GET /ui/me` and decodes `MeResp` including snake_case
fields (`mfa_enrolled`, `session_id`) via the AND-026 adapters.

**T-6 — `listSessions`** issues `GET /ui/sessions` and decodes a
`List<SessionInfo>` (or wrapper per Q-2), including timestamp fields.

**T-7 — `revokeSession`** issues `DELETE /ui/sessions/sess_1` (path param
interpolated) and decodes `OkResp`.

**T-8 — error propagation.** A `401` response from `me()` throws
`retrofit2.HttpException` with `code() == 401` (confirms non-2xx is not swallowed,
leaving room for AND-013/AND-015).

**T-9 — Hilt provider.** `@HiltAndroidTest` (or minimal `core-testing` harness)
injects `AuthApi` and asserts it is a non-null singleton built on the shared
Retrofit (same instance on repeated injection).

Coverage target: ≥90% on the new surface (interface binding + provider). Each of
the seven endpoints has at least one path/verb assertion.

## 12. Dependencies & Sequencing

**Hard upstream (must merge first):**
- **AND-026** — Auth DTOs + adapters. `AuthApi` references these types directly;
  blocking. (AND-026 itself depends on AND-010.)

**Transitive upstream (already required by AND-026/AND-010):** AND-010 (shared
Retrofit/Moshi), AND-009 (shared `OkHttpClient`), AND-006 (`BuildConfig`),
AND-003/AND-004 (module structure, Hilt baseline).

**Downstream (this ticket blocks):**
- The **session repository** in `core-data` and the **auth feature** ViewModels
  consume `AuthApi`.
- AND-013 (401-refresh `Authenticator`) calls `AuthApi.sessionRefresh()`; it can
  be developed in parallel but integration-depends on this signature.
- AND-025 (auth-gated routing) depends on `me()` being callable.
- (IDs AND-028/AND-029/AND-030 in `blocks` are placeholders for the
  repository/feature consumers; align to the actual backlog ids during grooming.)

**Sequencing within the ticket:** (1) confirm DTO names against AND-026 and
`/openapi.json`; (2) declare `AuthApi`; (3) add `AuthApiModule`; (4) write
MockWebServer tests T-1..T-9.

## 13. Risks & Open Questions

- **R-1 Empty-body decoding for refresh/logout.** If the backend returns a bare
  `200` with no body, declaring the return as `OkResp` will throw a Moshi
  `EOFException`. Mitigation: confirm shape via `/openapi.json`; use `Unit` return
  type for genuinely empty responses. Guarded by T-3/T-4.
- **R-2 Sessions list envelope.** `GET /ui/sessions` may return a bare array or a
  `{sessions:[...]}` wrapper. Mitigation: inspect web reference + OpenAPI before
  coding; pick the matching DTO. Guarded by T-6.
- **R-3 DTO drift from AND-026.** If AND-026 names a field/type differently than
  assumed here (e.g. `OkResp` vs `StatusResp`), this interface won't compile.
  Mitigation: this ticket consumes AND-026 as-is; resolve naming in AND-026, not
  by redefining DTOs here.
- **R-4 CSRF on mutating verbs.** If AND-012's interceptor is not yet present,
  `start`/`finalize`/`refresh`/`logout`/`revoke` may 403 against a real backend.
  Unit tests use MockWebServer and are unaffected; end-to-end depends on AND-012.
- **Q-1** Do `refresh`/`logout` return `{"ok":true}` or an empty body? *Proposed:*
  verify against `/openapi.json`; default to `OkResp`, fall back to `Unit`.
- **Q-2** Is `GET /ui/sessions` a bare array or wrapped? *Proposed:* match the web
  reference (`frontend/src/api/endpoints/*.ts`); default to `List<SessionInfo>`.
- **Q-3** Does `revokeSession` use `DELETE /ui/sessions/{id}` or `POST
  /ui/sessions/{id}/revoke`? *Proposed:* confirm via OpenAPI; spec assumes
  `DELETE`. Adjust the annotation if the contract differs.

## 14. Acceptance Criteria

- **AC-1 (backlog).** `AuthApi` declares all seven operations
  (`sessionStart`, `sessionFinalize`, `sessionRefresh`, `sessionLogout`, `me`,
  `listSessions`, `revokeSession`); the module compiles against AND-026 DTOs.
- **AC-2 (backlog).** Each endpoint is callable and its **verb + resolved path +
  request body** match the contract in Section 5, asserted with MockWebServer
  (T-1..T-7).
- **AC-3.** `sessionStart` serializes the nested
  `{challenge_context:{username,password}}` body exactly and decodes
  `{auth_required, challenge_id, required_factors}` (T-1).
- **AC-4.** `me()` decodes snake_case fields (`mfa_enrolled`, `session_id`) via
  AND-026 adapters (T-5).
- **AC-5.** Non-2xx (e.g. `401` from `me`) surfaces as `HttpException` and is not
  swallowed (T-8).
- **AC-6.** `AuthApi` is Hilt-provided as a `@Singleton` built on the shared
  Retrofit; repeated injection yields the same instance (T-9).
- **AC-7.** No new `OkHttpClient`/`Retrofit` is constructed; no per-method CSRF or
  cookie headers are declared in the interface.
- **AC-8.** All tests pass in CI; module builds clean under AGP 8.7.3 / Gradle 8.9
  / JDK 17 with KSP-generated adapters present and no detekt/lint regressions.

## 15. Definition of Done

- `AuthApi` (`com.testlogon.android.core.network.auth`) and `AuthApiModule`
  (`...auth.di`) are implemented in `core-network`, referencing AND-026 DTOs only
  (no DTOs redefined).
- Open questions Q-1/Q-2/Q-3 are resolved against `/openapi.json` and the web
  reference, and the interface's return types/verbs reflect the confirmed contract.
- MockWebServer tests T-1 through T-9 are implemented and green in CI; ≥90% line
  coverage on the new surface; every endpoint has a path/verb assertion.
- No second `OkHttpClient`/`Retrofit`; no manual cookie/CSRF/auth headers in the
  interface; `sessionStart` body and auth headers are redacted in logs (verified).
- `./gradlew :core-network:assemble :core-network:testDebugUnitTest` passes
  locally and in CI with no new lint/detekt violations (AND-005 config).
- Code reviewed and merged to `android-port`; the session repository / auth
  feature and AND-013 are unblocked (the `sessionRefresh()` seam is in place).
- A one-line note in the `core-network` README (owned by AND-007) records the
  `AuthApi` path/verb map and the delegation of cookie/CSRF/refresh to
  AND-011/AND-012/AND-013.
