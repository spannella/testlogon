---
id: AND-027
title: AuthApi (session endpoints)
milestone: M1
epic: E04
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- **Auth flow (authoritative — verified):** `POST /ui/session/start` with
  `{challenge_context:{…}}` (the backend `UiSessionStartReq.challenge_context` is a
  free-form object, `additionalProperties:true`; the web client passes a
  `Record<string, unknown>`, conventionally `{username, password}`, but the schema
  is **not** strongly typed) →
  `{auth_required, challenge_id?, required_factors[], session_id?}`; MFA via
  `/ui/mfa/{totp|sms|email}/begin|verify` (separate ticket); `POST
  /ui/session/finalize`; `GET /ui/me`. Session rides on cookies + a `ui_csrf`
  cookie echoed as `X-CSRF-Token` (verified in `src/api/client.ts`); on 401 the
  web client calls `POST /ui/session/refresh` once then retries — but **only if it
  was already authenticated**; an unauthenticated 401 (e.g. bad password on the
  login screen) propagates directly without a refresh attempt (Authenticator,
  AND-013).
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
import com.testlogon.android.core.model.auth.RevokeSessionReq
import com.testlogon.android.core.model.auth.SessionFinalizeReq
import com.testlogon.android.core.model.auth.SessionFinalizeResp
import com.testlogon.android.core.model.auth.SessionsResp
import com.testlogon.android.core.model.auth.SessionStartReq
import com.testlogon.android.core.model.auth.SessionStartResp
import com.testlogon.android.core.model.auth.StatusResp
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST

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
     * Backend returns `{ "status": "ok" }` (StatusResp), not `{ "ok": true }`.
     */
    @POST("ui/session/refresh")
    suspend fun sessionRefresh(): StatusResp

    /** Ends the current session (clears server-side state; cookies cleared by jar). */
    @POST("ui/session/logout")
    suspend fun sessionLogout(): StatusResp

    /** Current principal. Idempotent GET; used for auth-gating (AND-025). */
    @GET("ui/me")
    suspend fun me(): MeResp

    /**
     * Active sessions for the current principal. Idempotent GET. The backend
     * returns a WRAPPED object `{ "sessions": [...] }`, not a bare array — so the
     * return type is `SessionsResp(sessions: List<SessionInfo>)` (AND-026), NOT
     * `List<SessionInfo>`. Verified against `src/api/endpoints/auth.ts: getSessions`.
     */
    @GET("ui/sessions")
    suspend fun listSessions(): SessionsResp

    /**
     * Revoke a single session by id. The contract is `POST ui/sessions/revoke`
     * with a JSON body `{ "session_id": "..." }` — NOT `DELETE
     * ui/sessions/{id}`. Verified against OpenAPI `POST /ui/sessions/revoke`
     * (op=ui_sessions_revoke) and `src/api/endpoints/auth.ts: revokeSession`.
     */
    @Headers("Content-Type: application/json")
    @POST("ui/sessions/revoke")
    suspend fun revokeSession(@Body body: RevokeSessionReq): StatusResp
}
```

Notes:
- DTO types (`SessionStartReq`, `MeResp`, `StatusResp`, etc.) are **owned by
  AND-026**. If a referenced type is not yet present, this ticket is blocked.
- **`refresh`/`logout`/`revoke` return `StatusResp` (`{ "status": "ok" }`)**, NOT
  the generic `OkResp` (`{ "ok": true }`). This was an error in the original
  draft: the web client (`src/api/endpoints/auth.ts`) types `logout`, `refresh`,
  and `revokeSession` as `StatusResp`. `OkResp` is used elsewhere in the backend
  (e.g. `password-recovery/confirm`) but not by these three session endpoints.
  AND-026 must therefore expose a `StatusResp(status: String)` DTO. (Q-1 resolved.)
- **`listSessions` returns the WRAPPED `SessionsResp(sessions: List<SessionInfo>)`**
  — the backend returns `{ "sessions": [...] }`, not a bare array
  (`src/api/endpoints/auth.ts: getSessions` → `{ sessions: SessionInfo[] }`).
  (Q-2 resolved against the web reference.)
- **`SessionStartReq.challenge_context`** is a free-form object
  (`additionalProperties:true`); model it as `Map<String, Any?>` (or a permissive
  DTO) in AND-026 rather than a strict `{username, password}` type. The web client
  passes a `Record<string, unknown>`.

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
- Mutating verbs: `start`, `finalize`, `refresh`, `logout`, `revoke` are **all
  POST** (revoke is `POST ui/sessions/revoke`, not DELETE — corrected) — the CSRF
  interceptor (AND-012) attaches `X-CSRF-Token` to these.
- Idempotent GETs: `me`, `listSessions` — eligible for AND-016 bounded backoff.

### 4.4 Gradle wiring

No new dependencies. `core-network/build.gradle.kts` already has Retrofit, Moshi,
Hilt, and (test) MockWebServer from AND-010. This ticket adds source files only;
it depends on `:core-model` (AND-026 DTOs), which is already an `implementation`
dependency of `core-network`.

## 5. API Contract

Base path (`dev`): `http://18.222.237.167:8000/`. All bodies are JSON.

> All shapes below are **verified** against `reference/openapi.pretty.json`
> (`components.schemas.UiSession*`) and `reference/src/api/types.ts`. Where the
> original draft differed, the corrected shape is shown and the change is logged in
> §16.

### POST `ui/session/start`  (req=`UiSessionStartReq`, resp=`UiSessionStartResp`)
Request — `challenge_context` is a free-form object (`additionalProperties:true`);
the web client conventionally sends username/password but the schema does not
require any specific keys:
```json
{ "challenge_context": { "username": "alice@example.com", "password": "s3cret" } }
```
Response `200`:
```json
{
  "auth_required": true,
  "challenge_id": "chl_01HRX...",
  "required_factors": ["totp"],
  "session_id": "sess_01HRY..."
}
```
Only `auth_required` is required; `challenge_id` and `session_id` are nullable.

### POST `ui/session/finalize`  (req=`UiSessionFinalizeReq`)
Request (challenge id from start, after MFA verify succeeds). `remember_device`
is an optional boolean (default `false`):
```json
{ "challenge_id": "chl_01HRX...", "remember_device": false }
```
Response `200` (session cookies set via `Set-Cookie`; `ui_csrf` cookie included).
Corrected shape per `types.ts: SessionFinalizeResp` — the draft's
`{ok, user{username, roles}}` was wrong:
```json
{
  "status": "ok",
  "session_id": "sess_01HRY...",
  "required_factors": [],
  "passed": { "totp": true }
}
```
(`status` is `"ok" | "pending"`.)

### POST `ui/session/refresh`
Request: no body. Mutating verb; carries cookies + `X-CSRF-Token`.
Response `200` (corrected — `StatusResp`, not `OkResp`):
```json
{ "status": "ok" }
```

### POST `ui/session/logout`
Request: no body. Response `200`: `{ "status": "ok" }` (`StatusResp`). Cookie jar
clears session cookies on success (jar behavior owned by AND-011).

### GET `ui/me`
Response `200` (corrected per `types.ts: MeResp` — the draft's
`{username, roles, mfa_enrolled, session_id}` was wrong):
```json
{
  "user_sub": "usr_01HRZ...",
  "session_id": "sess_01HRY...",
  "ip": "203.0.113.7"
}
```
`401` when unauthenticated → triggers AND-013 refresh-then-retry once (only when a
session already existed; an unauthenticated 401 is terminal — see §2).

### GET `ui/sessions`
Response `200` — a WRAPPED object (corrected; the draft showed a bare array), with
`SessionInfo` fields per `types.ts: SessionInfo` (note `is_current`, not `current`;
`created_at`/`last_seen_at` are numeric epoch timestamps, not ISO strings; plus
`revoked`/`revoked_at`):
```json
{
  "sessions": [
    {
      "session_id": "sess_01HRY...",
      "is_current": true,
      "created_at": 1749124800,
      "last_seen_at": 1749126600,
      "ip": "203.0.113.7",
      "user_agent": "TestLogon-Android/1.0 (Pixel 7; Android 14)",
      "revoked": false,
      "revoked_at": null
    }
  ]
}
```

### POST `ui/sessions/revoke`  (corrected — was `DELETE ui/sessions/{id}`)
Request body `{ "session_id": "..." }`:
```json
{ "session_id": "sess_01HRY..." }
```
Response `200`: `{ "status": "ok" }` (`StatusResp`). A bad/unknown id surfaces as
`422 HTTPValidationError` (validation) or a non-2xx per backend policy — the
contract does not document a `404`.

> Related (out of scope for AND-027): `POST ui/sessions/revoke_others` exists in
> the contract for bulk revocation of all other sessions; it is not part of this
> ticket's scope.

**Error envelope (all endpoints):** validation failures return `422` with the
named schema **`HTTPValidationError`** (`{ "detail": [ { "loc": [...], "msg":
"...", "type": "..." } ] }`), per the OpenAPI index. Other FastAPI errors return
`{ "detail": string | {...} }`. Mapping to a typed `ApiError` is owned by
**AND-015**; this ticket lets non-2xx surface as `HttpException` so
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
body** and decodes `200 {"status":"ok"}` into `StatusResp`.

**T-4 — `sessionLogout`** issues `POST /ui/session/logout`, decodes `StatusResp`
(`{"status":"ok"}`).

**T-5 — `me`** issues `GET /ui/me` and decodes `MeResp` with fields
`user_sub`, `session_id`, `ip` via the AND-026 adapters.

**T-6 — `listSessions`** issues `GET /ui/sessions` and decodes the wrapped
`SessionsResp` (`{"sessions":[...]}`), including the numeric `created_at` /
`last_seen_at` epoch fields and the `is_current` flag.

**T-7 — `revokeSession`** issues `POST /ui/sessions/revoke` with body
`{"session_id":"sess_1"}` and decodes `StatusResp`.

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

- **R-1 Empty-body decoding for refresh/logout.** RESOLVED: the web client types
  both as `StatusResp` (`{"status":"ok"}`), so a non-empty JSON body is expected
  and `StatusResp` is the correct return type — no `Unit`/`EOFException` concern.
  Residual risk: the dev backend could still emit an empty body under error
  conditions; lenient handling at the repository layer mitigates. Guarded by
  T-3/T-4.
- **R-2 Sessions list envelope.** RESOLVED: `GET /ui/sessions` returns a
  `{"sessions":[...]}` wrapper (`src/api/endpoints/auth.ts: getSessions`), so the
  return type is `SessionsResp`, not a bare array. Guarded by T-6.
- **R-3 DTO drift from AND-026.** If AND-026 names a field/type differently than
  assumed here (e.g. `OkResp` vs `StatusResp`), this interface won't compile.
  Mitigation: this ticket consumes AND-026 as-is; resolve naming in AND-026, not
  by redefining DTOs here.
- **R-4 CSRF on mutating verbs.** If AND-012's interceptor is not yet present,
  `start`/`finalize`/`refresh`/`logout`/`revoke` may 403 against a real backend.
  Unit tests use MockWebServer and are unaffected; end-to-end depends on AND-012.
- **Q-1** Do `refresh`/`logout` return `{"ok":true}` or an empty body? **RESOLVED:**
  both return `StatusResp` (`{"status":"ok"}`), per `src/api/endpoints/auth.ts`.
- **Q-2** Is `GET /ui/sessions` a bare array or wrapped? **RESOLVED:** wrapped as
  `{"sessions":[...]}` → `SessionsResp` (`src/api/endpoints/auth.ts: getSessions`).
- **Q-3** Does `revokeSession` use `DELETE /ui/sessions/{id}` or a POST? **RESOLVED:**
  neither of the originally guessed forms — the contract is `POST
  /ui/sessions/revoke` with body `{"session_id":...}` (OpenAPI
  `op=ui_sessions_revoke`; `src/api/endpoints/auth.ts: revokeSession`). The
  interface has been corrected accordingly.

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
- **AC-4.** `me()` decodes snake_case fields (`user_sub`, `session_id`, `ip`) via
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
**OAI-IDX** = `reference/openapi.index.txt`; **OAI** = `reference/openapi.pretty.json`
(`components.schemas.<Name>`); frontend paths are under `reference/src/`.

1. **`POST /ui/session/start` (req `UiSessionStartReq`, resp `UiSessionStartResp`).**
   VERDICT: Verified. SOURCE: OAI-IDX `POST /ui/session/start`
   (`op=ui_session_start`); `src/api/endpoints/auth.ts: sessionStart`.
2. **`session/start` request is `{challenge_context:{…}}`.** VERDICT: Verified
   (with caveat). SOURCE: OAI `UiSessionStartReq.challenge_context`
   (`type:object, additionalProperties:true`); `src/api/types.ts: SessionStartReq`
   (`challenge_context?: Record<string, unknown>`). The `{username,password}`
   inner shape is a **convention**, not enforced by the schema — see Open
   assumptions.
3. **`session/start` response `{auth_required, challenge_id?, required_factors[],
   session_id?}`.** VERDICT: Corrected (added `session_id`; `challenge_id`
   nullable). SOURCE: OAI `UiSessionStartResp` (required: `auth_required`;
   `challenge_id`/`session_id` are `anyOf string|null`); `src/api/types.ts:
   SessionStartResp`.
4. **`POST /ui/session/finalize` (req `UiSessionFinalizeReq`).** VERDICT: Verified.
   SOURCE: OAI-IDX `POST /ui/session/finalize` (`op=ui_session_finalize`);
   `src/api/endpoints/auth.ts: sessionFinalize`.
5. **`finalize` request `{challenge_id, remember_device?}`.** VERDICT: Corrected
   (added `remember_device`, default false). SOURCE: OAI `UiSessionFinalizeReq`
   (required `challenge_id`; `remember_device` boolean default false);
   `src/api/types.ts: SessionFinalizeReq`.
6. **`finalize` response shape.** Draft claimed `{ok:true, user:{username,
   roles}}`. VERDICT: Corrected to `{status:"ok"|"pending", session_id?,
   required_factors[], passed:{}}`. SOURCE: `src/api/types.ts:
   SessionFinalizeResp`. (OAI-IDX shows `resp=200:` with no named schema, so the
   frontend type is the authoritative shape.)
7. **`POST /ui/session/refresh`, no body, returns `StatusResp`.** Draft claimed
   `OkResp` (`{ok:true}`). VERDICT: Corrected to `StatusResp` (`{status:"ok"}`).
   SOURCE: OAI-IDX `POST /ui/session/refresh` (`req=`, empty); `src/api/
   endpoints/auth.ts: refreshSession` (`api.post<StatusResp>`).
8. **`POST /ui/session/logout`, no body, returns `StatusResp`.** Draft claimed
   `OkResp`. VERDICT: Corrected to `StatusResp`. SOURCE: OAI-IDX `POST
   /ui/session/logout`; `src/api/endpoints/auth.ts: logout`
   (`api.post<StatusResp>`).
9. **`GET /ui/me` response `{user_sub, session_id, ip}`.** Draft claimed
   `{username, roles, mfa_enrolled, session_id}`. VERDICT: Corrected. SOURCE:
   `src/api/types.ts: MeResp`; OAI-IDX `GET /ui/me` (`op=ui_me`, `resp=200:` no
   named schema → frontend type authoritative).
10. **`GET /ui/sessions` returns a WRAPPED `{sessions:[...]}`, not a bare array.**
    VERDICT: Corrected (`SessionsResp`). SOURCE: `src/api/endpoints/auth.ts:
    getSessions` (`api.get<{ sessions: SessionInfo[] }>`); OAI-IDX `GET
    /ui/sessions`.
11. **`SessionInfo` fields.** Draft used `current`, ISO-string timestamps. VERDICT:
    Corrected to `{session_id, is_current, created_at:number, last_seen_at:number,
    ip, user_agent, revoked, revoked_at?}`. SOURCE: `src/api/types.ts:
    SessionInfo` (timestamps are numeric epoch; flag is `is_current`).
12. **Revoke is `POST /ui/sessions/revoke` with body `{session_id}` → `StatusResp`.**
    Draft claimed `DELETE /ui/sessions/{sessionId}` → `OkResp`. VERDICT: Corrected
    (verb, path, body, and return type all changed). SOURCE: OAI-IDX `POST
    /ui/sessions/revoke` (`op=ui_sessions_revoke`); `src/api/endpoints/auth.ts:
    revokeSession` (`api.post<StatusResp>("/ui/sessions/revoke", {session_id})`).
13. **`POST /ui/sessions/revoke_others` exists (out of scope).** VERDICT: Verified.
    SOURCE: OAI-IDX `POST /ui/sessions/revoke_others`; `src/api/endpoints/auth.ts:
    revokeOtherSessions`.
14. **CSRF: `ui_csrf` cookie echoed as `X-CSRF-Token` header on requests.**
    VERDICT: Verified. SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` →
    `headers.set("X-CSRF-Token", csrf)`).
15. **Session is cookie-based; client sends credentials with the request.**
    VERDICT: Verified. SOURCE: `src/api/client.ts` (`credentials: "include"` on
    every fetch).
16. **On 401, refresh-then-retry once — only if already authenticated.** VERDICT:
    Corrected/clarified (draft implied unconditional refresh). SOURCE:
    `src/api/client.ts` (`if (res.status === 401) { … if
    (!useAuthStore.getState().isAuthenticated) { throw … } … refreshSession() …
    retry }`).
17. **Validation errors return `422` with named schema `HTTPValidationError`.**
    VERDICT: Verified. SOURCE: OAI-IDX (every session endpoint lists
    `422:HTTPValidationError`); OAI `components.schemas.HTTPValidationError`.
18. **DTO ownership: types come from AND-026; this ticket only binds them.**
    VERDICT: Unverified-assumption (cross-ticket process claim, not in sources).
19. **Framework choices — Retrofit `suspend` returning DTO body; empty 2xx → `Unit`;
    `@Headers`, `@Body`, `@Path`, `@POST/@GET` semantics.** VERDICT:
    Unverified-assumption (framework ref). SOURCE: framework ref —
    https://square.github.io/retrofit/ (Retrofit 2.x annotations & coroutine
    support); not derivable from the backend/frontend sources.
20. **Hilt `@Provides @Singleton` provider built on the shared Retrofit.** VERDICT:
    Unverified-assumption (framework ref). SOURCE: framework ref —
    https://dagger.dev/hilt/ ; an Android architecture choice, not in the sources.
21. **Dev base URL `http://18.222.237.167:8000/` over plaintext HTTP.** VERDICT:
    Unverified-assumption. SOURCE: not present in the provided sources (no base
    URL/host in OpenAPI or frontend); carried over from upstream tickets
    AND-006/AND-009/AND-010.

### Corrections made

- **Revoke endpoint** rewritten: `DELETE /ui/sessions/{sessionId}` →
  `POST /ui/sessions/revoke` with `@Body RevokeSessionReq {session_id}`; return
  `OkResp` → `StatusResp`. (§4.1, §4.3, §5, T-7, AC-2.) [claim 12]
- **`listSessions`** return type: `List<SessionInfo>` → `SessionsResp`
  (`{sessions:[...]}` wrapper). (§4.1, §5, T-6.) [claim 10]
- **`refresh`/`logout` return type**: `OkResp` → `StatusResp`. (§4.1, §5, T-3,
  T-4.) [claims 7, 8]
- **`SessionFinalizeResp`** corrected from `{ok, user{…}}` to
  `{status, session_id?, required_factors, passed}`. (§5.) [claim 6]
- **`MeResp`** corrected from `{username, roles, mfa_enrolled, session_id}` to
  `{user_sub, session_id, ip}`. (§5, T-5, AC-4.) [claim 9]
- **`SessionInfo`** corrected: `current`→`is_current`; timestamps are numeric
  epoch, not ISO strings; added `revoked`/`revoked_at`. (§5, T-6.) [claim 11]
- **`session/start`** request `challenge_context` documented as free-form object;
  response gains nullable `challenge_id` and `session_id`. (§2, §5.) [claims 2, 3]
- **`finalize`** request gains optional `remember_device`. (§5.) [claim 5]
- **401 handling** clarified: refresh-then-retry only when already authenticated.
  (§2.) [claim 16]
- **Error envelope** named: `422 HTTPValidationError`. (§5.) [claim 17]
- Imports/annotations in §4.1 updated (`DELETE`/`Path`/`OkResp` removed;
  `StatusResp`/`SessionsResp`/`RevokeSessionReq` added). Q-1/Q-2/Q-3 and R-1/R-2
  marked RESOLVED. (§4.1, §13.)

### Open assumptions

- **`challenge_context` inner keys** (`username`/`password`): the schema is
  `additionalProperties:true` (free-form), so the exact key names are a convention
  copied from the web client's usage, not an enforced contract. AND-026 should
  model it as a permissive map. [claim 2]
- **DTO names/ownership in AND-026** (`StatusResp`, `SessionsResp`,
  `RevokeSessionReq`, etc.): assumed to exist/be added by AND-026; not verifiable
  from the backend/frontend sources. [claim 18]
- **Dev base URL / plaintext-HTTP host**: not present in any provided source;
  inherited from AND-006/AND-009. [claim 21]
- **Android framework behaviors** (Retrofit empty-body→`Unit`, Hilt singleton
  provider, KSP Moshi codegen): framework refs, not derivable from the sources.
  [claims 19, 20]
- **`me`/`finalize` exact server schema**: OpenAPI lists these with `resp=200:`
  and no named component schema, so the response shape is taken from the
  frontend `types.ts` (the contract the web client relies on) rather than from a
  formal backend schema. [claims 6, 9]

## 17. Test Plan

All tests use the production Moshi/Retrofit config against `MockWebServer` unless
noted. IDs trace to the §14 Acceptance Criteria.

- **TC-AND-027-01 — `sessionStart` contract.** Type: contract/MockWebServer.
  Preconditions: MockWebServer enqueues
  `200 {"auth_required":true,"challenge_id":"chl_1","required_factors":["totp"],"session_id":"sess_1"}`.
  Steps: call `sessionStart(SessionStartReq(challengeContext=mapOf("username" to
  "alice@example.com","password" to "s3cret")))`; capture the recorded request.
  Expected: method `POST`, path `/ui/session/start`, body contains
  `"challenge_context"` and `"username":"alice@example.com"`; decoded resp has
  `authRequired==true`, `challengeId=="chl_1"`, `requiredFactors==["totp"]`,
  `sessionId=="sess_1"`. Traces: AC-1, AC-2, AC-3.

- **TC-AND-027-02 — `sessionFinalize` contract.** Type: contract/MockWebServer.
  Preconditions: enqueue
  `200 {"status":"ok","session_id":"sess_1","required_factors":[],"passed":{"totp":true}}`.
  Steps: call `sessionFinalize(SessionFinalizeReq(challengeId="chl_1"))`. Expected:
  `POST /ui/session/finalize`; body contains `"challenge_id":"chl_1"`; decoded
  `status=="ok"`, `passed["totp"]==true`. Traces: AC-1, AC-2.

- **TC-AND-027-03 — `sessionRefresh` no-body + StatusResp.** Type:
  contract/MockWebServer. Preconditions: enqueue `200 {"status":"ok"}`. Steps:
  call `sessionRefresh()`. Expected: `POST /ui/session/refresh`, recorded request
  body length `== 0`; decoded `StatusResp.status=="ok"`. Traces: AC-1, AC-2.

- **TC-AND-027-04 — `sessionLogout` StatusResp.** Type: contract/MockWebServer.
  Preconditions: enqueue `200 {"status":"ok"}`. Steps: call `sessionLogout()`.
  Expected: `POST /ui/session/logout`, empty request body, decoded
  `status=="ok"`. Traces: AC-1, AC-2.

- **TC-AND-027-05 — `me` decodes corrected fields.** Type: contract/MockWebServer.
  Preconditions: enqueue
  `200 {"user_sub":"usr_1","session_id":"sess_1","ip":"203.0.113.7"}`. Steps: call
  `me()`. Expected: `GET /ui/me`; decoded `userSub=="usr_1"`,
  `sessionId=="sess_1"`, `ip=="203.0.113.7"` (snake_case mapped by adapters).
  Traces: AC-1, AC-2, AC-4.

- **TC-AND-027-06 — `listSessions` wrapped + numeric timestamps.** Type:
  contract/MockWebServer. Preconditions: enqueue `200 {"sessions":[{"session_id":
  "sess_1","is_current":true,"created_at":1749124800,"last_seen_at":1749126600,
  "ip":"203.0.113.7","user_agent":"x","revoked":false}]}`. Steps: call
  `listSessions()`. Expected: `GET /ui/sessions`; decoded
  `SessionsResp.sessions[0].isCurrent==true`, `createdAt==1749124800L`,
  `revoked==false`. (A bare-array body must NOT decode — guards the wrapper fix.)
  Traces: AC-1, AC-2.

- **TC-AND-027-07 — `revokeSession` POST + body.** Type: contract/MockWebServer.
  Preconditions: enqueue `200 {"status":"ok"}`. Steps: call
  `revokeSession(RevokeSessionReq(sessionId="sess_1"))`. Expected: method `POST`,
  path `/ui/sessions/revoke` (NOT DELETE, NOT path-templated), request body
  contains `"session_id":"sess_1"`; decoded `status=="ok"`. Traces: AC-1, AC-2.

- **TC-AND-027-08 — 401 surfaces as HttpException (not swallowed).** Type:
  contract/MockWebServer. Preconditions: enqueue `401` with body
  `{"detail":"Authentication required"}`. Steps: call `me()`; assert it throws.
  Expected: `retrofit2.HttpException` with `code()==401`; raw error body
  retrievable for AND-015. Traces: AC-5.

- **TC-AND-027-09 — 422 validation error shape preserved.** Type:
  contract/MockWebServer. Preconditions: enqueue `422` with
  `{"detail":[{"loc":["body","challenge_id"],"msg":"field required","type":"value_error.missing"}]}`.
  Steps: call `sessionFinalize(SessionFinalizeReq(challengeId=""))`. Expected:
  `HttpException` `code()==422`; `errorBody()` contains the `HTTPValidationError`
  `detail[].loc/msg/type` intact (decoding deferred to AND-015). Traces: AC-5.

- **TC-AND-027-10 — flaky-dev-host / offline transport failure.** Type:
  contract/MockWebServer (+ integration). Preconditions: enqueue
  `MockResponse().setSocketPolicy(NO_RESPONSE)` (or shut the server to simulate
  `UnknownHostException`). Steps: call `me()` with a short client timeout.
  Expected: an `IOException`/`SocketTimeoutException` propagates **unchanged**
  (no swallowing, no wrapping by `AuthApi`); leaves AND-009/AND-016 backoff to act.
  Traces: AC-5.

- **TC-AND-027-11 — Hilt provider is a shared singleton.** Type: integrated
  (`@HiltAndroidTest` or `core-testing` harness). Preconditions: Hilt graph with
  AND-010 `NetworkModule` + `AuthApiModule`. Steps: inject `AuthApi` twice.
  Expected: both injections non-null and the **same** instance; built on the
  shared `Retrofit` (no second `Retrofit`/`OkHttpClient` created). Traces: AC-6,
  AC-7.

- **TC-AND-027-12 — no per-method cookie/CSRF/auth headers in the interface.**
  Type: unit (reflection/source check). Preconditions: compiled `AuthApi`. Steps:
  reflect over each method's annotations (or a detekt/source assertion). Expected:
  no `@Header`/`@Headers` declaring `Cookie`, `Authorization`, or `X-CSRF-Token`;
  only `Content-Type: application/json` on JSON POSTs. (CSRF/cookies remain
  AND-011/AND-012 concerns.) Traces: AC-7.

- **TC-AND-027-13 — credentials never logged (security).** Type: unit/manual
  code-review gate. Preconditions: debug build with AND-009 logging interceptor.
  Steps: exercise `sessionStart` against MockWebServer with logging on; capture
  logcat/test log. Expected: the request body (password) and any `Set-Cookie` /
  `X-CSRF-Token` headers are redacted; the cleartext password never appears.
  Traces: AC-7. (Security/permission case.)

- **TC-AND-027-14 — module builds clean.** Type: integration/CI. Preconditions:
  AGP 8.7.3 / Gradle 8.9 / JDK 17, KSP Moshi adapters present for all referenced
  DTOs. Steps: run `:core-network:assemble` and `:core-network:testDebugUnitTest`.
  Expected: green build, no detekt/lint regressions, all TCs above pass. Traces:
  AC-1, AC-8.

> Accessibility: not applicable — `AuthApi` is a headless transport interface with
> no UI surface (see §9). No Compose-UI/a11y cases are in scope for this ticket;
> a11y is covered by the consuming `feature-auth` tickets.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 (all 7 ops declared, compiles vs AND-026) | TC-01..07, TC-14 |
| AC-2 (verb + path + body match contract, MockWebServer) | TC-01..07 |
| AC-3 (`start` nested `challenge_context` body + decode) | TC-01 |
| AC-4 (`me` snake_case fields decode) | TC-05 |
| AC-5 (non-2xx surfaces as `HttpException`, not swallowed) | TC-08, TC-09, TC-10 |
| AC-6 (Hilt `@Singleton`, same instance on re-injection) | TC-11 |
| AC-7 (no new client/Retrofit; no per-method CSRF/cookie headers) | TC-11, TC-12, TC-13 |
| AC-8 (CI green, builds clean, no lint/detekt regressions) | TC-14 |
