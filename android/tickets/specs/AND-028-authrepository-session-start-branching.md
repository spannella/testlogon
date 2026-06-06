---
id: AND-028
title: "AuthRepository: session start + branching"
milestone: M1
epic: E04
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-027, AND-018]
blocks: [AND-029, AND-031, AND-047]
---

# AND-028 — AuthRepository: session start + branching

## 1. Overview & Goal

This ticket introduces the first method of the cookie-based authentication repository:
`AuthRepository.login(username, password)`. It calls the FastAPI session-start endpoint
(`POST /ui/session/start`) wrapping a `challenge_context`, then **branches** the response
into one of two typed domain outcomes:

- **Authenticated** — the server completed the session in one step (no additional factors
  required); the session cookies are already set in the persistent jar and the caller may
  proceed to `getMe()` (AND-029). **[Corrected]** The authoritative signal for this branch,
  per the web reference (`src/pages/Login.tsx:145`), is `auth_required == false` **and a
  non-blank `session_id`** in the response — not merely "empty `required_factors`". See
  Section 16 for the correction detail.
- **MfaRequired(challengeId, factors)** — the server requires one or more additional
  factors; the caller must drive the MFA sub-flow (`/ui/mfa/{totp|sms|email}/begin|verify`)
  keyed by `challenge_id`, then finalize.

The goal is a single, testable seam in `core-data` (or `feature-auth` data layer) that
converts the raw `session/start` HTTP response into a `sealed interface LoginResult`
returned inside an `ApiResult<LoginResult>` (AND-018). All branching logic — interpreting
`auth_required`, `required_factors`, and `challenge_id` — lives here, behind an interface,
so that `LoginViewModel` (AND-031) never touches Retrofit types and can be unit-tested
against a fake repository.

Scope is intentionally limited to the *start + branch* step. `getMe()` and persistent auth
state are AND-029; finalize, refresh, logout, and the MFA verify calls are owned by their
own tickets (AND-027 already exposes the raw endpoints; the MFA repository methods come in
the E04 MFA tickets). This ticket consumes the `AuthApi.sessionStart` endpoint from
AND-027 and the `ApiResult`/`apiCall` machinery from AND-018.

## 2. Context & References

- **Module:** `core-data` (auth data sources/repositories) with domain models in
  `core-model`. Repository interface in `com.testlogon.android.core.data.auth`; domain
  result types in `com.testlogon.android.core.model.auth`.
- **Depends on (blocking):**
  - **AND-027** — `AuthApi` Retrofit interface exposing
    `session/start|finalize|refresh|logout`, `me`, `sessions(+revoke)`. This ticket calls
    only `sessionStart`.
  - **AND-018** — `ApiResult<T>`, `ApiError`, and the `apiCall { }` seam used to fold
    network failures into `ApiResult.NetworkError`.
- **Blocks:**
  - **AND-029** — `getMe()` + auth state store (calls `getMe()` after an `Authenticated`
    login).
  - **AND-031** — `LoginViewModel` maps `LoginResult` to navigation (MFA vs. home) + errors.
  - **AND-047** — depends on AuthRepository session behavior.
- **Related (not blocking):** AND-011 (persistent cookie jar — the session/CSRF cookies set
  by `session/start` must already be persisted by OkHttp), AND-012 (CSRF interceptor echoes
  `ui_csrf` as `X-CSRF-Token`), AND-013 (401 → `session/refresh` once → retry), AND-015
  (FastAPI `detail` mapping into `ApiError`).
- **Stack:** Kotlin 2.0.21, Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15,
  Hilt (KSP). minSdk 24, JDK 17.
- **Backend:** FastAPI dev host `http://18.222.237.167:8000` (plaintext, unreliable).
  OpenAPI at `/openapi.json`. Web reference flow in `frontend/src/api/endpoints/*.ts`,
  shared types in `frontend/src/api/types.ts`.
- **Auth flow (authoritative):** `POST /ui/session/start` with
  `{challenge_context:{username,password}}` → `{auth_required, challenge_id,
  required_factors[]}` → (if MFA) `/ui/mfa/...` → `POST /ui/session/finalize` →
  `GET /ui/me`. Session rides on cookies + a `ui_csrf` cookie echoed as `X-CSRF-Token`.

## 3. Functional Requirements

1. Define a repository interface:
   `interface AuthRepository { suspend fun login(username: String, password: String):
   ApiResult<LoginResult> }` in `core-data`.
2. Define the branch domain type `sealed interface LoginResult` in `core-model` with exactly
   two variants:
   - `Authenticated` — session completed in one step (`auth_required == false` **and**
     `session_id` is non-null/non-blank, mirroring the web client's
     `!resp.auth_required && resp.session_id` check at `src/pages/Login.tsx:145`).
   - `MfaRequired(challengeId: String, factors: List<MfaFactor>)` — additional factors
     required (anything that is not the `Authenticated` case: typically
     `auth_required == true`, surfacing a `challenge_id` + `required_factors`).
3. `login()` calls `AuthApi.sessionStart(SessionStartRequest(ChallengeContext(username,
   password)))` inside `apiCall { }` (AND-018) so transport failures fold to
   `ApiResult.NetworkError` and HTTP error bodies fold to `ApiResult.Failure(ApiError)`.
4. **Branching rule** (deterministic, single source of truth — aligned with the web
   reference at `src/pages/Login.tsx:145`):
   - **[Corrected]** If the call succeeds and `auth_required == false` **and** `session_id`
     is non-null/non-blank → return `ApiResult.Success(Authenticated)`. (The web client
     gates the "login complete" path on `!auth_required && session_id`, then calls
     `getMe()`; we mirror that.)
   - Otherwise, if `challenge_id` is non-null/non-blank → return
     `ApiResult.Success(MfaRequired(challengeId, requiredFactors.map(::fromWire)))`.
     (`required_factors` MAY be empty here; the MFA sub-flow tickets refine it. The presence
     of a `challenge_id` with `auth_required == true` is the operative MFA signal.)
   - If `auth_required == true` (or `session_id` is absent) **and** `challenge_id` is
     missing/blank → treat as a malformed server response: return
     `ApiResult.Failure(ApiError(status=200, code="malformed_mfa", message="MFA required but
     no challenge_id returned"))`. (Do not crash; do not return `Authenticated`.) This is the
     fail-closed default for the auth-critical branch.
5. `MfaFactor` is a typed enum mapped from `required_factors[]` strings (`"totp"`, `"sms"`,
   `"email"`); unknown factor strings map to `MfaFactor.Unknown(raw)` and are retained, not
   dropped (forward-compatibility).
6. The method MUST NOT throw for expected outcomes (network down, 401, 422); all such cases
   are encoded in `ApiResult`. `CancellationException` propagates (per AND-018 `apiCall`).
7. The repository is stateless beyond the injected `AuthApi`; the *session* state lives in
   the cookie jar (AND-011), not in this class. No `challenge_id` is persisted here — it is
   returned to the caller (held in `LoginViewModel`/MFA flow memory only).

## 4. Technical Design

Package layout:
- `com.testlogon.android.core.model.auth` — `LoginResult`, `MfaFactor`.
- `com.testlogon.android.core.data.auth` — `AuthRepository`, `AuthRepositoryImpl`.
- DTOs live with `AuthApi` (AND-027) in `com.testlogon.android.core.network.auth`.

Domain result (in `core-model`, framework-free):

```kotlin
package com.testlogon.android.core.model.auth

sealed interface LoginResult {
    /** Session fully established by session/start; cookies set. Proceed to getMe(). */
    data object Authenticated : LoginResult

    /** Additional factors required; drive the MFA flow keyed by [challengeId]. */
    data class MfaRequired(
        val challengeId: String,
        val factors: List<MfaFactor>,
    ) : LoginResult
}

sealed interface MfaFactor {
    data object Totp : MfaFactor
    data object Sms : MfaFactor
    data object Email : MfaFactor
    data class Unknown(val raw: String) : MfaFactor

    companion object {
        fun fromWire(raw: String): MfaFactor = when (raw.trim().lowercase()) {
            "totp" -> Totp
            "sms" -> Sms
            "email" -> Email
            else -> Unknown(raw)
        }
    }
}
```

Wire DTOs (defined in AND-027 alongside `AuthApi`; shown here for the contract this ticket
consumes):

```kotlin
@JsonClass(generateAdapter = true)
data class SessionStartRequest(
    @Json(name = "challenge_context") val challengeContext: ChallengeContext,
)

@JsonClass(generateAdapter = true)
data class ChallengeContext(
    val username: String,
    val password: String,
)

@JsonClass(generateAdapter = true)
data class SessionStartResponse(
    @Json(name = "auth_required") val authRequired: Boolean = false,
    @Json(name = "challenge_id") val challengeId: String? = null,
    @Json(name = "required_factors") val requiredFactors: List<String> = emptyList(),
    // [Corrected] Present in the real UiSessionStartResp schema and used by the web client
    // to gate the Authenticated branch (!auth_required && session_id). AND-027 must include it.
    @Json(name = "session_id") val sessionId: String? = null,
)
```

`AuthApi` method consumed (from AND-027):

```kotlin
@POST("ui/session/start")
suspend fun sessionStart(@Body body: SessionStartRequest): SessionStartResponse
```

Repository:

```kotlin
package com.testlogon.android.core.data.auth

interface AuthRepository {
    suspend fun login(username: String, password: String): ApiResult<LoginResult>
}

class AuthRepositoryImpl @Inject constructor(
    private val api: AuthApi,
) : AuthRepository {

    override suspend fun login(
        username: String,
        password: String,
    ): ApiResult<LoginResult> = apiCall {
        api.sessionStart(
            SessionStartRequest(ChallengeContext(username = username, password = password)),
        )
    }.flatMap { resp -> resp.toLoginResult() }

    private fun SessionStartResponse.toLoginResult(): ApiResult<LoginResult> {
        // [Corrected] Authenticated iff the web client's gate holds: !auth_required && session_id.
        val authenticated = !authRequired && !sessionId.isNullOrBlank()
        return when {
            authenticated -> ApiResult.Success(LoginResult.Authenticated)
            !challengeId.isNullOrBlank() ->
                ApiResult.Success(
                    LoginResult.MfaRequired(
                        challengeId = challengeId,
                        factors = requiredFactors.map(MfaFactor::fromWire),
                    ),
                )
            else -> // MFA implied but no usable challenge_id, or ambiguous response
                ApiResult.Failure(
                    ApiError(
                        status = 200,
                        code = "malformed_mfa",
                        message = "MFA required but no challenge_id returned",
                    ),
                )
        }
    }
}
```

Hilt binding (in an auth data module):

```kotlin
@Module
@InstallIn(SingletonComponent::class)
abstract class AuthDataModule {
    @Binds @Singleton
    abstract fun bindAuthRepository(impl: AuthRepositoryImpl): AuthRepository
}
```

`flatMap` (AND-018) preserves `Failure`/`NetworkError` from `apiCall` unchanged and only
applies the branch mapping on `Success`, keeping the original transport/HTTP failure intact
for the ViewModel.

## 5. API Contract

Single endpoint consumed: **`POST /ui/session/start`**.

Request body:

```json
{
  "challenge_context": {
    "username": "alice@example.com",
    "password": "hunter2"
  }
}
```

Headers: standard JSON `Content-Type: application/json`; cookies + `X-CSRF-Token`
(`ui_csrf`) are added by interceptors (AND-011/AND-012), not by this repository.

Response schema (`UiSessionStartResp`, verified against `components.schemas.UiSessionStartResp`):
only `auth_required` (boolean) is `required`; `challenge_id` (string|null), `required_factors`
(string[]) and **`session_id` (string|null)** are optional. The web client treats
`session_id` as the completed-login marker.

Representative success — **MFA required**:

```json
{
  "auth_required": true,
  "challenge_id": "chl_01HXYZ...",
  "required_factors": ["totp", "sms"],
  "session_id": null
}
```
→ `ApiResult.Success(LoginResult.MfaRequired("chl_01HXYZ...", [Totp, Sms]))`

Representative success — **fully authenticated** (session cookies set; `session_id` issued):

```json
{
  "auth_required": false,
  "challenge_id": null,
  "required_factors": [],
  "session_id": "ses_01HXYZ..."
}
```
→ `ApiResult.Success(LoginResult.Authenticated)` (web gate: `!auth_required && session_id`).

Error responses are folded by `apiCall`/AND-015 into `ApiResult.Failure(ApiError)`:

- **401 Unauthorized** (bad credentials) — **[Status corroborated; message unverified]** the
  OpenAPI spec for `POST /ui/session/start` documents only `200` and `422` responses; it does
  **not** declare a 401. However the web transport DOES treat an unauthenticated 401 as a real
  outcome: `src/api/client.ts:194-203` throws `ApiError(401, ...)` for a 401 when not already
  authenticated (and does **not** refresh it). So the **401 status** is corroborated by the
  reference client; only the exact `detail` **message string** below is assumed (FastAPI
  `detail`), not confirmed. The web client renders `err.detail || "Invalid credentials. Please
  try again."` (`src/pages/Login.tsx:178-186`) for any thrown `ApiError`, so a credentials
  failure surfaces through the generic error path regardless of the precise string.
  ```json
  { "detail": "Invalid username or password" }
  ```
  → `Failure(ApiError(status=401, message="<server detail>"))`.
  (Note: AND-013 only auto-refreshes 401s on *session* expiry; a credentials 401 from
  `session/start` is surfaced as-is, not retried — see Section 7.)
- **422 Unprocessable Entity** (validation) — VERIFIED in the spec (`resp=...;422:HTTPValidationError`).
  `detail` is an array of `ValidationError { loc: (string|int)[], msg: string, type: string }`
  (`components.schemas.ValidationError`; all three fields required):
  ```json
  { "detail": [ { "loc": ["body","challenge_context","username"], "msg": "field required", "type": "missing" } ] }
  ```
  → `Failure(ApiError(status=422, message="field required", code=null))` per AND-015.
- **5xx / unreachable host / timeout** → `ApiResult.NetworkError`.

Endpoint reachability, verbs, paths, and DTO shapes are *owned and MockWebServer-tested by
AND-027*; this ticket asserts only the branch mapping on top of representative responses.

## 6. Data & State Management

- `LoginResult` and `MfaFactor` are immutable value types, safe to carry in `StateFlow`
  (AND-031 holds the `MfaRequired` payload in its `LoginUiState` to navigate to the MFA
  screen).
- **No persistence in this ticket.** `challenge_id` is *transient* — returned to the caller
  and held in ViewModel memory for the duration of the MFA flow; it is never written to
  Room or DataStore.
- The **session itself** (auth cookies + `ui_csrf`) is persisted by the OkHttp cookie jar
  (AND-011) as a side effect of the HTTP call. This repository does not read or write
  cookies directly.
- Persistent *auth state* (authenticated flag, `user_sub`) is **out of scope** and owned by
  AND-029 (`getMe()` + DataStore-backed auth state store). After an `Authenticated` result,
  the caller (AND-031) invokes the AND-029 path; after `MfaRequired`, no auth state changes
  until finalize succeeds.
- `AuthRepositoryImpl` is a `@Singleton` and stateless apart from the injected `AuthApi`.

## 7. Error Handling & Resilience

- **No retry on `session/start`.** It is a non-idempotent `POST` with side effects (creates
  a challenge/session); AND-016 retry/backoff applies to idempotent GETs only. A
  `NetworkError` from `login()` is surfaced to the ViewModel, which offers a manual retry.
- **Timeouts:** OkHttp is configured for ~20s (AND-009) against the flaky dev host;
  `SocketTimeoutException` folds to `ApiResult.NetworkError(isTimeout = true)` via AND-018,
  letting AND-031 show "server is slow" copy distinct from "you're offline".
- **401 handling:** AND-013's authenticator triggers a single `session/refresh`+retry only
  for *expired-session* 401s. A credentials-failure 401 on `session/start` (no prior
  session) must surface as `Failure(ApiError(status=401, ...))` and must **not** loop
  through refresh. This ticket relies on AND-013 distinguishing the two; if AND-013 cannot,
  it is an open question (Section 13, Q1).
- **Malformed MFA response** (`auth_required=true`, blank `challenge_id`): mapped to
  `Failure(code="malformed_mfa")` rather than crashing or silently authenticating — a
  fail-closed default for an auth-critical branch.
- **Unknown factors:** preserved as `MfaFactor.Unknown(raw)` so an unrecognized server
  factor never silently drops a required step; the MFA UI can show "unsupported factor"
  instead of skipping security.
- `CancellationException` propagates unchanged (structured concurrency; AND-018 `apiCall`
  re-throws it).

## 8. Security & Privacy

- **Credentials handling:** `username`/`password` are passed straight into the request body
  and never logged, never stored, never placed in `ApiError`/`LoginResult`. They live only
  on the stack/coroutine frame for the duration of the call.
- **No request/response body logging** for this endpoint. The OkHttp logging interceptor
  (AND-009) MUST run at `BASIC` (or have `session/start` redacted) so the password and
  `challenge_id` never reach Logcat. Verified in Section 11.
- `challenge_id` is a short-lived secret tying the device to an in-progress MFA challenge;
  it is kept in memory only and excluded from telemetry (Section 10).
- Session and CSRF tokens are managed by the cookie jar (AND-011) / CSRF interceptor
  (AND-012); this repository never reads cookie values. Cleartext HTTP to the dev host is a
  known dev-only posture (network security config permits cleartext for the dev flavor only).
- `ApiError.rawBody`/`message` from a failed `session/start` must not echo the submitted
  password even if the server reflects input; AND-015 normalization plus BASIC logging
  mitigate this.

## 9. Accessibility & i18n

N/A for the repository layer — no UI is produced here. Note for downstream owners:
- `LoginResult.MfaRequired.factors` and `code="malformed_mfa"` are stable, machine-readable
  values so AND-031/MFA screens can select **localized** strings by factor/code rather than
  displaying server English.
- User-facing error copy for 401/422/network is localized in `core-ui`/`feature-auth`
  (AND-031), keyed off `ApiError.code`/`status`. This ticket deliberately emits raw,
  non-localized `ApiError.message` only as a diagnostic fallback.

## 10. Telemetry & Logging

- Emit a single structured event per login attempt via the Timber tree/analytics seam
  (AND-009), with **no PII**:
  - `auth_session_start` with fields: `outcome` (`authenticated|mfa_required|failure|
    network_error`), `http_status` (on failure), `error_code`, `factor_count` (on
    `mfa_required`), `is_timeout`.
- **Never log:** `username`, `password`, `challenge_id`, cookie values, or raw response
  bodies for this endpoint.
- Recommended factor breadcrumb: log the *set* of factor types requested (e.g.
  `["totp","sms"]`) for funnel analysis — these are categories, not secrets — but never the
  `challenge_id` that pairs with them.
- The repository depends on no Android logging API directly beyond the injected logger seam,
  keeping `core-model` types framework-free.

## 11. Testing Strategy

Unit tests in `core-data/src/test` (JUnit, Truth/kotlin-test, coroutines-test). The `AuthApi`
is faked (a hand-written fake or a MockK stub returning canned `SessionStartResponse`s) so
this ticket tests **branching**, not transport (transport is AND-027's MockWebServer suite).

Branch/mapping tests (the acceptance core; branching follows the corrected
`!auth_required && session_id` gate):
- `auth_required=true, challenge_id="chl_1", required_factors=["totp"], session_id=null` →
  `Success(MfaRequired("chl_1", [Totp]))`.
- `auth_required=true, challenge_id="chl_1", required_factors=["totp","sms","email"]` →
  factors map to `[Totp, Sms, Email]` in order.
- `auth_required=true, challenge_id="chl_1", required_factors=["totp","webauthn"]` →
  `[Totp, Unknown("webauthn")]` (unknown retained).
- `auth_required=false, session_id="ses_1", required_factors=[]` → `Success(Authenticated)`.
- `auth_required=false, session_id=null` (no session issued) but `challenge_id="chl_1"`
  present → `Success(MfaRequired("chl_1", ...))` (only `!auth_required && session_id`
  authenticates; absent `session_id` does not authenticate).
- `auth_required=true, required_factors=["totp"], challenge_id=null, session_id=null` →
  `Failure(status=200, code="malformed_mfa")`.
- `auth_required=true, challenge_id="chl_1", required_factors=[]` → `MfaRequired("chl_1", [])`
  (a challenge_id with empty factors is still a challenge; the MFA flow refines factors).

Failure-passthrough tests (fake `AuthApi` throws):
- `HttpException(401)` → `ApiResult.Failure(ApiError(status=401, ...))` (via AND-015 mapping
  seam), unchanged by `flatMap`.
- `SocketTimeoutException` → `ApiResult.NetworkError(isTimeout=true)`.
- generic `IOException` → `ApiResult.NetworkError(isTimeout=false)`.
- `CancellationException` thrown by the fake → re-thrown (asserted via `assertFailsWith`).

Request-shape test (one MockWebServer test, complementing AND-027):
- `login("alice","pw")` issues `POST /ui/session/start` with body
  `{"challenge_context":{"username":"alice","password":"pw"}}` (recorded request asserted).

Security test:
- with the OkHttp logging interceptor attached, a captured log of a `login()` call does
  **not** contain the password or `challenge_id` substring.

DI smoke test:
- Hilt provides `AuthRepository` bound to `AuthRepositoryImpl` (compile-time + a small
  `@HiltAndroidTest` or component test).

## 12. Dependencies & Sequencing

- **Requires (blocking):**
  - **AND-027** — `AuthApi.sessionStart` + `SessionStartRequest/Response` DTOs must exist
    and be MockWebServer-verified.
  - **AND-018** — `ApiResult`, `ApiError`, `apiCall`, `flatMap` must exist in `core-model`.
- **Strongly related (should be landed for end-to-end correctness, not strictly compile-time
  blocking):** AND-011 (cookie jar persists the session), AND-012 (CSRF header), AND-013
  (401 refresh), AND-009 (timeouts/logging), AND-015 (`detail` → `ApiError`). `login()`
  compiles and unit-tests without them via the faked `AuthApi`, but real-host behavior
  depends on them.
- **Enables / blocks:** AND-029 (`getMe()` after `Authenticated`), AND-031
  (`LoginViewModel` consuming `LoginResult`), AND-047.
- **Sequencing:** Land after AND-027 and AND-018; before AND-029, AND-031, AND-047. Freeze
  the `LoginResult`/`MfaFactor` shape and notify the AND-031 owner once merged.

## 13. Risks & Open Questions

- **R1 — Branch signal ambiguity.** *(Resolved during review.)* The web reference
  (`src/pages/Login.tsx:145`) gates "login complete" on `!auth_required && session_id`, then
  falls through to the MFA path. We adopt that exact gate: `Authenticated` requires
  `auth_required == false` **and** a non-blank `session_id`; everything else with a
  `challenge_id` is `MfaRequired`; a missing `challenge_id` in the non-authenticated case is
  `malformed_mfa`. `required_factors` is no longer part of the authenticate/MFA decision (it
  only populates `MfaRequired.factors`). Verified against `components.schemas.UiSessionStartResp`.
- **R2 — `challenge_id` field name/casing.** *(Verified.)* `components.schemas.UiSessionStartResp`
  uses snake_case `challenge_id` (nullable string), `auth_required` (boolean, required),
  `required_factors` (string[]), `session_id` (nullable string). The Moshi `@Json(name=...)`
  mappings in AND-027 must match these exact names — confirmed correct as written.
- **Q1 — 401 disambiguation (credentials vs. expired session).** *(Corroborated by the web
  reference.)* AND-013's authenticator must NOT loop `session/refresh` on a credentials 401 from
  `session/start` (there is no session to refresh). The web client encodes exactly this rule:
  `src/api/client.ts:194-203` refreshes+retries a 401 **only** when `isAuthenticated`, and throws
  an unauthenticated 401 straight to the caller. Android equivalent: gate AND-013's refresh on the
  presence of an existing session (auth state / cookie), or exclude `session/start` from refresh.
  Remaining open item is purely an AND-013 implementation detail (how it detects "already
  authenticated"), not a backend-contract unknown.
- **Q2 — Multi-factor selection.** `required_factors` may list several factors. This ticket
  returns the full ordered list; whether the user must satisfy *all* or *one* is decided by
  the MFA flow tickets, not here. Documented in `LoginResult.MfaRequired` KDoc.
- **Q3 — Does `session/start` ever return user data inline on `Authenticated`?** *(Largely
  resolved.)* `UiSessionStartResp` carries only `auth_required`/`challenge_id`/
  `required_factors`/`session_id` — **no user identity fields**. The web client always calls
  `getMe()` after the authenticated branch (`src/pages/Login.tsx:147`). So AND-029's
  `getMe()` is still required; `session_id` from start is not surfaced through `LoginResult`
  in this ticket (it only drives the branch decision).

## 14. Acceptance Criteria

1. `interface AuthRepository` with `suspend fun login(username, password):
   ApiResult<LoginResult>` exists in `com.testlogon.android.core.data.auth`, bound via Hilt
   to `AuthRepositoryImpl`.
2. `sealed interface LoginResult { Authenticated; MfaRequired(challengeId, factors) }` and
   `MfaFactor` (Totp/Sms/Email/Unknown) exist in `com.testlogon.android.core.model.auth`.
3. `login()` calls `POST /ui/session/start` with body
   `{"challenge_context":{"username","password"}}` (asserted via MockWebServer recorded
   request).
4. **Both branches return correct typed results for representative responses (tested):**
   an MFA response (`auth_required=true` + `challenge_id`) → `Success(MfaRequired(challengeId,
   factors))`; an authenticated response (`auth_required=false` + non-blank `session_id`) →
   `Success(Authenticated)` — per the Section 11 table and the `!auth_required && session_id`
   gate.
5. Unknown `required_factors` entries map to `MfaFactor.Unknown(raw)` and are retained.
6. A non-authenticated response with blank/missing `challenge_id` → `Failure(code="malformed_mfa")`,
   not a crash and not `Authenticated`.
7. Transport/HTTP failures pass through unchanged: `IOException`/timeout → `NetworkError`;
   HTTP error → `Failure(ApiError)`; `CancellationException` re-thrown.
8. No credential or `challenge_id` value appears in logs for a `login()` call (security
   test green).
9. `./gradlew :core-data:test` (and `:core-model:test`) green; ktlint/detekt (AND-005) pass.

## 15. Definition of Done

- `AuthRepository`/`AuthRepositoryImpl`, `LoginResult`, `MfaFactor`, and the Hilt binding are
  implemented, compile, and are merged to `android-port`.
- Unit tests cover every branch and failure-passthrough case in Section 11 and pass via
  `./gradlew :core-data:test`; the MockWebServer request-shape and no-PII-logging tests pass.
- Public types and the branching rule (Section 3.4) are documented in KDoc, including the
  corrected `!auth_required && session_id` ⇒ Authenticated gate and the all-vs-one factor
  note (Q2).
- No Retrofit/OkHttp types leak through the `AuthRepository` interface (verified by
  inspecting the interface signature; only `core-model` types appear).
- ktlint/detekt (AND-005) pass on new files; code reviewed.
- AND-029 and AND-031 owners notified that `LoginResult`/`MfaFactor` is frozen for
  consumption; open questions Q1–Q3 either resolved against `/openapi.json` or filed as
  follow-ups before AND-031 integration.

## 16. Citations & Assumption Audit

Sources are cited as: OpenAPI `METHOD /path` / `components.schemas.<Name>` (from
`reference/openapi.index.txt` and `reference/openapi.pretty.json`), or frontend paths under
`reference/src/`. "framework ref" labels framework-choice citations.

1. **Endpoint is `POST /ui/session/start`.** VERDICT: Verified.
   Source: OpenAPI `POST /ui/session/start` (`op=ui_session_start_ui_session_start_post`,
   `req=UiSessionStartReq`, `resp=200:UiSessionStartResp;422:HTTPValidationError`); frontend
   `src/api/endpoints/auth.ts: sessionStart` (`api.post<SessionStartResp>("/ui/session/start", body)`).
2. **Request body is `{ challenge_context: { username, password } }`.** VERDICT: Verified
   (call site) / Unverified-assumption (typing of inner object).
   Source: frontend `src/pages/Login.tsx:138-143` posts exactly `challenge_context: { username,
   password }`. However `components.schemas.UiSessionStartReq.challenge_context` is a free-form
   object (`additionalProperties: true`) and `src/api/types.ts: SessionStartReq` types it as
   `Record<string, unknown>`. The strongly-typed `ChallengeContext(username, password)` is a
   reasonable Android-side modeling assumption, not a backend-enforced schema.
3. **Response field names `auth_required`, `challenge_id`, `required_factors`.** VERDICT:
   Verified. Source: `components.schemas.UiSessionStartResp` (`auth_required` boolean, required;
   `challenge_id` string|null; `required_factors` string[]); frontend `src/api/types.ts:
   SessionStartResp`.
4. **Response also includes `session_id` (string|null).** VERDICT: Corrected (was omitted in
   the original spec DTO and contract). Source: `components.schemas.UiSessionStartResp.session_id`
   (anyOf string|null); `src/api/types.ts: SessionStartResp.session_id?`.
5. **Branching: Authenticated iff `!auth_required && session_id`.** VERDICT: Corrected (original
   spec used `auth_required && required_factors.isNotEmpty()`). Source: frontend
   `src/pages/Login.tsx:145` (`if (!resp.auth_required && resp.session_id) { ... login complete ... }`),
   then MFA fallthrough using `challenge_id` + `required_factors` (`:154-156`).
6. **`required_factors` strings include `"totp"`, `"sms"`, `"email"` (plus `recovery`).**
   VERDICT: Verified. Source: frontend `src/pages/Login.tsx:41,161-163,400-406` (`MfaMethod =
   "totp" | "sms" | "email" | "recovery"`, selection from `required_factors`). Mapping unknown
   factors to `MfaFactor.Unknown(raw)` is an Android forward-compat choice (Unverified-assumption
   that other factor strings exist, but harmless).
7. **CSRF: `ui_csrf` cookie echoed as `X-CSRF-Token` header.** VERDICT: Verified. Source:
   frontend `src/api/client.ts:168-170` (`const csrf = getCookie("ui_csrf"); headers.set("X-CSRF-Token", csrf)`).
8. **Session rides on cookies (`credentials: include`).** VERDICT: Verified. Source:
   `src/api/client.ts:183,220` (`credentials: "include"`); cookie jar persistence is the Android
   analog (AND-011).
9. **401 → single `session/refresh` + retry, but ONLY when already authenticated.** VERDICT:
   Verified (web transport behavior), with an important nuance. Source: `src/api/client.ts:122`
   (`refreshSession` POSTs `/ui/session/refresh`) and the 401 block (`:194-221`). The client
   refreshes+retries once **only if** `useAuthStore.getState().isAuthenticated` is true; an
   **unauthenticated** 401 (e.g. wrong password on the login page) is thrown straight to the
   caller without refresh (`:196-203`). This directly corroborates the Android plan: a
   credentials 401 from `session/start` (no prior session) must NOT loop through refresh.
   OpenAPI `POST /ui/session/refresh` exists (`resp=200`; index line 1847).
10. **422 validation error shape: `detail: ValidationError[]` with `loc`, `msg`, `type`.**
    VERDICT: Verified. Source: `components.schemas.HTTPValidationError` →
    `components.schemas.ValidationError` (`loc`, `msg`, `type` all required). The original spec's
    422 example omitted `type` — corrected in Section 5.
11. **401 for bad credentials (status), with FastAPI `detail` message.** VERDICT: Partially
    verified / message-string Unverified-assumption. The **401 status** for an unauthenticated
    request is corroborated by the web transport: `src/api/client.ts:194-203` constructs and
    throws an `ApiError(401, normalizeErrorDetail(body.detail, "Authentication required"), ...)`
    for a 401 when not authenticated. However, OpenAPI declares only `200`/`422` for
    `POST /ui/session/start` (index line 1848), so the 401 is not in the documented schema, and
    the **exact `detail` string** (e.g. "Invalid username or password") is NOT confirmed by any
    source — it is assumed. The Login page renders `err.detail || "Invalid credentials. Please
    try again."` (`src/pages/Login.tsx:178-186`) for any thrown error, so the UI copy does not
    depend on the precise server string.
12. **No user identity returned inline on Authenticated; `getMe()` required.** VERDICT: Verified.
    Source: `UiSessionStartResp` has no identity fields; `src/pages/Login.tsx:147` calls
    `getMe()` after the authenticated branch. `GET /ui/me` exists (OpenAPI `GET /ui/me`,
    `op=ui_me_ui_me_get`; `src/api/types.ts: MeResp { user_sub, session_id, ip }`).
13. **MFA sub-flow endpoints keyed by `challenge_id`.** VERDICT: Verified. Source: OpenAPI
    `POST /ui/mfa/totp/verify` (`TotpVerifyReq`), `POST /ui/mfa/sms/begin|verify`,
    `POST /ui/mfa/email/begin|verify`, `POST /ui/session/finalize` (`UiSessionFinalizeReq`);
    `src/api/types.ts: TotpVerifyReq.challenge_id`, `SessionFinalizeReq.challenge_id`. (Out of
    scope for this ticket; cited for context.)
14. **Stack: Kotlin/Coroutines, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Hilt, minSdk 24.**
    VERDICT: Unverified-assumption (framework ref — project convention, not derivable from the
    backend/frontend sources). These match the repository-wide Android stack stated in sibling
    AND tickets; no authoritative source in this reference set.

### Corrections made

- **C1 (DTO):** Added `session_id: String?` to `SessionStartResponse` — present in
  `UiSessionStartResp` and required by the corrected branch logic (Sections 4, 5; citation 4).
- **C2 (branch rule):** Changed the Authenticated signal from "`auth_required==false` or empty
  `required_factors`" to the web client's `!auth_required && session_id` gate; `MfaRequired` now
  keys off a non-blank `challenge_id`, and `required_factors` no longer participates in the
  authenticate/MFA decision (Sections 1, 3.2, 3.4, 4 impl, 5, 11, 13-R1, 14; citation 5).
- **C3 (422 shape):** Added the required `type` field to the `ValidationError` example
  (Section 5; citation 10).
- **C4 (401 claim):** Marked the 401 status and message as an unverified assumption since the
  OpenAPI documents only 200/422 for this endpoint (Section 5; citation 11).
- **C5 (R2 / Q3):** Promoted R2 (field casing) and Q3 (inline user data) from open questions to
  verified resolutions against the schema (citations 3, 4, 12).
- **C6 (401 evidence, re-review 2026-06-06):** Strengthened citations 9 and 11 and OA2/Q1 using
  `src/api/client.ts:194-203`: the web client refreshes+retries a 401 **only** when already
  authenticated and throws an unauthenticated 401 (wrong-password case) straight through without
  refresh. This corroborates both the 401 *status* on a credentials failure and the "no refresh
  loop on `session/start` credentials 401" requirement (Q1). The exact `detail` message string
  remains unverified (Sections 5, 7, 13-Q1, 16 citations 9/11, OA2).

### Open assumptions

- **OA1 — `challenge_context` inner typing.** Backend accepts a free-form object; `{username,
  password}` is confirmed only from the web call site. If the server later requires extra fields
  (e.g. device hints), the typed `ChallengeContext` must extend. (citation 2)
- **OA2 — Credentials-failure HTTP status/message.** The **401 status** is now corroborated by
  the web transport (`src/api/client.ts:194-203` throws `ApiError(401, ...)` for an
  unauthenticated 401), so it is no longer a pure assumption; what remains **unverified** is the
  exact `detail` message string, which is not in OpenAPI (endpoint documents only 200/422, index
  line 1848). Confirm the message against the live dev host if any UI keys off the literal text;
  do not branch on the string. (citation 11)
- **OA3 — Whether an Authenticated `session/start` can ever return `auth_required=false` with a
  null `session_id`.** The schema permits it (both optional/nullable). Spec treats null
  `session_id` as non-authenticated; if the backend can complete a session without echoing
  `session_id`, this rule would misclassify it as MFA/malformed — verify against the dev host.
- **OA4 — Android framework versions (citation 14).** Not verifiable from this reference set;
  carried as project convention.
- **OA5 — `MfaFactor.Unknown` factor strings.** No factor beyond totp/sms/email/recovery is
  observed in the sources; `Unknown(raw)` is defensive forward-compat, not evidence such factors
  exist. (citation 6)

## 17. Test Plan

All cases live in `core-data/src/test` (JVM unit) unless marked otherwise; the `AuthApi` is
faked/stubbed so these test branching, not transport (transport = AND-027). MockWebServer and
instrumented cases are explicitly typed. "Traces: AC-#" refers to Section 14 acceptance criteria.

- **TC-AND-028-01 — Happy path: MFA required.** Type: unit.
  Preconditions: fake `AuthApi.sessionStart` returns `{auth_required:true,
  challenge_id:"chl_1", required_factors:["totp","sms"], session_id:null}`.
  Steps: call `repo.login("alice","pw")`.
  Expected: `ApiResult.Success(LoginResult.MfaRequired("chl_1", [Totp, Sms]))`; factor order
  preserved. Traces: AC-2, AC-4.
- **TC-AND-028-02 — Happy path: fully authenticated.** Type: unit.
  Preconditions: fake returns `{auth_required:false, session_id:"ses_1",
  required_factors:[]}`.
  Steps: call `login`.
  Expected: `ApiResult.Success(LoginResult.Authenticated)`. Traces: AC-4.
- **TC-AND-028-03 — Authenticated gate requires `session_id`.** Type: unit.
  Preconditions: fake returns `{auth_required:false, session_id:null, challenge_id:"chl_1",
  required_factors:["totp"]}` (not authenticated despite `auth_required:false`).
  Steps: call `login`.
  Expected: `Success(MfaRequired("chl_1", [Totp]))` (only `!auth_required && session_id`
  authenticates). Traces: AC-4, AC-6.
- **TC-AND-028-04 — Unknown factor retained.** Type: unit.
  Preconditions: fake returns `{auth_required:true, challenge_id:"chl_1",
  required_factors:["totp","webauthn"]}`.
  Steps: call `login`.
  Expected: `MfaRequired("chl_1", [Totp, Unknown("webauthn")])` — unknown not dropped.
  Traces: AC-5.
- **TC-AND-028-05 — Malformed MFA (no challenge_id).** Type: unit.
  Preconditions: fake returns `{auth_required:true, required_factors:["totp"],
  challenge_id:null, session_id:null}`.
  Steps: call `login`.
  Expected: `ApiResult.Failure(ApiError(status=200, code="malformed_mfa", message="MFA
  required but no challenge_id returned"))`; no exception; not `Authenticated`. Traces: AC-6.
- **TC-AND-028-06 — Challenge with empty factors.** Type: unit.
  Preconditions: fake returns `{auth_required:true, challenge_id:"chl_1",
  required_factors:[]}`.
  Steps: call `login`.
  Expected: `Success(MfaRequired("chl_1", []))` (a challenge_id is the MFA signal; factors
  refined downstream). Traces: AC-4, AC-6.
- **TC-AND-028-07 — Request shape on the wire.** Type: contract/MockWebServer.
  Preconditions: MockWebServer enqueues a 200 `{auth_required:false, session_id:"ses_1"}`;
  real Retrofit `AuthApi` wired to the mock base URL.
  Steps: call `login("alice","pw")`; read `takeRequest()`.
  Expected: method `POST`, path `/ui/session/start`, body equals
  `{"challenge_context":{"username":"alice","password":"pw"}}`, `Content-Type:
  application/json`. Traces: AC-3.
- **TC-AND-028-08 — HTTP error passthrough (422 validation).** Type: contract/MockWebServer.
  Preconditions: MockWebServer enqueues `422` with body `{"detail":[{"loc":["body",
  "challenge_context","username"],"msg":"field required","type":"missing"}]}`.
  Steps: call `login`.
  Expected: `ApiResult.Failure(ApiError(status=422, message="field required"))` per AND-015;
  `flatMap` does not alter it; no `LoginResult` produced. Traces: AC-7.
- **TC-AND-028-09 — Credentials failure passthrough.** Type: contract/MockWebServer.
  Preconditions: MockWebServer enqueues `401` with `{"detail":"Invalid username or
  password"}` (401 status corroborated by `src/api/client.ts:194-203`; exact `detail` string
  is the OA2 assumption — the test asserts status and passthrough, not the literal message).
  Steps: call `login`.
  Expected: `ApiResult.Failure(ApiError(status=401, message="Invalid username or
  password"))`; not retried into Authenticated; no refresh loop. Traces: AC-7.
- **TC-AND-028-10 — Offline / flaky dev host → NetworkError.** Type: unit.
  Preconditions: fake `AuthApi` throws `SocketTimeoutException` (then a separate run throws
  generic `IOException`).
  Steps: call `login` for each.
  Expected: `ApiResult.NetworkError(isTimeout=true)` for the timeout;
  `NetworkError(isTimeout=false)` for the IOException; no exception escapes. Traces: AC-7.
- **TC-AND-028-11 — Cancellation propagates.** Type: unit.
  Preconditions: fake `AuthApi` throws `CancellationException`.
  Steps: `assertFailsWith<CancellationException> { login(...) }`.
  Expected: re-thrown unchanged (not folded into `NetworkError`). Traces: AC-7.
- **TC-AND-028-12 — No PII in logs (security).** Type: contract/MockWebServer + log capture.
  Preconditions: OkHttp logging interceptor attached at BASIC; password `"hunter2"` and a
  response containing `challenge_id:"chl_secret"`.
  Steps: call `login("alice","hunter2")`; capture emitted log lines.
  Expected: captured logs contain neither `"hunter2"` nor `"chl_secret"`; no request/response
  body for `session/start`. Traces: AC-8.
- **TC-AND-028-13 — Interface leaks no transport types (security/architecture).** Type: unit
  (reflection) / compile check.
  Preconditions: `AuthRepository` interface.
  Steps: reflect on `login`'s parameter and return types.
  Expected: only `core-model` types (`String`, `ApiResult<LoginResult>`); no Retrofit/OkHttp/
  Moshi types in the signature. Traces: AC-1, DoD.
- **TC-AND-028-14 — Hilt provides `AuthRepository`.** Type: instrumented/e2e
  (`@HiltAndroidTest`) or component test.
  Preconditions: app/test Hilt graph with `AuthDataModule` installed.
  Steps: inject `AuthRepository`.
  Expected: resolves to an `AuthRepositoryImpl` singleton; graph compiles. Traces: AC-1, AC-9.

Accessibility note: this ticket produces no UI, so no Compose-UI / a11y cases apply here;
accessibility of error/MFA copy is covered by AND-031 (its stable `code`/`factor` values are
asserted indirectly via TC-04/05).

### Coverage matrix

| AC (Section 14) | Covered by |
| --- | --- |
| AC-1 (interface + Hilt binding) | TC-13, TC-14 |
| AC-2 (LoginResult / MfaFactor types) | TC-01 |
| AC-3 (POST body shape) | TC-07 |
| AC-4 (both branches typed correctly) | TC-01, TC-02, TC-03, TC-06 |
| AC-5 (unknown factor retained) | TC-04 |
| AC-6 (malformed_mfa, not crash/Authenticated) | TC-03, TC-05, TC-06 |
| AC-7 (transport/HTTP passthrough; cancellation) | TC-08, TC-09, TC-10, TC-11 |
| AC-8 (no PII in logs) | TC-12 |
| AC-9 (tests green / lint) | TC-14 (+ all unit/contract TCs constitute the suite) |
