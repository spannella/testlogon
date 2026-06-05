---
id: AND-028
title: "AuthRepository: session start + branching"
milestone: M1
epic: E04
priority: P0
size: M
status: draft
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
  proceed to `getMe()` (AND-029).
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
   - `Authenticated` — no further factors required (`auth_required == false`, or
     `required_factors` empty).
   - `MfaRequired(challengeId: String, factors: List<MfaFactor>)` — additional factors
     required (`auth_required == true` with a non-empty `required_factors`).
3. `login()` calls `AuthApi.sessionStart(SessionStartRequest(ChallengeContext(username,
   password)))` inside `apiCall { }` (AND-018) so transport failures fold to
   `ApiResult.NetworkError` and HTTP error bodies fold to `ApiResult.Failure(ApiError)`.
4. **Branching rule** (deterministic, single source of truth):
   - If the call succeeds and `auth_required == true` **and** `required_factors` is non-empty
     **and** `challenge_id` is non-null/non-blank → `Authenticated` is **not** returned;
     return `ApiResult.Success(MfaRequired(challengeId, factors))`.
   - If `auth_required == false` (or `required_factors` is empty / absent) → return
     `ApiResult.Success(Authenticated)`.
   - If `auth_required == true` but `challenge_id` is missing/blank → treat as a malformed
     server response: return `ApiResult.Failure(ApiError(status=200, code="malformed_mfa",
     message="MFA required but no challenge_id returned"))`. (Do not crash; do not return
     `Authenticated`.)
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
        val mfaNeeded = authRequired && requiredFactors.isNotEmpty()
        return when {
            mfaNeeded && !challengeId.isNullOrBlank() ->
                ApiResult.Success(
                    LoginResult.MfaRequired(
                        challengeId = challengeId,
                        factors = requiredFactors.map(MfaFactor::fromWire),
                    ),
                )
            mfaNeeded -> // auth_required but no usable challenge_id
                ApiResult.Failure(
                    ApiError(
                        status = 200,
                        code = "malformed_mfa",
                        message = "MFA required but no challenge_id returned",
                    ),
                )
            else -> ApiResult.Success(LoginResult.Authenticated)
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

Representative success — **MFA required**:

```json
{
  "auth_required": true,
  "challenge_id": "chl_01HXYZ...",
  "required_factors": ["totp", "sms"]
}
```
→ `ApiResult.Success(LoginResult.MfaRequired("chl_01HXYZ...", [Totp, Sms]))`

Representative success — **fully authenticated** (session cookies set; no factors):

```json
{
  "auth_required": false,
  "challenge_id": null,
  "required_factors": []
}
```
→ `ApiResult.Success(LoginResult.Authenticated)`

Error responses are folded by `apiCall`/AND-015 into `ApiResult.Failure(ApiError)`:

- **401 Unauthorized** (bad credentials) — FastAPI `detail`:
  ```json
  { "detail": "Invalid username or password" }
  ```
  → `Failure(ApiError(status=401, message="Invalid username or password"))`.
  (Note: AND-013 only auto-refreshes 401s on *session* expiry; a credentials 401 from
  `session/start` is surfaced as-is, not retried — see Section 7.)
- **422 Unprocessable Entity** (validation) — `detail` as list:
  ```json
  { "detail": [ { "loc": ["body","challenge_context","username"], "msg": "field required" } ] }
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

Branch/mapping tests (the acceptance core):
- `auth_required=true, challenge_id="chl_1", required_factors=["totp"]` →
  `Success(MfaRequired("chl_1", [Totp]))`.
- `auth_required=true, required_factors=["totp","sms","email"]` → factors map to
  `[Totp, Sms, Email]` in order.
- `required_factors=["totp","webauthn"]` → `[Totp, Unknown("webauthn")]` (unknown retained).
- `auth_required=false, required_factors=[]` → `Success(Authenticated)`.
- `auth_required=false` but a stray `challenge_id` present → still `Authenticated`
  (auth_required is authoritative).
- `auth_required=true, required_factors=["totp"], challenge_id=null` → `Failure(status=200,
  code="malformed_mfa")`.
- `auth_required=true, required_factors=[]` → `Authenticated` (no factors ⇒ not MFA).

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

- **R1 — Branch signal ambiguity.** The backend may sometimes set `auth_required=true` with
  an empty `required_factors`, or `false` with factors present. Mitigation: `auth_required`
  is treated as authoritative for *whether* MFA is needed, but MFA is only triggered when
  factors are also non-empty (fail-open to `Authenticated` would be wrong; we require both).
  Confirm against `/openapi.json` and `frontend/src/api/endpoints` before merge.
- **R2 — `challenge_id` field name/casing.** Spec assumes snake_case `challenge_id`. If the
  real schema differs (e.g. `challengeId`), the Moshi `@Json(name=...)` in AND-027 must
  match; verify against `/openapi.json`.
- **Q1 — 401 disambiguation (credentials vs. expired session).** AND-013's authenticator
  must NOT loop `session/refresh` on a credentials 401 from `session/start` (there is no
  session to refresh). Open: confirm AND-013 scopes refresh to endpoints other than
  `session/start`, or that a no-cookie 401 short-circuits refresh.
- **Q2 — Multi-factor selection.** `required_factors` may list several factors. This ticket
  returns the full ordered list; whether the user must satisfy *all* or *one* is decided by
  the MFA flow tickets, not here. Documented in `LoginResult.MfaRequired` KDoc.
- **Q3 — Does `session/start` ever return user data inline on `Authenticated`?** Assumed no;
  caller fetches `GET /ui/me` (AND-029). Confirm; if it does, AND-029 may short-circuit.

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
   an MFA response → `Success(MfaRequired(challengeId, factors))`; a no-factor response →
   `Success(Authenticated)` — per the Section 11 table.
5. Unknown `required_factors` entries map to `MfaFactor.Unknown(raw)` and are retained.
6. `auth_required=true` with blank/missing `challenge_id` → `Failure(code="malformed_mfa")`,
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
  "auth_required + factors both required" rule and the all-vs-one factor note (Q2).
- No Retrofit/OkHttp types leak through the `AuthRepository` interface (verified by
  inspecting the interface signature; only `core-model` types appear).
- ktlint/detekt (AND-005) pass on new files; code reviewed.
- AND-029 and AND-031 owners notified that `LoginResult`/`MfaFactor` is frozen for
  consumption; open questions Q1–Q3 either resolved against `/openapi.json` or filed as
  follow-ups before AND-031 integration.
