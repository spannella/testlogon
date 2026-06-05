---
id: AND-034
title: "TOTP verify flow"
milestone: M1
epic: E05
priority: P0
size: M
status: draft
depends_on: [AND-033, AND-028, AND-018]
blocks: [AND-039, AND-047]
---

# AND-034 — TOTP verify flow

## 1. Overview & Goal

This ticket adds the TOTP (authenticator-app) verification step to the cookie-based
authentication MFA flow. It introduces a repository method
`MfaRepository.verifyTotp(challengeId, code)` that calls the FastAPI endpoint
`POST /ui/mfa/totp/verify`, maps the response into a typed domain result `MfaVerifyResult`,
and **surfaces the remaining factors** so the caller can decide whether the challenge is
complete (proceed to `session/finalize`) or whether further factors (SMS, email) are still
required.

The TOTP factor has no `begin` step — unlike SMS (AND-035) and email (AND-036), the user's
authenticator app already produces a code offline. Therefore this ticket owns only the
*verify* call: submit the 6-digit code against the in-progress `challenge_id` (from
AuthRepository's `MfaRequired` result, AND-028) and interpret the outcome.

Scope is the repository seam plus its domain result type, behind an interface, returned
inside `ApiResult<MfaVerifyResult>` (AND-018). All branching — interpreting whether the
challenge is now complete vs. has remaining factors, and distinguishing a wrong/expired code
from a transport error — lives here so the MFA ViewModel (AND-039) never touches Retrofit
types and is unit-testable against a fake. The raw `AuthApi.verifyTotp` Retrofit endpoint
and its DTOs are owned and MockWebServer-tested by AND-033; this ticket consumes that
endpoint and the `ApiResult`/`apiCall` machinery from AND-018.

## 2. Context & References

- **Module:** `core-data` (auth/MFA data sources + repositories) with domain models in
  `core-model`. Repository interface in `com.testlogon.android.core.data.auth`; domain
  result types in `com.testlogon.android.core.model.auth`. DTOs live with `AuthApi` in
  `com.testlogon.android.core.network.auth` (AND-033).
- **Depends on (blocking):**
  - **AND-033** — `AuthApi` MFA methods (`totp/verify`, `sms/begin+verify`,
    `email/begin+verify`, `recovery/{factor}`) and the `MfaVerifyResp` / request DTOs. This
    ticket calls only `verifyTotp`.
  - **AND-028** — `AuthRepository.login()` produces `LoginResult.MfaRequired(challengeId,
    factors)`; the `challengeId` consumed here originates there, and `MfaFactor` is reused
    for the remaining-factor list.
  - **AND-018** — `ApiResult<T>`, `ApiError`, `apiCall { }`, and `flatMap` for folding
    transport/HTTP failures and applying the branch mapping.
- **Blocks:**
  - **AND-039** — MFA screen + ViewModel that drives the OTP input (AND-020) and calls
    `verifyTotp`, mapping `MfaVerifyResult` to navigation (finalize vs. next factor) + errors.
  - **AND-047** — full auth end-to-end flow depends on TOTP verification.
- **Related (not blocking):** AND-011 (persistent cookie jar — the challenge/session cookies
  set by `session/start` ride this call), AND-012 (CSRF interceptor echoes `ui_csrf` as
  `X-CSRF-Token`), AND-013 (401 → `session/refresh` once → retry), AND-015 (FastAPI `detail`
  → `ApiError`), AND-009 (~20s timeouts, redacted logging), AND-020 (OTP input composable),
  AND-035/AND-036 (sibling SMS/email verify, same `MfaVerifyResult` shape).
- **Stack:** Kotlin 2.0.21, Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Hilt
  (KSP). minSdk 24, JDK 17.
- **Backend:** FastAPI dev host `http://18.222.237.167:8000` (plaintext, unreliable).
  OpenAPI at `/openapi.json`. Web reference flow in `frontend/src/api/endpoints/*.ts`,
  shared types in `frontend/src/api/types.ts`.
- **Auth/MFA flow (authoritative):** `POST /ui/session/start` →
  `{auth_required, challenge_id, required_factors[]}` → `/ui/mfa/{totp|sms|email}/verify`
  (with `challenge_id`) → `POST /ui/session/finalize` → `GET /ui/me`. Session rides on
  cookies + a `ui_csrf` cookie echoed as `X-CSRF-Token`.

## 3. Functional Requirements

1. Define a repository interface seam in `core-data`:
   `interface MfaRepository { suspend fun verifyTotp(challengeId: String, code: String):
   ApiResult<MfaVerifyResult> }`. (Sibling SMS/email methods, AND-035/AND-036, extend the
   same interface; this ticket lands `verifyTotp` and the shared `MfaVerifyResult`.)
2. Define the domain result `sealed interface MfaVerifyResult` in `core-model` with exactly
   two success variants:
   - `Completed` — the challenge is satisfied (no factors remain); the caller may proceed to
     `POST /ui/session/finalize`.
   - `FactorsRemaining(factors: List<MfaFactor>)` — at least one additional factor is still
     required; the caller drives the next factor's verify flow keyed by the same
     `challengeId`.
3. `verifyTotp()` calls `AuthApi.verifyTotp(MfaTotpVerifyRequest(challengeId, code))` inside
   `apiCall { }` (AND-018) so transport failures fold to `ApiResult.NetworkError` and HTTP
   error bodies fold to `ApiResult.Failure(ApiError)`.
4. **Branching rule** (deterministic, single source of truth) applied to a successful
   `MfaVerifyResp`:
   - If `verified == true` **and** `remaining_factors` is empty (and `auth_required` is
     false/absent) → `ApiResult.Success(MfaVerifyResult.Completed)`.
   - If `verified == true` **and** `remaining_factors` is non-empty → `ApiResult.Success(
     MfaVerifyResult.FactorsRemaining(factors))`, mapping factor strings via
     `MfaFactor.fromWire` (AND-028).
   - If `verified == false` → treat as a rejected code: `ApiResult.Failure(ApiError(
     status=200, code="totp_invalid", message=<server detail or default>))`. A 200 with
     `verified=false` MUST NOT be reported as success. (Servers that return HTTP 4xx for a
     bad code are handled in Section 7; both shapes resolve to `code="totp_invalid"`.)
5. The `code` argument is the user-entered 6-digit TOTP; the repository trims whitespace and
   passes it verbatim. It does **not** validate length/format — input validation is owned by
   the OTP composable / ViewModel (AND-020/AND-039). (A blank `code` short-circuits to a
   `Failure(code="totp_invalid")` without a network call — see Section 7.)
6. The remaining-factor list reuses `MfaFactor` (AND-028); unknown factor strings map to
   `MfaFactor.Unknown(raw)` and are retained, never dropped (forward-compatibility).
7. The method MUST NOT throw for expected outcomes (network down, 401, 422, wrong code); all
   such cases are encoded in `ApiResult`. `CancellationException` propagates unchanged (per
   AND-018 `apiCall`).
8. The repository is stateless beyond the injected `AuthApi`; `challengeId` is supplied per
   call by the caller (held in ViewModel memory, AND-039). No `challengeId` or `code` is
   persisted.

## 4. Technical Design

Package layout:
- `com.testlogon.android.core.model.auth` — `MfaVerifyResult` (+ reuses `MfaFactor` from
  AND-028).
- `com.testlogon.android.core.data.auth` — `MfaRepository`, `MfaRepositoryImpl`.
- DTOs live with `AuthApi` (AND-033) in `com.testlogon.android.core.network.auth`.

Domain result (in `core-model`, framework-free):

```kotlin
package com.testlogon.android.core.model.auth

/** Outcome of an MFA factor verification (shared by TOTP/SMS/email). */
sealed interface MfaVerifyResult {
    /** Challenge satisfied; no factors remain. Proceed to session/finalize. */
    data object Completed : MfaVerifyResult

    /** Factor accepted but [factors] still required; continue the MFA flow. */
    data class FactorsRemaining(
        val factors: List<MfaFactor>,
    ) : MfaVerifyResult
}
```

Wire DTOs (defined in AND-033 alongside `AuthApi`; shown for the contract this ticket
consumes):

```kotlin
@JsonClass(generateAdapter = true)
data class MfaTotpVerifyRequest(
    @Json(name = "challenge_id") val challengeId: String,
    val code: String,
)

@JsonClass(generateAdapter = true)
data class MfaVerifyResp(
    val verified: Boolean = false,
    @Json(name = "auth_required") val authRequired: Boolean = false,
    @Json(name = "remaining_factors") val remainingFactors: List<String> = emptyList(),
    val detail: String? = null,
)
```

`AuthApi` method consumed (from AND-033):

```kotlin
@POST("ui/mfa/totp/verify")
suspend fun verifyTotp(@Body body: MfaTotpVerifyRequest): MfaVerifyResp
```

Repository:

```kotlin
package com.testlogon.android.core.data.auth

interface MfaRepository {
    suspend fun verifyTotp(challengeId: String, code: String): ApiResult<MfaVerifyResult>
    // SMS/email verify methods added by AND-035 / AND-036.
}

class MfaRepositoryImpl @Inject constructor(
    private val api: AuthApi,
) : MfaRepository {

    override suspend fun verifyTotp(
        challengeId: String,
        code: String,
    ): ApiResult<MfaVerifyResult> {
        val trimmed = code.trim()
        if (trimmed.isEmpty()) {
            return ApiResult.Failure(
                ApiError(status = 0, code = "totp_invalid", message = "Enter your code"),
            )
        }
        return apiCall {
            api.verifyTotp(MfaTotpVerifyRequest(challengeId = challengeId, code = trimmed))
        }.flatMap { resp -> resp.toVerifyResult() }
    }

    private fun MfaVerifyResp.toVerifyResult(): ApiResult<MfaVerifyResult> = when {
        !verified -> ApiResult.Failure(
            ApiError(
                status = 200,
                code = "totp_invalid",
                message = detail ?: "Incorrect or expired code",
            ),
        )
        remainingFactors.isNotEmpty() || authRequired ->
            ApiResult.Success(
                MfaVerifyResult.FactorsRemaining(remainingFactors.map(MfaFactor::fromWire)),
            )
        else -> ApiResult.Success(MfaVerifyResult.Completed)
    }
}
```

Hilt binding (extend the existing auth data module, or co-locate with AuthRepository's):

```kotlin
@Module
@InstallIn(SingletonComponent::class)
abstract class MfaDataModule {
    @Binds @Singleton
    abstract fun bindMfaRepository(impl: MfaRepositoryImpl): MfaRepository
}
```

`flatMap` (AND-018) preserves `Failure`/`NetworkError` from `apiCall` unchanged and applies
the branch mapping only on `Success`, keeping the original transport/HTTP failure intact for
the ViewModel. The HTTP-level "bad code" case (server returns 4xx, Section 7) is normalized
to the same `code="totp_invalid"` by the AND-015 error mapper plus a small remap, so AND-039
has a single `code` to key its localized "incorrect code" copy off, regardless of whether the
backend signals via `verified=false` or an HTTP status.

## 5. API Contract

Single endpoint consumed: **`POST /ui/mfa/totp/verify`**.

Request body:

```json
{
  "challenge_id": "chl_01HXYZ...",
  "code": "123456"
}
```

Headers: `Content-Type: application/json`; cookies + `X-CSRF-Token` (`ui_csrf`) are added by
interceptors (AND-011/AND-012), not by this repository.

Representative success — **challenge complete** (only TOTP was required):

```json
{
  "verified": true,
  "auth_required": false,
  "remaining_factors": []
}
```
→ `ApiResult.Success(MfaVerifyResult.Completed)`

Representative success — **factor accepted, more required** (TOTP + SMS challenge):

```json
{
  "verified": true,
  "auth_required": true,
  "remaining_factors": ["sms"]
}
```
→ `ApiResult.Success(MfaVerifyResult.FactorsRemaining([Sms]))`

Representative **rejected code** (HTTP 200 with `verified=false`):

```json
{
  "verified": false,
  "detail": "Invalid authentication code"
}
```
→ `ApiResult.Failure(ApiError(status=200, code="totp_invalid", message="Invalid authentication code"))`

Error responses folded by `apiCall`/AND-015 into `ApiResult.Failure(ApiError)` and remapped:

- **400/401 bad-or-expired code** — some deployments signal a wrong code with an HTTP status
  and a `detail` string:
  ```json
  { "detail": "Invalid authentication code" }
  ```
  → `Failure(ApiError(status=400|401, message="Invalid authentication code"))`, remapped to
  `code="totp_invalid"`. Note: a *challenge*-expired/invalid 401 here is a credentials-class
  401, NOT a session-expiry 401, and must not loop through AND-013 refresh (Section 7).
- **422 Unprocessable Entity** (validation, e.g. missing `challenge_id`) — `detail` list:
  ```json
  { "detail": [ { "loc": ["body","code"], "msg": "field required" } ] }
  ```
  → `Failure(ApiError(status=422, message="field required"))` per AND-015 (distinct from
  `totp_invalid` — surfaced as a generic error, not "wrong code").
- **404 / 410 challenge not found or expired** → `Failure(ApiError(status=404|410,
  code="challenge_expired"))` so AND-039 can route back to login rather than re-prompt.
- **5xx / unreachable host / timeout** → `ApiResult.NetworkError`.

Endpoint reachability, verbs, paths, and DTO shapes are *owned and MockWebServer-tested by
AND-033*; this ticket asserts only the branch mapping on top of representative responses.

## 6. Data & State Management

- `MfaVerifyResult` and the reused `MfaFactor` are immutable value types, safe to carry in
  `StateFlow` (AND-039 holds `FactorsRemaining`/`Completed` in its `MfaUiState`).
- **No persistence in this ticket.** `challengeId` and `code` are *transient* — supplied per
  call, held only in ViewModel memory for the duration of the MFA flow; never written to Room
  or DataStore. The `code` is never retained after the call returns.
- The **session/challenge cookies** (and `ui_csrf`) are persisted by the OkHttp cookie jar
  (AND-011) as a side effect of the HTTP call; this repository does not read or write cookies.
- Persistent *auth state* (authenticated flag, `user_sub`) is **out of scope** and owned by
  AND-029; it changes only after `session/finalize` + `getMe()`, which follow a `Completed`
  result (driven by AND-039), not within this ticket.
- `MfaRepositoryImpl` is a `@Singleton` and stateless apart from the injected `AuthApi`.

## 7. Error Handling & Resilience

- **No retry.** `totp/verify` is a non-idempotent `POST` with side effects (consumes/advances
  the challenge, and TOTP codes are single-use); AND-016 retry/backoff applies to idempotent
  GETs only. A `NetworkError` is surfaced to the ViewModel, which offers a manual retry — but
  the user must enter a *fresh* code, because the prior code may have been consumed or have
  rotated.
- **Timeouts:** OkHttp ~20s (AND-009) against the flaky dev host; `SocketTimeoutException`
  folds to `ApiResult.NetworkError(isTimeout = true)` via AND-018, letting AND-039 show
  "server is slow" copy distinct from "you're offline".
- **Wrong/expired code:** both shapes — HTTP 200 `verified=false` and an HTTP 4xx with a
  `detail` — normalize to `ApiError(code="totp_invalid")`. AND-039 keeps the user on the OTP
  screen, clears the field, and shows a localized "incorrect or expired code" message; it does
  NOT navigate back to login for a `totp_invalid`.
- **Challenge expired/not found (404/410):** mapped to `code="challenge_expired"`; AND-039
  treats this as terminal for the current challenge and routes back to the login screen to
  restart `session/start`.
- **401 disambiguation:** a 401 here is a *challenge*-class rejection (bad code / invalid
  challenge), not session expiry. AND-013's authenticator must NOT loop `session/refresh` for
  `/ui/mfa/*` verify 401s (there is no completed session to refresh). This ticket relies on
  AND-013 scoping refresh away from MFA verify endpoints; otherwise an open question (Q1).
- **Blank code guard:** an empty/whitespace `code` short-circuits to
  `Failure(status=0, code="totp_invalid")` with no network call (defensive; primary validation
  is in AND-020/AND-039).
- **Malformed success** (`verified=true` but unknown/garbled `remaining_factors`): unknown
  factor strings are retained as `MfaFactor.Unknown(raw)`; the flow surfaces an "unsupported
  factor" rather than silently completing — fail-closed for an auth-critical branch.
- `CancellationException` propagates unchanged (structured concurrency; AND-018 `apiCall`
  re-throws it).

## 8. Security & Privacy

- **Code handling:** the TOTP `code` is passed straight into the request body and never
  logged, never stored, never placed in `ApiError`/`MfaVerifyResult`. It lives only on the
  coroutine frame for the duration of the call and is not retained after return.
- **`challenge_id`** is a short-lived secret tying the device to an in-progress challenge;
  kept in caller memory only, never persisted, never put in telemetry (Section 10).
- **No request/response body logging** for this endpoint. The OkHttp logging interceptor
  (AND-009) MUST run at `BASIC` (or redact `/ui/mfa/*`) so neither `code` nor `challenge_id`
  reaches Logcat. Verified in Section 11.
- Session/CSRF tokens are managed by the cookie jar (AND-011) / CSRF interceptor (AND-012);
  this repository never reads cookie values. Cleartext HTTP to the dev host is a known
  dev-only posture (network security config permits cleartext for the dev flavor only).
- `ApiError.message` from a rejected code carries the server `detail` only as a diagnostic
  fallback; it must never echo the submitted `code`. AND-015 normalization plus BASIC logging
  mitigate any server reflection of input.

## 9. Accessibility & i18n

N/A for the repository layer — no UI is produced here. Notes for the downstream owner
(AND-039):
- `MfaVerifyResult` variants and the stable, machine-readable `ApiError.code` values
  (`totp_invalid`, `challenge_expired`) let AND-039 select **localized** strings rather than
  display server English. The repository deliberately emits raw, non-localized
  `ApiError.message` only as a diagnostic fallback.
- The OTP entry affordance, content descriptions, RTL handling, and "incorrect code"
  announcements (live region) are owned by AND-020 (OTP composable) and AND-039 (MFA screen).

## 10. Telemetry & Logging

- Emit a single structured event per verify attempt via the Timber tree/analytics seam
  (AND-009), with **no PII / no secrets**:
  - `auth_mfa_totp_verify` with fields: `outcome` (`completed | factors_remaining |
    rejected | failure | network_error`), `http_status` (on failure),
    `error_code` (`totp_invalid | challenge_expired | …`), `remaining_factor_count` (on
    `factors_remaining`), `is_timeout`.
- **Never log:** the `code`, the `challenge_id`, cookie values, or raw request/response
  bodies for this endpoint.
- The set of `remaining_factors` *types* (e.g. `["sms"]`) is a category, useful for funnel
  analysis, and may be logged — but never paired with the `challenge_id`.
- The repository depends on no Android logging API directly beyond the injected logger seam,
  keeping `core-model` framework-free.

## 11. Testing Strategy

Unit tests in `core-data/src/test` (JUnit, Truth/kotlin-test, coroutines-test). `AuthApi` is
faked (hand-written fake or MockK stub returning canned `MfaVerifyResp` / throwing) so this
ticket tests **branching**, not transport (transport is AND-033's MockWebServer suite).

Branch/mapping tests (the acceptance core — correct vs. incorrect code):
- `verified=true, remaining_factors=[]` → `Success(Completed)`.
- `verified=true, auth_required=true, remaining_factors=["sms"]` →
  `Success(FactorsRemaining([Sms]))`.
- `verified=true, remaining_factors=["sms","email"]` → factors map to `[Sms, Email]` in order.
- `verified=true, remaining_factors=["webauthn"]` → `[Unknown("webauthn")]` (retained).
- `verified=false, detail="Invalid authentication code"` →
  `Failure(status=200, code="totp_invalid", message="Invalid authentication code")`.
- `verified=false, detail=null` → `Failure(code="totp_invalid", message="Incorrect or
  expired code")` (default message).

Failure-passthrough / remap tests (fake `AuthApi` throws or returns HTTP error):
- `HttpException(401)` with `detail` → `Failure(...)` remapped to `code="totp_invalid"`.
- `HttpException(400)` bad code → `code="totp_invalid"`.
- `HttpException(404)` / `(410)` → `code="challenge_expired"`.
- `HttpException(422)` → `Failure(status=422)` (generic, NOT `totp_invalid`).
- `SocketTimeoutException` → `NetworkError(isTimeout=true)`.
- generic `IOException` → `NetworkError(isTimeout=false)`.
- `CancellationException` thrown by the fake → re-thrown (`assertFailsWith`).

Input-guard test:
- `verifyTotp("chl_1", "   ")` → `Failure(code="totp_invalid")` with **no** request issued
  (assert the fake `AuthApi` was not called).

Request-shape test (one MockWebServer test, complementing AND-033):
- `verifyTotp("chl_1", "123456")` issues `POST /ui/mfa/totp/verify` with body
  `{"challenge_id":"chl_1","code":"123456"}` (recorded request asserted), and the code is
  trimmed (` "123456 " ` → `"123456"`).

Security test:
- with the OkHttp logging interceptor attached, a captured log of a `verifyTotp()` call does
  **not** contain the `code` or `challenge_id` substring.

DI smoke test:
- Hilt provides `MfaRepository` bound to `MfaRepositoryImpl` (`@HiltAndroidTest` or component
  test).

## 12. Dependencies & Sequencing

- **Requires (blocking):**
  - **AND-033** — `AuthApi.verifyTotp` + `MfaTotpVerifyRequest` / `MfaVerifyResp` DTOs must
    exist and be MockWebServer-verified.
  - **AND-028** — `MfaFactor` (reused for `remaining_factors`) and the `MfaRequired.
    challengeId` that feeds this call.
  - **AND-018** — `ApiResult`, `ApiError`, `apiCall`, `flatMap` in `core-model`.
- **Strongly related (needed for end-to-end correctness, not strictly compile-time
  blocking):** AND-011 (cookie jar carries the challenge), AND-012 (CSRF header), AND-013
  (401 scoping), AND-009 (timeouts/redacted logging), AND-015 (`detail` → `ApiError`).
  `verifyTotp()` compiles and unit-tests via the faked `AuthApi` without them.
- **Enables / blocks:** AND-039 (MFA ViewModel/screen consuming `MfaVerifyResult`), AND-047
  (auth end-to-end). Siblings AND-035 (SMS) / AND-036 (email) extend the same `MfaRepository`
  interface and reuse `MfaVerifyResult`.
- **Sequencing:** Land after AND-033, AND-028, AND-018; before AND-039 and AND-047. Freeze
  the `MfaVerifyResult` shape and the `code` taxonomy (`totp_invalid`, `challenge_expired`)
  and notify the AND-039 / AND-035 / AND-036 owners once merged.

## 13. Risks & Open Questions

- **R1 — Completion signal ambiguity.** The exact field signalling "challenge complete" is
  assumed to be `verified=true` + empty `remaining_factors`. The backend may instead reuse
  `auth_required` or return a `session` payload inline. Mitigation: treat non-empty
  `remaining_factors` OR `auth_required=true` as "more required"; otherwise `Completed`.
  Confirm against `/openapi.json` and `frontend/src/api/endpoints/*.ts` before merge.
- **R2 — Wrong-code signalling (200 vs. 4xx).** Spec handles both `verified=false` (HTTP 200)
  and an HTTP 4xx `detail`, normalizing to `code="totp_invalid"`. Confirm which the dev host
  actually uses so the AND-015 remap is correct; field name `verified` and `remaining_factors`
  casing must match the real schema (verify in AND-033 DTOs).
- **R3 — Does `totp/verify` emit `session/finalize` implicitly on completion?** Assumed no;
  the caller (AND-039) calls `POST /ui/session/finalize` after `Completed`. If the server
  finalizes inline and sets the full session cookie, AND-039 may skip finalize — confirm.
- **Q1 — 401 disambiguation.** AND-013's authenticator must NOT loop `session/refresh` on a
  `/ui/mfa/*` verify 401. Open: confirm AND-013 scopes refresh away from MFA verify endpoints
  (or a no-session 401 short-circuits refresh).
- **Q2 — TOTP `begin`?** Assumed none (authenticator generates codes offline). If
  `/ui/mfa/totp/begin` exists and is required (e.g. to nonce the challenge), this ticket must
  add it; AND-033's endpoint list does not include one. Confirm against `/openapi.json`.

## 14. Acceptance Criteria

1. `interface MfaRepository` with `suspend fun verifyTotp(challengeId: String, code: String):
   ApiResult<MfaVerifyResult>` exists in `com.testlogon.android.core.data.auth`, bound via
   Hilt to `MfaRepositoryImpl`.
2. `sealed interface MfaVerifyResult { Completed; FactorsRemaining(factors) }` exists in
   `com.testlogon.android.core.model.auth`, reusing `MfaFactor` (AND-028).
3. `verifyTotp()` calls `POST /ui/mfa/totp/verify` with body
   `{"challenge_id","code"}` (asserted via MockWebServer recorded request), trimming the code.
4. **Correct and incorrect codes produce the expected results (tested):** a `verified=true`
   no-remaining response → `Success(Completed)`; a `verified=true` with `remaining_factors` →
   `Success(FactorsRemaining(factors))`; a `verified=false` (or 4xx bad-code) →
   `Failure(code="totp_invalid")` — per the Section 11 table.
5. Remaining factors map via `MfaFactor.fromWire`; unknown entries → `MfaFactor.Unknown(raw)`
   and are retained.
6. Challenge-expired (404/410) → `Failure(code="challenge_expired")`; 422 → generic
   `Failure(status=422)` (not `totp_invalid`).
7. Transport/HTTP failures pass through unchanged: `IOException`/timeout → `NetworkError`;
   HTTP error → `Failure(ApiError)`; `CancellationException` re-thrown. Blank `code` →
   `Failure(code="totp_invalid")` with no network call.
8. No `code` or `challenge_id` value appears in logs for a `verifyTotp()` call (security test
   green).
9. `./gradlew :core-data:test` (and `:core-model:test`) green; ktlint/detekt (AND-005) pass.

## 15. Definition of Done

- `MfaRepository`/`MfaRepositoryImpl`, `MfaVerifyResult`, and the Hilt binding are
  implemented, compile, and are merged to `android-port`.
- Unit tests cover every branch, remap, and failure-passthrough case in Section 11 and pass
  via `./gradlew :core-data:test`; the MockWebServer request-shape and no-secret-logging
  tests pass.
- Public types, the branching rule (Section 3.4), and the error `code` taxonomy
  (`totp_invalid`, `challenge_expired`) are documented in KDoc.
- No Retrofit/OkHttp types leak through the `MfaRepository` interface (verified by inspecting
  the interface signature; only `core-model` types appear).
- ktlint/detekt (AND-005) pass on new files; code reviewed.
- AND-039 (and the AND-035/AND-036 owners) notified that `MfaVerifyResult` and the `code`
  taxonomy are frozen for consumption; open questions Q1–Q2 and risks R1–R3 either resolved
  against `/openapi.json` / `frontend/src/api/endpoints` or filed as follow-ups before AND-039
  integration.
