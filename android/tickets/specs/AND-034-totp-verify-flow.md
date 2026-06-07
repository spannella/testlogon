---
id: AND-034
title: "TOTP verify flow"
milestone: M1
epic: E05
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
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
3. `verifyTotp()` calls `AuthApi.verifyTotp(TotpVerifyReq(challengeId, totpCode))` inside
   `apiCall { }` (AND-018) so transport failures fold to `ApiResult.NetworkError` and HTTP
   error bodies fold to `ApiResult.Failure(ApiError)`.
4. **Branching rule** (deterministic, single source of truth) applied to a successful
   (HTTP 2xx) `MfaVerifyResp`. **CORRECTED:** the verified-against-sources response schema
   has **no** `verified` boolean and **no** `auth_required` field. The authoritative shape
   (`src/api/types.ts: MfaVerifyResp`) is
   `{ status: string; session_id?: string; required_factors: string[]; passed:
   Record<string, boolean>; remaining_factors: string[] }`. The web client
   (`src/pages/Login.tsx: handleMfaVerify`) decides completion purely from
   `remaining_factors.length === 0`. The corrected rule is:
   - If `remaining_factors` is **empty** → `ApiResult.Success(MfaVerifyResult.Completed)`.
     The caller then proceeds to `POST /ui/session/finalize`.
   - If `remaining_factors` is **non-empty** → `ApiResult.Success(
     MfaVerifyResult.FactorsRemaining(factors))`, mapping factor strings via
     `MfaFactor.fromWire` (AND-028).
   - **A wrong/expired code is NOT a 2xx response.** Verified against `src/api/client.ts`
     and `src/pages/Login.tsx`: an incorrect code surfaces as a **thrown HTTP error**
     (`ApiError` with a `status` + `detail` string), caught in the page's `catch` block.
     There is no `verified=false` 200 path — that field does not exist. The repository
     therefore maps the HTTP-error body (via AND-015) and remaps the relevant statuses to
     `code="totp_invalid"` (see Section 7). A reachable 2xx with a non-empty/empty
     `remaining_factors` is the ONLY success contract.
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

**CORRECTED to match the backend schema.** The OpenAPI request schema is `TotpVerifyReq`
(not `MfaTotpVerifyRequest`) with fields `challenge_id` and **`totp_code`** (not `code`) —
both required (OpenAPI `components.schemas.TotpVerifyReq`; `src/api/types.ts: TotpVerifyReq`).
The response schema is **not** annotated in OpenAPI (`POST /ui/mfa/totp/verify` →
`resp=200:` with no model), so the authoritative response contract is the frontend type
`src/api/types.ts: MfaVerifyResp` = `{ status, session_id?, required_factors[], passed,
remaining_factors[] }` — there is no `verified`, no `auth_required`, no `detail` on success.

```kotlin
@JsonClass(generateAdapter = true)
data class TotpVerifyReq(
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "totp_code") val totpCode: String,
)

@JsonClass(generateAdapter = true)
data class MfaVerifyResp(
    val status: String = "",
    @Json(name = "session_id") val sessionId: String? = null,
    @Json(name = "required_factors") val requiredFactors: List<String> = emptyList(),
    val passed: Map<String, Boolean> = emptyMap(),
    @Json(name = "remaining_factors") val remainingFactors: List<String> = emptyList(),
)
```

`AuthApi` method consumed (from AND-033):

```kotlin
@POST("ui/mfa/totp/verify")
suspend fun verifyTotp(@Body body: TotpVerifyReq): MfaVerifyResp
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
            api.verifyTotp(TotpVerifyReq(challengeId = challengeId, totpCode = trimmed))
        }.flatMap { resp -> resp.toVerifyResult() }
    }

    // CORRECTED: a 2xx response is always an accepted code. Completion is decided solely by
    // remaining_factors (matching src/pages/Login.tsx). A wrong code never reaches here as a
    // success — it is a thrown HTTP error folded by apiCall/AND-015 (see Section 7).
    private fun MfaVerifyResp.toVerifyResult(): ApiResult<MfaVerifyResult> =
        if (remainingFactors.isEmpty()) {
            ApiResult.Success(MfaVerifyResult.Completed)
        } else {
            ApiResult.Success(
                MfaVerifyResult.FactorsRemaining(remainingFactors.map(MfaFactor::fromWire)),
            )
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
the ViewModel. The "bad code" case (server returns an HTTP 4xx with a `detail`, Section 7 —
**the only** wrong-code signal; there is no 200 `verified=false`) is normalized to
`code="totp_invalid"` by the AND-015 error mapper plus a small remap, so AND-039 has a single
`code` to key its localized "incorrect code" copy off.

## 5. API Contract

Single endpoint consumed: **`POST /ui/mfa/totp/verify`**.

Request body (**CORRECTED** — field is `totp_code`, per `TotpVerifyReq`):

```json
{
  "challenge_id": "chl_01HXYZ...",
  "totp_code": "123456"
}
```

Headers: `Content-Type: application/json`; cookies + `X-CSRF-Token` (`ui_csrf`) are added by
interceptors (AND-011/AND-012), not by this repository.

**CORRECTED** success bodies below to the real `MfaVerifyResp` shape
(`{ status, session_id?, required_factors[], passed, remaining_factors[] }`).

Representative success — **challenge complete** (only TOTP was required):

```json
{
  "status": "ok",
  "required_factors": ["totp"],
  "passed": { "totp": true },
  "remaining_factors": []
}
```
→ `ApiResult.Success(MfaVerifyResult.Completed)`

Representative success — **factor accepted, more required** (TOTP + SMS challenge):

```json
{
  "status": "pending",
  "required_factors": ["totp", "sms"],
  "passed": { "totp": true, "sms": false },
  "remaining_factors": ["sms"]
}
```
→ `ApiResult.Success(MfaVerifyResult.FactorsRemaining([Sms]))`

Representative **rejected code** — **CORRECTED**: a wrong/expired code is **not** an HTTP 200;
it is a thrown HTTP error (FastAPI `detail`), confirmed via `src/api/client.ts` +
`src/pages/Login.tsx` (the page reads `err.detail`). Exact status is unverified (see §16);
the dev host was unreachable for live confirmation. Representative body:

```json
{ "detail": "Invalid authentication code" }
```
→ `ApiResult.Failure(ApiError(status=4xx, code="totp_invalid", message="Invalid authentication code"))`

Error responses folded by `apiCall`/AND-015 into `ApiResult.Failure(ApiError)` and remapped:

- **4xx bad-or-expired code** — the backend signals a wrong code with an HTTP error status
  and a `detail` string (this is the **primary** wrong-code path, confirmed via the web
  client; exact status code unverified — see §16):
  ```json
  { "detail": "Invalid authentication code" }
  ```
  → `Failure(ApiError(status=4xx, message="Invalid authentication code"))`, remapped to
  `code="totp_invalid"`. Note: a *challenge*-expired/invalid 401 here is a credentials-class
  401, NOT a session-expiry 401, and must not loop through AND-013 refresh (Section 7). This
  is consistent with `src/api/client.ts`, where an **unauthenticated** 401 (no active
  session — exactly the MFA-verify case) propagates to the caller and is NOT auto-refreshed.
- **422 Unprocessable Entity** (validation, e.g. missing `challenge_id`/`totp_code`) — the
  OpenAPI-declared error for this endpoint is `HTTPValidationError`, a `detail` list of
  `loc/msg/type` items (`POST /ui/mfa/totp/verify` → `resp=422:HTTPValidationError`):
  ```json
  { "detail": [ { "loc": ["body","totp_code"], "msg": "field required", "type": "missing" } ] }
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
- **Wrong/expired code:** **CORRECTED** — there is no HTTP 200 `verified=false` shape. A wrong
  code is an HTTP 4xx with a `detail` string (per `src/api/client.ts`/`Login.tsx`); the AND-015
  mapper plus a small remap normalize it to `ApiError(code="totp_invalid")`. AND-039 keeps the
  user on the OTP screen, clears the field, and shows a localized "incorrect or expired code"
  message; it does NOT navigate back to login for a `totp_invalid`.
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
- **Malformed success** (2xx with unknown/garbled `remaining_factors` entries): unknown
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

Branch/mapping tests (the acceptance core — correct vs. incorrect code). **CORRECTED** to the
real `MfaVerifyResp` shape: success is a 2xx with `remaining_factors`; there is no `verified`
field, so completion is keyed on `remaining_factors` only:
- `status="ok", remaining_factors=[]` → `Success(Completed)`.
- `status="pending", remaining_factors=["sms"]` → `Success(FactorsRemaining([Sms]))`.
- `remaining_factors=["sms","email"]` → factors map to `[Sms, Email]` in order.
- `remaining_factors=["webauthn"]` → `[Unknown("webauthn")]` (retained).

Failure-passthrough / remap tests (fake `AuthApi` throws or returns HTTP error). **CORRECTED**:
the wrong-code path is an HTTP 4xx with a `detail` string, NOT a 200 `verified=false`:
- `HttpException(4xx)` with `detail="Invalid authentication code"` → `Failure(...)` remapped to
  `code="totp_invalid"`, `message="Invalid authentication code"`.
- `HttpException(401)` (unauthenticated challenge-class) → `code="totp_invalid"`; MUST NOT
  trigger AND-013 `session/refresh`.
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
  `{"challenge_id":"chl_1","totp_code":"123456"}` (recorded request asserted; **CORRECTED**
  field name to `totp_code`), and the code is trimmed (` "123456 " ` → `"123456"`).

Security test:
- with the OkHttp logging interceptor attached, a captured log of a `verifyTotp()` call does
  **not** contain the `code` or `challenge_id` substring.

DI smoke test:
- Hilt provides `MfaRepository` bound to `MfaRepositoryImpl` (`@HiltAndroidTest` or component
  test).

## 12. Dependencies & Sequencing

- **Requires (blocking):**
  - **AND-033** — `AuthApi.verifyTotp` + `TotpVerifyReq` / `MfaVerifyResp` DTOs must
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

- **R1 — Completion signal ambiguity. RESOLVED (review 2026-06-06).** The assumed
  `verified`/`auth_required` fields **do not exist** on the verify response. Per
  `src/api/types.ts: MfaVerifyResp` and `src/pages/Login.tsx: handleMfaVerify`, completion is
  decided **solely** by `remaining_factors.length === 0`. The branching rule (Section 3.4) was
  corrected accordingly; the `status` field (`"ok"|"pending"`) is informational and not used
  for the branch. There is no inline `session` payload on verify (finalize is separate).
- **R2 — Wrong-code signalling. RESOLVED (review 2026-06-06).** There is **no** HTTP 200
  `verified=false` shape. A wrong code is a thrown HTTP error with a `detail` string
  (`src/api/client.ts`, `src/pages/Login.tsx` reads `err.detail`). Spec corrected to a single
  4xx-error path normalized to `code="totp_invalid"`. **Residual open item:** the exact HTTP
  status (400 vs 401 vs 403) is unverified — OpenAPI declares only `200` (empty) and `422`;
  the dev host was unreachable for live confirmation. The remap keys on the error class, not a
  specific status, so this does not block.
- **R3 — Does `totp/verify` finalize implicitly?** **Partially resolved.** Verified the web
  client always calls `POST /ui/session/finalize` separately after `remaining_factors` is
  empty (`Login.tsx`), and the verify response carries no full session — so AND-039 must
  finalize explicitly. `session/finalize` returns `{status, session_id?, required_factors[],
  passed}` (`SessionFinalizeResp`) and may itself still report `required_factors` (the web app
  re-prompts). Confirmed no implicit finalize on the verify call.
- **Q1 — 401 disambiguation. RESOLVED (review 2026-06-06).** The web client
  (`src/api/client.ts`) auto-refreshes a 401 **only when already authenticated**; an
  unauthenticated 401 (the MFA-verify case — there is no session yet) **propagates directly**
  to the caller and is NOT refreshed. AND-013 must mirror this (do not loop `session/refresh`
  for `/ui/mfa/*` verify 401s). This is now a confirmed contract, not an assumption.
- **Q2 — TOTP `begin`? RESOLVED (review 2026-06-06).** No `/ui/mfa/totp/begin` exists in the
  OpenAPI index (the only `totp` write endpoints are `verify` and the device
  enroll/confirm/remove set). The "no begin" assumption is confirmed against the spec.

## 14. Acceptance Criteria

1. `interface MfaRepository` with `suspend fun verifyTotp(challengeId: String, code: String):
   ApiResult<MfaVerifyResult>` exists in `com.testlogon.android.core.data.auth`, bound via
   Hilt to `MfaRepositoryImpl`.
2. `sealed interface MfaVerifyResult { Completed; FactorsRemaining(factors) }` exists in
   `com.testlogon.android.core.model.auth`, reusing `MfaFactor` (AND-028).
3. `verifyTotp()` calls `POST /ui/mfa/totp/verify` with body
   `{"challenge_id","totp_code"}` (**CORRECTED** field; asserted via MockWebServer recorded
   request), trimming the code.
4. **Correct and incorrect codes produce the expected results (tested):** a 2xx response with
   empty `remaining_factors` → `Success(Completed)`; a 2xx with non-empty `remaining_factors` →
   `Success(FactorsRemaining(factors))`; a 4xx bad-code error →
   `Failure(code="totp_invalid")` — per the Section 11 table (**CORRECTED**: no
   `verified` field exists; completion is keyed on `remaining_factors`).
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. "OpenAPI index" =
`reference/openapi.index.txt`; schema bodies from `reference/openapi.pretty.json`
(`components.schemas.<Name>`); frontend paths are under `reference/src/`.

1. **Endpoint is `POST /ui/mfa/totp/verify`.** VERIFIED. OpenAPI `POST /ui/mfa/totp/verify`
   (op=`ui_totp_verify_ui_mfa_totp_verify_post`); `src/api/endpoints/auth.ts: verifyTotp`
   (`api.post(...,"/ui/mfa/totp/verify", body)`).
2. **Request schema name.** CORRECTED — spec said `MfaTotpVerifyRequest`; actual schema is
   **`TotpVerifyReq`**. OpenAPI index `req=TotpVerifyReq`; `components.schemas.TotpVerifyReq`;
   `src/api/types.ts: TotpVerifyReq`.
3. **Request field for the code.** CORRECTED — spec said `code`; actual field is **`totp_code`**
   (with `challenge_id`), both required. `components.schemas.TotpVerifyReq.properties`
   (`challenge_id`, `totp_code`; `required: [challenge_id, totp_code]`);
   `src/api/types.ts: TotpVerifyReq` and call site `src/pages/Login.tsx` (`verifyTotp({
   challenge_id, totp_code })`). (Note: sibling SMS/email use field `code` — `SmsVerifyReq`/
   `EmailVerifyReq` — but TOTP is `totp_code`.)
4. **Response shape `MfaVerifyResp`.** CORRECTED — spec claimed `{verified, auth_required,
   remaining_factors, detail}`. The OpenAPI response is **unannotated** (`resp=200:` with no
   model), so the authoritative contract is `src/api/types.ts: MfaVerifyResp` =
   `{ status: string; session_id?: string; required_factors: string[]; passed:
   Record<string,boolean>; remaining_factors: string[] }`. No `verified`, no `auth_required`,
   no `detail` on success.
5. **Completion signal = empty `remaining_factors`.** CORRECTED/VERIFIED — spec keyed on
   `verified==true && remaining_factors empty`. Real web logic: `src/pages/Login.tsx:
   handleMfaVerify` branches on `resp.remaining_factors.length === 0` only, then calls
   `sessionFinalize`.
6. **Wrong/expired code is an HTTP error, not a 200 `verified=false`.** CORRECTED — spec's
   central 200 `verified=false` branch is fictional. `src/api/client.ts` throws `ApiError`
   for non-2xx; `src/pages/Login.tsx` catch reads `err.detail`. Exact 4xx status is an open
   assumption (see below).
7. **`session/finalize` is a separate explicit call after completion.** VERIFIED.
   `src/pages/Login.tsx` calls `sessionFinalize({ challenge_id, remember_device })` when
   `remaining_factors` is empty; `SessionFinalizeReq`/`SessionFinalizeResp` in
   `src/api/types.ts` (`SessionFinalizeResp.status: "ok"|"pending"`). OpenAPI
   `POST /ui/session/finalize` (req=`UiSessionFinalizeReq`).
8. **`session/start` returns `{auth_required, challenge_id?, required_factors[], session_id?}`.**
   VERIFIED. `components.schemas.UiSessionStartResp` (required: `auth_required`);
   `src/api/types.ts: SessionStartResp`; OpenAPI `POST /ui/session/start`
   (resp=`UiSessionStartResp`). The `challenge_id` consumed by this ticket originates here.
9. **CSRF: `ui_csrf` cookie echoed as `X-CSRF-Token`.** VERIFIED. `src/api/client.ts`
   (`const csrf = getCookie("ui_csrf"); headers.set("X-CSRF-Token", csrf)`).
10. **Cookie-based session transport (credentials included).** VERIFIED. `src/api/client.ts`
    fetch uses `credentials: "include"` on every call (and retry).
11. **401 on MFA verify must NOT loop `session/refresh`.** VERIFIED (was Q1, an assumption).
    `src/api/client.ts`: auto-refresh runs only when `useAuthStore...isAuthenticated`; an
    **unauthenticated** 401 (the MFA-verify state — no session yet) is thrown straight to the
    caller. OpenAPI `POST /ui/session/refresh` exists (`resp=200:`) but the client gates it.
12. **No `/ui/mfa/totp/begin` endpoint (TOTP is begin-less).** VERIFIED (was Q2). OpenAPI
    index: only `totp/verify` plus device enroll endpoints (`totp/devices/begin|confirm|
    {id}/remove`, `totp/devices` GET); no login-flow `totp/begin`.
13. **422 error is `HTTPValidationError` (`detail` list of loc/msg/type).** VERIFIED. OpenAPI
    `POST /ui/mfa/totp/verify` → `resp=200:;422:HTTPValidationError`; FastAPI standard shape;
    `normalizeErrorDetail` in `src/api/client.ts` walks `detail[].msg`.
14. **FastAPI `detail` → `ApiError` mapping (string or list).** VERIFIED against the web
    normalizer `src/api/client.ts: normalizeErrorDetail` (handles string `detail`, array of
    `{msg}`, and object `{code,...}` forms) — the AND-015 mapper this ticket relies on mirrors
    it. `ApiError` carries `status` + `detail` (`src/api/client.ts: class ApiError`).
15. **`code="totp_invalid"` / `code="challenge_expired"` taxonomy.** UNVERIFIED-ASSUMPTION —
    these are client-invented stable codes for AND-039 localization, not backend-supplied. The
    backend returns a `detail` string; the repository synthesizes these `code`s. Acceptable as
    an internal contract (documented as such).
16. **Repository/domain types (`MfaRepository`, `MfaVerifyResult`, `MfaRepositoryImpl`),
    package names, Hilt `@Binds`.** UNVERIFIED-ASSUMPTION (forward-looking Android design; no
    Android source exists yet in this repo). Internal design choice, consistent with
    AND-018/AND-028/AND-033 seams.
17. **`MfaFactor` reuse + `MfaFactor.fromWire` / `Unknown(raw)`.** UNVERIFIED-ASSUMPTION —
    owned by AND-028 (not present in `reference/`). The wire factor strings observed
    (`"totp"`, `"sms"`, `"email"`) come from `required_factors`/`remaining_factors` in
    `src/api/types.ts` and the method list in `src/pages/Login.tsx` (`totp|sms|email|recovery`).
18. **Stack (Kotlin 2.0.21, Retrofit 2.11/OkHttp 4.12/Moshi 1.15, Hilt+KSP, minSdk 24,
    JDK 17).** UNVERIFIED-ASSUMPTION (framework choices; no Gradle files in `reference/`).
    Labeled framework ref; Moshi `@Json`/Retrofit `@POST` usage is standard
    (framework ref: developer.android.com / square.github.io/retrofit, square.github.io/moshi).
19. **Dev host `http://18.222.237.167:8000`, cleartext, flaky; OpenAPI at `/openapi.json`.**
    UNVERIFIED at review time — host was not reachable for a live call; taken from the spec.
    The plaintext/cleartext dev posture is a stated assumption, not independently confirmed.

### Corrections made

- **C1 — Request schema/field (Sections 4, 5, 11, 14).** `MfaTotpVerifyRequest`/`code` →
  **`TotpVerifyReq`/`totp_code`** (the verified backend + frontend contract).
- **C2 — Response shape (Sections 1, 4, 5).** Removed the nonexistent `verified`,
  `auth_required`, and success-`detail` fields; replaced with the real
  `{status, session_id?, required_factors, passed, remaining_factors}`.
- **C3 — Branching rule (Section 3.4, 4 impl, 11, 14).** Completion now keyed on empty
  `remaining_factors` (matching `Login.tsx`), not a `verified` boolean. Removed the impossible
  200-`verified=false` rejection branch.
- **C4 — Wrong-code path (Sections 3, 4, 5, 7, 11).** A bad code is a thrown HTTP 4xx with a
  `detail`, not an HTTP 200; normalized to `code="totp_invalid"`. Single error path.
- **C5 — 422 example (Section 5).** Validation `loc` corrected to `["body","totp_code"]` and
  tied to the OpenAPI-declared `HTTPValidationError`.
- **C6 — Risks/Questions (Section 13).** R1, R2, Q1, Q2 marked RESOLVED with sources; R3
  partially resolved (explicit finalize confirmed). Frontmatter `status: reviewed` +
  `reviewed_on: 2026-06-06`.

### Open assumptions

- **OA1 — Exact wrong-code HTTP status (400 vs 401 vs 403).** OpenAPI declares only `200`
  (unannotated) and `422` for this op; the live dev host was unreachable, so the precise status
  a wrong `totp_code` returns is unconfirmed. The remap keys on the error class + AND-015, not
  a single status, so it is non-blocking; AND-033's MockWebServer suite should pin it once the
  host is reachable.
- **OA2 — 404/410 → `challenge_expired`.** No evidence in OpenAPI (only 200/422 declared) or
  the web client that the backend returns 404/410 for an expired challenge. This mapping is an
  assumption; if the backend instead returns a 4xx `detail`, AND-039's "route back to login"
  behavior must key off the actual status. Confirm in AND-033.
- **OA3 — `status` field values on verify (`"ok"`/`"pending"`).** Inferred from
  `SessionFinalizeResp.status: "ok"|"pending"`; `MfaVerifyResp.status` is typed only as
  `string`. The branch does not depend on it, so this is informational only.
- **OA4 — All Android-side types/stack (items 15–18 above).** No Android source or build files
  exist in `reference/`; these are design intent to be realized by AND-018/028/033/039.

## 17. Test Plan

Acceptance criteria referenced as AC-# map to Section 14. Test targets: **JVM** =
JVM unit/Robolectric (local, no device); **emulator** = headless AVD `test35`
(x86_64, API 35); **device** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a).
This ticket is a pure data/repository seam with **no UI and no device-specific behavior**, so
the core suite is JVM. The DI smoke test runs on emulator (Hilt). Cases that exist only
because the spec touches a hardware-class concern (none here directly) are noted; an
ABI/instrumented sanity case runs on the physical device to confirm Moshi codegen + arm64.

- **TC-AND-034-01** — Type: unit (JVM). Target: `MfaRepositoryImpl.verifyTotp`. Preconditions:
  fake `AuthApi` returns `MfaVerifyResp(status="ok", remaining_factors=[])`. Steps: call
  `verifyTotp("chl_1","123456")`. Expected: `ApiResult.Success(MfaVerifyResult.Completed)`.
  Traces: AC-4.
- **TC-AND-034-02** — Type: unit (JVM). Target: `verifyTotp` branch. Preconditions: fake
  returns `MfaVerifyResp(status="pending", remaining_factors=["sms"])`. Steps: call verify.
  Expected: `Success(FactorsRemaining([Sms]))`. Traces: AC-4, AC-5.
- **TC-AND-034-03** — Type: unit (JVM). Target: factor mapping/order + unknown retention.
  Preconditions: fake returns `remaining_factors=["sms","email","webauthn"]`. Steps: call
  verify. Expected: `FactorsRemaining([Sms, Email, Unknown("webauthn")])` in order; no entry
  dropped. Traces: AC-5.
- **TC-AND-034-04** — Type: contract/MockWebServer (JVM). Target: request shape + trimming.
  Preconditions: MockWebServer enqueues a 200 `{status:"ok",remaining_factors:[]}`. Steps:
  call `verifyTotp("chl_1"," 123456 ")`; capture the recorded request. Expected: `POST
  /ui/mfa/totp/verify`, body exactly `{"challenge_id":"chl_1","totp_code":"123456"}` (trimmed;
  field name `totp_code`, **not** `code`), `Content-Type: application/json`. Traces: AC-3.
- **TC-AND-034-05** — Type: unit (JVM). Target: wrong-code mapping. Preconditions: fake
  `AuthApi` throws `HttpException(4xx)` with body `{"detail":"Invalid authentication code"}`.
  Steps: call verify. Expected: `ApiResult.Failure(ApiError(code="totp_invalid",
  message="Invalid authentication code"))`; the result is NOT a `Success` and NOT
  `challenge_expired`. Traces: AC-4, AC-6.
- **TC-AND-034-06** — Type: unit (JVM). Target: 401 challenge-class disambiguation.
  Preconditions: fake throws `HttpException(401)` with a `detail`; an observable hook on the
  AND-013 authenticator/refresh seam. Steps: call verify. Expected: `Failure(code=
  "totp_invalid")` (or per remap) AND the `session/refresh` path is **not** invoked (assert
  zero refresh calls), mirroring the web client's unauthenticated-401 propagation. Traces:
  AC-4, AC-7.
- **TC-AND-034-07** — Type: unit (JVM). Target: challenge-expired + validation mapping.
  Preconditions: fake throws `HttpException(404)`, then `(410)`, then `(422)` with an
  `HTTPValidationError` `detail` list. Steps: call verify for each. Expected: 404/410 →
  `Failure(code="challenge_expired")`; 422 → `Failure(status=422)` generic (NOT
  `totp_invalid`). Traces: AC-6. (Note OA2: 404/410 mapping is an assumption pending AND-033.)
- **TC-AND-034-08** — Type: unit (JVM). Target: transport/offline + flaky-dev-host path.
  Preconditions: fake throws `SocketTimeoutException`, then a generic `IOException`. Steps:
  call verify for each. Expected: timeout → `NetworkError(isTimeout=true)`; IOException →
  `NetworkError(isTimeout=false)`; no exception escapes; no retry is performed (non-idempotent
  POST). Traces: AC-7.
- **TC-AND-034-09** — Type: unit (JVM). Target: cancellation propagation. Preconditions: fake
  throws `CancellationException`. Steps: call verify inside a cancellable scope. Expected:
  `CancellationException` is re-thrown unchanged (`assertFailsWith`), not folded into
  `ApiResult`. Traces: AC-7.
- **TC-AND-034-10** — Type: unit (JVM). Target: blank-code guard. Preconditions: spy/fake
  `AuthApi`. Steps: call `verifyTotp("chl_1","   ")`. Expected:
  `Failure(status=0, code="totp_invalid")` with **no** call to `AuthApi.verifyTotp` (verify
  zero interactions). Traces: AC-7.
- **TC-AND-034-11** — Type: contract/MockWebServer + security (JVM). Target: no-secret
  logging. Preconditions: OkHttp client with the AND-009 logging interceptor at BASIC (or
  `/ui/mfa/*` redaction) attached; capture log output. Steps: run `verifyTotp("chl_secret",
  "987654")` against a MockWebServer 200. Expected: captured logs contain neither the
  `totp_code` value `987654` nor the `challenge_id` value `chl_secret` (nor request/response
  bodies). Traces: AC-8.
- **TC-AND-034-12** — Type: integration (emulator `test35`). Target: Hilt DI binding.
  Preconditions: `@HiltAndroidTest` component test on AVD `test35`. Steps: inject
  `MfaRepository`. Expected: resolves to a `MfaRepositoryImpl` `@Singleton`; no missing-binding
  error. Traces: AC-1, AC-9.
- **TC-AND-034-13** — Type: instrumented/e2e (PHYSICAL DEVICE — SM-A156U, arm64-v8a, API 34).
  Target: Moshi adapter + ABI sanity for the corrected DTOs. Preconditions: app installed on
  the physical device (must run on device, not emulator, to exercise arm64 codegen vs the
  x86_64 AVD). Steps: deserialize a real `MfaVerifyResp` JSON (`{status, session_id,
  required_factors, passed, remaining_factors}`) and serialize a `TotpVerifyReq`
  (`{challenge_id, totp_code}`) via the production Moshi instance. Expected: round-trips with
  correct `@Json` names (`totp_code`, `remaining_factors`, etc.); no `NoClassDefFound`/codegen
  ABI failure on arm64. Traces: AC-2, AC-3. (On-device specifically catches arm64-vs-x86 +
  API-34-vs-35 codegen/runtime differences the emulator cannot.)
- **TC-AND-034-14** — Type: manual. Target: end-to-end happy path against the dev host (when
  reachable). Preconditions: dev host `http://18.222.237.167:8000` up; a real challenge from
  `session/start`; valid authenticator code. Steps: drive `session/start` →
  `verifyTotp(challengeId, code)` → on `Completed`, `session/finalize` → `getMe`. Expected:
  TOTP-only challenge completes and `getMe` returns the `user_sub`; pins the real wrong-code
  HTTP status to close OA1. Traces: AC-3, AC-4. (Manual because the dev host was unreachable
  during this review.)

### Coverage matrix

| Section-14 AC | Covered by |
|---|---|
| AC-1 (interface + Hilt binding) | TC-12 |
| AC-2 (`MfaVerifyResult` types) | TC-12, TC-13 |
| AC-3 (`POST` body `{challenge_id, totp_code}`, trimmed) | TC-04, TC-13, TC-14 |
| AC-4 (correct/incorrect → expected results) | TC-01, TC-02, TC-05, TC-06, TC-14 |
| AC-5 (factor mapping; unknown retained) | TC-02, TC-03 |
| AC-6 (404/410 → `challenge_expired`; 422 generic) | TC-05, TC-07 |
| AC-7 (transport/cancel/blank-code passthrough; no retry) | TC-06, TC-08, TC-09, TC-10 |
| AC-8 (no `code`/`challenge_id` in logs) | TC-11 |
| AC-9 (`:core-data:test`/`:core-model:test` green; lint) | TC-01–TC-11 (the JVM suite), TC-12 |
