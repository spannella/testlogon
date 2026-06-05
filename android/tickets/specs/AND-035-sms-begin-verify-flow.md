---
id: AND-035
title: "SMS begin/verify flow"
milestone: M1
epic: E05
priority: P0
size: M
status: draft
depends_on: [AND-033, AND-034, AND-028, AND-018]
blocks: [AND-039, AND-047]
---

# AND-035 — SMS begin/verify flow

## 1. Overview & Goal

This ticket adds the **SMS** factor to the cookie-based authentication MFA flow. Unlike TOTP
(AND-034), where the authenticator app produces a code offline, the SMS factor is a two-step
**begin → verify** exchange: the client first asks the backend to dispatch a one-time code to
the user's registered phone (`POST /ui/mfa/sms/begin`, which returns a *masked* destination
`sent_to`), then submits the user-entered code (`POST /ui/mfa/sms/verify`). The ticket also
delivers **resend** support, which is simply a re-invocation of `begin` gated by the
backend-supplied cooldown.

Scope is two repository-layer seams on the shared `MfaRepository` interface introduced by
AND-034: `beginSms(challengeId)` and `verifySms(challengeId, code)`, plus the
`resendSms(challengeId)` alias. `beginSms` returns a new domain result `MfaBeginResult`
carrying the masked destination and cooldown/expiry hints; `verifySms` **reuses the exact
`MfaVerifyResult` shape frozen by AND-034** (`Completed` | `FactorsRemaining`) so the MFA
ViewModel (AND-039) treats every factor uniformly. All branching — masked-destination
extraction, cooldown surfacing, resend-throttle handling, complete-vs-remaining
interpretation, and wrong/expired-code classification — lives here so AND-039 never touches
Retrofit/Moshi types and is unit-testable against a fake `MfaApiClient`.

The raw Retrofit `MfaApi.beginSms`/`verifySms` endpoints, their `Mfa*` DTOs, and the
`MfaApiClient` façade are **owned and MockWebServer-tested by AND-033**; this ticket consumes
`MfaApiClient.beginSms`/`verifySms` and the `ApiResult`/`safeApiCall` machinery (AND-018/027).
Success = both seams land on `MfaRepository`, the begin/verify round-trip is proven (a begin
dispatches a challenge; a correct verify advances or finishes; a wrong code is rejected), and
resend cooldown/throttling is correctly surfaced — all unit-tested.

## 2. Context & References

- **Module:** `core-data` (auth/MFA repositories) with domain models in `core-model`.
  Repository interface in `com.testlogon.android.core.data.auth`; domain result types in
  `com.testlogon.android.core.model.auth`. DTOs + `MfaApiClient` live in
  `com.testlogon.android.core.network.auth` (AND-033).
- **Depends on (blocking):**
  - **AND-033** — `MfaApiClient.beginSms(challengeId): ApiResult<MfaBeginResp>` and
    `verifySms(challengeId, code): ApiResult<MfaVerifyResp>`, plus the `MfaBeginResp` /
    `MfaVerifyResp` / `MfaVerifyReq` / `MfaBeginReq` DTOs, all MockWebServer-verified. This
    ticket calls only `beginSms` and `verifySms`.
  - **AND-034** — establishes `interface MfaRepository`, `MfaRepositoryImpl`, the shared
    `sealed interface MfaVerifyResult` (`Completed` | `FactorsRemaining`), the
    `verified=false → totp_invalid` / `404|410 → challenge_expired` taxonomy, and the
    `MfaFactor.fromWire` reuse. AND-035 **extends** that interface; it does not redefine
    `MfaVerifyResult`.
  - **AND-028** — `AuthRepository.login()` yields `LoginResult.MfaRequired(challengeId,
    factors)`; the `challengeId` consumed here originates there, and `MfaFactor` is reused for
    the remaining-factor list.
  - **AND-018** — `ApiResult<T>`, `ApiError`, the `safeApiCall`/`apiCall` wrapper, and
    `flatMap` for folding transport/HTTP failures and applying the branch mapping.
- **Blocks:**
  - **AND-039** — MFA screen + ViewModel that drives the OTP input (AND-020), shows the masked
    `sentTo`, runs the resend countdown timer, and maps `MfaBeginResult`/`MfaVerifyResult` to
    navigation (finalize vs. next factor) and errors.
  - **AND-047** — full auth end-to-end flow depends on SMS verification.
- **Related (not blocking):** AND-011 (persistent cookie jar — the challenge/session cookies
  set by `session/start` ride these calls), AND-012 (CSRF interceptor echoes `ui_csrf` as
  `X-CSRF-Token`), AND-013 (401 → `session/refresh` once → retry; must NOT loop for MFA verify
  401s), AND-015 (FastAPI `detail` → `ApiError`), AND-009 (~20s timeouts, redacted logging),
  AND-016 (GET-only retry — excludes these POSTs), AND-020 (OTP input composable), AND-036
  (sibling email begin/verify, identical shapes).
- **Stack:** Kotlin 2.0.21, Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Hilt
  (KSP). minSdk 24, JDK 17.
- **Backend:** FastAPI dev host `http://18.222.237.167:8000` (plaintext, unreliable). OpenAPI
  at `/openapi.json`. Web reference in `frontend/src/api/endpoints/*.ts`, shared types in
  `frontend/src/api/types.ts`.
- **MFA flow (authoritative):** `POST /ui/session/start` →
  `{auth_required, challenge_id, required_factors[]}` → `POST /ui/mfa/sms/begin` (dispatch) →
  `POST /ui/mfa/sms/verify` (with `challenge_id` + `code`) → `POST /ui/session/finalize` →
  `GET /ui/me`. Session rides on cookies + a `ui_csrf` cookie echoed as `X-CSRF-Token`.

## 3. Functional Requirements

1. Extend the existing repository seam (AND-034) with two SMS methods:
   ```kotlin
   interface MfaRepository {
       suspend fun verifyTotp(challengeId: String, code: String): ApiResult<MfaVerifyResult>   // AND-034
       suspend fun beginSms(challengeId: String): ApiResult<MfaBeginResult>                     // AND-035
       suspend fun verifySms(challengeId: String, code: String): ApiResult<MfaVerifyResult>     // AND-035
       suspend fun resendSms(challengeId: String): ApiResult<MfaBeginResult> = beginSms(challengeId)
       // email methods (AND-036) extend the same interface.
   }
   ```
   `resendSms` is a thin default delegating to `beginSms` — resend *is* re-begin — so callers
   express intent and telemetry can distinguish the two (Section 10) without divergent logic.
2. Define a new domain result `data class MfaBeginResult` in `core-model` carrying the masked
   destination and timing hints needed by AND-039's UI: `sentTo` (masked, e.g. `+1•••••1234`),
   `expiresInSeconds`, `resendAvailableInSeconds`.
3. `verifySms` **reuses** `MfaVerifyResult` (AND-034): `Completed` (challenge satisfied →
   caller proceeds to `session/finalize`) and `FactorsRemaining(factors)` (more factors
   required). No new verify result type is introduced.
4. `beginSms()` calls `MfaApiClient.beginSms(challengeId)` and folds the `ApiResult<MfaBeginResp>`
   into `ApiResult<MfaBeginResult>` via `flatMap`, mapping `sent_to` / `expires_in` /
   `resend_available_in` (defaulting `resend_available_in` to `0` if absent, per AND-033).
5. `verifySms()` calls `MfaApiClient.verifySms(challengeId, code.trim())` and applies the
   **same deterministic branching rule** AND-034 froze, against `MfaVerifyResp`:
   - `verified == true` && `remaining_factors` empty && `auth_complete == true` →
     `Success(MfaVerifyResult.Completed)`.
   - `verified == true` && (`remaining_factors` non-empty || `auth_complete == false`) →
     `Success(MfaVerifyResult.FactorsRemaining(remainingFactors.map(MfaFactor::fromWire)))`.
   - `verified == false` → `Failure(ApiError(status=200, code="sms_invalid", message=<detail
     or default>))`. A 200 with `verified=false` MUST NOT be reported as success.
6. The `code` argument is trimmed; the repository does **not** validate length/format (owned by
   AND-020/AND-039). A blank `code` short-circuits to `Failure(code="sms_invalid")` with **no**
   network call.
7. Remaining factors reuse `MfaFactor` (AND-028); unknown factor strings map to
   `MfaFactor.Unknown(raw)` and are retained, never dropped (forward-compat).
8. **Resend throttling:** a `429` from `begin`/resend maps to
   `Failure(ApiError(status=429, code="sms_resend_throttled", retryAfterSeconds=<retry_after>))`
   (AND-033's `ApiErrorMapper` surfaces `retry_after`); the repository passes it through so
   AND-039 can disable the resend control until the cooldown elapses.
9. Methods MUST NOT throw for expected outcomes (network down, 401, 422, 429, wrong code, blank
   code); all are encoded in `ApiResult`. `CancellationException` propagates unchanged.
10. The repository is stateless beyond the injected `MfaApiClient`; `challengeId`/`code` are
    supplied per call (held in ViewModel memory, AND-039) and never persisted.

## 4. Technical Design

Package layout:
- `com.testlogon.android.core.model.auth` — `MfaBeginResult` (new); reuses `MfaVerifyResult`
  and `MfaFactor` (AND-034/028).
- `com.testlogon.android.core.data.auth` — extends `MfaRepository` + `MfaRepositoryImpl`
  (AND-034).
- DTOs + `MfaApiClient` in `com.testlogon.android.core.network.auth` (AND-033).

Domain result (in `core-model`, framework-free):

```kotlin
package com.testlogon.android.core.model.auth

/** Outcome of an MFA "begin" dispatch (SMS or email). Carries UI-facing hints only. */
data class MfaBeginResult(
    /** Server-masked destination, e.g. "+1•••••1234". Pass through verbatim; never reformat. */
    val sentTo: String,
    /** Seconds until the dispatched code expires (for the AND-039 countdown). */
    val expiresInSeconds: Int,
    /** Seconds until resend is permitted; 0 means resend is immediately available. */
    val resendAvailableInSeconds: Int,
)
```

`MfaVerifyResult` is **defined by AND-034** and shown here only for the contract this ticket
reuses:

```kotlin
sealed interface MfaVerifyResult {
    data object Completed : MfaVerifyResult
    data class FactorsRemaining(val factors: List<MfaFactor>) : MfaVerifyResult
}
```

`MfaApiClient` methods consumed (from AND-033):

```kotlin
suspend fun beginSms(challengeId: String): ApiResult<MfaBeginResp>
suspend fun verifySms(challengeId: String, code: String): ApiResult<MfaVerifyResp>
```

Repository implementation (extending AND-034's `MfaRepositoryImpl`):

```kotlin
package com.testlogon.android.core.data.auth

class MfaRepositoryImpl @Inject constructor(
    private val client: MfaApiClient,                 // AND-033 façade
) : MfaRepository {

    // verifyTotp(...) implemented by AND-034.

    override suspend fun beginSms(challengeId: String): ApiResult<MfaBeginResult> =
        client.beginSms(challengeId).map { it.toBeginResult() }

    override suspend fun verifySms(
        challengeId: String,
        code: String,
    ): ApiResult<MfaVerifyResult> {
        val trimmed = code.trim()
        if (trimmed.isEmpty()) {
            return ApiResult.Failure(
                ApiError(status = 0, code = "sms_invalid", message = "Enter the code we sent you"),
            )
        }
        return client.verifySms(challengeId, trimmed).flatMap { it.toVerifyResult() }
    }

    private fun MfaBeginResp.toBeginResult() = MfaBeginResult(
        sentTo = sentTo,
        expiresInSeconds = expiresIn,
        resendAvailableInSeconds = resendAvailableIn,
    )

    private fun MfaVerifyResp.toVerifyResult(): ApiResult<MfaVerifyResult> = when {
        !verified -> ApiResult.Failure(
            ApiError(status = 200, code = "sms_invalid", message = detail ?: "Incorrect or expired code"),
        )
        remainingFactors.isNotEmpty() || !authComplete ->
            ApiResult.Success(MfaVerifyResult.FactorsRemaining(remainingFactors.map(MfaFactor::fromWire)))
        else -> ApiResult.Success(MfaVerifyResult.Completed)
    }
}
```

Notes:
- `map`/`flatMap` (AND-018) preserve `Failure`/`NetworkError` from `MfaApiClient` unchanged and
  apply the mapping only on `Success`, keeping the original transport/HTTP failure (including a
  `429`'s `retryAfterSeconds` and a `404|410` `challenge_expired`) intact for AND-039.
- HTTP-level "bad code" (server returns `400` with `detail.code == "mfa_invalid_code"`,
  AND-033) is normalized to `code="sms_invalid"` by a small remap layered on the AND-015
  mapper, so AND-039 keys a single localized "incorrect code" string off `sms_invalid`
  regardless of whether the backend signals via `verified=false` or an HTTP status.
- `resendSms` uses the interface default; no override needed.

Hilt binding is unchanged from AND-034 (`MfaRepositoryImpl` already `@Binds`-bound to
`MfaRepository`); this ticket adds no new module. `MfaApiClient` is injected per AND-033.

## 5. API Contract

Two endpoints consumed: **`POST /ui/mfa/sms/begin`** and **`POST /ui/mfa/sms/verify`**.
Cookies + `X-CSRF-Token` (`ui_csrf`) are added by interceptors (AND-011/AND-012), not by this
repository. `Content-Type: application/json`.

**Begin / resend** — `POST /ui/mfa/sms/begin`
Request:
```json
{ "challenge_id": "chl_7af3c2e1" }
```
Success `200`:
```json
{ "sent_to": "+1•••••1234", "expires_in": 300, "resend_available_in": 30, "challenge_id": "chl_7af3c2e1" }
```
→ `Success(MfaBeginResult(sentTo="+1•••••1234", expiresInSeconds=300, resendAvailableInSeconds=30))`

Resend throttled `429`:
```json
{ "detail": { "code": "mfa_resend_throttled", "retry_after": 22 } }
```
→ `Failure(ApiError(status=429, code="sms_resend_throttled", retryAfterSeconds=22))`

**Verify** — `POST /ui/mfa/sms/verify`
Request:
```json
{ "challenge_id": "chl_7af3c2e1", "code": "482915" }
```
Success — challenge complete (SMS was the last factor):
```json
{ "verified": true, "challenge_id": "chl_7af3c2e1", "remaining_factors": [], "auth_complete": true }
```
→ `Success(MfaVerifyResult.Completed)`

Success — factor accepted, more required:
```json
{ "verified": true, "challenge_id": "chl_7af3c2e1", "remaining_factors": ["email"], "auth_complete": false }
```
→ `Success(MfaVerifyResult.FactorsRemaining([Email]))`

Rejected code — HTTP 200 with `verified=false`:
```json
{ "verified": false, "challenge_id": "chl_7af3c2e1", "remaining_factors": [], "auth_complete": false, "detail": "Invalid code" }
```
→ `Failure(ApiError(status=200, code="sms_invalid", message="Invalid code"))`

Error responses folded by `safeApiCall`/AND-015 into `Failure(ApiError)` and remapped:
- **400 bad/expired code** — `{ "detail": { "code": "mfa_invalid_code", "attempts_remaining": 2 } }`
  → `Failure(ApiError(status=400, code="sms_invalid", attemptsRemaining=2))`. (A challenge-class
  `401` is also remapped to `sms_invalid`; it is NOT a session-expiry 401 and must not loop
  through AND-013 refresh — Section 7.)
- **422 validation** — `{ "detail": [ { "loc": ["body","code"], "msg": "field required" } ] }`
  → `Failure(ApiError(status=422, message="field required"))` (generic, **not** `sms_invalid`).
- **404 / 410 challenge not found/expired** → `Failure(ApiError(status=404|410,
  code="challenge_expired"))` so AND-039 routes back to login.
- **5xx / unreachable / timeout** → `ApiResult.NetworkError(isTimeout)`.

Endpoint reachability, verbs, paths, headers, and DTO shapes are *owned and MockWebServer-tested
by AND-033*; this ticket asserts only the begin/verify branch mapping and one request-shape test
over representative responses.

## 6. Data & State Management

- `MfaBeginResult`, `MfaVerifyResult`, and reused `MfaFactor` are immutable value types, safe to
  carry in `StateFlow` (AND-039 holds `sentTo` + the resend countdown in its `MfaUiState`).
- **No persistence in this ticket.** `challengeId` and `code` are transient — supplied per call,
  held only in ViewModel memory for the duration of the MFA flow; never written to Room or
  DataStore. The `code` is never retained after the call returns. The resend cooldown timer is
  UI state owned by AND-039, seeded from `resendAvailableInSeconds`; the repository does not
  track time.
- The **session/challenge cookies** (and `ui_csrf`) are persisted by the OkHttp cookie jar
  (AND-011) as a side effect of the HTTP calls; this repository neither reads nor writes cookies.
- Persistent *auth state* (authenticated flag, `user_sub`) is **out of scope** and owned by
  AND-029; it changes only after `session/finalize` + `getMe()`, which follow a `Completed`
  result (driven by AND-039), not within this ticket.
- `MfaRepositoryImpl` is a `@Singleton`, stateless apart from the injected `MfaApiClient`.

## 7. Error Handling & Resilience

- **No retry on POST.** Both `sms/begin` and `sms/verify` are non-idempotent, state-mutating
  POSTs (begin dispatches an SMS and resets the cooldown; verify consumes the single-use code).
  AND-016 retry/backoff applies to idempotent GETs only; each call issues exactly one network
  attempt. A `NetworkError` is surfaced to AND-039, which offers a manual retry — for `verify`
  the user must re-enter a *fresh* code (the prior one may be consumed/expired); for `begin` a
  manual retry re-dispatches.
- **Timeouts:** OkHttp ~20s (AND-009) against the flaky dev host; `SocketTimeoutException` folds
  to `ApiResult.NetworkError(isTimeout = true)` so AND-039 shows "server is slow" copy distinct
  from "you're offline".
- **Wrong/expired code:** both HTTP 200 `verified=false` and an HTTP 4xx with `detail.code ==
  mfa_invalid_code` normalize to `ApiError(code="sms_invalid")`, carrying `attemptsRemaining`
  when present. AND-039 keeps the user on the OTP screen, clears the field, surfaces remaining
  attempts, and does NOT navigate back to login for an `sms_invalid`.
- **Resend throttled (429):** mapped to `code="sms_resend_throttled"` with `retryAfterSeconds`;
  AND-039 disables the resend control until the cooldown elapses. The repository does not
  auto-retry a 429.
- **Challenge expired/not found (404/410):** mapped to `code="challenge_expired"`; AND-039
  treats this as terminal for the current challenge and routes back to `session/start`.
- **401 disambiguation:** a 401 on `/ui/mfa/sms/*` is a *challenge*-class rejection (bad code /
  invalid challenge), not session expiry; there is no completed session to refresh. AND-013's
  authenticator MUST NOT loop `session/refresh` for `/ui/mfa/*` verify 401s. This ticket relies
  on AND-013 scoping refresh away from MFA endpoints (open question Q1).
- **Blank code guard:** an empty/whitespace `code` short-circuits to
  `Failure(status=0, code="sms_invalid")` with no network call (defensive; primary validation in
  AND-020/AND-039).
- **Malformed success** (`verified=true` but unknown `remaining_factors`): unknown strings are
  retained as `MfaFactor.Unknown(raw)` and surfaced as "unsupported factor" rather than silently
  completing — fail-closed for an auth-critical branch.
- `CancellationException` propagates unchanged (structured concurrency; AND-018 wrapper rethrows).

## 8. Security & Privacy

- **Code handling:** the SMS OTP is passed straight into the request body and never logged,
  never stored, never placed in `ApiError`/`MfaVerifyResult`. It lives only on the coroutine
  frame for the call duration and is not retained after return.
- **`sent_to` is already masked** by the server (`+1•••••1234`); the repository passes it through
  verbatim and never reconstructs or logs a full phone number. It MUST NOT appear in telemetry
  (Section 10).
- **`challenge_id`** is short-lived session material tying the device to an in-progress
  challenge; held in caller memory only, never persisted, never logged or put in telemetry.
- **No request/response body logging** for `/ui/mfa/sms/*`. The OkHttp logging interceptor
  (AND-009/AND-033) MUST run at `BASIC` (or redact `/ui/mfa/*`) so neither `code`, `sent_to`,
  nor `challenge_id` reaches Logcat. Verified in Section 11.
- Session/CSRF tokens are managed by the cookie jar (AND-011) / CSRF interceptor (AND-012); this
  repository never reads cookie values. Cleartext HTTP to the dev host is a known dev-only
  posture (network security config permits cleartext for the dev flavor only); SMS codes
  traverse the wire unencrypted in dev only — production must enforce HTTPS (build-config owned
  upstream).
- `ApiError.message` from a rejected code carries the server `detail` only as a diagnostic
  fallback and must never echo the submitted `code` or the full destination.

## 9. Accessibility & i18n

N/A for the repository layer — no UI is produced here. Notes for the downstream owner (AND-039):
- `MfaBeginResult.sentTo` is server-masked and server-localized; AND-039 displays it verbatim
  (no client reformatting) and announces it via TalkBack ("code sent to +1•••••1234").
- The stable, machine-readable `ApiError.code` values (`sms_invalid`, `sms_resend_throttled`,
  `challenge_expired`) let AND-039 select **localized** strings rather than display server
  English; the repository emits raw `ApiError.message` only as a diagnostic fallback.
- The OTP entry affordance, content descriptions, the resend-countdown live-region
  announcements, RTL handling, and "incorrect code" announcements are owned by AND-020 (OTP
  composable) and AND-039 (MFA screen). `resendAvailableInSeconds`/`expiresInSeconds` are
  provided so AND-039 can render accessible countdowns.

## 10. Telemetry & Logging

- Emit structured events via the analytics/Timber seam (AND-009/AND-033), with **no PII / no
  secrets**:
  - `auth_mfa_sms_begin` with `is_resend` (true for `resendSms`), `outcome`
    (`sent | throttled | failure | network_error`), `http_status` (on failure),
    `retry_after_seconds` (on throttle), `is_timeout`.
  - `auth_mfa_sms_verify` with `outcome` (`completed | factors_remaining | rejected | failure |
    network_error`), `http_status` (on failure), `error_code` (`sms_invalid | challenge_expired
    | …`), `attempts_remaining` (when present), `remaining_factor_count` (on
    `factors_remaining`), `is_timeout`.
- **Never log:** the `code`, the `challenge_id`, the `sent_to` value, cookie values, or raw
  request/response bodies for these endpoints.
- The set of `remaining_factors` *types* (e.g. `["email"]`) is a category usable for funnel
  analysis and may be logged — but never paired with the `challenge_id`.
- The repository depends on no Android logging API directly beyond the injected logger seam,
  keeping `core-model` framework-free.

## 11. Testing Strategy

Unit tests in `core-data/src/test` (JUnit, Truth/kotlin-test, coroutines-test). `MfaApiClient`
is faked (hand-written fake or MockK stub returning canned `ApiResult<MfaBeginResp>` /
`ApiResult<MfaVerifyResp>`) so this ticket tests **branching/mapping**, not transport
(transport is AND-033's MockWebServer suite).

Begin mapping tests:
- `Success(MfaBeginResp(sentTo="+1•••••1234", expiresIn=300, resendAvailableIn=30))` →
  `Success(MfaBeginResult("+1•••••1234", 300, 30))`.
- `resendAvailableIn` absent (defaulted 0) → `resendAvailableInSeconds == 0`.
- `429` `mfa_resend_throttled` `retry_after=22` → `Failure(code="sms_resend_throttled",
  status=429, retryAfterSeconds=22)`.
- `resendSms(id)` delegates to `beginSms` (asserted: same client call, identical result).

Verify branch/mapping tests (acceptance core — begin sends, verify advances/finishes):
- `verified=true, remaining_factors=[], auth_complete=true` → `Success(Completed)`.
- `verified=true, remaining_factors=["email"], auth_complete=false` →
  `Success(FactorsRemaining([Email]))`.
- `verified=true, remaining_factors=["email","totp"]` → `[Email, Totp]` in order.
- `verified=true, remaining_factors=["webauthn"]` → `[Unknown("webauthn")]` (retained).
- `verified=false, detail="Invalid code"` → `Failure(status=200, code="sms_invalid",
  message="Invalid code")`.
- `verified=false, detail=null` → `Failure(code="sms_invalid", message="Incorrect or expired
  code")` (default).

Failure-passthrough / remap tests (fake `MfaApiClient` returns HTTP/network failure):
- `400` `mfa_invalid_code` `attempts_remaining=2` → `Failure(code="sms_invalid",
  attemptsRemaining=2)`.
- `401` challenge-class → remapped to `code="sms_invalid"` (NOT a refresh trigger here).
- `404` / `410` → `code="challenge_expired"`.
- `422` → `Failure(status=422)` (generic, NOT `sms_invalid`).
- timeout → `NetworkError(isTimeout=true)`; generic IO → `NetworkError(isTimeout=false)`.
- `CancellationException` from the fake → re-thrown (`assertFailsWith`).

Input-guard test:
- `verifySms("chl_1", "   ")` → `Failure(code="sms_invalid")` with **no** client call (assert the
  fake was not invoked).

Request-shape tests (one MockWebServer pair, complementing AND-033):
- `beginSms("chl_1")` issues `POST /ui/mfa/sms/begin` body `{"challenge_id":"chl_1"}`.
- `verifySms("chl_1", " 482915 ")` issues `POST /ui/mfa/sms/verify` body
  `{"challenge_id":"chl_1","code":"482915"}` (code trimmed; recorded request asserted).

Security test:
- with the OkHttp logging interceptor attached, a captured log of a `beginSms()`/`verifySms()`
  call contains none of the `code`, `challenge_id`, or `sent_to` substrings.

DI smoke test:
- Hilt provides `MfaRepository` (bound to `MfaRepositoryImpl`) with `beginSms`/`verifySms`
  callable (`@HiltAndroidTest` / component test).

## 12. Dependencies & Sequencing

- **Requires (blocking):**
  - **AND-033** — `MfaApiClient.beginSms`/`verifySms` + `MfaBeginResp`/`MfaVerifyResp` DTOs,
    MockWebServer-verified.
  - **AND-034** — `MfaRepository`/`MfaRepositoryImpl`, `MfaVerifyResult`, the branching rule, and
    the `MfaFactor.fromWire` reuse; this ticket extends them.
  - **AND-028** — `MfaFactor` (reused for `remaining_factors`) and the `MfaRequired.challengeId`
    that feeds these calls.
  - **AND-018** — `ApiResult`, `ApiError`, `safeApiCall`/`apiCall`, `map`/`flatMap`.
- **Strongly related (needed for end-to-end correctness, not strictly compile-time blocking):**
  AND-011 (cookie jar carries the challenge), AND-012 (CSRF header), AND-013 (401 scoping),
  AND-009 (timeouts/redacted logging), AND-015/AND-033 `ApiErrorMapper` (`detail` → `ApiError`,
  `retry_after`/`attempts_remaining`). The methods compile and unit-test via the faked
  `MfaApiClient` without them.
- **Enables / blocks:** AND-039 (MFA ViewModel/screen consuming `MfaBeginResult`/`MfaVerifyResult`
  and the resend control), AND-047 (auth end-to-end). Sibling AND-036 (email) extends the same
  interface and reuses both result types.
- **Sequencing:** Land after AND-033 and AND-034 (to inherit the frozen `MfaVerifyResult` shape
  and taxonomy), and AND-028/AND-018; before AND-039 and AND-047. Coordinate the `sms_invalid` /
  `sms_resend_throttled` / `challenge_expired` `code` taxonomy with the AND-034 (`totp_invalid`)
  and AND-036 (`email_invalid`) owners so AND-039 keys consistent localized copy.

## 13. Risks & Open Questions

- **R1 — Completion signal.** Assumes `auth_complete == true` + empty `remaining_factors`
  signals "challenge complete" (per AND-033's `MfaVerifyResp`). If the backend instead reuses
  `auth_required` or returns an inline session payload, adjust `toVerifyResult`. Confirm against
  `/openapi.json` and `frontend/src/api/endpoints/*.ts` before merge.
- **R2 — Wrong-code signalling (200 vs. 4xx).** Spec handles both `verified=false` (HTTP 200)
  and a `400` `mfa_invalid_code`, normalizing to `sms_invalid`. Confirm which the dev host uses
  and that `attempts_remaining` is populated, so the AND-015/AND-033 remap is correct.
- **R3 — `sent_to` / cooldown field names.** Assumes `sent_to`, `expires_in`,
  `resend_available_in` (AND-033 R1/R4). Verify against live samples; `resend_available_in` may
  be absent for some deployments (defaulted to 0).
- **R4 — Resend throttle code.** Assumes `429` `detail.code == mfa_resend_throttled` with
  `retry_after`. Confirm the code string and whether throttle is signalled on `begin` only or
  also `verify`.
- **Q1 — 401 disambiguation.** AND-013's authenticator must NOT loop `session/refresh` on a
  `/ui/mfa/*` 401 (no completed session to refresh). Confirm AND-013 scopes refresh away from
  MFA endpoints, or that a no-session 401 short-circuits refresh.
- **Q2 — Does a completing `sms/verify` finalize inline?** Assumed no; AND-039 calls
  `POST /ui/session/finalize` after `Completed`. If the server finalizes inline on the last
  factor and sets the full session cookie, AND-039 may skip finalize — confirm.

## 14. Acceptance Criteria

1. `MfaRepository` is extended with `suspend fun beginSms(challengeId): ApiResult<MfaBeginResult>`,
   `suspend fun verifySms(challengeId, code): ApiResult<MfaVerifyResult>`, and a `resendSms`
   default delegating to `beginSms`, in `com.testlogon.android.core.data.auth`; implemented in
   `MfaRepositoryImpl` (Hilt binding unchanged from AND-034).
2. `data class MfaBeginResult(sentTo, expiresInSeconds, resendAvailableInSeconds)` exists in
   `com.testlogon.android.core.model.auth`; `verifySms` returns the AND-034 `MfaVerifyResult`
   (no new verify type).
3. `beginSms()` calls `POST /ui/mfa/sms/begin` with body `{"challenge_id"}`; `verifySms()` calls
   `POST /ui/mfa/sms/verify` with body `{"challenge_id","code"}` (asserted via MockWebServer
   recorded requests), trimming the code.
4. **Begin sends the challenge; verify advances/finishes (tested):** a successful begin →
   `Success(MfaBeginResult(sentTo, …))`; a `verified=true` last-factor response →
   `Success(Completed)`; a `verified=true` with remaining factors →
   `Success(FactorsRemaining(factors))`; a `verified=false` (or 4xx bad-code) →
   `Failure(code="sms_invalid")` — per the Section 11 table.
5. Resend support works: `resendSms` re-invokes `begin`; a `429` maps to
   `Failure(code="sms_resend_throttled", retryAfterSeconds=…)`.
6. Remaining factors map via `MfaFactor.fromWire`; unknown entries → `MfaFactor.Unknown(raw)`,
   retained. Challenge-expired (404/410) → `Failure(code="challenge_expired")`; 422 → generic
   `Failure(status=422)` (not `sms_invalid`).
7. Transport/HTTP failures pass through unchanged: IO/timeout → `NetworkError`; HTTP error →
   `Failure(ApiError)`; `CancellationException` re-thrown. Blank `code` →
   `Failure(code="sms_invalid")` with no network call.
8. No `code`, `challenge_id`, or `sent_to` value appears in logs for begin/verify calls
   (security test green).
9. `./gradlew :core-data:test` (and `:core-model:test`) green; ktlint/detekt (AND-005) pass.

## 15. Definition of Done

- `beginSms`/`verifySms`/`resendSms` on `MfaRepository`, `MfaRepositoryImpl` implementations, and
  `MfaBeginResult` are implemented, compile, and are merged to `android-port`.
- Unit tests cover every begin/verify branch, the resend-throttle map, every remap and
  failure-passthrough case in Section 11, and pass via `./gradlew :core-data:test`; the
  MockWebServer request-shape and no-secret-logging tests pass.
- Public types, the reused branching rule (Section 3.5), and the `code` taxonomy (`sms_invalid`,
  `sms_resend_throttled`, `challenge_expired`) are documented in KDoc, cross-referencing the
  AND-034 `MfaVerifyResult` contract.
- No Retrofit/OkHttp/Moshi types leak through the `MfaRepository` interface (verified by
  inspecting the signature; only `core-model` types appear).
- ktlint/detekt (AND-005) pass on new files; code reviewed.
- AND-039 (and the AND-036 owner) notified that `MfaBeginResult` and the SMS `code` taxonomy are
  frozen for consumption; open questions Q1–Q2 and risks R1–R4 either resolved against
  `/openapi.json` / `frontend/src/api/endpoints` or filed as follow-ups before AND-039
  integration.
