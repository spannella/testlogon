---
id: AND-035
title: "SMS begin/verify flow"
milestone: M1
epic: E05
priority: P0
size: M
depends_on: [AND-033, AND-034, AND-028, AND-018]
blocks: [AND-039, AND-047]
status: reviewed
reviewed_on: 2026-06-06
---

# AND-035 — SMS begin/verify flow

## 1. Overview & Goal

This ticket adds the **SMS** factor to the cookie-based authentication MFA flow. Unlike TOTP
(AND-034), where the authenticator app produces a code offline, the SMS factor is a two-step
**begin → verify** exchange: the client first asks the backend to dispatch a one-time code to
the user's registered phone (`POST /ui/mfa/sms/begin`, which returns a `ChallengeResp` carrying
`challenge_id` and an **optional `sent_to` array of masked destinations** — CORRECTED: the
contract is `sent_to?: string[]`, not a single masked string and not a `MfaBeginResp` with
timing fields; see §16), then submits the user-entered code (`POST /ui/mfa/sms/verify`). The
ticket also delivers **resend** support, which is simply a re-invocation of `begin`. NOTE
(CORRECTED): the contract returns **no** `expires_in` / `resend_available_in` cooldown fields on
begin; any cooldown surfacing is an unverified assumption — see §16/§13.

Scope is two repository-layer seams on the shared `MfaRepository` interface introduced by
AND-034: `beginSms(challengeId)` and `verifySms(challengeId, code)`, plus the
`resendSms(challengeId)` alias. `beginSms` returns a new domain result `MfaBeginResult`
carrying the masked destination(s) from `ChallengeResp.sent_to` (CORRECTED: cooldown/expiry
hints are NOT in the contract and are dropped from the result — see §16); `verifySms` **reuses
the exact `MfaVerifyResult` shape frozen by AND-034** (`Completed` | `FactorsRemaining`) so the MFA
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
   destination(s). CORRECTED (§16): the begin response is `ChallengeResp = { challenge_id:
   string; sent_to?: string[] }` (verified against `src/api/types.ts: ChallengeResp` and
   `components.schemas` — the begin op response is the unnamed `200:` body the web client types
   as `ChallengeResp`). There are **no** `expires_in` / `resend_available_in` fields. Therefore:
   - `sentTo: List<String>` (the masked destinations, possibly empty/absent → empty list). Pass
     through verbatim; the web client never reformats.
   - `expiresInSeconds` / `resendAvailableInSeconds` are **removed** — they are not in the
     contract. If AND-039 needs a client-side resend cooldown it must own a fixed local timer
     (unverified product decision, see §16 Open assumptions), not a server hint.
3. `verifySms` **reuses** `MfaVerifyResult` (AND-034): `Completed` (challenge satisfied →
   caller proceeds to `session/finalize`) and `FactorsRemaining(factors)` (more factors
   required). No new verify result type is introduced.
4. `beginSms()` calls `MfaApiClient.beginSms(challengeId)` and folds the begin response (web
   contract `ChallengeResp`) into `ApiResult<MfaBeginResult>` via `map`, mapping `sent_to` (an
   optional `string[]`) to `sentTo: List<String>` (empty list if absent). CORRECTED: there is no
   `expires_in` / `resend_available_in` to map.
5. `verifySms()` calls `MfaApiClient.verifySms(challengeId, code.trim())` and applies the
   **same deterministic branching rule** AND-034 froze, against `MfaVerifyResp`. CORRECTED (§16):
   the verified contract is `MfaVerifyResp = { status: string; session_id?: string;
   required_factors: string[]; passed: Record<string,boolean>; remaining_factors: string[] }`
   (verified against `src/api/types.ts: MfaVerifyResp`). There is **no** `verified` boolean and
   **no** `auth_complete` boolean. The web client (`src/pages/Login.tsx` handleMfaVerify) treats
   a 200 as factor-accepted and branches solely on `remaining_factors.length`:
   - `remaining_factors` empty → `Success(MfaVerifyResult.Completed)` (caller then proceeds to
     `POST /ui/session/finalize`, exactly as `Login.tsx` does).
   - `remaining_factors` non-empty →
     `Success(MfaVerifyResult.FactorsRemaining(remainingFactors.map(MfaFactor::fromWire)))`.
   - A **rejected code is an HTTP error** (4xx with `detail`), NOT a 200 with `verified=false`.
     CORRECTED: the `verified=false`-on-200 branch is removed; there is no `verified` field. A
     200 is always a passed factor in the contract.
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

/**
 * Outcome of an MFA "begin" dispatch (SMS or email).
 * CORRECTED (§16): the begin contract is `ChallengeResp = { challenge_id; sent_to?: string[] }`.
 * There are NO server-supplied expiry/cooldown fields, so this result carries only the masked
 * destination list.
 */
data class MfaBeginResult(
    /**
     * Server-masked destination(s), e.g. ["+1•••••1234"]. Optional/absent → empty list.
     * Pass through verbatim; never reformat. (AND-039 typically shows the first entry.)
     */
    val sentTo: List<String>,
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
        // CORRECTED: a 200 is always a passed factor (no `verified` field), so a plain `map`
        // suffices — there is no in-body rejection branch to surface as Failure.
        return client.verifySms(challengeId, trimmed).map { it.toVerifyResult() }
    }

    // CORRECTED: ChallengeResp.sent_to is `string[]?`; no expires_in / resend_available_in.
    private fun MfaBeginResp.toBeginResult() = MfaBeginResult(
        sentTo = sentTo.orEmpty(),
    )

    // CORRECTED: branch ONLY on remaining_factors (no `verified` / `auth_complete` in contract),
    // matching src/pages/Login.tsx (`resp.remaining_factors.length === 0` → finalize).
    private fun MfaVerifyResp.toVerifyResult(): MfaVerifyResult =
        if (remainingFactors.isEmpty()) {
            MfaVerifyResult.Completed
        } else {
            MfaVerifyResult.FactorsRemaining(remainingFactors.map(MfaFactor::fromWire))
        }
}
```

Notes:
- `map` (AND-018) preserves `Failure`/`NetworkError` from `MfaApiClient` unchanged and applies
  the mapping only on `Success`, keeping the original transport/HTTP failure (including any
  `404|410` `challenge_expired`) intact for AND-039.
- HTTP-level "bad code": the rejection path is an HTTP **4xx with FastAPI `detail`** (the OpenAPI
  enumerates `422:HTTPValidationError` for verify; other 4xx bodies carry `detail` per the AND-015
  mapper). UNVERIFIED ASSUMPTION (§16): the exact 4xx status and a `detail.code ==
  "mfa_invalid_code"`/`attempts_remaining` shape are not in the OpenAPI (verify lists only
  `200` and `422`). If a non-422 bad-code status is used, remap it to `code="sms_invalid"` so
  AND-039 keys one localized "incorrect code" string; until confirmed, treat any 4xx `detail`
  generically. There is NO `verified=false`-on-200 signal in the contract.
- `resendSms` uses the interface default; no override needed.

Hilt binding is unchanged from AND-034 (`MfaRepositoryImpl` already `@Binds`-bound to
`MfaRepository`); this ticket adds no new module. `MfaApiClient` is injected per AND-033.

## 5. API Contract

Two endpoints consumed: **`POST /ui/mfa/sms/begin`** and **`POST /ui/mfa/sms/verify`**.
Cookies + `X-CSRF-Token` (`ui_csrf`) are added by interceptors (AND-011/AND-012), not by this
repository. `Content-Type: application/json`.

CONTRACT SOURCES (verified): request schemas `components.schemas.SmsBeginReq` /
`SmsVerifyReq`; begin response typed `ChallengeResp` and verify response typed `MfaVerifyResp`
by the web client (`src/api/endpoints/auth.ts: beginSms/verifySms`, `src/api/types.ts`). The
OpenAPI index lists both responses as `200:` (unnamed body) + `422:HTTPValidationError`.

**Begin / resend** — `POST /ui/mfa/sms/begin` (req schema `SmsBeginReq`)
Request:
```json
{ "challenge_id": "chl_7af3c2e1" }
```
Success `200` (`ChallengeResp`):
```json
{ "challenge_id": "chl_7af3c2e1", "sent_to": ["+1•••••1234"] }
```
→ `Success(MfaBeginResult(sentTo=["+1•••••1234"]))`
CORRECTED: `sent_to` is an OPTIONAL `string[]` (may be absent → empty list). There are NO
`expires_in` / `resend_available_in` fields. The web client (`Login.tsx handleSendSms`) ignores
the begin body entirely and just sets a "sent" flag.

Resend: simply re-`POST /ui/mfa/sms/begin` (the web client calls the same `beginSms`).
UNVERIFIED ASSUMPTION (§16): a `429`/`detail.code == "mfa_resend_throttled"`/`retry_after`
throttle shape is NOT present in the OpenAPI (begin lists only `200` + `422`). If the dev host
returns a 429 it should map to `code="sms_resend_throttled"` with `retryAfterSeconds`, but this
is unconfirmed; do not rely on a server cooldown.

**Verify** — `POST /ui/mfa/sms/verify` (req schema `SmsVerifyReq`)
Request:
```json
{ "challenge_id": "chl_7af3c2e1", "code": "482915" }
```
Success — challenge complete (SMS was the last factor), `MfaVerifyResp`:
```json
{ "status": "ok", "session_id": null, "required_factors": ["sms"], "passed": {"sms": true}, "remaining_factors": [] }
```
→ `Success(MfaVerifyResult.Completed)` (caller then `POST /ui/session/finalize`).
CORRECTED: completion is `remaining_factors.length === 0` (per `Login.tsx`), NOT a `verified` /
`auth_complete` boolean — neither field exists.

Success — factor accepted, more required:
```json
{ "status": "pending", "required_factors": ["sms","email"], "passed": {"sms": true}, "remaining_factors": ["email"] }
```
→ `Success(MfaVerifyResult.FactorsRemaining([Email]))`

Rejected code: CORRECTED — there is **no** HTTP-200 `verified:false` body. A wrong/expired code
is returned as an HTTP **4xx with FastAPI `detail`** and folded by `safeApiCall`/AND-015 into
`Failure(ApiError)`.

Error responses folded by `safeApiCall`/AND-015 into `Failure(ApiError)` and remapped:
- **4xx bad/expired code** — UNVERIFIED ASSUMPTION (§16): exact status + `detail.code ==
  "mfa_invalid_code"`/`attempts_remaining` shape are NOT in the OpenAPI (verify lists only `200`
  + `422`). Where present, remap to `Failure(ApiError(code="sms_invalid", attemptsRemaining=…))`.
  A challenge-class `401` (no completed session) is also remapped to `sms_invalid`; it must NOT
  loop through AND-013 refresh — Section 7. (Web client mechanism CONFIRMED: `client.ts` only
  refreshes a 401 when `isAuthenticated`; an unauthenticated 401 propagates directly — see §16.)
- **422 validation** (VERIFIED in OpenAPI: `422:HTTPValidationError`) —
  `{ "detail": [ { "loc": ["body","code"], "msg": "field required" } ] }`
  → `Failure(ApiError(status=422, message="field required"))` (generic, **not** `sms_invalid`).
- **404 / 410 challenge not found/expired** → `Failure(ApiError(status=404|410,
  code="challenge_expired"))` so AND-039 routes back to login. UNVERIFIED ASSUMPTION (§16): the
  OpenAPI does not enumerate 404/410 for these ops.
- **5xx / unreachable / timeout** → `ApiResult.NetworkError(isTimeout)`.

Endpoint reachability, verbs, paths, headers, and DTO shapes are *owned and MockWebServer-tested
by AND-033*; this ticket asserts only the begin/verify branch mapping and one request-shape test
over representative responses.

## 6. Data & State Management

- `MfaBeginResult`, `MfaVerifyResult`, and reused `MfaFactor` are immutable value types, safe to
  carry in `StateFlow` (AND-039 holds `sentTo` — a `List<String>` — in its `MfaUiState`; any
  resend countdown is a client-side timer, not a server hint — CORRECTED, see §16).
- **No persistence in this ticket.** `challengeId` and `code` are transient — supplied per call,
  held only in ViewModel memory for the duration of the MFA flow; never written to Room or
  DataStore. The `code` is never retained after the call returns. The resend cooldown timer is
  UI state owned by AND-039 (a fixed client-side timer; CORRECTED — there is no server
  `resend_available_in` to seed from, see §16); the repository does not track time.
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
- **Wrong/expired code:** CORRECTED — there is no HTTP-200 `verified=false` body (no `verified`
  field exists). A wrong/expired code is an HTTP **4xx with `detail`**, normalized to
  `ApiError(code="sms_invalid")`, carrying `attemptsRemaining` when present (the 4xx status +
  `attempts_remaining` shape is an UNVERIFIED ASSUMPTION, §16 — verify lists only 200/422). AND-039
  keeps the user on the OTP screen, clears the field, surfaces remaining attempts (when present),
  and does NOT navigate back to login for an `sms_invalid`.
- **Resend throttled (429):** UNVERIFIED ASSUMPTION (§16) — no 429 is enumerated for begin
  (200/422 only). IF returned, map to `code="sms_resend_throttled"` with `retryAfterSeconds` so
  AND-039 disables resend until the cooldown elapses; the repository does not auto-retry a 429.
  Until confirmed, AND-039 should gate resend with a fixed client-side cooldown.
- **Challenge expired/not found (404/410):** mapped to `code="challenge_expired"`; AND-039
  treats this as terminal for the current challenge and routes back to `session/start`.
- **401 disambiguation:** a 401 on `/ui/mfa/sms/*` is a *challenge*-class rejection (bad code /
  invalid challenge), not session expiry; there is no completed session to refresh. AND-013's
  authenticator MUST NOT loop `session/refresh` for `/ui/mfa/*` verify 401s. VERIFIED reference
  mechanism (`src/api/client.ts`): the web client refreshes a 401 **only when
  `isAuthenticated`** is already true; during the MFA flow the user is not yet authenticated, so
  an MFA 401 throws straight through without a refresh attempt. AND-013 should mirror this
  (gate refresh on an existing session / scope it away from `/ui/mfa/*`). (open question Q1)
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
- `MfaBeginResult.sentTo` is a server-masked `List<String>` (CORRECTED, see §16); AND-039
  displays the first entry verbatim (no client reformatting) and announces it via TalkBack
  ("code sent to +1•••••1234"). If the list is empty, AND-039 shows generic "code sent" copy.
- The stable, machine-readable `ApiError.code` values (`sms_invalid`, `sms_resend_throttled`,
  `challenge_expired`) let AND-039 select **localized** strings rather than display server
  English; the repository emits raw `ApiError.message` only as a diagnostic fallback.
- The OTP entry affordance, content descriptions, the resend-countdown live-region
  announcements, RTL handling, and "incorrect code" announcements are owned by AND-020 (OTP
  composable) and AND-039 (MFA screen). CORRECTED (§16): no server `resend_available_in` /
  `expires_in` is provided; any countdown AND-039 renders is a fixed client-side timer.

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

Begin mapping tests (CORRECTED to the real `ChallengeResp` shape):
- `Success(MfaBeginResp(sentTo=["+1•••••1234"]))` → `Success(MfaBeginResult(["+1•••••1234"]))`.
- `sent_to` absent/null → `sentTo == emptyList()`.
- `sent_to` multi-entry `["+1•••••1234","+44•••••999"]` → both retained, in order.
- `resendSms(id)` delegates to `beginSms` (asserted: same client call, identical result).
- (If/when a 429 throttle is confirmed — §16 open assumption — a `Failure(code=
  "sms_resend_throttled", status=429, retryAfterSeconds=…)` mapping test should be added.)

Verify branch/mapping tests (acceptance core — begin sends, verify advances/finishes;
CORRECTED — branch on `remaining_factors` only, no `verified`/`auth_complete`):
- `status="ok", remaining_factors=[]` → `Success(Completed)`.
- `status="pending", remaining_factors=["email"]` → `Success(FactorsRemaining([Email]))`.
- `remaining_factors=["email","totp"]` → `[Email, Totp]` in order.
- `remaining_factors=["webauthn"]` → `[Unknown("webauthn")]` (retained).

Failure-passthrough / remap tests (fake `MfaApiClient` returns HTTP/network failure):
- 4xx bad-code with `detail.code="mfa_invalid_code"` `attempts_remaining=2` →
  `Failure(code="sms_invalid", attemptsRemaining=2)` (UNVERIFIED 4xx shape — §16).
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

- **R1 — Completion signal.** RESOLVED (this review): completion is empty `remaining_factors`,
  NOT an `auth_complete`/`verified` flag (neither field exists). `MfaVerifyResp` =
  `{status, session_id?, required_factors, passed, remaining_factors}`; `src/pages/Login.tsx`
  branches on `remaining_factors.length === 0` then calls `session/finalize`. `toVerifyResult`
  corrected accordingly (§16).
- **R2 — Wrong-code signalling (200 vs. 4xx).** RESOLVED in part: there is NO HTTP-200
  `verified=false` body — a 200 is always a passed factor. A wrong code is an HTTP 4xx with
  `detail`. STILL OPEN: the exact 4xx status and whether `detail.code="mfa_invalid_code"` /
  `attempts_remaining` are populated (OpenAPI enumerates only `200` + `422` for verify). Confirm
  against the dev host (§16 Open assumptions).
- **R3 — `sent_to` / cooldown field names.** RESOLVED: begin returns `ChallengeResp =
  {challenge_id, sent_to?: string[]}` (verified). There are NO `expires_in` /
  `resend_available_in` fields — both removed from `MfaBeginResult` (§16). `sent_to` is an
  optional array (empty list if absent).
- **R4 — Resend throttle code.** STILL OPEN: no `429` is enumerated for begin (200/422 only);
  the `mfa_resend_throttled`/`retry_after` shape is unverified. Treat resend throttling as a
  client-side concern until confirmed (§16 Open assumptions).
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
2. `data class MfaBeginResult(sentTo: List<String>)` exists in
   `com.testlogon.android.core.model.auth` (CORRECTED — no `expiresInSeconds`/
   `resendAvailableInSeconds`; not in the contract); `verifySms` returns the AND-034
   `MfaVerifyResult` (no new verify type).
3. `beginSms()` calls `POST /ui/mfa/sms/begin` with body `{"challenge_id"}`; `verifySms()` calls
   `POST /ui/mfa/sms/verify` with body `{"challenge_id","code"}` (asserted via MockWebServer
   recorded requests), trimming the code.
4. **Begin sends the challenge; verify advances/finishes (tested):** a successful begin →
   `Success(MfaBeginResult(sentTo))`; a last-factor response (`remaining_factors == []`) →
   `Success(Completed)`; a response with remaining factors →
   `Success(FactorsRemaining(factors))`; a 4xx bad-code → `Failure(code="sms_invalid")` — per
   the Section 11 table. (CORRECTED: branch on `remaining_factors`, not `verified`/`auth_complete`;
   there is no 200 `verified=false` path.)
5. Resend support works: `resendSms` re-invokes `begin`. (CORRECTED: a server `429`
   `sms_resend_throttled` map is an UNVERIFIED assumption, §16 — only assert it if the dev host
   confirms a 429; resend gating is otherwise client-side.)
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact authoritative source.

1. **`POST /ui/mfa/sms/begin` exists, request body `{challenge_id}`.** VERIFIED.
   OpenAPI `POST /ui/mfa/sms/begin` (op `ui_sms_begin_…`, `req=SmsBeginReq`);
   `components.schemas.SmsBeginReq = { challenge_id: string }` (required). Frontend
   `src/api/endpoints/auth.ts: beginSms` → `api.post("/ui/mfa/sms/begin", body)`.
2. **`POST /ui/mfa/sms/verify` exists, request body `{challenge_id, code}`.** VERIFIED.
   OpenAPI `POST /ui/mfa/sms/verify` (`req=SmsVerifyReq`);
   `components.schemas.SmsVerifyReq = { challenge_id: string, code: string }` (both required).
   Frontend `src/api/endpoints/auth.ts: verifySms`.
3. **Both are POST (non-idempotent); no GET variant.** VERIFIED. OpenAPI index lists only the
   `POST` rows for these paths.
4. **Begin response carries a single masked `sent_to` string plus `expires_in` /
   `resend_available_in`.** CORRECTED. The begin response is typed `ChallengeResp` by the web
   client (`src/api/endpoints/auth.ts: beginSms` → `api.post<ChallengeResp>`), and
   `src/api/types.ts: ChallengeResp = { challenge_id: string; sent_to?: string[] }`. `sent_to`
   is an OPTIONAL array of strings; there are NO `expires_in` / `resend_available_in` fields.
   OpenAPI lists the begin response as unnamed `200:` (no schema), so the web type is
   authoritative. → `MfaBeginResult.sentTo` changed to `List<String>`; timing fields removed.
5. **Verify response has `verified: bool` and `auth_complete: bool`; a 200 with
   `verified=false` is a rejection.** CORRECTED. `src/api/types.ts: MfaVerifyResp =
   { status: string; session_id?: string; required_factors: string[]; passed:
   Record<string,boolean>; remaining_factors: string[] }`. No `verified`, no `auth_complete`.
   A 200 is always a passed factor; the in-body rejection branch was removed.
6. **Completion is signalled by empty `remaining_factors`, after which the caller calls
   `session/finalize`.** VERIFIED. `src/pages/Login.tsx` (handleMfaVerify): `if
   (resp.remaining_factors.length === 0) { … sessionFinalize({challenge_id, remember_device}) }`,
   then on `finalResp.status === "ok" && finalResp.session_id` calls `getMe()`.
7. **`session/finalize` shape.** VERIFIED. `src/api/types.ts: SessionFinalizeResp =
   { status: "ok"|"pending"; session_id?: string; required_factors: string[]; passed:
   Record<string,boolean> }`; req `SessionFinalizeReq = { challenge_id; remember_device? }`.
   (Context for the §2 flow; finalize itself is AND-039's call, not this ticket's.)
8. **`session/start` → `{auth_required, challenge_id, required_factors[]}`.** VERIFIED.
   `src/api/types.ts: SessionStartResp = { auth_required: boolean; challenge_id?: string;
   required_factors: string[]; session_id? }`. (§2 flow.)
9. **Auth/transport: cookies + `ui_csrf` cookie echoed as `X-CSRF-Token`.** VERIFIED.
   `src/api/client.ts`: `getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`, all
   requests use `credentials: "include"`. (Added by AND-011/AND-012 interceptors on Android,
   not by this repository.)
10. **A 401 on `/ui/mfa/*` must NOT trigger a `session/refresh` loop (no completed session).**
    VERIFIED (mechanism). `src/api/client.ts`: on 401 it refreshes only `if
    (useAuthStore.getState().isAuthenticated)`; an unauthenticated 401 throws straight through.
    During MFA the user is not yet authenticated, so no refresh occurs. AND-013 should mirror.
11. **Remaining factors are plain strings mapped via `MfaFactor.fromWire`; unknown → retained.**
    VERIFIED (shape). `remaining_factors: string[]` (citation 5); the web client passes them as
    strings (`setRequiredFactors(resp.required_factors)`). The `MfaFactor.fromWire`/`Unknown`
    mapping is AND-028/AND-034's contract (out of scope here) — reuse is a design choice.
12. **Resend = re-invoke `begin`.** VERIFIED. `src/pages/Login.tsx: handleSendSms` calls
    `beginSms({challenge_id})` for both initial send and resend; no distinct resend endpoint.
13. **Resend throttle: `429` `detail.code="mfa_resend_throttled"` with `retry_after`.**
    UNVERIFIED-ASSUMPTION. OpenAPI begin lists only `200` + `422:HTTPValidationError`; no 429
    enumerated and no such schema in `components.schemas`. The web client does not handle a 429
    specially for begin.
14. **Bad code → 4xx with `detail.code="mfa_invalid_code"` and `attempts_remaining`.**
    UNVERIFIED-ASSUMPTION. OpenAPI verify lists only `200` + `422:HTTPValidationError`; no
    `mfa_invalid_code`/`attempts_remaining` schema exists. What IS verified: a wrong code is an
    HTTP error (not a 200 body), and `client.ts` surfaces FastAPI `detail` via `ApiError`.
15. **404 / 410 → `challenge_expired`.** UNVERIFIED-ASSUMPTION. OpenAPI does not enumerate
    404/410 for these ops (only `200` + `422`). Reasonable mapping, but unconfirmed.
16. **422 validation → `HTTPValidationError`.** VERIFIED. OpenAPI index: both ops list
    `422:HTTPValidationError`; `components.schemas.HTTPValidationError` is the standard FastAPI
    `{detail: [{loc, msg, type}]}` list.
17. **Network-security: cleartext dev host `http://18.222.237.167:8000`.** UNVERIFIED-ASSUMPTION
    from the spec's environment notes; not checkable from OpenAPI/frontend sources (build-config
    concern owned upstream).
18. **`MfaApiClient`/DTOs (`MfaBeginResp`/`MfaVerifyResp`) and `ApiResult`/`safeApiCall`.**
    UNVERIFIED-ASSUMPTION (internal Android contracts owned by AND-033/AND-018; no source in
    this repo to verify). Their existence/shape is taken on the dependency contract; the DTO
    field names used here are constrained to match citations 4–5.
19. **Framework choices (Kotlin/Coroutines, Retrofit 2.11, Moshi, Hilt, minSdk 24).** framework
    ref — Android/library stack assertions; not verifiable against the provided sources, accepted
    as project conventions.

### Corrections made

- C1 — Begin response remodeled from a single masked `sent_to` string + `expires_in` +
  `resend_available_in` to `ChallengeResp = {challenge_id, sent_to?: string[]}`;
  `MfaBeginResult` reduced to `sentTo: List<String>` (citations 4). Updated §1, §2-adjacent,
  §3.2/§3.4, §4 (data class + `toBeginResult`), §5, §6, §9, §11, §14.2.
- C2 — Verify response remodeled: removed `verified` and `auth_complete`; branch solely on
  `remaining_factors` emptiness; removed the HTTP-200 `verified=false` rejection path (citations
  5, 6). Updated §3.5, §4 (`toVerifyResult` + `flatMap`→`map`), §5, §7, §11, §14.4.
- C3 — Resend throttle (`429`/`mfa_resend_throttled`/`retry_after`) demoted from asserted
  contract to explicitly-flagged unverified assumption with client-side fallback (citation 13).
  Updated §5, §7, §11, §13.R4, §14.5.
- C4 — Bad-code 4xx (`mfa_invalid_code`/`attempts_remaining`) and 404/410 `challenge_expired`
  flagged as unverified; clarified the rejection is an HTTP error not a 200 body (citations
  14, 15). Updated §4 notes, §5, §7, §13.R1/R2.
- C5 — 401-no-refresh claim upgraded to VERIFIED with the actual `client.ts` mechanism
  (citation 10). Updated §7.
- C6 — Frontmatter `status: draft` → `reviewed`; added `reviewed_on: 2026-06-06`.

### Open assumptions

- OA1 — Resend throttling shape (HTTP 429 + `detail.code="mfa_resend_throttled"` +
  `retry_after`). WHY: not in OpenAPI (begin = 200/422 only) and not in `components.schemas`;
  no frontend handling. Needs a live dev-host probe or backend confirmation.
- OA2 — Bad-code error shape (exact 4xx status + `detail.code="mfa_invalid_code"` +
  `attempts_remaining`). WHY: OpenAPI verify enumerates only 200 + 422; the field shape is not
  in `components.schemas`. Only the "it's an HTTP error, not a 200 body" fact is confirmed.
- OA3 — 404/410 `challenge_expired` mapping. WHY: not enumerated for these ops in OpenAPI.
- OA4 — Whether a completing `sms/verify` finalizes inline (Q2). WHY: the web client always
  calls `session/finalize` after empty `remaining_factors`; no inline-finalize signal is in the
  verify schema, but the dev-host runtime behavior is unconfirmed.
- OA5 — AND-033/AND-018 internal DTO/`ApiResult` shapes (`MfaBeginResp` naming, `flatMap`/`map`,
  `ApiError` fields). WHY: owned by other tickets; no source available in this repo.
- OA6 — Cleartext-HTTP dev posture and the framework/version stack. WHY: build-config / project
  conventions, not in the provided authoritative sources.

## 17. Test Plan

All cases target the `core-data` / `core-model` repository layer (the scope of this ticket).
The repository is pure JVM logic over a faked `MfaApiClient`, so the bulk runs as JVM unit tests
(no device). Contract/transport cases use MockWebServer (Robolectric/JVM). The few
device/emulator notes call out where the ABI/API matters. AC-# refer to §14.

- **TC-AND-035-01** — Type: unit (JVM). Target: `MfaRepositoryImpl.beginSms`. Preconditions:
  fake `MfaApiClient.beginSms` returns `Success(MfaBeginResp(sentTo=["+1•••••1234"]))`.
  Steps: call `beginSms("chl_1")`. Expected: `Success(MfaBeginResult(sentTo=["+1•••••1234"]))`;
  list passed through verbatim. Traces: AC-1, AC-2, AC-4.
- **TC-AND-035-02** — Type: unit (JVM). Target: `beginSms` absent `sent_to`. Preconditions:
  fake returns `Success(MfaBeginResp(sentTo=null))`. Steps: call `beginSms("chl_1")`. Expected:
  `Success(MfaBeginResult(sentTo=emptyList()))` (no NPE; defaulted). Traces: AC-2, AC-4.
- **TC-AND-035-03** — Type: unit (JVM). Target: `resendSms` default delegation. Preconditions:
  spy/fake `MfaApiClient`. Steps: call `resendSms("chl_1")`. Expected: identical to
  `beginSms("chl_1")` — same single client `beginSms` call, identical result; no separate
  endpoint. Traces: AC-1, AC-5.
- **TC-AND-035-04** — Type: unit (JVM). Target: `verifySms` completion branch. Preconditions:
  fake `verifySms` returns `Success(MfaVerifyResp(status="ok", remainingFactors=[]))`. Steps:
  call `verifySms("chl_1","482915")`. Expected: `Success(MfaVerifyResult.Completed)` (branch on
  empty `remaining_factors`; no `verified`/`auth_complete` referenced). Traces: AC-2, AC-4.
- **TC-AND-035-05** — Type: unit (JVM). Target: `verifySms` factors-remaining branch.
  Preconditions: fake returns `Success(MfaVerifyResp(status="pending",
  remainingFactors=["email"]))`. Steps: call `verifySms`. Expected:
  `Success(FactorsRemaining([MfaFactor.Email]))`. Traces: AC-4, AC-6.
- **TC-AND-035-06** — Type: unit (JVM). Target: factor mapping order + unknown retention.
  Preconditions: fake returns `remainingFactors=["email","totp","webauthn"]`. Steps: call
  `verifySms`. Expected: `FactorsRemaining([Email, Totp, Unknown("webauthn")])` — order
  preserved, unknown retained (fail-closed). Traces: AC-6.
- **TC-AND-035-07** — Type: unit (JVM). Target: blank-code guard. Preconditions: fake
  `MfaApiClient` records calls. Steps: call `verifySms("chl_1","   ")`. Expected:
  `Failure(ApiError(status=0, code="sms_invalid"))` and the fake's `verifySms` is NEVER invoked
  (assert zero interactions). Traces: AC-7.
- **TC-AND-035-08** — Type: unit (JVM). Target: HTTP bad-code remap (UNVERIFIED shape, OA2).
  Preconditions: fake returns `Failure(ApiError(status=4xx, code="mfa_invalid_code",
  attemptsRemaining=2))`. Steps: call `verifySms`. Expected: `Failure(code="sms_invalid",
  attemptsRemaining=2)` — remapped to the single taxonomy code; no 200 `verified=false` path
  exists. Traces: AC-4, AC-7. NOTE: keep the assertion behind the OA2 confirmation; if the dev
  host uses 422 for bad code, fold into TC-10 instead.
- **TC-AND-035-09** — Type: unit (JVM). Target: challenge-expired mapping (UNVERIFIED, OA3).
  Preconditions: fake returns `Failure(ApiError(status=404))` and (second case) `410`. Steps:
  call `verifySms`. Expected: `Failure(code="challenge_expired")` in both. Traces: AC-6.
- **TC-AND-035-10** — Type: unit (JVM). Target: 422 stays generic. Preconditions: fake returns
  `Failure(ApiError(status=422, message="field required"))`. Steps: call `verifySms`. Expected:
  `Failure(status=422)` NOT remapped to `sms_invalid`. Traces: AC-6.
- **TC-AND-035-11** — Type: unit (JVM). Target: transport passthrough + cancellation.
  Preconditions: fake returns `NetworkError(isTimeout=true)`, then `NetworkError(isTimeout=
  false)`, then throws `CancellationException`. Steps: call `verifySms` for each. Expected:
  `NetworkError(true)`, `NetworkError(false)`, and `CancellationException` re-thrown unchanged
  (`assertFailsWith`). Traces: AC-7.
- **TC-AND-035-12** — Type: contract/MockWebServer (Robolectric/JVM, no device). Target:
  request shapes. Preconditions: MockWebServer enqueues canned `ChallengeResp` and
  `MfaVerifyResp` 200s; real `MfaApiClient`. Steps: call `beginSms("chl_1")` and
  `verifySms("chl_1"," 482915 ")`. Expected: recorded requests are `POST /ui/mfa/sms/begin`
  body `{"challenge_id":"chl_1"}` and `POST /ui/mfa/sms/verify` body
  `{"challenge_id":"chl_1","code":"482915"}` (code trimmed); `Content-Type: application/json`.
  Traces: AC-3.
- **TC-AND-035-13** — Type: contract/MockWebServer. Target: offline / flaky-dev-host path.
  Preconditions: MockWebServer set to disconnect mid-body / enqueue a socket timeout (~20s
  OkHttp). Steps: call `verifySms`. Expected: `NetworkError(isTimeout=true)` for the timeout and
  `NetworkError(isTimeout=false)` for an abrupt disconnect; no retry attempted (single POST
  attempt — assert one recorded request). Traces: AC-7.
- **TC-AND-035-14** — Type: contract/MockWebServer (security). Target: no-secret logging.
  Preconditions: OkHttp logging interceptor attached at the configured level; capture Logcat /
  log output. Steps: run `beginSms`/`verifySms` with code `482915`, challenge `chl_secret`,
  `sent_to=["+1•••••1234"]`. Expected: captured logs contain NONE of the substrings `482915`,
  `chl_secret`, `+1•••••1234`, and no raw request/response body for `/ui/mfa/sms/*`. Traces:
  AC-8.
- **TC-AND-035-15** — Type: integration/Hilt (instrumented). Target: DI wiring. Preconditions:
  `@HiltAndroidTest` component test. Steps: inject `MfaRepository`. Expected: resolves to
  `MfaRepositoryImpl` (binding unchanged from AND-034) with `beginSms`/`verifySms`/`resendSms`
  callable. Run on emulator AVD `test35` (API 35) for speed; no hardware dependency. Traces:
  AC-1, AC-9.
- **TC-AND-035-16** — Type: instrumented (ABI/API differences). Target: Moshi (de)serialization
  of `ChallengeResp`/`MfaVerifyResp` and trimming behavior across runtimes. Preconditions: same
  canned payloads as TC-12. Steps: run the TC-04/05/12 assertions as an instrumented suite.
  Expected: identical results on emulator `test35` (x86_64, API 35) AND on the PHYSICAL Samsung
  Galaxy A15 5G (SM-A156U, arm64-v8a, API 34). MUST run on the physical device to catch
  arm64-vs-x86 / API-34-vs-35 codec or JSON differences. Traces: AC-2, AC-3, AC-4.

(Accessibility cases are N/A at this layer — no UI is produced here; TalkBack/RTL/live-region
checks belong to AND-020/AND-039 per §9.)

### Coverage matrix

| §14 AC | Covered by |
| --- | --- |
| AC-1 (interface extended, Hilt binding) | TC-01, TC-03, TC-15 |
| AC-2 (`MfaBeginResult(sentTo: List<String>)`; reuse `MfaVerifyResult`) | TC-01, TC-02, TC-04, TC-16 |
| AC-3 (correct POST paths + bodies, code trimmed) | TC-12, TC-16 |
| AC-4 (begin sends; verify advances/finishes; 4xx bad-code → `sms_invalid`) | TC-01, TC-04, TC-05, TC-08, TC-16 |
| AC-5 (resend re-invokes begin; optional 429 throttle) | TC-03 (+ TC-08 note for OA1 429) |
| AC-6 (factor mapping/unknown; 404/410 → `challenge_expired`; 422 generic) | TC-05, TC-06, TC-09, TC-10 |
| AC-7 (transport passthrough; cancellation; blank-code guard) | TC-07, TC-11, TC-13 |
| AC-8 (no secrets in logs) | TC-14 |
| AC-9 (gradle test/lint green) | TC-15 (+ all JVM unit TCs run under `:core-data:test`) |
