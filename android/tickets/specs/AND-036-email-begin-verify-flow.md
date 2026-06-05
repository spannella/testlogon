---
id: AND-036
title: Email begin/verify flow
milestone: M1
epic: E05
priority: P0
size: M
status: draft
depends_on: [AND-033]
blocks: [AND-038, AND-039]
---

# AND-036 — Email begin/verify flow

## 1. Overview & Goal

This ticket implements the **email one-time-code (OTP) MFA factor** for the TestLogon
native Android app: the repository-level `beginEmail` and `verifyEmail` operations,
their resend affordance, and the state surface that the MFA challenge UI consumes. It
sits inside epic **E05 (MFA)** and milestone **M1**.

The email factor is one of several interchangeable second factors selectable during the
cookie-based login flow. After `POST /ui/session/start` returns `auth_required: true`
with `required_factors` containing `"email"`, the user can choose email; the app then
calls `email/begin` to dispatch an OTP to the user's registered address, displays the
masked destination (`sent_to`), accepts a 6-digit code, and calls `email/verify`. A
successful verify either advances to the next required factor or signals that all factors
are satisfied (after which AND-038 finalizes the session via `POST /ui/session/finalize`).

The goal is a **contract-correct, fully tested** repository pair (`beginEmail`,
`verifyEmail`) plus resend support, mirroring the SMS flow (AND-035) but for email
delivery. The transport-layer `AuthApi` methods this calls already exist from AND-033;
this ticket owns the repository orchestration, DTO-to-domain mapping, error
normalization, resend cooldown logic, and the `MfaEmailUiState`/intent surface. Screen
composition and navigation wiring are owned downstream and are explicitly out of scope
here except for the ViewModel-facing state contract.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, monorepo subfolder `android/`, branch
  `android-port`. Code lands in `feature-auth` (repository + ViewModel + UI state) and
  consumes `core-network` (`AuthApi`, cookie jar, CSRF interceptor) and `core-model`
  (domain types). Package base: `com.testlogon.android`.
- **Upstream dependency — AND-033 (MFA API + DTOs):** provides the Retrofit `AuthApi`
  with `emailBegin`/`emailVerify` suspend methods and the wire DTOs. This ticket must not
  redefine those; it depends on their signatures.
- **Sibling reference — AND-035 (SMS begin/verify flow):** structurally identical
  (`begin` returns a masked `sent_to`, `verify` advances/finishes, resend supported).
  Reuse the shared MFA repository scaffolding and cooldown helper introduced there; do not
  fork it.
- **Sibling — AND-034 (TOTP verify flow):** no `begin` step (verify-only); shares the
  `MfaVerifyResp` → domain mapping and remaining-factor surfacing logic.
- **Downstream — AND-038 (finalize/session):** consumes the "all factors satisfied"
  outcome from `verifyEmail` to call `finalize`. **AND-039 (MFA selector/host UI)**
  consumes `MfaEmailUiState`.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP,
  unreliable). OpenAPI at `/openapi.json`. Web reference: `frontend/src/api/endpoints/*.ts`
  and `frontend/src/api/types.ts` for the canonical request/response shapes.
- **Auth model:** cookie-based session; `challenge_id` from `session/start` threads
  through every MFA call; `ui_csrf` cookie echoed as `X-CSRF-Token`; persistent cookie jar
  required; single `session/refresh` retry on 401.

## 3. Functional Requirements

1. **Begin email challenge.** Given a valid `challengeId`, the repository sends an OTP to
   the user's registered email and returns the masked destination (`sent_to`, e.g.
   `j•••@example.com`) and any server-provided resend/expiry hints.
2. **Verify email code.** Given `challengeId` and a user-entered code, the repository
   verifies it and returns one of: (a) factor satisfied and **more factors remain** (with
   the updated `required_factors`/`remaining` list), (b) factor satisfied and **all
   factors complete** (ready to finalize), or (c) **verification failed** (invalid/expired
   code, attempts remaining).
3. **Resend.** Re-invoking begin must be supported as an explicit resend. The repository
   exposes a **cooldown** (default 30s, server `retry_after` honored when present) and the
   UI state reflects remaining cooldown seconds; resend is rejected locally while the
   timer is active without hitting the network.
4. **Code format.** Codes are 6 numeric digits (configurable via the response if the server
   reports `code_length`). Client validates length/numeric before calling verify; empty or
   malformed input is rejected client-side with a field error and no network call.
5. **Idempotent re-entry.** Navigating back into the email factor while a code is already
   in flight must not double-dispatch. Verify is **not** retried automatically on network
   error (non-idempotent); begin/resend GET-like dispatch follows the project retry policy
   only for transient transport failures, never auto-resending on a 4xx.
6. **State surfacing.** All outcomes are projected into `MfaEmailUiState` as a
   `StateFlow`; the ViewModel exposes intents `Begin`, `CodeChanged`, `Verify`, `Resend`,
   `ClearError`.

## 4. Technical Design

Layering: `feature-auth` ViewModel → `MfaRepository` (interface in `core-model` or
`feature-auth` domain pkg, impl in `feature-auth`) → `AuthApi` (`core-network`). Hilt
(KSP) provides the repository; the ViewModel is `@HiltViewModel`.

### Domain results (`core-model`)

```kotlin
package com.testlogon.android.core.model.mfa

/** Outcome of email/begin (and resend). */
data class EmailChallengeStarted(
    val sentTo: String,            // masked destination, e.g. "j•••@example.com"
    val codeLength: Int = 6,
    val resendAfterSeconds: Int = 30,
    val expiresInSeconds: Int? = null,
)

/** Outcome of any MFA verify (shared with TOTP/SMS). */
sealed interface MfaVerifyOutcome {
    /** Factor passed; more factors still required. */
    data class FactorSatisfied(val remainingFactors: List<MfaFactor>) : MfaVerifyOutcome
    /** Factor passed; no factors remain — caller should finalize (AND-038). */
    data object AllFactorsComplete : MfaVerifyOutcome
}
```

### Repository (`feature-auth`)

```kotlin
interface MfaRepository {
    suspend fun beginEmail(challengeId: String): ApiResult<EmailChallengeStarted>
    suspend fun verifyEmail(challengeId: String, code: String): ApiResult<MfaVerifyOutcome>
    // beginSms/verifySms/verifyTotp live alongside (AND-034/035)
}
```

`ApiResult<T>` is the project's typed result (`Success`, `HttpError(code, ApiError)`,
`NetworkError`, `Unauthorized`). The impl wraps `AuthApi` calls in a shared
`safeApiCall { … }` helper that maps exceptions and decodes the FastAPI `detail` shape.

```kotlin
@Singleton
class MfaRepositoryImpl @Inject constructor(
    private val api: AuthApi,
    private val errorMapper: ApiErrorMapper,
) : MfaRepository {

    override suspend fun beginEmail(challengeId: String): ApiResult<EmailChallengeStarted> =
        safeApiCall(errorMapper) {
            api.emailBegin(EmailBeginReq(challengeId)).toDomain()
        }

    override suspend fun verifyEmail(
        challengeId: String, code: String,
    ): ApiResult<MfaVerifyOutcome> =
        safeApiCall(errorMapper) {
            api.emailVerify(EmailVerifyReq(challengeId, code)).toOutcome()
        }
}
```

### DTO mapping (`core-network`, DTOs from AND-033)

```kotlin
private fun EmailBeginResp.toDomain() = EmailChallengeStarted(
    sentTo = sentTo,
    codeLength = codeLength ?: 6,
    resendAfterSeconds = resendAfter ?: 30,
    expiresInSeconds = expiresIn,
)

private fun MfaVerifyResp.toOutcome(): MfaVerifyOutcome =
    if (requiredFactors.isNullOrEmpty() || authComplete == true)
        MfaVerifyOutcome.AllFactorsComplete
    else
        MfaVerifyOutcome.FactorSatisfied(requiredFactors.map(::toMfaFactor))
```

### ViewModel

```kotlin
@HiltViewModel
class MfaEmailViewModel @Inject constructor(
    private val repo: MfaRepository,
    private val clock: Clock,                  // injectable for tests
    savedState: SavedStateHandle,
) : ViewModel() {
    private val challengeId: String = savedState["challengeId"]!!
    private val _state = MutableStateFlow(MfaEmailUiState())
    val state: StateFlow<MfaEmailUiState> = _state.asStateFlow()

    fun onIntent(i: MfaEmailIntent) { /* Begin, CodeChanged, Verify, Resend, ClearError */ }
}
```

Cooldown is driven by a `viewModelScope` ticker that decrements `resendSecondsLeft`
each second from `resendAfterSeconds` down to 0; `Resend` is a no-op while `> 0`.

## 5. API Contract

Two endpoints, both `POST`, both requiring the session cookies + `X-CSRF-Token` header
(injected by the `core-network` CSRF interceptor — not set manually here).

### `POST /ui/mfa/email/begin`

Request:
```json
{ "challenge_id": "chl_8f3a..." }
```
Response `200`:
```json
{ "sent_to": "j•••@example.com", "code_length": 6, "resend_after": 30, "expires_in": 600 }
```

### `POST /ui/mfa/email/verify`

Request:
```json
{ "challenge_id": "chl_8f3a...", "code": "482915" }
```
Response `200` — more factors remain:
```json
{ "auth_complete": false, "required_factors": ["totp"] }
```
Response `200` — complete:
```json
{ "auth_complete": true, "required_factors": [] }
```

### Error responses (FastAPI `detail`)

The `detail` field is polymorphic — `string | [{msg, type, loc}] | {code, ...}`. The
shared `ApiErrorMapper` normalizes all three into `ApiError(code?, message)`.

- `400/422` invalid or expired code → `{"detail":{"code":"invalid_code","attempts_left":2}}`
  or validation array. Surface as field error; preserve `attempts_left` when present.
- `429` resend throttled → honor `Retry-After` header / `retry_after` body into cooldown.
- `401` → handled by OkHttp authenticator (one `POST /ui/session/refresh` then retry);
  if still 401, surfaced as `Unauthorized` → caller restarts login (out of scope here).

Field names assume Moshi `@Json(name="…")` snake_case mapping consistent with AND-033 and
`frontend/src/api/types.ts`. Verify exact names against `/openapi.json` during impl.

## 6. Data & State Management

No Room persistence — MFA is ephemeral session state. The `challenge_id`, cookies, and
`ui_csrf` are the only durable artifacts and are owned by `core-network`'s persistent
cookie jar; this ticket reads `challengeId` from `SavedStateHandle` (passed via nav args
from `session/start`, AND-032).

```kotlin
data class MfaEmailUiState(
    val phase: Phase = Phase.Idle,         // Idle, Sending, AwaitingCode, Verifying
    val sentTo: String? = null,
    val code: String = "",
    val codeLength: Int = 6,
    val resendSecondsLeft: Int = 0,
    val attemptsLeft: Int? = null,
    val error: UiText? = null,             // transient, cleared on edit/ClearError
    val completed: CompletionSignal? = null,  // FactorSatisfied(remaining) | AllComplete
) {
    val canVerify get() = code.length == codeLength && code.all(Char::isDigit)
        && phase == Phase.AwaitingCode
    val canResend get() = resendSecondsLeft == 0 && phase != Phase.Sending
}
```

State transitions: `Begin`/`Resend` → `Sending` → on success `AwaitingCode` (start
cooldown ticker) / on failure back to prior phase with `error`. `Verify` → `Verifying` →
success sets `completed` (consumed once by the host) / failure → `AwaitingCode` with
`error` + decremented `attemptsLeft`. `completed` is a one-shot event the host clears
after navigating (AND-039 host owns the actual navigation).

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp call timeout ~20s (project default for the unreliable dev host).
  Transport failure on `beginEmail`/`resend` → `NetworkError` → state shows a retryable
  banner; bounded backoff retry is permitted for the begin dispatch (idempotent-by-design
  re-send produces a fresh code) but **never** auto-retries on a 4xx.
- **`verifyEmail` is never auto-retried** (non-idempotent; could consume attempts). On
  `NetworkError`, surface "Couldn't reach server, tap to retry" and let the user retry.
- **Invalid/expired code:** map `invalid_code`/422 to an inline field error; show
  `attempts_left` when provided; do not clear the entered code automatically (let the user
  correct it) but on `expired` prompt the user to resend.
- **Throttle (429):** set `resendSecondsLeft` from `Retry-After`/`retry_after`; disable
  the resend control; no retry.
- **Stale/offline:** if begin fails entirely, the screen renders an offline state with a
  retry action; no cached fallback exists for OTP.
- **Cancellation:** in-flight begin/verify are tied to `viewModelScope`; navigating away
  cancels cleanly and the cooldown ticker stops.

## 8. Security & Privacy

- The OTP code is never logged, never persisted, and is held only in `MfaEmailUiState`
  (cleared on success/leave). Treat it as a secret.
- `sent_to` is **masked by the server**; the client must not attempt to unmask or store
  the full email address.
- All calls ride the session cookie jar + `X-CSRF-Token` (CSRF cookie echoed as header by
  the interceptor). This ticket adds no new credential handling.
- Dev host is **plaintext HTTP** — acceptable for the dev backend only; production builds
  must enforce HTTPS via `network_security_config` (owned by core-network setup). Do not
  hardcode the dev IP in this feature module; use the injected base URL.
- No PII (code, masked address) is sent to telemetry; only event names + non-PII outcome
  codes.

## 9. Accessibility & i18n

- All strings (instructions, masked-destination template, errors, resend countdown,
  "Resend code in {n}s") live in `feature-auth/src/main/res/values/strings.xml` as
  parameterized resources; no concatenation. Countdown uses a plurals/format resource.
- The code field declares `KeyboardType.NumberPassword`, `autofillHints =
  listOf(AutofillType.SmsOtpCode)` analog for email is N/A — set
  `contentDescription` to the localized "Email verification code".
- Errors are announced via `Modifier.semantics { liveRegion = LiveRegion.Assertive }` so
  TalkBack reads verification failures; the resend countdown uses `Polite`.
- Touch targets ≥48dp; resend control exposes a disabled state with an accessible reason
  ("available in {n} seconds"). All interactive controls have role semantics.

## 10. Telemetry & Logging

Emit structured analytics events (no PII):

- `mfa_email_begin` `{challenge_id_hash, result: ok|error, error_code?}`
- `mfa_email_resend` `{challenge_id_hash, cooldown_blocked: bool, result}`
- `mfa_email_verify` `{challenge_id_hash, result: pass|fail|complete, attempts_left?}`

`challenge_id` is hashed (not raw) before logging. Debug-level `Timber` logs may record
state transitions and HTTP status codes but **must redact** the `code` and `sent_to`
fields; an OkHttp logging interceptor, if enabled, runs at `BASIC` level in debug only.

## 11. Testing Strategy

**Unit (JUnit + Turbine + MockK, in `core-testing` fixtures):**

1. `beginEmail` success maps `EmailBeginResp` → `EmailChallengeStarted` (masked `sentTo`,
   defaults applied when fields null).
2. `verifyEmail` with empty `required_factors`/`auth_complete:true` → `AllFactorsComplete`.
3. `verifyEmail` with `required_factors:["totp"]` → `FactorSatisfied([Totp])`.
4. `verifyEmail` 422/`invalid_code` → `HttpError` with `attempts_left` preserved.
5. 429 sets cooldown from `Retry-After`; subsequent `Resend` within cooldown does **not**
   call `api.emailBegin` (verify via MockK `wasNot Called`).
6. `verifyEmail` is not auto-retried on `IOException` (NetworkError surfaced once).
7. Client-side validation: malformed/short code → `canVerify == false`, no network call.

**ViewModel state tests (Turbine):** intent sequence `Begin → CodeChanged → Verify`
drives `Idle → Sending → AwaitingCode → Verifying → completed`; cooldown ticker
decrements with injected `Clock`/test dispatcher.

**Contract tests:** MockWebServer fixtures for begin/verify success, multi-factor remain,
invalid, expired, throttled, and 401-then-refresh-then-success, asserting request body
JSON (`challenge_id`, `code`) and that `X-CSRF-Token` is present.

Coverage target: repository + mapper ≥ 90% line; all acceptance bullets backed by a named
test. No instrumented/UI tests required in this ticket (screen owned by AND-039).

## 12. Dependencies & Sequencing

- **Depends on AND-033** (MFA API + DTOs) — hard blocker; `emailBegin`/`emailVerify` and
  their DTOs must exist. If AND-033 lags, stub `AuthApi` behind the interface to unblock
  repository TDD.
- **Parallel with AND-034/AND-035** — share `MfaVerifyOutcome`, `safeApiCall`,
  `ApiErrorMapper`, and the cooldown ticker; coordinate to land shared helpers once
  (prefer AND-035 introduces them, this ticket reuses).
- **Blocks AND-038** (finalize) and **AND-039** (MFA host/selector UI), which consume
  `AllFactorsComplete` and `MfaEmailUiState` respectively.
- Indirectly relies on AND-032 (session start) to supply `challengeId` via nav args.

## 13. Risks & Open Questions

- **Exact wire field names** for `email/begin` (`sent_to` vs `masked_email`, `resend_after`
  vs `retry_after`, presence of `code_length`/`expires_in`) are assumed from the SMS
  analog; confirm against `/openapi.json` and `frontend/src/api/types.ts` before merge.
- **Completion signal:** whether verify returns `auth_complete` or only an empty
  `required_factors` — handle both (current mapping does).
- **Dev host flakiness:** intermittent 5xx/timeouts on the OTP dispatch may surface as
  "code never arrives"; mitigated by resend + clear offline state, but E2E reliability on
  the dev host is not guaranteed.
- **Email delivery latency** on the backend may exceed the cooldown; consider whether the
  default 30s cooldown should be server-driven only (currently honors server value with a
  30s fallback).
- Open: should resend be capped (max N resends per challenge)? Not specified by backlog;
  defer to server enforcement (429) unless product specifies.

## 14. Acceptance Criteria

1. **Begin per contract (tested):** `beginEmail(challengeId)` issues
   `POST /ui/mfa/email/begin` with `{challenge_id}`, returns `EmailChallengeStarted` with a
   masked `sentTo`; verified by unit + MockWebServer tests.
2. **Verify per contract (tested):** `verifyEmail(challengeId, code)` issues
   `POST /ui/mfa/email/verify` with `{challenge_id, code}`; a correct code yields
   `FactorSatisfied(remaining)` or `AllFactorsComplete`, an incorrect/expired code yields a
   mapped `HttpError` exposing `attempts_left` when provided. Both paths tested.
3. **Resend support:** resend re-dispatches the OTP only when the cooldown is elapsed; a
   resend attempt during cooldown performs no network call; 429/`Retry-After` updates the
   cooldown. Tested.
4. **Client validation:** non-6-digit/non-numeric input never reaches the network and
   blocks `Verify`.
5. **No secret leakage:** code and full email never logged/persisted (verified by code
   review + a redaction assertion in the logging test).
6. **State contract:** `MfaEmailUiState` flow emits the documented phase transitions for
   the canonical begin→verify→complete sequence (Turbine test).

## 15. Definition of Done

- `MfaRepository.beginEmail`/`verifyEmail` + `MfaEmailViewModel` + `MfaEmailUiState`
  implemented in `feature-auth`, wired via Hilt (KSP), consuming AND-033's `AuthApi`.
- DTO→domain mappers and `ApiErrorMapper` handling for the three `detail` shapes in place.
- Cooldown/resend logic implemented with an injectable clock/dispatcher.
- All section 11 tests written and green; repository/mapper coverage ≥ 90%; CI passes on
  branch `android-port`.
- No new lint/detekt warnings; strings externalized; no hardcoded dev IP or secrets.
- Wire field names reconciled against `/openapi.json` (section 13 risk resolved or noted).
- Code reviewed; PR references AND-036 and links the blocked tickets (AND-038, AND-039).
