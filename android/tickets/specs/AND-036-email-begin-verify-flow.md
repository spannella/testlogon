---
id: AND-036
title: Email begin/verify flow
milestone: M1
epic: E05
priority: P0
size: M
depends_on: [AND-033]
blocks: [AND-038, AND-039]
status: reviewed
reviewed_on: 2026-06-06
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
masked destination (`sent_to`, a **list of strings** in `ChallengeResp`), accepts a
6-digit code, and calls `email/verify`. A successful verify returns `MfaVerifyResp`; the
caller inspects `remaining_factors` — a non-empty list means advance to the next required
factor, an empty list means all factors are satisfied (after which AND-038 finalizes the
session via `POST /ui/session/finalize`). NOTE (corrected this review): there is **no
`auth_complete` field**; completion is signaled by `remaining_factors == []` per the web
client (`src/pages/Login.tsx`).

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
   the user's registered email and returns the `ChallengeResp` shape: `challenge_id` plus
   `sent_to` — a **list of masked destinations** (`string[]`, e.g. `["j•••@example.com"]`).
   CORRECTED (this review): the backend contract is `ChallengeResp`; `sent_to` is an array,
   not a scalar. There are **no** server-provided `code_length`/`resend_after`/`expires_in`
   fields in the verified contract (see §16) — those are client defaults, not wire fields.
2. **Verify email code.** Given `challengeId` and a user-entered code, the repository
   verifies it and returns `MfaVerifyResp` (`status`, `session_id?`, `required_factors[]`,
   `passed{}`, `remaining_factors[]`). It maps to one of: (a) factor satisfied and **more
   factors remain** (`remaining_factors` non-empty), (b) factor satisfied and **all factors
   complete** (`remaining_factors == []`, ready to finalize), or (c) **verification failed**
   (HTTP 4xx/422 — surfaced as a mapped error). CORRECTED: completion is keyed off
   `remaining_factors`, not an `auth_complete` flag (which does not exist).
3. **Resend.** Re-invoking begin must be supported as an explicit resend. The repository
   exposes a **client-side cooldown** (default 30s; see §16 — server `retry_after`/429 is an
   UNVERIFIED assumption, honored opportunistically if present) and the UI state reflects
   remaining cooldown seconds; resend is rejected locally while the timer is active without
   hitting the network.
4. **Code format.** Codes are validated client-side as 6 numeric digits (fixed default; the
   contract exposes **no** `code_length` field — UNVERIFIED, do not depend on it). Client
   validates length/numeric before calling verify; empty or malformed input is rejected
   client-side with a field error and no network call.
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

/** Outcome of email/begin (and resend).
 *  Wire source is ChallengeResp { challenge_id, sent_to: string[] }.
 *  codeLength/resendAfterSeconds/expiresInSeconds are CLIENT-SIDE defaults — the
 *  verified backend contract does NOT return them (see §16). */
data class EmailChallengeStarted(
    val sentTo: List<String>,      // masked destination(s) from ChallengeResp.sent_to
    val codeLength: Int = 6,       // client default; not a wire field
    val resendAfterSeconds: Int = 30, // client default; not a wire field
    val expiresInSeconds: Int? = null, // not a wire field; reserved for future use
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

CORRECTED (this review): the begin response DTO is `ChallengeResp` (not `EmailBeginResp`),
with `sent_to: List<String>` and `challenge_id: String`; it carries no length/expiry/resend
fields. The verify response DTO is `MfaVerifyResp` with `status`, `session_id?`,
`required_factors`, `passed`, and `remaining_factors` — there is **no `auth_complete`**.
Completion is keyed off `remaining_factors` (matching `src/pages/Login.tsx`,
`resp.remaining_factors.length === 0`).

```kotlin
// AND-033 DTO: ChallengeResp(@Json("challenge_id") val challengeId: String,
//                            @Json("sent_to") val sentTo: List<String>? = null)
private fun ChallengeResp.toDomain() = EmailChallengeStarted(
    sentTo = sentTo.orEmpty(),     // defensive: sent_to is optional in the contract
    // codeLength / resendAfterSeconds / expiresInSeconds use client defaults
)

// AND-033 DTO: MfaVerifyResp(status, session_id?, required_factors, passed, remaining_factors)
private fun MfaVerifyResp.toOutcome(): MfaVerifyOutcome =
    if (remainingFactors.isEmpty())
        MfaVerifyOutcome.AllFactorsComplete
    else
        MfaVerifyOutcome.FactorSatisfied(remainingFactors.map(::toMfaFactor))
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

Request (`EmailBeginReq`):
```json
{ "challenge_id": "chl_8f3a..." }
```
Response `200` (`ChallengeResp` — CORRECTED to the verified shape):
```json
{ "challenge_id": "chl_8f3a...", "sent_to": ["j•••@example.com"] }
```
`sent_to` is an **array of strings** and is optional. There are no `code_length`,
`resend_after`, or `expires_in` fields in the contract (verified against
`components.schemas.ChallengeResp` and `src/api/types.ts: ChallengeResp`).

### `POST /ui/mfa/email/verify`

Request (`EmailVerifyReq`):
```json
{ "challenge_id": "chl_8f3a...", "code": "482915" }
```
Response `200` (`MfaVerifyResp` — CORRECTED shape; **no `auth_complete`**) — more factors remain:
```json
{ "status": "ok", "session_id": null,
  "required_factors": ["totp"], "passed": {"email": true}, "remaining_factors": ["totp"] }
```
Response `200` — complete (no factors remain):
```json
{ "status": "ok", "session_id": null,
  "required_factors": [], "passed": {"email": true}, "remaining_factors": [] }
```
Completion is determined by `remaining_factors == []` (per `src/pages/Login.tsx`). The
`session_id` may be populated by the backend but the login flow proceeds to
`POST /ui/session/finalize` regardless (verified: `src/api/types.ts: MfaVerifyResp`,
`src/pages/Login.tsx`).

### Error responses (FastAPI `detail`)

The `detail` field is polymorphic — `string | [{msg, type, loc}] | {code, ...}` (verified
against `src/api/client.ts: normalizeErrorDetail`, which handles all three). The shared
`ApiErrorMapper` normalizes all three into `ApiError(code?, message)`.

- `422` validation error → `HTTPValidationError` (the only non-200 response declared in the
  OpenAPI for both endpoints): `{"detail":[{"loc":[...],"msg":"...","type":"..."}]}`.
  Surface the joined `msg` text as a field error (matches web `normalizeErrorDetail`).
- Invalid/expired code with a structured body such as
  `{"detail":{"code":"invalid_code","attempts_left":2}}` is an **UNVERIFIED assumption** —
  the OpenAPI declares no such schema and the web client only reads `detail`/`msg`. The
  mapper should tolerate (and preserve) a `code`/`attempts_left` object if returned, but the
  spec must not require it. See §16.
- `429` resend throttling / `Retry-After` / `retry_after` is **UNVERIFIED** — not declared
  in the OpenAPI (only `200`/`422`). Honor it opportunistically if the backend sends it; do
  not depend on it.
- `401` → handled by the OkHttp authenticator (one `POST /ui/session/refresh` then retry);
  if still 401, surfaced as `Unauthorized` → caller restarts login (out of scope here).
  Verified against `src/api/client.ts` (single refresh-then-retry on 401).

Field names use Moshi `@Json(name="…")` snake_case mapping consistent with AND-033 and the
verified `src/api/types.ts` shapes (`ChallengeResp`, `MfaVerifyResp`).

## 6. Data & State Management

No Room persistence — MFA is ephemeral session state. The `challenge_id`, cookies, and
`ui_csrf` are the only durable artifacts and are owned by `core-network`'s persistent
cookie jar; this ticket reads `challengeId` from `SavedStateHandle` (passed via nav args
from `session/start`, AND-032).

```kotlin
data class MfaEmailUiState(
    val phase: Phase = Phase.Idle,         // Idle, Sending, AwaitingCode, Verifying
    val sentTo: String? = null,            // display string joined from ChallengeResp.sent_to (List<String>)
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

1. `beginEmail` success maps `ChallengeResp` → `EmailChallengeStarted` (masked `sentTo`
   list, client defaults applied for codeLength/resend; tolerates absent `sent_to`).
2. `verifyEmail` with empty `remaining_factors` → `AllFactorsComplete`.
3. `verifyEmail` with `remaining_factors:["totp"]` → `FactorSatisfied([Totp])`.
4. `verifyEmail` 422 (`HTTPValidationError` array) → `HttpError` with joined `msg`; if an
   optional `{code, attempts_left}` body is present it is preserved (assumption-tolerant).
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

- **Exact wire field names** RESOLVED this review: `email/begin` returns `ChallengeResp`
  with `challenge_id` + `sent_to: string[]` only; there is **no** `code_length`,
  `resend_after`/`retry_after`, or `expires_in` in the contract (verified against
  `openapi.pretty.json` and `src/api/types.ts: ChallengeResp`). Treat those as client-side
  constants, not wire fields.
- **Completion signal:** RESOLVED — verify returns `MfaVerifyResp` and completion is
  `remaining_factors == []` (there is **no** `auth_complete` field). The mapper keys off
  `remaining_factors`, matching `src/pages/Login.tsx`.
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
   `POST /ui/mfa/email/begin` with `{challenge_id}`, parses `ChallengeResp` and returns
   `EmailChallengeStarted` with masked `sentTo`; verified by unit + MockWebServer tests.
2. **Verify per contract (tested):** `verifyEmail(challengeId, code)` issues
   `POST /ui/mfa/email/verify` with `{challenge_id, code}`, parses `MfaVerifyResp`; a correct
   code yields `FactorSatisfied(remaining)` when `remaining_factors` is non-empty or
   `AllFactorsComplete` when it is empty, an incorrect/invalid code yields a mapped
   `HttpError` (422 `HTTPValidationError`), preserving `attempts_left` if the backend
   provides it. Both paths tested.
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

## 16. Citations & Assumption Audit

Each key technical claim below is followed by a VERDICT and an exact SOURCE pointer.

1. **`POST /ui/mfa/email/begin` exists and accepts `EmailBeginReq`.** VERDICT: Verified.
   SOURCE: OpenAPI `POST /ui/mfa/email/begin` (op=`ui_email_begin_ui_mfa_email_begin_post`,
   req=`EmailBeginReq`); `src/api/endpoints/auth.ts: beginEmail`.
2. **`EmailBeginReq` body is `{ challenge_id: string }`.** VERDICT: Verified.
   SOURCE: `components.schemas.EmailBeginReq` (required: `challenge_id`);
   `src/api/types.ts: EmailBeginReq`.
3. **`email/begin` response shape.** Claim (original): custom `EmailBeginResp` with scalar
   `sent_to`, `code_length`, `resend_after`, `expires_in`. VERDICT: Corrected. The real
   response is `ChallengeResp` = `{ challenge_id: string, sent_to?: string[] }`; no
   length/resend/expiry fields exist. SOURCE: `src/api/endpoints/auth.ts: beginEmail`
   (`api.post<ChallengeResp>`); `src/api/types.ts: ChallengeResp` (lines 2848-2851).
   (OpenAPI index lists resp=`200:` with no schema body, consistent with a loosely-typed
   200; the frontend type is authoritative.)
4. **`sent_to` is an array of masked strings, not a scalar.** VERDICT: Corrected.
   SOURCE: `src/api/types.ts: ChallengeResp` (`sent_to?: string[]`).
5. **`POST /ui/mfa/email/verify` exists and accepts `EmailVerifyReq` `{challenge_id, code}`.**
   VERDICT: Verified. SOURCE: OpenAPI `POST /ui/mfa/email/verify`
   (op=`ui_email_verify_ui_mfa_email_verify_post`, req=`EmailVerifyReq`);
   `components.schemas.EmailVerifyReq` (required: `challenge_id`, `code`);
   `src/api/endpoints/auth.ts: verifyEmail`; `src/api/types.ts: EmailVerifyReq`.
6. **`email/verify` response shape.** Claim (original): `{ auth_complete, required_factors }`.
   VERDICT: Corrected. The real response is `MfaVerifyResp` =
   `{ status, session_id?, required_factors: string[], passed: Record<string,bool>,
   remaining_factors: string[] }`; there is **no `auth_complete`** field.
   SOURCE: `src/api/endpoints/auth.ts: verifyEmail` (`api.post<MfaVerifyResp>`);
   `src/api/types.ts: MfaVerifyResp` (lines 89-95).
7. **Completion is signaled by `remaining_factors == []`.** VERDICT: Verified (Corrected
   from `auth_complete`). SOURCE: `src/pages/Login.tsx` line 222
   (`if (resp.remaining_factors.length === 0) { … sessionFinalize(…) }`).
8. **On completion the flow finalizes via `POST /ui/session/finalize` with
   `{challenge_id, remember_device?}`.** VERDICT: Verified. SOURCE: OpenAPI
   `POST /ui/session/finalize` (req=`UiSessionFinalizeReq`);
   `src/api/endpoints/auth.ts: sessionFinalize`; `src/api/types.ts: SessionFinalizeReq`;
   `src/pages/Login.tsx` lines 224-227.
9. **`session/start` returns `auth_required`, `challenge_id?`, `required_factors[]`.**
   VERDICT: Verified. SOURCE: OpenAPI `POST /ui/session/start` (resp=`UiSessionStartResp`);
   `src/api/types.ts: SessionStartResp` (lines 12-17).
10. **CSRF: `ui_csrf` cookie echoed as `X-CSRF-Token` header by the transport.** VERDICT:
    Verified. SOURCE: `src/api/client.ts` lines 167-171
    (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`).
11. **401 triggers a single `POST /ui/session/refresh` then one retry.** VERDICT: Verified.
    SOURCE: `src/api/client.ts` lines 121-130 (`refreshSession` → `/ui/session/refresh`) and
    lines 194-237 (single refresh-then-retry, logout if still 401). OpenAPI
    `POST /ui/session/refresh` exists (no request body). Note: web `refreshSession` returns
    `StatusResp`; the index lists resp=`200:` (untyped).
12. **Error `detail` is polymorphic (`string | [{msg,type,loc}] | {code,…}`).** VERDICT:
    Verified. SOURCE: `src/api/client.ts: normalizeErrorDetail` (lines 66-102) handles all
    three forms; `mapAuthorizationError` handles the object/`code` form.
13. **The only declared non-200 response for both endpoints is `422 HTTPValidationError`.**
    VERDICT: Verified. SOURCE: OpenAPI index lines for both endpoints
    (`resp=200:;422:HTTPValidationError`).
14. **Sibling contracts: `beginSms`→`ChallengeResp`, `verifySms`/`verifyTotp`→`MfaVerifyResp`.**
    VERDICT: Verified. SOURCE: `src/api/endpoints/auth.ts` lines 78-91.
15. **Cookie-based session; cookie jar persisted client-side; `challenge_id` threads MFA
    calls.** VERDICT: Verified. SOURCE: `src/api/client.ts` (`credentials: "include"` on all
    requests, lines 183/220); request bodies all carry `challenge_id`
    (`src/pages/Login.tsx`). The Android **persistent cookie jar** requirement is a
    framework choice — framework ref: OkHttp `CookieJar`
    (https://square.github.io/okhttp/).
16. **`@HiltViewModel` + Hilt/KSP DI and Compose UI state via `StateFlow`.** VERDICT:
    Unverified-assumption (Android framework choice, not derivable from backend/frontend
    sources). framework ref: Hilt + ViewModel
    (https://developer.android.com/training/dependency-injection/hilt-android) and
    `StateFlow` (https://developer.android.com/kotlin/flow/stateflow-and-sharedflow).
17. **`network_security_config` enforces HTTPS in production; dev host is plaintext HTTP.**
    VERDICT: Unverified-assumption for this module (owned by core-network). framework ref:
    Android Network Security Config
    (https://developer.android.com/privacy-and-security/security-config).

### Corrections made

- C1 (§1, §3, §4, §5, §11, §14): begin response type corrected from a fabricated
  `EmailBeginResp` to the real `ChallengeResp` (`challenge_id`, `sent_to: string[]`).
- C2 (§1, §3, §4, §5): `sent_to` corrected from a scalar masked string to a `List<String>`.
- C3 (§3, §4): removed reliance on non-existent wire fields `code_length`, `resend_after`,
  and `expires_in`; reclassified as client-side defaults.
- C4 (§1, §3, §4, §5, §13, §14): verify response corrected from `{auth_complete, required_factors}`
  to `MfaVerifyResp`; completion criterion corrected to `remaining_factors == []`.
- C5 (§5, §11, §14): error model corrected — only `422 HTTPValidationError` is contractually
  declared; `invalid_code`/`attempts_left` structured body and `429`/`Retry-After` flagged as
  unverified-but-tolerated.

### Open assumptions

- A1: Structured `{code:"invalid_code", attempts_left:n}` error body — not in OpenAPI (only
  `422 HTTPValidationError`); the web client only reads `detail`/`msg`. Tolerated, not required.
- A2: `429`/`Retry-After`/`retry_after` server-driven resend throttling — not declared in the
  contract. Cooldown is therefore client-side (30s default); honor server hints if present.
- A3: `code_length` (variable OTP length) — no wire field; fixed 6-digit client validation.
- A4: `expires_in` / OTP TTL — not exposed by the contract; not surfaced to the user.
- A5: Android stack choices (Hilt/KSP, StateFlow, OkHttp persistent cookie jar,
  network_security_config) are framework conventions, not verifiable from the provided
  backend/frontend sources (see §16 items 15-17, framework refs).
- A6: AND-033 DTO field names/annotations (`ChallengeResp.sentTo`, `MfaVerifyResp.remainingFactors`)
  are assumed to mirror the frontend snake_case via Moshi `@Json`; verify when AND-033 lands.

## 17. Test Plan

Test IDs `TC-AND-036-NN`. "Traces" link to §14 Acceptance Criteria (AC-1..AC-6). Targets:
JVM/Robolectric (local), emulator AVD `test35` (API 35 x86_64), or PHYSICAL DEVICE
(Samsung Galaxy A15 5G, SM-A156U, API 34, arm64-v8a). This ticket is repository + ViewModel
+ UI-state only (screen owned by AND-039), so most cases are JVM/contract; UI/instrumented
cases are included for the ViewModel↔state contract and for the (downstream-owned) a11y/
phase surface where it can be exercised headlessly.

- **TC-AND-036-01 — Begin happy path maps ChallengeResp.**
  Type: unit (JVM). Target: JVM/Robolectric local. Preconditions: `MfaRepositoryImpl` with a
  faked `AuthApi` returning `ChallengeResp(challengeId="chl_1", sentTo=["j•••@example.com"])`.
  Steps: call `beginEmail("chl_1")`. Expected: `ApiResult.Success(EmailChallengeStarted)` with
  `sentTo == ["j•••@example.com"]`, `codeLength == 6`, `resendAfterSeconds == 30`. Traces: AC-1.

- **TC-AND-036-02 — Begin tolerates absent/empty `sent_to`.**
  Type: unit (JVM). Target: JVM local. Preconditions: API returns
  `ChallengeResp(challengeId="chl_1", sentTo=null)`. Steps: call `beginEmail`. Expected:
  Success with `sentTo == emptyList()`, no crash, defaults applied. Traces: AC-1.

- **TC-AND-036-03 — Verify: more factors remain → FactorSatisfied.**
  Type: unit (JVM). Target: JVM local. Preconditions: API returns
  `MfaVerifyResp(status="ok", requiredFactors=["totp"], passed={"email":true}, remainingFactors=["totp"])`.
  Steps: `verifyEmail("chl_1","482915")`. Expected:
  `Success(MfaVerifyOutcome.FactorSatisfied([Totp]))`. Traces: AC-2.

- **TC-AND-036-04 — Verify: all complete → AllFactorsComplete.**
  Type: unit (JVM). Target: JVM local. Preconditions: API returns
  `MfaVerifyResp(status="ok", requiredFactors=[], passed={"email":true}, remainingFactors=[])`.
  Steps: `verifyEmail`. Expected: `Success(MfaVerifyOutcome.AllFactorsComplete)` (keyed off
  empty `remaining_factors`, NOT a non-existent `auth_complete`). Traces: AC-2.

- **TC-AND-036-05 — Begin/verify contract over the wire (request + CSRF).**
  Type: contract/MockWebServer. Target: JVM local. Preconditions: MockWebServer enqueues a
  200 `ChallengeResp` then a 200 `MfaVerifyResp`; `ui_csrf` cookie present in the jar.
  Steps: call `beginEmail` then `verifyEmail`. Expected: recorded begin path
  `/ui/mfa/email/begin` (POST), body `{"challenge_id":"chl_1"}`; verify path
  `/ui/mfa/email/verify` (POST), body `{"challenge_id":"chl_1","code":"482915"}`; both
  requests carry header `X-CSRF-Token` equal to the `ui_csrf` cookie value. Traces: AC-1, AC-2.

- **TC-AND-036-06 — Verify 422 HTTPValidationError → mapped HttpError.**
  Type: contract/MockWebServer. Target: JVM local. Preconditions: enqueue
  `422 {"detail":[{"loc":["body","code"],"msg":"invalid code","type":"value_error"}]}`.
  Steps: `verifyEmail("chl_1","000000")`. Expected: `ApiResult.HttpError(422, ApiError(...))`
  with message containing the joined `msg`; no outcome emitted. Traces: AC-2.

- **TC-AND-036-07 — Verify tolerant of optional structured `{code, attempts_left}` body.**
  Type: contract/MockWebServer. Target: JVM local. Preconditions: enqueue
  `422 {"detail":{"code":"invalid_code","attempts_left":2}}` (UNVERIFIED shape; tolerance test).
  Steps: `verifyEmail`. Expected: `HttpError` whose `ApiError` preserves `code="invalid_code"`
  and `attempts_left=2` when present; mapper does not throw when the object form is used.
  Traces: AC-2. (Note: covers Open assumption A1; must not be a hard requirement.)

- **TC-AND-036-08 — Resend cooldown blocks network call.**
  Type: unit (JVM, MockK/Turbine + injected `Clock`/test dispatcher). Target: JVM local.
  Preconditions: ViewModel after a successful `Begin` (cooldown ticking, `resendSecondsLeft>0`).
  Steps: dispatch `Resend` intent while timer active. Expected: `api.emailBegin` is NOT called
  (verify `wasNot Called`); state `canResend == false`. Traces: AC-3.

- **TC-AND-036-09 — Resend after cooldown re-dispatches.**
  Type: unit (JVM, virtual time). Target: JVM local. Preconditions: ViewModel post-Begin.
  Steps: advance test clock past `resendAfterSeconds`, dispatch `Resend`. Expected:
  `api.emailBegin` called exactly once more; `resendSecondsLeft` reset and re-ticking.
  Traces: AC-3.

- **TC-AND-036-10 — Client-side validation blocks malformed code.**
  Type: unit (JVM, ViewModel state). Target: JVM local. Preconditions: phase `AwaitingCode`,
  `codeLength=6`. Steps: `CodeChanged("12a4")` then attempt `Verify`. Expected:
  `state.canVerify == false`, `Verify` performs no network call (`api.emailVerify` `wasNot
  Called`), field error surfaced. Traces: AC-4.

- **TC-AND-036-11 — Verify is not auto-retried on network failure.**
  Type: unit (JVM). Target: JVM local. Preconditions: API throws `IOException` on
  `emailVerify`. Steps: `verifyEmail`. Expected: single `api.emailVerify` invocation,
  `ApiResult.NetworkError` returned once (non-idempotent; no auto-retry consuming attempts).
  Traces: AC-2.

- **TC-AND-036-12 — 401 → single refresh-then-retry succeeds.**
  Type: contract/MockWebServer. Target: JVM local. Preconditions: enqueue `401` for
  `email/verify`, then `200` for `/ui/session/refresh`, then `200 MfaVerifyResp` on retry.
  Steps: `verifyEmail`. Expected: exactly one `/ui/session/refresh` POST, original request
  retried once, final `Success`; a second 401 instead would surface `Unauthorized`.
  Traces: AC-2. (Verifies §5/§16 item 11 transport behavior.)

- **TC-AND-036-13 — Flaky-dev-host / offline begin surfaces retryable state.**
  Type: integration (instrumented) on PHYSICAL DEVICE. Target: PHYSICAL DEVICE
  (SM-A156U, API 34) — MUST run on real hardware to exercise true radio-off/airplane-mode
  network loss (emulator network emulation is unreliable for this). Preconditions: app pointed
  at a stubbed/unreachable base URL or device in airplane mode. Steps: trigger `Begin`.
  Expected: `MfaEmailUiState` returns to a non-`Sending` phase with a retryable offline error
  banner; no OTP cached; retry action present. Traces: AC-1, AC-3.

- **TC-AND-036-14 — Secret redaction (code + email never logged).**
  Type: unit/Robolectric (JVM). Target: JVM/Robolectric local. Preconditions: a capturing
  `Timber` tree + OkHttp logging interceptor at BASIC in debug. Steps: run begin+verify with
  code `482915` and `sent_to=["j•••@example.com"]`. Expected: captured logs contain neither
  the raw `code` nor the full/masked email; `challenge_id` appears only hashed. Traces: AC-5.

- **TC-AND-036-15 — State phase contract for begin→verify→complete.**
  Type: unit (Turbine, ViewModel). Target: JVM local. Preconditions: faked repo returning
  begin success then `AllFactorsComplete`. Steps: emit `Begin`, `CodeChanged("482915")`,
  `Verify`. Expected: `MfaEmailUiState.phase` sequence `Idle → Sending → AwaitingCode →
  Verifying`, terminal `completed == AllComplete` (one-shot). Traces: AC-6.

- **TC-AND-036-16 — Accessibility: error live region + resend disabled-state semantics.**
  Type: Compose-UI (instrumented). Target: emulator AVD `test35` (API 35) — no real hardware
  needed; if AND-039's host screen is not yet available, run against a thin test harness
  composable that renders the §9 semantics. Preconditions: state with an error and an active
  cooldown. Steps: assert with Compose test/`SemanticsMatcher`. Expected: error node has
  `liveRegion = Assertive`; resend control exposes a disabled state with accessible reason
  "available in {n} seconds"; code field has the localized `contentDescription`; touch targets
  ≥48dp. Traces: AC-4, AC-5 (UI surfacing of validation/security state). (Owned with AND-039;
  included here for the state contract.)

### Coverage matrix

| AC (§14) | Covered by |
|----------|-----------|
| AC-1 Begin per contract | TC-01, TC-02, TC-05, TC-13 |
| AC-2 Verify per contract | TC-03, TC-04, TC-05, TC-06, TC-07, TC-11, TC-12 |
| AC-3 Resend / cooldown | TC-08, TC-09, TC-13 |
| AC-4 Client validation | TC-10, TC-16 |
| AC-5 No secret leakage | TC-14, TC-16 |
| AC-6 State contract | TC-15 |
