---
id: AND-058
title: "Password recovery: challenge verification"
milestone: M2
epic: E08
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-057]
blocks: [AND-059]
---

# AND-058 — Password recovery: challenge verification

## 1. Overview & Goal

AND-057 owns the recovery *start* step: the user submits a username, the backend
returns a `challenge_id`, the available `required_factors`, and a delivery
medium/destination, and the UI advances to a factor-selection / code-entry
screen. AND-058 owns the *middle* step of the unauthenticated password-recovery
flow: **verifying the chosen recovery challenge factor**. This ticket implements
the begin/verify round-trips for each supported factor variant —
email, SMS, TOTP, and any backup/recovery code path — and drives the recovery
state machine from "factor selected" to "challenge passed, ready to set a new
password".

The recovery flow is **unauthenticated**: there is no logged-in session and no
`ui_csrf` cookie from a finalized session. The state binding the steps together
is the `challenge_id` minted by AND-057 **plus the `username`** — both are
**required** on every begin/verify request per the backend schemas
(`PasswordRecoveryChallengeReq`, `PasswordRecovery{Email,Sms,Totp}VerifyReq`,
`PasswordRecoveryRecoveryCodeReq`). *(Correction: earlier drafts treated
`challenge_id` as the sole token; OpenAPI marks `username` as required on all
challenge requests.)* The goal of AND-058 is a
correct, resilient, fully testable factor-verification layer that, on success,
hands a verified `challenge_id` (and any returned recovery token / `code`) to
AND-059, which performs `/ui/password-recovery/confirm`.

Done means: for each challenge variant, a `begin` call (where applicable) issues
the code/prompt, a `verify` call validates the user-entered code, success
advances the UI to the confirm step, and every failure mode (wrong code,
expired challenge, rate-limited, network/offline, unreliable-host timeout) is
mapped to a deterministic UI state. Each path is covered by tests.

## 2. Context & References

- **Epic E08** — Password recovery (M2).
- **Upstream AND-057** (`password-recovery-start`) — owns the Recovery screen
  scaffold, `RecoveryViewModel` creation, and `/ui/password-recovery/start`.
  AND-058 extends the *same* feature module and ViewModel rather than creating a
  parallel one.
- **Downstream AND-059** (`password-recovery-confirm-new-password`) — consumes
  the verified `challenge_id` and password-strength rules; owns
  `/ui/password-recovery/confirm`. AND-058 must NOT implement password setting.
- **Module:** `feature-auth` (recovery lives alongside login/MFA), depending on
  `core-network`, `core-model`, `core-ui`, `core-data`, `core-testing`.
- **Namespace / applicationId base:** `com.testlogon.android`.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. FastAPI `detail`
  error shapes: `string | [{msg}] | {code,...}`.
- **Web reference:** `frontend/src/api/endpoints/*.ts` (recovery endpoint
  wrappers) and `frontend/src/api/types.ts` for the canonical request/response
  shapes; mirror field names exactly in Moshi models.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Retrofit 2.11 /
  OkHttp 4.12 / Moshi 1.15, Coroutines/Flow, DataStore. minSdk 24,
  compile/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.

## 3. Functional Requirements

FR-1. Given a `challenge_id` and a selected factor from AND-057's start
response, the user can trigger a `begin` for factors that require delivery
(`email`, `sms`). TOTP and recovery-code paths skip `begin` (no code is sent;
the user already possesses the code).

FR-2. After `begin`, the UI shows the masked delivery destination (e.g.
`j•••@example.com`, `+1 ••• ••• 4321`) returned by start/begin and a code-entry
field with a numeric keyboard.

FR-3. The user enters a code and submits a `verify` for the active factor. On
HTTP 200 with a passing verification, the flow advances to the AND-059 confirm
step, passing through the (now-verified) `challenge_id` plus any
`recovery_token`/`code` echoed by the backend.

FR-4. The user can request a **resend** for `email`/`sms` (re-invokes `begin`),
gated by a client-side cooldown (default 30s) to avoid hammering the unreliable
host.

FR-5. The user can **switch factor** (return to factor selection) without
losing the `challenge_id`, provided the challenge has not expired.

FR-6. Each variant must independently pass and fail correctly (paths verified
against the OpenAPI index — note the `recovery` path has **no** `/verify`
suffix):
- `POST /ui/password-recovery/challenge/email/begin` + `/email/verify`
- `POST /ui/password-recovery/challenge/sms/begin` + `/sms/verify`
- `POST /ui/password-recovery/challenge/totp/verify`
- `POST /ui/password-recovery/challenge/recovery` (backup recovery code —
  **flat path, not `/recovery/verify`**; resolves OQ-2)

FR-7. Wrong/expired/rate-limited codes surface a specific inline error and keep
the user on the code-entry screen with the field cleared (wrong code) or routed
back to start (expired challenge).

FR-8. The submit button is disabled while the code is empty/too short or while a
verify request is in flight. Verification is idempotent only at the UI level
(double-tap guarded); `verify` itself is a non-idempotent POST and is **never**
auto-retried.

## 4. Technical Design

### 4.1 Layering

```
feature-auth/recovery/
  RecoveryChallengeRoute.kt        // Compose route (collects state, wires callbacks)
  RecoveryChallengeScreen.kt       // stateless Composable
  RecoveryViewModel.kt             // shared with AND-057/AND-059 (extended here)
  RecoveryUiState.kt               // sealed state incl. challenge sub-states
core-network/auth/
  PasswordRecoveryApi.kt           // Retrofit interface (extended)
  PasswordRecoveryRepository.kt    // ApiResult<T> wrapper
core-model/auth/
  RecoveryChallengeModels.kt       // Moshi DTOs
```

### 4.2 Factor model

```kotlin
enum class RecoveryFactor { EMAIL, SMS, TOTP, RECOVERY }

val RecoveryFactor.requiresBegin: Boolean
    get() = this == RecoveryFactor.EMAIL || this == RecoveryFactor.SMS

val RecoveryFactor.pathSegment: String
    get() = when (this) {
        RecoveryFactor.EMAIL -> "email"
        RecoveryFactor.SMS -> "sms"
        RecoveryFactor.TOTP -> "totp"
        RecoveryFactor.RECOVERY -> "recovery"
    }
```

### 4.3 Retrofit interface

```kotlin
interface PasswordRecoveryApi {
    // AND-057 owns: @POST("ui/password-recovery/start")

    // Begin: email/sms only. Body = PasswordRecoveryChallengeReq {username, challenge_id}.
    @POST("ui/password-recovery/challenge/{factor}/begin")
    suspend fun beginChallenge(
        @Path("factor") factor: String,           // "email" | "sms"
        @Body body: RecoveryChallengeBeginRequest,
    ): Response<RecoveryChallengeBeginResponse>

    // Verify: email & sms share path shape and a {username, challenge_id, code} body.
    @POST("ui/password-recovery/challenge/{factor}/verify")
    suspend fun verifyEmailOrSms(
        @Path("factor") factor: String,           // "email" | "sms"
        @Body body: RecoveryEmailSmsVerifyRequest,
    ): Response<RecoveryVerifyResponse>

    // TOTP: distinct body field name `totp_code` (NOT `code`).
    @POST("ui/password-recovery/challenge/totp/verify")
    suspend fun verifyTotp(
        @Body body: RecoveryTotpVerifyRequest,
    ): Response<RecoveryVerifyResponse>

    // Recovery (backup) code: FLAT path, no /verify; body field is `recovery_code` + `factor`.
    @POST("ui/password-recovery/challenge/recovery")
    suspend fun verifyRecoveryCode(
        @Body body: RecoveryCodeRequest,
    ): Response<RecoveryVerifyResponse>
}
```

*(Correction: the original draft used a single `@Path("factor")` verify route
with one shared `RecoveryChallengeVerifyRequest`. Per OpenAPI the request bodies
differ by factor — email/sms use `code`, totp uses `totp_code`, recovery uses
`recovery_code` + `factor` — and the recovery route is the flat
`/challenge/recovery` with no `/verify` suffix. All bodies also require
`username`.)* `totp`/`recovery` have no `begin` route; `requiresBegin == false`
short-circuits before any begin request.

### 4.4 Repository

```kotlin
class PasswordRecoveryRepository @Inject constructor(
    private val api: PasswordRecoveryApi,
    private val errorMapper: ApiErrorMapper, // maps FastAPI detail shapes
) {
    // `username` is REQUIRED by every backend schema and must be carried from AND-057 start.
    suspend fun begin(
        factor: RecoveryFactor,
        username: String,
        challengeId: String,
    ): ApiResult<RecoveryChallengeBeginResponse> =
        if (!factor.requiresBegin) ApiResult.Success(RecoveryChallengeBeginResponse.None)
        else safeApiCall(errorMapper) {
            api.beginChallenge(
                factor.pathSegment, // "email" | "sms"
                RecoveryChallengeBeginRequest(username = username, challengeId = challengeId),
            )
        }

    suspend fun verify(
        factor: RecoveryFactor,
        username: String,
        challengeId: String,
        code: String,
    ): ApiResult<RecoveryVerifyResponse> = safeApiCall(errorMapper) {
        val c = code.trim()
        when (factor) {
            RecoveryFactor.EMAIL, RecoveryFactor.SMS ->
                api.verifyEmailOrSms(
                    factor.pathSegment,
                    RecoveryEmailSmsVerifyRequest(username, challengeId, code = c),
                )
            RecoveryFactor.TOTP ->
                api.verifyTotp(RecoveryTotpVerifyRequest(username, challengeId, totpCode = c))
            RecoveryFactor.RECOVERY ->
                api.verifyRecoveryCode(
                    RecoveryCodeRequest(username, challengeId, factor = "recovery", recoveryCode = c),
                )
        }
    }
}
```

`safeApiCall` returns `ApiResult.Success | ApiResult.Error(AppError)` and never
throws; `AppError` carries a typed `kind` (see §7).

### 4.5 ViewModel

```kotlin
@HiltViewModel
class RecoveryViewModel @Inject constructor(
    private val repo: PasswordRecoveryRepository,
    private val clock: Clock,
) : ViewModel() {

    private val _state = MutableStateFlow<RecoveryUiState>(RecoveryUiState.Loading)
    val state: StateFlow<RecoveryUiState> = _state.asStateFlow()

    fun selectFactor(factor: RecoveryFactor) { /* set active factor, begin if needed */ }
    fun onCodeChange(code: String) { /* update field, validate length */ }
    fun resendCode() { /* re-begin, enforce cooldown */ }
    fun verify() { /* guard in-flight; call repo.verify; on success emit Verified */ }
    fun switchFactor() { /* return to factor selection, keep challengeId */ }
}
```

### 4.6 State machine

`FactorSelect → (begin)? → CodeEntry → (verify) → Verified → [hand off to AND-059]`.
Expired challenge from any node → `RestartRequired` (route back to AND-057
start). The `challenge_id` is the single carried token across all transitions.

## 5. API Contract

Base URL `http://18.222.237.167:8000/`. All recovery endpoints are
unauthenticated POSTs with JSON bodies. In the web client, the transport sends
`X-CSRF-Token` **only when a `ui_csrf` cookie is present** (see
`src/api/client.ts`); during unauthenticated recovery no such cookie exists, so
no token is sent — but the rule is "send if cookie present," not "never send."
The Android `OkHttp` client should mirror this (omit the header when no cookie).

**Shapes verified against OpenAPI.** Two important facts the original draft got
wrong: (1) every request body **requires `username`**; (2) the documented
**success responses are untyped objects** (`additionalProperties: true` with no
declared fields) and the **only documented error is `422 HTTPValidationError`**.
Fields like `verified`, `next`, `recovery_token`, `delivery_medium`,
`destination`, `expires_at`, and `resend_available_in` are **NOT in the OpenAPI**
— they are forward-looking assumptions (see §16). The Moshi response models must
therefore tolerate-absent (all-nullable) and the implementer must confirm the
real runtime body against the dev host before relying on any of these fields.

### 5.1 Begin (email / sms only)

`POST /ui/password-recovery/challenge/email/begin`
`POST /ui/password-recovery/challenge/sms/begin`

Request — schema `PasswordRecoveryChallengeReq`, **both fields required**:
```json
{ "username": "alice", "challenge_id": "chl_8f2a1c..." }
```

Response 200 — OpenAPI declares an **untyped object** (`additionalProperties:
true`, no fields). The following is an **assumed/aspirational** shape (NOT in the
spec); treat all fields as optional/nullable and verify at runtime. Note the web
*start* response uses `delivery_destination` (not `destination`), so prefer that
name if/when present:
```json
{
  "challenge_id": "chl_8f2a1c...",
  "delivery_medium": "EMAIL",
  "delivery_destination": "j•••@example.com",
  "expires_at": "2026-06-05T18:42:00Z",
  "resend_available_in": 30
}
```

### 5.2 Verify (per factor — paths and bodies differ)

| Factor | Path | Schema | Code field |
|---|---|---|---|
| email | `POST /ui/password-recovery/challenge/email/verify` | `PasswordRecoveryEmailVerifyReq` | `code` |
| sms | `POST /ui/password-recovery/challenge/sms/verify` | `PasswordRecoverySmsVerifyReq` | `code` |
| totp | `POST /ui/password-recovery/challenge/totp/verify` | `PasswordRecoveryTotpVerifyReq` | `totp_code` |
| recovery | `POST /ui/password-recovery/challenge/recovery` (no `/verify`) | `PasswordRecoveryRecoveryCodeReq` | `recovery_code` (+ `factor`) |

*(Correction: original draft used one `{factor}/verify` path with a single
`code` field for all factors. OpenAPI shows distinct schemas and field names, and
the recovery route is flat.)* All bodies require `username` and `challenge_id`.

Requests:
```json
// email / sms
{ "username": "alice", "challenge_id": "chl_8f2a1c...", "code": "482913" }
// totp
{ "username": "alice", "challenge_id": "chl_8f2a1c...", "totp_code": "482913" }
// recovery (backup code)
{ "username": "alice", "challenge_id": "chl_8f2a1c...", "factor": "recovery", "recovery_code": "ABCD-1234-EFGH" }
```

Response 200 — **untyped object** in OpenAPI (`additionalProperties: true`, no
declared fields). The passed/`verified`/`next`/`recovery_token` shape below is an
**assumption**, not in the contract; implement defensively:
```json
{
  "challenge_id": "chl_8f2a1c...",
  "verified": true,
  "next": "confirm",
  "recovery_token": "rcv_...optional..."
}
```

Documented error — the **only** error response in OpenAPI is `422
HTTPValidationError`:
```json
{ "detail": [{ "loc": ["body", "code"], "msg": "...", "type": "..." }] }
```
The web client's `normalizeErrorDetail` (`src/api/client.ts`) additionally
tolerates a bare-string `detail`, an array of `{msg}`, and an object
`{code,...}`/`{msg}`; mirror that tolerance. **However, status codes
400/404/410/429 and `detail.code == "challenge_expired"` / `rate_limited` /
`Retry-After` are NOT documented in the OpenAPI** — they are assumptions (see
§16). Keep the mapping branches but treat them as defensive until confirmed
against the running backend.

Status codes the client should handle: 200 (success; if a `verified` field is
ever present, honor it), 422 (validation/invalid code), plus defensive handling
of 4xx/5xx/timeout as below.

DTOs (request shapes verified against OpenAPI `components.schemas`; response
fields are nullable because the contract declares only an untyped object):
```kotlin
// PasswordRecoveryChallengeReq — username + challenge_id both required
@JsonClass(generateAdapter = true)
data class RecoveryChallengeBeginRequest(
    @Json(name = "username") val username: String,
    @Json(name = "challenge_id") val challengeId: String,
)

// PasswordRecovery{Email,Sms}VerifyReq — code field
@JsonClass(generateAdapter = true)
data class RecoveryEmailSmsVerifyRequest(
    @Json(name = "username") val username: String,
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "code") val code: String,
)

// PasswordRecoveryTotpVerifyReq — totp_code field
@JsonClass(generateAdapter = true)
data class RecoveryTotpVerifyRequest(
    @Json(name = "username") val username: String,
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "totp_code") val totpCode: String,
)

// PasswordRecoveryRecoveryCodeReq — factor + recovery_code fields
@JsonClass(generateAdapter = true)
data class RecoveryCodeRequest(
    @Json(name = "username") val username: String,
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "factor") val factor: String,
    @Json(name = "recovery_code") val recoveryCode: String,
)

// Begin response: OpenAPI = untyped object. All fields nullable/assumed.
@JsonClass(generateAdapter = true)
data class RecoveryChallengeBeginResponse(
    @Json(name = "challenge_id") val challengeId: String? = null,
    @Json(name = "delivery_medium") val deliveryMedium: String? = null,
    // web start resp uses `delivery_destination`; accept both if needed
    @Json(name = "delivery_destination") val deliveryDestination: String? = null,
    @Json(name = "expires_at") val expiresAt: String? = null,
    @Json(name = "resend_available_in") val resendAvailableIn: Int? = null,
) { companion object { val None = RecoveryChallengeBeginResponse() } }

// Verify response: OpenAPI = untyped object. `verified`/`next`/`recovery_token`
// are ASSUMED (not in contract). Treat absent `verified` as "trust HTTP 200".
@JsonClass(generateAdapter = true)
data class RecoveryVerifyResponse(
    @Json(name = "challenge_id") val challengeId: String? = null,
    @Json(name = "verified") val verified: Boolean? = null,
    @Json(name = "next") val next: String? = null,
    @Json(name = "recovery_token") val recoveryToken: String? = null,
)
```

## 6. Data & State Management

### 6.1 UI state

```kotlin
sealed interface RecoveryUiState {
    data object Loading : RecoveryUiState
    data class FactorSelect(
        val challengeId: String,
        val factors: List<RecoveryFactor>,
    ) : RecoveryUiState
    data class CodeEntry(
        val challengeId: String,
        val factor: RecoveryFactor,
        val maskedDestination: String?,
        val code: String = "",
        val submitting: Boolean = false,
        val resendCooldownSec: Int = 0,
        val inlineError: String? = null,
    ) : RecoveryUiState
    data class Verified(
        val challengeId: String,
        val recoveryToken: String?,
    ) : RecoveryUiState
    data class RestartRequired(val reason: String) : RecoveryUiState
}
```

`code` length validation: numeric factors (email/sms/totp) require 6 digits;
`recovery` accepts the backend's backup-code format (length ≥ 8, alphanumeric).
Submit enabled only when length-valid and `!submitting`.

### 6.2 Persistence

The `challenge_id`, active `factor`, and `expires_at` are held in
`SavedStateHandle` so process death during code entry does not lose the
challenge. **No secrets** (entered code, `recovery_token`) are persisted to disk
or DataStore — they live only in in-memory state and `SavedStateHandle` for the
transient code string is acceptable but cleared on success/failure. The
`recovery_token` is passed in-memory to AND-059 via the nav back-stack /
ViewModel scope, never written to Room or DataStore.

### 6.3 Cooldown

`resend_available_in` (or default 30s) drives a `tickerFlow` that decrements
`resendCooldownSec` once per second on the ViewModel scope; resend is disabled
while `> 0`.

## 7. Error Handling & Resilience

```kotlin
enum class AppErrorKind {
    INVALID_CODE, CHALLENGE_EXPIRED, RATE_LIMITED,
    NETWORK_OFFLINE, TIMEOUT, SERVER, UNKNOWN
}
```

Mapping (note: only `422` is a documented error code; `verified` may be absent
in the real body — when absent, treat HTTP 200 as success; the `verified==false`
branch is defensive):
- `verified == false` or 400/422 → `INVALID_CODE` → inline "That code didn't
  match. Check it and try again."; clear the `code` field; stay on `CodeEntry`.
- 404/410 or `detail.code == "challenge_expired"` → `CHALLENGE_EXPIRED` →
  `RestartRequired` → route to AND-057 start with a one-line banner.
- 429 / `rate_limited` → `RATE_LIMITED` → disable submit, set
  `resendCooldownSec` from `Retry-After` (fallback 60s), inline "Too many
  attempts. Wait {n}s."
- `IOException`/no connectivity → `NETWORK_OFFLINE` → snackbar with **Retry**;
  no auto-retry (POST).
- 20s timeout (OkHttp `callTimeout = 20s`, applied to recovery client) →
  `TIMEOUT` → "The server is taking too long. Try again." with manual retry.
- 5xx → `SERVER`.

Resilience rules specific to the unreliable dev host:
- `callTimeout`/`readTimeout` = 20s; `connectTimeout` = 10s.
- **No automatic retry on `begin` or `verify`** — both mutate challenge state on
  the server (a code send and an attempt counter); auto-retry could burn the
  attempt budget or send duplicate SMS. Backoff retry is reserved for idempotent
  GETs elsewhere; not applicable here.
- Double-submit guard: `verify()` early-returns if `state.submitting`.

## 8. Security & Privacy

- Flow is unauthenticated; the `challenge_id` is the sole capability token and
  must be treated as a bearer secret in memory.
- Dev backend is plaintext HTTP (transport insecure by environment). Production
  config must use HTTPS; the network module enforces a cleartext allowlist
  scoped to the dev host only via `network_security_config.xml` — recovery
  codes/tokens must never traverse cleartext in production builds.
- Entered codes and `recovery_token` are excluded from logs (see §10), excluded
  from `toString()` of state via redaction, and never persisted to Room/DataStore.
- Code field uses `KeyboardType.NumberPassword` for numeric factors to suppress
  keyboard suggestion/learning; `recovery` uses `KeyboardType.Password`.
- Disable screenshots on the recovery code screen is optional; recommend
  `FLAG_SECURE` on the Activity window while a recovery code is on screen
  (coordinate with single-Activity owner; deferred if it conflicts with other
  screens — track as open question OQ-3).
- No user enumeration leakage: error copy for invalid code is identical
  regardless of whether the destination exists (backend already abstracts this).

## 9. Accessibility & i18n

- All strings in `feature-auth` `strings.xml`; no hardcoded copy. Keys:
  `recovery_code_title`, `recovery_code_sent_to`, `recovery_code_hint`,
  `recovery_resend`, `recovery_resend_in`, `recovery_switch_factor`,
  `recovery_error_invalid_code`, `recovery_error_expired`,
  `recovery_error_rate_limited`, `recovery_error_network`,
  `recovery_error_timeout`.
- Code field: `contentDescription` / `semantics` label; inline error wired via
  `Modifier.semantics { error(message) }` so TalkBack announces it.
- Resend cooldown announced as a live region (`liveRegion = Polite`) when it
  changes from disabled→enabled.
- Masked destination read in full to TalkBack (the mask itself is the content;
  no PII expansion).
- Touch targets ≥ 48dp; submit and resend buttons meet Material 3 minimums.
- Plurals for `recovery_resend_in` (seconds) via `<plurals>`.

## 10. Telemetry & Logging

- Events (no PII, no codes): `recovery_challenge_begin` `{factor}`,
  `recovery_challenge_verify_attempt` `{factor}`,
  `recovery_challenge_verify_result` `{factor, outcome=passed|invalid|expired|rate_limited|error}`,
  `recovery_challenge_resend` `{factor}`,
  `recovery_challenge_switch_factor` `{from, to}`.
- Logging: `Timber` at DEBUG for state transitions; request/response bodies are
  **never** logged at INFO+; OkHttp `HttpLoggingInterceptor` set to `HEADERS`
  (not `BODY`) for the recovery client, or `NONE` in release. A redacting
  interceptor strips `code` and `recovery_token` if body logging is ever
  enabled.
- Error events carry the mapped `AppErrorKind`, never raw `detail`.

## 11. Testing Strategy

Acceptance demands each challenge path passes/fails correctly (tested).

- **Repository unit tests** (`core-testing` + MockWebServer, JUnit5, Turbine):
  for each factor `{email, sms, totp, recovery}`:
  - verify success (200 `verified=true`) → `ApiResult.Success` with token.
  - verify wrong code (200 `verified=false` and 422 `detail[].msg`) →
    `AppErrorKind.INVALID_CODE`.
  - expired (410 `detail.code=challenge_expired`) → `CHALLENGE_EXPIRED`.
  - rate-limited (429 + `Retry-After`) → `RATE_LIMITED` with cooldown parsed.
  - timeout (`MockWebServer` no response / `SocketPolicy`) → `TIMEOUT`.
  - `begin` for email/sms hits the correct path; `totp`/`recovery` never call
    `begin` (verify-only) — assert request path and count.
- **ViewModel tests** (`MainDispatcherRule`, fake repo): state transitions
  FactorSelect→CodeEntry→Verified; invalid-code clears field and stays;
  expired→RestartRequired; double-tap `verify()` issues one call; resend
  cooldown ticks and gates resend.
- **Path-matrix test** parameterized over all four factors asserting the exact
  URL `ui/password-recovery/challenge/{factor}/verify` (and begin where
  applicable).
- **Compose UI tests** (`createAndroidComposeRule`): submit disabled until
  6-digit code; inline error rendered and announced; resend disabled during
  cooldown.
- **No live calls** to `18.222.237.167` in CI; MockWebServer only. One optional
  manual smoke checklist against the dev host documented in the PR.
- Coverage gate: every `AppErrorKind` branch exercised; every factor path
  exercised pass and fail.

## 12. Dependencies & Sequencing

- **Depends on AND-057** — requires the Recovery screen scaffold,
  `RecoveryViewModel`, `PasswordRecoveryApi`/`Repository` skeleton, and a valid
  `challenge_id` + `required_factors` from `/ui/password-recovery/start`. This
  ticket extends those artifacts; it does not create a second ViewModel.
- **Transitively depends on AND-030** (via AND-057) — base auth/network module
  and `ApiResult`/error-mapper plumbing.
- **Blocks AND-059** — confirm-new-password consumes the verified
  `challenge_id` and `recovery_token` produced here. The `Verified` state
  contract (`challengeId`, `recoveryToken`) is the integration surface.
- Sequence: AND-057 → **AND-058** → AND-059. Land behind the existing recovery
  nav graph; no flag needed beyond the E08 entry point gate from AND-057.

## 13. Risks & Open Questions

- **OQ-1 (partially resolved):** Exact `verify` success/failure contract. OpenAPI
  declares success as an **untyped object** and the only error as
  `422 HTTPValidationError` — there is no documented `verified` field nor
  documented 400/404/410/429. We keep both the `verified==false` and the 4xx
  branches as **defensive** behavior; the implementer MUST capture a real
  response from the dev host (`18.222.237.167:8000`) and prune dead branches.
  *(Verified against `openapi.index.txt` + `openapi.pretty.json`; the web app
  does not exercise these endpoints, so no frontend confirmation is available.)*
- **OQ-2 (RESOLVED):** The backup-code endpoint is the **flat**
  `POST /ui/password-recovery/challenge/recovery` (schema
  `PasswordRecoveryRecoveryCodeReq`), **not** `/challenge/recovery/verify` and
  **not** the unrelated `/ui/recovery/*` or `/ui/mfa/recovery/{factor}` (those
  use the MFA `RecoveryReq` schema). Implement it as its own call with body
  `{username, challenge_id, factor, recovery_code}`.
- **OQ-3:** `FLAG_SECURE` interaction with the single-Activity host (§8).
- **Risk:** Unreliable dev host causes flaky manual testing — mitigated by
  MockWebServer-only CI and explicit timeout/offline UI states.
- **Risk:** Attempt-budget exhaustion from accidental retries — mitigated by the
  no-auto-retry rule and double-submit guard.
- **Risk:** Token leakage in logs/state dumps — mitigated by redaction (§8/§10).

## 14. Acceptance Criteria

AC-1. For each factor `email`, `sms`, `totp`, `recovery`, a correct code yields
HTTP 200 `verified:true` and advances the UI to the AND-059 confirm step,
carrying the verified `challenge_id` (and `recovery_token` when present).
*(tested)*

AC-2. For each factor, an incorrect code surfaces the invalid-code inline error,
clears the field, and keeps the user on the code-entry screen. *(tested)*

AC-3. `email`/`sms` begin issues a delivery and shows the masked destination;
`totp`/`recovery` never call `begin`. *(tested — path/count assertions)*

AC-4. An expired challenge (404/410/`challenge_expired`) routes to
`RestartRequired` (back to AND-057 start) with a banner. *(tested)*

AC-5. Rate-limited (429) disables submit and shows a cooldown derived from
`Retry-After`. *(tested)*

AC-6. Network-offline and 20s-timeout each produce their distinct manual-retry
state with no automatic retry of the POST. *(tested)*

AC-7. Resend is gated by the cooldown; double-tapping submit issues exactly one
`verify` request. *(tested)*

AC-8. No code or `recovery_token` appears in logs or persisted storage; verified
by a redaction/logging test and code review.

## 15. Definition of Done

- All four challenge variants implemented (begin where applicable + verify) and
  wired into the existing `RecoveryViewModel` / nav graph from AND-057.
- Retrofit interface, Moshi DTOs, and repository merged in `core-network` /
  `core-model`, field names verified against `/openapi.json` and
  `frontend/src/api/types.ts`.
- All §14 acceptance criteria pass in CI (unit + ViewModel + Compose tests via
  MockWebServer; no live host calls).
- `Verified` state contract documented and consumed-readily by AND-059;
  integration handoff confirmed with AND-059 owner.
- All strings localized; accessibility (TalkBack error/live-region, 48dp
  targets) verified.
- Telemetry events emitted with no PII; logging interceptor scoped to
  `HEADERS`/`NONE` with redaction in place.
- Lint, detekt, and ktlint clean; no new cleartext-traffic exposure beyond the
  scoped dev-host allowlist.
- Open questions OQ-1/OQ-2 resolved or explicitly deferred with the chosen
  default documented in the PR description; reviewed and merged to
  `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim with its VERDICT and SOURCE pointer. OpenAPI sources are
`reference/openapi.index.txt` (index) and `reference/openapi.pretty.json`
(`components.schemas.<Name>`). Frontend sources are under `reference/src/`.

1. **Begin endpoints `POST /ui/password-recovery/challenge/{email,sms}/begin`
   exist.** VERIFIED. Source: OpenAPI `POST /ui/password-recovery/challenge/email/begin`
   and `.../sms/begin` (index lines), req schema `PasswordRecoveryChallengeReq`.
2. **Begin request body requires `username` AND `challenge_id`.** CORRECTED
   (draft sent only `challenge_id`). Source: schema `PasswordRecoveryChallengeReq`
   (`required: [username, challenge_id]`).
3. **Verify endpoints exist for email/sms/totp at `.../challenge/{factor}/verify`.**
   VERIFIED. Source: OpenAPI `POST /ui/password-recovery/challenge/email/verify`,
   `.../sms/verify`, `.../totp/verify`.
4. **Backup-code path is `/challenge/recovery/verify`.** CORRECTED → it is the
   flat `POST /ui/password-recovery/challenge/recovery` (no `/verify`). Source:
   OpenAPI `POST /ui/password-recovery/challenge/recovery` (op
   `password_recovery_code_...`), req `PasswordRecoveryRecoveryCodeReq`.
5. **A single shared verify body with one `code` field works for all factors.**
   CORRECTED → field names differ: email/sms `code`
   (`PasswordRecoveryEmailVerifyReq`, `PasswordRecoverySmsVerifyReq`), totp
   `totp_code` (`PasswordRecoveryTotpVerifyReq`), recovery `recovery_code` +
   `factor` (`PasswordRecoveryRecoveryCodeReq`). Source: those four schemas.
6. **All verify bodies require `username` + `challenge_id`.** VERIFIED/CORRECTED
   (draft omitted `username`). Source: `required` arrays of the four verify
   schemas (each lists `username`, `challenge_id`, plus the code field).
7. **Verify/begin success responses contain `verified`, `next`,
   `recovery_token`, `delivery_medium`, `destination`, `expires_at`,
   `resend_available_in`.** UNVERIFIED-ASSUMPTION → OpenAPI declares every success
   `200` as an untyped object (`additionalProperties: true`, no declared fields).
   Source: the `responses.200.content.application/json.schema` of each path
   (e.g. title "Response Password Recovery Email Verify ..."). Models made
   all-nullable; runtime capture required.
8. **The masked destination field is named `destination`.** CORRECTED → the web
   *start* response uses `delivery_destination`. Source:
   `src/api/types.ts: PasswordRecoveryStartResp` (`delivery_medium?`,
   `delivery_destination?`, `challenge_id?`, `required_factors`). Begin response
   is untyped, so `delivery_destination` is the better-evidenced name.
9. **The only documented error is `422 HTTPValidationError`; 400/404/410/429,
   `challenge_expired`, `rate_limited`, and `Retry-After` are real backend
   behaviors.** PARTIALLY VERIFIED / mostly UNVERIFIED-ASSUMPTION → only `422`
   appears in OpenAPI for all six paths; the other codes/strings are NOT in the
   contract. Source: `responses` of each path (only `200` + `422`); schema
   `HTTPValidationError` = `{ detail: ValidationError[] }`.
10. **FastAPI `detail` can be a string, an array of `{msg}`, or an object
    `{code,...}`/`{msg}`, and the client handles all three.** VERIFIED. Source:
    `src/api/client.ts: normalizeErrorDetail` (and `mapAuthorizationError`).
11. **No `X-CSRF-Token` is sent on recovery (unauthenticated).** VERIFIED with
    nuance → the client sends `X-CSRF-Token` only when a `ui_csrf` cookie exists
    and always uses `credentials: "include"`; unauthenticated recovery has no
    cookie so none is sent. Source: `src/api/client.ts` (`getCookie("ui_csrf")`
    → `headers.set("X-CSRF-Token", csrf)`).
12. **The web app exercises these per-factor challenge begin/verify endpoints.**
    CORRECTED → it does not. The web `PasswordRecovery` page uses only
    `passwordRecoveryStart` then `passwordRecoveryConfirm` (with
    `confirmation_code`). Source: `src/pages/PasswordRecovery.tsx`,
    `src/api/endpoints/auth.ts` (only `passwordRecoveryStart`/`Confirm` wrappers).
    The challenge endpoints are backend-only here; contract confirmation comes
    from OpenAPI alone.
13. **`/ui/password-recovery/start` returns `challenge_id` + `required_factors`
    (consumed from AND-057).** VERIFIED. Source:
    `src/api/types.ts: PasswordRecoveryStartResp`; OpenAPI
    `POST /ui/password-recovery/start` (req `PasswordRecoveryStartReq`).
14. **`/ui/password-recovery/confirm` (AND-059) takes
    `{username, confirmation_code, new_password, challenge_id?}`.** VERIFIED
    (informational; out of scope for AND-058). Source: schema
    `PasswordRecoveryConfirmReq`; `src/api/types.ts: PasswordRecoveryConfirmReq`.
15. **Stack choices: Compose/Material 3, Hilt, Retrofit/OkHttp/Moshi,
    SavedStateHandle for process-death survival, `KeyboardType.NumberPassword`,
    `FLAG_SECURE`, TalkBack live regions.** UNVERIFIED-ASSUMPTION (framework
    refs, not backend-checkable). framework ref:
    https://developer.android.com/jetpack/compose ,
    https://developer.android.com/topic/libraries/architecture/saved-state ,
    https://developer.android.com/reference/android/view/WindowManager.LayoutParams#FLAG_SECURE ,
    https://developer.android.com/jetpack/compose/text/configure-keyboard .

### Corrections made

- §1/§5/§5.2/DTOs: added `username` as a required field on every begin and verify
  request (was omitted; OpenAPI marks it required).
- §4.3/§4.4/§5.2/§6/§13: backup-code endpoint changed from
  `/challenge/recovery/verify` to the flat `/challenge/recovery` (resolves OQ-2).
- §4.3/§5.2/DTOs: split the single shared verify body into per-factor bodies with
  correct field names (`code`, `totp_code`, `recovery_code` + `factor`).
- §5/§5.1/§5.2/§7/DTOs: flagged all success-response fields and all error codes
  beyond `422` as untyped/assumed; made response models all-nullable; corrected
  masked field name to `delivery_destination`.
- §5: clarified the CSRF behavior (sent only when `ui_csrf` cookie present).
- §13: OQ-1 marked partially resolved, OQ-2 marked resolved.

### Open assumptions

- **Success-body fields** (`verified`, `next`, `recovery_token`,
  `delivery_medium`, `delivery_destination`, `expires_at`,
  `resend_available_in`): not in OpenAPI (untyped `200` objects). Unverifiable
  without a live capture from `18.222.237.167:8000`; the dev host is plaintext +
  unreliable and CI forbids live calls, so this stays open until manual capture.
- **Error semantics beyond `422`** (404/410 → expired, 429 + `Retry-After` →
  rate-limited, `detail.code` values): not in OpenAPI; kept as defensive branches.
- **TOTP/recovery code formats** (6-digit vs. backup-code length/charset):
  schemas type both as plain `string` with no pattern; the §6.1 length rules are
  client-side assumptions.
- **Whether `begin` returns a fresh `resend_available_in`/cooldown**: assumed;
  client falls back to a 30s default.

## 17. Test Plan

IDs `TC-AND-058-NN`. Targets: JVM = JVM unit/Robolectric (no device); EMU =
headless emulator AVD `test35` (x86_64, API 35); DEV = physical Samsung Galaxy
A15 5G (SM-A156U, API 34, arm64-v8a). MockWebServer (MWS) cases are pure
JVM/Robolectric. None of these endpoints need real hardware, so most run on JVM;
Compose-UI cases run on EMU (fast, KVM); a few run on DEV to confirm
arm64/API-34 parity and real soft-keyboard/TalkBack behavior. No live calls to
the dev host in CI.

- **TC-AND-058-01** — Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: MWS enqueues `200` for each verify path. Steps: for each factor
  call `repo.verify(factor, username, challengeId, code)` and capture the
  request. Expected: path is exactly `.../challenge/email/verify`,
  `.../sms/verify`, `.../totp/verify`, and `.../challenge/recovery` (no
  `/verify`); bodies carry `username`+`challenge_id` and the correct code field
  (`code` / `code` / `totp_code` / `recovery_code`+`factor`); result is
  `ApiResult.Success`. Traces: AC-1, AC-3.
- **TC-AND-058-02** — Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: MWS `200` for email & sms begin; verify-only factors stubbed.
  Steps: `repo.begin(EMAIL/SMS, ...)` then `repo.begin(TOTP/RECOVERY, ...)`.
  Expected: email/sms hit `.../challenge/{factor}/begin` with body
  `{username, challenge_id}` (HTTP requestCount == 2); totp/recovery make **zero**
  begin requests (short-circuit via `requiresBegin == false`). Traces: AC-3.
- **TC-AND-058-03** — Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: MWS returns `200` with body omitting `verified` (untyped object,
  matching OpenAPI). Steps: verify with a valid code. Expected: absent `verified`
  is treated as success → `ApiResult.Success`; any `recovery_token` present is
  surfaced. Traces: AC-1.
- **TC-AND-058-04** — Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: MWS returns `422 HTTPValidationError`
  `{detail:[{loc,msg,type}]}` and, in a second run, `200` with
  `{verified:false}`. Steps: verify wrong code under each. Expected: both map to
  `AppErrorKind.INVALID_CODE`; message derived via the detail-array `msg`.
  Traces: AC-2.
- **TC-AND-058-05** — Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: MWS returns `410` with `{detail:{code:"challenge_expired"}}`
  (defensive/assumed shape). Steps: verify. Expected: maps to
  `AppErrorKind.CHALLENGE_EXPIRED`. (Marked as exercising an UNVERIFIED backend
  branch per §16.) Traces: AC-4.
- **TC-AND-058-06** — Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: MWS returns `429` with header `Retry-After: 45`. Steps: verify.
  Expected: maps to `AppErrorKind.RATE_LIMITED`; cooldown parsed = 45s (fallback
  60s when header absent). (Assumed backend branch per §16.) Traces: AC-5.
- **TC-AND-058-07** — Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: MWS `SocketPolicy.NO_RESPONSE` (timeout) and, separately, no
  connectivity / `IOException`. Steps: verify under each. Expected: timeout →
  `AppErrorKind.TIMEOUT`; offline → `AppErrorKind.NETWORK_OFFLINE`; **no
  automatic retry** issued (requestCount == 1). Traces: AC-6.
- **TC-AND-058-08** — Type: unit (JVM). Target: JVM. Preconditions: fake repo,
  `MainDispatcherRule`, Turbine. Steps: drive ViewModel
  `selectFactor → onCodeChange(valid) → verify()` with repo success. Expected:
  state transitions `FactorSelect → CodeEntry → Verified(challengeId,
  recoveryToken)`; email/sms also pass through a begin call. Traces: AC-1.
- **TC-AND-058-09** — Type: unit (JVM). Target: JVM. Preconditions: fake repo
  returns INVALID_CODE then CHALLENGE_EXPIRED. Steps: `verify()` twice. Expected:
  first keeps `CodeEntry` with `inlineError` set and `code` cleared; second emits
  `RestartRequired`. Traces: AC-2, AC-4.
- **TC-AND-058-10** — Type: unit (JVM). Target: JVM. Preconditions: fake repo
  with a controllable delay; ViewModel double-submit guard. Steps: call
  `verify()` twice rapidly while `submitting == true`; separately tick the resend
  cooldown via fake `Clock`. Expected: exactly **one** repo.verify invocation;
  resend disabled while `resendCooldownSec > 0` and re-enabled at 0. Traces:
  AC-7.
- **TC-AND-058-11** — Type: Compose-UI (instrumented). Target: EMU (`test35`).
  Preconditions: `createAndroidComposeRule`, ViewModel in `CodeEntry`. Steps:
  type a 3-digit then 6-digit code; submit; trigger an inline error. Expected:
  submit disabled until length-valid; inline error rendered; resend disabled
  during cooldown. Traces: AC-2, AC-5, AC-7.
- **TC-AND-058-12** — Type: Compose-UI accessibility (instrumented). Target: DEV
  (physical SM-A156U — real TalkBack + soft keyboard). Preconditions: TalkBack
  on; `CodeEntry` shown. Steps: focus the code field; submit a wrong code; let
  the cooldown elapse. Expected: field has a `contentDescription`; inline error
  announced via `semantics { error(...) }`; cooldown→enabled announced as a
  Polite live region; numeric factors use `NumberPassword` keyboard (no
  suggestions); touch targets ≥ 48dp. Must run on DEV for authentic TalkBack/IME
  behavior. Traces: AC-2, AC-5.
- **TC-AND-058-13** — Type: integration/security (JVM + Robolectric). Target:
  JVM. Preconditions: capture Timber/OkHttp logs and a `SavedStateHandle`
  snapshot during a full verify cycle; logging interceptor at `HEADERS`. Steps:
  run begin+verify with a real code and a returned `recovery_token`; dump logs,
  state `toString()`, and any persisted DataStore/Room. Expected: entered code
  and `recovery_token` appear in **none** of logs, `toString()`, or persisted
  storage (redaction holds); only `challenge_id`/`factor`/`expires_at` persist in
  `SavedStateHandle`. Traces: AC-8.
- **TC-AND-058-14** — Type: contract/MockWebServer security (JVM). Target: JVM.
  Preconditions: MWS over plaintext (dev-host allowlist) vs. an HTTPS host
  outside the allowlist. Steps: point the recovery client at each. Expected:
  cleartext permitted only for the scoped dev host; no `X-CSRF-Token` header is
  sent when no `ui_csrf` cookie is present (unauthenticated flow). Traces: AC-8,
  AC-1.
- **TC-AND-058-15** — Type: manual (smoke). Target: DEV (or EMU). Preconditions:
  reachable dev host `18.222.237.167:8000`, a real `challenge_id`+`username` from
  AND-057. Steps: run each factor's begin/verify against the live backend once;
  record the actual JSON success body and any non-422 error. Expected: confirms
  or refutes the §16 open assumptions (success-body fields, error codes); findings
  pasted into the PR. Not run in CI. Traces: AC-1, AC-2, AC-4, AC-5.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 | TC-01, TC-03, TC-08, TC-14, TC-15 |
| AC-2 | TC-04, TC-09, TC-11, TC-12, TC-15 |
| AC-3 | TC-01, TC-02 |
| AC-4 | TC-05, TC-09, TC-15 |
| AC-5 | TC-06, TC-11, TC-12, TC-15 |
| AC-6 | TC-07 |
| AC-7 | TC-10, TC-11 |
| AC-8 | TC-13, TC-14 |
