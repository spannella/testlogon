---
id: AND-040
title: MfaViewModel (challenge state machine)
milestone: M1
epic: E05
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-038, AND-039]
blocks: []
---

# AND-040 — MfaViewModel (challenge state machine)

## 1. Overview & Goal

AND-040 delivers `MfaViewModel`, the presentation-layer state machine that drives the
multi-factor authentication (MFA) challenge flow for the TestLogon native Android app. It
sits between the MFA screen UI (AND-039) and the auth repository / finalize-sequencing logic
(AND-038). Its single responsibility is to model the challenge lifecycle as an explicit,
deterministic state machine keyed on `challenge_id`, the ordered set of `required_factors`,
and the shrinking set of `remaining_factors`, and to translate user intents (select factor,
request OTP, submit OTP, resend, switch factor, retry, cancel) into repository calls while
emitting a single immutable `MfaUiState` for Compose to render.

The goal is a fully unit-tested ViewModel whose transitions are exhaustively covered, with
robust error recovery (recoverable validation/OTP errors keep the user on the current factor;
session-level failures route back to login; transport failures offer retry). On the terminal
success transition — all factors verified and `session/finalize` succeeds — it emits a
one-shot navigation event to the post-login destination. This ViewModel owns *orchestration
and UI state only*; the network/cookie/CSRF mechanics and the finalize sequencing rules are
owned by AND-038's repository, and the visual surface is owned by AND-039.

## 2. Context & References

- Module: `feature-auth` (`com.testlogon.android.feature.auth.mfa`). Depends on `core-data`
  (`AuthRepository`), `core-model` (DTOs/domain), `core-ui` (UiText, error mapping), and
  `core-network` (`ApiResult<T>`).
- Auth flow (authoritative, verified against OpenAPI index + `frontend/src/pages/Login.tsx`):
  `POST /ui/session/start` (req `UiSessionStartReq`) → `UiSessionStartResp {auth_required,
  challenge_id?, required_factors[], session_id?}` → per-factor verify:
  `POST /ui/mfa/totp/verify` (`TotpVerifyReq{challenge_id, totp_code}`),
  `POST /ui/mfa/sms/verify` / `POST /ui/mfa/email/verify` (`{challenge_id, code}`), with SMS/
  email first triggered by `POST /ui/mfa/sms/begin` / `POST /ui/mfa/email/begin`
  (`{challenge_id}`). **CORRECTION:** there is NO `/ui/mfa/totp/begin` endpoint — TOTP is
  verify-only (confirms FR-3/R4). Each verify returns `MfaVerifyResp {status, session_id?,
  required_factors[], passed{}, remaining_factors[]}`. When `remaining_factors` empties,
  `POST /ui/session/finalize` (`UiSessionFinalizeReq{challenge_id, remember_device?}`) →
  `SessionFinalizeResp{status:"ok"|"pending", session_id?, required_factors[], passed{}}`;
  AND-038 then calls `GET /ui/me` (`MeResp{user_sub, session_id, ip}`). Session rides cookies +
  `ui_csrf` cookie echoed as `X-CSRF-Token` (verified `src/api/client.ts`); a 401 on an
  already-authenticated request triggers a single `POST /ui/session/refresh` then one retry.
  All of this is implemented in `AuthRepository` (AND-034/035/036/038); AND-040 consumes it.
- Upstream: **AND-038** (`AuthRepository.verifyFactor`, `beginFactor`, `finalize`,
  multi-factor sequencing, `remember_device`). **AND-039** (MFA screen consuming this
  ViewModel's `StateFlow<MfaUiState>` and dispatching `MfaIntent`).
- Web reference: `frontend/src/api/endpoints/*.ts` (MFA begin/verify/finalize calls),
  `frontend/src/api/types.ts` (factor enums, challenge response shape).
- Patterns: ViewModels expose `StateFlow<UiState>`; typed `ApiResult<T>`; FastAPI `detail`
  mapping (`string | [{msg}] | {code,...}`).

## 3. Functional Requirements

FR-1. On entry the ViewModel is seeded with the challenge produced by `session/start`
(`challenge_id`, ordered `required_factors`, initial `remaining_factors`). Seed is passed via
navigation args / `SavedStateHandle`, never re-fetched.

FR-2. The ViewModel selects the *active factor* as the first element of `remaining_factors`
in `required_factors` order. If multiple factors remain, the UI may offer a switch among
remaining factors (FR-7); the ViewModel never auto-skips a required factor.

FR-3. For `totp`, no `begin` call is required (authenticator-generated); the ViewModel goes
directly to OTP entry. For `sms` and `email`, the ViewModel calls `beginFactor` to trigger
code delivery before showing OTP entry, and exposes a resend cooldown timer.

FR-4. On OTP submit the ViewModel calls `verifyFactor(challengeId, factor, code)` (CORRECTED:
no `rememberDevice` on verify — the backend accepts `remember_device` only at finalize). On
success it updates `remaining_factors` (and `required_factors`) from the `MfaVerifyResp`; if
`remaining_factors` is non-empty it advances to the next factor (re-running FR-3 for that
factor); if empty it calls `finalize(challengeId, rememberDevice)`.

FR-5. On `finalize` success the ViewModel emits a one-shot `MfaEvent.NavigateToHome` and
transitions to `Finalized`. Finalize and `/ui/me` hydration sequencing belong to AND-038; this
ViewModel awaits the repository's authenticated-session result.

FR-6. Resend (`sms`/`email`) re-invokes `beginFactor` and restarts a client-side cooldown
timer, during which resend is disabled. CORRECTION/ASSUMPTION: the begin response
(`ChallengeResp`) carries NO `resend_cooldown_seconds`; the 30s default is a client-only value
and is NOT server-overridable. The web reference (`Login.tsx`) implements resend as a plain
re-call of begin with no cooldown timer at all — the cooldown is an Android UX addition (see
§16 Open assumptions).

FR-7. Switch-factor selects another member of `remaining_factors` as active; allowed only when
`remaining_factors.size > 1`. Switching clears the current OTP input and error.

FR-8. Recovery option (CORRECTED against `Login.tsx` + OpenAPI): recovery is its own endpoint
`POST /ui/mfa/recovery/{factor}` with body `RecoveryReq{challenge_id, recovery_code, factor?}`,
NOT a re-use of the `email` factor path. In the web client recovery is ALWAYS offered as a
fallback method (not gated on remaining-factor count), and the path param is the literal
`recovery`. `MfaIntent.UseRecovery` should therefore route to this recovery endpoint with the
user-entered recovery code; the prior "map to email factor" assumption was incorrect.

FR-9. Client-side OTP validation (length/charset configurable per factor, default 6 digits)
rejects malformed input without a network call and keeps the user on the active factor.

FR-10. Cancel returns to the login screen and discards challenge state (emits
`MfaEvent.NavigateToLogin`).

FR-11. The active OTP input, error text, busy flag, and cooldown survive configuration changes
(held in ViewModel + `SavedStateHandle` for `challenge_id`/`remaining_factors`).

## 4. Technical Design

### State, intents, events

```kotlin
package com.testlogon.android.feature.auth.mfa

enum class MfaFactor { TOTP, SMS, EMAIL }

sealed interface MfaPhase {
    data object Idle : MfaPhase                 // seeded, resolving active factor
    data class Delivering(val factor: MfaFactor) : MfaPhase   // begin in flight (sms/email)
    data class AwaitingCode(val factor: MfaFactor) : MfaPhase
    data class Verifying(val factor: MfaFactor) : MfaPhase
    data object Finalizing : MfaPhase
    data object Finalized : MfaPhase
    data class FatalError(val message: UiText) : MfaPhase     // session-level, route to login
}

data class MfaUiState(
    val challengeId: String,
    val requiredFactors: List<MfaFactor>,
    val remainingFactors: List<MfaFactor>,
    val activeFactor: MfaFactor?,
    val phase: MfaPhase = MfaPhase.Idle,
    val otpInput: String = "",
    val otpLength: Int = 6,
    val rememberDevice: Boolean = false,
    val canSwitchFactor: Boolean = false,
    val canUseRecovery: Boolean = false,
    val resendCooldownSeconds: Int = 0,
    val inlineError: UiText? = null,   // recoverable; shown in-place, user stays on factor
    val isBusy: Boolean = false,
)

sealed interface MfaIntent {
    data class SelectFactor(val factor: MfaFactor) : MfaIntent
    data class OtpChanged(val value: String) : MfaIntent
    data class RememberDeviceChanged(val value: Boolean) : MfaIntent
    data object SubmitOtp : MfaIntent
    data object Resend : MfaIntent
    data object UseRecovery : MfaIntent
    data object Retry : MfaIntent       // re-attempt last failed network step
    data object Cancel : MfaIntent
}

sealed interface MfaEvent {           // one-shot, via Channel/receiveAsFlow
    data object NavigateToHome : MfaEvent
    data object NavigateToLogin : MfaEvent
    data class ShowSnackbar(val message: UiText) : MfaEvent
}
```

### ViewModel

```kotlin
@HiltViewModel
class MfaViewModel @Inject constructor(
    private val authRepository: AuthRepository,
    private val savedState: SavedStateHandle,
    private val clock: TimeSource = TimeSource.Monotonic,   // injectable for tests
) : ViewModel() {

    private val _state = MutableStateFlow(seedFromArgs(savedState))
    val state: StateFlow<MfaUiState> = _state.asStateFlow()

    private val _events = Channel<MfaEvent>(Channel.BUFFERED)
    val events: Flow<MfaEvent> = _events.receiveAsFlow()

    private var cooldownJob: Job? = null
    private var lastNetworkStep: (() -> Unit)? = null   // for Retry

    init { resolveActiveFactor() }     // runs begin for sms/email, sets AwaitingCode for totp

    fun onIntent(intent: MfaIntent) { /* dispatch table over the sealed type */ }

    private fun resolveActiveFactor() { /* FR-2/FR-3 */ }
    private fun submitOtp() { /* validate (FR-9) -> Verifying -> verifyFactor -> advance/finalize */ }
    private fun advanceAfterVerify(remaining: List<MfaFactor>) { /* FR-4/FR-5 */ }
    private fun finalize() { /* Finalizing -> finalize -> NavigateToHome */ }
    private fun startCooldown(seconds: Int) { /* tick down resendCooldownSeconds on viewModelScope */ }
}
```

### Transition table (authoritative)

| From | Event | Guard | To | Side effect |
|------|-------|-------|----|-------------|
| Idle | resolve, active=totp | — | AwaitingCode(totp) | none |
| Idle | resolve, active∈{sms,email} | — | Delivering(f) | `beginFactor` |
| Delivering(f) | begin ok | — | AwaitingCode(f) | start cooldown |
| Delivering(f) | begin transport err | — | AwaitingCode(f) | inlineError + Retry armed |
| AwaitingCode(f) | SubmitOtp | otp valid | Verifying(f) | `verifyFactor` |
| AwaitingCode(f) | SubmitOtp | otp invalid | AwaitingCode(f) | inlineError (no call) |
| AwaitingCode(f) | Resend | cooldown==0, f≠totp | Delivering(f) | `beginFactor` |
| AwaitingCode(f) | SelectFactor(g) | g∈remaining, size>1 | resolve(g) | clear otp/error |
| Verifying(f) | verify ok, remaining≠∅ | — | resolve(next) | none |
| Verifying(f) | verify ok, remaining=∅ | — | Finalizing | `finalize` |
| Verifying(f) | verify rejected (bad code) | — | AwaitingCode(f) | inlineError, clear otp |
| Verifying(f) | verify 401→refresh ok | — | (retried in repo) | transparent |
| Verifying(f) | verify session expired | — | FatalError | NavigateToLogin |
| Finalizing | finalize ok | — | Finalized | NavigateToHome |
| Finalizing | finalize transport err | — | Finalizing(idle) | inlineError + Retry armed |
| any | Cancel | — | — | NavigateToLogin |

## 5. API Contract

This ViewModel does not call HTTP directly; it invokes `AuthRepository` (AND-038), which owns
cookies, CSRF, refresh-retry, and finalize sequencing. Contracts consumed:

```kotlin
interface AuthRepository {
    // No begin for TOTP — only sms/email have a begin endpoint.
    suspend fun beginFactor(challengeId: String, factor: MfaFactor): ApiResult<FactorBegin>
    // CORRECTED: backend verify takes NO remember_device; it is sent only at finalize.
    suspend fun verifyFactor(
        challengeId: String, factor: MfaFactor, code: String,
    ): ApiResult<FactorVerify>
    suspend fun finalize(challengeId: String, rememberDevice: Boolean): ApiResult<SessionMe>
}
// CORRECTED: begin returns ChallengeResp{challenge_id, sent_to?}; there is no cooldown or
// masked_target field. maskedTarget below is derived from sent_to?.firstOrNull(); the cooldown
// is a client-side default (no server field exists — see §16 Open assumptions).
data class FactorBegin(val sentTo: String?)   // from ChallengeResp.sent_to
// CORRECTED: verify returns MfaVerifyResp; advancement uses remaining_factors (and the server
// may also return updated required_factors + passed map).
data class FactorVerify(
    val status: String,
    val requiredFactors: List<MfaFactor>,
    val remainingFactors: List<MfaFactor>,
    val passed: Map<MfaFactor, Boolean>,
)
data class SessionMe(/* hydrated by AND-038 from GET /ui/me -> {user_sub, session_id, ip} */)
```

Underlying endpoints (reference, owned by AND-038 — verified against OpenAPI index and
`frontend/src/api/{endpoints/auth.ts,types.ts}`):
- `POST /ui/mfa/sms/begin` and `POST /ui/mfa/email/begin` — body `{ "challenge_id": "<id>" }`
  (req schemas `SmsBeginReq`/`EmailBeginReq`, no factor in body). **CORRECTION:** there is no
  `totp/begin` endpoint. Response is `ChallengeResp { "challenge_id": "<id>", "sent_to"?:
  ["+1***1234"] }`. **CORRECTION:** the backend does NOT return `delivered`,
  `resend_cooldown_seconds`, or `masked_target`; the only deliverable hint is optional
  `sent_to[]`. (See §16 / §13-R3 — the 30s resend cooldown is a client-only assumption.)
- `POST /ui/mfa/totp/verify` — body `{ "challenge_id": "<id>", "totp_code": "123456" }`
  (`TotpVerifyReq`; note field is `totp_code`, NOT `code`, and there is NO `remember_device`).
- `POST /ui/mfa/sms/verify` / `POST /ui/mfa/email/verify` — body
  `{ "challenge_id": "<id>", "code": "123456" }` (`SmsVerifyReq`/`EmailVerifyReq`; field is
  `code`, no `remember_device`).
- `POST /ui/mfa/recovery/{factor}` — body `RecoveryReq { "challenge_id", "recovery_code",
  "factor"? }`; the web client calls it with the path param literally `recovery`.
- All verify endpoints return `MfaVerifyResp { "status", "session_id"?, "required_factors":
  [...], "passed": {factor: bool}, "remaining_factors": [...] }`. **CORRECTION:** there is no
  `verified` boolean; success is conveyed via `status`/`passed`, and advancement is driven by
  `remaining_factors` (and updated `required_factors` — see §13-R2). HTTP 200 with non-empty
  `remaining_factors` means "advance to next factor", not failure.
- `POST /ui/session/finalize` — body `UiSessionFinalizeReq { "challenge_id", "remember_device"?
  }` → `SessionFinalizeResp { "status":"ok"|"pending", "session_id"?, "required_factors": [...],
  "passed": {...} }`. **CORRECTION:** `remember_device` is sent ONLY here (at finalize), not on
  per-factor verify/begin. AND-038 follows with `GET /ui/me`.
- Headers (repo): cookies + `X-CSRF-Token: <ui_csrf>` (verified `src/api/client.ts`). FastAPI
  errors map from `detail` (`string | [{msg}] | {code,...}` — verified `normalizeErrorDetail`)
  into `ApiResult.Error` and then to `UiText`.

## 6. Data & State Management

- Single source of truth: `MutableStateFlow<MfaUiState>` exposed read-only as
  `StateFlow<MfaUiState>`; UI is a pure function of this state.
- One-shot navigation/snackbar via `Channel(BUFFERED).receiveAsFlow()` to avoid replay on
  rotation.
- `SavedStateHandle` persists `challenge_id`, `required_factors`, `remaining_factors`,
  `active_factor`, and `otpInput` across process death. The challenge is never re-requested;
  if `SavedStateHandle` lacks a `challenge_id` (cold restore with no challenge), the ViewModel
  emits `NavigateToLogin`.
- Factor selection is derived (`remainingFactors.firstOrNull()`), not stored independently,
  except when the user explicitly switches (stored as `active_factor`).
- Cooldown is a `viewModelScope` coroutine decrementing `resendCooldownSeconds` once/second;
  cancelled and restarted on each begin/resend; uses injected `TimeSource` for deterministic
  tests.
- No Room/DataStore writes here; `remember_device` is forwarded to the repository which owns
  any persistent device-trust token (AND-038).

## 7. Error Handling & Resilience

- **Recoverable (in-place):** invalid OTP format (client), `verify` rejected (wrong/expired
  code), begin/resend transport timeout. These set `inlineError`, keep the user on the active
  factor, clear `otpInput` on a rejected code, and (for transport) arm `MfaIntent.Retry`.
- **Fatal (route to login):** expired/invalid challenge, or refresh-then-retry still 401.
  Transition to `FatalError`/`NavigateToLogin`. NOTE (unverified): the OpenAPI documents only
  `200` and `422:HTTPValidationError` for the MFA/session endpoints — specific `410`/`409`
  status codes and a `detail.code == "challenge_expired"` value are NOT in the spec or web
  client and are an assumption (see §16 Open assumptions). The post-refresh-still-401 →
  session-expired path IS verified in `src/api/client.ts` (logout("session_expired")).
- **Transport policy:** the dev backend (`http://18.222.237.167:8000`) is plaintext and
  unreliable; ~20s timeouts and bounded backoff for idempotent GETs live in `core-network`.
  MFA `begin`/`verify`/`finalize` are POSTs (non-idempotent) — the ViewModel does **not**
  auto-retry them; it surfaces an error and offers explicit user-driven `Retry`.
- Concurrency guard: `isBusy`/phase gating prevents double-submit; intents arriving during
  `Verifying`/`Finalizing` are ignored (except `Cancel`).
- `code` is trimmed; only the last in-flight verify result is applied (stale results from a
  superseded factor are dropped by checking the active factor before mutating state).

## 8. Security & Privacy

- OTP codes and `challenge_id` are never logged (see Section 10); the masked deliverable
  identifier (e.g. `+1***1234`) shown to the user is derived from `ChallengeResp.sent_to`
  (CORRECTED: there is no dedicated `masked_target` field; `sent_to[]` is optional and may be
  absent).
- No credentials are held here; session/CSRF/cookie handling is entirely in `core-network`/
  AND-038. The ViewModel passes opaque `challenge_id` only.
- `remember_device` defaults to `false` and is an explicit user opt-in; its persisted token is
  managed by the repository, not this layer.
- OTP input field is backed by transient state; on `Cancel`/`Finalized` the ViewModel clears
  `otpInput`. Recommend UI use `KeyboardType.NumberPassword` and `autofill` SMS-OTP hint
  (AND-039), but no plaintext OTP is persisted to `SavedStateHandle` beyond process-death
  restore convenience — acceptable since it is single-use and short-lived.

## 9. Accessibility & i18n

- All user-facing strings (`inlineError`, factor labels, resend/cooldown text, recovery hint)
  are `UiText` resolving to `strings.xml` resources — no hardcoded English; supports RTL and
  pseudo-locale.
- Cooldown announces via the UI (AND-039) using `liveRegion`; this ViewModel exposes the raw
  `resendCooldownSeconds` and a `canResend` derivation so the UI can build localized
  countdown text and content descriptions.
- Error text is concise and actionable; busy state exposed as `isBusy` for the UI to set
  `disabled` + content description. Numeric OTP entry is locale-agnostic.

## 10. Telemetry & Logging

- Structured, PII-free events via the app's logger: `mfa_factor_started{factor}`,
  `mfa_otp_submitted{factor}`, `mfa_verify_result{factor, ok}`, `mfa_factor_advanced`,
  `mfa_finalize_result{ok}`, `mfa_error{factor, kind=invalid|rejected|transport|fatal}`,
  `mfa_resend{factor}`, `mfa_cancel`.
- **Never** log `code`, full `challenge_id` (log a truncated hash if correlation is needed),
  phone/email targets, or cookie/CSRF values.
- Log level: INFO for transitions, WARN for recoverable errors, ERROR for fatal. Debug builds
  may add a transition trace gated behind `BuildConfig.DEBUG`.

## 11. Testing Strategy

Primary deliverable per Acceptance Criteria — exhaustive unit coverage of the state machine
with a fake `AuthRepository` and injected `TimeSource`/`StandardTestDispatcher`.

- **Transition coverage (every row in Section 4):** single-factor TOTP happy path
  (Idle→AwaitingCode→Verifying→Finalizing→Finalized + `NavigateToHome`); single-factor SMS/
  email with `begin` (Delivering→AwaitingCode); multi-factor sequence (e.g.
  `["totp","email"]`) verifying that `remaining_factors` drives advancement and finalize fires
  only when empty.
- **Error recovery:** invalid OTP rejected without repo call; wrong-code `verify` returns to
  `AwaitingCode` with `inlineError` and cleared input; transport error arms `Retry` and a
  subsequent `Retry` re-invokes the correct repository method; expired challenge →
  `FatalError`/`NavigateToLogin`.
- **Resend/cooldown:** `Resend` blocked while `resendCooldownSeconds > 0`; timer ticks to 0
  with virtual time; cooldown restarts on each begin.
- **Switch/recovery:** `SelectFactor` allowed only when `>1` remaining; `UseRecovery` routes
  to recovery factor or surfaces info when none.
- **Concurrency:** double `SubmitOtp` produces one `verifyFactor` call; stale verify result
  for a superseded factor is dropped.
- **Process death:** `SavedStateHandle` round-trip restores challenge and active factor;
  missing challenge emits `NavigateToLogin`.
- Tools: JUnit, Turbine (StateFlow/event assertions), `kotlinx-coroutines-test`, MockK fakes
  from `core-testing`. Target ≥90% line + 100% transition-row coverage for this class.

## 12. Dependencies & Sequencing

- **Depends on AND-038** — `AuthRepository.beginFactor/verifyFactor/finalize`, multi-factor
  sequencing semantics (`remaining_factors`), and `remember_device`. Required before this can
  compile/test against real signatures; until then, code against the interface in Section 4/5.
- **Depends on AND-039** — supplies the screen that hosts this ViewModel; AND-039's UI tests
  for TOTP + SMS exercise this ViewModel end-to-end. AND-040 must land its `StateFlow`/`Intent`
  contract first so AND-039 can bind to it (coordinate the contract early).
- Consumes shared types from `core-model` (factor enum mirroring `frontend/src/api/types.ts`)
  and `ApiResult<T>` / `UiText` from `core-network`/`core-ui`.
- No downstream ticket in this set is blocked by AND-040 (`blocks: []`).

## 13. Risks & Open Questions

- R1. RESOLVED (corrected): recovery is its own endpoint `POST /ui/mfa/recovery/{factor}`
  (`RecoveryReq{challenge_id, recovery_code, factor?}`), NOT the `email` factor path; the web
  client uses the literal path param `recovery` and always offers recovery as a fallback.
- R2. RESOLVED (verified): `MfaVerifyResp` returns BOTH `required_factors` and
  `remaining_factors` (plus `passed{}` and `status`). The ViewModel should treat
  `remaining_factors` as the advancement driver but also refresh `required_factors` from the
  response (the server may update it), matching `Login.tsx`.
- R3. RESOLVED (corrected): there is no server `resend_cooldown_seconds` field; `ChallengeResp`
  is `{challenge_id, sent_to?}`. The 30s cooldown is a client-only Android UX choice. The web
  reference has no cooldown at all (see §16).
- R4. RESOLVED (verified): `totp` has no `begin` endpoint at all — only `sms/begin` and
  `email/begin` exist; TOTP is verify-only (`POST /ui/mfa/totp/verify`).
- R5. Unreliable dev host may cause spurious transport errors; ensure tests use fakes and the
  UI clearly distinguishes "network problem, retry" from "wrong code".

## 14. Acceptance Criteria

- AC-1. Every transition row in Section 4 is exercised by a passing unit test (transition-row
  coverage = 100%).
- AC-2. Single-factor (TOTP) and multi-factor (e.g. TOTP→email) sequences reach `Finalized`
  and emit exactly one `MfaEvent.NavigateToHome`.
- AC-3. A wrong/expired OTP returns to `AwaitingCode` with a localized `inlineError`, cleared
  input, and no navigation; the user can retry without losing the challenge.
- AC-4. Client-side invalid OTP is rejected with no `verifyFactor` call.
- AC-5. Transport failure on a POST does not auto-retry; it arms `Retry`, and `Retry`
  re-invokes the correct repository method.
- AC-6. Expired/invalid challenge or post-refresh 401 emits `NavigateToLogin` and clears state.
- AC-7. Resend is disabled during cooldown; cooldown counts down deterministically (virtual
  time test).
- AC-8. Switch-factor is permitted only with `>1` remaining factor and clears OTP/error.
- AC-9. State and active factor survive a `SavedStateHandle` round-trip; absent challenge →
  `NavigateToLogin`.
- AC-10. No OTP code, CSRF, cookie, or full `challenge_id` appears in any log assertion.

## 15. Definition of Done

- `MfaViewModel`, `MfaUiState`, `MfaIntent`, `MfaEvent`, `MfaPhase`, and `MfaFactor` implemented
  in `com.testlogon.android.feature.auth.mfa`, Hilt-injectable via `@HiltViewModel`.
- Compiles against AND-038's `AuthRepository`; no direct Retrofit/OkHttp usage in this class.
- Unit test suite meets AC-1…AC-10 with ≥90% line coverage for the class; CI green.
- All strings are `UiText`/resource-backed; no hardcoded user-facing text; no PII in logs
  (lint/log-policy check passes).
- `ktlint`/`detekt` clean; public API documented with KDoc; merged to `android-port`.
- Contract (`StateFlow`/`MfaIntent`/`MfaEvent`) reviewed and accepted by AND-039 owner.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources: OpenAPI index
(`reference/openapi.index.txt`), OpenAPI schemas (`reference/openapi.pretty.json
components.schemas.*`), and frontend (`reference/src/...`).

1. **`POST /ui/session/start` returns `{auth_required, challenge_id?, required_factors[],
   session_id?}`.** VERIFIED. `POST /ui/session/start | req=UiSessionStartReq |
   resp=200:UiSessionStartResp`; `src/api/types.ts: SessionStartResp`.
2. **MFA verify is per-factor: `POST /ui/mfa/totp/verify`, `/ui/mfa/sms/verify`,
   `/ui/mfa/email/verify`.** VERIFIED. OpenAPI `POST /ui/mfa/{totp,sms,email}/verify`;
   `src/api/endpoints/auth.ts: verifyTotp/verifySms/verifyEmail`.
3. **TOTP has NO `begin` endpoint; only `sms/begin` and `email/begin` exist.** VERIFIED
   (Corrected the spec's `/ui/mfa/{totp|sms|email}/begin`). OpenAPI lists only `POST
   /ui/mfa/sms/begin` (`SmsBeginReq`) and `POST /ui/mfa/email/begin` (`EmailBeginReq`); no
   `totp/begin`. Confirms FR-3/R4. Source: `reference/openapi.index.txt` lines 1641/1649.
4. **TOTP verify request field is `totp_code` (not `code`) and has no `remember_device`.**
   VERIFIED (Corrected). `src/api/types.ts: TotpVerifyReq {challenge_id, totp_code}`.
5. **SMS/email verify request is `{challenge_id, code}` with no `remember_device`.** VERIFIED
   (Corrected). `src/api/types.ts: SmsVerifyReq`, `EmailVerifyReq`.
6. **begin request body is just `{challenge_id}` (no factor field, no remember_device).**
   VERIFIED. `src/api/types.ts: SmsBeginReq`, `EmailBeginReq`.
7. **begin response is `ChallengeResp {challenge_id, sent_to?}` — NO `delivered`,
   `resend_cooldown_seconds`, or `masked_target`.** VERIFIED (Corrected the fabricated
   begin-response shape). `src/api/types.ts: ChallengeResp`; `src/api/endpoints/auth.ts:
   beginSms/beginEmail` typed `ChallengeResp`.
8. **verify response is `MfaVerifyResp {status, session_id?, required_factors[], passed{},
   remaining_factors[]}`; there is no `verified` boolean.** VERIFIED (Corrected). `src/api/
   types.ts: MfaVerifyResp`; used in `src/pages/Login.tsx` (`resp.remaining_factors`,
   `resp.passed`, `resp.required_factors`).
9. **Advancement is driven by `remaining_factors`; finalize fires only when it is empty.**
   VERIFIED. `src/pages/Login.tsx:222` (`if (resp.remaining_factors.length === 0)` →
   `sessionFinalize`).
10. **verify also returns updated `required_factors` (R2).** VERIFIED. `MfaVerifyResp.
    required_factors`; `Login.tsx:242` sets `requiredFactors(resp.required_factors)`.
11. **`remember_device` is sent ONLY at finalize, not on verify/begin.** VERIFIED (Corrected
    FR-4 and the repo `verifyFactor` signature). `src/api/types.ts: SessionFinalizeReq
    {challenge_id, remember_device?}`; `Login.tsx:224-227` passes `remember_device` only to
    `sessionFinalize`.
12. **`POST /ui/session/finalize` returns `{status:"ok"|"pending", session_id?,
    required_factors[], passed{}}`.** VERIFIED. OpenAPI `POST /ui/session/finalize |
    req=UiSessionFinalizeReq`; `src/api/types.ts: SessionFinalizeResp`.
13. **After finalize success AND-038 calls `GET /ui/me` returning `{user_sub, session_id,
    ip}`.** VERIFIED. OpenAPI `GET /ui/me`; `src/api/types.ts: MeResp`; `Login.tsx:230`
    (`const me = await getMe()`).
14. **Recovery is `POST /ui/mfa/recovery/{factor}` with `RecoveryReq{challenge_id,
    recovery_code, factor?}`; web calls it with path param literally `recovery`; recovery is
    always offered as a fallback.** VERIFIED (Corrected FR-8/R1's "map to email" claim).
    OpenAPI `POST /ui/mfa/recovery/{factor} | req=RecoveryReq`; `src/api/endpoints/auth.ts:
    useRecoveryCode`; `src/pages/Login.tsx:160,209-214,405-406`.
15. **Session uses cookies + `ui_csrf` cookie echoed as `X-CSRF-Token`.** VERIFIED. `src/api/
    client.ts:168-170` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`) and
    `credentials:"include"` (line 183).
16. **A 401 on an already-authenticated request triggers a single `POST /ui/session/refresh`
    then one retry; still-401 → session-expired logout.** VERIFIED. `src/api/client.ts:
    194-236`; OpenAPI `POST /ui/session/refresh`.
17. **FastAPI error `detail` maps as `string | [{msg}] | {code,...}`.** VERIFIED. `src/api/
    client.ts: normalizeErrorDetail` (lines 35-83); endpoint error responses are
    `422:HTTPValidationError` in OpenAPI.
18. **MFA/session endpoints document only `200` and `422:HTTPValidationError` (no `409`/`410`
    /`challenge_expired`).** VERIFIED via OpenAPI index (all MFA/session rows show
    `resp=200:...;422:HTTPValidationError`). The spec's specific fatal status codes are an
    UNVERIFIED-ASSUMPTION (see below).
19. **ViewModel framework: `StateFlow` for UI state, `Channel.receiveAsFlow()` one-shot events,
    `SavedStateHandle` for process-death, `@HiltViewModel`, `kotlinx-coroutines-test` virtual
    time.** UNVERIFIED-ASSUMPTION (framework ref, standard Android guidance): StateFlow/
    SavedStateHandle — https://developer.android.com/topic/libraries/architecture/viewmodel ;
    one-shot events via Channel —
    https://developer.android.com/topic/architecture/ui-layer/events ; Hilt VM —
    https://developer.android.com/training/dependency-injection/hilt-jetpack . Not derivable
    from backend/frontend sources; these are Android-side design choices.

### Corrections made

- §2 / §5: replaced the non-existent `POST /ui/mfa/totp/begin` — TOTP is verify-only; begin
  exists only for sms/email.
- §5 / §5-interface / §4 FR-4: removed `remember_device` from per-factor verify — it is a
  finalize-only field.
- §5: replaced the fabricated begin response (`delivered`/`resend_cooldown_seconds`/
  `masked_target`) with the real `ChallengeResp {challenge_id, sent_to?}`.
- §5: corrected TOTP verify field name to `totp_code` (sms/email use `code`).
- §5: replaced the `{verified, remaining_factors}` verify response with the real `MfaVerifyResp
  {status, session_id?, required_factors[], passed{}, remaining_factors[]}`; removed the
  non-existent `verified` boolean.
- §4 FR-8 / §13-R1: corrected recovery to its own `POST /ui/mfa/recovery/{factor}` endpoint
  (was "map to email factor").
- §4 FR-6 / §13-R3: corrected the resend cooldown — no server field exists; 30s is client-only;
  web has no cooldown.
- §7 / §13-R2: noted verify returns updated `required_factors` (server may update); resolved R2.
- §7: marked the `409/410/challenge_expired` fatal codes as unverified (not in OpenAPI).
- §8: corrected masked-target source to `ChallengeResp.sent_to` (no `masked_target` field).
- §13-R4: resolved — confirmed no `totp/begin` endpoint.

### Open assumptions (unverifiable from sources)

- **Resend cooldown (30s) and its UI gating** — no server field (`ChallengeResp` lacks any
  cooldown); the web client implements no cooldown. This is an Android-only UX decision; pick a
  value with the AND-039 owner. (Why unverifiable: not present in OpenAPI or frontend.)
- **Specific fatal HTTP codes / `detail.code == "challenge_expired"`** — OpenAPI documents only
  `200`/`422` for these endpoints, so exact expiry status/code is unknown; the ViewModel should
  treat any non-2xx non-validation error on verify/finalize, or a post-refresh 401, as fatal
  and route to login. Confirm concrete codes with AND-038/backend before asserting them in
  tests. (Why unverifiable: error taxonomy beyond 422 is undocumented.)
- **`remaining_factors`/`required_factors` element ordering and active-factor selection** — the
  spec selects the first remaining factor in `required_factors` order; the backend's ordering
  guarantees are not documented. `Login.tsx` picks a default via `includes` priority
  (totp>sms>email>recovery), not strictly first-element. Treat ordering as best-effort. (Why
  unverifiable: ordering semantics not in OpenAPI.)
- **Android architecture choices** (StateFlow/Channel/SavedStateHandle/Hilt/virtual-time
  tests) — framework refs only; not contract-derived (see citation 19).

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (no device); **emu35** = headless emulator AVD
`test35` (x86_64, API 35); **deviceA15** = physical Samsung Galaxy A15 5G (SM-A156U, API 34,
arm64-v8a, serial R5CX821TA9R). This ViewModel is pure orchestration with no hardware
dependency, so the bulk runs on JVM with a fake `AuthRepository`, injected `TimeSource`, and
`StandardTestDispatcher`; a few instrumented/Compose cases run on emu35, and the
autofill/SMS-OTP + process-death-on-real-hardware cases run on deviceA15.

- **TC-AND-040-01** — Type: unit (JVM). Target: `MfaViewModel` + fake `AuthRepository`.
  Preconditions: seed `required_factors=["totp"]`, `remaining_factors=["totp"]`. Steps: observe
  state via Turbine; `OtpChanged("123456")`; `SubmitOtp`; fake verify returns `MfaVerifyResp
  status="ok", remaining_factors=[]`; fake `finalize` returns `status="ok"` + `SessionMe`.
  Expected: phases `Idle→AwaitingCode(TOTP)→Verifying(TOTP)→Finalizing→Finalized`; exactly one
  `MfaEvent.NavigateToHome`; `verifyFactor` called with `(challengeId, TOTP, "123456")` and NO
  remember_device; `finalize` called once with the user's `rememberDevice`. Traces: AC-1, AC-2.
- **TC-AND-040-02** — Type: unit (JVM). Target: ViewModel + fake repo. Preconditions: seed
  `required=["totp","email"]`, `remaining=["totp","email"]`. Steps: submit valid TOTP; fake
  verify returns `remaining_factors=["email"]`; ViewModel advances to email and calls
  `beginFactor(EMAIL)` (fake returns `ChallengeResp(sent_to=["a***@x.com"])`); submit valid
  email code; fake verify returns `remaining_factors=[]`; finalize ok. Expected: advances to
  `AwaitingCode(EMAIL)` after begin, reaches `Finalized`, exactly one `NavigateToHome`;
  `finalize` called once (not after the first factor). Traces: AC-1, AC-2.
- **TC-AND-040-03** — Type: unit (JVM). Target: ViewModel + fake repo. Preconditions: seed
  `["email"]`. Steps: ViewModel auto-`beginFactor(EMAIL)` on resolve; assert no begin for a TOTP
  seed in a sibling run. Expected: SMS/email path issues a `begin` before `AwaitingCode`; a TOTP
  seed issues NO begin call (verify-only). Traces: AC-1.
- **TC-AND-040-04** — Type: unit (JVM). Target: ViewModel client validation. Preconditions:
  seed `["totp"]`, `otpLength=6`. Steps: `OtpChanged("12a4")` then `SubmitOtp`; also try `"123"`
  (too short). Expected: `inlineError` set (localized `UiText`), phase stays
  `AwaitingCode(TOTP)`, and `verifyFactor` is NEVER called. Traces: AC-4.
- **TC-AND-040-05** — Type: contract/MockWebServer (JVM/Robolectric). Target: AND-038
  `AuthRepository` ↔ `MfaViewModel` against a MockWebServer serving the REAL response shapes.
  Preconditions: enqueue `POST /ui/mfa/totp/verify` → 200 `{"status":"ok","required_factors":
  [],"passed":{"totp":true},"remaining_factors":[]}`, then `POST /ui/session/finalize` → 200
  `{"status":"ok","session_id":"s1","required_factors":[],"passed":{"totp":true}}`, then
  `GET /ui/me` → 200 `{"user_sub":"u1","session_id":"s1","ip":"1.2.3.4"}`. Steps: drive happy
  path; inspect recorded requests. Expected: verify body is `{"challenge_id":...,"totp_code":
  ...}` (field `totp_code`, no `remember_device`); finalize body carries `remember_device`;
  `X-CSRF-Token` header present from `ui_csrf` cookie; reaches `Finalized`. Traces: AC-2.
- **TC-AND-040-06** — Type: contract/MockWebServer (JVM/Robolectric). Target: repo error
  mapping. Preconditions: enqueue verify → 422 `{"detail":[{"msg":"Invalid code"}]}`. Steps:
  submit code; observe state. Expected: error mapped via `detail [{msg}]` to a localized
  `inlineError`; phase returns to `AwaitingCode(f)`; `otpInput` cleared; no navigation. Traces:
  AC-3.
- **TC-AND-040-07** — Type: unit (JVM). Target: ViewModel retry arming. Preconditions: seed
  `["sms"]`; fake `beginFactor` throws transport error (`ApiResult.Error` network). Steps:
  resolve triggers begin → fails. Then dispatch `MfaIntent.Retry`; fake begin now succeeds.
  Expected: first failure sets `inlineError` + arms Retry, NO auto-retry of the POST; `Retry`
  re-invokes `beginFactor` (the correct last step). Repeat for a failed `verify`'s Retry calling
  `verifyFactor`. Traces: AC-5.
- **TC-AND-040-08** — Type: unit (JVM). Target: fatal/session-expired path. Preconditions: seed
  `["totp"]`; fake `verifyFactor` returns a fatal error (simulating post-refresh-still-401 /
  expired challenge). Steps: submit valid-format code. Expected: phase → `FatalError`, exactly
  one `MfaEvent.NavigateToLogin`, challenge state cleared. (Concrete HTTP code unverified — see
  §16; test asserts on the repo's fatal `ApiResult.Error`, not a hardcoded 410.) Traces: AC-6.
- **TC-AND-040-09** — Type: unit (JVM, virtual time). Target: resend cooldown. Preconditions:
  seed `["sms"]`; injected `TimeSource`/`StandardTestDispatcher`; cooldown=30s. Steps: begin
  succeeds → cooldown starts; dispatch `Resend` while `resendCooldownSeconds>0`; advance virtual
  time to 0; dispatch `Resend` again. Expected: first `Resend` is ignored (no extra
  `beginFactor`) and `resendCooldownSeconds` ticks 30→0 deterministically; after 0, `Resend`
  re-invokes `beginFactor` and restarts cooldown. (Cooldown is client-only — §16.) Traces: AC-7.
- **TC-AND-040-10** — Type: unit (JVM). Target: switch-factor + recovery routing.
  Preconditions: seed `required=["totp","email"]`, `remaining=["totp","email"]`. Steps: (a)
  `SelectFactor(EMAIL)` with size>1 → active=EMAIL, otp/error cleared; (b) reduce remaining to
  one and assert `SelectFactor` to a non-remaining factor is rejected (canSwitchFactor=false);
  (c) `UseRecovery` with a recovery code → ViewModel calls the recovery repo path (mapping to
  `POST /ui/mfa/recovery/{factor}`), not the email verify. Expected: switch gated on size>1;
  recovery routes to the recovery endpoint. Traces: AC-8.
- **TC-AND-040-11** — Type: unit (JVM). Target: concurrency + stale-result guard.
  Preconditions: seed `["totp"]`; fake verify suspends. Steps: dispatch `SubmitOtp` twice
  rapidly; also simulate a verify result arriving after the user switched factors. Expected:
  only ONE `verifyFactor` call (busy/phase gating); a stale verify result for a superseded
  factor is dropped (active-factor check before state mutation). Traces: AC-5 (no double-submit),
  AC-3.
- **TC-AND-040-12** — Type: unit (JVM). Target: `SavedStateHandle` round-trip. Preconditions:
  build VM with populated `SavedStateHandle` (challenge_id, required/remaining, active_factor,
  otpInput). Steps: simulate process death by reconstructing the VM from the same handle; also
  build a VM from an empty handle. Expected: restored VM resumes the correct active factor and
  state; empty/missing challenge emits `MfaEvent.NavigateToLogin`. Traces: AC-9.
- **TC-AND-040-13** — Type: unit (JVM) — logging/PII. Target: telemetry assertions with a fake
  logger. Preconditions: seed `["sms"]`, run a full submit+resend+finalize. Steps: capture all
  emitted log records. Expected: NO record contains the OTP `code`, the full `challenge_id`,
  `recovery_code`, `sent_to`/phone/email target, cookie, or CSRF value (only truncated-hash
  correlation, factor name, and ok/kind flags). Traces: AC-10.
- **TC-AND-040-14** — Type: Compose-UI + instrumented (emu35; SMS-autofill subset on deviceA15).
  Target: AND-039 MFA screen bound to a real `MfaViewModel` (fake repo) — accessibility +
  autofill. Preconditions: app installed; TalkBack assertions via Espresso/Compose semantics.
  Steps: render `AwaitingCode(SMS)`; verify OTP field exposes a content description and
  `KeyboardType.NumberPassword`, busy state disables submit with an announced state, resend
  countdown is in a `liveRegion`; on deviceA15, trigger a real SMS-OTP autofill hint to confirm
  the field accepts the platform OTP suggestion. Expected: semantics/contentDescription present,
  no hardcoded strings (resource-backed), RTL/pseudo-locale render OK; autofill populates the
  field on the physical device. MUST run the SMS-OTP autofill portion on deviceA15 (real SMS/
  autofill is not reliably exercised on the emulator); semantics checks may run on emu35.
  Traces: AC-3, AC-7 (cooldown announcement), AC-10 (no PII in UI).

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 (100% transition rows) | TC-01, TC-02, TC-03, plus error rows in TC-06, TC-07, TC-08, TC-09 |
| AC-2 (single + multi reach Finalized, one NavigateToHome) | TC-01, TC-02, TC-05 |
| AC-3 (wrong/expired OTP → AwaitingCode, cleared, no nav) | TC-06, TC-11, TC-14 |
| AC-4 (client-invalid OTP, no verify call) | TC-04 |
| AC-5 (POST no auto-retry; Retry re-invokes) | TC-07, TC-11 |
| AC-6 (expired challenge / post-refresh 401 → NavigateToLogin) | TC-08 |
| AC-7 (resend disabled during cooldown; deterministic countdown) | TC-09, TC-14 |
| AC-8 (switch only when >1 remaining; clears OTP/error) | TC-10 |
| AC-9 (SavedStateHandle round-trip; absent challenge → login) | TC-12 |
| AC-10 (no OTP/CSRF/cookie/full challenge_id in logs) | TC-13, TC-14 |
