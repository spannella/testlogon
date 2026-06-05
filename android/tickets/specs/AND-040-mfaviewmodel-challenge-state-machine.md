---
id: AND-040
title: MfaViewModel (challenge state machine)
milestone: M1
epic: E05
priority: P0
size: M
status: draft
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
- Auth flow (authoritative): `POST /ui/session/start` → `{auth_required, challenge_id,
  required_factors[]}` → per-factor `POST /ui/mfa/{totp|sms|email}/begin|verify` (carrying
  `challenge_id`) → when `remaining_factors` empties, `POST /ui/session/finalize` →
  `GET /ui/me`. Session rides cookies + `ui_csrf` cookie echoed as `X-CSRF-Token`; a 401
  triggers a single `POST /ui/session/refresh` then one retry. All of this is implemented in
  `AuthRepository` (AND-034/035/036/038); AND-040 consumes it.
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

FR-4. On OTP submit the ViewModel calls `verifyFactor(challengeId, factor, code,
rememberDevice)`. On success it updates `remaining_factors` from the response; if non-empty it
advances to the next factor (re-running FR-3 for that factor); if empty it calls `finalize`.

FR-5. On `finalize` success the ViewModel emits a one-shot `MfaEvent.NavigateToHome` and
transitions to `Finalized`. Finalize and `/ui/me` hydration sequencing belong to AND-038; this
ViewModel awaits the repository's authenticated-session result.

FR-6. Resend (`sms`/`email`) re-invokes `beginFactor`, restarts the cooldown timer, and is
disabled while the cooldown is active (default 30s, server-overridable via begin response).

FR-7. Switch-factor selects another member of `remaining_factors` as active; allowed only when
`remaining_factors.size > 1`. Switching clears the current OTP input and error.

FR-8. Recovery option: when offered, dispatches `MfaIntent.UseRecovery` which the ViewModel
maps to the `email` (or backend-designated recovery) factor path; if no recovery factor is
available it surfaces a non-fatal info message.

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
    suspend fun beginFactor(challengeId: String, factor: MfaFactor): ApiResult<FactorBegin>
    suspend fun verifyFactor(
        challengeId: String, factor: MfaFactor, code: String, rememberDevice: Boolean,
    ): ApiResult<FactorVerify>
    suspend fun finalize(challengeId: String, rememberDevice: Boolean): ApiResult<SessionMe>
}
data class FactorBegin(val resendCooldownSeconds: Int?, val maskedTarget: String?)
data class FactorVerify(val remainingFactors: List<MfaFactor>)
data class SessionMe(/* hydrated by AND-038 */)
```

Underlying endpoints (reference, owned by AND-038):
- `POST /ui/mfa/{totp|sms|email}/begin` — body `{ "challenge_id": "<id>" }` →
  `{ "delivered": true, "resend_cooldown_seconds": 30, "masked_target": "+1***1234" }`.
- `POST /ui/mfa/{totp|sms|email}/verify` — body
  `{ "challenge_id": "<id>", "code": "123456", "remember_device": false }` →
  `{ "verified": true, "remaining_factors": ["email"] }`.
- `POST /ui/session/finalize` — body `{ "challenge_id": "<id>", "remember_device": false }`
  → 200 sets session cookies; AND-038 follows with `GET /ui/me`.
- Headers (repo): cookies + `X-CSRF-Token: <ui_csrf>`. FastAPI errors map from `detail`
  (`string | [{msg}] | {code,...}`) into `ApiResult.Error` and then to `UiText`.

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
- **Fatal (route to login):** expired/invalid challenge (`410`/`409`/`detail.code ==
  "challenge_expired"`), or refresh-then-retry still 401. Transition to
  `FatalError`/`NavigateToLogin`.
- **Transport policy:** the dev backend (`http://18.222.237.167:8000`) is plaintext and
  unreliable; ~20s timeouts and bounded backoff for idempotent GETs live in `core-network`.
  MFA `begin`/`verify`/`finalize` are POSTs (non-idempotent) — the ViewModel does **not**
  auto-retry them; it surfaces an error and offers explicit user-driven `Retry`.
- Concurrency guard: `isBusy`/phase gating prevents double-submit; intents arriving during
  `Verifying`/`Finalizing` are ignored (except `Cancel`).
- `code` is trimmed; only the last in-flight verify result is applied (stale results from a
  superseded factor are dropped by checking the active factor before mutating state).

## 8. Security & Privacy

- OTP codes and `challenge_id` are never logged (see Section 10); `maskedTarget` (e.g.
  `+1***1234`) is the only deliverable identifier shown.
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

- R1. Recovery-option mapping: which concrete factor backs "recovery" (always `email`, or a
  distinct backend flag)? Confirm against `/openapi.json` and `frontend` MFA endpoints; assume
  `email` until confirmed.
- R2. Does `verify` ever return an updated ordered `required_factors` (server reordering) or
  only `remaining_factors`? Spec assumes only `remaining_factors`; reconcile with AND-038.
- R3. Resend cooldown source of truth — server `resend_cooldown_seconds` vs client default
  (30s). Spec uses server value when present, else default.
- R4. `totp` begin: confirmed no `begin` call needed; verify backend tolerates verify-without-
  begin for TOTP.
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
