---
id: AND-031
title: LoginViewModel
milestone: M1
epic: E04
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-028, AND-030]
blocks: [AND-034, AND-035, AND-036]
---

# AND-031 — LoginViewModel

## 1. Overview & Goal

`LoginViewModel` is the presentation-layer orchestrator for the email/password login
screen. It owns a single `StateFlow<LoginUiState>`, exposes intent-style entry points
for the Compose screen (AND-030), drives the credential submission through
`AuthRepository.login(...)` (AND-028), and maps the typed repository result into a
one-shot navigation effect: either *MFA required* (continue the challenge in the MFA
feature, E05) or *authenticated* (route to home). It is also responsible for the
loading/disabled lifecycle of the submit control and for surfacing typed,
human-readable errors without leaking transport details.

The goal of this ticket is the ViewModel only: state shape, intent handlers, the
result→navigation/error mapping, and exhaustive unit-test coverage of the state
machine. The screen composable, the repository, the API DTOs, and the MFA verify
flows are owned by adjacent tickets and are consumed — not implemented — here.

Module: `feature-auth` (depends on `core-data` for `AuthRepository`, `core-model`
for typed results, `core-ui` for `UiText`). Package:
`com.testlogon.android.feature.auth.login`.

## 2. Context & References

- **AND-028** `AuthRepository: session start + branching` — provides
  `suspend fun login(username, password): ApiResult<LoginResult>` where
  `LoginResult` is `Authenticated` or `MfaRequired(challengeId, factors)`. This is
  the sole collaborator the ViewModel calls.
- **AND-030** `Login screen UI` — the Compose screen that renders `LoginUiState`,
  forwards text edits and the submit click as intents, and consumes the navigation
  effect. Field-level validation (non-empty, email shape) lives partly in the UI;
  the ViewModel enforces the canonical gate for `submitEnabled`.
- **AND-029** `getMe + auth state store` — after `Authenticated`, the auth-state
  store is hydrated. The ViewModel does *not* call `getMe()` itself; it emits the
  `NavigateHome` effect and lets the post-login coordinator / `RootViewModel`
  refresh `me`. (If sequencing changes, see Open Questions §13.)
  > **Web divergence (verified):** the web client at `src/pages/Login.tsx:147-149`
  > awaits `getMe()` *before* navigating to `/` on a no-MFA login. This ticket
  > deliberately defers `getMe` to the post-login coordinator instead of mirroring
  > the web ordering; R1 (§13) tracks that decision.
- **AND-033..036** MFA flows — downstream consumers of the `NavigateToMfa`
  effect; this ticket only hands them `challengeId` + `factors`.
- Backend session start: `POST /ui/session/start` with
  `{challenge_context:{username,password}}` → `{auth_required, challenge_id,
  required_factors[]}`. Cookie + `ui_csrf`/`X-CSRF-Token` handling is internal to
  `core-network` and `AuthRepository`; the ViewModel is transport-agnostic.
- Web reference (corrected): `src/api/endpoints/auth.ts` (`sessionStart`),
  `src/api/types.ts` (`SessionStartReq` / `SessionStartResp`), and the credentials
  submit + branch logic in `src/pages/Login.tsx`. (There is no `session.ts`; the
  login submit lives in `auth.ts`, and the response DTO is `SessionStartResp`, not
  `SessionStartResponse`.) Backend schema names are `UiSessionStartReq` /
  `UiSessionStartResp`.

## 3. Functional Requirements

FR-1. Expose immutable UI state as `val uiState: StateFlow<LoginUiState>` seeded
with `LoginUiState()` (empty, idle, submit disabled).

FR-2. Accept user input intents that update field values and clear any transient
error: `onUsernameChange(String)`, `onPasswordChange(String)`,
`onTogglePasswordVisibility()`.

FR-3. Compute `submitEnabled` reactively: true iff `username` is non-blank, a
syntactically plausible email, `password` is non-blank, and `status != Submitting`.

FR-4. `onSubmit()` is idempotent while a request is in flight — a second call while
`status == Submitting` is a no-op (debounce double-tap).

FR-5. On submit: set `status = Submitting` (disables submit, shows progress), clear
prior `error`, then call `AuthRepository.login(username.trim(), password)`.

FR-6. Map `ApiResult.Success(LoginResult.MfaRequired)` → emit a one-shot
`LoginEffect.NavigateToMfa(challengeId, factors)` and return `status` to `Idle`.

FR-7. Map `ApiResult.Success(LoginResult.Authenticated)` → emit one-shot
`LoginEffect.NavigateHome`; keep `status = Submitting` until the screen is torn down
(prevents a re-enabled button flashing during navigation), or reset to `Idle` if the
effect is buffered — see §6.

FR-8. Map `ApiResult.Failure` → set `status = Idle` and `error = UiText` derived from
the typed error (invalid credentials, network/timeout, server). Submit re-enables so
the user can retry.

FR-9. `onErrorShown()` clears `error` after the screen consumes it (e.g. snackbar).

FR-10. Navigation is delivered as effects, never as state, so config changes /
recomposition cannot replay a navigation.

## 4. Technical Design

```kotlin
package com.testlogon.android.feature.auth.login

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.auth.LoginResult
import com.testlogon.android.core.model.auth.MfaFactor
import com.testlogon.android.core.data.auth.AuthRepository
import com.testlogon.android.core.ui.text.UiText
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class LoginViewModel @Inject constructor(
    private val authRepository: AuthRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(LoginUiState())
    val uiState: StateFlow<LoginUiState> = _uiState.asStateFlow()

    // One-shot navigation/effects. extraBufferCapacity guarantees non-suspending tryEmit.
    private val _effects = MutableSharedFlow<LoginEffect>(
        replay = 0,
        extraBufferCapacity = 1,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    val effects: SharedFlow<LoginEffect> = _effects.asSharedFlow()

    fun onUsernameChange(value: String) = _uiState.update {
        it.copy(username = value, error = null)
    }

    fun onPasswordChange(value: String) = _uiState.update {
        it.copy(password = value, error = null)
    }

    fun onTogglePasswordVisibility() = _uiState.update {
        it.copy(passwordVisible = !it.passwordVisible)
    }

    fun onErrorShown() = _uiState.update { it.copy(error = null) }

    fun onSubmit() {
        val snapshot = _uiState.value
        if (snapshot.status == LoginStatus.Submitting || !snapshot.submitEnabled) return
        _uiState.update { it.copy(status = LoginStatus.Submitting, error = null) }
        viewModelScope.launch {
            when (val result = authRepository.login(snapshot.username.trim(), snapshot.password)) {
                is ApiResult.Success -> handleSuccess(result.data)
                is ApiResult.Failure -> _uiState.update {
                    it.copy(status = LoginStatus.Idle, error = result.error.toLoginUiText())
                }
            }
        }
    }

    private fun handleSuccess(result: LoginResult) = when (result) {
        is LoginResult.MfaRequired -> {
            _uiState.update { it.copy(status = LoginStatus.Idle) }
            _effects.tryEmit(LoginEffect.NavigateToMfa(result.challengeId, result.factors))
        }
        LoginResult.Authenticated -> {
            // Keep Submitting so the button stays disabled through the nav transition.
            _effects.tryEmit(LoginEffect.NavigateHome)
        }
    }
}
```

Design notes:

- **Single source of truth.** All visible state is `LoginUiState`; `submitEnabled` is
  a *derived* property computed inside the data class so the ViewModel never stores a
  stale flag.
- **Effects over state for navigation.** `MutableSharedFlow(replay=0)` with a 1-slot
  buffer lets the screen collect effects in a lifecycle-aware `repeatOnLifecycle`
  block without replaying on rotation. `tryEmit` is non-suspending and safe because
  buffer + `DROP_OLDEST` guarantee it never returns false for our single-effect
  cadence.
- **No threading concerns in the ViewModel.** `AuthRepository.login` is `suspend`
  and switches to `Dispatchers.IO` internally (core-data convention); the ViewModel
  stays on the main dispatcher via `viewModelScope`.
- **Validation source of truth.** Email-shape validation uses
  `android.util.Patterns.EMAIL_ADDRESS` wrapped behind a `pure` Kotlin predicate in
  `core-ui` (`EmailValidator.isPlausible(String): Boolean`) so it is unit-testable on
  the JVM without Robolectric. The data class calls that predicate.

## 5. API Contract

No new endpoint is defined or called directly by this ticket. The ViewModel invokes
`AuthRepository.login(...)` (AND-028), which owns the
`POST /ui/session/start` call. For reference, the repository consumes:

Request body (schema `UiSessionStartReq`): a single free-form `challenge_context`
object (the backend schema declares it `additionalProperties: true`). The web client
populates it with `username`/`password` (verified at `src/pages/Login.tsx:138-143`):
```json
{ "challenge_context": { "username": "user@example.com", "password": "•••••" } }
```

Response (200, schema `UiSessionStartResp`) mapped by AND-028 into `LoginResult`:
```json
{ "auth_required": true, "challenge_id": "chl_7f3a…", "required_factors": ["totp", "sms"], "session_id": null }
```
Fields (verified against `UiSessionStartResp` and `SessionStartResp`): `auth_required`
(boolean, the only required field), `challenge_id` (nullable string), `required_factors`
(string array), `session_id` (nullable string).
- `auth_required == false` **and** `session_id` present → `LoginResult.Authenticated`.
  (This mirrors the web branch `if (!resp.auth_required && resp.session_id)` in
  `src/pages/Login.tsx:145`; AND-028 should require `session_id`, not merely an empty
  factor list, before treating the result as authenticated.)
- `auth_required == true` (challenge issued, factors listed) → `LoginResult.MfaRequired`.
- `required_factors` carries opaque lowercase strings (`"totp"`, `"sms"`, `"email"`,
  `"recovery"`); AND-028 maps these to the `MfaFactor` enum.

The ViewModel depends only on these `core-model` shapes (defined by AND-028):
```kotlin
sealed interface LoginResult {
    data object Authenticated : LoginResult
    data class MfaRequired(val challengeId: String, val factors: List<MfaFactor>) : LoginResult
}
enum class MfaFactor { TOTP, SMS, EMAIL, RECOVERY }
```
Endpoint/DTO ownership: `POST /ui/session/start` → AND-028; MFA endpoints → AND-033.
(Verified endpoint set: `POST /ui/mfa/totp/verify`, `POST /ui/mfa/sms/begin`,
`POST /ui/mfa/sms/verify`, `POST /ui/mfa/email/begin`, `POST /ui/mfa/email/verify`,
`POST /ui/mfa/recovery/{factor}`, and `POST /ui/session/finalize`. Note: TOTP has a
verify endpoint but **no** `begin` — the earlier `{totp|sms|email}/begin|verify`
shorthand was inexact.)

## 6. Data & State Management

```kotlin
data class LoginUiState(
    val username: String = "",
    val password: String = "",
    val passwordVisible: Boolean = false,
    val status: LoginStatus = LoginStatus.Idle,
    val error: UiText? = null,
) {
    val isSubmitting: Boolean get() = status == LoginStatus.Submitting
    val submitEnabled: Boolean
        get() = status != LoginStatus.Submitting &&
            username.isNotBlank() &&
            EmailValidator.isPlausible(username.trim()) &&
            password.isNotBlank()
}

enum class LoginStatus { Idle, Submitting }

sealed interface LoginEffect {
    data class NavigateToMfa(val challengeId: String, val factors: List<MfaFactor>) : LoginEffect
    data object NavigateHome : LoginEffect
}
```

State management rules:

- `_uiState` is updated only via `MutableStateFlow.update { }` to avoid lost-update
  races between input intents and the submit coroutine.
- **No persistence.** Login inputs are deliberately *not* written to
  `SavedStateHandle` or DataStore — passwords must never be persisted. On process
  death the form resets to empty; this is acceptable and intentional (see §8). The
  authenticated session itself is persisted by the cookie jar + DataStore auth store
  (AND-029), not here.
- **Effect collection.** The screen collects `effects` inside
  `viewLifecycleOwner.repeatOnLifecycle(STARTED)`; when paused it stops collecting and
  the buffered effect (if any) is delivered on resume. Because a successful login is
  terminal for this screen, at most one navigation effect is ever in flight.
- The `Authenticated` path leaves `status = Submitting`; the screen is removed from
  back-stack on `NavigateHome`, so the disabled button never reappears. If the nav
  graph keeps the screen alive, the destination's `LaunchedEffect` calls a `reset()`
  intent (covered by §13 open question).

## 7. Error Handling & Resilience

The ViewModel maps `ApiResult.Failure` (typed by `core-network`'s FastAPI `detail`
mapper: `string | [{msg}] | {code,...}`) into `UiText` via an extension:

```kotlin
private fun ApiResult.Failure.toLoginUiText(): UiText = when (val e = error) {
    is ApiError.Unauthorized      -> UiText.Res(R.string.login_error_invalid_credentials)
    is ApiError.Validation        -> UiText.Dynamic(e.firstMessage)               // [{msg}]
    is ApiError.Network,
    is ApiError.Timeout           -> UiText.Res(R.string.login_error_network)
    is ApiError.Server            -> UiText.Res(R.string.login_error_server)
    is ApiError.Unknown           -> UiText.Res(R.string.login_error_generic)
}
```

Resilience:

- **Timeouts.** The dev backend (`http://18.222.237.167:8000`) is plaintext and
  unreliable; OkHttp call timeout (~20s) is configured in `core-network` (AND-018).
  A timeout surfaces as `ApiError.Timeout` → network message, submit re-enabled.
- **No automatic retry.** `POST /ui/session/start` is non-idempotent; the bounded
  backoff retry policy applies only to idempotent GETs. The ViewModel therefore
  performs exactly one attempt per `onSubmit()` and relies on the user to retry.
- **401 refresh** is handled by the OkHttp authenticator in `core-network` (single
  `POST /ui/session/refresh` then retry). On a fresh login there is no session yet,
  so an `Unauthorized` here means genuinely bad credentials, surfaced as such.
- **Double-submit guard** (FR-4) prevents duplicate session-start calls on rapid
  taps.
- **Cancellation.** A pending login is cancelled automatically when `viewModelScope`
  is cleared; no manual `Job` tracking is required.

## 8. Security & Privacy

- The `password` field lives only in in-memory `LoginUiState`; it is never logged,
  never written to `SavedStateHandle`, DataStore, Room, or crash reports.
- Logging must redact credentials: the submit log line records only
  `username.length`/domain and never the password or full email at non-debug levels.
- `toString()` of `LoginUiState` is overridden (or `password` excluded) so accidental
  state logging cannot leak the secret.
- Compose `TextField` for password uses `PasswordVisualTransformation`; the
  `passwordVisible` toggle is UI-only and does not change what is stored.
- The session cookie + `ui_csrf` are managed by the persistent cookie jar in
  `core-network`; the ViewModel holds no tokens.
- No PII is emitted in telemetry beyond a hashed/length-only username (§10).

## 9. Accessibility & i18n

- The ViewModel emits all user-facing strings as `UiText` (string-resource or
  validated-dynamic), never hard-coded English, so the screen resolves them with the
  current locale. Error keys: `login_error_invalid_credentials`,
  `login_error_network`, `login_error_server`, `login_error_generic`.
- `submitEnabled` / `isSubmitting` drive the screen's content description and
  `Modifier.semantics { disabled() }` state for TalkBack (implemented in AND-030);
  the ViewModel guarantees these flags are always consistent so assistive tech reads
  the correct enabled/busy state.
- Errors are surfaced as state (`error: UiText?`) rather than transient toasts so a
  screen reader can announce them via `liveRegion`.
- No locale-specific parsing of credentials; `username.trim()` removes only
  surrounding whitespace.

## 10. Telemetry & Logging

Events emitted via the `core-data` analytics abstraction (no PII):

| Event | When | Properties |
|-------|------|-----------|
| `login_submit` | `onSubmit()` accepted | `username_domain`, `username_len` |
| `login_mfa_required` | `MfaRequired` mapped | `factor_count`, `factors` (enum names) |
| `login_success` | `Authenticated` mapped | — |
| `login_failure` | `ApiResult.Failure` | `error_type` (enum), `http_status?` |

- Debug `Timber` logs at `onSubmit`/result with redacted username; release builds
  strip verbose logs. No password, no `challenge_id` value in analytics (only
  factor metadata) to avoid correlating a challenge across systems.

## 11. Testing Strategy

Pure-JVM unit tests (no Robolectric) under
`feature-auth/src/test/.../login/LoginViewModelTest.kt`, using
`kotlinx-coroutines-test` (`StandardTestDispatcher` + `Turbine` for flows) and a fake
`AuthRepository` from `core-testing`.

```kotlin
class FakeAuthRepository(var loginResult: ApiResult<LoginResult>) : AuthRepository {
    var calls = 0
    override suspend fun login(username: String, password: String): ApiResult<LoginResult> {
        calls++; return loginResult
    }
}
```

Required cases (each asserts state transitions and/or emitted effect):

1. Initial state is empty, `Idle`, `submitEnabled == false`.
2. `onUsernameChange` + `onPasswordChange` with valid email/non-blank → `submitEnabled == true`.
3. Invalid email (`"foo"`) keeps `submitEnabled == false`.
4. Blank password keeps `submitEnabled == false`.
5. `onSubmit` sets `status == Submitting` and `submitEnabled == false` while in flight.
6. Success `Authenticated` → emits `NavigateHome` and `error == null`.
7. Success `MfaRequired` → emits `NavigateToMfa(challengeId, factors)`, `status` back to `Idle`.
8. Failure `Unauthorized` → `status == Idle`, `error == invalid_credentials`, submit re-enabled.
9. Failure `Timeout`/`Network` → network error mapped.
10. Failure `Validation` (`[{msg}]`) → `UiText.Dynamic(firstMsg)`.
11. Double `onSubmit` while `Submitting` → repository called exactly once (`calls == 1`).
12. `onErrorShown` clears `error`.
13. Any input change after a failure clears `error`.
14. `username` is trimmed before being passed to the repository.

Coverage gate: 100% of `LoginViewModel` branches and the `toLoginUiText` mapper.

## 12. Dependencies & Sequencing

- **Hard deps (must merge first):** AND-028 (`AuthRepository.login` + `LoginResult`),
  AND-030 (screen that hosts the ViewModel and renders `LoginUiState`).
- **Transitive:** AND-018 (OkHttp/Retrofit + cookie jar/CSRF), AND-027 (`AuthApi`),
  AND-020/AND-023 (core-ui scaffolding) arrive via the above.
- **Blocks / enables:** AND-034/035/036 (MFA verify flows) consume the
  `NavigateToMfa` effect; AND-029's auth store hydration follows `NavigateHome`.
- Develop alongside AND-030: the screen and ViewModel share `LoginUiState`,
  `LoginEffect`, and `LoginStatus`, which this ticket defines.

## 13. Risks & Open Questions

- **R1 — `getMe` ordering.** Does the ViewModel emit `NavigateHome` immediately, or
  await `getMe()` so home renders with `me` populated? Current design emits
  immediately and lets `RootViewModel`/post-login coordinator (AND-029) fetch `me`.
  *Decision needed* before AND-029 lands; if home must not render without `me`, add a
  `status = Finalizing` and call a repository `awaitSession()` here.
- **R2 — Authenticated-with-no-MFA realism.** Backend may always require ≥1 factor; if
  so the `Authenticated` branch is dead for normal users but must remain for
  recovery/passwordless paths. Keep the branch + test.
- **R3 — Effect buffering on rotation.** `DROP_OLDEST` with buffer=1 is safe for a
  single terminal effect; revisit if future requirements add concurrent effects.
- **R4 — Email-only usernames.** Web allows email; confirm backend doesn't accept
  bare usernames. If it does, relax `EmailValidator` to a non-blank check.

## 14. Acceptance Criteria

- AC-1. `LoginViewModel` exposes `StateFlow<LoginUiState>` and a `SharedFlow`/channel
  of `LoginEffect`; navigation is delivered only as one-shot effects.
- AC-2. `submitEnabled` is true exactly when username is a plausible email,
  password is non-blank, and no submit is in flight; otherwise false. (unit-tested)
- AC-3. While a login request is in flight, `isSubmitting == true` and
  `submitEnabled == false`; a second `onSubmit` does not issue a second request.
  (unit-tested)
- AC-4. `MfaRequired` result emits `NavigateToMfa(challengeId, factors)`;
  `Authenticated` result emits `NavigateHome`. (unit-tested)
- AC-5. Each `ApiResult.Failure` variant maps to the correct `UiText`, leaves
  `status == Idle`, and re-enables submit. (unit-tested)
- AC-6. Errors clear on next input change and on `onErrorShown()`. (unit-tested)
- AC-7. Password is never persisted or logged in plaintext.
- AC-8. All state transitions in §11 are covered by passing unit tests with 100%
  branch coverage of the ViewModel and error mapper.

## 15. Definition of Done

- Code merged to `android-port` under
  `feature-auth/src/main/java/com/testlogon/android/feature/auth/login/` with
  `LoginViewModel`, `LoginUiState`, `LoginStatus`, `LoginEffect`, and the
  `toLoginUiText` mapper.
- `@HiltViewModel` wiring compiles with KSP; ViewModel resolvable via
  `hiltViewModel()` in the AND-030 screen.
- `LoginViewModelTest` (cases 1–14) green in CI; branch coverage gate met.
- No password/credential appears in any log, `toString`, or analytics payload
  (verified by a test asserting `LoginUiState.toString()` excludes `password`).
- ktlint/detekt clean; no new public API in `core-*` modules (all new types live in
  `feature-auth` except shared `LoginResult`/`MfaFactor` owned by AND-028).
- Manual smoke against the dev backend: valid creds with MFA → MFA route; valid
  creds without MFA → home; bad creds → invalid-credentials error; airplane mode →
  network error, submit re-enabled.
- Spec open questions R1/R4 resolved or explicitly deferred with an owner.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Login submit hits `POST /ui/session/start`.** VERIFIED.
   Source: OpenAPI `POST /ui/session/start` (op `ui_session_start_ui_session_start_post`);
   frontend `src/api/endpoints/auth.ts: sessionStart`.
2. **Request body is `{ challenge_context: { username, password } }`.** VERIFIED for the
   outer `challenge_context` wrapper; the inner `username`/`password` keys are the web
   client's convention, not a typed contract.
   Source: schema `UiSessionStartReq` (single `challenge_context` object,
   `additionalProperties: true`); web population at `src/pages/Login.tsx:138-143`.
   The inner key *names* are best treated as a verified-by-web-usage convention rather
   than a schema guarantee (see Open assumptions).
3. **Response 200 shape: `auth_required`, `challenge_id?`, `required_factors[]`,
   `session_id?`.** VERIFIED.
   Source: schema `UiSessionStartResp` (only `auth_required` is required; `challenge_id`
   and `session_id` are nullable); frontend `src/api/types.ts: SessionStartResp`.
4. **Authenticated vs MFA branch condition.** CORRECTED. Spec originally said
   "`auth_required == false` (or no factors)". The web client branches on
   `!resp.auth_required && resp.session_id`.
   Source: `src/pages/Login.tsx:145`. Spec §5 now requires `session_id` present for the
   `Authenticated` mapping.
5. **`required_factors` values are lowercase strings `totp|sms|email|recovery`.** VERIFIED.
   Source: `src/pages/Login.tsx:159-163` (string comparisons `factors.includes("totp")`
   etc.) and the recovery factor path; mapped to `MfaFactor` enum by AND-028.
6. **CSRF: token from `ui_csrf` cookie sent as `X-CSRF-Token` header.** VERIFIED.
   Source: `src/api/client.ts:135,168-170` (`getCookie("ui_csrf")` →
   `headers.set("X-CSRF-Token", csrf)`).
7. **Cookie-based session (`credentials: include`).** VERIFIED.
   Source: `src/api/client.ts:182-183, 219-220`.
8. **401 handling: refresh once via `POST /ui/session/refresh` then retry, but only if
   already authenticated; an unauthenticated 401 (bad creds) surfaces directly.** VERIFIED.
   Source: `src/api/client.ts:191-224`; OpenAPI `POST /ui/session/refresh`
   (op `ui_session_refresh_ui_session_refresh_post`, resp `200`).
9. **Error `detail` shape is `string | [{msg}] | {code,...}`.** VERIFIED.
   Source: `src/api/client.ts:66-96` (`normalizeErrorDetail` handles string, array of
   `{msg}`, and object with `code` via `mapAuthorizationError`); OpenAPI
   `HTTPValidationError.detail` = array of `ValidationError` (each has `msg`); every
   `/ui/...` op lists `422:HTTPValidationError`.
10. **Web reference path for login submit.** CORRECTED. Spec cited
    `frontend/src/api/endpoints/session.ts` and DTO `SessionStartResponse`. No `session.ts`
    exists; the submit lives in `auth.ts` and the DTO is `SessionStartResp`.
    Source: `src/api/endpoints/auth.ts: sessionStart`; `src/api/types.ts: SessionStartResp`.
11. **MFA endpoint set (downstream, AND-033).** CORRECTED shorthand. Spec wrote
    `/ui/mfa/{totp|sms|email}/begin|verify`; TOTP has **no** `begin`.
    Source: OpenAPI — `POST /ui/mfa/totp/verify`, `POST /ui/mfa/sms/begin`,
    `POST /ui/mfa/sms/verify`, `POST /ui/mfa/email/begin`, `POST /ui/mfa/email/verify`,
    `POST /ui/mfa/recovery/{factor}`, `POST /ui/session/finalize`.
12. **Web awaits `getMe()` before navigating home on no-MFA login.** VERIFIED (and noted
    as a deliberate divergence for this ViewModel, which defers `getMe`).
    Source: `src/pages/Login.tsx:147-149`.
13. **`POST /ui/session/start` is non-idempotent / no auto-retry.** Plausible but
    UNVERIFIED-ASSUMPTION (idempotency is a design judgment; OpenAPI does not annotate it).
    Retry policy itself is owned by `core-network` (AND-018), outside these sources.
14. **`android.util.Patterns.EMAIL_ADDRESS` for email shape validation.** VERIFIED as a
    framework API. Source: framework ref —
    https://developer.android.com/reference/android/util/Patterns#EMAIL_ADDRESS .
15. **`MutableSharedFlow(replay=0, extraBufferCapacity=1, DROP_OLDEST)` gives a
    non-suspending `tryEmit` for one-shot effects.** VERIFIED as a framework behavior.
    Source: framework ref —
    https://kotlinlang.org/api/kotlinx.coroutines/kotlinx-coroutines-core/kotlinx.coroutines.flow/-mutable-shared-flow/ .
16. **Lifecycle-aware effect collection via `repeatOnLifecycle(STARTED)`.** VERIFIED as a
    framework pattern. Source: framework ref —
    https://developer.android.com/topic/libraries/architecture/coroutines#restart .
17. **Dev backend host `http://18.222.237.167:8000`.** UNVERIFIED-ASSUMPTION. The
    frontend resolves its base URL from `VITE_API_BASE_URL` (`src/api/client.ts:7`); the
    literal IP is not present in these sources (it comes from infra/`core-network` config).

### Corrections made

- §2 / §5: web reference path `session.ts` → `auth.ts`; DTO `SessionStartResponse` →
  `SessionStartResp`; added backend schema names `UiSessionStartReq` / `UiSessionStartResp`.
- §5: Authenticated branch now requires `auth_required == false` **and** `session_id`
  present (was "`auth_required == false` (or no factors)"), matching `Login.tsx:145`.
- §5: documented the full response field set incl. nullable `session_id`, and that
  `required_factors` are opaque lowercase strings.
- §5: clarified `challenge_context` is a free-form (`additionalProperties:true`) object;
  inner keys are the web convention.
- §5: corrected the MFA endpoint shorthand (TOTP has no `begin`; listed the real set).
- §2: added a verified note that the web client awaits `getMe()` before navigating,
  flagging this ViewModel's deferral as an intentional divergence.

### Open assumptions

- **Inner `challenge_context` keys (`username`/`password`).** The schema is free-form, so
  these names are guaranteed only by web usage, not by the typed contract. If the backend
  ever renames them, AND-028 (not this ticket) must follow; the ViewModel is agnostic.
- **Non-idempotency of `/ui/session/start` and the retry policy.** A reasonable design
  stance but not annotated in OpenAPI; the actual retry/backoff behavior is owned by
  `core-network` (AND-018) and not present in the verifiable sources here.
- **Dev backend IP/port.** Not in the frontend (env-driven); treat as infra config.
- **Typed `ApiError` taxonomy** (`Unauthorized/Validation/Network/Timeout/Server/Unknown`)
  and `UiText` are `core-network`/`core-ui` constructs owned by AND-018/AND-020 and are
  not defined in these reference sources; the mapping is consumed, not specified, here.

## 17. Test Plan

All cases are pure-JVM ViewModel tests unless noted, using `kotlinx-coroutines-test`
(`StandardTestDispatcher`), `Turbine` for `StateFlow`/`SharedFlow`, and a
`FakeAuthRepository`. MockWebServer/contract cases assert that the request/response
*shapes the ViewModel relies on* (owned by AND-028) line up with the verified
`UiSessionStart*` schemas; instrumented/Compose cases are listed where UI surfaces the
ViewModel's state (AND-030 host).

- **TC-AND-031-01** — Type: unit. Pre: fresh `LoginViewModel`. Steps: read
  `uiState.value`. Expected: `username=""`, `password=""`, `status=Idle`,
  `error=null`, `submitEnabled=false`, `isSubmitting=false`. Traces: AC-1, AC-2.
- **TC-AND-031-02** — Type: unit. Pre: fresh VM. Steps: `onUsernameChange("a@b.com")`,
  `onPasswordChange("pw")`; read state. Expected: `submitEnabled=true`. Traces: AC-2.
- **TC-AND-031-03** — Type: unit. Pre: fresh VM. Steps: `onUsernameChange("foo")`
  (no `@`), `onPasswordChange("pw")`. Expected: `submitEnabled=false` (email-shape gate).
  Also assert blank password (`onPasswordChange("")`) → `submitEnabled=false`.
  Traces: AC-2.
- **TC-AND-031-04** — Type: unit. Pre: valid creds entered; fake set to a never-completing
  `login` (suspend on a latch). Steps: `onSubmit()`; advance dispatcher. Expected:
  `status=Submitting`, `isSubmitting=true`, `submitEnabled=false` while in flight.
  Traces: AC-3.
- **TC-AND-031-05** — Type: unit. Pre: valid creds; fake returns
  `ApiResult.Success(LoginResult.Authenticated)`. Steps: collect `effects` with Turbine;
  `onSubmit()`. Expected: emits exactly `LoginEffect.NavigateHome`, `error=null`.
  Traces: AC-4.
- **TC-AND-031-06** — Type: unit. Pre: valid creds; fake returns
  `ApiResult.Success(MfaRequired("chl_1", [TOTP, SMS]))`. Steps: collect effects;
  `onSubmit()`. Expected: emits `NavigateToMfa("chl_1", [TOTP, SMS])`; `status` returns
  to `Idle`. Traces: AC-4.
- **TC-AND-031-07** — Type: unit. Pre: valid creds; fake returns
  `ApiResult.Failure(ApiError.Unauthorized)`. Steps: `onSubmit()`. Expected: `status=Idle`,
  `error=UiText.Res(login_error_invalid_credentials)`, `submitEnabled=true` (re-enabled),
  no effect emitted. Traces: AC-5.
- **TC-AND-031-08** — Type: unit (parameterized). Pre: valid creds. Steps: run
  `onSubmit()` for `ApiError.Timeout`, `ApiError.Network`, `ApiError.Server`,
  `ApiError.Unknown`. Expected: Timeout/Network → `login_error_network`; Server →
  `login_error_server`; Unknown → `login_error_generic`; all leave `status=Idle` and
  re-enable submit. Traces: AC-5.
- **TC-AND-031-09** — Type: unit. Pre: valid creds; fake returns
  `ApiResult.Failure(ApiError.Validation(firstMessage="bad"))` (the `[{msg}]` shape from
  `HTTPValidationError`). Steps: `onSubmit()`. Expected: `error=UiText.Dynamic("bad")`,
  `status=Idle`. Traces: AC-5.
- **TC-AND-031-10** — Type: unit. Pre: valid creds; slow fake. Steps: call `onSubmit()`
  twice before completion. Expected: `FakeAuthRepository.calls == 1` (double-tap
  debounced). Traces: AC-3.
- **TC-AND-031-11** — Type: unit. Pre: a failure has set `error != null`. Steps: (a)
  `onErrorShown()` → `error=null`; (b) from another failed state, `onUsernameChange("x")`
  → `error=null`; same for `onPasswordChange`. Traces: AC-6.
- **TC-AND-031-12** — Type: unit. Pre: `onUsernameChange("  a@b.com  ")`,
  `onPasswordChange("pw")`. Steps: `onSubmit()` with a capturing fake. Expected: fake
  receives `username == "a@b.com"` (trimmed); password passed unmodified. Traces: AC-2, AC-4.
- **TC-AND-031-13** — Type: unit (security). Pre: state populated with a password.
  Steps: call `LoginUiState.toString()`. Expected: output does not contain the password
  value (toString excludes/redacts `password`). Traces: AC-7.
- **TC-AND-031-14** — Type: contract/MockWebServer (boundary, via AND-028's
  `AuthRepository` against MockWebServer). Pre: server stubs
  `200 {"auth_required":false,"session_id":"sess_1","required_factors":[]}` and
  `200 {"auth_required":true,"challenge_id":"chl_1","required_factors":["totp"]}`.
  Steps: drive `login()` for each. Expected: first → `LoginResult.Authenticated`
  (because `auth_required=false` **and** `session_id` present), VM emits `NavigateHome`;
  second → `MfaRequired("chl_1",[TOTP])`, VM emits `NavigateToMfa`. Also assert request
  body carries `challenge_context.username/password` and `X-CSRF-Token` header is present.
  Traces: AC-1, AC-4.
- **TC-AND-031-15** — Type: integration (offline / flaky-dev-host path). Pre: network
  disabled or MockWebServer configured to time out beyond the OkHttp call timeout.
  Steps: valid creds, `onSubmit()`. Expected: `ApiError.Timeout`/`Network` →
  `error=login_error_network`, `status=Idle`, `submitEnabled=true`; exactly one attempt
  (no auto-retry on this non-idempotent POST). Traces: AC-5.
- **TC-AND-031-16** — Type: Compose-UI + accessibility (instrumented, AND-030 host).
  Pre: VM injected via `hiltViewModel()`. Steps: with `submitEnabled=false` and then a
  forced `Submitting` state, inspect the submit control. Expected: control reports a
  disabled/busy semantics state to TalkBack (`semantics { disabled() }`), and an
  `error` is exposed via a `liveRegion` so a screen reader announces it; visual toggle of
  `passwordVisible` does not alter stored password. Traces: AC-1, AC-3, AC-7.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
|---|---|
| AC-1 (StateFlow + one-shot effects) | TC-01, TC-14, TC-16 |
| AC-2 (submitEnabled gate) | TC-01, TC-02, TC-03, TC-12 |
| AC-3 (in-flight disable + single request) | TC-04, TC-10, TC-16 |
| AC-4 (MfaRequired→NavigateToMfa, Authenticated→NavigateHome) | TC-05, TC-06, TC-12, TC-14 |
| AC-5 (failure mapping, Idle, re-enable) | TC-07, TC-08, TC-09, TC-15 |
| AC-6 (error clears on input / onErrorShown) | TC-11 |
| AC-7 (password never persisted/logged) | TC-13, TC-16 |
| AC-8 (state transitions + branch coverage) | TC-01..TC-12 (whole suite) |
