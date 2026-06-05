---
id: AND-053
title: "Registration: start"
milestone: M2
epic: E08
priority: P1
size: M
status: draft
depends_on: [AND-030]
blocks: [AND-054]
---

# AND-053 — Registration: start

## 1. Overview & Goal

Build the **Register (start)** surface for the TestLogon native Android app: the
first step of self-service account creation. A logged-out user reaches this
screen from the Login screen's "Create account" link (AND-030) and enters their
profile and credentials (`full_name`, `email`, `password`, `confirm`), chooses a
verification **delivery method**, and optionally opts in to MFA enrollment
(SMS and/or TOTP). On valid submit the app calls `POST /ui/register/start`,
maps the `RegisterStartResp` (`verification_required` + `delivery`), and routes
forward to the confirmation step (account-verification screen, AND-054) carrying
the registration handle and the resolved delivery channel.

This ticket owns the **screen, its ViewModel, the registration DTOs/API method,
the repository call, and the local validation/error mapping** for the *start*
step only. It does **not** own the confirmation/verification screen that
consumes the code (AND-054), nor the post-verification login transition. The
goal is an end-to-end-testable registration entry: a Compose UI test drives the
form against a fake state holder, and a repository/MockWebServer test drives the
`POST /ui/register/start` request/response mapping including FastAPI error
shapes.

Definition of success: a valid form submission produces a `register/start`
request with the exact JSON contract, the typed `RegisterStartResp` is mapped to
a `RegisterStartUiState` outcome, and the screen routes to the confirm step with
the correct `delivery` channel; validation failures and server `detail` errors
are surfaced inline without navigating.

## 2. Context & References

- **Module:** `feature-auth` (Gradle module `:feature-auth`), package
  `com.testlogon.android.feature.auth.register`.
- **Depends on:**
  - **AND-030** — Login screen UI. Registration is reached via Login's
    `onRegister()` callback; this ticket adds the `register/start` route to the
    same unauthenticated nav graph (AND-023, transitively via AND-030) and
    reuses the core input composables (`AppTextField`, `PasswordField`,
    `AppButton`) and the `FieldError`/`FormError` patterns established there.
- **Blocks (downstream):**
  - **AND-054** — Registration confirm/verify screen, which consumes the
    `challenge_id`/registration handle and `delivery` channel produced here and
    calls the verify endpoint. The exact confirm endpoint and resend logic are
    owned there.
- **Reuses (core):** `core-network` (`ApiResult<T>`, OkHttp client with cookie
  jar AND-011, CSRF interceptor AND-012, 401-refresh authenticator AND-013,
  error/detail mapping AND-015), `core-model`, `core-ui` (theme + state
  composables AND-019/020/021).
- **Backend:** FastAPI + DynamoDB. Endpoint `POST /ui/register/start`.
  Dev host `http://18.222.237.167:8000` is plaintext HTTP and unreliable:
  ~20 s timeouts apply. `register/start` is a **non-idempotent POST** — it is
  **not** eligible for the idempotent-GET backoff retry (AND-016). OpenAPI at
  `/openapi.json`; confirm the live `RegisterStartReq`/`RegisterStartResp`
  schema at implementation time.
- **Web reference:** `frontend/src/api/endpoints/*.ts` (registration endpoint)
  and `frontend/src/api/types.ts` (`RegisterStartReq`, `RegisterStartResp`) for
  field names, delivery enum values, and IA parity.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Retrofit 2.11 /
  Moshi 1.15 / OkHttp 4.12, minSdk 24 / target 35, JDK 17.

## 3. Functional Requirements

FR-1 **Full name field.** Single-line `AppTextField`, capitalization `Words`,
autofill hint `name`, IME `Next`. Validation: non-blank, trimmed length ≥ 2.

FR-2 **Email field.** Single-line, keyboard `Email`, autofill hint
`emailAddress`, IME `Next`. Validation: non-blank and matches
`android.util.Patterns.EMAIL_ADDRESS` (registration always requires a real
email, unlike Login which permits username).

FR-3 **Password field.** `PasswordField` (AND-020) with show/hide toggle,
autofill hint `newPassword`, IME `Next`. Validation: non-blank and meets the
minimum policy (≥ 8 characters; mirror web policy if stricter). A lightweight
strength/requirement hint renders beneath the field.

FR-4 **Confirm password field.** `PasswordField`, autofill hint `newPassword`,
IME `Done` (triggers submit when valid). Validation: non-blank and **must equal**
the password field; mismatch renders `FieldError.PasswordMismatch`.

FR-5 **Delivery method selector.** A required single-choice control (segmented
buttons or radio group) selecting where the verification message is sent.
Options are the backend delivery enum — at minimum `email` and `sms`. When `sms`
is selected and no phone is on file, a phone-number field is required (see FR-6).
Default selection is `email`.

FR-6 **Phone number (conditional).** Shown only when delivery `sms` is selected
or SMS MFA opt-in is enabled. Keyboard `Phone`, autofill hint `phoneNumber`.
Validation: non-blank and a plausible E.164-ish pattern when required; ignored
otherwise.

FR-7 **Optional MFA opt-in.** Two independent toggles:
`enrollSmsMfa` and `enrollTotpMfa`. These are passed to the backend as opt-in
flags; actual factor enrollment occurs in the verify/confirm flow (AND-054) or
post-login. Enabling `enrollSmsMfa` forces the phone field (FR-6) to be required.

FR-8 **Submit gating.** The primary "Create account" button is enabled only when
all required fields pass local validation **and** `!isSubmitting`. Tapping submit
(or confirm-password IME `Done`) invokes the ViewModel submit handler.

FR-9 **Loading state.** While submitting: button shows a progress indicator and
is disabled; all fields, selectors, toggles, and the back link are disabled. No
full-screen blocking overlay.

FR-10 **Server/validation error display.** A dismissible error banner renders
`state.formError`. Field-scoped server errors (e.g., "email already registered")
are mapped back onto the offending field when the backend `detail` identifies a
field; otherwise they render in the banner.

FR-11 **Success routing.** On a successful `RegisterStartResp` with
`verification_required = true`, navigate to the confirm step (AND-054) passing
the registration handle/`challenge_id` and the resolved `delivery` channel. If
`verification_required = false` (no verification needed), route to Login with a
success message (edge case; copy from web).

FR-12 **Back / Sign-in link.** A secondary affordance to return to Login
(`onNavigateToLogin()`), disabled while submitting.

FR-13 **IA parity.** Field order, labels, delivery options, and action hierarchy
match the web registration page.

## 4. Technical Design

Follows the project stateless-screen + state-holder pattern (as AND-030). The
route composable reads `StateFlow` and forwards callbacks; the inner composable
is pure and is what previews/UI tests exercise.

```kotlin
package com.testlogon.android.feature.auth.register

// Route-level entry; bound by the unauthenticated nav graph.
@Composable
fun RegisterRoute(
    onNavigateToConfirm: (challengeId: String, delivery: DeliveryMethod) -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: RegisterViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is RegisterEvent.GoToConfirm ->
                    onNavigateToConfirm(event.challengeId, event.delivery)
                RegisterEvent.GoToLoginSuccess -> onNavigateToLogin()
            }
        }
    }
    RegisterScreen(
        state = state,
        onFullNameChange = viewModel::onFullNameChange,
        onEmailChange = viewModel::onEmailChange,
        onPasswordChange = viewModel::onPasswordChange,
        onConfirmChange = viewModel::onConfirmChange,
        onPhoneChange = viewModel::onPhoneChange,
        onDeliveryChange = viewModel::onDeliveryChange,
        onToggleSmsMfa = viewModel::onToggleSmsMfa,
        onToggleTotpMfa = viewModel::onToggleTotpMfa,
        onTogglePasswordVisibility = viewModel::onTogglePasswordVisibility,
        onSubmit = viewModel::onSubmit,
        onDismissError = viewModel::onDismissError,
        onNavigateToLogin = onNavigateToLogin,
    )
}

@Composable
fun RegisterScreen(
    state: RegisterUiState,
    onFullNameChange: (String) -> Unit,
    onEmailChange: (String) -> Unit,
    onPasswordChange: (String) -> Unit,
    onConfirmChange: (String) -> Unit,
    onPhoneChange: (String) -> Unit,
    onDeliveryChange: (DeliveryMethod) -> Unit,
    onToggleSmsMfa: (Boolean) -> Unit,
    onToggleTotpMfa: (Boolean) -> Unit,
    onTogglePasswordVisibility: () -> Unit,
    onSubmit: () -> Unit,
    onDismissError: () -> Unit,
    onNavigateToLogin: () -> Unit,
)
```

State, enums, and shared validation:

```kotlin
enum class DeliveryMethod(val wire: String) { Email("email"), Sms("sms") }

@Immutable
data class RegisterUiState(
    val fullName: String = "",
    val email: String = "",
    val password: String = "",
    val confirm: String = "",
    val phone: String = "",
    val delivery: DeliveryMethod = DeliveryMethod.Email,
    val enrollSmsMfa: Boolean = false,
    val enrollTotpMfa: Boolean = false,
    val isPasswordVisible: Boolean = false,
    val fullNameError: FieldError? = null,
    val emailError: FieldError? = null,
    val passwordError: FieldError? = null,
    val confirmError: FieldError? = null,
    val phoneError: FieldError? = null,
    val formError: FormError? = null,
    val isSubmitting: Boolean = false,
) {
    val isPhoneRequired: Boolean get() = delivery == DeliveryMethod.Sms || enrollSmsMfa
    val isSubmitEnabled: Boolean
        get() = !isSubmitting &&
            fullNameError == null && emailError == null &&
            passwordError == null && confirmError == null &&
            (!isPhoneRequired || (phone.isNotBlank() && phoneError == null)) &&
            fullName.isNotBlank() && email.isNotBlank() &&
            password.isNotBlank() && confirm.isNotBlank()
}

// FieldError extends the AND-030 enum surface with registration-specific cases.
enum class FieldError { Required, InvalidEmail, TooShort, PasswordMismatch, InvalidPhone }

object RegisterValidator {
    fun validateFullName(v: String): FieldError? = when {
        v.isBlank() -> FieldError.Required
        v.trim().length < 2 -> FieldError.TooShort
        else -> null
    }
    fun validateEmail(v: String): FieldError? = when {
        v.isBlank() -> FieldError.Required
        !Patterns.EMAIL_ADDRESS.matcher(v).matches() -> FieldError.InvalidEmail
        else -> null
    }
    fun validatePassword(v: String): FieldError? = when {
        v.isBlank() -> FieldError.Required
        v.length < 8 -> FieldError.TooShort
        else -> null
    }
    fun validateConfirm(pw: String, c: String): FieldError? = when {
        c.isBlank() -> FieldError.Required
        c != pw -> FieldError.PasswordMismatch
        else -> null
    }
    fun validatePhone(v: String, required: Boolean): FieldError? = when {
        !required -> null
        v.isBlank() -> FieldError.Required
        !v.matches(Regex("^\\+?[0-9]{7,15}$")) -> FieldError.InvalidPhone
        else -> null
    }
}
```

ViewModel (Hilt, `core-network` repository injected):

```kotlin
@HiltViewModel
class RegisterViewModel @Inject constructor(
    private val authRepository: AuthRepository, // adds registerStart(...) here
    savedState: SavedStateHandle,
) : ViewModel() {
    val uiState: StateFlow<RegisterUiState>
    val events: SharedFlow<RegisterEvent>   // one-shot navigation
    fun onSubmit() { /* validate all -> set isSubmitting -> call repo -> map */ }
}

sealed interface RegisterEvent {
    data class GoToConfirm(val challengeId: String, val delivery: DeliveryMethod) : RegisterEvent
    data object GoToLoginSuccess : RegisterEvent
}
```

Layout: `Scaffold` + scrollable `Column` with `imePadding()`. Order: header,
error banner, full-name, email, password (+ requirement hint), confirm, delivery
selector, conditional phone field, MFA opt-in toggles, primary submit, sign-in
link. `@Preview`s: empty, valid (email delivery), valid (sms delivery + phone),
mismatch error, submitting, form-error.

## 5. API Contract

**`POST /ui/register/start`** — non-idempotent. Sent through the shared OkHttp
client so the persistent cookie jar (AND-011) and `X-CSRF-Token` header
(AND-012, echoing the `ui_csrf` cookie) are applied; the 401-refresh
authenticator (AND-013) is in the chain though an unauthenticated registrant
will typically not yet hold a session.

Retrofit method (added to `AuthApi`, AND-027):

```kotlin
@POST("ui/register/start")
suspend fun registerStart(@Body body: RegisterStartReq): Response<RegisterStartResp>
```

DTOs (Moshi; confirm exact wire names against `/openapi.json` and
`frontend/src/api/types.ts`):

```kotlin
@JsonClass(generateAdapter = true)
data class RegisterStartReq(
    @Json(name = "full_name") val fullName: String,
    val email: String,
    val password: String,
    @Json(name = "delivery") val delivery: String,        // "email" | "sms"
    @Json(name = "phone") val phone: String? = null,
    @Json(name = "enroll_sms_mfa") val enrollSmsMfa: Boolean = false,
    @Json(name = "enroll_totp_mfa") val enrollTotpMfa: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class RegisterStartResp(
    @Json(name = "verification_required") val verificationRequired: Boolean,
    @Json(name = "delivery") val delivery: String,        // resolved channel
    @Json(name = "challenge_id") val challengeId: String? = null,
)
```

Request body example:

```json
{
  "full_name": "Ada Lovelace",
  "email": "ada@example.com",
  "password": "s3cretpassw0rd",
  "delivery": "email",
  "phone": null,
  "enroll_sms_mfa": false,
  "enroll_totp_mfa": true
}
```

Success (`200`/`201`):

```json
{ "verification_required": true, "delivery": "email", "challenge_id": "reg_8f2c..." }
```

Error (`409`/`422`) — FastAPI `detail` (string | `[{msg,loc}]` | `{code,...}`):

```json
{ "detail": [ { "loc": ["body", "email"], "msg": "email already registered" } ] }
```

Errors are decoded via the shared `ApiError`/detail mapper (AND-015) into
`ApiResult.Failure`; the repository surfaces a normalized message and, when
`loc` identifies a body field, a field key the ViewModel maps to the matching
`FieldError`. The verify/confirm endpoint that consumes `challenge_id` is owned
by **AND-054**.

## 6. Data & State Management

- **Single source of truth:** `StateFlow<RegisterUiState>` in `RegisterViewModel`.
  The screen is stateless and renders via `collectAsStateWithLifecycle()`.
- **Repository layer:** a new `suspend fun registerStart(req): ApiResult<RegisterStartResp>`
  on `AuthRepository` (AND-028 family) wraps the `AuthApi` call and the
  ApiResult/error mapping; the ViewModel never touches Retrofit directly.
- **Navigation outcome:** one-shot `RegisterEvent` via `SharedFlow` (not state),
  preventing re-navigation on recomposition/rotation. The `delivery` carried to
  AND-054 is the **server-resolved** value from `RegisterStartResp.delivery`,
  not the local selection.
- **Config change / process death:** non-sensitive fields (`fullName`, `email`,
  `phone`, `delivery`, MFA toggles) are restored via `SavedStateHandle`.
  `password` and `confirm` are **excluded** from saved state (Section 8) and
  re-rendered blank after process death.
- **Validation timing:** errors are derived by the ViewModel from
  `RegisterValidator` on blur and on submit; first keystroke does not surface
  errors. Cross-field confirm validation re-runs whenever either password field
  changes.

## 7. Error Handling & Resilience

- **No automatic retry.** `register/start` is a non-idempotent POST; the AND-016
  GET backoff does not apply. A failed attempt offers a manual Retry only for
  transport-level failures (network/timeout), never auto-resubmits.
- **Field-mapped server errors:** when `detail[].loc` names a body field
  (e.g., `email`), map to that field's `FieldError` and focus it
  (e.g., "email already registered" → email field). Duplicate-account (`409`)
  maps to the email field with an inline message and a link back to Login.
- **Form-level errors:** `FormError.Network` (timeout/connection on the
  unreliable plaintext host) renders a retryable banner with copy reflecting the
  ~20 s timeout ("Couldn't reach the server. Check your connection and try
  again."); `FormError.Server` (5xx / unmapped) renders a generic retryable
  banner; `FormError.Validation` (422 not field-mappable) renders the normalized
  detail string.
- **Duplicate-submit guard:** submit disabled while `isSubmitting`; the
  confirm-password IME `Done` is a no-op when `!isSubmitEnabled`.
- **Partial success / verification_required=false:** treated as success → route
  to Login with a success message; do not show an error.
- **Banner dismissal** via `onDismissError` clears `formError` without touching
  field contents.

## 8. Security & Privacy

- `password` and `confirm` use `PasswordVisualTransformation` by default; the
  shared visibility toggle reveals both. Autofill hint `newPassword`.
- `password`/`confirm` are **excluded** from `SavedStateHandle`/
  `rememberSaveable`, so plaintext credentials are never written to disk on
  process death.
- No credential or PII values are logged (Section 10): `full_name`, `email`,
  `phone`, and password are never included in logs or analytics; only structural
  flags (delivery channel enum, MFA opt-in booleans) are recorded.
- Request rides cookies + `X-CSRF-Token`; the CSRF header is mandatory for the
  POST (AND-012). The cookie jar persists any session/csrf cookies the backend
  sets during registration.
- Transport is plaintext HTTP on the dev host; this is a known dev-environment
  condition. The screen does not transmit over a user-configurable URL of its
  own — it uses the app's effective base URL. No `FLAG_SECURE` here (deferred to
  global auth-window policy), but it is a candidate given password entry.
- Password strength hint is advisory; authoritative policy enforcement is
  server-side via the `422` response.

## 9. Accessibility & i18n

- All strings in `strings.xml` (`feature-auth`); no hard-coded UI text. Keys:
  `register_title`, `register_full_name_label`, `register_email_label`,
  `register_password_label`, `register_confirm_label`, `register_phone_label`,
  `register_delivery_label`, `register_delivery_email`, `register_delivery_sms`,
  `register_mfa_sms`, `register_mfa_totp`, `register_submit`,
  `register_sign_in`, `register_error_required`, `register_error_invalid_email`,
  `register_error_too_short`, `register_error_password_mismatch`,
  `register_error_invalid_phone`, `register_error_network`,
  `register_error_email_taken`.
- Field errors associated via `semantics { error(...) }`; the form-error banner
  is a `liveRegion` so it is announced on appearance.
- Delivery selector exposes selection state to TalkBack; MFA toggles announce
  on/off. Conditional phone field appearance is announced (focus moves logically).
- Touch targets ≥ 48 dp; sp typography with dynamic font scaling; content
  scrolls under the IME; RTL-safe (start/end). Color is never the sole error
  signal (icon + text), verified for Material 3 contrast in light/dark.

## 10. Telemetry & Logging

- `auth_register_view` on first composition.
- `auth_register_submit` with non-PII props: `delivery` (`email`|`sms`),
  `sms_mfa` (bool), `totp_mfa` (bool) — never field values.
- `auth_register_validation_error` with `field` and `reason` enums.
- `auth_register_error_shown` with `error_type`
  (`email_taken`|`validation`|`network`|`server`).
- `auth_register_success` with `verification_required` (bool) and resolved
  `delivery`.
- `auth_register_link_tap` with `target` (`sign_in`).
- Structured logger at `debug`/`info`; no PII, no credentials, no request
  bodies. Analytics dispatch is invoked from the ViewModel at the defined points.

## 11. Testing Strategy

**Unit tests** (JVM, `core-testing`):
- `RegisterValidator` truth tables: full name (blank/short/valid), email
  (blank/malformed/valid), password (blank/short/valid), confirm (blank/
  mismatch/match), phone (required-blank, required-invalid, required-valid,
  not-required-ignored).
- `RegisterUiState.isSubmitEnabled` / `isPhoneRequired` derivation across
  delivery and MFA-toggle combinations.

**Repository / API tests** (MockWebServer harness AND-046):
- Valid `registerStart` produces the exact JSON body (field names, snake_case,
  delivery wire value, MFA flags) and parses `RegisterStartResp` to
  `ApiResult.Success` with `verificationRequired`, `delivery`, `challengeId`.
- `409`/`422` with `detail` array → `ApiResult.Failure` carrying the normalized
  message and the `email` field key.
- CSRF header present; cookies persisted via the cookie jar.
- Timeout/connection failure → mapped network failure (no auto-retry observed).

**Compose UI tests** (`feature-auth` androidTest, `createComposeRule`, fake
state — no network/Hilt):
- Typing updates rendered values via callbacks; submit disabled until all valid.
- Password mismatch surfaces `PasswordMismatch` under confirm; clears on fix.
- Selecting `sms` delivery reveals the phone field and makes it required; submit
  blocked until phone valid.
- Enabling SMS MFA forces phone requirement even when delivery is `email`.
- `isSubmitting` disables fields/links and shows progress; no duplicate submit.
- `FormError.Network` shows retryable banner with working Retry; email-taken
  maps to email field, non-retryable.
- Sign-in link invokes `onNavigateToLogin`; success event routes to confirm with
  the resolved delivery (verified via fake event emission).

**A11y test:** error association + live-region announcement + toggle/selector
state assertions in the UI suite.

## 12. Dependencies & Sequencing

- **Blocked by:** **AND-030** (Login UI) — provides the entry link, the
  unauthenticated nav graph slot, and the reused core input composables and
  `FieldError`/`FormError` patterns. Transitively relies on landed
  `core-network` plumbing (AND-011/012/013/015), `AuthApi`/`AuthRepository`
  (AND-027/028), and core-ui (AND-019/020/021).
- **Blocks:** **AND-054** (registration confirm/verify) — consumes the
  `challenge_id` and resolved `delivery` produced here.
- **Sequencing:** add the `RegisterStartReq`/`RegisterStartResp` DTOs and the
  `AuthApi.registerStart` method and `AuthRepository.registerStart` first
  (testable via MockWebServer), then the stateless `RegisterScreen` +
  `RegisterUiState` + `RegisterValidator` + previews + UI tests, then wire
  `RegisterRoute` with `hiltViewModel()` and register the route in the nav graph.

## 13. Risks & Open Questions

- **R1 — Schema drift.** Exact `RegisterStartReq`/`RegisterStartResp` field
  names, the delivery enum value set (is `totp`/`email`/`sms` the full set?), and
  whether MFA opt-in is part of `register/start` or a later step must be
  confirmed against `/openapi.json` and `frontend/`. *Open: are MFA opt-in flags
  accepted at start, or only at confirm?*
- **R2 — Field-error mapping.** Backend `detail[].loc` conventions for
  field-level errors (e.g., duplicate email) must be verified to map server
  errors to fields reliably; fall back to the banner if `loc` is absent.
- **R3 — Password policy.** Minimum length/complexity must match server policy to
  avoid a client-pass / server-422 mismatch; treat server `422` as authoritative.
- **R4 — Delivery vs phone coupling.** Whether `sms` delivery requires a phone in
  the request or the backend uses an on-file number needs confirmation. *Open:
  does `register/start` accept `phone`?*
- **R5 — verification_required=false path.** Confirm whether the backend ever
  returns this and what UX the web uses; current plan routes to Login with a
  success message.

## 14. Acceptance Criteria

AC-1 A fully valid form (full name, valid email, policy-passing password,
matching confirm, valid delivery and any required phone) enables submit; any
invalid/blank required field keeps it disabled. (UI-tested.)

AC-2 Field-level validation (required, invalid email, too-short password,
password mismatch, invalid/missing phone when required) surfaces under the
correct field on blur/submit and clears on correction. (UI-tested.)

AC-3 Selecting `sms` delivery (or enabling SMS MFA) reveals and requires the
phone field; `email` delivery hides it. (UI-tested.)

AC-4 Valid submit issues `POST /ui/register/start` with the exact JSON contract
(Section 5), including CSRF header and cookie jar. (Repository/MockWebServer
test.)

AC-5 A successful `RegisterStartResp` maps `verification_required`/`delivery`/
`challenge_id` and routes to the confirm step (AND-054) with the server-resolved
delivery; the navigation event fires exactly once. (Tested via fake event.)

AC-6 Server errors are surfaced: duplicate/`409` email maps to the email field
(non-retryable); network/timeout shows a retryable banner with working Retry;
no auto-retry of the POST occurs. (UI + repository tests.)

AC-7 Loading state disables the form and shows progress; no duplicate submits.
(UI-tested.)

AC-8 Behavior and IA (field order, delivery options, labels, action hierarchy)
match the web registration reference. (Screenshot/IA comparison.)

AC-9 No credentials/PII are logged, and `password`/`confirm` are excluded from
saved state across process death.

## 15. Definition of Done

- `RegisterScreen`, `RegisterRoute`, `RegisterViewModel`, `RegisterUiState`,
  `RegisterEvent`, `DeliveryMethod`, `RegisterValidator`, and the
  `RegisterStartReq`/`RegisterStartResp` DTOs implemented in `:feature-auth`
  under `com.testlogon.android.feature.auth.register`, with
  `AuthApi.registerStart` and `AuthRepository.registerStart` added and the route
  registered in the unauthenticated nav graph, reachable from Login (AND-030).
- All strings externalized; full a11y semantics (error association, live region,
  selector/toggle state, 48 dp targets, dynamic type, RTL).
- `@Preview`s for empty, valid-email, valid-sms, mismatch, submitting, and
  form-error states render in light and dark themes.
- Unit, repository/MockWebServer, and Compose UI tests (Section 11) pass in CI.
- No PII/credential logging; `password`/`confirm` excluded from saved state;
  CSRF header and cookie jar applied to the request; no auto-retry of the POST.
- Telemetry events wired at the defined interaction points.
- Builds clean with the project toolchain (Kotlin 2.0.21, AGP 8.7.3, JDK 17),
  passes lint/detekt, reviewed and merged to `android-port`.
