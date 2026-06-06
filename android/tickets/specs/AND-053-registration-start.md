---
id: AND-053
title: "Registration: start"
milestone: M2
epic: E08
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-030]
blocks: [AND-054]
---

# AND-053 — Registration: start

## 1. Overview & Goal

Build the **Register (start)** surface for the TestLogon native Android app: the
first step of self-service account creation. A logged-out user reaches this
screen from the Login screen's "Create account" link (AND-030) and enters their
profile and credentials (`full_name`, `email`, `password`, `confirm_password`),
and optionally opts in to MFA enrollment (SMS and/or TOTP). On valid submit the
app calls `POST /ui/register/start`, maps the `RegisterStartResp`
(`status` + `verification_required` + `delivery_medium`/`delivery_destination`
+ `session_id`), and routes forward to the confirmation step
(account-verification screen, AND-054) carrying the registrant's **email**
(the handle the confirm step keys on) and the resolved delivery medium.

> CORRECTED (review 2026-06-06): the web reference (`src/pages/Register.tsx`)
> has **no user-facing delivery-method selector**. `delivery_method` defaults to
> `email` server-side and the web never sends it. The phone field is shown only
> when the **SMS-MFA opt-in** is checked, not when an "sms delivery" is chosen.
> See §16 for the full audit; FR-5/FR-6/FR-13 below are amended accordingly.

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
the registrant email and resolved `delivery_medium`; validation failures and the
server's normalized `detail` string are surfaced inline without navigating.

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
    registrant **email** (the handle `POST /ui/register/confirm` keys on, via its
    `RegisterConfirmReq{email, confirmation_code}`) and the resolved
    `delivery_medium`/`delivery_destination` produced here, then calls
    `POST /ui/register/confirm` (and `POST /ui/register/resend`). The exact
    confirm/resend contracts are owned there. *Note: `RegisterStartResp` does
    **not** return a `challenge_id`; it returns `session_id` (used only on the
    no-verification auto-login path) — see §5.*
- **Reuses (core):** `core-network` (`ApiResult<T>`, OkHttp client with cookie
  jar AND-011, CSRF interceptor AND-012, 401-refresh authenticator AND-013,
  error/detail mapping AND-015), `core-model`, `core-ui` (theme + state
  composables AND-019/020/021).
- **Backend:** FastAPI + DynamoDB. Endpoint `POST /ui/register/start`
  (verified in `openapi.index.txt`: `op=register_start_ui_register_start_post`,
  `req=RegisterStartReq`, `resp=200:RegisterStartResp;422:HTTPValidationError`).
  The only documented responses are **200** (success) and **422**
  (validation). There is no documented `201` or `409`; the web additionally
  handles **429** (rate-limit) by surfacing the server `detail`. A sibling
  endpoint `POST /ui/register/check` (`RegisterEmailCheckReq` →
  `RegisterEmailCheckResp{status, available}`) is what the web uses to detect
  duplicate emails *before* submit; this ticket may adopt it (see §16 open
  assumptions). Dev host `http://18.222.237.167:8000` is plaintext HTTP and
  unreliable: ~20 s timeouts apply. `register/start` is a **non-idempotent
  POST** — it is **not** eligible for the idempotent-GET backoff retry
  (AND-016).
- **Web reference:** `frontend/src/api/endpoints/*.ts` (registration endpoint)
  and `frontend/src/api/types.ts` (`RegisterStartReq`, `RegisterStartResp`) for
  field names, delivery enum values, and IA parity.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Retrofit 2.11 /
  Moshi 1.15 / OkHttp 4.12, minSdk 24 / target 35, JDK 17.

## 3. Functional Requirements

FR-1 **Full name field.** Single-line `AppTextField`, capitalization `Words`,
autofill hint `name`, IME `Next`. Validation: non-blank (trimmed length ≥ 1).
*(CORRECTED: web requires only non-blank, `z.string().trim().min(1)`; the prior
"≥ 2" was not in the reference.)*

FR-2 **Email field.** Single-line, keyboard `Email`, autofill hint
`emailAddress`, IME `Next`. Validation: non-blank and matches
`android.util.Patterns.EMAIL_ADDRESS` (registration always requires a real
email, unlike Login which permits username).

FR-3 **Password field.** `PasswordField` (AND-020) with show/hide toggle,
autofill hint `newPassword`, IME `Next`. Validation **(CORRECTED to match web
policy in `src/pages/Register.tsx`):** length **12–128** characters and must
contain **at least one lowercase, one uppercase, one digit, and one special
character** (`[^A-Za-z0-9]`). The prior "≥ 8 characters" was wrong. A
requirement checklist + strength meter renders beneath the field, mirroring the
web's six requirement rows.

FR-4 **Confirm password field.** `PasswordField`, autofill hint `newPassword`,
IME `Done` (triggers submit when valid). Validation: non-blank and **must equal**
the password field; mismatch renders `FieldError.PasswordMismatch`.

FR-5 **Delivery method (no selector in v1).** *(CORRECTED.)* The web reference
exposes **no** delivery-method picker. `RegisterStartReq.delivery_method` is an
optional enum (`email`|`sms`, server default `email`) but the web **omits it
entirely** from the request. For IA parity, this screen **does not render a
delivery selector**; the request relies on the server default of `email`. The
`DeliveryMethod` enum is retained internally only to type the resolved
`delivery_medium` carried to AND-054. (If a selector is later wanted it is a
deliberate divergence from web, not parity — see §16.)

FR-6 **Phone number (conditional).** *(CORRECTED.)* Shown only when the **SMS
MFA opt-in** (`enable_sms_mfa`) is enabled — there is no "sms delivery" trigger.
Keyboard `Phone`, autofill hint `phoneNumber`. Validation: non-blank when
`enable_sms_mfa` is on (web rule: phone required iff `enable_sms_mfa`); a
plausible E.164-ish pattern is applied as a client nicety. The request sends
`phone` **only when `enable_sms_mfa` is true** (web: `phone: enable_sms_mfa ?
trimmedPhone : undefined`); otherwise `phone` is omitted/null.

FR-7 **Optional MFA opt-in.** Two independent toggles mapping to the wire flags
`enable_sms_mfa` and `enable_totp_mfa` *(CORRECTED from `enroll_*`)*. These are
passed to the backend as opt-in flags; actual factor enrollment occurs in the
verify/confirm + MFA-setup flow (AND-054) or post-login. Enabling
`enable_sms_mfa` makes the phone field (FR-6) required.

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

FR-11 **Success routing.** *(CORRECTED to mirror web `handleStart`.)* On a
successful `RegisterStartResp` with `verification_required = true`, navigate to
the confirm step (AND-054) passing the registrant **email** and the resolved
`delivery_medium`/`delivery_destination` (used for the "we sent a code via X to
Y" copy). If `verification_required = false`: when the response carries a
`session_id`, the user is already authenticated — fetch the session/profile and
route into the app (home), matching web's `getMe()`+`login()`+navigate("/")
path; when there is no `session_id`, show a success message and route to Login
("Continue to sign in"). The auto-login branch is owned/landed with AND-054's
session plumbing but the start screen must surface the correct outcome.

FR-12 **Back / Sign-in link.** A secondary affordance to return to Login
(`onNavigateToLogin()`), disabled while submitting.

FR-13 **IA parity.** *(CORRECTED.)* Field order, labels, and action hierarchy
match the web registration page: full name → email (with availability hint) →
password (+ requirement checklist + strength meter) → confirm password →
"Optional security upgrades" (TOTP toggle, then SMS toggle) → conditional phone
field → primary action (web copy: **"Request access"**, title **"Register"**) →
"Back to sign in" link. There is **no** delivery-method selector in the web IA
(see FR-5). Mirror the web button/title copy unless product decides otherwise.

## 4. Technical Design

Follows the project stateless-screen + state-holder pattern (as AND-030). The
route composable reads `StateFlow` and forwards callbacks; the inner composable
is pure and is what previews/UI tests exercise.

```kotlin
package com.testlogon.android.feature.auth.register

// Route-level entry; bound by the unauthenticated nav graph.
@Composable
fun RegisterRoute(
    // CORRECTED: confirm keys on EMAIL (RegisterConfirmReq), not a challenge_id.
    onNavigateToConfirm: (email: String, deliveryMedium: String?) -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: RegisterViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is RegisterEvent.GoToConfirm ->
                    onNavigateToConfirm(event.email, event.deliveryMedium)
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
// Retained to type the SERVER-RESOLVED delivery_medium carried to AND-054.
// NOT rendered as a user selector (see FR-5); register/start omits delivery_method.
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
    // CORRECTED: phone is required iff the SMS-MFA opt-in is on (web rule).
    // There is no "sms delivery" trigger in the web IA.
    val isPhoneRequired: Boolean get() = enrollSmsMfa
    val isSubmitEnabled: Boolean
        get() = !isSubmitting &&
            fullNameError == null && emailError == null &&
            passwordError == null && confirmError == null &&
            (!isPhoneRequired || (phone.isNotBlank() && phoneError == null)) &&
            fullName.isNotBlank() && email.isNotBlank() &&
            password.isNotBlank() && confirm.isNotBlank()
}

// FieldError extends the AND-030 enum surface with registration-specific cases.
// CORRECTED: split password failures into length vs complexity to mirror web copy.
enum class FieldError {
    Required, InvalidEmail, PolicyLength, PolicyComplexity, PasswordMismatch, InvalidPhone
}

object RegisterValidator {
    fun validateFullName(v: String): FieldError? = when {
        v.isBlank() -> FieldError.Required          // CORRECTED: web min is 1 (non-blank)
        else -> null
    }
    fun validateEmail(v: String): FieldError? = when {
        v.isBlank() -> FieldError.Required
        !Patterns.EMAIL_ADDRESS.matcher(v).matches() -> FieldError.InvalidEmail
        else -> null
    }
    // CORRECTED: web policy is 12..128 chars + lower + upper + digit + special.
    fun validatePassword(v: String): FieldError? = when {
        v.isBlank() -> FieldError.Required
        v.length < 12 || v.length > 128 -> FieldError.PolicyLength
        !v.any { it.isLowerCase() } -> FieldError.PolicyComplexity
        !v.any { it.isUpperCase() } -> FieldError.PolicyComplexity
        !v.any { it.isDigit() } -> FieldError.PolicyComplexity
        !v.any { !it.isLetterOrDigit() } -> FieldError.PolicyComplexity
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
    // CORRECTED: carry email (confirm handle) + resolved delivery_medium, not challenge_id.
    data class GoToConfirm(val email: String, val deliveryMedium: String?) : RegisterEvent
    data object GoToLoginSuccess : RegisterEvent
    data object GoToAppAuthenticated : RegisterEvent  // NEW: verification_required=false + session_id
}
```

Layout: `Scaffold` + scrollable `Column` with `imePadding()`. Order **(CORRECTED
to web IA — no delivery selector)**: header, error banner, full-name, email
(+ availability hint), password (+ requirement checklist + strength meter),
confirm password, "Optional security upgrades" (TOTP toggle, SMS toggle),
conditional phone field (shown when SMS MFA on), primary submit ("Request
access"), "Back to sign in" link. `@Preview`s: empty, valid (no MFA), valid
(SMS MFA on + phone), password-policy/mismatch error, submitting, form-error.

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

DTOs (Moshi) — **CORRECTED against `components.schemas.RegisterStartReq` /
`RegisterStartResp` in `openapi.pretty.json` and `src/api/types.ts`.** Prior
draft used `delivery`, `enroll_*`, and `challenge_id`, none of which exist on
the wire.

```kotlin
@JsonClass(generateAdapter = true)
data class RegisterStartReq(
    @Json(name = "full_name") val fullName: String,                 // required
    val email: String,                                              // required
    val password: String,                                           // required
    @Json(name = "confirm_password") val confirmPassword: String,   // required (NEW — was missing)
    @Json(name = "delivery_method") val deliveryMethod: String? = null, // optional; server default "email". Web OMITS it.
    @Json(name = "phone") val phone: String? = null,                // sent only when enable_sms_mfa = true
    @Json(name = "enable_sms_mfa") val enableSmsMfa: Boolean = false,   // was enroll_sms_mfa
    @Json(name = "enable_totp_mfa") val enableTotpMfa: Boolean = false, // was enroll_totp_mfa
)

@JsonClass(generateAdapter = true)
data class RegisterStartResp(
    val status: String,                                              // required (NEW — was missing)
    @Json(name = "verification_required") val verificationRequired: Boolean = false,
    @Json(name = "delivery_medium") val deliveryMedium: String? = null,        // was "delivery"
    @Json(name = "delivery_destination") val deliveryDestination: String? = null, // NEW
    @Json(name = "session_id") val sessionId: String? = null,        // was "challenge_id"
)
```

Request body example (matches web `handleStart`; `delivery_method` omitted,
`phone` present only because SMS MFA is opted in):

```json
{
  "full_name": "Ada Lovelace",
  "email": "ada@example.com",
  "password": "Ada!Lovelace2026",
  "confirm_password": "Ada!Lovelace2026",
  "phone": "+15551234567",
  "enable_sms_mfa": true,
  "enable_totp_mfa": true
}
```

Success (`200` only — there is no documented `201`):

```json
{
  "status": "verification_sent",
  "verification_required": true,
  "delivery_medium": "email",
  "delivery_destination": "a***@example.com",
  "session_id": null
}
```

Error (`422` validation) — FastAPI `HTTPValidationError` whose `detail` is an
array of `{loc, msg, type}`:

```json
{ "detail": [ { "loc": ["body", "email"], "msg": "field required", "type": "value_error.missing" } ] }
```

The shared transport (mirroring `src/api/client.ts`) **normalizes `detail` to a
single string** (string passthrough, or `detail[].msg` joined with ", ", or a
`{code,...}` object mapped to copy) and throws/returns it as one message — the
web does **not** map `loc` back to individual fields. Per AND-015 the Android
mapper should do the same: surface the normalized `detail` string in the form
banner. The web additionally special-cases **`429`** (rate limit) by showing the
server `detail` ("Too many registration attempts…"). The verify/confirm and
resend endpoints (`POST /ui/register/confirm`, `POST /ui/register/resend`),
which key on the registrant **email**, are owned by **AND-054**.

## 6. Data & State Management

- **Single source of truth:** `StateFlow<RegisterUiState>` in `RegisterViewModel`.
  The screen is stateless and renders via `collectAsStateWithLifecycle()`.
- **Repository layer:** a new `suspend fun registerStart(req): ApiResult<RegisterStartResp>`
  on `AuthRepository` (AND-028 family) wraps the `AuthApi` call and the
  ApiResult/error mapping; the ViewModel never touches Retrofit directly.
- **Navigation outcome:** one-shot `RegisterEvent` via `SharedFlow` (not state),
  preventing re-navigation on recomposition/rotation. The values carried to
  AND-054 are the **registrant email** (the confirm handle) and the
  **server-resolved** `delivery_medium`/`delivery_destination` from
  `RegisterStartResp` (CORRECTED: there is no client "delivery selection" and no
  `challenge_id`).
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
- **Server errors are surfaced as a normalized `detail` string in the banner**
  *(CORRECTED — the web does not field-map `loc`)*. The shared mapper flattens
  FastAPI `detail` (string / `detail[].msg` array / `{code,…}` object) to one
  message exactly as `src/api/client.ts:normalizeErrorDetail` does, and the
  ViewModel shows it in `formError`. Field-level focus mapping from `loc` is an
  **optional Android enhancement, NOT web parity** (see §16 open assumptions); if
  implemented it must degrade to the banner when `loc` is absent.
- **Duplicate email** is detected the way the web does: via the separate
  `POST /ui/register/check` (`available=false` → "An account with this email
  already exists"), surfaced as an inline email hint **before** submit. There is
  no `409` from `register/start`; a duplicate at submit time would arrive as a
  `422`/`detail` string and render in the banner.
- **Rate limiting:** `429` from `register/start` renders the server `detail`
  ("Too many registration attempts. Please wait and try again."), matching web
  `handleStart`. Non-retryable-by-spamming; user must wait.
- **Form-level errors:** `FormError.Network` (timeout/connection on the
  unreliable plaintext host) renders a retryable banner with copy reflecting the
  ~20 s timeout ("Couldn't reach the server. Check your connection and try
  again."); `FormError.Server` (5xx / unmapped) renders a generic retryable
  banner; `FormError.Validation` (`422`) renders the normalized detail string.
- **Duplicate-submit guard:** submit disabled while `isSubmitting`; the
  confirm-password IME `Done` is a no-op when `!isSubmitEnabled`.
- **verification_required=false:** treated as success. *(CORRECTED:)* if
  `session_id` is present the registrant is already authenticated → route into
  the app (web does `getMe()`+`login()`+navigate home); otherwise show a success
  message and route to Login ("Continue to sign in"). Never an error.
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
  `register_mfa_sms`, `register_mfa_totp`, `register_submit` ("Request access"),
  `register_sign_in` ("Back to sign in"), `register_error_required`,
  `register_error_invalid_email`, `register_error_password_length`,
  `register_error_password_complexity`, `register_error_password_mismatch`,
  `register_error_invalid_phone`, `register_error_network`,
  `register_email_unavailable` ("An account with this email already exists"),
  `register_error_rate_limited`. *(CORRECTED: removed `register_delivery_*`
  keys — no selector; split `too_short` into length/complexity to match web
  password copy.)*
- Field errors associated via `semantics { error(...) }`; the form-error banner
  is a `liveRegion` so it is announced on appearance.
- Delivery selector exposes selection state to TalkBack; MFA toggles announce
  on/off. Conditional phone field appearance is announced (focus moves logically).
- Touch targets ≥ 48 dp; sp typography with dynamic font scaling; content
  scrolls under the IME; RTL-safe (start/end). Color is never the sole error
  signal (icon + text), verified for Material 3 contrast in light/dark.

## 10. Telemetry & Logging

- `auth_register_view` on first composition.
- `auth_register_submit` with non-PII props: `sms_mfa` (bool), `totp_mfa`
  (bool) — never field values. *(CORRECTED: dropped a client `delivery` prop —
  there is no delivery selection; the resolved channel is only known from the
  response and is logged on success below.)*
- `auth_register_validation_error` with `field` and `reason` enums.
- `auth_register_error_shown` with `error_type`
  (`email_taken`|`validation`|`rate_limited`|`network`|`server`).
- `auth_register_success` with `verification_required` (bool) and resolved
  `delivery_medium`.
- `auth_register_link_tap` with `target` (`sign_in`).
- Structured logger at `debug`/`info`; no PII, no credentials, no request
  bodies. Analytics dispatch is invoked from the ViewModel at the defined points.

## 11. Testing Strategy

**Unit tests** (JVM, `core-testing`):
- `RegisterValidator` truth tables: full name (blank/valid), email
  (blank/malformed/valid), password (blank, <12, >128, missing lower/upper/
  digit/special, valid), confirm (blank/mismatch/match), phone (required-blank,
  required-invalid, required-valid, not-required-ignored).
- `RegisterUiState.isSubmitEnabled` / `isPhoneRequired` derivation across the
  `enable_sms_mfa` toggle (phone required iff on) and `enable_totp_mfa`.

**Repository / API tests** (MockWebServer harness AND-046):
- Valid `registerStart` produces the exact JSON body (snake_case field names:
  `full_name`, `email`, `password`, `confirm_password`, `enable_sms_mfa`,
  `enable_totp_mfa`; `delivery_method` omitted; `phone` present only when
  `enable_sms_mfa`) and parses `RegisterStartResp` to `ApiResult.Success` with
  `status`, `verificationRequired`, `deliveryMedium`, `deliveryDestination`,
  `sessionId`.
- `422` with a `detail` array → `ApiResult.Failure` carrying the normalized
  joined `detail[].msg` string (string-banner, not a field key).
- `429` → `ApiResult.Failure` carrying the server `detail` rate-limit string.
- CSRF header (`X-CSRF-Token` from `ui_csrf` cookie) present; cookies persisted
  via the cookie jar.
- Timeout/connection failure → mapped network failure (no auto-retry observed).

**Compose UI tests** (`feature-auth` androidTest, `createComposeRule`, fake
state — no network/Hilt):
- Typing updates rendered values via callbacks; submit disabled until all valid.
- Password mismatch surfaces `PasswordMismatch` under confirm; clears on fix.
- Enabling SMS MFA reveals the phone field and makes it required; disabling it
  hides the field and clears its requirement. (CORRECTED: no delivery selector.)
- `isSubmitting` disables fields/links and shows progress; no duplicate submit.
- `FormError.Network` shows retryable banner with working Retry; a `422`/`429`
  `detail` string renders in the banner (non-retryable for `429`).
- Sign-in link invokes `onNavigateToLogin`; success event routes to confirm with
  the registrant email + resolved `delivery_medium` (verified via fake event).

**A11y test:** error association + live-region announcement + toggle/selector
state assertions in the UI suite.

## 12. Dependencies & Sequencing

- **Blocked by:** **AND-030** (Login UI) — provides the entry link, the
  unauthenticated nav graph slot, and the reused core input composables and
  `FieldError`/`FormError` patterns. Transitively relies on landed
  `core-network` plumbing (AND-011/012/013/015), `AuthApi`/`AuthRepository`
  (AND-027/028), and core-ui (AND-019/020/021).
- **Blocks:** **AND-054** (registration confirm/verify) — consumes the
  registrant **email** and resolved `delivery_medium` produced here (confirm
  keys on email via `RegisterConfirmReq`).
- **Sequencing:** add the `RegisterStartReq`/`RegisterStartResp` DTOs and the
  `AuthApi.registerStart` method and `AuthRepository.registerStart` first
  (testable via MockWebServer), then the stateless `RegisterScreen` +
  `RegisterUiState` + `RegisterValidator` + previews + UI tests, then wire
  `RegisterRoute` with `hiltViewModel()` and register the route in the nav graph.

## 13. Risks & Open Questions

- **R1 — Schema drift.** *RESOLVED at review.* `RegisterStartReq` =
  `{full_name, email, password, confirm_password, delivery_method?(email|sms,
  default email), phone?, enable_sms_mfa, enable_totp_mfa}`; `RegisterStartResp`
  = `{status (required), verification_required, delivery_medium?,
  delivery_destination?, session_id?}`. The delivery enum is exactly
  `email|sms`. MFA opt-in flags **are** accepted at `register/start` (the web
  passes them); factor *enrollment* still happens later (confirm/MFA-setup).
- **R2 — Field-error mapping.** *RESOLVED.* The web does **not** map `detail[].loc`
  to fields; it shows a normalized `detail` string in a banner. Android should
  match. `loc`-based field focus is an optional enhancement, not parity.
- **R3 — Password policy.** *RESOLVED for the web client:* 12–128 chars + lower +
  upper + digit + special. Server `422` remains authoritative if backend policy
  differs; client mirrors web.
- **R4 — Delivery vs phone coupling.** *RESOLVED.* `register/start` accepts an
  optional `phone`; the web sends it **only when `enable_sms_mfa` is true** and
  never renders a delivery selector. No "sms delivery" coupling exists.
- **R5 — verification_required=false path.** *RESOLVED.* Backend may return it;
  the web auto-logs-in when `session_id` is present (else shows success → Login).
  See FR-11.
- **R6 — Email pre-check (open).** Whether to port `POST /ui/register/check`
  (debounced availability check) into this ticket or defer it. The web couples it
  to the start screen; this spec treats it as an optional adopt (see §16).

## 14. Acceptance Criteria

AC-1 A fully valid form (full name, valid email, policy-passing password,
matching confirm, valid delivery and any required phone) enables submit; any
invalid/blank required field keeps it disabled. (UI-tested.)

AC-2 Field-level validation (required, invalid email, too-short password,
password mismatch, invalid/missing phone when required) surfaces under the
correct field on blur/submit and clears on correction. (UI-tested.)

AC-3 Enabling **SMS MFA** reveals and requires the phone field; disabling it
hides the field and drops the requirement. There is no delivery selector.
(UI-tested.) *(CORRECTED.)*

AC-4 Valid submit issues `POST /ui/register/start` with the exact JSON contract
(§5): keys `full_name`, `email`, `password`, `confirm_password`,
`enable_sms_mfa`, `enable_totp_mfa`, with `phone` present only when SMS MFA is on
and `delivery_method` omitted; CSRF header (`X-CSRF-Token`) and cookie jar
applied. (Repository/MockWebServer test.)

AC-5 A successful `RegisterStartResp` maps `status`/`verification_required`/
`delivery_medium`/`delivery_destination`/`session_id` and (when
`verification_required`) routes to the confirm step (AND-054) with the registrant
**email** + resolved `delivery_medium`; when `verification_required=false` it
routes per FR-11. The navigation event fires exactly once. (Tested via fake
event.) *(CORRECTED: was `delivery`/`challenge_id`.)*

AC-6 Server errors are surfaced: `422`/`429` `detail` renders as a normalized
string in the banner (`429` non-retryable); duplicate email is shown via the
`register/check` availability hint; network/timeout shows a retryable banner with
working Retry; no auto-retry of the POST occurs. (UI + repository tests.)
*(CORRECTED: no `409`/field-mapping in web.)*

AC-7 Loading state disables the form and shows progress; no duplicate submits.
(UI-tested.)

AC-8 Behavior and IA (field order, labels, action hierarchy, no delivery
selector, "Request access" submit copy) match the web registration reference.
(Screenshot/IA comparison.) *(CORRECTED: removed "delivery options".)*

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.

1. **Endpoint is `POST /ui/register/start`.** VERIFIED.
   `openapi.index.txt`: `POST /ui/register/start | op=register_start_ui_register_start_post`;
   `src/api/endpoints/auth.ts: registerStart` → `api.post<RegisterStartResp>("/ui/register/start", body)`.
2. **Only documented responses are `200` (RegisterStartResp) and `422`
   (HTTPValidationError); no `201`/`409`.** CORRECTED (spec had `200`/`201` and
   `409`/`422`). `openapi.index.txt`: `resp=200:RegisterStartResp;422:HTTPValidationError`.
3. **`RegisterStartReq` fields = `full_name`, `email`, `password`,
   `confirm_password` (all required), `delivery_method?` (enum `email|sms`,
   default `email`), `phone?` (nullable), `enable_sms_mfa`, `enable_totp_mfa`.**
   CORRECTED (spec had `delivery`, `enroll_sms_mfa`, `enroll_totp_mfa`, and was
   missing `confirm_password`). `openapi.pretty.json: components.schemas.RegisterStartReq`;
   `src/api/types.ts: RegisterStartReq` (lines 240–249).
4. **`RegisterStartResp` fields = `status` (required string),
   `verification_required` (bool, default false), `delivery_medium?`,
   `delivery_destination?`, `session_id?`.** CORRECTED (spec had `delivery` +
   `challenge_id`, and omitted `status`/`delivery_destination`/`session_id`).
   `openapi.pretty.json: components.schemas.RegisterStartResp`;
   `src/api/types.ts: RegisterStartResp` (lines 251–257).
5. **The confirm step keys on the registrant EMAIL, not a `challenge_id`.**
   CORRECTED. `src/api/types.ts: RegisterConfirmReq` = `{email, confirmation_code}`;
   `src/pages/Register.tsx: handleConfirm` calls `registerConfirm({ email: registeredEmail, confirmation_code })`.
   `RegisterStartResp` has no `challenge_id`.
6. **No delivery-method selector exists in the web UI; `delivery_method` is
   omitted from the request and relies on the server default `email`.**
   CORRECTED. `src/pages/Register.tsx: handleStart` (lines 278–286) sends no
   `delivery_method`; the JSX (start step) renders no delivery control.
7. **Phone field is shown/required only when `enable_sms_mfa` is on; `phone` is
   sent only then.** CORRECTED (spec coupled it to "sms delivery").
   `src/pages/Register.tsx`: `{enableSmsMfa && (<phone input>)}` (line 769);
   zod `superRefine` requires phone iff `enable_sms_mfa` (lines 48–54);
   `phone: data.enable_sms_mfa ? trimmedPhone : undefined` (line 283).
8. **Password policy = 12–128 chars + lowercase + uppercase + digit + special
   character.** CORRECTED (spec said "≥ 8"). `src/pages/Register.tsx:
   registerSchema.password` (lines 29–35).
9. **Full-name validation = non-blank (min 1).** CORRECTED (spec said "≥ 2").
   `src/pages/Register.tsx`: `full_name: z.string().trim().min(1, ...)` (line 27).
10. **CSRF: `X-CSRF-Token` header is set from the `ui_csrf` cookie; requests use
    cookie credentials.** VERIFIED. `src/api/client.ts` (lines 167–171, 183
    `credentials: "include"`). Matches spec AND-011/AND-012 claims.
11. **Error `detail` is normalized to a single string (string passthrough /
    `detail[].msg` joined / `{code,…}` mapped); the web does NOT map `loc` to
    fields.** CORRECTED (spec proposed `loc`-based field mapping as parity).
    `src/api/client.ts: normalizeErrorDetail` (lines 66–102); `ApiError.detail`
    is typed `string` (lines 106–115); `Register.tsx` shows `err.detail` in a
    banner (lines 318–326).
12. **`429` (rate limit) is handled by showing the server `detail`.** VERIFIED.
    `src/pages/Register.tsx: handleStart` catch (lines 318–321).
13. **Duplicate-email is detected pre-submit via `POST /ui/register/check`
    (`RegisterEmailCheckResp{status, available}`), not via a `409` on start.**
    VERIFIED. `openapi.index.txt`: `POST /ui/register/check`;
    `openapi.pretty.json: RegisterEmailCheckResp`; `src/pages/Register.tsx`
    debounced `registerEmailCheck` effect (lines 218–267) and `emailStatus ===
    "unavailable"` hint (lines 616–621).
14. **`verification_required=false` path: if `session_id` present, the web
    auto-logs-in (`getMe()` + `login()` + navigate "/"); else success → Login.**
    VERIFIED. `src/pages/Register.tsx: handleStart` else-branch (lines 307–316).
15. **MFA opt-in flags are accepted at `register/start` (factor enrollment
    happens later).** VERIFIED. Present on `RegisterStartReq`
    (`openapi.pretty.json`); enrollment occurs in the `mfa` step
    (`src/pages/Register.tsx` lines 401–500) and `account` endpoints.
16. **Submit copy "Request access"; title "Register"; "Back to sign in" link.**
    VERIFIED. `src/pages/Register.tsx` (lines 525, 796, 806).
17. **Stack/toolchain choices (Compose, Material 3, Hilt, Retrofit/Moshi/OkHttp,
    SavedStateHandle exclusion of secrets).** UNVERIFIED-ASSUMPTION (project
    convention; not derivable from backend/frontend sources). Framework refs:
    Compose state hoisting — https://developer.android.com/develop/ui/compose/state ;
    `collectAsStateWithLifecycle` — https://developer.android.com/topic/libraries/architecture/coroutines#viewmodelscope ;
    autofill `newPassword`/`emailAddress` hints — https://developer.android.com/guide/topics/text/autofill ;
    accessibility/TalkBack semantics — https://developer.android.com/develop/ui/compose/accessibility .

### Corrections made

- §1/§5/§6: response carries `status`/`delivery_medium`/`delivery_destination`/
  `session_id`; **`challenge_id` does not exist** — confirm keys on email.
- §5 DTOs: `delivery` → `delivery_method`; `enroll_*` → `enable_*`; added
  required `confirm_password`; added `status`/`delivery_destination`.
- §5: removed `201`/`409`; documented `200`/`422`/`429` and string-normalized
  `detail`; added the `register/check` duplicate-email mechanism.
- §3 FR-3: password policy 12–128 + 4 character classes (was "≥ 8").
- §3 FR-1: full name non-blank (was "≥ 2").
- §3 FR-5/FR-6/FR-13 + §4 layout/state + §14 AC-3/AC-8: removed the
  delivery-method selector (not in web IA); phone tied to `enable_sms_mfa`.
- §4 validator/`FieldError`: split into `PolicyLength`/`PolicyComplexity`;
  `isPhoneRequired = enableSmsMfa`.
- §4 `RegisterEvent`/route: carry `email` + `deliveryMedium`; added
  `GoToAppAuthenticated` for the `session_id` auto-login branch.
- §7: error handling is banner-by-normalized-string + `429`; no `loc` field
  mapping (now an optional enhancement); duplicate email via `register/check`.
- §9 strings, §10 telemetry, §11 tests: aligned to the above.
- §13 risks R1–R5 marked RESOLVED; added R6 (email pre-check scope).
- Frontmatter: `status: reviewed`, `reviewed_on: 2026-06-06`.

### Open assumptions

- **Optional `loc`-based field focus** (mapping `detail[].loc` to a field) is NOT
  web behavior; if Android adds it, treat as enhancement and fall back to the
  banner. Unverifiable as parity because the web has no such mapping.
- **Adopting `POST /ui/register/check`** (debounced email availability) into this
  ticket vs deferring is a product/scope call; the web couples it to the start
  screen. Endpoint verified; inclusion in AND-053 scope is the open item.
- **`status` string enum values** (e.g., `"verification_sent"`) are not
  enumerated in the schema (free-form `string`); the example value is
  illustrative. Treat `verification_required`/`session_id` as the branching
  signals, not `status` text.
- **Backend password policy parity:** the 12–128 + complexity rule is the web
  client's rule; the server's exact policy is not in the OpenAPI schema (plain
  `string`). Server `422` stays authoritative on mismatch.
- **Android stack/toolchain & a11y/security specifics** (Hilt, Moshi, FLAG_SECURE
  deferral, SavedStateHandle exclusion) are project conventions, not verifiable
  from backend/frontend sources (framework refs cited in item 17).

## 17. Test Plan

Acceptance-criteria traceability uses the §14 IDs (AC-1…AC-9). Test targets:
**JVM** = Robolectric/JVM unit (no device); **emulator** = AVD `test35`
(x86_64, API 35); **device** = Samsung Galaxy A15 5G (SM-A156U, API 34,
arm64-v8a). This ticket is a form + JSON-contract screen with no
camera/biometric/WebRTC/FCM behavior, so almost everything runs on JVM/emulator;
one ABI/API-parity smoke is called out for the physical device.

- **TC-AND-053-01 — Validator truth tables.**
  Type: unit (JVM). Target: JVM. Preconditions: `RegisterValidator` available.
  Steps: drive `validateFullName` (blank→Required, "A"→null), `validateEmail`
  (blank→Required, "a@"→InvalidEmail, valid→null), `validatePassword`
  (blank→Required, 11-char→PolicyLength, 129-char→PolicyLength, "alllower1!"→
  PolicyComplexity, "Abcdefghij1!"→null), `validateConfirm`
  (blank→Required, mismatch→PasswordMismatch, equal→null), `validatePhone`
  (required+blank→Required, required+"abc"→InvalidPhone, required+"+15551234567"
  →null, not-required→null). Expected: every case returns the listed
  `FieldError?`. Traces: AC-2.

- **TC-AND-053-02 — `isSubmitEnabled` / `isPhoneRequired` derivation.**
  Type: unit (JVM). Target: JVM. Preconditions: `RegisterUiState`.
  Steps: toggle `enableSmsMfa` on/off with/without phone; set field errors null
  vs set; flip `isSubmitting`. Expected: `isPhoneRequired == enableSmsMfa`;
  `isSubmitEnabled` false when any error set, any required field blank, phone
  required-but-invalid, or `isSubmitting`; true only when all pass. Traces:
  AC-1, AC-3, AC-7.

- **TC-AND-053-03 — Happy-path request body + response mapping
  (contract).** Type: contract/MockWebServer. Target: JVM. Preconditions:
  MockWebServer enqueues `200 {status:"verification_sent",
  verification_required:true, delivery_medium:"email",
  delivery_destination:"a***@example.com", session_id:null}`. Steps: call
  `AuthRepository.registerStart` with full name/email/password/confirm,
  `enable_totp_mfa=true`, SMS off. Expected: recorded request is `POST
  /ui/register/start`; JSON body has exactly `full_name`, `email`, `password`,
  `confirm_password`, `enable_sms_mfa:false`, `enable_totp_mfa:true`; **no**
  `delivery_method`; **no** `phone` (or null). Response → `ApiResult.Success`
  with `status`, `verificationRequired=true`, `deliveryMedium="email"`,
  `deliveryDestination`, `sessionId=null`. Traces: AC-4, AC-5.

- **TC-AND-053-04 — SMS-MFA body includes phone (contract).**
  Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue any `200`.
  Steps: call `registerStart` with `enable_sms_mfa=true`, phone
  `"+15551234567"`. Expected: body contains `enable_sms_mfa:true` and
  `phone:"+15551234567"`. Conversely, with `enable_sms_mfa=false` and a phone
  string present, `phone` is omitted/null. Traces: AC-3, AC-4.

- **TC-AND-053-05 — CSRF header + cookie jar applied (contract).**
  Type: contract/MockWebServer. Target: JVM. Preconditions: seed the cookie jar
  with a `ui_csrf` cookie; enqueue `200`. Steps: call `registerStart`. Expected:
  recorded request carries `X-CSRF-Token` equal to the `ui_csrf` value and sends
  the cookie header; any `Set-Cookie` on the response is persisted by the jar.
  Traces: AC-4.

- **TC-AND-053-06 — `422` validation error → normalized banner string
  (contract).** Type: contract/MockWebServer. Target: JVM. Preconditions:
  enqueue `422 {detail:[{loc:["body","email"],msg:"field required",
  type:"value_error.missing"}]}`. Steps: call `registerStart`. Expected:
  `ApiResult.Failure` whose message equals the joined `detail[].msg`
  ("field required"); no per-field key is required (banner display). Traces:
  AC-6.

- **TC-AND-053-07 — `429` rate-limit → server detail string (contract).**
  Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue `429
  {detail:"Too many registration attempts. Please wait and try again."}`. Steps:
  call `registerStart`. Expected: `ApiResult.Failure` carrying that exact string;
  classified as non-retryable rate-limit (no auto-resubmit). Traces: AC-6.

- **TC-AND-053-08 — Offline / flaky-dev-host timeout, no auto-retry
  (integration).** Type: integration (MockWebServer + dispatcher). Target: JVM.
  Preconditions: MockWebServer set to no-response/socket-policy delay beyond the
  client timeout (simulating the ~20 s plaintext dev host), or disconnect.
  Steps: call `registerStart`. Expected: a single request is made (assert
  `takeRequest` count == 1 — POST is **not** auto-retried), result is a mapped
  network `ApiResult.Failure`; the UI maps it to a retryable `FormError.Network`
  banner. Traces: AC-6.

- **TC-AND-053-09 — Form gating + password/confirm validation (Compose-UI).**
  Type: Compose-UI. Target: emulator. Preconditions: `RegisterScreen` with fake
  state holder (no Hilt/network). Steps: assert submit disabled when empty; type
  full name, valid email, a policy-passing password, a mismatching confirm →
  assert `PasswordMismatch` shown under confirm and submit disabled; fix confirm
  → error clears and submit enables. Also enter an 11-char password → assert
  policy-length error. Expected: matches assertions. Traces: AC-1, AC-2, AC-7.

- **TC-AND-053-10 — SMS-MFA reveals/requires phone; no delivery selector
  (Compose-UI).** Type: Compose-UI. Target: emulator. Preconditions: fake state.
  Steps: assert no delivery selector node exists; enable SMS MFA → phone field
  appears and becomes required (submit blocked until a valid phone); disable SMS
  MFA → phone field hidden and requirement dropped. Expected: matches. Traces:
  AC-3, AC-8.

- **TC-AND-053-11 — Loading state + duplicate-submit guard (Compose-UI).**
  Type: Compose-UI. Target: emulator. Preconditions: fake state with
  `isSubmitting=true`. Steps: assert submit shows progress and is disabled, all
  fields/toggles/links disabled; tapping submit (or confirm IME Done) emits no
  second submit callback. Expected: exactly zero additional submit invocations.
  Traces: AC-7.

- **TC-AND-053-12 — Navigation events fire once (Compose-UI + fake events).**
  Type: Compose-UI. Target: emulator. Preconditions: fake event flow.
  Steps: emit `GoToConfirm(email, "email")` once → assert `onNavigateToConfirm`
  invoked exactly once with that email + medium; recompose/rotate → no
  re-navigation. Emit `GoToLoginSuccess` → `onNavigateToLogin` once; emit
  `GoToAppAuthenticated` → app-home callback once. Expected: each fires exactly
  once. Traces: AC-5.

- **TC-AND-053-13 — Accessibility semantics (Compose-UI a11y).**
  Type: Compose-UI (a11y assertions). Target: emulator. Preconditions: fake
  state with a field error and a form error set. Steps: assert the errored field
  exposes `SemanticsProperties.Error`; the form-error banner is a `liveRegion`;
  SMS/TOTP toggles expose on/off state; touch targets ≥ 48 dp; error conveyed by
  icon+text (not color alone). Expected: all assertions pass in light and dark.
  Traces: AC-2, AC-8, AC-9.

- **TC-AND-053-14 — Secrets excluded from saved state; no PII/credential logs
  (instrumented).** Type: instrumented. Target: emulator. Preconditions: a
  logging spy/test tree; `SavedStateHandle`-backed ViewModel. Steps: type all
  fields incl. password/confirm; trigger save→restore (config change / process
  death simulation); submit and inspect captured logs/analytics. Expected:
  `password`/`confirm` are blank after restore (excluded); non-sensitive fields
  restored; no log/analytics record contains `password`, `email`, `full_name`,
  or `phone` values (only structural booleans). Traces: AC-9.

- **TC-AND-053-15 — ABI/API parity smoke on physical device (instrumented/e2e).**
  Type: instrumented/e2e. Target: **physical device (SM-A156U, API 34,
  arm64-v8a) — MUST run here** to catch arm64-vs-x86 ABI and API-34-vs-35
  differences not covered by the API-35 x86_64 emulator. Preconditions: app
  installed on the device; MockWebServer or a stubbed base URL reachable from the
  device. Steps: drive the full happy path (fill form → submit → observe
  navigation to confirm) and the autofill `newPassword`/`emailAddress` hints
  surfacing. Expected: renders and behaves identically to the emulator; no
  ABI-specific crash; autofill hints present. Traces: AC-1, AC-4, AC-5, AC-8.

### Coverage matrix

| AC | Covered by |
| --- | --- |
| AC-1 (submit gating) | TC-02, TC-09, TC-15 |
| AC-2 (field validation) | TC-01, TC-09, TC-13 |
| AC-3 (SMS-MFA → phone) | TC-02, TC-04, TC-10 |
| AC-4 (exact request + CSRF/cookies) | TC-03, TC-04, TC-05, TC-15 |
| AC-5 (response mapping + single nav) | TC-03, TC-12, TC-15 |
| AC-6 (server/network errors, no auto-retry) | TC-06, TC-07, TC-08 |
| AC-7 (loading + no duplicate submit) | TC-02, TC-09, TC-11 |
| AC-8 (IA parity, no selector) | TC-10, TC-13, TC-15 |
| AC-9 (no PII logs, secrets out of saved state) | TC-13, TC-14 |
