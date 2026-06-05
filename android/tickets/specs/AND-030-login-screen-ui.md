---
id: AND-030
title: Login screen UI
milestone: M1
epic: E04
priority: P0
size: M
status: draft
depends_on: [AND-020, AND-023]
blocks: [AND-031, AND-053, AND-057, AND-060, AND-063]
---

# AND-030 — Login screen UI

## 1. Overview & Goal

Build the stateless Login screen for the TestLogon native Android app: the first
interactive surface a logged-out user sees and the start destination of the
unauthenticated navigation graph (AND-023). The screen presents an
email/password form with inline validation, a show/hide password affordance,
links to recovery and registration, an entry point for overriding the server
base URL, a submit button gated on validity, and a region for surfacing
server/network errors.

This ticket is strictly the **presentation layer**: the Composable screen, its
hoisted `LoginUiState`, an event/callback surface, and the local validation
logic. It does **not** own the network call, cookie/CSRF handling, or the
MFA-vs-home branching decision — those belong to `LoginViewModel` (AND-031)
which consumes `AuthRepository` (AND-028). The goal is a fully UI-testable,
preview-driven screen whose behavior and information architecture (IA) match the
web reference login page (`frontend/`), wired into the nav graph and ready for
the ViewModel to drop in behind it.

Definition of success: a Compose UI test drives the form end-to-end (typing,
toggling, error rendering, submit-enable) against a fake state holder with no
network, and the rendered IA is verified to match the web login screen.

## 2. Context & References

- **Module:** `feature-auth` (Gradle module `:feature-auth`), package
  `com.testlogon.android.feature.auth.login`.
- **Depends on:**
  - **AND-020** — Core input composables (`AppButton`, `AppTextField` with
    error/helper, `PasswordField` with show/hide). The Login screen composes
    these rather than raw Material 3 widgets.
  - **AND-023** — Unauthenticated nav graph. Login is the start destination;
    this screen exposes navigation callbacks the graph binds.
- **Consumed by (blocks):**
  - **AND-031** — `LoginViewModel` provides the real `StateFlow<LoginUiState>`
    and `onSubmit` handler; replaces the fake holder used in this ticket's tests.
  - **AND-053 / AND-057 / AND-060 / AND-063** — recovery, register, magic-link,
    and related auth surfaces reached via this screen's navigation callbacks.
- **Backend (informational, owned downstream):** cookie-based auth begins at
  `POST /ui/session/start` with `{challenge_context:{username,password}}`.
  OpenAPI at `http://18.222.237.167:8000/openapi.json`.
- **Web reference:** `frontend/src/api/endpoints/*.ts` (auth endpoints) and the
  web login route for IA parity (field order, labels, link placement, error
  presentation).
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, Hilt (KSP),
  Navigation-Compose, minSdk 24 / target 35, JDK 17.

## 3. Functional Requirements

FR-1 **Email/username field.** Single-line text field, keyboard type `Email`,
autofill hint `emailAddress`/`username`, IME action `Next`. Label and helper
match web copy. The backend field is `username`; the UI labels it per web (email).

FR-2 **Password field.** Uses `PasswordField` (AND-020) with a trailing
show/hide toggle (default obscured), keyboard type `Password`, autofill hint
`password`, IME action `Done` which triggers submit when the form is valid.

FR-3 **Inline validation.**
- Email/username: non-blank; if it contains `@`, must match a basic email
  pattern (`android.util.Patterns.EMAIL_ADDRESS`). Otherwise treated as a
  non-empty username.
- Password: non-blank.
- Errors render beneath the offending field. Field-level errors appear on blur
  or on submit attempt, not on first keystroke (avoid premature error noise).

FR-4 **Submit gating.** The submit button is enabled only when both fields pass
local validation **and** the screen is not in a loading state. Tapping submit
(or password IME `Done`) invokes `onSubmit(email, password)`.

FR-5 **Loading state.** While `isSubmitting` is true: button shows a progress
indicator and is disabled, fields are read-only/disabled, navigation links are
disabled. No spinner-blocking full-screen overlay.

FR-6 **Server/network error display.** A dismissible error banner (or inline
form error) renders `state.formError` text when present. Distinguishes
credential errors (e.g., "Invalid email or password") from
network/offline/timeout states with appropriate copy and a Retry affordance for
retryable errors.

FR-7 **Recovery & register links.** Two text-link affordances invoking
`onForgotPassword()` and `onRegister()`. Placement/labels match web IA.

FR-8 **Server-URL entry point.** A discoverable but secondary affordance
(overflow/settings icon or "Advanced" expander) opening a base-URL editor,
invoking `onEditServerUrl()`. The screen displays the current effective base URL
(passed in `state.serverUrlLabel`) but does not itself persist it (DataStore
persistence is owned by the server-config ticket; this screen only triggers the
flow and reflects the value).

FR-9 **IA parity.** Field order, primary/secondary action hierarchy, and link
labels match the web login page so the two clients are recognizably the same
product.

## 4. Technical Design

The screen follows the project's stateless-screen + state-holder pattern. The
public route-level composable reads state from a `StateFlow` and forwards
callbacks; the inner composable is pure (state in, events out) and is what UI
tests and previews exercise.

```kotlin
package com.testlogon.android.feature.auth.login

// Route-level entry; bound by the unauthenticated nav graph (AND-023).
@Composable
fun LoginRoute(
    onNavigateToMfa: (challengeId: String) -> Unit,
    onNavigateToHome: () -> Unit,
    onForgotPassword: () -> Unit,
    onRegister: () -> Unit,
    onEditServerUrl: () -> Unit,
    viewModel: LoginViewModel = hiltViewModel(), // provided by AND-031
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    // Navigation side-effects are consumed from one-shot events emitted by the
    // ViewModel (AND-031). This ticket only renders state + forwards intents.
    LoginScreen(
        state = state,
        onEmailChange = viewModel::onEmailChange,
        onPasswordChange = viewModel::onPasswordChange,
        onTogglePasswordVisibility = viewModel::onTogglePasswordVisibility,
        onSubmit = viewModel::onSubmit,
        onDismissError = viewModel::onDismissError,
        onForgotPassword = onForgotPassword,
        onRegister = onRegister,
        onEditServerUrl = onEditServerUrl,
    )
}

// Stateless, fully testable/previewable screen. This is the deliverable of AND-030.
@Composable
fun LoginScreen(
    state: LoginUiState,
    onEmailChange: (String) -> Unit,
    onPasswordChange: (String) -> Unit,
    onTogglePasswordVisibility: () -> Unit,
    onSubmit: () -> Unit,
    onDismissError: () -> Unit,
    onForgotPassword: () -> Unit,
    onRegister: () -> Unit,
    onEditServerUrl: () -> Unit,
)
```

State and validation contracts owned by this ticket (the ViewModel in AND-031
populates and mutates them):

```kotlin
@Immutable
data class LoginUiState(
    val email: String = "",
    val password: String = "",
    val isPasswordVisible: Boolean = false,
    val emailError: FieldError? = null,
    val passwordError: FieldError? = null,
    val formError: FormError? = null,
    val isSubmitting: Boolean = false,
    val serverUrlLabel: String = "",
) {
    val isSubmitEnabled: Boolean
        get() = !isSubmitting &&
            email.isNotBlank() && password.isNotBlank() &&
            emailError == null && passwordError == null
}

enum class FieldError { Required, InvalidEmail }

sealed interface FormError {
    val message: String
    val retryable: Boolean
    data class Credentials(override val message: String) : FormError { override val retryable = false }
    data class Network(override val message: String) : FormError { override val retryable = true }
    data class Server(override val message: String) : FormError { override val retryable = true }
}
```

Pure validation lives in a stateless helper so both the screen (for IME/submit
gating) and the ViewModel (AND-031) share one source of truth:

```kotlin
object LoginValidator {
    fun validateEmail(raw: String): FieldError? = when {
        raw.isBlank() -> FieldError.Required
        '@' in raw && !Patterns.EMAIL_ADDRESS.matcher(raw).matches() -> FieldError.InvalidEmail
        else -> null
    }
    fun validatePassword(raw: String): FieldError? =
        if (raw.isBlank()) FieldError.Required else null
}
```

Layout: a `Column` inside a `Scaffold`, vertically scrollable
(`verticalScroll`) and `imePadding()`-aware so the keyboard never occludes the
submit button. Composition order top-to-bottom: app/brand header, optional error
banner, email field, password field, recovery link, primary submit button,
register link, server-URL/advanced affordance. Uses `core-ui` theme tokens
(spacing, typography) so it matches the rest of the app. `@Preview` functions
cover empty, filled-valid, validation-error, submitting, and form-error states.

## 5. API Contract

**N/A for this ticket.** The Login screen issues no network calls. The auth API
contract — `POST /ui/session/start` with body
`{"challenge_context":{"username":"<email>","password":"<pw>"}}` returning
`{"auth_required":bool,"challenge_id":"...","required_factors":[...]}`, the
cookie + `ui_csrf`/`X-CSRF-Token` handling, the single `POST /ui/session/refresh`
retry on 401, and `GET /ui/me` — is owned by **AND-028** (`AuthRepository`) and
surfaced to this screen exclusively through `LoginViewModel` (**AND-031**). This
spec only defines the in-process contract between screen and state holder
(Section 4) and the error mapping the ViewModel must populate (Section 7).

## 6. Data & State Management

- **Single source of truth:** `StateFlow<LoginUiState>` from `LoginViewModel`
  (AND-031). The screen is stateless and renders the latest snapshot via
  `collectAsStateWithLifecycle()`.
- **Local UI state:** only ephemeral focus/blur tracking and IME state live in
  the composition (`remember`); all durable form state is hoisted into
  `LoginUiState`.
- **Configuration changes / process death:** because state is held in the
  ViewModel's `SavedStateHandle`-backed flow (AND-031), email text and visibility
  survive rotation. Password is intentionally **not** restored across process
  death (security; see Section 8). This ticket ensures the screen re-renders
  correctly from any restored `LoginUiState`.
- **Server URL:** `serverUrlLabel` is read-only input to the screen; persistence
  (DataStore prefs) and the editor dialog are external. The screen reflects the
  current value and triggers `onEditServerUrl()`.
- **Validation timing:** errors are derived state computed by the ViewModel from
  `LoginValidator` on blur/submit; the screen never silently mutates state.

## 7. Error Handling & Resilience

The screen renders errors; it does not classify network failures (that mapping
is in AND-028/AND-031). Required rendering behavior:

- `FormError.Credentials` → non-retryable inline form error, focus returns to
  email field, password is cleared by the ViewModel; no Retry button.
- `FormError.Network` → retryable banner with a Retry action that re-invokes
  `onSubmit`; copy reflects the unreliable plaintext dev host and ~20s timeout
  reality ("Couldn't reach the server. Check your connection and try again.").
- `FormError.Server` → retryable banner with generic server-error copy.
- Field errors (`Required`, `InvalidEmail`) render under the field and clear as
  soon as the field becomes valid on subsequent edits.
- Submit is disabled while `isSubmitting`, preventing duplicate requests; the
  password IME `Done` action is a no-op when `!isSubmitEnabled`.
- Error banner is dismissible via `onDismissError`; dismissing clears
  `formError` without altering field contents.
- FastAPI `detail` shapes (`string | [{msg}] | {code,...}`) are normalized to a
  user-facing `FormError.message` upstream; this screen only displays the string.

## 8. Security & Privacy

- Password field uses `PasswordVisualTransformation` by default and a deliberate
  show/hide toggle; the field carries the `password` autofill hint.
- Password is **excluded** from any `SavedStateHandle`/`rememberSaveable`
  persistence so it is not written to disk on process death.
- No credentials are logged. Telemetry (Section 10) records only event names and
  non-PII flags; `email`/`password` values are never included in logs or
  analytics.
- The screen reflects but does not validate transport security. Because the dev
  backend is plaintext HTTP, the server-URL editor (downstream) must warn on
  non-HTTPS; this screen passes through whatever label it is given.
- `android:autofillHints` configured so the platform credential manager / autofill
  can populate fields; no custom credential storage in this ticket.
- Consider `FLAG_SECURE` for the auth flow window is deferred to a global policy
  ticket; not enabled here.

## 9. Accessibility & i18n

- All strings sourced from `strings.xml` (`feature-auth` resources); no
  hard-coded user-facing text. Keys: `login_title`, `login_email_label`,
  `login_password_label`, `login_submit`, `login_forgot_password`,
  `login_register`, `login_server_url`, `login_error_credentials`,
  `login_error_network`, `login_error_required`, `login_error_invalid_email`.
- Every interactive element has a `contentDescription`/semantics; the show/hide
  toggle announces its current state ("Show password" / "Hide password").
- Field errors are associated with their fields via `semantics { error(...) }`
  so TalkBack announces them; the form-error banner uses a `liveRegion` so it is
  read when it appears.
- Touch targets ≥ 48dp; supports dynamic font scaling (sp units, no fixed
  heights that clip at large scale); content scrolls under the IME.
- Color is not the sole error signal (icon + text). Verified against Material 3
  contrast in both light and dark themes.
- RTL-safe layout (use start/end, not left/right).

## 10. Telemetry & Logging

- Emit screen-view event `auth_login_view` on first composition.
- Emit `auth_login_submit` on submit with non-PII property
  `email_format` (`email` | `username`) — never the value.
- Emit `auth_login_validation_error` with `field` and `reason` enums.
- Emit `auth_login_error_shown` with `error_type` (`credentials` | `network` |
  `server`).
- Emit `auth_login_link_tap` with `target` (`forgot` | `register` |
  `server_url`).
- Logging via the project's structured logger at `debug`/`info`; no PII, no
  credentials, no full URLs containing tokens. The actual analytics dispatch is
  invoked from the ViewModel (AND-031); this ticket defines the event surface
  and ensures callbacks fire at the right interaction points.

## 11. Testing Strategy

**Compose UI tests** (`feature-auth` androidTest, `createComposeRule`, fake
state — no network, no Hilt):
- Typing into email/password updates rendered values via the supplied callbacks.
- Submit button disabled when either field blank; enabled when both valid.
- Submit disabled and progress shown when `isSubmitting = true`; fields/links
  disabled.
- Invalid email (`a@b`) surfaces `InvalidEmail` error under the email field.
- `FormError.Credentials` renders non-retryable error, no Retry button.
- `FormError.Network` renders banner with working Retry that re-invokes
  `onSubmit`.
- Show/hide toggle flips `PasswordVisualTransformation` and updates the toggle's
  accessibility label.
- Recovery/register/server-URL affordances invoke the correct callbacks.
- IME `Done` on password triggers `onSubmit` only when valid.

**Unit tests** (JVM, `core-testing`):
- `LoginValidator.validateEmail` / `validatePassword` truth tables (blank,
  username, valid email, malformed email).
- `LoginUiState.isSubmitEnabled` derivation across representative combinations.

**IA parity check:** a documented screenshot comparison (Compose `@Preview` /
Paparazzi-style or manual) against the web login screen verifying field order,
action hierarchy, and link labels — satisfying "matches web behavior/IA".

**Accessibility test:** TalkBack semantics assertions (error announcement, live
region, toggle state) in the UI test suite.

## 12. Dependencies & Sequencing

- **Blocked by:**
  - **AND-020** (core input composables) — must land first; the screen composes
    `AppTextField`, `PasswordField`, `AppButton`.
  - **AND-023** (unauthenticated nav graph) — provides the route registration
    and navigation callback wiring (Login as start destination).
- **Blocks / unblocks:**
  - **AND-031** (`LoginViewModel`) — consumes `LoginUiState`/`LoginValidator`
    and replaces the fake state holder; the navigation side-effects (MFA vs
    home) are realized there.
  - **AND-053, AND-057, AND-060, AND-063** — auth surfaces reached from this
    screen's links.
- **Sequencing:** implement the stateless `LoginScreen` + `LoginUiState` +
  `LoginValidator` + previews + UI tests against a fake holder now; `LoginRoute`
  with `hiltViewModel()` is finalized in AND-031. Server-URL persistence and the
  editor dialog are external and stubbed via `onEditServerUrl()`.

## 13. Risks & Open Questions

- **R1 — IA drift from web.** Web login may evolve; lock IA against the current
  `frontend/` login at implementation time and capture a reference screenshot.
- **R2 — email vs username labeling.** Backend field is `username`; web labels
  it "email". Confirm exact web copy to avoid mismatched expectations. *Open:
  does the web accept non-email usernames?* Validation here is permissive
  (only validates format when `@` present).
- **R3 — server-URL ownership boundary.** This screen triggers but does not
  persist the base URL; ensure the downstream config ticket exists and the HTTPS
  warning lives there. *Open: which ticket owns DataStore base-URL persistence?*
- **R4 — autofill behavior on minSdk 24** varies; verify autofill hints degrade
  gracefully on older devices.
- **R5 — password restoration policy.** Confirmed: password not restored across
  process death; revisit only if UX explicitly requests it.

## 14. Acceptance Criteria

AC-1 Valid input (non-blank email/username + non-blank password, valid email
format when `@` present) enables the submit button; invalid/blank input keeps it
disabled. (UI-tested.)

AC-2 Field-level validation errors surface under the correct field on blur/submit
and clear when corrected. (UI-tested.)

AC-3 Server/network/credential errors surface via the form-error banner/inline
error with correct retryable behavior; network errors offer a working Retry.
(UI-tested.)

AC-4 Show/hide password toggle works and announces its state; password obscured
by default. (UI-tested.)

AC-5 Recovery, register, and server-URL entry-point affordances invoke their
callbacks; current server-URL label is displayed. (UI-tested.)

AC-6 Loading state disables the form and shows progress; no duplicate submits.
(UI-tested.)

AC-7 Screen behavior and IA (field order, action hierarchy, labels) match the
web login reference. (Verified via screenshot/IA comparison.)

AC-8 No credentials are logged or persisted across process death.

## 15. Definition of Done

- `LoginScreen`, `LoginRoute`, `LoginUiState`, `FieldError`/`FormError`, and
  `LoginValidator` implemented in `:feature-auth` under
  `com.testlogon.android.feature.auth.login`, composing AND-020 components and
  registered as the start destination in the AND-023 graph.
- All strings externalized; full a11y semantics (error association, live region,
  toggle state, 48dp targets, dynamic type, RTL).
- `@Preview`s for empty, valid, field-error, submitting, and form-error states
  render correctly in light and dark themes.
- Compose UI tests (Section 11) and `LoginValidator`/`isSubmitEnabled` unit
  tests pass in CI; IA parity check documented.
- No PII/credential logging; password excluded from saved state.
- Telemetry event surface wired at the defined interaction points.
- Builds clean with project toolchain (Kotlin 2.0.21, AGP 8.7.3, JDK 17),
  passes lint/detekt, and is reviewed and merged to `android-port`.
