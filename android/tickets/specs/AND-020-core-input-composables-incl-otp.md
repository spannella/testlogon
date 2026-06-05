---
id: AND-020
title: Core input composables (incl. OTP)
milestone: M1
epic: E03
priority: P0
size: M
status: draft
depends_on:
  - AND-019
blocks:
  - AND-030
  - AND-039
  - AND-347
---

# AND-020 — Core input composables (incl. OTP)

## 1. Overview & Goal

This ticket delivers the reusable, stateless input composables that every TestLogon
screen relies on for text entry and form submission. The deliverable is a small,
well-typed component library inside `core-ui` consisting of: a primary/secondary/text
`TlButton`, a general-purpose `TlTextField` (with error and helper text), a
`TlPasswordField` (with a show/hide toggle), and a dedicated **6-digit OTP input**
(`TlOtpField`) used by the MFA flow.

The goal is to centralize input look-and-feel, validation display, accessibility, and
keyboard behavior so that downstream feature screens (login, MFA, dynamic forms) compose
these primitives instead of re-implementing `OutlinedTextField` ad hoc. All components
are pure Compose, theme-driven (consuming the Material 3 theme from AND-019), stateless
(state hoisted to the caller), and fully previewable. Success means each component renders
its declared states correctly and the OTP field supports 6-digit entry plus clipboard
paste of a full or partial code — both covered by automated tests.

Out of scope: networking, ViewModels, validation business rules, and screen layout. This
ticket produces only presentational primitives and their state contracts.

## 2. Context & References

- Module: `core-ui` (Compose + Material 3). Package root: `com.testlogon.android.core.ui`.
- New package: `com.testlogon.android.core.ui.input`.
- Stack: Kotlin 2.0.21, Jetpack Compose (BOM as pinned in AND-003), Material 3,
  minSdk 24 / compileSdk 35 / targetSdk 35, JDK 17.
- Depends on **AND-019 (Material 3 theme)** for `TlTheme`, color scheme, typography,
  and shapes. All sizing/coloring derives from `MaterialTheme.colorScheme`,
  `MaterialTheme.typography`, and `MaterialTheme.shapes` — no hardcoded hex/`sp` magic
  numbers except documented spacing tokens.
- Downstream consumers (this ticket **blocks** them): **AND-030 (Login screen UI)** uses
  `TlTextField` + `TlPasswordField` + `TlButton`; **AND-039 (MFA screen UI)** uses
  `TlOtpField` + `TlButton` for the TOTP/SMS/email 6-digit code; **AND-347 (Dynamic form
  renderer)** maps backend field descriptors onto `TlTextField`/`TlPasswordField`.
- Web reference for OTP UX parity: `frontend/` MFA verify components (6-character
  numeric code, paste support). Backend MFA endpoints (`/ui/mfa/{totp|sms|email}/verify`)
  are owned by AND-039; this ticket only produces the UI surface.
- Material 3 `OutlinedTextField`, `BasicTextField`, `VisualTransformation`, and
  `Modifier.semantics` are the underlying primitives.

## 3. Functional Requirements

FR-1 **TlButton** renders a filled primary button by default and supports `Primary`,
`Secondary` (tonal/outlined), and `Text` variants. It supports an enabled/disabled state
and an inline `loading` state that swaps the label for a `CircularProgressIndicator` and
disables interaction without changing the button's measured width.

FR-2 **TlTextField** renders a labeled single-line (configurable) field. It displays
either helper text (neutral) or error text (error color) below the field — error text
takes precedence and switches the field into the Material 3 error visual state. It
supports leading/trailing slots, a configurable `KeyboardOptions` (keyboard type, IME
action), `KeyboardActions`, and an optional `isError` flag derived by the caller.

FR-3 **TlPasswordField** behaves like `TlTextField` but masks input by default and renders
a trailing icon button that toggles between masked/plain visual transformation. The toggle
must be reachable and labeled for accessibility ("Show password" / "Hide password"). The
keyboard type defaults to `KeyboardType.Password`.

FR-4 **TlOtpField** renders a fixed 6-cell numeric code input. Each digit is shown in a
visually distinct cell; the currently-focused cell is highlighted. It accepts only digits
`0-9`, ignores all other characters, and caps length at 6.

FR-5 **OTP paste**: pasting a string (e.g. from an SMS autofill or clipboard) fills the
cells left-to-right using only its digit characters, truncated to 6. Pasting a 6-digit
string fills the field completely; a partial paste fills the available cells. Non-digit
characters in the pasted string are stripped, not rejected wholesale.

FR-6 **OTP completion callback**: when the 6th digit is entered (by typing or paste),
`TlOtpField` invokes an `onCompleted: (String) -> Unit` callback exactly once per
transition to a complete state, in addition to the per-change `onValueChange`.

FR-7 All fields support an `enabled` flag and an `isError` visual state, and all
components expose a `modifier: Modifier = Modifier` parameter as the first optional
parameter after required ones, per Compose API guidelines.

FR-8 Every component is **stateless**: value/state is hoisted to the caller via
`value` + `onValueChange`. No component owns `remember`-ed business state (the password
visibility toggle is permitted internal UI state).

FR-9 Each component ships at least one `@Preview` (light + dark, default + error +
disabled + loading where applicable) demonstrating all declared states.

## 4. Technical Design

New files under `core-ui/src/main/java/com/testlogon/android/core/ui/input/`:
`TlButton.kt`, `TlTextField.kt`, `TlPasswordField.kt`, `TlOtpField.kt`,
`InputTokens.kt` (spacing/size constants).

### Public signatures

```kotlin
package com.testlogon.android.core.ui.input

enum class TlButtonVariant { Primary, Secondary, Text }

@Composable
fun TlButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    variant: TlButtonVariant = TlButtonVariant.Primary,
    enabled: Boolean = true,
    loading: Boolean = false,
    leadingIcon: ImageVector? = null,
)

@Composable
fun TlTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    isError: Boolean = false,
    errorText: String? = null,
    helperText: String? = null,
    singleLine: Boolean = true,
    leading: @Composable (() -> Unit)? = null,
    trailing: @Composable (() -> Unit)? = null,
    keyboardOptions: KeyboardOptions = KeyboardOptions.Default,
    keyboardActions: KeyboardActions = KeyboardActions.Default,
    visualTransformation: VisualTransformation = VisualTransformation.None,
)

@Composable
fun TlPasswordField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    isError: Boolean = false,
    errorText: String? = null,
    helperText: String? = null,
    imeAction: ImeAction = ImeAction.Done,
    onImeAction: () -> Unit = {},
)

@Composable
fun TlOtpField(
    value: String,
    onValueChange: (String) -> Unit,
    modifier: Modifier = Modifier,
    length: Int = 6,
    enabled: Boolean = true,
    isError: Boolean = false,
    errorText: String? = null,
    onCompleted: (String) -> Unit = {},
)
```

### TlButton

Internally delegates to `Button` (Primary), `OutlinedButton`/`FilledTonalButton`
(Secondary), or `TextButton` (Text). When `loading` is true the content is a
`Box` overlaying a `CircularProgressIndicator(strokeWidth = 2.dp)` sized to the text
height, so width is preserved; `onClick` is suppressed (button is rendered with
`enabled = enabled && !loading`).

### TlTextField / TlPasswordField

Both build on `OutlinedTextField`. The error/helper line is a single `supportingText`
slot: `errorText?.takeIf { isError || errorText != null }` is shown in
`colorScheme.error`, otherwise `helperText` in `colorScheme.onSurfaceVariant`.
`isError` is `isError || errorText != null`. `TlPasswordField` keeps internal
`var visible by remember { mutableStateOf(false) }`, applies
`PasswordVisualTransformation()` when hidden, and renders a trailing
`IconButton` with `Icons.Outlined.Visibility` / `VisibilityOff`.

### TlOtpField

Implemented with a single `BasicTextField` holding `TextFieldValue` plus an overlay
row of `length` cells (`Box` each, themed border + corner from `MaterialTheme.shapes`).
The real text field is transparent and full-width so the system handles focus,
soft-keyboard (`KeyboardType.NumberPassword`), and paste; the cells are decoration
that read from the hoisted `value`. Input is sanitized in one place:

```kotlin
private fun sanitizeOtp(raw: String, length: Int): String =
    raw.filter { it.isDigit() }.take(length)
```

`onValueChange` receives the sanitized string; when `value.length` transitions to
`length`, `onCompleted(value)` fires once (guarded by comparing previous/next length
inside the `onValueChange` lambda). Caret/selection is forced to the end so paste and
type both append. The focused cell index = `value.length.coerceAtMost(length - 1)`.

`InputTokens.kt` holds: `FieldSpacing = 4.dp`, `OtpCellSize = 44.dp`,
`OtpCellGap = 8.dp`, `ButtonMinHeight = 48.dp` (>= 48dp touch target).

## 5. API Contract

Not applicable. This ticket produces presentational composables only; it performs no
network I/O and defines no request/response types. The MFA verification network contract
(`POST /ui/mfa/{totp|sms|email}/verify` with `{ challenge_id, code }`) and the login
contract (`POST /ui/session/start`) are owned by their feature/data tickets and consumed
by **AND-039 (MFA screen UI)** and **AND-030 (Login screen UI)** respectively. `TlOtpField`
emits a plain `String` code via `onValueChange`/`onCompleted`; mapping that code into a
request body is the caller's responsibility.

## 6. Data & State Management

All components are stateless and state is hoisted to the caller (a ViewModel-backed
`StateFlow<UiState>` in downstream tickets). The data contracts are the function
parameters in section 4:

- Text inputs: `value: String` + `onValueChange: (String) -> Unit`. The caller owns the
  source-of-truth string and any validation; components only render `isError`/`errorText`.
- OTP: `value: String` is always a sanitized 0–6 char digit string; the component never
  surfaces invalid characters upward. `onCompleted` is a derived signal, not separate
  state.
- Password visibility is the only internal UI state and is intentionally not hoisted; it
  resets to hidden on recomposition-from-scratch and is not persisted (security choice).
- No DataStore, Room, or persistence is involved in this ticket. OTP autofill via the
  Android SMS Retriever / Autofill framework is **not** implemented here; the field merely
  accepts pasted/typed input. Autofill integration, if desired, is a follow-up tracked
  against AND-039.

## 7. Error Handling & Resilience

There is no I/O, so "errors" are purely presentational and input-sanitization concerns:

- **Error display**: `isError`/`errorText` drive the Material 3 error visual state and the
  supporting-text line. When `errorText != null`, the field is treated as errored even if
  `isError` was not set, preventing inconsistent states.
- **OTP input hardening**: `sanitizeOtp` filters non-digits and caps length, so malformed
  paste (e.g. `"12-34-56"`, `"123456789"`, or a code with whitespace/newlines) can never
  put the component into an invalid state. A paste longer than `length` is truncated, not
  rejected.
- **Idempotent completion**: `onCompleted` fires only on the transition into the complete
  state, so repeated recompositions do not re-trigger submission (which downstream would
  turn into duplicate network calls).
- **Disabled state**: when `enabled = false`, fields ignore input and buttons suppress
  `onClick`; the `loading` button variant additionally blocks interaction to prevent
  double-submit while a request is in flight.

## 8. Security & Privacy

- Password masking uses `PasswordVisualTransformation`; visibility defaults to hidden and
  is never persisted across process death.
- `TlPasswordField` and `TlOtpField` set `KeyboardType.Password` / `NumberPassword` so the
  IME disables predictive text/personalized learning, reducing keyboard caching of secrets.
- OTP and password values are never logged (see section 10) and never written to
  DataStore/Room by this component.
- No clipboard contents are read programmatically; paste is handled by the platform text
  field, so the app only receives data the user explicitly pasted.
- No PII or credential leaves the component except via the caller-provided callbacks; this
  ticket introduces no new permissions and no network surface.

## 9. Accessibility & i18n

- All labels, helper/error strings, and the password toggle content descriptions come from
  `strings.xml` (no hardcoded UI strings); the password toggle uses
  `R.string.cd_show_password` / `cd_hide_password`.
- Touch targets: buttons and the password toggle are >= 48dp; OTP cells are 44dp with
  adequate spacing and a single focusable field for screen-reader simplicity.
- `TlOtpField` exposes a single semantics node with a `contentDescription` describing the
  field as a 6-digit code and announces progress (e.g. "3 of 6 digits entered") via
  `Modifier.semantics { stateDescription = ... }`; cells themselves are
  `clearAndSetSemantics` to avoid 6 redundant nodes.
- Error text is associated with its field via `supportingText` so TalkBack reads the error
  when the field gains focus; error is not conveyed by color alone (text + error state).
- Components honor dynamic font scaling (no fixed `sp` overrides) and render correctly in
  RTL via standard layout direction; OTP cell order respects layout direction.

## 10. Telemetry & Logging

Minimal and privacy-safe. No analytics events are emitted from `core-ui` primitives;
instrumentation belongs to feature screens (AND-030/AND-039). Logging is limited to
debug-only structural logs (e.g. unexpected `length <= 0` for OTP) via the shared
`core-ui` logger. **Field contents (password, OTP, free text) are never logged** at any
level. If a downstream screen needs "MFA code submitted" telemetry, it instruments its own
`onCompleted` handler with no code value attached.

## 11. Testing Strategy

Compose UI tests in `core-ui/src/androidTest/...` using `createComposeRule()`
(robolectric/instrumented per AND-005 `core-testing` setup):

- `TlButton`: renders label; `loading = true` shows progress + suppresses `onClick`
  (assert callback not invoked on click); `enabled = false` suppresses `onClick`; each
  variant composes without crash.
- `TlTextField`: typing emits `onValueChange`; `errorText` shows in supporting text and
  sets error semantics; `helperText` shows when no error; error precedence over helper.
- `TlPasswordField`: input is masked by default; tapping the toggle reveals text (assert
  via semantics/text node) and toggles content description; toggling back re-masks.
- `TlOtpField` (acceptance-critical):
  - typing 6 digits populates all cells and fires `onCompleted("123456")` exactly once;
  - typing a 7th digit is ignored (value stays length 6);
  - non-digit key input is filtered;
  - **paste of `"123456"`** fills the field and fires `onCompleted` once;
  - **paste of `"12-3456x"`** sanitizes to `"123456"` and completes;
  - paste of `"123"` fills 3 cells and does **not** fire `onCompleted`.
- Unit test `sanitizeOtp` directly (JVM): digit filtering, truncation, empty input.
- `@Preview` screenshots compile in light and dark; CI verifies the previews build.

Target: each component has at least one rendering test and one interaction test; OTP
entry + paste are explicitly asserted to satisfy the acceptance criteria.

## 12. Dependencies & Sequencing

- **Depends on AND-019 (Material 3 theme)** — required for `TlTheme`, color scheme,
  typography, shapes consumed by every component. Must merge first.
- Transitively depends on AND-003 (`core-ui` module scaffold) and AND-005 (`core-testing`
  / Compose test harness) for the test infrastructure.
- **Blocks AND-030 (Login screen UI)**, **AND-039 (MFA screen UI)**, and **AND-347
  (Dynamic form renderer)**, which all compose these primitives.
- No backend or DI dependency; can be developed in parallel with `core-network`/`core-data`
  tickets. Sequencing: AND-019 → AND-020 → (AND-021 state composables, AND-030, AND-039).

## 13. Risks & Open Questions

- **OTP `BasicTextField` focus/caret quirks**: keeping the caret pinned to the end and
  ensuring paste works across OEM keyboards is the main implementation risk; mitigate with
  forced end-selection on every `onValueChange` and explicit paste tests.
- **Completion double-fire**: recomposition could re-trigger `onCompleted`; mitigated by
  the length-transition guard, but reviewers should verify across configuration changes.
- **Open question (AND-039)**: should `TlOtpField` integrate Android Autofill / SMS
  Retriever for one-tap code fill? Deferred; current scope is type + paste only.
- **Open question**: OTP length is parameterized (default 6) — confirm no MFA factor uses a
  non-6 length. If all factors are 6-digit, the parameter can be hardcoded later.
- **Theming gap**: if AND-019 does not expose distinct shapes for small components, OTP
  cells fall back to `MaterialTheme.shapes.small`.

## 14. Acceptance Criteria

AC-1 `TlButton`, `TlTextField`, `TlPasswordField`, and `TlOtpField` exist in
`com.testlogon.android.core.ui.input` with the signatures in section 4 and are stateless.

AC-2 Components render their declared states correctly: button primary/secondary/text +
disabled + loading; text field default/helper/error/disabled; password field
masked/revealed/error — each demonstrated by a `@Preview` and asserted by a UI test.

AC-3 `TlOtpField` supports **6-digit entry**: typing 6 digits fills all cells and emits a
6-char value (tested).

AC-4 `TlOtpField` supports **paste**: pasting a 6-digit string fills the field; pasting a
string with non-digits sanitizes to digits and truncates to 6; partial paste fills
partial cells (tested).

AC-5 `onCompleted` fires exactly once when the OTP reaches 6 digits and does not re-fire on
recomposition (tested).

AC-6 Password visibility toggle reveals/hides text and updates its content description; it
defaults to hidden (tested).

AC-7 All user-facing strings are externalized; password toggle and OTP field expose
content descriptions; touch targets meet >= 48dp / 44dp guidance.

AC-8 No field value (password/OTP/text) is logged at any level.

## 15. Definition of Done

- All section-14 acceptance criteria pass in CI.
- New composables live in `core-ui` under `com.testlogon.android.core.ui.input`, build
  against compileSdk 35 / JDK 17, and consume only `TlTheme` tokens (no hardcoded colors).
- Compose UI tests and the `sanitizeOtp` unit test are added and green; previews build in
  light and dark.
- No new lint/detekt warnings; public composables follow Compose API guidelines
  (`modifier` first optional param, slot/lambda ordering).
- No new permissions, no network code, no secret logging introduced.
- Code reviewed and merged to `android-port`; downstream tickets AND-030 / AND-039 / AND-347
  can compile against the published signatures.
