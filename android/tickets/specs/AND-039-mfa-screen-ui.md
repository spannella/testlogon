---
id: AND-039
title: MFA screen UI
milestone: M1
epic: E05
priority: P0
size: L
status: draft
depends_on: [AND-020, AND-038]
blocks: []
---

# AND-039 — MFA screen UI

## 1. Overview & Goal

This ticket delivers the user-facing Multi-Factor Authentication (MFA) screen for the
TestLogon native Android app. After the credential step (`POST /ui/session/start`) returns
`auth_required = true` with a `challenge_id` and a list of `required_factors`, the user must
satisfy one or more factors (TOTP, SMS, email) before the session can be finalized.

The goal of AND-039 is the **presentation and interaction layer** only: factor selection, OTP
code entry, resend/cooldown timers, switch-factor, a recovery/help affordance, and inline
error/timer surfaces. The orchestration that consumes the verified factors — calling each
factor's `begin`/`verify`, advancing through `remaining_factors`, and ultimately calling
`POST /ui/session/finalize` — is owned by **AND-038**. AND-039 binds to the state and
callbacks AND-038 exposes and renders them as Compose UI.

Out of scope: cookie/CSRF plumbing, the persistent cookie jar, refresh-on-401, and the
finalize/sequencing state machine (all AND-038 / core-network). AND-039 must not call
Retrofit directly.

## 2. Context & References

- **Module:** `feature-auth` (Compose UI + ViewModel binding), depending on `core-ui`
  (`com.testlogon.android.core.ui`) and `core-model` (`com.testlogon.android.core.model`).
- **Package root:** `com.testlogon.android.feature.auth.mfa`.
- **Dependencies:**
  - **AND-020** — Core input composables: provides the reusable `OtpInput` (6-digit entry +
    paste), `AppButton`, `AppTextField`, `PasswordField`. AND-039 composes `OtpInput`; it does
    not re-implement digit handling.
  - **AND-038** — Finalize + multi-factor sequencing: owns `MfaViewModel`/sequencing state,
    the `MfaUiState` data this screen renders, and all backend calls
    (`/ui/mfa/{totp|sms|email}/begin|verify`, `/ui/session/finalize`).
- **Web reference:** `frontend/src/api/endpoints/mfa.ts`, `frontend/src/api/types.ts`
  (factor enum, challenge shapes), and the web MFA component for UX parity (resend cooldown,
  switch-factor copy, recovery link).
- **Backend:** FastAPI dev host `http://18.222.237.167:8000` (PLAINTEXT, unreliable);
  OpenAPI at `/openapi.json`. Cookie-based session with `ui_csrf` echoed as `X-CSRF-Token`.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose (single Activity),
  Hilt (KSP), Coroutines/Flow. minSdk 24 / target 35.

## 3. Functional Requirements

FR-1 **Factor selection.** When `required_factors` (for the current step) contains more than
one available factor, render a selectable list of the factors the user may use to satisfy the
current step. Each item shows a localized label and icon (TOTP = authenticator app, SMS =
phone, EMAIL = envelope) and, where the backend provides it, a masked destination hint
(e.g. `•••• 4821`, `j••@example.com`). Selecting a factor triggers `onSelectFactor(factor)`
(handled by AND-038, which calls that factor's `begin`).

FR-2 **OTP entry.** Render the AND-020 `OtpInput` for code entry. Default length 6; the length
comes from `MfaUiState.codeLength`. Auto-advance and paste are provided by AND-020. When the
field reaches full length, auto-submit via `onSubmitCode(code)` unless `isVerifying` is true.

FR-3 **Submit.** A primary `AppButton` ("Verify") is enabled only when the entered code length
equals `codeLength` and `isVerifying == false`. Tapping calls `onSubmitCode(code)`. While
verifying, the button shows an inline progress indicator and is disabled.

FR-4 **Resend with cooldown.** For SMS/EMAIL factors, render a "Resend code" action. After a
send/resend it is disabled and shows a live countdown (`resendCooldownSeconds`, default 30s)
driven by a UI-side ticker; when it reaches 0 the action re-enables. Tapping calls
`onResend()`. TOTP has no resend (the code is generated on the user's device) — hide it.

FR-5 **Switch factor.** A "Use a different method" affordance is shown whenever more than one
factor is available for the current step. It returns the user to the factor-selection state
(FR-1) without losing the active `challenge_id`; it calls `onSwitchFactor()`.

FR-6 **Recovery option.** A low-emphasis "Can't access your device?" / "Use a recovery code"
link is always visible. It invokes `onRecovery()`. If the backend exposes a recovery factor it
is treated as another factor path; otherwise the link navigates to a help/contact destination
(`MfaRoute.Recovery`). Recovery code entry reuses `OtpInput` with `codeLength` from state.

FR-7 **Errors & timers.** Render `MfaUiState.error` inline below the OTP field (invalid code,
expired code, locked/too-many-attempts, network). When the active challenge has an expiry
(`expiresAtEpochMs`), show a "Code expires in mm:ss" timer; on expiry, disable submit and
surface "This code has expired — resend".

FR-8 **Multi-step continuation.** When a verify succeeds but `remaining_factors` is non-empty
(AND-038 advances state), the screen transitions to the next factor's selection/entry state
with the OTP field cleared and timers reset. No navigation event; same composable, new state.

FR-9 **Completion.** When AND-038 reports finalize success, AND-039 emits no terminal UI; it
observes a one-shot `MfaEvent.Authenticated` and lets the nav graph route onward (owned by
AND-038 / nav ticket). On `MfaEvent.SessionLost` it routes back to the credential screen.

## 4. Technical Design

Single-Activity Navigation-Compose. The MFA destination is a route in the auth nav graph:

```kotlin
// feature-auth/navigation
sealed interface MfaRoute {
    @Serializable data object Entry : MfaRoute      // factor select + OTP
    @Serializable data object Recovery : MfaRoute
}

fun NavGraphBuilder.mfaGraph(navController: NavController) {
    composable<MfaRoute.Entry> {
        val vm: MfaViewModel = hiltViewModel()      // provided by AND-038
        val state by vm.uiState.collectAsStateWithLifecycle()
        MfaScreen(
            state = state,
            onSelectFactor = vm::onSelectFactor,
            onSubmitCode   = vm::onSubmitCode,
            onResend       = vm::onResend,
            onSwitchFactor = vm::onSwitchFactor,
            onRecovery     = { navController.navigate(MfaRoute.Recovery) },
            onCodeChange   = vm::onCodeChange,
        )
        LaunchedEffect(Unit) {
            vm.events.collect { ev -> /* Authenticated / SessionLost routing */ }
        }
    }
}
```

The screen is a stateless composable driven entirely by `MfaUiState` + callbacks. AND-039 owns
only the rendering; `MfaViewModel` and `MfaUiState` are authored in AND-038 — AND-039 may
*propose* the shape below and is responsible for keeping the composable in sync with it.

```kotlin
@Composable
fun MfaScreen(
    state: MfaUiState,
    onSelectFactor: (MfaFactor) -> Unit,
    onSubmitCode: (String) -> Unit,
    onResend: () -> Unit,
    onSwitchFactor: () -> Unit,
    onRecovery: () -> Unit,
    onCodeChange: (String) -> Unit,
    modifier: Modifier = Modifier,
)
```

Proposed UI state (defined in AND-038, consumed here):

```kotlin
enum class MfaFactor { TOTP, SMS, EMAIL, RECOVERY }

data class FactorOption(
    val factor: MfaFactor,
    val destinationHint: String?,   // masked, may be null (TOTP)
    val enabled: Boolean,
)

data class MfaUiState(
    val mode: Mode,                       // SELECTING | ENTERING
    val availableFactors: List<FactorOption>,
    val activeFactor: MfaFactor?,
    val code: String = "",
    val codeLength: Int = 6,
    val isVerifying: Boolean = false,
    val isSending: Boolean = false,
    val resendCooldownSeconds: Int = 0,   // 0 = resend allowed
    val expiresAtEpochMs: Long? = null,
    val error: MfaError? = null,
    val stepIndex: Int = 0,
    val stepCount: Int = 1,
) {
    enum class Mode { SELECTING, ENTERING }
    val canSwitchFactor: Boolean get() = availableFactors.size > 1
    val canSubmit: Boolean get() = !isVerifying && code.length == codeLength
}
```

Internal composition (private composables in `MfaScreen.kt`): `FactorSelectList`,
`OtpEntrySection` (wraps AND-020 `OtpInput`), `ResendRow`, `ExpiryTimerText`,
`MfaErrorBanner`, `SwitchAndRecoveryRow`. The countdown timers (resend cooldown, expiry) are
pure UI concerns and are computed locally so the ViewModel is not woken every second:

```kotlin
@Composable
private fun rememberCountdown(targetEpochMs: Long?): State<Long> // remaining millis, ticks 1s
```

`resendCooldownSeconds` likewise drives a local `LaunchedEffect` ticker that decrements a
remembered value; `onResend()` resets it. Auto-submit: a `LaunchedEffect(state.code)` calls
`onSubmitCode` when `code.length == codeLength && !isVerifying`.

## 5. API Contract

AND-039 makes **no direct network calls**. All endpoints below are invoked by AND-038; they
are documented here because the UI renders their inputs/outputs. The shapes are the contract
AND-039 codes its rendering against.

`POST /ui/session/start` (AND-037/038) response that opens MFA:

```json
{
  "auth_required": true,
  "challenge_id": "chal_7Yc...",
  "required_factors": ["totp", "sms"]
}
```

`POST /ui/mfa/{totp|sms|email}/begin` — body `{ "challenge_id": "chal_..." }`:

```json
{
  "challenge_id": "chal_7Yc...",
  "factor": "sms",
  "destination_hint": "•••• 4821",
  "code_length": 6,
  "resend_cooldown_seconds": 30,
  "expires_at": 1749100000
}
```

`POST /ui/mfa/{totp|sms|email}/verify` — body `{ "challenge_id": "...", "code": "123456" }`:

```json
{ "verified": true, "remaining_factors": [] }
```

Error (FastAPI `detail`, mapped by core-network to typed `MfaError`):

```json
{ "detail": [{ "msg": "Invalid or expired code" }] }
```

`detail` may be a `string`, `[{msg}]`, or `{code,...}`; AND-038's mapper produces the typed
`MfaError` AND-039 renders. All MFA calls require the `X-CSRF-Token` header (ui_csrf cookie)
and ride the persistent cookie jar — handled by core-network, not this ticket.

## 6. Data & State Management

- **Source of truth:** `MfaViewModel.uiState: StateFlow<MfaUiState>` (AND-038). AND-039 reads
  it via `collectAsStateWithLifecycle()`; no separate UI-layer model store.
- **Code text:** held in `MfaUiState.code` so it survives the verify round-trip and is cleared
  by the ViewModel between steps. The `OtpInput` is a controlled component bound to
  `state.code` / `onCodeChange`.
- **Transient UI-only state:** countdown remaining-time and the resend ticker are derived via
  `remember`/`LaunchedEffect` keyed on `expiresAtEpochMs` and `resendCooldownSeconds`. These
  reset correctly across config changes because they recompute from the state value, not from
  wall-clock counters held in composables.
- **One-shot events:** `MfaViewModel.events: Flow<MfaEvent>` (`Authenticated`, `SessionLost`,
  `CodeResent`) collected in `LaunchedEffect`; not part of `MfaUiState`.
- **Persistence:** none in this ticket. Session cookies/`remember_device` live in DataStore +
  cookie jar (AND-038). `challenge_id` is in-memory for the auth flow lifetime only and is
  never written to disk.
- **Process death:** the auth challenge is intentionally not persisted; on restore the screen
  shows an empty state and routes back to credentials if no live challenge exists (via
  `SessionLost`).

## 7. Error Handling & Resilience

- **Invalid/expired code:** render `MfaError.InvalidCode` / `ExpiredCode` inline; keep the
  field populated for InvalidCode (let user correct), clear it for ExpiredCode and prompt
  resend.
- **Lockout / too many attempts:** `MfaError.Locked(retryAfterSeconds)` disables submit and
  shows a cooldown timer reusing `rememberCountdown`.
- **Network/timeout:** the dev backend is unreliable; verify is a non-idempotent POST so it is
  **not** auto-retried. On `MfaError.Network` show a retry affordance the user taps;
  `begin`/resend (effectively idempotent re-send) may use AND-038's bounded backoff. ~20s
  timeouts apply at the OkHttp layer.
- **401 mid-flow:** core-network performs the single `POST /ui/session/refresh` + retry; if it
  still fails AND-038 emits `SessionLost` and AND-039 routes to credentials.
- **Resend storms:** resend is hard-gated by the cooldown timer in the UI in addition to any
  server cooldown, preventing accidental double-sends.
- **Offline:** if connectivity is unavailable, show a non-blocking banner and keep the entered
  code; submit stays enabled so the user can retry when back online.

## 8. Security & Privacy

- OTP codes are treated as secrets: never logged, never placed in telemetry, never in crash
  breadcrumbs. The `OtpInput` uses numeric keyboard and `KeyboardType.NumberPassword` so codes
  are masked from keyboard suggestions/clipboard history where supported.
- Destination hints are **server-masked**; AND-039 renders them verbatim and never derives or
  un-masks full phone/email values.
- `challenge_id` is a short-lived opaque token, kept in memory only; excluded from logs.
- No screenshot blocking is required for the MFA screen by default, but the screen sets
  `FLAG_SECURE`-equivalent only if a project-wide secure-screen policy (separate ticket)
  dictates it; not implemented here.
- All transport security (cookies, CSRF, plaintext-HTTP dev caveat) is owned by core-network;
  AND-039 introduces no new network surface.

## 9. Accessibility & i18n

- All actionable elements (factor items, Verify, Resend, Switch, Recovery) have
  `contentDescription` / merged semantics and meet the 48dp minimum touch target.
- `OtpInput` exposes a combined semantics node ("One-time code, 6 digits") rather than 6
  separate fields, so TalkBack announces it as a single labeled field; the AND-020 component
  provides this and AND-039 supplies the label.
- Live regions: the error banner and expiry/cooldown timers use `liveRegion = Polite` so
  TalkBack announces "Code expired" / "Resend available" without stealing focus.
- Dynamic type / large fonts: layout uses scalable `sp` text and avoids fixed-height rows that
  clip; verified at 200% font scale.
- i18n: all copy via `stringResource` in `core-ui`/`feature-auth` `strings.xml`. Timer strings
  use plurals (`mm:ss`) and locale-aware number formatting. Factor labels and the masked-hint
  template are localizable. RTL mirrored (start/end paddings, no hardcoded left/right).

## 10. Telemetry & Logging

- Emit screen analytics via the core-ui analytics facade (no PII, no codes):
  - `mfa_screen_view { factors_count, step_index }`
  - `mfa_factor_selected { factor }`
  - `mfa_verify_attempt { factor }` and `mfa_verify_result { factor, outcome }`
    where `outcome ∈ {success, invalid, expired, locked, network}`
  - `mfa_resend { factor }`, `mfa_switch_factor`, `mfa_recovery_opened`
- Logging at `DEBUG` only, redacted: log factor + outcome, never `code` or `challenge_id`.
- Counters wired through the same analytics interface AND-038 uses for finalize events so the
  full funnel (start → factor → verify → finalize) is reconstructable.

## 11. Testing Strategy

UI/Compose tests (`androidTest`, `createAndroidComposeRule`) are the acceptance gate. The
acceptance criterion requires **TOTP and SMS paths completable from the UI**.

- **TOTP path (UI-tested):** seed `MfaUiState` (SELECTING, factors=[TOTP]) via a fake
  `MfaViewModel`/state holder in `core-testing`; assert OTP field shown, enter 6 digits, assert
  `onSubmitCode("123456")` invoked, then push a success state and assert advance/clear.
- **SMS path (UI-tested):** factors=[SMS] with `resend_cooldown_seconds=30`; assert resend
  disabled with countdown, advance virtual clock (`mainClock.advanceTimeBy`) to re-enable,
  tap Resend → `onResend()` invoked; enter code → verify invoked.
- **Multi-factor sequence:** state transitions TOTP→SMS (`remaining_factors` non-empty); assert
  OTP cleared and timers reset between steps.
- **Switch factor:** factors.size > 1 → "Use a different method" visible; tap → `onSwitchFactor`.
- **Recovery:** link always present; tap → `onRecovery` (nav to `MfaRoute.Recovery`).
- **Errors/timers:** push `InvalidCode` (field retained), `ExpiredCode` (field cleared, expiry
  banner), `Locked(retryAfter)` (submit disabled with countdown), `Network` (retry shown).
- **Submit gating:** Verify disabled until `code.length == codeLength`; disabled while
  `isVerifying`.
- **Unit tests:** `rememberCountdown` formatting (mm:ss, zero floor) via a small testable
  pure-function extraction.
- **Accessibility:** assert merged OTP semantics, content descriptions, and `liveRegion` on the
  timer/error nodes.
- Fakes live in `core-testing`; no real network — `MfaViewModel` is faked or driven via an
  injected fake repository so the screen is tested in isolation from AND-038's network code.

## 12. Dependencies & Sequencing

- **Hard depends_on:**
  - **AND-020** — must land first; supplies `OtpInput`/`AppButton`. AND-039 cannot be
    completed without the OTP composable.
  - **AND-038** — supplies `MfaViewModel`, `MfaUiState`, `MfaFactor`, `MfaError`, `MfaEvent`,
    and all backend calls. AND-039 binds to these. The two tickets share the state contract in
    §3/§4; if AND-038 is unfinished, AND-039 develops against a `core-testing` fake state holder
    matching that contract and integrates when AND-038 merges.
- **Upstream context:** AND-037 (credential screen → `session/start`) feeds the
  `required_factors` that open this screen.
- **Blocks:** none recorded in the backlog. (Nav routing to the post-auth home is owned by the
  finalize/nav work in AND-038's epic, not AND-039.)
- **Sequencing recommendation:** implement the stateless `MfaScreen` + private composables
  against the proposed `MfaUiState` in parallel with AND-038, gated on AND-020; integrate
  callbacks once `MfaViewModel` exists.

## 13. Risks & Open Questions

- **R1 — State contract drift with AND-038.** If `MfaUiState` diverges from §4, the screen
  breaks. Mitigation: co-locate the contract, review AND-038/AND-039 together, share the
  enum/state types in `core-model`.
- **R2 — Recovery factor ambiguity.** The backend may or may not expose a `recovery` factor vs.
  a help/contact flow. Open question: confirm via `/openapi.json` and `frontend` reference
  whether recovery is an MFA `verify` path. Default: treat as factor if present, else
  navigate to a static help destination.
- **R3 — Timer accuracy across background/foreground.** Countdowns derived from
  `expires_at`/cooldown epoch are robust to backgrounding; cooldowns expressed only as
  durations are not. Open question: does `begin` always return an absolute `expires_at`? Prefer
  absolute epochs from the server.
- **R4 — Unreliable dev host** can make UI tests flaky if accidentally hitting the network;
  mitigated by faking the ViewModel in `androidTest`.
- **R5 — Code length variability.** Email codes may differ in length; `codeLength` is sourced
  from `begin` rather than hardcoded to 6.

## 14. Acceptance Criteria

AC-1 Each factor path (TOTP, SMS, EMAIL, recovery-if-present) is completable from the UI:
selecting the factor, entering a code, and submitting invokes the correct callback and the
screen advances on success. **(Backlog AC.)**

AC-2 **UI-tested** Compose tests prove the **TOTP** and **SMS** paths complete end-to-end at the
UI layer (factor select → code entry → submit → success/advance), per the source ticket.

AC-3 Factor selection appears only when >1 factor is available; selecting calls
`onSelectFactor`.

AC-4 OTP entry uses the AND-020 `OtpInput`, supports 6-digit entry + paste, auto-submits at
full length, and Verify is gated on `code.length == codeLength && !isVerifying`.

AC-5 Resend is shown for SMS/EMAIL only, disabled during cooldown with a live countdown, and
re-enables at 0; TOTP shows no resend.

AC-6 Switch-factor returns to selection without losing `challenge_id`; recovery affordance is
always present and invokes `onRecovery`.

AC-7 Errors (invalid, expired, locked, network) and the expiry timer render correctly and gate
submit as specified in §7.

AC-8 Multi-step continuation clears the code and resets timers between factors.

AC-9 No OTP code, `challenge_id`, or unmasked destination is ever logged or sent to telemetry.

AC-10 Accessibility: merged OTP semantics, content descriptions on all actions, polite live
regions on timers/errors; passes at 200% font scale and in RTL.

## 15. Definition of Done

- `MfaScreen` and its private composables implemented in `feature-auth`
  (`com.testlogon.android.feature.auth.mfa`), bound to AND-038's `MfaViewModel` via
  Navigation-Compose route `MfaRoute.Entry` (+ `MfaRoute.Recovery`).
- All copy externalized to string resources; RTL and dynamic-type verified.
- Compose UI tests for TOTP and SMS paths pass in CI, plus error/timer/switch/recovery/multi-
  step tests; `rememberCountdown` unit test passes.
- No direct network calls in AND-039; lint/detekt clean; no secrets in logs (verified by a
  redaction test or manual log review).
- Builds on JDK 17 / AGP 8.7.3 / Gradle 8.9, compileSdk 35, against `android-port` branch.
- Code review approved; acceptance criteria AC-1…AC-10 demonstrably met; merged behind the
  auth nav graph with AND-020 and AND-038 integrated.
