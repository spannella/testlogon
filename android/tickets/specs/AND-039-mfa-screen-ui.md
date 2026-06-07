---
id: AND-039
title: MFA screen UI
milestone: M1
epic: E05
priority: P0
size: L
status: reviewed
reviewed_on: 2026-06-06
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
    the `MfaUiState` data this screen renders, and all backend calls. Verified endpoint set
    (see §16): `POST /ui/mfa/{sms,email}/begin`, `POST /ui/mfa/{totp,sms,email}/verify`,
    `POST /ui/mfa/recovery/{factor}`, and `POST /ui/session/finalize`. **There is no
    `/ui/mfa/totp/begin`** — TOTP is generated on-device and only has a `verify` step.
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
phone, EMAIL = envelope) and, where available, a masked destination hint
(e.g. `•••• 4821`, `j••@example.com`). Selecting a factor triggers `onSelectFactor(factor)`
(handled by AND-038, which calls that factor's `begin` for SMS/EMAIL; TOTP has no `begin`).

> Correction (verified §16): the backend does **not** return a per-factor `destination_hint`
> at the factor-selection step. The `begin` response (`ChallengeResp`) returns only
> `{ challenge_id, sent_to?: string[] }` (a masked recipients array), and it is returned
> *after* a factor is chosen, not before. So a pre-selection hint is an **unverified
> assumption**: if AND-038 surfaces a hint it must derive it from `sent_to` (post-begin) or
> from a source outside the verified MFA contract. AND-039 renders `destinationHint` if state
> provides it and omits the row otherwise.

FR-2 **OTP entry.** Render the AND-020 `OtpInput` for code entry. Default length 6; the length
is read from `MfaUiState.codeLength`. Auto-advance and paste are provided by AND-020. When the
field reaches full length, auto-submit via `onSubmitCode(code)` unless `isVerifying` is true.

> Correction (verified §16): the backend does **not** return a `code_length` in the `begin`
> response, and the web reference hardcodes length 6 (`OtpInput length=6`,
> `otpValue.length < 6` gating). A server-driven `codeLength` is therefore an **unverified
> assumption**. AND-039 keeps `codeLength` in state (defaulting to 6) so a future
> server-supplied length can be honored without UI changes, but TOTP/SMS/EMAIL all use 6 today.

FR-3 **Submit.** A primary `AppButton` ("Verify") is enabled only when the entered code length
equals `codeLength` and `isVerifying == false`. Tapping calls `onSubmitCode(code)`. While
verifying, the button shows an inline progress indicator and is disabled.

FR-4 **Resend with cooldown.** For SMS/EMAIL factors, render a "Resend code" action that calls
`onResend()` → AND-038's `begin` (`POST /ui/mfa/{sms,email}/begin`). After a send/resend it is
disabled and shows a live countdown (`resendCooldownSeconds`, default 30s) driven by a UI-side
ticker; when it reaches 0 the action re-enables. TOTP has no resend (the code is generated on
the user's device) — hide it.

> Correction (verified §16): the cooldown is a **client-side UX addition**, not a backend
> contract. The `begin` response does not carry `resend_cooldown_seconds`, and the web
> reference (`Login.tsx`) has **no cooldown at all** — "Resend code" re-calls `beginSms`/
> `beginEmail` with no gating. AND-039 still gates resend locally (default 30s) to prevent
> double-sends; the value is a client constant unless/until the server provides one (unverified
> assumption). The constant must not be presented as server-authoritative.

FR-5 **Switch factor.** A "Use a different method" affordance is shown whenever more than one
factor is available for the current step. It returns the user to the factor-selection state
(FR-1) without losing the active `challenge_id`; it calls `onSwitchFactor()`.

FR-6 **Recovery option.** A low-emphasis "Can't access your device?" / "Use a recovery code"
link is always visible. It invokes `onRecovery()`. The backend **does** expose a recovery path
(`POST /ui/mfa/recovery/{factor}`, body `RecoveryReq`), so recovery is treated as a real factor
path, not merely a help/contact link. `MfaRoute.Recovery` hosts the recovery-code entry.

> Correction (verified §16): the recovery request field is **`recovery_code`** (plus a
> `challenge_id` and an optional `factor`, default `"totp"`), not the generic `code`. Note also
> the web reference enters the recovery code with a **free-text field**, not the segmented
> `OtpInput`, because recovery codes are not fixed-length numeric. Reusing `OtpInput` with a
> 6-digit `codeLength` for recovery is an AND-039 design choice that diverges from the web
> contract and is an **unverified assumption** about recovery-code format; prefer a plain
> single-line text field for recovery entry to match the web reference.

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

> Field-source note (verified §16): of the state fields above, only `code`, `activeFactor`,
> `isVerifying`, `remaining_factors`-derived `stepIndex/stepCount`, and `error` map onto verified
> server data. `codeLength` (default 6), `resendCooldownSeconds` (default 30), and
> `expiresAtEpochMs` are **not** returned by the `begin`/`verify` contract (`ChallengeResp` =
> `{challenge_id, sent_to?}`); they are client-side defaults/UX state. `expiresAtEpochMs` should
> stay nullable and the expiry timer must be hidden when null rather than assuming the server
> always supplies an absolute expiry (this is R3's open question — answered: it does not).

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

> **Contract corrected against OpenAPI + frontend (§16).** Several shapes below were wrong in
> the draft and have been replaced with the verified shapes. Field names matter because they
> are what AND-038's serializers and AND-039's rendering bind to.

`POST /ui/session/start` (AND-037/038) → `UiSessionStartResp`. Request body is
`UiSessionStartReq { challenge_context?: object }`. Response that opens MFA (verified):

```json
{
  "auth_required": true,
  "challenge_id": "chal_7Yc...",
  "required_factors": ["totp", "sms"],
  "session_id": null
}
```
Only `auth_required` is required; `challenge_id` and `session_id` are nullable. `required_factors`
is an array of plain strings (`"totp" | "sms" | "email"`), not an enum object.

`POST /ui/mfa/{sms,email}/begin` — body `{ "challenge_id": "chal_..." }` (`SmsBeginReq` /
`EmailBeginReq`). **TOTP has no `begin`.** Verified response is `ChallengeResp`:

```json
{ "challenge_id": "chal_7Yc...", "sent_to": ["•••• 4821"] }
```
The earlier draft's `factor` / `destination_hint` / `code_length` / `resend_cooldown_seconds` /
`expires_at` fields are **NOT in the contract** (OpenAPI declares an untyped 200 body; the
frontend type `ChallengeResp` carries only `challenge_id` + optional `sent_to[]`). Any masked
hint must come from `sent_to`; code length, resend cooldown and code expiry are **not**
server-provided (see §16 Open assumptions).

`POST /ui/mfa/sms/verify` / `email/verify` — body `{ "challenge_id": "...", "code": "123456" }`
(`SmsVerifyReq` / `EmailVerifyReq`, field **`code`**).

`POST /ui/mfa/totp/verify` — body `{ "challenge_id": "...", "totp_code": "123456" }`
(`TotpVerifyReq`, field is **`totp_code`**, NOT `code`).

`POST /ui/mfa/recovery/{factor}` — body `{ "challenge_id": "...", "recovery_code": "...",
"factor"?: "totp" }` (`RecoveryReq`; field is **`recovery_code`**).

All verify/recovery calls return `MfaVerifyResp` (verified):

```json
{
  "status": "ok",
  "session_id": null,
  "required_factors": ["totp", "sms"],
  "passed": { "totp": true },
  "remaining_factors": ["sms"]
}
```
The draft's `{ "verified": true, ... }` is **wrong**: there is no `verified` boolean. Success is
read from `remaining_factors.length == 0` plus `status`/`passed`, exactly as the web client does
(`resp.remaining_factors.length === 0`). `finalize` (`UiSessionFinalizeReq { challenge_id,
remember_device?=false }`) is then called by AND-038 to complete login.

Error (FastAPI `detail`, mapped by core-network to typed `MfaError`):

```json
{ "detail": [{ "msg": "Invalid or expired code" }] }
```

`detail` may be a `string`, an array of `{ msg }` objects, or an object `{ code, ... }` — all
three forms are handled by the web client's `normalizeErrorDetail`; AND-038's mapper mirrors it
to produce the typed `MfaError` AND-039 renders. All MFA calls require the `X-CSRF-Token` header
(value taken from the `ui_csrf` cookie) and ride the persistent cookie jar
(`credentials: include`) — handled by core-network, not this ticket.

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
  resend. The backend returns these as a FastAPI `detail` (string / `[{msg}]` / `{code}`);
  AND-038 classifies them into the typed `MfaError`. **Note (§16):** the verify endpoints
  document only `200` and `422` in OpenAPI and an untyped success body, so the exact
  invalid/expired/locked discriminators are not formally specified — the typed `MfaError`
  buckets are an AND-038/AND-039 mapping convention, not a verified server contract.
- **Lockout / too many attempts:** `MfaError.Locked(retryAfterSeconds)` disables submit and
  shows a cooldown timer reusing `rememberCountdown`.
- **Network/timeout:** the dev backend is unreliable; verify is a non-idempotent POST so it is
  **not** auto-retried. On `MfaError.Network` show a retry affordance the user taps;
  `begin`/resend (effectively idempotent re-send) may use AND-038's bounded backoff. ~20s
  timeouts apply at the OkHttp layer.
- **401 mid-flow:** core-network performs at most a single `POST /ui/session/refresh` + one
  retry; if it still fails AND-038 emits `SessionLost` and AND-039 routes to credentials.
  **Correction (§16):** in the web reference the auto-refresh only runs when the user is
  **already authenticated**; an unauthenticated 401 (the normal case *during* MFA login, before
  finalize) propagates straight to the caller without a refresh attempt. So a 401 during the MFA
  step should be treated as `SessionLost`/challenge-expired and route to credentials rather than
  triggering a refresh; refresh+retry is the post-login behavior.
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
- **R2 — Recovery factor ambiguity.** *Resolved (§16):* the backend **does** expose recovery as
  a real verify path — `POST /ui/mfa/recovery/{factor}` with body `RecoveryReq
  { challenge_id, recovery_code, factor? }`. Treat recovery as a factor path, not a static help
  link. Remaining open point: recovery-code **format/length** is not specified (web uses a
  free-text field), so do not force a 6-digit `OtpInput` for it.
- **R3 — Timer accuracy across background/foreground.** *Resolved (§16):* `begin`
  (`ChallengeResp`) does **not** return an absolute `expires_at`, nor a cooldown duration. The
  expiry timer is therefore client-derived only when a (currently non-existent) server expiry is
  supplied; until then the screen must hide the expiry timer rather than fabricate one, and the
  resend cooldown is a client constant. If the backend later adds an absolute `expires_at`,
  prefer it over a duration so countdowns survive backgrounding.
- **R4 — Unreliable dev host** can make UI tests flaky if accidentally hitting the network;
  mitigated by faking the ViewModel in `androidTest`.
- **R5 — Code length variability.** *Corrected (§16):* `begin` (`ChallengeResp`) does **not**
  return a code length, and the web reference hardcodes 6 for TOTP/SMS/EMAIL. `codeLength`
  remains a state field defaulting to 6 so a future server-supplied length can be honored, but
  there is no current server source for it — do not present it as server-driven.

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. OpenAPI pointers are
`METHOD /path` and/or `components.schemas.<Name>` in
`reference/openapi.pretty.json` (index: `reference/openapi.index.txt`). Frontend pointers are
paths under `reference/src/`. "framework ref" = Android/Jetpack documentation.

1. **`POST /ui/session/start` opens MFA with `auth_required`, `challenge_id`,
   `required_factors`.** VERIFIED. `POST /ui/session/start` → `UiSessionStartResp`
   (`components.schemas.UiSessionStartResp`: `auth_required` (req), `challenge_id?`,
   `required_factors: string[]`, `session_id?`); `src/api/types.ts: SessionStartResp`;
   `src/api/endpoints/auth.ts: sessionStart`.
2. **`required_factors` is an array of plain strings (`totp|sms|email`), not an enum object.**
   VERIFIED. `UiSessionStartResp.required_factors.items.type = string`;
   `src/pages/Login.tsx` (`factors.includes("totp"|"sms"|"email")`).
3. **SMS/EMAIL have a `begin` step; TOTP does not.** CORRECTED (draft listed
   `/ui/mfa/{totp|sms|email}/begin`). VERIFIED endpoints: `POST /ui/mfa/sms/begin`
   (`SmsBeginReq`), `POST /ui/mfa/email/begin` (`EmailBeginReq`); **no** `/ui/mfa/totp/begin`
   in `openapi.index.txt`; `src/api/endpoints/auth.ts` defines `beginSms`/`beginEmail` but only
   `verifyTotp` (no `beginTotp`).
4. **`begin` request body is `{ challenge_id }`.** VERIFIED.
   `components.schemas.SmsBeginReq` / `EmailBeginReq` = `{ challenge_id }` (required);
   `src/api/types.ts: SmsBeginReq, EmailBeginReq`.
5. **`begin` response shape.** CORRECTED. Draft claimed
   `{ factor, destination_hint, code_length, resend_cooldown_seconds, expires_at }`. Actual:
   OpenAPI declares `POST /ui/mfa/sms/begin` 200 with an **untyped** body (`schema: {}`); the
   frontend types it as `ChallengeResp = { challenge_id, sent_to?: string[] }`
   (`src/api/types.ts: ChallengeResp`; `src/api/endpoints/auth.ts: beginSms` →
   `api.post<ChallengeResp>`). None of `destination_hint`/`code_length`/
   `resend_cooldown_seconds`/`expires_at` exist in the contract.
6. **SMS/EMAIL verify body field is `code`.** VERIFIED.
   `components.schemas.SmsVerifyReq` / `EmailVerifyReq` = `{ challenge_id, code }`;
   `src/api/types.ts: SmsVerifyReq, EmailVerifyReq`; `src/pages/Login.tsx`
   (`verifySms({ challenge_id, code })`).
7. **TOTP verify body field is `totp_code`, not `code`.** CORRECTED (draft used `code` for all).
   `components.schemas.TotpVerifyReq` = `{ challenge_id, totp_code }`;
   `src/api/types.ts: TotpVerifyReq`; `src/pages/Login.tsx`
   (`verifyTotp({ challenge_id, totp_code })`).
8. **Verify response shape.** CORRECTED. Draft claimed `{ verified, remaining_factors }`.
   Actual `MfaVerifyResp = { status, session_id?, required_factors, passed, remaining_factors }`
   (`src/api/types.ts: MfaVerifyResp`; `src/api/endpoints/auth.ts: verifyTotp/verifySms/
   verifyEmail` → `api.post<MfaVerifyResp>`). No `verified` boolean; success is
   `remaining_factors.length === 0` (`src/pages/Login.tsx`).
9. **Recovery is a real verify path.** VERIFIED/CORRECTED. `POST /ui/mfa/recovery/{factor}`
   (`op=ui_recovery_factor...`, `req=RecoveryReq`, path param `factor`);
   `src/api/endpoints/auth.ts: useRecoveryCode`. Request field is **`recovery_code`** (+
   `challenge_id`, optional `factor` default `"totp"`) — `components.schemas.RecoveryReq`;
   `src/api/types.ts: RecoveryReq`. (Draft FR-6 implied generic `code`.)
10. **Recovery code entry uses a segmented 6-digit `OtpInput`.** UNVERIFIED-ASSUMPTION /
    flagged. Web reference uses a free-text field for recovery (`src/pages/Login.tsx` recovery
    branch uses an `<Input>` bound to `recoveryCode`, not `OtpInput`); recovery-code format is
    not specified in OpenAPI. Recommend a plain text field.
11. **`finalize` request is `{ challenge_id, remember_device?=false }`.** VERIFIED.
    `POST /ui/session/finalize` → `req=UiSessionFinalizeReq`
    (`components.schemas.UiSessionFinalizeReq`); `src/api/types.ts: SessionFinalizeReq`;
    `src/api/endpoints/auth.ts: sessionFinalize`. (Owned by AND-038; cited for UI context.)
12. **CSRF: `ui_csrf` cookie echoed as `X-CSRF-Token`; cookie-jar transport.** VERIFIED.
    `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`,
    `credentials: "include"`).
13. **Error `detail` may be string / `[{msg}]` / `{code,...}`.** VERIFIED.
    `src/api/client.ts: normalizeErrorDetail` handles all three; tests in
    `src/api/client.errorMapping.test.ts`. Validation errors are
    `components.schemas.HTTPValidationError` (422).
14. **401 mid-flow → single `POST /ui/session/refresh` + one retry.** VERIFIED, with nuance.
    `POST /ui/session/refresh` exists (`openapi.index.txt`); `src/api/client.ts` performs one
    refresh+retry **only if already authenticated** — an unauthenticated 401 (the MFA-login
    case) propagates without refresh. Corrected in §7.
15. **`OtpInput` default length 6, digits-only, completion callback.** VERIFIED (component
    contract AND-020 mirrors). `src/components/ui/otp-input.tsx` (`length = 6`, digit regex
    `\D`, `onComplete`).
16. **Typed `MfaError` buckets (Invalid/Expired/Locked/Network) with `retryAfterSeconds`.**
    UNVERIFIED-ASSUMPTION. Verify endpoints document only `200`/`422` with an untyped success
    body in OpenAPI; the discriminated `MfaError` set and `Locked(retryAfterSeconds)` are an
    AND-038/AND-039 mapping convention, not a server contract.
17. **Compose / Material 3 / Navigation-Compose / Hilt + `collectAsStateWithLifecycle`,
    `liveRegion`, merged semantics, 48dp targets.** VERIFIED (framework ref):
    developer.android.com/jetpack/compose, developer.android.com/develop/ui/compose/navigation,
    developer.android.com/develop/ui/compose/accessibility,
    dagger.dev/hilt. Choices are reasonable Android conventions; not derivable from backend
    sources.

### Corrections made

- §2, §5: removed the nonexistent `/ui/mfa/totp/begin`; TOTP has only `verify`.
- §5: replaced fabricated `begin` response (`factor/destination_hint/code_length/
  resend_cooldown_seconds/expires_at`) with the real `ChallengeResp { challenge_id, sent_to? }`.
- §5: TOTP verify field corrected `code` → `totp_code`.
- §5: verify response corrected `{ verified, remaining_factors }` →
  `MfaVerifyResp { status, session_id?, required_factors, passed, remaining_factors }`; success
  is `remaining_factors.length == 0`.
- §5, FR-6, §13/R2: recovery request field corrected to `recovery_code` (+ optional `factor`);
  recovery confirmed as a real `verify` path, not a static help link.
- FR-1: pre-selection `destination_hint` flagged as not in contract; derive from `sent_to`.
- FR-2 / R5: `code_length` is not server-provided; web hardcodes 6.
- FR-4 / R3: resend cooldown and code expiry are client-side; web reference has no cooldown and
  `begin` returns no `expires_at`.
- §7: 401-during-MFA does not auto-refresh (user not yet authenticated) → treat as SessionLost.

### Open assumptions

- **Server-driven `codeLength`** — none in `ChallengeResp`/OpenAPI; assumed constant 6
  (matches web). Kept as nullable-defaulted state for forward compatibility.
- **`resendCooldownSeconds`** — purely a client UX constant (30s); no server source; web has no
  cooldown at all. Not server-authoritative.
- **`expiresAtEpochMs` / code-expiry timer** — `begin` returns no expiry; timer hidden when
  null. Cannot be verified because the contract omits it.
- **Masked per-factor `destination_hint` at selection time** — only `sent_to[]` exists, and only
  *after* `begin`. Any pre-selection hint is unverifiable from the sources.
- **Typed `MfaError` discriminators incl. `Locked(retryAfterSeconds)`** — error taxonomy is a
  client mapping; server only guarantees a FastAPI `detail` and 422 validation errors.
- **Recovery-code format/length** — unspecified; web uses free text. A 6-digit `OtpInput` for
  recovery is an unverified assumption.
- **TOTP/SMS test codes (e.g. `123456`) accepted by the dev host** — not assertable from
  sources; tests drive the UI via fakes, so real codes are irrelevant to AND-039's gate.

## 17. Test Plan

IDs `TC-AND-039-NN`. Acceptance Criteria referenced are from §14 (AC-1…AC-10). AND-039 is a
stateless Compose screen driven by a faked `MfaViewModel`/state holder (`core-testing`); no
real network. Targets: **JVM/Robolectric** (local, no device), **emulator AVD `test35`**
(API 35, x86_64; fast Compose/instrumented CI), **physical device** (Samsung Galaxy A15 5G,
SM-A156U, API 34, arm64-v8a). Compose-UI suites run on either device target; cases below note
when the **physical device** is preferred (real soft-keyboard `NumberPassword` behavior,
clipboard/paste, TalkBack, FLAG_SECURE, API-34-vs-35 differences). No camera/biometric/WebRTC/
FCM behavior is in scope for this ticket.

- **TC-AND-039-01 — TOTP happy path (UI).** Type: Compose-UI. Target: emulator `test35`
  (fast); re-run once on physical device for real keyboard/paste. Preconditions: faked state
  `Mode=ENTERING, activeFactor=TOTP, codeLength=6, isVerifying=false`. Steps: enter 6 digits via
  `OtpInput`; observe auto-submit at full length. Expected: `onSubmitCode("123456")` invoked
  once; on pushed success state (`remaining_factors=[]`) screen reports completion (no terminal
  UI; `Authenticated` event observed). Note: TOTP has **no** resend/begin — assert no "Resend"
  shown. Traces: AC-1, AC-2, AC-4.
- **TC-AND-039-02 — SMS happy path incl. resend cooldown (UI).** Type: Compose-UI. Target:
  emulator `test35`. Preconditions: `activeFactor=SMS, resendCooldownSeconds=30`. Steps: assert
  "Resend code" disabled with live countdown; `mainClock.advanceTimeBy(30s)` → re-enabled; tap
  Resend → `onResend()` (maps to `POST /ui/mfa/sms/begin`); enter 6 digits → `onSubmitCode`.
  Expected: countdown ticks to 0 and re-enables; `onResend` and `onSubmitCode` invoked. Traces:
  AC-1, AC-2, AC-4, AC-5.
- **TC-AND-039-03 — Verify request field mapping (contract/MockWebServer).** Type:
  contract/MockWebServer (drives AND-038's repo, included to lock the corrected field names the
  UI depends on). Target: JVM/Robolectric. Preconditions: MockWebServer queues 200
  `MfaVerifyResp`. Steps: trigger TOTP verify, then SMS verify, then recovery. Expected:
  recorded bodies are TOTP `{challenge_id, totp_code}`, SMS `{challenge_id, code}`, recovery
  `{challenge_id, recovery_code[, factor]}`; response parsed via `status`+`remaining_factors`
  (no `verified` field). Traces: AC-1, AC-2.
- **TC-AND-039-04 — Submit gating (UI).** Type: Compose-UI. Target: emulator `test35`.
  Preconditions: `codeLength=6`. Steps: enter 5 digits → assert Verify disabled; enter 6th →
  enabled; push `isVerifying=true` → Verify disabled + progress shown, auto-submit suppressed.
  Expected: gating equals `code.length == codeLength && !isVerifying`. Traces: AC-4.
- **TC-AND-039-05 — Factor selection visibility + selection callback (UI).** Type: Compose-UI.
  Target: emulator `test35`. Preconditions A: `availableFactors=[TOTP]` (single). Precondition
  B: `[TOTP, SMS]`. Steps: A → assert no selection list and no "Use a different method"; B →
  list shown, tap SMS → `onSelectFactor(SMS)`. Expected: selection appears only when >1 factor.
  Traces: AC-3, AC-6.
- **TC-AND-039-06 — Switch factor + recovery affordance (UI).** Type: Compose-UI. Target:
  emulator `test35`. Preconditions: `availableFactors=[TOTP, SMS]`, active=TOTP. Steps: tap "Use
  a different method" → `onSwitchFactor()` (state returns to SELECTING, `challenge_id`
  unchanged); assert recovery link always present; tap → `onRecovery()` navigates
  `MfaRoute.Recovery`. Expected: switch keeps challenge; recovery always available. Traces:
  AC-6.
- **TC-AND-039-07 — Recovery code entry (UI).** Type: Compose-UI. Target: emulator `test35`.
  Preconditions: on `MfaRoute.Recovery`. Steps: enter recovery code in a free-text field; submit
  → `onSubmitCode`/recovery callback. Expected: recovery uses a non-segmented text field (per
  §16 correction) and maps to `recovery_code`. Traces: AC-1, AC-6.
- **TC-AND-039-08 — Error states + expiry timer (UI).** Type: Compose-UI. Target: emulator
  `test35`. Steps: push `InvalidCode` → inline error, field retained; `ExpiredCode` → field
  cleared, resend prompted; `Locked(retryAfter=60)` → submit disabled with countdown; with
  `expiresAtEpochMs=null` assert **no** expiry timer rendered (per §16); with a non-null expiry
  in the past assert "expired" surfaced. Expected: each error renders inline below OTP and gates
  submit per §7. Traces: AC-7.
- **TC-AND-039-09 — Multi-step continuation (UI).** Type: Compose-UI. Target: emulator
  `test35`. Preconditions: verify success with `remaining_factors=["sms"]`. Steps: push next
  state (active=SMS). Expected: OTP field cleared, cooldown/expiry timers reset, no nav event
  (same composable). Traces: AC-8.
- **TC-AND-039-10 — Offline / flaky dev-host path (integration).** Type: integration (faked
  repo emitting `MfaError.Network`) + manual confirmation on physical device with airplane mode.
  Target: **physical device** (real radio/airplane-mode toggle) primary; emulator for the faked
  path. Steps: with connectivity off, submit code → assert non-blocking offline banner, entered
  code preserved, retry affordance available; restore network and retry → succeeds. Verify is a
  non-idempotent POST and is **not** auto-retried silently. Expected: graceful offline UX, no
  data loss, no auto-retry of verify. Traces: AC-7.
- **TC-AND-039-11 — Secret redaction (unit + manual).** Type: unit (redaction/log assertions) +
  manual log review. Target: JVM/Robolectric (unit); physical device for manual logcat review.
  Steps: drive verify/resend with a known code and `challenge_id`; capture analytics payloads
  and logs. Expected: no OTP `code`/`totp_code`/`recovery_code`, no `challenge_id`, no unmasked
  destination ever appears in logs/telemetry/crash breadcrumbs; `OtpInput` uses
  `KeyboardType.NumberPassword`. Traces: AC-9.
- **TC-AND-039-12 — `rememberCountdown` formatting (unit).** Type: unit. Target:
  JVM/Robolectric. Steps: feed remaining millis across boundaries (e.g. 65s→"01:05", 0→"00:00",
  negative floored to "00:00"). Expected: correct mm:ss, zero floor, no negatives. Traces: AC-5,
  AC-7.
- **TC-AND-039-13 — Accessibility (instrumented).** Type: instrumented/Compose-UI a11y. Target:
  **physical device** (real TalkBack) primary; emulator with Accessibility Test Framework for
  CI. Steps: assert `OtpInput` exposes one merged semantics node ("One-time code, 6 digits");
  all actions (Verify/Resend/Switch/Recovery/factor items) have content descriptions and ≥48dp
  targets; error banner and timers use `liveRegion = Polite`; render at 200% font scale and in
  RTL with no clipping/overlap. Expected: all assertions pass. Traces: AC-10.
- **TC-AND-039-14 — Process-death / no live challenge (instrumented).** Type:
  instrumented/e2e. Target: emulator `test35` (configurable process death) primary; spot-check
  physical device. Steps: enter MFA, trigger process death/recreate with no persisted challenge.
  Expected: screen shows empty state and routes back to credentials via `SessionLost`;
  `challenge_id` never persisted to disk. Traces: AC-9 (no persisted secrets), AC-1
  (flow-integrity).

### Coverage matrix

| AC (§14) | Covered by |
|---|---|
| AC-1 (each factor path completable) | TC-01, TC-02, TC-03, TC-07, TC-14 |
| AC-2 (TOTP+SMS UI end-to-end) | TC-01, TC-02, TC-03 |
| AC-3 (selection only when >1 factor) | TC-05 |
| AC-4 (OtpInput, paste, auto-submit, gating) | TC-01, TC-02, TC-04 |
| AC-5 (resend SMS/EMAIL, cooldown, TOTP none) | TC-01, TC-02, TC-12 |
| AC-6 (switch keeps challenge; recovery always) | TC-05, TC-06, TC-07 |
| AC-7 (errors + expiry timer gate submit) | TC-08, TC-10, TC-12 |
| AC-8 (multi-step clears code/resets timers) | TC-09 |
| AC-9 (no secrets logged/telemetered) | TC-11, TC-14 |
| AC-10 (accessibility, 200% font, RTL) | TC-13 |
