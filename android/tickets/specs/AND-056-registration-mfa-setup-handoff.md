---
id: AND-056
title: Registration → MFA setup handoff
milestone: M2
epic: E08
priority: P1
size: M
status: draft
depends_on: [AND-054, AND-064]
blocks: []
---

# AND-056 — Registration → MFA setup handoff

## 1. Overview & Goal

When a user completes account confirmation in the registration flow (AND-054,
`POST /ui/register/confirm`), the backend may indicate that the new account
still requires Multi-Factor Authentication enrollment before it can be used. The
confirm response carries an `mfa_setup` directive (and, for SMS, a pre-filled
`sms_phone`) describing which factors the user opted into during
`POST /ui/register/start` (AND-053).

This ticket implements the **handoff**: the logic and navigation that reads
`RegisterConfirmResp.mfa_setup` / `sms_phone` after a successful confirm and
routes the user directly into the MFA enrollment surfaces owned by AND-064 (MFA
device management), pre-seeding those screens so the user is "guided into device
enrollment" rather than dumped on a generic home or settings screen.

The scope is intentionally the *routing/glue layer only*. The enrollment screens
themselves (TOTP QR/secret confirm, SMS code confirm, email code confirm, the
device list) are owned by AND-064. This ticket consumes those screens through a
typed enrollment entry-point and guarantees that a freshly confirmed account
with pending MFA setup lands on the correct first enrollment step with the right
context populated.

Goal / definition of success: A new user who opted into MFA at registration and
then confirms their email is automatically and reliably guided into the matching
device-enrollment flow; a user with no pending MFA setup proceeds to the
authenticated home destination unchanged.

## 2. Context & References

- **Module**: `feature-auth` (registration sub-package
  `com.testlogon.android.feature.auth.register`), navigation glue in `app`
  module's `NavGraph`.
- **Upstream**:
  - AND-053 (Registration: start) defines the opt-in form
    (`delivery method`, optional SMS/TOTP MFA opt-in) and the
    `RegisterStartResp` mapping.
  - AND-054 (Registration: confirm + resend) owns the confirm screen,
    `POST /ui/register/confirm`, `POST /ui/register/resend`, and the
    `RegisterConfirmResp` DTO. This ticket extends the *consumption* of that
    DTO, not its definition.
  - AND-033 (MFA API + DTOs) provides `AuthApi` MFA methods and DTOs.
- **Downstream / target**: AND-064 (MFA device management) owns the actual
  enrollment screens and `devices/begin|confirm|{id}/remove` calls. This ticket
  navigates into AND-064 destinations.
- **Web reference**: `frontend/src/api/endpoints/register.ts` (confirm response
  shape) and `frontend/src/api/endpoints/mfa.ts` for the enrollment entry the
  web app uses post-confirm; shared types in `frontend/src/api/types.ts`
  (`RegisterConfirmResp`). Mirror the web routing semantics.
- **Backend**: FastAPI, `/openapi.json` on `http://18.222.237.167:8000`.
  Confirm `RegisterConfirmResp` field names/enum values against the live schema
  before finalizing the Moshi DTO (see §13).

## 3. Functional Requirements

FR-1. After a successful `POST /ui/register/confirm` (success surfaced by
AND-054), the registration confirm ViewModel must inspect
`RegisterConfirmResp.mfa_setup`.

FR-2. If `mfa_setup` indicates one or more pending factors, the app must route
the user into the corresponding first MFA enrollment step:
- `totp` → TOTP enrollment (QR + manual secret) screen (AND-064).
- `sms` → SMS device enrollment screen, **pre-filled** with
  `RegisterConfirmResp.sms_phone` when present.
- `email` → email device enrollment screen, pre-filled with the registered
  email if returned.

FR-3. If `mfa_setup` lists multiple factors, the user is routed to the **first**
required factor; on completion of that factor the enrollment flow (AND-064)
advances to the next pending factor. This ticket passes the full ordered list so
AND-064 can sequence; it does not itself render a chooser unless AND-064 expects
one (default: drive the first factor).

FR-4. If `mfa_setup` is absent/empty (no pending MFA), the app routes to the
authenticated home destination and clears the registration back stack.

FR-5. The MFA enrollment entered from registration is presented as a guided,
mandatory step: the back stack from confirm → enrollment must NOT allow popping
back into the registration confirm/start screens (those are completed). System
back from the first enrollment step should be handled per AND-064 policy
(typically a "skip/finish later" confirmation, not return to confirm).

FR-6. The handoff context (which factors, the phone number, the post-enrollment
destination) survives process death / configuration change.

FR-7. The routing decision must be a single, unit-testable pure function that
maps a `RegisterConfirmResp` to a navigation intent.

## 4. Technical Design

### 4.1 Handoff context model (`core-model`)

```kotlin
package com.testlogon.android.core.model.auth

/** Ordered factors the new account must enroll, derived from confirm. */
enum class MfaSetupFactor { TOTP, SMS, EMAIL }

/** Parcelable handoff payload passed into the MFA enrollment graph. */
@Parcelize
data class MfaSetupHandoff(
    val factors: List<MfaSetupFactor>,   // non-empty when enrollment required
    val smsPhone: String? = null,         // pre-fill for SMS factor
    val email: String? = null,            // pre-fill for email factor
) : Parcelable {
    val isRequired: Boolean get() = factors.isNotEmpty()
}
```

### 4.2 Routing decision (pure function)

```kotlin
package com.testlogon.android.feature.auth.register

sealed interface PostConfirmRoute {
    data class EnrollMfa(val handoff: MfaSetupHandoff) : PostConfirmRoute
    data object Home : PostConfirmRoute
}

/** Pure mapper — no Android deps; fully unit testable (FR-7). */
fun RegisterConfirmResp.toPostConfirmRoute(): PostConfirmRoute {
    val factors = mfaSetup
        ?.mapNotNull { it.toMfaSetupFactorOrNull() }
        ?.distinct()
        .orEmpty()
    return if (factors.isEmpty()) PostConfirmRoute.Home
    else PostConfirmRoute.EnrollMfa(
        MfaSetupHandoff(
            factors = factors,
            smsPhone = smsPhone?.takeIf { it.isNotBlank() },
            email = email?.takeIf { !it.isNullOrBlank() },
        ),
    )
}

private fun String.toMfaSetupFactorOrNull(): MfaSetupFactor? = when (lowercase()) {
    "totp", "authenticator" -> MfaSetupFactor.TOTP
    "sms" -> MfaSetupFactor.SMS
    "email" -> MfaSetupFactor.EMAIL
    else -> null   // unknown factor → ignored, logged (forward-compat)
}
```

Unknown factor strings are dropped rather than failing the whole handoff: a new
account should never be blocked from sign-in by an enum the client doesn't yet
understand. If dropping all factors leaves the list empty, the user proceeds to
home (degrade gracefully).

### 4.3 ViewModel integration (extends AND-054)

The AND-054 `RegisterConfirmViewModel` already exposes confirm state. This
ticket adds a one-shot navigation event channel:

```kotlin
@HiltViewModel
class RegisterConfirmViewModel @Inject constructor(
    private val registerRepository: RegisterRepository,   // AND-054
    private val savedState: SavedStateHandle,
) : ViewModel() {

    val uiState: StateFlow<RegisterConfirmUiState>          // AND-054

    private val _nav = Channel<PostConfirmRoute>(Channel.BUFFERED)
    val nav: Flow<PostConfirmRoute> = _nav.receiveAsFlow()

    fun onConfirm(code: String) = viewModelScope.launch {
        when (val r = registerRepository.confirm(code)) {   // ApiResult<RegisterConfirmResp>
            is ApiResult.Success -> _nav.send(r.data.toPostConfirmRoute())
            is ApiResult.Failure -> /* AND-054 error surfacing */
        }
    }
}
```

Using a buffered `Channel` (not `StateFlow`) ensures the navigation event fires
exactly once and is not re-emitted after a config change while the destination
is already on the stack.

### 4.4 Navigation (single-Activity Navigation-Compose)

Routes (type-safe Navigation-Compose, Kotlin serialization):

```kotlin
@Serializable data object RegisterConfirm
@Serializable data class MfaEnroll(            // entry into AND-064 graph
    val factorsCsv: String,                    // ordered, e.g. "TOTP,SMS"
    val smsPhone: String? = null,
    val email: String? = null,
)
@Serializable data object Home
```

Collector in the confirm composable:

```kotlin
LaunchedEffect(Unit) {
    vm.nav.collect { route ->
        when (route) {
            is PostConfirmRoute.EnrollMfa -> navController.navigate(
                MfaEnroll(
                    factorsCsv = route.handoff.factors.joinToString(",") { it.name },
                    smsPhone = route.handoff.smsPhone,
                    email = route.handoff.email,
                ),
            ) { popUpTo<RegisterStart>() { inclusive = true } }   // FR-5
            PostConfirmRoute.Home -> navController.navigate(Home) {
                popUpTo<RegisterStart>() { inclusive = true }
            }
        }
    }
}
```

`MfaEnroll` is the contract surface AND-064 must accept. The CSV-encoded ordered
factor list keeps the typed nav arg primitive-serializable while preserving
order; AND-064 parses it back into `List<MfaSetupFactor>` and drives the
first/next pending factor (FR-3).

## 5. API Contract

This ticket issues **no new network calls**. It consumes the response of
`POST /ui/register/confirm` (owned by AND-054) and hands off to enrollment
endpoints (owned by AND-064). The only API-adjacent work here is finalizing the
`RegisterConfirmResp` DTO fields this ticket reads.

Confirm request (AND-054, for reference, cookie + `X-CSRF-Token`):

```
POST /ui/register/confirm
Content-Type: application/json
X-CSRF-Token: <ui_csrf cookie value>

{ "email": "user@example.com", "code": "123456" }
```

Confirm response — fields consumed by this ticket:

```json
{
  "confirmed": true,
  "mfa_setup": ["totp", "sms"],
  "sms_phone": "+15551234567",
  "email": "user@example.com"
}
```

Moshi DTO (additive fields on the AND-054 DTO):

```kotlin
@JsonClass(generateAdapter = true)
data class RegisterConfirmResp(
    @Json(name = "confirmed") val confirmed: Boolean = false,
    @Json(name = "mfa_setup") val mfaSetup: List<String>? = null,
    @Json(name = "sms_phone") val smsPhone: String? = null,
    @Json(name = "email") val email: String? = null,
)
```

Notes:
- `mfa_setup` is tolerated as `null`, `[]`, or a list of factor strings.
  Verify the exact wire encoding against `/openapi.json`; if the backend returns
  an object (e.g. `{ "required": [...] }`) instead of a bare array, adapt the
  DTO accordingly (see §13 open question).
- Downstream enrollment endpoints (AND-064/AND-033): TOTP
  `devices/begin|confirm|{id}/remove`, SMS/email `begin|confirm|remove`. Their
  contracts are owned by those tickets and are out of scope here.

## 6. Data & State Management

- **Transient handoff**: `MfaSetupHandoff` is not persisted to Room/DataStore.
  It is ephemeral routing context carried as type-safe navigation arguments and
  mirrored into `SavedStateHandle` for process-death survival (FR-6). Once the
  user reaches the MFA enrollment graph, AND-064 owns its own state.
- **No DataStore writes** in this ticket. The "MFA pending" condition is derived
  fresh from each confirm response, not cached, to avoid stale enrollment
  prompts.
- **Session state**: After confirm, the account exists but is not necessarily an
  authenticated UI session. If `GET /ui/me` / session state is needed before
  enrollment, that is handled by AND-064's begin calls (which carry the session
  cookie). This ticket does not call `/ui/session/*`.
- **Back stack as state**: `popUpTo<RegisterStart>(inclusive = true)` removes the
  whole registration sub-graph so the enrollment/home destination becomes the
  new effective root of this flow (FR-4, FR-5).

## 7. Error Handling & Resilience

- Confirm-call failures (network/timeout/4xx) are surfaced by AND-054 and do not
  trigger any handoff (no `nav` emission on `ApiResult.Failure`).
- **Malformed `mfa_setup`**: unknown factor strings are filtered out; if all are
  unknown the user routes to Home rather than into a broken enrollment graph.
- **Missing `sms_phone` with SMS factor**: route into the SMS enrollment screen
  with an empty/editable phone field; AND-064's screen validates/collects it.
  The handoff never blocks on a missing pre-fill.
- **Missing `email` with email factor**: same degrade — enrollment screen
  collects it.
- **Unreliable dev backend**: this ticket adds no network calls, so backoff/
  timeout policy is inherited from AND-054 (confirm) and AND-064 (enrollment).
  No retry logic is introduced here.
- **Double navigation**: the one-shot `Channel` plus `popUpTo` guards against
  duplicate enrollment destinations if `onConfirm` is somehow invoked twice.

## 8. Security & Privacy

- `sms_phone` is PII. It is passed only as an in-memory/SavedStateHandle nav arg
  and must NOT be written to logs (see §10), persisted to disk, or included in
  crash reports. Log only a redacted form (e.g. last 4 digits) if needed.
- No credentials are handled in this ticket; the password lives in the
  registration start flow (AND-053) and is never re-read here.
- Enrollment of MFA happens over the authenticated cookie session established by
  the registration flow; CSRF (`X-CSRF-Token` echoing the `ui_csrf` cookie) is
  enforced by the OkHttp interceptor and applies to AND-064's calls, not this
  ticket's glue.
- Treat the MFA requirement as security-relevant: do not provide a silent bypass
  path. Any "skip" affordance is owned and gated by AND-064.

## 9. Accessibility & i18n

- This ticket renders no new UI of its own (it is navigation glue), so it has no
  standalone screen to make accessible. The destination screens are AND-064's
  responsibility.
- If a brief transitional "Setting up security…" state is shown during the
  confirm→enroll transition, it must use a `Modifier.semantics` live-region
  announcement and a localized string (`R.string.register_mfa_handoff_loading`),
  not a hardcoded literal.
- All factor labels surfaced to the user (TOTP / SMS / Email) must come from
  string resources to support i18n; the enum→label mapping lives with AND-064.
- No hardcoded user-facing strings introduced by this ticket.

## 10. Telemetry & Logging

- Emit a structured analytics event on handoff decision:
  - `register_mfa_handoff` with properties:
    `decision` (`enroll` | `home`), `factors` (ordered factor names, no PII),
    `has_sms_phone` (boolean — never the number itself).
- Debug logging: log the routing decision and factor list at `Log.d` only in
  debug builds; never log `sms_phone` or `email` (PII) — redact to last 4 / hash.
- On unknown-factor drop, log a `Log.w` "unknown mfa_setup factor" with the raw
  token (factor tokens are not PII) to aid backend contract drift detection.
- No analytics PII; comply with §8 redaction rules.

## 11. Testing Strategy

Unit tests (`core-testing`, JUnit + Truth), the bulk of this ticket's coverage:

- `RegisterConfirmRespMapperTest` (`toPostConfirmRoute`):
  - `mfa_setup = null` → `Home`.
  - `mfa_setup = []` → `Home`.
  - `["totp"]` → `EnrollMfa(factors=[TOTP])`.
  - `["sms"]` with `sms_phone` → `EnrollMfa(factors=[SMS], smsPhone=…)`.
  - `["sms"]` with null `sms_phone` → `EnrollMfa`, `smsPhone == null`.
  - `["totp","sms","email"]` → ordered `[TOTP, SMS, EMAIL]` preserved.
  - duplicate factors deduped; case-insensitive (`"TOTP"`, `"Totp"`).
  - unknown factor `["webauthn"]` → `Home`; `["totp","webauthn"]` → `[TOTP]`.
  - blank `sms_phone`/`email` normalized to `null`.
- `RegisterConfirmViewModelTest` (Turbine on `nav` Flow):
  - successful confirm with MFA setup emits `EnrollMfa` exactly once.
  - successful confirm without MFA setup emits `Home`.
  - failed confirm emits nothing on `nav`.
- DTO test: Moshi adapter parses each `mfa_setup` shape (null/array/string list)
  from fixture JSON without throwing.

Instrumented / Compose UI test (`feature-auth` androidTest):
- After a stubbed successful confirm with `["sms"]` + phone, assert navigation
  lands on the SMS enrollment route with `smsPhone` arg populated and that
  `RegisterStart`/`RegisterConfirm` are not on the back stack (FR-5).
- After a no-MFA confirm, assert `Home` is the current destination.

Use a fake `RegisterRepository` from `core-testing`; do not hit the dev backend
in CI.

## 12. Dependencies & Sequencing

- **Depends on AND-054** (confirm + resend): provides `RegisterConfirmResp`, the
  confirm ViewModel, and the success signal this ticket hooks into. Must merge
  first.
- **Depends on AND-064** (MFA device management): provides the enrollment
  destinations and must accept the `MfaEnroll` nav contract (factor CSV +
  `smsPhone` + `email`). Coordinate the nav-arg contract with AND-064 before
  implementation; if AND-064 is not yet merged, gate behind a temporary
  placeholder destination so this ticket can land and be wired up on AND-064
  merge.
- Transitively relies on AND-053 (start opt-in produces the factors) and AND-033
  (MFA DTOs/API used by AND-064).
- Sequencing: AND-053 → AND-054 → (AND-033 → AND-064) → **AND-056**.

## 13. Risks & Open Questions

- **R1 — `mfa_setup` wire shape unconfirmed.** Backend may return a bare array,
  an object with a `required` list, or per-factor objects. Mitigation: verify
  against `/openapi.json` and `frontend/src/api/types.ts` before finalizing the
  DTO; the mapper is isolated so only `toPostConfirmRoute` changes.
- **R2 — Factor sequencing ownership.** Whether the multi-factor "next pending
  factor" loop lives in AND-064 or here. Decision (this spec): AND-064 owns
  sequencing; we pass the ordered list. Confirm with AND-064 owner.
- **R3 — Mandatory vs skippable enrollment.** Is registration-driven MFA setup
  mandatory? Assumed guided-but-skippable per AND-064 policy; the skip gate is
  not implemented here. Open question for product.
- **R4 — Session readiness.** Does confirm establish a usable cookie session, or
  is a `session/start` needed before enrollment `begin` calls succeed? Verify;
  if a session step is required, AND-064 (not this ticket) must perform it.
- **R5 — `email` field presence.** Confirm response may not echo `email`; mapper
  already degrades to `null` and enrollment collects it.

## 14. Acceptance Criteria

- AC-1 (source): A new user who opted into MFA at registration and confirms
  their account is automatically guided into the matching device-enrollment
  flow.
- AC-2: `RegisterConfirmResp.mfa_setup` containing `totp` routes to TOTP
  enrollment; `sms` routes to SMS enrollment with `sms_phone` pre-filled when
  present; `email` routes to email enrollment.
- AC-3: Multiple factors route to the first listed factor with the full ordered
  list forwarded to AND-064.
- AC-4: Absent/empty/all-unknown `mfa_setup` routes to Home and clears the
  registration back stack.
- AC-5: After handoff, system back does not return to the registration
  confirm/start screens.
- AC-6: The handoff survives configuration change and process death.
- AC-7: `sms_phone` never appears in logs or analytics payloads.
- AC-8: All §11 unit tests pass, including unknown-factor and null/empty cases.

## 15. Definition of Done

- `MfaSetupHandoff`, `MfaSetupFactor`, `PostConfirmRoute`, and
  `RegisterConfirmResp.toPostConfirmRoute()` implemented in the stated packages
  under `com.testlogon.android.*`.
- `RegisterConfirmViewModel` extended with the one-shot `nav` event channel and
  wired into the confirm composable's `LaunchedEffect` collector.
- `MfaEnroll` typed navigation route added and agreed with AND-064; navigation
  uses `popUpTo<RegisterStart>(inclusive = true)`.
- `RegisterConfirmResp` DTO fields (`mfa_setup`, `sms_phone`, `email`) added and
  verified against `/openapi.json`.
- All unit, ViewModel, DTO, and Compose UI tests from §11 written and green in
  CI; no dev-backend calls in tests.
- Telemetry event `register_mfa_handoff` emitted with PII-safe properties; PII
  redaction verified.
- Lint/detekt/ktlint clean; no hardcoded user-facing strings.
- Code reviewed and merged to `android-port`; AND-064 owner has confirmed the
  `MfaEnroll` nav contract.
