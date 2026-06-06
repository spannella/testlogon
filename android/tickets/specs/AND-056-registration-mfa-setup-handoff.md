---
id: AND-056
title: Registration → MFA setup handoff
milestone: M2
epic: E08
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
    /**
     * Confirm succeeded but no `session_id` was returned: the account is
     * verified but there is no authenticated session, so we cannot enter the
     * cookie-gated enrollment graph. Mirror the web client's "you can now sign
     * in" success state. (Added in review 2026-06-06 to match web semantics.)
     */
    data object VerifiedSignIn : PostConfirmRoute
}

/**
 * Pure mapper — no Android deps; fully unit testable (FR-7).
 * `registeredEmail` is supplied by the caller (the confirm screen's own state)
 * because the confirm response does NOT carry an email field (see §5 correction).
 */
fun RegisterConfirmResp.toPostConfirmRoute(
    registeredEmail: String? = null,
): PostConfirmRoute {
    // No session established by confirm → cannot enter the cookie-gated
    // enrollment graph; mirror web "verified, please sign in" (see §6).
    if (sessionId.isNullOrBlank()) return PostConfirmRoute.VerifiedSignIn
    val factors = mfaSetup
        ?.mapNotNull { it.toMfaSetupFactorOrNull() }
        ?.distinct()
        .orEmpty()
    return if (factors.isEmpty()) PostConfirmRoute.Home
    else PostConfirmRoute.EnrollMfa(
        MfaSetupHandoff(
            factors = factors,
            smsPhone = smsPhone?.takeIf { it.isNotBlank() },
            // CORRECTED: RegisterConfirmResp has no `email` field (verified
            // against OpenAPI RegisterConfirmResp + src/api/types.ts). The
            // registered email must be passed in by the caller from the
            // confirm-screen's own state, not read off the response.
            email = registeredEmail?.takeIf { !it.isNullOrBlank() },
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
            // No session from confirm: show the verified/sign-in success state
            // rather than entering the enrollment graph (mirrors web client).
            PostConfirmRoute.VerifiedSignIn -> navController.navigate(SignIn) {
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

{ "email": "user@example.com", "confirmation_code": "123456" }
```

> **CORRECTED (review 2026-06-06):** the request field is `confirmation_code`,
> NOT `code`. Verified against OpenAPI `RegisterConfirmReq` (required:
> `email`, `confirmation_code`) and `src/api/types.ts: RegisterConfirmReq`.
> The request body is owned by AND-054; noted here for accuracy.

Confirm response — actual schema (verified against OpenAPI `RegisterConfirmResp`
and `src/api/types.ts: RegisterConfirmResp`):

```json
{
  "status": "confirmed",
  "session_id": "sess_abc123",
  "mfa_setup": ["totp", "sms"],
  "sms_phone": "+15551234567"
}
```

> **CORRECTED (review 2026-06-06):** the earlier draft claimed a boolean
> `confirmed` field and an `email` field on the response. Neither exists. The
> real required field is `status` (string); success is `getMe`/session-gated via
> `session_id`, not a boolean. There is **no `email`** in the response — the web
> client uses the locally-held registered email, not a response echo. `session_id`
> (nullable string) IS present and is load-bearing (see §6/§13-R4).

Moshi DTO (additive fields on the AND-054 DTO — corrected to match wire schema):

```kotlin
@JsonClass(generateAdapter = true)
data class RegisterConfirmResp(
    @Json(name = "status") val status: String = "",     // required on wire
    @Json(name = "session_id") val sessionId: String? = null,
    @Json(name = "mfa_setup") val mfaSetup: List<String>? = null,
    @Json(name = "sms_phone") val smsPhone: String? = null,
)
```

Notes:
- `mfa_setup` is a **bare array of strings** (`items: {type: string}`),
  tolerated as `null`/absent or `[]`. VERIFIED against OpenAPI — it is NOT an
  object with a `required` list, so R1 (§13) is resolved. The mapper still drops
  unknown tokens for forward-compat.
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
- **Session state (CORRECTED — review 2026-06-06)**: confirm DOES establish a
  session — the response returns a nullable `session_id`, and the web client
  (`src/pages/Register.tsx: handleConfirm`) gates the entire handoff on it: only
  when `resp.session_id` is truthy does the web app call `GET /ui/me`, `login()`,
  and THEN route to MFA enrollment or home. When `session_id` is null/absent the
  web app shows a "Registration verified, you can now sign in" success state
  instead of routing into enrollment. To mirror web semantics, the Android
  handoff must treat a missing `session_id` as "no authenticated session yet →
  do NOT enter the cookie-gated enrollment graph; show the sign-in/success
  path." The enrollment `begin` calls (AND-064) carry the session cookie set by
  confirm; this ticket still issues no network calls of its own, but the routing
  decision must consider `session_id`, not just `mfa_setup`. The web client also
  calls `GET /ui/me` after confirm — whether the Android handoff needs the same
  pre-fetch is delegated to AND-054/AND-064 (this ticket does not call
  `/ui/session/*` directly).
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

- **R1 — `mfa_setup` wire shape — RESOLVED (review 2026-06-06).** Verified
  against OpenAPI `RegisterConfirmResp` and `src/api/types.ts`: `mfa_setup` is a
  **bare array of strings** (`string[]`, optional). It is NOT an object with a
  `required` list nor per-factor objects. The DTO/mapper need no further change.
- **R2 — Factor sequencing ownership.** Whether the multi-factor "next pending
  factor" loop lives in AND-064 or here. Decision (this spec): AND-064 owns
  sequencing; we pass the ordered list. Confirm with AND-064 owner.
- **R3 — Mandatory vs skippable enrollment.** Is registration-driven MFA setup
  mandatory? Assumed guided-but-skippable per AND-064 policy; the skip gate is
  not implemented here. Open question for product.
- **R4 — Session readiness — RESOLVED (review 2026-06-06).** Confirm DOES return
  a (nullable) `session_id`; the web client treats it as the session gate (calls
  `GET /ui/me` + `login()` only when present, then routes to enrollment). When
  absent, the web app shows a verified/"please sign in" state and does NOT enter
  enrollment. The mapper now branches on `session_id` (→ `VerifiedSignIn` when
  null). Whether Android also needs the `GET /ui/me` pre-fetch before AND-064's
  `begin` calls is delegated to AND-054/AND-064 (out of scope here).
- **R5 — `email` field presence — RESOLVED (review 2026-06-06).** The confirm
  response has **no `email` field** (verified). The registered email must be
  supplied by the caller from the confirm screen's own state; the mapper now
  takes `registeredEmail` as a parameter and degrades to `null`/collect-in-UI.

## 14. Acceptance Criteria

- AC-1 (source): A new user who opted into MFA at registration and confirms
  their account is automatically guided into the matching device-enrollment
  flow.
- AC-2: `RegisterConfirmResp.mfa_setup` containing `totp` routes to TOTP
  enrollment; `sms` routes to SMS enrollment with `sms_phone` pre-filled when
  present; `email` routes to email enrollment. (Note: the web client only
  branches on `totp`/`sms` post-confirm; the `email` post-confirm factor is an
  unverified assumption — see §16 Open assumptions. Email-MFA *device*
  enrollment endpoints do exist (`/ui/mfa/email/devices/*`) but the web
  registration handoff does not route into them.)
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
- `RegisterConfirmResp` DTO fields (`status`, `session_id`, `mfa_setup`,
  `sms_phone`) added and verified against `/openapi.json`. (Corrected: the
  response carries no `email` field and no boolean `confirmed`; success is
  `status` + `session_id`-gated — see §5/§16.)
- All unit, ViewModel, DTO, and Compose UI tests from §11 written and green in
  CI; no dev-backend calls in tests.
- Telemetry event `register_mfa_handoff` emitted with PII-safe properties; PII
  redaction verified.
- Lint/detekt/ktlint clean; no hardcoded user-facing strings.
- Code reviewed and merged to `android-port`; AND-064 owner has confirmed the
  `MfaEnroll` nav contract.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **Confirm endpoint is `POST /ui/register/confirm`.** VERIFIED.
   Source: OpenAPI `POST /ui/register/confirm` (op
   `register_confirm_ui_register_confirm_post`, req=`RegisterConfirmReq`,
   resp=`200:RegisterConfirmResp`); `src/api/endpoints/auth.ts: registerConfirm`.
2. **Confirm request fields are `email` + `code`.** CORRECTED → the field is
   `confirmation_code`, not `code`.
   Source: OpenAPI `RegisterConfirmReq` (required: `email`, `confirmation_code`);
   `src/api/types.ts: RegisterConfirmReq`; `src/pages/Register.tsx` (handleConfirm
   sends `confirmation_code`).
3. **Confirm response has a boolean `confirmed` field.** CORRECTED → no such
   field. The required field is `status` (string).
   Source: OpenAPI `RegisterConfirmResp` (required: `[status]`);
   `src/api/types.ts: RegisterConfirmResp`.
4. **Confirm response carries `mfa_setup`.** VERIFIED — it is an optional **bare
   array of strings** (`items:{type:string}`), not an object/`required`-wrapper.
   Source: OpenAPI `RegisterConfirmResp.mfa_setup`; `src/api/types.ts:
   RegisterConfirmResp` (`mfa_setup?: string[]`).
5. **Confirm response carries `sms_phone` (nullable string).** VERIFIED.
   Source: OpenAPI `RegisterConfirmResp.sms_phone` (anyOf string|null);
   `src/api/types.ts: RegisterConfirmResp` (`sms_phone?: string | null`).
6. **Confirm response carries `email`.** CORRECTED → no `email` field exists on
   the response. The registered email is held in client state and passed into the
   mapper.
   Source: OpenAPI `RegisterConfirmResp` (properties: status, session_id,
   mfa_setup, sms_phone only); `src/api/types.ts: RegisterConfirmResp`;
   `src/pages/Register.tsx` (uses `registeredEmail` local var, not a response
   field).
7. **Confirm establishes/returns a session, gating the handoff.** CORRECTED/
   ADDED → response has nullable `session_id`; web routes to MFA/home only when
   `session_id` is present (after `getMe()`+`login()`), else shows a verified/
   sign-in success state.
   Source: OpenAPI `RegisterConfirmResp.session_id` (anyOf string|null);
   `src/pages/Register.tsx: handleConfirm` (`if (resp.session_id) { … } else
   setStep("success") `).
8. **Web client recognises `totp` and `sms` from `mfa_setup` post-confirm.**
   VERIFIED.
   Source: `src/pages/Register.tsx` (`mfaSetup.includes("sms")`,
   `mfaSetup.includes("totp")`).
9. **CSRF is `X-CSRF-Token` header echoing the `ui_csrf` cookie, cookie session
   transport.** VERIFIED.
   Source: `src/api/client.ts` (`getCookie("ui_csrf")` →
   `headers.set("X-CSRF-Token", csrf)`; `credentials: "include"`).
10. **TOTP enrollment endpoints `/ui/mfa/totp/devices/{begin,confirm,{id}/remove}`
    (AND-064 surface).** VERIFIED.
    Source: OpenAPI `POST /ui/mfa/totp/devices/begin`,
    `POST /ui/mfa/totp/devices/confirm`,
    `POST /ui/mfa/totp/devices/{device_id}/remove`;
    `src/api/endpoints/account.ts: beginTotpEnrollment` and siblings.
11. **SMS/email enrollment "begin|confirm|remove" shorthand.** CORRECTED/clarified
    → SMS & email device removal is a two-step `…/devices/{id}/remove/begin` +
    `…/devices/remove/confirm`, not a single `remove`.
    Source: OpenAPI `POST /ui/mfa/sms/devices/begin|confirm`,
    `/ui/mfa/sms/devices/{sms_device_id}/remove/begin`,
    `/ui/mfa/sms/devices/remove/confirm` (and email analogues);
    `src/api/endpoints/account.ts`.
12. **`mfa_setup` factor enum values are `totp`/`sms`/`email`.** UNVERIFIED-
    ASSUMPTION for exact string set — OpenAPI types `mfa_setup` as free-form
    `string[]` (no enum); only `totp` and `sms` are observed in the web client.
    `framework`/contract drift handled by the mapper dropping unknown tokens.
13. **`@Serializable`/type-safe Navigation-Compose + `popUpTo` back-stack reset.**
    VERIFIED (framework ref) — type-safe routes + `popUpTo(inclusive=true)`.
    Source: framework ref
    https://developer.android.com/guide/navigation/design/type-safety and
    https://developer.android.com/guide/navigation/backstack.
14. **One-shot nav via `Channel(...).receiveAsFlow()` (not StateFlow) for events.**
    VERIFIED (framework ref / Android UI-events guidance).
    Source: framework ref
    https://developer.android.com/topic/architecture/ui-layer/events.
15. **`@Parcelize`/`SavedStateHandle` for config-change & process-death survival.**
    VERIFIED (framework ref).
    Source: framework ref
    https://developer.android.com/topic/libraries/architecture/saving-states and
    https://developer.android.com/kotlin/parcelize.

### Corrections made

- §5 request body: `code` → `confirmation_code` (claim 2).
- §5 response + Moshi DTO: removed boolean `confirmed`, removed `email`; added
  required `status` and `session_id`; documented `mfa_setup` as `string[]`
  (claims 3, 4, 6, 7).
- §4.2 mapper: now gates on `session_id` (new `PostConfirmRoute.VerifiedSignIn`),
  and sources the email from a `registeredEmail` parameter instead of a
  non-existent response field (claims 6, 7).
- §4.4 nav collector: added the `VerifiedSignIn` branch.
- §6 session-state bullet: corrected to reflect that confirm returns/gates on
  `session_id` and the web client calls `GET /ui/me`/`login()` before enrollment.
- §13 R1, R4, R5: marked RESOLVED with verified findings.
- §11 SMS/email remove shorthand context and §15 DoD DTO field list corrected.
- AC-2: annotated that the `email` post-confirm factor is an assumption.

### Open assumptions

- **A1 — `email` as an `mfa_setup` factor post-confirm.** The web client never
  branches on `email` after confirm (only `totp`/`sms`). Email-MFA *device*
  endpoints exist but are not entered from the registration handoff. Kept in the
  mapper for forward-compat but UNVERIFIED; confirm with backend/product before
  shipping an email post-confirm route.
- **A2 — Exact `mfa_setup` token spelling/casing for non-observed factors.**
  OpenAPI declares no enum (free `string[]`); only lowercase `totp`/`sms` seen.
  The mapper lowercases and also accepts `"authenticator"` for TOTP — the
  `authenticator` alias is an UNVERIFIED defensive assumption.
- **A3 — Whether Android must call `GET /ui/me` before AND-064 `begin` calls.**
  Web does; this spec delegates the decision to AND-054/AND-064. UNVERIFIED here
  because it depends on those tickets' session bootstrapping.
- **A4 — Multi-factor sequencing ownership (AND-064 vs here).** Product/owner
  decision, not derivable from sources (R2). Assumed AND-064 sequences.
- **A5 — Mandatory vs skippable registration-driven MFA (R3).** Product policy,
  not in OpenAPI/frontend; UNVERIFIED.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **emu35** =
headless emulator AVD `test35` (x86_64, API 35); **A15** = physical Samsung
Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). This ticket is navigation/glue with
no hardware dependencies, so the bulk runs on JVM; Compose-UI/instrumented cases
run on **emu35** (fast in CI). A single config-change/process-death case is
flagged for **A15** to validate real arm64/API-34 lifecycle behavior.

- **TC-AND-056-01** — Type: unit (JVM). Target: `toPostConfirmRoute`.
  Preconditions: `RegisterConfirmResp(status="confirmed", sessionId="s1",
  mfaSetup=null)`. Steps: call mapper. Expected: returns `PostConfirmRoute.Home`.
  Traces: AC-4.
- **TC-AND-056-02** — Type: unit (JVM). Target: `toPostConfirmRoute`.
  Preconditions: resp with `sessionId="s1"`, `mfaSetup=[]`. Steps: call mapper.
  Expected: `Home`. Traces: AC-4.
- **TC-AND-056-03** — Type: unit (JVM). Target: `toPostConfirmRoute`.
  Preconditions: `sessionId="s1"`, `mfaSetup=["totp"]`. Steps: call mapper.
  Expected: `EnrollMfa(factors=[TOTP])`. Traces: AC-2.
- **TC-AND-056-04** — Type: unit (JVM). Target: `toPostConfirmRoute`.
  Preconditions: `sessionId="s1"`, `mfaSetup=["sms"]`, `smsPhone="+15551234567"`.
  Steps: call mapper. Expected: `EnrollMfa(factors=[SMS], smsPhone="+15551234567")`.
  Traces: AC-2.
- **TC-AND-056-05** — Type: unit (JVM). Target: `toPostConfirmRoute`.
  Preconditions: `sessionId="s1"`, `mfaSetup=["sms"]`, `smsPhone=null` (also a
  blank `"  "` variant). Steps: call mapper. Expected: `EnrollMfa(factors=[SMS])`
  with `smsPhone == null` (blank normalised to null). Traces: AC-2.
- **TC-AND-056-06** — Type: unit (JVM). Target: `toPostConfirmRoute`.
  Preconditions: `sessionId="s1"`, `mfaSetup=["TOTP","Sms","email"]` (mixed
  case, order significant). Steps: call mapper. Expected:
  `EnrollMfa(factors=[TOTP, SMS, EMAIL])` — order preserved, case-insensitive.
  Traces: AC-2, AC-3.
- **TC-AND-056-07** — Type: unit (JVM). Target: `toPostConfirmRoute`.
  Preconditions: `sessionId="s1"`, `mfaSetup=["totp","totp","sms"]` and an
  unknown-token variant `["totp","webauthn"]` plus all-unknown `["webauthn"]`.
  Steps: call mapper for each. Expected: deduped `[TOTP, SMS]`; `[TOTP]`
  (unknown dropped); `Home` (all unknown dropped → empty). Traces: AC-3, AC-4,
  AC-8.
- **TC-AND-056-08** — Type: unit (JVM). Target: `toPostConfirmRoute` (session
  gate, regression for the §6 correction). Preconditions:
  `RegisterConfirmResp(status="confirmed", sessionId=null, mfaSetup=["totp"])`.
  Steps: call mapper. Expected: `PostConfirmRoute.VerifiedSignIn` (NOT
  `EnrollMfa`) — no session means no enrollment-graph entry. Traces: AC-1, AC-4.
- **TC-AND-056-09** — Type: unit (JVM). Target: `toPostConfirmRoute` email
  source. Preconditions: `sessionId="s1"`, `mfaSetup=["email"]`,
  `registeredEmail="user@example.com"`; and a second call with
  `registeredEmail=null`. Steps: call mapper. Expected: `EnrollMfa(factors=
  [EMAIL], email="user@example.com")`; second call → `email == null`. Confirms
  email is sourced from the parameter, not a (nonexistent) response field.
  Traces: AC-2.
- **TC-AND-056-10** — Type: contract/MockWebServer (JVM/Robolectric). Target:
  `RegisterConfirmResp` Moshi adapter. Preconditions: fixture JSON bodies:
  (a) full `{status, session_id, mfa_setup:["totp","sms"], sms_phone}`,
  (b) minimal `{status:"confirmed"}` (mfa_setup absent, session_id absent),
  (c) `{status, session_id:null, mfa_setup:[]}`. Steps: enqueue each on
  MockWebServer, call the confirm endpoint, parse. Expected: all parse without
  throwing; absent fields → null/empty; `status` populated. Validates the wire
  schema from OpenAPI/`types.ts`. Traces: AC-8.
- **TC-AND-056-11** — Type: unit (JVM, Turbine). Target:
  `RegisterConfirmViewModel.nav`. Preconditions: fake `RegisterRepository`
  returns `ApiResult.Success(RegisterConfirmResp(sessionId="s1",
  mfaSetup=["sms"], smsPhone=…))`. Steps: call `onConfirm("123456")`, collect
  `nav`. Expected: emits exactly one `EnrollMfa` (no duplicate after re-collect).
  Traces: AC-1, AC-2.
- **TC-AND-056-12** — Type: unit (JVM, Turbine). Target:
  `RegisterConfirmViewModel.nav` error/offline path. Preconditions: fake repo
  returns `ApiResult.Failure` (simulating the flaky dev host / offline /
  timeout / 422). Steps: call `onConfirm`, observe `nav`. Expected: NO emission
  on `nav`; error surfaced via `uiState` (AND-054). Confirms a failed confirm
  triggers no handoff. Traces: AC-1.
- **TC-AND-056-13** — Type: Compose-UI / instrumented (emu35). Target: confirm
  composable `LaunchedEffect` nav collector + `NavController` back stack.
  Preconditions: stubbed successful confirm `mfaSetup=["sms"]`, `smsPhone` set,
  `sessionId` set. Steps: drive confirm; assert current destination is
  `MfaEnroll` with `smsPhone` arg populated and `factorsCsv="SMS"`; assert
  `RegisterStart`/`RegisterConfirm` are NOT on the back stack (system back does
  not return to them). Expected: lands on `MfaEnroll`; back stack cleared.
  Traces: AC-2, AC-5.
- **TC-AND-056-14** — Type: Compose-UI / instrumented (emu35). Target: nav
  collector, no-MFA and no-session branches. Preconditions: (a) confirm with
  `sessionId` set, `mfa_setup` empty → expect `Home` current destination, back
  stack cleared; (b) confirm with `sessionId=null` → expect `SignIn`/verified
  destination, enrollment NOT entered. Steps: drive each. Expected: as stated.
  Traces: AC-4, AC-5.
- **TC-AND-056-15** — Type: instrumented lifecycle (A15 — MUST run on physical
  device). Target: `SavedStateHandle`/`@Parcelize MfaSetupHandoff` survival.
  Preconditions: handoff in progress to `MfaEnroll(factorsCsv="TOTP,SMS",
  smsPhone=…)`. Steps: trigger configuration change (rotation) then process death
  (`adb shell am kill` / Don't-Keep-Activities) and restore. Expected: the
  enrollment destination and its args (factors order + `smsPhone`) are restored
  identically; no fallback to confirm/home. Runs on A15 to validate real
  arm64/API-34 process-death (differs from emulator). Traces: AC-6.
- **TC-AND-056-16** — Type: unit (JVM) + manual log/analytics inspection
  (security/PII). Target: telemetry emission + log redaction.
  Preconditions: handoff with `smsPhone="+15551234567"`, `email="u@x.com"`.
  Steps: trigger the `register_mfa_handoff` event and debug logging; capture the
  analytics payload and logcat. Expected: event has `decision`, `factors`
  (names only), `has_sms_phone=true`; the raw phone number and email appear
  NOWHERE in analytics payload or logs (at most last-4/redacted). Traces: AC-7.
- **TC-AND-056-17** — Type: Compose-UI accessibility (emu35). Target: transitional
  "Setting up security…" state (only if rendered). Preconditions: handoff in
  flight showing the transitional state. Steps: run with TalkBack/semantics
  assertions; assert the loading text is a live-region announcement sourced from
  `R.string.register_mfa_handoff_loading` (no hardcoded literal). Expected:
  semantics live-region present; string is localized resource. Traces: AC-1
  (a11y aspect of the guided handoff). If no transitional UI is rendered, mark
  N/A with justification.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (guided into enrollment) | TC-08, TC-11, TC-12, TC-17 |
| AC-2 (totp/sms/email routing + sms_phone prefill) | TC-03, TC-04, TC-05, TC-06, TC-09, TC-11, TC-13 |
| AC-3 (first factor + full ordered list forwarded) | TC-06, TC-07 |
| AC-4 (absent/empty/all-unknown → Home, stack cleared) | TC-01, TC-02, TC-07, TC-08, TC-14 |
| AC-5 (system back does not return to confirm/start) | TC-13, TC-14 |
| AC-6 (config-change + process-death survival) | TC-15 |
| AC-7 (sms_phone never in logs/analytics) | TC-16 |
| AC-8 (all unit tests incl. unknown/null/empty pass) | TC-01–TC-10 |
