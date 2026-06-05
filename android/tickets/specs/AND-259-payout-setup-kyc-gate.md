---
id: AND-259
title: Payout setup (+ KYC gate)
milestone: M6
epic: E35
priority: P1
size: L
status: draft
depends_on: [AND-258, AND-320]
blocks: [AND-260, AND-262, AND-263]
---

# AND-259 — Payout setup (+ KYC gate)

## 1. Overview & Goal

Let an authenticated user configure (add / edit / select) the payout method that
the platform uses to pay them, and gate that configuration behind the user's KYC
tier so a payout method can only be saved when the account has reached the tier
required to receive payouts. When the user's tier is insufficient, the screen must
not silently fail: it explains the gap and routes the user into the verification
flow that raises their tier.

This ticket owns the **payout setup screen and its KYC gating logic** in
`feature-payouts`. It composes two already-built data layers:

- **AND-258 (Payouts API)** — the `PayoutsApi` Retrofit interface, payout-method
  DTOs and their domain mappers. This ticket does not (re)define payout endpoints
  or DTOs; it consumes them.
- **AND-320 (Tier status & requirements)** — the KYC tier domain model
  (`TierStatus`, `TierRequirements`) and the evaluate action that refreshes tier
  state from `/v1/kyc/*`. This ticket reads tier state to decide gate vs. allow,
  and triggers `evaluate` after returning from verification.

Success means: a user at or above the required tier can save a payout method and
see it reflected as the active method; a user below the required tier is blocked
with a clear explanation and a working "Verify identity" route into the KYC flow;
and both branches are covered by deterministic tests.

## 2. Context & References

- Repo `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- Namespace / applicationId base: `com.testlogon.android`.
- Feature module: `feature-payouts` → consumes `core-network`, `core-model`,
  `core-data`, `core-ui`, `core-testing`.
- **AND-258** owns `PayoutsApi` (`payouts.ts` port), payout-method DTOs, and
  `PayoutsRepository` read/write methods + domain mappers. This ticket extends the
  repository with setup-oriented use cases but must not duplicate endpoint or DTO
  definitions; coordinate any new `PayoutsApi` method with AND-258.
- **AND-320** owns `TierStatus` / `TierRequirements` domain models and the KYC
  tier repository (`/v1/kyc/tiers/me`, `/v1/kyc/requirements`, `/v1/kyc/evaluate`).
  This ticket reads `currentTier` and the payout-required tier and calls
  `evaluate()` to refresh after verification; it does not own the KYC API.
- KYC capture/verification UI (document capture AND-321, ID scanner AND-322) is
  the **route target** of the gate, not part of this ticket. This ticket navigates
  to the KYC verification entry route by name; it does not implement capture.
- Cookie-based session: all calls ride the persistent cookie jar + `X-CSRF-Token`
  header echoed from `ui_csrf`. On `401` the OkHttp authenticator does one
  `POST /ui/session/refresh` then retries. Saving a payout method is a **mutation**
  (CSRF-required, not eligible for idempotent-GET backoff retry).
- Dev backend `http://18.222.237.167:8000` is plaintext HTTP and unreliable:
  ~20s timeouts, offline/stale UI states, no auto-retry on mutations.
- Web reference: `frontend/src/api/endpoints/payouts.ts`,
  `frontend/src/api/endpoints/*kyc*.ts`, and `frontend/src/api/types.ts`. Exact
  field names MUST be verified against `/openapi.json` at build time; shapes below
  are the contract this ticket implements.

## 3. Functional Requirements

FR-1. On entering Payout setup, the app concurrently loads (a) the current payout
method(s) via `PayoutsRepository` (AND-258) and (b) the KYC tier status via the
tier repository (AND-320), showing a single combined loading state.

FR-2. The screen derives a **gate decision** by comparing `currentTier` against
`requiredTierForPayouts` (the minimum tier required to receive payouts, sourced
from tier requirements / payout config). Result is one of `Allowed` or
`Blocked(missingRequirements)`.

FR-3. **Allowed branch:** the user can choose a payout-method type (e.g.
`bank_account`, `paypal`, `card` — exact set from `/openapi.json`), fill the
type-specific fields, validate locally, and submit. On success the saved method
becomes the active method and the form reflects it.

FR-4. **Blocked branch:** the setup form is disabled/hidden and replaced by a
KYC-gate panel that states the current tier, the required tier, and the
outstanding requirement(s). A primary "Verify identity" action navigates to the
KYC verification entry route.

FR-5. After the user returns from the KYC flow, the screen calls `evaluate()`
(AND-320) to refresh tier status and re-derives the gate; if the user now meets
the requirement, the form unlocks without a full screen reload.

FR-6. Editing an existing payout method is supported when allowed: the form is
pre-populated from the active method, and submit performs an update.

FR-7. Form validation is local and per-type before any network call (e.g.
non-empty account/routing for `bank_account`, valid email for `paypal`). Invalid
fields show inline errors and block submit.

FR-8. Save is idempotent from the user's view: a successful save shows a
confirmation, disables the submit button while in flight, and prevents
double-submission.

FR-9. Errors (network, 401-after-refresh-failure, 403 CSRF, 409 conflict, 422
validation, 5xx) surface a non-blocking, retryable message and leave entered form
state intact.

FR-10. If tier state is unavailable (KYC load failed) the screen treats the gate
as **closed** (fail-safe: do not allow saving a payout method without a confirmed
sufficient tier) and offers retry.

## 4. Technical Design

Module: `feature-payouts`. MVVM with Hilt, `StateFlow<UiState>`, typed
`ApiResult<T>`.

Domain models (shared / reused; payout DTOs owned by AND-258, tier by AND-320):

```kotlin
// core-model (reused from AND-258 / AND-320; shown for contract clarity)
enum class PayoutMethodType { BANK_ACCOUNT, PAYPAL, CARD, UNKNOWN }

data class PayoutMethod(
    val id: String?,                 // null when not yet created
    val type: PayoutMethodType,
    val displayName: String?,        // e.g. "Bank ****1234"
    val isDefault: Boolean,
    val fields: Map<String, String>, // type-specific, redacted in display
)

enum class KycTier { NONE, BASIC, VERIFIED, ENHANCED, UNKNOWN } // order = rank

data class TierStatus(            // from AND-320
    val currentTier: KycTier,
    val requiredTierForPayouts: KycTier,
    val missingRequirements: List<TierRequirement>,
)
```

Gate logic (pure, unit-testable, lives in this feature):

```kotlin
sealed interface PayoutGate {
    data object Allowed : PayoutGate
    data class Blocked(
        val currentTier: KycTier,
        val requiredTier: KycTier,
        val missing: List<TierRequirement>,
    ) : PayoutGate
    data object Unknown : PayoutGate // tier unavailable -> fail closed
}

object PayoutGateEvaluator {
    fun evaluate(status: TierStatus?): PayoutGate = when {
        status == null -> PayoutGate.Unknown
        status.currentTier.rank() >= status.requiredTierForPayouts.rank() ->
            PayoutGate.Allowed
        else -> PayoutGate.Blocked(
            status.currentTier, status.requiredTierForPayouts,
            status.missingRequirements,
        )
    }
}
```

Repository extension in `core-data` (consumes AND-258 `PayoutsApi` + AND-320 tier
repo; new use-case methods only — endpoints owned upstream):

```kotlin
class PayoutSetupRepository @Inject constructor(
    private val payoutsRepository: PayoutsRepository, // AND-258
    private val tierRepository: TierRepository,       // AND-320
    private val dispatchers: AppDispatchers,
) {
    suspend fun loadSetup(): ApiResult<PayoutSetupData> // method(s) + tier, parallel
    suspend fun savePayoutMethod(draft: PayoutMethodDraft): ApiResult<PayoutMethod>
    suspend fun refreshTier(): ApiResult<TierStatus>    // delegates evaluate()
}

data class PayoutSetupData(
    val methods: List<PayoutMethod>,
    val activeMethod: PayoutMethod?,
    val tierStatus: TierStatus?,   // null if KYC load failed
)
```

ViewModel:

```kotlin
@HiltViewModel
class PayoutSetupViewModel @Inject constructor(
    private val repo: PayoutSetupRepository,
) : ViewModel() {

    data class UiState(
        val isLoading: Boolean = true,
        val gate: PayoutGate = PayoutGate.Unknown,
        val form: PayoutFormState = PayoutFormState(),
        val isSaving: Boolean = false,
        val savedMethod: PayoutMethod? = null,
        val evaluating: Boolean = false,
        val error: UiError? = null,
    )

    data class PayoutFormState(
        val type: PayoutMethodType = PayoutMethodType.BANK_ACCOUNT,
        val values: Map<String, String> = emptyMap(),
        val fieldErrors: Map<String, Int> = emptyMap(), // field -> string res id
        val canSubmit: Boolean = false,
    )

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    fun load()                                   // FR-1, initial + retry
    fun onTypeSelected(type: PayoutMethodType)   // FR-3
    fun onFieldChanged(key: String, value: String) // FR-7 (re-validates)
    fun submit()                                 // FR-3/FR-6/FR-8 (gated)
    fun onReturnedFromKyc()                      // FR-5 -> evaluate + re-gate
    fun dismissError()
}
```

Composables (Material 3, `core-ui`):

```kotlin
@Composable
fun PayoutSetupRoute(
    viewModel: PayoutSetupViewModel = hiltViewModel(),
    onNavigateToKyc: () -> Unit,   // FR-4 route into verification
    onBack: () -> Unit,
)

@Composable
fun PayoutSetupScreen(
    state: PayoutSetupViewModel.UiState,
    onTypeSelected: (PayoutMethodType) -> Unit,
    onFieldChanged: (String, String) -> Unit,
    onSubmit: () -> Unit,
    onVerifyIdentity: () -> Unit,
    onRetry: () -> Unit,
    onDismissError: () -> Unit,
    onBack: () -> Unit,
)

@Composable
private fun KycGatePanel(blocked: PayoutGate.Blocked, onVerifyIdentity: () -> Unit)
```

Navigation: register `payoutSetup` route in the payouts nav graph. The "Verify
identity" action navigates to the KYC verification entry route (owned by E42 /
AND-321 etc.) by route name only. On returning, `PayoutSetupRoute` triggers
`onReturnedFromKyc()` via a `NavBackStackEntry` result or lifecycle `RESUMED`
re-check so tier is re-evaluated (FR-5).

Submit gating: `submit()` first asserts `state.gate is PayoutGate.Allowed`; if not,
it is a no-op (the UI should never present an enabled submit when blocked, but the
ViewModel guards defensively as the single source of truth).

## 5. API Contract

This ticket calls endpoints owned by AND-258 (payouts) and AND-320 (KYC tier).
Field names MUST be verified against `/openapi.json`; Moshi DTOs use
`@Json(name=...)` for snake_case.

Load payout method(s) — `GET /api/v1/payouts/methods` (AND-258) → 200:

```json
{
  "methods": [
    {
      "id": "pm_01HX...",
      "type": "bank_account",
      "display_name": "Bank ****1234",
      "is_default": true,
      "details": { "last4": "1234", "routing_last4": "0021" }
    }
  ],
  "default_method_id": "pm_01HX..."
}
```

Save / create payout method — `POST /api/v1/payouts/methods` (AND-258), mutation,
requires `X-CSRF-Token`. Request:

```json
{
  "type": "bank_account",
  "account_number": "000123456789",
  "routing_number": "110000000",
  "account_holder_name": "Jane Doe"
}
```

→ 201 returns the created `PayoutMethod` (same shape as a list item). Update uses
`PUT /api/v1/payouts/methods/{id}` (same body, same response).

Tier status — `GET /api/v1/kyc/tiers/me` (AND-320) → 200:

```json
{
  "current_tier": "basic",
  "required_tier_for_payouts": "verified",
  "missing_requirements": [
    { "code": "gov_id", "label": "Government ID", "satisfied": false }
  ]
}
```

Evaluate (refresh after KYC) — `POST /api/v1/kyc/evaluate` (AND-320), mutation,
returns the updated tier status (same shape as above).

Error envelope (FastAPI `detail`, mapped per project convention — string |
`[{msg}]` | `{code,...}`):

```json
{ "detail": "Invalid CSRF token" }
{ "detail": [{ "msg": "routing_number invalid", "loc": ["body","routing_number"] }] }
{ "detail": { "code": "kyc_tier_insufficient", "message": "Verification required" } }
```

Status handling: 200/201 success; **403 `kyc_tier_insufficient` on save** → treat
as server-side gate, switch UI to Blocked and surface "Verify identity" (defense
in depth even if the client gate passed); 401 → authenticator refresh-once-retry
(transparent), persistent 401 → "Session expired" + re-auth; 403 CSRF → retryable;
409 → "Payout method already exists / changed", refresh; 422 → map per-field
validation into `fieldErrors`; 5xx / timeout → retryable, form state preserved.

## 6. Data & State Management

- **No Room persistence** for payout/KYC state: payout-method details are
  financial PII and KYC tier is security-sensitive; both must reflect live server
  state, so they are fetched on demand and held only in `StateFlow` memory.
- Payout-method **field values** in `PayoutFormState.values` are kept in memory
  only; sensitive numbers (account/routing) are never written to DataStore or
  Room. Display uses redacted `display_name` / `last4`.
- The gate decision is **derived state**, recomputed by `PayoutGateEvaluator`
  whenever `tierStatus` changes (initial load, `onReturnedFromKyc`, or a 403 gate
  signal from save). It is never persisted.
- `loadSetup()` fetches methods and tier **in parallel** (`async`/`awaitAll`); a
  failure in the KYC leg yields `tierStatus = null` → `PayoutGate.Unknown`
  (fail-closed, FR-10), while a payout-leg failure surfaces a retryable error.
- Save is optimistic only on the confirmation UI (button disabled while
  `isSaving`); the rendered active method is replaced from the server response,
  not from local input (server is source of truth).
- This ticket reads `requiredTierForPayouts` from tier requirements; it writes no
  auth/tier state and does not own DataStore keys.

## 7. Error Handling & Resilience

- Timeouts ~20s (OkHttp from core-network). The two initial GETs are idempotent
  reads and MAY use the existing bounded-backoff retry for GETs; `POST`/`PUT` save
  and `POST /kyc/evaluate` are mutations and MUST NOT auto-retry.
- 401: handled by the OkHttp authenticator (single `POST /ui/session/refresh` then
  retry). Persistent 401 → "Session expired", route to re-auth (delegated).
- 403 CSRF: "Couldn't verify your session, try again"; retry re-reads `ui_csrf`.
- 403 `kyc_tier_insufficient`: do not show a generic error; flip the gate to
  Blocked using the server's tier hint (or trigger `evaluate()` to refresh), so
  the user is routed to verification rather than stuck on a failing form.
- 422 validation: map `detail[].loc`/`msg` to `fieldErrors`; keep form values.
- Network offline: offline banner with Retry; preserve entered form values; do not
  blank the screen if a prior state was rendered (mark stale).
- Fail-closed gate (FR-10): when tier is `Unknown`, the form is disabled and a
  retry-tier action is offered; saving is impossible until tier is confirmed.
- Double-submit guard: `isSaving` disables submit; the ViewModel ignores `submit()`
  while a save is in flight.

## 8. Security & Privacy

- All calls ride the existing authenticated cookie jar with `X-CSRF-Token`; no
  session tokens are logged or persisted by this feature.
- **Financial PII** (account number, routing number, card data) is never logged
  to logcat (debug or release), never put in analytics payloads, never written to
  crash breadcrumbs, and never persisted to disk. Only redacted forms
  (`display_name`, `last4`) appear in UI and state.
- KYC tier and missing-requirement codes are sensitive; telemetry uses only the
  coarse gate result, not raw requirement detail tied to the user.
- Save and evaluate are CSRF-protected mutations; the client enforces a tier gate
  and the server independently enforces it (403 `kyc_tier_insufficient`).
- Dev backend is plaintext HTTP; production MUST be HTTPS. This screen adds no new
  cleartext exemptions beyond the existing dev `network_security_config`.

## 9. Accessibility & i18n

- All strings in `feature-payouts` `strings.xml`; no hardcoded text. Tier names,
  requirement labels, and method-type labels are localized; currency/number
  formatting is locale-aware.
- The KYC-gate panel is announced as a single semantic group summarizing current
  tier, required tier, and the next action ("Verify identity to enable payouts").
- Form fields have labels, `contentDescription`, and inline error text associated
  via semantics; the submit button's disabled state and reason are exposed to
  TalkBack (e.g. "Verification required" when gated).
- Touch targets ≥ 48dp; dynamic font scaling and dark theme via Material 3;
  RTL-safe layouts (start/end paddings, no hardcoded left/right).
- Sensitive numeric fields use appropriate `KeyboardType` and IME flags; no
  autofill of full account numbers into logs.

## 10. Telemetry & Logging

- Events (no PII; no account/routing/card numbers, no raw requirement detail):
  `payout_setup_viewed` (`{gate: "allowed"|"blocked"|"unknown"}`),
  `payout_method_saved` (`{type}`),
  `payout_gate_blocked` (`{current_tier, required_tier}`),
  `payout_verify_identity_tapped`,
  `payout_tier_reevaluated` (`{result}`),
  `payout_setup_error` (`{type}`).
- Logging via the project Timber wrapper; debug-only request/response **metadata**,
  never field values, cookies, or `X-CSRF-Token`.
- Error mapping records the normalized `UiError.type`
  (network/auth/csrf/validation/server/gate), not raw `detail` strings.

## 11. Testing Strategy

- **Gate unit tests** (`PayoutGateEvaluator`, pure): allowed when
  `currentTier >= requiredTier`; blocked when below (carries missing reqs);
  `Unknown` when `status == null`; rank ordering across the `KycTier` enum.
- **MockWebServer (core-testing)**: fixtures for `GET /payouts/methods`,
  `GET /kyc/tiers/me` (above-tier and below-tier), `POST/PUT` save 201, and error
  responses (403 CSRF, 403 `kyc_tier_insufficient`, 422 validation, 409, 500,
  timeout). Assert verb, path, and presence of `X-CSRF-Token` on mutations.
- **ViewModel unit tests** (Turbine + coroutine test rule):
  - load maps method(s) + tier and derives the correct gate.
  - allowed branch: valid form → `submit()` calls save, `savedMethod` set.
  - blocked branch: `submit()` is a no-op; gate carries current/required tier.
  - `onReturnedFromKyc()` calls `evaluate()` and unlocks the form when tier rises.
  - KYC load failure → `gate = Unknown`, form disabled (fail-closed, FR-10).
  - 403 `kyc_tier_insufficient` on save flips gate to Blocked.
  - per-field validation blocks submit; 422 maps into `fieldErrors`.
  - double-submit guard: second `submit()` while saving is ignored.
- **Repository tests** (`PayoutSetupRepository`): parallel load composition;
  partial-failure handling (tier null vs payout error); error envelope mapping
  (string/array/object).
- **Compose UI tests**: below-tier fixture renders the KYC-gate panel with
  "Verify identity" (tapping invokes the KYC route) and the form is not
  submittable (satisfies "KYC gate routes to verification"); above-tier fixture
  renders the form, valid input enables submit, and a successful save shows
  confirmation (satisfies "Setup works").
- Deterministic, no real network.

## 12. Dependencies & Sequencing

- **Depends on AND-258** (Payouts API): provides `PayoutsApi`, payout DTOs,
  mappers, and base `PayoutsRepository` read/write. Hard blocker — this ticket
  consumes and extends them, never redefines endpoints/DTOs.
- **Depends on AND-320** (Tier status & requirements): provides `TierStatus` /
  `TierRequirements`, the tier repository, and `evaluate()`. Hard blocker — the
  gate decision and post-KYC refresh read from it.
- Soft dependency: the KYC verification entry route (E42 — AND-321 document
  capture / AND-322 ID scanner) is the navigation target of the gate; this ticket
  references that route by name and degrades to "verification coming soon" only if
  the route is not yet registered (tracked as Open Question).
- Transitively relies on the cookie jar, CSRF interceptor, and 401-refresh
  authenticator (E04 network chain, via AND-027 / AND-258).
- **Blocks**: AND-260 (payout history), AND-262 (payouts ViewModel), AND-263
  (payouts tests) build on the setup screen and gating state defined here.
- Sequencing: implement `PayoutGateEvaluator` + repository (unit + MockWebServer
  tested) first, then ViewModel, then Compose screen + nav wiring (incl. KYC route
  + return-result handling), then UI tests.

## 13. Risks & Open Questions

- Q1: Exact payout-method `type` enum and per-type required fields — verify against
  `/openapi.json`; the form schema must be data-driven where possible to tolerate
  added types.
- Q2: Source of `required_tier_for_payouts` — is it on `GET /kyc/tiers/me`, on a
  payout-config endpoint, or a static product constant? Confirm; the gate reads a
  single resolved value regardless.
- Q3: Does save return `403 kyc_tier_insufficient` or `422` when tier is short?
  Confirm so client error mapping (gate flip vs field error) aligns with server.
- Q4: KYC return signal — `NavBackStackEntry` result vs. lifecycle re-check for
  triggering `evaluate()` (FR-5). Pick one; result-based is preferred to avoid
  redundant evaluate calls.
- Q5: Is the KYC verification entry route available at M6 (E42 lands in M7)? If
  not, the gate must still block and present a deferred "verification not yet
  available" message rather than a dead button. Decision needed before release.
- Risk: unreliable dev host makes manual QA of save flaky; mitigated by
  MockWebServer being the source of truth for correctness.

## 14. Acceptance Criteria

AC-1. Entering Payout setup loads payout method(s) and KYC tier and derives a gate;
above-tier fixtures render the configurable form, below-tier fixtures render the
KYC-gate panel. (MockWebServer + Compose UI test.)

AC-2. **Setup works:** with a sufficient tier, entering valid details and
submitting calls `POST/PUT /api/v1/payouts/methods` with `X-CSRF-Token`, and on
201 the saved method becomes the active method with a confirmation.
(MockWebServer + ViewModel + UI test — satisfies "Setup works".)

AC-3. **KYC gate routes to verification:** with an insufficient tier, the form is
not submittable and the KYC-gate panel's "Verify identity" action navigates to the
KYC verification route. (Unit + UI test — satisfies "KYC gate routes to
verification when required".)

AC-4. Returning from the KYC flow triggers `POST /api/v1/kyc/evaluate`; if the
tier now meets the requirement, the form unlocks without a full reload. (ViewModel
test.)

AC-5. When tier status is unavailable, the gate is `Unknown` and saving is blocked
(fail-closed); a retry-tier action is offered. (ViewModel test.)

AC-6. A `403 kyc_tier_insufficient` from save flips the UI to Blocked and surfaces
"Verify identity" rather than a generic error. (MockWebServer + ViewModel test.)

AC-7. Local per-field validation blocks submit on invalid input, and a `422`
response maps to inline field errors while preserving entered values. (ViewModel
test.)

AC-8. Network/CSRF/server errors surface a retryable message and leave entered form
state intact (no data loss on a failed save). (MockWebServer test.)

## 15. Definition of Done

- `feature-payouts` Payout setup screen, `PayoutSetupViewModel`,
  `PayoutSetupRepository`, `PayoutGateEvaluator`, and nav wiring (incl. KYC route +
  return-result handling) implemented under `com.testlogon.android`.
- Payout endpoints/DTOs consumed from AND-258 and tier state from AND-320 with no
  duplicate endpoint or DTO definitions; any new `PayoutsApi` method coordinated
  with AND-258.
- All AC-1…AC-8 tests green: gate unit tests, repository/ViewModel unit tests,
  MockWebServer contract tests, and at least two Compose UI tests (allowed +
  blocked) passing in CI.
- No financial PII / cookie / CSRF leakage in logs or telemetry; strings
  externalized; TalkBack and dynamic-type verified.
- Lint/detekt/ktlint clean; builds on `compileSdk 35` / AGP 8.7.3 / JDK 17 /
  Gradle 8.9 wrapper.
- PR on `android-port` references AND-259 and links AND-258, AND-320 (and the KYC
  verification route owner once available).
