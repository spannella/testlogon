---
id: AND-259
title: Payout setup (+ KYC gate)
milestone: M6
epic: E35
priority: P1
size: L
status: reviewed
reviewed_on: 2026-06-06
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
  tier repository. **Verified endpoints** (frontend `src/api/endpoints/kyc-tiers.ts`,
  OpenAPI index): `GET /v1/kyc/tiers/me`, `GET /v1/kyc/tiers/me/requirements/{target_tier}`,
  `POST /v1/kyc/tiers/me/evaluate`. **Correction:** these are NOT under an `/api`
  prefix, evaluate is `…/me/evaluate` (not `/v1/kyc/evaluate`), and requirements is a
  per-target-tier GET (not a bare `/v1/kyc/requirements`). This ticket reads
  `currentTier` and calls `evaluate()` to refresh after verification; it does not own
  the KYC API.
- KYC capture/verification UI (document capture AND-321, ID scanner AND-322) is
  the **route target** of the gate, not part of this ticket. This ticket navigates
  to the KYC verification entry route by name; it does not implement capture.
- Cookie-based session: all calls ride the persistent cookie jar + `X-CSRF-Token`
  header echoed from `ui_csrf`. On `401` the OkHttp authenticator does one
  `POST /ui/session/refresh` then retries. Saving a payout method is a **mutation**
  (CSRF-required, not eligible for idempotent-GET backoff retry).
- Dev backend `http://18.222.237.167:8000` is plaintext HTTP and unreliable:
  ~20s timeouts, offline/stale UI states, no auto-retry on mutations.
- Web reference: `src/api/endpoints/payouts.ts`,
  `src/api/endpoints/kyc-tiers.ts`, `src/api/types.ts`, and the web page
  `src/pages/payouts/PayoutDashboard.tsx`. **Material correction from the reference:**
  the backend has **no saved-payout-method CRUD**. The web client requests a payout of
  an *amount* (`POST /ui/payouts/request` with `amount_cents` + a free-string `method`,
  default `"bank_transfer"`, options `bank_transfer`/`paypal`) and lists/cancels
  payouts; it does not store reusable `bank_account`/`card` objects with
  account/routing fields. The "payout setup" of this ticket therefore maps onto the
  payout-request flow + KYC gate, not a CRUD-of-methods flow. See §16 for the full audit.

## 3. Functional Requirements

FR-1. On entering Payout setup, the app concurrently loads (a) the current payout
method(s) via `PayoutsRepository` (AND-258) and (b) the KYC tier status via the
tier repository (AND-320), showing a single combined loading state.

FR-2. The screen derives a **gate decision**. **Corrected source:** the backend does
not expose a `required_tier_for_payouts` field. Instead the required tier is a
**client/product constant** (`PAYOUT_REQUIRED_TIER`, an integer rank) and the gate is
resolved either by (a) comparing `TierDetails.current_tier >= PAYOUT_REQUIRED_TIER`,
or preferably (b) calling `GET /v1/kyc/tiers/me/requirements/{PAYOUT_REQUIRED_TIER}`
and reading its `eligible` boolean plus `unmet[]` codes. Result is one of `Allowed`
or `Blocked(unmetRequirements)`. The exact required-tier integer must be confirmed
with product/backend (§16, Q2).

FR-3. **Allowed branch:** the user fills the payout-request form and submits.
**Corrected to match the verified backend:** the form collects an `amount_cents`
(validated client-side against `minimum_payout_cents ≤ amount ≤ available_cents` from
`GET /ui/payouts/balance`), a `method` chosen from the web's set (`bank_transfer`,
`paypal` — free string), and optional `notes` (≤500). Submit calls
`POST /ui/payouts/request`. On 201 the created payout (`payout_id`, `amount_cents`,
`status`) is shown as the latest request. (The original "choose a saved method type
with type-specific account/routing fields" is a forward-looking assumption with no
backend support — see §16; if implemented it requires new AND-258 endpoints.)

FR-4. **Blocked branch:** the setup form is disabled/hidden and replaced by a
KYC-gate panel that states the current tier, the required tier, and the
outstanding requirement(s). A primary "Verify identity" action navigates to the
KYC verification entry route.

FR-5. After the user returns from the KYC flow, the screen calls `evaluate()`
(AND-320) to refresh tier status and re-derives the gate; if the user now meets
the requirement, the form unlocks without a full screen reload.

FR-6. **Re-scoped:** there is no "edit saved method" operation in the backend
(no `PUT …/methods/{id}`). What IS supported is cancelling a pending payout request
via `POST /ui/payouts/{payout_id}/cancel` and submitting a fresh request. Treat
"edit" as cancel-and-resubmit; pre-populate the form from the last request's amount
where useful. (Original method-edit wording was based on a nonexistent endpoint —
§16.)

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

// Tiers are INTEGER ranks on the wire (TierDetails.current_tier: Int, tier_name: String).
// Model the rank as Int (or an enum mapped from the int); do NOT assume a fixed
// string enum — tier_name is server-supplied and labels are not guaranteed stable.
@JvmInline value class KycTier(val rank: Int) // from AND-320; 0 = none, higher = more

data class TierStatus(                 // mapped from TierDetails + a requirements call
    val currentTier: KycTier,          // <- TierDetails.current_tier (Int)
    val tierName: String,              // <- TierDetails.tier_name
    val requiredTierForPayouts: KycTier, // <- client constant PAYOUT_REQUIRED_TIER (not server)
    val eligibleForPayoutTier: Boolean?, // <- TierRequirements.eligible (null if not loaded)
    val unmetRequirements: List<String>, // <- TierRequirements.unmet (codes, not objects)
)
```

> **Correction (verified against `src/api/types.ts`):** `TierDetails` =
> `{ user_sub, current_tier: Int, tier_name: String, updated_at, history[] }`. It has
> NO `required_tier_for_payouts` and NO `missing_requirements`. Requirements come from
> `TierRequirements` = `{ target_tier: Int, current_tier: Int, met: String[],
> unmet: String[], eligible: Boolean }`. The original `KycTier` string enum and the
> `TierStatus.missingRequirements: List<TierRequirement>` object list were
> inaccurate; use integer ranks and string requirement codes.

Gate logic (pure, unit-testable, lives in this feature):

```kotlin
sealed interface PayoutGate {
    data object Allowed : PayoutGate
    data class Blocked(
        val currentTier: KycTier,
        val requiredTier: KycTier,
        val missing: List<String>, // requirement codes from TierRequirements.unmet
    ) : PayoutGate
    data object Unknown : PayoutGate // tier unavailable -> fail closed
}

object PayoutGateEvaluator {
    // Prefer the server's `eligible` boolean when available; fall back to rank compare.
    fun evaluate(status: TierStatus?): PayoutGate = when {
        status == null -> PayoutGate.Unknown
        status.eligibleForPayoutTier == true ||
            (status.eligibleForPayoutTier == null &&
             status.currentTier.rank >= status.requiredTierForPayouts.rank) ->
            PayoutGate.Allowed
        else -> PayoutGate.Blocked(
            status.currentTier, status.requiredTierForPayouts,
            status.unmetRequirements,
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
    suspend fun loadSetup(): ApiResult<PayoutSetupData> // balance + tier (+ reqs), parallel
    // Corrected: there is no "save method". The mutation is a payout REQUEST.
    suspend fun requestPayout(draft: PayoutRequestDraft): ApiResult<PayoutCreateResult>
    suspend fun refreshTier(): ApiResult<TierStatus>    // delegates POST .../me/evaluate
}

// PayoutRequestDraft -> POST /ui/payouts/request { amount_cents, method, notes }

data class PayoutSetupData(
    val balance: PayoutBalance,       // available/min/pending from GET /ui/payouts/balance
    val recentPayouts: List<Payout>,  // from GET /ui/payouts (status of prior requests)
    val tierStatus: TierStatus?,      // null if KYC load failed
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
Field names below are **verified against the OpenAPI spec and the frontend
reference**; Moshi DTOs use `@Json(name=...)` for snake_case. (An earlier draft of
this section cited `…/payouts/methods` CRUD endpoints, string tier enums, and a
`required_tier_for_payouts` field; none of those exist — corrected below, audited in
§16.)

Balance / eligibility context — `GET /ui/payouts/balance` (AND-258) → 200
(`PayoutBalanceOut`):

```json
{
  "available_cents": 50000,
  "pending_cents": 0,
  "hold_cents": 0,
  "total_earned_cents": 120000,
  "minimum_payout_cents": 1000,
  "currency": "USD"
}
```

List prior payouts — `GET /ui/payouts?limit=&cursor=` (AND-258) → 200
(`PayoutListOut`): `{ "items": PayoutOut[], "next_cursor": string|null }`. Each
`PayoutOut`: `{ payout_id, user_id, amount_cents, method, status, created_at,
updated_at, notes, reject_reason, approved_by, completed_at }`.

Request a payout — `POST /ui/payouts/request` (AND-258), mutation, requires
`X-CSRF-Token`. Request (`PayoutRequestIn`):

```json
{
  "amount_cents": 50000,
  "method": "bank_transfer",
  "notes": "Monthly withdrawal"
}
```

`amount_cents` is required (minimum 100) and is validated client-side against
`minimum_payout_cents ≤ amount_cents ≤ available_cents`; `method` is a free string
(default `"bank_transfer"`; web offers `bank_transfer`/`paypal`); `notes` is optional
(≤500 chars). → 201 returns `PayoutCreateOut`:

```json
{ "ok": true, "payout_id": "po_01HX...", "amount_cents": 50000, "status": "pending" }
```

Cancel a pending payout — `POST /ui/payouts/{payout_id}/cancel` (AND-258), mutation
→ 200 `PayoutActionOut` `{ ok, payout_id, status }`.

> Note: there is **no** `bank_account`/`card` saved-method object, no
> `account_number`/`routing_number`/`account_holder_name` request fields, no
> `display_name`/`last4`/`is_default`/`default_method_id` in the backend today. The
> "method-type form" described elsewhere in this spec is a forward-looking design
> assumption and must be coordinated with AND-258 before implementation (see §16
> Open assumptions).

Tier status — `GET /v1/kyc/tiers/me` (AND-320) → 200 (`TierDetails`; OpenAPI declares
an untyped `{}` body, shape taken from `src/api/types.ts`):

```json
{
  "user_sub": "user_123",
  "current_tier": 1,
  "tier_name": "basic",
  "updated_at": 1733000000,
  "history": []
}
```

`current_tier` is an **integer** rank (not a string enum). There is **no**
`required_tier_for_payouts` and **no** `missing_requirements` on this payload.

Requirements toward a target tier — `GET /v1/kyc/tiers/me/requirements/{target_tier}`
(`target_tier` is an **integer**) → 200 (`TierRequirements`):

```json
{
  "target_tier": 2,
  "current_tier": 1,
  "met": ["email_verified"],
  "unmet": ["gov_id"],
  "eligible": false
}
```

`met`/`unmet` are arrays of **requirement code strings** (not `{code,label,satisfied}`
objects); `eligible` is the boolean that drives the gate for the chosen target tier.

Evaluate (refresh after KYC) — `POST /v1/kyc/tiers/me/evaluate` (AND-320), mutation,
returns the updated `TierDetails` (same shape as `GET /v1/kyc/tiers/me`).

Error envelope (FastAPI `detail`, mapped per project convention — string |
`[{msg}]` | `{code,...}`):

```json
{ "detail": "Invalid CSRF token" }
{ "detail": [{ "msg": "routing_number invalid", "loc": ["body","routing_number"] }] }
{ "detail": { "code": "kyc_tier_insufficient", "message": "Verification required" } }
```

Status handling: 200/201 success; **403 with a tier-gate `detail.code` on save** →
treat as server-side gate, switch UI to Blocked and surface "Verify identity"
(defense in depth even if the client gate passed). **Unverified:** the exact code
string `kyc_tier_insufficient` is NOT present in the OpenAPI spec or frontend; the
client must match defensively (treat any 403 whose `detail` is an object with a
recognized tier/gate `code`, else fall back to a generic retryable 403) and the real
code must be confirmed with backend — see §16. 401 → authenticator refresh-once-retry
(transparent), persistent 401 → "Session expired" + re-auth; 403 CSRF → retryable;
409 → conflict, refresh and re-show state; 422 → map FastAPI `detail[].loc`/`msg`
into `fieldErrors`; 5xx / timeout → retryable, form state preserved. (The OpenAPI
index lists only `422:HTTPValidationError` for `POST /ui/payouts/request`; 401/403/409
behaviors are inferred from the shared `core-network` chain in `client.ts`, not from a
per-endpoint declaration.)

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

AC-2. **Setup works:** with a sufficient tier, entering a valid amount/method and
submitting calls `POST /ui/payouts/request` with `X-CSRF-Token`, and on 201 the
created payout (`payout_id`, `status`) is shown with a confirmation. (MockWebServer +
ViewModel + UI test — satisfies "Setup works". Corrected from `POST/PUT
/api/v1/payouts/methods`, which does not exist.)

AC-3. **KYC gate routes to verification:** with an insufficient tier, the form is
not submittable and the KYC-gate panel's "Verify identity" action navigates to the
KYC verification route. (Unit + UI test — satisfies "KYC gate routes to
verification when required".)

AC-4. Returning from the KYC flow triggers `POST /v1/kyc/tiers/me/evaluate`; if the
tier now meets the requirement, the form unlocks without a full reload. (ViewModel
test. Corrected from `POST /api/v1/kyc/evaluate`.)

AC-5. When tier status is unavailable, the gate is `Unknown` and saving is blocked
(fail-closed); a retry-tier action is offered. (ViewModel test.)

AC-6. A `403` tier-gate response from the payout request (object `detail` with a
recognized tier/gate `code`) flips the UI to Blocked and surfaces "Verify identity"
rather than a generic error. (MockWebServer + ViewModel test. The exact `code` string
is unverified — see §16; the test asserts behavior for the configured code constant.)

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. "OpenAPI index"
refers to `reference/openapi.index.txt`; "OpenAPI spec" to
`reference/openapi.pretty.json`; frontend paths are under `reference/src/`.

1. **Payout balance is read from `GET /ui/payouts/balance` returning
   `{available_cents, pending_cents, hold_cents, total_earned_cents,
   minimum_payout_cents, currency}`.** — Verified. OpenAPI `GET /ui/payouts/balance`
   → `PayoutBalanceOut` (spec `components.schemas.PayoutBalanceOut`); frontend
   `src/api/endpoints/payouts.ts: getPayoutBalance`, `src/api/types.ts: PayoutBalance`.

2. **A payout is created by `POST /ui/payouts/request` with body
   `{amount_cents (req, min 100), method (string, default "bank_transfer"),
   notes (≤500)}`, returning 201 `PayoutCreateOut {ok, payout_id, amount_cents,
   status}`.** — Verified. OpenAPI `POST /ui/payouts/request` → req
   `PayoutRequestIn`, resp `201:PayoutCreateOut`; frontend
   `src/api/endpoints/payouts.ts: requestPayout`, `src/api/types.ts: PayoutCreateResp`.

3. **The web payout method selector offers only `bank_transfer` and `paypal` as
   free-string `method` values (no typed bank/card objects).** — Verified.
   `src/pages/payouts/PayoutDashboard.tsx` (SelectItem `bank_transfer`/`paypal`;
   default state `"bank_transfer"`).

4. **A pending payout is cancelled via `POST /ui/payouts/{payout_id}/cancel` →
   `PayoutActionOut {ok, payout_id, status}`; prior payouts list via `GET /ui/payouts`
   → `PayoutListOut {items: PayoutOut[], next_cursor}`.** — Verified. OpenAPI
   `POST /ui/payouts/{payout_id}/cancel`, `GET /ui/payouts`; frontend
   `src/api/endpoints/payouts.ts: cancelPayout, listPayouts`,
   `src/api/types.ts: PayoutActionResp, PayoutListResp, Payout`.

5. **Original claim: payout methods are CRUD-managed via
   `GET/POST/PUT /api/v1/payouts/methods` with `{type, account_number,
   routing_number, account_holder_name}` and a `default_method_id`.** — Corrected
   (does not exist). No `/payouts/methods` path appears anywhere in the OpenAPI index;
   no such DTO in `src/api/types.ts`; the frontend has no method-CRUD call. Replaced
   with the payout-request model above.

6. **Tier status is read from `GET /v1/kyc/tiers/me` returning `TierDetails
   {user_sub, current_tier: Int, tier_name: String, updated_at, history[]}`.** —
   Verified path & shape. OpenAPI `GET /v1/kyc/tiers/me` (op `get_my_tier_…`); shape
   from frontend `src/api/endpoints/kyc-tiers.ts: getMyTier` +
   `src/api/types.ts: TierDetails`. (OpenAPI declares the 200 body as untyped `{}`, so
   the field names are sourced from the frontend types, which is authoritative here.)

7. **Original claim: tier endpoint is `GET /api/v1/kyc/tiers/me`.** — Corrected.
   Real path has no `/api` prefix: `GET /v1/kyc/tiers/me` (OpenAPI index;
   `kyc-tiers.ts`).

8. **Original claim: tier payload includes `required_tier_for_payouts` (string enum)
   and `missing_requirements: [{code,label,satisfied}]`, with string tiers
   ("basic"/"verified"/"enhanced").** — Corrected. `TierDetails` has neither field;
   `current_tier` is an **integer** rank with a separate `tier_name` string
   (`src/api/types.ts: TierDetails`). Requirement detail lives in a different call
   (#9), and requirement entries are plain **string codes** (also seen as
   `missing_requirements: string[]` in the KYC-case schema, OpenAPI spec
   `components.schemas` near the `kyc_case_id` field).

9. **Requirements toward a target tier come from
   `GET /v1/kyc/tiers/me/requirements/{target_tier}` (target_tier is an integer)
   returning `TierRequirements {target_tier, current_tier, met: String[],
   unmet: String[], eligible: Boolean}`.** — Verified. OpenAPI
   `GET /v1/kyc/tiers/me/requirements/{target_tier}` (path param typed `integer`);
   frontend `src/api/endpoints/kyc-tiers.ts: checkRequirements`,
   `src/api/types.ts: TierRequirements`.

10. **Tier re-evaluation is `POST /v1/kyc/tiers/me/evaluate` returning updated
    `TierDetails`.** — Verified path. OpenAPI `POST /v1/kyc/tiers/me/evaluate` (op
    `evaluate_my_tier_…`); frontend `src/api/endpoints/kyc-tiers.ts: evaluateTier`.

11. **Original claim: evaluate endpoint is `POST /api/v1/kyc/evaluate`.** —
    Corrected. Real path is `POST /v1/kyc/tiers/me/evaluate` (no `/api`, nested under
    `…/me`). OpenAPI index; `kyc-tiers.ts`.

12. **Original claim: requirements endpoint is `GET /v1/kyc/requirements`.** —
    Corrected. Real path is `GET /v1/kyc/tiers/me/requirements/{target_tier}`. OpenAPI
    index; `kyc-tiers.ts`.

13. **CSRF: every mutating call sends `X-CSRF-Token` echoed from the `ui_csrf`
    cookie; session rides cookies (`credentials: include`).** — Verified.
    `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`;
    `credentials: "include"`).

14. **On 401 the client performs a single `POST /ui/session/refresh` then retries the
    original request once; persistent 401 logs out.** — Verified.
    `src/api/client.ts: refreshSession()` + the 401 branch (single shared
    `refreshPromise`, one retry, `logout("session_expired")` on retry-401).

15. **Error envelope is FastAPI `detail` that may be a string, an array of
    `{msg, loc}`, or an object with a `code`.** — Verified.
    `src/api/client.ts: normalizeErrorDetail` (handles string / array-of-`{msg}` /
    object-with-`code`); object-`code` mapping in `mapAuthorizationError`.

16. **A 403 with a `kyc_tier_insufficient` code is returned when tier is short on
    save.** — Unverified-assumption. The string `kyc_tier_insufficient` appears in no
    source (OpenAPI spec, frontend). `POST /ui/payouts/request` declares only
    `200/201` + `422:HTTPValidationError` in OpenAPI. Treated as a defensively-matched
    constant; the real code/behavior must be confirmed with backend.

17. **The required tier for payouts is a single resolvable value driving the gate.**
    — Unverified-assumption. No backend field expresses it; modeled as a client
    constant `PAYOUT_REQUIRED_TIER` (integer) compared against `current_tier`, or via
    the `eligible` boolean from `requirements/{PAYOUT_REQUIRED_TIER}`. The actual rank
    must be confirmed (§13 Q2).

18. **The web payout flow itself enforces a KYC tier gate.** — Unverified /
    not-observed. `PayoutDashboard.tsx` validates only amount vs.
    min/available balance and does not call any tier endpoint before requesting a
    payout. The KYC gate in this ticket is an Android-side product requirement layered
    on top of the existing API, not a behavior copied from the web client.

19. **MVVM + Hilt + Compose Material 3 + Kotlin coroutines/StateFlow stack.** —
    Verified as framework choices (no source contradicts; standard Android arch).
    framework ref: developer.android.com/topic/architecture (UI layer / StateFlow),
    developer.android.com/jetpack/compose. (Project-level: aligns with the
    `compileSdk 35` / AGP 8.7.3 toolchain stated in §15.)

20. **Test targets (Robolectric JVM, emulator AVD `test35` API 35 x86_64, physical
    Samsung Galaxy A15 5G SM-A156U API 34 arm64) are available in CI/dev.** —
    Verified from the task environment description (not the codebase). Used to assign
    each §17 case to the right target.

### Corrections made

- C1 — Payout-method CRUD endpoints (`GET/POST/PUT /api/v1/payouts/methods`) and
  their `account_number`/`routing_number`/`account_holder_name`/`display_name`/`last4`/
  `default_method_id` fields **do not exist**; replaced with the verified payout-request
  flow (`GET /ui/payouts/balance`, `GET /ui/payouts`, `POST /ui/payouts/request`,
  `POST /ui/payouts/{id}/cancel`). Affected: §2, §3 (FR-3/FR-6), §4 (repo + data
  classes), §5, §6, §14 (AC-2). (Audit #2,#4,#5.)
- C2 — KYC tier paths corrected to drop the `/api` prefix and use the real nesting:
  `GET /v1/kyc/tiers/me`, `POST /v1/kyc/tiers/me/evaluate`,
  `GET /v1/kyc/tiers/me/requirements/{target_tier}`. Affected: §2, §5, §14 (AC-4).
  (Audit #7,#11,#12.)
- C3 — Tier model corrected: `current_tier` is an **integer** rank (+ `tier_name`
  string), not a string enum; `required_tier_for_payouts` and
  `missing_requirements` are NOT on `TierDetails`; requirements are
  `met`/`unmet` **string arrays** + `eligible` boolean on `TierRequirements`.
  Affected: §3 (FR-2), §4 (models + evaluator). (Audit #8,#9.)
- C4 — `403 kyc_tier_insufficient` demoted from a stated fact to a defensively-matched
  assumption pending backend confirmation. Affected: §5, §14 (AC-6). (Audit #16.)
- C5 — Method type set corrected from `bank_account`/`paypal`/`card` typed objects to
  the free-string values `bank_transfer`/`paypal`. Affected: §3 (FR-3), §5. (Audit #3.)

### Open assumptions

- OA1 — **Required payout tier value** (`PAYOUT_REQUIRED_TIER`): not exposed by any
  endpoint; must be set as a client/product constant and confirmed with backend
  (which integer rank gates payouts). Why unverifiable: no backend field; OpenAPI
  tier bodies are untyped `{}`. (Audit #17, §13 Q2.)
- OA2 — **Server-side tier-gate error code** on `POST /ui/payouts/request`: exact 403
  `detail.code` (assumed `kyc_tier_insufficient`) and whether the server returns 403
  vs 422 when tier is short. Why unverifiable: OpenAPI lists only `422` for that op;
  the code string is absent from all sources. (Audit #16, §13 Q3.)
- OA3 — **"Payout setup" product shape on Android**: whether M6 ships a true
  saved-method form (requires NEW AND-258 endpoints) or maps onto the existing
  amount+method payout-request flow. This spec implements the latter (verified API)
  and flags the former as out-of-scope-until-backend. Why unverifiable: no backend
  support today. (Audit #5, §13 Q1.)
- OA4 — **KYC verification entry route availability at M6** (E42/AND-321/AND-322 land
  M7): the gate's "Verify identity" destination may not exist yet; needs a graceful
  "verification not yet available" fallback. Why unverifiable: cross-ticket sequencing,
  not in these sources. (§13 Q5.)
- OA5 — **Exact `status` string values** for `PayoutCreateOut.status` /
  `PayoutOut.status` (e.g. "pending"): the schema types `status` as a free string with
  no enum, so example values are illustrative. Why unverifiable: no enum in the
  OpenAPI schema.

## 17. Test Plan

Test-target legend: **JVM** = local JVM/Robolectric (no device); **EMU** = headless
emulator AVD `test35` (x86_64, API 35); **DEVICE** = physical Samsung Galaxy A15 5G
(SM-A156U, API 34, arm64-v8a). Contract tests use MockWebServer (no real network).
Traces link to §14 acceptance criteria.

**TC-AND-259-01 — Gate evaluator: allowed/blocked/unknown + rank ordering**
- Type: unit. Target: JVM (`PayoutGateEvaluator`).
- Preconditions: none (pure function).
- Steps: Call `evaluate()` with (a) `null` status, (b) `eligible=true`, (c)
  `eligible=null` & `current_tier >= required`, (d) `eligible=false` &
  `current_tier < required` carrying `unmet=["gov_id"]`.
- Expected: (a) `Unknown`; (b)+(c) `Allowed`; (d) `Blocked(current, required,
  ["gov_id"])`. Integer-rank comparison correct across boundary.
- Traces: AC-1, AC-3, AC-5.

**TC-AND-259-02 — loadSetup composes balance + tier in parallel (happy path)**
- Type: contract/MockWebServer. Target: JVM (`PayoutSetupRepository`).
- Preconditions: MockWebServer queued: `GET /ui/payouts/balance` 200, `GET /ui/payouts`
  200, `GET /v1/kyc/tiers/me` 200 (`current_tier` above required), optionally
  `GET /v1/kyc/tiers/me/requirements/{n}` 200 `eligible=true`.
- Steps: Call `loadSetup()`; inspect recorded requests and result.
- Expected: All three reads issued (in parallel); `PayoutSetupData` has balance,
  recentPayouts, non-null `tierStatus`; derived gate = `Allowed`. Verb/path match the
  verified endpoints.
- Traces: AC-1, AC-2.

**TC-AND-259-03 — Successful payout request sends X-CSRF-Token and shows confirmation**
- Type: contract/MockWebServer. Target: JVM (`PayoutSetupRepository` +
  `PayoutSetupViewModel`).
- Preconditions: `ui_csrf` cookie present in the jar; gate `Allowed`; MockWebServer
  queues `POST /ui/payouts/request` → 201 `{ok:true, payout_id:"po_1",
  amount_cents:50000, status:"pending"}`.
- Steps: Set valid amount (≥ min, ≤ available) + method `bank_transfer`; call
  `submit()`.
- Expected: Recorded request is `POST /ui/payouts/request`, body
  `{amount_cents, method, notes}`, header `X-CSRF-Token` present; UiState shows
  `savedMethod`/created payout + confirmation; `isSaving` returns to false.
- Traces: AC-2.

**TC-AND-259-04 — Below-tier load derives Blocked; submit is a no-op**
- Type: unit (ViewModel, Turbine). Target: JVM.
- Preconditions: Fake repo returns `tierStatus` with `eligible=false`,
  `unmet=["gov_id"]`.
- Steps: `load()`; then call `submit()` while gated.
- Expected: gate = `Blocked` carrying current/required tier + `["gov_id"]`; `submit()`
  performs no network call (defensive guard); no `savedMethod`.
- Traces: AC-3, AC-5.

**TC-AND-259-05 — onReturnedFromKyc evaluates and unlocks when tier rises**
- Type: contract/MockWebServer. Target: JVM (ViewModel).
- Preconditions: initial tier below required (Blocked); MockWebServer queues
  `POST /v1/kyc/tiers/me/evaluate` → 200 `TierDetails` with raised `current_tier`
  (now ≥ required).
- Steps: After Blocked state, call `onReturnedFromKyc()`.
- Expected: a `POST /v1/kyc/tiers/me/evaluate` is issued; gate re-derives to
  `Allowed`; form unlocks without a full reload (no re-fetch of balance/list unless
  designed). `evaluating` toggles true→false.
- Traces: AC-4.

**TC-AND-259-06 — Fail-closed when KYC leg fails on load**
- Type: contract/MockWebServer. Target: JVM (repo + ViewModel).
- Preconditions: `GET /ui/payouts/balance` 200, `GET /v1/kyc/tiers/me` → 500 (or
  timeout).
- Steps: `load()`.
- Expected: `tierStatus = null` → gate = `Unknown`; form disabled; a retry-tier action
  offered; payout-leg success does not enable submit.
- Traces: AC-5.

**TC-AND-259-07 — 403 tier-gate on request flips UI to Blocked**
- Type: contract/MockWebServer. Target: JVM (ViewModel).
- Preconditions: gate `Allowed` client-side; MockWebServer queues
  `POST /ui/payouts/request` → 403 `{detail:{code:"<PAYOUT_GATE_CODE>",
  message:"Verification required"}}` (code = configured constant, OA2).
- Steps: `submit()` with a valid amount.
- Expected: UI flips to `Blocked`, surfaces "Verify identity" (not a generic error);
  entered amount preserved. Test is parameterized on the configured code constant.
- Traces: AC-6.

**TC-AND-259-08 — 422 validation maps to inline field errors; values preserved**
- Type: contract/MockWebServer. Target: JVM (ViewModel).
- Preconditions: MockWebServer queues `POST /ui/payouts/request` → 422
  `{detail:[{msg:"amount too low", loc:["body","amount_cents"]}]}`.
- Steps: `submit()` with an amount the client did not catch (forced).
- Expected: `fieldErrors["amount_cents"]` set from `loc`/`msg`; entered amount/method/
  notes retained; no crash on array `detail`.
- Traces: AC-7.

**TC-AND-259-09 — Local pre-network validation blocks submit**
- Type: unit (ViewModel). Target: JVM.
- Preconditions: balance min=1000, available=50000.
- Steps: Enter amount below min, then above available, then empty.
- Expected: `canSubmit=false` in each case; `submit()` issues no request; inline
  amount error shown. Boundary values (== min, == available) → `canSubmit=true`.
- Traces: AC-2, AC-7.

**TC-AND-259-10 — Network/CSRF/5xx errors are retryable and preserve form state**
- Type: contract/MockWebServer. Target: JVM (ViewModel).
- Preconditions: MockWebServer queues `POST /ui/payouts/request` → first a 403 CSRF
  (`detail:"Invalid CSRF token"`), then a disconnect/timeout, then a 500.
- Steps: `submit()` three times.
- Expected: each yields a non-blocking retryable `UiError` (csrf/network/server);
  entered values intact every time; double-submit guard keeps a second `submit()`
  while `isSaving` a no-op; no auto-retry of the mutation.
- Traces: AC-8.

**TC-AND-259-11 — Persistent 401 triggers single refresh then re-auth**
- Type: contract/MockWebServer. Target: JVM (network chain through repo).
- Preconditions: authenticated; MockWebServer: `POST /ui/payouts/request` → 401, then
  `POST /ui/session/refresh` → 401 (refresh fails).
- Steps: `submit()`.
- Expected: exactly one refresh attempt; on its failure surface "Session expired" /
  route to re-auth; no infinite retry loop. (Confirms the client.ts-derived behavior,
  Audit #14.)
- Traces: AC-8.

**TC-AND-259-12 — Compose UI: below-tier renders KYC-gate panel, taps route to KYC**
- Type: Compose-UI (instrumented). Target: EMU (`test35`).
- Preconditions: ViewModel seeded with `Blocked` state via fake repo;
  `onNavigateToKyc` lambda spy.
- Steps: Render `PayoutSetupScreen`; assert gate panel shows current/required tier +
  unmet; tap "Verify identity".
- Expected: amount form is not present/submittable; `onNavigateToKyc` invoked exactly
  once. Satisfies "KYC gate routes to verification".
- Traces: AC-1, AC-3.

**TC-AND-259-13 — Compose UI: above-tier form enables submit and shows confirmation**
- Type: Compose-UI (instrumented). Target: EMU (`test35`).
- Preconditions: ViewModel seeded with `Allowed` + balance; fake `submit()` → success.
- Steps: Render screen; enter valid amount + method; tap submit.
- Expected: submit enabled only with valid input; success confirmation rendered;
  button disabled while `isSaving`. Satisfies "Setup works".
- Traces: AC-1, AC-2.

**TC-AND-259-14 — Accessibility: gate panel & form semantics with TalkBack**
- Type: Compose-UI / accessibility (instrumented). Target: DEVICE (Samsung A15,
  API 34) — real TalkBack on hardware exercises the production accessibility stack and
  arm64/API-34 path; EMU is acceptable for the semantics-tree assertions only.
- Preconditions: both Blocked and Allowed fixtures.
- Steps: Assert merged semantics: gate panel announced as a single group ("Verify
  identity to enable payouts"); amount field has label + error semantics; disabled
  submit exposes reason ("Verification required"); touch targets ≥ 48dp; verify with
  TalkBack enabled on device.
- Expected: all semantics present; no unlabeled actionable nodes; targets meet size.
- Traces: AC-1, AC-3.

**TC-AND-259-15 — Manual: flaky/offline dev-host path (no data loss)**
- Type: manual. Target: DEVICE (real network to dev host
  `http://18.222.237.167:8000`, exercises cleartext + ~20s timeouts).
- Preconditions: app pointed at dev host; valid session.
- Steps: Enter a payout amount; toggle airplane mode mid-submit / let the request time
  out; restore connectivity and retry.
- Expected: offline banner with Retry; entered amount/method/notes preserved; no
  duplicate payout created (mutation not auto-retried); retry succeeds when host
  responds. Confirms §7 resilience on real hardware/network.
- Traces: AC-8.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 | TC-01, TC-02, TC-12, TC-13, TC-14 |
| AC-2 | TC-02, TC-03, TC-09, TC-13 |
| AC-3 | TC-01, TC-04, TC-12, TC-14 |
| AC-4 | TC-05 |
| AC-5 | TC-01, TC-04, TC-06 |
| AC-6 | TC-07 |
| AC-7 | TC-08, TC-09 |
| AC-8 | TC-10, TC-11, TC-15 |
