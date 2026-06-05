---
id: AND-214
title: Address / shipping
milestone: M5
epic: E29
priority: P1
size: M
status: draft
depends_on: [AND-213]
blocks: [AND-216]
---

# AND-214 — Address / shipping

## 1. Overview & Goal

Provide the address and shipping step of the native Android checkout flow. After a
checkout session has been created (AND-213), the user must be able to (a) select an
existing saved shipping address or enter a new one, (b) choose from the shipping
options the backend offers for that address, and (c) apply the selection so that the
active checkout session reflects the chosen `address_id` and `shipping_option_id`.
The single testable acceptance criterion for this ticket is: **the chosen address (and
its shipping option) applies to the order** — i.e., a subsequent read of the checkout
session returns the selected address and shipping option, and the order totals
recalculate to include shipping cost and any address-derived tax.

This is a `feature` ticket, priority **P1**, sized **M** (one feature screen, two
ViewModels' worth of state, an address form with validation, three new endpoints
wired through `core-network`, Room caching of saved addresses). It lives in a new
`feature-checkout` address sub-screen and reuses checkout session plumbing delivered
by AND-213.

## 2. Context & References

- Monorepo `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- Namespace / applicationId base: `com.testlogon.android`.
- Feature module: `feature-checkout` (created in AND-213). This ticket adds the
  `address` package: `com.testlogon.android.feature.checkout.address`.
- Layering: `app -> feature-checkout -> core-network, core-model, core-data, core-ui, core-testing`.
- Dev backend (FastAPI + DynamoDB): `http://18.222.237.167:8000` — plaintext HTTP,
  unreliable; ~20s timeouts, bounded backoff for idempotent GETs only.
- OpenAPI: `GET /openapi.json`. Web reference: `frontend/src/api/endpoints/*.ts`
  (`checkout.ts`, `addresses.ts`) and shared types in `frontend/src/api/types.ts`.
- Auth is cookie-based; all calls in this ticket are authenticated and ride the
  persistent cookie jar + `X-CSRF-Token` header established by the session stack.
- Upstream: **AND-213** (checkout session) supplies the `checkout_id` and the
  order-review surface this screen mutates.
- Downstream: **AND-216** (payment) consumes the finalized address/shipping state;
  this ticket therefore lists AND-216 in `blocks`. (Derived from M5/E29 sequencing:
  AND-213 review -> AND-214 address/shipping -> payment.)

## 3. Functional Requirements

FR-1. **List saved addresses.** On entering the screen, load the user's saved
addresses (`GET /ui/addresses`) and render them as a selectable list. The address
marked `is_default` is pre-selected; otherwise none is selected.

FR-2. **Select an address.** Tapping an address row selects it and triggers a shipping
quote (FR-4). Selection is single-choice (radio semantics).

FR-3. **Add a new address.** An "Add address" action opens an address form. On valid
submit, `POST /ui/addresses` persists it, the new address is appended to the list and
auto-selected. Required fields: `full_name`, `line1`, `city`, `region`,
`postal_code`, `country` (ISO-3166 alpha-2). `line2` and `phone` optional.

FR-4. **Quote shipping options.** Whenever the selected address changes, request
shipping options for the current checkout session and address
(`POST /ui/checkout/{checkout_id}/shipping/quote`). Render returned options with
service name, estimated delivery window, and price.

FR-5. **Select shipping option.** Options are single-choice; the cheapest (or
`is_default`) option is pre-selected. Selecting an option updates the displayed order
total preview.

FR-6. **Apply to order.** A primary "Continue" / "Apply" action commits the selected
`address_id` + `shipping_option_id` to the checkout session via
`PUT /ui/checkout/{checkout_id}/shipping`. On success the screen reports applied
totals and signals navigation toward payment (AND-216). The button is disabled until
both an address and a shipping option are selected.

FR-7. **Form validation.** Inline, field-level validation runs before submit; the
submit button is disabled while required fields are empty/invalid. Postal-code and
country validation are lenient (non-empty + country in ISO list) to avoid blocking
international test data.

FR-8. **Offline / stale.** If addresses cannot be fetched, show the last cached
address list (Room) with a stale banner; the "Add address" path and shipping quote
require connectivity and surface a retry affordance when offline.

## 4. Technical Design

New package `com.testlogon.android.feature.checkout.address`:

```kotlin
// UiState
sealed interface AddressShippingUiState {
    data object Loading : AddressShippingUiState
    data class Ready(
        val addresses: List<Address>,
        val selectedAddressId: String?,
        val shipping: ShippingQuoteState,
        val totalsPreview: OrderTotals?,
        val isStale: Boolean = false,
        val applying: Boolean = false,
        val error: UiError? = null,
    ) : AddressShippingUiState
    data class Error(val error: UiError, val cached: List<Address> = emptyList()) : AddressShippingUiState
}

sealed interface ShippingQuoteState {
    data object Idle : ShippingQuoteState
    data object Quoting : ShippingQuoteState
    data class Quoted(val options: List<ShippingOption>, val selectedOptionId: String?) : ShippingQuoteState
    data class Failed(val error: UiError) : ShippingQuoteState
}
```

```kotlin
@HiltViewModel
class AddressShippingViewModel @Inject constructor(
    private val savedState: SavedStateHandle,           // checkoutId nav arg
    private val addressRepository: AddressRepository,
    private val checkoutRepository: CheckoutRepository, // from AND-213
) : ViewModel() {
    val uiState: StateFlow<AddressShippingUiState>

    fun onSelectAddress(addressId: String)
    fun onAddAddress(draft: AddressDraft)
    fun onSelectShippingOption(optionId: String)
    fun onApply()                                       // commits, then emits NavEvent.ToPayment
    fun onRetry()
}
```

Repositories (in `core-data`, exposed as Hilt-bound interfaces):

```kotlin
interface AddressRepository {
    fun observeAddresses(): Flow<List<Address>>                 // Room-backed
    suspend fun refreshAddresses(): ApiResult<List<Address>>
    suspend fun createAddress(draft: AddressDraft): ApiResult<Address>
}

interface CheckoutRepository {                                   // extended by this ticket
    suspend fun quoteShipping(checkoutId: String, addressId: String): ApiResult<List<ShippingOption>>
    suspend fun applyShipping(checkoutId: String, addressId: String, optionId: String): ApiResult<CheckoutSession>
}
```

Compose surface (`core-ui` Material 3 components):

```kotlin
@Composable
fun AddressShippingRoute(onNavigateToPayment: (checkoutId: String) -> Unit,
                         onBack: () -> Unit,
                         vm: AddressShippingViewModel = hiltViewModel())

@Composable
fun AddressShippingScreen(state: AddressShippingUiState,
                          onEvent: (AddressShippingEvent) -> Unit)

@Composable
fun AddressFormSheet(initial: AddressDraft, onSubmit: (AddressDraft) -> Unit, onDismiss: () -> Unit)
```

`AddressFormSheet` is a Material 3 `ModalBottomSheet`. Address rows and shipping
options use `RadioButton` + `Card`. Navigation: a new `Checkout.AddressShipping`
destination with `checkoutId: String` argument added to the Navigation-Compose graph;
"Apply" success emits a one-shot `NavEvent` collected in the route to call
`onNavigateToPayment(checkoutId)`.

Shipping quote is debounced (250 ms) so rapid address re-selection coalesces into a
single network call; the in-flight quote `Job` is cancelled on new selection.

## 5. API Contract

All requests are authenticated (cookie jar) and mutating ones send `X-CSRF-Token`.
Field names mirror `frontend/src/api/types.ts`; verify exact shapes against
`/openapi.json` during implementation.

**GET `/ui/addresses`** → `200`
```json
{ "addresses": [
  { "id": "addr_01H...", "full_name": "Ada Lovelace", "line1": "5 Analytical Way",
    "line2": null, "city": "London", "region": "LDN", "postal_code": "EC1A 1BB",
    "country": "GB", "phone": "+44...", "is_default": true } ] }
```

**POST `/ui/addresses`** (idempotent? no — not retried)
```json
// request
{ "full_name": "Ada Lovelace", "line1": "5 Analytical Way", "line2": null,
  "city": "London", "region": "LDN", "postal_code": "EC1A 1BB",
  "country": "GB", "phone": null }
// 201 -> the created Address object (same shape as list element)
```

**POST `/ui/checkout/{checkout_id}/shipping/quote`** — quote options for an address.
GET semantics are mutation-free but it is modeled POST (carries address selection);
treat as **non-idempotent for retry purposes** (no auto-retry).
```json
// request
{ "address_id": "addr_01H..." }
// 200
{ "options": [
  { "id": "ship_std", "name": "Standard", "amount": 599, "currency": "USD",
    "estimated_days_min": 3, "estimated_days_max": 5, "is_default": true },
  { "id": "ship_exp", "name": "Express", "amount": 1499, "currency": "USD",
    "estimated_days_min": 1, "estimated_days_max": 2, "is_default": false } ] }
```

**PUT `/ui/checkout/{checkout_id}/shipping`** — apply address + option to session.
```json
// request
{ "address_id": "addr_01H...", "shipping_option_id": "ship_std" }
// 200 -> updated CheckoutSession (AND-213 model) including:
{ "checkout_id": "co_...", "shipping_address_id": "addr_01H...",
  "shipping_option_id": "ship_std",
  "totals": { "subtotal": 4200, "shipping": 599, "tax": 384, "total": 5183,
              "currency": "USD" } }
```

Amounts are integer minor units. Error body follows FastAPI `detail` union:
`string | [{ "msg": ... }] | { "code": ..., ... }`, decoded by the shared
`detail` mapper in `core-network`.

## 6. Data & State Management

- **Room (`core-data`):** `AddressEntity` table (PK `id`, columns mirroring the
  Address model + `is_default`, `updated_at`). `AddressDao` exposes
  `observeAll(): Flow<List<AddressEntity>>`, `upsertAll(...)`, `clearAndInsert(...)`.
  `refreshAddresses()` replaces the cached set in a transaction. This enables FR-8
  (stale list offline). Shipping quotes are **not** persisted (address-/time-specific,
  amounts volatile) — kept in `ShippingQuoteState` in memory only.
- **DataStore:** store `last_selected_address_id` (prefs) to pre-select on return; not
  authoritative — server `is_default` wins when present.
- **State exposure:** `StateFlow<AddressShippingUiState>` via `stateIn(viewModelScope,
  WhileSubscribed(5_000), Loading)`, built by combining `observeAddresses()` with an
  internal `MutableStateFlow` holding selection + quote + apply status.
- **Mapping:** Moshi DTOs in `core-network` → domain models in `core-model`
  (`Address`, `ShippingOption`, `OrderTotals`, `CheckoutSession`); entity ↔ domain
  mappers in `core-data`. `AddressDraft` is a UI-layer input model converted to the
  POST DTO.
- **Selection invariants:** changing `selectedAddressId` clears
  `selectedOptionId` and re-quotes; `applying` blocks further selection edits.

## 7. Error Handling & Resilience

- `GET /ui/addresses` is idempotent: bounded exponential backoff (e.g., 2 tries after
  the first, jittered, cap ~6s) within the ~20s OkHttp timeout. On total failure emit
  `Error(cached=...)` and show cached addresses + stale banner.
- `POST /ui/addresses`, `POST .../shipping/quote`, `PUT .../shipping` are **not**
  auto-retried (non-idempotent / state-mutating). On failure surface a `UiError` with
  a manual retry button; the form sheet stays open with entered data preserved.
- `401` is handled centrally by the OkHttp authenticator/interceptor: one
  `POST /ui/session/refresh`, then retry once; a second 401 propagates as an auth
  error that routes to re-login (owned by the session stack).
- Validation (`422`) from `POST /ui/addresses`: map the `detail[].loc` field path to
  per-field inline errors in `AddressFormSheet`.
- Quote failure leaves the address selected, sets `ShippingQuoteState.Failed`, and
  disables "Continue" until a successful re-quote.
- Apply failure does not advance navigation; totals preview is rolled back to the last
  applied snapshot.

## 8. Security & Privacy

- Addresses are PII (name, postal address, phone). They are persisted in Room only on
  the app's private storage; no logging of address field values (see §10 — redact).
- All requests carry session cookies + `X-CSRF-Token`; mutating requests
  (`POST`/`PUT`) MUST include the CSRF header echoed from the `ui_csrf` cookie.
- Backend is plaintext HTTP **dev only**; production builds must use HTTPS base URL
  (cleartext permitted via network-security-config only for the dev flavor — owned by
  the networking baseline ticket, not relaxed here).
- On logout, clear the `AddressEntity` table and `last_selected_address_id` DataStore
  key as part of the session-clear routine.
- No address data written to `SavedStateHandle` beyond `checkoutId`; the in-progress
  `AddressDraft` is held in process memory only.

## 9. Accessibility & i18n

- All inputs have associated labels; address rows expose a combined
  `contentDescription` (e.g., "Ada Lovelace, 5 Analytical Way, London, default
  address") and radio `selected`/`Role.RadioButton` semantics; shipping options
  announce name, price, and delivery window.
- Touch targets ≥ 48dp; supports dynamic type / large font scaling; form sheet is
  reachable and dismissible via TalkBack and IME `imeAction = Next/Done` ordering.
- All user-facing strings in `strings.xml` (no hardcoded literals). Prices formatted
  with `NumberFormat.getCurrencyInstance` using the option's `currency` and the device
  locale; delivery windows pluralized via `plurals`.
- Country selector is a searchable list of ISO-3166 names localized via
  `Locale(...).displayCountry`.

## 10. Telemetry & Logging

- Events (via the app analytics facade, no PII payloads): `checkout_address_viewed`,
  `checkout_address_added`, `checkout_address_selected` (id hashed),
  `checkout_shipping_quoted` (option_count, latency_ms),
  `checkout_shipping_selected` (option_id), `checkout_shipping_applied`
  (total_amount, currency), `checkout_address_error` (stage, http_code).
- Logging: structured Timber logs at the repository boundary record endpoint, status,
  and latency; address field values and phone numbers MUST be redacted. Quote/apply
  request bodies are logged with `address_id`/`option_id` only.
- A single `applied` event corresponds to the acceptance criterion and is the metric
  used to confirm successful address application in QA dashboards.

## 11. Testing Strategy

- **Unit (`core-testing`, JUnit5 + Turbine + MockWebServer):**
  - `AddressShippingViewModelTest`: default address pre-selection; selecting an
    address triggers a single (debounced) quote and clears option selection; apply
    success emits `NavEvent.ToPayment`; apply failure keeps state and shows error.
  - `AddressRepositoryTest`: `refreshAddresses` upserts Room and `observeAddresses`
    re-emits; backoff on GET; no retry on POST.
  - DTO↔domain and entity↔domain mapper tests, including `detail` union error decode
    and `422` field mapping.
- **Form tests:** validation matrix (missing required fields, invalid country,
  optional line2/phone) toggles submit-enabled correctly.
- **Compose UI tests (`createAndroidComposeRule`):** radio single-select semantics,
  "Continue" disabled until both selections present, stale banner shown on cached
  state, form sheet preserves input on submit error.
- **Acceptance test (instrumented, MockWebServer-backed):** select address → quote →
  select option → apply → assert the returned `CheckoutSession` has matching
  `shipping_address_id` / `shipping_option_id` and `totals.shipping > 0` and nav event
  fired. This directly verifies "Address applies to order."

## 12. Dependencies & Sequencing

- **Depends on AND-213 (Checkout session):** requires `checkoutId`,
  `CheckoutRepository`, `CheckoutSession`/`OrderTotals` models, and the
  `feature-checkout` module + navigation host. Hard blocker.
- **Blocks AND-216 (Payment):** payment consumes the applied address + shipping +
  recomputed totals from this step.
- Reuses the cookie/CSRF/refresh networking baseline and the Room/DataStore
  infrastructure already established earlier in the port. No new third-party libraries.
- Sequencing within ticket: (1) models + DTOs + mappers, (2) `core-network` endpoints,
  (3) `AddressRepository` + Room, (4) extend `CheckoutRepository`, (5) ViewModel,
  (6) Compose UI + nav, (7) tests.

## 13. Risks & Open Questions

- **R1 — Endpoint shape uncertainty.** The exact address/shipping paths and the quote
  verb (POST vs GET-with-query) must be confirmed against `/openapi.json` and
  `frontend/src/api/endpoints/`; the contract in §5 is the working assumption. *Owner:
  this ticket during impl.*
- **R2 — Tax recompute timing.** Whether tax is returned by the quote endpoint or only
  after `PUT .../shipping` affects the totals-preview UX. Assumption: authoritative
  totals come from the apply response; quote shows shipping price only.
- **R3 — Address edit/delete** is out of scope (add + select only); if the backend
  exposes PATCH/DELETE, defer to a follow-up ticket.
- **R4 — Dev host flakiness** may cause quote timeouts; mitigated by clear retry UI,
  but could surface in flaky instrumented tests → use MockWebServer, never the live
  dev host, in CI.
- **OQ:** Is there a maximum saved-address count or a server-side default-address
  setter? Not assumed; selection here is per-checkout only.

## 14. Acceptance Criteria

AC-1 (source). Selecting (or adding) an address and a shipping option and tapping
"Continue" results in those values being applied to the order: a subsequent
`GET`/`PUT` response shows `shipping_address_id` and `shipping_option_id` equal to the
selection and `totals.shipping`/`total` reflect the chosen option. **(Maps to the
source acceptance: "Address applies to order.")**

AC-2. Saved addresses load from `GET /ui/addresses`; the `is_default` address is
pre-selected.

AC-3. A new address submitted via the form persists (`POST /ui/addresses`), appears in
the list, and is auto-selected.

AC-4. Changing the selected address re-quotes shipping; options render with name,
price, and delivery window; the default/cheapest option is pre-selected.

AC-5. "Continue" is disabled until both an address and a shipping option are selected.

AC-6. Offline: cached addresses render with a stale banner; mutating actions surface a
retry affordance and do not crash.

AC-7. `422` validation errors from address creation map to inline per-field messages.

## 15. Definition of Done

- All ACs met and covered by the acceptance/instrumented test in §11.
- New code in `com.testlogon.android.feature.checkout.address`; layering respected
  (`feature-checkout -> core-*`), no `core -> feature` leaks.
- Unit + Compose + instrumented tests pass in CI against MockWebServer (not the live
  dev host); coverage on ViewModel + repository ≥ project threshold.
- No hardcoded user-facing strings; a11y semantics verified with TalkBack pass.
- No PII in logs/telemetry (verified by log redaction test); Room/DataStore cleared on
  logout.
- ktlint/detekt clean; KSP/Hilt graph compiles; builds for dev and release flavors
  with cleartext restricted to dev.
- Endpoint shapes reconciled with `/openapi.json`; any deviation from §5 documented in
  the PR.
- PR reviewed and merged to `android-port`; AND-216 unblocked.
