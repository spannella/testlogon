---
id: AND-214
title: Address / shipping
milestone: M5
epic: E29
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-213]
blocks: [AND-216]
---

# AND-214 — Address / shipping

## 1. Overview & Goal

> **REVIEW CORRECTION (2026-06-06).** A source audit (see §16) found that the
> backend exposes **no** shipping-quote or shipping-option-on-checkout endpoints.
> The address CRUD endpoints exist (under profile/settings, `GET/POST/PATCH/DELETE
> /ui/addresses`, `PUT /ui/addresses/primary`, `POST /ui/addresses/search`), but the
> entire "shipping options / quote / apply to checkout session" contract in the
> original draft was fabricated. The acceptance criterion "address applies to the
> order" cannot be satisfied through a checkout-session shipping API as drafted,
> because the cart/checkout surface (`POST /ui/checkout/session`, `POST
> /ui/shoppingcart/carts/{cart_id}/purchase`) carries **no** address or shipping
> selection. The closest real "shipping" concept is **post-purchase carrier
> tracking** (`PUT /ui/purchase-history/transactions/{txn_id}/shipping`, model
> `PurchaseShipping` = carrier/tracking/status). The sections below are corrected
> inline; claims that depend on the nonexistent endpoints are flagged as
> **Unverified-assumption / blocked** and reduced to the address-management slice
> that is actually buildable today. This warrants a scope conversation with the
> backend owners before implementation (see §13 R1 and §16 Open assumptions).

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
addresses (`GET /ui/addresses` — returns a **bare `AddressOut[]` array**, see §5) and
render them as a selectable list. The address marked **`is_primary_mailing`**
(corrected from the nonexistent `is_default`) is pre-selected; otherwise none is
selected.

FR-2. **Select an address.** Tapping an address row selects it and triggers a shipping
quote (FR-4). Selection is single-choice (radio semantics).

FR-3. **Add a new address.** An "Add address" action opens an address form. On valid
submit, `POST /ui/addresses` persists it (response **`200`**, body `AddressOut`), the
new address is appended to the list and auto-selected. **Corrected fields:** the
backend (`AddressIn`) requires **no** fields; the web reference enforces only `line1`
client-side. Form fields are `name`, `label`, `line1`, `line2`, `city`, `state`
(corrected from `region`), `postal_code`, `country`, `notes`. There is **no**
`full_name` (use `name`) and **no** `phone` field. We adopt the web convention:
`line1` required client-side; all others optional.

FR-4. **Quote shipping options.** **BLOCKED — no backend support (corrected).** No
shipping-quote endpoint or `ShippingOption` schema exists (verified against the
OpenAPI index and the entire frontend `src/`). This requirement cannot be implemented
as written and is deferred until the backend provides a quote endpoint; the original
`POST /ui/checkout/{checkout_id}/shipping/quote` path is fictitious. See §16 Open
assumptions and §13 R1.

FR-5. **Select shipping option.** **BLOCKED — depends on FR-4 (corrected).** No
shipping options are returned by any endpoint, so there is nothing to select. Deferred
with FR-4.

FR-6. **Apply to order.** **BLOCKED / re-scoped (corrected).** There is no
`PUT /ui/checkout/{checkout_id}/shipping` endpoint and the checkout-session / cart
models carry no `shipping_address_id` / `shipping_option_id` / shipping totals (§5).
The buildable substitute today is **persisting / marking a primary address**
(`PUT /ui/addresses/primary` with `{ address_id }`) and surfacing it for the
downstream payment step (AND-216) to read; "apply shipping option to order" is not
achievable until backend support lands. The original behavior (commit
address+option, read back applied totals, navigate to payment) is an
Unverified-assumption pending that endpoint.

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

All requests are authenticated and ride the **cookie jar + `Bearer` access token +
`X-CSRF-Token`**. **Correction:** the web client (`src/api/client.ts`) sets
`Authorization: Bearer <accessToken>` and `X-CSRF-Token` (from the `ui_csrf` cookie)
on **every** request, not only mutating ones, and always sends `credentials:
"include"`. The Android port should likewise attach the CSRF header to GETs too
(harmless and matches the reference). Field names below were corrected against
`src/api/types.ts` and `components.schemas.AddressIn/AddressOut`; the original draft
field names were wrong.

**GET `/ui/addresses`** → `200` — **Corrected.** Returns a **bare JSON array** of
`AddressOut`, NOT a `{ "addresses": [...] }` envelope (`src/api/endpoints/profile.ts:
getAddresses` types `Address[]`; the web page defensively guards with
`Array.isArray`). `AddressOut` fields are `address_id`, `name?`, `line1?`, `line2?`,
`city?`, `state?`, `postal_code?`, `country?`, `label?`, `notes?`,
`is_primary_mailing` (bool, default false), `created_at` (int epoch), `updated_at`
(int epoch). There is **no** `id`, `full_name`, `region`, `phone`, or `is_default`.
```json
[ { "address_id": "addr_01H...", "name": "Ada Lovelace", "line1": "5 Analytical Way",
    "line2": null, "city": "London", "state": "LDN", "postal_code": "EC1A 1BB",
    "country": "GB", "label": "home", "notes": null,
    "is_primary_mailing": true, "created_at": 1717600000, "updated_at": 1717600000 } ]
```

**POST `/ui/addresses`** — **Corrected.** Request body is `AddressIn`; **all fields
are optional server-side** (`name?, line1?, line2?, city?, state?, postal_code?,
country?, label?, notes?`). Response is **`200`** (NOT 201) with the created
`AddressOut`. Not auto-retried (mutating). The web form requires only `line1`
(client-side zod `min(1)`); the backend imposes no required fields.
```json
// request (AddressIn)
{ "name": "Ada Lovelace", "line1": "5 Analytical Way", "line2": null,
  "city": "London", "state": "LDN", "postal_code": "EC1A 1BB",
  "country": "GB", "label": "home", "notes": null }
// 200 -> AddressOut (shape above)
```

**PATCH `/ui/addresses/{address_id}`** — update; body `AddressIn`, `200 ->
AddressOut`. **DELETE `/ui/addresses/{address_id}`** — `200` (web reads `{ deleted:
true }`). **POST `/ui/addresses/search`** — body `{ "query": "..." }` →
`{ "query", "matches": AddressOut[] }`. (Edit/delete/search are out of this ticket's
scope per §13 R3, but listed for completeness — they DO exist.)

**PUT `/ui/addresses/primary`** — **Corrected default-address model.** The only
server-side notion of a "default" is the single primary *mailing* address, set via
`PUT /ui/addresses/primary` with body `AddressPrimaryReq` `{ "address_id": "..." }` →
`200 AddressOut`. There is no per-checkout default and no `is_default` flag; the
field is `is_primary_mailing`.

**~~POST `/ui/checkout/{checkout_id}/shipping/quote`~~ — DOES NOT EXIST.**
**Corrected/Removed.** No shipping-quote endpoint exists in the OpenAPI index or the
frontend. There is no `ShippingOption` schema (no service name / price /
`estimated_days` anywhere). FR-4/FR-5 are **blocked** pending a backend endpoint.

**~~PUT `/ui/checkout/{checkout_id}/shipping`~~ — DOES NOT EXIST.**
**Corrected/Removed.** The only `/ui/checkout/*` endpoints are
`POST /ui/checkout/session` and `POST /ui/checkout/session/file-bundle` (AND-213),
whose `UnifiedCheckoutSessionOut`/`FileBundleCheckoutSessionOut` carry **no**
`shipping_address_id` / `shipping_option_id` / `totals.shipping`. The cart purchase
path `POST /ui/shoppingcart/carts/{cart_id}/purchase` accepts **only**
`{ promo_code?, promo_code_id? }` and returns `CartPurchase` (no shipping fields);
`GET /ui/shoppingcart/carts/{cart_id}/total` returns `CartTotal = { cart_id,
total_cents, currency }` — **no** shipping or tax breakdown. So "apply address +
option to the order" has **no backend support** as drafted.

**Real "shipping" surface (informational):** post-purchase carrier tracking.
`PUT /ui/purchase-history/transactions/{txn_id}/shipping` with `PurchaseShippingReq`
(`PurchaseShipping`: `carrier?, tracking_number?, tracking_url?, status?,
status_description?, shipped_at?, delivered_at?, estimated_delivery?,
carrier_events?, address?`) → `PurchaseTransactionInfo`. This is tracking metadata,
not a pre-purchase shipping selector.

Amounts in the cart surface are integer **cents** (`*_cents`). Error body follows the
FastAPI `detail` union (`string | [{ "loc", "msg", "type" }] | { ... }`), decoded by
the shared `detail` mapper / `normalizeErrorDetail` in `core-network`; `422` carries
`HTTPValidationError` with `detail[].loc`/`msg`.

## 6. Data & State Management

- **Room (`core-data`):** `AddressEntity` table (PK **`address_id`** — corrected from
  `id`; columns mirroring `AddressOut`: `name`, `line1`, `line2`, `city`, `state`,
  `postal_code`, `country`, `label`, `notes`, **`is_primary_mailing`** — corrected
  from `is_default`, `created_at`, `updated_at`). `AddressDao` exposes
  `observeAll(): Flow<List<AddressEntity>>`, `upsertAll(...)`, `clearAndInsert(...)`.
  `refreshAddresses()` replaces the cached set in a transaction. This enables FR-8
  (stale list offline). Shipping quotes are **not** persisted (address-/time-specific,
  amounts volatile) — kept in `ShippingQuoteState` in memory only.
- **DataStore:** store `last_selected_address_id` (prefs) to pre-select on return; not
  authoritative — the server `is_primary_mailing` address wins when present
  (corrected from `is_default`).
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
- `POST /ui/addresses` (and the corrected `PUT /ui/addresses/primary`) are **not**
  auto-retried (mutating). On failure surface a `UiError` with a manual retry button;
  the form sheet stays open with entered data preserved. *(The shipping
  quote/apply error paths in the original draft are moot — those endpoints do not
  exist; see §5/§16.)*
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
- All requests carry session cookies + `Bearer` access token + `X-CSRF-Token`.
  **Correction:** the web reference (`src/api/client.ts`) attaches `X-CSRF-Token`
  (echoed from the `ui_csrf` cookie) and `Authorization: Bearer <token>` to **every**
  request, not only mutating ones; the Android port should match this (CSRF on GETs is
  harmless). `credentials: "include"` is always set.
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

- **R1 — Endpoint shape (RESOLVED by review; outcome: shipping API missing).** The
  2026-06-06 audit (§16) confirmed the address CRUD endpoints exist but the
  **shipping-quote / apply-to-checkout endpoints do not**. This is no longer
  uncertainty — it is a hard blocker for FR-4/FR-5/FR-6 and AC-1/AC-4. *Action: raise
  with backend owners; either descope this ticket to address management only, or block
  on a new shipping endpoint. Address field names corrected in §5 (`address_id`,
  `name`, `state`, `is_primary_mailing`; bare-array GET; 200-not-201 create).*
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

AC-1 (source). **BLOCKED pending backend (corrected).** As originally written —
applying address + shipping option to the order and reading back
`shipping_address_id`/`shipping_option_id`/`totals.shipping` — this is **not
achievable**: no such endpoints or fields exist (§5/§16). **Re-scoped interim AC-1:**
the selected address can be marked primary (`PUT /ui/addresses/primary`) and is
exposed to the downstream payment step; full "address+shipping applies to order"
requires a new backend endpoint. **(Source acceptance "Address applies to order."
cannot be fully met by this ticket alone.)**

AC-2. Saved addresses load from `GET /ui/addresses` (a **bare `AddressOut[]`** array);
the **`is_primary_mailing`** address (corrected from `is_default`) is pre-selected.

AC-3. A new address submitted via the form persists (`POST /ui/addresses`, response
**`200`** with `AddressOut`), appears in the list, and is auto-selected.

AC-4. **BLOCKED pending backend (corrected).** Re-quoting shipping on address change
is not implementable — no quote endpoint / `ShippingOption` schema exists (§5/§16).

AC-5. "Continue" is disabled until an address is selected. *(The "and a shipping
option" half is blocked with AC-4; with no options to select, the gate reduces to
address-selected.)*

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer. Sources:
OpenAPI index `reference/openapi.index.txt`, OpenAPI spec
`reference/openapi.pretty.json` (`components.schemas.*`), and frontend `reference/src`.

1. **`GET /ui/addresses` exists and lists saved addresses.** Verified.
   `GET /ui/addresses | op=ui_list_addresses_ui_addresses_get` (OpenAPI index);
   `src/api/endpoints/profile.ts: getAddresses`.
2. **`GET /ui/addresses` returns a bare array, not a `{ "addresses": [...] }`
   envelope.** Corrected (draft was wrong). `src/api/endpoints/profile.ts:
   getAddresses` → `api.get<Address[]>`; `src/pages/settings/Addresses.tsx` guards
   with `Array.isArray(addressesQuery.data)`.
3. **Address fields are `address_id`, `name`, `line1`, `line2`, `city`, `state`,
   `postal_code`, `country`, `label`, `notes`, `is_primary_mailing`, `created_at`,
   `updated_at`.** Corrected (draft used `id`, `full_name`, `region`, `phone`,
   `is_default`). `components.schemas.AddressOut` and `components.schemas.AddressIn`
   (OpenAPI); `src/api/types.ts: AddressIn` / `Address`.
4. **`POST /ui/addresses` creates an address; body `AddressIn`; all fields optional
   server-side; response is `200` (not `201`) with `AddressOut`.** Corrected (draft
   said 201 and listed required `full_name/city/region/postal_code/country`).
   `POST /ui/addresses | req=AddressIn | resp=200:AddressOut;422:HTTPValidationError`
   (OpenAPI index); `components.schemas.AddressIn` has empty `required`;
   `src/api/endpoints/profile.ts: createAddress`.
5. **Client-side, only `line1` is required for the address form.** Verified.
   `src/pages/settings/Addresses.tsx` zod schema: `line1: z.string().min(1, ...)`,
   all others `.optional()`.
6. **The "default"/primary address concept is `is_primary_mailing`, set via
   `PUT /ui/addresses/primary` with `{ address_id }`.** Corrected (draft used
   `is_default` and a per-checkout default). `PUT /ui/addresses/primary |
   req=AddressPrimaryReq | resp=200:AddressOut` (OpenAPI index);
   `components.schemas.AddressPrimaryReq` (`required: [address_id]`);
   `src/api/endpoints/profile.ts: setPrimaryAddress`.
7. **`POST /ui/checkout/{checkout_id}/shipping/quote` (shipping quote).** Corrected —
   **does not exist.** Absent from `openapi.index.txt` (only
   `POST /ui/checkout/session` and `POST /ui/checkout/session/file-bundle` exist under
   `/ui/checkout`); no `ShippingOption` schema; grep of `reference` for
   `ShippingOption|shipping/quote|estimated_days` returns no files.
8. **`PUT /ui/checkout/{checkout_id}/shipping` (apply address+option to session).**
   Corrected — **does not exist.** Same source as #7; checkout-session out-models carry
   no `shipping_address_id`/`shipping_option_id`/`totals.shipping`.
9. **Cart purchase carries address/shipping selection.** Corrected — it does not.
   `src/api/endpoints/cart.ts: purchaseCart` →
   `POST /ui/shoppingcart/carts/{cartId}/purchase` body `{ promo_code?, promo_code_id? }`;
   `src/api/types.ts: CartPurchase` (no shipping fields); `CartTotal = { cart_id,
   total_cents, currency }` (no shipping/tax breakdown).
10. **The real "shipping" surface is post-purchase carrier tracking.** Verified.
    `PUT /ui/purchase-history/transactions/{txn_id}/shipping | req=PurchaseShippingReq |
    resp=200:PurchaseTransactionInfo` (OpenAPI index);
    `src/api/endpoints/purchases.ts: updateShipping`; `src/api/types.ts:
    PurchaseShipping`.
11. **Auth: cookie-based session + CSRF via `ui_csrf` cookie → `X-CSRF-Token`.**
    Verified, with correction. `src/api/client.ts:168-171` reads cookie `ui_csrf` and
    sets `X-CSRF-Token`. Correction: it is set on **every** request (and a `Bearer`
    access token is also attached, `client.ts:157-160`), not only mutating ones as the
    draft implied.
12. **401 handling: one `POST /ui/session/refresh`, then retry the original request
    once.** Verified. `src/api/client.ts:121-122` (`refreshSession` →
    `/ui/session/refresh`) and `:204-221` (single refresh + one retry).
13. **`422` validation errors use FastAPI `HTTPValidationError` with `detail[].loc`.**
    Verified. All address ops show `422:HTTPValidationError` (OpenAPI index);
    `normalizeErrorDetail` in `src/api/client.ts`.
14. **Address edit/delete/search endpoints exist (out of ticket scope).** Verified.
    `PATCH /ui/addresses/{address_id}`, `DELETE /ui/addresses/{address_id}`,
    `POST /ui/addresses/search | req=AddressSearchReq | resp=200:AddressSearchResp`
    (OpenAPI index); `src/api/endpoints/profile.ts`.
15. **Compose / Material 3 / Hilt / Room / Navigation-Compose / DataStore choices.**
    Unverified-assumption (framework refs — not checkable from backend/frontend
    sources). Standard AOSP guidance: developer.android.com/jetpack/compose,
    developer.android.com/training/dependency-injection/hilt-android,
    developer.android.com/training/data-storage/room. (framework ref)

### Corrections made

- **C1.** `GET /ui/addresses` response shape: bare `AddressOut[]`, not
  `{ "addresses": [...] }` (§5, FR-1, AC-2). (Citation 2.)
- **C2.** Address field names: `address_id`/`name`/`state`/`is_primary_mailing`/
  `created_at`/`updated_at`; removed `id`/`full_name`/`region`/`phone`/`is_default`
  (§5, §6, FR-1, FR-3, AC-2). (Citation 3.)
- **C3.** `POST /ui/addresses` returns `200` (not `201`); no server-required fields,
  `line1`-only client-side (§5, FR-3, AC-3). (Citations 4, 5.)
- **C4.** Default-address model corrected to `PUT /ui/addresses/primary` +
  `is_primary_mailing` (§5, §6, FR-1). (Citation 6.)
- **C5.** Removed the fictitious `POST .../shipping/quote` and `PUT .../shipping`
  endpoints; flagged FR-4/FR-5/FR-6 and AC-1/AC-4 as blocked (§1 banner, §5, §3, §7,
  §13 R1, §14). (Citations 7-9.)
- **C6.** CSRF/auth: `X-CSRF-Token` + `Bearer` token on every request, not only
  mutating ones (§5, §8). (Citation 11.)

### Open assumptions

- **OA1.** *No shipping-quote / shipping-option-selection / apply-to-checkout backend
  exists.* The ticket's core acceptance ("address + shipping applies to the order")
  cannot be implemented until backend support is added. **Why unverifiable:** the
  endpoints and `ShippingOption`/checkout-shipping schemas are absent from both the
  OpenAPI spec and the frontend; nothing in the sources implements this. Needs a
  backend decision (new endpoint) or a descope to address management only.
- **OA2.** *`OrderTotals` / `CheckoutSession` shipping fields.* Assumed shape in the
  draft (`subtotal/shipping/tax/total`) is not present in `CartTotal`/`CartPurchase`;
  AND-213's session models would need to expose shipping totals. Unverified — pending
  AND-213's actual models and a backend totals contract.
- **OA3.** *All Android framework choices* (Compose, Hilt, Room, Navigation-Compose,
  Moshi, OkHttp authenticator) are architecture decisions, not backend contracts —
  verifiable only against Android docs (framework ref), not these sources.
- **OA4.** *Phone capture.* The draft's `phone` field has no backend home; if phone is
  a product requirement it must be added to `AddressIn`/`AddressOut` server-side first.

## 17. Test Plan

Acceptance criteria referenced are from §14 (note AC-1/AC-4 and the shipping half of
AC-5 are **blocked** by OA1 — see §16 — so coverage for them is limited to
"absence/blocked" assertions and contract guards rather than full behavior). IDs are
stable; "Traces" links each case to the AC(s) it exercises.

- **TC-AND-214-01** — Type: contract/MockWebServer. Target: JVM unit (Robolectric not
  required) — `AddressRepository.refreshAddresses` + DTO decode. Preconditions:
  MockWebServer enqueues `200` with a **bare JSON array** of two `AddressOut` objects
  (one `is_primary_mailing:true`). Steps: call `refreshAddresses()`; collect
  `observeAddresses()`. Expected: both addresses parsed (no envelope expected);
  `address_id`/`name`/`state`/`is_primary_mailing` mapped correctly; Room upserted and
  flow re-emits. Traces: AC-2.

- **TC-AND-214-02** — Type: unit. Target: JVM unit — `AddressShippingViewModel`
  default selection. Preconditions: repo emits list with one `is_primary_mailing:true`.
  Steps: init VM; read `uiState`. Expected: `selectedAddressId` == the primary
  address's `address_id`; no shipping quote attempted (feature blocked). Traces: AC-2,
  AC-5.

- **TC-AND-214-03** — Type: contract/MockWebServer. Target: JVM unit —
  `AddressRepository.createAddress`. Preconditions: MockWebServer enqueues **`200`**
  (not 201) returning the created `AddressOut`. Steps: call
  `createAddress(AddressDraft(line1="5 Analytical Way", name="Ada"))`. Expected:
  request body is `AddressIn` (no `full_name`/`region`/`phone` keys; uses
  `name`/`state`); `ApiResult.Success` with the new `Address`; it is appended +
  auto-selected. Traces: AC-3.

- **TC-AND-214-04** — Type: unit. Target: JVM unit — form validation matrix.
  Preconditions: none. Steps: drive `AddressDraft` through cases (empty `line1`;
  `line1` present + all others empty; with optional `label`/`notes`). Expected: submit
  enabled iff `line1` non-blank (matches web zod); no field is required beyond `line1`;
  no `phone` field present. Traces: AC-3, AC-5.

- **TC-AND-214-05** — Type: contract/MockWebServer. Target: JVM unit — `422` mapping.
  Preconditions: MockWebServer enqueues `422` `HTTPValidationError` with
  `detail:[{loc:["body","line1"],msg:"field required",type:"value_error.missing"}]`.
  Steps: submit address; map error. Expected: `detail[].loc` last segment (`line1`)
  maps to an inline per-field error in `AddressFormSheet`; sheet stays open with input
  preserved. Traces: AC-7.

- **TC-AND-214-06** — Type: contract/MockWebServer. Target: JVM unit — set-primary.
  Preconditions: MockWebServer enqueues `200 AddressOut` for `PUT
  /ui/addresses/primary`. Steps: call repo set-primary with an `address_id`. Expected:
  request path `/ui/addresses/primary`, body `{ "address_id": "..." }`; returned
  address has `is_primary_mailing:true`; list re-emits with new primary. Traces: AC-1
  (interim/re-scoped), AC-2.

- **TC-AND-214-07** — Type: contract/MockWebServer. Target: JVM unit — auth/CSRF
  headers. Preconditions: cookie jar holds `ui_csrf`; auth store holds an access token;
  MockWebServer records the request. Steps: issue `GET /ui/addresses` and `POST
  /ui/addresses`. Expected: **both** requests carry `X-CSRF-Token` (== cookie value)
  and `Authorization: Bearer <token>`; cookies attached. (Guards the §8 correction.)
  Traces: AC-2, AC-3.

- **TC-AND-214-08** — Type: contract/MockWebServer. Target: JVM unit — 401 refresh.
  Preconditions: queue `401`, then a `200` for `POST /ui/session/refresh`, then `200`
  for the retried `GET /ui/addresses`; a second `401` on a separate run. Steps: trigger
  GET. Expected: one refresh call to `/ui/session/refresh` then a single retry of the
  original request; a second consecutive `401` propagates as an auth error (routes to
  re-login). Traces: AC-2, AC-6.

- **TC-AND-214-09** — Type: integration (Robolectric/JVM, MockWebServer + in-memory
  Room). Target: offline/stale path. Preconditions: Room pre-seeded with one address;
  MockWebServer returns a connection failure (simulating the flaky dev host) for `GET
  /ui/addresses`. Steps: enter screen; `refreshAddresses()` fails after bounded
  backoff. Expected: cached address rendered; `isStale=true` banner; no crash; retry
  affordance present; mutating actions disabled/guarded offline. Traces: AC-6.

- **TC-AND-214-10** — Type: Compose-UI. Target: headless emulator AVD `test35`
  (API 35) — `createAndroidComposeRule`. Preconditions: VM seeded with two addresses,
  one primary. Steps: render `AddressShippingScreen`; assert radio single-select;
  toggle selection. Expected: address rows use `Role.RadioButton` with correct
  `selected` semantics; "Continue" enabled once an address is selected (no shipping
  gate, per blocked AC-4/AC-5). Traces: AC-2, AC-5.

- **TC-AND-214-11** — Type: Compose-UI (accessibility). Target: emulator AVD `test35`.
  Preconditions: address with `name`+`line1`+`city`. Steps: run a11y assertions over
  the list + form sheet. Expected: each row exposes a combined `contentDescription`
  (name, line1, city, "primary" when applicable); inputs have labels; touch targets
  ≥48dp; IME `Next/Done` ordering; large-font scaling does not clip. Traces: AC-2,
  AC-3, AC-5.

- **TC-AND-214-12** — Type: Compose-UI. Target: emulator AVD `test35` — form submit
  error preserves input. Preconditions: MockWebServer returns `422` for create. Steps:
  fill form, submit, observe sheet. Expected: inline error shown, sheet remains open,
  entered values retained. Traces: AC-7, AC-3.

- **TC-AND-214-13** — Type: instrumented/e2e. Target: **PHYSICAL DEVICE** Samsung
  Galaxy A15 5G (SM-A156U, API 34, arm64-v8a), MockWebServer-backed. Preconditions:
  app installed on device; MockWebServer reachable from device. Steps: launch → list
  addresses → add address (200) → mark primary (`PUT /ui/addresses/primary`) → return
  to screen. Expected: end-to-end flow works on real arm64/API-34 hardware (catches
  ABI/API-34-vs-35 deltas vs the x86_64/API-35 emulator); newly-primary address is the
  pre-selected one on return. **Must run on the physical device** (real
  arm64-v8a / API 34 path). Traces: AC-1 (interim), AC-2, AC-3.

- **TC-AND-214-14** — Type: manual. Target: any reviewer environment — blocked-feature
  documentation check. Preconditions: spec §16 OA1. Steps: confirm no code path calls a
  `shipping/quote` or `checkout/.../shipping` endpoint and that FR-4/FR-5/FR-6 surfaces
  are absent or feature-flagged off. Expected: build contains **no** reference to the
  nonexistent shipping endpoints; PR explicitly notes the descope. Traces: AC-1, AC-4
  (blocked-state verification).

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (apply to order — **blocked/re-scoped**) | TC-06 (interim set-primary), TC-13 (interim e2e), TC-14 (blocked-state) |
| AC-2 (list; primary pre-selected) | TC-01, TC-02, TC-06, TC-07, TC-08, TC-10, TC-11, TC-13 |
| AC-3 (add address persists/auto-selects) | TC-03, TC-04, TC-07, TC-11, TC-12, TC-13 |
| AC-4 (re-quote shipping — **blocked**) | TC-14 (blocked-state verification only) |
| AC-5 (Continue gate) | TC-02, TC-04, TC-10, TC-11 |
| AC-6 (offline cached + retry) | TC-08, TC-09 |
| AC-7 (`422` → inline field errors) | TC-05, TC-12 |
