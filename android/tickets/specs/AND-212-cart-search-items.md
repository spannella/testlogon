---
id: AND-212
title: Cart search/items
milestone: M5
epic: E29
priority: P2
size: S
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-210]
blocks: []
---

# AND-212 — Cart search/items

## 1. Overview & Goal

The cart can grow large (TestLogon carts are not bounded server-side and routinely
hold 30–80 line items in QA fixtures). Scrolling such a cart to find a single SKU is
slow. This ticket adds an in-cart **item/SKU search** that filters the already-loaded
cart line items locally as the user types, so the cart `LazyColumn` shows only the
matching rows plus a recomputed "matched subtotal" affordance.

The feature is **client-only filtering of the in-memory cart snapshot**. It does not
introduce a new backend call: the canonical cart payload is fetched once by AND-210's
`CartRepository` and rendered by AND-211's `CartScreen`. AND-212 layers a search field
and a derived, filtered view-model state on top of that existing screen. Goal: given a
cart with N items, typing a query of >= 1 non-whitespace character filters the visible
line items to those whose SKU or product name contains the query
(case-insensitive, diacritic-folded substring match), and clearing the query restores
the full cart.

> **REVIEW CORRECTION (2026-06-06):** The backend `ShoppingCartItemOut` schema and the
> web `CartItem` type have **no variant field** (no `variant_label`, `variant`, or
> `options`). The matchable text fields are `sku` and `name` only. All references to
> "variant label" / `variantLabel` below are struck through or corrected. The DTO field
> is `name`, **not** `product_name`. See §5 and §16 for the authoritative sources.

Success = "Search filters cart" (the source acceptance bullet) is demonstrably true,
debounced, accessible, and tested.

## 2. Context & References

- **Backlog:** AND-212 — *Cart search/items*. Type: Feature · Priority: P2 · Deps: AND-210.
  Scope: "Item/SKU search within cart." Acceptance: "Search filters cart."
- **Upstream / hard dependency:** AND-210 (*Cart API + DTOs*, P0) owns `cart.ts`-parity
  endpoints, the `CartDto`/`CartItemDto` shapes, `CartRepository`, and the domain
  `Cart`/`CartItem` models. AND-212 consumes those models read-only.
- **Sibling / integration surface:** AND-211 (*Cart screen*, P0) owns `CartScreen`,
  `CartViewModel`, `CartUiState`, the add/update-qty/remove interactions, totals, and
  the empty state. AND-212 extends `CartUiState` and `CartViewModel` and inserts a
  search field composable into `CartScreen`. AND-212 must merge cleanly with AND-211
  rather than fork it.
- **Web reference:** `src/api/endpoints/cart.ts` (endpoint calls) and `src/api/types.ts`
  (`CartItem`, `CartItemsResp`) are the DTO source of truth.
  **CORRECTED:** the web app does **not** have a cart item-filter input — `src/pages/shop/Cart.tsx`
  renders `getCartItems(cartId).items` directly with no client-side text filter, so there
  is no web filter to "mirror". This in-cart search is net-new for the Android client.
  The real match fields are `sku` and `name` only (there is no `variant`/`variant_label`).
  Note: a server-side endpoint `GET /ui/shoppingcart/carts/items/search?q=&limit=` exists
  but is unused by the web app; this ticket intentionally stays client-side (§5).
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity
  Navigation-Compose, Hilt (KSP), Coroutines/Flow. Module layering
  `app -> feature-cart -> core-*`. ViewModels expose `StateFlow<UiState>`.
- **Namespace:** all packages under `com.testlogon.android` (here
  `com.testlogon.android.feature.cart`).

## 3. Functional Requirements

FR-1. A single-line search `TextField` (Material 3 `OutlinedTextField` styled as a
search field) is pinned at the top of the cart content, above the line-item list and
below any cart header. It is **not** shown in the cart empty state (no items to search).

FR-2. As the user types, the visible line-item list filters to items matching the query.
Matching is **case-insensitive** and **diacritic-insensitive** (Unicode NFD fold +
strip combining marks) **substring** match against: `sku` and `name` (the Kotlin
domain field for the DTO `name`). An item qualifies if either field contains the
normalized query. (CORRECTED: there is no `variantLabel`/variant field on the cart
item — see §5/§16.)

FR-3. Filtering is **debounced** by 200 ms from the last keystroke before recomputation
to avoid recomposing the whole list on every character. The text field reflects the
typed value immediately (no input lag); only the derived filtered list is debounced.

FR-4. A trailing clear ("×") icon appears when the query is non-empty. Tapping it clears
the query and immediately restores the full cart (no debounce on clear).

FR-5. When the query yields **zero matches**, the list area shows a "no results" state:
text "No items match \"<query>\"" plus a "Clear search" text button. This is distinct
from AND-211's "empty cart" state.

FR-6. While a query is active, a **matched subtotal** line is shown above or within the
list header: "N of M items · subtotal $X.XX" where N = matched count, M = total count,
and subtotal = sum of `lineTotal` over matched items (currency-formatted via the same
formatter AND-211 uses for cart totals). The grand cart total area (owned by AND-211)
is **unchanged** — search never alters the actual cart, only the view.

FR-7. Editing item quantity or removing an item (AND-211 interactions) while a query is
active must keep the filter applied: the resulting cart re-emits, the filter re-runs,
and an item that no longer matches (e.g., removed) drops out. The query string survives
these mutations and survives configuration changes / process death-restore via
`SavedStateHandle`.

FR-8. The query is **transient view state**, not persisted to disk and not sent to the
server. Navigating away from and back to the cart starts with an empty query.

## 4. Technical Design

All work lives in `feature-cart` (`com.testlogon.android.feature.cart`). No `core-*`
changes are required; the domain `Cart`/`CartItem` from AND-210 are consumed as-is.

**State.** Extend AND-211's `CartUiState` (or wrap it) with search fields. Keep the
authoritative loaded cart separate from the query so filtering is a pure derivation:

```kotlin
package com.testlogon.android.feature.cart

data class CartUiState(
    val isLoading: Boolean = false,
    val cart: Cart? = null,                 // canonical, from CartRepository (AND-210)
    val query: String = "",                 // raw text field value
    val filtered: FilteredCart = FilteredCart.EMPTY,
    val errorMessage: String? = null,
    val isStale: Boolean = false,
)

data class FilteredCart(
    val items: List<CartItem> = emptyList(),
    val matchedCount: Int = 0,
    val totalCount: Int = 0,
    val matchedSubtotalCents: Long = 0L,
) {
    val isFiltering: Boolean get() = matchedCount != totalCount
    companion object { val EMPTY = FilteredCart() }
}
```

**Filtering logic** is a pure, unit-testable function in `core`-free feature code:

```kotlin
object CartSearch {
    fun normalize(s: String): String =
        java.text.Normalizer.normalize(s, java.text.Normalizer.Form.NFD)
            .replace(Regex("\\p{Mn}+"), "")
            .lowercase()
            .trim()

    fun filter(items: List<CartItem>, rawQuery: String): FilteredCart {
        val q = normalize(rawQuery)
        if (q.isEmpty()) return FilteredCart(
            items = items,
            matchedCount = items.size,
            totalCount = items.size,
            matchedSubtotalCents = items.sumOf { it.lineTotalCents },
        )
        // CORRECTED: match sku + name only; no variant field exists on CartItem.
        val matches = items.filter { item ->
            normalize(item.sku).contains(q) ||
                normalize(item.name).contains(q)
        }
        return FilteredCart(
            items = matches,
            matchedCount = matches.size,
            totalCount = items.size,
            matchedSubtotalCents = matches.sumOf { it.lineTotalCents },
        )
    }
}
```

**ViewModel.** Extend AND-211's `CartViewModel`. The query is held in a
`MutableStateFlow`, mirrored to `SavedStateHandle`, debounced, and combined with the
cart flow. `combine` re-derives `filtered` whenever either the cart or the (debounced)
query changes:

```kotlin
@HiltViewModel
class CartViewModel @Inject constructor(
    private val cartRepository: CartRepository,   // AND-210
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val query = MutableStateFlow(savedState["cart_query"] ?: "")

    @OptIn(FlowPreview::class)
    private val debouncedQuery = query
        .debounce { if (it.isEmpty()) 0L else 200L }
        .distinctUntilChanged()

    val uiState: StateFlow<CartUiState> =
        combine(cartRepository.cartFlow, query, debouncedQuery) { cartResult, raw, dq ->
            val cart = (cartResult as? ApiResult.Success)?.data
            CartUiState(
                isLoading = cartResult is ApiResult.Loading,
                cart = cart,
                query = raw,
                filtered = cart?.let { CartSearch.filter(it.items, dq) } ?: FilteredCart.EMPTY,
                errorMessage = (cartResult as? ApiResult.Error)?.message,
                isStale = (cartResult as? ApiResult.Success)?.fromCache == true,
            )
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), CartUiState(isLoading = true))

    fun onQueryChange(value: String) {
        query.value = value
        savedState["cart_query"] = value
    }
    fun onClearQuery() = onQueryChange("")
}
```

Note: `query` is included in the `combine` (not just `debouncedQuery`) so the text field
echoes keystrokes with zero lag while the heavy `filter` derivation keys off the
debounced value. `distinctUntilChanged` plus a 0 ms debounce for the empty string makes
"clear" instantaneous.

**UI.** A new composable in `CartScreen.kt`:

```kotlin
@Composable
fun CartSearchField(
    query: String,
    onQueryChange: (String) -> Unit,
    onClear: () -> Unit,
    modifier: Modifier = Modifier,
)
```

`CartScreen` renders `CartSearchField` (gated on `state.cart?.items?.isNotEmpty()`),
then the matched-subtotal header when `state.filtered.isFiltering`, then either the
filtered `LazyColumn` (keyed by `item.sku` — CORRECTED: `CartItem` has no `id`; `sku`
is the item identity, as the web PATCH/DELETE endpoints key on `sku`) or the no-results state. AND-211's row
composable (`CartItemRow`) is reused unchanged; AND-212 only changes the *list source*
from `state.cart.items` to `state.filtered.items`.

## 5. API Contract

No new network calls. AND-212 is pure client-side filtering over the cart snapshot that
AND-210 already fetches. **CORRECTED:** the cart items are fetched via
`GET /ui/shoppingcart/carts/{cart_id}/items` (op `ui_list_items...`, response schema
`ShoppingCartItemsOut`), **not** `GET /cart` — there is no `/cart` endpoint. The web
client calls this as `getCartItems(cartId)` in `src/api/endpoints/cart.ts`, returning
`CartItemsResp { cart_id, items: CartItem[] }`. Transport is cookie-authenticated with
`credentials: include`; the `X-CSRF-Token` request header is echoed from the `ui_csrf`
cookie; on a `401` for an authenticated user the client refreshes once via
`POST /ui/session/refresh` and retries (verified in `src/api/client.ts`). Timeout/backoff
values (~20s, bounded backoff) are AND-210/core-network policy and are **unverified** from
these sources — treat as an AND-210 assumption.

The authoritative per-item shape (backend `ShoppingCartItemOut`, required fields marked):

```json
{
  "sku": "TL-SHIRT-BLK-M",     // required
  "name": "TestLogon Tee",      // required  (NOT "product_name")
  "quantity": 2,                // required
  "unit_price_cents": 1999,     // required
  "line_total_cents": 3998,     // required
  "updated_at": "2026-06-01T...", // required (string)
  "image_url": "https://...",   // optional
  "category_id": "cat_…",       // optional
  "item_id": "itm_…",           // optional (catalog item id, NOT line identity)
  "product_type": "file_bundle",// optional
  "access_mode": "purchase"     // optional
}
```
There is **no** `id`, `product_name`, or `variant_label`/`variant` field. Line identity
is the **`sku`** (the PATCH/DELETE item endpoints are keyed by `sku`).

A faithful AND-210 domain mapping (search consumes only `sku`, `name`, `lineTotalCents`):

```kotlin
data class CartItem(
    val sku: String,            // identity + match field
    val name: String,           // match field (DTO "name")
    val quantity: Int,
    val unitPriceCents: Long,   // DTO unit_price_cents
    val lineTotalCents: Long,   // DTO line_total_cents
    val updatedAt: String,
    val imageUrl: String? = null,
    val categoryId: String? = null,
    val itemId: String? = null,
)
```

**Contract requirement on AND-210:** `sku` and `name` must be present and non-null on
`CartItem` (both are `required` in `ShoppingCartItemOut`, so this holds by the backend
schema). No variant field is required because none exists. See §13.

**Alternative not chosen:** a server-side `GET /ui/shoppingcart/carts/items/search`
(params `q` required minLength 1, `limit` default 100 max 200) exists but is **unused by
the web app** and returns an untyped `200` schema; client-side filtering of the already-
loaded list is simpler, offline-capable, and matches web behavior (which loads all items).

## 6. Data & State Management

- **Source of truth:** `CartRepository.cartFlow: Flow<ApiResult<Cart>>` (AND-210),
  unchanged. AND-212 never mutates the cart.
- **Derived state:** `FilteredCart` is recomputed from `(cart.items, debouncedQuery)`
  inside `combine`. It is ephemeral and never cached.
- **Query persistence:** `query` is mirrored to `SavedStateHandle["cart_query"]` so it
  survives configuration change and process-death restore (FR-7), but it is **not**
  written to DataStore/Room and is **not** restored across navigation sessions (FR-8).
- **Room/DataStore:** untouched by this ticket. Cart caching is AND-210's concern; a
  `fromCache`/stale cart filters identically to a fresh one.
- **List identity:** `LazyColumn` items use `key = { it.sku }` (CORRECTED: no `id` field;
  `sku` is unique per line) so filtering animates as removal/insertion and scroll/row
  state is preserved for surviving rows.
- **Performance:** `CartSearch.normalize` is O(len) per field; `filter` is O(N·fields).
  For carts of expected size (<= a few hundred items) this is well under a frame budget
  even without memoization; the 200 ms debounce caps recompute frequency.

## 7. Error Handling & Resilience

- Search introduces **no new failure modes**: it operates on an in-memory list. There is
  no loading, error, or retry state owned by this ticket.
- If the underlying cart load is in `ApiResult.Error` or `Loading`, the search field is
  hidden (no items to filter); AND-211 owns those states and their retry affordances.
- If the cart is **stale/offline** (`fromCache = true`), search still works over the
  cached items; the AND-211 stale banner remains visible. Search must not imply the
  results are live.
- Zero-match is a normal, non-error UI state (FR-5), visually distinct from the empty
  cart and from load errors.
- Defensive: empty `sku`/`name` are handled by the `contains` match in
  `CartSearch.filter` (both are non-null per schema); a query of only whitespace
  normalizes to empty and is treated as "no filter".

## 8. Security & Privacy

- The query never leaves the device: no network call, no logging of raw query content
  (see §10), no persistence beyond `SavedStateHandle` (process-scoped, not on disk).
- No PII is introduced. SKU/product/variant strings are already on-device from AND-210's
  authenticated cart fetch.
- Cookie/CSRF/session handling is entirely inherited from AND-210/core-network and is
  out of scope here; AND-212 issues no requests, so it cannot leak or mishandle the
  session.
- Filtering is purely local, so it functions unchanged whether the dev backend
  (`http://18.222.237.167:8000`, plaintext) is reachable or not.

## 9. Accessibility & i18n

- The search field has `contentDescription` / label "Search cart items" via a string
  resource `R.string.cart_search_hint`; the clear icon has `contentDescription`
  "Clear search" (`R.string.cart_search_clear`).
- All user-visible strings (`hint`, `clear`, no-results template, matched-subtotal
  template) live in `strings.xml`; the no-results and "N of M" strings use parameterized
  resources (`%1$s`, `%1$d`, `%2$d`) for translation and locale-correct ordering.
- Currency in the matched subtotal uses the same locale-aware formatter as AND-211
  (`NumberFormat.getCurrencyInstance`), not hand-built strings.
- Matching is diacritic-folded (FR-2) so users typing "cafe" match "Café"; this is
  locale-tolerant. Folding uses Unicode NFD, not a hardcoded ASCII table.
- The result count change must be announced to TalkBack: apply
  `Modifier.semantics { liveRegion = LiveRegionMode.Polite }` to the matched-subtotal
  header so screen-reader users hear "12 of 40 items" as they type.
- Minimum touch target 48dp for the clear icon; field meets Material 3 default height.

## 10. Telemetry & Logging

- Emit a single debounced analytics event `cart_search_used` with properties
  `query_length: Int`, `matched_count: Int`, `total_count: Int`, fired at most once per
  debounce settle when `query` is non-empty. **Never log the raw query text** (privacy,
  §8) — only its length.
- Emit `cart_search_zero_results` with `query_length`, `total_count` when a settled
  non-empty query matches zero items, to surface findability problems.
- Use the project's existing analytics abstraction (injected `Analytics`); no new
  telemetry infra. If the analytics interface is not yet wired in `feature-cart`, gate
  these behind a no-op default so this ticket does not block on it.
- Debug-level `Timber` logging only: log `matchedCount/totalCount`, never query content.

## 11. Testing Strategy

Unit (JVM, `core-testing` helpers):
- `CartSearchTest` — pure `CartSearch.filter` cases: empty query returns all + correct
  subtotal; SKU substring match; name (product-name) match; case-insensitive
  match; diacritic-folded match ("cafe" matches "Café"); whitespace-only query = all;
  zero-match returns empty list, `matchedCount = 0`, `subtotal = 0`;
  matched subtotal equals sum of `lineTotalCents` over matches. (No variant case — the
  cart item has no variant field.)
- `CartViewModelSearchTest` (`kotlinx-coroutines-test`, `TestDispatcher`,
  `Turbine`) — fake `CartRepository` emitting a fixed cart; assert: typing emits a
  filtered `uiState` after debounce; `query` field echoes raw immediately;
  `onClearQuery` restores full list with no debounce delay; cart re-emit (item removed)
  while query active re-filters; query restored from `SavedStateHandle`.

Compose UI (`createComposeRule`):
- `CartSearchUiTest` — search field hidden when cart empty; typing reduces visible rows;
  clear icon appears with non-empty query and restores list on tap; no-results state
  shows "Clear search" button and clears on tap; matched-subtotal header shows "N of M".

Acceptance gate: a test named `searchFiltersCart` proves the source acceptance bullet
("Search filters cart") end-to-end against `CartScreen` with a fixture cart.

Coverage target: 100% of branches in `CartSearch` and `CartViewModel.onQueryChange`/
`onClearQuery`.

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-210 (Cart API + DTOs) must be merged — provides `Cart`,
  `CartItem` (with `sku`, `name`, `lineTotalCents`; CORRECTED — no `productName`/
  `variantLabel`), and `CartRepository.cartFlow`. AND-212 cannot start until those
  fields exist.
- **Integration dependency:** AND-211 (Cart screen) provides `CartScreen`,
  `CartViewModel`, `CartUiState`, `CartItemRow`, and the currency formatter that
  AND-212 extends. Sequence AND-212 **after** AND-211 to avoid a three-way merge on
  `CartViewModel`/`CartUiState`. If developed in parallel, AND-212 owns the additive
  `query`/`filtered` fields and the `CartSearchField` composable; AND-211 owns
  everything else.
- **Blocks:** none.
- No new Gradle/library dependencies (Compose, Coroutines, Hilt, `Normalizer` from the
  JDK are already present).

## 13. Risks & Open Questions

- **R1 — DTO field availability.** RESOLVED by review: `sku` and `name` are both
  `required` in backend `ShoppingCartItemOut` and present on the web `CartItem`, so search
  fields are guaranteed. There is **no** `variant_label`/`variant`/`options` key — the
  earlier open question is answered (no variant field exists). Verified against
  `src/api/types.ts: CartItem` and `openapi.pretty.json: ShoppingCartItemOut`.
- **R2 — Merge contention on `CartViewModel`/`CartUiState`** with AND-211.
  *Mitigation:* additive fields + sequence after AND-211 (§12).
- **Q1 — Match scope:** should search also match other present fields (`category_id`,
  `item_id`, `product_type`)? Current decision: **SKU + name only** (variant does not
  exist; the web app has no cart filter to mirror). `category_id`/`product_type` are
  opaque ids/enums, not user-facing search terms. Revisit if QA carts make this
  insufficient.
- **Q2 — Highlighting:** should matched substrings be visually highlighted in rows?
  Out of scope for AND-212 (would require modifying AND-211's `CartItemRow`); proposed as
  a follow-up if requested.
- **Q3 — Debounce value:** 200 ms is an estimate; tune against device testing. Low risk.

## 14. Acceptance Criteria

AC-1. (Source bullet) Typing a non-empty query in the cart search field filters the
visible cart line items to those whose SKU or product name (`name`) contains the
query, case- and diacritic-insensitively; clearing the query restores all items.
(CORRECTED: no variant-label field exists.)

AC-2. Filtering is debounced ~200 ms; the text field shows typed characters with no
perceptible lag; clearing restores the full list immediately.

AC-3. A clear ("×") icon appears only when the query is non-empty and clears the query
on tap.

AC-4. A "N of M items · subtotal $X.XX" header is shown while filtering, computed over
matched items; the actual cart grand total (AND-211) is unaffected.

AC-5. Zero matches show a distinct "No items match \"<query>\"" state with a working
"Clear search" button — never the empty-cart state and never an error.

AC-6. The search field is hidden when the cart is empty or not yet loaded.

AC-7. The query survives configuration change and process-death restore; removing/qty-
editing an item while a query is active keeps the filter applied and drops items that no
longer match.

AC-8. No new network requests are issued; raw query text is never logged or persisted to
disk.

AC-9. Search field and clear icon have content descriptions; the matched-subtotal header
is a polite live region; all strings are in `strings.xml`.

AC-10. `searchFiltersCart` test and the unit/UI suites in §11 pass in CI.

## 15. Definition of Done

- `CartSearchField`, `CartSearch`, and the `query`/`filtered`/`SavedStateHandle`
  additions to `CartViewModel`/`CartUiState` are implemented under
  `com.testlogon.android.feature.cart` and wired into AND-211's `CartScreen`.
- All AC-1..AC-10 verified.
- Unit, ViewModel, and Compose UI tests from §11 (including `searchFiltersCart`) are
  written and green in CI; branch coverage targets met.
- No new lint/Detekt warnings; no new Gradle dependencies; package names and namespace
  are `com.testlogon.android.*`.
- All user-visible strings localized in `strings.xml`; accessibility (content
  descriptions, live region, 48dp clear target) verified with TalkBack.
- No raw query text in logs or persisted storage; telemetry events emit length/counts
  only.
- Code reviewed and merged to `android-port`; AND-212 ticket closed referencing the PR.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Cart items are fetched from `GET /ui/shoppingcart/carts/{cart_id}/items`** (not
   `GET /cart`). VERDICT: **Corrected** (spec said `GET /cart`, which does not exist).
   SOURCE: OpenAPI `GET /ui/shoppingcart/carts/{cart_id}/items`
   (op `ui_list_items...`, resp `200:ShoppingCartItemsOut`); frontend
   `src/api/endpoints/cart.ts: getCartItems`.

2. **Response shape is `CartItemsResp { cart_id, items: CartItem[] }`.** VERDICT: Verified.
   SOURCE: `src/api/types.ts: CartItemsResp`; OpenAPI schema `ShoppingCartItemsOut`
   (required `cart_id`, `items`).

3. **Per-item matchable fields are `sku` and `name`; the DTO field is `name`, not
   `product_name`.** VERDICT: **Corrected**. SOURCE: `src/api/types.ts: CartItem`
   (`sku`, `name`, `quantity`, `unit_price_cents`, `line_total_cents`, `updated_at`, …);
   OpenAPI schema `ShoppingCartItemOut` (required: `sku, name, quantity,
   unit_price_cents, line_total_cents, updated_at`).

4. **There is no `variant_label` / `variant` / `options` field on a cart item.** VERDICT:
   **Corrected** (spec matched against and required `variantLabel`). SOURCE: `src/api/types.ts:
   CartItem` (no variant key); OpenAPI `ShoppingCartItemOut` properties (no variant key);
   grep for "variant" in `openapi.pretty.json` returns only unrelated image schemas.

5. **There is no item `id`; line identity is `sku`.** VERDICT: **Corrected** (spec used
   `item.id` for the `LazyColumn` key and a `CartItem.id` field). SOURCE: `src/api/types.ts:
   CartItem` (no `id`); `src/api/endpoints/cart.ts: updateCartItemQty`/`removeCartItem`
   address items by `sku` (`/carts/{cartId}/items/${sku}`); OpenAPI
   `PATCH|DELETE /ui/shoppingcart/carts/{cart_id}/items/{sku}` (path param `sku`).
   Note: an optional `item_id` exists but is the catalog item id, not the line identity.

6. **`line_total_cents` and `unit_price_cents` exist (integer cents).** VERDICT: Verified.
   SOURCE: `src/api/types.ts: CartItem`; OpenAPI `ShoppingCartItemOut`.

7. **CSRF: `X-CSRF-Token` request header is set from the `ui_csrf` cookie; transport is
   cookie-auth (`credentials: include`).** VERDICT: Verified. SOURCE: `src/api/client.ts`
   (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`, `credentials: "include"`).

8. **On 401 for an authenticated user the client refreshes once via
   `POST /ui/session/refresh` and retries.** VERDICT: Verified. SOURCE: `src/api/client.ts`
   (`refreshSession()` posts `/ui/session/refresh`; single `refreshPromise`; one retry).

9. **The web app has a comparable in-cart filter input whose match fields should be
   mirrored.** VERDICT: **Corrected / Unverified-assumption** — false. The web cart page
   renders items with no client-side text filter. SOURCE: `src/pages/shop/Cart.tsx`
   (`items = itemsQuery.data?.items ?? []`; the only `.filter` is on cart `status`). This
   feature is net-new for Android.

10. **A server-side cart item search endpoint exists (alternative design).** VERDICT:
    Verified (exists), and Verified-unused by web. SOURCE: OpenAPI
    `GET /ui/shoppingcart/carts/items/search` (params `q` required minLength 1, `limit`
    default 100 max 200, resp untyped `200`/`422:HTTPValidationError`); no reference to it
    in `src/` (grep for `items/search`/`searchCartItems` → no frontend usage).

11. **Validation/error envelope for these endpoints is FastAPI `HTTPValidationError`
    (422) and an error `detail` field for 4xx.** VERDICT: Verified. SOURCE: OpenAPI cart
    endpoints list `422:HTTPValidationError;400;401;403;429`; `src/api/client.ts:
    normalizeErrorDetail` reads `body.detail` (string | array of `{msg}` | `{code,…}`).

12. **Framework choices** — `SavedStateHandle` survives process death; `LazyColumn`
    `key`; Compose `semantics { liveRegion = Polite }`; `kotlinx.coroutines.flow.debounce`
    is `@FlowPreview`; `java.text.Normalizer` NFD folding. VERDICT: Verified
    (framework ref). SOURCE (framework ref):
    https://developer.android.com/topic/libraries/architecture/saved-state ,
    https://developer.android.com/develop/ui/compose/lists#item-keys ,
    https://developer.android.com/develop/ui/compose/accessibility (live region),
    https://developer.android.com/reference/kotlin/kotlinx/coroutines/flow/package-summary#debounce ,
    https://docs.oracle.com/javase/8/docs/api/java/text/Normalizer.html .

13. **No new network call is introduced by this ticket.** VERDICT: Verified (design
    choice; consistent with sources). SOURCE: search operates over the in-memory list from
    citation #1; no endpoint is added.

### Corrections made

- §1, §3 (FR-2), §4 (filter logic + `LazyColumn` key), §5, §6, §11, §13 (R1, Q1), §14
  (AC-1): removed all `variantLabel`/`variant` matching — **no variant field exists**.
- §1, §3, §4, §5, §11, §14: renamed `productName` → `name` (the real DTO/domain field).
- §4, §5, §6: replaced item `id` with `sku` as the line identity and `LazyColumn` key;
  removed the `CartItem.id` field from the sample domain model and added the real
  optional fields (`updatedAt`, `imageUrl`, `categoryId`, `itemId`).
- §5: corrected the cart fetch path from the non-existent `GET /cart` to
  `GET /ui/shoppingcart/carts/{cart_id}/items` (`ShoppingCartItemsOut`); corrected the
  sample JSON to the real `ShoppingCartItemOut` shape; documented the existing-but-unused
  server search endpoint as an explicitly-not-chosen alternative.
- §2, §9-area, §13: corrected the false "mirror the web cart filter" premise (web has no
  cart item filter) and marked this as net-new behavior.

### Open assumptions

- **Network timeout/backoff (~20s, bounded backoff on idempotent GET):** Unverified — not
  expressed in OpenAPI or `src/api/client.ts` (web uses default `fetch` with no explicit
  timeout). This is an AND-210/core-network policy assumption, not an AND-212 contract.
- **AND-210 domain mapping names (`CartItem.name`, `lineTotalCents`, etc.):** Assumption —
  the Kotlin model is owned by AND-210 and not present in these sources; field *origins*
  (DTO `name`, `line_total_cents`) are verified, but the exact Kotlin identifiers are
  AND-210's to finalize. AND-212 must match whatever AND-210 ships.
- **AND-211 currency formatter / `CartItemRow` / empty-state composables:** Assumption —
  owned by AND-211, not in the reference sources; AND-212 reuses them by contract.
- **Analytics abstraction (`Analytics`) availability in `feature-cart`:** Unverified — not
  in sources; §10 already gates telemetry behind a no-op default.

## 17. Test Plan

Test IDs `TC-AND-212-NN`. "Traces" links to §14 acceptance criteria. Test targets:
JVM/Robolectric (local), emulator AVD `test35` (API 35 x86_64), or the physical
**Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a, serial R5CX821TA9R)**.

- **TC-AND-212-01 — Pure filter: happy path (sku + name match).**
  Type: unit (JVM). Target: `CartSearch.filter` (JVM, no device).
  Preconditions: fixture list of cart items with distinct `sku`/`name`.
  Steps: call `filter(items, "shirt")` where one item has `name` "TestLogon Tee shirt"
  and another `sku` "TL-SHIRT-BLK-M"; call `filter(items, "TL-MUG")`.
  Expected: only matching items returned; `matchedCount` correct; `totalCount` = list
  size; `matchedSubtotalCents` = sum of `lineTotalCents` over matches.
  Traces: AC-1, AC-4.

- **TC-AND-212-02 — Pure filter: case + diacritic folding, empty/whitespace query.**
  Type: unit (JVM). Target: `CartSearch.normalize` + `filter`.
  Preconditions: item with `name` "Café Blend"; full fixture list.
  Steps: `filter(items, "CAFE")`, `filter(items, "café")`, `filter(items, "")`,
  `filter(items, "   ")`.
  Expected: "CAFE"/"café" both match "Café Blend"; empty and whitespace-only queries
  return all items with `matchedCount == totalCount` and full subtotal.
  Traces: AC-1.

- **TC-AND-212-03 — Pure filter: zero matches.**
  Type: unit (JVM). Target: `CartSearch.filter`.
  Preconditions: fixture list with no item containing "zzz".
  Steps: `filter(items, "zzz")`.
  Expected: empty `items`, `matchedCount = 0`, `matchedSubtotalCents = 0`,
  `totalCount` = list size; `isFiltering == true`.
  Traces: AC-5.

- **TC-AND-212-04 — ViewModel: debounce + immediate echo.**
  Type: unit (`kotlinx-coroutines-test` + Turbine). Target: `CartViewModel.uiState`,
  `onQueryChange`. Preconditions: fake `CartRepository` emits a fixed cart.
  Steps: collect `uiState`; call `onQueryChange("s")`, advance < 200 ms, then >= 200 ms.
  Expected: `query` field updates immediately on each emission; `filtered` only
  recomputes after the 200 ms debounce settles; final `filtered` matches "s".
  Traces: AC-2.

- **TC-AND-212-05 — ViewModel: clear restores full list with no debounce.**
  Type: unit (coroutines-test + Turbine). Target: `onClearQuery`.
  Preconditions: VM with an active non-empty query already filtering.
  Steps: call `onClearQuery()`; advance virtual time by 0 ms.
  Expected: `query == ""` immediately; `filtered` restored to full list without waiting
  200 ms (empty-string debounce = 0 ms path).
  Traces: AC-2, AC-3.

- **TC-AND-212-06 — ViewModel: re-filter on cart mutation; query survives SavedState.**
  Type: unit (coroutines-test + Turbine). Target: `CartViewModel` + `SavedStateHandle`.
  Preconditions: fake repo with mutable cart flow; query active matching 2 items.
  Steps: (a) emit a new cart with one matching item removed; (b) construct a new VM with
  `SavedStateHandle` pre-seeded `cart_query = "shirt"`.
  Expected: (a) filtered list drops the removed item, filter stays applied; (b) new VM
  starts with `query == "shirt"` and the corresponding filtered view.
  Traces: AC-7.

- **TC-AND-212-07 — No network call is issued by search.**
  Type: contract/MockWebServer. Target: `CartViewModel` + repo over MockWebServer.
  Preconditions: MockWebServer enqueues exactly one `GET .../carts/{id}/items` response;
  cart loaded once. Steps: type several queries and clear; inspect recorded requests.
  Expected: zero additional HTTP requests after the initial cart load (no
  `/carts/items/search`, no `/cart`); `RecordedRequest` count stays at the load count.
  Traces: AC-8.

- **TC-AND-212-08 — Cart fetch contract parity (path/method/CSRF/shape).**
  Type: contract/MockWebServer. Target: AND-210 `CartRepository` cart-items call as
  consumed here. Preconditions: MockWebServer returns a valid `ShoppingCartItemsOut`
  JSON body (`cart_id`, `items[]` with `sku`,`name`,`line_total_cents`,…).
  Steps: trigger the load; assert the request line + headers; map and filter.
  Expected: request is `GET /ui/shoppingcart/carts/{cart_id}/items`; `X-CSRF-Token`
  header present (from `ui_csrf`); body deserializes with `name` (not `product_name`),
  no `variant`/`id` fields required; filter then works over the mapped items.
  Traces: AC-1, AC-8.

- **TC-AND-212-09 — 422 validation / error envelope handled by underlying load (search
  unaffected).** Type: contract/MockWebServer. Target: load path + `CartScreen` gating.
  Preconditions: MockWebServer returns `422 HTTPValidationError` (`detail: [{msg,…}]`)
  for the items load. Steps: load cart; observe UI state.
  Expected: AND-211 error state is shown; the search field is hidden (no items to
  filter); no crash; search introduces no new error state. Traces: AC-6.

- **TC-AND-212-10 — Compose UI: type filters rows; clear restores; field hidden when
  empty.** Type: Compose-UI (`createComposeRule`, can run on emulator `test35`).
  Target: `CartScreen` + `CartSearchField`. Preconditions: fixture cart with N rows;
  separate empty-cart fixture. Steps: type a query matching a subset; tap the clear
  ("×") icon; render the empty-cart fixture.
  Expected: visible rows reduce to matches; clear icon appears only with non-empty
  query and restores all rows on tap; search field is absent in the empty-cart state.
  Traces: AC-1, AC-3, AC-6.

- **TC-AND-212-11 — Compose UI: zero-results and matched-subtotal header.**
  Type: Compose-UI. Target: `CartScreen`. Preconditions: fixture cart.
  Steps: type a query with no matches; then a query matching some items.
  Expected: zero-match shows `No items match "<query>"` + working "Clear search" button
  (distinct from empty-cart and from error); filtering query shows
  `N of M items · subtotal $X.XX` with correct N/M and currency-formatted subtotal;
  grand total area unchanged. Traces: AC-4, AC-5.

- **TC-AND-212-12 — Acceptance gate `searchFiltersCart`.**
  Type: Compose-UI / instrumented. Target: `CartScreen` end-to-end with a fixture cart.
  Preconditions: loaded fixture cart. Steps: enter a query; assert filtered rows; clear;
  assert full list. Expected: proves the source bullet "Search filters cart".
  Traces: AC-1, AC-10.

- **TC-AND-212-13 — Process-death restore (real lifecycle).**
  Type: instrumented/e2e — **MUST run on the physical device** (SM-A156U, API 34) to
  exercise real Activity recreation under memory pressure / "Don't keep activities".
  Target: `CartScreen` + `CartViewModel` `SavedStateHandle`. Preconditions: cart loaded,
  active query typed. Steps: background the app, trigger process death (adb
  `am kill` / Developer-options "Don't keep activities"), relaunch.
  Expected: the query string and filtered view are restored; no crash. Note: also smoke
  on emulator `test35` to catch API-35 vs API-34 differences. Traces: AC-7.

- **TC-AND-212-14 — Accessibility (TalkBack live region + content descriptions).**
  Type: instrumented/e2e — **PREFER the physical device** (SM-A156U) with TalkBack
  enabled for real screen-reader announcement behavior; baseline semantics assertions
  can run on emulator `test35`. Target: `CartSearchField`, matched-subtotal header.
  Preconditions: TalkBack on; fixture cart. Steps: focus the search field; type to change
  the match count; focus the clear icon.
  Expected: field exposes label "Search cart items"; clear icon exposes "Clear search";
  the matched-subtotal header is a `liveRegion = Polite` and TalkBack announces the
  updated "N of M items"; clear icon touch target >= 48dp. Traces: AC-9.

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 | TC-01, TC-02, TC-08, TC-10, TC-12 |
| AC-2 | TC-04, TC-05 |
| AC-3 | TC-05, TC-10 |
| AC-4 | TC-01, TC-11 |
| AC-5 | TC-03, TC-11 |
| AC-6 | TC-09, TC-10 |
| AC-7 | TC-06, TC-13 |
| AC-8 | TC-07, TC-08 |
| AC-9 | TC-14 |
| AC-10 | TC-12 (plus all unit/UI suites green in CI) |
