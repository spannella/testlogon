---
id: AND-212
title: Cart search/items
milestone: M5
epic: E29
priority: P2
size: S
status: draft
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
line items to those whose SKU, product name, or variant label contains the query
(case-insensitive, diacritic-folded substring match), and clearing the query restores
the full cart.

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
- **Web reference:** `frontend/src/api/endpoints/cart.ts` (DTO shape source of truth)
  and `frontend/src/api/types.ts` (`CartItem`, `Cart`). The web app has a comparable
  cart filter input; mirror its match fields (sku, name, variant) and case-folding.
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
strip combining marks) **substring** match against, in priority order: `sku`,
`productName`, `variantLabel` (any non-null field that contains the normalized query
qualifies the item).

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
        val matches = items.filter { item ->
            normalize(item.sku).contains(q) ||
                normalize(item.productName).contains(q) ||
                item.variantLabel?.let { normalize(it).contains(q) } == true
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
filtered `LazyColumn` (keyed by `item.id`) or the no-results state. AND-211's row
composable (`CartItemRow`) is reused unchanged; AND-212 only changes the *list source*
from `state.cart.items` to `state.filtered.items`.

## 5. API Contract

No new network calls. AND-212 is pure client-side filtering over the cart snapshot that
AND-210 already fetches via `GET /cart` (cookie-authenticated, `X-CSRF-Token` echoed
from the `ui_csrf` cookie, ~20s timeout, bounded backoff on idempotent GET, refresh-once
on 401). The fields consumed by search are defined by AND-210; for reference the relevant
slice of the `CartItemDto`/`CartItem` shape this ticket depends on:

```json
{
  "id": "ci_8f2",
  "sku": "TL-SHIRT-BLK-M",
  "product_name": "TestLogon Tee",
  "variant_label": "Black / M",
  "quantity": 2,
  "unit_price_cents": 1999,
  "line_total_cents": 3998
}
```

mapped by AND-210 to:

```kotlin
data class CartItem(
    val id: String,
    val sku: String,
    val productName: String,
    val variantLabel: String?,
    val quantity: Int,
    val unitPriceCents: Long,
    val lineTotalCents: Long,
)
```

**Contract requirement on AND-210:** `sku`, `productName`, and `variantLabel` must be
present (non-null `sku`/`productName`; `variantLabel` nullable) on `CartItem`. If
AND-210 omits any, this ticket is blocked until they are added — see §13.

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
- **List identity:** `LazyColumn` items use `key = { it.id }` so filtering animates as
  removal/insertion and scroll/row state is preserved for surviving rows.
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
- Defensive: `variantLabel == null` and empty `sku`/`productName` are handled by the
  null-safe match in `CartSearch.filter`; a query of only whitespace normalizes to empty
  and is treated as "no filter".

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
  subtotal; SKU substring match; product-name match; variant match; case-insensitive
  match; diacritic-folded match ("cafe" matches "Café"); whitespace-only query = all;
  zero-match returns empty list, `matchedCount = 0`, `subtotal = 0`; `variantLabel = null`
  does not NPE; matched subtotal equals sum of `lineTotalCents` over matches.
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
  `CartItem` (with `sku`, `productName`, `variantLabel`, `lineTotalCents`), and
  `CartRepository.cartFlow`. AND-212 cannot start until those fields exist.
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

- **R1 — DTO field availability.** If AND-210's `CartItem` lacks `sku` or
  `variantLabel`, search degrades or blocks. *Mitigation:* §5 states the contract; verify
  against `frontend/src/api/types.ts` during AND-210 review. **Open:** confirm
  `variant_label` is the correct backend key (vs. `variant`/`options`).
- **R2 — Merge contention on `CartViewModel`/`CartUiState`** with AND-211.
  *Mitigation:* additive fields + sequence after AND-211 (§12).
- **Q1 — Match scope:** should search also match free-text product description or
  category if present on `CartItem`? Current decision: SKU + name + variant only (mirrors
  web reference). Revisit if QA carts make this insufficient.
- **Q2 — Highlighting:** should matched substrings be visually highlighted in rows?
  Out of scope for AND-212 (would require modifying AND-211's `CartItemRow`); proposed as
  a follow-up if requested.
- **Q3 — Debounce value:** 200 ms is an estimate; tune against device testing. Low risk.

## 14. Acceptance Criteria

AC-1. (Source bullet) Typing a non-empty query in the cart search field filters the
visible cart line items to those whose SKU, product name, or variant label contains the
query, case- and diacritic-insensitively; clearing the query restores all items.

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
