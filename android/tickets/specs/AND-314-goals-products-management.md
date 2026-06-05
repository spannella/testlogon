---
id: AND-314
title: Goals & products management
milestone: M7
epic: E41
priority: P2
size: L
status: draft
depends_on: [AND-282, AND-283]
blocks: []
---

# AND-314 — Goals & products management

## 1. Overview & Goal

This ticket delivers the **host-side management** surface for a live broadcast: the
ability to create and delete tip **goals**, and to add, reorder, remove, and price
**products** on the broadcast shelf for the session the user is currently hosting.
It is the authoring counterpart to the read-only viewer features built earlier:
AND-282 (Tips & goals — goal progress display) and AND-283 (Products shelf —
viewer-facing shelf + buy routing). Where those tickets render goals/products to
the audience, AND-314 lets the broadcaster mutate them in real time.

Concretely, the broadcaster opens a "Manage" panel from the live broadcast hosting
screen (owned by the broadcast-hosting feature in E41) and can:

- Create a tip goal (`label`, `target_cents`, optional `sort_order`) and delete an
  existing goal.
- Add a catalog product to the shelf (`item_id`, `category_id`, optional
  `display_order`), remove a shelf item, drag-reorder the shelf, and set or clear a
  broadcast-exclusive price (with optional expiry) on an item.

Success means full goals CRUD (create + list + delete) and full products
management (add + list + remove + reorder + set/clear price) are live against the
FastAPI backend, with optimistic UI for reorder, robust handling of the
plaintext/unreliable dev backend, and deterministic tests at the repository,
ViewModel, and Compose layers. The acceptance phrase from the backlog —
"Goals/products CRUD live" — is satisfied when every endpoint in §5 is wired and
its effect is visible in the management UI.

This is a host-only authoring feature. It does **not** own the live WebRTC
broadcast pipeline, the viewer shelf rendering, the checkout/buy flow, or the
catalog browsing screen — those belong to sibling/upstream tickets named in §12.

## 2. Context & References

- Repo `spannella/testlogon`; Android app under `android/` (monorepo subfolder),
  branch `android-port`.
- Namespace / applicationId base: `com.testlogon.android` (exact).
- Stack: Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity
  Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 +
  Moshi 1.15, Room 2.6, DataStore, Coil. minSdk 24, compile/targetSdk 35, JDK 17,
  Gradle 8.9, AGP 8.7.3.
- Module layering: `app → feature-broadcast-host → core-*`
  (`core-network`, `core-model`, `core-data`, `core-ui`, `core-testing`). New code
  for this ticket lives in package `com.testlogon.android.feature.broadcasthost.manage`.
- **AND-282** owns the goal **display** model and tip submission; this ticket reuses
  its `TipGoal` domain model where shapes match and extends it only with the
  host-authoring fields (`reached_at`, `created_at`, `sort_order`).
- **AND-283** owns the viewer products shelf and the buy → checkout route; this
  ticket reuses its `ShelfItem` domain model and must keep field names consistent so
  a single Moshi DTO and mapper serve both.
- ViewModels expose `StateFlow<UiState>`; networking returns typed `ApiResult<T>`;
  FastAPI `detail` errors map per the shared `ApiError` model (string |
  `[{msg}]` | `{code,...}`).
- Backend: FastAPI + DynamoDB. Dev backend `http://18.222.237.167:8000` is
  **plaintext HTTP** and an **unreliable dev host**: ~20s timeouts, bounded backoff
  for idempotent GETs only, offline/stale UI states. OpenAPI at `/openapi.json`.
- Auth is cookie-based: requests carry session cookies + the `ui_csrf` cookie echoed
  as `X-CSRF-Token`; on 401 the client does `POST /ui/session/refresh` once then
  retries. All mutating calls in this ticket (POST/PATCH/DELETE) require the CSRF
  header and are **not** eligible for GET backoff retry.
- Web reference: `frontend/src/api/endpoints/*.ts` and `frontend/src/api/types.ts`.
  Field shapes below are verified against `/openapi.json`
  (`BroadcastTipGoal*`, `BroadcastShelf*`, `BroadcastPrice*` schemas).

## 3. Functional Requirements

The feature operates on a known `session_id` (the broadcast the user is hosting,
provided by the E41 hosting screen via nav arg). The management surface has two
tabs: **Goals** and **Products**.

**Goals**
- FR-G1: Load and display all goals for the session via `GET .../goals`, sorted by
  `sort_order` then `created_at`. Each row shows `label`, progress
  `current_cents / target_cents`, a "reached" badge when `reached == true`.
- FR-G2: Create a goal from a form: `label` (1–200 chars, required),
  `target_cents` (integer, 100–10_000_000, required), `sort_order` (0–4, default 0).
  On success the new goal appears in the list without a full reload.
- FR-G3: Delete a goal via `DELETE .../goals/{goal_id}` with a confirm dialog. Row
  is removed on success.
- FR-G4: Client-side validation mirrors the server bounds (§5) and blocks submit,
  surfacing inline field errors before any network call.

**Products**
- FR-P1: Load and display the shelf via `GET .../products`, ordered by
  `display_order`. Each row shows `name`, `image_url` (Coil), catalog price
  `price_cents`, and — when a broadcast price is active — `effective_price_cents`,
  `discount_pct`, and an expiry countdown derived from `broadcast_price_expires_at`.
- FR-P2: Add a product via `POST .../products` with `item_id`, `category_id`
  (each 1–128 chars), optional `display_order` (0–999). The item id/category id are
  supplied by the catalog picker (AND-283/catalog ticket); this ticket accepts them
  as inputs and does not implement catalog browsing.
- FR-P3: Remove a shelf item via `DELETE .../products/{item_id}` (confirm dialog).
- FR-P4: Reorder the shelf by drag-and-drop. On drop, send the full ordered list of
  `item_id`s via `PATCH .../products/reorder` (1–50 items). UI updates optimistically
  and rolls back on failure.
- FR-P5: Set a broadcast price via `PATCH .../products/{item_id}/price` with
  `broadcast_price_cents` (> 0, must be **strictly less than** catalog price —
  enforced client-side as a pre-check and authoritatively by the server) and optional
  `expires_in_seconds` (60–86400).
- FR-P6: Clear a broadcast price via `DELETE .../products/{item_id}/price`; the row
  reverts to catalog price.
- FR-P7: All list reads support pull-to-refresh and show loading/empty/error/offline
  states from `core-ui` (AND-021).

**Cross-cutting**
- FR-X1: Concurrent mutations are serialized per entity; the UI disables the
  triggering control while its request is in flight.
- FR-X2: After any successful mutation, local state is reconciled from the response
  body (server is source of truth for computed fields like `discount_pct`,
  `effective_price_cents`, `reached`).

## 4. Technical Design

New feature module `feature-broadcast-host` (or sub-package if the module already
exists from E41). Package root: `com.testlogon.android.feature.broadcasthost.manage`.

**DTOs** (`core-network`, Moshi `@JsonClass(generateAdapter = true)`):

```kotlin
@JsonClass(generateAdapter = true)
data class TipGoalDto(
    @Json(name = "goal_id") val goalId: String,
    @Json(name = "session_id") val sessionId: String,
    val label: String,
    @Json(name = "target_cents") val targetCents: Long,
    @Json(name = "current_cents") val currentCents: Long = 0,
    val reached: Boolean = false,
    @Json(name = "reached_at") val reachedAt: Long? = null,
    @Json(name = "sort_order") val sortOrder: Int = 0,
    @Json(name = "created_at") val createdAt: Long,
)

@JsonClass(generateAdapter = true)
data class TipGoalCreateDto(
    val label: String,
    @Json(name = "target_cents") val targetCents: Long,
    @Json(name = "sort_order") val sortOrder: Int = 0,
)

@JsonClass(generateAdapter = true)
data class TipGoalsListDto(
    @Json(name = "session_id") val sessionId: String,
    val goals: List<TipGoalDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class ShelfItemDto(
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "item_id") val itemId: String,
    @Json(name = "category_id") val categoryId: String,
    val name: String,
    val description: String? = null,
    @Json(name = "price_cents") val priceCents: Long,
    val currency: String = "USD",
    @Json(name = "image_url") val imageUrl: String? = null,
    @Json(name = "display_order") val displayOrder: Int = 0,
    @Json(name = "added_by") val addedBy: String,
    @Json(name = "added_at") val addedAt: Long,
    @Json(name = "broadcast_price_cents") val broadcastPriceCents: Long? = null,
    @Json(name = "broadcast_price_expires_at") val broadcastPriceExpiresAt: Long? = null,
    @Json(name = "effective_price_cents") val effectivePriceCents: Long? = null,
    @Json(name = "is_broadcast_price") val isBroadcastPrice: Boolean = false,
    @Json(name = "discount_pct") val discountPct: Int = 0,
    @Json(name = "original_price_cents") val originalPriceCents: Long? = null,
)

@JsonClass(generateAdapter = true)
data class ShelfListDto(
    @Json(name = "session_id") val sessionId: String,
    val items: List<ShelfItemDto> = emptyList(),
    val count: Int = 0,
)

@JsonClass(generateAdapter = true)
data class ShelfAddDto(
    @Json(name = "item_id") val itemId: String,
    @Json(name = "category_id") val categoryId: String,
    @Json(name = "display_order") val displayOrder: Int = 0,
)

@JsonClass(generateAdapter = true)
data class ShelfReorderDto(@Json(name = "item_order") val itemOrder: List<String>)

@JsonClass(generateAdapter = true)
data class PriceSetDto(
    @Json(name = "broadcast_price_cents") val broadcastPriceCents: Long,
    @Json(name = "expires_in_seconds") val expiresInSeconds: Long? = null,
)

@JsonClass(generateAdapter = true)
data class PriceOutDto(
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "item_id") val itemId: String,
    @Json(name = "original_price_cents") val originalPriceCents: Long,
    @Json(name = "broadcast_price_cents") val broadcastPriceCents: Long,
    @Json(name = "broadcast_price_expires_at") val broadcastPriceExpiresAt: Long? = null,
    @Json(name = "discount_pct") val discountPct: Int,
    @Json(name = "set_by") val setBy: String,
    @Json(name = "set_at") val setAt: Long,
)
```

**Retrofit API** (`core-network`):

```kotlin
interface BroadcastManageApi {
    @GET("broadcast/sessions/{sessionId}/goals")
    suspend fun listGoals(@Path("sessionId") sessionId: String): Response<TipGoalsListDto>

    @POST("broadcast/sessions/{sessionId}/goals")
    suspend fun createGoal(
        @Path("sessionId") sessionId: String,
        @Body body: TipGoalCreateDto,
    ): Response<TipGoalDto>

    @DELETE("broadcast/sessions/{sessionId}/goals/{goalId}")
    suspend fun deleteGoal(
        @Path("sessionId") sessionId: String,
        @Path("goalId") goalId: String,
    ): Response<Unit>

    @GET("broadcast/sessions/{sessionId}/products")
    suspend fun listProducts(@Path("sessionId") sessionId: String): Response<ShelfListDto>

    @POST("broadcast/sessions/{sessionId}/products")
    suspend fun addProduct(
        @Path("sessionId") sessionId: String,
        @Body body: ShelfAddDto,
    ): Response<ShelfItemDto>

    @DELETE("broadcast/sessions/{sessionId}/products/{itemId}")
    suspend fun removeProduct(
        @Path("sessionId") sessionId: String,
        @Path("itemId") itemId: String,
    ): Response<Unit>

    @PATCH("broadcast/sessions/{sessionId}/products/reorder")
    suspend fun reorder(
        @Path("sessionId") sessionId: String,
        @Body body: ShelfReorderDto,
    ): Response<ShelfListDto>

    @PATCH("broadcast/sessions/{sessionId}/products/{itemId}/price")
    suspend fun setPrice(
        @Path("sessionId") sessionId: String,
        @Path("itemId") itemId: String,
        @Body body: PriceSetDto,
    ): Response<PriceOutDto>

    @DELETE("broadcast/sessions/{sessionId}/products/{itemId}/price")
    suspend fun clearPrice(
        @Path("sessionId") sessionId: String,
        @Path("itemId") itemId: String,
    ): Response<Unit>
}
```

**Repository** (`core-data`), wrapping calls in `ApiResult<T>` via the shared
`safeApiCall`/`ApiResult.of {}` helper (AND-018) and mapping DTO → domain:

```kotlin
class BroadcastManageRepository @Inject constructor(
    private val api: BroadcastManageApi,
    private val errorMapper: ApiErrorMapper,
) {
    suspend fun goals(sessionId: String): ApiResult<List<TipGoal>>
    suspend fun createGoal(sessionId: String, req: TipGoalCreateDto): ApiResult<TipGoal>
    suspend fun deleteGoal(sessionId: String, goalId: String): ApiResult<Unit>

    suspend fun products(sessionId: String): ApiResult<List<ShelfItem>>
    suspend fun addProduct(sessionId: String, req: ShelfAddDto): ApiResult<ShelfItem>
    suspend fun removeProduct(sessionId: String, itemId: String): ApiResult<Unit>
    suspend fun reorder(sessionId: String, order: List<String>): ApiResult<List<ShelfItem>>
    suspend fun setPrice(sessionId: String, itemId: String, req: PriceSetDto): ApiResult<ShelfItem>
    suspend fun clearPrice(sessionId: String, itemId: String): ApiResult<Unit>
}
```

**ViewModel + state** (`feature-broadcast-host`):

```kotlin
@HiltViewModel
class GoalsProductsViewModel @Inject constructor(
    private val repo: BroadcastManageRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {
    private val sessionId: String = checkNotNull(savedStateHandle["sessionId"])
    val state: StateFlow<ManageUiState>

    fun refreshGoals()
    fun refreshProducts()
    fun submitGoal(form: GoalForm)
    fun deleteGoal(goalId: String)
    fun addProduct(itemId: String, categoryId: String, displayOrder: Int = 0)
    fun removeProduct(itemId: String)
    fun onReorder(newOrder: List<String>)        // optimistic + commit
    fun setBroadcastPrice(itemId: String, cents: Long, expiresInSeconds: Long?)
    fun clearBroadcastPrice(itemId: String)
    fun dismissError()
}

data class ManageUiState(
    val goals: SectionState<List<TipGoal>> = SectionState.Loading,
    val products: SectionState<List<ShelfItem>> = SectionState.Loading,
    val pendingItemIds: Set<String> = emptySet(),   // in-flight per-item locks
    val goalSubmitting: Boolean = false,
    val transientError: String? = null,
)
```

`SectionState` is the existing sealed `Loading/Empty/Error/Offline/Data` wrapper
from `core-ui` (AND-021). The two sections refresh independently so a goals failure
does not blank the products list.

**Compose UI**: `GoalsProductsScreen(viewModel)` with a Material 3 `TabRow`
(Goals | Products), `PullToRefreshBox`, a `GoalCard`, a `ProductRow` with a
reorderable `LazyColumn` (drag handle), and bottom-sheet forms `GoalEditorSheet`
and `PriceEditorSheet`. Reorder uses a `rememberReorderableLazyListState`-style
helper; on settle it emits the full `item_id` order to `onReorder`.

**DI**: a Hilt module provides `BroadcastManageApi` from the shared authenticated
Retrofit instance (cookie jar + CSRF interceptor + 401 authenticator already
installed in `core-network` from E04 tickets).

## 5. API Contract

Base URL from build flavor (`BuildConfig.BASE_URL`, default dev
`http://18.222.237.167:8000`). All paths are relative to it. All requests send
session cookies + `X-CSRF-Token` (mutations require it).

**Goals**

- `GET /broadcast/sessions/{session_id}/goals` → 200 `BroadcastTipGoalsListOut`:
  ```json
  { "session_id": "sess_123",
    "goals": [ { "goal_id": "g1", "session_id": "sess_123", "label": "New mic",
      "target_cents": 50000, "current_cents": 12000, "reached": false,
      "reached_at": null, "sort_order": 0, "created_at": 1733000000 } ] }
  ```
- `POST /broadcast/sessions/{session_id}/goals` body `BroadcastTipGoalCreateIn`:
  ```json
  { "label": "New mic", "target_cents": 50000, "sort_order": 0 }
  ```
  Constraints: `label` 1–200; `target_cents` 100–10_000_000; `sort_order` 0–4
  (default 0). → 201 `BroadcastTipGoalOut` (single goal, shape as above).
- `DELETE /broadcast/sessions/{session_id}/goals/{goal_id}` → 200/204 (empty body).

**Products**

- `GET /broadcast/sessions/{session_id}/products` → 200 `BroadcastShelfListOut`:
  ```json
  { "session_id": "sess_123", "count": 1, "items": [ {
      "session_id": "sess_123", "item_id": "p1", "category_id": "cat1",
      "name": "Tee", "description": null, "price_cents": 2500, "currency": "USD",
      "image_url": "https://...", "display_order": 0, "added_by": "u1",
      "added_at": 1733000000, "broadcast_price_cents": 1999,
      "broadcast_price_expires_at": 1733003600, "effective_price_cents": 1999,
      "is_broadcast_price": true, "discount_pct": 20, "original_price_cents": 2500
  } ] }
  ```
- `POST /broadcast/sessions/{session_id}/products` body `BroadcastShelfAddIn`:
  ```json
  { "item_id": "p1", "category_id": "cat1", "display_order": 0 }
  ```
  Constraints: `item_id`/`category_id` 1–128; `display_order` 0–999.
  → 201 `BroadcastShelfItemOut`.
- `DELETE /broadcast/sessions/{session_id}/products/{item_id}` → 200/204.
- `PATCH /broadcast/sessions/{session_id}/products/reorder` body
  `BroadcastShelfReorderIn`: `{ "item_order": ["p2","p1","p3"] }` (1–50 ids).
  → 200 `BroadcastShelfListOut` (re-ordered).
- `PATCH /broadcast/sessions/{session_id}/products/{item_id}/price` body
  `BroadcastPriceSetIn`:
  ```json
  { "broadcast_price_cents": 1999, "expires_in_seconds": 3600 }
  ```
  Constraints: `broadcast_price_cents` > 0 and **strictly less than catalog price**
  (server-enforced against DDB); `expires_in_seconds` 60–86400 or null.
  → 200 `BroadcastPriceOut`. After success, re-fetch the item (or apply
  `PriceOutDto` fields) so computed pricing reflects on the row.
- `DELETE /broadcast/sessions/{session_id}/products/{item_id}/price` → 200 (empty).

**Errors**: 422 → `HTTPValidationError` `{ "detail": [{"loc":[...],"msg":"...","type":"..."}] }`;
other 4xx may return `{ "detail": "string" }` or `{ "detail": {"code":"..."} }`.
All map through the shared `ApiErrorMapper` (AND-015).

## 6. Data & State Management

- **No Room persistence** for this host-authoring data. Goals/products management is
  live and host-only; the server is authoritative and lists are short. Reads populate
  `StateFlow` only; on process death the screen reloads from the network. (If E41
  later requires offline draft authoring it will be a follow-up; flagged in §13.)
- **Domain models** `TipGoal` and `ShelfItem` live in `core-model`, shared with
  AND-282/AND-283. Mappers (`TipGoalDto.toDomain()`, `ShelfItemDto.toDomain()`)
  live in `core-data`. Monetary values are `Long` cents; formatting to currency
  strings happens in the UI layer using `currency` from the DTO (default `USD`).
- **Sorting**: goals by `(sortOrder, createdAt)`; products by `(displayOrder)`.
- **Optimistic reorder**: `onReorder` immediately writes the reordered list into
  `state.products`, calls `PATCH .../reorder`; on success it replaces state with the
  server response; on failure it restores the pre-drag snapshot and emits
  `transientError`.
- **Per-item in-flight locks**: `pendingItemIds` tracks items with an active
  mutation; the corresponding row controls (delete, price, drag) are disabled and
  show a small progress indicator.
- **Price expiry**: a derived UI ticker recomputes the countdown from
  `broadcastPriceExpiresAt`; when it lapses the row falls back to catalog price on the
  next refresh (the client does not locally mutate price state on expiry, it only
  greys the badge and prompts refresh).
- **Session id** flows in as a Navigation-Compose typed arg from the E41 hosting
  screen and is read via `SavedStateHandle`.

## 7. Error Handling & Resilience

- **Timeouts**: rely on the shared OkHttp ~20s timeouts (AND-009). On timeout the
  affected section shows an error state with Retry.
- **Idempotent GET retry**: list goals/products are GETs and use the shared bounded
  backoff retry (AND-016). All POST/PATCH/DELETE here are mutations and are **never**
  auto-retried; the user retries explicitly.
- **401**: handled transparently by the shared authenticator
  (`POST /ui/session/refresh` once, then retry). A second 401 surfaces a
  re-authentication prompt routed to the auth graph.
- **422 validation**: map `detail[].loc`/`msg` to the offending field (e.g.
  `target_cents` below min, `label` too long, broadcast price not below catalog) and
  show inline form errors rather than a generic toast.
- **Price rule violation** (broadcast price ≥ catalog): pre-validated client-side; if
  the server still rejects it, show the field error returned in `detail`.
- **Offline**: if the connectivity probe (AND-017) reports the backend unreachable,
  sections render the Offline state and submit buttons are disabled with an
  explanatory message; queued mutations are **not** stored, the user re-submits when
  back online.
- **Optimistic rollback**: reorder and any optimistic edits restore the prior
  snapshot on failure and report the error.
- **Confirm-before-destroy**: delete goal / remove product / clear price each require
  a confirm dialog to avoid accidental loss on a live broadcast.

## 8. Security & Privacy

- All requests are authenticated via the cookie-based session; mutations attach
  `X-CSRF-Token` (echoed from `ui_csrf`). The persistent cookie jar (AND-011) and
  CSRF interceptor (AND-012) are reused unchanged.
- **Plaintext HTTP**: the dev backend is HTTP; this is dev-only. The networking layer
  retains its dev-only cleartext allowance scoped to the dev flavor; the release
  config must not permit cleartext to arbitrary hosts. No credentials or session
  tokens are logged.
- **Authorization** is server-enforced: only the broadcast host/authorized roles may
  mutate goals/products for a session; the client surfaces 403 as a clear "not
  permitted" message and hides management controls when the session is not owned by
  the current user (`added_by`/host check available from session context).
- **No new PII**: goals (labels) and products (catalog references) contain no
  additional personal data; `added_by`/`set_by` are server-supplied opaque user ids
  shown only in host-side audit text.
- Price values are monetary; never cache them to disk in this ticket. Image URLs are
  loaded via Coil over the configured base host only.

## 9. Accessibility & i18n

- All controls have `contentDescription`/semantics: drag handle ("Reorder {name}"),
  delete ("Delete goal {label}"), price edit ("Set broadcast price for {name}").
- Drag-to-reorder is not the only path: provide "Move up"/"Move down" actions in each
  product row's overflow menu so reordering is operable without drag gestures (meets
  TalkBack/switch-access needs). These call the same `onReorder`.
- Touch targets ≥ 48dp; Material 3 dynamic color + dark theme via the app theme
  (AND-019). Form fields support large font scaling without truncation.
- All strings (labels, errors, confirm dialogs, "reached", "% off", expiry
  countdown) live in `strings.xml` with no concatenation; counts/plurals use
  `plurals`. Currency formatting uses `NumberFormat.getCurrencyInstance` keyed off the
  item `currency` and the device locale. Countdown uses locale-aware duration
  formatting.
- Color is never the sole signal: the "reached" and "on sale" states pair color with
  an icon and text.

## 10. Telemetry & Logging

- Structured analytics events via the app's telemetry interface (no PII, no monetary
  raw values beyond bucketed flags):
  `broadcast_goal_create` (`{has_sort_order}`), `broadcast_goal_delete`,
  `broadcast_product_add`, `broadcast_product_remove`,
  `broadcast_shelf_reorder` (`{count}`),
  `broadcast_price_set` (`{has_expiry, discount_pct_bucket}`),
  `broadcast_price_clear`. Each carries `session_id` and an `outcome`
  (`success|validation_error|network_error|forbidden`).
- OkHttp logging interceptor runs at `BODY` level in dev and `NONE`/headers-only in
  release; the CSRF token and cookies are redacted by the existing redaction rules.
- ViewModel logs (Timber) at `d` for state transitions and `w` for handled errors;
  no `e` spam on expected validation failures.
- Latency timing around each mutation is recorded to surface dev-host slowness; this
  is local logging only, not shipped telemetry.

## 11. Testing Strategy

- **Repository (unit, MockWebServer via `core-testing` harness AND-046)**: one test
  per endpoint asserting method + path + body JSON + parsed result, plus:
  - 201 create goal returns mapped `TipGoal`.
  - 422 create goal (label too long / target below min) → `ApiResult.Failure` with
    field-mapped `ApiError`.
  - reorder PATCH sends exact `{"item_order":[...]}` and returns re-ordered list.
  - set price sends `broadcast_price_cents` + `expires_in_seconds`; clear price
    issues DELETE with no body.
  - 401 → refresh-then-retry succeeds (authenticator integration).
- **ViewModel (unit, Turbine + fake repo)**:
  - optimistic reorder updates state immediately, commits on success, **rolls back**
    on failure and sets `transientError`.
  - `pendingItemIds` is set during a mutation and cleared after.
  - independent section failure: goals error does not clear products.
  - client validation blocks submit for out-of-range `target_cents` and for a
    broadcast price ≥ catalog price (no network call made).
- **Compose UI tests**: tabs switch; create-goal sheet validates and shows new row;
  delete shows confirm dialog and removes row; product row shows discount badge when
  `is_broadcast_price`; "Move up/down" overflow actions reorder; loading/empty/error
  /offline states render.
- **Accessibility test**: semantics assertions for drag handle alternative actions
  and content descriptions.
- Coverage target: repository + ViewModel ≥ 85% line coverage for this package.

## 12. Dependencies & Sequencing

- **Depends on AND-282** (Tips & goals): provides the goal display model and tip
  context; this ticket extends it with authoring. Must land first to avoid duplicate
  `TipGoal` models.
- **Depends on AND-283** (Products shelf): provides `ShelfItem`/shelf rendering and
  buy→checkout routing; this ticket reuses that model and adds host management.
- **Transitively relies on** core-network/auth tickets (AND-009 timeouts, AND-011
  cookie jar, AND-012 CSRF, AND-013 401 refresh, AND-015 error mapping, AND-016 GET
  backoff, AND-018 `ApiResult`), core-ui state composables (AND-021), Material 3 theme
  (AND-019), and the MockWebServer harness (AND-046).
- **Hosted within** the E41 broadcast-hosting screen, which supplies the `session_id`
  nav arg and the entry point to this management panel. If the hosting screen ticket
  is not yet merged, integrate behind a temporary debug entry point keyed by a
  hard-coded/dev `session_id`.
- **Blocks**: none recorded in the backlog.
- The catalog picker that yields `item_id`/`category_id` for "add product" is owned by
  AND-283 / the catalog feature; if unavailable, this ticket ships with a manual
  id-entry fallback dialog behind the dev flavor.

## 13. Risks & Open Questions

- **R1 — Goal update path**: OpenAPI exposes only POST/GET/DELETE for goals (no PATCH
  to edit a goal's label/target). "CRUD" in the backlog is therefore create + read +
  delete; editing is delete-and-recreate. Confirm with backend whether an update
  endpoint is planned; if so, add it as a follow-up. (Spec assumes no edit endpoint.)
- **R2 — Reorder concurrency**: if two host devices reorder simultaneously, last write
  wins; the optimistic UI may briefly diverge. Mitigated by reconciling from the PATCH
  response. Acceptable for v1.
- **R3 — Price expiry source of truth**: the client only displays expiry; it does not
  proactively clear an expired price. Confirm the server returns the item with
  `is_broadcast_price=false` after expiry on the next GET (assumed true).
- **R4 — `session_id` provenance**: depends on E41 hosting screen contract; if its nav
  arg name differs from `sessionId`, align the route key.
- **R5 — Offline authoring**: no local queueing of mutations in v1. Open question
  whether E41 needs draft persistence (would require Room + sync) — deferred.
- **R6 — Currency**: assumes a single `currency` per item; multi-currency shelves are
  out of scope.

## 14. Acceptance Criteria

- AC1: From the management panel for a session, a host can **create** a goal
  (label/target/sort) and it appears in the list; backend shows the goal via
  `GET .../goals`. (FR-G1/G2)
- AC2: A host can **delete** a goal after confirmation and the row is removed.
  (FR-G3)
- AC3: Goal create enforces server bounds client-side (label 1–200, target
  100–10_000_000, sort 0–4) and surfaces 422 field errors inline. (FR-G4)
- AC4: A host can **add** a product (`item_id`,`category_id`,optional order) and it
  appears on the shelf; backend `GET .../products` reflects it. (FR-P2)
- AC5: A host can **remove** a shelf item after confirmation. (FR-P3)
- AC6: A host can **reorder** the shelf via drag (and via Move up/down a11y actions);
  the new order persists through `PATCH .../reorder` and survives refresh; failure
  rolls back. (FR-P4)
- AC7: A host can **set** a broadcast price (with optional expiry) that is strictly
  below catalog price; the row shows discount % and effective price; an invalid price
  is rejected with a clear error. (FR-P5)
- AC8: A host can **clear** a broadcast price and the row reverts to catalog price.
  (FR-P6)
- AC9: All list reads support pull-to-refresh and render loading/empty/error/offline
  states; an unreliable/slow dev backend does not crash or hang past timeout.
  (FR-P7, §7)
- AC10: All repository endpoints, ViewModel logic (incl. optimistic rollback), and key
  Compose flows are covered by passing tests in §11; CI is green.
- AC11: Backlog phrase satisfied — "Goals/products CRUD live": every endpoint in §5 is
  wired and its effect is visible in the UI.

## 15. Definition of Done

- Code merged to `android-port` under `feature-broadcast-host`
  (`com.testlogon.android.feature.broadcasthost.manage`) with DTOs/API in
  `core-network`, repository/mappers in `core-data`, shared models in `core-model`.
- All §14 acceptance criteria demonstrably met against the dev backend
  (`http://18.222.237.167:8000`).
- Unit + ViewModel + Compose + accessibility tests pass locally and in CI (AND-008);
  package coverage ≥ 85% (repo + ViewModel).
- ktlint/detekt clean (AND-005); no new lint baseline suppressions.
- No plaintext-HTTP exposure in release config; cookies/CSRF redacted in logs.
- All user-facing strings externalized; TalkBack pass on goals + products + reorder.
- Telemetry events from §10 emitted and verified in a debug build.
- Spec field shapes re-verified against `/openapi.json` at implementation time;
  any drift reconciled and noted in the PR.
- PR description links AND-314, AND-282, AND-283 and documents R1 (no goal-edit
  endpoint) for reviewer awareness.
