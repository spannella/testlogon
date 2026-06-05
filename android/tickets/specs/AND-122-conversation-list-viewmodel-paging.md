---
id: AND-122
title: Conversation list ViewModel + paging
milestone: M3
epic: E18
priority: P0
size: M
status: draft
depends_on: [AND-120, AND-098]
blocks: [AND-121]
---

# AND-122 — Conversation list ViewModel + paging

## 1. Overview & Goal

Provide the presentation-layer engine that backs the conversation (inbox) list:
a Hilt-injected `ConversationListViewModel` that exposes a paged, sorted stream of
conversation summaries plus an aggregate of total unread count and a screen-level
`UiState`. Paging is driven by Paging 3 against the messaging API introduced in
AND-120, reusing the `PagingSource`/`RemoteMediator` conventions established by the
feed list in AND-098.

This ticket owns **logic only**: the `PagingSource`, the `Pager`/`Flow<PagingData>`
wiring, the unread-count aggregation, the sort policy, and the non-paging `UiState`
(refresh/empty/error). It does **not** own Composable rendering, list items, or
navigation — those belong to AND-121 (Conversation list screen). The deliverable is
a ViewModel whose paging and state machine are fully unit-tested in isolation from
Compose, satisfying the acceptance bullet "Paging + state unit-tested."

Goal: when AND-121 collects `pagingData` and `uiState`, it receives a correctly
ordered, deduplicated, lazily-paged conversation list and a live unread badge value,
with explicit loading/empty/error/offline states and idempotent refresh — without
re-implementing any data logic.

## 2. Context & References

- Module: `feature-messaging` (Compose feature module, layer `feature-* -> core-*`).
  This ViewModel lives in `feature-messaging`; DTOs/API live in `core-network` /
  `core-model` (AND-120); paging utilities and `ApiResult` live in `core-network`.
- **AND-120 (Messaging API + DTOs)** — provides `MessagingApi.getConversations(...)`,
  `ConversationDto`, `MessageDto`, pagination envelope, and `ConfigDto`. Hard
  dependency; this ticket calls that API and maps its DTOs to UI models.
- **AND-098 (Feed list, Paging 3)** — reference implementation for the Paging 3
  pattern: `PagingSource` keyed by cursor/page, `Pager` config, `LoadState`-driven
  footers, and refresh. Reuse its `cachedIn(viewModelScope)` and `LoadState` mapping
  conventions; do not fork them.
- **AND-121 (Conversation list screen)** — downstream consumer; owns Compose UI,
  pull-to-refresh gesture, item layout, and navigation to the thread (AND-123). Any
  rendering concern raised here is delegated to AND-121.
- Backend: FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` is plaintext and
  unreliable; design for ~20s timeouts and bounded retry on idempotent GETs only.
  Endpoint reference: `GET /messaging/conversations`. OpenAPI at `/openapi.json`.
- Web reference: `frontend/src/api/endpoints/messaging.ts` (list/cursor shape),
  `frontend/src/api/types.ts` (`Conversation`, `Message`).
- Namespace: `com.testlogon.android`. ViewModel package:
  `com.testlogon.android.feature.messaging.list`.

## 3. Functional Requirements

FR-1 — **Paged conversation stream.** Expose
`val pagingData: Flow<PagingData<ConversationListItem>>`, backed by a `Pager` whose
`PagingSource` calls `MessagingApi.getConversations(cursor, limit)`. Page size 20,
prefetch distance 5, no placeholders. `cachedIn(viewModelScope)` so config changes do
not re-fetch.

FR-2 — **Sort policy.** Conversations are ordered by most-recent activity descending:
primary key `lastMessageAt` (epoch millis, descending), tie-break by `conversationId`
ascending for stable ordering. The backend is expected to return list pages already
sorted by activity; the `PagingSource` must **preserve** server order across pages and
must not locally re-sort a page (re-sorting only the current page would corrupt global
order across page boundaries). The sort contract is asserted in tests against a
fixture whose server order is canonical.

FR-3 — **Unread aggregation.** Expose a total unread badge value
`val unreadTotal: StateFlow<Int>`. Source of truth is the server-provided aggregate
when present (`unread_total` in the list envelope / `GET /messaging/config`), falling
back to summing `unreadCount` over the materialized first page when the aggregate is
absent. The value is exposed independently of `PagingData` (Paging cannot reliably
sum across lazily-loaded pages).

FR-4 — **Screen UiState (non-paging).** Expose `val uiState: StateFlow<UiState>` with
`Loading`, `Content`, `Empty`, and `Error` for the screen chrome / first-load
experience. Per-page append/prepend loading and errors are surfaced through Paging's
`LoadState` (consumed by AND-121 footers), not through `UiState`.

FR-5 — **Refresh.** `fun refresh()` triggers a Paging refresh (re-invalidates the
source) and resets `uiState` to `Loading` only if the list is currently empty;
otherwise refresh is silent (existing content stays visible, footer/refresh indicator
owned by AND-121). Refresh is idempotent and safe to call repeatedly.

FR-6 — **Deduplication.** If the same `conversationId` appears across overlapping
pages (cursor drift on an active inbox), downstream rendering must not show
duplicates. Provide a stable item key (`conversationId`) so AND-121 keys
`LazyColumn` items; additionally the `PagingSource` must not emit a conversation whose
id was returned in the immediately preceding page (defensive dedup on cursor overlap).

FR-7 — **Mapping.** Map `ConversationDto` -> `ConversationListItem` (UI model) in the
ViewModel/source boundary: derive a display title, last-message preview, formatted
timestamp source value, avatar URL, and `unreadCount`. No DTO leaks past
`feature-messaging`'s public surface.

## 4. Technical Design

Package `com.testlogon.android.feature.messaging.list`.

```kotlin
data class ConversationListItem(
    val conversationId: String,
    val title: String,
    val avatarUrl: String?,
    val lastMessagePreview: String?,
    val lastMessageAt: Long,          // epoch millis; 0 if none
    val unreadCount: Int,
)

sealed interface ConvListUiState {
    data object Loading : ConvListUiState
    data object Content : ConvListUiState          // paging owns the rows
    data object Empty : ConvListUiState            // first page returned 0 items
    data class Error(val message: String, val isOffline: Boolean) : ConvListUiState
}
```

PagingSource keyed by an opaque string cursor (the envelope's `next_cursor`):

```kotlin
class ConversationPagingSource @AssistedInject constructor(
    private val api: MessagingApi,
    @Assisted private val pageSize: Int,
) : PagingSource<String, ConversationListItem>() {

    override suspend fun load(
        params: LoadParams<String>
    ): LoadResult<String, ConversationListItem> = try {
        val cursor = params.key                       // null on first load
        when (val r = api.getConversations(cursor = cursor, limit = params.loadSize)) {
            is ApiResult.Success -> {
                val items = r.value.conversations.map { it.toListItem() }
                LoadResult.Page(
                    data = items,
                    prevKey = null,                   // forward-only cursor
                    nextKey = r.value.nextCursor,     // null => end of list
                )
            }
            is ApiResult.Failure -> LoadResult.Error(r.toThrowable())
        }
    } catch (t: CancellationException) {
        throw t
    } catch (t: Throwable) {
        LoadResult.Error(t)
    }

    override fun getRefreshKey(state: PagingState<String, ConversationListItem>): String? = null
}
```

ViewModel:

```kotlin
@HiltViewModel
class ConversationListViewModel @Inject constructor(
    private val sourceFactory: ConversationPagingSource.Factory,
    private val api: MessagingApi,
    private val savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private companion object { const val PAGE_SIZE = 20; const val PREFETCH = 5 }

    val pagingData: Flow<PagingData<ConversationListItem>> =
        Pager(
            config = PagingConfig(
                pageSize = PAGE_SIZE,
                prefetchDistance = PREFETCH,
                enablePlaceholders = false,
                initialLoadSize = PAGE_SIZE,
            ),
            pagingSourceFactory = { sourceFactory.create(PAGE_SIZE) },
        ).flow.cachedIn(viewModelScope)

    private val _uiState = MutableStateFlow<ConvListUiState>(ConvListUiState.Loading)
    val uiState: StateFlow<ConvListUiState> = _uiState.asStateFlow()

    private val _unreadTotal = MutableStateFlow(0)
    val unreadTotal: StateFlow<Int> = _unreadTotal.asStateFlow()

    fun refresh() { /* exposes a signal AND-121 wires to lazyItems.refresh() */ }

    fun onLoadState(refresh: LoadState, itemCount: Int) { /* maps to ConvListUiState */ }

    fun onFirstPageLoaded(serverUnreadTotal: Int?, pageItems: List<ConversationListItem>) {
        _unreadTotal.value = serverUnreadTotal ?: pageItems.sumOf { it.unreadCount }
    }
}
```

`onLoadState` is the bridge between Paging `LoadState` and `ConvListUiState`:
AND-121 calls it from `LaunchedEffect(lazyItems.loadState)`. Mapping —
`LoadState.Loading && itemCount == 0 -> Loading`;
`LoadState.Error && itemCount == 0 -> Error(message, isOffline)`;
`LoadState.NotLoading && itemCount == 0 -> Empty`; otherwise `Content`. Append/prepend
states are left to AND-121's footer. This keeps the ViewModel testable without Compose
by exercising `onLoadState`/`onFirstPageLoaded` directly with synthetic `LoadState`s.

`ConversationDto.toListItem()` (mapper) lives in `feature-messaging`; it converts the
DTO timestamp (ISO-8601 string from FastAPI) to epoch millis and trims the preview.

## 5. API Contract

Consumes `MessagingApi` (owned by AND-120); this ticket defines no new endpoint.

`GET /messaging/conversations?cursor={opaque}&limit={n}` — idempotent GET, retry-safe.

Response envelope (mapped by AND-120's DTOs; shape this ticket relies on):

```json
{
  "conversations": [
    {
      "conversation_id": "cnv_8a1f",
      "title": "Ops On-call",
      "avatar_url": "https://.../a.png",
      "last_message": { "preview": "deploy is green", "created_at": "2026-06-05T14:02:11Z" },
      "unread_count": 3
    }
  ],
  "next_cursor": "eyJrIjoiY252XzZkMmUifQ==",
  "unread_total": 7
}
```

Field reliance: `conversation_id` (item key + dedup), `last_message.created_at`
(sort key -> `lastMessageAt`), `unread_count` (aggregation fallback), `next_cursor`
(`nextKey`; `null`/absent ⇒ end of list), `unread_total` (preferred aggregate; may be
absent). On absent `next_cursor` the source returns `nextKey = null`. Empty
`conversations` on first load with no cursor ⇒ `Empty`.

Error body (FastAPI `detail`, mapped by AND-120/core-network to `ApiResult.Failure`):
`detail` may be `string | [{msg}] | {code,...}`; the resulting message is surfaced via
`ConvListUiState.Error.message`. Transport/timeout/connection failures set
`isOffline = true`.

## 6. Data & State Management

- **Paged data:** held by Paging 3, cached via `cachedIn(viewModelScope)`; survives
  configuration change without refetch.
- **Screen state:** `StateFlow<ConvListUiState>` derived from `LoadState` + item count.
- **Unread total:** `StateFlow<Int>`, updated on first-page load and on refresh.
- **No Room/DataStore in this ticket.** A `RemoteMediator` + Room cache for
  offline conversation list is explicitly out of scope; if added later it is a separate
  ticket. Offline here means "show last cached `PagingData` if present, else Error
  with `isOffline = true`."
- **SavedStateHandle:** no scroll/cursor restoration is persisted here (Paging restores
  position on its own); reserved for future filter/search state.
- Threading: all API access on Dispatchers.IO via Retrofit suspend functions; state
  emitted on the main-safe `viewModelScope`.

## 7. Error Handling & Resilience

- **First-load error:** `LoadState.Refresh = Error` with 0 items ⇒
  `ConvListUiState.Error`; AND-121 renders full-screen error with retry → `refresh()`.
- **Append error:** surfaced through Paging `LoadState.Append = Error`; AND-121 shows a
  footer retry; `uiState` stays `Content`. The ViewModel does not swallow it.
- **Timeouts:** rely on OkHttp client config (~20s) from core-network. The list GET is
  idempotent, so bounded backoff retry for the GET is permitted at the network layer
  (core-network policy); the `PagingSource` does not add its own retry loop beyond
  Paging's `retry()`.
- **Offline / unreachable host:** connection/timeout exceptions map to
  `Error(isOffline = true)`. If a prior `PagingData` is cached, it remains visible and
  refresh failure is non-destructive (silent per FR-5).
- **401 handling:** transparent to this ticket — core-network's auth interceptor does
  the single `POST /ui/session/refresh` + retry; a still-failing 401 reaches the source
  as `ApiResult.Failure` and renders as `Error`.
- **Cursor drift / dedup:** see FR-6; defensive dedup prevents duplicate rows when an
  active inbox shifts page boundaries between loads.
- **Cancellation:** `CancellationException` is rethrown, never converted to
  `LoadResult.Error`.

## 8. Security & Privacy

- No new credential or token handling; the session rides on the persistent cookie jar
  and `X-CSRF-Token` header managed by core-network. GET requests carry the CSRF header
  per the global client policy.
- Message previews and titles are PII; they must never be written to logs (see §10) or
  to `SavedStateHandle`/crash metadata. Only `conversationId` and counts may appear in
  diagnostic logs.
- Avatar URLs are loaded by Coil in AND-121; this ticket only passes the URL string and
  performs no network fetch for images.
- Transport is plaintext HTTP on the dev host; that is a known dev-environment
  constraint, not a property of this ticket. No secrets are placed in query params
  (cursor is an opaque, non-secret pagination token).

## 9. Accessibility & i18n

- This ticket is non-UI; rendering accessibility (content descriptions, unread badge
  semantics, focus order, touch targets) is owned by **AND-121**.
- i18n responsibilities here: the mapper must not concatenate or hard-code
  user-facing strings. Empty/error messages exposed via `ConvListUiState` are either
  string resource ids resolved by AND-121 or server-provided `detail` text; the
  ViewModel passes resource ids/keys, not English literals.
- Timestamp formatting is deferred: the model exposes `lastMessageAt` as epoch millis;
  locale/timezone-aware formatting happens in AND-121 so it respects device locale.

## 10. Telemetry & Logging

- Emit structured analytics events (via core-data analytics facade, if present):
  `messaging_list_loaded { source: "network", page_count, item_count, duration_ms }`,
  `messaging_list_load_failed { stage: "refresh"|"append", is_offline, error_code }`,
  `messaging_list_refreshed`.
- Logging is debug-level only and PII-free: log `conversationId` counts and cursor
  presence (boolean), never previews, titles, or full cursors.
- The unread total change may emit `messaging_unread_total { value }` for badge
  observability; value is a count, not PII.

## 11. Testing Strategy

Primary acceptance: paging and state unit-tested (no instrumentation/Compose).

Unit tests (`core-testing` utilities, `kotlinx-coroutines-test`, `turbine`,
`paging-testing` `asSnapshot`):

- **PagingSource.load (first page):** fake `MessagingApi` returns a page +
  `next_cursor`; assert `LoadResult.Page` with mapped items, `prevKey == null`,
  `nextKey == next_cursor`.
- **PagingSource.load (end of list):** `next_cursor == null` ⇒ `nextKey == null`.
- **PagingSource.load (error):** API `ApiResult.Failure` ⇒ `LoadResult.Error`.
- **Pagination via `asSnapshot`:** drive `pagingData` through multiple pages; assert
  full concatenated order equals canonical server order (FR-2) and no duplicates across
  a deliberately overlapping fixture (FR-6).
- **Sort contract:** fixture with mixed `last_message.created_at`; assert global order
  is `lastMessageAt` desc, `conversationId` asc tie-break, preserved across page joins.
- **Unread aggregation:** (a) envelope has `unread_total` ⇒ `unreadTotal` equals it;
  (b) `unread_total` absent ⇒ equals sum of first-page `unread_count`.
- **UiState mapping (`onLoadState`):** parametrized over (`LoadState`, itemCount) ⇒
  Loading / Content / Empty / Error; offline flag set for connection/timeout throwable.
- **Refresh idempotency:** repeated `refresh()` calls don't crash; non-empty list ⇒
  `uiState` stays `Content`; empty list ⇒ `Loading`.
- **Mapper:** `ConversationDto.toListItem()` parses ISO-8601 ⇒ epoch millis; trims
  preview; null avatar tolerated.

Coverage target: ≥ 90% lines on `ConversationPagingSource`, the mapper, and the
state-mapping logic in `ConversationListViewModel`.

## 12. Dependencies & Sequencing

- **Depends on AND-120** — `MessagingApi`, `ConversationDto`, list envelope, `ApiResult`
  mapping. Must merge first; tests use the real DTOs against fixtures.
- **Depends on AND-098** — reuse the Paging 3 source/`Pager`/`LoadState` conventions
  and `cachedIn` pattern; do not duplicate them.
- **Blocks AND-121** — the conversation list screen collects `pagingData`, `uiState`,
  and `unreadTotal`, and calls `onLoadState`/`refresh`.
- Transitively enables AND-123 (thread screen) only via shared messaging plumbing; no
  direct API surface coupling.
- Libraries (already in version catalog per stack): `androidx.paging:paging-runtime`,
  `paging-common`, `paging-testing`, Hilt + KSP, Coroutines/Flow, Retrofit/Moshi
  (via AND-120), Turbine.

## 13. Risks & Open Questions

- **R1 — Aggregate availability.** Does `GET /messaging/conversations` return
  `unread_total`, or is it only on `GET /messaging/config`? Confirm against
  `/openapi.json`. Fallback (sum first page) under-counts if unread spans later pages;
  acceptable as interim, flagged for AND-121 review.
- **R2 — Cursor stability on active inbox.** Backend cursor may be activity-ordered;
  rapid new messages can cause page overlap/skips. Mitigated by FR-6 dedup + stable
  keys; a `RemoteMediator`/Room cache would fully fix it (out of scope, future ticket).
- **R3 — Sort authority.** Spec assumes server returns activity-sorted pages. If it
  does not, global sort across cursor pages is not achievable client-side without full
  materialization; this must be resolved server-side, not in this ticket.
- **R4 — `getRefreshKey`.** Returning `null` restarts from the first page on refresh,
  which is correct for an activity-ordered inbox; revisit if backend adds a stable
  positional key.
- **Open:** exact ISO-8601 format / timezone of `created_at` (assume UTC `Z`); confirm
  in AND-120 fixtures.

## 14. Acceptance Criteria

- AC-1 — `ConversationListViewModel` exposes `pagingData: Flow<PagingData<ConversationListItem>>`,
  `uiState: StateFlow<ConvListUiState>`, and `unreadTotal: StateFlow<Int>`, injectable
  via Hilt.
- AC-2 — Paging fetches successive pages from `MessagingApi.getConversations` using the
  envelope cursor; `next_cursor == null` terminates pagination. Verified by an
  `asSnapshot` multi-page test.
- AC-3 — Global ordering across pages is `lastMessageAt` desc with `conversationId` asc
  tie-break, preserving server order; verified by fixture test (FR-2).
- AC-4 — No duplicate `conversationId` appears across overlapping pages; stable item
  key exposed (FR-6).
- AC-5 — `unreadTotal` equals server `unread_total` when present, else the first-page
  sum; both paths unit-tested (FR-3).
- AC-6 — `uiState` correctly resolves Loading / Content / Empty / Error (with
  `isOffline`) from `LoadState` + item count; first-load error is distinguishable from
  append error.
- AC-7 — `refresh()` is idempotent and non-destructive on a non-empty list.
- AC-8 — **Paging + state are unit-tested** (the source acceptance bullet), all tests
  green in CI, no Compose/instrumentation required, coverage ≥ 90% on source/mapper/
  state logic.
- AC-9 — No `ConversationDto` or other DTO leaks past the `feature-messaging` public
  surface; only `ConversationListItem` / state types are exposed.

## 15. Definition of Done

- All Acceptance Criteria met; unit-test suite added under
  `feature-messaging/src/test/...` and passing locally + in CI.
- Code in `com.testlogon.android.feature.messaging.list`, layered `feature -> core`,
  no upward dependencies; Hilt graph compiles with KSP.
- `MessagingApi` consumed unchanged from AND-120; no endpoint or DTO defined in this
  ticket.
- No PII in logs or analytics payloads; lint/detekt and ktlint clean.
- Public API (`ConversationListViewModel`, `ConversationListItem`, `ConvListUiState`)
  documented with KDoc and ready for AND-121 to collect without further data logic.
- PR on branch `android-port`, references AND-122, links AND-120/AND-098, and notes
  AND-121 as the unblocked consumer. Reviewed and merged.
