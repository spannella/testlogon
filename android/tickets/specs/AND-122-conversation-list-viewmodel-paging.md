---
id: AND-122
title: Conversation list ViewModel + paging
milestone: M3
epic: E18
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
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
  **[CORRECTED 2026-06-06]** The documented backend contract for this endpoint declares
  NO `cursor` and NO `limit` query parameters (only `authorization`/`X-SESSION-ID`/`X-API-Key`
  headers), and its 200 response is a **bare JSON array of `ConversationOut`** — not an
  envelope object. There is therefore no server-provided `next_cursor` or `unread_total` in
  the current contract. The web client opportunistically sends `?cursor=` (tolerated but
  undocumented) and synthesizes an `{conversations, next_cursor}` envelope client-side, where
  `next_cursor` is `undefined` for the array shape. See §5 and §13 R1/R5 for the impact on
  paging design; the `MessagingApi` surface AND-120 exposes must reconcile this.
- Web reference: `frontend/src/api/endpoints/messaging.ts` (list/cursor shape),
  `frontend/src/api/types.ts` (`Conversation`, `Message`).
- Namespace: `com.testlogon.android`. ViewModel package:
  `com.testlogon.android.feature.messaging.list`.

## 3. Functional Requirements

FR-1 — **Paged conversation stream.** Expose
`val pagingData: Flow<PagingData<ConversationListItem>>`, backed by a `Pager` whose
`PagingSource` calls `MessagingApi.getConversations(cursor)`. Page size 20,
prefetch distance 5, no placeholders. `cachedIn(viewModelScope)` so config changes do
not re-fetch.
**[CORRECTED 2026-06-06]** The documented endpoint accepts NO `limit` query param
(OpenAPI declares only header params), so `limit`/`loadSize` is NOT sent to the server;
`PagingConfig.pageSize` governs only Paging-side buffering, and effective page size is
whatever the server returns. The web reference (`getConversations`) likewise passes only
`cursor`. Because the documented 200 body is a bare array with no `next_cursor`, true
server cursor paging is currently **not contractually supported**; the `PagingSource`
must treat a missing/`undefined` cursor as end-of-list (single-page result) until
AND-120/backend confirms a cursor contract. See §13 R5.

FR-2 — **Sort policy.** Conversations are ordered by most-recent activity descending:
primary key `lastMessageAt` (epoch millis, descending), tie-break by `conversationId`
ascending for stable ordering. The backend is expected to return list pages already
sorted by activity; the `PagingSource` must **preserve** server order across pages and
must not locally re-sort a page (re-sorting only the current page would corrupt global
order across page boundaries). The sort contract is asserted in tests against a
fixture whose server order is canonical.

FR-3 — **Unread aggregation.** Expose a total unread badge value
`val unreadTotal: StateFlow<Int>`. **[CORRECTED 2026-06-06]** There is NO server-provided
`unread_total` aggregate: it does not appear in the `GET /messaging/conversations`
response (a bare `ConversationOut[]`) nor in `MessagingConfigOut` (which is feature-flag
booleans only — `messaging_*_enabled`), and the token `unread_total` appears nowhere in
the OpenAPI spec or the web reference. The badge value MUST therefore be computed
client-side by summing per-conversation `unread_count` over the materialized first page.
The optional `serverUnreadTotal` parameter in the ViewModel is retained only as a
forward-compatible hook (always `null` against the current backend) and must default to
the first-page sum. The value is exposed independently of `PagingData` (Paging cannot
reliably sum across lazily-loaded pages). NOTE: a first-page-only sum under-counts if
unread conversations exist on later pages; flagged for AND-121 review (see §13 R1).

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
ViewModel/source boundary: derive a display title, last-message preview, the
last-activity timestamp, an avatar/icon URL, and `unreadCount`. No DTO leaks past
`feature-messaging`'s public surface.
**[CORRECTED 2026-06-06]** Field names per the authoritative `ConversationOut` schema:
the sort/timestamp source is the top-level **`last_message_at`** (an **epoch integer**,
NOT an ISO-8601 string — `created_at` and `last_message_at` are integers in the schema,
so NO ISO→epoch parsing is required; pass the integer through, defaulting null→0). The
preview is the top-level **`last_message_preview`** (string|null), not `last_message.preview`.
There is **no `avatar_url` field**; the conversation avatar source is **`icon`**
(string|null). `unread_count` is an integer.

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

`ConversationDto.toListItem()` (mapper) lives in `feature-messaging`. **[CORRECTED
2026-06-06]** The DTO timestamps are already **epoch integers** (`last_message_at`,
`created_at` per `ConversationOut`), so the mapper does NOT parse ISO-8601 — it passes
`last_message_at` through (null→0), copies `last_message_preview`, maps `icon` to the
item's avatar field, and trims the preview. Note the units: the source value is whatever
the backend emits (epoch seconds vs millis is unconfirmed — flag to AND-120 fixtures;
the model field is named generically and AND-121 formats it locale-aware, see §13 Open).

## 5. API Contract

Consumes `MessagingApi` (owned by AND-120); this ticket defines no new endpoint.

`GET /messaging/conversations` — idempotent GET, retry-safe. **[CORRECTED 2026-06-06]**
The documented contract declares NO query params (`cursor`/`limit` are not in the OpenAPI
parameter list; only `authorization`, `X-SESSION-ID`, `X-API-Key` headers). Required API
key scope: `messager:read`.

**Actual 200 response (authoritative `ConversationOut[]` — a bare array, NOT an
envelope):**

```json
[
  {
    "conversation_id": "cnv_8a1f",
    "type": "dm",
    "title": "Ops On-call",
    "icon": "https://.../a.png",
    "last_message_at": 1749132131000,
    "last_message_preview": "deploy is green",
    "created_at": 1749100000000,
    "unread_count": 3,
    "last_read_at": 1749130000000,
    "participant_count": 2,
    "status": "active"
  }
]
```

The previously-documented `{conversations, next_cursor, unread_total}` envelope does
**not** exist in the backend contract; it is a client-side construction in the web
reference (`getConversations` wraps the array as `{conversations, next_cursor}` with
`next_cursor === undefined` for the array shape). AND-120's `MessagingApi` is expected to
deserialize the bare array (and, if it surfaces an envelope, `nextCursor` will be null).

Field reliance (per `ConversationOut`): `conversation_id` (item key + dedup),
`last_message_at` (sort key -> `lastMessageAt`; **epoch integer**, nullable),
`last_message_preview` (preview), `icon` (avatar URL source), `unread_count`
(unread aggregation — the only available source, see FR-3). There is no `next_cursor`
in the response, so pagination terminates after the first page under the current
contract; an empty array on first load ⇒ `Empty`.

Error body (FastAPI `detail`, mapped by AND-120/core-network to `ApiResult.Failure`):
this endpoint documents **structured** error bodies — 400/401/403/429 return
`{ "detail": { "code", "reason", "message"?, ... } }` (e.g. 401 `{code:"api_key_invalid",
reason:"invalid_key"}`, 403 `{code:"api_entitlement_denied"}` / `{code:"api_key_scope_denied",
required_scopes:[...]}`, 400 `{code:"api_key_dual_credential_conflict"}`), and 422 returns
`HTTPValidationError` (`detail: [{loc,msg,type}]`). core-network's `detail` normalizer
must therefore handle `object{code,...}`, `array[{msg}]`, and `string`; the resulting
message is surfaced via `ConvListUiState.Error.message`. Transport/timeout/connection
failures set `isOffline = true`.

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

- **R1 — Aggregate availability.** RESOLVED [2026-06-06]: neither `GET /messaging/conversations`
  nor `GET /messaging/config` (`MessagingConfigOut`, feature flags only) returns an
  `unread_total`; the token does not exist anywhere in OpenAPI or the web reference. The
  unread badge MUST be the first-page `unread_count` sum (FR-3). This under-counts if
  unread conversations span later pages; accepted as interim, flagged for AND-121 review.
  A dedicated unread-count endpoint (if one is added later) would be a separate ticket.
- **R5 — No cursor pagination in the documented backend contract.** RESOLVED [2026-06-06]:
  `GET /messaging/conversations` documents no `cursor`/`limit` query params and returns a
  bare `ConversationOut[]` with no `next_cursor`. As written, this endpoint returns a
  single (likely capped) page. The Paging 3 scaffolding is still built (so the screen and
  tests are ready), but it will behave as a single-page source until the backend exposes a
  real cursor. AND-120 owns confirming whether the deployed backend returns more than the
  documented array (the web client tolerates an envelope) and defining the `MessagingApi`
  return shape; this ticket consumes whatever AND-120 exposes and maps `next_cursor` -> nextKey
  (null today). Do NOT assume a working cursor in acceptance until AND-120 confirms it.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources:
OpenAPI index = `reference/openapi.index.txt`; OpenAPI spec = `reference/openapi.pretty.json`
(`components.schemas.<Name>`); frontend = `reference/src/...`.

1. **Endpoint exists: `GET /messaging/conversations`.** VERIFIED. OpenAPI
   `GET /messaging/conversations` (op `list_conversations_messaging_conversations_get`);
   `reference/src/api/endpoints/messaging.ts: getConversations`.
2. **It is an idempotent GET (retry-safe).** VERIFIED (HTTP method GET). OpenAPI
   `GET /messaging/conversations`.
3. **Request takes `cursor` and `limit` query params.** CORRECTED. The documented
   OpenAPI operation declares NO query params — only headers `authorization`,
   `X-SESSION-ID`, `X-API-Key`. Source: OpenAPI `GET /messaging/conversations` parameters
   (index line shows `params=authorization,X-SESSION-ID,X-API-Key`). The web client
   sends only an optional `cursor` and never `limit`: `reference/src/api/endpoints/messaging.ts:
   getConversations` (`cursor ? { cursor } : undefined`).
4. **200 response is an `{conversations, next_cursor, unread_total}` envelope.** CORRECTED.
   The 200 body is a bare array `ConversationOut[]` (OpenAPI `GET /messaging/conversations`
   responses.200: `{type: array, items: $ref ConversationOut}`). The envelope is a
   client-side construct: `reference/src/api/endpoints/messaging.ts: getConversations`
   ("Backend returns a plain array; handle both array and object shapes").
5. **`next_cursor` field drives `nextKey`.** CORRECTED / UNVERIFIED for real paging. No
   `next_cursor` exists in the documented response; the web reference sets
   `next_cursor = undefined` for the array case. Source: OpenAPI `ConversationOut` (no such
   field) + `reference/src/api/endpoints/messaging.ts: getConversations`.
6. **`unread_total` aggregate exists in the list envelope or `GET /messaging/config`.**
   CORRECTED. `unread_total` appears nowhere in OpenAPI or the frontend.
   `MessagingConfigOut` is feature-flag booleans only (`messaging_dm_lottery_enabled`,
   `messaging_encrypted_messages_enabled`, `messaging_gallery_enabled`,
   `messaging_hide_controls_enabled`, `messaging_mass_send_enabled`, `messaging_pins_enabled`,
   `messaging_reporting_enabled`). Source: OpenAPI `components.schemas.MessagingConfigOut`;
   `GET /messaging/config` (op `messaging_config_messaging_config_get`).
7. **Item key field is `conversation_id`.** VERIFIED. OpenAPI `ConversationOut.conversation_id`
   (string, required); `reference/src/api/types.ts: Conversation.conversation_id`;
   `reference/src/api/endpoints/messagingAdapter.ts: adaptConversation` (`conversation_id`).
8. **Sort key is `last_message.created_at`, an ISO-8601 string needing ISO→epoch parsing.**
   CORRECTED. The sort source is top-level `last_message_at`, an **epoch integer** (nullable);
   `created_at` is likewise an integer. No ISO parsing. Source: OpenAPI
   `ConversationOut.last_message_at` (integer|null), `ConversationOut.created_at` (integer);
   `reference/src/api/types.ts: Conversation` (`last_message_at?: number`, `created_at: number`);
   `reference/src/api/endpoints/messagingAdapter.ts: adaptConversation` (`toNum(...)`).
9. **Preview comes from `last_message.preview`.** CORRECTED. The preview is the top-level
   `last_message_preview` (string|null). Source: OpenAPI `ConversationOut.last_message_preview`;
   `reference/src/api/types.ts: Conversation.last_message_preview`.
10. **Avatar comes from `avatar_url`.** CORRECTED. No `avatar_url` field exists; the avatar
    source is `icon` (string|null). Source: OpenAPI `ConversationOut.icon`;
    `reference/src/api/types.ts: Conversation.icon` (no `avatar_url`).
11. **`unread_count` is a per-conversation integer (aggregation source).** VERIFIED. OpenAPI
    `ConversationOut.unread_count`; `reference/src/api/types.ts: Conversation.unread_count: number`.
12. **GET requests carry the `X-CSRF-Token` header (global client policy).** VERIFIED.
    `reference/src/api/client.ts` sets `X-CSRF-Token` from the `ui_csrf` cookie on every
    request (no method gating) with `credentials: "include"`.
13. **401 handled by a single `POST /ui/session/refresh` + one retry.** VERIFIED. OpenAPI
    `POST /ui/session/refresh` (op `ui_session_refresh_ui_session_refresh_post`);
    `reference/src/api/client.ts: refreshSession` (`fetch(withApiBase("/ui/session/refresh"))`)
    and the 401 branch (single in-flight `refreshPromise`, one retry, then `logout`).
14. **Error body `detail` may be `string | [{msg}] | {code,...}`.** VERIFIED (and refined).
    `GET /messaging/conversations` documents structured `{detail:{code,reason,...}}` for
    400/401/403/429 and `HTTPValidationError` (`detail:[{loc,msg,type}]`) for 422. Source:
    OpenAPI `GET /messaging/conversations` responses (examples `api_key_invalid`,
    `api_entitlement_denied`, `api_key_scope_denied`, `api_key_dual_credential_conflict`);
    `reference/src/api/client.ts: normalizeErrorDetail`.
15. **Required API key scope `messager:read` for the list.** VERIFIED. OpenAPI
    `GET /messaging/conversations` description ("Required API key scope(s): `messager:read`").
16. **Paging 3 / `cachedIn` / `PagingSource` are the chosen Android paging mechanism.**
    VERIFIED (framework ref). androidx.paging — https://developer.android.com/topic/libraries/architecture/paging/v3-overview
17. **Compose `LazyColumn` item keys for dedup; `collectAsLazyPagingItems`.** VERIFIED
    (framework ref, owned by AND-121). https://developer.android.com/develop/ui/compose/lists#item-keys
    and https://developer.android.com/topic/libraries/architecture/paging/v3-paged-data#display-paged-data
18. **Hilt `@HiltViewModel` injection.** VERIFIED (framework ref).
    https://developer.android.com/training/dependency-injection/hilt-jetpack#viewmodels

### Corrections made

- C1 (claims 3): removed `limit` from the API call signature (`getConversations(cursor)`),
  noted no `cursor`/`limit` query params are documented (§2, FR-1, §5).
- C2 (claim 4): response is a bare `ConversationOut[]`, not an envelope; envelope is
  client-synthesized (§2, §5, §13 R5).
- C3 (claims 5, 6): no server `next_cursor` and no `unread_total` anywhere; pagination is
  effectively single-page and unread is first-page sum only (FR-1, FR-3, §5, §13 R1/R5).
- C4 (claim 8): timestamps are epoch integers, not ISO-8601; mapper does no ISO parsing
  (FR-7, §4).
- C5 (claim 9): preview field is `last_message_preview` (top-level), not `last_message.preview`
  (FR-7, §5).
- C6 (claim 10): avatar source is `icon`, not `avatar_url` (FR-7, §5).
- C7 (claim 14): error `detail` for this endpoint is predominantly a structured
  `{code,reason,...}` object (plus 422 array); normalizer must handle all three (§5).

### Open assumptions

- **Timestamp unit (seconds vs millis).** `last_message_at`/`created_at` are integers but
  the OpenAPI schema does not state the unit, and fixtures were not available here.
  UNVERIFIED — must be confirmed against AND-120 fixtures before formatting/sorting math.
- **Real cursor pagination.** Whether the *deployed* backend ever returns more than the
  documented bare array (the web client tolerates an envelope) is UNVERIFIED from the
  static sources; treated as single-page until AND-120 confirms (§13 R5).
- **Analytics facade existence.** §10 events assume a `core-data` analytics facade; its
  presence/shape is UNVERIFIED here (no Android source in the reference tree) — guarded by
  "if present".
- **AND-120 `MessagingApi`/`ApiResult` exact signatures.** This is an upstream Android
  ticket not present in the reference sources; UNVERIFIED — consumed as specified by AND-120.
- **`isOffline` mapping for transport failures.** The web client throws `ApiError(0,
  "Network error")` on fetch failure (`reference/src/api/client.ts`); the Android mapping of
  connection/timeout exceptions to `isOffline=true` is an Android-side convention, UNVERIFIED
  against a concrete core-network impl (not in reference tree).

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **emu35** = headless
emulator AVD `test35` (x86_64, API 35); **deviceA15** = physical Samsung Galaxy A15 5G
(SM-A156U, API 34, arm64-v8a, serial R5CX821TA9R). This ticket is logic-only, so most
cases are JVM unit/contract; UI/accessibility cases belong to the consumer (AND-121) but
are included where this ticket's outputs are observable. The list endpoint uses no camera/
biometric/WebRTC/FCM hardware, so deviceA15 is required only for the ABI-difference smoke.

- **TC-AND-122-01** — PagingSource first page (happy path).
  Type: unit (JVM). Target: JVM. Preconditions: fake `MessagingApi` returns N
  `ConversationOut` items mapped to `ConversationListItem`. Steps: call
  `source.load(Refresh, key=null)`. Expected: `LoadResult.Page` with mapped items in
  server order, `prevKey == null`, `nextKey` = mapped next cursor (null when the bare
  array / absent cursor is returned). Traces: AC-1, AC-2.

- **TC-AND-122-02** — End-of-list / single-page bare-array contract.
  Type: contract/MockWebServer. Target: JVM (MockWebServer). Preconditions: server returns
  a bare JSON array `ConversationOut[]` with no `next_cursor` (authoritative shape). Steps:
  drive `pagingData` via `asSnapshot`; let it attempt to append. Expected: exactly one page
  materialized, `nextKey == null`, no further network call, no crash. Traces: AC-2.

- **TC-AND-122-03** — Multi-page pagination via synthesized cursor (forward-compat).
  Type: contract/MockWebServer. Target: JVM. Preconditions: fake API returns
  `{conversations, next_cursor}` for page 1 then `next_cursor=null` for page 2 (envelope
  path the web client can produce). Steps: `asSnapshot` advancing through both pages.
  Expected: concatenated items = page1 ++ page2 in order; pagination stops when
  `next_cursor == null`. Traces: AC-2.

- **TC-AND-122-04** — Global sort order preserved across page joins.
  Type: unit (JVM). Target: JVM. Preconditions: fixture with mixed `last_message_at` epoch
  integers across two pages, canonical server order known. Steps: snapshot the concatenated
  list. Expected: order equals server order (`last_message_at` desc, `conversation_id` asc
  tie-break); the source does NOT locally re-sort a page. Traces: AC-3.

- **TC-AND-122-05** — Dedup across overlapping pages.
  Type: unit (JVM). Target: JVM. Preconditions: fixture where one `conversation_id` appears
  at the tail of page 1 and head of page 2 (cursor drift). Steps: snapshot concatenated
  list. Expected: the duplicated `conversation_id` appears once; stable item key
  (`conversation_id`) is exposed for `LazyColumn`. Traces: AC-4.

- **TC-AND-122-06** — Unread aggregation = first-page sum (no server aggregate).
  Type: unit (JVM). Target: JVM. Preconditions: first page items with `unread_count`
  values [3,0,2]; `serverUnreadTotal = null` (the only real case — no backend aggregate).
  Steps: call `onFirstPageLoaded(null, pageItems)`; read `unreadTotal`. Expected:
  `unreadTotal == 5`. Traces: AC-5.

- **TC-AND-122-07** — Unread aggregation respects optional server value if ever provided.
  Type: unit (JVM). Target: JVM. Preconditions: `onFirstPageLoaded(7, pageItems summing to
  5)`. Steps: read `unreadTotal`. Expected: `unreadTotal == 7` (forward-compat hook honored;
  documents that today's backend always passes null → falls back to the sum). Traces: AC-5.

- **TC-AND-122-08** — Mapper field correctness (epoch int, icon, preview, null tolerance).
  Type: unit (JVM). Target: JVM. Preconditions: `ConversationDto` with
  `last_message_at` integer, `last_message_preview` set, `icon` set, plus a second DTO with
  `last_message_at=null`, `last_message_preview=null`, `icon=null`. Steps: call
  `toListItem()`. Expected: `lastMessageAt` = the integer (and 0 for null), preview copied/
  trimmed (null tolerated), avatar field = `icon` (null tolerated); NO ISO parsing path is
  exercised. Traces: AC-1, AC-9.

- **TC-AND-122-09** — UiState mapping from LoadState + itemCount.
  Type: unit (JVM). Target: JVM. Preconditions: synthetic `LoadState`s. Steps: parametrize
  `onLoadState`: (Loading, 0)→Loading; (NotLoading, 0)→Empty; (Error, 0)→Error;
  (NotLoading/Error, >0)→Content. Expected: states resolve as mapped; append/prepend
  states do NOT alter `uiState` (stay Content). Traces: AC-6.

- **TC-AND-122-10** — First-load error vs offline flag.
  Type: contract/MockWebServer. Target: JVM. Preconditions: (a) server returns 403
  `{detail:{code:"api_entitlement_denied"}}`; (b) MockWebServer set to disconnect /
  socket timeout to simulate the flaky dev host. Steps: trigger refresh with 0 items; map
  the resulting `LoadState.Error` via `onLoadState`. Expected: (a) `Error(isOffline=false)`
  with normalized message from structured `detail.code`; (b) `Error(isOffline=true)`. The
  ViewModel never swallows the error. Traces: AC-6.

- **TC-AND-122-11** — Append error keeps content; refresh recovers.
  Type: contract/MockWebServer. Target: JVM. Preconditions: page 1 ok, page 2 errors. Steps:
  load page 1 (Content), trigger append (fails), then `retry()`/`refresh()` with page 2 ok.
  Expected: `uiState` stays `Content` on append error (error surfaced via Paging
  `LoadState.Append`, not `uiState`); retry succeeds. Traces: AC-6, AC-7.

- **TC-AND-122-12** — Refresh idempotency & non-destructiveness.
  Type: unit (JVM). Target: JVM. Preconditions: non-empty list loaded. Steps: call
  `refresh()` repeatedly. Expected: no crash; on a non-empty list `uiState` stays
  `Content` (silent refresh); on an empty list it resets to `Loading`. Traces: AC-7.

- **TC-AND-122-13** — 401 transparent refresh + retry; PII-free logging.
  Type: contract/MockWebServer. Target: JVM. Preconditions: first GET → 401, then
  `POST /ui/session/refresh` → 200, retried GET → 200 (mirrors core-network policy). Also
  capture logs. Steps: load the list while authenticated. Expected: list loads after one
  transparent refresh+retry; logs/analytics contain only `conversation_id`/counts/cursor-
  presence boolean — never titles, previews, or full cursors (security/PII check). Traces:
  AC-1, AC-8.

- **TC-AND-122-14** — Unread badge accessibility semantics (consumer-observable).
  Type: Compose-UI (instrumented). Target: emu35 (API 35) — accessibility/Compose semantics
  are device-independent here. Preconditions: AND-121 host collecting `unreadTotal` and
  `pagingData` from the real ViewModel with a fake API. Steps: render the list with unread
  total = 5 and assert via semantics. Expected: the unread badge exposes a non-empty
  content description / state description reflecting the count, and list rows are keyed by
  `conversation_id` (no duplicate-key crash). NOTE: gated on AND-121; included for coverage
  of this ticket's observable outputs. Traces: AC-4, AC-5.

- **TC-AND-122-15** — ABI / API-level smoke (arm64 API 34 vs x86_64 API 35).
  Type: instrumented/e2e. Target: **deviceA15 (MUST run on physical device)** for the
  arm64-v8a/API-34 leg; emu35 for the x86_64/API-35 leg. Preconditions: app built; list
  reachable against a fake/staging API. Steps: launch, open the conversation list, scroll.
  Expected: identical mapping/sort/dedup behavior and no ABI- or API-level
  (epoch/int-overflow, time formatting) discrepancy between the two targets. Traces: AC-2,
  AC-3, AC-8.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 (exposes pagingData/uiState/unreadTotal, Hilt) | TC-01, TC-08, TC-13 |
| AC-2 (paging via cursor; null terminates) | TC-01, TC-02, TC-03, TC-15 |
| AC-3 (global sort desc + tie-break, server order) | TC-04, TC-15 |
| AC-4 (no duplicate conversation_id; stable key) | TC-05, TC-14 |
| AC-5 (unreadTotal server-or-sum, both paths) | TC-06, TC-07, TC-14 |
| AC-6 (Loading/Content/Empty/Error + isOffline; first-load vs append) | TC-09, TC-10, TC-11 |
| AC-7 (refresh idempotent, non-destructive) | TC-11, TC-12 |
| AC-8 (paging+state unit-tested, green, no Compose required, coverage) | TC-01..TC-13, TC-15 |
| AC-9 (no DTO leak past feature-messaging) | TC-08 |
