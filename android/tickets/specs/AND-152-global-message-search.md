---
id: AND-152
title: Global message search
milestone: M3
epic: E21
priority: P1
size: M
status: draft
depends_on: [AND-120]
blocks: []
---

# AND-152 — Global message search

## 1. Overview & Goal

Provide a dedicated, full-screen **cross-conversation** message search experience:
a search entry point reachable from the messaging area, a query input, optional
`sender` and `after` filters, a paged results list spanning *all* conversations the
signed-in user participates in, and a tap-through that opens the originating
conversation thread scrolled to the matched message. This is the **global** sibling
of AND-151 (in-conversation search) and is backed by a distinct backend endpoint,
`GET /messaging/messages/search`.

Scope, verbatim from the backlog: *`/messaging/messages/search` with sender/after
filters; results screen.* The single acceptance bullet: *Cross-conversation search
returns + opens results* — i.e. a query (optionally narrowed by sender and/or an
`after` date) returns matching messages drawn from multiple conversations, and
tapping a result navigates into that conversation's thread at the matched message.

This ticket owns: the global-search Retrofit endpoint + DTOs in `core-network`
/`core-model`, a `GlobalSearchRepository` that wraps the call in `ApiResult<T>`,
a Paging 3 `PagingSource` over the cursor-paged results, a
`GlobalSearchViewModel` exposing `StateFlow<GlobalSearchUiState>` plus
`Flow<PagingData<MessageSearchResultItem>>`, the `feature-messaging`
`GlobalSearchScreen` (input bar, filter chips, results list, empty/loading/error
states), the navigation route for the screen, and the deep-link into the thread.
It reuses the shared `core-ui` highlight helper authored by AND-151 rather than
forking it.

It does **not** own: the in-conversation scoped search (AND-151), the Thread
screen / message list it deep-links into (AND-123), the messaging transport
conventions (AND-120), cookie/CSRF/refresh plumbing (AND-011/012/013), or the
`ApiResult`/`detail` mapping primitives (AND-018/AND-015) — those are reused.

## 2. Context & References

- **Repo / location:** `spannella/testlogon`, monorepo subfolder `android/`,
  branch `android-port`. Namespace `com.testlogon.android` everywhere. UI lives in
  **`feature-messaging`** (`com.testlogon.android.feature.messaging.search`);
  endpoint + DTOs in **`core-network`** / **`core-model`**
  (`...core.network.messaging`, `...core.model.messaging`); repository in
  **`core-data`**; the highlight helper is reused from **`core-ui`**.
- **Depends on AND-120 (Messaging API + DTOs):** the backlog-named dependency.
  AND-152 follows AND-120's transport conventions verbatim (relative paths with no
  leading slash, `suspend` methods returning DTO bodies, the
  `{ items, next_cursor }` cursor envelope, Moshi `@JsonClass(generateAdapter =
  true)` DTOs with snake_case `@Json(name=...)`, and the shared Retrofit/Hilt
  provider). The `MessageSearchResultItem`/result-item shape reuses `MessageDto`
  field conventions where they overlap.
- **Sibling AND-151 (In-conversation search):** owns the *scoped*
  `GET /conversations/{id}/messages/search`, the debounced-query controller
  pattern, and `core-ui/text/SearchHighlight.kt`. AND-152 **consumes** the
  `core-ui` highlight helper and mirrors the 300 ms debounce / ≥2-char rules; it
  does not re-author them. The two endpoints and screens are independent.
- **Deep-links into AND-123 (Thread screen):** tapping a result navigates to the
  thread route with the conversation id + a target message id so AND-123 scrolls
  to (and pulses) that message. AND-123 owns the actual scroll/jump; this ticket
  passes the target via the navigation argument contract (Q-3).
- **Paging precedent — AND-098 / AND-122:** reuse the Paging 3 `PagingSource` +
  `Pager` + `cachedIn(viewModelScope)` + `LoadState` mapping conventions. Do not
  fork them.
- **Web reference:** `frontend/src/api/endpoints/messaging.ts` (global search call)
  and `frontend/src/api/types.ts` (`MessageSearchResult`) are the source of truth
  for field names; the request filter names (`sender` vs `sender_id`, `after`
  date format) are reconciled against these and `/openapi.json` (Q-1/Q-2).
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` is
  plaintext and unreliable (~20s timeouts; bounded backoff for idempotent GETs —
  AND-009/AND-016). OpenAPI at `/openapi.json`. Search is an idempotent GET → it
  is retry-eligible.
- **Auth:** cookie session + `ui_csrf` → `X-CSRF-Token` (AND-011/012); a `401`
  triggers AND-013 refresh-then-retry once. The endpoint is header-agnostic.

## 3. Functional Requirements

FR-1. **Entry point.** A "Search messages" action (magnifier icon,
`contentDescription = R.string.search_messages`) in the conversation-list
(inbox) top app bar (AND-121) navigates to the global-search route. The route is
also directly addressable (`messaging/search`).

FR-2. **Query input.** A single-line search field is focused on entry (IME shown).
Input is trimmed and debounced 300 ms before any network call. Blank or <2-char
queries clear results, issue no call, and show an inline hint
(`R.string.search_min_chars`, "Type at least 2 characters").

FR-3. **Sender filter (optional).** A `sender` filter narrows results to messages
from a chosen participant/username. Surfaced as a filter chip that opens a small
picker (free-text username field for v1; participant autocomplete is out of scope
— Q-4). A set sender filter is shown as a removable assist chip and is sent as the
`sender` query param.

FR-4. **After filter (optional).** An `after` date filter restricts results to
messages created on/after a chosen date. Surfaced as a date-picker chip
(Material 3 `DatePicker`). The selected date is sent as an ISO-8601 date/datetime
query param (`after`, format reconciled per Q-2). A removable chip shows the
active value.

FR-5. **Filter composition.** `q`, `sender`, and `after` compose: changing any of
them (after debounce for `q`; immediately for filter chips) re-issues the search
from the first page. Active filters are reflected in chip state and persisted
across config change (FR-11).

FR-6. **Cross-conversation results.** Results span every conversation the user
participates in. Each result item shows: the conversation title (or participant
names when untitled), the sender username + avatar, the matched message body with
the query substring(s) highlighted (reusing `core-ui` `highlightMatches`), and a
locale-formatted timestamp. Results are ordered most-recent-first (Q-2 confirms
ordering).

FR-7. **Paging.** Results are cursor-paged (`{ items, next_cursor }`) via Paging 3.
The list lazily loads further pages on scroll; `next_cursor == null` denotes
end-of-results. A footer renders append loading/error (retry) using the AND-098
`LoadState` mapping.

FR-8. **Empty / loading / error states.** Distinct states: initial idle (no query
yet → prompt), loading (spinner), loaded-empty ("No messages match"), error
(retryable), and offline. These reuse `core-ui` state composables (AND-021).

FR-9. **Open result.** Tapping a result navigates to the Thread screen (AND-123)
for that result's `conversation_id`, passing the result's `message_id` as the
scroll target so the thread opens scrolled to (and momentarily emphasizing) the
matched message. Back returns to the search screen with query, filters, scroll
position, and results intact.

FR-10. **Dismissal.** A back/close affordance returns to the inbox. Clearing the
query (the field's clear "X") resets to the idle prompt and clears filters per
Q-4 default (clear query only; filters persist unless explicitly removed).

FR-11. **Persistence across config change.** `query`, `sender`, and `after` survive
rotation / light process death via `SavedStateHandle`. Paging data is re-fetched
on restore (Paging 3 cache is `viewModelScope`-bound, not persisted).

## 4. Technical Design

### Module & files

```
feature-messaging/
  search/
    GlobalSearchRoute.kt          // NavGraphBuilder ext + nav arguments
    GlobalSearchScreen.kt         // input bar + filter chips + results list
    GlobalSearchUiState.kt
    GlobalSearchViewModel.kt
    SearchResultRow.kt            // single result item composable
core-network/messaging/
    MessageSearchApi.kt
core-model/messaging/
    MessageSearchPageDto.kt       // { items, next_cursor }
    MessageSearchResultDto.kt
core-data/messaging/
    GlobalSearchRepository.kt
    GlobalSearchPagingSource.kt
```

### 4.1 UI state

```kotlin
package com.testlogon.android.feature.messaging.search

data class GlobalSearchUiState(
    val query: String = "",
    val sender: String? = null,          // username filter, null = any sender
    val after: java.time.LocalDate? = null, // date floor, null = no floor
    val phase: Phase = Phase.Idle,       // non-paging screen status
) {
    val hasActiveFilters: Boolean get() = sender != null || after != null
    val isQueryValid: Boolean get() = query.trim().length >= 2

    sealed interface Phase {
        data object Idle : Phase             // no query yet -> prompt
        data object TooShort : Phase         // 1-char / blank after edit
        data object Searching : Phase        // initial load in flight
        data object Results : Phase          // ≥1 result; paging drives the list
        data object Empty : Phase            // loaded, zero results
        data object Offline : Phase
        data class Error(val message: String) : Phase
    }
}
```

`GlobalSearchUiState` carries only the *screen-level* status; the result rows
themselves flow through `PagingData` (single source of truth for list content),
mirroring AND-122.

### 4.2 Result domain model (`core-model`)

```kotlin
package com.testlogon.android.core.model.messaging

data class MessageSearchResultItem(
    val messageId: String,
    val conversationId: String,
    val conversationTitle: String?,   // null -> derive from participants
    val senderId: String,
    val senderUsername: String,
    val senderAvatarUrl: String?,
    val body: String,
    val createdAt: java.time.Instant,
)
```

### 4.3 ViewModel

```kotlin
@HiltViewModel
class GlobalSearchViewModel @Inject constructor(
    private val repository: GlobalSearchRepository,
    private val saved: SavedStateHandle,
) : ViewModel() {

    val uiState: StateFlow<GlobalSearchUiState>

    /** Paged, cross-conversation results for the current (debounced) query+filters. */
    val results: Flow<PagingData<MessageSearchResultItem>>

    fun onQueryChange(raw: String)             // updates query + restarts debounce
    fun onSenderChange(sender: String?)        // re-search immediately
    fun onAfterChange(after: LocalDate?)        // re-search immediately
    fun clearFilters()
    fun retry()                                // re-issue current query/filters

    @OptIn(FlowPreview::class, ExperimentalCoroutinesApi::class)
    private val criteria: StateFlow<SearchCriteria> // (query, sender, after)
    // criteria.debounce(QUERY?300:0).distinctUntilChanged()
    //   .filter { it.query.trim().length >= 2 }
    //   .flatMapLatest { repository.pager(it).flow }
    //   .cachedIn(viewModelScope)
}

internal data class SearchCriteria(
    val query: String,
    val sender: String?,
    val after: LocalDate?,
)
```

Only the *query* leg of `criteria` is debounced (300 ms); filter-chip changes are
applied immediately. `flatMapLatest` cancels stale searches so only the newest
criteria's `PagingData` is emitted. `query`/`sender`/`after` are read from and
written to `SavedStateHandle` (`search_query`, `search_sender`, `search_after`).

### 4.4 Repository + PagingSource (`core-data`)

```kotlin
class GlobalSearchRepository @Inject constructor(
    private val api: MessageSearchApi,
    @IoDispatcher private val io: CoroutineDispatcher,
) {
    fun pager(criteria: SearchCriteria): Pager<String, MessageSearchResultItem> =
        Pager(PagingConfig(pageSize = 30, enablePlaceholders = false)) {
            GlobalSearchPagingSource(api, criteria, io)
        }

    /** One-shot non-paged search used by unit tests / count checks. */
    suspend fun searchFirstPage(c: SearchCriteria): ApiResult<MessageSearchPageDto> =
        safeApiCall(io) {
            api.search(q = c.query.trim(), sender = c.sender,
                       after = c.after?.toString(), cursor = null, limit = 30)
        }
}
```

```kotlin
class GlobalSearchPagingSource(
    private val api: MessageSearchApi,
    private val criteria: SearchCriteria,
    private val io: CoroutineDispatcher,
) : PagingSource<String, MessageSearchResultItem>() {

    override suspend fun load(
        params: LoadParams<String>,
    ): LoadResult<String, MessageSearchResultItem> = withContext(io) {
        try {
            val page = api.search(
                q = criteria.query.trim(),
                sender = criteria.sender,
                after = criteria.after?.toString(),
                cursor = params.key,
                limit = params.loadSize,
            )
            LoadResult.Page(
                data = page.items.map { it.toItem() },
                prevKey = null,                     // forward-only
                nextKey = page.nextCursor,          // null -> end of results
            )
        } catch (e: Exception) {
            LoadResult.Error(e)
        }
    }

    override fun getRefreshKey(state: PagingState<String, MessageSearchResultItem>) = null
}
```

`MessageSearchResultDto.toItem()` lives in `core-data` mappers (converts
`created_at` ISO-8601 `String` → `Instant`, derives a display title from
participants when `conversation_title` is null).

### 4.5 Endpoint (`core-network`)

```kotlin
interface MessageSearchApi {
    /** Cross-conversation message search. Idempotent GET. */
    @GET("messaging/messages/search")
    suspend fun search(
        @Query("q") q: String,
        @Query("sender") sender: String? = null,
        @Query("after") after: String? = null,   // ISO-8601 date or datetime
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): MessageSearchPageDto
}
```

Provided by a Hilt `@Provides @Singleton fun provideMessageSearchApi(retrofit:
Retrofit): MessageSearchApi = retrofit.create(...)` on the shared Retrofit
(AND-010) — no new client. Path prefix (`messaging/` vs root) reconciled per Q-1.

### 4.6 Navigation

`GlobalSearchRoute.kt` registers `composable("messaging/search")` and provides the
deep-link into the thread by reusing AND-123's thread route argument contract:

```kotlin
fun NavController.openSearchResult(item: MessageSearchResultItem) =
    navigate("messaging/thread/${item.conversationId}?focusMessageId=${item.messageId}")
```

The `focusMessageId` optional argument is consumed by AND-123 to scroll-to/pulse
the target message (Q-3 confirms the argument name with AND-123).

## 5. API Contract

Base (`dev`): `http://18.222.237.167:8000/`. Path uses the assumed `messaging/`
prefix (confirm per Q-1, consistent with AND-120).

### GET `messaging/messages/search`

Query params: `q` (required, trimmed, ≥2 chars), `sender` (optional username/id —
Q-4), `after` (optional ISO-8601 — Q-2), `cursor` (optional opaque), `limit`
(optional, default 30). `q`/`sender` are URL-encoded by Retrofit `@Query`.

Example request:
```
GET messaging/messages/search?q=deploy&sender=alice&after=2026-05-01&limit=30
Cookies: session + ui_csrf
```

Response `200`:
```json
{
  "items": [
    {
      "message_id": "msg_0001",
      "conversation_id": "conv_01HZ",
      "conversation_title": null,
      "sender_id": "usr_1",
      "sender_username": "alice",
      "sender_avatar_url": null,
      "body": "we deploy to prod after the deploy freeze",
      "created_at": "2026-05-02T18:21:00Z",
      "participants": [
        { "user_id": "usr_1", "username": "alice", "avatar_url": null },
        { "user_id": "usr_2", "username": "bob", "avatar_url": "https://.../b.png" }
      ]
    }
  ],
  "next_cursor": "eyJvIjozMH0="
}
```
`next_cursor` is `null` on the last page. `participants` (when present) lets the
client derive a display title for untitled conversations; if the backend instead
returns only `conversation_title`, the `participants` field is omitted and the row
shows the title verbatim (Q-2).

DTOs (`core-model`, Moshi codegen):
```kotlin
@JsonClass(generateAdapter = true)
data class MessageSearchPageDto(
    @Json(name = "items") val items: List<MessageSearchResultDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class MessageSearchResultDto(
    @Json(name = "message_id") val messageId: String,
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "conversation_title") val conversationTitle: String? = null,
    @Json(name = "sender_id") val senderId: String,
    @Json(name = "sender_username") val senderUsername: String,
    @Json(name = "sender_avatar_url") val senderAvatarUrl: String? = null,
    @Json(name = "body") val body: String,
    @Json(name = "created_at") val createdAt: String,   // ISO-8601 UTC
    @Json(name = "participants") val participants: List<ParticipantDto> = emptyList(),
)
```
`ParticipantDto` is reused from AND-120.

**Error envelope:** FastAPI `detail` union (`string | [{msg,type,loc}] |
{code,...}`). The call is wrapped by `safeApiCall` → `ApiResult` (AND-018) and the
`detail` mapping (AND-015). `401` → AND-013 refresh-then-retry once; `422` (bad
query/filter) → inline hint; `404`/`5xx`/IO → retryable error state.

## 6. Data & State Management

- **No persistence.** Search results are transient and are **not** written to Room
  or DataStore. Result rows live only in the `viewModelScope`-cached `PagingData`.
- **SavedStateHandle (config-change survival):** `search_query` (String),
  `search_sender` (String?), `search_after` (epoch-day Long?). Paging data is not
  saved; on restore the `criteria` flow re-emits and Paging 3 re-fetches.
- **Single source of truth:** result list content = `PagingData`; screen status =
  `GlobalSearchUiState.phase` derived from `LoadState` (initial `Loading` →
  `Searching`; `NotLoading` with `itemCount == 0` → `Empty`; with items →
  `Results`; `Error` → `Error`/`Offline`), mirroring AND-122's mapping.
- **Cursor paging contract:** `{ items, next_cursor }` is the unit of paging
  (AND-120 envelope). `next_cursor` → `LoadResult.nextKey`; `null` → end-of-list;
  forward-only (`prevKey = null`).
- **Filter composition:** `criteria = (query, sender, after)`; any change rebuilds
  the `Pager` (new `PagingSource`) so the list restarts at page 1.
- **Session state** (cookies/CSRF) is owned by AND-011/012; this layer is unaware.
- **Threading:** API calls run on the injected IO dispatcher; the ViewModel exposes
  flows collected on the main dispatcher by Compose.

## 7. Error Handling & Resilience

- **Timeouts:** the unreliable dev host uses the project-wide ~20s call timeout
  (AND-009); a spinner shows while `phase == Searching` / append `LoadState.Loading`.
- **Retry (idempotent GET):** the search GET is eligible for AND-016 bounded
  backoff (max 2 jittered retries on timeout/5xx/IOException). Initial-load failure
  → `Phase.Error`/`Phase.Offline` with a retry affordance (`retry()` re-issues the
  current criteria → `PagingSource.invalidate()`); append failure → footer retry
  via Paging's `retry()`.
- **flatMapLatest cancellation:** rapid typing / quick filter toggles cancel the
  in-flight search; only the newest criteria's `PagingData` is applied (no stale
  counts or flicker).
- **Empty results:** `LoadState.NotLoading` + `itemCount == 0` → `Phase.Empty`
  ("No messages match") — not an error.
- **`422` bad query/filter** (e.g. malformed `after`) → mapped to inline hint, not
  a full-screen error; the offending filter chip is flagged.
- **`401`** → AND-013 `Authenticator` refreshes once and retries; a terminal second
  `401` routes to login (AND-025).
- **Deep-link target missing:** if the tapped result's message is unreachable in the
  thread (deleted / too far back), AND-123 handles the fallback (it owns the jump);
  AND-152 only passes a valid `conversationId` + `focusMessageId`.
- **Offline:** treated as a retryable error; there is no cached/offline search.

## 8. Security & Privacy

- **Authenticated surface:** the endpoint requires an active cookie session and is
  server-scoped to the caller's conversations — the backend never returns messages
  from conversations the user does not participate in (no client-side trust).
- **Cleartext on dev:** queries and matched message bodies (which may contain
  personal content) ride plaintext HTTP on the `dev` host — a known dev-only risk
  permitted by the scoped cleartext config (AND-006); `staging`/`prod` are
  HTTPS-only.
- **No PII at rest / in logs:** the raw query string, `sender` filter value, and
  result bodies are **never** persisted to disk/DataStore and **never** logged
  (Section 10 logs query *length* only). Query/filter state lives in memory +
  `SavedStateHandle` (in-process bundle).
- **Injection-safe:** `q`/`sender` are sent as URL query params (Retrofit encodes);
  local highlight matching reuses the `core-ui` literal-substring matcher (no regex
  compilation of user input → no ReDoS).
- **CSRF/cookies** delegated to AND-011/012; no manual `Cookie`/`Authorization`
  headers declared.

## 9. Accessibility & i18n

- All controls have `contentDescription`: search field, clear-query ("Clear
  search"), sender filter chip, after/date chip, each removable chip's remove
  affordance, and the back/close action.
- Result count / status (`Phase.Empty`, `Searching`, result totals) is announced via
  `liveRegion = LiveRegionMode.Polite` so screen-reader users hear state changes.
- Highlight emphasis does not rely on color alone: matched substrings get a subtle
  bold weight in addition to the highlight background; `matchBg` meets WCAG AA
  contrast against body text in both light and dark Material 3 themes (the shared
  `core-ui` helper already enforces this for AND-151).
- Result rows are a single focusable, clickable target with a `role = Button`
  semantic and an accessible label combining sender, conversation, and snippet;
  touch targets (chips, clear, nav) ≥ 48dp.
- All user-facing strings (hints, empty/error copy, content descriptions, chip
  labels) are `stringResource` in `feature-messaging` `strings.xml`; result counts
  use `R.plurals.search_results`. Timestamps are formatted locale-aware from the
  `Instant` (the wire value is ISO-8601 UTC); date-filter picker respects the device
  locale. No hardcoded strings.

## 10. Telemetry & Logging

- **Events** (project analytics interface, no PII): `global_search_opened`,
  `global_search_executed { query_length, has_sender_filter, has_after_filter,
  result_count, latency_ms }`, `global_search_result_opened { position }`,
  `global_search_page_loaded { page_index }`, `global_search_error { reason }`,
  `global_search_closed`. **The raw query and `sender` value are never logged** —
  only `query_length` and boolean filter-presence flags.
- **Logging:** debug-only `Timber.d` for phase / `LoadState` transitions; query and
  body content redacted at all levels (inherits AND-009's redacting interceptor —
  message content must not reach logcat in release).
- **Metrics of interest:** search latency / retry rate on the unreliable host,
  empty-result rate (relevance signal), and result-open rate (validates the "opens
  results" acceptance bullet).

## 11. Testing Strategy

**Unit (JVM, JUnit + Turbine + coroutines-test):**
- `GlobalSearchViewModel`: query debounce coalesces rapid input to one search;
  `<2` chars → `Phase.TooShort` and no call; setting/removing `sender`/`after`
  re-issues from page 1; `flatMapLatest` drops stale results (only newest criteria
  applied); `clearFilters()` resets chips and re-searches; `query`/`sender`/`after`
  round-trip through `SavedStateHandle`.
- `GlobalSearchPagingSource`: first `load` returns a `LoadResult.Page` with
  `nextKey = next_cursor`; a subsequent `load(key=cursor)` forwards the cursor in
  the request; `next_cursor: null` → `nextKey == null` (end); an exception →
  `LoadResult.Error`. Assert `q`/`sender`/`after`/`cursor`/`limit` query params via
  MockWebServer `takeRequest()`.
- `MessageSearchResultDto.toItem()`: `created_at` parses to `Instant`; null
  `conversation_title` derives a title from `participants`; null avatar tolerated.
- DTO Moshi round-trip vs captured fixture (AND-046): paged envelope decodes;
  unknown keys ignored; absent optionals default; `next_cursor: null` → `null`.
- Error mapping: `422` → inline hint; `404`/`5xx` → retryable error; `401` path
  delegates to the authenticator (covered by core-network, asserted via
  MockWebServer 401-then-200 retry).

**API contract (MockWebServer, `core-network`):**
- `GET messaging/messages/search?q=deploy&sender=alice&after=2026-05-01&limit=30`:
  assert verb, resolved path, and every query param; decode `MessageSearchPageDto`
  from `messaging/messages_search_page.json` fixture; assert cross-conversation
  items (≥2 distinct `conversation_id`s) and `next_cursor`.

**Instrumented / Compose UI (`feature-messaging`):**
- Typing a known term renders matching rows from multiple conversations and the
  highlighted substring (assert highlight semantics). *(maps to acceptance:
  "Cross-conversation search returns")*
- Tapping a result navigates to the thread route with the correct
  `conversationId` + `focusMessageId` argument (assert nav args via a
  `TestNavHostController`). *(maps to acceptance: "opens results")*
- Empty query → idle prompt, no call; `<2` chars → hint.
- Setting a sender chip then an after chip re-issues the search and shows the active
  chips; removing a chip re-searches.
- Empty / error / offline states render the correct `core-ui` state composable;
  error retry re-issues the search.
- Rotation preserves query + filters.

**Fakes:** `FakeMessageSearchApi` returns deterministic fixtures (multi-conversation
page, second page via cursor, empty, error). MockWebServer covers retry / timeout /
401-refresh integration.

Coverage target: ≥85% on the new ViewModel/repository/PagingSource/DTO surface; the
nav-args assertion explicitly covers the "opens results" bullet.

## 12. Dependencies & Sequencing

**Hard upstream (must merge first):**
- **AND-120 (Messaging API + DTOs)** — backlog-named dependency; supplies the
  transport conventions, the `{ items, next_cursor }` cursor envelope, `ParticipantDto`,
  and the shared Retrofit/Hilt provider this ticket extends.

**Effective upstream (reused, normally landed before M3 messaging UI):**
- **AND-098 / AND-122** — Paging 3 `PagingSource`/`Pager`/`LoadState` conventions.
- **AND-151** — authors `core-ui/text/SearchHighlight.kt` and the debounce/≥2-char
  pattern reused here. If AND-151 has not merged, the highlight helper must be
  promoted to `core-ui` as part of this ticket and AND-151 then consumes it
  (coordinate to avoid a fork).
- **AND-123** — Thread screen + `focusMessageId` scroll-to argument the deep-link
  targets; the nav-argument name is confirmed with AND-123 (Q-3).
- **AND-018 / AND-015** — `ApiResult`/`safeApiCall` + FastAPI `detail` mapping.
- **AND-021** — `core-ui` loading/empty/error/offline state composables.
- **AND-009 / AND-016** — timeouts + bounded backoff for the idempotent search GET.
- **AND-046** — MockWebServer harness + fixture loader for the tests.

**Downstream (blocked by this ticket):** none (`blocks: []`).

**Sequencing within the ticket:** (1) confirm path prefix / param names / `after`
format / ordering against `/openapi.json` + web reference and capture fixtures
(AND-046); (2) `core-model` DTOs + `MessageSearchResultItem`; (3) `MessageSearchApi`
+ Hilt provider + MockWebServer contract test; (4) `GlobalSearchRepository` +
`GlobalSearchPagingSource` + mappers + tests; (5) `GlobalSearchViewModel` +
debounce/filter/SavedState + unit tests; (6) `GlobalSearchScreen` + chips + result
rows + nav route + deep-link; (7) Compose UI / instrumented tests.

## 13. Risks & Open Questions

- **R-1 Route prefix / param names.** The backlog lists `/messaging/messages/search`;
  the assumed `messaging/` prefix and the filter param names (`sender`, `after`)
  must match the live backend. Mitigation: reconcile against `/openapi.json` + web
  reference before coding; path/param assertions catch drift. (Q-1)
- **R-2 `sender` filter semantics.** `sender` may expect a username, a user id, or a
  participant id; v1 sends free text. Mitigation: confirm via OpenAPI; if id-based,
  add a participant picker that resolves username → id. (Q-4)
- **R-3 `after` date format.** Date-only vs datetime, inclusive vs exclusive,
  timezone handling. Mitigation: confirm format; send ISO-8601 and let the backend
  define inclusivity; tests pin the chosen format. (Q-2)
- **R-4 Result envelope shape.** The endpoint may return a bare array, a different
  page envelope, or offset/limit instead of cursor. Mitigation: inspect web
  reference; the assumed `{items,next_cursor}` (AND-120) is guarded by the contract
  test; only the DTO/PagingSource changes if it differs.
- **R-5 Deep-link contract with AND-123.** The `focusMessageId` argument name /
  scroll behavior is owned by AND-123. Mitigation: agree the nav-arg contract during
  grooming; this ticket only passes `conversationId` + target id. (Q-3)
- **R-6 Large/common-term result volume + relevance ordering.** Very common terms
  could return huge result sets; paging bounds memory, but ordering (recency vs
  relevance score) affects UX. Mitigation: confirm backend ordering; default to
  recency. (Q-2)
- **Q-1** Is the route `messaging/messages/search` (assumed) or root
  `messages/search`? *Proposed:* match `/openapi.json`; spec assumes `messaging/`.
- **Q-2** Exact `after` format/inclusivity and result ordering? *Proposed:* ISO-8601,
  server-defined inclusivity, recency-desc order — confirm before coding.
- **Q-3** What nav-argument does AND-123 consume to scroll-to a message
  (`focusMessageId`?)? *Proposed:* align with AND-123's thread route.
- **Q-4** Does `sender` take a username or id, and does clearing the query also clear
  filters? *Proposed:* username free-text for v1; clearing query keeps filters until
  explicitly removed.

## 14. Acceptance Criteria

- **AC-1 (backlog).** Entering a ≥2-char query calls
  `GET messaging/messages/search?q=...` and renders matching messages drawn from
  **more than one conversation** (cross-conversation), with the query substring
  highlighted in each result. *(maps to "Cross-conversation search returns")*
- **AC-2 (backlog).** Tapping a result navigates to the Thread screen (AND-123) for
  that result's `conversation_id`, passing the result's `message_id` as the scroll
  target. *(maps to "opens results")*
- **AC-3 (filters).** The `sender` filter sends `&sender=<value>` and the `after`
  filter sends `&after=<iso>`; both are reflected as removable chips, compose with
  `q`, and re-issue the search from page 1.
- **AC-4 (paging).** Results are cursor-paged via Paging 3; scrolling loads further
  pages; `next_cursor: null` ends the list; append errors show a footer retry.
- **AC-5 (states).** Distinct idle-prompt / `<2`-char hint / loading / empty
  ("No messages match") / error (retryable) / offline states render via the
  `core-ui` state composables.
- **AC-6 (debounce + cancellation).** Rapid typing issues a single search for the
  settled query; stale responses never overwrite newer ones (`flatMapLatest`).
- **AC-7 (DTO mapping).** The `{items,next_cursor}` envelope and snake_case result
  fields decode via Moshi codegen vs captured fixtures; unknown keys ignored;
  absent optionals default; `next_cursor: null` → Kotlin `null`.
- **AC-8 (resilience).** The idempotent search GET retries with bounded backoff on
  transient failure; a `401` triggers exactly one session refresh + retry; `422`
  maps to an inline hint.
- **AC-9 (persistence).** `query`, `sender`, and `after` survive rotation.
- **AC-10 (privacy).** No raw query/sender/body text appears in logs or telemetry
  (length + boolean flags only); nothing is persisted to disk.
- **AC-11 (build/quality).** `feature-messaging`, `core-network`, `core-model`,
  `core-data` build clean under AGP 8.7.3 / Gradle 8.9 / JDK 17 with KSP adapters
  present; all unit + Compose tests pass in CI; no new lint/detekt violations
  (AND-005).

## 15. Definition of Done

- All §14 acceptance criteria pass.
- `MessageSearchApi` + provider (`core-network`), DTOs + `MessageSearchResultItem`
  (`core-model`), `GlobalSearchRepository` + `GlobalSearchPagingSource` + mappers
  (`core-data`), and `GlobalSearchViewModel` + `GlobalSearchScreen` + route +
  deep-link (`feature-messaging`) are implemented under `com.testlogon.android`,
  reusing AND-120's envelope/`ParticipantDto`, the shared Retrofit (AND-010), the
  `core-ui` highlight helper, and the AND-098/122 Paging conventions — nothing
  forked.
- Open questions Q-1..Q-4 resolved against `/openapi.json` and the web reference;
  the route path, `sender`/`after` param names + format, result ordering, and the
  thread deep-link argument reflect the confirmed contract.
- JSON fixtures captured (via AND-046) for a multi-conversation results page, a
  cursor second page, and an empty page, matching live backend shapes.
- Unit, MockWebServer contract, and Compose/instrumented tests from §11 implemented
  and green in CI (≥85% on the new surface); the nav-args assertion explicitly
  covers the "opens results" acceptance bullet, and the multi-conversation UI test
  covers "cross-conversation search returns".
- No second `OkHttpClient`/`Retrofit`; no manual cookie/CSRF/auth headers; message
  bodies and query/sender values treated as sensitive — never logged in release,
  never persisted (verified in review).
- All strings localized (incl. result-count plurals); accessibility checks (content
  descriptions, polite live region, ≥48dp targets, AA contrast) pass.
- `./gradlew :core-model:testDebugUnitTest :core-network:testDebugUnitTest
  :core-data:testDebugUnitTest :feature-messaging:assemble
  :feature-messaging:testDebugUnitTest` passes locally and in CI with no new
  lint/detekt violations (AND-005).
- Code reviewed and merged to `android-port`; a one-line note in the
  `feature-messaging` README (AND-007) records the global-search route, the
  `messaging/messages/search` path/params, and reuse of the `core-ui` highlight
  helper (shared with AND-151).
