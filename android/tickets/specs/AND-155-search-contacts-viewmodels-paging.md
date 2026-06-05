---
id: AND-155
title: Search/contacts ViewModels + paging
milestone: M3
epic: E21
priority: P1
size: M
status: draft
depends_on: [AND-152, AND-153]
blocks: [AND-156]
---

# AND-155 — Search/contacts ViewModels + paging

## 1. Overview & Goal

AND-152 (global message search) and AND-153 (contacts list + search) introduced
the search/contacts feature surfaces and their thin Retrofit endpoints, but each
landed with ad-hoc state holding wired directly into Compose. This ticket
extracts and hardens the **state-management layer** for both surfaces: two
`ViewModel`s that own debounced query input, cursor-backed Paging 3 streams,
loading/empty/error UI states, and reactive re-querying when the search term
changes.

The goal is a single, unit-tested behavioral contract for "type a query → see
paged results, with proper debounce, empty, and error handling" shared in spirit
across message search and contacts search. Concretely this ticket delivers
`MessageSearchViewModel` and `ContactSearchViewModel` in `feature-search`, the
`PagingSource`/`Pager` plumbing in `core-data`, the `UiState` types, and a full
unit-test suite (Turbine + coroutine-test) proving debounce, paging, and
empty-state semantics. UI composition is **not** owned here (it stays in AND-152
/ AND-153); this ticket owns only the ViewModels, paging infrastructure, and
their tests, which then unblock the dedicated test pass in AND-156.

Done means: typing in the search field debounces input, the resulting
`PagingData` flows update the list, distinct empty/loading/error states are
surfaced deterministically, and `./gradlew :feature-search:testDebugUnitTest`
passes with coverage of the debounce/paging/empty paths.

## 2. Context & References

- **Repo:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`.
- **Namespace / applicationId base:** `com.testlogon.android`. Feature package:
  `com.testlogon.android.feature.search`. Paging in
  `com.testlogon.android.core.data.search`.
- **Module layering:** `app -> feature-search -> core-data -> core-network ->
  core-model`; `core-ui`, `core-testing` consumed where relevant. ViewModels
  expose `StateFlow<UiState>` and `Flow<PagingData<T>>`; repositories return
  typed `ApiResult<T>` for non-paged calls.
- **Upstream deps:**
  - **AND-152** — `MessageSearchApi.search(...)` over
    `GET /messaging/messages/search` with `sender`/`after` filters and the
    results screen Composable.
  - **AND-153** — `ContactsApi.search(...)` over
    `GET /messaging/contacts/search` (server-side name tokenization) and the
    contacts screen Composable.
- **Downstream:** **AND-154** (contact → start conversation) consumes
  `ContactUiModel` selection events; **AND-156** owns the broader repo + UI test
  matrix and depends on the unit tests delivered here.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext, unreliable). OpenAPI at `/openapi.json`. Web reference:
  `frontend/src/api/endpoints/messaging.ts`, `frontend/src/api/types.ts`.
  Auth is cookie-based with the `X-CSRF-Token` echo and a single
  `POST /ui/session/refresh` retry on 401 (handled by the shared OkHttp
  authenticator from AND-12x; not re-implemented here).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  Paging 3, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15. minSdk 24, compileSdk/
  targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.

## 3. Functional Requirements

FR-1 **Debounced query.** Both ViewModels expose `onQueryChange(query: String)`.
Input is debounced 300 ms and de-duplicated (`distinctUntilChanged`); a query is
considered "active" only after `trim()` yields length ≥ 2. Queries of length 0–1
clear results to the **Idle** state without hitting the network.

FR-2 **Reactive paging.** A debounced, qualifying query produces a new
`Flow<PagingData<T>>` via Paging 3 (`flatMapLatest` so a newer query cancels the
older stream). The list is cursor-paged using the backend's `next_cursor`.

FR-3 **Message search filters.** `MessageSearchViewModel` additionally holds
optional `sender: String?` and `after: Instant?` filters. Changing a filter
re-triggers the active query (subject to the same debounce gate). Filters are
passed through to `GET /messaging/messages/search`.

FR-4 **Empty states.** Three terminal "no rows" conditions are distinguished:
**Idle** (query too short / never searched), **Empty** (qualifying query, 0
results returned), and **Error** (query failed). These are derived from
`CombinedLoadStates` + item count and exposed on the `UiState`.

FR-5 **Loading states.** Initial-load and append (footer) loading are surfaced
distinctly so the UI can show a full-screen spinner vs. a footer spinner.

FR-6 **Retry.** `retry()` re-runs the current Paging request (`LoadState.Error`
recovery) without re-typing the query.

FR-7 **Selection events (one-shot).** `ContactSearchViewModel` exposes a
`Flow<ContactSelected>` (via `Channel`) so AND-154 can navigate to a DM;
`MessageSearchViewModel` exposes `Flow<MessageResultSelected>` to open the source
conversation at the matched message. These are events, not state.

FR-8 **Query persistence across config change.** The active query and filters
survive rotation via `SavedStateHandle`.

## 4. Technical Design

### 4.1 UiState

```kotlin
package com.testlogon.android.feature.search

data class MessageSearchUiState(
    val query: String = "",
    val sender: String? = null,
    val after: Instant? = null,
    val listState: SearchListState = SearchListState.Idle,
)

data class ContactSearchUiState(
    val query: String = "",
    val listState: SearchListState = SearchListState.Idle,
)

enum class SearchListState { Idle, Loading, Content, Empty, Error }
```

`SearchListState` is *derived* from Paging `loadState` + `itemCount` in the UI
layer's collector, but the ViewModel publishes a coarse mirror (Idle vs.
Active) so non-paging logic (e.g., short query) stays testable without a
recyclerview. The fine-grained `Loading/Content/Empty/Error` mapping is provided
as a pure helper that AND-156 can unit-test:

```kotlin
fun resolveListState(
    isQueryActive: Boolean,
    loadStates: CombinedLoadStates,
    itemCount: Int,
): SearchListState
```

### 4.2 ViewModels

```kotlin
@HiltViewModel
class MessageSearchViewModel @Inject constructor(
    private val repo: MessageSearchRepository,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val queryInput = MutableStateFlow(savedState.get<String>(KEY_Q).orEmpty())
    private val filters = MutableStateFlow(SearchFilters())

    val uiState: StateFlow<MessageSearchUiState>

    @OptIn(FlowPreview::class, ExperimentalCoroutinesApi::class)
    val pagingData: Flow<PagingData<MessageResultUiModel>> =
        combine(queryInput, filters) { q, f -> q.trim() to f }
            .debounce(DEBOUNCE_MS)
            .distinctUntilChanged()
            .flatMapLatest { (q, f) ->
                if (q.length < MIN_QUERY_LEN) flowOf(PagingData.empty())
                else repo.searchMessages(q, f.sender, f.after)
            }
            .cachedIn(viewModelScope)

    fun onQueryChange(query: String) { queryInput.value = query; savedState[KEY_Q] = query }
    fun onSenderFilter(sender: String?) { filters.update { it.copy(sender = sender) } }
    fun onAfterFilter(after: Instant?) { filters.update { it.copy(after = after) } }
    fun onResultClick(result: MessageResultUiModel)  // emits MessageResultSelected

    private val _events = Channel<MessageResultSelected>(Channel.BUFFERED)
    val events: Flow<MessageResultSelected> = _events.receiveAsFlow()

    companion object {
        const val DEBOUNCE_MS = 300L
        const val MIN_QUERY_LEN = 2
        const val PAGE_SIZE = 20
        private const val KEY_Q = "msg_search_query"
    }
}
```

`ContactSearchViewModel` is structurally identical minus filters, emitting
`ContactSelected(contactId, displayName)`.

### 4.3 Paging source (core-data)

```kotlin
package com.testlogon.android.core.data.search

class MessageSearchPagingSource(
    private val api: MessageSearchApi,
    private val query: String,
    private val sender: String?,
    private val after: Instant?,
) : PagingSource<String, MessageResult>() {

    override suspend fun load(
        params: LoadParams<String>,
    ): LoadResult<String, MessageResult> = try {
        val resp = api.search(
            q = query, sender = sender,
            after = after?.toString(), cursor = params.key,
            limit = params.loadSize,
        )
        LoadResult.Page(
            data = resp.items,
            prevKey = null,                 // forward-only cursor paging
            nextKey = resp.nextCursor,
        )
    } catch (e: IOException) {
        LoadResult.Error(e)
    } catch (e: HttpException) {
        LoadResult.Error(e)
    }

    override fun getRefreshKey(state: PagingState<String, MessageResult>) = null
}
```

Repository builds the `Pager`:

```kotlin
class MessageSearchRepository @Inject constructor(
    private val api: MessageSearchApi,
    private val mapper: MessageResultMapper,
) {
    fun searchMessages(q: String, sender: String?, after: Instant?)
        : Flow<PagingData<MessageResultUiModel>> = Pager(
        config = PagingConfig(
            pageSize = 20, prefetchDistance = 5, initialLoadSize = 20,
            enablePlaceholders = false,
        ),
        pagingSourceFactory = { MessageSearchPagingSource(api, q, sender, after) },
    ).flow.map { it.map(mapper::toUi) }
}
```

`ContactSearchPagingSource` / `ContactSearchRepository` mirror this against
`ContactsApi.search`.

### 4.4 DI

A Hilt `@Module` in `core-data` provides the repositories (constructor
injection; module exists only to satisfy `feature-search` boundary). ViewModels
are `@HiltViewModel`. No new network module — `MessageSearchApi`/`ContactsApi`
come from AND-152/AND-153.

### 4.5 Threading

Debounce/flatMapLatest run on `Dispatchers.Default`; network is suspend on the
Retrofit dispatcher. Paging is `cachedIn(viewModelScope)`. A `@TestDispatcher`
override (injected via `core-testing` `MainDispatcherRule`) makes debounce
deterministic in tests via `advanceTimeBy`.

## 5. API Contract

This ticket **consumes** endpoints defined by AND-152/AND-153; it does not add
new endpoints. Shapes (confirm against `/openapi.json`):

`GET /messaging/messages/search`
Query params: `q` (string, required), `sender` (string, optional, user id/
handle), `after` (ISO-8601 instant, optional), `cursor` (string, optional),
`limit` (int, default 20).

```json
{
  "items": [
    {
      "message_id": "m_01H...",
      "conversation_id": "c_01H...",
      "sender_id": "u_42",
      "sender_name": "Ada Lovelace",
      "snippet": "…matched <em>text</em>…",
      "created_at": "2026-05-30T18:22:05Z"
    }
  ],
  "next_cursor": "eyJwayI6..."
}
```

`GET /messaging/contacts/search`
Query params: `q` (string, required, tokenized server-side), `cursor`, `limit`.

```json
{
  "items": [
    { "contact_id": "u_42", "display_name": "Ada Lovelace",
      "handle": "ada", "avatar_url": null, "presence": "offline" }
  ],
  "next_cursor": null
}
```

Retrofit:

```kotlin
@GET("messaging/messages/search")
suspend fun search(
    @Query("q") q: String,
    @Query("sender") sender: String? = null,
    @Query("after") after: String? = null,
    @Query("cursor") cursor: String? = null,
    @Query("limit") limit: Int = 20,
): MessageSearchPageDto
```

`next_cursor == null` (or absent) signals the last page → `nextKey = null`.
Error `detail` follows the shared FastAPI mapping (`string | [{msg}] |
{code,...}`) handled by the existing `ApiResult` adapter; `PagingSource` only
needs the `HttpException`/`IOException` distinction.

## 6. Data & State Management

- **Source of truth:** server. Paging holds the in-memory window; no Room cache
  for search results (results are query-scoped and ephemeral — explicitly out of
  scope, contrast with conversation caching in AND-120).
- **Query/filter state:** `MutableStateFlow` inside the ViewModel, persisted to
  `SavedStateHandle` (`msg_search_query`, plus serialized filters). No DataStore
  (search is not a user preference).
- **Cursor:** opaque `String` from `next_cursor`, passed back as `cursor`.
  Forward-only; `prevKey = null` and `getRefreshKey = null` because a refresh
  restarts from the first page (acceptable for search).
- **Mapping:** `MessageResultMapper` / `ContactMapper` convert DTO → UiModel in
  `core-data`; `created_at`/`after` parsed to `Instant`; `snippet` HTML is
  sanitized to a display `AnnotatedString` spec deferred to the UI ticket — here
  the UiModel carries the raw `snippet` string and a parsed `Instant`.
- **Derived list state:** `resolveListState(...)` maps
  `(isQueryActive, loadState.refresh, itemCount)`:
  Idle when `!isQueryActive`; Loading when `refresh is Loading`; Error when
  `refresh is Error`; Empty when `refresh is NotLoading && itemCount == 0`;
  Content otherwise.

## 7. Error Handling & Resilience

- **Timeouts:** rely on the shared OkHttp client (~20 s connect/read/call) from
  the network module. The dev host is unreliable; a failed initial load lands in
  `LoadState.Error` → `SearchListState.Error` with a retry affordance.
- **Retry policy:** Paging `retry()` is user-initiated (no auto-retry loops).
  Bounded backoff for idempotent GETs is provided by the shared OkHttp
  interceptor; this ticket adds **no** custom retry beyond `retry()`.
- **flatMapLatest cancellation:** a newer query cancels the in-flight older
  query; cancelled loads must not surface errors. Verified by test.
- **401 handling:** delegated to the shared authenticator (single
  `POST /ui/session/refresh` then retry). If refresh fails, the request fails →
  `Error` state; navigation to re-auth is owned by the session layer, not here.
- **Empty vs. error disambiguation:** an HTTP 200 with `items: []` is **Empty**,
  never Error; an `IOException`/non-2xx is **Error**. This distinction is a
  required test case.
- **Append failures:** an append error keeps existing items and exposes a footer
  retry; it never clears the list to a full-screen error.

## 8. Security & Privacy

- No new credentials, tokens, or storage. Search rides the existing cookie jar +
  `X-CSRF-Token` (added by the shared interceptor); this ticket must **not**
  attach auth headers manually.
- Query strings may contain PII (names, message fragments). They are **not**
  logged at INFO. Telemetry records only query **length** and result **count**,
  never query content (see §10).
- `SavedStateHandle` persistence of the active query is in-process Android
  saved-instance-state only; no on-disk persistence of queries.
- `snippet` may contain server-provided markup; it is treated as untrusted text
  and never rendered as HTML/web content in this layer (UiModel holds a plain
  string).

## 9. Accessibility & i18n

UI composition is owned by AND-152/AND-153; this ViewModel/paging ticket has
limited direct a11y surface. Requirements it must enable:

- Empty/Idle/Error states expose distinct, stringresource-backed messages
  (`R.string.search_empty`, `search_idle_hint`, `search_error`,
  `search_loading`) so the UI tickets can announce them via `liveRegion`. The
  ViewModel exposes the **state enum**, not hardcoded strings.
- No string concatenation of user/locale data in this layer. Date filter
  `after` is stored as `Instant`; formatting is the UI's responsibility
  (locale-aware).
- All copy is in `strings.xml` (default `values/`); no hardcoded English in
  ViewModel or repository.

## 10. Telemetry & Logging

- Events via the shared analytics interface (from core-data telemetry, if
  present; otherwise structured `Timber` debug logs):
  - `search_submitted` { surface: "messages"|"contacts", query_len: Int,
    has_sender_filter: Bool, has_after_filter: Bool }
  - `search_result_count` { surface, count: Int, is_empty: Bool }
  - `search_error` { surface, http_status: Int? , cause: String }
  - `search_result_opened` { surface }
- **Never log** `query` content, `snippet`, contact names, or cursors.
- Debounce/cancellation is logged at `Timber.v` only in debug builds.

## 11. Testing Strategy

This ticket delivers the unit tests (its sole acceptance bar) in
`feature-search/src/test` and `core-data/src/test`, using
`kotlinx-coroutines-test`, Turbine, MockK, and Paging's `AsyncPagingDataDiffer`
/ `asSnapshot`.

- **Debounce:** rapid `onQueryChange("a","ab","abc")` within 300 ms triggers
  exactly **one** repo call after `advanceTimeBy(300)`. Asserted via MockK
  `verify(exactly = 1)`.
- **Min length gate:** `onQueryChange("a")` → no repo call, state Idle;
  `onQueryChange("ab")` → repo called.
- **distinctUntilChanged:** typing then deleting back to the same query does not
  re-fetch.
- **flatMapLatest cancellation:** a second query while the first is suspended
  cancels the first; first's emission/error is dropped.
- **Paging happy path:** `pagingData.asSnapshot()` returns mapped UiModels;
  cursor advance fetches page 2 with `cursor=next_cursor`.
- **Empty state:** `items: []` → `resolveListState` returns `Empty` (not Error).
- **Error state:** `IOException` / `HttpException(500)` → `Error`; `retry()`
  re-invokes the source.
- **Last page:** `next_cursor = null` → no further append load.
- **Filters (messages):** `onSenderFilter`/`onAfterFilter` re-trigger query and
  forward params; verified with an arg captor.
- **SavedState:** query restored from a seeded `SavedStateHandle`.
- **Events:** `onResultClick` emits exactly one `*Selected` event (Turbine).
- **resolveListState** pure-function table test over all
  (isActive × loadState × count) combinations.

Coverage target: ≥ 85 % line coverage on the two ViewModels, two
PagingSources, repositories, and `resolveListState`. AND-156 layers
instrumentation/UI tests on top.

## 12. Dependencies & Sequencing

- **Depends on AND-152** (MessageSearchApi + results screen) and **AND-153**
  (ContactsApi + contacts screen) — both must provide the Retrofit interfaces
  and DTOs this ticket pages over. If either lands without a `cursor`/`limit`
  param, that endpoint must be amended (small follow-up) before paging works.
- **Blocks AND-156** (search/contacts repo + UI tests) which depends on these
  ViewModels and the unit-test scaffolding.
- **Indirectly enables AND-154** (contact → start conversation) by emitting
  `ContactSelected` events, though AND-154 lists AND-153/AND-127 as its formal
  deps.
- Sequencing within ticket: (1) PagingSources + repos in `core-data`; (2)
  UiState + `resolveListState`; (3) ViewModels + debounce; (4) unit tests.

## 13. Risks & Open Questions

- **R1 — Cursor param availability.** AND-152/153 endpoints may not yet expose
  `cursor`/`limit`. If absent, paging degrades to single-page; needs a backend/
  API confirmation against `/openapi.json`. *Owner: this ticket to verify before
  implementation.*
- **R2 — Debounce vs. test determinism.** `debounce` requires the test
  dispatcher's virtual clock; misconfiguration causes flaky tests. Mitigated by
  `MainDispatcherRule` + `runTest`.
- **R3 — Unreliable dev host** inflates `Error` states during manual testing,
  masking real empty-state regressions. Mitigated by MockWebServer-backed unit
  tests rather than live host.
- **OQ1** — Should `after` be a date-only filter (UI date picker) or full
  `Instant`? Assumed `Instant`, serialized ISO-8601; confirm with AND-152 UI.
- **OQ2** — Should the contacts surface support the same debounce length (≥2) or
  allow single-char prefix search given server tokenization? Assumed ≥2 for both;
  revisit if product wants single-char contact prefixing.
- **OQ3** — Min query length: 2 assumed; confirm with web reference
  (`frontend/src/api/endpoints/messaging.ts`).

## 14. Acceptance Criteria

1. `MessageSearchViewModel` and `ContactSearchViewModel` exist in
   `com.testlogon.android.feature.search`, `@HiltViewModel`, exposing
   `StateFlow<…UiState>` and `Flow<PagingData<…UiModel>>`.
2. Query input is debounced 300 ms, de-duplicated, and gated at min length 2;
   sub-threshold queries produce no network call and yield Idle.
3. Results are cursor-paged via Paging 3 with `pageSize = 20`,
   `enablePlaceholders = false`; page 2+ loads send the previous `next_cursor`.
4. A newer query cancels the in-flight older query (flatMapLatest) with no
   surfaced error from the cancelled stream.
5. Distinct **Idle / Loading / Content / Empty / Error** states are derivable
   via `resolveListState`; HTTP 200 + `items: []` maps to **Empty**, transport/
   HTTP failures map to **Error**.
6. `retry()` recovers a failed load without re-typing; append failures retain
   existing items.
7. Message search forwards `sender`/`after` filters and re-queries on change;
   active query/filters survive rotation via `SavedStateHandle`.
8. Selection emits one-shot `ContactSelected` / `MessageResultSelected` events.
9. **Unit-tested** (the ticket's stated acceptance): the §11 suite passes;
   `./gradlew :feature-search:testDebugUnitTest :core-data:testDebugUnitTest`
   is green with ≥ 85 % coverage on the listed classes.
10. No query content, snippet, or contact PII is logged; telemetry carries only
    length/count/flags.

## 15. Definition of Done

- Code merged to `android-port` under `feature-search/` and `core-data/` with
  the classes and signatures in §4.
- All §14 criteria met; `./gradlew :feature-search:testDebugUnitTest
  :core-data:testDebugUnitTest` passes locally and in CI.
- `./gradlew :feature-search:lintDebug detekt ktlintCheck` clean; no new
  warnings suppressed without justification.
- No new endpoints added; consumed endpoints verified against `/openapi.json`
  (R1 resolved or follow-up filed).
- Strings externalized to `strings.xml`; no hardcoded user-facing copy in
  ViewModel/repository.
- PR description links AND-152, AND-153, AND-156 and notes the cursor-param
  verification result.
- Reviewed by one Android maintainer; AND-156 unblocked.
