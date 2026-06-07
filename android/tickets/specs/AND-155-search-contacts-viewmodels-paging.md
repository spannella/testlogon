---
id: AND-155
title: Search/contacts ViewModels + paging
milestone: M3
epic: E21
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
    `GET /messaging/messages/search` with `sender_id`/`after_ts`/`kind` filters
    and the results screen Composable. **[CORRECTED]** The real query params are
    `sender_id` (string) and `after_ts` (Unix-epoch **integer**, ≥0), plus an
    optional `kind` array — not `sender`/`after` (ISO string). Verified against
    OpenAPI `GET /messaging/messages/search`.
  - **AND-153** — `ContactsApi.search(...)` over
    `GET /messaging/contacts/search` and the contacts screen Composable.
    **[CORRECTED]** The web client (`searchUsers`) sends only `q` + `limit`;
    there is no documented "server-side name tokenization" param. Verified
    against `src/api/endpoints/messaging.ts: searchUsers` and OpenAPI.
- **Downstream:** **AND-154** (contact → start conversation) consumes
  `ContactUiModel` selection events; **AND-156** owns the broader repo + UI test
  matrix and depends on the unit tests delivered here.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext, unreliable). OpenAPI at `/openapi.json`. Web reference:
  `src/api/endpoints/messaging.ts` (`searchUsers`), `src/api/types.ts`
  (`UserSearchResult`), `src/api/client.ts` (transport). **[NOTE]** The web
  client only calls `/messaging/contacts/search`; it has **no** message-search
  call, so the `/messaging/messages/search` contract is verified against
  OpenAPI only (no web reference exists for it).
  Auth is cookie-based: the shared client (`src/api/client.ts`) reads the
  `ui_csrf` cookie and sets `X-CSRF-Token`, sends `credentials: "include"`, and
  on a 401 (only when already authenticated) does a single single-flight
  `POST /ui/session/refresh` then retries the original request once — verified.
  On Android this is handled by the shared OkHttp authenticator from AND-12x;
  not re-implemented here. (OpenAPI also lists `authorization`/`X-SESSION-ID`
  header auth on these endpoints as an alternate mode; the app uses cookies.)
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  Paging 3, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15. minSdk 24, compileSdk/
  targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.

## 3. Functional Requirements

FR-1 **Debounced query.** Both ViewModels expose `onQueryChange(query: String)`.
Input is debounced 300 ms (matches the web client's 300 ms `setTimeout` —
verified in `src/pages/messages/UserSearch.tsx`) and de-duplicated
(`distinctUntilChanged`). **[CORRECTED]** A query is considered "active" after
`trim()` yields length ≥ 1, matching the web client gate (`enabled:
debouncedQuery.trim().length > 0`) and the backend `q` constraint (`minLength:
1` for both endpoints). The previous "≥ 2" gate was an unverified assumption;
empty/blank queries clear results to **Idle** without hitting the network.
(Sending `q=""` would return HTTP **422**, not empty results — the client gate
prevents that round-trip.)

FR-2 **Reactive paging.** A debounced, qualifying query produces a new
`Flow<PagingData<T>>` via Paging 3 (`flatMapLatest` so a newer query cancels the
older stream). **[CORRECTED]** Neither endpoint exposes a `cursor` query param
or a `next_cursor` response field — both return a **bare JSON array** capped by
`limit` (messages default 50 / max 200; contacts default 10 / max 50). There is
**no server-side cursor pagination**. Paging 3 is therefore used as a
single-page source: `LoadResult.Page` with `prevKey = null` and `nextKey =
null`, page size driven by `limit`. (See R1 — resolved negative.) If true
paging is later required it needs a backend change, tracked as a follow-up.

FR-3 **Message search filters.** `MessageSearchViewModel` additionally holds
optional `senderId: String?` and `afterTs: Long?` filters. **[CORRECTED]** The
real params are `sender_id` (string) and `after_ts` (Unix-epoch **seconds**,
integer ≥ 0), plus an optional `kind` (array of message-kind strings). Changing
a filter re-triggers the active query (subject to the same debounce gate).
Filters are passed through to `GET /messaging/messages/search`. The UI may model
`after` as an `Instant` for the picker but must convert to epoch seconds at the
API boundary.

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
                else repo.searchMessages(q, f.senderId, f.afterTs, f.kind)
            }
            .cachedIn(viewModelScope)

    fun onQueryChange(query: String) { queryInput.value = query; savedState[KEY_Q] = query }
    // CORRECTED: param is sender_id (string); after_ts is epoch seconds (Long); optional kind filter.
    fun onSenderFilter(senderId: String?) { filters.update { it.copy(senderId = senderId) } }
    fun onAfterFilter(afterTs: Long?) { filters.update { it.copy(afterTs = afterTs) } }
    fun onKindFilter(kind: List<String>?) { filters.update { it.copy(kind = kind) } }
    fun onResultClick(result: MessageResultUiModel)  // emits MessageResultSelected

    private val _events = Channel<MessageResultSelected>(Channel.BUFFERED)
    val events: Flow<MessageResultSelected> = _events.receiveAsFlow()

    companion object {
        const val DEBOUNCE_MS = 300L
        const val MIN_QUERY_LEN = 1   // CORRECTED: web gate is length > 0; backend q minLength=1
        const val PAGE_SIZE = 20      // Android choice; must be ≤ backend max (messages 200, contacts 50)
        private const val KEY_Q = "msg_search_query"
    }
}
```

`ContactSearchViewModel` is structurally identical minus filters, emitting
`ContactSelected(contactId, displayName)`.

### 4.3 Paging source (core-data)

```kotlin
package com.testlogon.android.core.data.search

// CORRECTED: the endpoint has no cursor and returns a bare List<MessageOut>.
// We model it as a single-page source keyed by Unit (prevKey/nextKey = null).
class MessageSearchPagingSource(
    private val api: MessageSearchApi,
    private val query: String,
    private val senderId: String?,
    private val afterTs: Long?,
    private val kind: List<String>?,
) : PagingSource<Unit, MessageOut>() {

    override suspend fun load(
        params: LoadParams<Unit>,
    ): LoadResult<Unit, MessageOut> = try {
        val items: List<MessageOut> = api.search(
            q = query,
            senderId = senderId,
            afterTs = afterTs,            // epoch seconds, not ISO string
            kind = kind,
            limit = params.loadSize,
        )
        LoadResult.Page(
            data = items,
            prevKey = null,
            nextKey = null,               // no server cursor → single page
        )
    } catch (e: IOException) {
        LoadResult.Error(e)
    } catch (e: HttpException) {
        LoadResult.Error(e)              // 422 (bad q/limit), 5xx, etc.
    }

    override fun getRefreshKey(state: PagingState<Unit, MessageOut>) = null
}
```

Repository builds the `Pager`:

```kotlin
class MessageSearchRepository @Inject constructor(
    private val api: MessageSearchApi,
    private val mapper: MessageResultMapper,
) {
    fun searchMessages(q: String, senderId: String?, afterTs: Long?, kind: List<String>?)
        : Flow<PagingData<MessageResultUiModel>> = Pager(
        config = PagingConfig(
            pageSize = 20, prefetchDistance = 5, initialLoadSize = 20,
            enablePlaceholders = false,
        ),
        pagingSourceFactory = { MessageSearchPagingSource(api, q, senderId, afterTs, kind) },
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
new endpoints. Shapes below are **verified against `/openapi.json`** (and, for
contacts, the web client). The original draft's shapes were wrong and have been
corrected.

`GET /messaging/messages/search` — verified `GET /messaging/messages/search`
Query params (CORRECTED — no `cursor`):
- `q` (string, **required**, minLength 1, maxLength 200)
- `limit` (int, optional, **default 50, min 1, max 200**)
- `sender_id` (string, optional, maxLength 64) — was `sender`
- `after_ts` (integer, optional, **Unix epoch seconds**, ≥ 0) — was `after` (ISO)
- `kind` (array of strings, optional) — message-kind filter, was undocumented

Response: a **bare JSON array** of `MessageOut` (no `items`/`next_cursor`
wrapper). `MessageOut` required fields: `conversation_id`, `message_id`,
`sender_id`, `created_at` (**integer epoch**, not ISO string), `kind`. The
message body is `text` (nullable string). There is **no `sender_name`** and
**no `snippet`/highlighted-markup** field returned by the API.

```json
[
  {
    "message_id": "m_01H...",
    "conversation_id": "c_01H...",
    "sender_id": "u_42",
    "kind": "text",
    "text": "…matched text…",
    "created_at": 1748629325
  }
]
```

`GET /messaging/contacts/search` — verified `GET /messaging/contacts/search`
Query params (CORRECTED — no `cursor`, no documented tokenization param):
- `q` (string, **required**, minLength 1, maxLength 64)
- `limit` (int, optional, **default 10, min 1, max 50**)

Response: a **bare JSON array** of `Contact`, whose only fields are `user_id`
and `display_name` (both required). The draft's `contact_id`/`handle`/
`avatar_url`/`presence` fields do **not** exist. The web client types this as
`UserSearchResult { user_id: string; display_name: string }`
(`src/api/types.ts`).

```json
[
  { "user_id": "u_42", "display_name": "Ada Lovelace" }
]
```

Retrofit (CORRECTED — returns a `List`, not a page DTO):

```kotlin
@GET("messaging/messages/search")
suspend fun search(
    @Query("q") q: String,
    @Query("sender_id") senderId: String? = null,
    @Query("after_ts") afterTs: Long? = null,
    @Query("kind") kind: List<String>? = null,
    @Query("limit") limit: Int = 50,
): List<MessageOut>

@GET("messaging/contacts/search")
suspend fun search(
    @Query("q") q: String,
    @Query("limit") limit: Int = 10,
): List<Contact>
```

Because the response is a bare list with no cursor, the last page is the **only**
page; `nextKey = null` always. Error `detail` on **422** follows the FastAPI
shape `{ "detail": [ { "loc": [...], "msg": "...", "type": "..." } ] }`
(`HTTPValidationError` → `ValidationError[]`); 5xx/transport errors are opaque.
The shared `ApiResult`/error adapter handles `detail` parsing; `PagingSource`
only needs the `HttpException`/`IOException` distinction.

## 6. Data & State Management

- **Source of truth:** server. Paging holds the in-memory window; no Room cache
  for search results (results are query-scoped and ephemeral — explicitly out of
  scope, contrast with conversation caching in AND-120).
- **Query/filter state:** `MutableStateFlow` inside the ViewModel, persisted to
  `SavedStateHandle` (`msg_search_query`, plus serialized filters). No DataStore
  (search is not a user preference).
- **Cursor:** **[CORRECTED]** there is no server cursor. The `PagingSource` is
  single-page (`prevKey = null`, `nextKey = null`, `getRefreshKey = null`); a
  refresh re-runs the single query. `limit` (default 50 messages / 10 contacts,
  Android override 20) bounds the result window.
- **Mapping:** `MessageResultMapper` / `ContactMapper` convert DTO → UiModel in
  `core-data`. **[CORRECTED]** `created_at` is a Unix-epoch **integer**, parsed
  via `Instant.ofEpochSecond(...)`; the `after_ts` filter is sent as epoch
  seconds. There is **no `snippet`** field — the message body is the nullable
  `text` field, carried as a plain string on the UiModel (display formatting /
  highlight is the UI ticket's job). `Contact` maps `user_id` + `display_name`
  only; there is no `handle`/`avatar_url`/`presence` from this endpoint.
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
  `X-CSRF-Token` (read from the `ui_csrf` cookie and set by the shared
  interceptor — verified in `src/api/client.ts`); this ticket must **not**
  attach auth headers manually. (The endpoints also accept `authorization` /
  `X-SESSION-ID` headers per OpenAPI, but the app uses the cookie+CSRF path.)
- Query strings may contain PII (names, message fragments). They are **not**
  logged at INFO. Telemetry records only query **length** and result **count**,
  never query content (see §10).
- `SavedStateHandle` persistence of the active query is in-process Android
  saved-instance-state only; no on-disk persistence of queries.
- The message body `text` (CORRECTED: the API returns no `snippet` field) is
  server-provided and treated as untrusted text — never rendered as HTML/web
  content in this layer (UiModel holds a plain string). If a future API revision
  adds highlighted markup, the same untrusted-text rule applies.

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
- **Min length gate:** `onQueryChange("")`/blank → no repo call, state Idle;
  `onQueryChange("a")` → repo called (CORRECTED: gate is ≥ 1, not ≥ 2).
- **distinctUntilChanged:** typing then deleting back to the same query does not
  re-fetch.
- **flatMapLatest cancellation:** a second query while the first is suspended
  cancels the first; first's emission/error is dropped.
- **Paging happy path:** `pagingData.asSnapshot()` returns mapped UiModels from
  the single bare-array response (CORRECTED: no cursor / no page-2 append — the
  source returns one page with `nextKey = null`).
- **Empty state:** `items: []` → `resolveListState` returns `Empty` (not Error).
- **Error state:** `IOException` / `HttpException(500)` / `HttpException(422)` →
  `Error`; `retry()` re-invokes the source. (422 example: `q` too long.)
- **Single page:** the bare-array response yields exactly one page; no append
  load is attempted (CORRECTED from "last page via next_cursor = null").
- **Filters (messages):** `onSenderFilter`/`onAfterFilter`/`onKindFilter`
  re-trigger query and forward `sender_id`/`after_ts`(epoch seconds)/`kind`;
  verified with an arg captor (CORRECTED param names).
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

- **R1 — Cursor param availability. [RESOLVED — negative.]** Verified against
  `/openapi.json`: neither endpoint exposes a `cursor` param or `next_cursor`
  response field. Both return bare arrays bounded by `limit`. Paging is
  therefore single-page (degraded as predicted). True pagination would require a
  backend change (out of scope; file a follow-up if product needs >`limit`
  results).
- **R2 — Debounce vs. test determinism.** `debounce` requires the test
  dispatcher's virtual clock; misconfiguration causes flaky tests. Mitigated by
  `MainDispatcherRule` + `runTest`.
- **R3 — Unreliable dev host** inflates `Error` states during manual testing,
  masking real empty-state regressions. Mitigated by MockWebServer-backed unit
  tests rather than live host.
- **OQ1 — [RESOLVED].** The API takes `after_ts` as a Unix-epoch **integer
  (seconds)**, not an ISO-8601 string. A UI date picker may produce a date-only
  value; convert to epoch seconds at the boundary. Granularity (date vs.
  datetime) is still a UI/product choice for AND-152.
- **OQ2 — [RESOLVED].** Contacts gate is ≥ 1 (single char allowed): the web
  client enables search at `trim().length > 0` and the backend `q` is
  `minLength: 1`. No separate "tokenization" param exists.
- **OQ3 — [RESOLVED].** Min query length is **1**, not 2. Verified against
  `src/pages/messages/UserSearch.tsx` (`enabled: ...length > 0`) and the OpenAPI
  `q` constraint (`minLength: 1`) for both endpoints.

## 14. Acceptance Criteria

1. `MessageSearchViewModel` and `ContactSearchViewModel` exist in
   `com.testlogon.android.feature.search`, `@HiltViewModel`, exposing
   `StateFlow<…UiState>` and `Flow<PagingData<…UiModel>>`.
2. Query input is debounced 300 ms, de-duplicated, and gated at min length 1
   (CORRECTED from 2; matches web client + backend `q` minLength 1);
   empty/blank queries produce no network call and yield Idle.
3. Results are surfaced via Paging 3 with `enablePlaceholders = false`. The
   source is **single-page** (no server cursor — CORRECTED): one bare-array
   response per query, `nextKey = null`, bounded by `limit`.
4. A newer query cancels the in-flight older query (flatMapLatest) with no
   surfaced error from the cancelled stream.
5. Distinct **Idle / Loading / Content / Empty / Error** states are derivable
   via `resolveListState`; HTTP 200 + `items: []` maps to **Empty**, transport/
   HTTP failures map to **Error**.
6. `retry()` recovers a failed load without re-typing; append failures retain
   existing items.
7. Message search forwards `sender_id`/`after_ts`(epoch seconds)/`kind` filters
   (CORRECTED names) and re-queries on change; active query/filters survive
   rotation via `SavedStateHandle`.
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

## 16. Citations & Assumption Audit

Each key technical claim with its verdict and exact source pointer.

1. **`GET /messaging/contacts/search` exists.** VERIFIED.
   Source: OpenAPI index `GET /messaging/contacts/search`
   (op `search_contact_messaging_contacts_search_get`); frontend
   `src/api/endpoints/messaging.ts: searchUsers`.
2. **`GET /messaging/messages/search` exists.** VERIFIED.
   Source: OpenAPI index `GET /messaging/messages/search`
   (op `search_messages_all_conversations_messaging_messages_search_get`).
3. **Both are HTTP GET.** VERIFIED. Source: same OpenAPI entries.
4. **contacts/search query params are only `q` + `limit` (no `cursor`).**
   CORRECTED (draft claimed `cursor` + server tokenization).
   Source: OpenAPI `GET /messaging/contacts/search` params=`q,limit`;
   `src/api/endpoints/messaging.ts: searchUsers` sends only `{q, limit}`.
5. **messages/search params are `q,limit,sender_id,after_ts,kind` (no `cursor`;
   filter is `sender_id` not `sender`; time is `after_ts` epoch int not `after`
   ISO).** CORRECTED. Source: OpenAPI `GET /messaging/messages/search` params;
   schema shows `after_ts` integer (≥0) and `sender_id` string (maxLength 64).
6. **No server-side cursor pagination on either endpoint; responses are bare
   JSON arrays.** CORRECTED (draft used `{items, next_cursor}`). Source: OpenAPI
   200 response schema is `type: array, items: $ref MessageOut` (resp.
   `Contact`); `src/api/endpoints/messaging.ts` types it `UserSearchResult[]`.
7. **`Contact` schema fields are only `user_id` + `display_name`.** CORRECTED
   (draft invented `contact_id`/`handle`/`avatar_url`/`presence`). Source:
   OpenAPI `components.schemas.Contact`; `src/api/types.ts: UserSearchResult`.
8. **`MessageOut` required fields: `conversation_id, message_id, sender_id,
   created_at, kind`; body is nullable `text`; `created_at` is integer epoch; no
   `sender_name`/`snippet`.** CORRECTED. Source: OpenAPI
   `components.schemas.MessageOut` (required array + field types).
9. **`limit` defaults/maxes: messages default 50/max 200; contacts default
   10/max 50.** VERIFIED (draft implied a single default 20). Source: OpenAPI
   `limit` schema on each endpoint. Android PAGE_SIZE=20 is a client choice
   within bounds (UNVERIFIED-assumption as a product decision).
10. **`q` constraints: messages minLength 1/maxLength 200; contacts minLength
    1/maxLength 64.** VERIFIED. Source: OpenAPI `q` schema on each endpoint.
11. **Min client query length is 1 (not 2).** CORRECTED. Source:
    `src/pages/messages/UserSearch.tsx` (`enabled: debouncedQuery.trim().length
    > 0`) + OpenAPI `q` minLength 1.
12. **Debounce is 300 ms.** VERIFIED. Source:
    `src/pages/messages/UserSearch.tsx` (`setTimeout(... , 300)`).
13. **Auth is cookie-based with `X-CSRF-Token` from the `ui_csrf` cookie.**
    VERIFIED. Source: `src/api/client.ts` (`getCookie("ui_csrf")` →
    `headers.set("X-CSRF-Token", csrf)`, `credentials: "include"`).
14. **Single `POST /ui/session/refresh` retry on 401, single-flight, retries
    the original request once.** VERIFIED. Source: `src/api/client.ts`
    (401 branch → `refreshSession()` guarded by `refreshPromise`, then one
    retry fetch).
15. **422 error shape is `{detail: [{loc,msg,type}]}` (HTTPValidationError →
    ValidationError[]).** VERIFIED. Source: OpenAPI
    `components.schemas.HTTPValidationError` + `ValidationError`.
16. **Web client has no message-search call.** VERIFIED (so the messages/search
    contract rests on OpenAPI alone). Source: grep of `src/` finds only
    `searchUsers` (contacts); no `messages/search` caller.
17. **Paging 3, Compose, Hilt/KSP, Coroutines/Flow, Turbine,
    `kotlinx-coroutines-test`, `AsyncPagingDataDiffer`/`asSnapshot` are the
    intended Android stack.** UNVERIFIED-assumption (framework choice, not in
    backend/frontend sources). Framework refs:
    https://developer.android.com/topic/libraries/architecture/paging/v3-overview
    (Paging 3); https://developer.android.com/kotlin/coroutines/test
    (coroutines-test / virtual clock).

### Corrections made

- §2/§3/§5/§14: filter param `sender` → `sender_id`; time filter `after` (ISO
  string) → `after_ts` (Unix-epoch integer seconds); added the previously
  undocumented optional `kind` array filter.
- §3/§5/§6/§11/§14: removed the cursor-pagination premise — endpoints expose no
  `cursor`/`next_cursor`; responses are bare arrays; PagingSource is now
  single-page (`nextKey = null`). R1 marked resolved-negative.
- §5/§6/§8: `MessageOut` has no `sender_name`/`snippet`; body is nullable
  `text`; `created_at` is an integer epoch (parse with `Instant.ofEpochSecond`).
- §5: `Contact` reduced to `user_id` + `display_name`; dropped fabricated
  `contact_id`/`handle`/`avatar_url`/`presence`.
- §3/§4.2/§11/§14: min query length 2 → 1 (web gate + backend minLength 1).
- §5: corrected `limit` defaults (50 messages / 10 contacts) and maxes
  (200 / 50); Retrofit returns `List<MessageOut>` / `List<Contact>`, not a page
  DTO.
- §4.3/§4.2: PagingSource key type `String` → `Unit`; repo/VM filter signatures
  updated to `senderId`/`afterTs: Long?`/`kind`.
- §13: R1, OQ1, OQ2, OQ3 marked resolved with sources.

### Open assumptions

- **Android PAGE_SIZE = 20.** A client choice; the backend default differs
  (50/10). Unverifiable from sources because it is a product/UX decision. Must
  stay ≤ backend max (200/50).
- **Android framework stack** (Paging 3, Hilt/KSP, Turbine, exact lib versions
  in §2). Not derivable from backend/frontend sources; standard Android refs
  cited (claim 17). Treat versions as the team's stated baseline.
- **Telemetry/analytics interface existence** (§10 "if present"). Not in the
  provided sources; assumed to follow the core-data telemetry convention.
- **Shared OkHttp authenticator from AND-12x.** Behavior mirrors the verified
  web client (single refresh + retry); the Android implementation itself is in
  a dependency ticket, not in these sources.
- **`kind` enum values** for the message-kind filter are taken from
  `MessageOut.kind` enum (text, image, file, audio, video, gallery, …); the
  search endpoint does not separately constrain `kind`, so passing an unknown
  value's behavior is unverified.

## 17. Test Plan

IDs `TC-AND-155-NN`. "AC-#" traces to §14 acceptance criteria. Unless noted,
cases are JVM unit/Robolectric (local, no device) since this ticket's acceptance
bar is unit tests; device/emulator notes are given where a case must run there.

- **TC-AND-155-01 — Debounce coalesces rapid input.** Type: unit
  (coroutines-test virtual clock). Target: `MessageSearchViewModel` (+ mirror on
  `ContactSearchViewModel`). Preconditions: `MainDispatcherRule`, MockK repo.
  Steps: `onQueryChange("a")`, `"ab"`, `"abc"` within 300 ms;
  `advanceTimeBy(300)`; `runCurrent()`. Expected: repo `searchMessages` called
  `exactly = 1` with `q = "abc"`. Traces: AC-2.
- **TC-AND-155-02 — Min-length gate (≥1) and Idle.** Type: unit. Target: both
  ViewModels. Preconditions: MockK repo. Steps: `onQueryChange("")` then
  `"  "` (blank); advance clock. Then `onQueryChange("a")`; advance. Expected:
  blank/empty → no repo call, `listState = Idle`, `PagingData.empty()`;
  single char "a" → repo called once. Traces: AC-2.
- **TC-AND-155-03 — distinctUntilChanged.** Type: unit. Target: ViewModel.
  Steps: `onQueryChange("ab")` (advance, 1 call), then `"abc"` then back to
  `"ab"` ending on `"ab"` after debounce. Expected: no extra fetch for the
  re-arrived identical query. Traces: AC-2.
- **TC-AND-155-04 — flatMapLatest cancels the in-flight query.** Type: unit.
  Target: ViewModel. Preconditions: repo first call suspends on a deferred.
  Steps: trigger query A (suspends), then query B; complete A afterward.
  Expected: A's stream is cancelled, only B's `PagingData` is collected, A's
  late emission/error is dropped (no Error surfaced). Traces: AC-4.
- **TC-AND-155-05 — Paging happy path (single bare-array page).** Type:
  contract/MockWebServer. Target: `MessageSearchPagingSource` +
  `MessageSearchRepository` (+ contacts mirror). Preconditions: MockWebServer
  returns a JSON **array** of `MessageOut` (fields `conversation_id`,
  `message_id`, `sender_id`, `created_at` int, `kind`, `text`). Steps:
  `pager.flow.asSnapshot()`. Expected: mapped `MessageResultUiModel`s in order;
  `created_at` parsed via `Instant.ofEpochSecond`; one page only, no second
  request issued (`RecordedRequest` count == 1). Traces: AC-1, AC-3.
- **TC-AND-155-06 — Contact response shape.** Type: contract/MockWebServer.
  Target: `ContactSearchPagingSource`/`ContactMapper`. Preconditions:
  MockWebServer returns `[{"user_id":"u_42","display_name":"Ada Lovelace"}]`.
  Steps: collect snapshot. Expected: `ContactUiModel(user_id, display_name)`;
  request path `messaging/contacts/search?q=...&limit=...`, no `cursor` param.
  Traces: AC-1, AC-3, AC-8.
- **TC-AND-155-07 — Empty vs. Error disambiguation.** Type:
  unit + contract/MockWebServer. Target: `resolveListState` + PagingSource.
  Steps: (a) server returns `[]` with 200 → `resolveListState` = **Empty**;
  (b) server returns 500 / socket drop → **Error**. Expected: 200+empty is
  Empty (never Error); transport/5xx is Error. Traces: AC-5.
- **TC-AND-155-08 — 422 validation error maps to Error.** Type:
  contract/MockWebServer. Target: PagingSource error path. Preconditions: server
  returns 422 with `{"detail":[{"loc":["query","q"],"msg":"...","type":"..."}]}`
  (e.g., `q` exceeding maxLength). Steps: trigger load. Expected:
  `LoadState.Error` (HttpException 422) → `SearchListState.Error`; `detail`
  parsed without crashing the mapper. Traces: AC-5.
- **TC-AND-155-09 — retry() recovers without re-typing.** Type: unit. Target:
  ViewModel + PagingSource. Preconditions: first load fails (IOException), second
  succeeds. Steps: observe Error, call `retry()`. Expected: source re-invoked,
  items load, state → Content; query not re-entered. Traces: AC-6.
- **TC-AND-155-10 — Message filters forwarded with correct names/types.** Type:
  unit (MockK arg captor) + contract/MockWebServer. Target:
  `MessageSearchViewModel` → `MessageSearchApi.search`. Steps:
  `onSenderFilter("u_42")`, `onAfterFilter(1748629325L)`,
  `onKindFilter(listOf("text"))`; advance. Expected: request carries
  `sender_id=u_42`, `after_ts=1748629325` (integer), `kind=text`; re-query
  triggered on each change. Traces: AC-7.
- **TC-AND-155-11 — SavedStateHandle restores query across rotation.** Type:
  unit. Target: ViewModel. Preconditions: seed `SavedStateHandle` with
  `msg_search_query = "ada"` (+ serialized filters). Steps: construct VM; read
  `uiState.query`. Expected: query (and filters) restored; debounced fetch fires
  for the restored query. Traces: AC-7.
- **TC-AND-155-12 — One-shot selection events.** Type: unit (Turbine). Target:
  both ViewModels' `events` flow. Steps: `onResultClick(model)` /
  contact select. Expected: exactly one `MessageResultSelected` /
  `ContactSelected(user_id, display_name)`; not replayed to a second collector
  (Channel semantics). Traces: AC-8.
- **TC-AND-155-13 — resolveListState truth table.** Type: unit
  (parameterized). Target: `resolveListState`. Steps: enumerate
  `(isQueryActive ∈ {t,f}) × (refresh ∈ {Loading, NotLoading, Error}) ×
  (itemCount ∈ {0, >0})`. Expected: `!active`→Idle; Loading→Loading;
  Error→Error; NotLoading & count 0→Empty; else Content. Traces: AC-5.
- **TC-AND-155-14 — No PII logged.** Type: unit (Robolectric/Timber test tree).
  Target: ViewModel + repository logging. Steps: plant a test `Timber.Tree`;
  run a search with query "Ada Lovelace" against text containing PII. Expected:
  no log record contains query content, `text` body, or contact names; only
  `query_len`/`count`/flags appear. Traces: AC-10.
- **TC-AND-155-15 — Flaky/offline dev host → Error with retry, no crash.**
  Type: instrumented/e2e. Target: end-to-end search against an unreachable host.
  **Run on the PHYSICAL DEVICE** (Samsung Galaxy A15 5G, SM-A156U,
  R5CX821TA9R, API 34/arm64) to exercise real radio/airplane-mode toggling and
  real DNS/connect failures (toggle Wi-Fi/airplane mode), with the emulator
  `test35` as a fallback for CI using a stubbed unreachable endpoint.
  Preconditions: app built, network toggled off mid-search. Steps: type a query,
  drop connectivity, observe Error state, restore connectivity, tap retry.
  Expected: `SearchListState.Error` with retry affordance; retry succeeds; no
  ANR/crash; cancelled in-flight loads surface no error. Traces: AC-5, AC-6.
- **TC-AND-155-16 — Accessibility of state announcements.** Type: Compose-UI
  (Robolectric/`createComposeRule`, or instrumented on emulator `test35`).
  Target: the thin state-host that AND-152/153 will render (verifies the enum →
  string-resource contract this ticket enables). Steps: drive
  Idle/Loading/Empty/Error states; assert each exposes a distinct
  string-resource-backed message via `liveRegion` semantics
  (`onNodeWithText`/`assertHasNoClickAction` as appropriate). Expected: distinct
  announced messages per state; no hardcoded English. Traces: AC-5, AC-9-related
  (enabling a11y); supports AC-10 (no PII in announcements).

### Coverage matrix

| §14 AC | Covered by |
| --- | --- |
| AC-1 (VMs exist, expose StateFlow + PagingData) | TC-05, TC-06 |
| AC-2 (debounce 300 ms, dedupe, min-len 1, Idle) | TC-01, TC-02, TC-03 |
| AC-3 (Paging 3, single page, no cursor) | TC-05, TC-06 |
| AC-4 (flatMapLatest cancellation, no stray error) | TC-04 |
| AC-5 (Idle/Loading/Content/Empty/Error; 200+[]=Empty) | TC-07, TC-08, TC-13, TC-15, TC-16 |
| AC-6 (retry; append failure retains items) | TC-09, TC-15 |
| AC-7 (sender_id/after_ts/kind forwarded; SavedState) | TC-10, TC-11 |
| AC-8 (one-shot selection events) | TC-06, TC-12 |
| AC-9 (unit suite green ≥85%) | TC-01..TC-14 (the unit/contract suite) |
| AC-10 (no PII logged; only len/count/flags) | TC-14, TC-16 |
