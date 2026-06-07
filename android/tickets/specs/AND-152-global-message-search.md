---
id: AND-152
title: Global message search
milestone: M3
epic: E21
priority: P1
size: M
depends_on: [AND-120]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
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

> **REVIEW NOTE (verified 2026-06-06).** The backlog's "sender/after filters" map to
> the *backend's* `sender_id` (string user id, not username free-text) and `after_ts`
> (**Unix epoch-seconds integer**, not an ISO-8601 string) query params. The endpoint
> returns a **bare JSON array of `MessageOut`** — there is **no `{items,next_cursor}`
> envelope and no cursor/offset pagination**; `limit` (default 50, max 200) is the
> only result-count control. The web client has **no** global-message-search call, so
> there is no frontend contract to mirror for this endpoint — the OpenAPI spec is the
> sole source of truth. See §16 for the full audit; §5 and §4 are corrected inline.

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
  leading slash, `suspend` methods returning DTO bodies, Moshi
  `@JsonClass(generateAdapter = true)` DTOs with snake_case `@Json(name=...)`, and
  the shared Retrofit/Hilt provider). **CORRECTED:** the `{ items, next_cursor }`
  cursor envelope is **not** used by this endpoint — `GET /messaging/messages/search`
  returns a **bare `array<MessageOut>`** with no envelope and no cursor; see §4/§5.
  The result-item DTO reuses `MessageOut` field conventions (the response array
  element type), which means the matched text field is `text` (nullable) and the
  sender is identified only by `sender_id`.
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
- **Web reference:** ~~`frontend/src/api/endpoints/messaging.ts` (global search call)
  and `frontend/src/api/types.ts` (`MessageSearchResult`)~~ **CORRECTED:** the web
  client has **no** global-message-search call (`messaging.ts` only has
  `searchUsers` → `/messaging/contacts/search`, and there is no `MessageSearchResult`
  type in `types.ts`). The web client therefore is **not** a contract source for this
  endpoint. The **OpenAPI spec is the sole source of truth**: request params are
  `q`, `limit`, `sender_id`, `after_ts`, `kind`; the response is `array<MessageOut>`.
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

FR-3. **Sender filter (optional).** A sender filter narrows results to messages
from a chosen participant. **CORRECTED:** the backend param is **`sender_id`** (a
**user id string**, maxLength 64), **not** a `sender` username. v1 must therefore
resolve a chosen participant to their `sender_id` (e.g. via the existing
`/messaging/contacts/search` user-search → `user_id`), since the endpoint does not
accept a free-text username. Surfaced as a filter chip + picker; a set value is
shown as a removable assist chip and sent as the `sender_id` query param.

FR-4. **After filter (optional).** An `after` date filter restricts results to
messages created on/after a chosen date. Surfaced as a date-picker chip
(Material 3 `DatePicker`). **CORRECTED:** the backend param is **`after_ts`**, a
**Unix epoch-**seconds** integer** (`minimum: 0`), **not** an ISO-8601 string. The
client must convert the picked `LocalDate` to an epoch-seconds `Long` (start-of-day
in the chosen zone) before sending. A removable chip shows the active value.

FR-5. **Filter composition.** `q`, `sender_id`, and `after_ts` compose: changing any
of them (after debounce for `q`; immediately for filter chips) re-issues the search
from the first page. Active filters are reflected in chip state and persisted
across config change (FR-11). (An optional `kind` filter — array of message kinds —
also exists in the backend contract but is **out of scope** for v1.)

FR-6. **Cross-conversation results.** Results span every conversation the user
participates in. **CORRECTED:** the `MessageOut` response element does **not**
include `conversation_title`, `participants`, `sender_username`, or
`sender_avatar_url` — it carries only `sender_id` (string), `conversation_id`,
`message_id`, `created_at` (epoch-seconds int), `kind`, and a nullable `text`. Each
result row therefore shows: the matched message **`text`** with the query
substring(s) highlighted (reusing `core-ui` `highlightMatches`) and a
locale-formatted timestamp derived from `created_at`. Display of a **sender
name/avatar and conversation title requires a secondary lookup** (resolve
`sender_id` and `conversation_id` against existing conversation/contact data) — this
enrichment is an unverified design assumption (see §16) and should be confirmed
during grooming; a v1 fallback renders `sender_id`/`conversation_id` verbatim.
Result ordering is **not specified by OpenAPI** (no documented sort) — recency-desc
is an assumption to confirm against the live backend (see §16).

FR-7. **Paging.** **CORRECTED:** the endpoint is **not** cursor- or offset-paged —
it returns a single bounded `array<MessageOut>` capped by `limit` (default 50, max
200). There is no `next_cursor`. v1 therefore performs a **single bounded fetch**
(request `limit` up to the 200 max) rather than incremental Paging 3 page loads; the
list renders that one page. If endless scrolling is required, the only available
lever is increasing `limit` (still capped at 200) — true pagination would need a
backend change. The Paging 3 `PagingSource`/cursor design in §4 is **revised**
accordingly (single-page source: first `load` returns the array, `nextKey = null`).

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
    MessageSearchResultDto.kt     // CORRECTED: no MessageSearchPageDto — response
                                  // is a bare array<MessageOut>, no page envelope
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

**CORRECTED to match `MessageOut`** (the response array element). `MessageOut` has
no `sender_username`, `sender_avatar_url`, `conversation_title`, `participants`, or
`body`; `text` is nullable and `created_at` is an epoch-seconds integer:

```kotlin
package com.testlogon.android.core.model.messaging

data class MessageSearchResultItem(
    val messageId: String,            // message_id (required)
    val conversationId: String,       // conversation_id (required)
    val senderId: String,             // sender_id (required; only sender identifier)
    val kind: String,                 // kind (required)
    val text: String?,                // text (nullable; matched body, may be null)
    val createdAt: java.time.Instant, // from created_at: Long epoch-seconds
    // Display-only enrichment resolved client-side (NOT on MessageOut):
    val senderDisplayName: String? = null,   // resolved from sender_id (assumption)
    val senderAvatarUrl: String? = null,     // resolved from sender_id (assumption)
    val conversationTitle: String? = null,   // resolved from conversation_id (assumption)
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
    val senderId: String?,   // CORRECTED: backend param is sender_id (user id), not username
    val after: LocalDate?,   // converted to after_ts epoch-seconds Long at the call site
)
```

Only the *query* leg of `criteria` is debounced (300 ms); filter-chip changes are
applied immediately. `flatMapLatest` cancels stale searches so only the newest
criteria's `PagingData` is emitted. `query`/`senderId`/`after` are read from and
written to `SavedStateHandle` (`search_query`, `search_sender_id`, `search_after`).

### 4.4 Repository + PagingSource (`core-data`)

```kotlin
class GlobalSearchRepository @Inject constructor(
    private val api: MessageSearchApi,
    @IoDispatcher private val io: CoroutineDispatcher,
) {
    // CORRECTED: key type Int (single page; no string cursor). pageSize informational
    // only — one bounded array is returned per search.
    fun pager(criteria: SearchCriteria): Pager<Int, MessageSearchResultItem> =
        Pager(PagingConfig(pageSize = 50, enablePlaceholders = false)) {
            GlobalSearchPagingSource(api, criteria, io)
        }

    /** One-shot bounded search (the endpoint returns a single array, no paging). */
    suspend fun search(c: SearchCriteria): ApiResult<List<MessageSearchResultDto>> =
        safeApiCall(io) {
            api.search(
                q = c.query.trim(),
                senderId = c.senderId,                  // -> sender_id
                afterTs = c.after?.atStartOfDay(ZoneId.systemDefault())
                                 ?.toEpochSecond(),     // -> after_ts (epoch seconds)
                limit = 200,                            // max; no cursor available
            )
        }
}
// CORRECTED: no `MessageSearchPageDto` (no envelope), no `cursor` param;
// `sender` -> `sender_id` (user id), `after` ISO string -> `after_ts` epoch-seconds Long.
```

```kotlin
class GlobalSearchPagingSource(
    private val api: MessageSearchApi,
    private val criteria: SearchCriteria,
    private val io: CoroutineDispatcher,
) : PagingSource<Int, MessageSearchResultItem>() {   // CORRECTED: Int key, single page

    // CORRECTED: single-page source. The endpoint has no cursor/offset, so there is
    // exactly one page; nextKey is always null. (Paging 3 is retained only for the
    // shared LoadState/retry UI plumbing; it loads one bounded array.)
    override suspend fun load(
        params: LoadParams<Int>,
    ): LoadResult<Int, MessageSearchResultItem> = withContext(io) {
        try {
            val list = api.search(
                q = criteria.query.trim(),
                senderId = criteria.senderId,             // sender_id (user id)
                afterTs = criteria.after?.atStartOfDay(ZoneId.systemDefault())
                                 ?.toEpochSecond(),       // after_ts (epoch seconds)
                limit = 200,                              // max; no further pages
            )
            LoadResult.Page(
                data = list.map { it.toItem() },
                prevKey = null,
                nextKey = null,                           // no pagination -> end
            )
        } catch (e: Exception) {
            LoadResult.Error(e)
        }
    }

    override fun getRefreshKey(state: PagingState<Int, MessageSearchResultItem>) = null
}
```

`MessageSearchResultDto.toItem()` lives in `core-data` mappers (converts
`created_at` **epoch-seconds `Long`** → `Instant` via `Instant.ofEpochSecond`,
tolerates a null `text`, and leaves the display-name/title/avatar enrichment fields
to be resolved separately from `sender_id`/`conversation_id`).

### 4.5 Endpoint (`core-network`)

**CORRECTED** to the verified OpenAPI contract (`q`, `limit`, `sender_id`,
`after_ts`, `kind`; response is a bare array — no `cursor`, no page envelope):

```kotlin
interface MessageSearchApi {
    /** Cross-conversation message search. Idempotent GET. Returns a bare array. */
    @GET("messaging/messages/search")
    suspend fun search(
        @Query("q") q: String,                       // required, 1..200 chars
        @Query("sender_id") senderId: String? = null,// user id (<=64), NOT username
        @Query("after_ts") afterTs: Long? = null,    // Unix epoch seconds (>=0)
        @Query("kind") kind: List<String>? = null,   // optional; out of scope v1
        @Query("limit") limit: Int? = null,          // default 50, max 200
    ): List<MessageSearchResultDto>                  // bare array<MessageOut>, no envelope
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

> **Verified against OpenAPI** `GET /messaging/messages/search`
> (`op=search_messages_all_conversations_messaging_messages_search_get`),
> response `200: array<MessageOut>`, `422: HTTPValidationError`.

Query params (CORRECTED to the live contract):
- `q` — **required**, string, 1..200 chars (OpenAPI `minLength:1, maxLength:200`).
  (The spec's UI rule of ≥2 chars is a stricter *client* gate; the backend accepts 1.)
- `sender_id` — optional, string, **maxLength 64** (a **user id**, not a username).
- `after_ts` — optional, **integer Unix epoch seconds**, `minimum: 0`.
- `kind` — optional, array of strings (message kinds). **Out of scope for v1.**
- `limit` — optional, integer, **default 50, min 1, max 200**.
- **There is NO `cursor`/`offset` param and NO pagination.**
- Headers: OpenAPI lists optional `authorization` and `X-SESSION-ID`. The Android
  app relies on the shared cookie session + `X-CSRF-Token` transport (AND-011/012);
  whether cookie-only auth (no `Authorization`/`X-SESSION-ID`) is accepted by the
  server is an **unverified assumption** — confirm against the live host (see §16).

Example request:
```
GET messaging/messages/search?q=deploy&sender_id=usr_1&after_ts=1746057600&limit=200
Cookies: session + ui_csrf      (X-CSRF-Token: <ui_csrf>)
```

Response `200` — a **bare JSON array** of `MessageOut` (no envelope, no
`next_cursor`). Required `MessageOut` fields: `conversation_id`, `message_id`,
`sender_id`, `created_at` (epoch-seconds int), `kind`; `text` is nullable. Note the
absent fields the prior draft assumed (`conversation_title`, `participants`,
`sender_username`, `sender_avatar_url`, `body` — **none exist on `MessageOut`**):
```json
[
  {
    "message_id": "msg_0001",
    "conversation_id": "conv_01HZ",
    "sender_id": "usr_1",
    "kind": "text",
    "text": "we deploy to prod after the deploy freeze",
    "created_at": 1746210060
  }
]
```
There is no last-page sentinel — the array is the entire (limit-bounded) result set.
Sender display name / avatar and conversation title are **not** in the payload and
must be resolved client-side from `sender_id`/`conversation_id` (assumption, §16).

DTOs (`core-model`, Moshi codegen) — CORRECTED to `MessageOut` (no page envelope):
```kotlin
// No MessageSearchPageDto: the response is List<MessageSearchResultDto> directly.

@JsonClass(generateAdapter = true)
data class MessageSearchResultDto(
    @Json(name = "message_id") val messageId: String,
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "sender_id") val senderId: String,
    @Json(name = "kind") val kind: String,
    @Json(name = "text") val text: String? = null,        // nullable on MessageOut
    @Json(name = "created_at") val createdAt: Long,        // epoch SECONDS (integer)
)
```
(`MessageOut` carries many more optional fields — `bot_*`, `file`, `image`,
`reactions`, etc.; v1 deserializes only the subset above, relying on Moshi ignoring
unknown keys. `ParticipantDto` is **not** applicable here — there is no
`participants` array on this response.)

**Error envelope:** OpenAPI documents only `200` and `422: HTTPValidationError` for
this endpoint (FastAPI `detail` is `string | [{loc,msg,type}]`). The call is wrapped
by `safeApiCall` → `ApiResult` (AND-018) and the `detail` mapping (AND-015). `422`
(e.g. `q` empty / >200 chars, malformed `after_ts`/`sender_id`) → inline hint. `401`
(undocumented for this op but produced platform-wide by the session middleware —
mirrors the web `client.ts` 401→refresh→retry-once flow) → AND-013 refresh-then-retry
once. `5xx`/IO/timeouts (also undocumented; expected from the flaky dev host) →
retryable error state.

## 6. Data & State Management

- **No persistence.** Search results are transient and are **not** written to Room
  or DataStore. Result rows live only in the `viewModelScope`-cached `PagingData`.
- **SavedStateHandle (config-change survival):** `search_query` (String),
  `search_sender_id` (String?, CORRECTED from `search_sender`), `search_after`
  (epoch-day Long?). Paging data is not saved; on restore the `criteria` flow
  re-emits and the search re-fetches.
- **Single source of truth:** result list content = `PagingData`; screen status =
  `GlobalSearchUiState.phase` derived from `LoadState` (initial `Loading` →
  `Searching`; `NotLoading` with `itemCount == 0` → `Empty`; with items →
  `Results`; `Error` → `Error`/`Offline`), mirroring AND-122's mapping.
- **Paging contract (CORRECTED):** there is **no cursor envelope** — the endpoint
  returns a single `array<MessageOut>` bounded by `limit` (≤200). The `PagingSource`
  is single-page (`nextKey = null` always); Paging 3 is retained only for the shared
  `LoadState`/retry UI plumbing, not for incremental fetching.
- **Filter composition:** `criteria = (query, senderId, after)`; any change rebuilds
  the `Pager` (new `PagingSource`) so the (single-page) result set is re-fetched.
- **Session state** (cookies/CSRF) is owned by AND-011/012; this layer is unaware.
- **Threading:** API calls run on the injected IO dispatcher; the ViewModel exposes
  flows collected on the main dispatcher by Compose.

## 7. Error Handling & Resilience

- **Timeouts:** the unreliable dev host uses the project-wide ~20s call timeout
  (AND-009); a spinner shows while `phase == Searching` / append `LoadState.Loading`.
- **Retry (idempotent GET):** the search GET is eligible for AND-016 bounded
  backoff (max 2 jittered retries on timeout/5xx/IOException). Initial-load failure
  → `Phase.Error`/`Phase.Offline` with a retry affordance (`retry()` re-issues the
  current criteria → `PagingSource.invalidate()`). **CORRECTED:** there is no
  "append" path (single bounded page, no pagination), so the only failure surface is
  the initial load — no footer-append retry applies.
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
  `Instant` (the wire value is `created_at`, an **epoch-seconds integer** — CORRECTED
  from ISO-8601); date-filter picker respects the device locale. No hardcoded strings.

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
- `GlobalSearchPagingSource` (CORRECTED — single page): first `load` returns a
  `LoadResult.Page` with `nextKey == null`; an exception → `LoadResult.Error`.
  Assert `q`/`sender_id`/`after_ts`/`limit` query params via MockWebServer
  `takeRequest()` (no `cursor` param; `after_ts` is an epoch-seconds integer).
- `MessageSearchResultDto.toItem()`: `created_at` (epoch-seconds `Long`) parses to
  `Instant`; null `text` tolerated; `sender_id`/`conversation_id` carried through
  (display-name/title enrichment resolved separately, not from the payload).
- DTO Moshi round-trip vs captured fixture (AND-046): the **bare array** decodes to
  `List<MessageSearchResultDto>`; unknown `MessageOut` keys ignored; absent optionals
  (e.g. `text`) default to null. (No envelope / no `next_cursor` to assert.)
- Error mapping: `422` → inline hint; `404`/`5xx` → retryable error; `401` path
  delegates to the authenticator (covered by core-network, asserted via
  MockWebServer 401-then-200 retry).

**API contract (MockWebServer, `core-network`):**
- `GET messaging/messages/search?q=deploy&sender_id=usr_1&after_ts=1746057600&limit=200`
  (CORRECTED params): assert verb, resolved path, and every query param; decode the
  **bare array** into `List<MessageSearchResultDto>` from a
  `messaging/messages_search.json` fixture; assert cross-conversation items (≥2
  distinct `conversation_id`s). (No `next_cursor` to assert — none in the response.)

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
array, empty array, error). **CORRECTED:** there is no "second page via cursor" — the
endpoint returns one bounded array. MockWebServer covers retry / timeout /
401-refresh integration.

Coverage target: ≥85% on the new ViewModel/repository/PagingSource/DTO surface; the
nav-args assertion explicitly covers the "opens results" bullet.

## 12. Dependencies & Sequencing

**Hard upstream (must merge first):**
- **AND-120 (Messaging API + DTOs)** — backlog-named dependency; supplies the
  transport conventions and the shared Retrofit/Hilt provider this ticket extends.
  **CORRECTED:** the `{ items, next_cursor }` cursor envelope and `ParticipantDto`
  do **not** apply to this endpoint (bare `array<MessageOut>`, no participants in the
  payload); only the wider transport/DI conventions are reused.

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

- **R-1 Route prefix / param names — RESOLVED (verified).** Route is
  `GET /messaging/messages/search`; params are `q`, `sender_id`, `after_ts`, `kind`,
  `limit` (OpenAPI). Residual risk is param drift; path/param assertions catch it. (Q-1)
- **R-2 `sender` filter semantics — RESOLVED (verified).** `sender_id` is a **user
  id** (≤64 chars), not a username; v1 must resolve username→id (e.g. via
  `/messaging/contacts/search`) rather than send free text. (Q-4)
- **R-3 `after` format — RESOLVED (param) / OPEN (semantics).** `after_ts` is an
  **integer Unix epoch-seconds** (not ISO-8601). Inclusivity (`>=`/`>`) and the zone of
  the day-boundary are undocumented; send epoch-seconds and pin observed behavior in a
  test. (Q-2)
- **R-4 Result envelope shape — RESOLVED (verified).** The endpoint returns a **bare
  `array<MessageOut>`** with **no pagination** (no cursor/offset/envelope); the
  contract test asserts the array shape and the single-page `PagingSource`
  (`nextKey==null`). If true pagination is ever needed it requires a backend change.
- **R-5 Deep-link contract with AND-123.** The `focusMessageId` argument name /
  scroll behavior is owned by AND-123. Mitigation: agree the nav-arg contract during
  grooming; this ticket only passes `conversationId` + target id. (Q-3)
- **R-6 Large/common-term result volume + relevance ordering.** Very common terms
  could return huge result sets; paging bounds memory, but ordering (recency vs
  relevance score) affects UX. Mitigation: confirm backend ordering; default to
  recency. (Q-2)
- **Q-1 RESOLVED (verified).** Route is `GET /messaging/messages/search` (OpenAPI
  `op=search_messages_all_conversations_messaging_messages_search_get`). The
  `messaging/` prefix is confirmed.
- **Q-2 RESOLVED (partly).** `after` is **`after_ts`, an integer Unix epoch-seconds**
  (not ISO-8601); inclusivity is undocumented (assume `>=`, confirm live). **Result
  ordering is NOT documented by OpenAPI** — recency-desc remains an assumption to
  confirm against the live backend (§16, Open assumptions).
- **Q-3 (unchanged, unverifiable here).** Nav-argument `focusMessageId` is owned by
  AND-123; no source in this reference set confirms it — cross-ticket assumption (§16).
- **Q-4 RESOLVED (verified).** `sender` is **`sender_id`, a user id string** (≤64),
  **not** a username — v1 must resolve a username→id (e.g. via
  `/messaging/contacts/search`). Clearing the query keeps filters until removed
  (a UX choice, not a backend constraint).

## 14. Acceptance Criteria

- **AC-1 (backlog).** Entering a ≥2-char query calls
  `GET messaging/messages/search?q=...` and renders matching messages drawn from
  **more than one conversation** (cross-conversation), with the query substring
  highlighted in each result. *(maps to "Cross-conversation search returns")*
- **AC-2 (backlog).** Tapping a result navigates to the Thread screen (AND-123) for
  that result's `conversation_id`, passing the result's `message_id` as the scroll
  target. *(maps to "opens results")*
- **AC-3 (filters).** (CORRECTED) The sender filter sends `&sender_id=<userId>` and
  the after filter sends `&after_ts=<epochSeconds>`; both are reflected as removable
  chips, compose with `q`, and re-issue the search from a fresh fetch.
- **AC-4 (results bounding).** (CORRECTED — endpoint has no pagination) Results are
  a single bounded array (`limit` ≤200) rendered via a single-page Paging 3 source;
  there is no cursor/append. Initial-load errors show a retryable error state.
- **AC-5 (states).** Distinct idle-prompt / `<2`-char hint / loading / empty
  ("No messages match") / error (retryable) / offline states render via the
  `core-ui` state composables.
- **AC-6 (debounce + cancellation).** Rapid typing issues a single search for the
  settled query; stale responses never overwrite newer ones (`flatMapLatest`).
- **AC-7 (DTO mapping).** (CORRECTED) The **bare `array<MessageOut>`** decodes via
  Moshi codegen into `List<MessageSearchResultDto>` vs captured fixtures;
  `created_at` epoch-seconds `Long` maps to `Instant`; unknown `MessageOut` keys
  ignored; absent optionals (e.g. `text`) default to `null`. (No envelope/`next_cursor`.)
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
- JSON fixtures captured (via AND-046) for a multi-conversation results array and an
  empty array, matching live backend shapes. (CORRECTED: no "cursor second page" —
  the endpoint returns a single bounded array, no pagination.)
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

## 16. Citations & Assumption Audit

Each key technical claim below is listed with its VERDICT (Verified / Corrected /
Unverified-assumption) and an exact source pointer. OpenAPI pointers use the form
`METHOD /path` and/or schema name; frontend pointers use a repo path + symbol.

1. **Endpoint path & method = `GET /messaging/messages/search`.**
   VERDICT: **Verified.** SOURCE: OpenAPI `GET /messaging/messages/search`
   (`op=search_messages_all_conversations_messaging_messages_search_get`),
   `openapi.index.txt` line 412.
2. **Search is an idempotent GET (retry-eligible).**
   VERDICT: **Verified.** SOURCE: same op (HTTP GET).
3. **Required query param `q` (string, 1..200 chars).**
   VERDICT: **Verified.** SOURCE: OpenAPI param `q` (`minLength:1, maxLength:200,
   required:true`). NOTE: spec's client-side ≥2-char gate is stricter than the
   backend's 1-char minimum — a deliberate UX rule, not a contract mismatch.
4. **Sender filter param is `sender_id` (user-id string, maxLength 64) — NOT a
   `sender` username.** VERDICT: **Corrected.** SOURCE: OpenAPI param `sender_id`
   (`anyOf:[{maxLength:64,type:string},null]`). The draft's `sender`/username was wrong.
5. **After filter param is `after_ts` (integer Unix epoch seconds, `minimum:0`) — NOT
   an ISO-8601 `after` string.** VERDICT: **Corrected.** SOURCE: OpenAPI param
   `after_ts` (`anyOf:[{minimum:0,type:integer},null]`).
6. **`limit` default 50, min 1, max 200 — NOT default 30.**
   VERDICT: **Corrected.** SOURCE: OpenAPI param `limit`
   (`default:50, minimum:1, maximum:200`).
7. **Optional `kind` param (array of strings) exists; out of scope for v1.**
   VERDICT: **Verified** (existence). SOURCE: OpenAPI param `kind`
   (`anyOf:[{items:{type:string},type:array},null]`).
8. **No `cursor`/`offset` param and no pagination.**
   VERDICT: **Corrected.** SOURCE: OpenAPI parameter list for the op contains only
   `q,limit,sender_id,after_ts,kind,authorization,X-SESSION-ID` — no cursor/offset.
9. **Response 200 is a bare `array<MessageOut>` — NOT a `{items,next_cursor}`
   envelope and NOT a `MessageSearchResult`/`MessageSearchPageDto`.**
   VERDICT: **Corrected.** SOURCE: OpenAPI 200 schema `type:array,
   items:$ref MessageOut`; no `next_cursor` in this op's response; no
   `MessageSearchResult` schema exists in `openapi.pretty.json` or
   `src/api/types.ts`.
10. **`MessageOut` required fields = `conversation_id, message_id, sender_id,
    created_at, kind`; `created_at` is an integer (epoch seconds); `text` is
    nullable.** VERDICT: **Verified.** SOURCE: `components.schemas.MessageOut`
    `required` array + `created_at:{type:integer}`, `text:{anyOf:[string,null]}`.
11. **`MessageOut` has NO `sender_username`, `sender_avatar_url`,
    `conversation_title`, `participants`, or `body`.** VERDICT: **Corrected**
    (draft assumed all of these). SOURCE: full `MessageOut` property scan in
    `openapi.pretty.json` — none of those keys present; sender identity is only
    `sender_id` (plus `sender_type` enum user|bot); message text is `text`.
12. **The web client has NO global-message-search call; OpenAPI is the sole contract
    source.** VERDICT: **Corrected** (draft cited a nonexistent
    `messaging.ts` global-search call and `types.ts` `MessageSearchResult`).
    SOURCE: `src/api/endpoints/messaging.ts` (only `searchUsers` →
    `/messaging/contacts/search`, line 527); no `MessageSearchResult` in
    `src/api/types.ts`.
13. **Error responses documented for this op = `200`, `422 HTTPValidationError`
    only.** VERDICT: **Verified.** SOURCE: OpenAPI op `responses` (200, 422). NOTE:
    `404`/`5xx` are undocumented for this op (draft listed `404` explicitly — softened).
14. **Auth transport = cookie session + `ui_csrf` cookie → `X-CSRF-Token` header,
    applied to all requests (incl. GET); `401` → refresh-then-retry once → terminal
    logout.** VERDICT: **Verified** (web contract). SOURCE: `src/api/client.ts`
    `getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)` (lines 167-171),
    `credentials:"include"` (line 183), 401 refresh-retry-once block (lines 194-226).
15. **`detail` error union mapping (`string | [{loc,msg,type}]`).**
    VERDICT: **Verified.** SOURCE: `HTTPValidationError`/`ValidationError` schemas
    in `openapi.pretty.json`; `normalizeErrorDetail(...detail...)` in `client.ts`.
16. **Sibling in-conversation search `GET /conversations/{id}/messages/search` uses
    the same `sender_id`/`after_ts`/`kind` param vocabulary (AND-151 consistency).**
    VERDICT: **Verified.** SOURCE: OpenAPI `openapi.index.txt` line 345
    (`params=conversation_id,q,limit,sender_id,after_ts,kind,...`).

**Framework references (design choices, not backend contract):**
17. **Paging 3 `PagingSource`/`Pager`/`LoadState`/`cachedIn`.** framework ref:
    https://developer.android.com/topic/libraries/architecture/paging/v3-overview .
    NOTE: used here only for shared LoadState/retry UI plumbing over a single page.
18. **`SavedStateHandle` for config-change survival.** framework ref:
    https://developer.android.com/topic/libraries/architecture/viewmodel/viewmodel-savedstate .
19. **Hilt `@HiltViewModel`/`@Provides`.** framework ref:
    https://developer.android.com/training/dependency-injection/hilt-android .
20. **Material 3 `DatePicker` for the after filter.** framework ref:
    https://developer.android.com/develop/ui/compose/components/datepickers .

### Corrections made

- C1. `sender` → **`sender_id`** (user-id string, not username) — §2, §3 FR-3, §4
  (criteria/endpoint/repo/source), §5, §6, §14 AC-3, §16#4.
- C2. `after` ISO-8601 string → **`after_ts` integer epoch-seconds** — §3 FR-4, §4,
  §5, §14 AC-3, §16#5.
- C3. `{items,next_cursor}` cursor envelope / `MessageSearchPageDto` → **bare
  `array<MessageOut>`, no pagination, single-page `PagingSource`** — §1, §2, §3 FR-7,
  §4 (model/DTO/repo/source/pager key `String`→`Int`), §5, §6, §7, §11, §14 AC-4/AC-7,
  §15, §16#8/#9.
- C4. Removed nonexistent `MessageOut` fields (`sender_username`, `sender_avatar_url`,
  `conversation_title`, `participants`, `body`); matched text is **`text`** (nullable),
  sender is only `sender_id` — §3 FR-6, §4.2, §5, §16#11. Display name/title/avatar now
  flagged as client-side enrichment.
- C5. `created_at` ISO-8601 `String` → **epoch-seconds `Long`** (parse via
  `Instant.ofEpochSecond`) — §4.2/§4.4, §5, §11, §14 AC-7.
- C6. `limit` default 30 → **default 50 / max 200** — §4, §5, §16#6.
- C7. "Web reference is source of truth for this endpoint" → corrected: **no web
  call exists; OpenAPI is the sole source** — §2, §16#12.
- C8. Removed `404` from the explicitly-documented error list (only `200`/`422`
  documented); kept `401`/`5xx`/IO as platform-wide/operational handling — §5, §16#13.
- C9. `SavedStateHandle` key `search_sender` → `search_sender_id` — §4.3, §6.

### Open assumptions (unverifiable from the provided sources)

- A1. **Result ordering** (recency-desc vs relevance). OpenAPI documents no sort order
  for this op and there is no web client to observe. WHY unverifiable: not expressible
  in OpenAPI; needs a live-host probe. Pin the observed order in a contract test.
- A2. **`after_ts` inclusivity** (`>=` vs `>`) and **timezone** of the epoch boundary.
  WHY: not in OpenAPI; confirm against the live backend; tests should pin it.
- A3. **Sender/conversation display enrichment** — resolving `sender_id` →
  username/avatar and `conversation_id` → title requires a secondary call/cache; the
  exact source (conversation list cache vs `/messaging/contacts/search`) is a design
  choice not dictated by this endpoint. WHY: payload lacks these fields.
- A4. **Cookie-only auth acceptance.** OpenAPI lists optional `authorization` +
  `X-SESSION-ID` headers; whether the server accepts the Android cookie-session +
  `X-CSRF-Token` transport WITHOUT those headers is unproven here. WHY: header
  requirements are `required:false` but server-side enforcement is opaque; confirm live.
- A5. **`401` behavior for this specific op** is inferred from the web `client.ts`
  global flow (op documents only 200/422). WHY: not documented per-op; assumed
  platform-wide via session middleware.
- A6. **AND-123 `focusMessageId` nav-argument name & scroll/pulse behavior.** WHY:
  cross-ticket dependency, no source in this reference set — confirm with AND-123 (Q-3).
- A7. **`kind` enum values** for any future kind filter. WHY: OpenAPI types `kind` as a
  free `array<string>`; concrete values (e.g. `text`, `file`) are not enumerated for
  the param. Out of scope for v1 regardless.

## 17. Test Plan

Test IDs `TC-AND-152-NN`. Targets: **JVM** (local JUnit/Robolectric, no device);
**Emulator** = headless AVD `test35` (x86_64, API 35) for fast CI UI/instrumented
suites; **Physical** = Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34,
arm64-v8a) for cases needing real hardware/ABI/API-34 behavior. This ticket is a
network + Compose-UI feature with no camera/biometrics/WebRTC/FCM/Telecom surface, so
most cases run on JVM/Emulator; physical-device cases are limited to real-host
network/offline behavior and an arm64/API-34 smoke (TC-12, TC-13).

- **TC-AND-152-01 — Happy path: cross-conversation results + highlight.**
  Type: unit + Compose-UI. Target: JVM (unit) / Emulator (Compose).
  Preconditions: `FakeMessageSearchApi`/MockWebServer returns a bare array with ≥2
  distinct `conversation_id`s, each `text` containing "deploy".
  Steps: enter "deploy"; wait past 300 ms debounce.
  Expected: `GET messaging/messages/search?q=deploy&limit=...` issued; rows from ≥2
  conversations render; "deploy" substring highlighted (assert highlight semantics).
  Traces: AC-1, AC-6.

- **TC-AND-152-02 — Open result deep-links to thread with correct args.**
  Type: Compose-UI (TestNavHostController). Target: Emulator.
  Preconditions: results rendered (as TC-01).
  Steps: tap a row whose `conversation_id=conv_X`, `message_id=msg_Y`.
  Expected: nav to `messaging/thread/conv_X?focusMessageId=msg_Y`; back returns to
  search with query/filters/scroll intact. Traces: AC-2, AC-9.

- **TC-AND-152-03 — Param mapping contract (sender_id, after_ts, limit).**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: MockWebServer enqueues a 200 array.
  Steps: search q="deploy", senderId="usr_1", after=2026-05-01 (→ epoch-seconds),
  limit=200.
  Expected: `takeRequest()` path = `/messaging/messages/search`, method GET, query =
  `q=deploy&sender_id=usr_1&after_ts=<epochSeconds>&limit=200`; **no** `cursor` and
  **no** `sender`/`after` legacy params. Traces: AC-3.

- **TC-AND-152-04 — DTO decode of bare array (epoch-seconds, nullable text, unknown
  keys).** Type: unit (Moshi). Target: JVM.
  Preconditions: fixture `messaging/messages_search.json` = JSON array of `MessageOut`
  objects, some with `text:null`, extra unknown keys (`file`, `reactions_counts`).
  Steps: decode to `List<MessageSearchResultDto>`; map `.toItem()`.
  Expected: list size matches; `created_at` Long → `Instant.ofEpochSecond`; null
  `text` tolerated; unknown keys ignored; no envelope expected. Traces: AC-7.

- **TC-AND-152-05 — Single-page PagingSource (no cursor).**
  Type: unit. Target: JVM.
  Preconditions: fake returns a 3-item array.
  Steps: invoke `PagingSource.load(Refresh)`.
  Expected: `LoadResult.Page` with `data.size==3`, `prevKey==null`, **`nextKey==null`**
  (no further pages). Traces: AC-4.

- **TC-AND-152-06 — Debounce coalescing + flatMapLatest cancellation.**
  Type: unit (Turbine + coroutines-test virtual time). Target: JVM.
  Preconditions: ViewModel with fake repo recording calls.
  Steps: emit "d","de","dep","depl" within <300 ms, then idle; then quickly change
  filters mid-flight.
  Expected: exactly ONE network search for the settled query "depl"; stale in-flight
  results never overwrite the newest criteria's `PagingData`. Traces: AC-6.

- **TC-AND-152-07 — Query validation gate (<2 chars / blank).**
  Type: unit + Compose-UI. Target: JVM / Emulator.
  Preconditions: fresh screen.
  Steps: type "d"; then clear.
  Expected: no network call; `Phase.TooShort` hint ("Type at least 2 characters")
  for "d"; `Phase.Idle` prompt when blank. Traces: AC-5, AC-6.

- **TC-AND-152-08 — 422 validation error → inline hint (real shape).**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: enqueue 422 with body
  `{"detail":[{"loc":["query","q"],"msg":"...","type":"string_too_long"}]}`.
  Steps: search a >200-char query (or force malformed `after_ts`).
  Expected: mapped to inline hint on the offending field; NOT a full-screen error;
  no crash. Traces: AC-5, AC-8.

- **TC-AND-152-09 — 401 → refresh-then-retry once, then results.**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: enqueue 401, then (after refresh) 200 array.
  Steps: issue a search.
  Expected: exactly one session refresh + one retry; final state renders results; a
  terminal second 401 routes to login (assert single retry, no loop). Traces: AC-8.

- **TC-AND-152-10 — Empty results vs error distinction.**
  Type: Compose-UI. Target: Emulator.
  Preconditions: (a) fake returns empty array `[]`; (b) fake returns 5xx.
  Steps: search in each.
  Expected: (a) `Phase.Empty` "No messages match" (not an error); (b) retryable
  error state; tapping retry re-issues. Traces: AC-4, AC-5, AC-8.

- **TC-AND-152-11 — SavedStateHandle persistence across rotation.**
  Type: Compose-UI/instrumented. Target: Emulator.
  Preconditions: query="deploy", sender chip set (sender_id), after chip set.
  Steps: rotate device (config change / recreate activity).
  Expected: `search_query`, `search_sender_id`, `search_after` restored; chips +
  query shown; results re-fetched. Traces: AC-9.

- **TC-AND-152-12 — Flaky-host retry + offline path on REAL network.**
  Type: instrumented/e2e. Target: **Physical (must)** — needs real radio/connectivity
  and real socket timeouts against the unreliable plaintext dev host.
  Preconditions: device on the build host's network; dev host
  `http://18.222.237.167:8000` reachable; then toggle airplane mode for the offline leg.
  Steps: (a) search and let a slow/timed-out GET trigger AND-016 bounded backoff
  (≤2 jittered retries); (b) enable airplane mode and retry.
  Expected: (a) spinner during `Searching`, eventual success or retryable error after
  bounded retries; (b) offline → retryable `Phase.Offline`, no crash, retry works on
  reconnect. WHY physical: emulator network is too clean to reproduce real
  timeout/offline behavior. Traces: AC-8, AC-5.

- **TC-AND-152-13 — arm64 / API-34 cleartext + decode smoke.**
  Type: instrumented/e2e. Target: **Physical (must)** — arm64-v8a / API 34 differs
  from the x86_64/API-35 emulator (NDK/cleartext-config/JSON behavior).
  Preconditions: app installed on SM-A156U; cleartext permitted for dev host (AND-006).
  Steps: run one end-to-end search against the dev host and open a result.
  Expected: cleartext HTTP to dev host succeeds on API 34; bare-array decode works on
  arm64; deep-link opens the thread. Traces: AC-1, AC-2, AC-11.

- **TC-AND-152-14 — Privacy: no raw query/sender/body in logs or telemetry.**
  Type: unit + manual. Target: JVM (assert telemetry payloads) + manual logcat review.
  Preconditions: telemetry sink captured in test; release-style logging.
  Steps: perform a search with a distinctive query and a result body; inspect emitted
  events and logcat.
  Expected: events carry only `query_length` + boolean filter flags (no raw `q`,
  `sender_id` value, or `text`); no message body in logcat; nothing written to
  disk/DataStore. Traces: AC-10.

- **TC-AND-152-15 — Accessibility checks.**
  Type: Compose-UI (a11y). Target: Emulator.
  Preconditions: results + chips rendered.
  Steps: assert semantics: contentDescriptions on search field, clear-X, filter chips
  + remove affordances, back/close; result row is one `role=Button` focusable target
  with combined label; touch targets ≥48dp; status (`Empty`/`Searching`/counts)
  announced via a polite `liveRegion`; highlight uses bold weight (not color-only).
  Traces: AC-10 (privacy-safe labels), AC-5; supports AC-11.

### Coverage matrix (§14 AC → covering TCs)

| AC | Covered by |
|----|------------|
| AC-1  (cross-conversation returns + highlight) | TC-01, TC-13 |
| AC-2  (open result → thread deep-link)          | TC-02, TC-13 |
| AC-3  (sender_id/after_ts filters compose)      | TC-03 |
| AC-4  (single bounded result set, no append)    | TC-05, TC-10 |
| AC-5  (idle/short/loading/empty/error/offline)  | TC-07, TC-08, TC-10, TC-12 |
| AC-6  (debounce + flatMapLatest cancellation)   | TC-01, TC-06, TC-07 |
| AC-7  (bare-array Moshi decode, epoch-seconds)  | TC-04 |
| AC-8  (retry/backoff, 401-once, 422 hint)       | TC-08, TC-09, TC-12 |
| AC-9  (query+filters survive rotation)          | TC-02, TC-11 |
| AC-10 (no PII in logs/telemetry)                | TC-14, TC-15 |
| AC-11 (build/quality, all tests green)          | TC-13 + full suite (TC-01..15) |
