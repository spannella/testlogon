---
id: AND-153
title: Contacts list + search
milestone: M3
epic: E21
priority: P1
size: M
status: draft
depends_on: [AND-120]
blocks: [AND-154]
---

# AND-153 — Contacts list + search

## 1. Overview & Goal

Deliver a **Contacts** feature surface for the TestLogon Android app that lists the
authenticated user's messaging contacts and lets the user find a contact by typing a
name or name *fragment*. The screen is the entry point into the messaging-people graph:
selecting a contact is consumed by **AND-154** (Contact → start conversation) to open a
profile / start a DM. This ticket owns the list UI, the search input, the
`/messaging/contacts/search` integration (name tokenization), paging, and the empty /
loading / error / offline states. It does **not** own conversation creation or profile
rendering (AND-154), nor cross-conversation message search (AND-152).

Concretely the goal is: given a query string `q`, calling the contacts search endpoint
returns matching contacts whose display name contains the queried token(s), rendered as a
scrollable, paged list; an empty `q` returns the full contact set (first page). The
acceptance bar is: **search by full name and by partial name fragment both return the
expected contacts and render them.**

This is a `feature-messaging` module addition layered on the `MessagingApi` shipped in
AND-120. No new backend work; we consume the existing FastAPI endpoint.

## 2. Context & References

- **Repo / branch:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`.
- **Namespace:** all new code under `com.testlogon.android` (module
  `feature-messaging` → `com.testlogon.android.feature.messaging.contacts`).
- **Module layering:** `app → feature-messaging → core-network, core-model, core-data,
  core-ui, core-testing`. This ticket adds code to `feature-messaging` and DTOs/models to
  `core-model`; it reuses the Retrofit service + auth/cookie/CSRF plumbing in
  `core-network`.
- **Upstream dependency — AND-120 (Messaging API + DTOs):** provides `MessagingApi`
  (Retrofit interface), the `ApiResult<T>` wrapper, Moshi setup, and the FastAPI
  `detail` error mapping. This ticket extends `MessagingApi` with the contacts-search
  call and adds the contact DTO/domain model.
- **Downstream — AND-154:** consumes the `Contact` domain model and a click callback
  `onContactClick(contactId: String)` exposed by this screen.
- **Sibling — AND-152 (Global message search):** uses
  `/messaging/messages/search`; **distinct** endpoint and screen — do not merge.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` is **plaintext
  HTTP and unreliable**: ~20s timeouts, bounded backoff retry for idempotent GETs only,
  explicit offline/stale UI. OpenAPI at `/openapi.json`; web reference for the contacts
  endpoint and shapes lives in `frontend/src/api/endpoints/messaging.ts` and
  `frontend/src/api/types.ts` (confirm exact field names against these and
  `/openapi.json` during implementation).
- **Auth:** cookie-based session + `ui_csrf` cookie echoed as `X-CSRF-Token`; persistent
  cookie jar; on 401 the client does `POST /ui/session/refresh` once then retries. All of
  this is already handled by the `core-network` OkHttp stack; the contacts call inherits
  it.

## 3. Functional Requirements

1. **List on entry.** On first composition the screen requests the first page of contacts
   with an empty query and renders them in a vertically scrolling list. Each row shows
   avatar (Coil), display name, and an optional secondary line (username / handle if
   present).
2. **Search by name or fragment.** A search field at the top filters contacts via
   `/messaging/contacts/search?q=<token>`. Server-side name tokenization means a fragment
   (`"ali"`) matches `"Alice Nguyen"` and `"Khalil"`-style substrings per backend rules;
   the client sends the raw trimmed query and renders whatever the server returns. Search
   is **debounced** (300 ms) and trims leading/trailing whitespace.
3. **Empty query.** Clearing the field (or whitespace-only) reverts to the full first
   page (empty-`q` behavior).
4. **Paging.** Results are paged with Paging 3 (`PagingData<Contact>`); scrolling to the
   end loads the next page. Search query is part of the paging key, so changing `q`
   resets paging from page 1.
5. **States.** The screen renders distinct UI for: initial load (skeleton/spinner),
   loaded list, append-loading footer, empty result ("No contacts match \"q\""), error
   (with Retry), and offline/stale (cached results + banner).
6. **Selection.** Tapping a row invokes `onContactClick(contactId)`; navigation target is
   wired by AND-154. This ticket only emits the event and provides the nav route stub.
7. **Clear / cancel.** A clear (×) affordance empties the field; back dismisses the
   screen.
8. **Result ordering.** Preserve server order (the backend returns ranked/sorted
   results); the client does not re-sort.

## 4. Technical Design

New package `com.testlogon.android.feature.messaging.contacts`.

### 4.1 Domain model (core-model)

```kotlin
data class Contact(
    val id: String,
    val displayName: String,
    val username: String?,      // handle, nullable
    val avatarUrl: String?,
    val presence: Presence = Presence.UNKNOWN,
)

enum class Presence { ONLINE, OFFLINE, UNKNOWN }
```

### 4.2 API surface (extends AND-120 `MessagingApi`)

```kotlin
interface MessagingApi {
    // ...existing AND-120 members...

    @GET("/messaging/contacts/search")
    suspend fun searchContacts(
        @Query("q") query: String?,         // null/blank => full list
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = PAGE_SIZE,
    ): ContactSearchResponseDto

    companion object { const val PAGE_SIZE = 30 }
}
```

DTOs (Moshi, `core-model`):

```kotlin
@JsonClass(generateAdapter = true)
data class ContactSearchResponseDto(
    @Json(name = "items") val items: List<ContactDto>,
    @Json(name = "next_cursor") val nextCursor: String?,
    @Json(name = "total") val total: Int? = null,
)

@JsonClass(generateAdapter = true)
data class ContactDto(
    @Json(name = "id") val id: String,
    @Json(name = "display_name") val displayName: String,
    @Json(name = "username") val username: String? = null,
    @Json(name = "avatar_url") val avatarUrl: String? = null,
    @Json(name = "presence") val presence: String? = null,
)

fun ContactDto.toDomain() = Contact(
    id = id,
    displayName = displayName,
    username = username,
    avatarUrl = avatarUrl,
    presence = when (presence?.lowercase()) {
        "online" -> Presence.ONLINE
        "offline" -> Presence.OFFLINE
        else -> Presence.UNKNOWN
    },
)
```

> Field names (`display_name`, `next_cursor`, etc.) are the assumed snake_case FastAPI
> convention; **verify against `/openapi.json` and `frontend/src/api/types.ts`** and
> adjust `@Json` names only — domain model stays stable. (See Risks §13.)

### 4.3 Repository + paging (core-data / feature-messaging)

```kotlin
class ContactsRepository @Inject constructor(
    private val api: MessagingApi,
) {
    fun contacts(query: String): Flow<PagingData<Contact>> =
        Pager(
            config = PagingConfig(pageSize = MessagingApi.PAGE_SIZE, enablePlaceholders = false),
            pagingSourceFactory = { ContactsPagingSource(api, query.trim()) },
        ).flow
}

class ContactsPagingSource(
    private val api: MessagingApi,
    private val query: String,
) : PagingSource<String, Contact>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, Contact> =
        try {
            val resp = api.searchContacts(
                query = query.ifBlank { null },
                cursor = params.key,
                limit = params.loadSize,
            )
            LoadResult.Page(
                data = resp.items.map { it.toDomain() },
                prevKey = null,                 // forward-only cursor paging
                nextKey = resp.nextCursor,
            )
        } catch (t: Throwable) {
            LoadResult.Error(t)
        }

    override fun getRefreshKey(state: PagingState<String, Contact>): String? = null
}
```

### 4.4 ViewModel

```kotlin
@HiltViewModel
class ContactsViewModel @Inject constructor(
    private val repo: ContactsRepository,
) : ViewModel() {

    private val query = MutableStateFlow("")

    val queryText: StateFlow<String> = query.asStateFlow()

    @OptIn(FlowPreview::class, ExperimentalCoroutinesApi::class)
    val contacts: Flow<PagingData<Contact>> =
        query
            .debounce(300)
            .map { it.trim() }
            .distinctUntilChanged()
            .flatMapLatest { repo.contacts(it) }
            .cachedIn(viewModelScope)

    fun onQueryChange(value: String) { query.value = value }
    fun onClear() { query.value = "" }
}
```

### 4.5 UI (Compose + Material 3)

```kotlin
@Composable
fun ContactsRoute(
    onContactClick: (String) -> Unit,
    viewModel: ContactsViewModel = hiltViewModel(),
)

@Composable
fun ContactsScreen(
    query: String,
    items: LazyPagingItems<Contact>,
    onQueryChange: (String) -> Unit,
    onClear: () -> Unit,
    onContactClick: (String) -> Unit,
)
```

- `SearchBar` / `OutlinedTextField` with leading search icon, trailing clear icon when
  non-empty, `imeAction = Search`, `singleLine = true`.
- `LazyColumn` driven by `items.itemCount`; row = `ContactRow(contact, onContactClick)`
  using `AsyncImage` (Coil) for the avatar with an initials placeholder.
- Footer item reflects `items.loadState.append` (spinner / Retry).
- Refresh state (`items.loadState.refresh`) drives full-screen skeleton / empty / error.

### 4.6 Navigation

Add route `messaging/contacts` to the Navigation-Compose graph; `onContactClick` resolves
to the AND-154 destination (`messaging/profile/{contactId}`), left as a TODO/stub route
in this ticket so AND-154 only wires the destination.

## 5. API Contract

**Endpoint:** `GET /messaging/contacts/search`
**Auth:** session cookies + `X-CSRF-Token` (handled by `core-network`).
**Idempotent GET** — eligible for bounded backoff retry.

Query params:

| param | type | notes |
|-------|------|-------|
| `q` | string? | trimmed query; omit/blank for full list. Tokenized server-side. |
| `cursor` | string? | opaque forward cursor; omit for first page. |
| `limit` | int | page size, default 30. |

Request example: `GET /messaging/contacts/search?q=ali&limit=30`

Response `200`:

```json
{
  "items": [
    {
      "id": "u_1029",
      "display_name": "Alice Nguyen",
      "username": "alice",
      "avatar_url": "https://.../u_1029.png",
      "presence": "online"
    }
  ],
  "next_cursor": "eyJvZmZzZXQiOjMwfQ==",
  "total": 1
}
```

Empty result `200`: `{"items": [], "next_cursor": null, "total": 0}`.

**Errors** (FastAPI `detail` mapping from AND-120):

- `401 Unauthorized` → client performs `POST /ui/session/refresh` once, then retries the
  GET. Second 401 → surface auth-expired and route to login (owned by core-network +
  session feature; this screen just shows the error state).
- `422 Unprocessable Entity` → `detail` is `[{"loc", "msg", "type"}]`; map first `msg`.
- `4xx/5xx` with `{"detail": "string"}` or `{"detail": {"code": ...}}` → map per the
  shared `ApiResult` error decoder.
- Network timeout / connection failure → `IOException` → offline state.

## 6. Data & State Management

- **UI state:** Paging 3 `LazyPagingItems<Contact>` + a `StateFlow<String>` for query
  text. No bespoke sealed `UiState` is needed for the list body — Paging's
  `CombinedLoadStates` (`refresh`, `append`, `prepend`) is the source of truth; the search
  text is the only separate piece of mutable state.
- **State derivation:**
  - `refresh is LoadState.Loading` → skeleton.
  - `refresh is LoadState.NotLoading && itemCount == 0` → empty (`No contacts match "q"`
    when `q` non-blank, else `No contacts yet`).
  - `refresh is LoadState.Error` → full-screen error w/ Retry (`items.retry()`).
  - `append` mirrors footer spinner / retry.
- **Caching (offline/stale):** `cachedIn(viewModelScope)` retains paged results across
  config changes. For the **empty-query first page only**, persist the last successful
  page to a Room table `cached_contacts(id, display_name, username, avatar_url, presence,
  cached_at)` via `core-data`, so the list renders instantly and survives an offline cold
  start; a stale banner appears when served from cache after a failed network refresh.
  Search-query results are **not** cached (transient).
- **Query as key:** changing `q` triggers `flatMapLatest` → a new `Pager` → paging resets
  to page 1; the previous in-flight request is cancelled.
- **DataStore:** no preferences owned here.

## 7. Error Handling & Resilience

- **Timeouts:** rely on the `core-network` OkHttp client configured for ~20s
  call/read/connect timeouts.
- **Retry policy:** `searchContacts` is an idempotent GET → eligible for the shared
  bounded exponential backoff interceptor (max 2 retries, jittered, GET-only). Manual
  `items.retry()` is also offered in error/append states.
- **401 handling:** single `POST /ui/session/refresh` then retry, via the existing
  authenticator/interceptor; not re-implemented here.
- **Empty vs error:** distinguish HTTP-200-empty (empty state) from transport/HTTP error
  (error state) — never show "no results" for a failed request.
- **Offline:** on `IOException` with cached empty-query data available, render cache +
  "Offline — showing saved contacts" banner; with no cache, render error state with
  Retry.
- **Debounce + cancel:** rapid typing cancels superseded requests via `flatMapLatest`,
  preventing out-of-order list flicker.
- **Unreliable dev host:** treat intermittent 5xx like network errors (Retry-able); log
  at WARN, do not crash.

## 8. Security & Privacy

- All requests inherit the cookie session + `ui_csrf` → `X-CSRF-Token` header; the
  persistent cookie jar is the only credential store. No tokens are added to logs or to
  the Room cache.
- The dev backend is **plaintext HTTP**; `usesCleartextTraffic` / a network-security
  config permitting the dev host is already established by core-network for non-release
  builds only. Release builds must not ship cleartext to arbitrary hosts (out of scope
  here, but do not regress it).
- Cached contacts in Room contain display name, username, avatar URL — low-sensitivity
  but still user data; cache is app-private storage, cleared on logout (hook into the
  existing session-clear path: add `cachedContactsDao().clear()` to the logout cleanup).
- Search query strings are user PII-adjacent; never persist queries, never log raw query
  text at INFO+ in release (see §10).

## 9. Accessibility & i18n

- Search field: `contentDescription`/label "Search contacts"; clear button
  "Clear search"; TalkBack-focusable, IME `Search` action.
- Contact rows: merged semantics announcing display name + presence ("Alice Nguyen,
  online"); min touch target 48dp; avatar marked decorative when an initials fallback is
  shown.
- All user-visible strings in `strings.xml` (`feature-messaging`):
  `contacts_title`, `contacts_search_hint`, `contacts_empty_query` (with `%1$s`
  placeholder), `contacts_empty_default`, `contacts_error`, `contacts_offline_banner`,
  `contacts_retry`, `contacts_clear_cd`. No hardcoded UI text. Plurals not required.
- RTL supported via standard Compose start/end paddings.
- Respect dynamic font scaling; rows use wrap-content height.

## 10. Telemetry & Logging

- **Events** (via existing analytics abstraction in `core-data`):
  - `contacts_screen_view`
  - `contacts_search_performed` — props: `query_len` (Int, **length only, never the
    text**), `result_count`, `latency_ms`, `from_cache` (Bool).
  - `contact_selected` — props: `position` (Int). No PII.
- **Logging:** WARN on network/HTTP failures with status code and endpoint (no query
  text, no cookies). DEBUG-only logging may include `q` for local builds; gate behind
  `BuildConfig.DEBUG`.
- **Paging:** log `LoadState.Error` causes at WARN with throwable class + HTTP code.

## 11. Testing Strategy

- **DTO mapping (unit, core-model):** Moshi parse of fixture JSON →
  `ContactSearchResponseDto`; assert `toDomain()` mapping incl. presence enum and null
  username/avatar. Fixtures: `contacts_search_full.json`, `contacts_search_fragment.json`,
  `contacts_search_empty.json`.
- **PagingSource (unit):** with a fake `MessagingApi`, assert first `load` returns the
  page and `nextKey == next_cursor`; cursor pass-through on append; error path →
  `LoadResult.Error`.
- **ViewModel (unit, coroutines-test):** typing emits debounced distinct queries; blank
  query maps to full-list call; `flatMapLatest` cancels superseded queries (assert only
  last query reaches repo via Turbine). Use `core-testing` `MainDispatcherRule`.
- **Repository / API (instrumented or MockWebServer):** assert request path
  `/messaging/contacts/search`, `q`, `cursor`, `limit` params; assert `X-CSRF-Token`
  header present; 401→refresh→retry happy path.
- **Compose UI tests:** initial list renders; typing "ali" shows the fragment fixture
  result (**covers the acceptance bar — search by fragment**); clearing reverts to full
  list; empty fixture shows empty state with the query in the message; error fixture shows
  Retry and `retry()` re-requests; offline shows banner over cached rows.
- **Snapshot/semantics:** TalkBack semantics for a row and the search field.

## 12. Dependencies & Sequencing

- **Hard dependency:** **AND-120** — `MessagingApi`, Retrofit/Moshi setup, `ApiResult`,
  FastAPI error mapping. Must be merged first; this ticket extends that interface.
- **Implicitly relies on** the `core-network` cookie/CSRF/refresh stack (AND-027 chain via
  AND-120) and `core-ui` shared components (avatar, error/empty scaffolds).
- **Blocks:** **AND-154** (Contact → start conversation) — needs the `Contact` model and
  `onContactClick(contactId)` callback / nav route from this screen.
- **Sequencing:** land DTO + `MessagingApi.searchContacts` first (unblocks parallel API
  testing), then repository/paging, then ViewModel, then Compose screen + nav stub.
- No shared files with AND-152 (separate endpoint/screen) — can proceed in parallel.

## 13. Risks & Open Questions

1. **Exact response shape unverified.** Field names (`items` vs `contacts`, `next_cursor`
   vs `cursor`, presence enum values) must be confirmed against `/openapi.json` and
   `frontend/src/api/types.ts`. Mitigation: DTO `@Json` names are isolated from the domain
   model; adjust once confirmed. **Owner: this ticket, before merge.**
2. **Pagination mechanism.** Endpoint may use offset/`page` rather than opaque `cursor`.
   `ContactsPagingSource` key type (`String`) may need to become `Int`. Confirm via
   OpenAPI.
3. **Tokenization semantics.** Whether matching is prefix-only, substring, or
   multi-token-AND is server-defined; the client must not assume — tests assert against
   fixtures, not hand-derived expectations. Open question: does empty `q` return all
   contacts or 422? (Assumed: returns full list.)
4. **`total` availability.** May be absent; UI must not depend on it (uses `itemCount`).
5. **Avatar host / cleartext.** Avatar URLs may point to a cleartext host; ensure Coil +
   network-security config allow them in dev only.

## 14. Acceptance Criteria

1. Opening the Contacts screen shows the first page of contacts (empty-`q` request)
   rendered as rows with avatar + display name.
2. **Searching by full name returns the matching contact(s).** (Backlog acceptance.)
3. **Searching by a name fragment returns the matching contact(s) and renders them.**
   (Primary backlog acceptance — verified by Compose UI test against the fragment
   fixture.)
4. Clearing the search field reverts to the full first page.
5. A query with no matches shows an empty state containing the query string; a failed
   request shows an error state with a working Retry; offline shows cached contacts (when
   available) with a stale banner.
6. Scrolling past the first page loads the next page (cursor paging); changing the query
   resets paging to page 1.
7. The request hits `GET /messaging/contacts/search` with `q`/`cursor`/`limit` and the
   `X-CSRF-Token` header; a single 401 triggers refresh-then-retry transparently.
8. Tapping a contact emits `onContactClick(contactId)` (consumed by AND-154).
9. Search query length is debounced; no per-keystroke request; superseded requests are
   cancelled.

## 15. Definition of Done

- Code merged to `android-port` under `com.testlogon.android.feature.messaging.contacts`
  (+ DTO/model in `core-model`, optional cache DAO in `core-data`).
- `MessagingApi.searchContacts` added; DTO `@Json` names verified against `/openapi.json`.
- Unit tests (DTO mapping, PagingSource, ViewModel), MockWebServer API test, and Compose
  UI tests (incl. the fragment-search acceptance test) pass in CI.
- All strings externalized; accessibility semantics present; no PII (query text/cookies)
  in release logs or telemetry.
- Offline cache cleared on logout; no cleartext regression for release builds.
- `onContactClick` callback + `messaging/contacts` route in the nav graph, with the
  AND-154 destination stubbed.
- Lint/detekt/ktlint clean; no new warnings in `feature-messaging`.
- Spec acceptance criteria §14 demonstrably met; reviewer sign-off on `android-port`.
