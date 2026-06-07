---
id: AND-153
title: Contacts list + search
milestone: M3
epic: E21
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
scrollable list. The acceptance bar is: **search by full name and by partial name
fragment both return the expected contacts and render them.**

> **CORRECTED (contract):** `q` is a **required** parameter (`minLength: 1`, `maxLength:
> 64`) — an empty/blank `q` returns **HTTP 422**, it does **not** return the full contact
> set. The "empty query → full list" behavior assumed by the original draft is wrong (see
> §16). On screen entry with no query the screen therefore shows an idle/empty prompt
> ("Search for contacts") rather than auto-loading a list. Source: OpenAPI
> `GET /messaging/contacts/search` (`q` required) and frontend `src/api/endpoints/
> messaging.ts: searchUsers`.

> **CORRECTED (scope):** `GET /messaging/contacts/search` is in practice a **user/people
> search** (the web client wraps it as `searchUsers`, returning `UserSearchResult[]`); it
> is NOT the saved-contacts roster. The web "Contacts" page (`src/pages/contacts/
> ContactsPage.tsx`) uses a *different* endpoint, `GET /ui/contacts` (`getContacts` →
> `ContactEntry[]` with favorite/blocked grouping). This ticket targets the search
> endpoint named in the backlog; do not conflate it with `/ui/contacts`.

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

1. **Idle on entry.** On first composition, with no query entered, the screen shows an
   idle prompt ("Search for contacts") and an empty/focused search field. **CORRECTED:** it
   does **not** auto-request a list, because `q` is required and a blank `q` would 422 (see
   §16). Each result row shows avatar (Coil, initials fallback — the API returns no avatar
   URL, so the avatar is always the initials placeholder; see §16) and display name.
2. **Search by name or fragment.** A search field at the top filters contacts via
   `/messaging/contacts/search?q=<token>`. Server-side name tokenization means a fragment
   (`"ali"`) matches `"Alice Nguyen"` and `"Khalil"`-style substrings per backend rules;
   the client sends the raw trimmed query and renders whatever the server returns. Search
   is **debounced** (300 ms) and trims leading/trailing whitespace. The query is capped at
   64 chars client-side to match the server `maxLength: 64`.
3. **Empty query.** Clearing the field (or whitespace-only) returns to the idle prompt and
   clears results; **no request is issued for a blank query** (would 422). **CORRECTED**
   from the original "reverts to the full first page".
4. **No server paging.** **CORRECTED:** the endpoint exposes **no `cursor`/`page`
   parameter** and returns a single bounded array (`limit`, default 10, max 50 — see §16).
   There is therefore no next-page fetch. The list is a single page of up to `limit`
   results. Paging 3 is **not** required; a plain `StateFlow<UiState>` over the result list
   is sufficient (the original Paging 3 / cursor design is removed — see §4 and §16).
5. **States.** The screen renders distinct UI for: idle (no query), loading
   (skeleton/spinner), loaded list, empty result ("No contacts match \"q\""), error (with
   Retry), and offline (error + Retry; see §16 re: caching). (No append-loading footer —
   there is no paging.)
6. **Selection.** Tapping a row invokes `onContactClick(contactId)`; navigation target is
   wired by AND-154. This ticket only emits the event and provides the nav route stub.
7. **Clear / cancel.** A clear (×) affordance empties the field; back dismisses the
   screen.
8. **Result ordering.** Preserve server order (the backend returns ranked/sorted
   results); the client does not re-sort.

## 4. Technical Design

New package `com.testlogon.android.feature.messaging.contacts`.

### 4.1 Domain model (core-model)

**CORRECTED:** the OpenAPI `Contact` response schema has **only** `user_id` and
`display_name` (both required). There is **no** `username`, `avatar_url`, or `presence`
field. The domain model is trimmed accordingly; the avatar is rendered as an initials
placeholder only.

```kotlin
data class Contact(
    val id: String,            // <- maps from "user_id"
    val displayName: String,   // <- maps from "display_name"
)
```

> The `username`, `avatarUrl`, and `presence` fields and the `Presence` enum from the
> original draft are **removed** — they are not in the response schema (verified against
> OpenAPI `components.schemas.Contact` and `src/api/types.ts: UserSearchResult`). If a
> richer profile is needed, AND-154 must fetch it from a separate profile endpoint.

### 4.2 API surface (extends AND-120 `MessagingApi`)

**CORRECTED** — `q` is required, `limit` default is **10** (max 50), there is **no
`cursor`**, and the response is a **bare JSON array** of contacts (not a wrapper object):

```kotlin
interface MessagingApi {
    // ...existing AND-120 members...

    @GET("/messaging/contacts/search")
    suspend fun searchContacts(
        @Query("q") query: String,           // required, 1..64 chars; blank => 422
        @Query("limit") limit: Int = PAGE_SIZE,
    ): List<ContactDto>                       // bare array response

    companion object { const val PAGE_SIZE = 20 } // server default 10, max 50
}
```

DTO (Moshi, `core-model`) — fields verified against OpenAPI `components.schemas.Contact`:

```kotlin
@JsonClass(generateAdapter = true)
data class ContactDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "display_name") val displayName: String,
)

fun ContactDto.toDomain() = Contact(
    id = userId,
    displayName = displayName,
)
```

> **CORRECTED:** field names are now verified, not assumed — `user_id` + `display_name`
> only. The previous `ContactSearchResponseDto` wrapper (`items`/`next_cursor`/`total`) and
> the `ContactDto` fields `username`/`avatar_url`/`presence` do **not** exist in the
> contract and are removed. Source: OpenAPI `GET /messaging/contacts/search` 200 schema
> (array of `Contact`) and `src/api/endpoints/messaging.ts: searchUsers` (typed
> `UserSearchResult[]`).

### 4.3 Repository (feature-messaging)

**CORRECTED:** Paging 3 / `PagingSource` is **removed** — the endpoint returns a single
bounded array with no cursor (see §16). The repository is a plain suspend call that maps
the array and wraps transport errors. A blank query is rejected client-side before any
request (the server would 422).

```kotlin
class ContactsRepository @Inject constructor(
    private val api: MessagingApi,
) {
    suspend fun search(query: String): ApiResult<List<Contact>> {
        val q = query.trim()
        if (q.isEmpty()) return ApiResult.Success(emptyList()) // idle; never call with blank q
        return try {
            ApiResult.Success(
                api.searchContacts(query = q.take(64), limit = MessagingApi.PAGE_SIZE)
                    .map { it.toDomain() }
            )
        } catch (t: Throwable) {
            ApiResult.Error(t) // mapped via AND-120 ApiResult error decoder
        }
    }
}
```

### 4.4 ViewModel

**CORRECTED:** no `PagingData`/`cachedIn`; the ViewModel exposes a sealed `UiState`.
`flatMapLatest` is retained for debounce + cancellation of superseded requests, which is
still load-bearing for AC-9.

```kotlin
sealed interface ContactsUiState {
    data object Idle : ContactsUiState                       // blank query
    data object Loading : ContactsUiState
    data class Success(val contacts: List<Contact>) : ContactsUiState
    data class Empty(val query: String) : ContactsUiState
    data class Error(val retryable: Boolean) : ContactsUiState
}

@HiltViewModel
class ContactsViewModel @Inject constructor(
    private val repo: ContactsRepository,
) : ViewModel() {

    private val query = MutableStateFlow("")
    val queryText: StateFlow<String> = query.asStateFlow()

    @OptIn(FlowPreview::class, ExperimentalCoroutinesApi::class)
    val uiState: StateFlow<ContactsUiState> =
        query
            .debounce(300)
            .map { it.trim() }
            .distinctUntilChanged()
            .flatMapLatest { q ->
                if (q.isEmpty()) flowOf(ContactsUiState.Idle)
                else flow {
                    emit(ContactsUiState.Loading)
                    emit(
                        when (val r = repo.search(q)) {
                            is ApiResult.Success ->
                                if (r.data.isEmpty()) ContactsUiState.Empty(q)
                                else ContactsUiState.Success(r.data)
                            is ApiResult.Error -> ContactsUiState.Error(retryable = true)
                        }
                    )
                }
            }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), ContactsUiState.Idle)

    fun onQueryChange(value: String) { query.value = value.take(64) }
    fun onClear() { query.value = "" }
    fun retry() { val q = query.value; query.value = ""; query.value = q } // re-trigger
}
```

### 4.5 UI (Compose + Material 3)

**CORRECTED:** the screen takes a `ContactsUiState` instead of `LazyPagingItems`.

```kotlin
@Composable
fun ContactsRoute(
    onContactClick: (String) -> Unit,
    viewModel: ContactsViewModel = hiltViewModel(),
)

@Composable
fun ContactsScreen(
    query: String,
    state: ContactsUiState,
    onQueryChange: (String) -> Unit,
    onClear: () -> Unit,
    onRetry: () -> Unit,
    onContactClick: (String) -> Unit,
)
```

- `SearchBar` / `OutlinedTextField` with leading search icon, trailing clear icon when
  non-empty, `imeAction = Search`, `singleLine = true`.
- Body switches on `state`: `Idle` → prompt; `Loading` → skeleton/spinner; `Success` →
  `LazyColumn` of `ContactRow(contact, onContactClick)` (avatar is always an initials
  placeholder — the API returns no avatar URL, so no Coil `AsyncImage` network load is
  needed here); `Empty` → empty message with the query; `Error` → full-screen error with a
  working Retry (`onRetry`).

### 4.6 Navigation

Add route `messaging/contacts` to the Navigation-Compose graph; `onContactClick` resolves
to the AND-154 destination (`messaging/profile/{contactId}`), left as a TODO/stub route
in this ticket so AND-154 only wires the destination.

## 5. API Contract

**Endpoint:** `GET /messaging/contacts/search` (verified, OpenAPI op
`search_contact_messaging_contacts_search_get`).
**Auth:** session cookies + `ui_csrf` echoed as `X-CSRF-Token`, plus `Authorization:
Bearer` from the auth store (all handled by `core-network`). Verified in
`src/api/client.ts` (sets `X-CSRF-Token` from the `ui_csrf` cookie and `Authorization:
Bearer <accessToken>`). OpenAPI also documents optional `authorization` and `X-SESSION-ID`
headers for this route.
**Idempotent GET** — eligible for bounded backoff retry.

Query params (**CORRECTED** — verified against OpenAPI):

| param | type | required | notes |
|-------|------|----------|-------|
| `q` | string | **yes** | `minLength: 1`, `maxLength: 64`. Tokenized server-side. Blank → **422**. |
| `limit` | int | no | `default: 10`, `minimum: 1`, `maximum: 50`. (Was wrongly "default 30".) |

> **REMOVED:** there is **no `cursor` param** on this endpoint.

Request example: `GET /messaging/contacts/search?q=ali&limit=20`

Response `200` — **CORRECTED: a bare JSON array** of `Contact` (`{user_id, display_name}`),
not a wrapper object:

```json
[
  { "user_id": "u_1029", "display_name": "Alice Nguyen" }
]
```

Empty result `200`: `[]`.

**Errors** (FastAPI `detail` mapping from AND-120):

- `422 Unprocessable Entity` → returned when `q` is missing/blank or exceeds 64 chars, or
  `limit` is out of range. `detail` is `HTTPValidationError` =
  `[{"loc", "msg", "type"}]`; map first `msg` (verified: `src/api/client.ts:
  normalizeErrorDetail` joins `msg` values; OpenAPI 422 →
  `components.schemas.HTTPValidationError`). The client should normally **prevent** this by
  never sending a blank/over-long `q`.
- `401 Unauthorized` → client performs `POST /ui/session/refresh` once, then retries the
  GET (verified: `src/api/client.ts: refreshSession` + single-retry logic). Second 401 →
  logout / route to login (`useAuthStore.logout("session_expired")`); this screen just
  shows the error state.
- `403 Forbidden` → `{"detail": "string"}` or `{"detail": {"code": ...}}`; map per the
  shared `ApiResult`/`normalizeErrorDetail` decoder (verified in `src/api/client.ts`).
- `4xx/5xx` with `{"detail": ...}` → mapped per the shared decoder.
- Network timeout / connection failure → `IOException` → error state with Retry.

## 6. Data & State Management

**CORRECTED:** this section previously assumed Paging 3 and a Room cache of the
empty-query first page. Since (a) there is no paging and (b) there is no empty-query list
(blank `q` 422s), both are removed.

- **UI state:** a single `StateFlow<ContactsUiState>` (see §4.4) plus a `StateFlow<String>`
  for query text.
- **State derivation:** blank query → `Idle`; request in flight → `Loading`; non-empty
  result → `Success`; HTTP-200 empty array → `Empty(q)` (`No contacts match "q"`);
  transport/HTTP error → `Error` with Retry.
- **Caching:** **REMOVED.** There is no empty-query "full list" to cache, and search
  results are transient/PII-adjacent (query text), so they are not persisted. No
  `cached_contacts` Room table is added by this ticket. (If AND-154 later needs a roster
  cache it should target `/ui/contacts`, a different endpoint — see §16.) Recomposition
  survival is provided by `stateIn(... WhileSubscribed)`.
- **Query as key:** changing `q` triggers `flatMapLatest`, cancelling the previous in-flight
  request and starting a new one.
- **DataStore:** no preferences owned here.

## 7. Error Handling & Resilience

- **Timeouts:** rely on the `core-network` OkHttp client configured for ~20s
  call/read/connect timeouts.
- **Retry policy:** `searchContacts` is an idempotent GET → eligible for the shared
  bounded exponential backoff interceptor (max 2 retries, jittered, GET-only). Manual
  `ViewModel.retry()` is also offered in the error state. (**CORRECTED:** no
  `items.retry()` — there is no `LazyPagingItems`.)
- **401 handling:** single `POST /ui/session/refresh` then retry, via the existing
  authenticator/interceptor; not re-implemented here (verified in `src/api/client.ts`).
- **422 prevention:** never issue a request for a blank/whitespace-only or >64-char `q`;
  the ViewModel short-circuits blank to `Idle` and caps length at 64.
- **Empty vs error:** distinguish HTTP-200 empty array (`Empty` state) from transport/HTTP
  error (`Error` state) — never show "no results" for a failed request.
- **Offline:** on `IOException`, render the `Error` state with Retry. (**CORRECTED:** no
  offline cache / stale banner — see §6 and §16; nothing is cached.)
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
- **No persistence:** **CORRECTED** — this ticket no longer adds a Room contacts cache
  (see §6/§16), so there is no cached user data to clear on logout. Search results live
  only in memory (`StateFlow`) and are dropped when the screen leaves scope.
- Search query strings are user PII-adjacent; never persist queries, never log raw query
  text at INFO+ in release (see §10).

## 9. Accessibility & i18n

- Search field: `contentDescription`/label "Search contacts"; clear button
  "Clear search"; TalkBack-focusable, IME `Search` action.
- Contact rows: merged semantics announcing the display name (e.g. "Alice Nguyen").
  **CORRECTED:** no presence announcement — the API returns no presence field. Min touch
  target 48dp; the initials-fallback avatar is marked decorative.
- All user-visible strings in `strings.xml` (`feature-messaging`):
  `contacts_title`, `contacts_search_hint`, `contacts_idle_prompt`, `contacts_empty_query`
  (with `%1$s` placeholder), `contacts_error`, `contacts_retry`, `contacts_clear_cd`. No
  hardcoded UI text. Plurals not required. (**CORRECTED:** removed
  `contacts_empty_default` and `contacts_offline_banner` — no empty-list-on-entry state and
  no offline banner; added `contacts_idle_prompt`.)
- RTL supported via standard Compose start/end paddings.
- Respect dynamic font scaling; rows use wrap-content height.

## 10. Telemetry & Logging

- **Events** (via existing analytics abstraction in `core-data`):
  - `contacts_screen_view`
  - `contacts_search_performed` — props: `query_len` (Int, **length only, never the
    text**), `result_count`, `latency_ms`. (**CORRECTED:** dropped `from_cache` — no
    caching.)
  - `contact_selected` — props: `position` (Int). No PII.
- **Logging:** WARN on network/HTTP failures with status code and endpoint (no query
  text, no cookies). DEBUG-only logging may include `q` for local builds; gate behind
  `BuildConfig.DEBUG`.
- **Paging:** log `LoadState.Error` causes at WARN with throwable class + HTTP code.

## 11. Testing Strategy

**CORRECTED** for the array response / no-paging / no-cache contract.

- **DTO mapping (unit, core-model):** Moshi parse of a fixture JSON **array** →
  `List<ContactDto>`; assert `toDomain()` maps `user_id`→`id` and `display_name`. Fixtures:
  `contacts_search_full.json`, `contacts_search_fragment.json`, `contacts_search_empty.json`
  (the last is `[]`).
- **ViewModel (unit, coroutines-test):** typing emits debounced distinct queries; blank
  query → `Idle` and **no** repo call; `flatMapLatest` cancels superseded queries (assert
  only last query reaches repo via Turbine); 200 array → `Success`; `[]` → `Empty`; error →
  `Error`. Use `core-testing` `MainDispatcherRule`.
- **Repository / API (MockWebServer):** assert request path `/messaging/contacts/search`
  with `q` and `limit` (and **no** `cursor`); assert `X-CSRF-Token` and `Authorization`
  headers present; 401→`/ui/session/refresh`→retry happy path; 422 body
  (`HTTPValidationError`) → mapped error.
- **Compose UI tests:** idle prompt on entry; typing "ali" shows the fragment fixture
  result (**covers the acceptance bar — search by fragment**); clearing returns to idle;
  empty fixture shows empty state with the query in the message; error fixture shows Retry
  and `retry()` re-requests.
- **Snapshot/semantics:** TalkBack semantics for a row and the search field.

## 12. Dependencies & Sequencing

- **Hard dependency:** **AND-120** — `MessagingApi`, Retrofit/Moshi setup, `ApiResult`,
  FastAPI error mapping. Must be merged first; this ticket extends that interface.
- **Implicitly relies on** the `core-network` cookie/CSRF/refresh stack (AND-027 chain via
  AND-120) and `core-ui` shared components (avatar, error/empty scaffolds).
- **Blocks:** **AND-154** (Contact → start conversation) — needs the `Contact` model and
  `onContactClick(contactId)` callback / nav route from this screen.
- **Sequencing:** land DTO + `MessagingApi.searchContacts` first (unblocks parallel API
  testing), then repository, then ViewModel, then Compose screen + nav stub.
- No shared files with AND-152 (separate endpoint/screen) — can proceed in parallel.

## 13. Risks & Open Questions

1. **Response shape — RESOLVED.** Confirmed against OpenAPI `components.schemas.Contact`
   and `src/api/endpoints/messaging.ts: searchUsers`: a bare array of `{user_id,
   display_name}`. No wrapper, no `username`/`avatar_url`/`presence`. DTO updated in §4.2.
2. **Pagination — RESOLVED.** Endpoint has **no** `cursor`/`page` param; it returns a
   single bounded array capped by `limit` (default 10, max 50). Paging 3 removed.
3. **Tokenization semantics — open (server-defined).** Whether matching is prefix-only,
   substring, or multi-token-AND is server-defined; the client must not assume — tests
   assert against fixtures, not hand-derived expectations. **RESOLVED sub-question:** empty
   `q` does **not** return all contacts — it returns **422** (`q` is required,
   `minLength: 1`). The screen never sends a blank `q`.
4. **`limit` default — RESOLVED.** Server default is 10 (max 50); client uses
   `PAGE_SIZE = 20`. There is no `total` field to depend on.
5. **Avatar host — moot.** The response carries no avatar URL, so no remote avatar is
   loaded by this screen and there is no cleartext-avatar concern here; rows use an
   initials placeholder.

## 14. Acceptance Criteria

1. Opening the Contacts screen with no query shows the idle prompt (no request is issued;
   blank `q` would 422). **CORRECTED** from "shows the first page (empty-`q` request)".
2. **Searching by full name returns the matching contact(s).** (Backlog acceptance.)
3. **Searching by a name fragment returns the matching contact(s) and renders them.**
   (Primary backlog acceptance — verified by Compose UI test against the fragment
   fixture.)
4. Clearing the search field returns to the idle prompt and clears results. **CORRECTED**
   from "reverts to the full first page".
5. A query with no matches (HTTP 200 `[]`) shows an empty state containing the query
   string; a failed/offline request shows an error state with a working Retry. **CORRECTED**
   — no cached-contacts/stale-banner path (nothing is cached).
6. Results render as a single bounded list (up to `limit`); changing the query issues a
   fresh search and replaces the list. **CORRECTED** — no cursor paging / next-page load.
7. The request hits `GET /messaging/contacts/search` with `q` and `limit` (no `cursor`) and
   the `X-CSRF-Token` + `Authorization` headers; a single 401 triggers
   refresh-then-retry transparently.
8. Tapping a contact emits `onContactClick(contactId)` (consumed by AND-154).
9. Search input is debounced; no per-keystroke request; superseded requests are cancelled.

## 15. Definition of Done

- Code merged to `android-port` under `com.testlogon.android.feature.messaging.contacts`
  (+ DTO/model in `core-model`). **CORRECTED:** no cache DAO in `core-data` (nothing
  cached).
- `MessagingApi.searchContacts` added; DTO `@Json` names verified against `/openapi.json`
  (`user_id`, `display_name`).
- Unit tests (DTO mapping, ViewModel), MockWebServer API test, and Compose UI tests (incl.
  the fragment-search acceptance test) pass in CI. **CORRECTED:** no PagingSource test (no
  paging).
- All strings externalized; accessibility semantics present; no PII (query text/cookies)
  in release logs or telemetry.
- No cleartext regression for release builds. (**CORRECTED:** removed "offline cache
  cleared on logout" — no cache.)
- `onContactClick` callback + `messaging/contacts` route in the nav graph, with the
  AND-154 destination stubbed.
- Lint/detekt/ktlint clean; no new warnings in `feature-messaging`.
- Spec acceptance criteria §14 demonstrably met; reviewer sign-off on `android-port`.

## 16. Citations & Assumption Audit

Each claim below lists the claim, a VERDICT (Verified / Corrected / Unverified-assumption),
and an exact SOURCE pointer.

1. **Endpoint is `GET /messaging/contacts/search`.** VERDICT: Verified. SOURCE: OpenAPI
   `GET /messaging/contacts/search` (op `search_contact_messaging_contacts_search_get`);
   frontend `src/api/endpoints/messaging.ts: searchUsers`.
2. **`q` is a required query param, `minLength: 1`, `maxLength: 64`; blank `q` → 422.**
   VERDICT: Corrected (draft assumed `q` optional / blank returns full list). SOURCE:
   OpenAPI `GET /messaging/contacts/search` param `q` (`required: true`,
   `minLength: 1`, `maxLength: 64`).
3. **`limit` default is 10, min 1, max 50.** VERDICT: Corrected (draft said "default 30").
   SOURCE: OpenAPI `GET /messaging/contacts/search` param `limit`
   (`default: 10`, `minimum: 1`, `maximum: 50`).
4. **No `cursor`/`page` param exists.** VERDICT: Corrected (draft designed cursor paging
   with Paging 3). SOURCE: OpenAPI `GET /messaging/contacts/search` parameters
   (only `q`, `limit`, `authorization`, `X-SESSION-ID`); `src/api/endpoints/messaging.ts:
   searchUsers` (passes only `q`, `limit`).
5. **200 response is a bare JSON array of `Contact`, not a `{items,next_cursor,total}`
   wrapper.** VERDICT: Corrected. SOURCE: OpenAPI 200 schema (`type: array`,
   `items: $ref Contact`); `src/api/endpoints/messaging.ts: searchUsers` (typed
   `UserSearchResult[]`).
6. **`Contact` item fields are `user_id` + `display_name` only (no `username`,
   `avatar_url`, `presence`).** VERDICT: Corrected. SOURCE: OpenAPI
   `components.schemas.Contact` (required `user_id`, `display_name`);
   `src/api/types.ts: UserSearchResult` (`{ user_id, display_name }`).
7. **Auth: cookie session + `ui_csrf` echoed as `X-CSRF-Token`, plus `Authorization:
   Bearer`.** VERDICT: Verified (CSRF + Bearer); draft omitted the Bearer header. SOURCE:
   `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`;
   `Authorization: Bearer ${accessToken}`). OpenAPI additionally documents optional
   `authorization` and `X-SESSION-ID` headers.
8. **401 → single `POST /ui/session/refresh` → retry once; second 401 → logout.** VERDICT:
   Verified. SOURCE: `src/api/client.ts: refreshSession` and the 401 retry block
   (`useAuthStore.getState().logout("session_expired")` on a second 401).
9. **422 error body is `HTTPValidationError` = `[{loc,msg,type}]`; client maps first
   `msg`.** VERDICT: Verified. SOURCE: OpenAPI 422 →
   `components.schemas.HTTPValidationError`; `src/api/client.ts: normalizeErrorDetail`
   (joins `msg` values from the array).
10. **403 maps `{detail:string}` / `{detail:{code:...}}` via the shared decoder.** VERDICT:
    Verified. SOURCE: `src/api/client.ts` 403 handling + `normalizeErrorDetail` /
    `mapAuthorizationError`.
11. **`/messaging/contacts/search` is people/user search, distinct from the saved-contacts
    roster `/ui/contacts`.** VERDICT: Verified. SOURCE: OpenAPI `GET /ui/contacts`
    (op `list_contacts_ui_contacts_get`, `ContactEntry`) vs the search endpoint;
    `src/pages/contacts/ContactsPage.tsx` uses `getContacts` (`/ui/contacts`), while
    `searchUsers` (search endpoint) is used only inside the Add-Contact `UserSearch` dialog.
12. **Server-side name tokenization / fragment matching semantics.** VERDICT:
    Unverified-assumption (backend behavior; not expressible in the OpenAPI schema). The
    ticket's acceptance only requires that whatever the server returns for a full name and a
    fragment is rendered; tests assert against fixtures, not hand-derived match rules.
13. **Debounce 300 ms.** VERDICT: Unverified-assumption (client UX choice; web client uses
    its own debounce in `UserSearch`, value not asserted here). Framework ref: Kotlin Flow
    `debounce` (kotlinx.coroutines docs).
14. **Compose Material 3 `SearchBar`/`OutlinedTextField`, Hilt `@HiltViewModel`,
    `StateFlow`/`stateIn`, Coil `AsyncImage` for any avatar.** VERDICT:
    Unverified-assumption (Android implementation choices, not constrained by sources).
    Framework ref: Android Developers — Compose Material 3, Hilt + Jetpack, Kotlin Flow
    `stateIn`/`flatMapLatest`.

### Corrections made

- **Empty-`q` behavior:** draft said empty `q` returns the full contact list and the screen
  auto-loads on entry. Corrected: `q` is required (`minLength: 1`); blank → 422; screen
  shows an idle prompt and issues no request for a blank query. (§1, §3, §4.4, §7, §14.1/4)
- **Response shape:** draft used a `ContactSearchResponseDto` wrapper with
  `items`/`next_cursor`/`total`. Corrected to a bare `List<ContactDto>`. (§4.2, §5)
- **DTO fields / domain model:** draft `ContactDto`/`Contact` had
  `username`/`avatar_url`/`presence` and a `Presence` enum. Corrected to `user_id` +
  `display_name` only; `Presence` removed. (§4.1, §4.2, §9 presence announcement removed)
- **Pagination:** draft used Paging 3 + `ContactsPagingSource` + cursor. Corrected: no
  paging param exists; replaced with a single suspend call + sealed `ContactsUiState`.
  (§3.4, §4.3, §4.4, §4.5, §6, §13.2)
- **`limit` default:** 30 → 10 (server default; max 50). (§4.2, §5, §13.4)
- **Caching / offline:** draft added a `cached_contacts` Room table, stale banner, and
  logout cache-clear. Corrected: nothing is cached (no full list to cache; query results
  PII-adjacent); offline → error+Retry. (§5, §6, §7, §8, §10, §15)
- **Auth header:** added the `Authorization: Bearer` header alongside `X-CSRF-Token`. (§5)
- **Strings:** removed `contacts_empty_default` and `contacts_offline_banner`; added
  `contacts_idle_prompt`. (§9)

### Open assumptions

- **Tokenization / match semantics** (claim 12): server-defined and not exposed in the
  OpenAPI schema; cannot be verified from the provided sources. Tests assert against
  fixtures rather than derived expectations.
- **Debounce interval 300 ms** (claim 13): a client UX choice; the exact web value is not
  asserted in the reference and the backend imposes no constraint.
- **Android framework/library choices** (claim 14): Compose M3, Hilt, Flow operators, Coil
  — selected for the Android port; the reference app is React/TS, so these are not
  verifiable against it (framework refs only).
- **Whether `limit` clamps or 422s when sent > 50:** OpenAPI declares `maximum: 50`, but
  whether the server rejects (422) or silently clamps is not observable from the schema.
  The client caps at `PAGE_SIZE = 20`, well under the max, so this does not arise in
  practice.

## 17. Test Plan

Targets: **JVM** = JVM unit/Robolectric (local, no device); **MockWebServer** =
JVM contract test with a mock HTTP server; **emulator (test35)** = headless AVD,
x86_64 / API 35; **device (SM-A156U)** = physical Samsung Galaxy A15 5G, arm64 / API 34.
For this ticket (text search list, no camera/biometrics/WebRTC/push), most instrumented
cases run fine on the **emulator**; one ABI/API-difference smoke case is called out for the
**physical device**.

- **TC-AND-153-01 — DTO maps array response.** Type: unit (JVM). Target: JVM.
  Preconditions: Moshi configured as in AND-120; fixture `contacts_search_full.json` is a
  JSON array `[{"user_id":"u_1029","display_name":"Alice Nguyen"}, ...]`. Steps: parse
  fixture to `List<ContactDto>`; map each via `toDomain()`. Expected: list size matches; each
  `Contact.id == user_id`, `Contact.displayName == display_name`; no `username`/`avatar`/
  `presence` members exist. Traces: AC-2, AC-3.
- **TC-AND-153-02 — Empty array parses to empty list.** Type: unit (JVM). Target: JVM.
  Preconditions: fixture `contacts_search_empty.json` = `[]`. Steps: parse + map. Expected:
  empty list (not null, no error). Traces: AC-5.
- **TC-AND-153-03 — Repository rejects blank query without a request.** Type: unit (JVM).
  Target: JVM (fake `MessagingApi`). Preconditions: fake api records calls. Steps: call
  `repo.search("   ")`. Expected: returns `Success(emptyList())`; fake api received **zero**
  calls (no blank-`q` request → avoids 422). Traces: AC-1, AC-4.
- **TC-AND-153-04 — Request shape: path, params, headers.** Type: contract/MockWebServer.
  Target: MockWebServer (JVM). Preconditions: MockWebServer enqueues a 200 array; core-network
  stack with a session cookie + `ui_csrf` cookie + access token configured. Steps: call
  `searchContacts("ali", 20)`. Expected: recorded request is
  `GET /messaging/contacts/search?q=ali&limit=20`; **no** `cursor` param; headers include
  `X-CSRF-Token` and `Authorization: Bearer ...`. Traces: AC-7.
- **TC-AND-153-05 — 401 → refresh → retry succeeds.** Type: contract/MockWebServer. Target:
  MockWebServer (JVM). Preconditions: enqueue 401, then a 200 for `POST /ui/session/refresh`,
  then a 200 array for the retried GET; user is authenticated. Steps: call `searchContacts`.
  Expected: client issues `POST /ui/session/refresh` once then re-issues the GET; final result
  is the contact list; only one refresh occurs. Traces: AC-7.
- **TC-AND-153-06 — Second 401 surfaces auth error.** Type: contract/MockWebServer. Target:
  MockWebServer (JVM). Preconditions: enqueue 401, refresh 200, then 401 again. Steps: call
  `searchContacts`. Expected: `ApiResult.Error`; session-expired/logout path triggered; screen
  maps to `Error` state. Traces: AC-7.
- **TC-AND-153-07 — 422 validation body maps to error.** Type: contract/MockWebServer.
  Target: MockWebServer (JVM). Preconditions: enqueue 422 with body
  `{"detail":[{"loc":["query","q"],"msg":"String should have at least 1 character","type":"string_too_short"}]}`.
  Steps: force a request with an out-of-contract `q` (test-only) and call. Expected: error is
  decoded to the first `msg`; no crash; `Error` state. Traces: AC-5.
- **TC-AND-153-08 — ViewModel: debounce, distinct, cancellation.** Type: unit
  (coroutines-test). Target: JVM (Turbine + `MainDispatcherRule`). Preconditions: fake repo with
  controllable delay. Steps: emit `onQueryChange` rapidly "a","al","ali" within the debounce
  window. Expected: only the final query "ali" reaches the repo; superseded calls are cancelled
  (`flatMapLatest`); states observed: Idle→Loading→Success. Traces: AC-9.
- **TC-AND-153-09 — ViewModel: blank → Idle, 200 → Success, [] → Empty, error → Error.**
  Type: unit (coroutines-test). Target: JVM. Preconditions: fake repo scripted per case.
  Steps: drive each input. Expected: blank → `Idle` (no repo call); non-empty array →
  `Success`; `[]` → `Empty(query)`; thrown `IOException` → `Error(retryable=true)`. Traces:
  AC-1, AC-2, AC-5.
- **TC-AND-153-10 — Compose: fragment search renders results (acceptance bar).** Type:
  Compose-UI (instrumented). Target: emulator (test35). Preconditions: fake VM emits
  `Success` with the fragment fixture for query "ali". Steps: type "ali" into the search
  field. Expected: rows for the fixture contacts render with display names; matches the
  primary backlog acceptance (search by fragment). Traces: AC-3.
- **TC-AND-153-11 — Compose: full-name search and clear-to-idle.** Type: Compose-UI
  (instrumented). Target: emulator (test35). Preconditions: fake VM. Steps: type a full
  name → assert the matching row; tap the clear (×) affordance. Expected: full-name match
  renders; after clear the field empties and the body returns to the idle prompt (no list).
  Traces: AC-2, AC-4.
- **TC-AND-153-12 — Compose: empty + error states.** Type: Compose-UI (instrumented).
  Target: emulator (test35). Preconditions: fake VM emits `Empty("zzz")`, then `Error`.
  Steps: render each. Expected: empty state shows the query string ("No contacts match
  \"zzz\""); error state shows a Retry control that invokes `onRetry` (re-issues the search).
  Traces: AC-5.
- **TC-AND-153-13 — Compose: selection emits contactId + accessibility.** Type: Compose-UI
  (instrumented). Target: emulator (test35). Preconditions: fake VM with a `Success` list;
  TalkBack semantics assertions. Steps: assert each row exposes merged semantics announcing
  the display name and a 48dp touch target; the search field has the "Search contacts"
  label and the clear button "Clear search"; tap a row. Expected: `onContactClick(contactId)`
  fires with the tapped contact's id; semantics present. Traces: AC-8.
- **TC-AND-153-14 — Offline path shows error+Retry; recovery succeeds.** Type:
  instrumented/e2e. Target: device (SM-A156U) — exercises real radio/airplane-mode offline
  behavior and the arm64/API-34 build (vs the x86_64/API-35 emulator) as the ABI/API smoke.
  Preconditions: app authenticated; toggle airplane mode ON. Steps: type "ali" while offline →
  observe `Error` state; turn airplane mode OFF; tap Retry. Expected: offline yields the
  `Error` state with a working Retry (no cache shown, no stale banner); after reconnect, Retry
  fetches and renders results. Traces: AC-5, AC-9.

### Coverage matrix

| AC (§14) | Covered by |
|----------|-----------|
| AC-1 (idle on entry, no blank request) | TC-03, TC-09 |
| AC-2 (full-name search) | TC-01, TC-09, TC-11 |
| AC-3 (fragment search renders) | TC-01, TC-10 |
| AC-4 (clear → idle) | TC-03, TC-11 |
| AC-5 (empty / error / offline) | TC-02, TC-07, TC-09, TC-12, TC-14 |
| AC-6 (single bounded list; query replaces list) | TC-04 (limit/no-cursor), TC-10/TC-11 (replace) |
| AC-7 (request shape + headers; 401 refresh-retry) | TC-04, TC-05, TC-06 |
| AC-8 (tap emits contactId) | TC-13 |
| AC-9 (debounce; cancel superseded) | TC-08, TC-14 |
