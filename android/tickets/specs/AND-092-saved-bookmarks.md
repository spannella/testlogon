---
id: AND-092
title: Saved / bookmarks
milestone: M2
epic: E13
priority: P1
size: M
status: draft
depends_on: [AND-027]
blocks: []
---

# AND-092 — Saved / bookmarks

## 1. Overview & Goal

Build the "Saved" screen for the TestLogon Android app: an authenticated, paginated
list of the user's bookmarked content backed by the backend bookmarks API, plus the
ability to remove a bookmark ("unsave") with the list updating to reflect the change.
This is the read-and-remove surface for the existing server-side bookmarks feature; the
act of *creating* a bookmark from a content card (the "save" toggle on a feed/post item)
is out of scope and owned by the feed/content tickets that embed the toggle.

The screen lives in `feature-saved` (module `android/feature-saved`) reached from the
activity/saved area of E13. It consumes the AuthApi / E04 network chain (cookie jar,
CSRF interceptor, 401-refresh authenticator) and adds a `BookmarksApi`, a repository, a
Paging 3 source, a ViewModel exposing `StateFlow<UiState>`, and a Compose Material 3
screen.

Success means: navigating to Saved fetches `GET /ui/bookmarks` and renders the user's
saved items with cursor pagination; tapping "Unsave" on a row calls
`DELETE /ui/bookmarks/{content_type}/{content_id}`, optimistically removes the row, and
rolls back on failure; and all of these behaviors are covered by deterministic tests
(MockWebServer + ViewModel/repository unit tests + at least one Compose UI test) — the
backlog acceptance "Saved items list; unsave updates (tested)."

## 2. Context & References

- Repo `spannella/testlogon`; Android app under `android/`, branch `android-port`.
- Namespace / applicationId base: `com.testlogon.android`. New module package
  `com.testlogon.android.feature.saved`.
- Module layering: `feature-saved` → `core-network`, `core-model`, `core-data`,
  `core-ui`, `core-testing`. ViewModels expose `StateFlow<UiState>`; calls return the
  typed `ApiResult<T>` (AND-018); FastAPI `detail` mapping per AND-015.
- **AND-027** (hard dependency) owns the Retrofit API pattern (`AuthApi`, session
  endpoints), the `Response<T>` suspend-method convention, and the network module wiring.
  `BookmarksApi` follows that pattern and is registered alongside `AuthApi`. The cookie
  jar (AND-011), CSRF interceptor (AND-012), and 401-refresh authenticator (AND-013) are
  assumed present via that chain.
- Backend: FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` is plaintext HTTP
  and unreliable — design for ~20s timeouts, bounded-backoff retry for the idempotent
  list `GET` only (AND-016), and offline/stale UI states (AND-021/AND-045 patterns).
- Reference: web app `frontend/src/api/endpoints/bookmarks.ts` and shared types in
  `frontend/src/api/types.ts`; authoritative paths and request bodies verified against
  `/openapi.json` (see §5). The list/status responses are loosely typed in OpenAPI
  (no response schema ref); field names below are the contract this ticket implements
  and MUST be reconciled against `bookmarks.ts` + a live `/openapi.json` at build time.
- Paging: Paging 3 (`androidx.paging`) with a cursor-based `PagingSource`.

## 3. Functional Requirements

FR-1. On entering the Saved screen the app calls `GET /ui/bookmarks?limit=20` and shows
a loading state, then a list of saved items ordered as returned by the server (most
recently saved first).

FR-2. The list is cursor-paginated: when the user scrolls near the end, the next page is
requested with `cursor=<next_cursor>` from the previous page; pagination stops when the
server returns a null/absent `next_cursor`.

FR-3. Each row shows: a thumbnail (Coil), a title/primary label, a content-type label
(e.g. "Post", "Video"), the saved-at timestamp (relative), and an "Unsave" affordance.

FR-4. Tapping "Unsave" on a row calls
`DELETE /ui/bookmarks/{content_type}/{content_id}` (with `X-CSRF-Token`), optimistically
removes the row from the rendered list, and on failure restores the row at its original
position and surfaces a retryable error.

FR-5. Unsave requires no extra confirmation dialog (it is reversible by re-saving and
low-risk), but exposes an in-row Undo via a snackbar for a few seconds after a successful
unsave; tapping Undo re-creates the bookmark via `POST /ui/bookmarks`.

FR-6. Tapping a row navigates to the underlying content detail (delegated; this ticket
emits an `onOpen(contentType, contentId)` callback consumed by the host nav graph —
detail screens are owned by E14/E24/E26).

FR-7. Pull-to-refresh re-fetches from the first page (invalidates the `PagingSource`).

FR-8. Empty state ("You haven't saved anything yet") is shown when the first page is
empty; an error/offline state with Retry is shown when the first page fails.

FR-9. The filter UI is not built in this ticket, but the API/repository signatures accept
optional `content_type`/`collection_id` filters so the follow-up (achievements/
collections) does not need to re-thread them.

## 4. Technical Design

Module `feature-saved`, MVVM with Hilt, `StateFlow<UiState>`, Paging 3.

Domain model (`core-model`):

```kotlin
data class Bookmark(
    val contentType: String,   // "post" | "video" | "clip" | ...
    val contentId: String,
    val collectionId: String?,
    val title: String?,        // derived display label
    val subtitle: String?,
    val thumbnailUrl: String?,
    val savedAt: Instant?,
)
```

API (`core-network`, same module/pattern as `AuthApi` per AND-027):

```kotlin
interface BookmarksApi {
    @GET("ui/bookmarks")
    suspend fun listBookmarks(
        @Query("limit") limit: Int = 20,
        @Query("cursor") cursor: String? = null,
        @Query("content_type") contentType: String? = null,
        @Query("collection_id") collectionId: String? = null,
    ): Response<BookmarkPageDto>

    @DELETE("ui/bookmarks/{content_type}/{content_id}")
    suspend fun deleteBookmark(
        @Path("content_type") contentType: String,
        @Path("content_id") contentId: String,
    ): Response<Unit>

    @POST("ui/bookmarks")
    suspend fun createBookmark(@Body body: CreateBookmarkDto): Response<Unit> // for Undo
}
```

DTOs (Moshi, `@Json(name=...)` for snake_case):

```kotlin
@JsonClass(generateAdapter = true)
data class BookmarkPageDto(
    @Json(name = "items") val items: List<BookmarkDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class BookmarkDto(
    @Json(name = "content_type") val contentType: String,
    @Json(name = "content_id") val contentId: String,
    @Json(name = "collection_id") val collectionId: String? = null,
    @Json(name = "title") val title: String? = null,
    @Json(name = "subtitle") val subtitle: String? = null,
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
    @Json(name = "saved_at") val savedAt: String? = null,
)

@JsonClass(generateAdapter = true)
data class CreateBookmarkDto(
    @Json(name = "content_type") val contentType: String?,
    @Json(name = "content_id") val contentId: String,
    @Json(name = "collection_id") val collectionId: String? = null,
)
```

Repository (`core-data`) maps DTO → domain + `ApiResult<T>` and owns the
`PagingSource`:

```kotlin
class BookmarksRepository @Inject constructor(
    private val api: BookmarksApi,
    private val dispatchers: AppDispatchers,
) {
    fun pager(contentType: String? = null, collectionId: String? = null): Flow<PagingData<Bookmark>>
    suspend fun unsave(contentType: String, contentId: String): ApiResult<Unit>
    suspend fun resave(b: Bookmark): ApiResult<Unit>   // Undo
}

class BookmarksPagingSource(
    private val api: BookmarksApi,
    private val contentType: String?,
    private val collectionId: String?,
) : PagingSource<String, Bookmark>() {
    override suspend fun load(params: LoadParams<String>): LoadResult<String, Bookmark>
    override fun getRefreshKey(state: PagingState<String, Bookmark>): String? = null
}
```

ViewModel:

```kotlin
@HiltViewModel
class SavedViewModel @Inject constructor(
    private val repo: BookmarksRepository,
) : ViewModel() {

    data class UiState(
        val removedIds: Set<String> = emptySet(),     // "type/id" keys hidden optimistically
        val undo: UndoTarget? = null,                  // last unsaved item for snackbar
        val error: UiError? = null,
    )
    data class UndoTarget(val bookmark: Bookmark)

    val pagingItems: Flow<PagingData<Bookmark>> =
        repo.pager().cachedIn(viewModelScope)

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    fun unsave(b: Bookmark)        // optimistic hide + DELETE; on fail un-hide + error
    fun undoUnsave()               // POST re-create, un-hide
    fun dismissUndo()
    fun dismissError()
    fun refresh()                  // signals UI to call refresh() on LazyPagingItems
}
```

The optimistic removal is implemented by tracking `removedIds` in `UiState` and filtering
the rendered `LazyPagingItems` against it (Paging 3 does not support in-place item
deletion without invalidation, so visual removal is via the filter set; a `refresh()` is
triggered after a short debounce or on next screen entry to reconcile with the server).
On unsave failure the id is removed from `removedIds` (row reappears) and `error` is set.

Composables (Material 3, `core-ui`):

```kotlin
@Composable
fun SavedRoute(
    viewModel: SavedViewModel = hiltViewModel(),
    onOpen: (contentType: String, contentId: String) -> Unit,
    onBack: () -> Unit,
)

@Composable
fun SavedScreen(
    items: LazyPagingItems<Bookmark>,
    state: SavedViewModel.UiState,
    onUnsave: (Bookmark) -> Unit,
    onUndo: () -> Unit,
    onDismissUndo: () -> Unit,
    onDismissError: () -> Unit,
    onOpen: (String, String) -> Unit,
    onBack: () -> Unit,
)
```

Navigation: register a `saved` route in the authenticated nav graph (AND-024) reached
from the activity/saved hub. Initial/append/error states use the shared
`core-ui` state composables (AND-021): loading, empty, error, offline.

## 5. API Contract

`GET /ui/bookmarks` (idempotent read) — query params: `limit` (int, default 20),
`cursor` (opaque string, nullable), `content_type` (nullable), `collection_id`
(nullable). The session rides on cookies; no auth header needed beyond cookies.
200 →

```json
{
  "items": [
    {
      "content_type": "post",
      "content_id": "post_01HX...",
      "collection_id": null,
      "title": "Sunset shoot — behind the scenes",
      "subtitle": "@creator",
      "thumbnail_url": "https://.../thumb.jpg",
      "saved_at": "2026-06-05T09:31:44Z"
    }
  ],
  "next_cursor": "eyJrIjoi..."
}
```

`DELETE /ui/bookmarks/{content_type}/{content_id}` (mutation) — requires
`X-CSRF-Token` (echoed from `ui_csrf` cookie by AND-012). 200 (or 204) on success.
Idempotent on the server (deleting an already-deleted bookmark returns success / 404);
the client treats 200/204/404 as "row gone".

`POST /ui/bookmarks` (Undo) — requires `X-CSRF-Token`. Body
`CreateBookmarkRequest`:

```json
{ "content_type": "post", "content_id": "post_01HX...", "collection_id": null }
```

201 on success (`content_id` is the only server-required field).

Error envelope (FastAPI `detail`, mapped per AND-015 — `string | [{msg}] | {code,...}`):

```json
{ "detail": "Not authenticated" }
{ "detail": [{ "msg": "field required", "loc": ["query","limit"] }] }
{ "detail": { "code": "bookmark_not_found", "message": "..." } }
```

Status handling: 200/201/204 success; 401 → authenticator performs
`POST /ui/session/refresh` once then retries (transparent); 403 → CSRF/forbidden
surfaced as retryable error; 404 on delete → treat as already-removed (keep row hidden,
no error); 422 → validation error mapped via `detail` array form; 5xx / timeout →
retryable error, list unchanged. Notes: the OpenAPI list/delete responses are loosely
typed (`Successful Response`, no schema ref) — DTO field names MUST be verified against
`frontend/src/api/endpoints/bookmarks.ts` and a live `/openapi.json` before merge; Moshi
DTOs tolerate unknown/missing fields (defaults + nullable). The `user_sub`,
`X-SESSION-ID`, and `X-IMPERSONATION-TOKEN` parameters in OpenAPI are server/admin
concerns and are NOT sent by this client (session is cookie-derived).

## 6. Data & State Management

- Pagination state is held by Paging 3 (`PagingData` flow `cachedIn(viewModelScope)`);
  the cursor is the page key. `getRefreshKey` returns null (refresh restarts at page 1)
  because cursors are opaque and forward-only.
- Optimistic unsave state (`removedIds`, `UndoTarget`) lives in `StateFlow<UiState>` in
  memory only — it is reconciled away by the next list refresh/invalidation.
- No Room persistence in this ticket: the Saved list is fetched on demand and held in
  Paging memory. A Room-backed `RemoteMediator` offline cache is a possible follow-up
  (E13/offline cross-cutting) and is out of scope here.
- `saved_at` is parsed to `Instant`; tolerate null/absent and unparseable values (show
  no timestamp rather than crashing).
- After a successful unsave whose Undo window elapses, a `refresh()` of the
  `LazyPagingItems` reconciles the paged data with the server so `removedIds` can be
  cleared, preventing unbounded growth of the hidden set across pages.

## 7. Error Handling & Resilience

- Timeouts ~20s (core-network OkHttp config). The list `GET` is idempotent and MAY use
  the bounded-backoff retry for GETs (AND-016); `DELETE`/`POST` mutations MUST NOT
  auto-retry (no duplicate destructive/creative effects).
- 401: handled by the OkHttp authenticator (single `POST /ui/session/refresh` then
  retry). If refresh fails the call returns 401 → map to "Session expired" and defer to
  the auth flow (not re-implemented here).
- 403 (CSRF mismatch): surface "Couldn't verify your session, try again"; retry re-reads
  the `ui_csrf` cookie via the existing interceptor.
- Offline / first-page failure: render the shared error/offline state with Retry
  (AND-045 pattern). Append (next-page) errors render a retryable footer via Paging's
  `LoadState.Error`.
- Optimistic-unsave failure: re-insert the row (remove id from `removedIds`) and show a
  non-blocking error snackbar with Retry. 404 on delete is NOT a failure (row stays
  gone).
- Undo failure (re-create POST fails): keep the row hidden, show "Couldn't restore
  bookmark" with a Retry.

## 8. Security & Privacy

- All calls use the existing authenticated cookie jar; mutations carry `X-CSRF-Token`.
  No session cookies, CSRF token, or auth headers are logged or persisted by this
  feature.
- `content_id`/`collection_id` and titles are user content; never written to logcat in
  release, never included in analytics payloads beyond the hashed/omitted ids in §10.
- Thumbnails are loaded via Coil over the configured (dev: cleartext) base host; this
  feature adds no new cleartext exemptions beyond the existing dev
  `network_security_config`. Production must be HTTPS.
- No new local at-rest storage of bookmark content in this ticket (memory only), so no
  new on-disk PII surface.

## 9. Accessibility & i18n

- All strings in `feature-saved` `strings.xml`; no hardcoded text. Relative timestamps
  via a locale-aware formatter (`DateUtils.getRelativeTimeSpanString`).
- Each row exposes a merged `contentDescription` summarizing title, content type, and
  saved time; the thumbnail is decorative (`contentDescription = null`) since the title
  conveys meaning.
- The "Unsave" control has an explicit `contentDescription` ("Remove <title> from
  saved"); touch targets ≥ 48dp. The Undo snackbar action is TalkBack-announceable.
- Supports dynamic font scaling and dark theme via Material 3; RTL-safe layouts
  (start/end paddings, no hardcoded left/right). Empty/error states are focus-reachable
  and announced.

## 10. Telemetry & Logging

- Events (no raw content ids; ids hashed or omitted): `saved_viewed`,
  `bookmark_unsaved` (`{content_type}`), `bookmark_unsave_undone` (`{content_type}`),
  `saved_load_error` (`{type, page: "initial"|"append"}`).
- Logging via the project Timber wrapper; request/response metadata debug-only, never
  cookies, `X-CSRF-Token`, or raw `content_id`/titles.
- Error mapping records the normalized `UiError.type` (network/auth/csrf/validation/
  server) for triage, not raw `detail` strings.

## 11. Testing Strategy

- **MockWebServer (core-testing, AND-046 harness)**: enqueue `GET /ui/bookmarks`
  fixtures with `next_cursor` (page 1 → page 2 → null), an empty first page,
  `DELETE /ui/bookmarks/{type}/{id}` 200/204 and 404, `POST /ui/bookmarks` 201, and
  error responses (403 CSRF, 422, 500, timeout). Assert verbs, paths, query params
  (`limit`, `cursor`), and presence of `X-CSRF-Token` on `DELETE`/`POST`.
- **Repository / PagingSource tests** (coroutine test rule): `load()` returns
  `LoadResult.Page` with the correct `nextKey` from `next_cursor`; null cursor →
  `nextKey == null` (end of pagination); DTO→domain mapping incl. null/absent
  `saved_at`; error envelope mapping (string/array/object forms) → `ApiResult.Error`.
- **ViewModel unit tests** (Turbine): `unsave()` adds the key to `removedIds`
  optimistically and calls the API; on failure the key is removed (rollback) and `error`
  set; 404 on delete leaves the row removed with no error; `undoUnsave()` POSTs and
  clears the removed key; undo/error dismissal gating.
- **Compose UI test**: list renders saved items from a fake/paged source; tapping
  Unsave removes the row from the screen and shows the Undo snackbar; the empty state
  renders for an empty page. (Satisfies "Saved items list" and "unsave updates"
  acceptance.)
- All tests deterministic (no real network); coverage focus matches §14.

## 12. Dependencies & Sequencing

- **Depends on AND-027** (hard blocker): provides the Retrofit/Hilt API pattern and
  network module the `BookmarksApi` is registered into. Transitively relies on the cookie
  jar (AND-011), CSRF interceptor (AND-012), and 401-refresh authenticator (AND-013) via
  AND-027's chain, plus `ApiResult` (AND-018) and `detail` mapping (AND-015), and the
  shared state composables (AND-021) and authenticated nav graph (AND-024).
- The Paging 3 dependency must be present in the version catalog (E01 scaffolding); add
  `androidx.paging:paging-runtime` / `paging-compose` if not already declared.
- Blocks: none currently tracked. The in-card "save" toggle on feed/content rows is
  owned by the feed tickets (E14/E24) and reuses `BookmarksApi.createBookmark` /
  `GET /ui/bookmarks/status`; this ticket establishes those API methods and DTOs.
- Sequencing: DTOs/mapper + `BookmarksApi` + repository/`PagingSource` first (unit +
  MockWebServer tested), then ViewModel, then Compose screen + nav wiring, then UI test.

## 13. Risks & Open Questions

- Q1: The OpenAPI list/delete/status responses have no typed schema. Confirm the actual
  list envelope field names (`items` vs `bookmarks`, `next_cursor` vs `cursor`/`next`)
  against `frontend/src/api/endpoints/bookmarks.ts` and a live `/openapi.json` before
  finalizing DTOs. Mapper/DTO defaults reduce breakage but field names must match.
- Q2: Does `GET /ui/bookmarks` return enough display metadata (title, thumbnail) or only
  `{content_type, content_id}` references? If only references, rows must hydrate from the
  per-content detail endpoints (a follow-up); for this ticket the row degrades gracefully
  to id/type + a placeholder thumbnail when title/thumbnail are absent.
- Q3: Is `DELETE` keyed by `{content_type, content_id}` (per OpenAPI) idempotent and does
  it return 200 or 204? Tests cover both; confirm 404-on-missing semantics.
- Q4: Confirm the page key is `cursor` (assumed, forward-only opaque) and the max
  `limit`. `getRefreshKey` assumes forward-only cursors.
- Q5: Collections (`/ui/bookmark-collections`) and `GET /ui/bookmarks/status` exist but
  are out of scope (achievements/collections follow-up); signatures leave room for
  `collection_id` filtering without rework.
- Risk: unreliable dev host makes manual QA flaky; mitigated by MockWebServer coverage
  as the source of truth for correctness.

## 14. Acceptance Criteria

AC-1. Navigating to Saved issues `GET /ui/bookmarks?limit=20` and renders the returned
saved items; scrolling to the end requests the next page with `cursor=<next_cursor>` and
stops when `next_cursor` is null. (MockWebServer + Compose/Paging test — satisfies
"Saved items list".)

AC-2. Tapping Unsave on a row calls `DELETE /ui/bookmarks/{content_type}/{content_id}`
with `X-CSRF-Token`, removes the row from the rendered list on success, and rolls the row
back on failure. (MockWebServer + ViewModel test — satisfies "unsave updates (tested)".)

AC-3. A 404 on delete is treated as already-removed: the row stays gone and no error is
shown. (ViewModel + MockWebServer test.)

AC-4. After a successful unsave an Undo snackbar appears; tapping Undo calls
`POST /ui/bookmarks` and the row reappears. (ViewModel test.)

AC-5. Empty first page renders the empty state; first-page failure/offline renders a
retryable error state; append failure renders a retryable footer. (Compose + Paging
test.)

AC-6. Network/CSRF/server errors surface a retryable message and leave the list
consistent (no row lost on a failed unsave). (MockWebServer test.)

AC-7. No cookies, CSRF token, or raw content ids/titles appear in logs or telemetry.
(Code review + log assertion in tests.)

## 15. Definition of Done

- `feature-saved` Saved screen, `SavedViewModel`, `BookmarksRepository`,
  `BookmarksPagingSource`, `BookmarksApi`, and DTOs/mapper implemented under
  `com.testlogon.android.feature.saved`, with nav wiring into the authenticated graph.
- `BookmarksApi` (list/delete/create) registered in the `core-network` Retrofit/Hilt
  module following the AND-027 pattern; field names reconciled against `bookmarks.ts` /
  `/openapi.json`.
- All AC-1…AC-7 tests green: MockWebServer, repository/`PagingSource` unit, ViewModel
  unit, and at least one Compose UI test, included and passing in CI (AND-050).
- No cookie/CSRF/content-id leakage in logs or telemetry; strings externalized; TalkBack
  and dynamic-type verified.
- Lint/detekt/ktlint clean; builds on `compileSdk 35` / `targetSdk 35` / AGP 8.7.3 /
  Kotlin 2.0.21 / JDK 17 / Gradle 8.9.
- PR on `android-port` references AND-092 and links AND-027.
