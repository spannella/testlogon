---
id: AND-092
title: Saved / bookmarks
milestone: M2
epic: E13
priority: P1
size: M
depends_on: [AND-027]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
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
    val contentType: String,   // backend enum: "post" | "video" only (not "clip")
    val contentId: String,
    val collectionId: String?,
    // Derived display labels mapped from the DTO's nested `content_preview`:
    //   title    ← content_preview.author_display_name ?: author_id
    //   subtitle ← content_preview.body_snippet
    //   thumbnailUrl ← content_preview.image_url
    val title: String?,
    val subtitle: String?,
    val thumbnailUrl: String?,
    val savedAt: Instant?,     // mapped from DTO field `created_at` (NOT `saved_at`)
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

    // CORRECTED: DELETE returns HTTP 200 with a JSON body `{ "ok": true }`
    // (NOT 204 / empty). Parse a tiny DTO (or Response<ResponseBody>) rather
    // than Response<Unit>, which would leave the body unconsumed.
    @DELETE("ui/bookmarks/{content_type}/{content_id}")
    suspend fun deleteBookmark(
        @Path("content_type") contentType: String,
        @Path("content_id") contentId: String,
    ): Response<OkDto>

    // POST returns 201 with a body `{ ok, content_type, content_id,
    // collection_id, created_at }`; we ignore the body for Undo.
    @POST("ui/bookmarks")
    suspend fun createBookmark(@Body body: CreateBookmarkDto): Response<OkDto> // for Undo
}
```

DTOs (Moshi, `@Json(name=...)` for snake_case):

```kotlin
@JsonClass(generateAdapter = true)
data class BookmarkPageDto(
    // CORRECTED: the list envelope key is `bookmarks` (NOT `items`), per
    // frontend BookmarkListResponse in src/api/endpoints/bookmarks.ts.
    @Json(name = "bookmarks") val bookmarks: List<BookmarkDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
    // CORRECTED: envelope also carries a `total_count` (int) — captured for
    // optional header display; not required for pagination.
    @Json(name = "total_count") val totalCount: Int? = null,
)

@JsonClass(generateAdapter = true)
data class BookmarkDto(
    // content_type is constrained to "post" | "video" by the backend enum
    // (CreateBookmarkRequest) and the frontend BookmarkItem union.
    @Json(name = "content_type") val contentType: String,
    @Json(name = "content_id") val contentId: String,
    @Json(name = "collection_id") val collectionId: String? = null,
    // CORRECTED: the saved timestamp field is `created_at` (NOT `saved_at`).
    @Json(name = "created_at") val createdAt: String? = null,
    // CORRECTED: display metadata is nested under `content_preview`, NOT flat
    // `title`/`subtitle`/`thumbnail_url` fields. Map preview → domain below.
    @Json(name = "content_preview") val contentPreview: ContentPreviewDto? = null,
)

@JsonClass(generateAdapter = true)
data class ContentPreviewDto(
    @Json(name = "author_id") val authorId: String? = null,
    @Json(name = "author_display_name") val authorDisplayName: String? = null,
    @Json(name = "body_snippet") val bodySnippet: String? = null,
    @Json(name = "image_url") val imageUrl: String? = null,
    @Json(name = "like_count") val likeCount: Int? = null,
)

@JsonClass(generateAdapter = true)
data class CreateBookmarkDto(
    // Backend CreateBookmarkRequest: content_id required (pattern
    // ^[a-zA-Z0-9_]+$, 1..64); content_type defaults to "post" (enum
    // post|video); collection_id defaults to "default" server-side.
    @Json(name = "content_type") val contentType: String? = null,
    @Json(name = "content_id") val contentId: String,
    @Json(name = "collection_id") val collectionId: String? = null,
)

@JsonClass(generateAdapter = true)
data class OkDto(
    // Both DELETE (200) and POST (201) return at least `{ "ok": true }`.
    @Json(name = "ok") val ok: Boolean = true,
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
(nullable). The session rides on cookies. NOTE: the web client (`client.ts`) also
sends an `Authorization: Bearer <accessToken>` header (from its auth store) AND an
`X-CSRF-Token` header (from the `ui_csrf` cookie) on EVERY request, including this
GET — not only on mutations. This Android ticket is designed cookie-only (AND-011
jar) on the assumption the backend accepts cookie-session auth for `/ui/*`; the
CSRF interceptor (AND-012) likewise attaches `X-CSRF-Token` whenever the cookie is
present. Whether the GET strictly requires the Bearer header is an UNVERIFIED
assumption (the web app supplies it unconditionally).
200 →

200 → (CORRECTED to match frontend `BookmarkListResponse` / `BookmarkItem` in
`src/api/endpoints/bookmarks.ts`: envelope key is `bookmarks` not `items`, there
is a `total_count`, each item carries `created_at` and a nested
`content_preview`, NOT flat `title`/`subtitle`/`thumbnail_url`/`saved_at`):

```json
{
  "bookmarks": [
    {
      "content_type": "post",
      "content_id": "post_01HX",
      "collection_id": "default",
      "created_at": "2026-06-05T09:31:44Z",
      "content_preview": {
        "author_id": "user_abc",
        "author_display_name": "Sunset Studio",
        "body_snippet": "Behind the scenes of the shoot...",
        "image_url": "https://.../thumb.jpg",
        "like_count": 42
      }
    }
  ],
  "next_cursor": "eyJrIjoi",
  "total_count": 137
}
```

`DELETE /ui/bookmarks/{content_type}/{content_id}` (mutation) — requires
`X-CSRF-Token` (echoed from `ui_csrf` cookie by AND-012). CORRECTED: OpenAPI
documents only **200 with a JSON body `{ "ok": true }`** (and 422) — there is no
documented 204 and no documented 404 for this route. Treat 200 as success; the
client still defensively treats any 404 as "already removed" (row gone) since the
web client (`removeBookmark`) relies on server idempotency, but 204/404 are
UNVERIFIED assumptions, not part of the published contract.

`POST /ui/bookmarks` (Undo) — requires `X-CSRF-Token`. Body
`CreateBookmarkRequest`:

```json
{ "content_type": "post", "content_id": "post_01HX", "collection_id": "default" }
```

201 on success with body `{ ok, content_type, content_id, collection_id,
created_at }`. Per `CreateBookmarkRequest`: `content_id` is the only required
field (string, pattern `^[a-zA-Z0-9_]+$`, len 1..64); `content_type` defaults to
`"post"` and is constrained to the enum `post|video`; `collection_id` is nullable
and defaults server-side to `"default"` (NOT `null`).

Error envelope (FastAPI `detail`, mapped per AND-015 — `string | [{msg}] | {code,...}`):

```json
{ "detail": "Not authenticated" }
{ "detail": [{ "msg": "field required", "loc": ["query","limit"] }] }
{ "detail": { "code": "bookmark_not_found", "message": "..." } }
```

Status handling: 200/201/204 success; 401 → authenticator performs
`POST /ui/session/refresh` once then retries (transparent — matches web
`refreshSession()` in `client.ts`); 403 → CSRF/forbidden surfaced as retryable
error; 404 on delete → defensively treated as already-removed (keep row hidden, no
error) — NOTE 404 is NOT a documented response for this route (only 200/422), so
this is a tolerant assumption; 422 → validation error mapped via `detail` array
form; 5xx / timeout →
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
  `DELETE /ui/bookmarks/{type}/{id}` 200 (`{"ok":true}`) plus a tolerated 404,
  `POST /ui/bookmarks` 201, and
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

- Q1: RESOLVED in this review. The OpenAPI list/delete responses have no typed
  schema (`schema: {}`), but `frontend/src/api/endpoints/bookmarks.ts`
  (`BookmarkListResponse`) is authoritative: envelope is `{ bookmarks[],
  next_cursor?, total_count }` — i.e. `bookmarks` (NOT `items`) and `next_cursor`
  (NOT `cursor`/`next`). DTOs in §4 corrected accordingly.
- Q2: RESOLVED. `GET /ui/bookmarks` DOES return display metadata, but nested under
  `content_preview` (`author_id`, `author_display_name`, `body_snippet`,
  `image_url`, `like_count`) plus top-level `created_at` — NOT flat
  `title`/`thumbnail_url`. The row derives title from
  `author_display_name ?: author_id`, subtitle from `body_snippet`, thumbnail from
  `image_url`, and degrades gracefully when `content_preview`/`image_url` is absent.
- Q3: RESOLVED. `DELETE` is keyed by `{content_type, content_id}` and returns
  **HTTP 200 with body `{ "ok": true }`** (NOT 204; OpenAPI documents only
  200/422). 404-on-missing is NOT documented; the client tolerates it defensively
  but tests should not assume the server emits it.
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

## 16. Citations & Assumption Audit

Each key technical claim with VERDICT and SOURCE pointer.

1. **Endpoint `GET /ui/bookmarks` with query params `limit`, `cursor`,
   `content_type`, `collection_id`.** VERDICT: Verified. SOURCE: OpenAPI
   `GET /ui/bookmarks` (op `list_bookmarks_ui_bookmarks_get`,
   params=`limit,cursor,content_type,collection_id,...`); frontend
   `src/api/endpoints/bookmarks.ts: getBookmarks`.
2. **Endpoint `DELETE /ui/bookmarks/{content_type}/{content_id}`.** VERDICT:
   Verified. SOURCE: OpenAPI `DELETE /ui/bookmarks/{content_type}/{content_id}`
   (op `delete_bookmark_ui_bookmarks__content_type___content_id__delete`);
   frontend `src/api/endpoints/bookmarks.ts: removeBookmark`.
3. **Endpoint `POST /ui/bookmarks` with body `CreateBookmarkRequest`, returns
   201.** VERDICT: Verified. SOURCE: OpenAPI `POST /ui/bookmarks` (op
   `create_bookmark_ui_bookmarks_post`, req=`CreateBookmarkRequest`,
   resp=`201`); frontend `src/api/endpoints/bookmarks.ts: createBookmark`.
4. **List response envelope key is `bookmarks` (the spec originally said
   `items`) and also includes `total_count`.** VERDICT: Corrected. SOURCE:
   frontend `src/api/endpoints/bookmarks.ts: BookmarkListResponse`
   (`{ bookmarks: BookmarkItem[]; next_cursor?: string; total_count: number }`).
   OpenAPI list response schema is empty (`schema: {}`), so frontend is
   authoritative.
5. **Pagination key is `next_cursor`; pagination stops when it is null/absent.**
   VERDICT: Verified. SOURCE: frontend `src/pages/saved/SavedPage.tsx`
   (`getNextPageParam: (lastPage) => lastPage.next_cursor || undefined`);
   `src/api/endpoints/bookmarks.ts: BookmarkListResponse.next_cursor`.
6. **Item timestamp field is `created_at` (the spec originally said
   `saved_at`).** VERDICT: Corrected. SOURCE: frontend
   `src/api/endpoints/bookmarks.ts: BookmarkItem.created_at`; used in
   `src/pages/saved/SavedPage.tsx` (`new Date(item.created_at)`).
7. **Item display metadata is nested under `content_preview`
   (`author_id`, `author_display_name`, `body_snippet`, `image_url`,
   `like_count`), NOT flat `title`/`subtitle`/`thumbnail_url`.** VERDICT:
   Corrected. SOURCE: frontend `src/api/endpoints/bookmarks.ts: BookmarkItem`;
   rendered in `src/pages/saved/SavedPage.tsx` (author_display_name/author_id,
   body_snippet, image_url).
8. **`content_type` is constrained to the enum `post` | `video` (the spec's
   model listed `"clip" | ...`).** VERDICT: Corrected. SOURCE: OpenAPI
   `components.schemas.CreateBookmarkRequest.content_type` (enum `[post, video]`,
   default `post`); frontend `BookmarkItem.content_type: "post" | "video"`.
9. **`CreateBookmarkRequest`: `content_id` required (string, pattern
   `^[a-zA-Z0-9_]+$`, len 1..64); `content_type` default `post`; `collection_id`
   nullable, server default `"default"`.** VERDICT: Verified (and the spec's
   `collection_id: null` example corrected to `"default"`). SOURCE: OpenAPI
   `components.schemas.CreateBookmarkRequest`.
10. **`DELETE` returns HTTP 200 with a JSON body `{ "ok": true }` (the spec
    originally claimed 200/204 and Retrofit `Response<Unit>`).** VERDICT:
    Corrected. SOURCE: OpenAPI `DELETE /ui/bookmarks/{content_type}/{content_id}`
    responses (only `200` with `schema: {}` and `422`); frontend
    `removeBookmark` typed `api.del<{ ok: boolean }>`. Changed Android return
    type to `Response<OkDto>`.
11. **CSRF: `X-CSRF-Token` is read from the `ui_csrf` cookie and sent on
    requests.** VERDICT: Verified (with nuance). SOURCE: frontend
    `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token",
    csrf)`). NUANCE/Corrected: the web client sends it on EVERY request, not
    only mutations; the spec's "mutations carry `X-CSRF-Token`" is narrower than
    web behavior (noted inline in §5).
12. **401 handling: a single `POST /ui/session/refresh` then retry, transparent
    to the caller.** VERDICT: Verified. SOURCE: frontend `src/api/client.ts`
    (`refreshSession()` → `fetch("/ui/session/refresh", { method: "POST" })`,
    then one retry of the original request).
13. **Network/offline error surfaces as a retryable error.** VERDICT: Verified.
    SOURCE: frontend `src/api/client.ts` catch block → `throw new ApiError(0,
    "Network error", err)`.
14. **FastAPI `detail` error envelope takes string | array-of-`{msg}` | object
    forms.** VERDICT: Verified. SOURCE: frontend `src/api/client.ts:
    normalizeErrorDetail` (handles string, array of `{msg}`, and object with
    `code`/`msg`); OpenAPI `components.schemas.HTTPValidationError` (422).
15. **422 is the documented validation response for all bookmark routes.**
    VERDICT: Verified. SOURCE: OpenAPI index lines for all four bookmark routes
    (`resp=...;422:HTTPValidationError`).
16. **`GET /ui/bookmarks/status` exists, takes `ids` (comma-joined) and returns
    `{ statuses: Record<string, boolean> }` — out of scope here.** VERDICT:
    Verified. SOURCE: OpenAPI `GET /ui/bookmarks/status`
    (op `bookmark_status_ui_bookmarks_status_get`, params=`ids,...`); frontend
    `src/api/endpoints/bookmarks.ts: getBookmarkStatus`.
17. **Collections endpoints (`/ui/bookmark-collections`) exist — out of scope.**
    VERDICT: Verified. SOURCE: OpenAPI `GET/POST /ui/bookmark-collections`,
    `DELETE/PATCH /ui/bookmark-collections/{collection_id}`; frontend
    `getCollections`/`createCollection`/`renameCollection`/`deleteCollection`.
18. **Paging 3 with cursor `PagingSource` / `cachedIn` / `LazyPagingItems`.**
    VERDICT: Verified (framework ref). SOURCE: framework ref
    https://developer.android.com/topic/libraries/architecture/paging/v3-overview
19. **`DateUtils.getRelativeTimeSpanString` for locale-aware relative
    timestamps.** VERDICT: Verified (framework ref). SOURCE: framework ref
    https://developer.android.com/reference/android/text/format/DateUtils
20. **Default page `limit`.** VERDICT: Unverified-assumption (spec uses 20).
    SOURCE: frontend `src/pages/saved/SavedPage.tsx` actually requests
    `limit: 24`; no documented max in OpenAPI (`limit` has no schema bounds in
    the index). 20 is a safe client choice but differs from web.

### Corrections made

- §4 DTO `BookmarkPageDto`: list key `items` → `bookmarks`; added
  `total_count` (claim 4).
- §4 DTO `BookmarkDto`: `saved_at` → `created_at` (claim 6); removed flat
  `title`/`subtitle`/`thumbnail_url`; added nested `content_preview`
  (`ContentPreviewDto`) and documented the preview→domain mapping (claim 7).
- §4 domain `Bookmark`: corrected `content_type` comment (no `clip`; enum
  `post|video`, claim 8) and noted `savedAt` maps from `created_at`.
- §4 `BookmarksApi`: `deleteBookmark` / `createBookmark` return type
  `Response<Unit>` → `Response<OkDto>` because both return a JSON body; added
  `OkDto` (claim 10).
- §5 GET 200 example rewritten to the real envelope/item shape (claims 4, 6, 7).
- §5 DELETE note: removed the unsupported "200/204 success / 404" contract claim;
  documented 200-with-body and flagged 204/404 as tolerant assumptions
  (claims 10, and open assumption on 404).
- §5 POST note: documented 201 body, enum `content_type`, and `collection_id`
  default `"default"` (claims 3, 9); example `collection_id` `null` → `"default"`.
- §5 auth note: clarified web also sends `Authorization: Bearer` + `X-CSRF-Token`
  on every request (claim 11); flagged cookie-only Android design as assumption.
- §5 status-handling: flagged 404-on-delete as undocumented (claim 10).
- §11: DELETE fixture wording `200/204` → `200 ({"ok":true})` + tolerated 404.
- §13 Q1/Q2/Q3: marked RESOLVED with the verified field names/shapes/status.
- Frontmatter: `status: draft` → `status: reviewed`; added `reviewed_on:
  2026-06-06`.

### Open assumptions

- **204 / 404 on `DELETE`.** Unverifiable: OpenAPI documents only 200/422 for
  the delete route and the frontend does not exercise a missing-bookmark path, so
  the server's behavior for an already-deleted bookmark (404 vs 200) is unknown.
  The client tolerates 200/404 defensively; tests must not assert the server
  emits 404.
- **Cookie-only auth for `/ui/bookmarks` (no `Authorization: Bearer`).**
  Unverifiable from sources: the web client always attaches a Bearer token from
  its auth store in addition to cookies, so whether the backend accepts pure
  cookie-session auth is not confirmable here. Depends on AND-027/AND-011 session
  model; verify against a live backend before merge.
- **Default/max `limit`.** Unverifiable: OpenAPI exposes no bounds and web uses
  24 while this spec uses 20. No documented maximum (Q4 in §13).
- **Cursor opacity / forward-only semantics (`getRefreshKey` → null).**
  Unverifiable: `next_cursor` is an opaque string in both OpenAPI (untyped) and
  frontend; its internal structure and any backward-paging support are unknown.
  Forward-only is a safe assumption matching the web's infinite-scroll usage.
- **Relative-timestamp display.** Android UX choice: the web renders an absolute
  `toLocaleDateString()`; relative formatting (FR-3) is an Android enhancement,
  not a contract requirement.
- **Optimistic removal + Undo snackbar + `POST` re-save (FR-4/FR-5).** Android
  UX enhancement: the web client performs a plain delete then
  `invalidateQueries` (no optimistic UI, no Undo) per `SavedPage.tsx`. The
  optimistic/Undo flow is this ticket's design, not mirrored from web.

## 17. Test Plan

Test target legend: JVM = JVM unit/Robolectric (local, no device);
EMU = headless emulator AVD `test35` (x86_64, API 35); DEV = physical Samsung
Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). This feature is network/UI only
(no camera, biometrics, push, WebRTC, Telecom, or streaming), so most cases run
on JVM/EMU; DEV is used only for the real-network/flaky-host and ABI/API-level
checks where physical-device behavior matters.

- **TC-AND-092-01 — Happy path: first-page list render.** Type:
  contract/MockWebServer. Target: JVM. Preconditions: MockWebServer enqueues
  `GET /ui/bookmarks?limit=20` → 200 with `{ bookmarks:[2 items], next_cursor:
  "C1", total_count: 2 }`. Steps: call `BookmarksPagingSource.load(Refresh)`.
  Expected: `LoadResult.Page` with 2 mapped `Bookmark`s; `prevKey == null`;
  `nextKey == "C1"`; request path `/ui/bookmarks` with query `limit=20`, no
  `cursor`; title derived from `content_preview.author_display_name`. Traces:
  AC-1.
- **TC-AND-092-02 — Cursor pagination + end-of-list.** Type:
  contract/MockWebServer. Target: JVM. Preconditions: page 1 → `next_cursor:
  "C1"`; page 2 (request carries `cursor=C1`) → `{ bookmarks:[1], next_cursor:
  null }`. Steps: `load(Refresh)` then `load(Append, key="C1")`. Expected: page 2
  request includes `cursor=C1`; second `LoadResult.Page` has `nextKey == null`
  (pagination stops). Traces: AC-1.
- **TC-AND-092-03 — DTO→domain mapping incl. null/absent fields.** Type: unit.
  Target: JVM. Preconditions: fixtures with (a) full `content_preview`, (b)
  missing `content_preview`, (c) null `created_at`, (d) unparseable `created_at`.
  Steps: run the mapper. Expected: (a) title/subtitle/thumbnail populated from
  preview; (b) title/subtitle/thumbnail null, no crash; (c)/(d) `savedAt == null`
  (no crash, no timestamp shown). Traces: AC-1, AC-5.
- **TC-AND-092-04 — Unsave happy path: DELETE + CSRF + optimistic removal.**
  Type: contract/MockWebServer + unit (ViewModel/Turbine). Target: JVM.
  Preconditions: `ui_csrf` cookie present; `DELETE /ui/bookmarks/post/post_1` →
  200 `{"ok":true}`. Steps: `SavedViewModel.unsave(bookmark)`. Expected: request
  is `DELETE /ui/bookmarks/post/post_1` carrying header `X-CSRF-Token`;
  `removedIds` contains `"post/post_1"` immediately (optimistic); `UndoTarget`
  set; no error. Traces: AC-2, AC-4.
- **TC-AND-092-05 — Unsave failure rollback.** Type: contract/MockWebServer +
  unit (ViewModel). Target: JVM. Preconditions: `DELETE` → 500. Steps:
  `unsave(bookmark)` then await result. Expected: key first added to `removedIds`
  (optimistic) then removed on failure (row reappears); `error` set to a
  retryable `UiError(type=server)`; list otherwise unchanged. Traces: AC-2, AC-6.
- **TC-AND-092-06 — 404 on delete tolerated as already-removed.** Type:
  contract/MockWebServer + unit (ViewModel). Target: JVM. Preconditions:
  `DELETE` → 404 (note: undocumented server behavior; simulated). Steps:
  `unsave(bookmark)`. Expected: row stays in `removedIds` (gone); no `error` set;
  no `UndoTarget` regression. Traces: AC-3.
- **TC-AND-092-07 — Undo re-creates via POST.** Type: contract/MockWebServer +
  unit (ViewModel). Target: JVM. Preconditions: after a successful unsave,
  `POST /ui/bookmarks` → 201 `{ ok:true, ... }`. Steps: `undoUnsave()`. Expected:
  POST body is `{ content_type, content_id, collection_id }` for the unsaved
  item; carries `X-CSRF-Token`; key removed from `removedIds` (row reappears);
  `UndoTarget` cleared. Traces: AC-4.
- **TC-AND-092-08 — Error-envelope mapping (string / array / object).** Type:
  unit. Target: JVM. Preconditions: three fixtures — `{"detail":"Not
  authenticated"}`, `{"detail":[{"msg":"field required","loc":["query","limit"]}]}`,
  `{"detail":{"code":"bookmark_not_found","message":"..."}}`. Steps: run the
  `detail` mapper (AND-015) on each. Expected: each maps to the correct
  `UiError.type` (auth / validation / server) and a normalized message; matches
  web `normalizeErrorDetail` semantics. Traces: AC-6.
- **TC-AND-092-09 — Compose: list renders + unsave removes row + Undo
  snackbar.** Type: Compose-UI. Target: EMU. Preconditions: fake paged source
  with 3 items. Steps: assert 3 rows; tap the "Unsave" affordance on row 1.
  Expected: row 1 disappears from the rendered list; an Undo snackbar is shown;
  tapping Undo restores the row. Traces: AC-2, AC-4.
- **TC-AND-092-10 — Compose: empty + error/offline states.** Type: Compose-UI.
  Target: EMU. Preconditions: (a) first page empty; (b) first page
  `LoadState.Error`. Steps: render each. Expected: (a) empty state ("You haven't
  saved anything yet"); (b) retryable error/offline state with a Retry control;
  append error renders a retryable footer. Traces: AC-5, AC-6.
- **TC-AND-092-11 — Accessibility: row semantics, touch targets, TalkBack.**
  Type: Compose-UI (Robolectric semantics) + manual TalkBack pass. Target: EMU
  for assertions; DEV for the manual TalkBack pass. Preconditions: list with ≥1
  row. Steps: assert merged row `contentDescription` (title + type + saved time);
  decorative thumbnail has null description; "Unsave" has
  `contentDescription` "Remove <title> from saved" and a ≥48dp touch target;
  Undo snackbar action is announced. Expected: all semantics present; manual
  TalkBack announces row, unsave, and undo. Traces: AC-2 (UI), supports §9.
- **TC-AND-092-12 — Mutations never auto-retried; GET may retry (resilience).**
  Type: contract/MockWebServer. Target: JVM. Preconditions: `GET` first attempt
  timeout then 200 (bounded-backoff per AND-016); `DELETE` → 500. Steps: trigger
  a list load and an unsave. Expected: `GET` is retried and eventually succeeds;
  `DELETE` is issued exactly once (no duplicate destructive call) and surfaces an
  error. Traces: AC-6.
- **TC-AND-092-13 — Real flaky/offline dev-host behavior (end-to-end).** Type:
  instrumented/e2e. Target: DEV (physical A15, API 34, real network). MUST run on
  the physical device: exercises real radio/airplane-mode transitions and the
  cleartext-HTTP dev host `http://18.222.237.167:8000`, which the emulator's NAT
  masks. Preconditions: app pointed at the dev host. Steps: open Saved online
  (list loads); enable airplane mode and pull-to-refresh; re-enable and Retry.
  Expected: offline → retryable error/offline state (no crash, no lost rows);
  Retry recovers and reloads page 1. Traces: AC-5, AC-6.
- **TC-AND-092-14 — Security: no cookie/CSRF/content-id leakage; ABI/API
  sanity.** Type: instrumented + log assertion. Target: DEV (release-style build
  on arm64-v8a / API 34 to catch ABI- and API-34-vs-35 differences vs the EMU).
  Preconditions: Timber test tree capturing logs; perform list + unsave + undo.
  Steps: drive the flows; capture all logcat output and any analytics payloads.
  Expected: no `ui_csrf`/session cookie values, no `X-CSRF-Token` value, and no
  raw `content_id`/title strings appear in logs or telemetry; telemetry events
  carry only `content_type` and normalized `UiError.type`. Traces: AC-7.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 (list render + cursor pagination + stop on null) | TC-01, TC-02, TC-03 |
| AC-2 (unsave: DELETE+CSRF, remove on success, rollback on fail) | TC-04, TC-05, TC-09, TC-11 |
| AC-3 (404 on delete = already-removed, no error) | TC-06 |
| AC-4 (Undo snackbar → POST re-create, row reappears) | TC-04, TC-07, TC-09 |
| AC-5 (empty / error-offline / append-footer states) | TC-03, TC-10, TC-13 |
| AC-6 (network/CSRF/server errors retryable, list consistent) | TC-05, TC-08, TC-10, TC-12, TC-13 |
| AC-7 (no cookie/CSRF/content-id leakage in logs/telemetry) | TC-14 |
