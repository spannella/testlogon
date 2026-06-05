---
id: AND-332
title: File manager browse
milestone: M7
epic: E43
priority: P1
size: L
status: draft
depends_on: [AND-331]
blocks: [AND-333]
---

# AND-332 — File manager browse

## 1. Overview & Goal

Deliver the read-only browsing surface of the TestLogon file manager for the native
Android client: a folder/file tree navigator with breadcrumb path, in-folder (and
optionally global) search, and client-driven sort. This ticket consumes the typed
DTOs and Retrofit service produced by **AND-331 (Files API + DTOs)** and exposes a
`feature-files` module with a single Compose screen, a `FilesViewModel`, and a
`FilesRepository` backed by Paging 3 over the FastAPI listing endpoint.

Goal: a user lands on the Files tab, sees the contents of the current folder, can tap
folders to descend, tap back/breadcrumbs to ascend, type a query to filter/search the
listing, and change sort order (name / size / modified, ascending or descending). All
of this must behave correctly against the unreliable plaintext dev backend
(`http://18.222.237.167:8000`): bounded retry on idempotent GETs, visible
loading/empty/error/offline states, and stale-while-revalidate from a Room cache.

Out of scope (owned by sibling tickets): upload (**AND-333**, presigned PUT), and
create/rename/delete/move mutations (folder CRUD, a later E43 ticket). This spec
defines the navigation/search/sort UX and the cache that the mutation tickets will
invalidate.

## 2. Context & References

- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, Navigation-Compose
  (single-Activity), Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 /
  Moshi 1.15, Room 2.6, DataStore, Paging 3, Coil. minSdk 24, compile/target 35,
  JDK 17, Gradle 8.9, AGP 8.7.3.
- **Namespace / applicationId base:** `com.testlogon.android`. This module is
  `com.testlogon.android.feature.files`.
- **Module layering:** `app -> feature-files -> core-*` (`core-network`,
  `core-model`, `core-data`, `core-ui`, `core-testing`). No feature-to-feature deps.
- **AND-331 (dependency, P0):** owns `FilesApi` (Retrofit), the file/folder DTOs
  (`FileNodeDto`, `FileListResponseDto`), and DTO→domain mapping. This ticket MUST
  NOT re-declare those types; it imports the domain models and service from
  `core-network`/`core-model`. The web reference is `frontend/src/api/endpoints/files.ts`
  with shared types in `frontend/src/api/types.ts`.
- **AND-333 (downstream, blocked by this):** upload via presign reuses
  `FilesRepository.invalidateFolder(folderId)` and the current-folder state defined here.
- **Auth:** cookie-based session with `ui_csrf` echoed as `X-CSRF-Token`; persistent
  cookie jar and 401→`POST /ui/session/refresh`→retry interceptor live in
  `core-network` and apply transparently to all `FilesApi` calls.
- **OpenAPI:** `/openapi.json` is the contract of record; the shapes in §5 reflect the
  current dev backend and `files.ts`.

## 3. Functional Requirements

FR-1 **Folder listing.** On entering the Files tab the screen loads the root folder
(`folderId = null` ⇒ server returns root) and renders a paged list of child nodes
(folders first by default, then files), each row showing name, type icon, size
(files), and relative modified time.

FR-2 **Descend / ascend.** Tapping a folder row pushes that folder onto an in-memory
navigation stack and loads its children. A breadcrumb bar shows the path
(`Root / A / B`); tapping any crumb pops to that level. System Back and the top-bar
up-affordance pop one level; at root, Back yields to the host nav graph.

FR-3 **Search.** A search field in the top bar filters the current view. Queries ≥2
chars are debounced (300 ms) and sent to the server search endpoint scoped to the
current folder by default, with a toggle for "search everywhere" (recursive/global).
Empty query restores the plain folder listing.

FR-4 **Sort.** A sort control offers three keys — `NAME`, `SIZE`, `MODIFIED` — each
toggleable ascending/descending. Sort is applied server-side via query params and is
persisted across sessions in DataStore. Folders-before-files grouping is preserved
under `NAME`; under `SIZE`/`MODIFIED` the grouping toggle is user-selectable.

FR-5 **States.** The screen renders distinct UI for: initial loading (shimmer),
populated, empty folder ("This folder is empty"), empty search ("No matches"),
error (retryable), and offline-stale (cached data with a banner).

FR-6 **Pagination.** Listings page via Paging 3 (`PagingData<FileNode>`); scrolling to
the end appends the next page; a footer shows append-load and append-error (retry).

FR-7 **Pull-to-refresh** forces a network revalidation of the current folder,
bypassing the freshness window.

FR-8 **Selection of a file** emits a navigation event (file detail/preview is a
separate ticket); this screen only exposes the click callback and does not implement
preview.

## 4. Technical Design

New module `feature-files` (`com.testlogon.android.feature.files`).

```
feature-files/
  ui/        FilesScreen.kt, FilesRoute.kt, FilesTopBar.kt, FileRow.kt, SortSheet.kt
  presentation/ FilesViewModel.kt, FilesUiState.kt, FilesUiEvent.kt
  data/      FilesRepository.kt, FilesPagingSource.kt, FilesSearchPagingSource.kt
  di/        FilesModule.kt
```

**Navigation (Navigation-Compose).** Route is parameterless at entry; current folder
is ViewModel state, not a nav arg, so deep navigation does not create a back-stack
entry per folder (Back is handled in-screen).

```kotlin
@Serializable data object FilesRoute
fun NavGraphBuilder.filesScreen(onOpenFile: (FileId) -> Unit) {
    composable<FilesRoute> { FilesScreen(onOpenFile = onOpenFile) }
}
```

**ViewModel.**

```kotlin
@HiltViewModel
class FilesViewModel @Inject constructor(
    private val repo: FilesRepository,
    private val prefs: FilesPreferences,        // DataStore-backed
) : ViewModel() {

    val uiState: StateFlow<FilesUiState>        // breadcrumb, sort, query, mode, banner

    // Combine(folderStack, query, sort) -> Pager -> Flow<PagingData<FileNode>>.cachedIn
    val items: Flow<PagingData<FileNode>>

    fun onOpenFolder(node: FileNode)
    fun onCrumbClick(index: Int)
    fun onBack(): Boolean                        // false => let host handle
    fun onQueryChange(text: String)              // debounced upstream
    fun onScopeToggle(global: Boolean)
    fun onSortChange(key: SortKey, dir: SortDir)
    fun onRefresh()
    fun onRetry()
}
```

**State model.**

```kotlin
data class FilesUiState(
    val breadcrumb: List<Crumb> = listOf(Crumb.Root),   // Crumb(id: FileId?, name)
    val query: String = "",
    val globalSearch: Boolean = false,
    val sort: SortSpec = SortSpec(SortKey.NAME, SortDir.ASC, foldersFirst = true),
    val isOffline: Boolean = false,                       // shows stale banner
    val refreshing: Boolean = false,
)
enum class SortKey { NAME, SIZE, MODIFIED }
enum class SortDir { ASC, DESC }
data class SortSpec(val key: SortKey, val dir: SortDir, val foldersFirst: Boolean)
```

**Repository + Paging.** `FilesRepository` builds a `Pager(PagingConfig(pageSize=50,
prefetchDistance=10, initialLoadSize=50))`. Browse uses `FilesPagingSource` (cursor or
offset per §5); search uses `FilesSearchPagingSource`. A Room-backed
`RemoteMediator` is used for the *browse* path only (stale-while-revalidate, cache
key = folderId+sort); search is network-only (not cached) because result sets are
ephemeral and query-dependent.

```kotlin
interface FilesRepository {
    fun browse(folderId: FileId?, sort: SortSpec): Flow<PagingData<FileNode>>
    fun search(folderId: FileId?, query: String, global: Boolean, sort: SortSpec):
        Flow<PagingData<FileNode>>
    suspend fun invalidateFolder(folderId: FileId?)      // used by refresh + AND-333
}
```

**Sort semantics.** Server is the source of truth for ordering when it supports the
sort param; if a sort key is unsupported by the backend, the repository falls back to
in-page client sort and the ViewModel sets a one-time non-blocking notice. Decision
is recorded once at startup by probing `/openapi.json` capabilities cached in DataStore
(see §13 open question).

**Compose.** `FilesScreen` collects `uiState` and `items.collectAsLazyPagingItems()`.
`LazyColumn` renders `FileRow`s keyed by `node.id`; `loadState.refresh/append` drive
shimmer/empty/error composables from `core-ui`. `FilesTopBar` hosts the search field
(expandable), scope toggle, and sort affordance opening `SortSheet` (Material 3
`ModalBottomSheet`). Pull-to-refresh via `PullToRefreshBox`.

## 5. API Contract

All endpoints are GET (idempotent ⇒ eligible for bounded retry). Paths/shapes are
owned by AND-331; reproduced here for the consumed surface.

**Browse a folder.**
```
GET /ui/files?folder_id={id|omit-for-root}&sort={name|size|modified}
    &order={asc|desc}&limit=50&cursor={opaque|omit}
```
Response `FileListResponseDto`:
```json
{
  "items": [
    { "id": "f_01H...", "parent_id": null, "name": "Reports",
      "type": "folder", "size": null, "mime": null,
      "modified_at": "2026-05-30T14:02:11Z", "child_count": 7 },
    { "id": "o_01H...", "parent_id": "f_root", "name": "q1.pdf",
      "type": "file", "size": 184320, "mime": "application/pdf",
      "modified_at": "2026-05-29T09:11:00Z", "child_count": null }
  ],
  "next_cursor": "eyJrIjoi...",
  "total": 128
}
```

**Search.**
```
GET /ui/files/search?q={query}&folder_id={id|omit}&recursive={true|false}
    &sort={...}&order={...}&limit=50&cursor={...}
```
Same `FileListResponseDto` body; `recursive=true` ⇒ global search, `false` ⇒ scoped to
`folder_id`.

**Breadcrumb resolution.** Crumbs are built incrementally from `parent_id` chains
already in hand during descent (no extra call needed). If the screen is entered with a
non-root folder (future deep link), resolve via `GET /ui/files/{id}` for the node's
ancestors; not required for this ticket's entry path.

**Error body (FastAPI `detail`).** Mapped by `core-network` per project convention:
`string | [{ "msg": str, "type": str }] | { "code": str, ... }` → `ApiError`. This
screen surfaces `ApiError.message` and a `retryable` flag.

`next_cursor == null` ⇒ end of list (`PagingSource.LoadResult.Page(nextKey = null)`).

## 6. Data & State Management

**Domain model** (from AND-331 / `core-model`):
```kotlin
data class FileNode(
    val id: FileId, val parentId: FileId?, val name: String,
    val kind: FileKind, val size: Long?, val mime: String?,
    val modifiedAt: Instant, val childCount: Int?,
)
enum class FileKind { FOLDER, FILE }
```

**Room cache** (`core-data`, browse path only):
```kotlin
@Entity(tableName = "file_node", primaryKey... )
data class FileNodeEntity(
    @PrimaryKey val id: String, val parentId: String?, val name: String,
    val kind: String, val size: Long?, val mime: String?,
    val modifiedAtEpoch: Long, val childCount: Int?,
    val cacheFolderKey: String,   // "<folderId>|<sortKey>|<order>"
    val pageIndex: Int, val fetchedAtEpoch: Long,
)
@Dao interface FileNodeDao {
    @Query("SELECT * FROM file_node WHERE cacheFolderKey=:key ORDER BY pageIndex")
    fun pagingSource(key: String): PagingSource<Int, FileNodeEntity>
    @Query("DELETE FROM file_node WHERE cacheFolderKey LIKE :folderPrefix || '%'")
    suspend fun clearFolder(folderPrefix: String)
}
@Entity data class FileRemoteKey(val cacheFolderKey: String, val nextCursor: String?)
```
Freshness window: 60 s. `RemoteMediator.load(REFRESH)` skips network if
`now - fetchedAt < 60s` unless forced by pull-to-refresh.

**Preferences (DataStore):** persisted `sort.key`, `sort.order`, `sort.foldersFirst`,
`search.globalDefault`. Read once into `uiState` on init; written on user change.

**State exposure:** `uiState: StateFlow<FilesUiState>` (replay-1, started
`WhileSubscribed(5_000)`); `items: Flow<PagingData<FileNode>>` `cachedIn(viewModelScope)`.
Navigation stack is a private `MutableStateFlow<List<Crumb>>`.

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp call timeout 20 s (per project default for the dev host);
  Paging surfaces `LoadState.Error` on timeout.
- **Bounded retry:** browse/search are GETs ⇒ eligible for the `core-network`
  idempotent-GET retry policy (max 3 attempts, exponential backoff 500 ms→2 s, jitter,
  retry on IOException / HTTP 502/503/504). No retry on 4xx.
- **Stale-while-revalidate:** on network failure during REFRESH where cached rows
  exist, the `RemoteMediator` returns `MediatorResult.Success(endOfPaginationReached=false)`
  with cached data and the ViewModel sets `isOffline=true` to show the stale banner;
  background revalidation retried on next refresh.
- **Empty vs error:** distinguish `loadState.refresh is NotLoading && itemCount==0`
  (empty) from `loadState.refresh is Error` (error card with Retry → `retry()`).
- **Search of empty/short query:** queries <2 chars never hit the network; the view
  reverts to the browse pager.
- **401:** handled by the shared refresh interceptor (single `POST /ui/session/refresh`
  then retry); on repeated 401 the request fails and the app-level auth gate routes to
  re-auth — this screen renders a generic error and does not implement refresh itself.

## 8. Security & Privacy

- All file metadata travels over the session cookie + `X-CSRF-Token` (CSRF cookie
  echoed). GETs technically need no CSRF header, but the shared client attaches it
  uniformly; no tokens are logged.
- Dev backend is **plaintext HTTP**; production base URL must be HTTPS. The manifest
  uses a debug-only `network-security-config` allowing cleartext to the dev host;
  release builds set `cleartextTrafficPermitted=false`. No file *contents* are fetched
  here (browse is metadata-only), so no blob caching/encryption concerns in this
  ticket; file bytes are out of scope (preview/download own that).
- Room cache stores only non-sensitive metadata (names, sizes, timestamps) in app
  private storage; cache is cleared on logout via the existing `core-data` logout hook.
- Search queries are not persisted to disk (network-only path); only sort/scope
  *preferences* persist.

## 9. Accessibility & i18n

- Every `FileRow` exposes a merged semantics node: `contentDescription` =
  "{name}, {folder|file}, {size}, modified {relative time}". Type icons are decorative
  (`contentDescription = null`).
- Touch targets ≥48 dp; sort/search affordances are `IconButton`s with `stateDescription`
  reflecting current sort key/direction.
- Search field declares `Role.SearchField` semantics and an IME `Search` action.
- All user-facing strings (state messages, sort labels, breadcrumb "Root") are in
  `strings.xml`; plurals (`"%d items"`, `child_count`) use `<plurals>`. Sizes formatted
  via `android.text.format.Formatter.formatShortFileSize` (locale-aware); timestamps via
  `DateUtils.getRelativeTimeSpanString`. Layout is RTL-safe (breadcrumb uses
  `Arrangement.Start` + logical chevrons).

## 10. Telemetry & Logging

Events via the existing `core-telemetry` `Analytics` interface (no PII; never log file
names or queries):
- `files_browse_open` { folder_depth }
- `files_folder_open` { depth }
- `files_search` { scope: local|global, query_len, has_results } (length only)
- `files_sort_change` { key, dir }
- `files_refresh` { trigger: pull|retry }
- `files_load_error` { phase: refresh|append, http_status?, kind: timeout|io|http }

Logging: structured `Timber` at DEBUG for load-state transitions and cache hits/misses
(folder key only, never names/queries); WARN on retry exhaustion. Release builds strip
DEBUG via the project Timber tree config.

## 11. Testing Strategy

Use `core-testing` (MockWebServer, Turbine, `MainDispatcherRule`, fake DataStore).

**Unit / repository:**
- `FilesPagingSource` returns `Page(nextKey)` from `next_cursor`; `null` cursor ⇒
  `nextKey = null` (end). Offset/cursor math covered.
- `RemoteMediator`: fresh cache (<60 s) skips network; stale triggers fetch; network
  failure with cached rows ⇒ `Success` + offline flag; with no cache ⇒ `Error`.
- Sort param mapping: `(SortKey, SortDir)` → `sort/order` query strings; client-side
  fallback sort ordering is stable and folders-first when configured.
- Error mapping: FastAPI `detail` variants → `ApiError.retryable` correctly.

**ViewModel (Turbine):**
- Query debounce (300 ms), <2-char no-op, scope toggle switches source, sort change
  persists to DataStore and re-keys the pager.
- Navigation stack: open/crumb-click/back transitions; `onBack()` returns false at root.

**UI (Compose test):**
- States render: loading shimmer, populated, empty folder, empty search, error+retry,
  offline banner.
- Tap folder descends and updates breadcrumb; tap crumb ascends; pull-to-refresh
  invokes `onRefresh`.
- Semantics assertions for `FileRow` contentDescription and sort `stateDescription`.

**Instrumented (optional, dev backend):** smoke test against `/ui/files` guarded by a
build flag (skipped in CI given host unreliability).

Acceptance gate: "Browse + search work" is verified by the populated-state UI test,
the search-source-switch ViewModel test, and the PagingSource/RemoteMediator unit
tests all green.

## 12. Dependencies & Sequencing

- **Depends on AND-331 (P0)** — `FilesApi`, DTOs, and DTO→domain mapping MUST exist;
  this ticket imports them and adds no new DTOs. If AND-331 sort/search params differ
  from §5, this spec defers to AND-331's actual signatures and adapts the repository.
- **Depends transitively on AND-027** (the network/session foundation that AND-331
  builds on) for the cookie jar + CSRF + refresh interceptor.
- **Blocks AND-333 (Upload via presign)** — upload reuses current-folder state and
  `invalidateFolder()` defined here to refresh the listing after a completed upload.
- Folder CRUD (create/rename/delete/move) is a separate later E43 ticket; this ticket
  must leave `invalidateFolder()` and the cache key scheme usable by it.
- Sequencing: land `feature-files` module + DI, then repository/Paging + cache, then
  ViewModel, then Compose UI; wire `filesScreen()` into the app nav graph last.

## 13. Risks & Open Questions

- **R1 Backend sort/search support.** Whether `/ui/files` honors `sort`/`order` and
  whether `/ui/files/search` supports `recursive` is per the live dev backend; if
  unsupported, fall back to client-side per-page sort and folder-scoped-only search,
  and file a backend ticket. Confirm against `/openapi.json` during AND-331.
- **R2 Pagination model.** Cursor vs offset: §5 assumes opaque `next_cursor`; if the
  backend is offset-based, `FilesPagingSource` keys become `Int` offsets. Resolve from
  AND-331's `FilesApi`.
- **R3 Global search cost.** Recursive search on the unreliable host may be slow;
  mitigate with the 20 s timeout, debounce, and a "searching everywhere…" indicator.
- **R4 Deep-link entry to a non-root folder** requires ancestor resolution
  (`GET /ui/files/{id}`); deferred — entry is root-only this ticket.
- **OQ:** Does the backend return `child_count` for folders? If absent, hide the
  count subtitle rather than calling per-folder.

## 14. Acceptance Criteria

AC-1 Entering the Files tab loads and displays the root folder's children (folders
then files) within the loading→populated transition; empty folders show the empty
state. (Backlog: "Browse … work.")

AC-2 Tapping a folder descends and updates the breadcrumb; tapping a crumb and System
Back ascend correctly; at root, Back yields to the host. (FR-2)

AC-3 Typing a ≥2-char query (debounced) shows server search results scoped to the
current folder; toggling "search everywhere" switches to recursive results; clearing
the query restores the browse listing; no matches shows the empty-search state.
(Backlog: "search work"; FR-3)

AC-4 Sort by name/size/modified ascending and descending reorders the listing and the
choice persists across app restarts. (FR-4)

AC-5 Pagination appends pages on scroll; append errors show a retry footer that
recovers. (FR-6)

AC-6 On network failure with cached data, the screen shows cached rows plus an offline
banner; with no cache it shows a retryable error. (FR-5, §7)

AC-7 The named unit/ViewModel/UI tests in §11 pass in CI, satisfying backlog
"Browse + search work."

AC-8 No file names or search queries appear in logs or telemetry; only metadata
travels over the authenticated session.

## 15. Definition of Done

- `feature-files` module created under `com.testlogon.android.feature.files`, wired
  into the app nav graph via `filesScreen(onOpenFile)`; builds with Gradle 8.9 / AGP
  8.7.3 / JDK 17.
- `FilesRepository` (browse + search Paging, Room-backed browse cache with 60 s
  freshness and stale-while-revalidate, `invalidateFolder`), `FilesViewModel`
  (`StateFlow<FilesUiState>`, debounced search, persisted sort), and `FilesScreen`
  (breadcrumb, search, sort sheet, pull-to-refresh, all six states) implemented.
- Consumes AND-331 DTOs/service with zero duplicated DTOs; GET retry + 20 s timeout +
  401 refresh inherited from `core-network`.
- All §11 tests written and green in CI; lint/detekt/ktlint clean; no new cleartext
  permitted in release config.
- Telemetry events (§10) emitted with no PII; strings externalized and a11y semantics
  present.
- PR on branch `android-port` reviewed; AC-1…AC-8 demonstrably met; `invalidateFolder`
  and cache-key scheme documented for AND-333 and the future CRUD ticket.
