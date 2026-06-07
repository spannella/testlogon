---
id: AND-332
title: File manager browse
milestone: M7
epic: E43
priority: P1
size: L
status: reviewed
reviewed_on: 2026-06-06
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
`FilesRepository` backed by Paging 3 over the FastAPI listing endpoint
(`GET /v1/fs/list`).

> **Review note (2026-06-06):** This spec was originally drafted against a
> hypothetical `/ui/files` folder-id API. The authoritative backend (OpenAPI
> `GET /v1/fs/list`) and the web reference (`src/api/endpoints/files.ts`) are
> **path-based**, not folder-id-based, and the file DTO differs from what was
> drafted. All API claims have been corrected inline; see §16 for the full audit.

Goal: a user lands on the Files tab, sees the contents of the current folder, can tap
folders to descend, tap back/breadcrumbs to ascend, type a query to filter/search the
listing, and change sort order (name / updated / size, ascending or descending — these
are the only sort keys the backend accepts; see §5). All
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
- **AND-331 (dependency, P0):** owns `FilesApi` (Retrofit), the file DTO and list
  wrapper, and DTO→domain mapping. The backend returns a flat `FileEntry`
  (web type `FileEntry` in `src/api/types.ts`) wrapped by `FileListResp`
  (`{ path, items, cursor }`) — **not** the `FileNodeDto` / `FileListResponseDto`
  names this spec originally used. This ticket MUST NOT re-declare those types; it
  imports the domain models and service from `core-network`/`core-model`. The web
  reference is `src/api/endpoints/files.ts` (`listFiles`, `searchFiles`, `searchText`)
  with shared types in `src/api/types.ts` (`FileEntry`, `FileListResp`).
- **AND-333 (downstream, blocked by this):** upload via presign reuses
  `FilesRepository.invalidateFolder(folderId)` and the current-folder state defined here.
- **Auth:** cookie-based session (`credentials: include`) with `ui_csrf` cookie echoed
  as `X-CSRF-Token`, plus an `Authorization: Bearer <accessToken>` header from the auth
  store (both attached by the web `src/api/client.ts`); persistent cookie jar and
  401→`POST /ui/session/refresh`→retry-once interceptor live in `core-network` and
  apply transparently to all `FilesApi` calls. (Verified against `src/api/client.ts`.)
  Note: the OpenAPI declares `/v1/fs/list` security as `ApiKeyAuth` with scope
  `filemanager:read` and an `X-API-Key` header alternative; the **web/native client
  path uses the session cookie + Bearer**, not an API key.
- **OpenAPI:** `/openapi.json` is the contract of record; the shapes in §5 reflect the
  current dev backend (`GET /v1/fs/list`, `/v1/fs/search`, `/v1/fs/search-text`) and
  `files.ts`.

## 3. Functional Requirements

FR-1 **Folder listing.** On entering the Files tab the screen loads the root folder
(`path = "/"`, the server default) and renders a paged list of child nodes
(folders first by default, then files), each row showing name, type icon, size
(files), and relative modified time (`updated_at`). Navigation is by **path string**,
not folder id (the backend has no node ids).

FR-2 **Descend / ascend.** Tapping a folder row appends its segment to the current
**path** (e.g. `/A` → `/A/B`) and loads its children. A breadcrumb bar is derived by
splitting the current path string on `/` (`Root / A / B`); tapping any crumb truncates
the path to that level. System Back and the top-bar up-affordance pop one segment; at
root (`/`), Back yields to the host nav graph. No node-id navigation stack is required —
the path string is the single source of truth.

FR-3 **Search.** A search field in the top bar filters the current view. Queries ≥2
chars are debounced (300 ms) and sent to a server search endpoint. **Correction:** the
backend search endpoints are flat and global — `GET /v1/fs/search?prefix=&limit=`
(filename-prefix match) and `GET /v1/fs/search-text?q=&limit=` (content/text match).
Neither accepts a `folder_id`/`path`, a `recursive` flag, sort params, or a cursor;
results are a non-paginated `results: FileEntry[]` list (max 200). The "search
everywhere" toggle therefore selects **which search endpoint** to call
(prefix vs text) rather than a folder-scope flag; folder-scoped search is **not
supported by the backend** and, if desired, must be approximated client-side by
filtering results whose `path` is under the current folder (documented as a fallback,
not a server feature). Empty/short (<2 char) query restores the plain folder listing.

FR-4 **Sort.** A sort control offers three keys — `NAME`, `UPDATED`, `SIZE` (mapping to
the backend `sort_by` values `name|updated|size`) — each toggleable ascending/descending
(`sort_dir=asc|desc`). **Correction:** the backend sort key for modified time is
`updated`, not `modified`, and the param names are `sort_by`/`sort_dir`, not
`sort`/`order`. Sort is applied server-side on the **browse** (`/v1/fs/list`) path and
persisted across sessions in DataStore. Search endpoints do **not** accept sort params,
so search results are sorted client-side. Folders-before-files grouping is preserved
under `NAME`; under `UPDATED`/`SIZE` the grouping toggle is user-selectable.

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
**path** is ViewModel state, not a nav arg, so deep navigation does not create a
back-stack entry per folder (Back is handled in-screen). File identity is the `path`
string (the backend exposes no node ids), so `onOpenFile` carries the file `path`.

```kotlin
@Serializable data object FilesRoute
fun NavGraphBuilder.filesScreen(onOpenFile: (path: String) -> Unit) {
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

    fun onOpenFolder(node: FileNode)             // appends node.path segment
    fun onCrumbClick(index: Int)                 // truncates path to crumb level
    fun onBack(): Boolean                        // false => let host handle
    fun onQueryChange(text: String)              // debounced upstream
    fun onSearchModeToggle(text: Boolean)        // false=prefix(/v1/fs/search), true=text(/v1/fs/search-text)
    fun onSortChange(key: SortKey, dir: SortDir)
    fun onRefresh()
    fun onRetry()
}
```

**State model.**

```kotlin
data class FilesUiState(
    val path: String = "/",                               // current folder path
    val breadcrumb: List<Crumb> = listOf(Crumb.Root),     // derived from path split
    val query: String = "",
    val textSearch: Boolean = false,                      // false=prefix, true=full-text
    val sort: SortSpec = SortSpec(SortKey.NAME, SortDir.ASC, foldersFirst = true),
    val isOffline: Boolean = false,                       // shows stale banner
    val refreshing: Boolean = false,
)
enum class SortKey { NAME, UPDATED, SIZE }                // maps to sort_by: name|updated|size
enum class SortDir { ASC, DESC }                          // maps to sort_dir: asc|desc
data class SortSpec(val key: SortKey, val dir: SortDir, val foldersFirst: Boolean)
```

**Repository + Paging.** `FilesRepository` builds a `Pager(PagingConfig(pageSize=50,
prefetchDistance=10, initialLoadSize=50))`. Browse uses `FilesPagingSource` (cursor or
offset per §5); search uses `FilesSearchPagingSource`. A Room-backed
`RemoteMediator` is used for the *browse* path only (stale-while-revalidate, cache
key = path+sort); search is network-only (not cached) because result sets are
ephemeral and query-dependent. **Correction:** because the search endpoints are
non-paginated (no cursor, single `results[]` array capped at 200), the "search paging
source" emits a single page (`nextKey = null`); it is not truly paged.

```kotlin
interface FilesRepository {
    fun browse(path: String, sort: SortSpec): Flow<PagingData<FileNode>>
    fun search(query: String, textSearch: Boolean, sort: SortSpec):
        Flow<PagingData<FileNode>>                        // flat results, client-sorted
    suspend fun invalidateFolder(path: String)            // used by refresh + AND-333
}
```

**Sort semantics.** Server is the source of truth for ordering on the browse path:
`/v1/fs/list` accepts `sort_by` ∈ `{name, updated, size}` and `sort_dir` ∈ `{asc, desc}`
(verified against OpenAPI param patterns), so no capability probe is required for
browse — all three keys are supported. **Correction:** the original "probe
`/openapi.json` at startup" mechanism is unnecessary and is removed; the contract is
fixed and known. Search endpoints accept no sort params, so search results are sorted
client-side using the same `SortSpec` (stable sort, folders-first when configured).

**Compose.** `FilesScreen` collects `uiState` and `items.collectAsLazyPagingItems()`.
`LazyColumn` renders `FileRow`s keyed by `node.id`; `loadState.refresh/append` drive
shimmer/empty/error composables from `core-ui`. `FilesTopBar` hosts the search field
(expandable), scope toggle, and sort affordance opening `SortSheet` (Material 3
`ModalBottomSheet`). Pull-to-refresh via `PullToRefreshBox`.

## 5. API Contract

> **This section was rewritten in review (2026-06-06).** The originally drafted
> `/ui/files` / `/ui/files/search` folder-id endpoints **do not exist**. The
> authoritative contract is the `/v1/fs/*` filemanager API (OpenAPI + `files.ts`),
> reproduced below. All shapes verified against OpenAPI `GET /v1/fs/list`,
> `GET /v1/fs/search`, `GET /v1/fs/search-text` and `src/api/types.ts: FileEntry`,
> `FileListResp`.

All endpoints are GET (idempotent ⇒ eligible for bounded retry). Paths/shapes are
owned by AND-331; reproduced here for the consumed surface.

**Browse a folder.** (OpenAPI `GET /v1/fs/list`, op `list_files_v1_fs_list_get`;
`src/api/endpoints/files.ts: listFiles`.)
```
GET /v1/fs/list?path={/folder/path}&sort_by={name|updated|size}
    &sort_dir={asc|desc}&limit={1..200}&cursor={opaque|omit}
```
- `path` defaults to `/` (root) when omitted.
- `limit` default 50, **max 200** (server-clamped).
- `sort_by` default `name`, regex `^(name|updated|size)$`.
- `sort_dir` default `asc`, regex `^(asc|desc)$`.

Response `FileListResp` (`src/api/types.ts`):
```json
{
  "path": "/Reports",
  "items": [
    { "name": "Q1", "path": "/Reports/Q1", "type": "folder",
      "updated_at": "2026-05-30T14:02:11Z", "created_at": "2026-05-01T00:00:00Z" },
    { "name": "q1.pdf", "path": "/Reports/q1.pdf", "type": "file",
      "size": 184320, "content_type": "application/pdf",
      "updated_at": "2026-05-29T09:11:00Z", "is_encrypted": false,
      "preview_supported": true }
  ],
  "cursor": "eyJrIjoi..."
}
```
`FileEntry` fields actually returned: `name`, `path`, `type` (`"file"|"folder"`),
`size?`, `content_type?`, `updated_at?`, `created_at?`, `is_encrypted?`, plus
encryption/preview metadata (`enc_*`, `preview_*`, `poster_url`, etc.). **There is no
`id`, `parent_id`, `mime`, `modified_at`, or `child_count` field** — the original spec
invented these. Folder identity = `path`; modified time = `updated_at`; MIME =
`content_type`. No `total` count is returned.

**Search.** Two flat, non-paginated, **global** endpoints (no folder scope, no
recursive flag, no sort, no cursor):
- Filename-prefix: `GET /v1/fs/search?prefix={text}&limit={1..200}` (default 50) →
  `{ "prefix": str, "results": FileEntry[] }`
  (OpenAPI `search_filenames_v1_fs_search_get`; `files.ts: searchFiles`).
- Full-text: `GET /v1/fs/search-text?q={text}&limit={1..200}` (default 200) →
  `{ "query": str, "results": FileEntry[] }`
  (OpenAPI `search_text_files_v1_fs_search_text_get`; `files.ts: searchText`).

The `textSearch` toggle picks which endpoint to call. Folder-scoped search is **not a
server feature**; if needed it is approximated client-side by filtering `results` whose
`path` starts with the current folder path. Search responses are wrapped under
`results` (not `items`) and carry no cursor — treat as a single page.

**Breadcrumb resolution.** Crumbs are derived purely by **splitting the current folder
`path` string on `/`** (e.g. `/A/B` → `[Root, A, B]`); no API call is needed and there
is no ancestor-resolution endpoint. (The original `GET /ui/files/{id}` ancestor call
does not exist; node lookup, if ever needed, is `GET /v1/fs/info?path=` →
`getFileInfo`.)

**Error body (FastAPI `detail`).** Mapped by `core-network` per project convention.
`/v1/fs/list` documents structured `detail.code` shapes (verified in OpenAPI):
- 400 `api_key_dual_credential_conflict`, 401 `api_key_invalid`,
  403 `api_entitlement_denied` / `api_key_scope_denied` (`required_scopes:["filemanager:read"]`),
  429 `api_limit_exceeded`, 422 `HTTPValidationError`
  (`detail: [{ loc, msg, type }]`).
`detail` may be `string | [{ "msg": str, "type": str, "loc": [...] }] | { "code": str, ... }`
→ `ApiError`. This screen surfaces `ApiError.message` and a `retryable` flag (429/5xx
and IOErrors retryable; 4xx other than 429 not retryable).

`cursor == null/absent` ⇒ end of list (`PagingSource.LoadResult.Page(nextKey = null)`).

## 6. Data & State Management

**Domain model** (from AND-331 / `core-model`; mapped from `FileEntry`). Since the
backend has no node id, the domain identity is `path`:
```kotlin
data class FileNode(
    val path: String,          // identity (e.g. "/Reports/q1.pdf")
    val name: String,          // FileEntry.name
    val kind: FileKind,        // from FileEntry.type
    val size: Long?,           // FileEntry.size (null for folders)
    val contentType: String?,  // FileEntry.content_type
    val updatedAt: Instant?,   // FileEntry.updated_at
    val createdAt: Instant?,   // FileEntry.created_at
    val isEncrypted: Boolean = false,
)
enum class FileKind { FOLDER, FILE }
```
> Note: there is **no `child_count`** in the API, so folder rows cannot show an item
> count without an extra listing call — the count subtitle is dropped (see §13 OQ,
> now resolved).

**Room cache** (`core-data`, browse path only):
```kotlin
@Entity(tableName = "file_node")
data class FileNodeEntity(
    @PrimaryKey val rowKey: String,   // "<cacheFolderKey>|<path>" (path is unique per folder)
    val path: String, val name: String,
    val kind: String, val size: Long?, val contentType: String?,
    val updatedAtEpoch: Long?, val createdAtEpoch: Long?, val isEncrypted: Boolean,
    val cacheFolderKey: String,   // "<folderPath>|<sortBy>|<sortDir>"
    val pageIndex: Int, val fetchedAtEpoch: Long,
)
@Dao interface FileNodeDao {
    @Query("SELECT * FROM file_node WHERE cacheFolderKey=:key ORDER BY pageIndex")
    fun pagingSource(key: String): PagingSource<Int, FileNodeEntity>
    @Query("DELETE FROM file_node WHERE cacheFolderKey LIKE :folderPrefix || '%'")
    suspend fun clearFolder(folderPrefix: String)
}
@Entity data class FileRemoteKey(@PrimaryKey val cacheFolderKey: String, val cursor: String?)
```
Freshness window: 60 s. `RemoteMediator.load(REFRESH)` skips network if
`now - fetchedAt < 60s` unless forced by pull-to-refresh.

**Preferences (DataStore):** persisted `sort.key`, `sort.dir`, `sort.foldersFirst`,
`search.textDefault`. Read once into `uiState` on init; written on user change.

**State exposure:** `uiState: StateFlow<FilesUiState>` (replay-1, started
`WhileSubscribed(5_000)`); `items: Flow<PagingData<FileNode>>` `cachedIn(viewModelScope)`.
Current path is a private `MutableStateFlow<String>` (breadcrumbs derived from it).

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp call timeout 20 s (per project default for the dev host);
  Paging surfaces `LoadState.Error` on timeout.
- **Bounded retry:** browse/search are GETs ⇒ eligible for the `core-network`
  idempotent-GET retry policy (max 3 attempts, exponential backoff 500 ms→2 s, jitter,
  retry on IOException / HTTP 502/503/504, and 429 `api_limit_exceeded` honoring any
  `Retry-After`). No retry on other 4xx (400/401/403/422).
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

- All file metadata travels over the session cookie + `Authorization: Bearer` +
  `X-CSRF-Token` (CSRF `ui_csrf` cookie echoed — verified in `src/api/client.ts`).
  GETs technically need no CSRF header, but the shared client attaches it uniformly;
  no tokens are logged.
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
  `strings.xml`; plurals (e.g. `"%d items"` for search-result counts) use `<plurals>`
  (note: per-folder `child_count` is not available from the API, so no count subtitle on
  folder rows). Sizes formatted
  via `android.text.format.Formatter.formatShortFileSize` (locale-aware); timestamps via
  `DateUtils.getRelativeTimeSpanString`. Layout is RTL-safe (breadcrumb uses
  `Arrangement.Start` + logical chevrons).

## 10. Telemetry & Logging

Events via the existing `core-telemetry` `Analytics` interface (no PII; never log file
names or queries):
- `files_browse_open` { folder_depth }
- `files_folder_open` { depth }
- `files_search` { mode: prefix|text, query_len, has_results } (length only)
- `files_sort_change` { key, dir }
- `files_refresh` { trigger: pull|retry }
- `files_load_error` { phase: refresh|append, http_status?, kind: timeout|io|http }

Logging: structured `Timber` at DEBUG for load-state transitions and cache hits/misses
(folder key only, never names/queries); WARN on retry exhaustion. Release builds strip
DEBUG via the project Timber tree config.

## 11. Testing Strategy

Use `core-testing` (MockWebServer, Turbine, `MainDispatcherRule`, fake DataStore).

**Unit / repository:**
- `FilesPagingSource` returns `Page(nextKey)` from `FileListResp.cursor`; `null`/absent ⇒
  `nextKey = null` (end). Offset/cursor math covered.
- `RemoteMediator`: fresh cache (<60 s) skips network; stale triggers fetch; network
  failure with cached rows ⇒ `Success` + offline flag; with no cache ⇒ `Error`.
- Sort param mapping: `(SortKey, SortDir)` → `sort_by`(name|updated|size)/`sort_dir`
  (asc|desc) query strings; client-side search sort ordering is stable and
  folders-first when configured.
- Error mapping: FastAPI `detail` variants → `ApiError.retryable` correctly.

**ViewModel (Turbine):**
- Query debounce (300 ms), <2-char no-op, search-mode toggle switches endpoint
  (prefix↔text), sort change persists to DataStore and re-keys the pager.
- Path navigation: open/crumb-click/back transitions over the path string;
  `onBack()` returns false at root (`/`).

**UI (Compose test):**
- States render: loading shimmer, populated, empty folder, empty search, error+retry,
  offline banner.
- Tap folder descends and updates breadcrumb; tap crumb ascends; pull-to-refresh
  invokes `onRefresh`.
- Semantics assertions for `FileRow` contentDescription and sort `stateDescription`.

**Instrumented (optional, dev backend):** smoke test against `/v1/fs/list` guarded by a
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

- **R1 Backend sort/search support — RESOLVED.** Verified against OpenAPI: `/v1/fs/list`
  honors `sort_by` ∈ {name,updated,size} and `sort_dir` ∈ {asc,desc}, so browse sort is
  server-side for all three keys. Search (`/v1/fs/search`, `/v1/fs/search-text`) supports
  **no** sort and **no** folder scope/recursive flag → search results are sorted and
  (optionally) folder-filtered client-side. No backend ticket needed for browse sort;
  folder-scoped search is a genuine backend gap, tracked as an Open assumption in §16.
- **R2 Pagination model — RESOLVED for browse.** Verified: `/v1/fs/list` is **cursor**-
  based (opaque `cursor` query param ↔ `FileListResp.cursor` in the body), so
  `FilesPagingSource` uses `String` cursor keys, not `Int` offsets. Search endpoints are
  **not paginated** (single `results[]`, max 200, no cursor).
- **R3 Search cost.** Full-text search on the unreliable host may be slow and returns up
  to 200 rows in one shot; mitigate with the 20 s timeout, 300 ms debounce, and a
  "searching…" indicator.
- **R4 Deep-link entry to a non-root folder — RESOLVED (no special call).** Because
  navigation is path-based, a deep link can pass a path directly; breadcrumbs are derived
  by splitting the path string. There is no ancestor-resolution endpoint (the
  `GET /ui/files/{id}` call in the old draft does not exist); a single node's metadata,
  if ever needed, is `GET /v1/fs/info?path=`. Entry remains root-only for this ticket.
- **OQ — RESOLVED.** The backend does **not** return `child_count` (no such field on
  `FileEntry`); the folder item-count subtitle is dropped (no per-folder fan-out calls).

## 14. Acceptance Criteria

AC-1 Entering the Files tab loads and displays the root folder's children (folders
then files) within the loading→populated transition; empty folders show the empty
state. (Backlog: "Browse … work.")

AC-2 Tapping a folder descends and updates the breadcrumb; tapping a crumb and System
Back ascend correctly; at root, Back yields to the host. (FR-2)

AC-3 Typing a ≥2-char query (debounced) shows server search results (global, via
`/v1/fs/search` for prefix mode); toggling the search mode switches to full-text
results (`/v1/fs/search-text`); clearing the query restores the browse listing; no
matches shows the empty-search state. (Backlog: "search work"; FR-3)

AC-4 Sort by name/updated/size ascending and descending reorders the browse listing
(server-side `sort_by`/`sort_dir`) and the choice persists across app restarts. (FR-4)

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

## 16. Citations & Assumption Audit

Each key technical claim with verdict and exact source pointer. Sources: **OAI** =
`reference/openapi.index.txt` / `reference/openapi.pretty.json`; **FE** =
`reference/src/...`.

1. **Browse endpoint is `GET /v1/fs/list` (not `/ui/files`).** VERDICT: **Corrected**
   (original spec said `/ui/files`). SOURCE: OAI `GET /v1/fs/list`
   (`op=list_files_v1_fs_list_get`); FE `src/api/endpoints/files.ts: listFiles`.
2. **Browse is path-based (`path` query, default `/`), not folder-id-based.** VERDICT:
   **Corrected**. SOURCE: OAI `GET /v1/fs/list` param `path` (default `"/"`);
   FE `files.ts: listFiles(path = "/")`.
3. **Browse sort params are `sort_by` ∈ {name,updated,size} and `sort_dir` ∈ {asc,desc}**
   (not `sort`/`order` with key `modified`). VERDICT: **Corrected**. SOURCE: OAI
   `GET /v1/fs/list` param schemas `sort_by` (`pattern ^(name|updated|size)$`, default
   `name`), `sort_dir` (`pattern ^(asc|desc)$`, default `asc`).
4. **`limit` default 50, max 200.** VERDICT: **Verified**. SOURCE: OAI `GET /v1/fs/list`
   param `limit` (`default 50, minimum 1, maximum 200`).
5. **Browse pagination is opaque cursor (`cursor` param ↔ `FileListResp.cursor`).**
   VERDICT: **Verified/Corrected** (was `next_cursor`; real field is `cursor`). SOURCE:
   OAI `GET /v1/fs/list` param `cursor`; FE `src/api/types.ts: FileListResp` (`cursor?`).
6. **List response shape is `FileListResp { path, items, cursor }` (no `total`,
   no `next_cursor`).** VERDICT: **Corrected**. SOURCE: FE `src/api/types.ts:
   FileListResp`.
7. **File DTO is `FileEntry` with `name, path, type, size?, content_type?, updated_at?,
   created_at?, is_encrypted?, preview_*` — no `id`/`parent_id`/`mime`/`modified_at`/
   `child_count`.** VERDICT: **Corrected** (original invented `id`, `parent_id`, `mime`,
   `modified_at`, `child_count`). SOURCE: FE `src/api/types.ts: FileEntry`.
8. **`type` values are `"file" | "folder"`.** VERDICT: **Verified**. SOURCE: FE
   `src/api/types.ts: FileEntry.type`.
9. **Search endpoints are `GET /v1/fs/search?prefix=&limit=` (filename prefix) and
   `GET /v1/fs/search-text?q=&limit=` (full text) — both global, non-paginated, no
   folder scope / no `recursive` / no sort.** VERDICT: **Corrected** (original had
   `/ui/files/search?q=&folder_id=&recursive=&sort=&order=&cursor=`). SOURCE: OAI
   `GET /v1/fs/search` (param `prefix` required, `limit`), `GET /v1/fs/search-text`
   (param `q` required, `limit` default 200); FE `files.ts: searchFiles`, `searchText`.
10. **Search response shapes are `{ prefix, results: FileEntry[] }` and
    `{ query, results: FileEntry[] }` (key `results`, not `items`; no cursor).**
    VERDICT: **Corrected**. SOURCE: FE `files.ts: searchFiles` / `searchText` return
    types.
11. **Breadcrumbs derive from splitting the `path` string; no ancestor-resolution
    endpoint exists (the old `GET /ui/files/{id}` does not exist).** VERDICT:
    **Corrected**. SOURCE: absence in OAI index (no `/ui/files/{id}`); single-node
    metadata is FE `files.ts: getFileInfo` → `GET /v1/fs/info?path=`.
12. **Auth = session cookie (`credentials: include`) + `Authorization: Bearer
    <accessToken>` + `X-CSRF-Token` from `ui_csrf` cookie; 401 → `POST
    /ui/session/refresh` → retry once.** VERDICT: **Verified** (Bearer header was
    omitted in the original; added). SOURCE: FE `src/api/client.ts` (lines ~157–171
    headers; ~121–130 `refreshSession`; ~194–237 401 handling).
13. **Documented error `detail` shapes for `/v1/fs/list`: 400
    `api_key_dual_credential_conflict`, 401 `api_key_invalid`, 403
    `api_entitlement_denied` / `api_key_scope_denied` (`required_scopes`:
    `["filemanager:read"]`), 429 `api_limit_exceeded`, 422 `HTTPValidationError`.**
    VERDICT: **Verified**. SOURCE: OAI `GET /v1/fs/list` `responses` examples
    (`openapi.pretty.json` ~lines 273173–273267).
14. **OpenAPI declares `/v1/fs/list` security as `ApiKeyAuth` (scope `filemanager:read`,
    `X-API-Key` header), but the web/native client path uses session+Bearer, not an
    API key.** VERDICT: **Verified** (noted as a divergence). SOURCE: OAI
    `GET /v1/fs/list` `security: [{ApiKeyAuth: []}]`, `x-api-key-scopes`; vs FE
    `src/api/client.ts` (no API-key header).
15. **FastAPI `detail` normalization handles `string | [{msg,type,loc}] | {code,...}`.**
    VERDICT: **Verified**. SOURCE: FE `src/api/client.ts: normalizeErrorDetail`,
    `mapAuthorizationError`.
16. **No `child_count` on folders; folder item-count subtitle is dropped.** VERDICT:
    **Verified** (resolves §13 OQ). SOURCE: FE `src/api/types.ts: FileEntry` (field
    absent).
17. **Framework choices (Paging 3 with cursor `PagingSource`, Room `RemoteMediator`,
    Compose `PullToRefreshBox`, Hilt/KSP).** VERDICT: **Unverified-assumption**
    (architectural choice, not derivable from backend/FE). SOURCE: framework ref —
    Android Paging 3 (`https://developer.android.com/topic/libraries/architecture/paging/v3-overview`),
    Compose Material3 pull-to-refresh
    (`https://developer.android.com/develop/ui/compose/components/pull-to-refresh`).
18. **DTO/service ownership by AND-331 (this ticket adds zero DTOs).** VERDICT:
    **Unverified-assumption** (cross-ticket sequencing; AND-331 spec not inspected
    here). SOURCE: ticket dependency `depends_on: [AND-331]`.

### Corrections made

- §1/§2/§5/§6: Browse endpoint `/ui/files` → **`GET /v1/fs/list`**; search
  `/ui/files/search` → **`GET /v1/fs/search`** (prefix) and **`/v1/fs/search-text`** (q).
- Navigation/identity: **folder-id model → path-string model** throughout (state,
  ViewModel callbacks, Room key, breadcrumb derivation, `onOpenFile` carries `path`).
- DTO: `FileNodeDto`/`FileListResponseDto` → **`FileEntry`/`FileListResp`**; removed
  invented fields (`id`, `parent_id`, `mime`, `modified_at`, `child_count`, `total`,
  `next_cursor`); mapped `content_type`/`updated_at`/`created_at`; list cursor field is
  `cursor`; search results under `results` not `items`.
- Sort: keys `NAME/SIZE/MODIFIED` → **`NAME/UPDATED/SIZE`**; params `sort/order` →
  **`sort_by/sort_dir`**; removed the unnecessary "`/openapi.json` capability probe".
- Search semantics: removed non-existent `folder_id`/`recursive`/sort/cursor; "search
  everywhere" toggle re-scoped to **prefix-vs-text endpoint selection**; search is flat
  (single page, ≤200) and client-sorted; folder-scoping is a client-side approximation.
- Auth: added the **`Authorization: Bearer`** header (cookie + Bearer + CSRF).
- Retry: added **429 `api_limit_exceeded`** (honoring `Retry-After`) to the retryable
  set.
- §13 R1/R2/R4/OQ marked **RESOLVED** with verified facts; AC-3/AC-4 reworded to match.

### Open assumptions

- **Folder-scoped search is unsupported by the backend.** Both search endpoints are
  global; scoping to the current folder can only be approximated by client-side path
  filtering of the ≤200 results. Why unverifiable: no scope/recursive param exists in
  OAI or FE — this is a genuine backend capability gap, not a doc gap.
- **AND-331 final service/DTO signatures.** This spec assumes AND-331 maps `FileEntry`/
  `FileListResp` exactly as in the web reference and exposes browse/search per §5; the
  AND-331 spec/source was not inspected in this review. Why: out of scope of the
  provided sources.
- **`invalidateFolder(path)` contract for AND-333.** Assumed cache key
  `"<folderPath>|<sortBy>|<sortDir>"` and `LIKE '<folderPrefix>%'` clearing are
  acceptable to the downstream upload/CRUD tickets. Why: those tickets are not yet
  written.
- **Framework/UX choices** (Paging config numbers, 60 s freshness window, 300 ms
  debounce, 20 s timeout, shimmer states) are engineering decisions, not contract facts;
  unverifiable against backend/FE by design.

## 17. Test Plan

IDs `TC-AND-332-NN`. "Traces" link to §14 Acceptance Criteria. Test targets per the
ticket's CI matrix: **JVM/Robolectric** (local), **emulator `test35`** (API 35
x86_64), **physical device** Samsung Galaxy A15 5G (SM-A156U, API 34 arm64,
serial R5CX821TA9R). Most cases here are non-hardware and run on JVM or `test35`; the
ABI/API-difference smoke (TC-13) MUST run on the physical device.

- **TC-AND-332-01** — Type: contract/MockWebServer. Target: JVM (Robolectric not
  needed). Precond: MockWebServer enqueues a `FileListResp` JSON for `/v1/fs/list?path=/`
  with one folder + one file. Steps: call `FilesRepository.browse("/", SortSpec(NAME,
  ASC))` and collect first `PagingData`. Expected: request path is
  `/v1/fs/list?path=/&sort_by=name&sort_dir=asc&limit=50`; mapped `FileNode`s have
  `path`, `name`, `kind`, `size`, `contentType`, `updatedAt`; folder first. Traces: AC-1,
  AC-4.

- **TC-AND-332-02** — Type: unit. Target: JVM. Precond: a `FileListResp` with
  `cursor="eyJ..."` then a second page with `cursor` absent. Steps: drive
  `FilesPagingSource.load` twice. Expected: page 1 `nextKey="eyJ..."`; page 2
  `nextKey=null` (end of pagination). Traces: AC-5.

- **TC-AND-332-03** — Type: unit. Target: JVM. Precond: SortSpec permutations. Steps:
  map each `(SortKey,SortDir)` to query params. Expected: `NAME→name`, `UPDATED→updated`,
  `SIZE→size`; `ASC→asc`, `DESC→desc`; no `modified`/`sort`/`order` strings ever emitted.
  Traces: AC-4.

- **TC-AND-332-04** — Type: contract/MockWebServer. Target: JVM. Precond: enqueue
  `/v1/fs/search?prefix=re&limit=50` → `{ "prefix":"re", "results":[FileEntry,...] }`
  and `/v1/fs/search-text?q=re&limit=200` → `{ "query":"re", "results":[...] }`. Steps:
  `search("re", textSearch=false)` then `search("re", textSearch=true)`. Expected: prefix
  mode hits `/v1/fs/search` and reads `results`; text mode hits `/v1/fs/search-text`;
  both emit a single page (`nextKey=null`); results client-sorted by active SortSpec.
  Traces: AC-3.

- **TC-AND-332-05** — Type: unit (ViewModel, Turbine). Target: JVM. Precond:
  `FilesViewModel` with fake repo + fake DataStore. Steps: `onQueryChange("r")` then
  `onQueryChange("re")` within 300 ms; advance virtual time. Expected: 1-char query is a
  no-op (browse pager stays active); the 2-char query, after 300 ms debounce, switches
  to the search source exactly once. Traces: AC-3.

- **TC-AND-332-06** — Type: unit (ViewModel, Turbine). Target: JVM. Precond: VM at path
  `/`. Steps: `onOpenFolder(node path="/A")`, `onOpenFolder(node path="/A/B")`,
  `onCrumbClick(1)`, then `onBack()` twice. Expected: path transitions `/`→`/A`→`/A/B`,
  crumb-click truncates to `/A`, back → `/`, second `onBack()` returns `false` (host
  handles); breadcrumb list always derived from the path split. Traces: AC-2.

- **TC-AND-332-07** — Type: unit (RemoteMediator). Target: JVM (Robolectric for Room
  in-memory). Precond: Room seeded with rows for `cacheFolderKey="/|name|asc"` at
  `fetchedAt = now-30s`. Steps: `load(REFRESH)` (not forced). Expected: network is **not**
  called (fresh < 60 s); cached rows served. Then set `fetchedAt = now-90s` and
  `load(REFRESH)`: network **is** called. Traces: AC-1, AC-6.

- **TC-AND-332-08** — Type: unit (RemoteMediator). Target: JVM/Robolectric. Precond:
  stale cache present; MockWebServer returns an `IOException`/timeout. Steps:
  `load(REFRESH)`. Expected: `MediatorResult.Success(endOfPaginationReached=false)` with
  cached rows; ViewModel surfaces `isOffline=true` (stale banner). With cache **empty**
  and same failure: `MediatorResult.Error`. Traces: AC-6.

- **TC-AND-332-09** — Type: contract/MockWebServer. Target: JVM. Precond: enqueue 429
  with body `{"detail":{"code":"api_limit_exceeded","reason":"limit_exceeded"}}` then a
  200. Steps: trigger a browse load. Expected: GET is retried (bounded, honoring
  `Retry-After`) and ultimately succeeds; a 422 `HTTPValidationError`
  (`{"detail":[{"loc":[...],"msg":"...","type":"..."}]}`) and 403 `api_key_scope_denied`
  are mapped to non-retryable `ApiError` with a human message and `retryable=false`.
  Traces: AC-6.

- **TC-AND-332-10** — Type: Compose-UI. Target: emulator `test35`. Precond: fake VM
  emitting each state. Steps: render loading→populated→empty-folder→empty-search→
  error+Retry→offline-banner. Expected: each state shows its distinct composable; the
  error card's Retry invokes `onRetry`; offline banner appears only when `isOffline`.
  Traces: AC-1, AC-3, AC-6.

- **TC-AND-332-11** — Type: Compose-UI. Target: emulator `test35`. Precond: populated
  list with a folder row + a file row. Steps: tap folder row; tap a breadcrumb crumb;
  perform pull-to-refresh gesture. Expected: tapping the folder descends and updates the
  breadcrumb; tapping a crumb ascends; pull-to-refresh invokes `onRefresh`. Traces:
  AC-2, AC-1.

- **TC-AND-332-12** — Type: Compose-UI (accessibility). Target: emulator `test35`.
  Precond: one file row (`q1.pdf`, 180 KB, updated 2 days ago) + sort affordance.
  Steps: assert semantics. Expected: `FileRow` merged `contentDescription` =
  "q1.pdf, file, 180 KB, modified 2 days ago"; type icon `contentDescription=null`
  (decorative); touch targets ≥48 dp; sort `IconButton` exposes `stateDescription` for
  current key/dir; search field has `Role`-appropriate semantics + IME Search action.
  Traces: AC-2, AC-4, AC-8 (UI-side; no PII in a11y text).

- **TC-AND-332-13** — Type: instrumented/e2e (ABI/API smoke). Target: **PHYSICAL DEVICE
  (SM-A156U, arm64-v8a, API 34)** — MUST run here, not the x86_64/API-35 emulator, to
  catch arm64-vs-x86 and API-34-vs-35 differences. Precond: app installed via adb on the
  device; build flag enabling the dev-backend smoke; network reachable. Steps: launch
  Files tab, browse root, descend one folder, run a search, change sort. Expected: app
  loads real `/v1/fs/list` data without ABI crash; cursor paging, search, and sort behave
  as on emulator; no arm64-specific failures (e.g. Moshi/KSP codegen, time formatting).
  Traces: AC-1, AC-3, AC-4, AC-5.

- **TC-AND-332-14** — Type: integration (security/transport). Target: JVM/Robolectric
  (transport assertions) + manual check of release config. Precond: OkHttp client from
  `core-network` with the dev host; release `network-security-config`. Steps: inspect
  outgoing browse request headers; attempt cleartext under a simulated release config.
  Expected: every request carries the session cookie, `Authorization: Bearer`, and
  `X-CSRF-Token` (from `ui_csrf`); no file names or query strings appear in Timber logs
  or telemetry payloads; release build rejects cleartext to non-dev hosts
  (`cleartextTrafficPermitted=false`). Traces: AC-8.

- **TC-AND-332-15** — Type: manual (offline / flaky-dev-host). Target: **PHYSICAL
  DEVICE** (real radio toggle gives a truer offline signal than the emulator). Precond:
  folder previously browsed (cache warm). Steps: enable airplane mode; reopen the Files
  tab / pull-to-refresh; then disable airplane mode and refresh. Expected: cached rows
  render with the offline banner; on reconnection a refresh revalidates and clears the
  banner; an uncached folder while offline shows the retryable error card. Traces: AC-6.

### Coverage matrix

| AC (§14) | Covered by |
|----------|-----------|
| AC-1 Browse root, folders-then-files, empty state | TC-01, TC-07, TC-10, TC-11, TC-13 |
| AC-2 Descend/ascend (folder, crumb, back-at-root) | TC-06, TC-11, TC-12 |
| AC-3 Search (prefix/text), clear restores, no-match | TC-04, TC-05, TC-10, TC-13 |
| AC-4 Sort name/updated/size asc/desc + persistence | TC-01, TC-03, TC-12, TC-13 |
| AC-5 Pagination append + retry footer | TC-02, TC-13 |
| AC-6 Offline-stale w/ cache vs retryable error | TC-07, TC-08, TC-09, TC-10, TC-15 |
| AC-7 Named §11 tests green in CI | TC-01…TC-12 (the CI-runnable suite) |
| AC-8 No PII in logs/telemetry; authed metadata only | TC-12, TC-14 |
