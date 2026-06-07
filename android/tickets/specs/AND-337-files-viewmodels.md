---
id: AND-337
title: Files ViewModels
milestone: M7
epic: E43
priority: P1
size: M
depends_on: [AND-331]
blocks: [AND-332, AND-333, AND-334, AND-338]
status: reviewed
reviewed_on: 2026-06-06
---

# AND-337 — Files ViewModels

## 1. Overview & Goal

This ticket delivers the presentation-layer state machinery for the Files feature: the
`ViewModel`s, `UiState` shapes, intent/action surface, and Paging 3 wiring that the Files
UI tickets (browse AND-332, upload AND-333, download/open AND-334, share AND-335, Drive
import AND-336) consume. It is a pure state + paging ticket — no Composable screens are
produced here. The goal is a fully unit-tested, deterministic set of ViewModels that:

- Expose folder/file listings as `Flow<PagingData<FileEntry>>` filtered by the current
  folder, search query, and sort order.
- Hold non-paged screen chrome (current folder breadcrumb, search/sort controls, selection
  set, transient errors, refresh state) in a `StateFlow<FilesUiState>`.
- Translate user intents into `core-data` repository calls and map `ApiResult<T>` outcomes
  into UI state transitions, including the dev-host offline/stale and 401-refresh behaviors
  defined project-wide.

Out of scope: networking/DTOs (owned by AND-331), Composables and navigation (AND-332+),
upload transfer engine and download/open intents beyond their ViewModel entry points
(AND-333/AND-334 supply the repository methods; this ticket exposes the state hooks).

## 2. Context & References

- Module: `feature-files` (depends on `core-data`, `core-model`, `core-ui`, `core-network`,
  `core-testing`). Package root `com.testlogon.android.feature.files`.
- Upstream dependency **AND-331** (Files API + DTOs) provides `FilesApi` (Retrofit),
  the wire DTOs, and the `FileEntry`/`FolderRef` domain models in `core-model`, plus the
  `FilesRepository` interface in `core-data`. This ticket assumes those types exist and
  consumes them; if a repository method named here is not yet present, it is added in the
  AND-331/AND-333/AND-334 surface, not invented here.
- Web reference: `src/api/endpoints/files.ts` (browse/CRUD/search) and shared
  types in `src/api/types.ts`. The Android paging/sort/search semantics mirror
  the web list semantics. **CORRECTION:** the real backend filesystem API is **path-based**
  under `/v1/fs/*`, not the `/ui/files` folder-id/cursor model previously assumed here. Nodes
  are identified by their `path` string; there is **no `id` field**. See §5 for the corrected
  contract and the §16 audit.
- Architecture: ViewModels expose `StateFlow<UiState>`; repositories return typed
  `ApiResult<T>`; FastAPI `detail` is mapped to `AppError` upstream. Cookie-based session
  with single `POST /ui/session/refresh` on 401 is handled in the OkHttp authenticator
  (core-network), transparent to this layer. (Verified against `src/api/client.ts`: refresh
  once via `POST /ui/session/refresh`, then retry; second 401 logs out. Note the web client
  also sends `Authorization: Bearer <accessToken>` alongside cookies — see §8/§16.)
- Backend is plaintext HTTP on an unreliable dev host (`http://18.222.237.167:8000`):
  ~20s timeouts, bounded backoff retry for idempotent GETs only, offline/stale UI states.

## 3. Functional Requirements

FR-1. **Browse state.** A `FilesViewModel` exposes the current folder (root if none),
breadcrumb trail, and a paged stream of that folder's children. Navigating into a folder
or up the breadcrumb re-targets the paged stream.

FR-2. **Search.** A debounced (300ms) free-text query filters the listing server-side via
the search endpoint. An empty query reverts to plain folder browse. **CORRECTION:** the
backend search is **global (not folder-scoped) and not paged**. Two modes exist:
name/prefix search via `GET /v1/fs/search?prefix={q}&limit={n}` and full-text content search
via `GET /v1/fs/search-text?q={q}&limit={n}`; both return `{ results: FileEntry[] }` with no
cursor. The previously-assumed `searchAllFolders` per-folder flag has **no backend support**
and is dropped; `searchMode` (NAME | CONTENT) replaces it, mirroring the web reference.

FR-3. **Sort.** The list supports server-side sort, each ascending/descending. **CORRECTION:**
the backend `GET /v1/fs/list` `sort_by` accepts only `name | updated | size` (regex
`^(name|updated|size)$`) and `sort_dir` only `asc | desc`. There is **no `KIND` sort** and
"modified" maps to the wire value `updated`. The `FileSortField` enum is therefore
`NAME, UPDATED, SIZE` (KIND removed). Changing sort invalidates and re-pages without losing
the current folder/query.

FR-4. **Refresh.** A pull-to-refresh / manual refresh intent invalidates the `PagingSource`
and re-fetches page 1, surfacing a `isRefreshing` flag distinct from initial load.

FR-5. **Selection.** Multi-select mode tracks a `Set<String>` of selected **file paths**
(not ids — the system has no ids; the web app keys `selectedKeys` by `FileEntry.path`) for
batch actions (delete, move, share). Selection survives sort/search changes for still-visible
items and is cleared on folder navigation. **NOTE:** batch delete/move have **no batch
endpoint**; the web reference iterates client-side calling the single-item endpoints per
selected path (see §5/§7).

FR-6. **CRUD intents.** Create folder, rename, delete (single + batch), and move emit
through the ViewModel, call the repository, and on success invalidate the relevant paging
source. Failures surface as transient `UiMessage` events without dropping the list.

FR-7. **Per-item transfer hooks.** The ViewModel exposes entry points
`startUpload(...)`, `startDownload(...)`, `openFile(...)` that delegate to the repository
APIs introduced by AND-333/AND-334. This ticket wires the state/intent plumbing and
progress reflection; the transfer engines themselves live in those tickets.

FR-8. **Offline/stale.** When the network is unavailable or the dev host times out, the
ViewModel surfaces the last successfully loaded page as stale (`isStale = true`) rather
than clearing the list, and shows a retry affordance.

FR-9. **Determinism for tests.** All async work runs on an injected `CoroutineDispatcher`;
debounce/timeout use an injectable time source so tests can use `runTest` virtual time.

## 4. Technical Design

Two ViewModels keep responsibilities small. `FilesViewModel` owns browse/search/sort/
selection/CRUD. A separate `FileShareViewModel` (consumed by AND-335) is stubbed only to
the extent of its `UiState`/intents that depend on the shared repository; its full logic
is owned by AND-335 and is N/A here beyond a referenced placeholder.

```kotlin
package com.testlogon.android.feature.files.vm

@HiltViewModel
class FilesViewModel @Inject constructor(
    private val repo: FilesRepository,
    private val savedState: SavedStateHandle,
    @IoDispatcher private val io: CoroutineDispatcher,
    private val clock: TimeSource = TimeSource.Monotonic,
) : ViewModel() {

    private val _uiState = MutableStateFlow(FilesUiState())
    val uiState: StateFlow<FilesUiState> = _uiState.asStateFlow()

    private val _events = Channel<FilesEvent>(Channel.BUFFERED)
    val events: Flow<FilesEvent> = _events.receiveAsFlow()

    // Drives Pager invalidation: any change to folder/query/sort emits a new key.
    private val listKey: StateFlow<ListKey> = /* combine of folder+query+sort */

    val pagedFiles: Flow<PagingData<FileListItem>> =
        listKey.flatMapLatest { key -> pagerFor(key).flow }
            .cachedIn(viewModelScope)

    fun onIntent(intent: FilesIntent)   // single entry point, see §6
}
```

`ListKey` is `data class ListKey(folderPath: String, query: String, searchMode: SearchMode,
sort: FileSort)` (**CORRECTION:** `folderPath: String` keyed by path with `"/"` as root, not a
nullable `folderId`). `pagerFor` builds a `Pager(PagingConfig(pageSize = 50,
prefetchDistance = 10, initialLoadSize = 50, enablePlaceholders = false)) {
FilesPagingSource(repo, key, io) }` (page size 50 matches the backend `limit` default; max 200).

`FilesPagingSource : PagingSource<String, FileListItem>` uses an opaque cursor `String?`
(the `cursor` field — **not** `nextCursor` — returned by `GET /v1/fs/list`). `load()` calls
`repo.listFolder(...)` for browse, or `repo.searchByName(...)`/`repo.searchText(...)` when a
query is present (search responses are **unpaged**: a single `LoadResult.Page` with
`nextKey = null`). It maps `ApiResult`:
`Success` -> `LoadResult.Page(data, prevKey = null, nextKey = cursor)`;
`Failure(NetworkError)` -> if a cached page exists, mark `isStale` via the ViewModel and
return the cached page; else `LoadResult.Error(throwable)`. CSRF/401/refresh and backoff
retry are handled by the OkHttp stack from `core-network`, so the source treats a returned
`ApiResult.Failure` as terminal for that attempt.

Search debounce is implemented on the query input as a `MutableStateFlow<String>` with
`.debounce(300).distinctUntilChanged()` feeding `listKey`. Selection, refresh, stale, and
error chrome live entirely in `FilesUiState` and never inside `PagingData`.

`FileListItem` is a thin UI projection of `FileEntry`. **CORRECTION:** the wire `FileEntry`
(`src/api/types.ts`) has fields `name`, `path`, `type: "file"|"folder"`, `size?`,
`content_type?`, `updated_at?`, `created_at?` (plus encryption/preview metadata) — there is
**no `id`, `kind`, `size_bytes`, `mime_type`, `modified_at`, or `parent_id`**. The projection
is therefore `(path, name, isFolder = type == "folder", sizeBytes = size, contentType,
updatedAt, transferState)` and is keyed by `path` so the paged list and the selection/CRUD
state can co-evolve without re-fetching.

## 5. API Contract

This ticket calls repository methods only; raw HTTP is owned by AND-331. Repository
surface consumed (from `core-data`, namespace `com.testlogon.android.core.data.files`):

**CORRECTION — the repository surface below was re-derived from the real `/v1/fs/*` API and
`src/api/endpoints/files.ts`. It is path-based with single-item mutations.**

```kotlin
interface FilesRepository {
    // GET /v1/fs/list?path={p}&limit={n}&cursor={c}&sort_by={name|updated|size}&sort_dir={asc|desc}
    suspend fun listFolder(
        path: String, cursor: String?, limit: Int, sort: FileSort
    ): ApiResult<FilePage>
    // GET /v1/fs/search?prefix={q}&limit={n}        (name/prefix, unpaged)
    suspend fun searchByName(query: String, limit: Int): ApiResult<List<FileEntry>>
    // GET /v1/fs/search-text?q={q}&limit={n}        (full-text, unpaged)
    suspend fun searchText(query: String, limit: Int): ApiResult<List<FileEntry>>
    // POST /v1/fs/folder  { "path": "<parentPath>/<name>" }
    suspend fun createFolder(path: String): ApiResult<Unit>          // resp { ok: bool }
    // POST /v1/fs/rename-file | /v1/fs/rename-folder  { "path", "new_name" }
    suspend fun renameFile(path: String, newName: String): ApiResult<Unit>   // {ok,src,dst}
    suspend fun renameFolder(path: String, newName: String): ApiResult<Unit>
    // DELETE /v1/fs/file?path={p} | DELETE /v1/fs/folder?path={p}
    suspend fun deleteFile(path: String): ApiResult<Unit>
    suspend fun deleteFolder(path: String): ApiResult<Unit>          // {ok,deleted_count}
    // POST /v1/fs/move  { "src", "dst" }   (single node)
    suspend fun move(src: String, dst: String): ApiResult<Unit>      // {ok,src,dst}
}
// data class FilePage(val items: List<FileEntry>, val cursor: String?)
```

The underlying endpoints (verified against `reference/openapi.index.txt` /
`reference/openapi.pretty.json` and `src/api/endpoints/files.ts`):
`GET /v1/fs/list` params `path,limit,cursor,sort_by,sort_dir` -> `FileListResp { path, items[], cursor? }`,
`GET /v1/fs/search` params `prefix,limit` -> `{ prefix, results: FileEntry[] }`,
`GET /v1/fs/search-text` params `q,limit` -> `{ query, results: FileEntry[] }`,
`POST /v1/fs/folder` body `{ "path": str }` (schema `Body_create_folder_v1_fs_folder_post`),
`POST /v1/fs/rename-file` / `POST /v1/fs/rename-folder` body `{ "path": str, "new_name": str }`,
`POST /v1/fs/move` body `{ "src": str, "dst": str }` (schema `Body_move_fs_node_v1_fs_move_post`),
`DELETE /v1/fs/file?path={p}` and `DELETE /v1/fs/folder?path={p}` (query param, not body).
There is **no `id`, no batch `ids` payload, no `PATCH`/`/ui/files`** anywhere in this API.
Batch delete/move = client-side iteration over selected paths (see §7).

Representative list response shape mapped by AND-331 into `FilePage` (real `FileEntry`):

```json
{
  "path": "/reports",
  "items": [
    { "name": "report.pdf", "path": "/reports/report.pdf", "type": "file",
      "size": 80213, "content_type": "application/pdf",
      "updated_at": "2026-05-30T14:02:11Z", "created_at": "2026-05-01T09:00:00Z" }
  ],
  "cursor": "eyJrIjoi..."
}
```

Error `detail` mapping (`string | [{msg}] | {code,...}`) is already normalized to
`AppError` by the repository (verified: `normalizeErrorDetail` in `src/api/client.ts`
handles all three shapes; FastAPI 422 uses `[{msg}]`, role/geo errors use `{code,...}`).
This ticket consumes `ApiResult.Failure(AppError)`.

## 6. Data & State Management

```kotlin
data class FilesUiState(
    val currentFolderPath: String = "/",      // path-based; "/" is root (no folder ids)
    val breadcrumb: List<FolderCrumb> = emptyList(),
    val query: String = "",
    val searchMode: SearchMode = SearchMode.NAME,  // replaces searchAllFolders (no backend scope flag)
    val sort: FileSort = FileSort(FileSortField.NAME, ascending = true),
    val selectionMode: Boolean = false,
    val selectedPaths: Set<String> = emptySet(),   // keyed by FileEntry.path, not id
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val createFolderDialog: Boolean = false,
    val inFlight: Set<FileOp> = emptySet(),   // delete/move/rename spinners
)

// CORRECTION: backend sort_by supports only name|updated|size (no KIND); UPDATED == wire "updated".
enum class FileSortField(val wire: String) { NAME("name"), UPDATED("updated"), SIZE("size") }
enum class SearchMode { NAME, CONTENT }    // NAME -> /v1/fs/search; CONTENT -> /v1/fs/search-text
// FileSort.ascending maps to sort_dir asc|desc.
data class FileSort(val field: FileSortField, val ascending: Boolean)

sealed interface FilesIntent {
    // CORRECTION: path-based throughout (no ids). Rename/delete/move take FileEntry paths.
    data class OpenFolder(val folderPath: String, val name: String) : FilesIntent
    data class NavigateCrumb(val index: Int) : FilesIntent
    data class QueryChanged(val q: String) : FilesIntent
    data class SearchModeChanged(val mode: SearchMode) : FilesIntent
    data class SortChanged(val sort: FileSort) : FilesIntent
    data object Refresh : FilesIntent
    data class ToggleSelect(val path: String) : FilesIntent
    data object ClearSelection : FilesIntent
    data class CreateFolder(val name: String) : FilesIntent       // VM builds child path
    data class Rename(val path: String, val isFolder: Boolean, val newName: String) : FilesIntent
    data class Delete(val paths: List<FileSelection>) : FilesIntent  // batch = client-side fan-out
    data class Move(val paths: List<String>, val targetFolderPath: String) : FilesIntent
    data class Retry(val key: ListKey) : FilesIntent
}
// FileSelection(val path: String, val isFolder: Boolean) so delete/move can pick file vs folder endpoint.

sealed interface FilesEvent {
    data class Message(val text: UiText) : FilesEvent
    data class NavigateToOpen(val path: String) : FilesEvent  // for AND-334 hook (was misdeclared FilesIntent + id)
}
```

State persistence: `currentFolderPath`, `query`, and `sort` are mirrored into
`SavedStateHandle` (keys `folder_path`, `query`, `sort`) so process death restores the same
listing. (**CORRECTION:** key is `folder_path`, value is a path string, not `folder_id`.)
`cachedIn(viewModelScope)` retains the paged stream across configuration changes.
Selection is intentionally not persisted across process death (cleared on restore). No
Room/DataStore writes occur here — caching of file metadata, if any, is owned by AND-331's
repository; this ViewModel observes the repository's emitted state only.

## 7. Error Handling & Resilience

- **Load errors (paging):** `LoadState.Error` from the `CombinedLoadStates` is reflected by
  the UI tickets; this ViewModel additionally sets `isStale = true` and emits a
  `FilesEvent.Message` when a refresh fails but a previous page is shown.
- **Timeout/offline:** A `NetworkError`/timeout from the dev host on initial load yields
  `LoadResult.Error`; on subsequent refresh with existing data it yields the cached page +
  `isStale`. Retry intent (`Retry`) calls `PagingSource.invalidate()` via a tracked
  `refresh` trigger.
- **401:** Handled transparently by the core-network authenticator (single
  `POST /ui/session/refresh` then retry). If refresh fails, the repository returns
  `AppError.Unauthorized`; the ViewModel emits a `FilesEvent.Message` and a
  `FilesEvent`-driven re-auth signal is left to the app shell (out of scope here).
- **CRUD failures:** never mutate the list optimistically beyond a removable spinner in
  `inFlight`; on `Failure` the op is removed from `inFlight` and a message is emitted; on
  `Success` the relevant `PagingSource` is invalidated to reflect server truth.
- **Batch delete/move (CORRECTION):** there is no batch endpoint. The ViewModel fans out
  one single-item call per selected path (`deleteFile`/`deleteFolder` by `type`, or `move`
  with `src/dst`), as the web app does, and aggregates partial failure into a single
  `FilesEvent.Message` ("N of M failed"). It invalidates the pager once after the batch.
- **Idempotency:** Only GET-backed methods (`listFolder`, `searchByName`, `searchText`) are
  eligible for the bounded backoff retry, which is configured in OkHttp (core-network), not
  retried in the ViewModel. Mutations (POST/DELETE) are issued exactly once per item per intent.

## 8. Security & Privacy

No new credential or token handling is introduced. The session rides cookies + the
`ui_csrf` cookie echoed as `X-CSRF-Token` (verified: `getCookie("ui_csrf")` ->
`X-CSRF-Token` in `src/api/client.ts`), fully managed by core-network's persistent
cookie jar and interceptors. **NOTE:** the web client additionally sends an
`Authorization: Bearer <accessToken>` header from its auth store; whether the Android client
relies on cookies alone or also carries a Bearer token is an AND-331/core-network decision
(see §16 open assumptions). Either way this layer never reads them. ViewModels never read or
log cookies, CSRF tokens, or presigned URLs. File names and ids may be PII-adjacent and must not be logged at INFO or
above (see §10). No file contents are held in `FilesUiState`. Search queries are sent over
the dev host's plaintext HTTP — this is a known dev-environment constraint inherited
project-wide; production TLS enforcement is an app-shell concern, not this ticket's.

## 9. Accessibility & i18n

This is a non-UI ticket, so no Composables or content descriptions are authored here.
However, the ViewModel emits user-facing text only as `UiText` (string-resource references
or resolved-later wrappers), never hardcoded English, so AND-332+ can localize. Sort field
and order, breadcrumb labels, and error messages are all `UiText`/resource ids. Accessibility
semantics (focus order, content descriptions, selection announcements) are owned by the UI
tickets that render this state.

## 10. Telemetry & Logging

- Structured debug logs via the project `Logger` (Timber-backed) at DEBUG only:
  `files_list_load` (folderId hash, query length, sort, page size, latency ms, result),
  `files_op` (op type, count, result, latency ms). File names and raw ids are hashed
  (truncated SHA-256) before logging; raw values never logged.
- Counters/timers (if `core-telemetry` present): `files.list.latency`,
  `files.list.error`, `files.op.{delete,move,rename,create}.{ok,err}`,
  `files.stale.shown`. No analytics PII (file names, query text) leaves the device.
- Paging `LoadState` transitions are logged at VERBOSE for diagnosing the unreliable host.

## 11. Testing Strategy

Acceptance for this ticket is "Unit-tested." All tests live in `feature-files`
`src/test` using `core-testing` (JUnit4, `kotlinx-coroutines-test` `runTest`, Turbine for
flows, MockK, a fake `FilesRepository`). No instrumentation tests here (UI tests belong to
AND-338).

- `FilesPagingSourceTest`: first page maps `FilePage` to `LoadResult.Page` with correct
  `nextKey`; empty folder -> empty page with null `nextKey`; `Failure(NetworkError)` with
  no cache -> `LoadResult.Error`; cursor threading across two `load()` calls.
- `FilesViewModelStateTest` (Turbine): `OpenFolder` updates folder + breadcrumb and emits a
  new `ListKey`; `QueryChanged` debounces (assert single downstream emit after 300ms virtual
  time for rapid keystrokes); empty query reverts to browse; `SortChanged` preserves
  folder/query; `Refresh` toggles `isRefreshing` then back.
- `FilesViewModelSelectionTest`: toggle select adds/removes paths; folder navigation clears
  selection; selection retained across sort change.
- `FilesViewModelCrudTest`: `CreateFolder`/`Rename`/`Delete`/`Move` success invalidates the
  pager (assert refresh trigger) and clears `inFlight`; failure emits `FilesEvent.Message`
  and removes `inFlight`; batch delete/move fans out one single-item repo call per selected
  path and aggregates partial failure into one message (no batch endpoint exists).
- `FilesViewModelResilienceTest`: timeout on refresh with prior data sets `isStale=true` and
  keeps items; `Retry` re-invokes the source; `AppError.Unauthorized` emits the message
  event.
- `SavedStateRestoreTest`: folder/query/sort survive a `SavedStateHandle` round-trip;
  selection is cleared on restore.
- Use `PagingSource.load(LoadParams.Refresh(...))` directly and
  `AsyncPagingDataDiffer`/`PagingData.from` snapshots to assert mapped item content.
- Target ≥85% line coverage on `vm` and `paging` packages; deterministic via injected
  dispatcher + virtual time (no `Thread.sleep`, no real network).

## 12. Dependencies & Sequencing

- **Depends on AND-331** (Files API + DTOs): requires `FilesRepository`, `FilePage`,
  `FileEntry`, and `FileSort` types. Cannot start until AND-331's repository interface is
  merged (the wire layer may stub responses behind the fake during development).
- **Blocks AND-332** (browse UI), **AND-333** (upload), **AND-334** (download/open),
  **AND-335** (share, via `FileShareViewModel` seam), **AND-336** (Drive import seam), and
  **AND-338** (Files tests — repo + UI tests build on these ViewModels and fakes).
- Internal order: define `FilesUiState`/intents/events -> `FilesPagingSource` -> `Pager`
  wiring -> CRUD intent handlers -> SavedState + stale/resilience -> tests.
- Libraries already in the version catalog (Paging 3, Hilt/KSP, coroutines, Turbine, MockK);
  no new Gradle dependencies expected. If Paging's test artifact
  (`androidx.paging:paging-testing`) is absent, add it to the catalog as part of this ticket.

## 13. Risks & Open Questions

- R1: **RESOLVED.** `GET /v1/fs/list` is cursor-based; the response field is `cursor` (not
  `next_cursor`), type `string?`. `PagingSource<String, FileListItem>` stands. Verified against
  `openapi.pretty.json` (op `list_files_v1_fs_list_get`) and `FileListResp` in `src/api/types.ts`.
- R2: **RESOLVED.** `GET /v1/fs/list` honors server-side `sort_by` (`name|updated|size`) and
  `sort_dir` (`asc|desc`). No client-side sort needed; KIND sort is not supported and was removed.
- R3: **RESOLVED.** Backend search is global and unpaged, with two modes (name/prefix via
  `/v1/fs/search`, content via `/v1/fs/search-text`). The web reference (`FilesPage.tsx`) confirms
  no folder scoping; the invented `searchAllFolders` flag was dropped in favor of `searchMode`.
- R4: **RESOLVED (clarified).** There is no batch endpoint. Partial failure is handled by
  client-side fan-out + aggregated message; `ApiResult<Unit>` per item is sufficient (see §7).
- R5: Stale-while-error UX (showing cached page on timeout) requires the `PagingSource` to
  retain a last-good page; verify memory implications for large folders.

## 14. Acceptance Criteria

- AC-1: `FilesViewModel` exposes `uiState: StateFlow<FilesUiState>`,
  `events: Flow<FilesEvent>`, `pagedFiles: Flow<PagingData<FileListItem>>`, and a single
  `onIntent(FilesIntent)` entry point.
- AC-2: Changing folder, query (debounced 300ms), or sort produces a new paged stream
  without losing the other two dimensions; verified by unit tests.
- AC-3: `FilesPagingSource` correctly threads the cursor across pages and maps
  success/empty/error cases as specified (unit-tested).
- AC-4: CRUD intents call the repository exactly once, invalidate the pager on success, and
  emit a message on failure without clearing the list (unit-tested).
- AC-5: Timeout/offline on refresh sets `isStale=true` and preserves the prior page; `Retry`
  re-pages (unit-tested).
- AC-6: `folder_path`, `query`, and `sort` survive a `SavedStateHandle` round-trip; selection
  is cleared (unit-tested).
- AC-7: All async paths use the injected dispatcher and virtual time; no flakiness, no real
  network; suite green under `./gradlew :feature-files:testDebugUnitTest`.
- AC-8: No file names, ids, queries, cookies, CSRF tokens, or presigned URLs appear in logs
  at DEBUG or above (raw); verified by a log-redaction test or code review.
- AC-9: ≥85% line coverage on `com.testlogon.android.feature.files.vm` and `.paging`.

## 15. Definition of Done

- Code merged to `android-port` under `android/feature-files/` in package
  `com.testlogon.android.feature.files`, building with Kotlin 2.0.21 / AGP 8.7.3 /
  Gradle 8.9 / JDK 17, compileSdk/targetSdk 35, minSdk 24.
- `FilesViewModel`, `FilesUiState`, `FilesIntent`, `FilesEvent`, `FilesPagingSource`,
  `FileListItem`, and `FileSort` implemented and `@HiltViewModel`-injectable.
- All unit tests in §11 implemented and passing in CI; coverage gate met.
- ktlint/detekt clean; no new lint baseline entries; no unused dependencies.
- Public types are documented with KDoc and depended-on by at least the AND-332 UI ticket's
  draft wiring (compile-level integration verified).
- Risks R1–R4 resolved during this review against the OpenAPI spec and web reference (see
  §13 and §16); any residual AND-331 wire details carried forward as tracked follow-ups.
- PR description links AND-337 and notes the blocked downstream tickets (AND-332..AND-336,
  AND-338).

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources: OpenAPI =
`reference/openapi.index.txt` / `reference/openapi.pretty.json`; FE = `reference/src/...`.

1. **File-listing endpoint is `GET /ui/files?folder_id=...&cursor=...&sort={field}:{dir}`.**
   VERDICT: **Corrected.** No such endpoint exists. The real one is `GET /v1/fs/list` with
   params `path,limit,cursor,sort_by,sort_dir`. SOURCE: OpenAPI `GET /v1/fs/list`
   (op `list_files_v1_fs_list_get`); FE `src/api/endpoints/files.ts: listFiles`.

2. **List response is `{ items, next_cursor }` with items `{ id, kind, size_bytes, mime_type, modified_at, parent_id }`.**
   VERDICT: **Corrected.** Response is `FileListResp { path, items: FileEntry[], cursor? }`;
   `FileEntry` = `{ name, path, type:"file"|"folder", size?, content_type?, updated_at?, created_at?, ... }`
   — no `id`/`kind`/`size_bytes`/`mime_type`/`modified_at`/`parent_id`. SOURCE:
   `src/api/types.ts: FileListResp`, `src/api/types.ts: FileEntry`.

3. **Pagination cursor field name/type.** VERDICT: **Corrected** (`cursor`, `string?`, not
   `next_cursor`). Cursor-based paging confirmed. SOURCE: OpenAPI `GET /v1/fs/list` `cursor`
   param + `FileListResp.cursor` in `src/api/types.ts`. (Resolves R1.)

4. **Server-side sort fields are NAME, MODIFIED, SIZE, KIND.** VERDICT: **Corrected.**
   `sort_by` regex is `^(name|updated|size)$`, `sort_dir` `^(asc|desc)$`. No KIND; "modified"
   is `updated`. SOURCE: OpenAPI `GET /v1/fs/list` `sort_by`/`sort_dir` schema patterns. (Resolves R2.)

5. **Search endpoint is `GET /ui/files/search?q=&folder_id=&cursor=` (paged, folder-scoped, `searchAllFolders` flag).**
   VERDICT: **Corrected.** Backend has two global, unpaged search endpoints: name/prefix
   `GET /v1/fs/search?prefix=&limit=` -> `{prefix, results: FileEntry[]}`, and content
   `GET /v1/fs/search-text?q=&limit=` -> `{query, results: FileEntry[]}`. No folder scope, no
   cursor. SOURCE: OpenAPI `GET /v1/fs/search`, `GET /v1/fs/search-text`; FE
   `src/api/endpoints/files.ts: searchFiles, searchText`; FE `src/pages/files/FilesPage.tsx`
   (nameSearchQuery/contentSearchQuery, no folder param). (Resolves R3.)

6. **Create folder is `POST /ui/files/folders {parent_id, name}`.** VERDICT: **Corrected.**
   It is `POST /v1/fs/folder` with body `{ "path": str }` (caller builds `parentPath + "/" + name`).
   SOURCE: OpenAPI schema `Body_create_folder_v1_fs_folder_post`; FE
   `src/api/endpoints/files.ts: createFolder`; FE `FilesPage.tsx: createFolderMut`.

7. **Rename is `PATCH /ui/files/{id} {name}`.** VERDICT: **Corrected.** Separate file/folder
   POST endpoints: `POST /v1/fs/rename-file` and `POST /v1/fs/rename-folder`, body
   `{ "path": str, "new_name": str }`. SOURCE: OpenAPI schemas
   `Body_rename_file_v1_fs_rename_file_post` / `Body_rename_folder_v1_fs_rename_folder_post`;
   FE `src/api/endpoints/files.ts: renameFile, renameFolder`.

8. **Delete is `POST /ui/files/delete {ids:[...]}` (batch).** VERDICT: **Corrected.** Single
   node only: `DELETE /v1/fs/file?path=` and `DELETE /v1/fs/folder?path=` (query param, no
   body, no ids). SOURCE: OpenAPI `DELETE /v1/fs/file`, `DELETE /v1/fs/folder`; FE
   `src/api/endpoints/files.ts: deleteFile, deleteFolder`.

9. **Move is `POST /ui/files/move {ids:[...], target_folder_id}` (batch).** VERDICT:
   **Corrected.** Single node: `POST /v1/fs/move` body `{ "src": str, "dst": str }`. SOURCE:
   OpenAPI schema `Body_move_fs_node_v1_fs_move_post`; FE `src/api/endpoints/files.ts: moveFile`.

10. **Batch delete/move semantics.** VERDICT: **Corrected.** No batch endpoint; the web app
    iterates client-side over selected paths calling single-item endpoints. SOURCE: FE
    `src/pages/files/BulkActions.tsx` (loop over `selectedItems` calling deleteFile/deleteFolder)
    and `src/pages/files/FilesPage.tsx` (loop calling `moveFile` per selected). (Resolves R4.)

11. **Selection is keyed by file `id` (`Set<String>` of ids).** VERDICT: **Corrected.** No ids
    exist; selection is keyed by `path`. SOURCE: FE `src/pages/files/FilesPage.tsx`
    (`selectedKeys: Set<string>` populated from `f.path`); FE `BulkActions.tsx`
    (`selectedKeys.has(f.path)`).

12. **401 handling = single `POST /ui/session/refresh` then retry once.** VERDICT: **Verified.**
    SOURCE: OpenAPI `POST /ui/session/refresh` (op `ui_session_refresh_ui_session_refresh_post`,
    empty req body); FE `src/api/client.ts: refreshSession` + the 401 branch (single
    `refreshPromise`, one retry, logout on second 401).

13. **CSRF = `ui_csrf` cookie echoed as `X-CSRF-Token`.** VERDICT: **Verified.** SOURCE: FE
    `src/api/client.ts` (`getCookie("ui_csrf")` -> `headers.set("X-CSRF-Token", csrf)`).

14. **Error `detail` is `string | [{msg}] | {code,...}`, normalized upstream.** VERDICT:
    **Verified.** SOURCE: FE `src/api/client.ts: normalizeErrorDetail` (handles all three);
    OpenAPI `HTTPValidationError` (422) uses `detail: [{loc,msg,type}]`.

15. **Session is purely cookie-based.** VERDICT: **Unverified-assumption (partially corrected).**
    The web client ALSO sends `Authorization: Bearer <accessToken>` from its auth store in
    addition to cookies. Whether the Android client mirrors that is a core-network/AND-331
    decision, transparent to this layer. SOURCE: FE `src/api/client.ts` (sets both
    `Authorization: Bearer` and relies on `credentials: "include"`).

16. **Paging page size.** VERDICT: **Corrected for alignment** (30 -> 50). Backend `limit`
    default is 50, max 200. Page size is a client choice but 50 matches the wire default and
    the web client. SOURCE: OpenAPI `GET /v1/fs/list` `limit` schema (default 50, max 200);
    FE `src/api/endpoints/files.ts: searchFiles` (default limit 50).

17. **`NavigateToOpen` declared inside `FilesEvent` as `: FilesIntent` using `fileId`.**
    VERDICT: **Corrected** (spec-internal bug). Now `data class NavigateToOpen(val path: String) : FilesEvent`.
    SOURCE: internal consistency with the path-based model (no framework source needed).

18. **Framework: Paging 3 `PagingSource`/`Pager`/`cachedIn`, Hilt `@HiltViewModel`,
    `SavedStateHandle`, `kotlinx-coroutines-test runTest` virtual time, Turbine, `paging-testing`.**
    VERDICT: **Verified (framework ref).** SOURCE (framework refs):
    https://developer.android.com/topic/libraries/architecture/paging/v3-paged-data ,
    https://developer.android.com/training/dependency-injection/hilt-jetpack ,
    https://developer.android.com/topic/libraries/architecture/saving-states ,
    https://developer.android.com/kotlin/coroutines/test ,
    https://developer.android.com/reference/kotlin/androidx/paging/testing/package-summary .

### Corrections made

- API surface rewritten from the fictional `/ui/files` folder-id/cursor model to the real
  **path-based `/v1/fs/*`** API (claims 1–11): `listFolder(path,...)`, `searchByName`/`searchText`
  (unpaged, global), `createFolder(path)`, `rename-file`/`rename-folder`, single-item
  `deleteFile`/`deleteFolder` (query param), single-node `move(src,dst)`.
- `FileEntry`/`FileListItem` field names corrected (`name/path/type/size/content_type/updated_at`;
  removed `id/kind/size_bytes/mime_type/modified_at/parent_id`). Cursor field `cursor` (not `next_cursor`).
- `FileSortField` reduced to `NAME, UPDATED, SIZE` (KIND removed); `sort_dir asc|desc`.
- Search reworked to `searchMode {NAME, CONTENT}`; removed the invented `searchAllFolders` flag.
- Selection and all intents re-keyed from `id` to `path`; batch ops documented as client-side fan-out.
- `currentFolderId`->`currentFolderPath` and SavedState key `folder_id`->`folder_path`; AC-6 updated.
- Fixed spec-internal bug: `FilesEvent.NavigateToOpen` was declared `: FilesIntent` with `fileId`.
- Page size 30 -> 50 to match the backend default; risks R1–R4 marked resolved.

### Open assumptions

- **Bearer token vs cookie-only (claim 15):** unverifiable from this layer; depends on how
  AND-331/core-network build the OkHttp stack. Web sends both; carried forward to AND-331.
- **`FilePage.cursor` is a true forward-paging cursor on the backend:** the field exists in
  `FileListResp`, but the web reference never threads it (it fetches a single page), so live
  multi-page cursor behavior is unverified against a running server. Cursor-threading is exercised
  only via fakes in unit tests; confirm against the dev host during AND-331 integration.
- **Stale-while-error cache retention (R5):** a project-wide ViewModel/PagingSource convention,
  not an API contract; no authoritative source — verify memory cost for large folders empirically.
- **`core-telemetry` presence (§10 counters):** conditional/optional module; unverifiable here.

## 17. Test Plan

All cases are JVM/Robolectric unit tests (the ticket's acceptance is "Unit-tested"; UI/instrumented
tests belong to AND-338). Where a target is noted as device/emulator it is a forward-looking note
for the downstream UI ticket, not required to close AND-337. "Traces" links to §14 ACs.

- **TC-AND-337-01** — Type: unit (Turbine). Target: JVM unit/Robolectric. Pre: `FilesViewModel`
  with fake repo returning a non-empty `FilePage`. Steps: collect `uiState`, `events`, `pagedFiles`;
  call `onIntent`. Expected: all four surfaces exist and emit; single `onIntent` entry point routes
  intents. Traces: AC-1.

- **TC-AND-337-02** — Type: unit (Turbine + virtual time). Target: JVM unit. Pre: fake repo.
  Steps: emit 5 rapid `QueryChanged` within 300ms via `runTest` virtual time. Expected: exactly one
  downstream `ListKey`/search emission after debounce; intervening keystrokes coalesced. Traces: AC-2.

- **TC-AND-337-03** — Type: unit. Target: JVM unit. Pre: in folder `/reports` with query active.
  Steps: dispatch `SortChanged(UPDATED desc)`. Expected: new paged stream; `currentFolderPath` and
  `query` preserved; repo called with `sort_by=updated,sort_dir=desc`. Traces: AC-2.

- **TC-AND-337-04** — Type: contract / MockWebServer. Target: JVM unit (MockWebServer; via repo
  fake or real Retrofit if available). Pre: enqueue `FileListResp { path, items, cursor:"c2" }`.
  Steps: `FilesPagingSource.load(Refresh)` then `load(Append(key="c2"))`. Expected: page 1
  `nextKey="c2"`; page 2 request carries `cursor=c2`; items map `name/path/type/size/content_type/updated_at`
  correctly. Asserts real field names (no `id`/`next_cursor`). Traces: AC-3.

- **TC-AND-337-05** — Type: unit. Target: JVM unit. Pre: empty folder. Steps: `load(Refresh)` with
  repo returning `items=[]`, `cursor=null`. Expected: `LoadResult.Page(data=[], prevKey=null, nextKey=null)`.
  Traces: AC-3.

- **TC-AND-337-06** — Type: unit (validation/error shape). Target: JVM unit. Pre: repo returns
  `ApiResult.Failure(AppError)` derived from a 422 `{detail:[{msg:"path is required"}]}`. Steps:
  `load(Refresh)` with no prior page. Expected: `LoadResult.Error`; message text comes from the
  normalized `detail` (not a generic string). Traces: AC-3, AC-4.

- **TC-AND-337-07** — Type: unit. Target: JVM unit. Pre: fake repo records calls. Steps: dispatch
  `CreateFolder("new")` in `/reports`. Expected: repo `createFolder("/reports/new")` called exactly
  once; pager invalidated on success; `inFlight` cleared. Traces: AC-4.

- **TC-AND-337-08** — Type: unit. Target: JVM unit. Pre: two items selected (one file, one folder).
  Steps: dispatch `Delete([file, folder])`. Expected: client-side fan-out — `deleteFile(path)` and
  `deleteFolder(path)` each called once (correct endpoint per `isFolder`); pager invalidated once;
  selection cleared. Traces: AC-4.

- **TC-AND-337-09** — Type: unit (partial-failure error path). Target: JVM unit. Pre: batch of 3
  moves; repo fails the 2nd with `AppError`. Steps: dispatch `Move([a,b,c], "/dst")`. Expected: all
  3 single `move(src,dst)` calls attempted; one aggregated `FilesEvent.Message` ("1 of 3 failed");
  list not cleared; pager invalidated once. Traces: AC-4.

- **TC-AND-337-10** — Type: unit (offline/flaky-dev-host). Target: JVM unit. Pre: a page already
  loaded; repo then returns `Failure(NetworkError/timeout)` on refresh. Steps: dispatch `Refresh`.
  Expected: `isStale=true`, prior items preserved (not cleared), retry affordance reflected; no crash.
  Traces: AC-5.

- **TC-AND-337-11** — Type: unit. Target: JVM unit. Pre: stale state from TC-10. Steps: dispatch
  `Retry(key)`. Expected: `PagingSource.invalidate()`/refresh trigger fires; repo re-queried with the
  same `ListKey`; `isStale` clears on success. Traces: AC-5.

- **TC-AND-337-12** — Type: unit (SavedState round-trip). Target: JVM unit. Pre: set
  `currentFolderPath="/a/b"`, `query="q"`, `sort=SIZE asc`, two paths selected. Steps: write to a new
  `SavedStateHandle`, reconstruct VM. Expected: keys `folder_path/query/sort` restored equal; selection
  empty after restore. Traces: AC-6.

- **TC-AND-337-13** — Type: unit (security / log redaction). Target: JVM unit (Robolectric Timber tree
  or in-memory log capture). Pre: planted log tree. Steps: drive list load + a failing op with
  PII-ish names/paths/queries; trigger 401->refresh path. Expected: no raw file names, paths, query
  text, cookies, `X-CSRF-Token`, or presigned URLs at DEBUG+; only hashed/truncated identifiers.
  Traces: AC-8.

- **TC-AND-337-14** — Type: unit (determinism / coverage gate). Target: JVM unit. Pre: full suite.
  Steps: run `./gradlew :feature-files:testDebugUnitTest` with injected dispatcher + virtual time.
  Expected: green, no `Thread.sleep`, no real network; coverage >=85% on `.vm` and `.paging`.
  Traces: AC-7, AC-9.

- **TC-AND-337-15** — Type: unit. Target: JVM unit. Pre: in search mode. Steps: dispatch
  `QueryChanged("photo")` then `SearchModeChanged(CONTENT)`, then clear query. Expected: NAME mode
  calls `searchByName`/`/v1/fs/search` (unpaged, single page, `nextKey=null`); CONTENT mode calls
  `searchText`/`/v1/fs/search-text`; empty query reverts to folder browse via `listFolder`. Traces:
  AC-2, AC-3.

Note on targets: every case above is device-independent and runs on **JVM unit/Robolectric** (no
device/emulator needed) because this is a pure state+paging layer with a faked repository. The
headless emulator `test35` and the physical Samsung Galaxy A15 (SM-A156U) become relevant only for
the downstream UI tickets (AND-332/AND-338); no camera, biometrics, FCM, WebRTC, or ABI/API-specific
behavior is exercised by AND-337, so no case must run on the physical device.

### Coverage matrix

| AC | Covered by |
| --- | --- |
| AC-1 | TC-01 |
| AC-2 | TC-02, TC-03, TC-15 |
| AC-3 | TC-04, TC-05, TC-06, TC-15 |
| AC-4 | TC-06, TC-07, TC-08, TC-09 |
| AC-5 | TC-10, TC-11 |
| AC-6 | TC-12 |
| AC-7 | TC-14 |
| AC-8 | TC-13 |
| AC-9 | TC-14 |
