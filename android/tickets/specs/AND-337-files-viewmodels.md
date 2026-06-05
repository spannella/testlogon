---
id: AND-337
title: Files ViewModels
milestone: M7
epic: E43
priority: P1
size: M
status: draft
depends_on: [AND-331]
blocks: [AND-332, AND-333, AND-334, AND-338]
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
- Web reference: `frontend/src/api/endpoints/files.ts` (browse/CRUD/search) and shared
  types in `frontend/src/api/types.ts`. The Android paging/sort/search semantics mirror
  the web list semantics.
- Architecture: ViewModels expose `StateFlow<UiState>`; repositories return typed
  `ApiResult<T>`; FastAPI `detail` is mapped to `AppError` upstream. Cookie-based session
  with single `POST /ui/session/refresh` on 401 is handled in the OkHttp authenticator
  (core-network), transparent to this layer.
- Backend is plaintext HTTP on an unreliable dev host (`http://18.222.237.167:8000`):
  ~20s timeouts, bounded backoff retry for idempotent GETs only, offline/stale UI states.

## 3. Functional Requirements

FR-1. **Browse state.** A `FilesViewModel` exposes the current folder (root if none),
breadcrumb trail, and a paged stream of that folder's children. Navigating into a folder
or up the breadcrumb re-targets the paged stream.

FR-2. **Search.** A debounced (300ms) free-text query filters the listing server-side via
the search endpoint. An empty query reverts to plain folder browse. Search is scoped to
the current folder unless `searchAllFolders` is enabled in state.

FR-3. **Sort.** The list supports sort by `NAME`, `MODIFIED`, `SIZE`, `KIND`, each
ascending/descending. Changing sort invalidates and re-pages without losing the current
folder/query.

FR-4. **Refresh.** A pull-to-refresh / manual refresh intent invalidates the `PagingSource`
and re-fetches page 1, surfacing a `isRefreshing` flag distinct from initial load.

FR-5. **Selection.** Multi-select mode tracks a `Set<String>` of selected file ids for
batch actions (delete, move, share). Selection survives sort/search changes for still-visible
items and is cleared on folder navigation.

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

`ListKey` is `data class ListKey(folderId: String?, query: String, sort: FileSort)`.
`pagerFor` builds a `Pager(PagingConfig(pageSize = 30, prefetchDistance = 10,
initialLoadSize = 30, enablePlaceholders = false)) { FilesPagingSource(repo, key, io) }`.

`FilesPagingSource : PagingSource<String, FileListItem>` uses an opaque cursor `String?`
(the `nextCursor` returned by AND-331's list/search endpoints). `load()` calls
`repo.listFolder(...)` or `repo.searchFiles(...)` per `key.query`, maps `ApiResult`:
`Success` -> `LoadResult.Page(data, prevKey = null, nextKey = nextCursor)`;
`Failure(NetworkError)` -> if a cached page exists, mark `isStale` via the ViewModel and
return the cached page; else `LoadResult.Error(throwable)`. CSRF/401/refresh and backoff
retry are handled by the OkHttp stack from `core-network`, so the source treats a returned
`ApiResult.Failure` as terminal for that attempt.

Search debounce is implemented on the query input as a `MutableStateFlow<String>` with
`.debounce(300).distinctUntilChanged()` feeding `listKey`. Selection, refresh, stale, and
error chrome live entirely in `FilesUiState` and never inside `PagingData`.

`FileListItem` is a thin UI projection of `FileEntry` (id, displayName, kind, sizeBytes,
modifiedAt, isFolder, mimeType, transferState) so the paged list and the selection/CRUD
state can co-evolve without re-fetching.

## 5. API Contract

This ticket calls repository methods only; raw HTTP is owned by AND-331. Repository
surface consumed (from `core-data`, namespace `com.testlogon.android.core.data.files`):

```kotlin
interface FilesRepository {
    suspend fun listFolder(
        folderId: String?, cursor: String?, limit: Int, sort: FileSort
    ): ApiResult<FilePage>
    suspend fun searchFiles(
        query: String, folderId: String?, cursor: String?, limit: Int, sort: FileSort
    ): ApiResult<FilePage>
    suspend fun createFolder(parentId: String?, name: String): ApiResult<FileEntry>
    suspend fun rename(fileId: String, newName: String): ApiResult<FileEntry>
    suspend fun delete(fileIds: List<String>): ApiResult<Unit>
    suspend fun move(fileIds: List<String>, targetFolderId: String?): ApiResult<Unit>
}
// data class FilePage(val items: List<FileEntry>, val nextCursor: String?)
```

The underlying endpoints (for reference; verified against `/openapi.json` in AND-331):
`GET /ui/files?folder_id={id}&cursor={c}&limit={n}&sort={field}:{dir}`,
`GET /ui/files/search?q={q}&folder_id={id}&cursor={c}&limit={n}&sort=...`,
`POST /ui/files/folders` `{ "parent_id": str|null, "name": str }`,
`PATCH /ui/files/{id}` `{ "name": str }`,
`POST /ui/files/delete` `{ "ids": [str] }`,
`POST /ui/files/move` `{ "ids": [str], "target_folder_id": str|null }`.

Representative list response shape mapped by AND-331 into `FilePage`:

```json
{
  "items": [
    { "id": "f_01H...", "name": "report.pdf", "kind": "file",
      "size_bytes": 80213, "mime_type": "application/pdf",
      "modified_at": "2026-05-30T14:02:11Z", "parent_id": "d_root" }
  ],
  "next_cursor": "eyJrIjoi..."
}
```

Error `detail` mapping (`string | [{msg}] | {code,...}`) is already normalized to
`AppError` by the repository; this ticket consumes `ApiResult.Failure(AppError)`.

## 6. Data & State Management

```kotlin
data class FilesUiState(
    val currentFolderId: String? = null,
    val breadcrumb: List<FolderCrumb> = emptyList(),
    val query: String = "",
    val searchAllFolders: Boolean = false,
    val sort: FileSort = FileSort(FileSortField.NAME, ascending = true),
    val selectionMode: Boolean = false,
    val selectedIds: Set<String> = emptySet(),
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val createFolderDialog: Boolean = false,
    val inFlight: Set<FileOp> = emptySet(),   // delete/move/rename spinners
)

enum class FileSortField { NAME, MODIFIED, SIZE, KIND }
data class FileSort(val field: FileSortField, val ascending: Boolean)

sealed interface FilesIntent {
    data class OpenFolder(val folderId: String?, val name: String) : FilesIntent
    data class NavigateCrumb(val index: Int) : FilesIntent
    data class QueryChanged(val q: String) : FilesIntent
    data class SortChanged(val sort: FileSort) : FilesIntent
    data object Refresh : FilesIntent
    data class ToggleSelect(val fileId: String) : FilesIntent
    data object ClearSelection : FilesIntent
    data class CreateFolder(val name: String) : FilesIntent
    data class Rename(val fileId: String, val newName: String) : FilesIntent
    data class Delete(val fileIds: List<String>) : FilesIntent
    data class Move(val fileIds: List<String>, val target: String?) : FilesIntent
    data class Retry(val key: ListKey) : FilesIntent
}

sealed interface FilesEvent {
    data class Message(val text: UiText) : FilesEvent
    data class NavigateToOpen(val fileId: String) : FilesIntent  // for AND-334 hook
}
```

State persistence: `currentFolderId`, `query`, and `sort` are mirrored into
`SavedStateHandle` (keys `folder_id`, `query`, `sort`) so process death restores the same
listing. `cachedIn(viewModelScope)` retains the paged stream across configuration changes.
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
- **Idempotency:** Only GET-backed methods (`listFolder`, `searchFiles`) are eligible for
  the bounded backoff retry, which is configured in OkHttp (core-network), not retried in
  the ViewModel. Mutations are issued exactly once per intent.

## 8. Security & Privacy

No new credential or token handling is introduced. The session rides cookies + the
`ui_csrf` cookie echoed as `X-CSRF-Token`, fully managed by core-network's persistent
cookie jar and interceptors; ViewModels never read or log cookies, CSRF tokens, or
presigned URLs. File names and ids may be PII-adjacent and must not be logged at INFO or
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
- `FilesViewModelSelectionTest`: toggle select adds/removes ids; folder navigation clears
  selection; selection retained across sort change.
- `FilesViewModelCrudTest`: `CreateFolder`/`Rename`/`Delete`/`Move` success invalidates the
  pager (assert refresh trigger) and clears `inFlight`; failure emits `FilesEvent.Message`
  and removes `inFlight`; delete-batch passes full id list to repo.
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

- R1: AND-331's list/search pagination model (cursor vs offset/page) is assumed
  cursor-based. If it is offset-based, `PagingSource<Int, _>` and `ListKey` change. **Confirm
  the `next_cursor` field name and type against `/openapi.json` before coding.**
- R2: Server-side sort support — if `sort` is not honored by `GET /ui/files`, sort must be
  client-side over a full page, which conflicts with paging. Open question for AND-331.
- R3: Search scope semantics (current folder vs global) may differ from web `files.ts`;
  default chosen here is current-folder with a `searchAllFolders` flag — verify against the
  web reference.
- R4: Batch delete/move atomicity on the backend is unknown; partial failure handling
  (some ids fail) may require richer result types than `ApiResult<Unit>`. Flagged to AND-331.
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
- AC-6: `folder_id`, `query`, and `sort` survive a `SavedStateHandle` round-trip; selection
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
- Risks R1–R3 resolved or explicitly carried forward as tracked follow-ups against AND-331.
- PR description links AND-337 and notes the blocked downstream tickets (AND-332..AND-336,
  AND-338).
