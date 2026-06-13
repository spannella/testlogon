package com.testlogon.android.feature.files

import androidx.lifecycle.SavedStateHandle
import androidx.paging.PagingData
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.files.FileNode
import com.testlogon.android.core.model.files.FileNodeType
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.files.data.FileSort
import com.testlogon.android.feature.files.data.FileSortBy
import com.testlogon.android.feature.files.data.FileSortDir
import com.testlogon.android.feature.files.data.FilesRepository
import com.testlogon.android.feature.files.data.FolderRefreshBus
import com.testlogon.android.feature.files.data.SearchMode
import com.testlogon.android.feature.files.data.SortPrefs
import com.testlogon.android.feature.files.presentation.CrudKind
import com.testlogon.android.feature.files.presentation.FilesEvent
import com.testlogon.android.feature.files.presentation.FilesViewModel
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-338 - additional [FilesViewModel] coverage beyond [FilesViewModelTest] / [FilesViewModelCrudTest].
 *
 * These ADD the browse / search / selection / CRUD-guard gaps the AND-332 / AND-337 waves left untested:
 * the debounce cancels a superseded keystroke; the search-mode toggle re-runs with the new mode; a sort
 * change re-runs a LIVE search; selection survives sort + search but clears on folder nav; the CRUD
 * double-submit guard short-circuits a concurrent op; the FolderRefreshBus re-pages the on-screen folder;
 * moveSelected reports failure when ANY per-path move fails; a search NetworkError surfaces the offline
 * copy.
 *
 * ANTI-HANG DISCIPLINE (same as the sibling tests): no poll loop; the ONLY timed wait is the 300 ms
 * debounce, advanced with a BOUNDED advanceTimeBy(300). runCurrent() otherwise - NEVER advanceUntilIdle.
 * No nested runTest; event collection on backgroundScope.launch. Distinct fake-helper names.
 */
class FilesViewModelBrowseGapsTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    /** Records browse / search / CRUD calls and serves configurable results (distinct from FakeRepo). */
    private class GapsFakeRepo : FilesRepository {
        val searchQueries = mutableListOf<String>()
        val searchModes = mutableListOf<SearchMode>()
        val searchSorts = mutableListOf<FileSort>()
        var searchResult: ApiResult<List<FileNode>> = ApiResult.Success(emptyList())

        val moveCalls = mutableListOf<Pair<String, String>>()
        /** Per-src move outcome (defaults to success); lets a test fail exactly one path. */
        var moveOutcomeFor: (String) -> ApiResult<Unit> = { ApiResult.Success(Unit) }

        /** A gate that, when set, parks the next CRUD op so the in-flight guard can be observed. */
        var crudGate: CompletableDeferred<Unit>? = null
        var deleteCount = 0

        /** Records every (path, sort) the Pager re-keys on (the re-page seam). */
        val pagedKeys = mutableListOf<Pair<String, FileSort>>()

        override fun pagedFolder(path: String, sort: FileSort): Flow<PagingData<FileNode>> {
            pagedKeys += path to sort
            return flowOf(PagingData.empty())
        }

        override suspend fun search(
            query: String,
            mode: SearchMode,
            sort: FileSort,
        ): ApiResult<List<FileNode>> {
            searchQueries += query
            searchModes += mode
            searchSorts += sort
            return searchResult
        }

        override suspend fun createFolder(parentPath: String, name: String): ApiResult<Unit> =
            ApiResult.Success(Unit)

        override suspend fun rename(path: String, newName: String, isFolder: Boolean): ApiResult<Unit> =
            ApiResult.Success(Unit)

        override suspend fun delete(path: String, isFolder: Boolean): ApiResult<Unit> {
            deleteCount++
            // one-shot gate: only the first delete parks (so a later delete after release proceeds).
            val gate = crudGate
            crudGate = null
            gate?.await()
            return ApiResult.Success(Unit)
        }

        override suspend fun move(src: String, dst: String): ApiResult<Unit> {
            moveCalls += src to dst
            return moveOutcomeFor(src)
        }
    }

    private class GapsFakeSortPrefs(var stored: FileSort = FileSort()) : SortPrefs {
        override suspend fun read(): FileSort = stored
        override suspend fun write(sort: FileSort) {
            stored = sort
        }
    }

    private fun folder(name: String, path: String = "/$name") =
        FileNode(path = path, name = name, type = FileNodeType.FOLDER)

    private fun file(name: String, path: String = "/$name") =
        FileNode(path = path, name = name, type = FileNodeType.FILE)

    private fun TestScope.gapsVm(
        repo: GapsFakeRepo = GapsFakeRepo(),
        prefs: GapsFakeSortPrefs = GapsFakeSortPrefs(),
        saved: SavedStateHandle = SavedStateHandle(),
        refreshBus: FolderRefreshBus = FolderRefreshBus(),
    ): FilesViewModel {
        val model = FilesViewModel(repo, prefs, refreshBus, saved)
        runCurrent() // let the init prefs read settle.
        return model
    }

    @Test
    fun searchDebounce_supersededKeystroke_runsOnlyTheLatestQuery() = runTest {
        val repo = GapsFakeRepo().apply { searchResult = ApiResult.Success(listOf(file("hit.txt"))) }
        val model = gapsVm(repo)

        model.onSearchChanged("re") // schedules a search.
        runCurrent()
        // a new keystroke before the window elapses cancels the pending search.
        model.onSearchChanged("rep")
        advanceTimeBy(FilesViewModel.DEBOUNCE_MS)
        runCurrent()

        // exactly one search ran, for the latest query.
        assertEquals(listOf("rep"), repo.searchQueries)
    }

    @Test
    fun onToggleSearchMode_switchesMode_andReRunsLiveSearch() = runTest {
        val repo = GapsFakeRepo().apply { searchResult = ApiResult.Success(listOf(file("hit.txt"))) }
        val model = gapsVm(repo)

        model.onSearchChanged("todo")
        advanceTimeBy(FilesViewModel.DEBOUNCE_MS)
        runCurrent()
        assertEquals(SearchMode.PREFIX, model.uiState.value.searchMode)
        assertEquals(listOf(SearchMode.PREFIX), repo.searchModes)

        model.onToggleSearchMode()
        runCurrent()
        assertEquals(SearchMode.TEXT, model.uiState.value.searchMode)
        // the live search re-ran with the new mode (no extra debounce wait on a mode toggle).
        assertEquals(listOf(SearchMode.PREFIX, SearchMode.TEXT), repo.searchModes)
        assertEquals(listOf("todo", "todo"), repo.searchQueries)
    }

    @Test
    fun onSortChanged_whileSearching_reRunsSearchWithNewSort() = runTest {
        val repo = GapsFakeRepo().apply { searchResult = ApiResult.Success(listOf(file("hit.txt"))) }
        val model = gapsVm(repo)

        model.onSearchChanged("re")
        advanceTimeBy(FilesViewModel.DEBOUNCE_MS)
        runCurrent()
        assertTrue(model.uiState.value.isSearching)
        assertEquals(1, repo.searchSorts.size)

        model.onSortChanged(FileSortBy.SIZE, FileSortDir.DESC)
        runCurrent()
        // the live search re-ran client-side with the new sort.
        assertEquals(2, repo.searchSorts.size)
        assertEquals(FileSortBy.SIZE, repo.searchSorts.last().sortBy)
        assertEquals(FileSortDir.DESC, repo.searchSorts.last().sortDir)
    }

    @Test
    fun selection_survivesSortChange_andSearch_butClearsOnFolderNav() = runTest {
        val repo = GapsFakeRepo().apply { searchResult = ApiResult.Success(emptyList()) }
        val model = gapsVm(repo)

        model.toggleSelected("/a.txt")
        runCurrent()
        assertEquals(setOf("/a.txt"), model.uiState.value.selected)

        // a sort change keeps the selection.
        model.onSortChanged(FileSortBy.SIZE, FileSortDir.DESC)
        runCurrent()
        assertEquals(setOf("/a.txt"), model.uiState.value.selected)

        // starting a search keeps the selection (it is folder-scoped, not browse-vs-search scoped).
        model.onSearchChanged("re")
        advanceTimeBy(FilesViewModel.DEBOUNCE_MS)
        runCurrent()
        assertEquals(setOf("/a.txt"), model.uiState.value.selected)

        // navigating into a folder clears it.
        model.onOpenFolder(folder("docs"))
        runCurrent()
        assertTrue(model.uiState.value.selected.isEmpty())
        assertFalse(model.uiState.value.selectionMode)
    }

    @Test
    fun crudDoubleSubmitGuard_secondOpWhileInFlightIsSkipped() = runTest {
        val gate = CompletableDeferred<Unit>()
        val repo = GapsFakeRepo().apply { crudGate = gate }
        val model = gapsVm(repo)

        // first delete parks on the gate (stays in flight).
        model.delete("/one.txt", isFolder = false)
        runCurrent()
        assertEquals(1, repo.deleteCount)

        // a second non-idempotent op is short-circuited by the in-flight guard.
        model.delete("/two.txt", isFolder = false)
        runCurrent()
        assertEquals(1, repo.deleteCount)

        // release the first; the guard clears so a later op proceeds.
        gate.complete(Unit)
        runCurrent()
        model.delete("/three.txt", isFolder = false)
        runCurrent()
        assertEquals(2, repo.deleteCount)
    }

    @Test
    fun refreshBus_signalForCurrentFolder_rePagesButIgnoresOtherFolders() = runTest {
        val bus = FolderRefreshBus()
        val repo = GapsFakeRepo()
        val model = gapsVm(repo, refreshBus = bus)
        // collect the paged flow so flatMapLatest invokes pagedFolder on each pagerKey change.
        val pagingJob = backgroundScope.launch { model.pagedItems.collect { } }
        runCurrent()
        val keysAfterInit = repo.pagedKeys.size

        // a signal for a DIFFERENT folder than the on-screen root must NOT re-page.
        bus.signal("/docs")
        runCurrent()
        assertEquals(keysAfterInit, repo.pagedKeys.size)

        // a signal for the on-screen folder re-anchors the Pager (one new pagedFolder call).
        bus.signal(model.uiState.value.currentPath)
        runCurrent()
        assertEquals(keysAfterInit + 1, repo.pagedKeys.size)
        pagingJob.cancel()
    }

    @Test
    fun moveSelected_partialFailure_reportsBatchFailure_butStillClearsSelection() = runTest {
        val repo = GapsFakeRepo().apply {
            moveOutcomeFor = { src ->
                if (src == "/bad.txt") {
                    ApiResult.Failure(com.testlogon.android.core.model.ApiError(status = 500, message = "no"))
                } else {
                    ApiResult.Success(Unit)
                }
            }
        }
        val model = gapsVm(repo)
        val events = mutableListOf<FilesEvent>()
        val job = backgroundScope.launch { model.events.collect { events += it } }
        runCurrent()

        model.toggleSelected("/ok.txt")
        model.toggleSelected("/bad.txt")
        runCurrent()

        model.moveSelected("/dst")
        runCurrent()

        // both paths were attempted.
        assertEquals(2, repo.moveCalls.size)
        // the batch reports failure because one path failed.
        assertTrue(events.contains(FilesEvent.CrudMessage(CrudKind.MOVE_BATCH, success = false)))
        // selection is cleared regardless (the batch ran to completion).
        assertTrue(model.uiState.value.selected.isEmpty())
        job.cancel()
    }

    @Test
    fun search_networkError_surfacesOfflineMessage() = runTest {
        val repo = GapsFakeRepo().apply {
            searchResult = ApiResult.NetworkError(java.io.IOException("offline"))
        }
        val model = gapsVm(repo)

        model.onSearchChanged("re")
        advanceTimeBy(FilesViewModel.DEBOUNCE_MS)
        runCurrent()

        val state = model.uiState.value
        assertFalse(state.searchLoading)
        assertTrue(state.searchResults.isEmpty())
        // a non-null, user-facing offline message (the VM's OFFLINE_MESSAGE constant).
        assertTrue(state.searchError?.isNotBlank() == true)
    }
}
