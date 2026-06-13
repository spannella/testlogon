package com.testlogon.android.feature.files

import androidx.lifecycle.SavedStateHandle
import androidx.paging.PagingData
import com.testlogon.android.core.model.ApiError
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
import com.testlogon.android.feature.files.presentation.FilePath
import com.testlogon.android.feature.files.presentation.FilesEvent
import com.testlogon.android.feature.files.presentation.FilesViewModel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-332 - unit tests for [FilesViewModel].
 *
 * ANTI-HANG DISCIPLINE: the VM has NO poll loop - the ONLY timed wait is the 300 ms search debounce, a
 * single cancellable job. Tests advance it with a BOUNDED advanceTimeBy(300) and otherwise use
 * runCurrent() - NEVER advanceUntilIdle. The runCurrent helpers are [TestScope] extensions; no nested
 * runTest. Browse paging is not materialized here (the PagingSource tests cover that); the fake repo
 * records the requested (path, sort) and serves bounded search results.
 */
class FilesViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private class FakeRepo : FilesRepository {
        val pagedPaths = mutableListOf<String>()
        val pagedSorts = mutableListOf<FileSort>()
        var searchResult: ApiResult<List<FileNode>> = ApiResult.Success(emptyList())
        val searchQueries = mutableListOf<String>()
        val searchModes = mutableListOf<SearchMode>()

        override fun pagedFolder(path: String, sort: FileSort): Flow<PagingData<FileNode>> {
            pagedPaths += path
            pagedSorts += sort
            return flowOf(PagingData.empty())
        }

        override suspend fun search(
            query: String,
            mode: SearchMode,
            sort: FileSort,
        ): ApiResult<List<FileNode>> {
            searchQueries += query
            searchModes += mode
            return searchResult
        }
    }

    private class FakeSortPrefs(var stored: FileSort = FileSort()) : SortPrefs {
        var writes = 0
        override suspend fun read(): FileSort = stored
        override suspend fun write(sort: FileSort) {
            stored = sort
            writes++
        }
    }

    private fun folder(name: String, path: String = "/$name") =
        FileNode(path = path, name = name, type = FileNodeType.FOLDER)

    private fun file(name: String, path: String = "/$name") =
        FileNode(path = path, name = name, type = FileNodeType.FILE)

    private fun TestScope.vm(
        repo: FakeRepo = FakeRepo(),
        prefs: FakeSortPrefs = FakeSortPrefs(),
        saved: SavedStateHandle = SavedStateHandle(),
        refreshBus: FolderRefreshBus = FolderRefreshBus(),
    ): FilesViewModel {
        val model = FilesViewModel(repo, prefs, refreshBus, saved)
        runCurrent() // let the init prefs read settle.
        return model
    }

    @Test
    fun onOpenFolder_appendsPath_andDerivesBreadcrumbs() = runTest {
        val model = vm()
        model.onOpenFolder(folder("docs"))
        runCurrent()

        val state = model.uiState.value
        assertEquals("/docs", state.currentPath)
        // root crumb + the docs crumb.
        assertEquals(listOf(FilePath.ROOT, "/docs"), state.breadcrumbs.map { it.path })
    }

    @Test
    fun onBreadcrumb_truncatesPath() = runTest {
        val model = vm()
        model.onOpenFolder(folder("a", "/a"))
        runCurrent()
        model.onOpenFolder(folder("b", "/b"))
        runCurrent()
        assertEquals("/a/b", model.uiState.value.currentPath)

        model.onBreadcrumb(1) // back to the first segment.
        runCurrent()
        assertEquals("/a", model.uiState.value.currentPath)
    }

    @Test
    fun onUp_atRoot_emitsNavigateUp() = runTest {
        val model = vm()
        val events = mutableListOf<FilesEvent>()
        val job = backgroundScope.launch { model.events.collect { events += it } }
        runCurrent()

        model.onUp()
        runCurrent()
        assertTrue(events.contains(FilesEvent.NavigateUp))
        job.cancel()
    }

    @Test
    fun onUp_belowRoot_popsSegment() = runTest {
        val model = vm()
        model.onOpenFolder(folder("docs"))
        runCurrent()
        model.onUp()
        runCurrent()
        assertEquals(FilePath.ROOT, model.uiState.value.currentPath)
    }

    @Test
    fun onSearchChanged_debouncedSearch_runsAfter300ms() = runTest {
        val repo = FakeRepo().apply { searchResult = ApiResult.Success(listOf(file("hit.txt"))) }
        val model = vm(repo)

        model.onSearchChanged("re")
        runCurrent()
        assertTrue(model.uiState.value.isSearching)
        assertTrue(repo.searchQueries.isEmpty()) // still within the debounce window.

        advanceTimeBy(FilesViewModel.DEBOUNCE_MS)
        runCurrent()
        assertEquals(listOf("re"), repo.searchQueries)
        assertEquals(listOf("hit.txt"), model.uiState.value.searchResults.map { it.name })
    }

    @Test
    fun onSearchChanged_belowMinLength_restoresBrowse() = runTest {
        val repo = FakeRepo().apply { searchResult = ApiResult.Success(listOf(file("hit.txt"))) }
        val model = vm(repo)
        model.onSearchChanged("re")
        advanceTimeBy(FilesViewModel.DEBOUNCE_MS)
        runCurrent()
        assertTrue(model.uiState.value.isSearching)

        model.onSearchChanged("r") // below the 2-char minimum.
        runCurrent()
        assertFalse(model.uiState.value.isSearching)
        assertTrue(model.uiState.value.searchResults.isEmpty())
    }

    @Test
    fun search_failure_setsSearchError() = runTest {
        val repo = FakeRepo().apply {
            searchResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        }
        val model = vm(repo)
        model.onSearchChanged("re")
        advanceTimeBy(FilesViewModel.DEBOUNCE_MS)
        runCurrent()
        assertEquals("boom", model.uiState.value.searchError)
        assertTrue(model.uiState.value.searchResults.isEmpty())
    }

    @Test
    fun onSortChanged_persists_andRePages() = runTest {
        val repo = FakeRepo()
        val prefs = FakeSortPrefs()
        val model = vm(repo, prefs)
        // Collect the paging flow so the flatMapLatest actually invokes the repo's pagedFolder per key.
        val pagingJob = backgroundScope.launch { model.pagedItems.collect { } }
        runCurrent()

        model.onSortChanged(FileSortBy.SIZE, FileSortDir.DESC)
        runCurrent()

        assertEquals(FileSortBy.SIZE, model.uiState.value.sort.sortBy)
        assertEquals(FileSortDir.DESC, model.uiState.value.sort.sortDir)
        assertEquals(1, prefs.writes)
        assertEquals(FileSortBy.SIZE, prefs.stored.sortBy)
        // The Pager re-keyed for the new sort (the last requested sort matches).
        assertEquals(FileSortBy.SIZE, repo.pagedSorts.last().sortBy)
        pagingJob.cancel()
    }

    @Test
    fun onOpenFile_emitsOpenFileEvent() = runTest {
        val model = vm()
        val events = mutableListOf<FilesEvent>()
        val job = backgroundScope.launch { model.events.collect { events += it } }
        runCurrent()

        model.onOpenFile(file("report.txt", "/report.txt"))
        runCurrent()
        assertEquals(FilesEvent.OpenFile("/report.txt"), events.lastOrNull())
        job.cancel()
    }

    @Test
    fun onOpenFile_ignoresFolders() = runTest {
        val model = vm()
        val events = mutableListOf<FilesEvent>()
        val job = backgroundScope.launch { model.events.collect { events += it } }
        runCurrent()

        model.onOpenFile(folder("docs"))
        runCurrent()
        assertNull(events.lastOrNull())
        job.cancel()
    }
}
