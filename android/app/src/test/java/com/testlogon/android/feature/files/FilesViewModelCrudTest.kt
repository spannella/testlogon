package com.testlogon.android.feature.files

import androidx.lifecycle.SavedStateHandle
import androidx.paging.PagingData
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.files.FileNode
import com.testlogon.android.core.model.files.FileNodeType
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.files.data.FileSort
import com.testlogon.android.feature.files.data.FilesRepository
import com.testlogon.android.feature.files.data.FolderRefreshBus
import com.testlogon.android.feature.files.data.SearchMode
import com.testlogon.android.feature.files.data.SortPrefs
import com.testlogon.android.feature.files.presentation.CrudKind
import com.testlogon.android.feature.files.presentation.FilesEvent
import com.testlogon.android.feature.files.presentation.FilesViewModel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-337 - unit tests for the multi-select state + folder CRUD intents added to [FilesViewModel].
 *
 * ANTI-HANG DISCIPLINE (same as [FilesViewModelTest]): no poll loop, no nested runTest; CRUD ops are
 * synchronous coroutines settled with runCurrent() (NEVER advanceUntilIdle); event collection runs on
 * backgroundScope.launch. The fake repo records every CRUD call and serves a configurable result.
 */
class FilesViewModelCrudTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private class CrudFakeRepo : FilesRepository {
        val createFolderCalls = mutableListOf<Pair<String, String>>()
        val renameCalls = mutableListOf<Triple<String, String, Boolean>>()
        val deleteCalls = mutableListOf<Pair<String, Boolean>>()
        val moveCalls = mutableListOf<Pair<String, String>>()
        var crudOutcome: ApiResult<Unit> = ApiResult.Success(Unit)

        override fun pagedFolder(path: String, sort: FileSort): Flow<PagingData<FileNode>> =
            flowOf(PagingData.empty())

        override suspend fun search(
            query: String,
            mode: SearchMode,
            sort: FileSort,
        ): ApiResult<List<FileNode>> = ApiResult.Success(emptyList())

        override suspend fun createFolder(parentPath: String, name: String): ApiResult<Unit> {
            createFolderCalls += parentPath to name
            return crudOutcome
        }

        override suspend fun rename(path: String, newName: String, isFolder: Boolean): ApiResult<Unit> {
            renameCalls += Triple(path, newName, isFolder)
            return crudOutcome
        }

        override suspend fun delete(path: String, isFolder: Boolean): ApiResult<Unit> {
            deleteCalls += path to isFolder
            return crudOutcome
        }

        override suspend fun move(src: String, dst: String): ApiResult<Unit> {
            moveCalls += src to dst
            return crudOutcome
        }
    }

    private class CrudFakeSortPrefs(var stored: FileSort = FileSort()) : SortPrefs {
        override suspend fun read(): FileSort = stored
        override suspend fun write(sort: FileSort) {
            stored = sort
        }
    }

    private fun folder(name: String, path: String = "/$name") =
        FileNode(path = path, name = name, type = FileNodeType.FOLDER)

    private fun TestScope.crudVm(
        repo: CrudFakeRepo = CrudFakeRepo(),
        prefs: CrudFakeSortPrefs = CrudFakeSortPrefs(),
        saved: SavedStateHandle = SavedStateHandle(),
        refreshBus: FolderRefreshBus = FolderRefreshBus(),
    ): FilesViewModel {
        val model = FilesViewModel(repo, prefs, refreshBus, saved)
        runCurrent() // let the init prefs read settle.
        return model
    }

    @Test
    fun createFolder_callsRepoWithCurrentPath_andEmitsSuccessMessage() = runTest {
        val repo = CrudFakeRepo()
        val model = crudVm(repo)
        model.onOpenFolder(folder("docs"))
        runCurrent()
        val events = mutableListOf<FilesEvent>()
        val job = backgroundScope.launch { model.events.collect { events += it } }
        runCurrent()

        model.createFolder("photos")
        runCurrent()

        assertEquals(listOf("/docs" to "photos"), repo.createFolderCalls)
        assertTrue(events.contains(FilesEvent.CrudMessage(CrudKind.CREATE_FOLDER, success = true)))
        job.cancel()
    }

    @Test
    fun rename_callsRepo_andEmitsSuccess() = runTest {
        val repo = CrudFakeRepo()
        val model = crudVm(repo)
        val events = mutableListOf<FilesEvent>()
        val job = backgroundScope.launch { model.events.collect { events += it } }
        runCurrent()

        model.rename("/a.txt", "b.txt", isFolder = false)
        runCurrent()

        assertEquals(listOf(Triple("/a.txt", "b.txt", false)), repo.renameCalls)
        assertTrue(events.contains(FilesEvent.CrudMessage(CrudKind.RENAME, success = true)))
        job.cancel()
    }

    @Test
    fun delete_callsRepo_andEmitsSuccess() = runTest {
        val repo = CrudFakeRepo()
        val model = crudVm(repo)
        val events = mutableListOf<FilesEvent>()
        val job = backgroundScope.launch { model.events.collect { events += it } }
        runCurrent()

        model.delete("/old.txt", isFolder = false)
        runCurrent()

        assertEquals(listOf("/old.txt" to false), repo.deleteCalls)
        assertTrue(events.contains(FilesEvent.CrudMessage(CrudKind.DELETE, success = true)))
        job.cancel()
    }

    @Test
    fun deleteSelected_overTwoPaths_deletesEach_andClearsSelection() = runTest {
        val repo = CrudFakeRepo()
        val model = crudVm(repo)
        val events = mutableListOf<FilesEvent>()
        val job = backgroundScope.launch { model.events.collect { events += it } }
        runCurrent()

        model.toggleSelected("/one.txt")
        model.toggleSelected("/two.txt")
        runCurrent()
        assertEquals(setOf("/one.txt", "/two.txt"), model.uiState.value.selected)

        model.deleteSelected()
        runCurrent()

        assertEquals(2, repo.deleteCalls.size)
        assertTrue(repo.deleteCalls.containsAll(listOf("/one.txt" to false, "/two.txt" to false)))
        assertTrue(model.uiState.value.selected.isEmpty())
        assertFalse(model.uiState.value.selectionMode)
        assertTrue(events.contains(FilesEvent.CrudMessage(CrudKind.DELETE_BATCH, success = true)))
        job.cancel()
    }

    @Test
    fun move_andMoveSelected_callRepo() = runTest {
        val repo = CrudFakeRepo()
        val model = crudVm(repo)

        model.move("/a.txt", "/dst")
        runCurrent()
        assertEquals(listOf("/a.txt" to "/dst"), repo.moveCalls)

        model.toggleSelected("/x.txt")
        model.toggleSelected("/y.txt")
        runCurrent()
        model.moveSelected("/dst")
        runCurrent()

        assertTrue(repo.moveCalls.containsAll(listOf("/x.txt" to "/dst", "/y.txt" to "/dst")))
        assertTrue(model.uiState.value.selected.isEmpty())
    }

    @Test
    fun toggleSelected_addsThenRemovesPath() = runTest {
        val model = crudVm()

        model.toggleSelected("/a.txt")
        runCurrent()
        assertEquals(setOf("/a.txt"), model.uiState.value.selected)
        assertTrue(model.uiState.value.selectionMode)

        model.toggleSelected("/a.txt")
        runCurrent()
        assertTrue(model.uiState.value.selected.isEmpty())
    }

    @Test
    fun clearSelection_emptiesSelection() = runTest {
        val model = crudVm()
        model.toggleSelected("/a.txt")
        runCurrent()
        model.clearSelection()
        runCurrent()
        assertTrue(model.uiState.value.selected.isEmpty())
    }

    @Test
    fun selection_clearedOnOpenFolder() = runTest {
        val model = crudVm()
        model.toggleSelected("/a.txt")
        runCurrent()
        assertEquals(setOf("/a.txt"), model.uiState.value.selected)

        model.onOpenFolder(folder("docs"))
        runCurrent()
        assertTrue(model.uiState.value.selected.isEmpty())
        assertFalse(model.uiState.value.selectionMode)
    }

    @Test
    fun crudFailure_emitsErrorMessage_withoutClearingSelectionInappropriately() = runTest {
        val repo = CrudFakeRepo().apply {
            crudOutcome = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        }
        val model = crudVm(repo)
        val events = mutableListOf<FilesEvent>()
        val job = backgroundScope.launch { model.events.collect { events += it } }
        runCurrent()

        model.toggleSelected("/keep.txt")
        runCurrent()

        // A single rename fails - it must report failure but leave the (unrelated) selection intact.
        model.rename("/a.txt", "b.txt", isFolder = false)
        runCurrent()

        assertTrue(events.contains(FilesEvent.CrudMessage(CrudKind.RENAME, success = false)))
        assertEquals(setOf("/keep.txt"), model.uiState.value.selected)
        job.cancel()
    }
}
