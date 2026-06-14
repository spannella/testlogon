package com.testlogon.android.feature.files.drive

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.files.drive.data.GoogleDriveRepository
import com.testlogon.android.feature.files.drive.model.DriveFile
import com.testlogon.android.feature.files.drive.model.DriveFilesPage
import com.testlogon.android.feature.files.drive.model.DriveImportResult
import com.testlogon.android.feature.files.drive.model.DriveStatus
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-338 - additional [DrivePickerViewModel] coverage beyond [DrivePickerViewModelTest].
 *
 * These ADD the folder-navigation + secondary-action gaps the AND-336 wave left untested: onBreadcrumb
 * and onUp pop the crumb stack and re-list; onSearch re-lists the current folder with the query; onImport
 * failure clears the spinner and surfaces an inline error WITHOUT emitting Imported; onDisconnect returns
 * to NotConnected; and a status NetworkError maps to the offline Error panel.
 *
 * ANTI-HANG DISCIPLINE (same as the sibling test): no poll loop; runCurrent() only - NEVER
 * advanceUntilIdle; one-shot events on backgroundScope.launch. Distinct fake-helper names.
 */
class DrivePickerViewModelGapsTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    /** A fake [GoogleDriveRepository] recording list / import args (distinct from FakeDriveRepo). */
    private class GapsDriveRepo(
        var statusResult: ApiResult<DriveStatus> = ApiResult.Success(DriveStatus(connected = true)),
        var filesResult: ApiResult<DriveFilesPage> = ApiResult.Success(DriveFilesPage(emptyList())),
        var importResult: ApiResult<DriveImportResult> =
            ApiResult.Success(DriveImportResult(ok = true, path = "/p")),
        var disconnectResult: ApiResult<Unit> = ApiResult.Success(Unit),
    ) : GoogleDriveRepository {
        val listFolderIds = mutableListOf<String?>()
        val listQueries = mutableListOf<String?>()
        var importCount = 0

        override suspend fun status(): ApiResult<DriveStatus> = statusResult
        override suspend fun connectUrl(): ApiResult<String> = ApiResult.Success("u")
        override suspend fun completeCallback(code: String, state: String?): ApiResult<DriveStatus> = statusResult
        override suspend fun disconnect(): ApiResult<Unit> = disconnectResult
        override suspend fun listFiles(
            folderId: String?,
            query: String?,
            pageToken: String?,
        ): ApiResult<DriveFilesPage> {
            listFolderIds += folderId
            listQueries += query
            return filesResult
        }

        override suspend fun import(fileId: String, targetFolderPath: String?): ApiResult<DriveImportResult> {
            importCount++
            return importResult
        }
    }

    private fun driveFolder(id: String, name: String = id) = DriveFile(id = id, name = name, isFolder = true)
    private fun driveDoc(id: String, name: String = id) = DriveFile(id = id, name = name, isFolder = false)

    private fun TestScope.gapsVm(
        repo: GapsDriveRepo = GapsDriveRepo(),
        saved: SavedStateHandle = SavedStateHandle(),
    ): DrivePickerViewModel {
        val model = DrivePickerViewModel(repo, saved)
        runCurrent() // let the init status probe settle.
        return model
    }

    @Test
    fun onBreadcrumb_truncatesStack_andReListsThatFolder() = runTest {
        val repo = GapsDriveRepo(filesResult = ApiResult.Success(DriveFilesPage(emptyList())))
        val model = gapsVm(repo)

        model.onOpenFolder(driveFolder("a", "A"))
        runCurrent()
        model.onOpenFolder(driveFolder("b", "B"))
        runCurrent()
        val deep = model.uiState.value as DrivePickerUiState.Browsing
        assertEquals(listOf("Drive", "A", "B"), deep.breadcrumbs.map { it.name })

        // jump back to crumb index 1 (folder A).
        model.onBreadcrumb(1)
        runCurrent()
        val state = model.uiState.value as DrivePickerUiState.Browsing
        assertEquals(listOf("Drive", "A"), state.breadcrumbs.map { it.name })
        assertEquals("a", state.folderId)
        assertEquals("a", repo.listFolderIds.last())
    }

    @Test
    fun onUp_belowRoot_popsOneFolder() = runTest {
        val repo = GapsDriveRepo(filesResult = ApiResult.Success(DriveFilesPage(emptyList())))
        val model = gapsVm(repo)

        model.onOpenFolder(driveFolder("a", "A"))
        runCurrent()
        model.onUp()
        runCurrent()
        val state = model.uiState.value as DrivePickerUiState.Browsing
        // back at the Drive root crumb.
        assertEquals(listOf("Drive"), state.breadcrumbs.map { it.name })
        assertNull(state.folderId)
    }

    @Test
    fun onUp_atRoot_isNoOp() = runTest {
        val repo = GapsDriveRepo(filesResult = ApiResult.Success(DriveFilesPage(emptyList())))
        val model = gapsVm(repo)
        // init already listed the root once.
        val listsBefore = repo.listFolderIds.size

        model.onUp()
        runCurrent()
        // no extra listing at the root.
        assertEquals(listsBefore, repo.listFolderIds.size)
    }

    @Test
    fun onSearch_reListsCurrentFolder_withQuery() = runTest {
        val repo = GapsDriveRepo(filesResult = ApiResult.Success(DriveFilesPage(emptyList())))
        val model = gapsVm(repo)

        model.onSearch("report")
        runCurrent()
        val state = model.uiState.value as DrivePickerUiState.Browsing
        assertEquals("report", state.query)
        assertEquals("report", repo.listQueries.last())
    }

    @Test
    fun onImport_failure_clearsSpinner_setsError_andEmitsNoImported() = runTest {
        val repo = GapsDriveRepo(
            filesResult = ApiResult.Success(DriveFilesPage(listOf(driveDoc("d1")))),
            importResult = ApiResult.Failure(ApiError(status = 500, message = "nope")),
        )
        val saved = SavedStateHandle(mapOf(DrivePickerViewModel.KEY_TARGET to "/docs"))
        val model = gapsVm(repo, saved)
        val events = mutableListOf<DrivePickerEvent>()
        val job = backgroundScope.launch { model.events.collect { events += it } }
        runCurrent()

        model.onImport(driveDoc("d1"))
        runCurrent()

        val state = model.uiState.value as DrivePickerUiState.Browsing
        assertNull(state.importing)
        assertEquals("nope", state.error)
        // no Imported event on failure.
        assertTrue(events.none { it is DrivePickerEvent.Imported })
        job.cancel()
    }

    @Test
    fun onDisconnect_success_returnsToNotConnected() = runTest {
        val repo = GapsDriveRepo(disconnectResult = ApiResult.Success(Unit))
        val model = gapsVm(repo)
        assertTrue(model.uiState.value is DrivePickerUiState.Browsing)

        model.onDisconnect()
        runCurrent()
        assertTrue(model.uiState.value is DrivePickerUiState.NotConnected)
    }

    @Test
    fun init_statusNetworkError_showsOfflineError() = runTest {
        val repo = GapsDriveRepo(statusResult = ApiResult.NetworkError(java.io.IOException("offline")))
        val model = gapsVm(repo)
        val state = model.uiState.value
        assertTrue(state is DrivePickerUiState.Error)
        assertTrue((state as DrivePickerUiState.Error).message.isNotBlank())
    }
}
