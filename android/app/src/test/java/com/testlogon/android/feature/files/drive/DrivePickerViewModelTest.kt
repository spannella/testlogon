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
import kotlinx.coroutines.awaitCancellation
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
 * AND-336 - unit tests for [DrivePickerViewModel] with a fake [GoogleDriveRepository].
 *
 * ANTI-HANG DISCIPLINE: the VM has NO poll loop (status re-check is a single call); tests use
 * runCurrent() only - NEVER advanceUntilIdle. One-shot events are collected on backgroundScope.launch.
 * Distinct fake-helper names from any other feature fake.
 */
class DrivePickerViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    /** A fake [GoogleDriveRepository] serving configured results + recording arguments. */
    private class FakeDriveRepo(
        var statusResult: ApiResult<DriveStatus> = ApiResult.Success(DriveStatus(connected = true)),
        var connectResult: ApiResult<String> = ApiResult.Success("https://consent.example"),
        var filesResult: ApiResult<DriveFilesPage> = ApiResult.Success(DriveFilesPage(emptyList())),
        var importResult: ApiResult<DriveImportResult> = ApiResult.Success(DriveImportResult(ok = true, path = "/p")),
    ) : GoogleDriveRepository {
        val listFolderIds = mutableListOf<String?>()
        var importCount = 0
        val importedTargets = mutableListOf<String?>()

        override suspend fun status(): ApiResult<DriveStatus> = statusResult
        override suspend fun connectUrl(): ApiResult<String> = connectResult
        override suspend fun completeCallback(code: String, state: String?): ApiResult<DriveStatus> = statusResult
        override suspend fun disconnect(): ApiResult<Unit> = ApiResult.Success(Unit)
        override suspend fun listFiles(
            folderId: String?,
            query: String?,
            pageToken: String?,
        ): ApiResult<DriveFilesPage> {
            listFolderIds += folderId
            return filesResult
        }

        override suspend fun import(fileId: String, targetFolderPath: String?): ApiResult<DriveImportResult> {
            importCount++
            importedTargets += targetFolderPath
            return importResult
        }
    }

    private fun driveFolder(id: String, name: String = id) = DriveFile(id = id, name = name, isFolder = true)
    private fun driveDoc(id: String, name: String = id) = DriveFile(id = id, name = name, isFolder = false)

    private fun TestScope.vm(
        repo: FakeDriveRepo = FakeDriveRepo(),
        saved: SavedStateHandle = SavedStateHandle(),
    ): DrivePickerViewModel {
        val model = DrivePickerViewModel(repo, saved)
        runCurrent() // let the init status probe settle.
        return model
    }

    @Test
    fun init_connected_listsRoot_browsing() = runTest {
        val repo = FakeDriveRepo(
            statusResult = ApiResult.Success(DriveStatus(connected = true)),
            filesResult = ApiResult.Success(DriveFilesPage(listOf(driveDoc("d1")))),
        )
        val model = vm(repo)
        val state = model.uiState.value
        assertTrue(state is DrivePickerUiState.Browsing)
        assertEquals(listOf<String?>(null), repo.listFolderIds) // root listed with null folderId
        assertEquals(listOf("d1"), (state as DrivePickerUiState.Browsing).files.map { it.id })
    }

    @Test
    fun init_notConnected_showsNotConnected() = runTest {
        val repo = FakeDriveRepo(statusResult = ApiResult.Success(DriveStatus(connected = false)))
        val model = vm(repo)
        assertTrue(model.uiState.value is DrivePickerUiState.NotConnected)
    }

    @Test
    fun onConnect_emitsOpenUrl_withAuthUrl() = runTest {
        val repo = FakeDriveRepo(
            statusResult = ApiResult.Success(DriveStatus(connected = false)),
            connectResult = ApiResult.Success("https://consent.example/x"),
        )
        val model = vm(repo)
        val events = mutableListOf<DrivePickerEvent>()
        val job = backgroundScope.launch { model.events.collect { events += it } }
        runCurrent()

        model.onConnect()
        runCurrent()
        assertEquals(DrivePickerEvent.OpenUrl("https://consent.example/x"), events.lastOrNull())
        job.cancel()
    }

    @Test
    fun refreshStatus_afterConnect_movesToBrowsing() = runTest {
        val repo = FakeDriveRepo(statusResult = ApiResult.Success(DriveStatus(connected = false)))
        val model = vm(repo)
        assertTrue(model.uiState.value is DrivePickerUiState.NotConnected)

        // Simulate the user having connected in the external browser; the backend now reports connected.
        repo.statusResult = ApiResult.Success(DriveStatus(connected = true))
        model.refreshStatus()
        runCurrent()
        assertTrue(model.uiState.value is DrivePickerUiState.Browsing)
    }

    @Test
    fun onOpenFolder_navigates_andPushesBreadcrumb() = runTest {
        val repo = FakeDriveRepo(filesResult = ApiResult.Success(DriveFilesPage(emptyList())))
        val model = vm(repo)

        model.onOpenFolder(driveFolder("fld_1", "Reports"))
        runCurrent()
        val state = model.uiState.value as DrivePickerUiState.Browsing
        assertEquals("fld_1", state.folderId)
        // root crumb (Drive) + Reports crumb.
        assertEquals(listOf("Drive", "Reports"), state.breadcrumbs.map { it.name })
        assertEquals("fld_1", repo.listFolderIds.last())
    }

    @Test
    fun onImport_emitsImported_andClearsSpinner() = runTest {
        val repo = FakeDriveRepo(
            filesResult = ApiResult.Success(DriveFilesPage(listOf(driveDoc("d1")))),
            importResult = ApiResult.Success(DriveImportResult(ok = true, path = "/docs/d1")),
        )
        val saved = SavedStateHandle(mapOf(DrivePickerViewModel.KEY_TARGET to "/docs"))
        val model = vm(repo, saved)
        val events = mutableListOf<DrivePickerEvent>()
        val job = backgroundScope.launch { model.events.collect { events += it } }
        runCurrent()

        model.onImport(driveDoc("d1"))
        runCurrent()
        assertEquals(DrivePickerEvent.Imported("/docs/d1"), events.lastOrNull())
        assertEquals(listOf("/docs"), repo.importedTargets)
        assertNull((model.uiState.value as DrivePickerUiState.Browsing).importing)
        job.cancel()
    }

    @Test
    fun onImport_doubleSendGuard_importsOnce() = runTest {
        // A never-completing import keeps importing != null so a second tap is ignored.
        val repo = object : GoogleDriveRepository {
            var count = 0
            override suspend fun status() = ApiResult.Success(DriveStatus(connected = true))
            override suspend fun connectUrl() = ApiResult.Success("u")
            override suspend fun completeCallback(code: String, state: String?) = status()
            override suspend fun disconnect() = ApiResult.Success(Unit)
            override suspend fun listFiles(folderId: String?, query: String?, pageToken: String?) =
                ApiResult.Success(DriveFilesPage(listOf(driveDoc("d1"))))
            override suspend fun import(fileId: String, targetFolderPath: String?): ApiResult<DriveImportResult> {
                count++
                awaitCancellation()
            }
        }
        val model = DrivePickerViewModel(repo, SavedStateHandle())
        runCurrent()

        model.onImport(driveDoc("d1"))
        runCurrent()
        assertEquals("d1", (model.uiState.value as DrivePickerUiState.Browsing).importing)
        model.onImport(driveDoc("d1")) // ignored: an import is in flight.
        runCurrent()
        assertEquals(1, repo.count)
    }

    @Test
    fun init_statusFailure_showsError() = runTest {
        val repo = FakeDriveRepo(statusResult = ApiResult.Failure(ApiError(status = 500, message = "boom")))
        val model = vm(repo)
        val state = model.uiState.value
        assertTrue(state is DrivePickerUiState.Error)
        assertEquals("boom", (state as DrivePickerUiState.Error).message)
    }
}
