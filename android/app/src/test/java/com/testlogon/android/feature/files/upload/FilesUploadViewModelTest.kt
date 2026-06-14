package com.testlogon.android.feature.files.upload

import android.net.Uri
import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.files.CompleteUploadRequest
import com.testlogon.android.core.model.files.CreateFolderRequest
import com.testlogon.android.core.model.files.DeleteFolderDto
import com.testlogon.android.core.model.files.FileEntryDto
import com.testlogon.android.core.model.files.FileListDto
import com.testlogon.android.core.model.files.FileSearchDto
import com.testlogon.android.core.model.files.FileTextSearchDto
import com.testlogon.android.core.model.files.MoveRequest
import com.testlogon.android.core.model.files.MoveResultDto
import com.testlogon.android.core.model.files.OkRespDto
import com.testlogon.android.core.model.files.PresignRequest
import com.testlogon.android.core.model.files.PresignResponse
import com.testlogon.android.core.model.files.RenameRequest
import com.testlogon.android.core.network.files.FilesApi
import com.testlogon.android.data.upload.StorageUploadClient
import com.testlogon.android.feature.files.data.FolderRefreshBus
import com.testlogon.android.core.testing.MainDispatcherRule
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import okhttp3.RequestBody
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.mockito.Mockito

/**
 * AND-333 - unit tests for [FilesUploadViewModel]. The VM is a thin delegate over the singleton
 * [UploadCoordinator]; these tests assert enqueue / cancel / retry flow through to the coordinator and
 * that the exposed [FilesUploadViewModel.uploadJobs] StateFlow mirrors the coordinator's jobs. Bounded
 * runCurrent only; no advanceUntilIdle.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class FilesUploadViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private class StubFilesApi : FilesApi {
        override suspend fun presignUpload(body: PresignRequest) = PresignResponse(
            upload_url = "https://s/put", key = "k", ticket_id = "t", path = body.path,
        )
        override suspend fun completeUpload(body: CompleteUploadRequest) =
            FileEntryDto(name = "n.bin", path = body.path, type = "file")
        override suspend fun list(path: String, limit: Int?, cursor: String?, sortBy: String?, sortDir: String?) =
            FileListDto(path = path)
        override suspend fun info(path: String) = FileEntryDto(name = "", path = path, type = "file")
        // AND-334 - download is unused here; trivial empty-body stub.
        override suspend fun download(path: String) =
            retrofit2.Response.success(ByteArray(0).toResponseBody())
        override suspend fun search(prefix: String, limit: Int) = FileSearchDto(prefix = prefix)
        override suspend fun searchText(query: String, limit: Int) = FileTextSearchDto(query = query)
        override suspend fun createFolder(body: CreateFolderRequest) = OkRespDto(ok = true)
        override suspend fun renameFile(body: RenameRequest) = MoveResultDto(ok = true)
        override suspend fun renameFolder(body: RenameRequest) = MoveResultDto(ok = true)
        override suspend fun move(body: MoveRequest) = MoveResultDto(ok = true)
        override suspend fun deleteFile(path: String) = OkRespDto(ok = true)
        override suspend fun deleteFolder(path: String) = DeleteFolderDto(ok = true)
    }

    private class GatedPut : StoragePut {
        var gate: CompletableDeferred<Unit>? = null
        override suspend fun put(url: String, contentType: String, body: RequestBody): StorageUploadClient.PutResult {
            gate?.await()
            return StorageUploadClient.PutResult(success = true, httpStatus = 200)
        }
    }

    private class StubSource : UploadSource {
        override fun metadata(uri: Uri) =
            UploadMetadata(displayName = "a.bin", mimeType = "application/octet-stream", sizeBytes = 10L)
        override fun requestBody(uri: Uri, mimeType: String, sizeBytes: Long, onProgress: (Long) -> Unit): RequestBody {
            onProgress(sizeBytes)
            return Mockito.mock(RequestBody::class.java)
        }
    }

    private fun uri() = Mockito.mock(Uri::class.java)

    // AND-334 - distinct helper name; the download stub returns an empty body that is never read here.
    private fun emptyResponseBody() = ByteArray(0).toResponseBody()

    @Test
    fun onFilesPicked_enqueuesOnePerUri_targetingPath() = runTest {
        val put = GatedPut().apply { gate = CompletableDeferred() } // hold them in-flight.
        val coordinator = UploadCoordinator(
            StubFilesApi(), put, StubSource(), FolderRefreshBus(), StandardTestDispatcher(testScheduler),
        )
        val vm = FilesUploadViewModel(coordinator, SavedStateHandle())

        vm.onFilesPicked(listOf(uri(), uri()), "/docs")
        runCurrent()

        assertEquals(2, vm.uploadJobs.value.size)
        assertTrue(vm.uploadJobs.value.all { it.targetFolderPath == "/docs" })
        put.gate?.complete(Unit)
    }

    @Test
    fun onCancel_delegatesToCoordinator() = runTest {
        val put = GatedPut().apply { gate = CompletableDeferred() }
        val coordinator = UploadCoordinator(
            StubFilesApi(), put, StubSource(), FolderRefreshBus(), StandardTestDispatcher(testScheduler),
        )
        val vm = FilesUploadViewModel(coordinator, SavedStateHandle())

        vm.onFilesPicked(listOf(uri()), "/docs")
        runCurrent()
        val id = vm.uploadJobs.value.single().id

        vm.onCancel(id)
        runCurrent()
        assertEquals(UploadState.CANCELLED, vm.uploadJobs.value.single().state)
        put.gate?.complete(Unit)
    }

    @Test
    fun onRetry_delegatesToCoordinator() = runTest {
        // No gate -> the upload completes; retry on a DONE job is a guarded no-op but still delegates.
        val coordinator = UploadCoordinator(
            StubFilesApi(), GatedPut(), StubSource(), FolderRefreshBus(), StandardTestDispatcher(testScheduler),
        )
        val vm = FilesUploadViewModel(coordinator, SavedStateHandle())

        vm.onFilesPicked(listOf(uri()), "/docs")
        runCurrent()
        val id = vm.uploadJobs.value.single().id
        assertEquals(UploadState.DONE, vm.uploadJobs.value.single().state)

        vm.onRetry(id) // delegates; double-send guard keeps the DONE job DONE.
        runCurrent()
        assertEquals(UploadState.DONE, vm.uploadJobs.value.single().state)
    }
}
