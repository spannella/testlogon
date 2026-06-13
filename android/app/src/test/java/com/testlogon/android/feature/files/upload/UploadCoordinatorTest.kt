package com.testlogon.android.feature.files.upload

import android.net.Uri
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
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.mockito.Mockito

/**
 * AND-333 - unit tests for [UploadCoordinator].
 *
 * ANTI-HANG DISCIPLINE: the coordinator has NO poll loop - the only suspension is the network / IO
 * legs (here: fakes whose pause is an explicit gate the test releases). Flow collection uses
 * backgroundScope.launch and progress is asserted off the captured snapshots; we drive with bounded
 * runCurrent / advanceTimeBy and NEVER advanceUntilIdle. The coordinator runs on the test's
 * StandardTestDispatcher so its child coroutines are deterministically schedulable.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class UploadCoordinatorTest {

    // ---- distinct fake-helper names ----

    private class RecordingFilesApi : FilesApi {
        val presignPaths = mutableListOf<String>()
        val completeBodies = mutableListOf<CompleteUploadRequest>()
        var presignCalls = 0
        var completeCalls = 0
        var presignError: Throwable? = null

        override suspend fun presignUpload(body: PresignRequest): PresignResponse {
            presignCalls++
            presignPaths += body.path
            presignError?.let { throw it }
            return PresignResponse(
                upload_url = "https://storage.example/put",
                key = "k-${body.path}",
                ticket_id = "t-123",
                path = body.path,
                content_type = body.content_type,
            )
        }

        override suspend fun completeUpload(body: CompleteUploadRequest): FileEntryDto {
            completeCalls++
            completeBodies += body
            // Return a CANONICAL path that differs from the request path so the test proves the coordinator
            // adopts the server-returned node path (FR-8), not the locally-built object path.
            return FileEntryDto(name = "server-name.bin", path = "/docs/server-name.bin", type = "file", size = 10L)
        }

        // ---- unused reads / mutations ----
        override suspend fun list(path: String, limit: Int?, cursor: String?, sortBy: String?, sortDir: String?) =
            FileListDto(path = path)
        override suspend fun info(path: String) = FileEntryDto(name = "", path = path, type = "file")
        override suspend fun search(prefix: String, limit: Int) = FileSearchDto(prefix = prefix)
        override suspend fun searchText(query: String, limit: Int) = FileTextSearchDto(query = query)
        override suspend fun createFolder(body: CreateFolderRequest) = OkRespDto(ok = true)
        override suspend fun renameFile(body: RenameRequest) = MoveResultDto(ok = true)
        override suspend fun renameFolder(body: RenameRequest) = MoveResultDto(ok = true)
        override suspend fun move(body: MoveRequest) = MoveResultDto(ok = true)
        override suspend fun deleteFile(path: String) = OkRespDto(ok = true)
        override suspend fun deleteFolder(path: String) = DeleteFolderDto(ok = true)
    }

    private class GatedStoragePut : StoragePut {
        /** When set, put() suspends on this gate until the test completes it (to hold a permit). */
        var gate: CompletableDeferred<Unit>? = null
        var result = StorageUploadClient.PutResult(success = true, httpStatus = 200)
        var calls = 0

        override suspend fun put(url: String, contentType: String, body: RequestBody): StorageUploadClient.PutResult {
            calls++
            gate?.await()
            return result
        }
    }

    private class StubUploadSource(
        private val size: Long = 100L,
    ) : UploadSource {
        override fun metadata(uri: Uri) =
            UploadMetadata(displayName = "photo.jpg", mimeType = "image/jpeg", sizeBytes = size)

        override fun requestBody(
            uri: Uri,
            mimeType: String,
            sizeBytes: Long,
            onProgress: (bytesSent: Long) -> Unit,
        ): RequestBody {
            // Emit a couple of progress ticks so UPLOADING progress is observable.
            onProgress(sizeBytes / 2)
            onProgress(sizeBytes)
            return Mockito.mock(RequestBody::class.java)
        }
    }

    private fun fakeUri(): Uri = Mockito.mock(Uri::class.java)

    @Test
    fun happyPath_reachesDone_withCorrectContract_andSignalsRefresh() = runTest {
        val api = RecordingFilesApi()
        val bus = FolderRefreshBus()
        val dispatcher = StandardTestDispatcher(testScheduler)
        val coordinator = UploadCoordinator(api, GatedStoragePut(), StubUploadSource(), bus, dispatcher)

        val signals = mutableListOf<String>()
        backgroundScope.launch { bus.refreshes.collect { signals += it } }

        val id = coordinator.enqueue(fakeUri(), "/docs")
        runCurrent()

        val job = coordinator.jobs.value.single()
        assertEquals(UploadState.DONE, job.state)
        // the server-returned canonical path is authoritative (NOT the locally-built object path).
        assertEquals("/docs/server-name.bin", job.resultPath)
        assertEquals(1f, job.progress, 0.001f)

        // presign got the object path "<folder>/<name>".
        assertEquals(listOf("/docs/photo.jpg"), api.presignPaths)
        // complete carried {path,key,ticket_id} from the presign response.
        val complete = api.completeBodies.single()
        assertEquals("/docs/photo.jpg", complete.path)
        assertEquals("k-/docs/photo.jpg", complete.key)
        assertEquals("t-123", complete.ticket_id)
        // the destination folder was signalled for re-paging.
        assertEquals(listOf("/docs"), signals)
        // id is stable / non-blank.
        assertTrue(id.isNotBlank())
    }

    @Test
    fun lifecycle_visitsUploadingWithProgress_thenConfirming_thenDone() = runTest {
        val api = RecordingFilesApi()
        val put = GatedStoragePut().apply { gate = CompletableDeferred() }
        val dispatcher = StandardTestDispatcher(testScheduler)
        val coordinator = UploadCoordinator(api, put, StubUploadSource(), FolderRefreshBus(), dispatcher)

        coordinator.enqueue(fakeUri(), "/docs")
        runCurrent() // runs presign -> UPLOADING -> (gated) PUT, where it parks.

        val uploading = coordinator.jobs.value.single()
        assertEquals(UploadState.UPLOADING, uploading.state)
        // the streaming body reported progress to completion before the gated PUT returned.
        assertEquals(1f, uploading.progress, 0.001f)
        assertEquals(0, api.completeCalls) // confirm not yet sent (double-send window not entered).

        put.gate?.complete(Unit)
        runCurrent() // PUT returns -> CONFIRMING -> complete -> DONE.
        assertEquals(UploadState.DONE, coordinator.jobs.value.single().state)
        assertEquals(1, api.completeCalls)
    }

    @Test
    fun presignFailure_marksFailed_andRetryRestartsFromPresign() = runTest {
        val api = RecordingFilesApi().apply { presignError = retrofit2.HttpException(errorResponse(422)) }
        val put = GatedStoragePut()
        val dispatcher = StandardTestDispatcher(testScheduler)
        val coordinator = UploadCoordinator(api, put, StubUploadSource(), FolderRefreshBus(), dispatcher)

        val id = coordinator.enqueue(fakeUri(), "/docs")
        runCurrent()
        assertEquals(UploadState.FAILED, coordinator.jobs.value.single().state)
        assertEquals(1, api.presignCalls)

        // retry restarts from presign (same id), this time succeeding.
        api.presignError = null
        coordinator.retry(id)
        runCurrent()
        assertEquals(UploadState.DONE, coordinator.jobs.value.single().state)
        assertEquals(id, coordinator.jobs.value.single().id)
        assertEquals(2, api.presignCalls)
    }

    @Test
    fun doubleSendGuard_doneJobIsNotRestartedByRetry() = runTest {
        val api = RecordingFilesApi()
        val dispatcher = StandardTestDispatcher(testScheduler)
        val coordinator = UploadCoordinator(api, GatedStoragePut(), StubUploadSource(), FolderRefreshBus(), dispatcher)

        val id = coordinator.enqueue(fakeUri(), "/docs")
        runCurrent()
        assertEquals(UploadState.DONE, coordinator.jobs.value.single().state)
        assertEquals(1, api.completeCalls)

        // retry on a DONE job is a no-op (non-idempotent complete is never re-sent).
        coordinator.retry(id)
        runCurrent()
        assertEquals(1, api.completeCalls)
        assertEquals(1, api.presignCalls)
    }

    @Test
    fun cancel_marksCancelled() = runTest {
        val api = RecordingFilesApi()
        val put = GatedStoragePut().apply { gate = CompletableDeferred() }
        val dispatcher = StandardTestDispatcher(testScheduler)
        val coordinator = UploadCoordinator(api, put, StubUploadSource(), FolderRefreshBus(), dispatcher)

        val id = coordinator.enqueue(fakeUri(), "/docs")
        runCurrent() // advances into the gated PUT (held open).
        assertEquals(UploadState.UPLOADING, coordinator.jobs.value.single().state)

        coordinator.cancel(id)
        runCurrent()
        assertEquals(UploadState.CANCELLED, coordinator.jobs.value.single().state)
        assertNull(coordinator.jobs.value.single().error)
        // confirm was never sent.
        assertEquals(0, api.completeCalls)
        put.gate?.complete(Unit)
    }

    @Test
    fun boundedConcurrency_twoActive_oneQueued() = runTest {
        val api = RecordingFilesApi()
        val put = GatedStoragePut().apply { gate = CompletableDeferred() } // hold all PUTs open.
        val dispatcher = StandardTestDispatcher(testScheduler)
        val coordinator = UploadCoordinator(api, put, StubUploadSource(), FolderRefreshBus(), dispatcher)

        coordinator.enqueue(fakeUri(), "/a")
        coordinator.enqueue(fakeUri(), "/b")
        coordinator.enqueue(fakeUri(), "/c")
        runCurrent()

        val states = coordinator.jobs.value.map { it.state }
        // limit 2 -> two jobs are UPLOADING (holding the gated PUT), one still QUEUED.
        assertEquals(2, states.count { it == UploadState.UPLOADING })
        assertEquals(1, states.count { it == UploadState.QUEUED })

        // release the first two; the queued one then acquires a permit and runs.
        put.gate?.complete(Unit)
        runCurrent()
        assertTrue(coordinator.jobs.value.all { it.state == UploadState.DONE })
    }

    private fun errorResponse(code: Int): retrofit2.Response<Any> =
        retrofit2.Response.error(
            code,
            "{\"detail\":\"err\"}".toResponseBody("application/json".toMediaType()),
        )
}
