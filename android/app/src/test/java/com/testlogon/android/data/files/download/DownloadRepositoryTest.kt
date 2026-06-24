package com.testlogon.android.data.files.download

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.files.CompleteUploadRequest
import com.testlogon.android.core.model.files.CreateFolderRequest
import com.testlogon.android.core.model.files.DeleteFolderDto
import com.testlogon.android.core.model.files.FileEntryDto
import com.testlogon.android.core.model.files.FileListDto
import com.testlogon.android.core.model.files.FileNode
import com.testlogon.android.core.model.files.FileNodeType
import com.testlogon.android.core.model.files.FileSearchDto
import com.testlogon.android.core.model.files.FileTextSearchDto
import com.testlogon.android.core.model.files.MoveRequest
import com.testlogon.android.core.model.files.MoveResultDto
import com.testlogon.android.core.model.files.OkRespDto
import com.testlogon.android.core.model.files.PresignRequest
import com.testlogon.android.core.model.files.PresignResponse
import com.testlogon.android.core.model.files.RenameRequest
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.files.FilesApi
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.mockito.Mockito
import retrofit2.Response
import java.time.Instant

/**
 * AND-334 - unit tests for [DownloadRepositoryImpl.download].
 *
 * ANTI-HANG DISCIPLINE: the download flow is bounded (it ends when the byte stream is exhausted - there
 * is NO poll loop), so each test simply collects the cold flow to a List inside runTest on the test's
 * StandardTestDispatcher. We never advanceUntilIdle. A real [FileCacheStore] is built over a JUnit
 * TemporaryFolder by mocking [android.content.Context.cacheDir] to point at that folder (the only Context
 * member FileCacheStore reads). A hand-rolled fake FilesApi (distinct from the AND-332 FakeFilesApi)
 * serves a settable download body and counts calls so the cache-hit test can assert zero network.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class DownloadRepositoryTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val parser = ApiErrorParser(Moshi.Builder().build())

    // ---- distinct fake-helper names (must not shadow the AND-332 FakeFilesApi) ----

    private class StubDownloadApi : FilesApi {
        var downloadCalls = 0
        var lastPath: String? = null

        /** The response served by [download]; default is a small known body. */
        var response: () -> Response<ResponseBody> = {
            Response.success(BYTES.toResponseBody("application/octet-stream".toMediaType()))
        }

        /** When set, [download] throws this instead of returning [response]. */
        var throwable: Throwable? = null

        override suspend fun download(path: String): Response<ResponseBody> {
            downloadCalls++
            lastPath = path
            throwable?.let { throw it }
            return response()
        }

        // ---- unused verbs ----
        override suspend fun list(path: String, limit: Int?, cursor: String?, sortBy: String?, sortDir: String?) =
            FileListDto(path = path, items = emptyList(), cursor = null)
        override suspend fun info(path: String): FileEntryDto = error("unused in AND-334 download tests")
        override suspend fun search(prefix: String, limit: Int) = FileSearchDto(prefix = prefix, results = emptyList())
        override suspend fun searchText(query: String, limit: Int) =
            FileTextSearchDto(query = query, results = emptyList())
        override suspend fun createFolder(body: CreateFolderRequest): OkRespDto = error("unused")
        override suspend fun renameFile(body: RenameRequest): MoveResultDto = error("unused")
        override suspend fun renameFolder(body: RenameRequest): MoveResultDto = error("unused")
        override suspend fun move(body: MoveRequest): MoveResultDto = error("unused")
        override suspend fun copy(body: MoveRequest): MoveResultDto = error("unused")
        override suspend fun deleteFile(path: String): OkRespDto = error("unused")
        override suspend fun deleteFolder(path: String): DeleteFolderDto = error("unused")
        override suspend fun presignUpload(body: PresignRequest): PresignResponse = error("unused")
        override suspend fun completeUpload(body: CompleteUploadRequest): FileEntryDto = error("unused")
    }

    /** A real [FileCacheStore] backed by [tmp] (its only Context dependency is cacheDir). */
    private fun cacheStore(): FileCacheStore {
        val context = Mockito.mock(android.content.Context::class.java)
        Mockito.`when`(context.cacheDir).thenReturn(tmp.root)
        return FileCacheStore(context, maxBytes = FileCacheStore.DEFAULT_MAX_BYTES)
    }

    // The repo's IO dispatcher is the test scheduler's StandardTestDispatcher so the flowOn(io) upstream
    // is deterministically driven by runTest (toList suspends until the bounded flow completes).
    private fun TestScope.repo(api: FilesApi, cache: FileCacheStore): DownloadRepositoryImpl =
        DownloadRepositoryImpl(api = api, cache = cache, errorParser = parser, io = StandardTestDispatcher(testScheduler))

    private fun fileNode(
        name: String = "report.bin",
        path: String = "/docs/report.bin",
        contentType: String? = "application/pdf",
        updatedAt: Instant? = Instant.ofEpochMilli(1_000L),
    ) = FileNode(
        path = path,
        name = name,
        type = FileNodeType.FILE,
        contentType = contentType,
        updatedAt = updatedAt,
    )

    @Test
    fun download_emitsInProgressThenSuccess_withBytesAndNodeMetadata() = runTest {
        val api = StubDownloadApi()
        val cache = cacheStore()
        val node = fileNode(name = "report.bin", contentType = "application/pdf")

        val emissions = repo(api, cache).download(node).toList()

        // at least one InProgress then a terminal Success.
        assertTrue(emissions.any { it is DownloadStatus.InProgress })
        val success = emissions.last() as DownloadStatus.Success
        val cached = success.cached
        // displayName + mimeType come from the FileNode (the endpoint content-type is misleading).
        assertEquals("report.bin", cached.displayName)
        assertEquals("application/pdf", cached.mimeType)
        assertEquals(node.path, cached.path)
        // the committed file on disk holds exactly the served bytes.
        assertArrayEquals(BYTES, cached.file.readBytes())
        assertEquals(1, api.downloadCalls)
        assertEquals(node.path, api.lastPath)
    }

    @Test
    fun download_secondCallSameVersion_isCacheHit_noNetwork() = runTest {
        val api = StubDownloadApi()
        val cache = cacheStore()
        val node = fileNode(updatedAt = Instant.ofEpochMilli(42L))

        // first download populates the cache (1 network call).
        val first = repo(api, cache).download(node).toList()
        assertTrue(first.last() is DownloadStatus.Success)
        assertEquals(1, api.downloadCalls)

        // second download of the SAME (path + version) is a pure cache hit: a single Success, no network.
        val second = repo(api, cache).download(node).toList()
        assertEquals(1, second.size)
        val hit = second.single() as DownloadStatus.Success
        assertArrayEquals(BYTES, hit.cached.file.readBytes())
        assertEquals("report.bin", hit.cached.displayName)
        // call count is unchanged - no second API hit.
        assertEquals(1, api.downloadCalls)
    }

    @Test
    fun download_changedVersion_missesStaleEntry_andRefetches() = runTest {
        val api = StubDownloadApi()
        val cache = cacheStore()

        repo(api, cache).download(fileNode(updatedAt = Instant.ofEpochMilli(1L))).toList()
        assertEquals(1, api.downloadCalls)

        // a newer updatedAt produces a new cache key -> miss -> a fresh network fetch.
        repo(api, cache).download(fileNode(updatedAt = Instant.ofEpochMilli(2L))).toList()
        assertEquals(2, api.downloadCalls)
    }

    @Test
    fun download_http403_emitsFailedNotRetryable() = runTest {
        val api = StubDownloadApi().apply {
            response = { Response.error(403, "{\"detail\":\"forbidden\"}".toResponseBody("application/json".toMediaType())) }
        }
        val emissions = repo(api, cacheStore()).download(fileNode()).toList()

        val failed = emissions.last() as DownloadStatus.Failed
        assertEquals(403, failed.error.status)
        // 403 is a documented client/auth error - a blind retry will not fix it.
        assertFalse(failed.retryable)
    }

    @Test
    fun download_http503_emitsFailedRetryable() = runTest {
        val api = StubDownloadApi().apply {
            response = { Response.error(503, "{\"detail\":\"down\"}".toResponseBody("application/json".toMediaType())) }
        }
        val emissions = repo(api, cacheStore()).download(fileNode()).toList()

        val failed = emissions.last() as DownloadStatus.Failed
        assertEquals(503, failed.error.status)
        // 5xx is transient - worth a retry.
        assertTrue(failed.retryable)
    }

    @Test
    fun download_ioException_emitsFailedRetryable() = runTest {
        val api = StubDownloadApi().apply { throwable = java.io.IOException("offline") }
        val emissions = repo(api, cacheStore()).download(fileNode()).toList()

        val failed = emissions.last() as DownloadStatus.Failed
        // network sentinel + retryable for a transport failure.
        assertEquals(com.testlogon.android.core.model.ApiError.STATUS_NETWORK, failed.error.status)
        assertTrue(failed.retryable)
        // nothing was committed to the cache.
        val bins = tmp.root.walkTopDown().filter { it.isFile && it.name.endsWith(".bin") }.toList()
        assertTrue(bins.isEmpty())
    }

    @Test
    fun download_emptyBody_emitsFailedRetryable() = runTest {
        val api = StubDownloadApi().apply { response = { Response.success(null) } }
        val emissions = repo(api, cacheStore()).download(fileNode()).toList()

        val failed = emissions.last() as DownloadStatus.Failed
        assertEquals(com.testlogon.android.core.model.ApiError.STATUS_NETWORK, failed.error.status)
        assertTrue(failed.retryable)
    }

    private companion object {
        val BYTES: ByteArray = "AND-334 download payload".toByteArray(Charsets.UTF_8)
    }
}
