package com.testlogon.android.data.vod.download

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.defaultTestClient
import com.testlogon.android.core.testing.net.retrofit
import com.testlogon.android.data.feed.FakeAuthStateStore
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.mockito.Mockito
import java.io.File

/**
 * AND-195 — contract + fail-closed tests for [WatermarkDownloadRepositoryImpl] against MockWebServer.
 *
 * Covers: identity-unresolved fails closed before any work (TC-03); begin (no body) -> ready -> stream
 * produces a watermarked, attributable file (TC-01/04); render `failed` fails closed with no final
 * artifact (TC-05). Uses a mocked Context whose cacheDir/filesDir are temp folders.
 */
class WatermarkDownloadRepositoryTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi = Moshi.Builder().build()
    private val dao = FakeDownloadDao()
    private lateinit var filesDir: File
    private lateinit var cacheDir: File
    private val context = Mockito.mock(android.content.Context::class.java)

    @Before
    fun setUp() {
        filesDir = File.createTempFile("files", "").let { it.delete(); it.mkdirs(); it }
        cacheDir = File.createTempFile("cache", "").let { it.delete(); it.mkdirs(); it }
        Mockito.`when`(context.filesDir).thenReturn(filesDir)
        Mockito.`when`(context.cacheDir).thenReturn(cacheDir)
    }

    private fun repo(userSub: String? = "user_a"): WatermarkDownloadRepositoryImpl {
        val client = defaultTestClient()
        val api = backend.retrofit(moshi, client).create(VodWatermarkDownloadApi::class.java)
        return WatermarkDownloadRepositoryImpl(
            context = context,
            api = api,
            artifactClient = WatermarkArtifactClient(client),
            dao = dao,
            authState = FakeAuthStateStore(userSub = userSub),
        )
    }

    @Test
    fun runDownload_identityUnresolved_failsClosed_noNetwork() = runTest {
        val result = repo(userSub = null).runDownload("v1")
        assertTrue(result is ApiResult.Failure)
        assertEquals(DownloadError.IDENTITY_UNRESOLVED.name, (result as ApiResult.Failure).error.code)
        assertEquals(0, backend.requestCount)
        assertEquals("FAILED", dao.snapshot().single().status)
    }

    @Test
    fun runDownload_beginReadySync_streamsWatermarkedFile() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"status":"ready","render_id":"rnd_1","download_url":"${backend.baseUrl}mock/wm.mp4",
                   "watermark_payload":"wmp_1"}""".trimIndent(),
            ),
        )
        backend.enqueue(MockResponse().setResponseCode(200).setBody("watermarked-bytes"))

        val result = repo().runDownload("v1")
        assertTrue(result is ApiResult.Success)
        val item = (result as ApiResult.Success).data
        assertTrue(item.watermarked)
        assertEquals("user_a", item.identityId)         // identity captured + attributable
        assertEquals("wmp_1", item.watermarkPayload)    // forensic token recorded

        val row = dao.snapshot().single()
        assertEquals("COMPLETED", row.status)
        assertTrue(row.watermarked)
        // The begin POST carries no body (identity is server-side from the session).
        val beginReq = backend.takeRequest()
        assertEquals("POST", beginReq.method)
        assertEquals("/ui/vod/watermark-download/v1", beginReq.requestUrl?.encodedPath)
        assertTrue(beginReq.bodyJson().isEmpty())

        // The final artifact exists; no temp part remains.
        assertTrue(File(filesDir, "downloads/v1.mp4").exists())
        assertFalse(File(cacheDir, "dl-tmp/v1.part").exists())
    }

    @Test
    fun runDownload_renderFailed_failsClosed_noFinalArtifact() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"failed","render_id":"rnd_2"}"""))
        val result = repo().runDownload("v1")
        assertTrue(result is ApiResult.Failure)
        assertEquals(DownloadError.WATERMARK_FAILED.name, (result as ApiResult.Failure).error.code)
        assertFalse(File(filesDir, "downloads/v1.mp4").exists())
        assertEquals("FAILED", dao.snapshot().single().status)
    }

    @Test
    fun runDownload_notEntitled403_mapsNotEntitled() = runTest {
        backend.enqueue(Fixtures.error("\"forbidden\"", 403))
        val result = repo().runDownload("v1")
        assertTrue(result is ApiResult.Failure)
        assertEquals(DownloadError.NOT_ENTITLED.name, (result as ApiResult.Failure).error.code)
    }
}
