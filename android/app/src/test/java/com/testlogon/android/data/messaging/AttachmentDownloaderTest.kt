package com.testlogon.android.data.messaging

import com.squareup.moshi.Moshi
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.mockito.Mockito
import java.io.File

/**
 * AND-132 — MockWebServer tests for the grant -> (consume?) -> GET-bytes download flow, cache reuse,
 * and the single-re-grant retry policy. Uses a mocked Context whose cacheDir is a temp folder.
 */
class AttachmentDownloaderTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()
    private lateinit var cacheDir: File
    private lateinit var downloader: DefaultAttachmentDownloader

    @Before
    fun setUp() {
        cacheDir = File.createTempFile("cache", "").let { it.delete(); it.mkdirs(); it }
        val context = Mockito.mock(android.content.Context::class.java)
        Mockito.`when`(context.cacheDir).thenReturn(cacheDir)
        val api = backend.retrofit(moshi).create(MessagingApi::class.java)
        downloader = DefaultAttachmentDownloader(api, context)
    }

    @Test
    fun policyNone_grantThenGetBytes_noConsume() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"grant_token":"g1","expires_at":99,"conversation_id":"c1","message_id":"m1"}"""),
        )
        backend.enqueue(MockResponse().setResponseCode(200).setBody("hello-file-bytes"))

        val emissions = downloader.download("c1", "m1", "report.pdf", "none").toList()

        // grant POST then bytes GET — NO consume POST for policy "none".
        val grantReq = backend.takeRequest()
        assertEquals("/messaging/conversations/c1/messages/m1/attachment/grant", grantReq.requestUrl?.encodedPath)
        val getReq = backend.takeRequest()
        assertEquals("/messaging/conversations/c1/messages/m1/attachment", getReq.requestUrl?.encodedPath)
        assertEquals("g1", getReq.requestUrl?.queryParameter("grant_token"))

        val done = emissions.last()
        assertTrue(done is DownloadProgress.Done)
        val file = (done as DownloadProgress.Done).file
        assertEquals("hello-file-bytes", file.readText())
        // Progress fractions are monotonic and end at 1.0.
        val fractions = emissions.filterIsInstance<DownloadProgress.Downloading>().map { it.fraction }
        assertEquals(1f, fractions.last(), 0.001f)
    }

    @Test
    fun viewOnce_grantConsumeThenGet() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"grant_token":"g2","expires_at":99,"conversation_id":"c1","message_id":"m2"}"""),
        )
        backend.enqueue(
            Fixtures.okBody(
                """{"ok":true,"conversation_id":"c1","message_id":"m2","consumption_state":"consumed",
                    "consumed_at":1,"consumption_attempt_id":"a"}""",
            ),
        )
        backend.enqueue(MockResponse().setResponseCode(200).setBody("once-bytes"))

        val emissions = downloader.download("c1", "m2", "secret.pdf", "view_once").toList()

        assertEquals("/messaging/conversations/c1/messages/m2/attachment/grant", backend.takeRequest().requestUrl?.encodedPath)
        val consumeReq = backend.takeRequest()
        assertEquals("/messaging/conversations/c1/messages/m2/attachment/consume", consumeReq.requestUrl?.encodedPath)
        assertEquals("g2", consumeReq.requestUrl?.queryParameter("grant_token"))
        assertEquals("/messaging/conversations/c1/messages/m2/attachment", backend.takeRequest().requestUrl?.encodedPath)

        assertTrue(emissions.last() is DownloadProgress.Done)
    }

    @Test
    fun rejectedGrant_reGrantsOnce_thenGrantExpired() = runTest {
        // First grant rejected, second grant also rejected -> GrantExpired (exactly two grant attempts).
        backend.enqueue(MockResponse().setResponseCode(403).setBody("""{"detail":"expired"}"""))
        backend.enqueue(MockResponse().setResponseCode(403).setBody("""{"detail":"expired"}"""))

        val emissions = downloader.download("c1", "m3", "x.pdf", "none").toList()

        assertEquals(2, backend.requestCount)
        val failed = emissions.last()
        assertTrue(failed is DownloadProgress.Failed)
        assertEquals(FileError.GrantExpired, (failed as DownloadProgress.Failed).reason)
    }

    @Test
    fun cacheReuse_policyNone_skipsNetwork() = runTest {
        // Seed a cached file for m4.
        val dir = File(File(cacheDir, "attachments"), "m4").apply { mkdirs() }
        File(dir, "cached.pdf").writeText("cached")

        val emissions = downloader.download("c1", "m4", "cached.pdf", "none").toList()

        assertEquals(0, backend.requestCount) // no network for a cached, policy-none file
        assertTrue(emissions.single() is DownloadProgress.Done)
    }
}
