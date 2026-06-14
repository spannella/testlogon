package com.testlogon.android.core.network.retry

import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import kotlin.random.Random

class RetryInterceptorTest {

    private lateinit var server: MockWebServer

    // Zero delays so tests don't actually sleep.
    private val fastConfig = RetryConfig(baseDelayMs = 0L, maxDelayMs = 0L)

    private fun client() = OkHttpClient.Builder()
        .addInterceptor(RetryInterceptor(fastConfig, Random(0)))
        .build()

    @Before
    fun setUp() {
        server = MockWebServer().apply { start() }
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun `transient 503 then 200 yields success after retry`() {
        server.enqueue(MockResponse().setResponseCode(503).setBody("""{"detail":"down"}"""))
        server.enqueue(MockResponse().setResponseCode(200).setBody("ok"))

        val response = client().newCall(
            Request.Builder().url(server.url("/ui/me")).build(),
        ).execute()

        assertEquals(200, response.code)
        assertEquals(2, server.requestCount)
        response.close()
    }

    @Test
    fun `post is never retried`() {
        server.enqueue(MockResponse().setResponseCode(503))

        val response = client().newCall(
            Request.Builder()
                .url(server.url("/ui/session/start"))
                .post("{}".toRequestBody())
                .build(),
        ).execute()

        assertEquals(503, response.code)
        assertEquals(1, server.requestCount)
        response.close()
    }

    @Test
    fun `exhaustion returns terminal response`() {
        repeat(3) { server.enqueue(MockResponse().setResponseCode(503)) }

        val response = client().newCall(
            Request.Builder().url(server.url("/ui/me")).build(),
        ).execute()

        assertEquals(503, response.code)
        assertEquals(3, server.requestCount)
        response.close()
    }

    @Test
    fun `non-retryable 404 is not retried`() {
        server.enqueue(MockResponse().setResponseCode(404))

        val response = client().newCall(
            Request.Builder().url(server.url("/ui/me")).build(),
        ).execute()

        assertEquals(404, response.code)
        assertEquals(1, server.requestCount)
        response.close()
    }

    @Test
    fun `backoff delay stays within full-jitter bounds`() {
        val interceptor = RetryInterceptor(RetryConfig(baseDelayMs = 250, maxDelayMs = 4_000), Random(0))
        for (attempt in 0..5) {
            val ceiling = minOf(4_000L, (250L shl attempt).coerceAtLeast(250L))
            val delay = interceptor.delayMsFor(attempt)
            assertTrue("delay $delay <= $ceiling", delay in 0..ceiling)
        }
    }
}
