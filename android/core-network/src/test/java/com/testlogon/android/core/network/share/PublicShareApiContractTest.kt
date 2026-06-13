package com.testlogon.android.core.network.share

import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.model.files.PublicDownloadRequest
import com.testlogon.android.core.network.json.BigDecimalAdapter
import com.testlogon.android.core.network.kyc.KycCaseStatusAdapter
import com.testlogon.android.core.network.kyc.KycFileTypeAdapter
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory

/**
 * AND-335 - contract tests for [PublicShareApi] (the PUBLIC, session-free surface) against MockWebServer
 * with the production-style shared Moshi. Besides the verb / path / body / decode assertions, these tests
 * ALSO assert that NO Authorization / Cookie / X-CSRF-Token headers are sent (the api is built on a plain
 * cookieless client here, just as ShareNetworkModule builds a cookieless Retrofit in production). The
 * recorded body is read ONCE; no nested runTest.
 */
class PublicShareApiContractTest {

    private lateinit var server: MockWebServer

    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(KycCaseStatusAdapter)
        .add(KycFileTypeAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private val mapAdapter = moshi.adapter<Map<String, Any?>>(
        Types.newParameterizedType(Map::class.java, String::class.java, Any::class.java),
    )

    /** A plain client with NO cookie jar / CSRF / auth interceptor (mirrors the production cookieless one). */
    private fun api(): PublicShareApi = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
        .create(PublicShareApi::class.java)

    private fun RecordedRequest.bodyJson(): Map<String, Any?> {
        val raw = body.readUtf8()
        if (raw.isBlank()) return emptyMap()
        return mapAdapter.fromJson(raw) ?: emptyMap()
    }

    private fun RecordedRequest.assertSessionFree() {
        assertNull(getHeader("Authorization"))
        assertNull(getHeader("Cookie"))
        assertNull(getHeader("X-CSRF-Token"))
    }

    private fun jsonResponse(body: String, code: Int = 200) =
        MockResponse().setResponseCode(code).setHeader("Content-Type", "application/json").setBody(body)

    @Before
    fun setUp() {
        server = MockWebServer().apply { start() }
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun info_verb_path_sessionFree_and_decode() = runTest {
        server.enqueue(jsonResponse(INFO_BODY))

        val out = api().resolvePublic("lnk_1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/public/files/share/lnk_1/info", recorded.requestUrl?.encodedPath)
        recorded.assertSessionFree()
        assertEquals("lnk_1", out.link_id)
        assertEquals("report.pdf", out.file_name)
        assertEquals(1234L, out.size)
        assertEquals("application/pdf", out.content_type)
        assertEquals(true, out.password_required)
        assertEquals(false, out.revoked)
        assertEquals(true, out.expired)
    }

    @Test
    fun download_verb_path_body_sessionFree_and_bytes() = runTest {
        server.enqueue(MockResponse().setResponseCode(200).setBody("file-bytes"))

        val response = api().downloadPublic("lnk_1", PublicDownloadRequest(password = "secret"))

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/public/files/share/lnk_1/download", recorded.requestUrl?.encodedPath)
        recorded.assertSessionFree()
        val body = recorded.bodyJson()
        assertEquals("secret", body["password"])
        // The body is opaque bytes (read ONCE).
        assertEquals("file-bytes", response.body()?.string())
    }

    @Test
    fun download_omitsPassword_whenNull() = runTest {
        server.enqueue(MockResponse().setResponseCode(200).setBody("x"))
        api().downloadPublic("lnk_1", PublicDownloadRequest(password = null))
        val recorded = server.takeRequest()
        assertNull(recorded.bodyJson()["password"])
        // Drain the response body once.
        // (no assertion needed; just exercises the streamed path)
    }

    private companion object {
        val INFO_BODY = """
            {
              "link_id": "lnk_1",
              "file_name": "report.pdf",
              "size": 1234,
              "content_type": "application/pdf",
              "expires_at": 1700000000000,
              "password_required": true,
              "revoked": false,
              "expired": true,
              "exhausted": false,
              "download_count": 0,
              "max_downloads": 3
            }
        """.trimIndent()
    }
}
