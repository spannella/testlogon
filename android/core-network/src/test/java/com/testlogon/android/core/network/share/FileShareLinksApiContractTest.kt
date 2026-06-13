package com.testlogon.android.core.network.share

import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.model.files.CreateShareLinkRequest
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
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory

/**
 * AND-335 - contract tests for [FileShareLinksApi] (the OWNER surface) against MockWebServer with the
 * production-style shared Moshi (mirroring NetworkModule.provideMoshi). Each test asserts the verb,
 * resolved path + body, and that the response decodes. The recorded request body is read ONCE. The 422
 * case is checked with try/catch (NO nested runTest).
 */
class FileShareLinksApiContractTest {

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

    private fun api(): FileShareLinksApi = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
        .create(FileShareLinksApi::class.java)

    private fun RecordedRequest.bodyJson(): Map<String, Any?> {
        val raw = body.readUtf8()
        if (raw.isBlank()) return emptyMap()
        return mapAdapter.fromJson(raw) ?: emptyMap()
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
    fun list_verb_path_and_decode() = runTest {
        server.enqueue(jsonResponse(LIST_BODY))

        val out = api().listLinks()

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/files/share-links", recorded.requestUrl?.encodedPath)
        assertEquals(2, out.links.size)
        val link = out.links[0]
        assertEquals("lnk_1", link.link_id)
        assertEquals("https://host/s/lnk_1", link.share_url)
        assertEquals("file_9", link.file_node_id)
        assertEquals(1_700_000_000_000L, link.expires_at)
        assertEquals(true, link.password_protected)
        assertEquals(3, link.max_downloads)
        assertEquals(1, link.download_count)
    }

    @Test
    fun create_verb_path_body_and_decode() = runTest {
        server.enqueue(jsonResponse(CREATE_BODY, code = 201))

        val out = api().createLink(
            CreateShareLinkRequest(
                file_node_id = "file_9",
                expiry_hours = 24,
                max_downloads = 3,
                password = "secret",
            ),
        )

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/files/share-links", recorded.requestUrl?.encodedPath)
        val body = recorded.bodyJson()
        assertEquals("file_9", body["file_node_id"])
        // Numbers decode to Double through the loose map adapter.
        assertEquals(24.0, body["expiry_hours"])
        assertEquals(3.0, body["max_downloads"])
        assertEquals("secret", body["password"])
        // Response decodes (share_url + epoch).
        assertEquals("lnk_new", out.link_id)
        assertEquals("https://host/s/lnk_new", out.share_url)
        assertEquals(1_700_000_500_000L, out.expires_at)
        assertEquals(true, out.password_protected)
    }

    @Test
    fun create_omitsPassword_whenNull() = runTest {
        server.enqueue(jsonResponse(CREATE_BODY, code = 201))
        api().createLink(
            CreateShareLinkRequest(file_node_id = "file_9", expiry_hours = 1, max_downloads = 1, password = null),
        )
        val body = server.takeRequest().bodyJson()
        assertNull(body["password"])
    }

    @Test
    fun revoke_verb_path_and_decode() = runTest {
        server.enqueue(jsonResponse(REVOKE_BODY))

        val out = api().revokeLink("lnk_1")

        val recorded = server.takeRequest()
        assertEquals("DELETE", recorded.method)
        assertEquals("/ui/files/share-links/lnk_1", recorded.requestUrl?.encodedPath)
        assertEquals(true, out.ok)
        assertEquals("lnk_1", out.link_id)
    }

    @Test
    fun create_422_validation_throwsHttpException() = runTest {
        server.enqueue(jsonResponse(VALIDATION_DETAIL, code = 422))
        val ex = try {
            api().createLink(
                CreateShareLinkRequest(file_node_id = "file_9", expiry_hours = 999, max_downloads = 1),
            )
            null
        } catch (e: HttpException) {
            e
        }
        assertEquals(422, ex?.code())
        val raw = ex?.response()?.errorBody()?.string()
        assertTrue(raw?.contains("expiry_hours") == true)
    }

    private companion object {
        val LIST_BODY = """
            {
              "links": [
                {
                  "link_id": "lnk_1",
                  "share_url": "https://host/s/lnk_1",
                  "file_node_id": "file_9",
                  "expiry_hours": 24,
                  "expires_at": 1700000000000,
                  "max_downloads": 3,
                  "download_count": 1,
                  "password_protected": true,
                  "created_at": 1699990000000,
                  "revoked": false
                },
                {
                  "link_id": "lnk_2",
                  "share_url": "https://host/s/lnk_2",
                  "file_node_id": "file_other",
                  "password_protected": false
                }
              ]
            }
        """.trimIndent()

        val CREATE_BODY = """
            {
              "link_id": "lnk_new",
              "file_node_id": "file_9",
              "share_url": "https://host/s/lnk_new",
              "expiry_hours": 24,
              "expires_at": 1700000500000,
              "max_downloads": 3,
              "download_count": 0,
              "password_protected": true,
              "created_at": 1700000400000,
              "revoked": false
            }
        """.trimIndent()

        val REVOKE_BODY = """{ "ok": true, "link_id": "lnk_1" }"""

        val VALIDATION_DETAIL = """
            {
              "detail": [
                { "loc": ["body", "expiry_hours"], "msg": "out of range", "type": "value_error" }
              ]
            }
        """.trimIndent()
    }
}
