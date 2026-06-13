package com.testlogon.android.core.network.drive

import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.model.files.DriveCallbackReqDto
import com.testlogon.android.core.model.files.DriveImportReqDto
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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory

/**
 * AND-336 - contract tests for [GoogleDriveApi] against MockWebServer with the production-style shared
 * Moshi (BigDecimalAdapter + the KYC enum adapters + KotlinJsonAdapterFactory, mirroring
 * NetworkModule.provideMoshi and the AND-331 FilesApiContractTest). For each endpoint this asserts the
 * verb, the resolved path + query / body, and that the response decodes. The recorded request body is
 * read ONCE per request. The 422 case is checked with try/catch (NO nested runTest).
 */
class GoogleDriveApiContractTest {

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

    private fun api(): GoogleDriveApi = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
        .create(GoogleDriveApi::class.java)

    /** Decode a recorded request body to a loosely-typed map (read the body source ONCE). */
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
    fun status_verb_path_and_decode() = runTest {
        server.enqueue(jsonResponse(STATUS_BODY))
        val out = api().status()
        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/integrations/google-drive/status", recorded.requestUrl?.encodedPath)
        assertTrue(out.connected)
        assertEquals("user@example.com", out.email)
        assertEquals(true, out.mock)
    }

    @Test
    fun connect_verb_path_and_decode() = runTest {
        server.enqueue(jsonResponse(CONNECT_BODY))
        val out = api().connect()
        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/integrations/google-drive/connect", recorded.requestUrl?.encodedPath)
        assertEquals("https://accounts.example/consent?x=1", out.auth_url)
    }

    @Test
    fun files_verb_query_and_decode_folderVsFile() = runTest {
        server.enqueue(jsonResponse(FILES_BODY))
        val out = api().files(folderId = "fld_1", query = "report", pageToken = "p2", pageSize = 50)
        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        val url = recorded.requestUrl
        assertEquals("/ui/integrations/google-drive/files", url?.encodedPath)
        assertEquals("fld_1", url?.queryParameter("folder_id"))
        assertEquals("report", url?.queryParameter("q"))
        assertEquals("p2", url?.queryParameter("page_token"))
        assertEquals("50", url?.queryParameter("page_size"))
        assertEquals(3, out.files.size)
        assertEquals("next1", out.next_page_token)
        // Explicit is_folder flag.
        assertEquals(true, out.files[0].is_folder)
        // Folder by mime discriminator.
        assertEquals("application/vnd.google-apps.folder", out.files[1].mime_type)
        // A plain file.
        assertEquals("text/plain", out.files[2].mime_type)
        assertEquals(1234L, out.files[2].size)
    }

    @Test
    fun files_optionalQueries_omittedWhenNull() = runTest {
        server.enqueue(jsonResponse(FILES_BODY))
        api().files()
        val url = server.takeRequest().requestUrl
        assertNull(url?.queryParameter("folder_id"))
        assertNull(url?.queryParameter("q"))
        assertNull(url?.queryParameter("page_token"))
        assertNull(url?.queryParameter("page_size"))
    }

    @Test
    fun callback_verb_path_body_and_decode() = runTest {
        server.enqueue(jsonResponse(STATUS_BODY))
        val out = api().callback(DriveCallbackReqDto(code = "auth-code", state = "st"))
        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/integrations/google-drive/callback", recorded.requestUrl?.encodedPath)
        val body = recorded.bodyJson()
        assertEquals("auth-code", body["code"])
        assertEquals("st", body["state"])
        assertTrue(out.connected)
    }

    @Test
    fun import_verb_path_body_and_decode() = runTest {
        server.enqueue(jsonResponse(IMPORT_BODY))
        val out = api().import(DriveImportReqDto(file_id = "file_1", folder_id = "/docs"))
        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/integrations/google-drive/import", recorded.requestUrl?.encodedPath)
        val body = recorded.bodyJson()
        assertEquals("file_1", body["file_id"])
        assertEquals("/docs", body["folder_id"])
        assertTrue(out.ok)
        assertEquals("/docs/report.pdf", out.path)
    }

    @Test
    fun disconnect_verb_path_emptyBody() = runTest {
        server.enqueue(MockResponse().setResponseCode(200))
        val resp = api().disconnect()
        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/integrations/google-drive/disconnect", recorded.requestUrl?.encodedPath)
        assertTrue(resp.isSuccessful)
    }

    @Test
    fun import_422_validation_throwsHttpException() = runTest {
        server.enqueue(jsonResponse(VALIDATION_DETAIL, code = 422))
        // assertThrows takes a non-suspend lambda, so catch the suspend call directly (no nested runTest).
        val ex = try {
            api().import(DriveImportReqDto(file_id = "bad"))
            null
        } catch (e: HttpException) {
            e
        }
        assertEquals(422, ex?.code())
        val raw = ex?.response()?.errorBody()?.string()
        assertEquals(true, raw?.contains("file_id"))
    }

    @Test
    fun statusDecode_sparseBody_defaultsNotConnected() {
        val adapter = moshi.adapter(com.testlogon.android.core.model.files.DriveStatusRespDto::class.java)
        val out = adapter.fromJson("{}")
        assertFalse(out?.connected ?: true)
    }

    private companion object {
        val STATUS_BODY = """
            { "connected": true, "email": "user@example.com", "mock": true }
        """.trimIndent()

        val CONNECT_BODY = """
            { "auth_url": "https://accounts.example/consent?x=1", "mock": true }
        """.trimIndent()

        val FILES_BODY = """
            {
              "files": [
                { "id": "fld_1", "name": "Reports", "is_folder": true },
                { "id": "fld_2", "name": "Photos", "mime_type": "application/vnd.google-apps.folder" },
                {
                  "id": "file_1",
                  "name": "report.pdf",
                  "mime_type": "text/plain",
                  "size": 1234,
                  "modified_time": "2026-01-02T03:04:05Z"
                }
              ],
              "next_page_token": "next1"
            }
        """.trimIndent()

        val IMPORT_BODY = """{ "ok": true, "path": "/docs/report.pdf" }"""

        val VALIDATION_DETAIL = """
            {
              "detail": [
                { "loc": ["body", "file_id"], "msg": "not found", "type": "value_error" }
              ]
            }
        """.trimIndent()
    }
}
