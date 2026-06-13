package com.testlogon.android.core.network.files

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.model.files.CompleteUploadRequest
import com.testlogon.android.core.model.files.CreateFolderRequest
import com.testlogon.android.core.model.files.FileEntryDto
import com.testlogon.android.core.model.files.FileNodeType
import com.testlogon.android.core.model.files.MoveRequest
import com.testlogon.android.core.model.files.PresignRequest
import com.testlogon.android.core.model.files.RenameRequest
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
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory

/**
 * AND-331 - contract tests for [FilesApi] against MockWebServer with the production-style shared Moshi
 * (BigDecimalAdapter + the KYC enum adapters + KotlinJsonAdapterFactory, mirroring
 * NetworkModule.provideMoshi and the AND-319 KycApiContractTest). For each endpoint this asserts the
 * verb, the resolved path + query / body, and that the response decodes. The recorded request body is
 * read ONCE per request. The 422 case is checked with try/catch (NO nested runTest).
 */
class FilesApiContractTest {

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

    private fun api(): FilesApi = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
        .create(FilesApi::class.java)

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
    fun list_verb_path_query_and_decode_with_unknown_type() = runTest {
        server.enqueue(jsonResponse(LIST_BODY))

        val page = api().list(path = "/docs", limit = 25, cursor = "c1", sortBy = "name", sortDir = "asc")
            .toDomain()

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        val url = recorded.requestUrl
        assertEquals("/v1/fs/list", url?.encodedPath)
        assertEquals("/docs", url?.queryParameter("path"))
        assertEquals("25", url?.queryParameter("limit"))
        assertEquals("c1", url?.queryParameter("cursor"))
        assertEquals("name", url?.queryParameter("sort_by"))
        assertEquals("asc", url?.queryParameter("sort_dir"))

        // Decode + map: path/items/cursor pass through; the file entry carries size/content_type/updated_at.
        assertEquals("/docs", page.path)
        assertEquals("c1", page.cursor)
        assertEquals(3, page.items.size)
        val file = page.items[0]
        assertEquals(FileNodeType.FILE, file.type)
        assertEquals(1234L, file.sizeBytes)
        assertEquals("text/plain", file.contentType)
        assertEquals("2026-01-02T03:04:05Z", file.updatedAt.toString())
        assertEquals(FileNodeType.FOLDER, page.items[1].type)
        // An unknown `type` token stays a raw string on the DTO and maps to UNKNOWN.
        assertEquals(FileNodeType.UNKNOWN, page.items[2].type)
    }

    @Test
    fun list_defaultPath_isRoot() = runTest {
        server.enqueue(jsonResponse(LIST_BODY))
        api().list()
        val url = server.takeRequest().requestUrl
        assertEquals("/", url?.queryParameter("path"))
        // Optional queries are omitted when null.
        assertNull(url?.queryParameter("limit"))
        assertNull(url?.queryParameter("cursor"))
    }

    @Test
    fun info_verb_path_query_and_decode() = runTest {
        server.enqueue(jsonResponse(ENTRY_BODY))
        val entry = api().info(path = "/docs/a.txt")
        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/v1/fs/info", recorded.requestUrl?.encodedPath)
        assertEquals("/docs/a.txt", recorded.requestUrl?.queryParameter("path"))
        assertEquals("a.txt", entry.name)
        assertEquals(FileNodeType.FILE, entry.toDomain().type)
    }

    @Test
    fun search_verb_path_query_and_decode() = runTest {
        server.enqueue(jsonResponse(SEARCH_BODY))
        val results = api().search(prefix = "rep")
        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/v1/fs/search", recorded.requestUrl?.encodedPath)
        assertEquals("rep", recorded.requestUrl?.queryParameter("prefix"))
        // Default limit is sent.
        assertEquals("50", recorded.requestUrl?.queryParameter("limit"))
        assertEquals("rep", results.prefix)
        assertEquals(1, results.results.size)
    }

    @Test
    fun searchText_verb_path_query_and_decode() = runTest {
        server.enqueue(jsonResponse(TEXT_SEARCH_BODY))
        val results = api().searchText(query = "invoice")
        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/v1/fs/search-text", recorded.requestUrl?.encodedPath)
        assertEquals("invoice", recorded.requestUrl?.queryParameter("q"))
        assertEquals("50", recorded.requestUrl?.queryParameter("limit"))
        assertEquals("invoice", results.query)
        assertEquals(1, results.results.size)
    }

    @Test
    fun createFolder_verb_path_body_and_decode() = runTest {
        server.enqueue(jsonResponse(OK_RESP_BODY))
        val out = api().createFolder(CreateFolderRequest(path = "/docs/new"))
        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/v1/fs/folder", recorded.requestUrl?.encodedPath)
        val body = recorded.bodyJson()
        assertEquals("/docs/new", body["path"])
        assertEquals(true, out.ok)
        assertEquals("/docs/new", out.path)
    }

    @Test
    fun renameFile_verb_path_body_and_decode() = runTest {
        server.enqueue(jsonResponse(MOVE_RESULT_BODY))
        val out = api().renameFile(RenameRequest(path = "/docs/a.txt", new_name = "b.txt"))
        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/v1/fs/rename-file", recorded.requestUrl?.encodedPath)
        val body = recorded.bodyJson()
        assertEquals("/docs/a.txt", body["path"])
        assertEquals("b.txt", body["new_name"])
        assertEquals(true, out.ok)
        assertEquals("b.txt", out.new_name)
    }

    @Test
    fun renameFolder_verb_path_body() = runTest {
        server.enqueue(jsonResponse(MOVE_RESULT_BODY))
        api().renameFolder(RenameRequest(path = "/docs/old", new_name = "new"))
        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/v1/fs/rename-folder", recorded.requestUrl?.encodedPath)
        val body = recorded.bodyJson()
        assertEquals("/docs/old", body["path"])
        assertEquals("new", body["new_name"])
    }

    @Test
    fun move_verb_path_body_and_decode() = runTest {
        server.enqueue(jsonResponse(MOVE_RESULT_BODY))
        val out = api().move(MoveRequest(src = "/docs/a.txt", dst = "/archive/a.txt"))
        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/v1/fs/move", recorded.requestUrl?.encodedPath)
        val body = recorded.bodyJson()
        assertEquals("/docs/a.txt", body["src"])
        assertEquals("/archive/a.txt", body["dst"])
        assertEquals(true, out.ok)
    }

    @Test
    fun deleteFile_verb_path_query_and_decode() = runTest {
        server.enqueue(jsonResponse(OK_RESP_BODY))
        val out = api().deleteFile(path = "/docs/a.txt")
        val recorded = server.takeRequest()
        assertEquals("DELETE", recorded.method)
        assertEquals("/v1/fs/file", recorded.requestUrl?.encodedPath)
        assertEquals("/docs/a.txt", recorded.requestUrl?.queryParameter("path"))
        assertEquals(true, out.ok)
    }

    @Test
    fun deleteFolder_verb_path_query_and_decode() = runTest {
        server.enqueue(jsonResponse(DELETE_FOLDER_BODY))
        val out = api().deleteFolder(path = "/docs/old")
        val recorded = server.takeRequest()
        assertEquals("DELETE", recorded.method)
        assertEquals("/v1/fs/folder", recorded.requestUrl?.encodedPath)
        assertEquals("/docs/old", recorded.requestUrl?.queryParameter("path"))
        assertEquals(true, out.ok)
        assertEquals(4, out.deleted_count)
    }

    @Test
    fun presignUpload_verb_path_body_and_decode() = runTest {
        server.enqueue(jsonResponse(PRESIGN_BODY))
        val out = api().presignUpload(PresignRequest(path = "/docs/a.txt", content_type = "text/plain"))
        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/v1/fs/presign-upload", recorded.requestUrl?.encodedPath)
        val body = recorded.bodyJson()
        assertEquals("/docs/a.txt", body["path"])
        assertEquals("text/plain", body["content_type"])
        assertEquals("https://signed.example/put", out.upload_url)
        assertEquals("k_1", out.key)
        assertEquals("t_1", out.ticket_id)
        assertEquals("/docs/a.txt", out.path)
    }

    @Test
    fun completeUpload_verb_path_body_and_decode() = runTest {
        server.enqueue(jsonResponse(ENTRY_BODY))
        val out = api().completeUpload(
            CompleteUploadRequest(path = "/docs/a.txt", key = "k_1", ticket_id = "t_1"),
        )
        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/v1/fs/complete-upload", recorded.requestUrl?.encodedPath)
        val body = recorded.bodyJson()
        assertEquals("/docs/a.txt", body["path"])
        assertEquals("k_1", body["key"])
        assertEquals("t_1", body["ticket_id"])
        // encrypted defaults to false in the body.
        assertEquals(false, body["encrypted"])
        // Response decodes as a FileEntry.
        assertEquals("a.txt", out.name)
        assertEquals(FileNodeType.FILE, out.toDomain().type)
    }

    @Test
    fun mutating_422_validation_throwsHttpException() = runTest {
        server.enqueue(jsonResponse(VALIDATION_DETAIL, code = 422))
        // assertThrows takes a non-suspend lambda, so catch the suspend call directly (no nested runTest).
        val ex = try {
            api().createFolder(CreateFolderRequest(path = "/docs/dup"))
            null
        } catch (e: HttpException) {
            e
        }
        assertEquals(422, ex?.code())
        val raw = ex?.response()?.errorBody()?.string()
        assertEquals(true, raw?.contains("path"))
    }

    @Test
    fun entryDecode_missingName_throwsJsonDataException() {
        val adapter = moshi.adapter(FileEntryDto::class.java)
        assertThrows(JsonDataException::class.java) {
            adapter.fromJson(ENTRY_MISSING_NAME)
        }
    }

    @Test
    fun entryDecode_toleratesUnknownEncAndPreviewKeys() {
        val adapter = moshi.adapter(FileEntryDto::class.java)
        val entry = adapter.fromJson(ENTRY_WITH_EXTRA_KEYS)
        assertTrue(entry != null)
        assertEquals("a.txt", entry?.name)
        assertEquals(true, entry?.is_encrypted)
    }

    private companion object {
        // A file (file), a folder (folder), and an entry with an unrecognized type token.
        val LIST_BODY = """
            {
              "path": "/docs",
              "items": [
                {
                  "name": "a.txt",
                  "path": "/docs/a.txt",
                  "type": "file",
                  "size": 1234,
                  "content_type": "text/plain",
                  "updated_at": "2026-01-02T03:04:05Z",
                  "created_at": "2026-01-01T00:00:00Z"
                },
                { "name": "photos", "path": "/docs/photos", "type": "folder" },
                { "name": "mystery", "path": "/docs/mystery", "type": "symlink" }
              ],
              "cursor": "c1"
            }
        """.trimIndent()

        val ENTRY_BODY = """
            {
              "name": "a.txt",
              "path": "/docs/a.txt",
              "type": "file",
              "size": 1234,
              "content_type": "text/plain",
              "updated_at": "2026-01-02T03:04:05Z"
            }
        """.trimIndent()

        val ENTRY_MISSING_NAME = """
            { "path": "/docs/a.txt", "type": "file" }
        """.trimIndent()

        val ENTRY_WITH_EXTRA_KEYS = """
            {
              "name": "a.txt",
              "path": "/docs/a.txt",
              "type": "file",
              "is_encrypted": true,
              "enc_algo": "aes-gcm",
              "enc_key_id": "kek_1",
              "preview_kind": "image",
              "preview_thumb_url": "https://cdn.example/t.png"
            }
        """.trimIndent()

        val SEARCH_BODY = """
            {
              "prefix": "rep",
              "results": [
                { "name": "report.pdf", "path": "/docs/report.pdf", "type": "file" }
              ]
            }
        """.trimIndent()

        val TEXT_SEARCH_BODY = """
            {
              "query": "invoice",
              "results": [
                { "name": "invoice.pdf", "path": "/docs/invoice.pdf", "type": "file" }
              ]
            }
        """.trimIndent()

        val OK_RESP_BODY = """{ "ok": true, "path": "/docs/new" }"""

        val MOVE_RESULT_BODY = """
            { "ok": true, "path": "/docs/b.txt", "new_name": "b.txt", "src": "/docs/a.txt", "dst": "/docs/b.txt" }
        """.trimIndent()

        val DELETE_FOLDER_BODY = """{ "ok": true, "deleted_count": 4 }"""

        val PRESIGN_BODY = """
            {
              "upload_url": "https://signed.example/put",
              "bucket": "files",
              "key": "k_1",
              "ticket_id": "t_1",
              "path": "/docs/a.txt",
              "content_type": "text/plain"
            }
        """.trimIndent()

        val VALIDATION_DETAIL = """
            {
              "detail": [
                { "loc": ["body", "path"], "msg": "already exists", "type": "value_error" }
              ]
            }
        """.trimIndent()
    }
}
