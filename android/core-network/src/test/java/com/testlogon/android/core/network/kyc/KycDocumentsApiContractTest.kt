package com.testlogon.android.core.network.kyc

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.model.kyc.KycDocumentUploadRequestDto
import com.testlogon.android.core.network.json.BigDecimalAdapter
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory

/**
 * AND-321 - contract tests for [KycDocumentsApi] against MockWebServer with the production-style shared
 * Moshi (BigDecimalAdapter + the KYC enum adapters + KotlinJsonAdapterFactory, mirroring
 * NetworkModule.provideMoshi and the AND-319 KycApiContractTest). Asserts the verb/path/body of the
 * `ui/kyc/documents` POST and the 201 KycDocumentOut decode (document_id, status string, epoch Long
 * timestamps), plus 422 and 403 error mapping. The recorded request body is read ONCE.
 */
class KycDocumentsApiContractTest {

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

    private fun api(): KycDocumentsApi = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
        .create(KycDocumentsApi::class.java)

    /** Decode a recorded request body to a loosely-typed map (read the body source ONCE). */
    private fun RecordedRequest.bodyJson(): Map<String, Any?> {
        val raw = body.readUtf8()
        if (raw.isBlank()) return emptyMap()
        return mapAdapter.fromJson(raw) ?: emptyMap()
    }

    private fun jsonResponse(body: String, code: Int) =
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
    fun uploadDocument_verb_path_body_and_201_decode() = runTest {
        server.enqueue(jsonResponse(DOCUMENT_OUT, code = 201))

        val out = api().uploadDocument(
            KycDocumentUploadRequestDto(
                document_type = "id_front",
                file_name = "id-front.jpg",
                content_b64 = "QUJD",
                case_id = "case_9",
            ),
        )

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        // /ui/ prefix, NOT /v1/.
        assertEquals("/ui/kyc/documents", recorded.requestUrl?.encodedPath)

        val body = recorded.bodyJson()
        assertEquals("id_front", body["document_type"])
        assertEquals("id-front.jpg", body["file_name"])
        assertEquals("QUJD", body["content_b64"])
        assertEquals("case_9", body["case_id"])

        // document_id (NOT id); status as a string; epoch-second Long timestamps.
        assertEquals("doc_1", out.document_id)
        assertEquals("pending", out.status)
        assertEquals(1_780_000_000L, out.created_at)
        assertEquals(1_780_000_100L, out.updated_at)
        assertEquals("case_9", out.case_id)
        assertEquals("https://cdn.example/doc_1.jpg", out.image_url)
    }

    @Test
    fun uploadDocument_omittedCaseId_serializesNull() = runTest {
        server.enqueue(jsonResponse(DOCUMENT_OUT, code = 201))
        api().uploadDocument(
            KycDocumentUploadRequestDto(
                document_type = "id_back",
                file_name = "back.jpg",
                content_b64 = "QUJD",
            ),
        )
        val body = server.takeRequest().bodyJson()
        assertEquals("id_back", body["document_type"])
        assertNull(body["case_id"])
    }

    @Test
    fun uploadDocument_422_validation_throwsHttpException() = runTest {
        server.enqueue(jsonResponse(VALIDATION_DETAIL, code = 422))
        // assertThrows takes a non-suspend lambda, so catch the suspend call directly (no nested runTest).
        val ex = try {
            api().uploadDocument(KycDocumentUploadRequestDto("id_front", "x.jpg", "QUJD"))
            null
        } catch (e: HttpException) {
            e
        }
        assertEquals(422, ex?.code())
        // The error body is available for ApiErrorParser to decode the FastAPI detail union.
        val raw = ex?.response()?.errorBody()?.string()
        assertEquals(true, raw?.contains("content_b64"))
    }

    @Test
    fun uploadDocument_403_csrf_throwsHttpException() = runTest {
        server.enqueue(jsonResponse(FORBIDDEN_DETAIL, code = 403))
        val ex = try {
            api().uploadDocument(KycDocumentUploadRequestDto("id_front", "x.jpg", "QUJD"))
            null
        } catch (e: HttpException) {
            e
        }
        assertEquals(403, ex?.code())
    }

    @Test
    fun documentDecode_missingCreatedAt_throwsJsonDataException() {
        val adapter = moshi.adapter(
            com.testlogon.android.core.model.kyc.KycDocumentOutDto::class.java,
        )
        assertThrows(JsonDataException::class.java) {
            adapter.fromJson(DOCUMENT_OUT_MISSING_CREATED_AT)
        }
    }

    private companion object {
        val DOCUMENT_OUT = """
            {
              "document_id": "doc_1",
              "document_type": "id_front",
              "file_name": "id-front.jpg",
              "status": "pending",
              "image_url": "https://cdn.example/doc_1.jpg",
              "extracted_fields": {},
              "case_id": "case_9",
              "user_sub": "user_1",
              "created_at": 1780000000,
              "updated_at": 1780000100
            }
        """.trimIndent()

        val DOCUMENT_OUT_MISSING_CREATED_AT = """
            {
              "document_id": "doc_1",
              "document_type": "id_front",
              "file_name": "id-front.jpg",
              "status": "pending",
              "updated_at": 1780000100
            }
        """.trimIndent()

        val VALIDATION_DETAIL = """
            {
              "detail": [
                { "loc": ["body", "content_b64"], "msg": "field required", "type": "value_error.missing" }
              ]
            }
        """.trimIndent()

        val FORBIDDEN_DETAIL = """{ "detail": "CSRF token missing or invalid" }"""
    }
}
