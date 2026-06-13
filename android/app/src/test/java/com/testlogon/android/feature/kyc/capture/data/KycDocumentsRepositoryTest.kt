package com.testlogon.android.feature.kyc.capture.data

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.kyc.KycDocumentOutDto
import com.testlogon.android.core.model.kyc.KycDocumentUploadRequestDto
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.kyc.KycDocumentsApi
import com.testlogon.android.feature.kyc.capture.model.KycDocumentStatus
import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Response
import java.io.IOException
import java.net.SocketTimeoutException
import java.time.Instant

/**
 * AND-330 — contract tests for [KycDocumentsRepositoryImpl] (AND-321). No repository-level test existed:
 * the prior coverage was the core-network MockWebServer contract (KycDocumentsApiContractTest) + the
 * ViewModel. These lock the repo's DTO -> domain mapping (document_id NOT id; status token -> lenient enum
 * incl. UNKNOWN; epoch-second Long -> Instant), the request-field pass-through (case_id), and the
 * HttpException -> Failure / IOException -> NetworkError folding.
 *
 * Uses a fake [KycDocumentsApi] (the only method) + a plain Moshi for the [ApiErrorParser]. The repo hops
 * to Dispatchers.IO internally; runTest awaits it (no MainDispatcherRule needed).
 */
class KycDocumentsRepositoryTest {

    private val errorParser = ApiErrorParser(Moshi.Builder().build())

    private class FakeDocumentsApi(
        var responder: (KycDocumentUploadRequestDto) -> KycDocumentOutDto,
    ) : KycDocumentsApi {
        var lastRequest: KycDocumentUploadRequestDto? = null
        var calls = 0
        override suspend fun uploadDocument(body: KycDocumentUploadRequestDto): KycDocumentOutDto {
            calls++
            lastRequest = body
            return responder(body)
        }
    }

    private fun repo(api: FakeDocumentsApi) = KycDocumentsRepositoryImpl(api, errorParser)

    @Test
    fun upload_passesRequestFields_andMapsDtoToDomain() = runTest {
        val api = FakeDocumentsApi { outDto(documentType = it.document_type, status = "pending") }
        val result = repo(api).uploadDocument(
            documentType = "id_front",
            fileName = "front.jpg",
            contentB64 = "QUJD",
            caseId = "case_42",
        )

        // Request field pass-through.
        val sent = api.lastRequest!!
        assertEquals("id_front", sent.document_type)
        assertEquals("front.jpg", sent.file_name)
        assertEquals("QUJD", sent.content_b64)
        assertEquals("case_42", sent.case_id)

        // DTO -> domain.
        val doc = (result as ApiResult.Success).data
        assertEquals("doc_1", doc.documentId) // document_id, NOT id.
        assertEquals("id_front", doc.documentType)
        assertEquals(KycDocumentStatus.PENDING, doc.status)
        assertEquals(Instant.ofEpochSecond(1_780_000_000), doc.createdAt)
        assertEquals(Instant.ofEpochSecond(1_780_000_100), doc.updatedAt)
    }

    @Test
    fun upload_omittedCaseId_passesNull() = runTest {
        val api = FakeDocumentsApi { outDto(documentType = it.document_type, status = "pending") }
        repo(api).uploadDocument(documentType = "id_back", fileName = "back.jpg", contentB64 = "QUJD")
        assertNull(api.lastRequest?.case_id)
    }

    @Test
    fun upload_unknownStatusToken_mapsToUnknownEnum_neverThrows() = runTest {
        val api = FakeDocumentsApi { outDto(documentType = it.document_type, status = "in_review") }
        val doc = (repo(api).uploadDocument("id_front", "f.jpg", "QUJD") as ApiResult.Success).data
        assertEquals(KycDocumentStatus.UNKNOWN, doc.status)
    }

    @Test
    fun upload_422_mapsToFailureWithStatus() = runTest {
        val api = FakeDocumentsApi { throw http(422) }
        val result = repo(api).uploadDocument("id_front", "f.jpg", "QUJD")
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun upload_ioError_mapsToNetworkError() = runTest {
        val api = FakeDocumentsApi { throw IOException("offline") }
        val result = repo(api).uploadDocument("id_front", "f.jpg", "QUJD")
        assertTrue(result is ApiResult.NetworkError)
        assertFalse((result as ApiResult.NetworkError).isTimeout)
    }

    @Test
    fun upload_timeout_setsTimeoutFlag() = runTest {
        val api = FakeDocumentsApi { throw SocketTimeoutException("slow") }
        val result = repo(api).uploadDocument("id_front", "f.jpg", "QUJD")
        assertTrue(result is ApiResult.NetworkError)
        assertTrue((result as ApiResult.NetworkError).isTimeout)
    }

    private companion object {
        fun outDto(documentType: String, status: String): KycDocumentOutDto = KycDocumentOutDto(
            document_id = "doc_1",
            document_type = documentType,
            file_name = "front.jpg",
            status = status,
            image_url = "https://cdn.example/doc_1.jpg",
            case_id = null,
            created_at = 1_780_000_000,
            updated_at = 1_780_000_100,
        )

        fun http(code: Int): HttpException =
            HttpException(Response.error<Any>(code, "{}".toResponseBody("application/json".toMediaType())))
    }
}
