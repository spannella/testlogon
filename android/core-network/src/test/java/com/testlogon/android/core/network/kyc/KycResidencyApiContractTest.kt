package com.testlogon.android.core.network.kyc

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.model.kyc.AddressInputDto
import com.testlogon.android.core.model.kyc.KycResidencyDocumentOutDto
import com.testlogon.android.core.model.kyc.KycResidencyUploadRequestDto
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
 * AND-326 - contract tests for [KycResidencyApi] against MockWebServer with the production-style shared
 * Moshi (BigDecimalAdapter + the KYC enum adapters + KotlinJsonAdapterFactory, mirroring
 * NetworkModule.provideMoshi and the AND-321/325 contract tests). Asserts:
 *   - listResidency GET decode of the {documents:[...]} envelope (status string, recency, epoch Longs),
 *   - uploadResidency POST verb / path `/ui/kyc/residency` / body + 201 decode,
 *   - extractResidency POST path interpolation,
 *   - verifyAddress POST verb / path `/v1/kyc/address-verification/cases/case_1/verify` / body + 200 decode
 *     (status + decision + discrepancies + standardized_address),
 *   - getAddressVerification GET path,
 *   - 422 via try/catch (NO nested runTest),
 *   - a required-field-absent (document_id) decode failure (JsonDataException).
 * The recorded request body is read ONCE.
 */
class KycResidencyApiContractTest {

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

    private fun api(): KycResidencyApi = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
        .create(KycResidencyApi::class.java)

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
    fun listResidency_path_and_decode() = runTest {
        server.enqueue(jsonResponse(LIST_OUT, code = 200))

        val out = api().listResidency()

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/kyc/residency", recorded.requestUrl?.encodedPath)

        assertEquals(1, out.documents.size)
        val doc = out.documents[0]
        assertEquals("doc_1", doc.document_id)
        assertEquals("utility_bill", doc.document_type)
        assertEquals("pending", doc.status)
        assertEquals(true, doc.recency_valid)
        assertEquals(20, doc.recency_days)
        assertEquals(1_780_000_000L, doc.created_at)
        assertEquals(1_780_000_100L, doc.updated_at)
        assertEquals("Acme Power", doc.issuing_entity)
        assertEquals("Main St 1", doc.extracted_address?.get("line_1"))
    }

    @Test
    fun uploadResidency_verb_path_body_and_201_decode() = runTest {
        server.enqueue(jsonResponse(DOCUMENT_OUT, code = 201))

        val out = api().uploadResidency(
            KycResidencyUploadRequestDto(
                document_type = "utility_bill",
                issuing_entity = "Acme Power",
                document_date = "2026-05-01",
                file_name = "bill.jpg",
                content_b64 = "QUJD",
                case_id = "case_1",
            ),
        )

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        // /ui/ prefix, NOT /v1/.
        assertEquals("/ui/kyc/residency", recorded.requestUrl?.encodedPath)

        val body = recorded.bodyJson()
        assertEquals("utility_bill", body["document_type"])
        assertEquals("Acme Power", body["issuing_entity"])
        assertEquals("2026-05-01", body["document_date"])
        assertEquals("bill.jpg", body["file_name"])
        assertEquals("QUJD", body["content_b64"])
        assertEquals("case_1", body["case_id"])

        assertEquals("doc_1", out.document_id)
        assertEquals("pending", out.status)
    }

    @Test
    fun uploadResidency_omittedCaseId_serializesNull() = runTest {
        server.enqueue(jsonResponse(DOCUMENT_OUT, code = 201))
        api().uploadResidency(
            KycResidencyUploadRequestDto(
                document_type = "bank_statement",
                issuing_entity = "Bank",
                document_date = "2026-05-01",
                file_name = "stmt.pdf",
                content_b64 = "QUJD",
            ),
        )
        val body = server.takeRequest().bodyJson()
        assertEquals("bank_statement", body["document_type"])
        assertNull(body["case_id"])
    }

    @Test
    fun extractResidency_pathInterpolation() = runTest {
        server.enqueue(jsonResponse(DOCUMENT_OUT, code = 200))

        api().extractResidency(documentId = "doc_1")

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/kyc/residency/doc_1/extract", recorded.requestUrl?.encodedPath)
    }

    @Test
    fun verifyAddress_verb_path_body_and_200_decode() = runTest {
        server.enqueue(jsonResponse(VERIFICATION_OUT, code = 200))

        val out = api().verifyAddress(
            caseId = "case_1",
            body = AddressInputDto(
                line_1 = "Main St 1",
                line_2 = "Apt 2",
                city = "Springfield",
                state = "IL",
                postal_code = "62704",
                country = "US",
            ),
        )

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/v1/kyc/address-verification/cases/case_1/verify", recorded.requestUrl?.encodedPath)

        val body = recorded.bodyJson()
        assertEquals("Main St 1", body["line_1"])
        assertEquals("Apt 2", body["line_2"])
        assertEquals("Springfield", body["city"])
        assertEquals("IL", body["state"])
        assertEquals("62704", body["postal_code"])
        assertEquals("US", body["country"])

        assertEquals("partial_match", out.status)
        assertEquals("needs_review", out.decision)
        assertEquals(1, out.discrepancies.size)
        assertEquals("postal_code", out.discrepancies[0]["field"])
        assertEquals(72, out.confidence_score)
        assertEquals("MAIN ST 1", out.standardized_address?.get("line_1"))
    }

    @Test
    fun getAddressVerification_pathInterpolation_and_decode() = runTest {
        server.enqueue(jsonResponse(VERIFICATION_VERIFIED, code = 200))

        val out = api().getAddressVerification(caseId = "case_1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/v1/kyc/address-verification/cases/case_1", recorded.requestUrl?.encodedPath)

        assertEquals("verified", out.status)
        assertEquals("verified", out.decision)
        assertEquals(0, out.discrepancies.size)
    }

    @Test
    fun verifyAddress_422_validation_throwsHttpException() = runTest {
        server.enqueue(jsonResponse(VALIDATION_DETAIL, code = 422))
        // assertThrows takes a non-suspend lambda, so catch the suspend call directly (no nested runTest).
        val ex = try {
            api().verifyAddress(
                caseId = "case_1",
                body = AddressInputDto(
                    line_1 = "",
                    city = "x",
                    state = "x",
                    postal_code = "x",
                    country = "x",
                ),
            )
            null
        } catch (e: HttpException) {
            e
        }
        assertEquals(422, ex?.code())
        val raw = ex?.response()?.errorBody()?.string()
        assertEquals(true, raw?.contains("line_1"))
    }

    @Test
    fun documentDecode_missingDocumentId_throwsJsonDataException() {
        val adapter = moshi.adapter(KycResidencyDocumentOutDto::class.java)
        assertThrows(JsonDataException::class.java) {
            adapter.fromJson(DOCUMENT_OUT_MISSING_ID)
        }
    }

    private companion object {
        val DOCUMENT_OUT = """
            {
              "document_id": "doc_1",
              "document_type": "utility_bill",
              "file_name": "bill.jpg",
              "status": "pending",
              "issuing_entity": "Acme Power",
              "document_date": "2026-05-01",
              "recency_valid": true,
              "recency_days": 20,
              "created_at": 1780000000,
              "updated_at": 1780000100
            }
        """.trimIndent()

        val LIST_OUT = """
            {
              "documents": [
                {
                  "document_id": "doc_1",
                  "document_type": "utility_bill",
                  "file_name": "bill.jpg",
                  "status": "pending",
                  "issuing_entity": "Acme Power",
                  "document_date": "2026-05-01",
                  "recency_valid": true,
                  "recency_days": 20,
                  "extracted_address": { "line_1": "Main St 1", "city": "Springfield" },
                  "created_at": 1780000000,
                  "updated_at": 1780000100
                }
              ]
            }
        """.trimIndent()

        val VERIFICATION_OUT = """
            {
              "status": "partial_match",
              "decision": "needs_review",
              "discrepancies": [
                { "field": "postal_code", "detail": "does not match records" }
              ],
              "confidence_score": 72,
              "standardized_address": { "line_1": "MAIN ST 1", "city": "SPRINGFIELD" }
            }
        """.trimIndent()

        val VERIFICATION_VERIFIED = """
            {
              "status": "verified",
              "decision": "verified",
              "discrepancies": [],
              "confidence_score": 98
            }
        """.trimIndent()

        val DOCUMENT_OUT_MISSING_ID = """
            {
              "document_type": "utility_bill",
              "file_name": "bill.jpg",
              "status": "pending",
              "recency_valid": true,
              "recency_days": 20,
              "created_at": 1780000000,
              "updated_at": 1780000100
            }
        """.trimIndent()

        val VALIDATION_DETAIL = """
            {
              "detail": [
                { "loc": ["body", "line_1"], "msg": "field required", "type": "value_error.missing" }
              ]
            }
        """.trimIndent()
    }
}
