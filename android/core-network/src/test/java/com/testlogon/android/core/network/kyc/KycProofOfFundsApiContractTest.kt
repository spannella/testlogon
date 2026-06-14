package com.testlogon.android.core.network.kyc

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.model.kyc.ProofOfFundsSubmissionOutDto
import com.testlogon.android.core.model.kyc.ProofOfFundsSubmitRequestDto
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
 * AND-327 - contract tests for [KycProofOfFundsApi] against MockWebServer with the production-style shared
 * Moshi (BigDecimalAdapter + the KYC enum adapters + KotlinJsonAdapterFactory, mirroring
 * NetworkModule.provideMoshi and the AND-321/325/326 contract tests). Asserts:
 *   - summary GET path + decode (count, verified_count, doubles, lenient extras),
 *   - listSubmissions GET path + {submissions:[...]} decode (status string, epoch Longs, reviewer_note),
 *   - getSubmission GET path interpolation,
 *   - submit POST verb / path `/ui/kyc/proof-of-funds/submissions` / body
 *     {source_category, declared_amount_cents, currency, document_s3_key, note} + 200 decode,
 *   - submit with omitted optional fields serializes nulls (omitted),
 *   - 422 via try/catch (NO nested runTest),
 *   - a required-field-absent (submission_id) decode failure (JsonDataException).
 * The recorded request body is read ONCE.
 */
class KycProofOfFundsApiContractTest {

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

    private fun api(): KycProofOfFundsApi = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
        .create(KycProofOfFundsApi::class.java)

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
    fun summary_path_and_decode() = runTest {
        server.enqueue(jsonResponse(SUMMARY_OUT, code = 200))

        val out = api().summary()

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/kyc/proof-of-funds/summary", recorded.requestUrl?.encodedPath)

        assertEquals(3, out.count)
        assertEquals(1, out.verified_count)
        assertEquals(0.42, out.active_risk_contribution!!, 0.0001)
        assertEquals(500_000L, out.verified_amount_cents)
        assertEquals(listOf("bank_statement", "savings"), out.verified_categories)
        assertEquals("user_1", out.user_sub)
    }

    @Test
    fun listSubmissions_path_and_decode() = runTest {
        server.enqueue(jsonResponse(LIST_OUT, code = 200))

        val out = api().listSubmissions()

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/kyc/proof-of-funds/submissions", recorded.requestUrl?.encodedPath)

        assertEquals(1, out.submissions.size)
        val item = out.submissions[0]
        assertEquals("sub_1", item.submission_id)
        assertEquals("needs_more_info", item.status)
        assertEquals("bank_statement", item.source_category)
        assertEquals(250_000L, item.declared_amount_cents)
        assertEquals("USD", item.currency)
        assertEquals("kyc/pof/abc.jpg", item.document_s3_key)
        assertEquals("please reupload", item.reviewer_note)
        assertEquals(1_780_000_000L, item.created_at)
        assertEquals(1_780_000_500L, item.reviewed_at)
    }

    @Test
    fun getSubmission_pathInterpolation_and_decode() = runTest {
        server.enqueue(jsonResponse(SUBMISSION_OUT, code = 200))

        val out = api().getSubmission(submissionId = "sub_1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/kyc/proof-of-funds/submissions/sub_1", recorded.requestUrl?.encodedPath)
        assertEquals("sub_1", out.submission_id)
        assertEquals("pending", out.status)
    }

    @Test
    fun submit_verb_path_body_and_200_decode() = runTest {
        server.enqueue(jsonResponse(SUBMISSION_OUT, code = 200))

        val out = api().submit(
            ProofOfFundsSubmitRequestDto(
                source_category = "pay_stub",
                declared_amount_cents = 123_45L,
                currency = "USD",
                document_s3_key = "kyc/pof/abc.jpg",
                note = "March payslip",
            ),
        )

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/kyc/proof-of-funds/submissions", recorded.requestUrl?.encodedPath)

        val body = recorded.bodyJson()
        assertEquals("pay_stub", body["source_category"])
        // JSON numbers decode to Double via the loosely-typed map adapter.
        assertEquals(12345.0, body["declared_amount_cents"])
        assertEquals("USD", body["currency"])
        assertEquals("kyc/pof/abc.jpg", body["document_s3_key"])
        assertEquals("March payslip", body["note"])

        // Success is 200 (NOT 201).
        assertEquals("sub_1", out.submission_id)
        assertEquals("pending", out.status)
    }

    @Test
    fun submit_omittedOptionalFields_serializeNull() = runTest {
        server.enqueue(jsonResponse(SUBMISSION_OUT, code = 200))

        api().submit(ProofOfFundsSubmitRequestDto())

        val body = server.takeRequest().bodyJson()
        assertNull(body["source_category"])
        assertNull(body["declared_amount_cents"])
        assertNull(body["document_s3_key"])
        assertNull(body["note"])
    }

    @Test
    fun submit_422_validation_throwsHttpException() = runTest {
        server.enqueue(jsonResponse(VALIDATION_DETAIL, code = 422))
        // assertThrows takes a non-suspend lambda, so catch the suspend call directly (no nested runTest).
        val ex = try {
            api().submit(ProofOfFundsSubmitRequestDto(currency = "ZZZ"))
            null
        } catch (e: HttpException) {
            e
        }
        assertEquals(422, ex?.code())
        val raw = ex?.response()?.errorBody()?.string()
        assertEquals(true, raw?.contains("currency"))
    }

    @Test
    fun submissionDecode_missingSubmissionId_throwsJsonDataException() {
        val adapter = moshi.adapter(ProofOfFundsSubmissionOutDto::class.java)
        assertThrows(JsonDataException::class.java) {
            adapter.fromJson(SUBMISSION_OUT_MISSING_ID)
        }
    }

    private companion object {
        val SUMMARY_OUT = """
            {
              "count": 3,
              "verified_count": 1,
              "active_risk_contribution": 0.42,
              "verified_amount_cents": 500000,
              "verified_categories": ["bank_statement", "savings"],
              "user_sub": "user_1",
              "extra_field": "ignored"
            }
        """.trimIndent()

        val SUBMISSION_OUT = """
            {
              "submission_id": "sub_1",
              "status": "pending",
              "source_category": "pay_stub",
              "declared_amount_cents": 12345,
              "currency": "USD",
              "document_s3_key": "kyc/pof/abc.jpg",
              "note": "March payslip",
              "score": 0.9,
              "risk_contribution": 0.1,
              "created_at": 1780000000,
              "updated_at": 1780000100
            }
        """.trimIndent()

        val LIST_OUT = """
            {
              "submissions": [
                {
                  "submission_id": "sub_1",
                  "status": "needs_more_info",
                  "source_category": "bank_statement",
                  "declared_amount_cents": 250000,
                  "currency": "USD",
                  "document_s3_key": "kyc/pof/abc.jpg",
                  "reviewer_sub": "reviewer_1",
                  "reviewer_note": "please reupload",
                  "reviewed_at": 1780000500,
                  "created_at": 1780000000,
                  "updated_at": 1780000200
                }
              ]
            }
        """.trimIndent()

        val SUBMISSION_OUT_MISSING_ID = """
            {
              "status": "pending",
              "created_at": 1780000000
            }
        """.trimIndent()

        val VALIDATION_DETAIL = """
            {
              "detail": [
                { "loc": ["body", "currency"], "msg": "invalid currency", "type": "value_error" }
              ]
            }
        """.trimIndent()
    }
}
