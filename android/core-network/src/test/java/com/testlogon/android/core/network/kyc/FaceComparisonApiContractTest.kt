package com.testlogon.android.core.network.kyc

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.squareup.moshi.Json
import com.testlogon.android.core.model.kyc.FaceComparisonResultDto
import com.testlogon.android.core.network.json.BigDecimalAdapter
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory
import retrofit2.http.Body
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Url

/**
 * AND-323 - contract tests for [FaceComparisonApi] against MockWebServer with the production-style shared
 * Moshi (BigDecimalAdapter + the KYC enum adapters + KotlinJsonAdapterFactory, mirroring
 * NetworkModule.provideMoshi and the AND-321/AND-322 contract tests). Asserts the compare-face POST
 * (EMPTY body), the face-comparisons GET decode (result enum string, nested anti_spoof checks[], epoch
 * created_at, remaining_attempts), the AND-129 presign POST {path, content_type} -> 200 decode (the
 * selfie-upload presign this feature REUSES; modelled here with a LOCAL request/response twin because
 * the real PresignBody/PresignResponse live in :app, which core-network does not depend on — the wire
 * shape is identical), plus 422 / 403 error mapping and a required-field-absent (comparison_id) decode
 * failure. The recorded request body is read ONCE. No nested runTest.
 */
class FaceComparisonApiContractTest {

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

    private fun retrofit(): Retrofit = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()

    private fun api(): FaceComparisonApi = retrofit().create(FaceComparisonApi::class.java)

    private fun presignApi(): PresignTestApi = retrofit().create(PresignTestApi::class.java)

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
    fun compareFace_verb_path_emptyBody_and_200_decode() = runTest {
        server.enqueue(jsonResponse(COMPARISON_OUT, code = 200))

        val out = api().compareFace(caseId = "kyc_1")

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/v1/kyc/cases/kyc_1/compare-face", recorded.requestUrl?.encodedPath)
        // compare-face takes NO @Body -> empty request body.
        assertEquals(0L, recorded.bodySize)

        assertEquals("cmp_1", out.comparison_id)
        assertEquals(92, out.confidence_score)
        assertEquals("pass", out.result)
        assertEquals(true, out.anti_spoof.passed)
        assertEquals(3, out.anti_spoof.total_checks)
        assertEquals(3, out.anti_spoof.passed_checks)
        assertEquals(2, out.anti_spoof.checks.size)
        assertEquals("liveness", out.anti_spoof.checks[0].check)
        assertEquals(true, out.anti_spoof.checks[0].passed)
        assertEquals(1, out.attempt_number)
        assertEquals(3, out.max_attempts)
        assertEquals(2, out.remaining_attempts)
        assertEquals(1_780_000_000L, out.created_at)
    }

    @Test
    fun listComparisons_verb_path_and_200_decode() = runTest {
        server.enqueue(jsonResponse(LIST_OUT, code = 200))

        val out = api().listComparisons(caseId = "kyc_1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/v1/kyc/cases/kyc_1/face-comparisons", recorded.requestUrl?.encodedPath)

        assertEquals(2, out.comparisons.size)
        assertEquals("cmp_1", out.comparisons[0].comparison_id)
        assertEquals("fail", out.comparisons[1].result)
        assertEquals(0, out.comparisons[1].remaining_attempts)
    }

    @Test
    fun listComparisons_absentWrapper_decodesEmpty() = runTest {
        // A body without the "comparisons" key decodes leniently to an empty list (history is auxiliary).
        server.enqueue(jsonResponse("""{}""", code = 200))
        val out = api().listComparisons("kyc_1")
        server.takeRequest()
        assertTrue(out.comparisons.isEmpty())
    }

    @Test
    fun presign_verb_path_body_and_200_decode() = runTest {
        server.enqueue(jsonResponse(PRESIGN_OUT, code = 200))

        val out = presignApi().presign(
            path = "v1/fs/presign-upload",
            body = PresignBodyTwin(contentType = "image/jpeg", path = "/kyc/kyc_1/selfie-x.jpg"),
        )

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/v1/fs/presign-upload", recorded.requestUrl?.encodedPath)
        val body = recorded.bodyJson()
        assertEquals("image/jpeg", body["content_type"])
        assertEquals("/kyc/kyc_1/selfie-x.jpg", body["path"])

        assertEquals("https://storage.example/upload/abc", out.uploadUrl)
        assertEquals("kyc-bucket", out.bucket)
        assertEquals("kyc/kyc_1/selfie-x.jpg", out.key)
        assertEquals("ticket_42", out.ticketId)
        assertEquals("/kyc/kyc_1/selfie-x.jpg", out.path)
        assertEquals("image/jpeg", out.contentType)
    }

    @Test
    fun compareFace_422_throwsHttpException() = runTest {
        server.enqueue(jsonResponse(VALIDATION_DETAIL, code = 422))
        val ex = try {
            api().compareFace("kyc_1")
            null
        } catch (e: HttpException) {
            e
        }
        assertEquals(422, ex?.code())
    }

    @Test
    fun compareFace_403_csrf_throwsHttpException() = runTest {
        server.enqueue(jsonResponse(FORBIDDEN_DETAIL, code = 403))
        val ex = try {
            api().compareFace("kyc_1")
            null
        } catch (e: HttpException) {
            e
        }
        assertEquals(403, ex?.code())
    }

    @Test
    fun comparisonDecode_missingComparisonId_throwsJsonDataException() {
        val adapter = moshi.adapter(FaceComparisonResultDto::class.java)
        assertThrows(JsonDataException::class.java) {
            adapter.fromJson(COMPARISON_OUT_MISSING_ID)
        }
    }

    /** A minimal local twin of AND-129's AttachmentApi.presign, to exercise the REUSED presign call shape. */
    private interface PresignTestApi {
        @Headers("Content-Type: application/json")
        @POST
        suspend fun presign(@Url path: String, @Body body: PresignBodyTwin): PresignResponseTwin
    }

    /** Local twin of :app's PresignBody (same wire shape; :app is not a core-network dependency). */
    private data class PresignBodyTwin(
        @Json(name = "content_type") val contentType: String,
        @Json(name = "path") val path: String? = null,
    )

    /** Local twin of :app's PresignResponse (same wire shape). */
    private data class PresignResponseTwin(
        @Json(name = "upload_url") val uploadUrl: String,
        @Json(name = "bucket") val bucket: String,
        @Json(name = "key") val key: String,
        @Json(name = "content_type") val contentType: String,
        @Json(name = "ticket_id") val ticketId: String? = null,
        @Json(name = "path") val path: String? = null,
    )

    private companion object {
        val COMPARISON_OUT = """
            {
              "comparison_id": "cmp_1",
              "confidence_score": 92,
              "result": "pass",
              "anti_spoof": {
                "passed": true,
                "checks": [
                  { "check": "liveness", "passed": true, "detail": "blink detected" },
                  { "check": "depth", "passed": true, "detail": null }
                ],
                "total_checks": 3,
                "passed_checks": 3
              },
              "attempt_number": 1,
              "max_attempts": 3,
              "remaining_attempts": 2,
              "created_at": 1780000000,
              "admin_override": null
            }
        """.trimIndent()

        val LIST_OUT = """
            {
              "comparisons": [
                {
                  "comparison_id": "cmp_1",
                  "confidence_score": 92,
                  "result": "pass",
                  "anti_spoof": { "passed": true, "checks": [], "total_checks": 3, "passed_checks": 3 },
                  "attempt_number": 1,
                  "max_attempts": 3,
                  "remaining_attempts": 2,
                  "created_at": 1780000000
                },
                {
                  "comparison_id": "cmp_2",
                  "confidence_score": 41,
                  "result": "fail",
                  "anti_spoof": { "passed": false, "checks": [], "total_checks": 3, "passed_checks": 1 },
                  "attempt_number": 3,
                  "max_attempts": 3,
                  "remaining_attempts": 0,
                  "created_at": 1780000300
                }
              ]
            }
        """.trimIndent()

        val PRESIGN_OUT = """
            {
              "upload_url": "https://storage.example/upload/abc",
              "bucket": "kyc-bucket",
              "key": "kyc/kyc_1/selfie-x.jpg",
              "content_type": "image/jpeg",
              "ticket_id": "ticket_42",
              "path": "/kyc/kyc_1/selfie-x.jpg"
            }
        """.trimIndent()

        val COMPARISON_OUT_MISSING_ID = """
            {
              "confidence_score": 92,
              "result": "pass",
              "anti_spoof": { "passed": true, "checks": [], "total_checks": 3, "passed_checks": 3 },
              "attempt_number": 1,
              "max_attempts": 3,
              "remaining_attempts": 2,
              "created_at": 1780000000
            }
        """.trimIndent()

        val VALIDATION_DETAIL = """
            {
              "detail": [
                { "loc": ["body", "selfie"], "msg": "no selfie attached", "type": "value_error" }
              ]
            }
        """.trimIndent()

        val FORBIDDEN_DETAIL = """{ "detail": "CSRF token missing or invalid" }"""
    }
}
