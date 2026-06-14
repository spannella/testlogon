package com.testlogon.android.core.network.kyc

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.model.kyc.KycLivenessCallOutDto
import com.testlogon.android.core.model.kyc.KycLivenessCallScheduleRequestDto
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
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory

/**
 * AND-324 - contract tests for [KycLivenessCallApi] against MockWebServer with the production-style shared
 * Moshi (BigDecimalAdapter + the KYC enum adapters + KotlinJsonAdapterFactory, mirroring
 * NetworkModule.provideMoshi and the AND-321/AND-322/AND-323 contract tests). Asserts the schedule POST
 * (verb / path `/ui/kyc/liveness-call` / body), the 201 KycLivenessCallOut decode (status enum string,
 * epoch scheduled_at, join_url, null result), the list GET ({calls:[...]}) decode, the getCall GET path
 * interpolation, the cancel POST (`.../{callId}/cancel`, NO body -> status cancelled), 422 error mapping
 * (try/catch, NO nested runTest), and a required-field-absent (call_id) decode failure. The recorded
 * request body is read ONCE.
 */
class KycLivenessCallApiContractTest {

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

    private fun api(): KycLivenessCallApi = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
        .create(KycLivenessCallApi::class.java)

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
    fun scheduleCall_verb_path_body_and_201_decode() = runTest {
        server.enqueue(jsonResponse(CALL_OUT_SCHEDULED, code = 201))

        val out = api().scheduleCall(
            KycLivenessCallScheduleRequestDto(
                case_id = "kyc_9",
                scheduled_at = 1_780_000_000L,
                duration_minutes = 15,
                note = "Please call in the morning",
            ),
        )

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/kyc/liveness-call", recorded.requestUrl?.encodedPath)

        val body = recorded.bodyJson()
        assertEquals("kyc_9", body["case_id"])
        assertEquals(1_780_000_000.0, body["scheduled_at"])
        assertEquals(15.0, body["duration_minutes"])
        assertEquals("Please call in the morning", body["note"])

        // status as a string token; epoch-second Long scheduled_at; join_url present; result null.
        assertEquals("call_1", out.call_id)
        assertEquals("kyc_9", out.case_id)
        assertEquals("scheduled", out.status)
        assertEquals(1_780_000_000L, out.scheduled_at)
        assertEquals(15, out.duration_minutes)
        assertEquals("https://verify.example/join/abc", out.join_url)
        assertNull(out.result)
    }

    @Test
    fun scheduleCall_omittedNote_serializesNull() = runTest {
        server.enqueue(jsonResponse(CALL_OUT_SCHEDULED, code = 201))
        api().scheduleCall(
            KycLivenessCallScheduleRequestDto(
                case_id = "kyc_9",
                scheduled_at = 1_780_000_000L,
                duration_minutes = 15,
            ),
        )
        val body = server.takeRequest().bodyJson()
        assertEquals("kyc_9", body["case_id"])
        assertNull(body["note"])
        assertNull(body["verifier_sub"])
    }

    @Test
    fun listCalls_verb_path_and_200_decode() = runTest {
        server.enqueue(jsonResponse(LIST_OUT, code = 200))

        val out = api().listCalls()

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/kyc/liveness-call", recorded.requestUrl?.encodedPath)

        assertEquals(2, out.calls.size)
        assertEquals("call_1", out.calls[0].call_id)
        assertEquals("scheduled", out.calls[0].status)
        assertEquals("cancelled", out.calls[1].status)
    }

    @Test
    fun listCalls_absentWrapper_decodesEmpty() = runTest {
        // A body without the "calls" key decodes leniently to an empty list.
        server.enqueue(jsonResponse("""{}""", code = 200))
        val out = api().listCalls()
        server.takeRequest()
        assertTrue(out.calls.isEmpty())
    }

    @Test
    fun getCall_pathInterpolation_and_decode() = runTest {
        server.enqueue(jsonResponse(CALL_OUT_SCHEDULED, code = 200))

        val out = api().getCall(callId = "call_1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/kyc/liveness-call/call_1", recorded.requestUrl?.encodedPath)
        assertEquals("call_1", out.call_id)
    }

    @Test
    fun getCaseStatus_pathInterpolation_and_envelope_decode() = runTest {
        server.enqueue(jsonResponse(CASE_STATUS_OUT, code = 200))

        val out = api().getCaseStatus(caseId = "kyc_9")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/kyc/liveness-call/case/kyc_9", recorded.requestUrl?.encodedPath)
        assertEquals("scheduled", out.verification_call?.status)
        assertEquals(1_780_000_000L, out.verification_call?.scheduled_at)
    }

    @Test
    fun getCaseStatus_nullVerificationCall_decodesNull() = runTest {
        server.enqueue(jsonResponse("""{ "verification_call": null }""", code = 200))
        val out = api().getCaseStatus("kyc_9")
        server.takeRequest()
        assertNull(out.verification_call)
    }

    @Test
    fun cancelCall_verb_path_emptyBody_and_decode() = runTest {
        server.enqueue(jsonResponse(CALL_OUT_CANCELLED, code = 200))

        val out = api().cancelCall(callId = "call_1")

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/kyc/liveness-call/call_1/cancel", recorded.requestUrl?.encodedPath)
        // cancel takes NO @Body -> empty request body.
        assertEquals(0L, recorded.bodySize)
        assertEquals("cancelled", out.status)
    }

    @Test
    fun scheduleCall_422_validation_throwsHttpException() = runTest {
        server.enqueue(jsonResponse(VALIDATION_DETAIL, code = 422))
        // assertThrows takes a non-suspend lambda, so catch the suspend call directly (no nested runTest).
        val ex = try {
            api().scheduleCall(
                KycLivenessCallScheduleRequestDto(
                    case_id = "kyc_9",
                    scheduled_at = 1_780_000_000L,
                    duration_minutes = 15,
                ),
            )
            null
        } catch (e: HttpException) {
            e
        }
        assertEquals(422, ex?.code())
        val raw = ex?.response()?.errorBody()?.string()
        assertEquals(true, raw?.contains("scheduled_at"))
    }

    @Test
    fun callDecode_missingCallId_throwsJsonDataException() {
        val adapter = moshi.adapter(KycLivenessCallOutDto::class.java)
        assertThrows(JsonDataException::class.java) {
            adapter.fromJson(CALL_OUT_MISSING_CALL_ID)
        }
    }

    private companion object {
        val CALL_OUT_SCHEDULED = """
            {
              "call_id": "call_1",
              "case_id": "kyc_9",
              "status": "scheduled",
              "scheduled_at": 1780000000,
              "duration_minutes": 15,
              "join_url": "https://verify.example/join/abc",
              "result": null,
              "created_at": 1779990000,
              "updated_at": 1779990000,
              "note": "Please call in the morning",
              "verifier_sub": null
            }
        """.trimIndent()

        val CALL_OUT_CANCELLED = """
            {
              "call_id": "call_1",
              "case_id": "kyc_9",
              "status": "cancelled",
              "scheduled_at": 1780000000,
              "duration_minutes": 15,
              "join_url": null,
              "result": null
            }
        """.trimIndent()

        val LIST_OUT = """
            {
              "calls": [
                {
                  "call_id": "call_1",
                  "case_id": "kyc_9",
                  "status": "scheduled",
                  "scheduled_at": 1780000000,
                  "duration_minutes": 15,
                  "join_url": "https://verify.example/join/abc"
                },
                {
                  "call_id": "call_2",
                  "case_id": "kyc_9",
                  "status": "cancelled",
                  "scheduled_at": 1779000000,
                  "duration_minutes": 30
                }
              ]
            }
        """.trimIndent()

        val CASE_STATUS_OUT = """
            {
              "verification_call": {
                "status": "scheduled",
                "result": null,
                "scheduled_at": 1780000000,
                "join_url": "https://verify.example/join/abc"
              }
            }
        """.trimIndent()

        val CALL_OUT_MISSING_CALL_ID = """
            {
              "case_id": "kyc_9",
              "status": "scheduled",
              "scheduled_at": 1780000000,
              "duration_minutes": 15
            }
        """.trimIndent()

        val VALIDATION_DETAIL = """
            {
              "detail": [
                { "loc": ["body", "scheduled_at"], "msg": "field required", "type": "value_error.missing" }
              ]
            }
        """.trimIndent()
    }
}
