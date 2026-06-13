package com.testlogon.android.core.network.kyc

import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.network.json.BigDecimalAdapter
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory

/**
 * AND-329 - contract tests for [KycMonitoringApi] against MockWebServer with the production-style shared Moshi
 * (BigDecimalAdapter + the KYC enum adapters + KotlinJsonAdapterFactory, mirroring NetworkModule.provideMoshi
 * and the AND-326..328 contract tests). Asserts:
 *   - schedule GET decode of the {schedule:{status,next_review_date,...}} envelope,
 *   - a null schedule ({} / {schedule:null}) decodes to schedule == null,
 *   - triggers GET decode of the {events:[...]} envelope (+ empty list),
 *   - 422 via try/catch (NO nested runTest).
 * Both endpoints are READ-ONLY GETs; the recorded request body is not read (the body is read ONCE, for the
 * 422 error body only).
 */
class KycMonitoringApiContractTest {

    private lateinit var server: MockWebServer

    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(KycCaseStatusAdapter)
        .add(KycFileTypeAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private fun api(): KycMonitoringApi = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
        .create(KycMonitoringApi::class.java)

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
    fun schedule_path_and_decode() = runTest {
        server.enqueue(jsonResponse(SCHEDULE_OUT, code = 200))

        val out = api().schedule()

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/v1/kyc/monitoring/schedule", recorded.requestUrl?.encodedPath)

        val schedule = out.schedule!!
        assertEquals("case_1", schedule.case_id)
        assertEquals("needs_review", schedule.status)
        assertEquals(1_780_000_000L, schedule.next_review_date)
        assertEquals(1_780_500_000L, schedule.grace_deadline)
        assertEquals(1_770_000_000L, schedule.last_review_date)
    }

    @Test
    fun schedule_nullSchedule_decodesNull() = runTest {
        server.enqueue(jsonResponse(NULL_SCHEDULE, code = 200))

        val out = api().schedule()

        assertEquals("GET", server.takeRequest().method)
        assertNull(out.schedule)
    }

    @Test
    fun triggers_path_and_decode() = runTest {
        server.enqueue(jsonResponse(TRIGGERS_OUT, code = 200))

        val out = api().triggers()

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/v1/kyc/monitoring/triggers", recorded.requestUrl?.encodedPath)

        assertEquals(2, out.events.size)
        val first = out.events[0]
        assertEquals("evt_1", first.event_id)
        assertEquals("periodic_review", first.trigger_type)
        assertEquals("case_1", first.case_id)
        assertEquals(1_780_000_000L, first.created_at)
        assertEquals("Annual review due", first.note)
        assertEquals("risk_change", out.events[1].trigger_type)
    }

    @Test
    fun triggers_emptyEvents_decodesEmptyList() = runTest {
        server.enqueue(jsonResponse(EMPTY_TRIGGERS, code = 200))

        val out = api().triggers()

        assertEquals("GET", server.takeRequest().method)
        assertEquals(0, out.events.size)
    }

    @Test
    fun schedule_422_validation_throwsHttpException() = runTest {
        server.enqueue(jsonResponse(VALIDATION_DETAIL, code = 422))
        // assertThrows takes a non-suspend lambda, so catch the suspend call directly (no nested runTest).
        val ex = try {
            api().schedule()
            null
        } catch (e: HttpException) {
            e
        }
        assertEquals(422, ex?.code())
        val raw = ex?.response()?.errorBody()?.string()
        assertEquals(true, raw?.contains("monitoring"))
    }

    private companion object {
        val SCHEDULE_OUT = """
            {
              "schedule": {
                "case_id": "case_1",
                "status": "needs_review",
                "next_review_date": 1780000000,
                "grace_deadline": 1780500000,
                "last_review_date": 1770000000
              }
            }
        """.trimIndent()

        val NULL_SCHEDULE = """
            {
              "schedule": null
            }
        """.trimIndent()

        val TRIGGERS_OUT = """
            {
              "events": [
                {
                  "event_id": "evt_1",
                  "trigger_type": "periodic_review",
                  "case_id": "case_1",
                  "created_at": 1780000000,
                  "note": "Annual review due"
                },
                {
                  "event_id": "evt_2",
                  "trigger_type": "risk_change",
                  "created_at": 1780000100
                }
              ]
            }
        """.trimIndent()

        val EMPTY_TRIGGERS = """
            {
              "events": []
            }
        """.trimIndent()

        val VALIDATION_DETAIL = """
            {
              "detail": [
                { "loc": ["query", "monitoring"], "msg": "invalid", "type": "value_error" }
              ]
            }
        """.trimIndent()
    }
}
