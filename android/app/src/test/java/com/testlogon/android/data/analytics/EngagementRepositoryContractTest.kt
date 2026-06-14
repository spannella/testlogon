package com.testlogon.android.data.analytics

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.RecordedRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-254 / AND-257 — contract tests for [EngagementRepositoryImpl]: concurrent rate + history combine,
 * the period_days param on the rate call, history best-effort degradation, and HTTP/network failure
 * mapping. A path-based dispatcher is used because the two GETs race.
 */
class EngagementRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun installDispatcher(rate: () -> MockResponse, history: () -> MockResponse) {
        backend.server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                val path = request.path.orEmpty()
                return when {
                    path.startsWith("/ui/analytics/engagement/history") -> history()
                    path.startsWith("/ui/analytics/engagement") -> rate()
                    else -> MockResponse().setResponseCode(404)
                }
            }
        }
    }

    private fun repo(): EngagementRepositoryImpl {
        val api = backend.retrofit(moshi).create(EngagementApi::class.java)
        return EngagementRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    private fun json(body: String) =
        MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json").setBody(body)

    @Test
    fun load_combinesRateAndHistory_andSendsPeriodDays() = runTest {
        installDispatcher({ json(RATE) }, { json(HISTORY) })
        val result = repo().load(90)
        assertTrue(result is ApiResult.Success)
        val e = (result as ApiResult.Success).data
        assertEquals(9.83, e.metrics.engagementRate!!, 1e-9)
        assertEquals(2, e.trend.size)
        assertEquals(983, e.trend[0].engagementRateBps)

        val requests = (0 until backend.requestCount).map { backend.takeRequest() }
        val rateReq = requests.first {
            val p = it.path.orEmpty()
            p.startsWith("/ui/analytics/engagement") && !p.startsWith("/ui/analytics/engagement/history")
        }
        assertEquals("90", rateReq.requestUrl?.queryParameter("period_days"))
    }

    @Test
    fun load_historyFails_butRateOk_yieldsSuccessWithEmptyTrend() = runTest {
        installDispatcher({ json(RATE) }, { MockResponse().setResponseCode(500).setBody("""{"detail":"x"}""") })
        val result = repo().load()
        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data.trend.isEmpty())
    }

    @Test
    fun load_rateHttpError_mapsToFailure() = runTest {
        installDispatcher({ MockResponse().setResponseCode(500).setBody("""{"detail":"boom"}""") }, { json(HISTORY) })
        val result = repo().load()
        assertTrue(result is ApiResult.Failure)
    }

    @Test
    fun load_emptyRate_yieldsSuccess_withEmptyEngagement() = runTest {
        installDispatcher({ json("{}") }, { json("{}") })
        val result = repo().load()
        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data.isEmpty)
    }

    private companion object {
        val RATE = """
            {
              "engagement_rate": 9.83, "engagement_rate_bps": 983, "period_days": 30,
              "total_interactions": 1626, "follower_count": 18450, "posts_in_period": 42,
              "likes": 1320, "comments": 210, "shares": 96, "tips": 0, "trend": "up", "trend_delta": 1.17
            }
        """.trimIndent()
        val HISTORY = """
            {
              "items": [
                { "date": "2026-05-01", "engagement_rate": 9.83, "engagement_rate_bps": 983, "interactions": 120, "post_count": 3 },
                { "date": "2026-05-02", "engagement_rate": 8.10, "engagement_rate_bps": 810, "interactions": 90, "post_count": 2 }
              ]
            }
        """.trimIndent()
    }
}
