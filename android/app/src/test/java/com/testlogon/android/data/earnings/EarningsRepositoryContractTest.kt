package com.testlogon.android.data.earnings

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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-252 — contract tests for [EarningsRepositoryImpl]: concurrent quick-stats + summary combine,
 * correct from_date/to_date/granularity on the summary call (no range param on quick-stats), cache
 * population, and failure handling. A path-based dispatcher is used because the two GETs race.
 */
class EarningsRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private val fixedClock = object : EarningsClock {
        override fun todayEpochDay(): Long = 20613L // 2026-06-09
        override fun nowEpochMs(): Long = 1_749_000_000_000L
    }

    private fun installDispatcher(summary: () -> MockResponse, quickStats: () -> MockResponse) {
        backend.server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                val path = request.path.orEmpty()
                return when {
                    path.startsWith("/ui/earnings/summary") -> summary()
                    path.startsWith("/ui/earnings/quick-stats") -> quickStats()
                    else -> MockResponse().setResponseCode(404)
                }
            }
        }
    }

    private fun repo(): EarningsRepositoryImpl {
        val api = backend.retrofit(moshi).create(EarningsApi::class.java)
        return EarningsRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi), clock = fixedClock)
    }

    private fun json(body: String) =
        MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json").setBody(body)

    @Test
    fun loadDashboard_combinesBothCalls_andSetsCorrectSummaryParams() = runTest {
        installDispatcher({ json(SUMMARY) }, { json(QUICK) })
        val r = repo()
        val result = r.loadDashboard(EarningsRange.D30)
        assertTrue(result is ApiResult.Success)
        val d = (result as ApiResult.Success).data
        assertEquals(1284350L, d.quickStats.allTime.cents)
        assertEquals(318900L, d.summary.total.cents)
        assertEquals(2, d.summary.series.size)
        assertEquals("USD", d.currency)
        assertFalse(d.isStale)
        assertFalse(d.isEmpty)
        assertNotNull(r.cached(EarningsRange.D30))

        val requests = (0 until backend.requestCount).map { backend.takeRequest() }
        val summaryReq = requests.first { it.path.orEmpty().startsWith("/ui/earnings/summary") }
        assertEquals("2026-06-09", summaryReq.requestUrl?.queryParameter("to_date"))
        assertEquals("2026-05-11", summaryReq.requestUrl?.queryParameter("from_date"))
        assertEquals("day", summaryReq.requestUrl?.queryParameter("granularity"))
        val quickReq = requests.first { it.path.orEmpty().startsWith("/ui/earnings/quick-stats") }
        assertNull(quickReq.requestUrl?.queryParameter("from_date"))
    }

    @Test
    fun loadDashboard_all_omitsDates() = runTest {
        installDispatcher({ json(SUMMARY) }, { json(QUICK) })
        repo().loadDashboard(EarningsRange.ALL)
        val requests = (0 until backend.requestCount).map { backend.takeRequest() }
        val summaryReq = requests.first { it.path.orEmpty().startsWith("/ui/earnings/summary") }
        assertNull(summaryReq.requestUrl?.queryParameter("from_date"))
        assertNull(summaryReq.requestUrl?.queryParameter("to_date"))
    }

    @Test
    fun loadDashboard_httpError_mapsToFailure_noCache() = runTest {
        installDispatcher(
            { MockResponse().setResponseCode(500).setBody("""{"detail":"boom"}""") },
            { json(QUICK) },
        )
        val r = repo()
        val result = r.loadDashboard(EarningsRange.D7)
        assertTrue(result is ApiResult.Failure)
        assertNull(r.cached(EarningsRange.D7))
    }

    @Test
    fun emptyData_mapsToEmptyDashboard() = runTest {
        installDispatcher({ json("{}") }, { json("{}") })
        val result = repo().loadDashboard(EarningsRange.D30)
        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data.isEmpty)
    }

    private companion object {
        val SUMMARY = """
            {
              "total_cents": 318900, "currency": "USD", "transaction_count": 87,
              "breakdown": { "subscriptions": 98500, "tips": 40000, "unlocks": 12000, "vod_purchases": 8000, "other": 1500 },
              "time_series": [
                { "date": "2026-05-07", "total": 10200 },
                { "date": "2026-05-08", "total": 9800 }
              ]
            }
        """.trimIndent()
        val QUICK = """
            {
              "today_cents": 4200, "this_week_cents": 31800, "this_month_cents": 120500,
              "all_time_cents": 1284350, "pending_payout_cents": 120000, "currency": "USD"
            }
        """.trimIndent()
    }
}
