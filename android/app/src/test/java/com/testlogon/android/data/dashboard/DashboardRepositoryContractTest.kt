package com.testlogon.android.data.dashboard

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** AND-065 — contract tests for the dashboard data layer against MockWebServer (real Retrofit/Moshi). */
class DashboardRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    // Codegen adapters resolve without the reflection factory; matches SessionsRepositoryContractTest.
    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): DashboardRepositoryImpl {
        val api = backend.retrofit(moshi).create(DashboardApi::class.java)
        return DashboardRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun getDashboard_loadsAndMapsToDomain() = runTest {
        backend.enqueue(Fixtures.okBody(FIXTURE))
        val result = repo().getDashboard()
        assertTrue(result is ApiResult.Success)
        val dashboard = (result as ApiResult.Success).data
        assertEquals(12750L, dashboard.todayEarningsCents)
        assertEquals(8000L, dashboard.earningsBreakdown.subscriptions)
        assertEquals(1280L, dashboard.totalSubscribers)
        assertEquals(1, dashboard.topContent.size)
        assertEquals(1, dashboard.activeBroadcasts.size)
        assertEquals(1, dashboard.recentMilestones.size)
        assertEquals("USD", dashboard.currency)
        assertEquals(1749126600L * 1000L, dashboard.generatedAtMillis)

        val recorded = backend.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/dashboard/summary", recorded.requestUrl?.encodedPath)
    }

    @Test
    fun getDashboard_ignoresUnknownKeys() = runTest {
        backend.enqueue(Fixtures.okBody("""{"today_earnings_cents":5,"unknown_field":42,"earnings_breakdown":{"subscriptions":1,"surprise":9}}"""))
        val result = repo().getDashboard()
        assertTrue(result is ApiResult.Success)
        assertEquals(5L, (result as ApiResult.Success).data.todayEarningsCents)
        assertEquals(1L, result.data.earningsBreakdown.subscriptions)
    }

    @Test
    fun getDashboard_httpError_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("\"Service unavailable\"", 500))
        val result = repo().getDashboard()
        assertTrue(result is ApiResult.Failure)
        assertEquals(500, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun getDashboard_transportFailure_mapsToNetworkError() = runTest {
        backend.enqueue(Fixtures.disconnect())
        val result = repo().getDashboard()
        assertTrue(result is ApiResult.NetworkError)
    }

    @Test
    fun forceRefresh_postsRefreshThenReadsSummary() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true,"message":"queued","refreshed_at":1749126600}"""))
        backend.enqueue(Fixtures.okBody(FIXTURE))
        val result = repo().getDashboard(forceRefresh = true)
        assertTrue(result is ApiResult.Success)

        val refresh = backend.takeRequest()
        assertEquals("POST", refresh.method)
        assertEquals("/ui/dashboard/refresh", refresh.requestUrl?.encodedPath)
        val summary = backend.takeRequest()
        assertEquals("GET", summary.method)
        assertEquals("/ui/dashboard/summary", summary.requestUrl?.encodedPath)
    }

    @Test
    fun successPopulatesCache() = runTest {
        backend.enqueue(Fixtures.okBody(FIXTURE))
        val r = repo()
        r.getDashboard()
        assertTrue(r.cachedDashboard() != null)
    }

    private companion object {
        val FIXTURE = """
            {
              "today_earnings_cents": 12750,
              "earnings_breakdown": { "subscriptions": 8000, "tips": 2500, "unlocks": 1500, "vod_purchases": 750, "other": 0 },
              "period_views": 18342,
              "period_revenue_cents": 96000,
              "total_subscribers": 1280,
              "top_content": [ { "content_id": "c_1", "content_type": "video", "title": "Best of May", "views": 5400, "revenue_cents": 32000 } ],
              "active_broadcasts": [ { "session_id": "b_1", "status": "live", "name": "Live Q&A", "started_at": "2026-06-05T12:00:00Z" } ],
              "recent_milestones": [ { "milestone_id": "m_1", "user_id": "u_1", "metric": "subscribers", "threshold": 1000, "current_value": 1280, "formatted": "1,000 subscribers", "achieved_at": 1748952000, "acknowledged": false } ],
              "currency": "USD",
              "generated_at": 1749126600,
              "warnings": []
            }
        """.trimIndent()
    }
}
