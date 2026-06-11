package com.testlogon.android.data.analytics

import com.squareup.moshi.Moshi
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-254 / AND-257 — contract tests for [EngagementApi] against MockWebServer (real Retrofit/Moshi):
 * path/verb/period_days query, full EngagementRateOut mapping, defaults tolerance, trend edge cases,
 * and the history endpoint mapping (date degradation included).
 */
class EngagementApiContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun api(): EngagementApi = backend.retrofit(moshi).create(EngagementApi::class.java)

    @Test
    fun getEngagement_path_verb_andPeriodDaysParam() = runTest {
        backend.enqueue(Fixtures.okBody(FULL))
        api().getEngagement() // default 30

        val recorded = backend.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/analytics/engagement", recorded.requestUrl?.encodedPath)
        assertEquals("30", recorded.requestUrl?.queryParameter("period_days"))
        // No date/granularity params on this endpoint.
        assertNull(recorded.requestUrl?.queryParameter("from_date"))
        assertNull(recorded.requestUrl?.queryParameter("granularity"))
    }

    @Test
    fun getEngagement_customPeriod_isSent() = runTest {
        backend.enqueue(Fixtures.okBody(FULL))
        api().getEngagement(periodDays = 90)
        assertEquals("90", backend.takeRequest().requestUrl?.queryParameter("period_days"))
    }

    @Test
    fun getEngagement_mapsAllFields() = runTest {
        backend.enqueue(Fixtures.okBody(FULL))
        val m = api().getEngagement().toMetrics()
        assertEquals(9.83, m.engagementRate!!, 1e-9)
        assertEquals(983, m.engagementRateBps)
        assertEquals(1626, m.totalInteractions)
        assertEquals(18450, m.followerCount)
        assertEquals(42, m.postsInPeriod)
        assertEquals(1320, m.likes)
        assertEquals(210, m.comments)
        assertEquals(96, m.shares)
        assertEquals(0, m.tips)
        assertEquals(Trend.UP, m.trend)
        assertEquals(1.17, m.trendDelta!!, 1e-9)
        assertEquals(30, m.periodDays)
    }

    @Test
    fun getEngagement_emptyBody_decodesToAllZeroSummary() = runTest {
        backend.enqueue(Fixtures.okBody("{}"))
        val m = api().getEngagement().toMetrics()
        assertEquals(0.0, m.engagementRate!!, 1e-9) // never null
        assertEquals(0, m.followerCount)
        assertEquals(Trend.UNKNOWN, m.trend)
        assertNull(m.localReconcileRate) // no followers -> null
    }

    @Test
    fun getEngagement_unexpectedTrendTokens_mapToUnknown() = runTest {
        backend.enqueue(Fixtures.okBody("""{"engagement_rate":1.2,"trend":"rising","follower_count":5}"""))
        val m = api().getEngagement().toMetrics()
        assertEquals(Trend.UNKNOWN, m.trend)
        assertEquals(1.2, m.engagementRate!!, 1e-9)
    }

    @Test
    fun getEngagementHistory_path_verb_mapsItems_andDegradesNonIsoDates() = runTest {
        backend.enqueue(Fixtures.okBody(HISTORY))
        val points = api().getEngagementHistory().toDomain()

        val recorded = backend.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/analytics/engagement/history", recorded.requestUrl?.encodedPath)

        assertEquals(3, points.size)
        assertEquals("2026-05-01", points[0].rawDate)
        assertEquals(20574L, points[0].dateEpochDay) // LocalDate("2026-05-01").toEpochDay()
        assertEquals(983, points[0].engagementRateBps)
        assertEquals(9.83, points[0].engagementRate, 1e-9)
        assertEquals(120, points[0].interactions)
        assertEquals(3, points[0].postCount)
        // weekly/monthly label degrades to null epoch day, raw preserved.
        assertNull(points[2].dateEpochDay)
        assertEquals("2026-W18", points[2].rawDate)
    }

    @Test
    fun getEngagementHistory_emptyBody_isEmptyList() = runTest {
        backend.enqueue(Fixtures.okBody("{}"))
        assertTrue(api().getEngagementHistory().toDomain().isEmpty())
    }

    private companion object {
        val FULL = """
            {
              "engagement_rate": 9.83, "engagement_rate_bps": 983, "period_days": 30,
              "total_interactions": 1626, "follower_count": 18450, "posts_in_period": 42,
              "likes": 1320, "comments": 210, "shares": 96, "tips": 0,
              "trend": "up", "trend_delta": 1.17
            }
        """.trimIndent()

        val HISTORY = """
            {
              "items": [
                { "date": "2026-05-01", "engagement_rate": 9.83, "engagement_rate_bps": 983, "interactions": 120, "post_count": 3 },
                { "date": "2026-05-02", "engagement_rate": 8.10, "engagement_rate_bps": 810, "interactions": 90, "post_count": 2 },
                { "date": "2026-W18", "engagement_rate": 7.50, "engagement_rate_bps": 750, "interactions": 60, "post_count": 1 }
              ]
            }
        """.trimIndent()
    }
}
