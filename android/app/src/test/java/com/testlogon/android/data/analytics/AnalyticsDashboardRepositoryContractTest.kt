package com.testlogon.android.data.analytics

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import com.testlogon.android.data.earnings.EarningsClock
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.RecordedRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-399 — contract tests for [AnalyticsDashboardRepositoryImpl] (MockWebServer). Covers the
 * per-metric fan-out assembly, the from_date/to_date params from the injected clock, partial failure
 * (a secondary section 5xx leaves the page renderable), empty-200 -> isEmpty, the recompute POST on
 * refresh, and HTTP/network failure mapping. A path-based dispatcher is used because the GETs race.
 */
class AnalyticsDashboardRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    // 2026-06-05 (inclusive LAST_30 window -> from_date=2026-05-07, to_date=2026-06-05).
    private val fixedClock = object : EarningsClock {
        override fun todayEpochDay(): Long = 20609L
        override fun nowEpochMs(): Long = 1_749_081_600_000L
    }

    private fun repo(): AnalyticsDashboardRepositoryImpl {
        val api = backend.retrofit(moshi).create(AnalyticsDashboardApi::class.java)
        return AnalyticsDashboardRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi), clock = fixedClock)
    }

    private fun json(body: String) =
        MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json").setBody(body)

    private fun installAll(
        overview: () -> MockResponse = { json(OVERVIEW) },
        views: () -> MockResponse = { json(VIEWS) },
        subscribers: () -> MockResponse = { json(SUBSCRIBERS) },
        topContent: () -> MockResponse = { json(TOP_CONTENT) },
        audience: () -> MockResponse = { json(AUDIENCE) },
        refresh: () -> MockResponse = { json("""{"status":"ok"}""") },
    ) {
        backend.server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                val path = request.path.orEmpty()
                return when {
                    path.startsWith("/ui/analytics/refresh") -> refresh()
                    path.startsWith("/ui/analytics/overview") -> overview()
                    path.startsWith("/ui/analytics/views") -> views()
                    path.startsWith("/ui/analytics/subscribers") -> subscribers()
                    path.startsWith("/ui/analytics/top-content") -> topContent()
                    path.startsWith("/ui/analytics/audience") -> audience()
                    else -> MockResponse().setResponseCode(404)
                }
            }
        }
    }

    @Test
    fun loadDashboard_assemblesFanOut_andSendsFromToParams() = runTest {
        installAll()
        val result = repo().loadDashboard(AnalyticsDashboardRange.LAST_30)
        assertTrue(result is ApiResult.Success)
        val d = (result as ApiResult.Success).data
        assertEquals(184320L, d.overview!!.periodViews)
        assertEquals(942180L, d.overview!!.periodRevenueCents)
        assertEquals(1372L, d.overview!!.periodNewSubscribers)
        assertEquals(51240L, d.overview!!.totalSubscribers)
        assertEquals(2, d.views.size)
        assertEquals(2, d.subscribers.size)
        assertEquals(1, d.topContent.size)
        assertEquals(1, d.audienceCountries.size)
        assertEquals(1, d.audienceDevices.size)
        assertFalse(d.isEmpty)

        val requests = (0 until backend.requestCount).map { backend.takeRequest() }
        val overviewReq = requests.first { it.path.orEmpty().startsWith("/ui/analytics/overview") }
        assertEquals("2026-05-07", overviewReq.requestUrl?.queryParameter("from_date"))
        assertEquals("2026-06-05", overviewReq.requestUrl?.queryParameter("to_date"))
    }

    @Test
    fun loadDashboard_partialFailure_audience5xx_pageStillRenders() = runTest {
        installAll(audience = { MockResponse().setResponseCode(503).setBody("""{"detail":"down"}""") })
        val result = repo().loadDashboard(AnalyticsDashboardRange.LAST_30)
        assertTrue(result is ApiResult.Success)
        val d = (result as ApiResult.Success).data
        assertTrue(d.audienceFailed)
        assertTrue(d.audienceCountries.isEmpty())
        // Tiles + other sections survived the partial failure.
        assertEquals(184320L, d.overview!!.periodViews)
        assertEquals(1, d.topContent.size)
        assertFalse(d.isEmpty)
    }

    @Test
    fun loadDashboard_overviewHttpError_mapsToFailure() = runTest {
        installAll(overview = { MockResponse().setResponseCode(422).setBody(VALIDATION_422) })
        val result = repo().loadDashboard(AnalyticsDashboardRange.LAST_30)
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun loadDashboard_emptyPayloads_yieldEmptyDashboard() = runTest {
        installAll(
            overview = { json("{}") },
            views = { json("{}") },
            subscribers = { json("{}") },
            topContent = { json("{}") },
            audience = { json("{}") },
        )
        val result = repo().loadDashboard(AnalyticsDashboardRange.LAST_30)
        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data.isEmpty)
    }

    @Test
    fun refresh_issuesRecomputePost_thenReQueries() = runTest {
        installAll()
        val r = repo()
        val result = r.refresh(AnalyticsDashboardRange.LAST_30)
        assertTrue(result is ApiResult.Success)

        val requests = (0 until backend.requestCount).map { backend.takeRequest() }
        val refresh = requests.first { it.path.orEmpty().startsWith("/ui/analytics/refresh") }
        assertEquals("POST", refresh.method)
        // The metric GETs were re-issued after the recompute.
        assertTrue(requests.any { it.path.orEmpty().startsWith("/ui/analytics/overview") })
    }

    @Test
    fun loadDashboard_hitsOnlyRealPerMetricEndpoints_neverPhantomDashboardOrBreakdown() = runTest {
        // AND-402 / TC-AND-402-07 (gap fill): the web reference assembles the dashboard from discrete
        // per-metric GETs; the corrected contract (spec §5/§16 claims 11-13) deleted the phantom
        // /ui/analytics/dashboard and /ui/analytics/breakdown endpoints. Pin the EXACT path set the
        // repository touches, assert the phantom endpoints are never requested, and assert every
        // metric GET carries from_date/to_date from the injected clock.
        installAll()
        val result = repo().loadDashboard(AnalyticsDashboardRange.LAST_30)
        assertTrue(result is ApiResult.Success)

        val requests = (0 until backend.requestCount).map { backend.takeRequest() }
        val paths = requests.mapNotNull { it.requestUrl?.encodedPath }.toSet()

        // Exactly the real per-metric reads were issued (loadDashboard does not POST refresh).
        assertEquals(
            setOf(
                "/ui/analytics/overview",
                "/ui/analytics/views",
                "/ui/analytics/subscribers",
                "/ui/analytics/top-content",
                "/ui/analytics/audience",
            ),
            paths,
        )

        // The corrected (non-existent) endpoints are never hit.
        assertFalse(paths.any { it.startsWith("/ui/analytics/dashboard") })
        assertFalse(paths.any { it.startsWith("/ui/analytics/breakdown") })

        // Every metric GET is a windowed read carrying from_date/to_date (no start/end).
        for (req in requests) {
            assertEquals("GET", req.method)
            val url = req.requestUrl
            assertEquals("2026-05-07", url?.queryParameter("from_date"))
            assertEquals("2026-06-05", url?.queryParameter("to_date"))
            assertTrue(url?.queryParameter("start") == null)
            assertTrue(url?.queryParameter("end") == null)
        }
    }

    @Test
    fun loadDashboard_populatesCache_forStaleService() = runTest {
        installAll()
        val r = repo()
        r.loadDashboard(AnalyticsDashboardRange.LAST_30)
        val cached = r.cached(AnalyticsDashboardRange.LAST_30)
        assertEquals(184320L, cached!!.overview!!.periodViews)
        r.clear()
        assertTrue(r.cached(AnalyticsDashboardRange.LAST_30) == null)
    }

    @Test
    fun mapping_unitsAndPassthrough() = runTest {
        installAll()
        val d = (repo().loadDashboard(AnalyticsDashboardRange.LAST_30) as ApiResult.Success).data
        val top = d.topContent.first()
        assertEquals(188200L, top.revenueCents)            // integer cents
        assertEquals(0.0613, top.engagementRate, 1e-9)     // 0..1 fraction (NOT scaled)
        assertEquals(318400L, d.views.first().watchTimeSeconds) // integer seconds
        assertEquals(38.0, d.audienceCountries.first().percentage, 1e-9) // 0..100 (NOT scaled)
    }

    private companion object {
        val OVERVIEW = """
            {
              "period_views": 184320, "period_revenue_cents": 942180,
              "period_new_subscribers": 1372, "total_subscribers": 51240, "currency": "USD",
              "top_content": [
                { "content_id": "vid_77", "content_type": "video", "title": "Launch Recap",
                  "views": 41200, "revenue_cents": 188200, "engagement_rate": 0.0613 }
              ]
            }
        """.trimIndent()
        val VIEWS = """
            {
              "time_series": [
                { "date": "2026-05-09", "views": 6210, "unique_viewers": 2110, "watch_time_seconds": 318400 },
                { "date": "2026-05-10", "views": 5980, "unique_viewers": 2010, "watch_time_seconds": 301100 }
              ],
              "total_views": 184320, "total_watch_time_seconds": 9421800
            }
        """.trimIndent()
        val SUBSCRIBERS = """
            {
              "time_series": [
                { "date": "2026-05-09", "new": 120, "churned": 30, "net": 90, "total": 50000 },
                { "date": "2026-05-10", "new": 110, "churned": 20, "net": 90, "total": 50090 }
              ],
              "current_total": 51240, "net_change": 180
            }
        """.trimIndent()
        val TOP_CONTENT = """
            {
              "items": [
                { "content_id": "vid_77", "content_type": "video", "title": "Launch Recap",
                  "views": 41200, "revenue_cents": 188200, "engagement_rate": 0.0613 }
              ],
              "total_items": 1
            }
        """.trimIndent()
        val AUDIENCE = """
            {
              "countries": [ { "code": "US", "name": "United States", "viewers": 70110, "percentage": 38.0 } ],
              "devices": [ { "type": "mobile", "viewers": 51240, "percentage": 61.0 } ],
              "total_unique_viewers": 51240
            }
        """.trimIndent()
        val VALIDATION_422 = """
            {"detail":[{"loc":["query","from_date"],"msg":"invalid date","type":"value_error"}]}
        """.trimIndent()
    }
}
