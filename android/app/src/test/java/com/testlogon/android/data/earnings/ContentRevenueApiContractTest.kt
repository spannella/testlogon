package com.testlogon.android.data.earnings

import com.squareup.moshi.Moshi
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test

/** AND-253 — contract + mapping tests for [ContentRevenueApi]. */
class ContentRevenueApiContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()
    private fun api() = backend.retrofit(moshi).create(ContentRevenueApi::class.java)

    @Test
    fun list_defaults_pathVerbAndParams() = runTest {
        backend.enqueue(Fixtures.okBody(LIST))
        api().list()
        val r = backend.takeRequest()
        assertEquals("GET", r.method)
        assertEquals("/ui/analytics/content-revenue", r.requestUrl?.encodedPath)
        assertEquals("total_cents", r.requestUrl?.queryParameter("sort_by"))
        assertEquals("desc", r.requestUrl?.queryParameter("sort_order"))
        assertEquals("50", r.requestUrl?.queryParameter("limit"))
        assertNull(r.requestUrl?.queryParameter("from_date"))
        assertNull(r.requestUrl?.queryParameter("content_type"))
        assertNull(r.requestUrl?.queryParameter("cursor"))
        assertNull(r.requestUrl?.queryParameter("user_sub"))
    }

    @Test
    fun list_customSortAndFilters_emittedExactly() = runTest {
        backend.enqueue(Fixtures.okBody(LIST))
        api().list(
            fromDate = "2026-05-01",
            toDate = "2026-05-31",
            sortBy = "tips_cents",
            sortOrder = "asc",
            contentType = "video",
            limit = 100,
            cursor = "C1",
        )
        val r = backend.takeRequest()
        assertEquals("2026-05-01", r.requestUrl?.queryParameter("from_date"))
        assertEquals("2026-05-31", r.requestUrl?.queryParameter("to_date"))
        assertEquals("tips_cents", r.requestUrl?.queryParameter("sort_by"))
        assertEquals("asc", r.requestUrl?.queryParameter("sort_order"))
        assertEquals("video", r.requestUrl?.queryParameter("content_type"))
        assertEquals("100", r.requestUrl?.queryParameter("limit"))
        assertEquals("C1", r.requestUrl?.queryParameter("cursor"))
    }

    @Test
    fun list_mapsAllFields_andDefaults() = runTest {
        backend.enqueue(Fixtures.okBody(LIST))
        val page = api().list().toDomain()
        assertEquals(137, page.totalItems)
        assertEquals(1894322L, page.totalRevenueCents)
        assertEquals("USD", page.currency)
        assertEquals("eyJvIjo1MH0=", page.nextCursor)
        assertEquals(2, page.items.size)
        val full = page.items[0]
        assertEquals("ct_123", full.contentId)
        assertEquals("video", full.contentType)
        assertEquals("Behind the scenes", full.title)
        assertEquals(1717200000L, full.publishedAtEpochSec)
        assertEquals(27050L, full.totalCents)
        assertEquals(350L, full.adsCents)
        // second item omits optionals -> defaults; title falls back to id for display
        val sparse = page.items[1]
        assertEquals("ct_999", sparse.contentId)
        assertEquals("post", sparse.contentType)
        assertEquals("", sparse.title)
        assertEquals("ct_999", sparse.displayTitle)
        assertEquals(0L, sparse.publishedAtEpochSec)
        assertEquals(0L, sparse.totalCents)
    }

    @Test
    fun list_lastPage_nextCursorNull() = runTest {
        backend.enqueue(Fixtures.okBody("""{"items":[],"total_items":0,"total_revenue_cents":0,"next_cursor":null,"currency":"USD"}"""))
        val page = api().list().toDomain()
        assertNull(page.nextCursor)
        assertEquals(0, page.items.size)
    }

    @Test
    fun detail_mapsSeries() = runTest {
        backend.enqueue(Fixtures.okBody(DETAIL))
        val d = api().detail("ct_123").toDomain()
        assertEquals("ct_123", d.content.contentId)
        assertEquals("USD", d.currency)
        assertEquals(1, d.series.size)
        assertEquals("2026-05-07", d.series[0].rawDate)
        assertEquals(20580L, d.series[0].dateEpochDay) // 2026-05-07 == 2026-05-01 (20574) + 6
        assertEquals(10200L, d.series[0].totalCents)
    }

    private companion object {
        val LIST = """
            {
              "items": [
                { "content_id": "ct_123", "content_type": "video", "title": "Behind the scenes",
                  "published_at": 1717200000, "tips_cents": 4500, "unlocks_cents": 12000,
                  "subscriptions_cents": 8000, "ads_cents": 350, "vod_cents": 2200, "total_cents": 27050 },
                { "content_id": "ct_999" }
              ],
              "total_items": 137,
              "total_revenue_cents": 1894322,
              "next_cursor": "eyJvIjo1MH0=",
              "currency": "USD"
            }
        """.trimIndent()

        val DETAIL = """
            {
              "content_id": "ct_123", "content_type": "video", "title": "Behind the scenes",
              "published_at": 1717200000, "total_cents": 27050, "currency": "USD",
              "time_series": [ { "date": "2026-05-07", "total_cents": 10200, "tips_cents": 3000 } ]
            }
        """.trimIndent()
    }
}
