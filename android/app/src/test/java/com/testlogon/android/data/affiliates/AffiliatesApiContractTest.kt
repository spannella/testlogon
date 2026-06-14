package com.testlogon.android.data.affiliates

import com.squareup.moshi.Moshi
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-265 — contract tests for [AffiliatesApi] against MockWebServer (real Retrofit/Moshi).
 * Asserts a single GET ui/affiliates/links with NO query params, mapping (cents + percentages +
 * lenient status), client-side earnings aggregation, and sparse-payload defaults.
 */
class AffiliatesApiContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun api(): AffiliatesApi = backend.retrofit(moshi).create(AffiliatesApi::class.java)

    @Test
    fun getLinks_path_verb_noQueryParams() = runTest {
        backend.enqueue(Fixtures.okBody(LINKS_FULL))
        api().getLinks()
        val recorded = backend.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/affiliates/links", recorded.requestUrl?.encodedPath)
        assertTrue(recorded.requestUrl?.querySize == 0)
    }

    @Test
    fun getLinks_mapsFields_andAggregatesEarnings() = runTest {
        backend.enqueue(Fixtures.okBody(LINKS_FULL))
        val domain = api().getLinks().toDomain("USD")

        assertEquals(2, domain.links.size)
        val first = domain.links[0]
        assertEquals("My Product", first.label)
        assertEquals("/r/abc123", first.shortUrl)
        assertEquals(LinkStatus.ACTIVE, first.status)
        assertEquals(1840L, first.clicks)
        assertEquals(92L, first.conversions)
        assertEquals(4827310L, first.revenue.cents)
        assertEquals(482731L, first.commissionEarned.cents)
        assertEquals(10.0, first.commissionPercent, 0.001)
        // unknown status -> OTHER
        assertEquals(LinkStatus.OTHER, domain.links[1].status)

        // Aggregation = Σ of per-link cents/counts.
        assertEquals(482731L + 1000L, domain.earnings.totalEarned.cents)
        assertEquals(4827310L + 5000L, domain.earnings.totalRevenue.cents)
        assertEquals(1840L + 10L, domain.earnings.totalClicks)
        assertEquals(92L + 1L, domain.earnings.totalConversions)
        assertEquals(2L, domain.earnings.linkCount)
    }

    @Test
    fun getLinks_sparsePayload_defaultsTolerated() = runTest {
        backend.enqueue(Fixtures.okBody("""{"links":[{"link_id":"afl_1"}]}"""))
        val domain = api().getLinks().toDomain("USD")
        val link = domain.links.single()
        assertEquals("afl_1", link.id)
        assertEquals(0L, link.clicks)
        assertEquals(0L, link.commissionEarned.cents)
        assertTrue(link.label.isEmpty())
    }

    @Test
    fun getLinks_emptyLinks_isEmptyDashboard() = runTest {
        backend.enqueue(Fixtures.okBody("""{"links":[]}"""))
        val domain = api().getLinks().toDomain("USD")
        assertTrue(domain.isEmpty)
        assertEquals(0L, domain.earnings.totalEarned.cents)
    }

    private companion object {
        val LINKS_FULL = """
            {
              "links": [
                {
                  "link_id": "afl_1", "affiliate_user_id": "usr_a", "product_owner_id": "usr_b",
                  "target_type": "catalog_item", "target_id": "cat_1", "target_name": "My Product",
                  "tracking_code": "abc123", "short_url": "/r/abc123",
                  "destination_url": "https://testlogon.com/p/cat_1",
                  "commission_percent": 10, "status": "active",
                  "click_count": 1840, "unique_click_count": 1502, "conversion_count": 92,
                  "revenue_cents": 4827310, "commission_earned_cents": 482731,
                  "conversion_rate_pct": 5.0, "created_at": 1748000000, "updated_at": 1748100000
                },
                {
                  "link_id": "afl_2", "target_name": "Another", "tracking_code": "xyz",
                  "short_url": "/r/xyz", "status": "paused",
                  "click_count": 10, "conversion_count": 1,
                  "revenue_cents": 5000, "commission_earned_cents": 1000,
                  "created_at": 1748000000, "updated_at": 1748000000
                }
              ]
            }
        """.trimIndent()
    }
}
