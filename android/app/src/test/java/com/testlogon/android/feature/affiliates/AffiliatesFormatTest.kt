package com.testlogon.android.feature.affiliates

import com.testlogon.android.data.affiliates.AffiliateLink
import com.testlogon.android.data.affiliates.AffiliateMoney
import com.testlogon.android.data.affiliates.LinkStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-265 — pure affiliate format + chart-mapping + share-URL tests. */
class AffiliatesFormatTest {

    private fun link(
        id: String = "afl_1",
        short: String = "/r/abc",
        commissionCents: Long = 1000,
    ) = AffiliateLink(
        id = id,
        label = "L",
        shortUrl = short,
        destinationUrl = "https://x",
        trackingCode = "abc",
        commissionPercent = 10.0,
        status = LinkStatus.ACTIVE,
        rawStatus = "active",
        clicks = 5,
        uniqueClicks = 4,
        conversions = 1,
        revenue = AffiliateMoney(2000, "USD"),
        commissionEarned = AffiliateMoney(commissionCents, "USD"),
        conversionRatePct = 5.0,
        createdAtEpochSeconds = 1,
        updatedAtEpochSeconds = 2,
    )

    @Test
    fun shareUrl_prefixesWebOrigin_relativePath() {
        assertEquals("https://app.testlogon.com/r/abc", link(short = "/r/abc").shareUrl("https://app.testlogon.com"))
    }

    @Test
    fun shareUrl_handlesNonLeadingSlash() {
        assertEquals("https://app.testlogon.com/r/abc", link(short = "r/abc").shareUrl("https://app.testlogon.com/"))
    }

    @Test
    fun commissionSeriesGeometry_reusesChartCore_nonZero() {
        val geo = listOf(link(commissionCents = 100), link(commissionCents = 300)).commissionSeriesGeometry()
        assertFalse(geo.isEmpty)
        assertEquals(2, geo.points.size)
    }

    @Test
    fun commissionSeriesGeometry_allZero_isEmpty() {
        val geo = listOf(link(commissionCents = 0)).commissionSeriesGeometry()
        assertTrue(geo.isEmpty)
    }

    @Test
    fun formatPercent_appendsPercentSign() {
        assertTrue(formatPercent(10.0, java.util.Locale.US).endsWith("%"))
        assertTrue(formatPercent(10.0, java.util.Locale.US).startsWith("10"))
    }
}
