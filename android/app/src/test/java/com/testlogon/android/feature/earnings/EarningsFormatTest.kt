package com.testlogon.android.feature.earnings

import com.testlogon.android.data.earnings.EarningsBreakdown
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Locale

/** AND-252 — pure breakdown rows (sort/share/zero-filter) + bucket-label + money formatting. */
class EarningsFormatTest {

    @Test
    fun money_formatsCentsToMajorUnits_us() {
        assertEquals("$3,189.00", formatEarningsMoney(318900, "USD", Locale.US))
        assertEquals("$2.70", formatEarningsMoney(270, "USD", Locale.US))
    }

    @Test
    fun money_unknownCurrency_fallsBack() {
        val out = formatEarningsMoney(1000, "ZZZ", Locale.US)
        assertTrue(out.contains("ZZZ"))
        assertTrue(out.contains("10.00"))
    }

    @Test
    fun breakdown_sortedDesc_zerosFiltered_sharesFromCents() {
        val b = EarningsBreakdown(
            subscriptions = 98500,
            tips = 40000,
            unlocks = 0,
            vodPurchases = 8000,
            other = 0,
            currencyCode = "USD",
        )
        val rows = b.toRows()
        // unlocks (0) and other (0) hidden
        assertEquals(3, rows.size)
        assertEquals(EarningsSource.SUBSCRIPTIONS, rows[0].source)
        assertEquals(EarningsSource.TIPS, rows[1].source)
        assertEquals(EarningsSource.VOD_PURCHASES, rows[2].source)
        // total = 146500; subs share = round(98500/146500*100) = 67
        assertEquals(67, rows[0].sharePct)
        assertEquals(27, rows[1].sharePct)
        assertEquals(5, rows[2].sharePct)
    }

    @Test
    fun breakdown_allZero_emptyRows() {
        val b = EarningsBreakdown(0, 0, 0, 0, 0, "USD")
        assertTrue(b.toRows().isEmpty())
    }

    @Test
    fun bucketLabel_parseableVsRaw() {
        // 2026-05-01 == epoch day 20574 -> "05-01"
        assertEquals("05-01", formatBucketLabel(20574L, "2026-05-01"))
        assertEquals("2026-W18", formatBucketLabel(null, "2026-W18"))
    }

    @Test
    fun publishedDate_zeroIsUnknown() {
        assertEquals(null, formatPublishedDate(0L))
        assertEquals(null, formatPublishedDate(null))
    }
}
