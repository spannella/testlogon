package com.testlogon.android.feature.analytics.engagement

import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.Locale

/**
 * AND-254 / AND-257 — locale-aware engagement formatting: 2dp percent, signed delta, grouped counts,
 * and the em-dash placeholder for null values. Locale.GERMANY proves no hard-coded `.`/`,` assumption.
 */
class EngagementFormatTest {

    @Test
    fun percent_twoDecimals_us() {
        assertEquals("9.83%", formatEngagementPercent(9.83, Locale.US))
        assertEquals("0.00%", formatEngagementPercent(0.0, Locale.US))
    }

    @Test
    fun percent_localeGermany_usesCommaDecimal() {
        assertEquals("9,83%", formatEngagementPercent(9.83, Locale.GERMANY))
    }

    @Test
    fun percent_null_isPlaceholder() {
        assertEquals(ENGAGEMENT_PLACEHOLDER, formatEngagementPercent(null, Locale.US))
    }

    @Test
    fun delta_isSigned() {
        assertEquals("+1.17", formatEngagementDelta(1.17, Locale.US))
        assertEquals("-0.50", formatEngagementDelta(-0.5, Locale.US))
        assertEquals("0.00", formatEngagementDelta(0.0, Locale.US))
        assertEquals(ENGAGEMENT_PLACEHOLDER, formatEngagementDelta(null, Locale.US))
    }

    @Test
    fun count_isGrouped() {
        assertEquals("18,450", formatEngagementCount(18450, Locale.US))
        assertEquals("18.450", formatEngagementCount(18450, Locale.GERMANY))
        assertEquals("0", formatEngagementCount(0, Locale.US))
    }
}
