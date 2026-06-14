package com.testlogon.android.feature.billing.config

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Locale

/** AND-248/250 — pure formatter tests: bps -> percent and cents -> locale currency (+ fallback). */
class BillingConfigFormatTest {

    @Test
    fun bps_formatsAsOneDecimalPercent() {
        assertEquals("2.5%", formatBps(250, Locale.US))
        assertEquals("15.0%", formatBps(1500, Locale.US))
        assertEquals("0.0%", formatBps(0, Locale.US))
    }

    @Test
    fun cents_formatsAsLocaleCurrency() {
        assertEquals("$0.25", formatConfigCents(25, "USD", Locale.US))
        assertEquals("$50.00", formatConfigCents(5000, "USD", Locale.US))
    }

    @Test
    fun cents_unknownCurrency_fallsBack() {
        val text = formatConfigCents(1000, "zzz", Locale.US)
        assertTrue(text.contains("ZZZ"))
        assertTrue(text.contains("10.00"))
    }
}
