package com.testlogon.android.feature.purchases

import com.testlogon.android.data.purchases.Money
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigDecimal
import java.util.Locale

/**
 * AND-219 / AND-222 — [formatMoney] / [formatEpochSeconds] purity: the major-unit decimal is formatted
 * as-is (NOT divided by 100), an unknown currency falls back gracefully, and epoch seconds format to a
 * locale date. Locale is pinned so the assertions are deterministic.
 */
class PurchasesFormatTest {

    @Test
    fun formatMoney_majorUnits_notDividedBy100() {
        val out = formatMoney(Money(BigDecimal("49.00"), "USD"), Locale.US)
        assertEquals("$49.00", out) // not $0.49
    }

    @Test
    fun formatMoney_highPrecisionPreserved() {
        val out = formatMoney(Money(BigDecimal("42.99"), "USD"), Locale.US)
        assertEquals("$42.99", out)
    }

    @Test
    fun formatMoney_unknownCurrency_fallsBack_noCrash() {
        val out = formatMoney(Money(BigDecimal("10.00"), "XYZ"), Locale.US)
        assertTrue(out.contains("10.00"))
        assertTrue(out.contains("XYZ"))
    }

    @Test
    fun formatEpochSeconds_producesNonEmptyDate() {
        // 1748715724 -> a valid date string in the pinned locale (exact text is locale-data dependent).
        val out = formatEpochSeconds(1748715724, Locale.US)
        assertTrue(out.isNotBlank())
    }
}
