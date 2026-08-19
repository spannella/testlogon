package com.testlogon.android.feature.custody

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Money-safety decision logic for the custody transfer/withdraw forms (extracted from
 * [CustodyViewModel]). Covers the money-correctness rules that used to be untestable inside the
 * ViewModel: positive-amount required, over-spend blocked ONLY against an EXACT source (never against
 * best-effort guidance), Max respecting the source decimals, and the decimal-input sanitizer.
 */
class MoneySafetyTest {

    private fun exact(v: Double?) = MoneySafety.Source(amount = v, exact = true)
    private fun guidance(v: Double?) = MoneySafety.Source(amount = v, exact = false)

    // ---- positiveAmount ----

    @Test
    fun positiveAmount_requiresStrictlyPositiveNumber() {
        assertEquals(1.5, MoneySafety.positiveAmount("1.5"))
        assertEquals(2.0, MoneySafety.positiveAmount("  2 "))
        assertNull(MoneySafety.positiveAmount("0"))
        assertNull(MoneySafety.positiveAmount("-3"))
        assertNull(MoneySafety.positiveAmount(""))
        assertNull(MoneySafety.positiveAmount("abc"))
    }

    // ---- overspends: EXACT source blocks, guidance never blocks ----

    @Test
    fun overspends_blocksWhenAmountExceedsExactSource() {
        assertTrue(MoneySafety.overspends("10", exact(5.0)))
    }

    @Test
    fun overspends_allowsAmountAtOrBelowExactSource() {
        assertFalse(MoneySafety.overspends("5", exact(5.0)))
        assertFalse(MoneySafety.overspends("4.99", exact(5.0)))
    }

    @Test
    fun overspends_neverBlocksBestEffortGuidance() {
        // A settle/best-effort source is guidance only — over-spend must NOT block.
        assertFalse(MoneySafety.overspends("1000000", guidance(5.0)))
    }

    @Test
    fun overspends_unknownSourceDoesNotBlock() {
        assertFalse(MoneySafety.overspends("10", exact(null)))
    }

    @Test
    fun overspends_nonPositiveAmountIsNotAnOverspend() {
        // A blank/zero amount is a separate positive-amount error, not an over-spend.
        assertFalse(MoneySafety.overspends("0", exact(5.0)))
        assertFalse(MoneySafety.overspends("", exact(5.0)))
    }

    // ---- canMax / maxValue: only meaningful for EXACT + known ----

    @Test
    fun canMax_trueOnlyForExactKnownSource() {
        assertTrue(MoneySafety.canMax(exact(5.0)))
        assertFalse(MoneySafety.canMax(exact(null)))
        assertFalse(MoneySafety.canMax(guidance(5.0)))
    }

    @Test
    fun maxValue_trimsWholeNumbersAndKeepsFractions() {
        assertEquals("5", MoneySafety.maxValue(exact(5.0)))
        assertEquals("2.5", MoneySafety.maxValue(exact(2.5)))
    }

    @Test
    fun maxValue_nullWhenNotMeaningful() {
        assertNull(MoneySafety.maxValue(guidance(5.0)))
        assertNull(MoneySafety.maxValue(exact(null)))
    }

    // ---- trimDecimal ----

    @Test
    fun trimDecimal_dropsTrailingZeroForWholeNumbers() {
        assertEquals("7", MoneySafety.trimDecimal(7.0))
        assertEquals("0", MoneySafety.trimDecimal(0.0))
        assertEquals("0.25", MoneySafety.trimDecimal(0.25))
    }

    // ---- sanitizeDecimal ----

    @Test
    fun sanitizeDecimal_stripsNonNumericAndExtraDots() {
        assertEquals("12.34", MoneySafety.sanitizeDecimal("1a2.3b4"))
        // only the FIRST dot survives.
        assertEquals("1.2345", MoneySafety.sanitizeDecimal("1.23.45"))
        assertEquals("100", MoneySafety.sanitizeDecimal("100"))
        assertEquals("", MoneySafety.sanitizeDecimal("abc"))
    }

    @Test
    fun sanitizeDecimal_capsLength() {
        val long = "1".repeat(40)
        assertEquals(24, MoneySafety.sanitizeDecimal(long).length)
    }
}
