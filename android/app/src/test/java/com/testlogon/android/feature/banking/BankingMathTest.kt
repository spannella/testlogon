package com.testlogon.android.feature.banking

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure JVM unit tests for [BankingMath] — money formatting + metadata validation rules. */
class BankingMathTest {

    // ─── Balance / amount formatting ─────────────────────────────────────────

    @Test
    fun formatBalance_uppercasesCurrency_groupsThousands_twoDecimals() {
        assertEquals("USD 1,234.50", BankingMath.formatBalance(1234.5, "usd"))
    }

    @Test
    fun formatBalance_zeroAndSmall() {
        assertEquals("USD 0.00", BankingMath.formatBalance(0.0, "usd"))
        assertEquals("USD 0.05", BankingMath.formatBalance(0.05, "USD"))
    }

    @Test
    fun formatBalance_blankCurrency_dropsCode() {
        assertEquals("42.00", BankingMath.formatBalance(42.0, "  "))
    }

    @Test
    fun formatBalance_largeGrouping() {
        assertEquals("EUR 1,000,000.00", BankingMath.formatBalance(1_000_000.0, "eur"))
    }

    @Test
    fun formatAmount2dp_roundsHalfUp() {
        assertEquals("2.35", BankingMath.formatAmount2dp(2.345))
        assertEquals("0.10", BankingMath.formatAmount2dp(0.1))
    }

    @Test
    fun formatAmount2dp_negativePreservesSign() {
        assertEquals("-1,234.50", BankingMath.formatAmount2dp(-1234.5))
    }

    @Test
    fun formatAmount2dp_negativeZeroHasNoSign() {
        // -0.001 rounds to 0.00 -> no leading minus
        assertEquals("0.00", BankingMath.formatAmount2dp(-0.001))
    }

    @Test
    fun formatTxnAmount_parsesDecimalString() {
        assertEquals("USD 12.50", BankingMath.formatTxnAmount("12.5", "usd"))
        assertEquals("USD -3.40", BankingMath.formatTxnAmount("-3.4", "USD"))
    }

    @Test
    fun formatTxnAmount_nonNumericPassthrough() {
        assertEquals("USD n/a", BankingMath.formatTxnAmount("n/a", "usd"))
    }

    @Test
    fun isDebit_detectsNegative() {
        assertTrue(BankingMath.isDebit("-5.00"))
        assertFalse(BankingMath.isDebit("5.00"))
        assertFalse(BankingMath.isDebit("0"))
        assertFalse(BankingMath.isDebit("garbage"))
    }

    // ─── Account subtitle ────────────────────────────────────────────────────

    @Test
    fun accountSubtitle_prefersMaskedThenIbanThenRouting() {
        assertEquals("••1234", BankingMath.accountSubtitle("••1234", "DE89", "021000021"))
        assertEquals("DE89", BankingMath.accountSubtitle(" ", "DE89", "021000021"))
        assertEquals("Routing 021000021", BankingMath.accountSubtitle(null, null, "021000021"))
        assertNull(BankingMath.accountSubtitle(null, "", "  "))
    }

    // ─── Metadata validation (mirrors backend Field constraints) ─────────────

    @Test
    fun narrativeValidation_nonBlankUpToMax() {
        assertTrue(BankingMath.isValidNarrative("hello"))
        assertFalse(BankingMath.isValidNarrative("   "))
        assertFalse(BankingMath.isValidNarrative(""))
        assertTrue(BankingMath.isValidNarrative("a".repeat(BankingMath.NARRATIVE_MAX)))
        assertFalse(BankingMath.isValidNarrative("a".repeat(BankingMath.NARRATIVE_MAX + 1)))
    }

    @Test
    fun tagValidation_nonBlankUpToMax() {
        assertTrue(BankingMath.isValidTag("groceries"))
        assertFalse(BankingMath.isValidTag(""))
        assertTrue(BankingMath.isValidTag("a".repeat(BankingMath.TAG_MAX)))
        assertFalse(BankingMath.isValidTag("a".repeat(BankingMath.TAG_MAX + 1)))
    }

    @Test
    fun commentValidation_nonBlankUpToMax() {
        assertTrue(BankingMath.isValidComment("nice"))
        assertFalse(BankingMath.isValidComment("  "))
        assertTrue(BankingMath.isValidComment("a".repeat(BankingMath.COMMENT_MAX)))
        assertFalse(BankingMath.isValidComment("a".repeat(BankingMath.COMMENT_MAX + 1)))
    }

    @Test
    fun geotagValidation_rangeChecks() {
        assertTrue(BankingMath.isValidLat(90.0))
        assertTrue(BankingMath.isValidLat(-90.0))
        assertFalse(BankingMath.isValidLat(90.1))
        assertTrue(BankingMath.isValidLon(180.0))
        assertFalse(BankingMath.isValidLon(-180.5))
    }

    @Test
    fun geotagValidation_stringPair() {
        assertTrue(BankingMath.isValidGeotag("40.7", "-74.0"))
        assertFalse(BankingMath.isValidGeotag("abc", "-74.0"))
        assertFalse(BankingMath.isValidGeotag("40.7", "999"))
        assertFalse(BankingMath.isValidGeotag("", ""))
    }
}
