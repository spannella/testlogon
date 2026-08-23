package com.testlogon.android.feature.cash

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Money-correctness for the FIAT (USD) Cash screen: dollars<->cents parse/format (exact, no float
 * drift), the $1 minimum deposit rule, and withdraw bounded by both the $1 minimum and the balance.
 */
class CashMathTest {

    // ---- parseDollarsToCents ----

    @Test
    fun parse_exactCentsNoFloatDrift() {
        assertEquals(1099L, CashMath.parseDollarsToCents("10.99"))
        assertEquals(100L, CashMath.parseDollarsToCents("1"))
        assertEquals(150L, CashMath.parseDollarsToCents("1.5"))
        assertEquals(0L, CashMath.parseDollarsToCents("0"))
    }

    @Test
    fun parse_acceptsSymbolCommasAndWhitespace() {
        assertEquals(123456L, CashMath.parseDollarsToCents(" $1,234.56 "))
    }

    @Test
    fun parse_truncatesExtraPrecisionTowardZero() {
        assertEquals(1099L, CashMath.parseDollarsToCents("10.999"))
    }

    @Test
    fun parse_rejectsBlankNegativeAndNonNumeric() {
        assertNull(CashMath.parseDollarsToCents(""))
        assertNull(CashMath.parseDollarsToCents("   "))
        assertNull(CashMath.parseDollarsToCents("-5"))
        assertNull(CashMath.parseDollarsToCents("abc"))
    }

    // ---- formatCents / formatCentsUsd ----

    @Test
    fun format_alwaysTwoDecimals() {
        assertEquals("10.99", CashMath.formatCents(1099L))
        assertEquals("1.00", CashMath.formatCents(100L))
        assertEquals("0.00", CashMath.formatCents(0L))
        assertEquals("1234.56", CashMath.formatCents(123456L))
    }

    @Test
    fun formatUsd_prependsSymbol() {
        assertEquals("$10.99", CashMath.formatCentsUsd(1099L))
        assertEquals("$0.00", CashMath.formatCentsUsd(0L))
    }

    @Test
    fun parseThenFormat_roundTrips() {
        val cents = CashMath.parseDollarsToCents("42.07")!!
        assertEquals("42.07", CashMath.formatCents(cents))
    }

    // ---- sanitizeAmountInput ----

    @Test
    fun sanitize_stripsNonNumericCapsTwoDecimalsAndFirstDot() {
        assertEquals("12.34", CashMath.sanitizeAmountInput("1a2.3b4"))
        assertEquals("1.23", CashMath.sanitizeAmountInput("1.23.45"))
        assertEquals("100", CashMath.sanitizeAmountInput("100"))
        assertEquals("", CashMath.sanitizeAmountInput("abc"))
    }

    // ---- isDepositValid: >= $1 ----

    @Test
    fun depositValid_requiresAtLeastOneDollar() {
        assertTrue(CashMath.isDepositValid("1"))
        assertTrue(CashMath.isDepositValid("1.00"))
        assertTrue(CashMath.isDepositValid("500"))
        assertFalse(CashMath.isDepositValid("0.99"))
        assertFalse(CashMath.isDepositValid("0"))
        assertFalse(CashMath.isDepositValid(""))
        assertFalse(CashMath.isDepositValid("-3"))
    }

    // ---- isWithdrawValid: >= $1 AND <= balance ----

    @Test
    fun withdrawValid_boundedByMinAndBalance() {
        val balance = 5000L // $50.00
        assertTrue(CashMath.isWithdrawValid("1", balance))
        assertTrue(CashMath.isWithdrawValid("50", balance))
        assertTrue(CashMath.isWithdrawValid("49.99", balance))
        assertFalse(CashMath.isWithdrawValid("50.01", balance))     // over balance
        assertFalse(CashMath.isWithdrawValid("0.99", balance))      // under $1
        assertFalse(CashMath.isWithdrawValid("", balance))
    }

    @Test
    fun withdrawValid_zeroBalanceBlocksEverything() {
        assertFalse(CashMath.isWithdrawValid("1", 0L))
    }
}
