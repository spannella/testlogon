package com.testlogon.android.feature.adsbilling.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * FE-160 - correctness for the ad-account top-up amount presets + validation + balance projection.
 * Pure integer math (cents), no clock or I/O. The crypto rate-lock math is covered separately by
 * CheckoutCryptoMathTest (reused as-is).
 */
class AdDepositMathTest {

    @Test
    fun presets_are_the_expected_usd_amounts_in_cents() {
        assertEquals(listOf(2_500L, 5_000L, 10_000L, 25_000L), AdDepositMath.PRESET_TOPUPS_CENTS)
    }

    @Test
    fun every_preset_is_valid() {
        AdDepositMath.PRESET_TOPUPS_CENTS.forEach {
            assertTrue("preset $it should be valid", AdDepositMath.isValidTopUpCents(it))
        }
    }

    @Test
    fun min_topup_is_one_dollar_inclusive() {
        assertTrue(AdDepositMath.isValidTopUpCents(100L))
        assertFalse(AdDepositMath.isValidTopUpCents(99L))
    }

    @Test
    fun zero_and_negative_are_invalid() {
        assertFalse(AdDepositMath.isValidTopUpCents(0L))
        assertFalse(AdDepositMath.isValidTopUpCents(-500L))
    }

    @Test
    fun max_topup_is_inclusive_and_above_is_invalid() {
        assertTrue(AdDepositMath.isValidTopUpCents(10_000_000L))
        assertFalse(AdDepositMath.isValidTopUpCents(10_000_001L))
    }

    @Test
    fun topUpLabel_whole_dollars_have_no_decimals() {
        assertEquals("$25", AdDepositMath.topUpLabel(2_500L))
        assertEquals("$100", AdDepositMath.topUpLabel(10_000L))
    }

    @Test
    fun topUpLabel_fractional_dollars_show_two_decimals() {
        assertEquals("$25.50", AdDepositMath.topUpLabel(2_550L))
        assertEquals("$0.05", AdDepositMath.topUpLabel(5L))
    }

    @Test
    fun newBalance_adds_credit() {
        assertEquals(15_000L, AdDepositMath.newBalanceCents(5_000L, 10_000L))
    }

    @Test
    fun newBalance_treats_negatives_as_zero() {
        assertEquals(10_000L, AdDepositMath.newBalanceCents(-1L, 10_000L))
        assertEquals(5_000L, AdDepositMath.newBalanceCents(5_000L, -10_000L))
        assertEquals(0L, AdDepositMath.newBalanceCents(-1L, -1L))
    }

    @Test
    fun newBalance_saturates_on_overflow() {
        assertEquals(Long.MAX_VALUE, AdDepositMath.newBalanceCents(Long.MAX_VALUE, 1L))
    }

    @Test
    fun dollars_to_cents_rounds_half_up_and_clamps() {
        assertEquals(2_500L, AdDepositMath.dollarsToCents(25.0))
        assertEquals(2_555L, AdDepositMath.dollarsToCents(25.554))
        assertEquals(2_556L, AdDepositMath.dollarsToCents(25.555))
        assertEquals(0L, AdDepositMath.dollarsToCents(-5.0))
        assertEquals(0L, AdDepositMath.dollarsToCents(Double.NaN))
    }

    @Test
    fun cents_to_dollars_roundtrips() {
        assertEquals(25.0, AdDepositMath.centsToDollars(2_500L), 0.0001)
        assertEquals(0.05, AdDepositMath.centsToDollars(5L), 0.0001)
    }

    @Test
    fun formatCents_handles_whole_fractional_and_negative() {
        assertEquals("25", AdDepositMath.formatCents(2_500L))
        assertEquals("25.50", AdDepositMath.formatCents(2_550L))
        assertEquals("0.05", AdDepositMath.formatCents(5L))
        assertEquals("-25.50", AdDepositMath.formatCents(-2_550L))
    }
}
