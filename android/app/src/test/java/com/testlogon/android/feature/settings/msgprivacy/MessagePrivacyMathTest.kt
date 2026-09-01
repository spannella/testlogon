package com.testlogon.android.feature.settings.msgprivacy

import com.testlogon.android.feature.settings.msgprivacy.MessagePrivacyMath.MinTipResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** TIP-B4 (TIP-404) — pure unit tests for the pay-to-message validation + formatting logic. */
class MessagePrivacyMathTest {

    // --- validateMinTip: gate ON ---

    @Test
    fun requireOn_validAmount_returnsCents() {
        val r = MessagePrivacyMath.validateMinTip(requireTip = true, dollarsInput = "5")
        assertEquals(MinTipResult.Valid(500), r)
    }

    @Test
    fun requireOn_decimalAmount_roundsToCents() {
        val r = MessagePrivacyMath.validateMinTip(requireTip = true, dollarsInput = "2.99")
        assertEquals(MinTipResult.Valid(299), r)
    }

    @Test
    fun requireOn_zero_isInvalidTooLow() {
        val r = MessagePrivacyMath.validateMinTip(requireTip = true, dollarsInput = "0")
        assertEquals(MinTipResult.Invalid(MessagePrivacyMath.ERROR_TOO_LOW), r)
    }

    @Test
    fun requireOn_negative_isInvalidTooLow() {
        val r = MessagePrivacyMath.validateMinTip(requireTip = true, dollarsInput = "-3")
        assertEquals(MinTipResult.Invalid(MessagePrivacyMath.ERROR_TOO_LOW), r)
    }

    @Test
    fun requireOn_blank_isInvalidTooLow() {
        val r = MessagePrivacyMath.validateMinTip(requireTip = true, dollarsInput = "   ")
        assertEquals(MinTipResult.Invalid(MessagePrivacyMath.ERROR_TOO_LOW), r)
    }

    @Test
    fun requireOn_nonNumeric_isInvalidTooLow() {
        val r = MessagePrivacyMath.validateMinTip(requireTip = true, dollarsInput = "abc")
        assertEquals(MinTipResult.Invalid(MessagePrivacyMath.ERROR_TOO_LOW), r)
    }

    @Test
    fun requireOn_aboveMax_isInvalidTooHigh() {
        val r = MessagePrivacyMath.validateMinTip(requireTip = true, dollarsInput = "1000.01")
        assertEquals(MinTipResult.Invalid(MessagePrivacyMath.ERROR_TOO_HIGH), r)
    }

    @Test
    fun requireOn_exactlyMax_isValid() {
        val r = MessagePrivacyMath.validateMinTip(requireTip = true, dollarsInput = "1000")
        assertEquals(MinTipResult.Valid(MessagePrivacyMath.MAX_MIN_TIP_CENTS), r)
    }

    @Test
    fun requireOn_whitespacePadded_isTrimmed() {
        val r = MessagePrivacyMath.validateMinTip(requireTip = true, dollarsInput = "  7.50 ")
        assertEquals(MinTipResult.Valid(750), r)
    }

    // --- validateMinTip: gate OFF (advisory) ---

    @Test
    fun requireOff_blank_coalescesToZero() {
        val r = MessagePrivacyMath.validateMinTip(requireTip = false, dollarsInput = "")
        assertEquals(MinTipResult.Valid(0), r)
    }

    @Test
    fun requireOff_negative_coalescesToZero() {
        val r = MessagePrivacyMath.validateMinTip(requireTip = false, dollarsInput = "-9")
        assertEquals(MinTipResult.Valid(0), r)
    }

    @Test
    fun requireOff_positive_preservesCents() {
        val r = MessagePrivacyMath.validateMinTip(requireTip = false, dollarsInput = "4")
        assertEquals(MinTipResult.Valid(400), r)
    }

    // --- dollars <-> cents ---

    @Test
    fun dollarsToCents_roundsHalfUp() {
        assertEquals(300, MessagePrivacyMath.dollarsToCents(2.999))
        assertEquals(0, MessagePrivacyMath.dollarsToCents(0.0))
        assertEquals(0, MessagePrivacyMath.dollarsToCents(-5.0))
    }

    @Test
    fun centsToDollarsField_positive() {
        assertEquals("5.0", MessagePrivacyMath.centsToDollarsField(500))
    }

    @Test
    fun centsToDollarsField_zeroShowsDefault() {
        assertEquals(MessagePrivacyMath.DEFAULT_MIN_TIP_DOLLARS, MessagePrivacyMath.centsToDollarsField(0))
    }

    @Test
    fun centsToDollarsField_negativeShowsDefault() {
        assertEquals(MessagePrivacyMath.DEFAULT_MIN_TIP_DOLLARS, MessagePrivacyMath.centsToDollarsField(-1))
    }

    // --- allowlist helpers ---

    @Test
    fun duplicateAllowlist_caseInsensitive() {
        assertTrue(MessagePrivacyMath.isDuplicateAllowlistEntry(listOf("User-1"), "user-1"))
    }

    @Test
    fun duplicateAllowlist_trimsInput() {
        assertTrue(MessagePrivacyMath.isDuplicateAllowlistEntry(listOf("bob"), "  bob "))
    }

    @Test
    fun duplicateAllowlist_absentReturnsFalse() {
        assertFalse(MessagePrivacyMath.isDuplicateAllowlistEntry(listOf("alice"), "bob"))
    }

    @Test
    fun normalizeAllowlistInput_blankIsNull() {
        assertEquals(null, MessagePrivacyMath.normalizeAllowlistInput("   "))
    }

    @Test
    fun normalizeAllowlistInput_trimsValue() {
        assertEquals("carol", MessagePrivacyMath.normalizeAllowlistInput("  carol "))
    }

    // --- degrade-on-404 ---

    @Test
    fun missingConfig_404_isBenign() {
        assertTrue(MessagePrivacyMath.isBenignMissingConfig(404))
    }

    @Test
    fun missingConfig_otherStatus_isNotBenign() {
        assertFalse(MessagePrivacyMath.isBenignMissingConfig(500))
        assertFalse(MessagePrivacyMath.isBenignMissingConfig(null))
    }
}
