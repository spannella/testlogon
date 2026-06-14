package com.testlogon.android.feature.messaging.thread

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-139 — pure tip-amount parsing + sheet validation (integer cents, [1, 100000] bounds). */
class TipAmountLogicTest {

    @Test
    fun parseDollarsToCents_roundsToNearestCent() {
        assertEquals(750L, parseDollarsToCents("7.50"))
        assertEquals(500L, parseDollarsToCents("5"))
        assertEquals(1L, parseDollarsToCents("0.01"))
        assertEquals(100000L, parseDollarsToCents("1000"))
    }

    @Test
    fun parseDollarsToCents_rejectsBlankNegativeOrGarbage() {
        assertNull(parseDollarsToCents(""))
        assertNull(parseDollarsToCents("   "))
        assertNull(parseDollarsToCents("abc"))
        assertNull(parseDollarsToCents("-5"))
    }

    @Test
    fun tipSheet_confirmEnabledOnlyWithinBounds() {
        val base = TipSheetState(messageId = "m1")
        assertFalse(base.isConfirmEnabled) // no amount
        assertFalse(base.copy(customInput = "0").isConfirmEnabled) // 0 cents < min
        assertFalse(base.copy(customInput = "1000.01").isConfirmEnabled) // > max (100000 cents)
        assertTrue(base.copy(selectedCents = 500).isConfirmEnabled)
        assertTrue(base.copy(customInput = "7.50").isConfirmEnabled)
    }

    @Test
    fun tipSheet_amountFromPresetOrCustom() {
        assertEquals(500L, TipSheetState(selectedCents = 500).amountCents)
        assertEquals(750L, TipSheetState(customInput = "7.50").amountCents)
        assertNull(TipSheetState().amountCents)
    }

    @Test
    fun tipSheet_overLongNoteDisablesConfirm() {
        val longNote = "x".repeat(TipSheetState.MAX_NOTE_LENGTH + 1)
        assertFalse(TipSheetState(selectedCents = 500, note = longNote).isConfirmEnabled)
    }

    @Test
    fun countdownPicker_sendEnabledRequiresTitleAndTarget() {
        assertFalse(CountdownPickerState().isSendEnabled)
        assertFalse(CountdownPickerState(title = "Launch").isSendEnabled) // no target
        assertFalse(CountdownPickerState(targetEpochSeconds = 9999L).isSendEnabled) // no title
        assertTrue(CountdownPickerState(title = "Launch", targetEpochSeconds = 9999L).isSendEnabled)
        assertFalse(CountdownPickerState(title = "x".repeat(201), targetEpochSeconds = 9999L).isSendEnabled)
    }
}
