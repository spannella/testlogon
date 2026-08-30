package com.testlogon.android.feature.messaging.mute

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * FE-140 — pure unit tests for [MuteMath]. All times are epoch SECONDS; a fixed [NOW] is passed in
 * (no clock reads inside the SUT).
 */
class MuteMathTest {

    private companion object {
        const val NOW = 1_700_000_000L
        const val HOUR = 3_600L
        const val DAY = 86_400L
        const val WEEK = 7L * DAY
    }

    @Test fun muteOptions_hasFourInOrder() {
        assertEquals(
            listOf(MuteMath.OPT_1_HOUR, MuteMath.OPT_8_HOURS, MuteMath.OPT_1_WEEK, MuteMath.OPT_UNTIL_OFF),
            MuteMath.muteOptions(),
        )
    }

    @Test fun computeMutedUntil_oneHour() =
        assertEquals(NOW + HOUR, MuteMath.computeMutedUntil(MuteMath.OPT_1_HOUR, NOW))

    @Test fun computeMutedUntil_eightHours() =
        assertEquals(NOW + 8 * HOUR, MuteMath.computeMutedUntil(MuteMath.OPT_8_HOURS, NOW))

    @Test fun computeMutedUntil_oneWeek() =
        assertEquals(NOW + WEEK, MuteMath.computeMutedUntil(MuteMath.OPT_1_WEEK, NOW))

    @Test fun computeMutedUntil_untilOff_isSentinel() =
        assertEquals(MuteMath.FOREVER_SENTINEL, MuteMath.computeMutedUntil(MuteMath.OPT_UNTIL_OFF, NOW))

    @Test fun computeMutedUntil_unknown_failsShortToOneHour() =
        assertEquals(NOW + HOUR, MuteMath.computeMutedUntil("bogus", NOW))

    @Test fun isMuted_futureIsTrue() = assertTrue(MuteMath.isMuted(NOW + 1, NOW))

    @Test fun isMuted_zeroIsFalse() = assertFalse(MuteMath.isMuted(0L, NOW))

    @Test fun isMuted_pastIsFalse() = assertFalse(MuteMath.isMuted(NOW - 1, NOW))

    @Test fun isMuted_exactlyNowIsFalse() = assertFalse(MuteMath.isMuted(NOW, NOW))

    @Test fun isMuted_sentinelIsTrue() = assertTrue(MuteMath.isMuted(MuteMath.FOREVER_SENTINEL, NOW))

    @Test fun isForever_sentinelTrue_realDateFalse() {
        assertTrue(MuteMath.isForever(MuteMath.FOREVER_SENTINEL))
        assertFalse(MuteMath.isForever(NOW + WEEK))
    }

    @Test fun mutedLabel_notMutedIsEmpty() = assertEquals("", MuteMath.mutedLabel(0L, NOW))

    @Test fun mutedLabel_foreverIsMuted() =
        assertEquals("Muted", MuteMath.mutedLabel(MuteMath.FOREVER_SENTINEL, NOW))

    @Test fun mutedLabel_daysRoundUp() =
        assertEquals("Muted for 7 days", MuteMath.mutedLabel(NOW + WEEK, NOW))

    @Test fun mutedLabel_singularDay() =
        assertEquals("Muted for 1 day", MuteMath.mutedLabel(NOW + DAY, NOW))

    @Test fun mutedLabel_hours() =
        assertEquals("Muted for 8 hours", MuteMath.mutedLabel(NOW + 8 * HOUR, NOW))

    @Test fun mutedLabel_singularHour() =
        assertEquals("Muted for 1 hour", MuteMath.mutedLabel(NOW + HOUR, NOW))

    @Test fun mutedLabel_minutesFallback() =
        assertEquals("Muted for 30 minutes", MuteMath.mutedLabel(NOW + 30 * 60, NOW))

    @Test fun formatMuteOption_labels() {
        assertEquals("1 hour", MuteMath.formatMuteOption(MuteMath.OPT_1_HOUR))
        assertEquals("8 hours", MuteMath.formatMuteOption(MuteMath.OPT_8_HOURS))
        assertEquals("1 week", MuteMath.formatMuteOption(MuteMath.OPT_1_WEEK))
        assertEquals("Until I turn it back on", MuteMath.formatMuteOption(MuteMath.OPT_UNTIL_OFF))
    }
}
