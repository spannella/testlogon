package com.testlogon.android.feature.videos

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** AND-189 — pure duration-badge formatting (seconds -> mm:ss / h:mm:ss; null for non-positive). */
class VideoDurationFormatTest {

    @Test
    fun formatsUnderAnHour_asMmSs() {
        assertEquals("6:12", VideoDurationFormat.badge(372))
        assertEquals("0:05", VideoDurationFormat.badge(5))
    }

    @Test
    fun formatsOverAnHour_asHmmSs() {
        assertEquals("1:30:00", VideoDurationFormat.badge(5400))
    }

    @Test
    fun nullOrNonPositive_yieldsNoBadge() {
        assertNull(VideoDurationFormat.badge(null))
        assertNull(VideoDurationFormat.badge(0))
        assertNull(VideoDurationFormat.badge(-3))
    }
}
