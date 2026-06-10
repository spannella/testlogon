package com.testlogon.android.feature.messaging.presence

import org.junit.Assert.assertEquals
import org.junit.Test

/** AND-145 — pure "last seen" relative phrasing from epoch seconds. */
class RelativeLastSeenTest {

    private val now = 1_000_000L

    @Test
    fun underAMinuteIsMomentsAgo() {
        assertEquals("moments ago", relativeLastSeen(now, now - 30))
    }

    @Test
    fun minutesBucket() {
        assertEquals("5m ago", relativeLastSeen(now, now - 5 * 60))
    }

    @Test
    fun hoursBucket() {
        assertEquals("2h ago", relativeLastSeen(now, now - 2 * 3_600))
    }

    @Test
    fun daysBucket() {
        assertEquals("3d ago", relativeLastSeen(now, now - 3 * 86_400))
    }

    @Test
    fun futureTimestampClampsToMomentsAgo() {
        assertEquals("moments ago", relativeLastSeen(now, now + 500))
    }
}
