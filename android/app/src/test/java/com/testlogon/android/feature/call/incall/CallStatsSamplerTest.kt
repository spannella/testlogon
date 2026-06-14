package com.testlogon.android.feature.call.incall

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * AND-298 — table-driven tests for the pure [classifyConnectionQuality] thresholds. No android, no SDK.
 */
class CallStatsSamplerTest {

    @Test
    fun classify_excellent_whenLowRttAndLoss() {
        assertEquals(
            ConnectionQuality.EXCELLENT,
            classifyConnectionQuality(rttMs = 80, packetLossPct = 1.0, iceDisconnected = false, msSinceLastStats = null),
        )
    }

    @Test
    fun classify_good_whenModerateRttAndLoss() {
        assertEquals(
            ConnectionQuality.GOOD,
            classifyConnectionQuality(rttMs = 200, packetLossPct = 3.0, iceDisconnected = false, msSinceLastStats = null),
        )
    }

    @Test
    fun classify_poor_whenHighRttAndLoss() {
        assertEquals(
            ConnectionQuality.POOR,
            classifyConnectionQuality(rttMs = 400, packetLossPct = 8.0, iceDisconnected = false, msSinceLastStats = null),
        )
    }

    @Test
    fun classify_lost_whenIceDisconnected() {
        assertEquals(
            ConnectionQuality.LOST,
            classifyConnectionQuality(rttMs = 80, packetLossPct = 1.0, iceDisconnected = true, msSinceLastStats = null),
        )
    }

    @Test
    fun classify_lost_whenStatsStale() {
        assertEquals(
            ConnectionQuality.LOST,
            classifyConnectionQuality(rttMs = 80, packetLossPct = 1.0, iceDisconnected = false, msSinceLastStats = 7_000),
        )
    }

    @Test
    fun classify_unknown_whenNoStatsYet() {
        assertEquals(
            ConnectionQuality.UNKNOWN,
            classifyConnectionQuality(rttMs = null, packetLossPct = null, iceDisconnected = false, msSinceLastStats = null),
        )
    }
}
