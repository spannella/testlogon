package com.testlogon.android.feature.messaging.voice

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-133 — recorder-limit policy + player seek mapping (pure JVM). */
class VoiceLogicTest {

    @Test
    fun isKeepable_belowMinIsDropped() {
        assertFalse(RecorderLimits.isKeepable(999))
        assertTrue(RecorderLimits.isKeepable(1_000))
        assertTrue(RecorderLimits.isKeepable(5_000))
    }

    @Test
    fun shouldAutoStop_atMaxDuration() {
        assertFalse(RecorderLimits.shouldAutoStop(119_000))
        assertTrue(RecorderLimits.shouldAutoStop(120_000))
        assertTrue(RecorderLimits.shouldAutoStop(125_000))
    }

    @Test
    fun countdown_onlyInFinalWindow() {
        assertNull(RecorderLimits.countdownSeconds(109_000))
        assertEquals(10, RecorderLimits.countdownSeconds(110_000))
        assertEquals(0, RecorderLimits.countdownSeconds(120_000))
    }

    @Test
    fun clampDuration_cappedAtMax() {
        assertEquals(120_000L, RecorderLimits.clampDuration(125_000))
        assertEquals(5_000L, RecorderLimits.clampDuration(5_000))
        assertEquals(0L, RecorderLimits.clampDuration(-1))
    }

    @Test
    fun playbackState_seekFractionMapping() {
        val state = VoicePlaybackState(durationMs = 10_000L)
        assertEquals(0L, state.positionForFraction(0f))
        assertEquals(5_000L, state.positionForFraction(0.5f))
        assertEquals(10_000L, state.positionForFraction(1f))
        // Out-of-range fractions are clamped.
        assertEquals(10_000L, state.positionForFraction(2f))
        assertEquals(0L, state.positionForFraction(-1f))
    }

    @Test
    fun playbackState_fractionFromPosition() {
        val state = VoicePlaybackState(durationMs = 8_000L, positionMs = 2_000L)
        assertEquals(0.25f, state.fraction, 0.001f)
        // Zero duration never divides by zero.
        assertEquals(0f, VoicePlaybackState(durationMs = 0L, positionMs = 100L).fraction, 0.001f)
    }
}
