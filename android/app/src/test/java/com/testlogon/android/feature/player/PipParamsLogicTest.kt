package com.testlogon.android.feature.player

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-287 — pure JVM tests for the Picture-in-Picture params decisions shared by the live-broadcast
 * viewer and the existing VOD/messaging/feed callers: aspect clamping, real-video-size preference,
 * the API-31 auto-enter capability gate, and the auto-enter-on-leave predicate. No Android runtime.
 */
class PipParamsLogicTest {

    // --- safeAspect: clamp to Android's permitted [1:2.39 .. 2.39:1] window ------------------------

    @Test
    fun safeAspect_passesThroughInRangeRatios() {
        assertEquals(16 to 9, PipParamsLogic.safeAspect(16, 9))
        assertEquals(9 to 16, PipParamsLogic.safeAspect(9, 16)) // portrait, still within 1:2.39
        assertEquals(1 to 1, PipParamsLogic.safeAspect(1, 1))
    }

    @Test
    fun safeAspect_clampsUltraWideLandscape() {
        // 32:9 (~3.56) exceeds 2.39 -> clamp to 239:100.
        assertEquals(239 to 100, PipParamsLogic.safeAspect(32, 9))
    }

    @Test
    fun safeAspect_clampsUltraTallPortrait() {
        // 9:32 (~0.28) is below 1/2.39 -> clamp to 100:239.
        assertEquals(100 to 239, PipParamsLogic.safeAspect(9, 32))
    }

    @Test
    fun safeAspect_nonPositiveFallsBackTo16by9() {
        assertEquals(16 to 9, PipParamsLogic.safeAspect(0, 0))
        assertEquals(16 to 9, PipParamsLogic.safeAspect(-5, 10))
        assertEquals(16 to 9, PipParamsLogic.safeAspect(10, 0))
    }

    // --- resolveAspect: prefer real player video size, else caller fallback -----------------------

    @Test
    fun resolveAspect_prefersRealVideoSizeWhenKnown() {
        // Live HLS reports 1920x1080 -> that (in-range) wins over a 1:1 fallback.
        assertEquals(1920 to 1080, PipParamsLogic.resolveAspect(1920, 1080, 1, 1))
    }

    @Test
    fun resolveAspect_fallsBackWhenVideoSizeUnknown() {
        // Broadcast not yet sized (0x0) -> use the caller-supplied 16:9 default.
        assertEquals(16 to 9, PipParamsLogic.resolveAspect(0, 0, 16, 9))
    }

    @Test
    fun resolveAspect_clampsRealVideoSizeTooo() {
        // A bizarre ultra-wide stream still gets clamped, never rejected by the system.
        assertEquals(239 to 100, PipParamsLogic.resolveAspect(4000, 500, 16, 9))
    }

    // --- supportsAutoEnter: API 31 (S) capability gate --------------------------------------------

    @Test
    fun supportsAutoEnter_trueOnApi31Plus() {
        assertTrue(PipParamsLogic.supportsAutoEnter(31))
        assertTrue(PipParamsLogic.supportsAutoEnter(34))
    }

    @Test
    fun supportsAutoEnter_falseBelow31() {
        assertFalse(PipParamsLogic.supportsAutoEnter(30)) // R — manual onUserLeaveHint path
        assertFalse(PipParamsLogic.supportsAutoEnter(26)) // O — PiP supported but manual-enter only
        assertFalse(PipParamsLogic.supportsAutoEnter(24)) // pre-PiP
    }

    // --- shouldAutoEnterOnLeave: broadcast-active + PiP-supported ---------------------------------

    @Test
    fun shouldAutoEnterOnLeave_trueWhenBroadcastActiveAndSupported() {
        // Broadcast playing on a PiP-capable device -> leaving the app floats the live stream.
        assertTrue(PipParamsLogic.shouldAutoEnterOnLeave(videoActive = true, pipSupported = true))
    }

    @Test
    fun shouldAutoEnterOnLeave_falseWhenNoActiveVideo() {
        // Left the broadcast (video inactive) -> no PiP on Home.
        assertFalse(PipParamsLogic.shouldAutoEnterOnLeave(videoActive = false, pipSupported = true))
    }

    @Test
    fun shouldAutoEnterOnLeave_falseWhenPipUnsupported() {
        assertFalse(PipParamsLogic.shouldAutoEnterOnLeave(videoActive = true, pipSupported = false))
    }
}
