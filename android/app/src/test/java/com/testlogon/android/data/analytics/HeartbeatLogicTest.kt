package com.testlogon.android.data.analytics

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-171 / AND-172 — pure JVM tests for the heartbeat scheduling/accounting logic: the playing edge,
 * interval clamping, watched-time clamping (seek resistance), and the verified phase -> server-call
 * mapping (VOD one-shot vs broadcast join/heartbeat/leave). No Media3 / Retrofit / Android.
 */
class HeartbeatLogicTest {

    @Test
    fun isPlaying_onlyWhenReadyAndPlayWhenReady() {
        assertTrue(HeartbeatLogic.isPlaying(HeartbeatLogic.STATE_READY, playWhenReady = true))
        assertFalse(HeartbeatLogic.isPlaying(HeartbeatLogic.STATE_READY, playWhenReady = false))
        assertFalse(HeartbeatLogic.isPlaying(2 /* buffering */, playWhenReady = true))
        assertFalse(HeartbeatLogic.isPlaying(4 /* ended */, playWhenReady = true))
    }

    @Test
    fun clampInterval_bounds() {
        assertEquals(5_000L, HeartbeatLogic.clampInterval(1_000L))
        assertEquals(10_000L, HeartbeatLogic.clampInterval(10_000L))
        assertEquals(60_000L, HeartbeatLogic.clampInterval(120_000L))
    }

    // TC-AND-171-10 — watched-time clamping resists seeks.
    @Test
    fun watchedMsDelta_clampedToIntervalAndPosition_whenVod() {
        // Normal: wall ~10s, position advanced ~10s, interval 10s -> 10s.
        assertEquals(
            10_000L,
            HeartbeatLogic.watchedMsDelta(10_000L, 10_000L, 10_000L, isLive = false, speed = 1f),
        )
        // Forward seek: position delta 60s but wall only 10s and interval 10s -> clamped to 10s.
        assertEquals(
            10_000L,
            HeartbeatLogic.watchedMsDelta(10_000L, 10_000L, 60_000L, isLive = false, speed = 1f),
        )
        // Backward seek: negative position delta -> 0 watched.
        assertEquals(
            0L,
            HeartbeatLogic.watchedMsDelta(10_000L, 10_000L, -5_000L, isLive = false, speed = 1f),
        )
        // Stall: wall 30s but interval bound caps it to 10s.
        assertEquals(
            10_000L,
            HeartbeatLogic.watchedMsDelta(30_000L, 10_000L, 12_000L, isLive = false, speed = 1f),
        )
    }

    @Test
    fun watchedMsDelta_liveIgnoresPositionDelta() {
        // Live has no meaningful position delta; bounded only by wall vs interval*speed.
        assertEquals(
            10_000L,
            HeartbeatLogic.watchedMsDelta(10_000L, 10_000L, positionDeltaMs = 0L, isLive = true, speed = 1f),
        )
    }

    @Test
    fun watchedMsDelta_respectsSpeed() {
        // 2x speed over a 10s interval allows up to 20s watched (wall measured 18s).
        assertEquals(
            18_000L,
            HeartbeatLogic.watchedMsDelta(18_000L, 10_000L, 18_000L, isLive = true, speed = 2f),
        )
    }

    // AND-171 §5.1 — verified phase -> server-call mapping.
    @Test
    fun callMapping_contentIsOneShotView() {
        val content = PlaybackTarget.Content("vid_1")
        assertTrue(HeartbeatLogic.startCallsServer(content))   // record view once
        assertFalse(HeartbeatLogic.heartbeatCallsServer(content)) // no periodic VOD call
        assertFalse(HeartbeatLogic.stopCallsServer(content))      // no stop call
    }

    @Test
    fun callMapping_broadcastIsJoinHeartbeatLeave() {
        val bc = PlaybackTarget.Broadcast("sess_1")
        assertTrue(HeartbeatLogic.startCallsServer(bc))      // join
        assertTrue(HeartbeatLogic.heartbeatCallsServer(bc))  // periodic heartbeat
        assertTrue(HeartbeatLogic.stopCallsServer(bc))       // leave
    }

    @Test
    fun playbackTarget_kindStrings() {
        assertEquals("content", PlaybackTarget.Content("x").kind)
        assertEquals("broadcast", PlaybackTarget.Broadcast("x").kind)
    }
}
