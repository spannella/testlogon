package com.testlogon.android.data.watchparties

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure JVM tests for [WatchPartyMath] (host gating + playback-position sync). */
class WatchPartyMathTest {

    private fun party(
        host: String = "host",
        status: WatchPartyStatus = WatchPartyStatus.PLAYING,
    ) = WatchParty(
        id = "wp_1",
        hostUserSub = host,
        videoId = "vid",
        videoTitle = "Video",
        videoDurationSeconds = 600,
        title = "Party",
        inviteCode = "ABC123",
        status = status,
        maxParticipants = 50,
        participantCount = 3,
        positionSeconds = 0,
        positionUpdatedAtSeconds = 0,
        createdAtSeconds = 1,
        endedAtSeconds = if (status == WatchPartyStatus.ENDED) 2 else null,
    )

    private fun participant(
        sub: String,
        role: ParticipantRole = ParticipantRole.MEMBER,
        status: ParticipantStatus = ParticipantStatus.ACTIVE,
    ) = WatchPartyParticipant(userSub = sub, role = role, status = status, joinedAtSeconds = 1)

    // ---- isHost ----

    @Test
    fun isHost_true_forHostSub() = assertTrue(WatchPartyMath.isHost(party(), "host"))

    @Test
    fun isHost_false_forOther() = assertFalse(WatchPartyMath.isHost(party(), "someone"))

    @Test
    fun isHost_false_forNullOrBlank() {
        assertFalse(WatchPartyMath.isHost(party(), null))
        assertFalse(WatchPartyMath.isHost(party(), ""))
    }

    // ---- canControlPlayback ----

    @Test
    fun canControl_true_forHost() =
        assertTrue(WatchPartyMath.canControlPlayback(party(), emptyList(), "host"))

    @Test
    fun canControl_true_forActiveCoHost() {
        val ps = listOf(participant("bob", ParticipantRole.CO_HOST))
        assertTrue(WatchPartyMath.canControlPlayback(party(), ps, "bob"))
    }

    @Test
    fun canControl_false_forPlainMember() {
        val ps = listOf(participant("bob", ParticipantRole.MEMBER))
        assertFalse(WatchPartyMath.canControlPlayback(party(), ps, "bob"))
    }

    @Test
    fun canControl_false_forLeftCoHost() {
        val ps = listOf(participant("bob", ParticipantRole.CO_HOST, ParticipantStatus.LEFT))
        assertFalse(WatchPartyMath.canControlPlayback(party(), ps, "bob"))
    }

    @Test
    fun canControl_false_whenEnded_evenForHost() =
        assertFalse(WatchPartyMath.canControlPlayback(party(status = WatchPartyStatus.ENDED), emptyList(), "host"))

    // ---- canManageParty / targeting ----

    @Test
    fun canManage_hostOnly_andNotWhenEnded() {
        assertTrue(WatchPartyMath.canManageParty(party(), "host"))
        assertFalse(WatchPartyMath.canManageParty(party(), "bob"))
        assertFalse(WatchPartyMath.canManageParty(party(status = WatchPartyStatus.ENDED), "host"))
    }

    @Test
    fun canTarget_false_forHostSelfAndInactive() {
        val hostP = participant("host", ParticipantRole.HOST)
        val self = participant("host")
        val gone = participant("x", status = ParticipantStatus.KICKED)
        assertFalse(WatchPartyMath.canTargetParticipant(party(), "host", hostP))
        assertFalse(WatchPartyMath.canTargetParticipant(party(), "host", self))
        assertFalse(WatchPartyMath.canTargetParticipant(party(), "host", gone))
    }

    @Test
    fun canTarget_true_forActiveMember() {
        assertTrue(WatchPartyMath.canTargetParticipant(party(), "host", participant("bob")))
    }

    @Test
    fun canPromote_falseWhenAlreadyCoHost_trueForMember() {
        assertFalse(WatchPartyMath.canPromoteToCoHost(party(), "host", participant("bob", ParticipantRole.CO_HOST)))
        assertTrue(WatchPartyMath.canPromoteToCoHost(party(), "host", participant("bob")))
    }

    // ---- normalizeAction ----

    @Test
    fun normalizeAction_mapsValid_andRejectsUnknown() {
        assertEquals("play", WatchPartyMath.normalizeAction("  PLAY "))
        assertEquals("seek", WatchPartyMath.normalizeAction("seek"))
        assertNull(WatchPartyMath.normalizeAction("stop"))
    }

    // ---- targetPositionSeconds ----

    @Test
    fun target_frozenWhenPaused() {
        assertEquals(30.0, WatchPartyMath.targetPositionSeconds(30.0, 100, isPlaying = false, nowEpochSeconds = 200), 0.0001)
    }

    @Test
    fun target_advancesWhenPlaying() {
        // updated at t=100 with pos 30; now t=145 -> 30 + 45
        assertEquals(75.0, WatchPartyMath.targetPositionSeconds(30.0, 100, isPlaying = true, nowEpochSeconds = 145), 0.0001)
    }

    @Test
    fun target_neverNegative_andClampsBackwardsClock() {
        assertEquals(0.0, WatchPartyMath.targetPositionSeconds(-5.0, 100, isPlaying = false, nowEpochSeconds = 200), 0.0001)
        // now BEFORE updatedAt -> elapsed clamps to 0, position unchanged
        assertEquals(30.0, WatchPartyMath.targetPositionSeconds(30.0, 100, isPlaying = true, nowEpochSeconds = 50), 0.0001)
    }

    // ---- shouldReseek ----

    @Test
    fun shouldReseek_falseWithinTolerance_trueBeyond() {
        // host at 75 (30 + 45s), local at 74 -> within 2s
        assertFalse(WatchPartyMath.shouldReseek(30.0, 100, true, localPositionSeconds = 74.0, nowEpochSeconds = 145))
        // local far behind at 60 -> 15s drift
        assertTrue(WatchPartyMath.shouldReseek(30.0, 100, true, localPositionSeconds = 60.0, nowEpochSeconds = 145))
    }

    // ---- formatClock ----

    @Test
    fun formatClock_mmss_and_hhmmss_and_clampNegative() {
        assertEquals("0:05", WatchPartyMath.formatClock(5.0))
        assertEquals("2:03", WatchPartyMath.formatClock(123.0))
        assertEquals("1:01:01", WatchPartyMath.formatClock(3661.0))
        assertEquals("0:00", WatchPartyMath.formatClock(-10.0))
    }
}
