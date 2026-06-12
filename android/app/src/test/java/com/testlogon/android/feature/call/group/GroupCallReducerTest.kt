package com.testlogon.android.feature.call.group

import com.testlogon.android.data.call.group.ConnQuality
import com.testlogon.android.data.call.group.GroupParticipant
import com.testlogon.android.data.call.group.ParticipantState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-299 — pure unit tests for [GroupCallReducer]. */
class GroupCallReducerTest {

    private fun participant(
        userId: String,
        displayName: String? = userId,
        state: ParticipantState = ParticipantState.Connecting,
        micMuted: Boolean = false,
        cameraOff: Boolean = false,
        quality: ConnQuality = ConnQuality.Unknown,
        joinedAt: Long = 0,
    ) = GroupParticipant(
        userId = userId,
        displayName = displayName,
        isSelf = false,
        isHost = false,
        state = state,
        micMuted = micMuted,
        cameraOff = cameraOff,
        quality = quality,
        joinedAt = joinedAt,
    )

    private fun stateWith(vararg p: GroupParticipant) =
        GroupCallUiState(callId = "c1", phase = GroupCallPhase.Active, participants = p.toList())

    @Test
    fun participantJoined_adds() {
        val out = GroupCallReducer.reduce(stateWith(), GroupCallEvent.ParticipantJoined(participant("u1")))
        assertEquals(1, out.participants.size)
        assertEquals("u1", out.participants.first().userId)
    }

    @Test
    fun participantJoined_isIdempotent_updatesNotDuplicates() {
        val start = stateWith(participant("u1", displayName = "Old", joinedAt = 5))
        val out = GroupCallReducer.reduce(
            start,
            GroupCallEvent.ParticipantJoined(participant("u1", displayName = "New", joinedAt = 5)),
        )
        assertEquals(1, out.participants.size)
        assertEquals("New", out.participants.first().displayName)
    }

    @Test
    fun participantLeft_removesByUserId() {
        val start = stateWith(participant("u1"), participant("u2"))
        val out = GroupCallReducer.reduce(start, GroupCallEvent.ParticipantLeft("u1"))
        assertEquals(listOf("u2"), out.participants.map { it.userId })
    }

    @Test
    fun mediaStatusChanged_updatesMatchingParticipantOnly() {
        val start = stateWith(participant("u1"), participant("u2"))
        val out = GroupCallReducer.reduce(
            start,
            GroupCallEvent.MediaStatusChanged("u2", micMuted = true, cameraOff = true),
        )
        assertFalse(out.participants.first { it.userId == "u1" }.micMuted)
        assertTrue(out.participants.first { it.userId == "u2" }.micMuted)
        assertTrue(out.participants.first { it.userId == "u2" }.cameraOff)
    }

    @Test
    fun stateChanged_updatesMatchingParticipant() {
        val start = stateWith(participant("u1"))
        val out = GroupCallReducer.reduce(
            start,
            GroupCallEvent.StateChanged("u1", ParticipantState.Connected),
        )
        assertEquals(ParticipantState.Connected, out.participants.first().state)
    }

    @Test
    fun qualityChanged_updatesMatchingParticipant() {
        val start = stateWith(participant("u1"))
        val out = GroupCallReducer.reduce(start, GroupCallEvent.QualityChanged("u1", ConnQuality.Poor))
        assertEquals(ConnQuality.Poor, out.participants.first().quality)
    }

    @Test
    fun speaking_setsActiveSpeaker_andClearsOnLeave() {
        val start = stateWith(participant("u1"), participant("u2"))
        val speaking = GroupCallReducer.reduce(start, GroupCallEvent.Speaking("u2", speaking = true))
        assertEquals("u2", speaking.activeSpeakerUserId)
        assertTrue(speaking.participants.first { it.userId == "u2" }.speaking)

        val left = GroupCallReducer.reduce(speaking, GroupCallEvent.ParticipantLeft("u2"))
        assertNull(left.activeSpeakerUserId)
    }

    @Test
    fun speakingFalse_clearsActiveSpeakerForThatUser() {
        val start = stateWith(participant("u1")).copy(activeSpeakerUserId = "u1")
        val out = GroupCallReducer.reduce(start, GroupCallEvent.Speaking("u1", speaking = false))
        assertNull(out.activeSpeakerUserId)
    }

    @Test
    fun callEnded_movesPhaseToEnded() {
        val out = GroupCallReducer.reduce(stateWith(participant("u1")), GroupCallEvent.CallEnded("host_left"))
        assertEquals(GroupCallPhase.Ended, out.phase)
        assertEquals("host_left", out.error)
    }

    @Test
    fun participants_stableSortedByJoinedAtThenName() {
        val start = stateWith()
        val a = GroupCallReducer.reduce(start, GroupCallEvent.ParticipantJoined(participant("late", "Z", joinedAt = 30)))
        val b = GroupCallReducer.reduce(a, GroupCallEvent.ParticipantJoined(participant("early", "A", joinedAt = 10)))
        val c = GroupCallReducer.reduce(b, GroupCallEvent.ParticipantJoined(participant("mid", "M", joinedAt = 10)))
        // joinedAt asc, then displayName asc for ties.
        assertEquals(listOf("early", "mid", "late"), c.participants.map { it.userId })
    }
}
