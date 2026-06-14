package com.testlogon.android.feature.call.group

import com.testlogon.android.data.call.group.ConnQuality
import com.testlogon.android.data.call.group.GroupParticipant
import com.testlogon.android.data.call.group.ParticipantState
import org.junit.Assert.assertEquals
import org.junit.Test

/** AND-300 — pure unit tests for [GridLayoutPolicy.order] (deterministic pin / active-speaker ordering). */
class GridLayoutPolicyOrderTest {

    private fun p(userId: String, joinedAt: Long, isSelf: Boolean = false) = GroupParticipant(
        userId = userId,
        displayName = userId,
        isSelf = isSelf,
        isHost = false,
        state = ParticipantState.Connected,
        micMuted = false,
        cameraOff = false,
        quality = ConnQuality.Good,
        joinedAt = joinedAt,
    )

    private fun ids(list: List<GroupParticipant>) = list.map { it.userId }

    private val roster = listOf(
        p("self", joinedAt = 1, isSelf = true),
        p("b", joinedAt = 2),
        p("c", joinedAt = 3),
        p("d", joinedAt = 4),
    )

    @Test
    fun noPinNoSpeaker_isStableJoinOrder() {
        val out = GridLayoutPolicy.order(roster, pinnedUserId = null, activeSpeakerUserId = null)
        assertEquals(listOf("self", "b", "c", "d"), ids(out))
    }

    @Test
    fun pinned_isFirst_restStableJoinOrder() {
        val out = GridLayoutPolicy.order(roster, pinnedUserId = "c", activeSpeakerUserId = null)
        assertEquals(listOf("c", "self", "b", "d"), ids(out))
    }

    @Test
    fun activeSpeaker_isSecond_whenNotPinned() {
        val out = GridLayoutPolicy.order(roster, pinnedUserId = "c", activeSpeakerUserId = "d")
        assertEquals(listOf("c", "d", "self", "b"), ids(out))
    }

    @Test
    fun activeSpeaker_isFirst_whenNoPin() {
        val out = GridLayoutPolicy.order(roster, pinnedUserId = null, activeSpeakerUserId = "d")
        assertEquals(listOf("d", "self", "b", "c"), ids(out))
    }

    @Test
    fun pinnedActiveSpeaker_isNotDuplicated() {
        val out = GridLayoutPolicy.order(roster, pinnedUserId = "b", activeSpeakerUserId = "b")
        assertEquals(listOf("b", "self", "c", "d"), ids(out))
    }

    @Test
    fun self_keepsJoinOrderSlot_notFloatedToFront() {
        // Self joined first (joinedAt = 1) so it leads the tail; pin/speaker promotion does not change that.
        val out = GridLayoutPolicy.order(roster, pinnedUserId = null, activeSpeakerUserId = null)
        assertEquals("self", ids(out).first())
        // With another participant pinned, self stays at the head of the remaining tail (its join slot).
        val pinned = GridLayoutPolicy.order(roster, pinnedUserId = "d", activeSpeakerUserId = null)
        assertEquals(listOf("d", "self", "b", "c"), ids(pinned))
    }

    @Test
    fun tailSortedByJoinedAtThenUserId() {
        val sameInstant = listOf(
            p("z", joinedAt = 5),
            p("a", joinedAt = 5),
            p("m", joinedAt = 5),
        )
        val out = GridLayoutPolicy.order(sameInstant, pinnedUserId = null, activeSpeakerUserId = null)
        assertEquals(listOf("a", "m", "z"), ids(out))
    }

    @Test
    fun unknownPinOrSpeaker_isIgnoredGracefully() {
        val out = GridLayoutPolicy.order(roster, pinnedUserId = "ghost", activeSpeakerUserId = "phantom")
        assertEquals(listOf("self", "b", "c", "d"), ids(out))
    }

    @Test
    fun identicalInput_producesIdenticalOutput() {
        val a = GridLayoutPolicy.order(roster, pinnedUserId = "c", activeSpeakerUserId = "b")
        val b = GridLayoutPolicy.order(roster, pinnedUserId = "c", activeSpeakerUserId = "b")
        assertEquals(ids(a), ids(b))
    }

    @Test
    fun emptyRoster_returnsEmpty() {
        val out = GridLayoutPolicy.order(emptyList(), pinnedUserId = "x", activeSpeakerUserId = "y")
        assertEquals(emptyList<String>(), ids(out))
    }
}
