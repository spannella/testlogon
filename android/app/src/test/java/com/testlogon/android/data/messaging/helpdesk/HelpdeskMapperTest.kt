package com.testlogon.android.data.messaging.helpdesk

import com.testlogon.android.data.messaging.ConversationDto
import com.testlogon.android.data.messaging.ParticipantDto
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** AND-161/AND-162 — pure mapper tests: ConversationOut -> queue item, ClaimState, claim result, sort. */
class HelpdeskMapperTest {

    private fun convo(
        id: String = "conv_1",
        title: String? = "Cannot access my account",
        routingState: String? = "awaiting_agent",
        activeAgent: String? = null,
        lastMessageAt: Long? = 1749132069,
        participants: List<ParticipantDto> = emptyList(),
    ) = ConversationDto(
        conversationId = id,
        title = title,
        lastMessagePreview = "I tried resetting but...",
        lastMessageAt = lastMessageAt,
        unreadCount = 2,
        routingState = routingState,
        activeAgentUserId = activeAgent,
        participants = participants,
    )

    @Test
    fun queueItem_mapsFields_epochSecondsPreserved() {
        val item = convo().toHelpdeskQueueItem(currentUserId = "usr_me")
        assertEquals("conv_1", item.conversationId)
        assertEquals("Cannot access my account", item.title)
        assertEquals("I tried resetting but...", item.preview)
        assertEquals(HelpdeskRoutingState.AWAITING_AGENT, item.routingState)
        assertEquals(2, item.unreadCount)
        assertEquals(1749132069L, item.lastMessageAtEpochSeconds)
        assertEquals(ClaimState.UNASSIGNED, item.claimState)
    }

    @Test
    fun claimState_threeWayDerivation() {
        assertEquals(ClaimState.UNASSIGNED, deriveClaimState(null, "usr_me"))
        assertEquals(ClaimState.UNASSIGNED, deriveClaimState("", "usr_me"))
        assertEquals(ClaimState.CLAIMED_BY_ME, deriveClaimState("usr_me", "usr_me"))
        assertEquals(ClaimState.CLAIMED_BY_OTHER, deriveClaimState("usr_other", "usr_me"))
    }

    @Test
    fun title_fallsBackToNonSelfParticipantName() {
        val item = convo(
            title = null,
            participants = listOf(
                ParticipantDto(userId = "usr_123", displayName = "Jamie R."),
                ParticipantDto(userId = "usr_me", displayName = "Me"),
            ),
        ).toHelpdeskQueueItem(currentUserId = "usr_me")
        assertEquals("Jamie R.", item.title)
    }

    @Test
    fun title_nullWhenNoParticipantsOrTitle() {
        val item = convo(title = null, participants = emptyList()).toHelpdeskQueueItem("usr_me")
        assertNull(item.title)
    }

    @Test
    fun sort_unassignedFirstThenMostRecent() {
        val items = listOf(
            convo(id = "claimed_old", activeAgent = "usr_x", lastMessageAt = 100),
            convo(id = "unassigned_old", activeAgent = null, lastMessageAt = 50),
            convo(id = "unassigned_new", activeAgent = null, lastMessageAt = 200),
        ).map { it.toHelpdeskQueueItem("usr_me") }.sortedForQueue()
        assertEquals(listOf("unassigned_new", "unassigned_old", "claimed_old"), items.map { it.conversationId })
    }

    @Test
    fun claimResult_assignedToMeVsOther() {
        val me = HelpdeskClaimOutDto(
            ok = true, conversationId = "c1", state = "assigned",
            assignedAgentUserId = "usr_me", assignmentVersion = 3, idempotent = false,
        ).toResult(currentUserId = "usr_me")
        assertEquals(HelpdeskAssignment.ASSIGNED_TO_ME, me.assignment)

        val other = HelpdeskClaimOutDto(
            ok = true, conversationId = "c1", state = "assigned",
            assignedAgentUserId = "usr_other", assignmentVersion = 4, idempotent = false,
        ).toResult(currentUserId = "usr_me")
        assertEquals(HelpdeskAssignment.ASSIGNED_TO_OTHER, other.assignment)

        val closed = HelpdeskClaimOutDto(
            ok = true, conversationId = "c1", state = "closed",
            assignedAgentUserId = "usr_me", assignmentVersion = 5,
        ).toResult("usr_me")
        assertEquals(HelpdeskAssignment.CLOSED, closed.assignment)
    }
}
