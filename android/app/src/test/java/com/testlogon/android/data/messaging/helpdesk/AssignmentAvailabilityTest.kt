package com.testlogon.android.data.messaging.helpdesk

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-378 — TC-AND-378-12: action-availability matrix.
 *
 * Claim is Available only on an unassigned `awaiting_agent` row for an agent. Assign/Transfer are
 * permanently Gated(NO_BACKEND_ROUTE) regardless of capability (spec section 16: no helpdesk route).
 */
class AssignmentAvailabilityTest {

    private val agent = AgentCapabilities(isAgent = true, canAssign = false)
    private val agentWithAssign = AgentCapabilities(isAgent = true, canAssign = true)

    private fun queueItem(
        routing: HelpdeskRoutingState,
        claim: ClaimState,
        active: String? = null,
    ) = HelpdeskQueueItem(
        conversationId = "c1", title = "T", preview = null,
        routingState = routing, claimState = claim,
        activeAgentUserId = active, unreadCount = 0, lastMessageAtEpochSeconds = 1,
    )

    @Test
    fun claim_availableOnly_whenUnassignedAwaitingAgent() {
        val r = assignmentAvailability(HelpdeskRoutingState.AWAITING_AGENT, ClaimState.UNASSIGNED, agent)
        assertEquals(Availability.Available, r[AssignmentAction.CLAIM])
    }

    @Test
    fun claim_hidden_whenAssignedToMe() {
        val r = assignmentAvailability(HelpdeskRoutingState.ASSIGNED, ClaimState.CLAIMED_BY_ME, agent)
        assertEquals(Availability.Hidden, r[AssignmentAction.CLAIM])
    }

    @Test
    fun claim_hidden_whenAssignedToOther() {
        val r = assignmentAvailability(HelpdeskRoutingState.ASSIGNED, ClaimState.CLAIMED_BY_OTHER, agent)
        assertEquals(Availability.Hidden, r[AssignmentAction.CLAIM])
    }

    @Test
    fun claim_hidden_whenClosed() {
        val r = assignmentAvailability(HelpdeskRoutingState.CLOSED, ClaimState.UNASSIGNED, agent)
        assertEquals(Availability.Hidden, r[AssignmentAction.CLAIM])
    }

    @Test
    fun claim_hidden_whenNotAnAgent() {
        val caps = AgentCapabilities(isAgent = false)
        val r = assignmentAvailability(HelpdeskRoutingState.AWAITING_AGENT, ClaimState.UNASSIGNED, caps)
        assertEquals(Availability.Hidden, r[AssignmentAction.CLAIM])
    }

    @Test
    fun assign_and_transfer_alwaysGated_evenWithCapability() {
        val r = assignmentAvailability(
            HelpdeskRoutingState.ASSIGNED,
            ClaimState.CLAIMED_BY_ME,
            agentWithAssign,
        )
        assertEquals(Availability.Gated(GateReason.NO_BACKEND_ROUTE), r[AssignmentAction.ASSIGN])
        assertEquals(Availability.Gated(GateReason.NO_BACKEND_ROUTE), r[AssignmentAction.TRANSFER])
    }

    @Test
    fun isClaimable_helper_matchesMatrix() {
        assertTrue(queueItem(HelpdeskRoutingState.AWAITING_AGENT, ClaimState.UNASSIGNED).isClaimable(agent))
        assertFalse(
            queueItem(HelpdeskRoutingState.ASSIGNED, ClaimState.CLAIMED_BY_OTHER, "usr_other")
                .isClaimable(agent),
        )
    }
}
