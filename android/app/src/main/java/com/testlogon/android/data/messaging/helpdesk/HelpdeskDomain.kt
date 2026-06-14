package com.testlogon.android.data.messaging.helpdesk

import com.testlogon.android.data.messaging.ConversationDto

/**
 * AND-161 / AND-162 — domain models + pure mappers for the helpdesk queue and claim.
 *
 * JVM-pure (no android.* / java.time API-26). Timestamps stay epoch-SECONDS Longs; the UI formats them.
 */

/** Claim ownership relative to the current agent. */
enum class ClaimState { UNASSIGNED, CLAIMED_BY_ME, CLAIMED_BY_OTHER }

/** Backend routing/assignment state for a helpdesk conversation. */
enum class HelpdeskRoutingState {
    AWAITING_AGENT,
    ASSIGNED,
    PAUSED_NO_AGENTS_ONLINE,
    CLOSED,
    UNKNOWN,
    ;

    companion object {
        fun fromWire(value: String?): HelpdeskRoutingState = when (value?.lowercase()) {
            "awaiting_agent" -> AWAITING_AGENT
            "assigned" -> ASSIGNED
            "paused_no_agents_online" -> PAUSED_NO_AGENTS_ONLINE
            "closed" -> CLOSED
            else -> UNKNOWN
        }
    }
}

/** AND-162 — assignment of a helpdesk conversation relative to the current agent. */
enum class HelpdeskAssignment { UNCLAIMED, ASSIGNED_TO_ME, ASSIGNED_TO_OTHER, CLOSED }

/** One row in the helpdesk queue (mapped from ConversationOut). */
data class HelpdeskQueueItem(
    val conversationId: String,
    val title: String?,
    val preview: String?,
    val routingState: HelpdeskRoutingState,
    val claimState: ClaimState,
    val activeAgentUserId: String?,
    val unreadCount: Int,
    val lastMessageAtEpochSeconds: Long?,
)

/** AND-162 — result of a claim, reconciled against the current user id. */
data class HelpdeskClaimResult(
    val conversationId: String,
    val assignment: HelpdeskAssignment,
    val assignedAgentUserId: String,
    val assignmentVersion: Int,
    val idempotent: Boolean,
)

// ---- pure mappers ----

/** Derive [ClaimState] by comparing `active_agent_user_id` to the current user id. */
internal fun deriveClaimState(activeAgentUserId: String?, currentUserId: String?): ClaimState = when {
    activeAgentUserId.isNullOrBlank() -> ClaimState.UNASSIGNED
    activeAgentUserId == currentUserId -> ClaimState.CLAIMED_BY_ME
    else -> ClaimState.CLAIMED_BY_OTHER
}

/**
 * ConversationOut -> HelpdeskQueueItem. Title falls back to the first non-self participant display name
 * (matching the web HelpdeskPage.tsx). `last_message_at` is epoch-SECONDS.
 */
internal fun ConversationDto.toHelpdeskQueueItem(currentUserId: String?): HelpdeskQueueItem {
    val resolvedTitle = title?.takeIf { it.isNotBlank() }
        ?: participants.firstOrNull { it.userId != currentUserId }?.displayName?.takeIf { it.isNotBlank() }
        ?: participants.firstNotNullOfOrNull { it.displayName?.takeIf(String::isNotBlank) }
    return HelpdeskQueueItem(
        conversationId = conversationId,
        title = resolvedTitle,
        preview = lastMessagePreview ?: lastMessage?.preview ?: lastMessage?.text,
        routingState = HelpdeskRoutingState.fromWire(routingState),
        claimState = deriveClaimState(activeAgentUserId, currentUserId),
        activeAgentUserId = activeAgentUserId,
        unreadCount = unreadCount,
        lastMessageAtEpochSeconds = lastMessageAt,
    )
}

/**
 * AND-161 — sort fallback when the backend does not pre-sort: unassigned first, then most-recent first.
 * Deterministic and unit-tested.
 */
internal fun List<HelpdeskQueueItem>.sortedForQueue(): List<HelpdeskQueueItem> =
    sortedWith(
        compareBy<HelpdeskQueueItem> { it.claimState != ClaimState.UNASSIGNED }
            .thenByDescending { it.lastMessageAtEpochSeconds ?: 0L },
    )

/** AND-162 — map the claim response `state` + assigned agent to the client assignment, vs current user. */
internal fun HelpdeskClaimOutDto.toResult(currentUserId: String?): HelpdeskClaimResult {
    val routing = HelpdeskRoutingState.fromWire(state)
    val assignment = when (routing) {
        HelpdeskRoutingState.CLOSED -> HelpdeskAssignment.CLOSED
        HelpdeskRoutingState.ASSIGNED ->
            if (assignedAgentUserId.isNotBlank() && assignedAgentUserId == currentUserId) {
                HelpdeskAssignment.ASSIGNED_TO_ME
            } else {
                HelpdeskAssignment.ASSIGNED_TO_OTHER
            }
        else -> HelpdeskAssignment.UNCLAIMED
    }
    return HelpdeskClaimResult(
        conversationId = conversationId,
        assignment = assignment,
        assignedAgentUserId = assignedAgentUserId,
        assignmentVersion = assignmentVersion,
        idempotent = idempotent,
    )
}
