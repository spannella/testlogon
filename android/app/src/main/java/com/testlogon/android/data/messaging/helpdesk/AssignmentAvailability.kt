package com.testlogon.android.data.messaging.helpdesk

/**
 * AND-378 — pure, JVM-testable action-availability matrix for the helpdesk
 * claim / assign / transfer affordances (FR-4).
 *
 * IMPORTANT scope correction (spec section 16): the helpdesk backend exposes ONLY
 * `POST messaging/helpdesk/conversations/{id}/claim` and `GET messaging/helpdesk/queue`.
 * There is NO helpdesk `assign` endpoint and NO helpdesk `transfer` endpoint (and no
 * transfer-to-queue route anywhere). Therefore this ticket ships CLAIM as a real,
 * backend-backed action and keeps ASSIGN / TRANSFER permanently GATED OFF
 * (Availability.Gated) so they are never presented as functional. When/if the backend
 * adds those routes the gate reason flips here without touching the call sites.
 *
 * This resolver is intentionally dependency-free (no android.*, no network types) so the
 * availability rules are unit-tested in isolation (TC-AND-378-12).
 */

/** The three assignment-style actions discussed in the spec. */
enum class AssignmentAction { CLAIM, ASSIGN, TRANSFER }

/** Whether an action is offered, and if not, why. */
sealed interface Availability {
    /** The action is offered and functional. */
    data object Available : Availability

    /**
     * The action is not offered for the current row/agent state but COULD be in another
     * state (a normal UX hint, e.g. claim on an already-assigned row).
     */
    data object Hidden : Availability

    /**
     * The action is structurally unsupported by the backend right now (assign / transfer):
     * it must never be shown as functional regardless of client capability hints.
     */
    data class Gated(val reason: GateReason) : Availability
}

/** Why an action is gated off independent of the current row state. */
enum class GateReason {
    /** No backend endpoint exists for this action (assign / transfer). */
    NO_BACKEND_ROUTE,
}

/**
 * Client-side capability hints for the current agent. These are a UX guard ONLY; the server
 * `403` is always authoritative (AC-7). `canAssign` is carried for forward-compatibility but,
 * because no assign/transfer route exists, it does not unlock those actions today.
 */
data class AgentCapabilities(
    val isAgent: Boolean = true,
    val canAssign: Boolean = false,
)

/**
 * AND-378 — resolve which assignment actions are available for one queue row, given the
 * current agent. Claim availability follows FR-4:
 *  - Claim: Available only when the conversation is UNASSIGNED (`awaiting_agent` and no
 *    active agent) and the caller is an agent; otherwise Hidden.
 *  - Assign / Transfer: always Gated(NO_BACKEND_ROUTE) per spec section 16, even when the
 *    agent reports `canAssign`. The matrix returns Gated (not Available) so the UI keeps the
 *    affordances off and a future backend addition is a one-line change here.
 *
 * @param routingState backend routing state for the conversation.
 * @param claimState ownership of the row relative to the current agent.
 * @param caps client capability hints (UX only).
 */
fun assignmentAvailability(
    routingState: HelpdeskRoutingState,
    claimState: ClaimState,
    caps: AgentCapabilities,
): Map<AssignmentAction, Availability> {
    val claim = when {
        !caps.isAgent -> Availability.Hidden
        routingState == HelpdeskRoutingState.CLOSED -> Availability.Hidden
        claimState == ClaimState.UNASSIGNED &&
            routingState == HelpdeskRoutingState.AWAITING_AGENT -> Availability.Available
        else -> Availability.Hidden
    }
    return mapOf(
        AssignmentAction.CLAIM to claim,
        // Section 16: assign/transfer have no helpdesk route — never functional.
        AssignmentAction.ASSIGN to Availability.Gated(GateReason.NO_BACKEND_ROUTE),
        AssignmentAction.TRANSFER to Availability.Gated(GateReason.NO_BACKEND_ROUTE),
    )
}

/** Convenience: is a single inline claim affordance offered for this row? */
fun HelpdeskQueueItem.isClaimable(caps: AgentCapabilities = AgentCapabilities()): Boolean =
    assignmentAvailability(routingState, claimState, caps)[AssignmentAction.CLAIM] == Availability.Available
