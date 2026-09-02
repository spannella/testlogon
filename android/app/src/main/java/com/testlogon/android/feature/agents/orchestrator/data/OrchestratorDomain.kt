package com.testlogon.android.feature.agents.orchestrator.data

/**
 * AGENT-ORCHESTRATOR (web-parity) - framework-free domain for the agent-loop ORCHESTRATOR console (mobile
 * mirror of the web agent-orchestrator control surface). One console drives a single worker's loop lifecycle:
 * start/pause/resume/stop + manual claim/complete/release + heartbeat + eligible-ticket preview.
 *
 * The domain is deliberately pure (no Android / coroutine / Retrofit deps) so [OrchestratorMath] is
 * JVM-unit-testable.
 */

/**
 * The agent loop state, mirroring backend agent_state values ("idle"/"working"/"paused"/"stopped"). [UNKNOWN]
 * covers any value the server introduces later so the console degrades rather than crashes.
 */
enum class AgentLoopState(val wire: String, val label: String) {
    IDLE("idle", "Idle"),
    WORKING("working", "Working"),
    PAUSED("paused", "Paused"),
    STOPPED("stopped", "Stopped"),
    UNKNOWN("", "Unknown");

    companion object {
        fun from(raw: String?): AgentLoopState =
            entries.firstOrNull { it.wire.isNotEmpty() && it.wire.equals(raw?.trim(), ignoreCase = true) }
                ?: UNKNOWN
    }
}

/** The finite set of loop-control actions the console can offer. */
enum class LoopAction {
    START, PAUSE, RESUME, STOP, CLAIM, COMPLETE, RELEASE, HEARTBEAT,
}

/** The worker's ticket-filter config (round-trips status GET <-> ticket-filter PUT). */
data class TicketFilter(
    val types: List<String> = emptyList(),
    val tags: List<String> = emptyList(),
    val spaceIds: List<String> = emptyList(),
    val priorities: List<String> = emptyList(),
) {
    val isEmpty: Boolean
        get() = types.isEmpty() && tags.isEmpty() && spaceIds.isEmpty() && priorities.isEmpty()
}

/** The orchestrator status snapshot for one worker (GET .../status). */
data class AgentStatus(
    val workerId: String,
    val state: AgentLoopState,
    val currentTicketId: String,
    val currentTicketTitle: String,
    val ticketsCompleted: Int,
    val ticketsFailed: Int,
    val heartbeatAt: Long,
    val lastActivityAt: Long,
    val ticketFilter: TicketFilter,
    val loopRunning: Boolean,
) {
    /** True when a ticket is currently claimed to this worker. */
    val hasActiveTicket: Boolean get() = currentTicketId.isNotBlank()
}

/** One ticket the loop is eligible to pick up (GET .../eligible-tickets). */
data class EligibleTicket(
    val ticketId: String,
    val title: String,
    val priority: String,
    val type: String,
    val tags: List<String>,
    val spaceId: String,
    val createdAt: Long,
)

/** The eligible-tickets preview with its applied filter. */
data class EligibleTickets(
    val tickets: List<EligibleTicket>,
    val count: Int,
    val filterApplied: TicketFilter?,
)

/** Result of a loop-control action (start/pause/resume/stop). */
data class LoopActionResult(
    val ok: Boolean,
    val workerId: String,
    val agentState: AgentLoopState,
    val message: String,
)

/** Result of a ticket op (release/complete). */
data class TicketOpResult(
    val ok: Boolean,
    val workerId: String,
    val ticketId: String,
    val agentState: AgentLoopState,
)

/** Result of a manual heartbeat. */
data class HeartbeatResult(
    val ok: Boolean,
    val heartbeatAt: Long,
)
