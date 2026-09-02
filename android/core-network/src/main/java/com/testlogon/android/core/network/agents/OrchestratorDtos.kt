package com.testlogon.android.core.network.agents

import com.squareup.moshi.Json

/**
 * AGENT-ORCHESTRATOR (web-parity) - transport DTOs for the agent-loop ORCHESTRATOR surface
 * (backend app/routers/agent_orchestrator.py, prefix ui/agent/orchestrator; web
 * frontend/src/api/endpoints/agentOrchestrator.ts).
 *
 * CODEGEN NOTE (identical to AgentsDtos / AgentsBasicsDtos): core-network does NOT apply Moshi KSP codegen, so
 * these DTOs decode via the reflective KotlinJsonAdapterFactory registered on the shared Moshi. That factory maps
 * property names to JSON keys VERBATIM (no auto snake_case), so every wire key is pinned with an explicit
 * @Json(name = ...). @JsonClass(generateAdapter = true) is intentionally OMITTED.
 *
 * TIME fields are EPOCH SECONDS typed as Long (0 == "never"/"unset"). All paths are require_ui_session.
 */

/** The agent ticket-filter config (GET status embeds it; PUT ticket-filter sets it). */
data class TicketFilterConfigDto(
    @Json(name = "types") val types: List<String> = emptyList(),
    @Json(name = "tags") val tags: List<String> = emptyList(),
    @Json(name = "space_ids") val spaceIds: List<String> = emptyList(),
    @Json(name = "priorities") val priorities: List<String> = emptyList(),
)

/** GET ui/agent/orchestrator/{worker_id}/status (AgentStatusOut). */
data class AgentStatusDto(
    @Json(name = "worker_id") val workerId: String = "",
    @Json(name = "agent_state") val agentState: String = "idle",
    @Json(name = "current_ticket_id") val currentTicketId: String = "",
    @Json(name = "current_ticket_title") val currentTicketTitle: String = "",
    @Json(name = "tickets_completed") val ticketsCompleted: Int = 0,
    @Json(name = "tickets_failed") val ticketsFailed: Int = 0,
    @Json(name = "heartbeat_at") val heartbeatAt: Long = 0,
    @Json(name = "last_activity_at") val lastActivityAt: Long = 0,
    @Json(name = "ticket_filter") val ticketFilter: TicketFilterConfigDto? = null,
    @Json(name = "loop_running") val loopRunning: Boolean = false,
)

/** Common loop-control result (start/pause/resume/stop). Fields degrade when the server omits them. */
data class LoopActionResultDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "worker_id") val workerId: String = "",
    @Json(name = "agent_state") val agentState: String = "",
    @Json(name = "current_ticket_id") val currentTicketId: String = "",
    @Json(name = "message") val message: String = "",
)

/** POST .../release-ticket result. */
data class ReleaseTicketResultDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "worker_id") val workerId: String = "",
    @Json(name = "released_ticket_id") val releasedTicketId: String = "",
    @Json(name = "agent_state") val agentState: String = "",
)

/** POST .../complete-ticket result. */
data class CompleteTicketResultDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "worker_id") val workerId: String = "",
    @Json(name = "completed_ticket_id") val completedTicketId: String = "",
    @Json(name = "agent_state") val agentState: String = "",
)

/** POST .../heartbeat result. */
data class HeartbeatResultDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "heartbeat_at") val heartbeatAt: Long = 0,
)

/** One eligible ticket (elements of EligibleTicketsOut.tickets; keys pinned, extras ignored). */
data class EligibleTicketDto(
    @Json(name = "ticket_id") val ticketId: String = "",
    @Json(name = "title") val title: String = "",
    @Json(name = "priority") val priority: String = "",
    @Json(name = "type") val type: String = "",
    @Json(name = "tags") val tags: List<String> = emptyList(),
    @Json(name = "space_id") val spaceId: String = "",
    @Json(name = "created_at") val createdAt: Long = 0,
)

/** GET .../eligible-tickets (EligibleTicketsOut). */
data class EligibleTicketsDto(
    @Json(name = "tickets") val tickets: List<EligibleTicketDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
    @Json(name = "filter_applied") val filterApplied: TicketFilterConfigDto? = null,
)

/** Body for POST .../claim-ticket. */
data class ClaimTicketRequest(
    @Json(name = "ticket_id") val ticketId: String,
)

/** Body for POST .../complete-ticket (both fields optional server-side). */
data class CompleteTicketRequest(
    @Json(name = "summary") val summary: String? = null,
    @Json(name = "pr_url") val prUrl: String? = null,
)
