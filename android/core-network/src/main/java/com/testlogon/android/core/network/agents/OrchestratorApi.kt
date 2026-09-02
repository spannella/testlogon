package com.testlogon.android.core.network.agents

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.PUT
import retrofit2.http.Path

/**
 * AGENT-ORCHESTRATOR (web-parity) - Retrofit interface for the agent-loop ORCHESTRATOR surface (web
 * /ui/agent/orchestrator). Transport only; the :app repository folds these into ApiResult. Mirrors
 * frontend/src/api/endpoints/agentOrchestrator.ts + backend app/routers/agent_orchestrator.py.
 *
 * Paths have NO leading slash (relative to the shared Retrofit base URL). The shared authenticated client
 * attaches the session cookie jar + Authorization + X-CSRF-Token via the global interceptors; no per-call header
 * wiring here. All endpoints are backend require_ui_session.
 *
 * [status], [checkpoint] (GET) and [eligibleTickets] are idempotent GETs. The loop-control (start/pause/resume/
 * stop), ticket operations (claim/complete/release), checkpoint SAVE, heartbeat, ticket-filter PUT and
 * create-worker are NON-idempotent mutations excluded from auto-retry.
 */
interface OrchestratorApi {

    // -- Status --
    @GET("ui/agent/orchestrator/{workerId}/status")
    suspend fun status(@Path("workerId") workerId: String): AgentStatusDto

    // -- Loop control --
    @POST("ui/agent/orchestrator/{workerId}/start")
    suspend fun start(@Path("workerId") workerId: String): LoopActionResultDto

    @POST("ui/agent/orchestrator/{workerId}/pause")
    suspend fun pause(@Path("workerId") workerId: String): LoopActionResultDto

    @POST("ui/agent/orchestrator/{workerId}/resume")
    suspend fun resume(@Path("workerId") workerId: String): LoopActionResultDto

    @POST("ui/agent/orchestrator/{workerId}/stop")
    suspend fun stop(@Path("workerId") workerId: String): LoopActionResultDto

    // -- Ticket operations --
    @POST("ui/agent/orchestrator/{workerId}/release-ticket")
    suspend fun releaseTicket(@Path("workerId") workerId: String): ReleaseTicketResultDto

    @POST("ui/agent/orchestrator/{workerId}/claim-ticket")
    suspend fun claimTicket(
        @Path("workerId") workerId: String,
        @Body body: ClaimTicketRequest,
    ): Map<String, Any?>

    @POST("ui/agent/orchestrator/{workerId}/complete-ticket")
    suspend fun completeTicket(
        @Path("workerId") workerId: String,
        @Body body: CompleteTicketRequest,
    ): CompleteTicketResultDto

    // -- Heartbeat --
    @POST("ui/agent/orchestrator/{workerId}/heartbeat")
    suspend fun heartbeat(@Path("workerId") workerId: String): HeartbeatResultDto

    // -- Eligible tickets --
    @GET("ui/agent/orchestrator/{workerId}/eligible-tickets")
    suspend fun eligibleTickets(@Path("workerId") workerId: String): EligibleTicketsDto

    // -- Ticket filter --
    @PUT("ui/agent/orchestrator/{workerId}/ticket-filter")
    suspend fun updateTicketFilter(
        @Path("workerId") workerId: String,
        @Body body: TicketFilterConfigDto,
    ): Map<String, Any?>
}
