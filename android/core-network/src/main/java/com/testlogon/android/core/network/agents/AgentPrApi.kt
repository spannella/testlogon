package com.testlogon.android.core.network.agents

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AGENTS-BASICS (web-parity) - Retrofit interface for the agent-PR surface (web /agents/prs). Transport only;
 * the :app repository folds these into ApiResult. Mirrors frontend/src/api/endpoints/agentPrIntegration.ts +
 * backend app/routers/agent_pr_integration.py (prefix ui/agent/pr, require_ui_session).
 *
 * [list] and [get] are idempotent GETs. [complete] (POST ui/agent/pr/{workerId}/complete) runs the
 * work-completion pipeline (summary + optional PR + status transition) and is a non-idempotent mutation
 * excluded from auto-retry. The admin ui/admin/agent/prs list + status-flow config remain out of scope.
 * Paths have NO leading slash (relative to the shared authenticated Retrofit base URL).
 */
interface AgentPrApi {

    @GET("ui/agent/pr")
    suspend fun list(
        @Query("worker_id") workerId: String? = null,
        @Query("ticket_id") ticketId: String? = null,
        @Query("limit") limit: Int? = null,
    ): AgentPrListDto

    @GET("ui/agent/pr/{prId}")
    suspend fun get(@Path("prId") prId: String): AgentPrDto

    @POST("ui/agent/pr/{workerId}/complete")
    suspend fun complete(
        @Path("workerId") workerId: String,
        @Body body: AgentWorkCompleteRequest,
    ): AgentCompletionDto
}
