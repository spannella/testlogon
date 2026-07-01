package com.testlogon.android.core.network.agents

import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AGENTS-BASICS (web-parity) - Retrofit interface for the agent-PR surface (web /agents/prs). Transport only;
 * the :app repository folds these into ApiResult. Mirrors frontend/src/api/endpoints/agentPrIntegration.ts +
 * backend app/routers/agent_pr_integration.py (prefix ui/agent/pr, require_ui_session).
 *
 * This BASICS wave is READ-ONLY (list + detail): [list] and [get] are idempotent GETs. The create/complete
 * mutations + the admin ui/admin/agent/prs list (admin-gated) are intentionally out of scope for the basics.
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
}
