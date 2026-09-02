package com.testlogon.android.core.network.agents

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AGENTS-BASICS (web-parity) - Retrofit interface for the FEEDBACK surface (web /agents/feedback). Transport
 * only; the :app repository folds these into ApiResult. Mirrors frontend/src/api/endpoints/agentFeedback.ts +
 * backend app/routers/agent_feedback.py (prefix ui/agent/feedback, require_ui_session).
 *
 * Paths have NO leading slash (relative to the shared authenticated Retrofit base URL). [list] and
 * [terminalLog] are idempotent GETs; [create], [respond] and [skip] are non-idempotent mutations excluded
 * from auto-retry. NOTE: the backend registers POST /{worker_id} (create) BEFORE the catch-all
 * /{worker_id}/{request_id} routes, so the plain worker path is the create endpoint.
 */
interface FeedbackApi {

    @GET("ui/agent/feedback")
    suspend fun list(@Query("status") status: String? = null): FeedbackListDto

    @POST("ui/agent/feedback/{workerId}")
    suspend fun create(
        @Path("workerId") workerId: String,
        @Body body: CreateFeedbackRequest,
    ): FeedbackRequestDto

    @GET("ui/agent/feedback/{workerId}/terminal-log")
    suspend fun terminalLog(
        @Path("workerId") workerId: String,
        @Query("chars") chars: Int? = null,
    ): TerminalOutputDto

    @POST("ui/agent/feedback/{workerId}/{requestId}/respond")
    suspend fun respond(
        @Path("workerId") workerId: String,
        @Path("requestId") requestId: String,
        @Body body: FeedbackRespondRequest,
    ): FeedbackRequestDto

    @POST("ui/agent/feedback/{workerId}/{requestId}/skip")
    suspend fun skip(
        @Path("workerId") workerId: String,
        @Path("requestId") requestId: String,
    ): FeedbackRequestDto
}
