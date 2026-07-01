package com.testlogon.android.core.network.agents

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AGENTS-BASICS (web-parity) - Retrofit interface for the WORKERS surface (web /agents/workers). Transport only;
 * the :app repository folds these into ApiResult. Mirrors frontend/src/api/endpoints/agentWorkers.ts.
 *
 * Paths have NO leading slash (relative to the shared Retrofit base URL). The shared authenticated client
 * attaches the session cookie jar + Authorization + X-CSRF-Token via the global interceptors; no per-call header
 * wiring here. All endpoints are backend require_ui_session (the test acct CAN use them).
 *
 * [list], [get], [tools], [computeOptions] and [provisionLog] are idempotent GETs. [create], [start], [stop] and
 * [terminate] are NON-idempotent mutations excluded from auto-retry.
 */
interface WorkersApi {

    @GET("ui/agent/workers")
    suspend fun list(
        @Query("status") status: String? = null,
        @Query("agent_type") agentType: String? = null,
    ): WorkerListDto

    @GET("ui/agent/workers/{workerId}")
    suspend fun get(@Path("workerId") workerId: String): WorkerDto

    @POST("ui/agent/workers")
    suspend fun create(@Body body: CreateWorkerRequest): WorkerDto

    @POST("ui/agent/workers/{workerId}/start")
    suspend fun start(@Path("workerId") workerId: String): WorkerDto

    @POST("ui/agent/workers/{workerId}/stop")
    suspend fun stop(@Path("workerId") workerId: String): WorkerDto

    @DELETE("ui/agent/workers/{workerId}")
    suspend fun terminate(@Path("workerId") workerId: String): WorkerDto

    @GET("ui/agent/workers/{workerId}/provision-log")
    suspend fun provisionLog(@Path("workerId") workerId: String): List<ProvisionStepDto>

    @GET("ui/agent/workers/tools")
    suspend fun tools(): ToolListDto

    @GET("ui/agent/workers/compute-options")
    suspend fun computeOptions(): ComputeOptionListDto
}
