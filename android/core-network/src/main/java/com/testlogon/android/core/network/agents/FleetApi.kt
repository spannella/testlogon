package com.testlogon.android.core.network.agents

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AGENTS-BASICS (web-parity) - Retrofit interface for the FLEET dashboard surface (web /agents/fleet).
 * Transport only; the :app repository folds these into ApiResult. Mirrors frontend/src/api/endpoints/agentFleet.ts.
 *
 * Paths have NO leading slash. The shared authenticated client attaches auth via the global interceptors. All
 * endpoints are backend require_ui_session. [status], [capacity] and [templates] are idempotent GETs; the bulk
 * actions + template create/delete/create-from are NON-idempotent (no auto-retry).
 */
interface FleetApi {

    @GET("ui/agent/fleet/status")
    suspend fun status(): FleetStatusDto

    @GET("ui/agent/fleet/capacity")
    suspend fun capacity(): FleetCapacityDto

    @POST("ui/agent/fleet/start-all")
    suspend fun startAll(): BulkActionResultDto

    @POST("ui/agent/fleet/stop-all")
    suspend fun stopAll(): BulkActionResultDto

    @GET("ui/agent/fleet/templates")
    suspend fun templates(): WorkerTemplateListDto

    @DELETE("ui/agent/fleet/templates/{templateId}")
    suspend fun deleteTemplate(@Path("templateId") templateId: String)

    @POST("ui/agent/fleet/templates/{templateId}/create")
    suspend fun createFromTemplate(@Path("templateId") templateId: String): WorkerDto
}
