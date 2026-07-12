package com.testlogon.android.core.network.agents

import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.PUT
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AGENTS-BASICS (web-parity) - Retrofit interface for the per-worker MEMORY surface (web /agents/memory/:workerId).
 * Transport only; the :app repository folds these into ApiResult. Mirrors frontend/src/api/endpoints/agentMemory.ts +
 * backend app/routers/agent_memory.py (prefix ui/agent/memory, require_ui_session).
 *
 * [getIdentity], [getProject], [listEntries], [fullContext] are idempotent GETs. [updateIdentity]/[updateProject]
 * (PUT), [addEntry]/[updateEntry] and [deleteEntry] are mutations excluded from auto-retry. Paths have NO leading
 * slash (relative to the shared authenticated Retrofit base URL). DELETE returns an opaque {ok:...} -> Response<Unit>.
 */
interface MemoryApi {

    @GET("ui/agent/memory/{workerId}/identity")
    suspend fun getIdentity(@Path("workerId") workerId: String): AgentIdentityDto

    @PUT("ui/agent/memory/{workerId}/identity")
    suspend fun updateIdentity(
        @Path("workerId") workerId: String,
        @Body body: AgentIdentityUpdateRequest,
    ): AgentIdentityDto

    @GET("ui/agent/memory/{workerId}/project")
    suspend fun getProject(@Path("workerId") workerId: String): ProjectContextDto

    @PUT("ui/agent/memory/{workerId}/project")
    suspend fun updateProject(
        @Path("workerId") workerId: String,
        @Body body: ProjectContextUpdateRequest,
    ): ProjectContextDto

    @GET("ui/agent/memory/{workerId}/entries")
    suspend fun listEntries(
        @Path("workerId") workerId: String,
        @Query("category") category: String? = null,
    ): MemoryListDto

    @POST("ui/agent/memory/{workerId}/entries")
    suspend fun addEntry(
        @Path("workerId") workerId: String,
        @Body body: MemoryEntryCreateRequest,
    ): MemoryEntryDto

    @DELETE("ui/agent/memory/{workerId}/entries/{memoryId}")
    suspend fun deleteEntry(
        @Path("workerId") workerId: String,
        @Path("memoryId") memoryId: String,
    ): Response<Unit>

    @GET("ui/agent/memory/{workerId}/full-context")
    suspend fun fullContext(@Path("workerId") workerId: String): FullContextDto

    @GET("ui/agent/memory/templates")
    suspend fun templates(): List<MemoryTemplateDto>
}
