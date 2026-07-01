package com.testlogon.android.core.network.agents

import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AGENTS-BASICS (web-parity) - Retrofit interface for the DOC-COVERAGE surface (web /agents/docs +
 * /agents/docs/templates). Transport only; the :app repository folds these into ApiResult. Mirrors
 * frontend/src/api/endpoints/docsAgent.ts + backend app/routers/agent_docs.py.
 *
 * NOTE the prefix is ui/agents/docs (PLURAL "agents") - distinct from the ui/agent/... (singular) feedback / PR /
 * memory routers. [coverage], [coverageDetails], [stale], [listTemplates] are idempotent GETs. [freshnessCheck]
 * (POST), [createTemplate] and [deleteTemplate] are mutations excluded from auto-retry. Paths have NO leading
 * slash. deleteTemplate returns {ok, template_id} -> Response<Unit>.
 */
interface DocsApi {

    @GET("ui/agents/docs/coverage")
    suspend fun coverage(): DocCoverageSummaryDto

    @GET("ui/agents/docs/coverage/details")
    suspend fun coverageDetails(@Query("doc_type") docType: String? = null): DocCoverageDetailsDto

    @GET("ui/agents/docs/stale")
    suspend fun stale(@Query("limit") limit: Int? = null): StaleDocsListDto

    @POST("ui/agents/docs/freshness-check")
    suspend fun freshnessCheck(@Body body: Map<String, String> = emptyMap()): FreshnessCheckDto

    @GET("ui/agents/docs/templates")
    suspend fun listTemplates(@Query("doc_type") docType: String? = null): DocTemplatesListDto

    @POST("ui/agents/docs/templates")
    suspend fun createTemplate(@Body body: CreateDocTemplateRequest): DocTemplateDto

    @DELETE("ui/agents/docs/templates/{templateId}")
    suspend fun deleteTemplate(@Path("templateId") templateId: String): Response<Unit>
}
