package com.testlogon.android.data.crm

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * CRM-AND-1 / CRM-AND-LED — Retrofit interface for SuiteCRM Leads (LED-*). Paths are relative;
 * cookies / Authorization / X-CSRF-Token are attached by the core-network interceptor chain.
 *
 * Backend gates on S.leads_enabled — when off every route returns 404 ("Leads module not enabled");
 * the repository maps that to a degraded/empty result. Admin routes (admin/ + sources/summary)
 * additionally return 403 for non-admins; the repository surfaces that as a forbidden state.
 * Verified against frontend/src/api/endpoints/leads.ts.
 *
 * Scope: list / get / create / update / delete / convert / assign / merge / duplicates / score /
 * score-history / activities, prospects CRUD, and the admin scoring-rules + source-summary +
 * admin/all endpoints.
 */
interface LeadsApi {

    // ── Core lead CRUD ───────────────────────────────────────────────────────

    @GET("ui/leads")
    suspend fun listLeads(
        @Query("status") status: String? = null,
        @Query("lead_source") leadSource: String? = null,
        @Query("assigned_to") assignedTo: String? = null,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): LeadListRespDto

    @GET("ui/leads/{leadId}")
    suspend fun getLead(@Path("leadId") leadId: String): LeadDto

    @POST("ui/leads")
    suspend fun createLead(@Body body: LeadCreateInDto): LeadDto

    @PATCH("ui/leads/{leadId}")
    suspend fun updateLead(
        @Path("leadId") leadId: String,
        @Body body: LeadUpdateInDto,
    ): LeadDto

    @DELETE("ui/leads/{leadId}")
    suspend fun deleteLead(@Path("leadId") leadId: String)

    // ── Lead actions ─────────────────────────────────────────────────────────

    @POST("ui/leads/{leadId}/convert")
    suspend fun convertLead(
        @Path("leadId") leadId: String,
        @Body body: LeadConversionInDto,
    ): LeadConversionResultDto

    @POST("ui/leads/{leadId}/assign")
    suspend fun assignLead(
        @Path("leadId") leadId: String,
        @Body body: LeadAssignInDto,
    ): LeadDto

    @POST("ui/leads/{leadId}/merge")
    suspend fun mergeLeads(
        @Path("leadId") primaryLeadId: String,
        @Body body: LeadMergeInDto,
    ): LeadDto

    @GET("ui/leads/{leadId}/duplicates")
    suspend fun findDuplicates(@Path("leadId") leadId: String): LeadDuplicatesRespDto

    @POST("ui/leads/{leadId}/score")
    suspend fun computeScore(
        @Path("leadId") leadId: String,
        @Body body: Map<String, String> = emptyMap(),
    ): LeadScoreResultDto

    @GET("ui/leads/{leadId}/score-history")
    suspend fun scoreHistory(
        @Path("leadId") leadId: String,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): LeadScoreHistoryRespDto

    // ── Activities ───────────────────────────────────────────────────────────

    @GET("ui/leads/{leadId}/activities")
    suspend fun listActivities(
        @Path("leadId") leadId: String,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): LeadActivityListRespDto

    @POST("ui/leads/{leadId}/activities")
    suspend fun logActivity(
        @Path("leadId") leadId: String,
        @Body body: LeadLogActivityInDto,
    ): LeadActivityDto

    // ── Prospects (LED-007) ──────────────────────────────────────────────────

    @GET("ui/leads/prospects")
    suspend fun listProspects(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
        @Query("include_suppressed") includeSuppressed: Boolean? = null,
        @Query("include_deleted") includeDeleted: Boolean? = null,
    ): ProspectListRespDto

    @GET("ui/leads/prospects/{prospectId}")
    suspend fun getProspect(@Path("prospectId") prospectId: String): ProspectDto

    @POST("ui/leads/prospects")
    suspend fun createProspect(@Body body: ProspectCreateInDto): ProspectDto

    @PATCH("ui/leads/prospects/{prospectId}")
    suspend fun updateProspect(
        @Path("prospectId") prospectId: String,
        @Body body: ProspectUpdateInDto,
    ): ProspectDto

    @DELETE("ui/leads/prospects/{prospectId}")
    suspend fun deleteProspect(@Path("prospectId") prospectId: String)

    // ── Admin (LED-013) + source summary ─────────────────────────────────────

    @GET("ui/leads/sources/summary")
    suspend fun sourceSummary(): LeadSourceSummaryRespDto

    @GET("ui/leads/admin/all")
    suspend fun adminListAllLeads(
        @Query("status") status: String? = null,
        @Query("lead_source") leadSource: String? = null,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): LeadListRespDto

    @GET("ui/leads/admin/scoring-rules")
    suspend fun getScoringRules(): LeadScoreRulesDto

    @POST("ui/leads/admin/scoring-rules")
    suspend fun updateScoringRules(@Body body: LeadScoreRulesInDto): LeadScoreRulesDto
}
