package com.testlogon.android.data.crm

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * CRM-AND-1 — Retrofit interface for SuiteCRM Leads (LED-*). Paths are relative; cookies /
 * Authorization / X-CSRF-Token are attached by the core-network interceptor chain.
 *
 * Backend gates on S.leads_enabled — when off every route returns 404 ("Leads module not enabled");
 * the repository maps that to a degraded/empty result. Verified against
 * frontend/src/api/endpoints/leads.ts.
 *
 * MVP scope: list / get / create / update / convert / score / activities. Merge / duplicates /
 * prospects / admin scoring-rules are deferred to phase-2 (noted in the repository).
 */
interface LeadsApi {

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

    @POST("ui/leads/{leadId}/convert")
    suspend fun convertLead(
        @Path("leadId") leadId: String,
        @Body body: LeadConversionInDto,
    ): LeadConversionResultDto

    @POST("ui/leads/{leadId}/score")
    suspend fun computeScore(
        @Path("leadId") leadId: String,
        @Body body: Map<String, String> = emptyMap(),
    ): LeadScoreResultDto

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
}
