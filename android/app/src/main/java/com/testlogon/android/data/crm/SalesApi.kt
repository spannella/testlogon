package com.testlogon.android.data.crm

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.PUT
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * CRM-AND-1 / CRM-AND-OPP — Retrofit interface for SuiteCRM Opportunities (OPP-*). Router prefixes
 * /ui/sales (rep) and /ui/admin/sales (admin).
 *
 * Backend gates on S.sales_pipeline_enabled — endpoints 503 when off (feature-status never 503s); the
 * repository treats 503/404 as a degraded/empty result. Admin endpoints additionally 403 for
 * non-admins (surfaced as a "forbidden" empty state). Verified against
 * frontend/src/api/endpoints/opportunities.ts.
 */
interface SalesApi {

    @GET("ui/sales/feature-status")
    suspend fun getFeatureStatus(): FeatureStatusDto

    @GET("ui/sales/stages")
    suspend fun listStages(): StageConfigOutDto

    // Admin: replace the stage list (PUT /ui/admin/sales/stages — 403 for non-admins).
    @PUT("ui/admin/sales/stages")
    suspend fun updateStages(@Body body: StageConfigInDto): StageConfigOutDto

    @GET("ui/sales/opportunities")
    suspend fun listOpportunities(
        @Query("stage") stage: String? = null,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): OpportunityListRespDto

    @GET("ui/sales/opportunities/{oppId}")
    suspend fun getOpportunity(
        @Path("oppId") oppId: String,
        @Query("include_contacts") includeContacts: Boolean? = null,
    ): OpportunityOutDto

    @POST("ui/sales/opportunities")
    suspend fun createOpportunity(@Body body: OpportunityCreateInDto): OpportunityOutDto

    @PATCH("ui/sales/opportunities/{oppId}")
    suspend fun updateOpportunity(
        @Path("oppId") oppId: String,
        @Body body: OpportunityUpdateInDto,
    ): OpportunityOutDto

    @DELETE("ui/sales/opportunities/{oppId}")
    suspend fun deleteOpportunity(@Path("oppId") oppId: String)

    // ── OPP-004: Contact-role junction ────────────────────────────────────────

    @POST("ui/sales/opportunities/{oppId}/contacts")
    suspend fun addContactRole(
        @Path("oppId") oppId: String,
        @Body body: OppContactRoleInDto,
    ): OppContactRoleOutDto

    @GET("ui/sales/opportunities/{oppId}/contacts")
    suspend fun listContactRoles(@Path("oppId") oppId: String): List<OppContactRoleOutDto>

    @DELETE("ui/sales/opportunities/{oppId}/contacts/{contactRef}")
    suspend fun removeContactRole(
        @Path("oppId") oppId: String,
        @Path("contactRef") contactRef: String,
    )

    // ── OPP-005: Forecast worksheet ───────────────────────────────────────────

    @GET("ui/sales/forecast/{periodKey}")
    suspend fun getForecast(@Path("periodKey") periodKey: String): ForecastWorksheetOutDto

    @PUT("ui/sales/forecast/{periodKey}")
    suspend fun upsertForecast(
        @Path("periodKey") periodKey: String,
        @Body body: ForecastWorksheetInDto,
    ): ForecastWorksheetOutDto

    // ── OPP-006: Pipeline report ──────────────────────────────────────────────

    @GET("ui/sales/reports/pipeline")
    suspend fun getPipelineReport(
        @Query("from_ts") fromTs: Long? = null,
        @Query("to_ts") toTs: Long? = null,
    ): PipelineReportOutDto

    @GET("ui/admin/sales/reports/pipeline")
    suspend fun getAdminPipelineReport(
        @Query("from_ts") fromTs: Long? = null,
        @Query("to_ts") toTs: Long? = null,
    ): PipelineReportOutDto

    // ── OPP-005: Admin quota ──────────────────────────────────────────────────

    @POST("ui/admin/sales/quotas")
    suspend fun setQuota(@Body body: SalesQuotaInDto): SalesQuotaOutDto

    @GET("ui/admin/sales/quotas/{userSub}")
    suspend fun listUserQuotas(
        @Path("userSub") userSub: String,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): SalesQuotaListOutDto
}
