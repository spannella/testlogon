package com.testlogon.android.data.crm

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * CRM-AND-1 — Retrofit interface for SuiteCRM Opportunities (OPP-*). Router prefix /ui/sales.
 *
 * Backend gates on S.sales_pipeline_enabled — endpoints 503 when off (feature-status never 503s); the
 * repository treats 503/404 as a degraded/empty result. Verified against
 * frontend/src/api/endpoints/opportunities.ts.
 *
 * MVP scope: feature-status / stages / list / get / create / update (stage move). Forecast / quota /
 * reports / contact-roles are deferred to phase-2 (noted in the repository).
 */
interface SalesApi {

    @GET("ui/sales/feature-status")
    suspend fun getFeatureStatus(): FeatureStatusDto

    @GET("ui/sales/stages")
    suspend fun listStages(): StageConfigOutDto

    @GET("ui/sales/opportunities")
    suspend fun listOpportunities(
        @Query("stage") stage: String? = null,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): OpportunityListRespDto

    @GET("ui/sales/opportunities/{oppId}")
    suspend fun getOpportunity(@Path("oppId") oppId: String): OpportunityOutDto

    @POST("ui/sales/opportunities")
    suspend fun createOpportunity(@Body body: OpportunityCreateInDto): OpportunityOutDto

    @PATCH("ui/sales/opportunities/{oppId}")
    suspend fun updateOpportunity(
        @Path("oppId") oppId: String,
        @Body body: OpportunityUpdateInDto,
    ): OpportunityOutDto
}
