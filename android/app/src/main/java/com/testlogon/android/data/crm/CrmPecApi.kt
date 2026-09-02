package com.testlogon.android.data.crm

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * CRM-AND-PEC — Retrofit interfaces for the SuiteCRM Projects / Events / Campaigns surfaces. Paths are
 * relative; cookies / Authorization / X-CSRF-Token are attached by the core-network interceptor chain.
 *
 * Each backend module is feature-gated and returns 404 when off; the repositories map that to a
 * degraded/empty result. Verified against the web contracts:
 *   crmProjects.ts (/v1/crm/projects) · crmEvents.ts (/ui/crm/events) · crmCampaigns.ts
 *   (/ui/crm-marketing/campaigns).
 *
 * MVP scope: projects list/detail (+ tasks) + create; events list/get/create (+ capacity);
 * campaigns list/detail (+ attribution). Members / templates / invitees / registrations / A-B / send
 * / email-templates are deferred (noted in the repository).
 */

// ─── Projects: prefix /v1/crm/projects ───────────────────────────────────────

interface CrmProjectsApi {

    @GET("v1/crm/projects")
    suspend fun listProjects(
        @Query("status") status: String? = null,
        @Query("name_query") nameQuery: String? = null,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): CrmProjectListRespDto

    @GET("v1/crm/projects/{projectId}")
    suspend fun getProject(@Path("projectId") projectId: String): CrmProjectDto

    @POST("v1/crm/projects")
    suspend fun createProject(@Body body: CrmProjectCreateInDto): CrmProjectDto

    @GET("v1/crm/projects/{projectId}/tasks")
    suspend fun listTasks(
        @Path("projectId") projectId: String,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): CrmProjectTaskListRespDto
}

// ─── Events: prefix /ui/crm/events ───────────────────────────────────────────

interface CrmEventsApi {

    // list is @router.get("") on the prefix → /ui/crm/events (no trailing slash).
    @GET("ui/crm/events")
    suspend fun listEvents(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): CrmEventListRespDto

    @GET("ui/crm/events/{eventId}")
    suspend fun getEvent(@Path("eventId") eventId: String): CrmEventDto

    // create is @router.post("/") on the prefix → /ui/crm/events/ (trailing slash required).
    @POST("ui/crm/events/")
    suspend fun createEvent(@Body body: CrmEventCreateInDto): CrmEventDto

    @GET("ui/crm/events/{eventId}/capacity")
    suspend fun getCapacity(@Path("eventId") eventId: String): CrmEventCapacityDto
}

// ─── Campaigns: prefix /ui/crm-marketing ─────────────────────────────────────

interface CrmCampaignsApi {

    @GET("ui/crm-marketing/campaigns")
    suspend fun listCampaigns(
        @Query("campaign_type") campaignType: String? = null,
        @Query("status") status: String? = null,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): CrmCampaignListRespDto

    @GET("ui/crm-marketing/campaigns/{campaignId}")
    suspend fun getCampaign(@Path("campaignId") campaignId: String): CrmCampaignDto

    @GET("ui/crm-marketing/campaigns/{campaignId}/attribution")
    suspend fun getAttribution(@Path("campaignId") campaignId: String): CrmCampaignAttributionDto
}
