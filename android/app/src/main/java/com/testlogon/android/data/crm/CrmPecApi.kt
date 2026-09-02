package com.testlogon.android.data.crm

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.PATCH
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

    // ── EVT-002: event update + invitee management ────────────────────────────

    @PATCH("ui/crm/events/{eventId}")
    suspend fun updateEvent(
        @Path("eventId") eventId: String,
        @Body body: CrmEventUpdateInDto,
    ): CrmEventDto

    @POST("ui/crm/events/{eventId}/invitees")
    suspend fun addInvitee(
        @Path("eventId") eventId: String,
        @Body body: CrmInviteeAddInDto,
    ): CrmInviteeDto

    // 204 No Content on success → suspend Unit tolerates the empty body.
    @DELETE("ui/crm/events/{eventId}/invitees/{inviteeSub}")
    suspend fun removeInvitee(
        @Path("eventId") eventId: String,
        @Path("inviteeSub") inviteeSub: String,
    )

    @POST("ui/crm/events/{eventId}/invitees/bulk-import")
    suspend fun bulkImportInvitees(
        @Path("eventId") eventId: String,
        @Body body: CrmInviteeBulkImportInDto,
    ): CrmBulkImportDto

    @POST("ui/crm/events/{eventId}/invitees/send-invitations")
    suspend fun sendInvitations(
        @Path("eventId") eventId: String,
        @Body body: Map<String, String> = emptyMap(),
    ): CrmSendInvitationsDto

    @GET("ui/crm/events/{eventId}/invitees")
    suspend fun listInvitees(
        @Path("eventId") eventId: String,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): CrmInviteeListRespDto

    // ── EVT-003: registration workflow ────────────────────────────────────────

    @POST("ui/crm/events/{eventId}/registrations")
    suspend fun registerForEvent(
        @Path("eventId") eventId: String,
        @Body body: Map<String, String> = emptyMap(),
    ): CrmRegistrationDto

    @POST("ui/crm/events/{eventId}/registrations/{registrantSub}/respond")
    suspend fun respondToInvitation(
        @Path("eventId") eventId: String,
        @Path("registrantSub") registrantSub: String,
        @Body body: CrmRespondInDto,
    ): CrmRegistrationDto

    @POST("ui/crm/events/{eventId}/registrations/{registrantSub}/check-in")
    suspend fun checkInAttendee(
        @Path("eventId") eventId: String,
        @Path("registrantSub") registrantSub: String,
        @Body body: Map<String, String> = emptyMap(),
    ): CrmRegistrationDto

    // 204 No Content on success → suspend Unit tolerates the empty body.
    @DELETE("ui/crm/events/{eventId}/registrations/{registrantSub}")
    suspend fun cancelRegistration(
        @Path("eventId") eventId: String,
        @Path("registrantSub") registrantSub: String,
    )

    @GET("ui/crm/events/{eventId}/registrations")
    suspend fun listRegistrations(
        @Path("eventId") eventId: String,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): CrmRegistrationListRespDto
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
