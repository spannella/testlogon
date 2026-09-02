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

    // ── PRJ-002: project update / delete ──────────────────────────────────────

    @PATCH("v1/crm/projects/{projectId}")
    suspend fun updateProject(
        @Path("projectId") projectId: String,
        @Body body: CrmProjectUpdateInDto,
    ): CrmProjectDto

    // 200 with an {ok:true}-ish body; a bare Unit tolerates any shape.
    @DELETE("v1/crm/projects/{projectId}")
    suspend fun deleteProject(@Path("projectId") projectId: String)

    // ── PRJ-003/004/005: task board + workload + milestones ───────────────────

    @POST("v1/crm/projects/{projectId}/tasks")
    suspend fun createTask(
        @Path("projectId") projectId: String,
        @Body body: CrmProjectTaskCreateInDto,
    ): CrmProjectTaskDto

    @GET("v1/crm/projects/{projectId}/tasks/{taskId}")
    suspend fun getTask(
        @Path("projectId") projectId: String,
        @Path("taskId") taskId: String,
    ): CrmProjectTaskDto

    @PATCH("v1/crm/projects/{projectId}/tasks/{taskId}")
    suspend fun updateTask(
        @Path("projectId") projectId: String,
        @Path("taskId") taskId: String,
        @Body body: CrmProjectTaskUpdateInDto,
    ): CrmProjectTaskDto

    @DELETE("v1/crm/projects/{projectId}/tasks/{taskId}")
    suspend fun deleteTask(
        @Path("projectId") projectId: String,
        @Path("taskId") taskId: String,
    )

    @PUT("v1/crm/projects/{projectId}/tasks/order")
    suspend fun reorderTasks(
        @Path("projectId") projectId: String,
        @Body body: CrmProjectTaskReorderInDto,
    ): CrmProjectTaskOrderRespDto

    @GET("v1/crm/projects/{projectId}/workload")
    suspend fun getWorkload(@Path("projectId") projectId: String): CrmProjectWorkloadRespDto

    @GET("v1/crm/projects/{projectId}/milestones")
    suspend fun getMilestoneSummary(
        @Path("projectId") projectId: String,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): CrmMilestoneSummaryRespDto

    @GET("v1/crm/projects/{projectId}/status-history")
    suspend fun getStatusHistory(
        @Path("projectId") projectId: String,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): CrmProjectStatusHistoryRespDto

    // ── PRJ-007: members ──────────────────────────────────────────────────────

    @POST("v1/crm/projects/{projectId}/members")
    suspend fun addMember(
        @Path("projectId") projectId: String,
        @Body body: CrmProjectAddMemberInDto,
    ): CrmProjectMemberDto

    @GET("v1/crm/projects/{projectId}/members")
    suspend fun listMembers(
        @Path("projectId") projectId: String,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): CrmProjectMemberListRespDto

    @PATCH("v1/crm/projects/{projectId}/members/{userSub}")
    suspend fun updateMemberRole(
        @Path("projectId") projectId: String,
        @Path("userSub") userSub: String,
        @Body body: CrmProjectUpdateMemberInDto,
    ): CrmProjectMemberDto

    @DELETE("v1/crm/projects/{projectId}/members/{userSub}")
    suspend fun removeMember(
        @Path("projectId") projectId: String,
        @Path("userSub") userSub: String,
    )

    // ── PRJ-010: contact links ────────────────────────────────────────────────

    @POST("v1/crm/projects/{projectId}/contact-links")
    suspend fun addContactLink(
        @Path("projectId") projectId: String,
        @Body body: CrmProjectAddContactLinkInDto,
    ): CrmProjectContactLinkDto

    @GET("v1/crm/projects/{projectId}/contact-links")
    suspend fun listContactLinks(
        @Path("projectId") projectId: String,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): CrmProjectContactLinkListRespDto

    @DELETE("v1/crm/projects/{projectId}/contact-links/{entityId}")
    suspend fun removeContactLink(
        @Path("projectId") projectId: String,
        @Path("entityId") entityId: String,
    )

    // ── PRJ-006: templates (owner-scoped; degrade-on-404) ─────────────────────

    @GET("v1/crm/projects/templates")
    suspend fun listTemplates(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): CrmTemplateListRespDto

    @GET("v1/crm/projects/templates/{templateId}")
    suspend fun getTemplate(@Path("templateId") templateId: String): CrmProjectTemplateDto

    @POST("v1/crm/projects/templates")
    suspend fun createTemplate(@Body body: CrmTemplateCreateInDto): CrmProjectTemplateDto

    @POST("v1/crm/projects/templates/from-project/{projectId}")
    suspend fun createTemplateFromProject(
        @Path("projectId") projectId: String,
        @Body body: CrmTemplateFromProjectInDto,
    ): CrmProjectTemplateDto

    @DELETE("v1/crm/projects/templates/{templateId}")
    suspend fun deleteTemplate(@Path("templateId") templateId: String)

    @POST("v1/crm/projects/templates/{templateId}/instantiate")
    suspend fun instantiateTemplate(
        @Path("templateId") templateId: String,
        @Body body: CrmTemplateInstantiateInDto,
    ): CrmProjectDto
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
