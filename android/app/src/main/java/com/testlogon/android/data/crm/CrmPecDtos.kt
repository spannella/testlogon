package com.testlogon.android.data.crm

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * CRM-AND-PEC — wire DTOs for the SuiteCRM Projects (/v1/crm/projects), Events (/ui/crm/events) and
 * Marketing Campaigns (/ui/crm-marketing/campaigns) surfaces.
 *
 * Field names mirror the LIVE web contracts:
 *   frontend/src/api/endpoints/crmProjects.ts   (app/routers/crm_projects.py)
 *   frontend/src/api/endpoints/crmEvents.ts     (app/routers/crm_events.py)
 *   frontend/src/api/endpoints/crmCampaigns.ts  (app/routers/crm_campaigns.py)
 *
 * Every field is nullable / defaulted so a partial or drifted server body decodes rather than
 * throwing; unknown fields are ignored by Moshi.
 */

// ───────────────────────────  PROJECTS  ───────────────────────────

@JsonClass(generateAdapter = true)
data class CrmProjectDto(
    @Json(name = "id") val id: String = "",
    @Json(name = "owner_sub") val ownerSub: String? = null,
    @Json(name = "name") val name: String = "",
    @Json(name = "description") val description: String? = null,
    @Json(name = "status") val status: String = "draft",
    @Json(name = "priority") val priority: Int = 0,
    @Json(name = "start_date") val startDate: Long? = null,
    @Json(name = "end_date") val endDate: Long? = null,
    @Json(name = "assigned_user_sub") val assignedUserSub: String? = null,
    @Json(name = "account_id") val accountId: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class CrmProjectListRespDto(
    @Json(name = "items") val items: List<CrmProjectDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class CrmProjectCreateInDto(
    @Json(name = "name") val name: String,
    @Json(name = "description") val description: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "priority") val priority: Int? = null,
)

@JsonClass(generateAdapter = true)
data class CrmProjectTaskDto(
    @Json(name = "id") val id: String = "",
    @Json(name = "project_id") val projectId: String = "",
    @Json(name = "name") val name: String = "",
    @Json(name = "description") val description: String? = null,
    @Json(name = "task_order") val taskOrder: Int = 0,
    @Json(name = "duration_days") val durationDays: Int = 0,
    @Json(name = "start_date") val startDate: Long? = null,
    @Json(name = "end_date") val endDate: Long? = null,
    @Json(name = "percent_complete") val percentComplete: Int = 0,
    @Json(name = "is_milestone") val isMilestone: Boolean = false,
    @Json(name = "assigned_user_sub") val assignedUserSub: String? = null,
    @Json(name = "predecessor_task_ids") val predecessorTaskIds: List<String> = emptyList(),
    @Json(name = "project_resource_type") val projectResourceType: String = "user",
    @Json(name = "linked_contact_id") val linkedContactId: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class CrmProjectTaskListRespDto(
    @Json(name = "items") val items: List<CrmProjectTaskDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
)

// ───────────────────────────  EVENTS  ─────────────────────────────

@JsonClass(generateAdapter = true)
data class CrmEventDto(
    @Json(name = "event_id") val eventId: String = "",
    @Json(name = "owner_sub") val ownerSub: String? = null,
    @Json(name = "name") val name: String = "",
    @Json(name = "description") val description: String = "",
    @Json(name = "calendar_event_id") val calendarEventId: String? = null,
    @Json(name = "max_attendance") val maxAttendance: Int? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class CrmEventListRespDto(
    @Json(name = "events") val events: List<CrmEventDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class CrmEventCreateInDto(
    @Json(name = "name") val name: String,
    @Json(name = "description") val description: String? = null,
    @Json(name = "max_attendance") val maxAttendance: Int? = null,
)

@JsonClass(generateAdapter = true)
data class CrmEventCapacityDto(
    @Json(name = "event_id") val eventId: String = "",
    @Json(name = "max_attendance") val maxAttendance: Int? = null,
    @Json(name = "accepted_count") val acceptedCount: Int = 0,
    @Json(name = "waitlisted_count") val waitlistedCount: Int = 0,
    @Json(name = "available_spots") val availableSpots: Int? = null,
)

// EVT-002 — partial event update (PATCH). Only set fields are sent; nulls are omitted by Moshi.
@JsonClass(generateAdapter = true)
data class CrmEventUpdateInDto(
    @Json(name = "name") val name: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "calendar_event_id") val calendarEventId: String? = null,
    @Json(name = "max_attendance") val maxAttendance: Int? = null,
)

// EVT-002 — invitee management.
@JsonClass(generateAdapter = true)
data class CrmInviteeAddInDto(
    @Json(name = "invitee_sub") val inviteeSub: String,
)

@JsonClass(generateAdapter = true)
data class CrmInviteeBulkImportInDto(
    @Json(name = "user_subs") val userSubs: List<String>,
)

@JsonClass(generateAdapter = true)
data class CrmInviteeDto(
    @Json(name = "event_id") val eventId: String = "",
    @Json(name = "invitee_sub") val inviteeSub: String = "",
    @Json(name = "invite_status") val inviteStatus: String = "pending",
    @Json(name = "invited_at") val invitedAt: Long = 0,
    @Json(name = "responded_at") val respondedAt: Long? = null,
    @Json(name = "display_name") val displayName: String? = null,
)

@JsonClass(generateAdapter = true)
data class CrmInviteeListRespDto(
    @Json(name = "invitees") val invitees: List<CrmInviteeDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class CrmBulkImportDto(
    @Json(name = "added") val added: Int = 0,
    @Json(name = "skipped") val skipped: Int = 0,
)

@JsonClass(generateAdapter = true)
data class CrmSendInvitationsDto(
    @Json(name = "sent") val sent: Int = 0,
    @Json(name = "skipped") val skipped: Int = 0,
    @Json(name = "failed") val failed: Int = 0,
)

// EVT-003 — registration / RSVP.
@JsonClass(generateAdapter = true)
data class CrmRespondInDto(
    @Json(name = "new_status") val newStatus: String,
)

@JsonClass(generateAdapter = true)
data class CrmRegistrationDto(
    @Json(name = "event_id") val eventId: String = "",
    @Json(name = "registrant_sub") val registrantSub: String = "",
    @Json(name = "status") val status: String = "registered",
    @Json(name = "registered_at") val registeredAt: Long = 0,
    @Json(name = "responded_at") val respondedAt: Long? = null,
    @Json(name = "checked_in_at") val checkedInAt: Long? = null,
    @Json(name = "waitlist_position") val waitlistPosition: Int? = null,
    @Json(name = "invited") val invited: Boolean? = null,
)

@JsonClass(generateAdapter = true)
data class CrmRegistrationListRespDto(
    @Json(name = "registrations") val registrations: List<CrmRegistrationDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
)

// ──────────────────────────  CAMPAIGNS  ───────────────────────────

@JsonClass(generateAdapter = true)
data class CrmCampaignDto(
    @Json(name = "campaign_id") val campaignId: String = "",
    @Json(name = "owner_id") val ownerId: String? = null,
    @Json(name = "name") val name: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "objective") val objective: String? = null,
    @Json(name = "budget_cents") val budgetCents: Long = 0,
    @Json(name = "tracking_code") val trackingCode: String? = null,
    @Json(name = "campaign_type") val campaignType: String = "email",
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class CrmCampaignListRespDto(
    @Json(name = "campaigns") val campaigns: List<CrmCampaignDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
    @Json(name = "count") val count: Int = 0,
)

@JsonClass(generateAdapter = true)
data class CrmCampaignAttributionDto(
    @Json(name = "campaign_id") val campaignId: String = "",
    @Json(name = "total_sent") val totalSent: Int = 0,
    @Json(name = "email_sent") val emailSent: Int = 0,
    @Json(name = "open_count") val openCount: Int = 0,
    @Json(name = "open_rate") val openRate: Double = 0.0,
    @Json(name = "click_count") val clickCount: Int = 0,
    @Json(name = "click_rate") val clickRate: Double = 0.0,
)

// ───────────────────────  PROJECTS: PRJ-002+ additions  ───────────────────────
// PRJ-002/003/004/005/006/007/009/010 — task board, workload, milestones, templates,
// members, status history, contact links. Mirrors frontend/src/api/endpoints/crmProjects.ts.

// Partial project update (PATCH). Only set fields are sent; nulls are omitted by Moshi.
@JsonClass(generateAdapter = true)
data class CrmProjectUpdateInDto(
    @Json(name = "name") val name: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "priority") val priority: Int? = null,
    @Json(name = "start_date") val startDate: Long? = null,
    @Json(name = "end_date") val endDate: Long? = null,
    @Json(name = "assigned_user_sub") val assignedUserSub: String? = null,
    @Json(name = "account_id") val accountId: String? = null,
)

@JsonClass(generateAdapter = true)
data class CrmProjectTaskCreateInDto(
    @Json(name = "name") val name: String,
    @Json(name = "description") val description: String? = null,
    @Json(name = "task_order") val taskOrder: Int? = null,
    @Json(name = "duration_days") val durationDays: Int? = null,
    @Json(name = "start_date") val startDate: Long? = null,
    @Json(name = "end_date") val endDate: Long? = null,
    @Json(name = "percent_complete") val percentComplete: Int? = null,
    @Json(name = "is_milestone") val isMilestone: Boolean? = null,
    @Json(name = "assigned_user_sub") val assignedUserSub: String? = null,
)

@JsonClass(generateAdapter = true)
data class CrmProjectTaskUpdateInDto(
    @Json(name = "name") val name: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "task_order") val taskOrder: Int? = null,
    @Json(name = "duration_days") val durationDays: Int? = null,
    @Json(name = "start_date") val startDate: Long? = null,
    @Json(name = "end_date") val endDate: Long? = null,
    @Json(name = "percent_complete") val percentComplete: Int? = null,
    @Json(name = "is_milestone") val isMilestone: Boolean? = null,
    @Json(name = "assigned_user_sub") val assignedUserSub: String? = null,
)

@JsonClass(generateAdapter = true)
data class CrmProjectTaskReorderInDto(
    @Json(name = "task_ids") val taskIds: List<String>,
)

@JsonClass(generateAdapter = true)
data class CrmProjectTaskOrderRespDto(
    @Json(name = "items") val items: List<CrmProjectTaskDto> = emptyList(),
)

// ── Workload (PRJ-004) ─────────────────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class CrmTaskWorkloadEntryDto(
    @Json(name = "assignee_key") val assigneeKey: String = "",
    @Json(name = "resource_type") val resourceType: String = "user",
    @Json(name = "assigned_id") val assignedId: String = "",
    @Json(name = "task_count") val taskCount: Int = 0,
    @Json(name = "overdue_count") val overdueCount: Int = 0,
)

@JsonClass(generateAdapter = true)
data class CrmProjectWorkloadRespDto(
    @Json(name = "project_id") val projectId: String = "",
    @Json(name = "entries") val entries: List<CrmTaskWorkloadEntryDto> = emptyList(),
)

// ── Milestones (PRJ-005) ───────────────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class CrmMilestoneSummaryItemDto(
    @Json(name = "id") val id: String = "",
    @Json(name = "project_id") val projectId: String = "",
    @Json(name = "name") val name: String = "",
    @Json(name = "task_order") val taskOrder: Int = 0,
    @Json(name = "start_date") val startDate: Long? = null,
    @Json(name = "end_date") val endDate: Long? = null,
    @Json(name = "percent_complete") val percentComplete: Int = 0,
    @Json(name = "on_track") val onTrack: Boolean = false,
    @Json(name = "overdue") val overdue: Boolean = false,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class CrmMilestoneSummaryRespDto(
    @Json(name = "items") val items: List<CrmMilestoneSummaryItemDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
    @Json(name = "total_milestones") val totalMilestones: Int = 0,
    @Json(name = "overdue_count") val overdueCount: Int = 0,
    @Json(name = "on_track_count") val onTrackCount: Int = 0,
    @Json(name = "no_date_count") val noDateCount: Int = 0,
)

// ── Templates (PRJ-006) ────────────────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class CrmTemplateTaskDefDto(
    @Json(name = "template_task_id") val templateTaskId: String = "",
    @Json(name = "name") val name: String = "",
    @Json(name = "description") val description: String? = null,
    @Json(name = "task_order") val taskOrder: Int = 0,
    @Json(name = "duration_days") val durationDays: Int = 1,
    @Json(name = "is_milestone") val isMilestone: Boolean = false,
    @Json(name = "predecessor_template_task_ids") val predecessorTemplateTaskIds: List<String> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class CrmProjectTemplateDto(
    @Json(name = "id") val id: String = "",
    @Json(name = "owner_sub") val ownerSub: String? = null,
    @Json(name = "name") val name: String = "",
    @Json(name = "description") val description: String? = null,
    @Json(name = "task_defs") val taskDefs: List<CrmTemplateTaskDefDto> = emptyList(),
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class CrmTemplateListRespDto(
    @Json(name = "items") val items: List<CrmProjectTemplateDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class CrmTemplateCreateInDto(
    @Json(name = "name") val name: String,
    @Json(name = "description") val description: String? = null,
    @Json(name = "task_defs") val taskDefs: List<CrmTemplateTaskDefDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class CrmTemplateFromProjectInDto(
    @Json(name = "name") val name: String,
    @Json(name = "description") val description: String? = null,
)

@JsonClass(generateAdapter = true)
data class CrmTemplateInstantiateInDto(
    @Json(name = "project_name") val projectName: String,
    @Json(name = "start_date") val startDate: Long? = null,
)

// ── Members (PRJ-007) ──────────────────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class CrmProjectMemberDto(
    @Json(name = "project_id") val projectId: String = "",
    @Json(name = "user_sub") val userSub: String = "",
    @Json(name = "role") val role: String = "member",
    @Json(name = "added_by") val addedBy: String = "",
    @Json(name = "added_at") val addedAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class CrmProjectMemberListRespDto(
    @Json(name = "items") val items: List<CrmProjectMemberDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class CrmProjectAddMemberInDto(
    @Json(name = "user_sub") val userSub: String,
    @Json(name = "role") val role: String? = null,
)

@JsonClass(generateAdapter = true)
data class CrmProjectUpdateMemberInDto(
    @Json(name = "role") val role: String,
)

// ── Status history (PRJ-009) ───────────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class CrmProjectStatusHistoryEntryDto(
    @Json(name = "project_id") val projectId: String = "",
    @Json(name = "from_status") val fromStatus: String? = null,
    @Json(name = "to_status") val toStatus: String = "",
    @Json(name = "changed_by") val changedBy: String = "",
    @Json(name = "changed_at") val changedAt: Long = 0,
    @Json(name = "event_id") val eventId: String = "",
)

@JsonClass(generateAdapter = true)
data class CrmProjectStatusHistoryRespDto(
    @Json(name = "items") val items: List<CrmProjectStatusHistoryEntryDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
)

// ── Contact links (PRJ-010) ────────────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class CrmProjectContactLinkDto(
    @Json(name = "project_id") val projectId: String = "",
    @Json(name = "linked_entity_id") val linkedEntityId: String = "",
    @Json(name = "linked_entity_type") val linkedEntityType: String = "",
    @Json(name = "added_by") val addedBy: String = "",
    @Json(name = "added_at") val addedAt: Long = 0,
    @Json(name = "note") val note: String? = null,
)

@JsonClass(generateAdapter = true)
data class CrmProjectContactLinkListRespDto(
    @Json(name = "items") val items: List<CrmProjectContactLinkDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class CrmProjectAddContactLinkInDto(
    @Json(name = "linked_entity_id") val linkedEntityId: String,
    @Json(name = "linked_entity_type") val linkedEntityType: String? = null,
    @Json(name = "note") val note: String? = null,
)

// ─────────────────  CAMPAIGNS: CMP additions  ─────────────────
// CMP-001..CMP-008 — campaign CRUD/send/preview/ab-results + email-template editor + admin leads.
// Mirrors frontend/src/api/endpoints/crmCampaigns.ts + crmEmail.ts (app/routers/crm_campaigns.py).

// Full campaign shape (extends the compact list DTO's fields the earlier list view used).
@JsonClass(generateAdapter = true)
data class CrmCampaignFullDto(
    @Json(name = "campaign_id") val campaignId: String = "",
    @Json(name = "owner_id") val ownerId: String? = null,
    @Json(name = "name") val name: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "objective") val objective: String? = null,
    @Json(name = "budget_cents") val budgetCents: Long = 0,
    @Json(name = "contact_list_ids") val contactListIds: List<String> = emptyList(),
    @Json(name = "segment_ids") val segmentIds: List<String> = emptyList(),
    @Json(name = "tracking_code") val trackingCode: String? = null,
    @Json(name = "email_template_id") val emailTemplateId: String? = null,
    @Json(name = "questionnaire_id") val questionnaireId: String? = null,
    @Json(name = "questionnaire_url") val questionnaireUrl: String? = null,
    @Json(name = "campaign_type") val campaignType: String = "email",
    @Json(name = "variants") val variants: List<Map<String, Any?>>? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class CrmCampaignCreateInDto(
    @Json(name = "name") val name: String,
    @Json(name = "objective") val objective: String? = null,
    @Json(name = "budget_cents") val budgetCents: Long? = null,
    @Json(name = "contact_list_ids") val contactListIds: List<String>? = null,
    @Json(name = "segment_ids") val segmentIds: List<String>? = null,
    @Json(name = "tracking_code") val trackingCode: String? = null,
    @Json(name = "start_date") val startDate: String? = null,
    @Json(name = "end_date") val endDate: String? = null,
    @Json(name = "campaign_type") val campaignType: String? = null,
    @Json(name = "email_template_id") val emailTemplateId: String? = null,
    @Json(name = "questionnaire_id") val questionnaireId: String? = null,
)

@JsonClass(generateAdapter = true)
data class CrmCampaignUpdateInDto(
    @Json(name = "name") val name: String? = null,
    @Json(name = "objective") val objective: String? = null,
    @Json(name = "budget_cents") val budgetCents: Long? = null,
    @Json(name = "contact_list_ids") val contactListIds: List<String>? = null,
    @Json(name = "segment_ids") val segmentIds: List<String>? = null,
    @Json(name = "tracking_code") val trackingCode: String? = null,
    @Json(name = "start_date") val startDate: String? = null,
    @Json(name = "end_date") val endDate: String? = null,
    @Json(name = "campaign_type") val campaignType: String? = null,
    @Json(name = "email_template_id") val emailTemplateId: String? = null,
    @Json(name = "questionnaire_id") val questionnaireId: String? = null,
)

@JsonClass(generateAdapter = true)
data class CrmCampaignSendInDto(
    @Json(name = "dry_run") val dryRun: Boolean = false,
    @Json(name = "snapshot_ts") val snapshotTs: Long? = null,
)

@JsonClass(generateAdapter = true)
data class CrmCampaignSendOutDto(
    @Json(name = "campaign_id") val campaignId: String = "",
    @Json(name = "total_resolved") val totalResolved: Int = 0,
    @Json(name = "total_sent") val totalSent: Int = 0,
    @Json(name = "total_skipped") val totalSkipped: Int = 0,
    @Json(name = "dry_run") val dryRun: Boolean = false,
    @Json(name = "send_id") val sendId: String? = null,
)

// CMP-007 — A/B test results.
@JsonClass(generateAdapter = true)
data class CrmAbVariantStatsDto(
    @Json(name = "variant_id") val variantId: String = "",
    @Json(name = "label") val label: String = "",
    @Json(name = "sent") val sent: Int = 0,
    @Json(name = "opens") val opens: Int = 0,
    @Json(name = "clicks") val clicks: Int = 0,
    @Json(name = "open_rate") val openRate: Double = 0.0,
    @Json(name = "click_rate") val clickRate: Double = 0.0,
)

@JsonClass(generateAdapter = true)
data class CrmAbResultsDto(
    @Json(name = "campaign_id") val campaignId: String = "",
    @Json(name = "variant_stats") val variantStats: List<CrmAbVariantStatsDto> = emptyList(),
)

// CMP-008 — merge-tag email preview.
@JsonClass(generateAdapter = true)
data class CrmEmailPreviewInDto(
    @Json(name = "sample_party_id") val samplePartyId: String? = null,
    @Json(name = "sample_vars") val sampleVars: Map<String, String> = emptyMap(),
)

@JsonClass(generateAdapter = true)
data class CrmEmailPreviewOutDto(
    @Json(name = "subject") val subject: String = "",
    @Json(name = "body_text") val bodyText: String = "",
    @Json(name = "body_html") val bodyHtml: String? = null,
    @Json(name = "merge_vars_used") val mergeVarsUsed: Map<String, String> = emptyMap(),
    @Json(name = "merge_vars_missing") val mergeVarsMissing: List<String> = emptyList(),
)

// CMP-002 — HTML email templates.
@JsonClass(generateAdapter = true)
data class CrmEmailTemplateDto(
    @Json(name = "template_id") val templateId: String = "",
    @Json(name = "owner_id") val ownerId: String? = null,
    @Json(name = "name") val name: String = "",
    @Json(name = "subject_template") val subjectTemplate: String = "",
    @Json(name = "body_html_template") val bodyHtmlTemplate: String = "",
    @Json(name = "variables") val variables: List<String> = emptyList(),
    @Json(name = "status") val status: String = "draft",
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class CrmEmailTemplateListRespDto(
    @Json(name = "templates") val templates: List<CrmEmailTemplateDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
    @Json(name = "count") val count: Int = 0,
)

@JsonClass(generateAdapter = true)
data class CrmEmailTemplateCreateInDto(
    @Json(name = "name") val name: String,
    @Json(name = "subject_template") val subjectTemplate: String,
    @Json(name = "body_html_template") val bodyHtmlTemplate: String,
)

@JsonClass(generateAdapter = true)
data class CrmEmailTemplateUpdateInDto(
    @Json(name = "name") val name: String? = null,
    @Json(name = "subject_template") val subjectTemplate: String? = null,
    @Json(name = "body_html_template") val bodyHtmlTemplate: String? = null,
    @Json(name = "status") val status: String? = null,
)

@JsonClass(generateAdapter = true)
data class CrmEmailTemplatePreviewInDto(
    @Json(name = "sample_vars") val sampleVars: Map<String, String> = emptyMap(),
)

@JsonClass(generateAdapter = true)
data class CrmEmailTemplatePreviewOutDto(
    @Json(name = "subject") val subject: String = "",
    @Json(name = "body_html") val bodyHtml: String = "",
    @Json(name = "variables") val variables: List<String> = emptyList(),
    @Json(name = "missing_vars") val missingVars: List<String> = emptyList(),
)

// CMP-006 — admin web-to-lead list (server returns leads as loose dicts).
@JsonClass(generateAdapter = true)
data class CrmWebLeadDto(
    @Json(name = "capture_id") val captureId: String = "",
    @Json(name = "first_name") val firstName: String? = null,
    @Json(name = "last_name") val lastName: String? = null,
    @Json(name = "email") val email: String? = null,
    @Json(name = "phone") val phone: String? = null,
    @Json(name = "company") val company: String? = null,
    @Json(name = "message") val message: String? = null,
    @Json(name = "campaign_id") val campaignId: String? = null,
    @Json(name = "source_ip") val sourceIp: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class CrmWebLeadListRespDto(
    @Json(name = "leads") val leads: List<CrmWebLeadDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
    @Json(name = "count") val count: Int = 0,
)
