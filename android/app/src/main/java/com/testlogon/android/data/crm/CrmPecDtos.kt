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
