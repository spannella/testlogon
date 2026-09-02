package com.testlogon.android.data.crm

/**
 * CRM-AND-PEC — domain models + DTO→domain mappers for the Projects / Events / Campaigns surfaces.
 * Raw DTOs never leak into the UI.
 */

// ─── Projects ────────────────────────────────────────────────────────────────

data class CrmProject(
    val id: String,
    val name: String,
    val description: String?,
    val status: String,
    val priority: Int,
    val startDate: Long?,
    val endDate: Long?,
    val assignedUserSub: String?,
    val accountId: String?,
    val createdAt: Long,
    val updatedAt: Long,
)

data class CrmProjectTask(
    val id: String,
    val name: String,
    val description: String?,
    val taskOrder: Int,
    val durationDays: Int,
    val startDate: Long?,
    val endDate: Long?,
    val percentComplete: Int,
    val isMilestone: Boolean,
)

// ─── Events ──────────────────────────────────────────────────────────────────

data class CrmEvent(
    val eventId: String,
    val name: String,
    val description: String,
    val maxAttendance: Int?,
    val createdAt: Long,
    val updatedAt: Long,
)

data class CrmEventCapacity(
    val maxAttendance: Int?,
    val acceptedCount: Int,
    val waitlistedCount: Int,
    val availableSpots: Int?,
)

data class CrmInvitee(
    val eventId: String,
    val inviteeSub: String,
    val inviteStatus: String,
    val invitedAt: Long,
    val respondedAt: Long?,
    val displayName: String?,
)

data class CrmRegistration(
    val eventId: String,
    val registrantSub: String,
    val status: String,
    val registeredAt: Long,
    val respondedAt: Long?,
    val checkedInAt: Long?,
    val waitlistPosition: Int?,
    val invited: Boolean?,
)

/** Roll-up of a send-invitations run. */
data class CrmSendInvitationsResult(
    val sent: Int,
    val skipped: Int,
    val failed: Int,
)

/** Roll-up of a bulk-import run. */
data class CrmBulkImportResult(
    val added: Int,
    val skipped: Int,
)

// ─── Campaigns ───────────────────────────────────────────────────────────────

data class CrmCampaign(
    val campaignId: String,
    val name: String,
    val status: String,
    val objective: String?,
    val budgetCents: Long,
    val trackingCode: String?,
    val campaignType: String,
    val createdAt: Long,
    val updatedAt: Long,
)

data class CrmCampaignAttribution(
    val totalSent: Int,
    val emailSent: Int,
    val openCount: Int,
    val openRate: Double,
    val clickCount: Int,
    val clickRate: Double,
)

// ─── Mappers ─────────────────────────────────────────────────────────────────

fun CrmProjectDto.toDomain(): CrmProject = CrmProject(
    id = id,
    name = name,
    description = description,
    status = status,
    priority = priority,
    startDate = startDate,
    endDate = endDate,
    assignedUserSub = assignedUserSub,
    accountId = accountId,
    createdAt = createdAt,
    updatedAt = updatedAt,
)

fun CrmProjectTaskDto.toDomain(): CrmProjectTask = CrmProjectTask(
    id = id,
    name = name,
    description = description,
    taskOrder = taskOrder,
    durationDays = durationDays,
    startDate = startDate,
    endDate = endDate,
    percentComplete = percentComplete,
    isMilestone = isMilestone,
)

fun CrmEventDto.toDomain(): CrmEvent = CrmEvent(
    eventId = eventId,
    name = name,
    description = description,
    maxAttendance = maxAttendance,
    createdAt = createdAt,
    updatedAt = updatedAt,
)

fun CrmEventCapacityDto.toDomain(): CrmEventCapacity = CrmEventCapacity(
    maxAttendance = maxAttendance,
    acceptedCount = acceptedCount,
    waitlistedCount = waitlistedCount,
    availableSpots = availableSpots,
)

fun CrmInviteeDto.toDomain(): CrmInvitee = CrmInvitee(
    eventId = eventId,
    inviteeSub = inviteeSub,
    inviteStatus = inviteStatus,
    invitedAt = invitedAt,
    respondedAt = respondedAt,
    displayName = displayName,
)

fun CrmRegistrationDto.toDomain(): CrmRegistration = CrmRegistration(
    eventId = eventId,
    registrantSub = registrantSub,
    status = status,
    registeredAt = registeredAt,
    respondedAt = respondedAt,
    checkedInAt = checkedInAt,
    waitlistPosition = waitlistPosition,
    invited = invited,
)

fun CrmSendInvitationsDto.toDomain(): CrmSendInvitationsResult = CrmSendInvitationsResult(
    sent = sent,
    skipped = skipped,
    failed = failed,
)

fun CrmBulkImportDto.toDomain(): CrmBulkImportResult = CrmBulkImportResult(
    added = added,
    skipped = skipped,
)

fun CrmCampaignDto.toDomain(): CrmCampaign = CrmCampaign(
    campaignId = campaignId,
    name = name,
    status = status,
    objective = objective,
    budgetCents = budgetCents,
    trackingCode = trackingCode,
    campaignType = campaignType,
    createdAt = createdAt,
    updatedAt = updatedAt,
)

fun CrmCampaignAttributionDto.toDomain(): CrmCampaignAttribution = CrmCampaignAttribution(
    totalSent = totalSent,
    emailSent = emailSent,
    openCount = openCount,
    openRate = openRate,
    clickCount = clickCount,
    clickRate = clickRate,
)
