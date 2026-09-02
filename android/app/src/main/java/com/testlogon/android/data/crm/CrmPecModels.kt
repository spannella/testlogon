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
    val assignedUserSub: String? = null,
    val predecessorTaskIds: List<String> = emptyList(),
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
    assignedUserSub = assignedUserSub,
    predecessorTaskIds = predecessorTaskIds,
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

// ───────────────────────  PROJECTS: PRJ-002+ domain + mappers  ─────────────────
// PRJ-002/003/004/005/006/007/009/010 domain models. Raw DTOs never leak to the UI.

data class CrmProjectMember(
    val projectId: String,
    val userSub: String,
    val role: String,
    val addedBy: String,
    val addedAt: Long,
)

data class CrmTaskWorkloadEntry(
    val assigneeKey: String,
    val resourceType: String,
    val assignedId: String,
    val taskCount: Int,
    val overdueCount: Int,
)

data class CrmProjectWorkload(
    val projectId: String,
    val entries: List<CrmTaskWorkloadEntry>,
)

data class CrmMilestoneSummaryItem(
    val id: String,
    val name: String,
    val taskOrder: Int,
    val startDate: Long?,
    val endDate: Long?,
    val percentComplete: Int,
    val onTrack: Boolean,
    val overdue: Boolean,
)

data class CrmMilestoneSummary(
    val items: List<CrmMilestoneSummaryItem>,
    val totalMilestones: Int,
    val overdueCount: Int,
    val onTrackCount: Int,
    val noDateCount: Int,
)

data class CrmTemplateTaskDef(
    val templateTaskId: String,
    val name: String,
    val description: String?,
    val taskOrder: Int,
    val durationDays: Int,
    val isMilestone: Boolean,
)

data class CrmProjectTemplate(
    val id: String,
    val name: String,
    val description: String?,
    val taskDefs: List<CrmTemplateTaskDef>,
    val createdAt: Long,
    val updatedAt: Long,
)

data class CrmProjectStatusHistoryEntry(
    val projectId: String,
    val fromStatus: String?,
    val toStatus: String,
    val changedBy: String,
    val changedAt: Long,
    val eventId: String,
)

data class CrmProjectContactLink(
    val projectId: String,
    val linkedEntityId: String,
    val linkedEntityType: String,
    val addedBy: String,
    val addedAt: Long,
    val note: String?,
)

// ── Mappers ─────────────────────────────────────────────────────────────────

fun CrmProjectMemberDto.toDomain(): CrmProjectMember = CrmProjectMember(
    projectId = projectId,
    userSub = userSub,
    role = role,
    addedBy = addedBy,
    addedAt = addedAt,
)

fun CrmTaskWorkloadEntryDto.toDomain(): CrmTaskWorkloadEntry = CrmTaskWorkloadEntry(
    assigneeKey = assigneeKey,
    resourceType = resourceType,
    assignedId = assignedId,
    taskCount = taskCount,
    overdueCount = overdueCount,
)

fun CrmProjectWorkloadRespDto.toDomain(): CrmProjectWorkload = CrmProjectWorkload(
    projectId = projectId,
    entries = entries.map { it.toDomain() },
)

fun CrmMilestoneSummaryItemDto.toDomain(): CrmMilestoneSummaryItem = CrmMilestoneSummaryItem(
    id = id,
    name = name,
    taskOrder = taskOrder,
    startDate = startDate,
    endDate = endDate,
    percentComplete = percentComplete,
    onTrack = onTrack,
    overdue = overdue,
)

fun CrmMilestoneSummaryRespDto.toDomain(): CrmMilestoneSummary = CrmMilestoneSummary(
    items = items.map { it.toDomain() },
    totalMilestones = totalMilestones,
    overdueCount = overdueCount,
    onTrackCount = onTrackCount,
    noDateCount = noDateCount,
)

fun CrmTemplateTaskDefDto.toDomain(): CrmTemplateTaskDef = CrmTemplateTaskDef(
    templateTaskId = templateTaskId,
    name = name,
    description = description,
    taskOrder = taskOrder,
    durationDays = durationDays,
    isMilestone = isMilestone,
)

fun CrmProjectTemplateDto.toDomain(): CrmProjectTemplate = CrmProjectTemplate(
    id = id,
    name = name,
    description = description,
    taskDefs = taskDefs.map { it.toDomain() },
    createdAt = createdAt,
    updatedAt = updatedAt,
)

fun CrmProjectStatusHistoryEntryDto.toDomain(): CrmProjectStatusHistoryEntry = CrmProjectStatusHistoryEntry(
    projectId = projectId,
    fromStatus = fromStatus,
    toStatus = toStatus,
    changedBy = changedBy,
    changedAt = changedAt,
    eventId = eventId,
)

fun CrmProjectContactLinkDto.toDomain(): CrmProjectContactLink = CrmProjectContactLink(
    projectId = projectId,
    linkedEntityId = linkedEntityId,
    linkedEntityType = linkedEntityType,
    addedBy = addedBy,
    addedAt = addedAt,
    note = note,
)

// ─────────────────  CAMPAIGNS: CMP domain + mappers  ─────────────────
// CMP-001..CMP-008 — full campaign, send result, A/B results, email template, preview, web lead.

/** Full campaign (extends the compact list projection). Fields default so the compact list DTO
 *  → domain mapping stays valid. */
data class CrmCampaignFull(
    val campaignId: String,
    val name: String,
    val status: String,
    val objective: String?,
    val budgetCents: Long,
    val contactListIds: List<String>,
    val segmentIds: List<String>,
    val trackingCode: String?,
    val emailTemplateId: String?,
    val questionnaireId: String?,
    val questionnaireUrl: String?,
    val campaignType: String,
    val variantLabels: List<String>,
    val createdAt: Long,
    val updatedAt: Long,
)

data class CrmCampaignSendResult(
    val campaignId: String,
    val totalResolved: Int,
    val totalSent: Int,
    val totalSkipped: Int,
    val dryRun: Boolean,
    val sendId: String?,
)

data class CrmAbVariantStats(
    val variantId: String,
    val label: String,
    val sent: Int,
    val opens: Int,
    val clicks: Int,
    val openRate: Double,
    val clickRate: Double,
)

data class CrmAbResults(
    val campaignId: String,
    val variants: List<CrmAbVariantStats>,
)

data class CrmEmailPreview(
    val subject: String,
    val bodyText: String,
    val bodyHtml: String?,
    val mergeVarsUsed: Map<String, String>,
    val mergeVarsMissing: List<String>,
)

data class CrmEmailTemplate(
    val templateId: String,
    val name: String,
    val subjectTemplate: String,
    val bodyHtmlTemplate: String,
    val variables: List<String>,
    val status: String,
    val createdAt: Long,
    val updatedAt: Long,
)

data class CrmEmailTemplatePreview(
    val subject: String,
    val bodyHtml: String,
    val variables: List<String>,
    val missingVars: List<String>,
)

data class CrmWebLead(
    val captureId: String,
    val firstName: String?,
    val lastName: String?,
    val email: String?,
    val phone: String?,
    val company: String?,
    val message: String?,
    val campaignId: String?,
    val sourceIp: String?,
    val createdAt: Long?,
)

// ── Mappers ──────────────────────────────────────────────────────────────────

private fun variantLabelsOf(variants: List<Map<String, Any?>>?): List<String> =
    variants.orEmpty().mapIndexed { i, v ->
        (v["label"] as? String)?.takeIf { it.isNotBlank() }
            ?: (v["variant_id"] as? String)?.takeIf { it.isNotBlank() }
            ?: "Variant ${('A' + i)}"
    }

fun CrmCampaignFullDto.toDomain(): CrmCampaignFull = CrmCampaignFull(
    campaignId = campaignId,
    name = name,
    status = status,
    objective = objective,
    budgetCents = budgetCents,
    contactListIds = contactListIds,
    segmentIds = segmentIds,
    trackingCode = trackingCode,
    emailTemplateId = emailTemplateId,
    questionnaireId = questionnaireId,
    questionnaireUrl = questionnaireUrl,
    campaignType = campaignType,
    variantLabels = variantLabelsOf(variants),
    createdAt = createdAt,
    updatedAt = updatedAt,
)

fun CrmCampaignSendOutDto.toDomain(): CrmCampaignSendResult = CrmCampaignSendResult(
    campaignId = campaignId,
    totalResolved = totalResolved,
    totalSent = totalSent,
    totalSkipped = totalSkipped,
    dryRun = dryRun,
    sendId = sendId,
)

fun CrmAbVariantStatsDto.toDomain(): CrmAbVariantStats = CrmAbVariantStats(
    variantId = variantId,
    label = label,
    sent = sent,
    opens = opens,
    clicks = clicks,
    openRate = openRate,
    clickRate = clickRate,
)

fun CrmAbResultsDto.toDomain(): CrmAbResults = CrmAbResults(
    campaignId = campaignId,
    variants = variantStats.map { it.toDomain() },
)

fun CrmEmailPreviewOutDto.toDomain(): CrmEmailPreview = CrmEmailPreview(
    subject = subject,
    bodyText = bodyText,
    bodyHtml = bodyHtml,
    mergeVarsUsed = mergeVarsUsed,
    mergeVarsMissing = mergeVarsMissing,
)

fun CrmEmailTemplateDto.toDomain(): CrmEmailTemplate = CrmEmailTemplate(
    templateId = templateId,
    name = name,
    subjectTemplate = subjectTemplate,
    bodyHtmlTemplate = bodyHtmlTemplate,
    variables = variables,
    status = status,
    createdAt = createdAt,
    updatedAt = updatedAt,
)

fun CrmEmailTemplatePreviewOutDto.toDomain(): CrmEmailTemplatePreview = CrmEmailTemplatePreview(
    subject = subject,
    bodyHtml = bodyHtml,
    variables = variables,
    missingVars = missingVars,
)

fun CrmWebLeadDto.toDomain(): CrmWebLead = CrmWebLead(
    captureId = captureId,
    firstName = firstName,
    lastName = lastName,
    email = email,
    phone = phone,
    company = company,
    message = message,
    campaignId = campaignId,
    sourceIp = sourceIp,
    createdAt = createdAt,
)
