package com.testlogon.android.data.crm

/**
 * CRM-AND-1 — domain models for the CRM Sales surface (no raw DTOs leak into the UI) + DTO→domain mappers.
 */

/** A CRM lead / prospect. */
data class Lead(
    val leadId: String,
    val firstName: String,
    val lastName: String,
    val email: String,
    val phone: String?,
    val company: String?,
    val title: String?,
    val leadSource: String?,
    val description: String?,
    val status: String,
    val score: Int,
    val assignedTo: String?,
    val createdAt: Long,
    val updatedAt: Long,
    val convertedAt: Long?,
) {
    val fullName: String
        get() = listOf(firstName, lastName).filter { it.isNotBlank() }.joinToString(" ").ifBlank { email }

    val isConverted: Boolean get() = status == "converted" || convertedAt != null
}

data class LeadActivity(
    val activityId: String,
    val activityType: String,
    val subject: String?,
    val description: String?,
    val createdAt: Long,
)

data class LeadConversionResult(
    val leadId: String,
    val status: String,
    val opportunityId: String?,
    val opportunityName: String?,
    val opportunityAmountCents: Long,
    val convertedAt: Long,
)

/** An opportunity in the sales pipeline. Implements [CrmSalesMath.PipelineOppLike] for the roll-ups. */
data class Opportunity(
    val oppId: String,
    val name: String,
    override val stage: String,
    override val amountCents: Long,
    val serverWeightedCents: Long,
    override val probability: Int,
    val closeDate: Long,
    val leadSource: String?,
    val description: String?,
    val createdAt: Long,
    val updatedAt: Long,
) : CrmSalesMath.PipelineOppLike

data class StageConfigItem(
    val stageKey: String,
    val label: String,
    val probabilityDefault: Int,
    val order: Int,
    val isWon: Boolean,
    val isLost: Boolean,
)

// ── DTO -> domain mappers ──────────────────────────────────────────────────

internal fun LeadDto.toDomain(): Lead = Lead(
    leadId = leadId,
    firstName = firstName,
    lastName = lastName,
    email = email,
    phone = phone,
    company = company,
    title = title,
    leadSource = leadSource,
    description = description,
    status = status,
    score = score,
    assignedTo = assignedTo,
    createdAt = createdAt,
    updatedAt = updatedAt,
    convertedAt = convertedAt,
)

internal fun LeadActivityDto.toDomain(): LeadActivity = LeadActivity(
    activityId = activityId,
    activityType = activityType,
    subject = subject,
    description = description,
    createdAt = createdAt,
)

internal fun LeadConversionResultDto.toDomain(): LeadConversionResult = LeadConversionResult(
    leadId = leadId,
    status = status,
    opportunityId = opportunity?.opportunityId,
    opportunityName = opportunity?.name,
    opportunityAmountCents = opportunity?.amountCents ?: 0L,
    convertedAt = convertedAt,
)

internal fun OpportunityOutDto.toDomain(): Opportunity {
    val effectiveProbability =
        if (probability > 0) probability else CrmSalesMath.defaultProbabilityFor(stage)
    val effectiveWeighted =
        if (weightedAmountCents > 0) weightedAmountCents
        else CrmSalesMath.weightedAmountCents(amountCents, effectiveProbability, stage)
    return Opportunity(
        oppId = oppId,
        name = name,
        stage = stage,
        amountCents = amountCents,
        serverWeightedCents = effectiveWeighted,
        probability = effectiveProbability,
        closeDate = closeDate,
        leadSource = leadSource,
        description = description,
        createdAt = createdAt,
        updatedAt = updatedAt,
    )
}

internal fun StageConfigItemOutDto.toDomain(): StageConfigItem = StageConfigItem(
    stageKey = stageKey,
    label = label.ifBlank { CrmSalesMath.stageLabel(stageKey) },
    probabilityDefault = probabilityDefault,
    order = order,
    isWon = isWon,
    isLost = isLost,
)
