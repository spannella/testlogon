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

// ── CRM-AND-LED: prospect / scoring-rules / score-history domain + mappers ──

/** A marketing prospect (pre-lead contact; LED-007). */
data class Prospect(
    val prospectId: String,
    val email: String,
    val firstName: String?,
    val lastName: String?,
    val phone: String?,
    val company: String?,
    val suppressed: Boolean,
    val createdAt: Long,
    val updatedAt: Long,
) {
    val displayName: String
        get() = listOfNotNull(firstName?.ifBlank { null }, lastName?.ifBlank { null })
            .joinToString(" ").ifBlank { email }
}

/** One entry in a lead's score history (LED-011). */
data class LeadScoreHistoryEntry(
    val score: Int,
    val trigger: String?,
    val computedAt: Long,
)

/** A single admin scoring rule (LED-011). */
data class LeadScoreRule(
    val field: String,
    val operator: String,
    val value: String,
    val points: Int,
)

/** The admin scoring-rules set (LED-011 / LED-013). */
data class LeadScoreRules(
    val rules: List<LeadScoreRule>,
    val maxScore: Int,
    val updatedAt: Long,
)

internal fun ProspectDto.toDomain(): Prospect = Prospect(
    prospectId = prospectId,
    email = email,
    firstName = firstName,
    lastName = lastName,
    phone = phone,
    company = company,
    suppressed = suppressed,
    createdAt = createdAt,
    updatedAt = updatedAt,
)

internal fun LeadScoreHistoryEntryDto.toDomain(): LeadScoreHistoryEntry = LeadScoreHistoryEntry(
    score = score,
    trigger = trigger,
    computedAt = computedAt,
)

internal fun LeadScoreRuleDto.toDomain(): LeadScoreRule = LeadScoreRule(
    field = field,
    operator = operator,
    value = value,
    points = points,
)

internal fun LeadScoreRule.toDto(): LeadScoreRuleDto = LeadScoreRuleDto(
    field = field,
    operator = operator,
    value = value,
    points = points,
)

internal fun LeadScoreRulesDto.toDomain(): LeadScoreRules = LeadScoreRules(
    rules = rules.map { it.toDomain() },
    maxScore = maxScore,
    updatedAt = updatedAt,
)


// ── CRM-AND-OPP: forecast / quota / pipeline-report / contact-role domain + mappers ──

/** A contact linked to an opportunity in a buying role (OPP-004). */
data class OppContactRole(
    val oppId: String,
    val contactRef: String,
    val contactRole: String,
    val ownerSub: String,
    val createdAt: Long,
) {
    /** Human label for the role key (title-cased, de-underscored). */
    val roleLabel: String
        get() = contactRole.split('_')
            .filter { it.isNotBlank() }
            .joinToString(" ") { part -> part.replaceFirstChar { it.uppercaseChar() } }
            .ifBlank { "—" }
}

/** A rep's forecast worksheet for one period (OPP-005). */
data class ForecastWorksheet(
    val userSub: String,
    val periodKey: String,
    val committedCents: Long,
    val bestCaseCents: Long,
    val pipelineCents: Long,
    val closedCents: Long,
    val quotaCents: Long,
    val attainmentPct: Int,
    val notes: String?,
    val createdAt: Long,
    val updatedAt: Long,
)

/** A per-stage row in the pipeline funnel report (OPP-006). Implements [ForecastMath.StageMetricLike]. */
data class PipelineStageMetric(
    override val stage: String,
    val label: String,
    override val count: Int,
    override val totalAmountCents: Long,
    override val weightedAmountCents: Long,
    val avgCloseDate: Long?,
) : ForecastMath.StageMetricLike

/** The full pipeline funnel report (OPP-006). */
data class PipelineReport(
    val stages: List<PipelineStageMetric>,
    val totalAmountCents: Long,
    val totalWeightedCents: Long,
    val generatedAt: Long,
)

/** A sales quota target for a rep + period (OPP-005, admin-set). */
data class SalesQuota(
    val userSub: String,
    val periodType: String,
    val periodKey: String,
    val targetAmountCents: Long,
    val createdAt: Long,
    val updatedAt: Long,
    val setBySub: String,
)

internal fun OppContactRoleOutDto.toDomain(): OppContactRole = OppContactRole(
    oppId = oppId,
    contactRef = contactRef,
    contactRole = contactRole,
    ownerSub = ownerSub,
    createdAt = createdAt,
)

internal fun ForecastWorksheetOutDto.toDomain(): ForecastWorksheet = ForecastWorksheet(
    userSub = userSub,
    periodKey = periodKey,
    committedCents = committedCents,
    bestCaseCents = bestCaseCents,
    pipelineCents = pipelineCents,
    closedCents = closedCents,
    quotaCents = quotaCents,
    attainmentPct = attainmentPct,
    notes = notes,
    createdAt = createdAt,
    updatedAt = updatedAt,
)

internal fun PipelineStageMetricDto.toDomain(): PipelineStageMetric = PipelineStageMetric(
    stage = stage,
    label = label.ifBlank { CrmSalesMath.stageLabel(stage) },
    count = count,
    totalAmountCents = totalAmountCents,
    weightedAmountCents = weightedAmountCents,
    avgCloseDate = avgCloseDate,
)

internal fun PipelineReportOutDto.toDomain(): PipelineReport = PipelineReport(
    stages = stages.map { it.toDomain() },
    totalAmountCents = totalAmountCents,
    totalWeightedCents = totalWeightedCents,
    generatedAt = generatedAt,
)

internal fun SalesQuotaOutDto.toDomain(): SalesQuota = SalesQuota(
    userSub = userSub,
    periodType = periodType,
    periodKey = periodKey,
    targetAmountCents = targetAmountCents,
    createdAt = createdAt,
    updatedAt = updatedAt,
    setBySub = setBySub,
)
