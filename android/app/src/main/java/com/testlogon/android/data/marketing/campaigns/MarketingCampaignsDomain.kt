package com.testlogon.android.data.marketing.campaigns

/**
 * Framework-free domain models + total DTO -> domain mappers for OFBiz Marketing CAMPAIGNS.
 *
 * Mirrors the web marketing pages (campaigns list/create, contact lists, segments). Timestamps are
 * epoch-seconds. Status/objective are folded into [MarketingMath] enums so the UI can gate lifecycle
 * actions exactly like the web pages.
 */

data class MarketingCampaign(
    val id: String,
    val name: String,
    val objective: MarketingMath.CampaignObjective?,
    val objectiveRaw: String,
    val status: MarketingMath.CampaignStatus,
    val budgetCents: Long,
    val contactListIds: List<String>,
    val segmentIds: List<String>,
    val trackingCode: String?,
    val startDateSeconds: Long?,
    val endDateSeconds: Long?,
    val createdAtSeconds: Long,
    val updatedAtSeconds: Long,
) {
    val budgetLabel: String get() = MarketingMath.formatBudget(budgetCents)
    val allowedTransitions: List<MarketingMath.CampaignStatus>
        get() = MarketingMath.allowedTransitions(status)
    val canSend: Boolean get() = MarketingMath.canSend(status)
}

data class MarketingCampaignPage(
    val campaigns: List<MarketingCampaign>,
    val cursor: String?,
) {
    val isEmpty: Boolean get() = campaigns.isEmpty()
}

data class ContactList(
    val id: String,
    val name: String,
    val description: String?,
    val memberCount: Int,
    val createdAtSeconds: Long,
    val updatedAtSeconds: Long,
) {
    val sizeLabel: String get() = MarketingMath.formatSegmentSize(memberCount)
}

data class ContactListMember(
    val partyId: String,
    val displayName: String?,
    val suppressed: Boolean,
    val joinedAtSeconds: Long?,
) {
    val label: String get() = displayName?.takeIf { it.isNotBlank() } ?: partyId
}

data class SegmentPredicate(
    val attribute: String,
    val operator: String,
    val value: String,
) {
    val summary: String get() = MarketingMath.formatPredicate(attribute, operator, value)
}

data class PartySegment(
    val id: String,
    val name: String,
    val description: String?,
    val predicates: List<SegmentPredicate>,
    val candidateSource: String?,
    val createdAtSeconds: Long,
    val updatedAtSeconds: Long,
)

// ---- Mappers (DTO -> domain) ----

internal fun MarketingCampaignDto.toDomain(): MarketingCampaign = MarketingCampaign(
    id = campaignId,
    name = name,
    objective = MarketingMath.CampaignObjective.from(objective),
    objectiveRaw = objective,
    status = MarketingMath.CampaignStatus.from(status),
    budgetCents = budgetCents,
    contactListIds = contactListIds.orEmpty(),
    segmentIds = segmentIds.orEmpty(),
    trackingCode = trackingCode?.takeIf { it.isNotBlank() },
    startDateSeconds = startDate,
    endDateSeconds = endDate,
    createdAtSeconds = createdAt,
    updatedAtSeconds = updatedAt,
)

internal fun CampaignListRespDto.toDomain(): MarketingCampaignPage = MarketingCampaignPage(
    campaigns = campaigns.map { it.toDomain() },
    cursor = cursor,
)

internal fun ContactListDto.toDomain(): ContactList = ContactList(
    id = listId,
    name = name,
    description = description?.takeIf { it.isNotBlank() },
    memberCount = memberCount,
    createdAtSeconds = createdAt,
    updatedAtSeconds = updatedAt,
)

internal fun ContactListMemberDto.toDomain(): ContactListMember = ContactListMember(
    partyId = partyId,
    displayName = displayName?.takeIf { it.isNotBlank() },
    suppressed = suppressed == true,
    joinedAtSeconds = joinedAt,
)

internal fun SegmentPredicateDto.toDomain(): SegmentPredicate = SegmentPredicate(
    attribute = attribute,
    operator = operator,
    value = value?.toString().orEmpty(),
)

internal fun PartySegmentDto.toDomain(): PartySegment = PartySegment(
    id = segmentId,
    name = name,
    description = description?.takeIf { it.isNotBlank() },
    predicates = predicates.orEmpty().map { it.toDomain() },
    candidateSource = candidateSource?.takeIf { it.isNotBlank() },
    createdAtSeconds = createdAt,
    updatedAtSeconds = updatedAt,
)
