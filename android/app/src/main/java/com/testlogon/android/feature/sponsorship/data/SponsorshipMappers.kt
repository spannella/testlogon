package com.testlogon.android.feature.sponsorship.data

import com.testlogon.android.core.model.sponsorship.SponsorshipDeal
import com.testlogon.android.core.model.sponsorship.SponsorshipDealStatus
import com.testlogon.android.core.network.sponsorship.SponsorshipDealDto

/**
 * AND-365 - DTO -> domain mapper for the READ-ONLY sponsorship inbox.
 *
 * PLACEMENT: core-model has no dependency on core-network's DTOs (and core-network has no domain dep), so the
 * bridging mapper lives here in the feature, which depends on BOTH (mirrors AND-358 CollaborationMappers).
 *
 * Key transforms: `status` is kept RAW on the domain AND parsed via [SponsorshipDealStatus.from] (UNKNOWN
 * fallback); compensation_cents stays a Long; created_at stays a Long epoch; deadline stays the ISO string.
 */
fun SponsorshipDealDto.toDomain(): SponsorshipDeal {
    val rawStatus = status.orEmpty()
    return SponsorshipDeal(
        dealId = dealId,
        advertiserSub = advertiserSub,
        brief = brief,
        status = rawStatus,
        statusEnum = SponsorshipDealStatus.from(rawStatus),
        compensationCents = compensationCents,
        deadline = deadline,
        createdAt = createdAt,
    )
}
