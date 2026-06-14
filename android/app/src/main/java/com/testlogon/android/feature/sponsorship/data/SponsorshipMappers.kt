package com.testlogon.android.feature.sponsorship.data

import com.testlogon.android.core.model.sponsorship.SponsorshipDeal
import com.testlogon.android.core.model.sponsorship.SponsorshipDealDetail
import com.testlogon.android.core.model.sponsorship.SponsorshipDealEvent
import com.testlogon.android.core.model.sponsorship.SponsorshipDealStatus
import com.testlogon.android.core.network.sponsorship.SponsorshipDealDetailDto
import com.testlogon.android.core.network.sponsorship.SponsorshipDealDto
import com.testlogon.android.core.network.sponsorship.SponsorshipDealEventDto

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

/**
 * AND-366 - DTO -> domain mapper for the FULL deal. Same key transforms as the inbox row plus the detail-only
 * fields: deliverables defaults to an empty list (a null wire array -> []); platform_commission_bps stays an
 * Int; payment_details collapses to a [SponsorshipDealDetail.hasPaymentDetails] presence flag (the opaque
 * object is never rendered field-by-field).
 */
fun SponsorshipDealDetailDto.toDomain(): SponsorshipDealDetail {
    val rawStatus = status.orEmpty()
    return SponsorshipDealDetail(
        dealId = dealId,
        advertiserSub = advertiserSub,
        creatorSub = creatorSub,
        brief = brief,
        status = rawStatus,
        statusEnum = SponsorshipDealStatus.from(rawStatus),
        compensationCents = compensationCents,
        deliverables = deliverables.orEmpty(),
        deadline = deadline,
        cpmBonusCents = cpmBonusCents,
        platformCommissionBps = platformCommissionBps,
        contentId = contentId,
        hasPaymentDetails = !paymentDetails.isNullOrEmpty(),
    )
}

/**
 * AND-366 - DTO -> domain mapper for a history event. The OPAQUE `details` payload is flattened to a single
 * display string: a plain String passes through; a Map is rendered as "k: v" pairs joined by ", " (stable
 * order via the map's iteration); anything else uses its toString (null / empty -> null).
 */
fun SponsorshipDealEventDto.toDomain(): SponsorshipDealEvent = SponsorshipDealEvent(
    eventId = eventId,
    eventType = eventType,
    actorSub = actorSub,
    detailsText = flattenDetails(details),
    createdAt = createdAt,
)

/** Flattens the opaque event `details` (String | Map | other) into a single display string, or null. */
private fun flattenDetails(details: Any?): String? = when (details) {
    null -> null
    is String -> details.ifBlank { null }
    is Map<*, *> -> details.entries
        .joinToString(separator = ", ") { (k, v) -> "$k: $v" }
        .ifBlank { null }
    else -> details.toString().ifBlank { null }
}
