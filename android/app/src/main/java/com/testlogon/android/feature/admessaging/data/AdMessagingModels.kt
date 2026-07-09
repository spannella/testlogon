package com.testlogon.android.feature.admessaging.data

import com.testlogon.android.core.network.admessaging.AdDmAudienceDto
import com.testlogon.android.core.network.admessaging.AdMessageOfferDto
import com.testlogon.android.core.network.admessaging.AdMessageSendDto

/**
 * ADV2-E5 (F5+F6) — framework-free domain model for the ad-messaging surface, mapped from the transport
 * DTOs. Kept in the feature layer (self-contained slice). `status` is a raw wire String kept verbatim +
 * surfaced via [statusEnum] with an UNKNOWN fallback.
 */

enum class AdMessageOfferStatus(val wire: String) {
    PENDING_CREATOR("pending_creator"),
    APPROVED("approved"),
    REJECTED("rejected"),
    UNKNOWN("");

    companion object {
        fun from(raw: String?): AdMessageOfferStatus = entries.firstOrNull { it.wire == raw } ?: UNKNOWN
    }
}

/** One advertiser-drafted, creator-reviewed sponsored-MESSAGE offer (F5). */
data class AdMessageOffer(
    val offerId: String,
    val advertiserSub: String?,
    val creatorSub: String?,
    val body: String?,
    val ctaUrl: String?,
    val accountId: String?,
    val campaignId: String?,
    val sponsorLabel: String?,
    val segment: String?,
    val status: String,
    val sendId: String?,
    val createdAt: Long?,
) {
    val statusEnum: AdMessageOfferStatus get() = AdMessageOfferStatus.from(status)
}

/**
 * A send record + funnel counters (shared across F5 approve/send + F6 create/detail). Delivered = on send
 * (2c), opened (+5c), clicked (+10c); [spendCents] is the advertisers total spend on this send.
 */
data class AdMessageSend(
    val sendId: String?,
    val product: String?,
    val status: String,
    val recipientCount: Int,
    val deliveredCount: Int,
    val openedCount: Int,
    val clickedCount: Int,
    val spendCents: Long,
    val stoppedInsufficientFunds: Boolean,
    val audience: AdDmAudience?,
) {
    /** True when the funds-guard stopped the send mid-way (advertiser balance ran out). */
    val paused: Boolean get() = stoppedInsufficientFunds || status == "paused_insufficient_funds"
}

/** The resolved eligible mass-DM audience (F6): reachable [count] + the exclusion tallies. */
data class AdDmAudience(
    val count: Int,
    val excludedOptoutCount: Int,
    val excludedNonRelationshipCount: Int,
    val capped: Boolean,
    val subscriberEnumerationDeferred: Boolean,
)

internal fun AdMessageOfferDto.toDomain(): AdMessageOffer = AdMessageOffer(
    offerId = offerId,
    advertiserSub = advertiserSub,
    creatorSub = creatorSub,
    body = body,
    ctaUrl = ctaUrl,
    accountId = accountId ?: sponsorAccountId,
    campaignId = campaignId,
    sponsorLabel = sponsorLabel,
    segment = segment,
    status = status.orEmpty(),
    sendId = sendId,
    createdAt = createdAt,
)

internal fun AdMessageSendDto.toDomain(): AdMessageSend = AdMessageSend(
    sendId = sendId,
    product = product,
    status = status.orEmpty(),
    recipientCount = recipientCount ?: 0,
    deliveredCount = deliveredCount ?: 0,
    openedCount = openedCount ?: 0,
    clickedCount = clickedCount ?: 0,
    spendCents = spendCents ?: 0L,
    stoppedInsufficientFunds = stoppedInsufficientFunds ?: false,
    audience = audience?.toDomain(),
)

internal fun AdDmAudienceDto.toDomain(): AdDmAudience = AdDmAudience(
    count = count ?: 0,
    excludedOptoutCount = excludedOptoutCount ?: 0,
    excludedNonRelationshipCount = excludedNonRelationshipCount ?: 0,
    capped = capped ?: false,
    subscriberEnumerationDeferred = subscriberEnumeration == "deferred_dec2_followers_only",
)
