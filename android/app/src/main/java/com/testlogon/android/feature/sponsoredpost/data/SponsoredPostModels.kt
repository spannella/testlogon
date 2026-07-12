package com.testlogon.android.feature.sponsoredpost.data

import com.testlogon.android.core.network.sponsoredpost.SponsoredPostApproveDto
import com.testlogon.android.core.network.sponsoredpost.SponsoredPostPlacementDto
import com.testlogon.android.core.network.sponsoredpost.SponsoredPostProposalDto

/**
 * ADV2-E4 (F4) — framework-free domain model for the sponsored-as-creator (paid partnership) surface,
 * mapped from the transport DTOs. Kept in the feature layer (not core-model) as this is a self-contained
 * slice. `status` is a raw wire String kept verbatim + surfaced via [statusEnum] with an UNKNOWN fallback.
 */

enum class SponsoredPostStatus(val wire: String) {
    DRAFT_PROPOSED("draft_proposed"),
    APPROVED("approved"),
    REJECTED("rejected"),
    UNKNOWN("");

    companion object {
        fun from(raw: String?): SponsoredPostStatus =
            entries.firstOrNull { it.wire == raw } ?: UNKNOWN
    }
}

/** One advertiser-drafted, creator-reviewed sponsored-post proposal. */
data class SponsoredPostProposal(
    val proposalId: String,
    val advertiserSub: String?,
    val creatorSub: String?,
    val body: String?,
    val imageUrls: List<String>,
    val videoId: String?,
    val accountId: String?,
    val campaignId: String?,
    val creativeId: String?,
    val sponsorLabel: String?,
    val disclosure: String?,
    val status: String,
    val publishedPostId: String?,
    val createdAt: Long?,
) {
    val statusEnum: SponsoredPostStatus get() = SponsoredPostStatus.from(status)
}

/** Result of approving a proposal — the published creator post id. */
data class SponsoredPostApproveResult(
    val proposalId: String?,
    val status: String?,
    val postId: String?,
)

/**
 * The per-viewer billing handle for a published paid_partnership post (from GET .../{postId}/placement).
 * [billable] is false for an organic post or a self-view; when true the ids round-trip to POST ui/ads/track
 * to bill the advertiser (impression/click) + credit the creator the placement share.
 */
data class SponsoredPostPlacement(
    val billable: Boolean,
    val adClickId: String?,
    val campaignId: String?,
    val accountId: String?,
    val creativeId: String?,
    val contentOwnerId: String?,
)

internal fun SponsoredPostProposalDto.toDomain(): SponsoredPostProposal = SponsoredPostProposal(
    proposalId = proposalId,
    advertiserSub = advertiserSub,
    creatorSub = creatorSub,
    body = body,
    imageUrls = imageUrls.orEmpty(),
    videoId = videoId,
    accountId = accountId ?: sponsorAccountId,
    campaignId = campaignId,
    creativeId = creativeId,
    sponsorLabel = sponsorLabel,
    disclosure = disclosure,
    status = status.orEmpty(),
    publishedPostId = publishedPostId,
    createdAt = createdAt,
)

internal fun SponsoredPostApproveDto.toDomain(): SponsoredPostApproveResult =
    SponsoredPostApproveResult(proposalId = proposalId, status = status, postId = postId)

internal fun SponsoredPostPlacementDto.toDomain(): SponsoredPostPlacement = SponsoredPostPlacement(
    billable = billable,
    adClickId = adClickId,
    campaignId = campaignId,
    accountId = accountId,
    creativeId = creativeId,
    contentOwnerId = contentOwnerId,
)
