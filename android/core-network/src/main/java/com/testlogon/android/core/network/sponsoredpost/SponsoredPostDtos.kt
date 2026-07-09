package com.testlogon.android.core.network.sponsoredpost

import com.squareup.moshi.Json

/**
 * ADV2-E4 (F4) / ADV2-407..409 — transport DTOs for the SPONSORED-AS-CREATOR (paid partnership) surface:
 * an advertiser DRAFTS a post + PROPOSES it to a target creator; only that creator may APPROVE (which
 * publishes a NORMAL creator-authored post carrying the DISTINCT `paid_partnership` flag — tippable /
 * likeable / commentable, NO forced "Sponsored" label) or REJECT. Billing (advertiser charged per
 * impression/click, creator credited the placement share) rides the ad ledger via the placement mint.
 *
 * This is the platform's OWN REST surface (ui/ads/sponsored-posts/...), NOT the ADS-013 brand-deal
 * sponsorship inbox (ui/ads/sponsorships/...) — a deliberately SEPARATE api/dto/repo so the two never mix.
 *
 * CODEGEN NOTE (identical to the AND-365 sponsorship DTOs): core-network does NOT apply the Moshi KSP
 * plugin, so these decode via the reflective KotlinJsonAdapterFactory on the shared Moshi. The reflective
 * factory maps property names to JSON keys VERBATIM (no auto snake_case), so every wire key is pinned with
 * an explicit @Json(name = ...) and @JsonClass(generateAdapter = true) is intentionally OMITTED. `status`
 * is a RAW String (the typed enum lives in the feature layer).
 */

/** Request body for POST ui/ads/sponsored-posts/proposals (advertiser drafts + proposes). */
data class SponsoredPostProposalReq(
    @Json(name = "creator_sub") val creatorSub: String,
    @Json(name = "body") val body: String = "",
    @Json(name = "body_format") val bodyFormat: String = "plain",
    @Json(name = "image_urls") val imageUrls: List<String> = emptyList(),
    @Json(name = "video_id") val videoId: String? = null,
    @Json(name = "account_id") val accountId: String = "",
    @Json(name = "campaign_id") val campaignId: String = "",
    @Json(name = "creative_id") val creativeId: String = "",
    @Json(name = "sponsor_label") val sponsorLabel: String = "",
    @Json(name = "disclosure") val disclosure: String = "",
)

/** Request body for POST ui/ads/sponsored-posts/proposals/{id}/reject (optional reason). */
data class SponsoredPostRejectReq(
    @Json(name = "reason") val reason: String = "",
)

/**
 * One sponsored-post PROPOSAL row (the raw stored item). `proposal_id` is the only structural required key;
 * everything else is nullable / defaulted (extra / unknown wire keys tolerated leniently). `status` is one
 * of draft_proposed | approved | rejected (raw String; typed in the feature mapper).
 */
data class SponsoredPostProposalDto(
    @Json(name = "proposal_id") val proposalId: String,
    @Json(name = "advertiser_sub") val advertiserSub: String? = null,
    @Json(name = "creator_sub") val creatorSub: String? = null,
    @Json(name = "body") val body: String? = null,
    @Json(name = "body_format") val bodyFormat: String? = null,
    @Json(name = "image_urls") val imageUrls: List<String>? = null,
    @Json(name = "video_id") val videoId: String? = null,
    @Json(name = "account_id") val accountId: String? = null,
    @Json(name = "sponsor_account_id") val sponsorAccountId: String? = null,
    @Json(name = "campaign_id") val campaignId: String? = null,
    @Json(name = "creative_id") val creativeId: String? = null,
    @Json(name = "sponsor_label") val sponsorLabel: String? = null,
    @Json(name = "disclosure") val disclosure: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "published_post_id") val publishedPostId: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,
)

/** Envelope for the inbox/outbox queue reads: { "proposals": [ ... ] }. */
data class SponsoredPostListDto(
    @Json(name = "proposals") val proposals: List<SponsoredPostProposalDto> = emptyList(),
)

/** Result of POST .../approve -> the published post id + terminal status. */
data class SponsoredPostApproveDto(
    @Json(name = "proposal_id") val proposalId: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "post_id") val postId: String? = null,
)

/** Result of POST .../reject -> terminal status (no post). */
data class SponsoredPostRejectResultDto(
    @Json(name = "proposal_id") val proposalId: String? = null,
    @Json(name = "status") val status: String? = null,
)

/**
 * Result of GET .../{post_id}/placement — the per-viewer ad-click mint for a published paid_partnership
 * post. `billable=false` (with everything else null) for an organic post or a self-view; otherwise carries
 * the tracking handle the client round-trips to POST ui/ads/track to bill the advertiser (impression/click)
 * + credit the creator the placement share.
 */
data class SponsoredPostPlacementDto(
    @Json(name = "billable") val billable: Boolean = false,
    @Json(name = "ad_click_id") val adClickId: String? = null,
    @Json(name = "campaign_id") val campaignId: String? = null,
    @Json(name = "account_id") val accountId: String? = null,
    @Json(name = "creative_id") val creativeId: String? = null,
    @Json(name = "content_owner_id") val contentOwnerId: String? = null,
    @Json(name = "impression_url") val impressionUrl: String? = null,
    @Json(name = "click_url") val clickUrl: String? = null,
)
