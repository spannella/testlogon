package com.testlogon.android.core.network.admessaging

import com.squareup.moshi.Json

/**
 * ADV2-E5 (F5+F6) — transport DTOs for the AD-MESSAGING surface (shared billing engine + F5 sponsored
 * mass-messaging + F6 advertiser direct mass-DM). This is the platforms own REST surface
 * (ui/ads/sponsored-messages, ui/ads/mass-dm, ui/ads/messages), distinct from the E4 sponsored-POST
 * surface and the ADS-013 brand-deal inbox — a deliberately SEPARATE api/dto/repo so the three never mix.
 *
 * CODEGEN NOTE (identical to the E4 sponsored-post DTOs): core-network does NOT apply the Moshi KSP
 * plugin, so these decode via the reflective KotlinJsonAdapterFactory. Every wire key is pinned with an
 * explicit @Json(name = ...) and @JsonClass(generateAdapter = true) is intentionally OMITTED; `status` /
 * `product` are RAW Strings (typed in the feature layer). Extra/unknown wire keys are tolerated leniently.
 */

/** Request body for POST ui/ads/sponsored-messages/offers (F5 — advertiser drafts + offers to a creator). */
data class AdMessageOfferReq(
    @Json(name = "creator_sub") val creatorSub: String,
    @Json(name = "body") val body: String = "",
    @Json(name = "cta_url") val ctaUrl: String = "",
    @Json(name = "image_url") val imageUrl: String = "",
    @Json(name = "account_id") val accountId: String = "",
    @Json(name = "campaign_id") val campaignId: String = "",
    @Json(name = "creative_id") val creativeId: String = "",
    @Json(name = "sponsor_label") val sponsorLabel: String = "",
    @Json(name = "segment") val segment: String = "followers",
)

/** Request body for POST .../offers/{id}/approve — optional creator wording override (D3, no forced label). */
data class AdMessageApproveReq(
    @Json(name = "body") val body: String = "",
)

/** Request body for POST .../offers/{id}/reject — optional reason. */
data class AdMessageRejectReq(
    @Json(name = "reason") val reason: String = "",
)

/** Request body for POST ui/ads/mass-dm/campaigns (F6 — advertiser composes + sends AS itself). */
data class AdMassDmCreateReq(
    @Json(name = "account_id") val accountId: String,
    @Json(name = "campaign_id") val campaignId: String,
    @Json(name = "body") val body: String = "",
    @Json(name = "cta_url") val ctaUrl: String = "",
    @Json(name = "image_url") val imageUrl: String = "",
    @Json(name = "creative_id") val creativeId: String = "",
    @Json(name = "sponsor_label") val sponsorLabel: String = "",
)

/** Request body for PUT ui/ads/messages/ad-preferences — the per-user ad-messages opt-out. */
data class AdMessagePrefsReq(
    @Json(name = "allow_ad_messages") val allowAdMessages: Boolean = true,
)

/** One F5 sponsored-message OFFER row. `offer_id` is the only structural required key. */
data class AdMessageOfferDto(
    @Json(name = "offer_id") val offerId: String,
    @Json(name = "advertiser_sub") val advertiserSub: String? = null,
    @Json(name = "creator_sub") val creatorSub: String? = null,
    @Json(name = "body") val body: String? = null,
    @Json(name = "cta_url") val ctaUrl: String? = null,
    @Json(name = "image_url") val imageUrl: String? = null,
    @Json(name = "account_id") val accountId: String? = null,
    @Json(name = "sponsor_account_id") val sponsorAccountId: String? = null,
    @Json(name = "campaign_id") val campaignId: String? = null,
    @Json(name = "creative_id") val creativeId: String? = null,
    @Json(name = "sponsor_label") val sponsorLabel: String? = null,
    @Json(name = "segment") val segment: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "send_id") val sendId: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,
)

/** Envelope for the F5 inbox/outbox reads: { "offers": [ ... ] }. */
data class AdMessageOfferListDto(
    @Json(name = "offers") val offers: List<AdMessageOfferDto> = emptyList(),
)

/** Generic terminal result of approve / reject / cancel (send-bearing keys are all optional). */
data class AdMessageOfferResultDto(
    @Json(name = "offer_id") val offerId: String? = null,
    @Json(name = "send_id") val sendId: String? = null,
    @Json(name = "status") val status: String? = null,
)

/**
 * A send record + counters — returned by approve_and_send (F5), send_mass_dm (F6) and the send/campaign
 * detail GETs. Delivered/opened/clicked + spend are the funnel counters; `audience` is present on the
 * create/approve response (the just-resolved audience), absent on the plain detail GET.
 */
data class AdMessageSendDto(
    @Json(name = "send_id") val sendId: String? = null,
    @Json(name = "offer_id") val offerId: String? = null,
    @Json(name = "product") val product: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "creator_sub") val creatorSub: String? = null,
    @Json(name = "advertiser_sub") val advertiserSub: String? = null,
    @Json(name = "account_id") val accountId: String? = null,
    @Json(name = "campaign_id") val campaignId: String? = null,
    @Json(name = "recipient_count") val recipientCount: Int? = null,
    @Json(name = "delivered_count") val deliveredCount: Int? = null,
    @Json(name = "opened_count") val openedCount: Int? = null,
    @Json(name = "clicked_count") val clickedCount: Int? = null,
    @Json(name = "spend_cents") val spendCents: Long? = null,
    @Json(name = "stopped_insufficient_funds") val stoppedInsufficientFunds: Boolean? = null,
    @Json(name = "audience") val audience: AdDmAudienceDto? = null,
)

/** Envelope for the F6 campaigns list read: { "sends": [ ... ] }. */
data class AdMessageSendListDto(
    @Json(name = "sends") val sends: List<AdMessageSendDto> = emptyList(),
)

/**
 * The resolved eligible mass-DM audience (F6 preview + the audience echoed on a send). `count` is the
 * reachable count; the excluded_* counts report opt-out + non-relationship exclusions. `capped` flags the
 * MAX_RECIPIENTS cap; `subscriber_enumeration` logs the DEC-2 followers-only cap.
 */
data class AdDmAudienceDto(
    @Json(name = "segment") val segment: String? = null,
    @Json(name = "count") val count: Int? = null,
    @Json(name = "excluded_optout_count") val excludedOptoutCount: Int? = null,
    @Json(name = "excluded_non_relationship_count") val excludedNonRelationshipCount: Int? = null,
    @Json(name = "capped") val capped: Boolean? = null,
    @Json(name = "subscriber_enumeration") val subscriberEnumeration: String? = null,
)

/** Result of PUT/GET ui/ads/messages/ad-preferences — the per-user opt-out state. */
data class AdMessagePrefsDto(
    @Json(name = "allow_ad_messages") val allowAdMessages: Boolean = true,
)

/** Result of POST ui/ads/messages/{ad_click_id}/open|click — the charged surcharge (repo ignores body). */
data class AdMessageEngagementDto(
    @Json(name = "event") val event: String? = null,
    @Json(name = "ad_click_id") val adClickId: String? = null,
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "charge_cents") val chargeCents: Long = 0,
)
