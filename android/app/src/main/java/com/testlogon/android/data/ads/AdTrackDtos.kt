package com.testlogon.android.data.ads

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * ADV-106 — wire DTOs for POST /ui/ads/track (op track_ad_event_endpoint, AdTrackEventIn).
 *
 * Verified against app/models.py::AdTrackEventIn / app/routers/ads.py::track_ad_event_endpoint:
 *  - event in {impression|click|skip|complete}; creative_id/campaign_id/account_id/surface/slot_type/
 *    content_id/creator_id are ALL required, min_length 1.
 *  - ad_click_id is the per-serve CPA-attribution id minted by serve_ad (ADV-103) and carried through
 *    the injected sponsored feed unit (ADV-104); sent so a later attribution pass can join back to the
 *    AdClicks row. Extra keys are tolerated by the endpoint.
 * Response mirrors AdTrackEventOut; all fields defaulted so a partial body never crashes the parse.
 */
@JsonClass(generateAdapter = true)
data class AdTrackEventDto(
    @Json(name = "event") val event: String,
    @Json(name = "creative_id") val creativeId: String,
    @Json(name = "campaign_id") val campaignId: String,
    @Json(name = "account_id") val accountId: String,
    @Json(name = "surface") val surface: String,
    @Json(name = "slot_type") val slotType: String,
    @Json(name = "content_id") val contentId: String,
    @Json(name = "creator_id") val creatorId: String,
    @Json(name = "ad_click_id") val adClickId: String? = null,
    @Json(name = "view_time_ms") val viewTimeMs: Int? = null,
)

@JsonClass(generateAdapter = true)
data class AdTrackResultDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "event_id") val eventId: String = "",
    @Json(name = "flagged") val flagged: Boolean = false,
    @Json(name = "fraud_score") val fraudScore: Int = 0,
)


/**
 * ADV2-207 (F2) — wire DTOs for POST /ui/ads/cta-click (op cta_click_endpoint, CtaClickIn). A
 * structured CTA tap. The backend charges CPC to the advertiser (funds-guarded, idempotent per
 * {ad_click_id}#cta#{cta_type}) EXCEPT tip (no advertiser charge). ad_click_id + cta_type are
 * required; target_id is optional (subscribe/tip resolve to the placement content owner server-side).
 */
@JsonClass(generateAdapter = true)
data class CtaClickDto(
    @Json(name = "ad_click_id") val adClickId: String,
    @Json(name = "cta_type") val ctaType: String,
    @Json(name = "target_id") val targetId: String = "",
)

/** Response mirrors record_cta_click; all fields defaulted so a partial body never crashes the parse. */
@JsonClass(generateAdapter = true)
data class CtaClickResultDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "charged") val charged: Boolean = false,
    @Json(name = "charge_cents") val chargeCents: Int = 0,
    @Json(name = "reason") val reason: String = "",
)
