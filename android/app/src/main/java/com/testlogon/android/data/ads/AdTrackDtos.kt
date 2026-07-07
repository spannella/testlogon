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
