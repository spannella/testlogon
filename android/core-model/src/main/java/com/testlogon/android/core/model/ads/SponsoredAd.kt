package com.testlogon.android.core.model.ads

/**
 * ADV (group + syndicate feed ads) — a server-injected SPONSORED (paid) unit as consumed by the
 * NON-newsfeed feed surfaces (group feed, syndicate feed). The main newsfeed has its own
 * `com.testlogon.android.data.feed.SponsoredInfo` (:app); this is the core-model twin so the group /
 * syndicate domain models (which live in :core-model and cannot depend on :app) can carry the paid-unit
 * payload. The :app layer maps this to a `SponsoredInfo` when firing impression/click tracking through
 * the shared `AdTrackRepository`.
 *
 * [creativeId]/[campaignId]/[accountId] identify the ad for billing; [adClickId] is the per-serve
 * CPA-attribution id; [surface]/[slotType]/[creatorId]/[contentId] round-trip back to /ui/ads/track.
 * A standalone feed ad has no content owner, so the money-path books platform-100% on charge.
 */
data class SponsoredAd(
    val label: String,
    val headline: String?,
    val body: String?,
    val ctaText: String?,
    val ctaUrl: String?,
    val imageUrls: List<String>,
    val adClickId: String?,
    val creativeId: String,
    val campaignId: String,
    val accountId: String,
    val surface: String,
    val slotType: String,
    val creatorId: String,
    val contentId: String,
) {
    /** Stable de-dup key for a one-shot impression (per serve, falling back to the creative). */
    val impressionKey: String get() = adClickId?.takeIf { it.isNotBlank() } ?: creativeId
}
