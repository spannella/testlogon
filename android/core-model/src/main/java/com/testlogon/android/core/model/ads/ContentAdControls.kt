package com.testlogon.android.core.model.ads

/**
 * Domain models for the CONTENT AD-CONTROLS surface (web parity: ContentAdControlsPage.tsx).
 *
 * core-model has NO Moshi dependency: these are plain domain types. The wire DTOs (core-network
 * ContentAdOverrideDto / RevenueShareDto / AdRevenueBreakdownDto / AdvertiserTransparencyDto) are mapped to
 * these in the feature layer (which depends on both core-model + core-network). MONEY is a flat *_cents
 * [Long]; revenue share is integer basis-points; updated_at is an epoch [Long].
 */

/** Ad density bucket for a per-content override (low | standard | high), with an UNKNOWN fallback. */
enum class AdDensity {
    LOW,
    STANDARD,
    HIGH,
    UNKNOWN,
    ;

    /** The wire token for this density (UNKNOWN serializes as "standard" — a safe default). */
    val wire: String
        get() = when (this) {
            LOW -> "low"
            STANDARD -> "standard"
            HIGH -> "high"
            UNKNOWN -> "standard"
        }

    companion object {
        /** Parses a wire token; null / unrecognized -> [STANDARD] (never throws). */
        fun from(wire: String?): AdDensity = when (wire?.trim()?.lowercase()) {
            "low" -> LOW
            "standard" -> STANDARD
            "high" -> HIGH
            else -> STANDARD
        }
    }
}

/** A per-content ad override the caller owns. Identity is [contentId]. */
data class ContentAdOverride(
    val contentId: String,
    val contentType: String = "video",
    val adEnabled: Boolean = true,
    val adDensity: AdDensity = AdDensity.STANDARD,
    val preRollEnabled: Boolean = true,
    val midRollEnabled: Boolean = true,
    val adsFreeForSubscribers: Boolean = false,
    val updatedAt: Long? = null,
)

/** One by-content row of the ad-revenue breakdown. */
data class AdRevenueContent(
    val contentId: String,
    val revenueCents: Long = 0L,
)

/** The ad-revenue breakdown over a day window. */
data class AdRevenueBreakdown(
    val totalAdRevenueCents: Long = 0L,
    val entryCount: Int = 0,
    val days: Int = 30,
    val revenueShareBps: Int = 7000,
    val topContent: List<AdRevenueContent> = emptyList(),
)

/** One advertiser whose ads ran on the caller's content. */
data class AdvertiserTransparency(
    val accountId: String,
    val companyName: String = "Unknown",
    val totalImpressions: Long = 0L,
    val totalClicks: Long = 0L,
    val totalRevenueCents: Long = 0L,
)
