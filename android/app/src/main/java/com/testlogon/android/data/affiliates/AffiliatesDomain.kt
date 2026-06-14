package com.testlogon.android.data.affiliates

/**
 * AND-265 — framework-free affiliate domain models + total DTO -> domain mappers.
 *
 * Money is integer cents (revenue/commission). Percentages (commission_percent / conversion_rate_pct)
 * are kept as Double but are display-only and explicitly OUTSIDE the money graph. The aggregated earnings
 * are COMPUTED client-side by summing per-link fields (there is no summary endpoint). Mapping is TOTAL.
 */

/** Integer cents + ISO-4217 currency (the affiliate payload carries no currency code; defaults to USD). */
data class AffiliateMoney(val cents: Long, val currency: String)

enum class LinkStatus {
    ACTIVE,
    INACTIVE,
    REVOKED,
    OTHER,
    ;

    companion object {
        fun from(raw: String?): LinkStatus = when (raw?.lowercase()) {
            "active" -> ACTIVE
            "inactive" -> INACTIVE
            "revoked" -> REVOKED
            else -> OTHER
        }
    }
}

data class AffiliateLink(
    val id: String,
    val label: String,
    /** Relative path (e.g. "/r/abc123"); prefix with the web origin before copy/share. */
    val shortUrl: String,
    val destinationUrl: String,
    val trackingCode: String,
    val commissionPercent: Double,
    val status: LinkStatus,
    val rawStatus: String,
    val clicks: Long,
    val uniqueClicks: Long,
    val conversions: Long,
    val revenue: AffiliateMoney,
    val commissionEarned: AffiliateMoney,
    val conversionRatePct: Double,
    val createdAtEpochSeconds: Long,
    val updatedAtEpochSeconds: Long,
) {
    /**
     * Full shareable URL = <webOrigin> + shortUrl (mirrors the web's `window.location.origin + short_url`).
     * Pure String build (no android.net.Uri) -> JVM-testable. [webOrigin] must be the public web origin.
     */
    fun shareUrl(webOrigin: String): String {
        val base = webOrigin.trimEnd('/')
        return if (shortUrl.startsWith("/")) "$base$shortUrl" else "$base/$shortUrl"
    }
}

/** Client-side aggregation over links[] (no server pending/paid split; summed in the mapper). */
data class AffiliateEarnings(
    val totalEarned: AffiliateMoney,
    val totalRevenue: AffiliateMoney,
    val totalClicks: Long,
    val totalConversions: Long,
    val linkCount: Long,
)

data class AffiliateDashboard(
    val links: List<AffiliateLink>,
    val earnings: AffiliateEarnings,
) {
    val isEmpty: Boolean get() = links.isEmpty()
}

// ---- Mappers (DTO -> domain) ----

internal fun AffiliateLinkDto.toDomain(currency: String): AffiliateLink = AffiliateLink(
    id = linkId,
    label = targetName,
    shortUrl = shortUrl,
    destinationUrl = destinationUrl,
    trackingCode = trackingCode,
    commissionPercent = commissionPercent,
    status = LinkStatus.from(status),
    rawStatus = status,
    clicks = clickCount,
    uniqueClicks = uniqueClickCount,
    conversions = conversionCount,
    revenue = AffiliateMoney(revenueCents, currency),
    commissionEarned = AffiliateMoney(commissionEarnedCents, currency),
    conversionRatePct = conversionRatePct,
    createdAtEpochSeconds = createdAt,
    updatedAtEpochSeconds = updatedAt,
)

internal fun AffiliateLinksDto.toDomain(currency: String): AffiliateDashboard {
    val domainLinks = links.map { it.toDomain(currency) }
    return AffiliateDashboard(
        links = domainLinks,
        earnings = domainLinks.aggregateEarnings(currency),
    )
}

/** AND-265 — client-side earnings aggregation: sums per-link fields (integer cents, no Double). */
internal fun List<AffiliateLink>.aggregateEarnings(currency: String): AffiliateEarnings = AffiliateEarnings(
    totalEarned = AffiliateMoney(sumOf { it.commissionEarned.cents }, currency),
    totalRevenue = AffiliateMoney(sumOf { it.revenue.cents }, currency),
    totalClicks = sumOf { it.clicks },
    totalConversions = sumOf { it.conversions },
    linkCount = size.toLong(),
)
