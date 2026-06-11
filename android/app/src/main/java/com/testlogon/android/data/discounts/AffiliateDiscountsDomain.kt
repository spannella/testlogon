package com.testlogon.android.data.discounts

/**
 * AND-267 — framework-free affiliate-discount domain models + total DTO -> domain mappers.
 *
 * The verified wire shape (src/api/types.ts:AdAffiliateDiscount) carries NO numeric value, currency,
 * validity window, redemption cap, or enabled flag — so there is no money graph and no server status here.
 * "Value" is the free-text promo_value_display (rendered verbatim, matching the web PromoBadge). The
 * shareable link is click_through_url. Timestamps are epoch SECONDS (Long) — no java.time (API-26) so this
 * stays JVM-testable. Mapping is TOTAL: absent optionals default per the schema.
 *
 * [DiscountKind] is a BEST-EFFORT, client-derived bucket parsed from promo_value_display purely for chip
 * styling/icons (NOT a server field, NOT authoritative). [deriveKind] never throws.
 */

/** Best-effort discount-kind bucket derived from the free-text promo_value_display. Not a server field. */
enum class DiscountKind {
    PERCENT,
    FIXED,
    FREE_TRIAL,
    UNKNOWN,
}

/**
 * Heuristic parse of the free-text [display] badge into a [DiscountKind] for chip styling only.
 * "20% OFF" -> PERCENT, "$5 OFF" / "5 OFF" with a currency hint -> FIXED, "FREE TRIAL" -> FREE_TRIAL,
 * everything else (incl. null/blank/"BOGO") -> UNKNOWN. Never throws; case-insensitive.
 */
fun deriveKind(display: String?): DiscountKind {
    val text = display?.trim()?.lowercase().orEmpty()
    if (text.isEmpty()) return DiscountKind.UNKNOWN
    return when {
        text.contains("free") && text.contains("trial") -> DiscountKind.FREE_TRIAL
        text.contains('%') || text.contains("percent") -> DiscountKind.PERCENT
        text.contains('$') || text.contains("usd") -> DiscountKind.FIXED
        else -> DiscountKind.UNKNOWN
    }
}

data class AffiliateDiscount(
    /** Primary key (no separate discount id exists on the wire). */
    val creativeId: String,
    val campaignId: String,
    val ownerSub: String,
    /** Affiliate tracking code (nullable). */
    val affiliateCode: String?,
    /** Promo code (nullable). */
    val promoCode: String?,
    /** Free-text badge rendered verbatim (e.g. "20% OFF"); nullable. */
    val promoValueDisplay: String?,
    /** Affiliate landing link to share (nullable). */
    val clickThroughUrl: String?,
    val clickCount: Long,
    val redemptionCount: Long,
    /** Epoch seconds; 0 = unknown. */
    val createdAtEpochSeconds: Long,
    val updatedAtEpochSeconds: Long,
) {
    /** Best-effort kind for chip styling, derived from [promoValueDisplay]. Not authoritative. */
    val derivedKind: DiscountKind get() = deriveKind(promoValueDisplay)

    /** The code shown/copied: promo_code first, falling back to affiliate_code. */
    val displayCode: String? get() = promoCode?.takeIf { it.isNotBlank() } ?: affiliateCode?.takeIf { it.isNotBlank() }

    /** Text to share: the click-through URL, falling back to the display code. */
    fun shareText(): String? = clickThroughUrl?.takeIf { it.isNotBlank() } ?: displayCode
}

/** Aggregate for the discounts screen: the attached discounts list. */
data class AffiliateDiscounts(
    val items: List<AffiliateDiscount>,
) {
    val isEmpty: Boolean get() = items.isEmpty()
}

// ---- Mappers (DTO -> domain) ----

internal fun AffiliateDiscountDto.toDomain(): AffiliateDiscount = AffiliateDiscount(
    creativeId = creativeId,
    campaignId = campaignId,
    ownerSub = ownerSub,
    affiliateCode = affiliateCode,
    promoCode = promoCode,
    promoValueDisplay = promoValueDisplay,
    clickThroughUrl = clickThroughUrl,
    clickCount = clickCount,
    redemptionCount = redemptionCount,
    createdAtEpochSeconds = createdAt,
    updatedAtEpochSeconds = updatedAt,
)

internal fun AffiliateDiscountListDto.toDomain(): AffiliateDiscounts =
    AffiliateDiscounts(items = items.map { it.toDomain() })
