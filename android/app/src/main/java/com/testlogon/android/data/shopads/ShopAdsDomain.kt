package com.testlogon.android.data.shopads

import com.testlogon.android.data.ads.toCtaActions
import com.testlogon.android.data.feed.SponsoredInfo

/**
 * ADV x ECOM (B2) — immutable domain model for a shop sponsored product unit.
 *
 * Carries the product display fields (name / price / image / category+item ids) AND the [tracking]
 * [SponsoredInfo] the SHARED AdTrackRepository consumes, so a sponsored product card fires
 * impression / click through the one /ui/ads/track money-path exactly like a newsfeed sponsored unit.
 * A shop unit is STANDALONE (no third-party content owner) so its charge books platform-100%; the
 * split is driven server-side off [SponsoredInfo.adClickId] (the AdClicks row carries content_owner="").
 * Sponsored products are NOT tippable and carry no like/wishlist affordance.
 */
data class SponsoredProduct(
    val unitId: String,
    /** Catalog item id (the product page's itemId). */
    val productId: String,
    /** Catalog category id (the product page's categoryId); may be blank on a stale unit. */
    val categoryId: String,
    val name: String,
    val priceCents: Long,
    val currency: String,
    val imageUrl: String?,
    val sponsorLabel: String,
    val ctaText: String,
    val tracking: SponsoredInfo,
) {
    /** The per-serve ad-click id to stash for CPA attribution + carry to /ui/ads/track (null if blank). */
    val adClickId: String? get() = tracking.adClickId?.takeIf { it.isNotBlank() }

    /** True when we can route to the real product page (both ids present). */
    val isRoutable: Boolean get() = productId.isNotBlank() && categoryId.isNotBlank()
}

/**
 * Map a served shop sponsored unit to the domain model. Builds the [SponsoredInfo] with a non-blank
 * creator_id ("platform") + content_id (the unit id) + slot_type ("sponsored_post") so the required
 * /ui/ads/track fields are satisfied; the platform-100% split is enforced server-side off the
 * ad_click_id (the standalone AdClicks row), NOT this metadata. Returns null for a unit missing the
 * product id (nothing to render / route).
 */
internal fun ShopSponsoredUnitDto.toDomainOrNull(fallbackCategoryId: String): SponsoredProduct? {
    val product = productId.trim()
    if (product.isBlank()) return null
    val category = productCategoryId.trim().ifBlank { fallbackCategoryId.trim() }
    val label = sponsorLabel.ifBlank { "Sponsored" }
    val display = productName.ifBlank { headline?.takeIf { it.isNotBlank() } ?: "Sponsored product" }
    val image = productImageUrl.ifBlank { imageUrl }.takeIf { it.isNotBlank() }
    val tracking = SponsoredInfo(
        label = label,
        headline = headline,
        ctaText = ctaText.ifBlank { "Shop now" },
        ctaUrl = null,
        adClickId = adClickId.takeIf { it.isNotBlank() },
        creativeId = creativeId,
        campaignId = campaignId,
        accountId = accountId,
        surface = surface.ifBlank { "shop_browse" },
        slotType = "sponsored_post",
        // Standalone shop placement has no third-party creator; a non-blank value is required by the
        // /ui/ads/track contract. The revenue split is driven off ad_click_id server-side.
        creatorId = "platform",
        contentId = unitId.ifBlank { "shop_${creativeId}" },
        ctas = ctas.toCtaActions(),
    )
    return SponsoredProduct(
        unitId = unitId.ifBlank { "shop_${creativeId}" },
        productId = product,
        categoryId = category,
        name = display,
        priceCents = productPriceCents,
        currency = productCurrency.ifBlank { "USD" },
        imageUrl = image,
        sponsorLabel = label,
        ctaText = ctaText.ifBlank { "Shop now" },
        tracking = tracking,
    )
}

/** ADV x ECOM (B4) — result of a seller product boost. */
data class BoostResult(
    val campaignId: String,
    val creativeId: String,
    val accountId: String,
    val productName: String,
    val budgetCents: Long,
    val status: String,
)

internal fun ProductBoostOutDto.toDomain(): BoostResult = BoostResult(
    campaignId = campaignId,
    creativeId = creativeId,
    accountId = accountId,
    productName = productName,
    budgetCents = budgetCents,
    status = status,
)
