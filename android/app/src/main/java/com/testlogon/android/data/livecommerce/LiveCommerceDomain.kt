package com.testlogon.android.data.livecommerce

/**
 * LIVECOM L5 — immutable domain models for live-stream commerce. DTO -> domain mapping lives here so the
 * repository never leaks raw DTOs. Money stays integer minor units (cents) for the presentation layer to
 * format.
 */

/**
 * One product pinned to a live broadcast session ("shop this stream"). [isAffiliate] is derived
 * server-side from ownership; [affiliateCommissionBps] is the seller-set % the host earns on an
 * affiliate sale (0 for an own-product pin). [pinnedBy] is the host (broadcast session creator), used to
 * attribute an in-stream purchase to the host.
 */
data class PinnedProduct(
    val sessionId: String,
    val productId: String,
    val categoryId: String,
    val sellerId: String,
    val isAffiliate: Boolean,
    val affiliateCommissionBps: Int,
    val name: String,
    val priceCents: Long,
    val currency: String,
    val imageUrl: String?,
    val pinnedBy: String,
    val pinnedAt: Long,
) {
    /** The host's affiliate commission rendered as a percent (e.g. 1000 bps -> 10.0). */
    val commissionPercent: Double get() = affiliateCommissionBps / 100.0
}

internal fun PinnedProductDto.toDomain(): PinnedProduct = PinnedProduct(
    sessionId = sessionId,
    productId = productId,
    categoryId = categoryId,
    sellerId = sellerId,
    isAffiliate = isAffiliate,
    affiliateCommissionBps = affiliateCommissionBps,
    name = name,
    priceCents = priceCents,
    currency = currency,
    imageUrl = imageUrl?.takeIf { it.isNotBlank() },
    pinnedBy = pinnedBy,
    pinnedAt = pinnedAt,
)
