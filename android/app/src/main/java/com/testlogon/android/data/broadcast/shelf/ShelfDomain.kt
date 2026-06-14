package com.testlogon.android.data.broadcast.shelf

/**
 * AND-283 — products shelf domain model (DTO-free). The Buy hand-off routes to the AND-206 product
 * detail (`shop/{categoryId}/{itemId}`), so [categoryId] + [itemId] are the load-bearing fields.
 * [priceCents] prefers effective_price_cents (broadcast/live price) over the base price_cents;
 * [originalPriceCents] is non-null only when a broadcast price is active (for a strikethrough).
 */
data class ShelfProduct(
    val itemId: String,
    val categoryId: String,
    val name: String,
    val priceCents: Long,
    val currency: String,
    val imageUrl: String?,
    val originalPriceCents: Long?,
    // AND-314 — host-authoring fields (additive/defaulted; AND-283 viewer never reads them). The catalog
    // (base) price is preserved so the host can pre-check a new broadcast price against it and clear back to
    // it; the broadcast-price metadata drives the live discount badge + expiry countdown on the host shelf.
    val catalogPriceCents: Long = priceCents,
    val displayOrder: Int = 0,
    val isBroadcastPrice: Boolean = false,
    val broadcastPriceCents: Long? = null,
    val broadcastPriceExpiresAtEpochSeconds: Long? = null,
    val discountPct: Int = 0,
)

internal fun ShelfItemDto.toDomain(): ShelfProduct {
    val effective = effectivePriceCents ?: priceCents
    val original = originalPriceCents?.takeIf { isBroadcastPrice && it != effective }
    return ShelfProduct(
        itemId = itemId,
        categoryId = categoryId,
        name = name,
        priceCents = effective,
        currency = currency.ifBlank { "USD" },
        imageUrl = imageUrl,
        originalPriceCents = original,
        // AND-314 — original_price_cents (when present) is the catalog price; otherwise the base price_cents.
        catalogPriceCents = originalPriceCents ?: priceCents,
        displayOrder = displayOrder,
        isBroadcastPrice = isBroadcastPrice,
        broadcastPriceCents = broadcastPriceCents,
        broadcastPriceExpiresAtEpochSeconds = broadcastPriceExpiresAt,
        discountPct = discountPct,
    )
}

/** Maps + orders by display_order (web parity), then item_id as a stable tiebreaker. */
internal fun ShelfListDto.toDomain(): List<ShelfProduct> =
    items.sortedWith(compareBy({ it.displayOrder }, { it.itemId })).map { it.toDomain() }
