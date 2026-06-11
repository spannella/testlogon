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
    )
}

/** Maps + orders by display_order (web parity), then item_id as a stable tiebreaker. */
internal fun ShelfListDto.toDomain(): List<ShelfProduct> =
    items.sortedWith(compareBy({ it.displayOrder }, { it.itemId })).map { it.toDomain() }
