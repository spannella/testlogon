package com.testlogon.android.data.wishlist

/**
 * ECOM — immutable domain model for a saved wishlist item. Money is carried as integer minor units
 * (priceCents) + ISO-4217 currency so locale formatting happens in the presentation layer. [available]
 * is false when the underlying catalog item was deleted after saving. Tapping through to product detail
 * uses exactly [categoryId] + [itemId].
 */
data class WishlistItem(
    val categoryId: String,
    val itemId: String,
    val name: String?,
    val description: String?,
    val priceCents: Long?,
    val currency: String,
    val imageUrls: List<String>,
    val creatorId: String?,
    val stockStatus: String?,
    val available: Boolean,
    val addedAt: String?,
) {
    /** First image is the list thumbnail; null when the saved item has no images. */
    val thumbnailUrl: String? get() = imageUrls.firstOrNull()

    /** Stable membership key (category + item) shared with the heart-toggle saved-set. */
    val key: String get() = wishlistKey(categoryId, itemId)
}

/** Canonical membership key used by the in-memory saved-set (heart toggle) across screens. */
fun wishlistKey(categoryId: String, itemId: String): String = "$categoryId#$itemId"

internal fun WishlistItemDto.toDomain(): WishlistItem = WishlistItem(
    categoryId = categoryId,
    itemId = itemId,
    name = name,
    description = description,
    priceCents = priceCents,
    currency = currency,
    imageUrls = imageUrls,
    creatorId = creatorId,
    stockStatus = stockStatus,
    available = available,
    addedAt = addedAt,
)
