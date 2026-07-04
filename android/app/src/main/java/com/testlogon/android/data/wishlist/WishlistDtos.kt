package com.testlogon.android.data.wishlist

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * ECOM — wire DTOs for the wishlist router. Mirrors the `WishlistItemOut` contract: render fields are
 * snapshotted at save time but price/stock/availability are refreshed live from the catalog on read.
 */

/** POST ui/wishlist request body — the two keys that identify a catalog item. */
@JsonClass(generateAdapter = true)
data class WishlistAddDto(
    @Json(name = "category_id") val categoryId: String,
    @Json(name = "item_id") val itemId: String,
)

/** One saved wishlist entry (schema WishlistItemOut). */
@JsonClass(generateAdapter = true)
data class WishlistItemDto(
    @Json(name = "category_id") val categoryId: String,
    @Json(name = "item_id") val itemId: String,
    @Json(name = "name") val name: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "price_cents") val priceCents: Long? = null,
    @Json(name = "currency") val currency: String = "USD",
    @Json(name = "image_urls") val imageUrls: List<String> = emptyList(),
    @Json(name = "creator_id") val creatorId: String? = null,
    @Json(name = "stock_status") val stockStatus: String? = null,
    @Json(name = "available") val available: Boolean = true,
    @Json(name = "added_at") val addedAt: String? = null,
)

/** GET ui/wishlist envelope: newest-first items + a server-side count. */
@JsonClass(generateAdapter = true)
data class WishlistListDto(
    @Json(name = "items") val items: List<WishlistItemDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
)

/** DELETE ui/wishlist/... response (idempotent, always 200). */
@JsonClass(generateAdapter = true)
data class WishlistDeleteDto(
    @Json(name = "deleted") val deleted: Boolean = true,
)
