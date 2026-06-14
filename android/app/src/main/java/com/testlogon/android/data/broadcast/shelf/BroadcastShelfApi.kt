package com.testlogon.android.data.broadcast.shelf

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.Response
import retrofit2.http.GET
import retrofit2.http.Path

/**
 * AND-283 — dedicated Retrofit interface for the broadcast products shelf.
 *
 * VERIFIED against reference/openapi.index.txt line 219 + src/api/endpoints/broadcast-shelf.ts:
 *  - GET broadcast/sessions/{id}/products -> BroadcastShelfListOut { session_id, items: [...], count }
 *
 * The session linkage is the {id} PATH segment (NOT a ?session_id= query). Each item is a FLAT
 * BroadcastShelfItemOut (item_id, flat price_cents + currency, single image_url, category_id REQUIRED).
 * Idempotent GET; no mutation in this ticket (Buy routes to the AND-206 product detail). `chat/product`
 * is a separate broadcaster POST and is NOT this surface.
 */
interface BroadcastShelfApi {

    @GET("broadcast/sessions/{id}/products")
    suspend fun getSessionProducts(
        @Path("id") sessionId: String,
    ): Response<ShelfListDto>
}

/** BroadcastShelfListOut — { session_id, items, count }. */
@JsonClass(generateAdapter = true)
data class ShelfListDto(
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "items") val items: List<ShelfItemDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
)

/**
 * BroadcastShelfItemOut (flat). `category_id` is required in the contract. `price_cents` is flat (no
 * nested price object); `image_url` is a single nullable URL (no media[] array). `added_at` is epoch
 * SECONDS. Live-pricing fields (broadcast_price_cents / effective_price_cents / original_price_cents /
 * is_broadcast_price / discount_pct) are optional and used to prefer the effective price when present.
 */
@JsonClass(generateAdapter = true)
data class ShelfItemDto(
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "item_id") val itemId: String,
    @Json(name = "category_id") val categoryId: String,
    @Json(name = "name") val name: String = "",
    @Json(name = "description") val description: String? = null,
    @Json(name = "price_cents") val priceCents: Long = 0L,
    @Json(name = "currency") val currency: String = "USD",
    @Json(name = "image_url") val imageUrl: String? = null,
    @Json(name = "display_order") val displayOrder: Int = 0,
    @Json(name = "added_by") val addedBy: String = "",
    @Json(name = "added_at") val addedAt: Long = 0L,
    @Json(name = "effective_price_cents") val effectivePriceCents: Long? = null,
    @Json(name = "original_price_cents") val originalPriceCents: Long? = null,
    @Json(name = "is_broadcast_price") val isBroadcastPrice: Boolean = false,
    // AND-314 — host-authoring broadcast-price fields (additive/defaulted; AND-283 viewer ignores them).
    @Json(name = "broadcast_price_cents") val broadcastPriceCents: Long? = null,
    @Json(name = "broadcast_price_expires_at") val broadcastPriceExpiresAt: Long? = null,
    @Json(name = "broadcast_price_set_at") val broadcastPriceSetAt: Long? = null,
    @Json(name = "discount_pct") val discountPct: Int = 0,
)
