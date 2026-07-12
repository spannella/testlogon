package com.testlogon.android.data.livecommerce

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * LIVECOM L5 — wire DTOs for the live-stream commerce surface (backend router
 * app/routers/live_commerce.py, prefix ui/live-commerce). Paths are relative so they resolve against
 * the shared Retrofit base URL; session cookies + Authorization: Bearer + X-CSRF-Token are attached by
 * the core-network interceptor chain.
 *
 * Backend contract:
 *  - POST   ui/live-commerce/sessions/{sid}/products                 -> PinnedProductDto (body PinProductDto)
 *  - DELETE ui/live-commerce/sessions/{sid}/products/{pid}           -> LiveCommerceOkDto
 *  - GET    ui/live-commerce/sessions/{sid}/products                 -> StreamProductsDto
 *  - POST   ui/live-commerce/listings/{cat}/{item}/affiliate-commission -> AffiliateCommissionDto (body)
 *  - GET    ui/live-commerce/listings/{cat}/{item}/affiliate-commission -> AffiliateCommissionDto
 */

/** POST pin body: the catalog product to pin to the live session. */
@JsonClass(generateAdapter = true)
data class PinProductDto(
    @Json(name = "product_id") val productId: String,
    @Json(name = "category_id") val categoryId: String,
)

/**
 * One pinned "shop this stream" product (backend _pinned_out). is_affiliate is DERIVED server-side from
 * ownership (catalog creator_id != the session host); affiliate_commission_bps is the seller-set % the
 * host earns. pinned_by is the host (= broadcast session created_by).
 */
@JsonClass(generateAdapter = true)
data class PinnedProductDto(
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "product_id") val productId: String = "",
    @Json(name = "category_id") val categoryId: String = "",
    @Json(name = "seller_id") val sellerId: String = "",
    @Json(name = "is_affiliate") val isAffiliate: Boolean = false,
    @Json(name = "affiliate_commission_bps") val affiliateCommissionBps: Int = 0,
    @Json(name = "name") val name: String = "",
    @Json(name = "price_cents") val priceCents: Long = 0L,
    @Json(name = "currency") val currency: String = "USD",
    @Json(name = "image_url") val imageUrl: String? = null,
    @Json(name = "pinned_by") val pinnedBy: String = "",
    @Json(name = "pinned_at") val pinnedAt: Long = 0L,
)

/** GET shop-this-stream response: the session id + its pinned products. */
@JsonClass(generateAdapter = true)
data class StreamProductsDto(
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "products") val products: List<PinnedProductDto> = emptyList(),
)

/**
 * The seller-set per-listing affiliate commission (bps). Serves BOTH the POST set body and the GET/POST
 * response (the response also carries category_id/item_id/seller_id, tolerated but unused by the body).
 */
@JsonClass(generateAdapter = true)
data class AffiliateCommissionDto(
    @Json(name = "affiliate_commission_bps") val affiliateCommissionBps: Int,
    @Json(name = "category_id") val categoryId: String? = null,
    @Json(name = "item_id") val itemId: String? = null,
    @Json(name = "seller_id") val sellerId: String? = null,
)

/** The `{ "ok": true, ... }` envelope returned by unpin. */
@JsonClass(generateAdapter = true)
data class LiveCommerceOkDto(
    @Json(name = "ok") val ok: Boolean = true,
)
