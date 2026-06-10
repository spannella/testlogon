package com.testlogon.android.data.cart

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-206 — wire DTOs for the shopping-cart surface consumed by product detail add-to-cart.
 *
 * Verified against the backend OpenAPI (ShoppingCartSummary / ShoppingCartItemIn / ShoppingCartItemOut)
 * and reference/src/api/types.ts (CartSummary, CartItemIn, CartItem). Add-to-cart is a TWO-step flow:
 * list-or-create a cart (ui/shoppingcart/carts) then post a line item
 * (ui/shoppingcart/carts/{cart_id}/items). The catalog item exposes no sku, so the web client reuses
 * item_id as the sku (reference/src/pages/shop/ProductDetail.tsx -> addCartItem sku: item.item_id);
 * this port does the same.
 *
 * Money is flat minor units (unit_price_cents / line_total_cents). Moshi tolerates the extra response
 * keys (access_mode, product_type, scope, ...) we do not model.
 */

/** A cart envelope (schema ShoppingCartSummary). required: cart_id, status, created_at, currency. */
@JsonClass(generateAdapter = true)
data class CartSummaryDto(
    @Json(name = "cart_id") val cartId: String,
    @Json(name = "status") val status: String,
    @Json(name = "created_at") val createdAt: String,
    @Json(name = "currency") val currency: String? = null,
)

/**
 * Add-to-cart request body (schema ShoppingCartItemIn). required: sku, name, unit_price_cents.
 * quantity defaults to 1 (server bounds 1..1000). sku/category_id/item_id/image_url carried per the
 * web client.
 */
@JsonClass(generateAdapter = true)
data class CartItemInDto(
    @Json(name = "sku") val sku: String,
    @Json(name = "name") val name: String,
    @Json(name = "unit_price_cents") val unitPriceCents: Long,
    @Json(name = "quantity") val quantity: Int = 1,
    @Json(name = "item_id") val itemId: String? = null,
    @Json(name = "category_id") val categoryId: String? = null,
    @Json(name = "image_url") val imageUrl: String? = null,
)

/**
 * The created/updated line item (schema ShoppingCartItemOut) — a SINGLE line item, NOT a cart summary
 * (no item_count, no subtotal). required: sku, name, quantity, unit_price_cents, line_total_cents,
 * updated_at.
 */
@JsonClass(generateAdapter = true)
data class CartItemOutDto(
    @Json(name = "sku") val sku: String,
    @Json(name = "name") val name: String,
    @Json(name = "quantity") val quantity: Int,
    @Json(name = "unit_price_cents") val unitPriceCents: Long,
    @Json(name = "line_total_cents") val lineTotalCents: Long,
    @Json(name = "updated_at") val updatedAt: String,
    @Json(name = "item_id") val itemId: String? = null,
    @Json(name = "category_id") val categoryId: String? = null,
    @Json(name = "image_url") val imageUrl: String? = null,
)

/**
 * AND-210 — the list-items response (schema ShoppingCartItemsOut). required: cart_id, items.
 * Items are nullable here only because the dev backend may return a partial payload; the mapper
 * substitutes an empty list rather than throwing.
 */
@JsonClass(generateAdapter = true)
data class CartItemsRespDto(
    @Json(name = "cart_id") val cartId: String,
    @Json(name = "items") val items: List<CartItemOutDto>? = null,
)

/**
 * AND-210 — the server-computed grand total (schema ShoppingCartTotalOut). There is no
 * subtotal/tax/shipping breakdown anywhere in the API — only this single total_cents + currency.
 */
@JsonClass(generateAdapter = true)
data class CartTotalDto(
    @Json(name = "cart_id") val cartId: String,
    @Json(name = "total_cents") val totalCents: Long? = null,
    @Json(name = "currency") val currency: String? = null,
)

/**
 * AND-210 — quantity-update request body (schema ShoppingCartUpdateQtyIn). Server bounds the value
 * to 0..1000 (0 is schema-valid; a dedicated DELETE is used for explicit removal).
 */
@JsonClass(generateAdapter = true)
data class UpdateCartItemQtyRequest(
    @Json(name = "quantity") val quantity: Int,
)

/** AND-210 — the `{ "ok": true }` envelope returned by remove-item and delete-cart (schema OkResp). */
@JsonClass(generateAdapter = true)
data class OkRespDto(
    @Json(name = "ok") val ok: Boolean? = null,
)
