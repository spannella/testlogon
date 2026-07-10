package com.testlogon.android.data.sellerstore

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * ECOM-SELLER (G1-G4) — wire DTOs for the SELLER-SCOPED sales surface (`/ui/seller/sales`).
 *
 * A non-admin authenticated seller lists / fetches ONLY their own per-seller ship groups and advances
 * the order-lifecycle state machine scoped to their own group. Each `SellerSaleOut` carries that
 * seller's REAL line-item names (G4) + the BUYER shipping address (G2) — never other sellers' items nor
 * the buyer's payment internals (G3). Verified against the prod `SellerSaleOut` / `SellerSaleListOut` /
 * `SellerSaleLineItem` / `SellerSaleTransitionIn` contract. Unknown `ship_to` keys are ignored by Moshi.
 */

@JsonClass(generateAdapter = true)
data class SellerSaleShipToDto(
    @Json(name = "name") val name: String? = null,
    @Json(name = "label") val label: String? = null,
    @Json(name = "line1") val line1: String? = null,
    @Json(name = "line2") val line2: String? = null,
    @Json(name = "city") val city: String? = null,
    @Json(name = "state") val state: String? = null,
    @Json(name = "postal_code") val postalCode: String? = null,
    @Json(name = "country") val country: String? = null,
)

@JsonClass(generateAdapter = true)
data class SellerSaleLineItemDto(
    @Json(name = "item_id") val itemId: String = "",
    @Json(name = "sku") val sku: String? = null,
    @Json(name = "name") val name: String? = null,
    @Json(name = "quantity") val quantity: Int = 1,
    @Json(name = "unit_price_cents") val unitPriceCents: Long = 0,
    @Json(name = "line_total_cents") val lineTotalCents: Long = 0,
)

@JsonClass(generateAdapter = true)
data class SellerSaleDto(
    @Json(name = "ship_group_id") val shipGroupId: String,
    @Json(name = "order_id") val orderId: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "allowed_transitions") val allowedTransitions: List<String>? = null,
    @Json(name = "buyer_name") val buyerName: String? = null,
    @Json(name = "buyer_email") val buyerEmail: String? = null,
    @Json(name = "ship_to") val shipTo: SellerSaleShipToDto? = null,
    @Json(name = "line_items") val lineItems: List<SellerSaleLineItemDto>? = null,
    @Json(name = "item_count") val itemCount: Int = 0,
    @Json(name = "subtotal_cents") val subtotalCents: Long = 0,
    @Json(name = "currency") val currency: String = "USD",
    @Json(name = "tracking_number") val trackingNumber: String? = null,
    @Json(name = "carrier") val carrier: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class SellerSaleListOutDto(
    @Json(name = "sales") val sales: List<SellerSaleDto>? = null,
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class SellerSaleTransitionRequestDto(
    @Json(name = "target_status") val targetStatus: String,
    @Json(name = "reason") val reason: String? = null,
    @Json(name = "tracking_number") val trackingNumber: String? = null,
    @Json(name = "carrier") val carrier: String? = null,
    @Json(name = "idempotency_key") val idempotencyKey: String? = null,
)
