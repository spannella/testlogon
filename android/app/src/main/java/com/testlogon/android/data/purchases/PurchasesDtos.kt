package com.testlogon.android.data.purchases

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import java.math.BigDecimal

/**
 * AND-218 — wire DTOs for the purchase-history (transactions) surface.
 *
 * Verified contract (reference/openapi.index.txt lines 1761/1763/1764;
 * reference/src/api/endpoints/purchases.ts listTransactions/searchTransactions/getTransaction;
 * reference/src/api/types.ts PurchaseTransactionSummary / PurchaseTransactionInfo / PurchaseShipping):
 *  - GET ui/purchase-history/transactions            -> PurchaseTransactionSummary list (BARE array)
 *  - GET ui/purchase-history/transactions/search      -> PurchaseTransactionSummary list (BARE array)
 *  - GET ui/purchase-history/transactions/{txn_id}    -> PurchaseTransactionInfo
 *
 * Contract notes (corrections vs early drafts, all verified against the reference):
 *  - List and search return a BARE JSON array of summaries (no items/page/total/next_cursor envelope);
 *    the only request controls are limit (+ status on list, q on search). No server pagination.
 *  - Money is flat: amount (JSON number) + currency (ISO-4217). NOT minor units / no nested money / no
 *    subtotal-tax-shipping breakdown. amount is modeled as BigDecimal (Moshi maps JSON numbers
 *    losslessly) — never Double (float drift).
 *  - Timestamps are integer epoch SECONDS (created_at/updated_at, detail completed_at/reverted_at/
 *    receipt_generated_at, shipping shipped_at/delivered_at/last_carrier_check). estimated_delivery is
 *    a String. There is no purchased_at.
 *  - status is a raw String (mapping to a typed status is a domain concern; unknown values never throw).
 *  - There is NO line-item array on the transaction; items come from a separate cart fetch via
 *    metadata.cart_id (AND-220 reuses the existing CartRepository, no new endpoint).
 *
 * Session cookies + Authorization: Bearer + X-CSRF-Token are attached by core-network. Unknown keys are
 * tolerated (Moshi codegen default) so additive backend evolution never throws.
 */

/**
 * Carrier/shipping/tracking sub-object (schema PurchaseShippingIn; frontend PurchaseShipping). All
 * fields optional. carrier_events / cancel / metadata / address are free-form objects kept as raw maps.
 */
@JsonClass(generateAdapter = true)
data class PurchaseShippingDto(
    @Json(name = "carrier") val carrier: String? = null,
    @Json(name = "tracking_number") val trackingNumber: String? = null,
    @Json(name = "tracking_url") val trackingUrl: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "status_description") val statusDescription: String? = null,
    // epoch SECONDS.
    @Json(name = "shipped_at") val shippedAt: Long? = null,
    // epoch SECONDS.
    @Json(name = "delivered_at") val deliveredAt: Long? = null,
    // String (NOT epoch).
    @Json(name = "estimated_delivery") val estimatedDelivery: String? = null,
    @Json(name = "carrier_events") val carrierEvents: List<Map<String, Any?>> = emptyList(),
    // epoch SECONDS.
    @Json(name = "last_carrier_check") val lastCarrierCheck: Long? = null,
    @Json(name = "address") val address: Map<String, Any?>? = null,
)

/**
 * List/search row (schema PurchaseTransactionSummary).
 * required: txn_id, created_at, updated_at, status, amount, currency.
 */
@JsonClass(generateAdapter = true)
data class PurchaseTransactionSummaryDto(
    @Json(name = "txn_id") val txnId: String,
    // epoch SECONDS.
    @Json(name = "created_at") val createdAt: Long,
    // epoch SECONDS.
    @Json(name = "updated_at") val updatedAt: Long,
    @Json(name = "status") val status: String,
    // JSON number, lossless via BigDecimal (never Double).
    @Json(name = "amount") val amount: BigDecimal,
    @Json(name = "currency") val currency: String,
    @Json(name = "merchant_id") val merchantId: String? = null,
    @Json(name = "external_ref") val externalRef: String? = null,
    @Json(name = "description") val description: String? = null,
)

/**
 * Full transaction detail (schema PurchaseTransactionInfo; a superset of the summary).
 * required adds: buyer_id, version.
 */
@JsonClass(generateAdapter = true)
data class PurchaseTransactionInfoDto(
    @Json(name = "txn_id") val txnId: String,
    @Json(name = "created_at") val createdAt: Long,
    @Json(name = "updated_at") val updatedAt: Long,
    @Json(name = "status") val status: String,
    @Json(name = "amount") val amount: BigDecimal,
    @Json(name = "currency") val currency: String,
    @Json(name = "buyer_id") val buyerId: String,
    @Json(name = "version") val version: Int,
    @Json(name = "merchant_id") val merchantId: String? = null,
    @Json(name = "external_ref") val externalRef: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "shipping") val shipping: PurchaseShippingDto? = null,
    @Json(name = "cancel") val cancel: Map<String, Any?>? = null,
    // epoch SECONDS.
    @Json(name = "completed_at") val completedAt: Long? = null,
    // epoch SECONDS.
    @Json(name = "reverted_at") val revertedAt: Long? = null,
    @Json(name = "metadata") val metadata: Map<String, Any?>? = null,
    @Json(name = "receipt_path") val receiptPath: String? = null,
    // epoch SECONDS.
    @Json(name = "receipt_generated_at") val receiptGeneratedAt: Long? = null,
    // ECOMX-42 (B2): the physical fulfilment state from the order-lifecycle header
    // (distinct from `status` = money PENDING/COMPLETED). Drives the realistic
    // "Processing / Shipped / Delivered" order status + the confirm-delivery gate.
    @Json(name = "order_status") val orderStatus: String? = null,
    @Json(name = "fulfillment_status") val fulfillmentStatus: String? = null,
)
