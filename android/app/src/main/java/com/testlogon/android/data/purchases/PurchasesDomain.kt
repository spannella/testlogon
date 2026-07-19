package com.testlogon.android.data.purchases

import java.math.BigDecimal

/**
 * AND-218 / AND-221 — immutable, render-ready domain models for the purchase-history surface. DTO ->
 * domain mapping lives here so the repository / paging source never leak raw DTOs.
 *
 * Money is carried as a lossless [BigDecimal] major-unit amount + ISO-4217 currency (the wire `amount`
 * is a JSON number in major units — NOT cents; cart line items are the cents-typed surface and live in
 * data/cart). Timestamps are Long epoch SECONDS, passed through unchanged (formatted by a pure helper in
 * the presentation layer — no java.time on the unit-tested path). `status` is mapped to a typed
 * [OrderStatus] with an [OrderStatus.Unknown] fallback so unknown wire values never throw.
 */

/** A purchase amount: a lossless major-unit decimal + its ISO-4217 currency code. */
data class Money(
    val amount: BigDecimal,
    val currency: String,
)

/**
 * Typed transaction status. Wire values are observed lowercase in the history list
 * (pending/completed/cancelled/reverted) and UPPERCASE in the detail/action surface
 * (PENDING/COMPLETED/CANCELLED/REVERTED/CANCEL_REQUESTED/CANCEL_DENIED); the mapper is case-insensitive.
 * Unknown values fall back to [Unknown] (never throws).
 */
sealed interface OrderStatus {
    data object Pending : OrderStatus
    data object Completed : OrderStatus
    data object Cancelled : OrderStatus
    data object Reverted : OrderStatus
    data object CancelRequested : OrderStatus
    data object CancelDenied : OrderStatus
    data class Unknown(val raw: String) : OrderStatus
}

/** History list / search row (maps PurchaseTransactionSummary). */
data class PurchaseListItem(
    val id: String,
    val status: OrderStatus,
    val money: Money,
    val createdAtEpochSec: Long,
    val updatedAtEpochSec: Long,
    val merchantId: String? = null,
    val externalRef: String? = null,
    val description: String? = null,
) {
    /** Header/title label: description, else "Order " + the first 8 chars of the id (web parity). */
    val title: String
        get() = description?.takeIf { it.isNotBlank() } ?: "Order ${id.take(8)}"
}

/** A single shipment (maps PurchaseShipping). Timestamps are Long epoch SECONDS. */
data class PurchaseShipping(
    val carrier: String? = null,
    val trackingNumber: String? = null,
    val trackingUrl: String? = null,
    val status: String? = null,
    val statusDescription: String? = null,
    val shippedAtEpochSec: Long? = null,
    val deliveredAtEpochSec: Long? = null,
    val estimatedDelivery: String? = null,
) {
    /** True when there is a carrier or tracking number to surface (drives the tracking section). */
    val hasShipment: Boolean
        get() = !carrier.isNullOrBlank() || !trackingNumber.isNullOrBlank()
}

/** Full transaction detail (maps PurchaseTransactionInfo, a superset of the summary). */
data class PurchaseDetail(
    val id: String,
    val status: OrderStatus,
    val money: Money,
    val createdAtEpochSec: Long,
    val updatedAtEpochSec: Long,
    val buyerId: String,
    val version: Int,
    val merchantId: String? = null,
    val externalRef: String? = null,
    val description: String? = null,
    val completedAtEpochSec: Long? = null,
    val revertedAtEpochSec: Long? = null,
    val shipping: PurchaseShipping? = null,
    /** From metadata.cart_id; drives the separate cart-items fetch (AND-220). Null when absent. */
    val cartId: String? = null,
    // ECOMX-42 (B2): the physical fulfilment state from the order header. `status` above is the
    // money state; these drive the buyer-facing "Processing/Shipped/Delivered" + confirm gate.
    val orderStatus: String? = null,
    val fulfillmentStatus: String? = null,
) {
    val title: String
        get() = description?.takeIf { it.isNotBlank() } ?: "Order ${id.take(8)}"

    /** ECOMX-42 (B6): the buyer may confirm delivery once shipped/out-for-delivery/delivered and
     *  the order is not yet money-completed. */
    val canConfirmDelivery: Boolean
        get() = status != OrderStatus.Completed &&
            (fulfillmentStatus in setOf("shipped", "out_for_delivery", "delivered", "partially_shipped") ||
                orderStatus in setOf("shipped", "completed"))

    /**
     * ECOMX selldash-E3 — true when this order has a real shipment to track. The txn-detail `shipping`
     * sub-object is the LEGACY SHP shape and is never populated by the seller-ship (ship-group) flow, so
     * [PurchaseShipping.hasShipment] alone is always false for real orders. The authoritative signal is
     * the order-lifecycle header state ([fulfillmentStatus]/[orderStatus]), which E1 surfaces. When this
     * is true the detail VM GETs `.../tracking` (the E1/ECOMX-E3 endpoint that aggregates the buyer's own
     * ship-group tracking) so the buyer sees the real carrier/number/status the seller entered — WITHOUT
     * needing the ship_group_id. Money-only txns (no fulfilment) stay NotShipped and skip the call.
     */
    val hasShipmentEvidence: Boolean
        get() = shipping?.hasShipment == true ||
            fulfillmentStatus in setOf(
                "shipped", "partially_shipped", "out_for_delivery", "delivered",
            ) ||
            orderStatus in setOf("shipped", "delivered", "completed")
}

// ---- Mappers (DTO -> domain) ----

/** Case-insensitive status mapping; unrecognized values fall back to [OrderStatus.Unknown] (no throw). */
internal fun String.toOrderStatus(): OrderStatus = when (uppercase().trim()) {
    "PENDING" -> OrderStatus.Pending
    "COMPLETED" -> OrderStatus.Completed
    "CANCELLED", "CANCELED" -> OrderStatus.Cancelled
    "REVERTED" -> OrderStatus.Reverted
    "CANCEL_REQUESTED" -> OrderStatus.CancelRequested
    "CANCEL_DENIED" -> OrderStatus.CancelDenied
    else -> OrderStatus.Unknown(this)
}

internal fun PurchaseTransactionSummaryDto.toDomain(): PurchaseListItem = PurchaseListItem(
    id = txnId,
    status = status.toOrderStatus(),
    money = Money(amount = amount, currency = currency),
    createdAtEpochSec = createdAt,
    updatedAtEpochSec = updatedAt,
    merchantId = merchantId?.takeIf { it.isNotBlank() },
    externalRef = externalRef?.takeIf { it.isNotBlank() },
    description = description?.takeIf { it.isNotBlank() },
)

internal fun PurchaseShippingDto.toDomain(): PurchaseShipping = PurchaseShipping(
    carrier = carrier?.takeIf { it.isNotBlank() },
    trackingNumber = trackingNumber?.takeIf { it.isNotBlank() },
    trackingUrl = trackingUrl?.takeIf { it.isNotBlank() },
    status = status?.takeIf { it.isNotBlank() },
    statusDescription = statusDescription?.takeIf { it.isNotBlank() },
    shippedAtEpochSec = shippedAt,
    deliveredAtEpochSec = deliveredAt,
    estimatedDelivery = estimatedDelivery?.takeIf { it.isNotBlank() },
)

internal fun PurchaseTransactionInfoDto.toDomain(): PurchaseDetail = PurchaseDetail(
    id = txnId,
    status = status.toOrderStatus(),
    money = Money(amount = amount, currency = currency),
    createdAtEpochSec = createdAt,
    updatedAtEpochSec = updatedAt,
    buyerId = buyerId,
    version = version,
    merchantId = merchantId?.takeIf { it.isNotBlank() },
    externalRef = externalRef?.takeIf { it.isNotBlank() },
    description = description?.takeIf { it.isNotBlank() },
    completedAtEpochSec = completedAt,
    revertedAtEpochSec = revertedAt,
    shipping = shipping?.toDomain()?.takeIf { it.hasShipment },
    cartId = (metadata?.get("cart_id") as? String)?.takeIf { it.isNotBlank() },
    orderStatus = orderStatus?.takeIf { it.isNotBlank() },
    fulfillmentStatus = fulfillmentStatus?.takeIf { it.isNotBlank() },
)
