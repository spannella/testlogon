package com.testlogon.android.data.sellerstore

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * ECOM (seller store) — wire DTOs for the order-lifecycle surface (`/ui/orders`). Orders-received are
 * listed by status; the detail exposes the line items + the server-authoritative `allowed_transitions`
 * (the set of fulfilment moves), which the UI renders as fulfil / mark-shipped / cancel actions.
 *
 * Verified against the prod OpenAPI (OrderListOut / OrderListItem / OrderLifecycleOut /
 * OrderLineItemOut / OrderStatusHistoryEntry / OrderTransitionRequest / OrderCancelIn). Nullable arrays
 * are declared nullable so a `null` from the server maps to empty.
 */

@JsonClass(generateAdapter = true)
data class OrderListItemDto(
    @Json(name = "order_id") val orderId: String,
    @Json(name = "user_id") val userId: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "lifecycle_status") val lifecycleStatus: String? = null,
    @Json(name = "created_at") val createdAt: String? = null,
    @Json(name = "updated_at") val updatedAt: String? = null,
    @Json(name = "amount_cents") val amountCents: Long = 0,
    @Json(name = "currency") val currency: String = "USD",
    @Json(name = "line_item_count") val lineItemCount: Int = 0,
    @Json(name = "correlation_id") val correlationId: String? = null,
    @Json(name = "source_system") val sourceSystem: String? = null,
)

@JsonClass(generateAdapter = true)
data class OrderListOutDto(
    @Json(name = "orders") val orders: List<OrderListItemDto>? = null,
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class OrderLineItemDto(
    @Json(name = "item_id") val itemId: String,
    @Json(name = "sku") val sku: String? = null,
    @Json(name = "name") val name: String? = null,
    @Json(name = "quantity") val quantity: Int = 1,
    @Json(name = "unit_price_cents") val unitPriceCents: Long = 0,
    @Json(name = "currency") val currency: String = "USD",
)

@JsonClass(generateAdapter = true)
data class OrderStatusHistoryDto(
    @Json(name = "event_id") val eventId: String? = null,
    @Json(name = "from_status") val fromStatus: String? = null,
    @Json(name = "to_status") val toStatus: String? = null,
    @Json(name = "actor") val actor: String? = null,
    @Json(name = "reason") val reason: String? = null,
    @Json(name = "ts") val ts: Long = 0,
)

@JsonClass(generateAdapter = true)
data class OrderLifecycleDto(
    @Json(name = "order_id") val orderId: String,
    @Json(name = "status") val status: String? = null,
    @Json(name = "lifecycle_status") val lifecycleStatus: String? = null,
    @Json(name = "amount_cents") val amountCents: Long = 0,
    @Json(name = "currency") val currency: String = "USD",
    @Json(name = "created_at") val createdAt: String? = null,
    @Json(name = "updated_at") val updatedAt: String? = null,
    @Json(name = "line_item_count") val lineItemCount: Int = 0,
    @Json(name = "allowed_transitions") val allowedTransitions: List<String>? = null,
    @Json(name = "line_items") val lineItems: List<OrderLineItemDto>? = null,
    @Json(name = "status_history") val statusHistory: List<OrderStatusHistoryDto>? = null,
)

@JsonClass(generateAdapter = true)
data class OrderTransitionRequestDto(
    @Json(name = "target_status") val targetStatus: String,
    @Json(name = "reason") val reason: String? = null,
    @Json(name = "idempotency_key") val idempotencyKey: String? = null,
)

/** Transition response — the `order` payload is ignored; the client re-fetches the lifecycle. */
@JsonClass(generateAdapter = true)
data class OrderTransitionResultDto(
    @Json(name = "to_status") val toStatus: String? = null,
    @Json(name = "event_id") val eventId: String? = null,
    @Json(name = "from_status") val fromStatus: String? = null,
)

@JsonClass(generateAdapter = true)
data class OrderCancelDto(
    @Json(name = "reason") val reason: String? = null,
    @Json(name = "refund") val refund: Boolean = false,
)
