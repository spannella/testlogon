package com.testlogon.android.data.checkout

/**
 * AND-213 — framework-free domain models for the checkout session. DTO -> domain mapping lives here so
 * the repository never leaks raw DTOs. Totals/currency are NOT on the response schema; they are seeded
 * from the cart (the cart screen already holds the authoritative total) and carried through for display.
 */

/** The status of a created checkout session. The wire value is a free string; unknown -> [UNKNOWN]. */
enum class CheckoutStatus {
    PENDING_PAYMENT,
    REQUIRES_PAYMENT,
    COMPLETED,
    EXPIRED,
    CANCELED,
    UNKNOWN,
    ;

    companion object {
        fun fromWire(value: String?): CheckoutStatus = when (value?.lowercase()) {
            "pending_payment" -> PENDING_PAYMENT
            "requires_payment" -> REQUIRES_PAYMENT
            "completed", "complete", "paid" -> COMPLETED
            "expired" -> EXPIRED
            "canceled", "cancelled" -> CANCELED
            else -> UNKNOWN
        }
    }
}

/** One server-confirmed line item, projected defensively from the free-form line_items[] objects. */
data class CheckoutLineItem(
    val sku: String,
    val name: String,
    val quantity: Int,
    val unitPriceCents: Long = 0,
    val lineTotalCents: Long = 0,
)

/**
 * A created checkout session. [id] is the hand-off value the billing step (AND-227) consumes.
 * Money fields are integer minor units seeded from the cart (the response carries no totals).
 */
data class CheckoutSession(
    val id: String,
    val orderId: String,
    val status: CheckoutStatus,
    val lineItems: List<CheckoutLineItem>,
    val totalCents: Long,
    val currency: String,
)

// ---- Mappers (DTO -> domain) ----

private fun Map<String, Any?>.toLineItem(): CheckoutLineItem {
    val sku = (this["sku"] as? String).orEmpty()
    val name = (this["name"] as? String) ?: sku
    val quantity = when (val q = this["quantity"]) {
        is Number -> q.toInt()
        is String -> q.toIntOrNull() ?: 1
        else -> 1
    }
    // The response carries no `name`, but it does carry amount_cents and pricing_ref.unit_price_cents.
    val lineTotal = (this["amount_cents"] as? Number)?.toLong() ?: 0L
    val unit = ((this["pricing_ref"] as? Map<*, *>)?.get("unit_price_cents") as? Number)?.toLong()
        ?: if (quantity > 0 && lineTotal > 0) lineTotal / quantity else lineTotal
    return CheckoutLineItem(
        sku = sku,
        name = name,
        quantity = quantity,
        unitPriceCents = unit,
        lineTotalCents = lineTotal,
    )
}

/**
 * Maps the response into a [CheckoutSession]. Totals come from [totalCents]/[currency] (the cart's
 * authoritative total) because the response schema has no monetary fields.
 */
internal fun UnifiedCheckoutSessionOutDto.toDomain(totalCents: Long, currency: String): CheckoutSession =
    CheckoutSession(
        id = checkoutSessionId,
        orderId = orderId,
        status = CheckoutStatus.fromWire(status),
        lineItems = lineItems.orEmpty().map { it.toLineItem() },
        totalCents = totalCents,
        currency = currency,
    )
