package com.testlogon.android.data.cart

/**
 * AND-206 — immutable domain models for the shopping cart. DTO -> domain mapping lives here so the
 * repository never leaks raw DTOs. Money stays integer minor units (cents) for the presentation layer
 * to format.
 */

/** A cart handle resolved/created before adding a line item. */
data class Cart(
    val cartId: String,
    val status: String,
)

/**
 * One cart line item. The AND-206 add-to-cart success payload AND the AND-211 cart-screen row use the
 * same type; imageUrl/categoryId are optional (absent on the add response, present on list-items).
 */
data class CartItem(
    val sku: String,
    val name: String,
    val quantity: Int,
    val unitPriceCents: Long,
    val lineTotalCents: Long,
    val itemId: String? = null,
    val imageUrl: String? = null,
    val categoryId: String? = null,
)

/**
 * AND-210 — the server-computed grand total. The backend exposes a single total_cents + currency
 * (no subtotal/tax/shipping). Money stays integer minor units for the presentation layer to format.
 */
data class CartTotal(
    val cartId: String,
    val totalCents: Long,
    val currency: String,
)

/**
 * AND-210 — an Android-side cart aggregate. The backend has no combined cart object, so this is
 * composed from a cart id + its line items + the server total. itemCount/subtotalCents are derived
 * client-side; totalCents is authoritative (from the /total endpoint).
 */
data class FullCart(
    val cartId: String,
    val items: List<CartItem>,
    val totalCents: Long,
    val currency: String,
) {
    val isEmpty: Boolean get() = items.isEmpty()
    val itemCount: Int get() = items.sumOf { it.quantity }
    val subtotalCents: Long get() = items.sumOf { it.lineTotalCents }

    companion object {
        fun empty(cartId: String, currency: String = "USD"): FullCart =
            FullCart(cartId = cartId, items = emptyList(), totalCents = 0L, currency = currency)
    }
}

// ---- Mappers (DTO -> domain) ----

internal fun CartSummaryDto.toDomain(): Cart = Cart(cartId = cartId, status = status)

internal fun CartItemOutDto.toDomain(): CartItem = CartItem(
    sku = sku,
    name = name,
    quantity = quantity,
    unitPriceCents = unitPriceCents,
    lineTotalCents = lineTotalCents,
    itemId = itemId,
    imageUrl = imageUrl?.takeIf { it.isNotBlank() },
    categoryId = categoryId?.takeIf { it.isNotBlank() },
)

internal fun CartTotalDto.toDomain(): CartTotal = CartTotal(
    cartId = cartId,
    totalCents = totalCents ?: 0L,
    currency = currency ?: "USD",
)

/**
 * Composes the list-items response + the server total into a [FullCart]. If the total fetch failed
 * (null), the client falls back to the derived subtotal so the screen still shows a sensible figure.
 */
internal fun CartItemsRespDto.toDomain(total: CartTotal?): FullCart {
    val mappedItems = items.orEmpty().map { it.toDomain() }
    val derivedSubtotal = mappedItems.sumOf { it.lineTotalCents }
    return FullCart(
        cartId = cartId,
        items = mappedItems,
        totalCents = total?.totalCents ?: derivedSubtotal,
        currency = total?.currency ?: "USD",
    )
}

/**
 * FIX (ecom residual #1) — the result of a completed cart purchase. [purchaseTxnId] is the
 * purchase-history transaction id used to route to the order-confirmation / tracking screen.
 */
data class CartPurchaseResult(
    val cartId: String,
    val orderId: String,
    val purchaseTxnId: String?,
    val purchasedTotalCents: Long,
    val currency: String,
    val discountCents: Long,
    // ECOMX-40 (B3): shipping/tax breakdown; null when the order collected neither (digital/self).
    val merchandiseCents: Long? = null,
    val shippingCents: Long? = null,
    val taxCents: Long? = null,
)

internal fun CartPurchaseOutDto.toDomain(): CartPurchaseResult = CartPurchaseResult(
    cartId = cartId,
    orderId = orderId,
    purchaseTxnId = purchaseTxnId,
    purchasedTotalCents = purchasedTotalCents,
    currency = currency ?: "USD",
    discountCents = discountCents ?: 0L,
    merchandiseCents = merchandiseCents,
    shippingCents = shippingCents,
    taxCents = taxCents,
)
