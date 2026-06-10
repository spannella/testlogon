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

/** One line item added to a cart (the add-to-cart success payload). */
data class CartItem(
    val sku: String,
    val name: String,
    val quantity: Int,
    val unitPriceCents: Long,
    val lineTotalCents: Long,
    val itemId: String? = null,
)

// ---- Mappers (DTO -> domain) ----

internal fun CartSummaryDto.toDomain(): Cart = Cart(cartId = cartId, status = status)

internal fun CartItemOutDto.toDomain(): CartItem = CartItem(
    sku = sku,
    name = name,
    quantity = quantity,
    unitPriceCents = unitPriceCents,
    lineTotalCents = lineTotalCents,
    itemId = itemId,
)
