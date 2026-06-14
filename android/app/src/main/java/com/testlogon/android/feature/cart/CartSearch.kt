package com.testlogon.android.feature.cart

import com.testlogon.android.data.cart.CartItem
import java.text.Normalizer

/**
 * AND-212 — pure, JVM-testable in-cart item/SKU search. Client-only filtering over the already-loaded
 * cart snapshot (no new network call). Matching is case-insensitive and diacritic-folded (NFD + strip
 * combining marks) substring over `sku` and `name` (the only matchable fields on the cart item).
 */
object CartSearch {

    private val combiningMarks = Regex("\\p{Mn}+")

    fun normalize(s: String): String =
        Normalizer.normalize(s, Normalizer.Form.NFD)
            .replace(combiningMarks, "")
            .lowercase()
            .trim()

    fun filter(items: List<CartItem>, rawQuery: String): FilteredCart {
        val q = normalize(rawQuery)
        if (q.isEmpty()) {
            return FilteredCart(
                items = items,
                matchedCount = items.size,
                totalCount = items.size,
                matchedSubtotalCents = items.sumOf { it.lineTotalCents },
            )
        }
        val matches = items.filter { item ->
            normalize(item.sku).contains(q) || normalize(item.name).contains(q)
        }
        return FilteredCart(
            items = matches,
            matchedCount = matches.size,
            totalCount = items.size,
            matchedSubtotalCents = matches.sumOf { it.lineTotalCents },
        )
    }
}

/** AND-212 — the derived, filtered view over the cart. Ephemeral; never cached or sent to the server. */
data class FilteredCart(
    val items: List<CartItem> = emptyList(),
    val matchedCount: Int = 0,
    val totalCount: Int = 0,
    val matchedSubtotalCents: Long = 0L,
) {
    /** True when a query is narrowing the list (fewer matches than the full cart). */
    val isFiltering: Boolean get() = matchedCount != totalCount

    companion object {
        val EMPTY = FilteredCart()
    }
}
