package com.testlogon.android.data.sellerstore

/**
 * ECOM (catalog depth) — pure, side-effect-free helpers for the advanced seller product editor
 * (variants / price components / bundle components / product features). Kept UI- and network-free so
 * they can be exhaustively unit-tested on the JVM. Mirrors the backend contract in
 * app/services/product_price_components.py + product_variants.py and the web helpers in
 * frontend/src/api/endpoints/productDepth.ts (formatCents / formatDeltaCents).
 *
 * All money is integer minor units (cents). No floating-point arithmetic on money.
 */
object CatalogSellerMath {

    /** The valid PriceType values (mirrors PriceTypeEnum in app/models.py). */
    val PRICE_TYPES: List<String> = listOf(
        "LIST", "DEFAULT", "PROMO", "COMPETITIVE", "MINIMUM", "AVERAGE_COST",
    )

    /** The valid product types (mirrors the web ProductType union). */
    val PRODUCT_TYPES: List<String> = listOf(
        "standalone", "virtual", "variant", "bundle", "kit", "digital",
    )

    /** True when [productType] is one that may carry bundle components (bundle or kit). */
    fun isBundleType(productType: String?): Boolean =
        productType == "bundle" || productType == "kit"

    /** True when [priceType] is one of the recognised price types (case-sensitive, as the server is). */
    fun isValidPriceType(priceType: String?): Boolean =
        priceType != null && priceType in PRICE_TYPES

    /**
     * Sum of a variant's feature price deltas over the item's base price.
     *
     * @param basePriceCents the parent item's scalar price (>= 0).
     * @param deltas the price_delta_cents of each selected feature value (may be negative for discounts).
     * @return the effective variant price, floored at 0 (a product is never sold for negative money).
     */
    fun variantEffectivePriceCents(basePriceCents: Long, deltas: List<Long>): Long {
        val sum = basePriceCents + deltas.sum()
        return if (sum < 0L) 0L else sum
    }

    /**
     * Total cents contributed by a bundle's components: sum of (unit price * quantity) across lines.
     * Lines with an unknown (null) component price are treated as 0 (the server may not have resolved
     * a price yet). Quantities <= 0 are ignored (the server enforces quantity >= 1 on write).
     */
    fun bundleTotalCents(lines: List<BundleLineMath>): Long =
        lines.sumOf { line ->
            val qty = line.quantity.coerceAtLeast(0)
            val unit = line.unitPriceCents ?: 0L
            unit * qty
        }

    /**
     * A price component is "active" as of [asOf] (epoch seconds) when it has taken effect
     * (effective_at <= asOf) and has not yet expired (expires_at is null OR expires_at >= asOf).
     */
    fun isPriceComponentActive(effectiveAt: Long, expiresAt: Long?, asOf: Long): Boolean =
        effectiveAt <= asOf && (expiresAt == null || expiresAt >= asOf)

    /**
     * Resolve the active price-component amount for a set of components of one price type, newest
     * effective-date first (mirrors resolve_effective_price's GSI walk). Returns null when none are
     * active — the caller then falls back to the scalar price (for DEFAULT) or 0.
     */
    fun resolveActiveAmountCents(components: List<PriceComponentMath>, asOf: Long): Long? =
        components
            .sortedByDescending { it.effectiveAt }
            .firstOrNull { isPriceComponentActive(it.effectiveAt, it.expiresAt, asOf) }
            ?.amountCents

    /**
     * Client-side validation for a new price component before POST. Returns null when valid, otherwise
     * a short human-readable reason. Mirrors the server field constraints (amount >= 0, effective_at
     * >= 0, expires_at (if set) must be after effective_at) + a valid price type.
     */
    fun validatePriceComponent(
        priceType: String?,
        amountCents: Long,
        effectiveAt: Long,
        expiresAt: Long?,
    ): String? = when {
        !isValidPriceType(priceType) -> "Choose a price type"
        amountCents < 0L -> "Amount can't be negative"
        effectiveAt < 0L -> "Invalid effective time"
        expiresAt != null && expiresAt < effectiveAt -> "Expiry must be after the effective time"
        else -> null
    }

    /**
     * Client-side validation for creating a variant. Returns null when valid, otherwise a reason.
     * A variant must map at least one feature category to a value, and every mapped value must be
     * non-blank (mirrors the server's non-empty feature_values dict requirement).
     */
    fun validateVariant(featureValues: Map<String, String>): String? = when {
        featureValues.isEmpty() -> "Pick at least one option"
        featureValues.any { it.key.isBlank() || it.value.isBlank() } -> "Every option needs a value"
        else -> null
    }

    /**
     * Client-side validation for adding a bundle component. Returns null when valid, otherwise a reason.
     * Guards against self-reference and non-positive quantity (server enforces quantity 1..100000).
     */
    fun validateBundleComponent(
        parentItemId: String,
        componentItemId: String,
        quantity: Int,
    ): String? = when {
        componentItemId.isBlank() -> "Pick a component product"
        componentItemId == parentItemId -> "A bundle can't contain itself"
        quantity < 1 -> "Quantity must be at least 1"
        quantity > 100_000 -> "Quantity is too large"
        else -> null
    }

    /** Render integer cents as a plain "$#.##" string (locale-free; UI adds currency symbol). */
    fun formatCents(cents: Long, currency: String = "USD"): String {
        val negative = cents < 0L
        val abs = if (negative) -cents else cents
        val dollars = abs / 100
        val rem = (abs % 100).toInt()
        val body = "$dollars.${rem.toString().padStart(2, '0')}"
        val symbol = if (currency == "USD") "$" else "$currency "
        return if (negative) "-$symbol$body" else "$symbol$body"
    }

    /** Render a signed delta with an explicit +/- prefix (mirrors web formatDeltaCents). */
    fun formatDeltaCents(cents: Long, currency: String = "USD"): String {
        val sign = when {
            cents > 0L -> "+"
            cents < 0L -> "-"
            else -> ""
        }
        val abs = if (cents < 0L) -cents else cents
        return sign + formatCents(abs, currency)
    }
}

/** Minimal projection of a bundle component line for [CatalogSellerMath.bundleTotalCents]. */
data class BundleLineMath(
    val quantity: Int,
    val unitPriceCents: Long?,
)

/** Minimal projection of a price component for [CatalogSellerMath.resolveActiveAmountCents]. */
data class PriceComponentMath(
    val amountCents: Long,
    val effectiveAt: Long,
    val expiresAt: Long?,
)
