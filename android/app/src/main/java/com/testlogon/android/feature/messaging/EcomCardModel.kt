package com.testlogon.android.feature.messaging

import java.util.Locale

/**
 * EPIC F (FE-150 / FE-151) - pure, dependency-free model for the two e-commerce chat cards
 * (product_card + order_share). Kept Android-free so the payload build/encode/parse, price format,
 * previews, and the ORDER PII-stripping choke point can be JVM-unit-tested in isolation
 * (EcomCardModelTest).
 *
 * TRANSPORT (works-now, degrade-on-404, mirrors [CryptoTransferModel] / [TradingCardModel]): both
 * cards ride on a NORMAL text message. The structured payload is encoded into the message body behind a
 * rare sentinel tag distinct from every other card sentinel; MessageDto.toMedia parses the body back to
 * a card and renders it, falling through to a plain text bubble when the body is not a card (so an
 * un-upgraded client just shows text).
 *
 * Encoding: [SENTINEL] + wireKind + ";" + key=value pairs joined by ";". Reserved chars (";", "=",
 * "%", newline) are percent-escaped so any user-facing value round-trips through [parse].
 */
object EcomCardModel {

    /** Sentinel prefix marking an ecom card payload. Distinct from every other card sentinel. */
    const val SENTINEL: String = "TLSHOP1:"

    const val WIRE_PRODUCT: String = "product_card"
    const val WIRE_ORDER: String = "order_share"

    /**
     * FE-151 - how the caller frames a shared order. RECEIPT is the PII-SENSITIVE mode and the
     * [buildOrderPayload] choke point strips buyer name/address for it; GIFT/RECOMMENDATION are framing
     * only. Wire value round-trips; unknown -> RECOMMENDATION (the most conservative, non-receipt).
     */
    enum class OrderMode(val wire: String) {
        RECEIPT("receipt"),
        GIFT("gift"),
        RECOMMENDATION("recommendation"),
        ;

        companion object {
            fun fromWire(w: String?): OrderMode = entries.firstOrNull { it.wire == w } ?: RECOMMENDATION
        }
    }

    /**
     * FE-150 - a shared product. [priceCents] is integer minor units + [currency] (ISO-4217) so the
     * price formats with no float drift. [categoryId]/[itemId] address the product-detail screen the
     * Buy button opens. [imageUrl] is the optional thumbnail; [inStock] drives the stock badge.
     */
    data class ProductCard(
        val categoryId: String,
        val itemId: String,
        val title: String,
        val priceCents: Long,
        val currency: String,
        val imageUrl: String?,
        val inStock: Boolean,
    )

    /**
     * FE-151 - a shared order. In RECEIPT mode the [buyerName] MUST be null (the build choke point
     * guarantees it); there is no address field on the card at all (never carried in any mode).
     * [summary] is the item summary line; [status] is the order status label; [totalCents]/[currency]
     * are the (optional) money total shown only when present.
     */
    data class OrderCard(
        val orderId: String,
        val summary: String,
        val status: String,
        val mode: OrderMode,
        val totalCents: Long?,
        val currency: String?,
        /** Buyer display name; ALWAYS null in RECEIPT mode (PII-stripped). Never an address. */
        val buyerName: String?,
    )

    /** FE-150 - build a [ProductCard] payload from a picked catalog item. Pure. */
    fun buildProductPayload(
        categoryId: String,
        itemId: String,
        title: String,
        priceCents: Long,
        currency: String,
        imageUrl: String?,
        inStock: Boolean,
    ): ProductCard = ProductCard(
        categoryId = categoryId,
        itemId = itemId,
        title = title.trim().ifBlank { "Product" },
        priceCents = priceCents,
        currency = currency.trim().ifBlank { "USD" },
        imageUrl = imageUrl?.takeIf { it.isNotBlank() },
        inStock = inStock,
    )

    /**
     * FE-151 - build an [OrderCard] payload from one of the caller's orders, in [mode]. This is the
     * SINGLE PII choke point: in RECEIPT mode the buyer name is DROPPED (set to null) so a receipt
     * shared in chat never leaks the buyer's identity; an address is never carried in any mode.
     * GIFT / RECOMMENDATION keep the (non-sensitive) buyer display name for attribution.
     */
    fun buildOrderPayload(
        orderId: String,
        summary: String,
        status: String,
        mode: OrderMode,
        totalCents: Long?,
        currency: String?,
        buyerName: String?,
    ): OrderCard {
        val safeName = if (mode == OrderMode.RECEIPT) null else buyerName?.takeIf { it.isNotBlank() }
        return OrderCard(
            orderId = orderId,
            summary = summary.trim().ifBlank { "Order" },
            status = status.trim().ifBlank { "unknown" },
            mode = mode,
            totalCents = totalCents,
            currency = currency?.takeIf { it.isNotBlank() },
            buyerName = safeName,
        )
    }

    /** Format integer minor units + ISO currency, e.g. 129900,"USD" -> "$1,299.00". */
    fun formatPrice(cents: Long, currency: String): String {
        val symbol = when (currency.trim().uppercase()) {
            "USD", "CAD", "AUD" -> "$"
            "EUR" -> "€"
            "GBP" -> "£"
            else -> ""
        }
        val amount = String.format(Locale.US, "%,.2f", cents / 100.0)
        return if (symbol.isNotEmpty()) "$symbol$amount" else "$amount ${currency.trim().uppercase()}"
    }

    /** FE-150 - conversation / reply preview for a product card. */
    fun productPreview(card: ProductCard): String = "[Product: ${card.title}]"

    /** FE-151 - conversation / reply preview for an order card (never contains PII). */
    fun orderPreview(card: OrderCard): String = "[Order: ${card.summary}]"

    /**
     * Preview for a message body that MAY be an ecom card; null when it is not one (so the caller keeps
     * the server text preview). Used by the conversation list + reply preview.
     */
    fun previewForBody(body: String?): String? = when (val c = parse(body)) {
        is ProductCard -> productPreview(c)
        is OrderCard -> orderPreview(c)
        else -> null
    }

    /** True when [body] begins with the ecom-card sentinel (fast pre-check before a full parse). */
    fun isCard(body: String?): Boolean = body != null && body.startsWith(SENTINEL)

    fun encode(card: ProductCard): String {
        val sb = StringBuilder(SENTINEL)
        sb.append(WIRE_PRODUCT)
        sb.append(SEP).append(kv("cat", card.categoryId))
        sb.append(SEP).append(kv("item", card.itemId))
        sb.append(SEP).append(kv("title", card.title))
        sb.append(SEP).append(kv("price", card.priceCents.toString()))
        sb.append(SEP).append(kv("cur", card.currency))
        card.imageUrl?.takeIf { it.isNotBlank() }?.let { sb.append(SEP).append(kv("img", it)) }
        sb.append(SEP).append(kv("stock", if (card.inStock) "1" else "0"))
        return sb.toString()
    }

    fun encode(card: OrderCard): String {
        val sb = StringBuilder(SENTINEL)
        sb.append(WIRE_ORDER)
        sb.append(SEP).append(kv("oid", card.orderId))
        sb.append(SEP).append(kv("sum", card.summary))
        sb.append(SEP).append(kv("st", card.status))
        sb.append(SEP).append(kv("mode", card.mode.wire))
        card.totalCents?.let { sb.append(SEP).append(kv("total", it.toString())) }
        card.currency?.takeIf { it.isNotBlank() }?.let { sb.append(SEP).append(kv("cur", it)) }
        // PII guard AT THE WIRE too: never emit a buyer name in receipt mode, even if one slipped in.
        if (card.mode != OrderMode.RECEIPT) {
            card.buyerName?.takeIf { it.isNotBlank() }?.let { sb.append(SEP).append(kv("buyer", it)) }
        }
        return sb.toString()
    }

    /**
     * Parse a message body into a [ProductCard] or [OrderCard], or null when it is not a (well-formed)
     * ecom card. The receipt-mode PII guard is re-applied on parse so a hand-crafted body can never
     * surface a buyer name in receipt mode.
     */
    fun parse(body: String?): Any? {
        if (body == null || !body.startsWith(SENTINEL)) return null
        val payload = body.substring(SENTINEL.length)
        val parts = payload.split(SEP)
        if (parts.isEmpty()) return null
        val kind = parts[0]
        val map = HashMap<String, String>()
        for (i in 1 until parts.size) {
            val seg = parts[i]
            val eq = seg.indexOf(EQ)
            if (eq <= 0) continue
            map[unescape(seg.substring(0, eq))] = unescape(seg.substring(eq + 1))
        }
        return when (kind) {
            WIRE_PRODUCT -> {
                val itemId = map["item"]?.takeIf { it.isNotBlank() } ?: return null
                ProductCard(
                    categoryId = map["cat"] ?: "",
                    itemId = itemId,
                    title = map["title"]?.takeIf { it.isNotBlank() } ?: "Product",
                    priceCents = map["price"]?.toLongOrNull() ?: 0L,
                    currency = map["cur"]?.takeIf { it.isNotBlank() } ?: "USD",
                    imageUrl = map["img"]?.takeIf { it.isNotBlank() },
                    inStock = map["stock"] != "0",
                )
            }
            WIRE_ORDER -> {
                val orderId = map["oid"]?.takeIf { it.isNotBlank() } ?: return null
                val mode = OrderMode.fromWire(map["mode"])
                OrderCard(
                    orderId = orderId,
                    summary = map["sum"]?.takeIf { it.isNotBlank() } ?: "Order",
                    status = map["st"]?.takeIf { it.isNotBlank() } ?: "unknown",
                    mode = mode,
                    totalCents = map["total"]?.toLongOrNull(),
                    currency = map["cur"]?.takeIf { it.isNotBlank() },
                    // Re-apply the choke point on parse: no buyer name ever surfaces in receipt mode.
                    buyerName = if (mode == OrderMode.RECEIPT) null else map["buyer"]?.takeIf { it.isNotBlank() },
                )
            }
            else -> null
        }
    }

    private const val SEP: Char = ';'
    private const val EQ: Char = '='

    private fun kv(k: String, v: String): String = escape(k) + "=" + escape(v)

    /** Percent-escape the reserved delimiters so any user-facing value round-trips through [parse]. */
    private fun escape(s: String): String {
        val sb = StringBuilder(s.length)
        for (c in s) {
            when (c) {
                '%' -> sb.append("%25")
                ';' -> sb.append("%3B")
                '=' -> sb.append("%3D")
                '\n' -> sb.append("%0A")
                '\r' -> sb.append("%0D")
                else -> sb.append(c)
            }
        }
        return sb.toString()
    }

    private fun unescape(s: String): String {
        if (s.indexOf('%') < 0) return s
        val sb = StringBuilder(s.length)
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '%' && i + 2 < s.length) {
                val hex = s.substring(i + 1, i + 3)
                val code = hex.toIntOrNull(16)
                if (code != null) { sb.append(code.toChar()); i += 3; continue }
            }
            sb.append(c); i++
        }
        return sb.toString()
    }
}
