package com.testlogon.android.feature.messaging

/**
 * EPIC B (FE-110 / FE-111) - pure, dependency-free model for the "send crypto in chat" card
 * (crypto_transfer). Kept Android-free so send-validation, fiat-equivalent math, direction, status
 * labelling, and the payload encode/parse can be JVM-unit-tested in isolation (CryptoTransferModelTest).
 *
 * TRANSPORT (works-now, degrade-on-404, mirrors [TradingCardModel]): a crypto-transfer card rides on a
 * NORMAL text message. The structured payload is encoded into the message body behind a rare sentinel
 * tag; the message dispatch parses the body back to a [CryptoTransfer] and renders the card, and falls
 * through to a plain text bubble when the body is not a card (so an un-upgraded client just shows text).
 * There is NO dedicated crypto-send endpoint (POST me/custody/transfer was retired), so the tagged-body
 * text path IS the transport; the card records the intent + amount + parties.
 *
 * Encoding: SENTINEL + "crypto_transfer" + ";" + key=value pairs joined by ";". Reserved chars (";",
 * "=", "%", newline) are percent-escaped so values round-trip through [parse].
 */
object CryptoTransferModel {

    /** Sentinel prefix marking a crypto-transfer payload. Distinct from TradingCardModel.SENTINEL. */
    const val SENTINEL: String = "TLXFER1:"

    const val WIRE_KIND: String = "crypto_transfer"

    /** Lifecycle of a chat crypto transfer (display + badge styling only). */
    enum class Status(val wire: String) {
        PENDING("pending"),
        COMPLETE("complete"),
        FAILED("failed"),
        ;

        companion object {
            fun fromWire(w: String?): Status = entries.firstOrNull { it.wire == w } ?: PENDING
        }
    }

    /** Whether the viewer SENT or RECEIVED this transfer (drives styling + preview). */
    enum class Direction { SENT, RECEIVED }

    /**
     * Static USD reference price per whole unit for the fiat-equivalent estimate. There is no live FX
     * read on the custody surface, so stablecoins peg to $1 and volatile assets use a coarse reference
     * (clearly an estimate, shown as "~"). Symbols match case-insensitively; an unknown symbol yields
     * no estimate (null), never a wrong number.
     */
    val REFERENCE_USD: Map<String, Double> = mapOf(
        "USDC" to 1.0,
        "USDT" to 1.0,
        "DAI" to 1.0,
        "ETH" to 2_500.0,
        "BNB" to 600.0,
        "POL" to 0.50,
        "BTC" to 60_000.0,
    )

    // ---- parsed card shape ----

    /**
     * FE-111 - a chat crypto transfer. [amount] is the whole-unit decimal string exactly as entered
     * (kept as text so no precision is lost across the wire). [fromSub]/[toSub] are party subs for
     * direction resolution; [fromName]/[toName] are display attributions. [status] is the badge.
     */
    data class CryptoTransfer(
        val asset: String,
        val amount: String,
        val fromSub: String,
        val toSub: String,
        val fromName: String,
        val toName: String,
        val status: Status,
        val memo: String?,
    )

    // ---- send validation (FE-110) ----

    /** The reason a send is blocked, or [OK] when it may proceed. */
    enum class SendValidation(val ok: Boolean) {
        OK(true),
        NO_ASSET(false),
        NON_POSITIVE(false),
        INSUFFICIENT(false),
    }

    /**
     * FE-110 - validate a compose attempt. Blocks: no asset picked, a non-positive/unparseable amount,
     * and (only when [balance] is known) an over-spend. A null [balance] never blocks on funds (we
     * cannot prove an over-spend), matching the MoneySafety "best-effort never blocks" rule.
     */
    fun validateSend(asset: String?, amountText: String, balance: Double?): SendValidation {
        if (asset.isNullOrBlank()) return SendValidation.NO_ASSET
        val amt = positiveAmount(amountText) ?: return SendValidation.NON_POSITIVE
        if (balance != null && amt > balance) return SendValidation.INSUFFICIENT
        return SendValidation.OK
    }

    /** Parse a user-entered amount to a strictly-positive Double, or null when blank/non-numeric/<=0. */
    fun positiveAmount(text: String): Double? = text.trim().toDoubleOrNull()?.takeIf { it > 0.0 }

    /**
     * FE-110 - fiat (USD) equivalent of [amountText] of [asset], in whole cents (rounded), or null when
     * the amount is non-positive or the asset has no reference price. Pure integer-cent output.
     */
    fun fiatEquivalentCents(asset: String?, amountText: String): Long? {
        val amt = positiveAmount(amountText) ?: return null
        val px = asset?.let { REFERENCE_USD[it.trim().uppercase()] } ?: return null
        return Math.round(amt * px * 100.0)
    }

    /** FE-111 - the viewer's direction: SENT when they are the sender, else RECEIVED. */
    fun transferDirection(card: CryptoTransfer, viewerSub: String?): Direction =
        if (viewerSub != null && viewerSub == card.fromSub) Direction.SENT else Direction.RECEIVED

    /** FE-111 - a short human status label for the badge. */
    fun statusLabel(status: Status): String = when (status) {
        Status.PENDING -> "Pending"
        Status.COMPLETE -> "Completed"
        Status.FAILED -> "Failed"
    }

    // ---- conversation / reply preview strings ----

    /** Preview from the VIEWER'S perspective: "[Sent X ASSET]" / "[Received X ASSET]". */
    fun preview(card: CryptoTransfer, viewerSub: String?): String =
        when (transferDirection(card, viewerSub)) {
            Direction.SENT -> "[Sent ${card.amount} ${card.asset}]"
            Direction.RECEIVED -> "[Received ${card.amount} ${card.asset}]"
        }

    /** Direction-agnostic preview (used where the viewer is unknown). */
    fun previewNeutral(card: CryptoTransfer): String = "[Crypto: ${card.amount} ${card.asset}]"

    /**
     * Preview for a message body that MAY be a crypto-transfer card; null when it is not one (so the
     * caller keeps the server text preview). Used by the conversation list + reply preview.
     */
    fun previewForBody(body: String?, viewerSub: String?): String? {
        val card = parse(body) ?: return null
        return preview(card, viewerSub)
    }

    // ---- encode / parse ----

    /** True when [body] begins with the crypto-transfer sentinel (fast pre-check before a full parse). */
    fun isCard(body: String?): Boolean = body != null && body.startsWith(SENTINEL)

    fun encode(card: CryptoTransfer): String {
        val sb = StringBuilder(SENTINEL)
        sb.append(WIRE_KIND)
        sb.append(';').append(kv("asset", card.asset))
        sb.append(';').append(kv("amt", card.amount))
        sb.append(';').append(kv("from", card.fromSub))
        sb.append(';').append(kv("to", card.toSub))
        sb.append(';').append(kv("fromn", card.fromName))
        sb.append(';').append(kv("ton", card.toName))
        sb.append(';').append(kv("st", card.status.wire))
        card.memo?.takeIf { it.isNotBlank() }?.let { sb.append(';').append(kv("memo", it)) }
        return sb.toString()
    }

    /** Parse a message body into a [CryptoTransfer], or null when it is not a (well-formed) card. */
    fun parse(body: String?): CryptoTransfer? {
        if (body == null || !body.startsWith(SENTINEL)) return null
        val payload = body.substring(SENTINEL.length)
        val parts = payload.split(';')
        if (parts.isEmpty() || parts[0] != WIRE_KIND) return null
        val map = HashMap<String, String>()
        for (i in 1 until parts.size) {
            val seg = parts[i]
            val eq = seg.indexOf('=')
            if (eq <= 0) continue
            map[unescape(seg.substring(0, eq))] = unescape(seg.substring(eq + 1))
        }
        val asset = map["asset"]?.takeIf { it.isNotBlank() } ?: return null
        val amount = map["amt"]?.takeIf { it.isNotBlank() } ?: return null
        return CryptoTransfer(
            asset = asset,
            amount = amount,
            fromSub = map["from"] ?: "",
            toSub = map["to"] ?: "",
            fromName = map["fromn"] ?: "",
            toName = map["ton"] ?: "",
            status = Status.fromWire(map["st"]),
            memo = map["memo"]?.takeIf { it.isNotBlank() },
        )
    }

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
