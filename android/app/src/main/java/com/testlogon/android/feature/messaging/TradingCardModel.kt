package com.testlogon.android.feature.messaging

/**
 * FE-101 / FE-102 — pure, dependency-free model for the two "trading-in-chat" card kinds
 * (market_card, position_card). Kept Android-free so the payload encode/parse + the disclosure
 * field-selection logic can be JVM-unit-tested in isolation (see TradingCardModelTest).
 *
 * TRANSPORT (works-now, no backend change, degrade-on-404): a trading card rides on a NORMAL text
 * message. The structured payload is encoded into the message body behind a rare sentinel tag; the
 * message dispatch parses the body back to a [TradingCard] and renders the card, and falls through
 * to a plain text bubble when the body is not a card (so an un-upgraded client just shows text).
 *
 * The encoding is a single line: SENTINEL + "market_card" | "position_card" + ";" + key=value pairs
 * joined by ";". Reserved chars (";", "=", "%", newline) are percent-escaped so values round-trip.
 */
object TradingCardModel {

    /** Sentinel prefix on the message body that marks a trading-card payload. */
    const val SENTINEL: String = "TLCARD1:"

    enum class Kind(val wire: String) {
        MARKET("market_card"),
        POSITION("position_card"),
    }

    /**
     * FE-102 disclosure selector. The sender chooses how much of their position to reveal:
     *  - [FULL]: side, qty, entry, mark, liquidation, uPnL AND the derived percentages.
     *  - [PNL_PCT]: uPnL% only (no absolute cash amounts, no qty/entry/liq).
     *  - [ROI]: return-on-margin % only (no absolute cash amounts, no qty/entry/liq).
     */
    enum class Disclosure(val wire: String) {
        FULL("full"),
        PNL_PCT("pnl_pct"),
        ROI("roi"),
        ;

        companion object {
            fun fromWire(w: String?): Disclosure = entries.firstOrNull { it.wire == w } ?: FULL
        }
    }

    /** The permitted field set for a disclosure. A field absent here MUST NOT be sent/rendered. */
    enum class PositionField { SIDE, QTY, ENTRY_PRICE, MARK_PRICE, LIQUIDATION_PRICE, UPNL_ABS, PNL_PCT, ROI_PCT }

    /**
     * FE-102 — the single source of truth for "what a disclosure permits". FULL reveals everything;
     * PNL_PCT reveals ONLY the P&L percentage; ROI reveals ONLY the ROI percentage. Directional color
     * needs the SIDE, but SIDE is an identity (not a dollar amount), so it is permitted in every mode.
     */
    fun permittedFields(disclosure: Disclosure): Set<PositionField> = when (disclosure) {
        Disclosure.FULL -> setOf(
            PositionField.SIDE,
            PositionField.QTY,
            PositionField.ENTRY_PRICE,
            PositionField.MARK_PRICE,
            PositionField.LIQUIDATION_PRICE,
            PositionField.UPNL_ABS,
            PositionField.PNL_PCT,
            PositionField.ROI_PCT,
        )
        Disclosure.PNL_PCT -> setOf(PositionField.SIDE, PositionField.PNL_PCT)
        Disclosure.ROI -> setOf(PositionField.SIDE, PositionField.ROI_PCT)
    }

    // ---- parsed card shapes ----

    sealed interface TradingCard {
        val symbolId: Int
        val symbol: String
    }

    /** FE-101 — a shared market reference. Live price/change/sparkline are fetched at render time. */
    data class MarketCard(
        override val symbolId: Int,
        override val symbol: String,
    ) : TradingCard

    /**
     * FE-102 — a shared position. Carries ONLY the fields permitted by [disclosure]; every optional
     * field is null when the disclosure withholds it (so the payload itself never leaks a hidden
     * dollar amount). [owner] is the display attribution ("shared by <owner>").
     */
    data class PositionCard(
        override val symbolId: Int,
        override val symbol: String,
        val disclosure: Disclosure,
        val owner: String,
        val side: String?,          // "buy" | "sell" | null
        val qty: Long?,
        val entryPrice: Long?,
        val markPrice: Long?,
        val liquidationPrice: Long?,
        val unrealizedPnl: Long?,   // minor units (raw)
        val pnlPct: Double?,        // uPnL as % of notional
        val roiPct: Double?,        // uPnL as % of margin/ROI
    ) : TradingCard {
        val isLong: Boolean? get() = when (side) { "buy" -> true; "sell" -> false; else -> null }
    }

    // ---- projection: build a permitted position payload from the FULL raw values ----

    /** Raw (FULL) position values known to the sender before disclosure filtering. */
    data class RawPosition(
        val symbolId: Int,
        val symbol: String,
        val owner: String,
        val side: String?,
        val qty: Long,
        val entryPrice: Long,
        val markPrice: Long,
        val liquidationPrice: Long,
        val unrealizedPnl: Long,
        val pnlPct: Double?,
        val roiPct: Double?,
    )

    /**
     * FE-102 — project a raw position down to EXACTLY the fields permitted by [disclosure]. Fields the
     * disclosure withholds are nulled out here (never transmitted), so a PNL_PCT/ROI share can never
     * leak entry/qty/liq/absolute-uPnL even if the wire is inspected.
     */
    fun project(raw: RawPosition, disclosure: Disclosure): PositionCard {
        val f = permittedFields(disclosure)
        return PositionCard(
            symbolId = raw.symbolId,
            symbol = raw.symbol,
            disclosure = disclosure,
            owner = raw.owner,
            side = if (PositionField.SIDE in f) raw.side else null,
            qty = if (PositionField.QTY in f) raw.qty else null,
            entryPrice = if (PositionField.ENTRY_PRICE in f) raw.entryPrice else null,
            markPrice = if (PositionField.MARK_PRICE in f) raw.markPrice else null,
            liquidationPrice = if (PositionField.LIQUIDATION_PRICE in f) raw.liquidationPrice else null,
            unrealizedPnl = if (PositionField.UPNL_ABS in f) raw.unrealizedPnl else null,
            pnlPct = if (PositionField.PNL_PCT in f) raw.pnlPct else null,
            roiPct = if (PositionField.ROI_PCT in f) raw.roiPct else null,
        )
    }

    // ---- conversation / reply preview strings ----

    fun marketPreview(symbol: String): String = "[Market: $symbol]"
    fun positionPreview(symbol: String): String = "[Position: $symbol]"

    /**
     * Preview for a message body that MAY be a trading card; null when the body is not a card (so the
     * caller keeps the server-provided text preview). Used by the conversation list + reply preview.
     */
    fun previewForBody(body: String?): String? {
        val card = parse(body) ?: return null
        return when (card) {
            is MarketCard -> marketPreview(card.symbol)
            is PositionCard -> positionPreview(card.symbol)
        }
    }

    // ---- encode / parse ----

    /** True when [body] begins with the trading-card sentinel (fast pre-check before a full parse). */
    fun isCard(body: String?): Boolean = body != null && body.startsWith(SENTINEL)

    fun encode(card: TradingCard): String {
        val sb = StringBuilder(SENTINEL)
        when (card) {
            is MarketCard -> {
                sb.append(Kind.MARKET.wire)
                sb.append(';').append(kv("sid", card.symbolId.toString()))
                sb.append(';').append(kv("sym", card.symbol))
            }
            is PositionCard -> {
                sb.append(Kind.POSITION.wire)
                sb.append(';').append(kv("sid", card.symbolId.toString()))
                sb.append(';').append(kv("sym", card.symbol))
                sb.append(';').append(kv("disc", card.disclosure.wire))
                sb.append(';').append(kv("owner", card.owner))
                card.side?.let { sb.append(';').append(kv("side", it)) }
                card.qty?.let { sb.append(';').append(kv("qty", it.toString())) }
                card.entryPrice?.let { sb.append(';').append(kv("entry", it.toString())) }
                card.markPrice?.let { sb.append(';').append(kv("mark", it.toString())) }
                card.liquidationPrice?.let { sb.append(';').append(kv("liq", it.toString())) }
                card.unrealizedPnl?.let { sb.append(';').append(kv("upnl", it.toString())) }
                card.pnlPct?.let { sb.append(';').append(kv("pnlpct", it.toString())) }
                card.roiPct?.let { sb.append(';').append(kv("roipct", it.toString())) }
            }
        }
        return sb.toString()
    }

    /** Parse a message body into a [TradingCard], or null when it is not a (well-formed) card. */
    fun parse(body: String?): TradingCard? {
        if (body == null || !body.startsWith(SENTINEL)) return null
        val payload = body.substring(SENTINEL.length)
        val parts = payload.split(';')
        if (parts.isEmpty()) return null
        val wireKind = parts[0]
        val map = HashMap<String, String>()
        for (i in 1 until parts.size) {
            val seg = parts[i]
            val eq = seg.indexOf('=')
            if (eq <= 0) continue
            map[unescape(seg.substring(0, eq))] = unescape(seg.substring(eq + 1))
        }
        val sid = map["sid"]?.toIntOrNull() ?: return null
        val sym = map["sym"] ?: return null
        return when (wireKind) {
            Kind.MARKET.wire -> MarketCard(symbolId = sid, symbol = sym)
            Kind.POSITION.wire -> PositionCard(
                symbolId = sid,
                symbol = sym,
                disclosure = Disclosure.fromWire(map["disc"]),
                owner = map["owner"] ?: "",
                side = map["side"],
                qty = map["qty"]?.toLongOrNull(),
                entryPrice = map["entry"]?.toLongOrNull(),
                markPrice = map["mark"]?.toLongOrNull(),
                liquidationPrice = map["liq"]?.toLongOrNull(),
                unrealizedPnl = map["upnl"]?.toLongOrNull(),
                pnlPct = map["pnlpct"]?.toDoubleOrNull(),
                roiPct = map["roipct"]?.toDoubleOrNull(),
            )
            else -> null
        }
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
