package com.testlogon.android.feature.taxreport

/**
 * PURE, unit-testable tax-lot / cost-basis engine. NO Android / coroutine / Compose deps: the
 * ViewModel normalizes the exchange fills feed into [NormalizedFill]s and hands them here; every
 * number below is computed in plain Kotlin (integer cents / raw engine units) so it can be tested in
 * isolation.
 *
 * The engine walks each symbol's fills oldest -> newest. A BUY opens a lot (qty + cost basis = qty *
 * price + the buy fee). A SELL closes open lots for that symbol according to the chosen
 * [CostBasisMethod]:
 *   - FIFO: oldest open lot first.
 *   - LIFO: newest open lot first.
 *   - AVERAGE: a single blended lot per symbol (weighted-average cost basis); a sell closes a slice of
 *     the blended lot pro-rata.
 * A close realizes gain = proceeds - matched cost basis - the sell's fee (fees FOLD IN). Holding period
 * runs from the matched lot's open timestamp to the close; a position held > 365 days is LONG term,
 * otherwise SHORT. Overselling (a sell with no / insufficient open qty) is guarded: only the available
 * open quantity is matched and the remainder is dropped (no negative lots, no crash on empty input).
 *
 * Amounts are integer cents (Long). Timestamps are nanosecond ticks (matching the engine feed); holding
 * days are derived from the tick delta. Prices/qty are raw integer units; proceeds/cost = qty * price.
 */
object TaxLotMath {

    /** Long-term threshold: a holding strictly greater than this many days is LONG term. */
    const val LONG_TERM_DAYS = 365L

    private const val NANOS_PER_DAY = 24L * 60L * 60L * 1_000_000_000L

    enum class CostBasisMethod { FIFO, LIFO, AVERAGE }

    enum class Term { SHORT, LONG }

    /** One normalized fill the engine consumes. [side] is "buy"/"sell" (case-insensitive). */
    data class NormalizedFill(
        val tsNs: Long,
        val symbol: String,
        val side: String,
        val qty: Long,
        val priceCents: Long,
        val feeCents: Long,
    )

    /** An open (unclosed) tax lot: acquired [qty] at [costBasisCents] total, opened at [openTs]. */
    data class OpenLot(
        val symbol: String,
        val openTs: Long,
        val qty: Long,
        val costBasisCents: Long,
    )

    /** One realized (closed) tax-lot slice with its gain and holding-period classification. */
    data class RealizedLot(
        val symbol: String,
        val closeTs: Long,
        val qty: Long,
        val proceedsCents: Long,
        val costBasisCents: Long,
        val feeCents: Long,
        val gainCents: Long,
        val holdingDays: Long,
        val term: Term,
    )

    /** The engine result: everything still open + every realized slice (close order). */
    data class LotResult(
        val openLots: List<OpenLot>,
        val realized: List<RealizedLot>,
    )

    /** Per-symbol realized roll-up. */
    data class SymbolRealized(
        val symbol: String,
        val proceedsCents: Long,
        val costBasisCents: Long,
        val feeCents: Long,
        val gainCents: Long,
        val qty: Long,
        val lotCount: Int,
    )

    /** Short vs long term split of realized gains. */
    data class TermSplit(val shortCents: Long, val longCents: Long)

    /** The realized-gains summary. */
    data class RealizedSummary(
        val bySymbol: List<SymbolRealized>,
        val byTerm: TermSplit,
        val totalGainCents: Long,
    )

    /** Per-symbol unrealized cost-vs-market on the still-open lots. */
    data class UnrealizedRow(
        val symbol: String,
        val qty: Long,
        val costBasisCents: Long,
        val marketValueCents: Long,
        val unrealizedCents: Long,
    )

    private fun isBuy(side: String): Boolean = side.trim().equals("buy", ignoreCase = true)
    private fun isSell(side: String): Boolean = side.trim().equals("sell", ignoreCase = true)

    /** Holding period in whole days between two nanosecond ticks (never negative). */
    private fun holdingDays(openTs: Long, closeTs: Long): Long {
        val delta = closeTs - openTs
        if (delta <= 0L) return 0L
        return delta / NANOS_PER_DAY
    }

    private fun termFor(days: Long): Term = if (days > LONG_TERM_DAYS) Term.LONG else Term.SHORT

    /**
     * Run the tax-lot engine over [fills] under [method]. Fills are grouped per symbol and walked
     * oldest -> newest. Returns the residual open lots + the realized slices (in close order per symbol,
     * symbols concatenated). Empty input -> empty result. Oversells match only the available open qty.
     */
    fun computeLots(fills: List<NormalizedFill>, method: CostBasisMethod): LotResult {
        val openLots = mutableListOf<OpenLot>()
        val realized = mutableListOf<RealizedLot>()

        fills.groupBy { it.symbol }.forEach { (symbol, symbolFills) ->
            // A mutable open-lot list for this symbol (each is qty + total cost basis + open ts).
            val lots = mutableListOf<MutableLot>()
            symbolFills.sortedBy { it.tsNs }.forEach { f ->
                if (f.qty <= 0L) return@forEach
                when {
                    isBuy(f.side) -> openBuy(lots, f, method)
                    isSell(f.side) -> closeSell(lots, symbol, f, method, realized)
                    else -> { /* unknown side: ignore */ }
                }
            }
            lots.forEach { l ->
                if (l.qty > 0L) openLots += OpenLot(symbol = symbol, openTs = l.openTs, qty = l.qty, costBasisCents = l.costCents)
            }
        }
        return LotResult(openLots = openLots, realized = realized)
    }

    /** Mutable working lot used only inside [computeLots]. */
    private class MutableLot(var openTs: Long, var qty: Long, var costCents: Long)

    private fun openBuy(lots: MutableList<MutableLot>, f: NormalizedFill, method: CostBasisMethod) {
        val cost = f.qty * f.priceCents + f.feeCents
        if (method == CostBasisMethod.AVERAGE) {
            // AVERAGE keeps ONE blended lot per symbol: fold this buy into it (weighted cost basis).
            val existing = lots.firstOrNull()
            if (existing == null) {
                lots.add(MutableLot(openTs = f.tsNs, qty = f.qty, costCents = cost))
            } else {
                existing.qty += f.qty
                existing.costCents += cost
                // Keep the earliest acquisition ts so the blended lot's holding period is conservative.
                if (f.tsNs < existing.openTs) existing.openTs = f.tsNs
            }
        } else {
            lots.add(MutableLot(openTs = f.tsNs, qty = f.qty, costCents = cost))
        }
    }

    private fun closeSell(
        lots: MutableList<MutableLot>,
        symbol: String,
        f: NormalizedFill,
        method: CostBasisMethod,
        out: MutableList<RealizedLot>,
    ) {
        var remaining = f.qty
        // The sell fee is distributed across the matched slices pro-rata to the qty each slice closes,
        // so it always folds fully into realized gain (any rounding remainder lands on the last slice).
        val totalToClose = minOf(f.qty, lots.sumOf { it.qty })
        if (totalToClose <= 0L) return // oversell with no open position: nothing to match, drop.
        var feeAssigned = 0L
        var qtyClosedSoFar = 0L

        while (remaining > 0L) {
            val lot = pickLot(lots, method) ?: break
            val take = minOf(remaining, lot.qty)
            if (take <= 0L) { lots.remove(lot); continue }

            // Cost basis for the slice = pro-rata share of the lot's total cost basis.
            val sliceCost = if (lot.qty == take) lot.costCents else lot.costCents * take / lot.qty
            val proceeds = take * f.priceCents

            qtyClosedSoFar += take
            // Fee share for this slice (last slice absorbs the rounding remainder to reconcile exactly).
            val sliceFee = if (qtyClosedSoFar == totalToClose) {
                f.feeCents - feeAssigned
            } else {
                f.feeCents * take / totalToClose
            }
            feeAssigned += sliceFee

            val days = holdingDays(lot.openTs, f.tsNs)
            val gain = proceeds - sliceCost - sliceFee
            out += RealizedLot(
                symbol = symbol,
                closeTs = f.tsNs,
                qty = take,
                proceedsCents = proceeds,
                costBasisCents = sliceCost,
                feeCents = sliceFee,
                gainCents = gain,
                holdingDays = days,
                term = termFor(days),
            )

            // Reduce / consume the lot.
            lot.qty -= take
            lot.costCents -= sliceCost
            if (lot.qty <= 0L) lots.remove(lot)
            remaining -= take
        }
        // Any residual [remaining] is an oversell beyond open qty -> guarded (dropped, no negative lot).
    }

    /** Pick the next lot to close against per [method]: FIFO = front, LIFO = back, AVERAGE = the blend. */
    private fun pickLot(lots: MutableList<MutableLot>, method: CostBasisMethod): MutableLot? = when (method) {
        CostBasisMethod.FIFO -> lots.firstOrNull()
        CostBasisMethod.LIFO -> lots.lastOrNull()
        CostBasisMethod.AVERAGE -> lots.firstOrNull()
    }

    /** Roll realized slices up into per-symbol totals + a short/long split + the grand total gain. */
    fun realizedSummary(realized: List<RealizedLot>): RealizedSummary {
        val bySymbol = realized.groupBy { it.symbol }.map { (symbol, rows) ->
            SymbolRealized(
                symbol = symbol,
                proceedsCents = rows.sumOf { it.proceedsCents },
                costBasisCents = rows.sumOf { it.costBasisCents },
                feeCents = rows.sumOf { it.feeCents },
                gainCents = rows.sumOf { it.gainCents },
                qty = rows.sumOf { it.qty },
                lotCount = rows.size,
            )
        }.sortedByDescending { Math.abs(it.gainCents) }

        val shortCents = realized.filter { it.term == Term.SHORT }.sumOf { it.gainCents }
        val longCents = realized.filter { it.term == Term.LONG }.sumOf { it.gainCents }
        val total = realized.sumOf { it.gainCents }
        return RealizedSummary(bySymbol = bySymbol, byTerm = TermSplit(shortCents, longCents), totalGainCents = total)
    }

    /**
     * Per-symbol unrealized cost-vs-market on the [openLots]. [marks] maps a symbol to its current mark
     * price (raw price units, same scale as the fill price). A symbol with no usable mark is SKIPPED (no
     * phantom loss); only symbols with a mark are valued.
     */
    fun unrealized(openLots: List<OpenLot>, marks: Map<String, Long>): List<UnrealizedRow> {
        return openLots.groupBy { it.symbol }.mapNotNull { (symbol, lots) ->
            val mark = marks[symbol] ?: marks[symbol.uppercase()] ?: return@mapNotNull null
            val qty = lots.sumOf { it.qty }
            val cost = lots.sumOf { it.costBasisCents }
            val marketValue = qty * mark
            UnrealizedRow(
                symbol = symbol,
                qty = qty,
                costBasisCents = cost,
                marketValueCents = marketValue,
                unrealizedCents = marketValue - cost,
            )
        }.sortedByDescending { Math.abs(it.unrealizedCents) }
    }

    // ---- CSV (RFC 4180) ----

    private const val DELIM = ','

    /** RFC 4180 escaping: wrap in quotes + double embedded quotes when the field needs it. */
    fun csvField(raw: String): String {
        val needsQuote = raw.any { it == DELIM || it == '"' || it == '\n' || it == '\r' }
        return if (needsQuote) "\"" + raw.replace("\"", "\"\"") + "\"" else raw
    }

    private fun row(vararg cells: String): String = cells.joinToString(DELIM.toString()) { csvField(it) }

    /**
     * Realized-lots CSV: one row per closed slice (close order) with symbol / close-time / qty /
     * proceeds / cost-basis / fee / gain / holding-days / term. Always emits a header, even when there
     * are no realized lots. Timestamps render as ISO-8601-ish UTC; a 0 tick renders empty.
     */
    fun lotsToCsv(realized: List<RealizedLot>): String {
        val header = row("Symbol", "CloseTime", "Qty", "ProceedsCents", "CostBasisCents", "FeeCents", "GainCents", "HoldingDays", "Term")
        val body = realized.map { r ->
            row(
                r.symbol,
                formatTs(r.closeTs),
                r.qty.toString(),
                r.proceedsCents.toString(),
                r.costBasisCents.toString(),
                r.feeCents.toString(),
                r.gainCents.toString(),
                r.holdingDays.toString(),
                r.term.name,
            )
        }
        return (listOf(header) + body).joinToString("\r\n")
    }

    /** Format a nanosecond tick as yyyy-MM-dd HH:mm:ss 'UTC'; a tick of 0 (unknown) -> empty string. */
    fun formatTs(tsNs: Long): String {
        if (tsNs <= 0L) return ""
        val millis = tsNs / 1_000_000L
        val fmt = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.US)
        fmt.timeZone = java.util.TimeZone.getTimeZone("UTC")
        return fmt.format(java.util.Date(millis)) + " UTC"
    }
}
