package com.testlogon.android.feature.paper

import com.testlogon.android.data.exchange.OrderSide
import com.testlogon.android.feature.paper.PaperEngine.PaperAccount
import com.testlogon.android.feature.paper.PaperEngine.PaperOrderStatus
import com.testlogon.android.feature.paper.PaperEngine.PaperOrderType

/**
 * PURE, framework-free adapters that project the shared client-side [PaperAccount] (plus live marks +
 * symbol-name resolution) into the render shapes the read-only Blotter / PnL / Portfolio screens
 * already consume. NO Android / coroutine / Compose deps: every function below is a deterministic
 * transformation over immutable value types so it is unit-testable in isolation and reused by each
 * ViewModel when paper mode is ON.
 *
 * When paper mode is OFF the screens keep their existing (live/mock) data source untouched; these
 * adapters are ONLY invoked to build the paper projection. The blotter uses string symbols + Double
 * money; the paper engine uses symbolId + raw int64 engine units (scaler = 1 today, so notional =
 * price * qty). The conversion here is the single choke point that keeps that mapping in one place.
 */
object PaperViews {

    /** Resolve a symbolId to its display name, falling back to a stable "#id" token. */
    private fun name(symbolId: Int, names: Map<Int, String>): String =
        names[symbolId] ?: "#" + symbolId

    // ---- Blotter -----------------------------------------------------------

    /**
     * Project the paper account into flat blotter Order rows (the Orders tab source of truth). Each
     * paper order becomes one [com.testlogon.android.feature.blotter.BlotterOrder]:
     *  - WORKING limit -> LIVE (leaves = full qty, cumQty = 0).
     *  - FILLED (market or triggered limit) -> FILLED (cumQty = qty, leaves = 0, avgPx = fill price).
     *  - CANCELLED -> CANCELLED (leaves = 0).
     * The matching fill (for FILLED orders) supplies the executed avg price; a working order has none.
     * Fills + positions are DERIVED from these rows by the existing blotter state (cumQty > 0), so we
     * only need to emit the order rows correctly.
     */
    fun blotterOrders(
        acct: PaperAccount,
        marks: Map<Int, Long>,
        names: Map<Int, String>,
    ): List<com.testlogon.android.feature.blotter.BlotterOrder> {
        // Index the latest fill price per order id (a paper order fills at most once in this engine).
        val fillPxByOrder = acct.fills.associate { it.orderId to it.price }
        return acct.orders.map { o ->
            val side = if (o.side == OrderSide.BUY) {
                com.testlogon.android.feature.blotter.BlotterSide.BUY
            } else {
                com.testlogon.android.feature.blotter.BlotterSide.SELL
            }
            val qty = o.qty.toDouble()
            val fillPx = fillPxByOrder[o.id]
            // Row px carries the LIVE mark when known so the derived Positions tab marks each symbol at
            // its current price (uPnl = (mark - avgCost) * net); avgPx below keeps the true fill basis.
            val px = (marks[o.symbolId] ?: o.limitPrice ?: fillPx ?: 0L).toDouble()
            val filled = o.status == PaperOrderStatus.FILLED
            val cumQty = if (filled) qty else 0.0
            val avgPx = if (filled) (fillPx ?: o.limitPrice ?: 0L).toDouble() else 0.0
            val leaves = when (o.status) {
                PaperOrderStatus.WORKING -> qty
                else -> 0.0
            }
            val status = when (o.status) {
                PaperOrderStatus.WORKING -> com.testlogon.android.feature.blotter.BlotterStatus.LIVE
                PaperOrderStatus.FILLED -> com.testlogon.android.feature.blotter.BlotterStatus.FILLED
                PaperOrderStatus.CANCELLED -> com.testlogon.android.feature.blotter.BlotterStatus.CANCELLED
            }
            // Market orders are effectively immediate; model TIF as IOC, resting limits as GTC.
            val tif = if (o.type == PaperOrderType.MARKET) {
                com.testlogon.android.feature.blotter.BlotterTif.IOC
            } else {
                com.testlogon.android.feature.blotter.BlotterTif.GTC
            }
            com.testlogon.android.feature.blotter.BlotterOrder(
                clord = o.id,
                sym = name(o.symbolId, names),
                side = side,
                px = px,
                qty = qty,
                cumQty = cumQty,
                leaves = leaves,
                avgPx = avgPx,
                status = status,
                tif = tif,
            )
        }
    }

    // ---- PnL ---------------------------------------------------------------

    /**
     * Project the paper account + marks into the [com.testlogon.android.feature.pnl.PnlStats] the PnL
     * screen renders. Realized comes straight off the engine; unrealized is the marked total; volume +
     * fees + trade/win counts are walked from the fill history (paper has no fees, so fees = 0). The
     * per-symbol breakdown mirrors the same walk keyed by symbol.
     */
    fun pnlStats(
        acct: PaperAccount,
        marks: Map<Int, Long>,
    ): com.testlogon.android.feature.pnl.PnlStats {
        val realized = acct.realizedPnl
        val unrealized = PaperEngine.unrealized(acct, marks)
        var volume = 0L
        for (f in acct.fills) volume += Math.abs(f.qty) * f.price
        val closing = closingTradeStats(acct)
        return com.testlogon.android.feature.pnl.PnlStats(
            netRealized = realized,
            unrealized = unrealized,
            totalFees = 0L,
            winRate = if (closing.first > 0) closing.second.toFloat() / closing.first.toFloat() else 0f,
            closingTradeCount = closing.first,
            tradeCount = acct.fills.size,
            volume = volume,
            fundingTotal = 0L,
            liquidationPnl = 0L,
        )
    }

    /** Per-symbol PnL rows for the paper account (realized walk per symbol, fees = 0). */
    fun pnlBySymbol(
        acct: PaperAccount,
        names: Map<Int, String>,
    ): List<com.testlogon.android.feature.pnl.SymbolRow> =
        acct.fills.groupBy { it.symbolId }.map { (symbolId, fills) ->
            var realized = 0L
            var netQty = 0L
            var avgEntry = 0L
            var volume = 0L
            fills.sortedBy { it.tsMs }.forEach { f ->
                volume += Math.abs(f.qty) * f.price
                val dir = if (f.side == OrderSide.BUY) 1 else -1
                val signedQty = dir * f.qty
                if (netQty == 0L || sameSign(netQty, signedQty)) {
                    avgEntry = weightedEntry(netQty, avgEntry, f.qty, f.price)
                    netQty += signedQty
                } else {
                    val closable = Math.min(f.qty, Math.abs(netQty))
                    val posDir = if (netQty > 0) 1 else -1
                    realized += (f.price - avgEntry) * closable * posDir
                    val remaining = Math.abs(netQty) - closable
                    netQty = posDir.toLong() * remaining
                    if (netQty == 0L) {
                        avgEntry = 0L
                        val flip = f.qty - closable
                        if (flip > 0L) {
                            netQty = dir.toLong() * flip
                            avgEntry = f.price
                        }
                    }
                }
            }
            com.testlogon.android.feature.pnl.SymbolRow(
                symbol = name(symbolId, names),
                realized = realized,
                volume = volume,
                fees = 0L,
                tradeCount = fills.size,
            )
        }.sortedByDescending { Math.abs(it.realized) }

    /** (closingTradeCount, winningTradeCount) walked from the fill history. */
    private fun closingTradeStats(acct: PaperAccount): Pair<Int, Int> {
        var closing = 0
        var winning = 0
        acct.fills.groupBy { it.symbolId }.forEach { (_, fills) ->
            var netQty = 0L
            var avgEntry = 0L
            fills.sortedBy { it.tsMs }.forEach { f ->
                val dir = if (f.side == OrderSide.BUY) 1 else -1
                val signedQty = dir * f.qty
                if (netQty == 0L || sameSign(netQty, signedQty)) {
                    avgEntry = weightedEntry(netQty, avgEntry, f.qty, f.price)
                    netQty += signedQty
                } else {
                    val closable = Math.min(f.qty, Math.abs(netQty))
                    val posDir = if (netQty > 0) 1 else -1
                    val pnl = (f.price - avgEntry) * closable * posDir
                    closing += 1
                    if (pnl > 0) winning += 1
                    val remaining = Math.abs(netQty) - closable
                    netQty = posDir.toLong() * remaining
                    if (netQty == 0L) {
                        avgEntry = 0L
                        val flip = f.qty - closable
                        if (flip > 0L) {
                            netQty = dir.toLong() * flip
                            avgEntry = f.price
                        }
                    }
                }
            }
        }
        return closing to winning
    }

    // ---- Portfolio ---------------------------------------------------------

    /** Open paper positions projected into the portfolio position rows (liq price unknown -> 0). */
    fun portfolioPositions(
        acct: PaperAccount,
        marks: Map<Int, Long>,
        names: Map<Int, String>,
    ): List<com.testlogon.android.feature.portfolio.PortfolioPosition> =
        acct.positions.entries.sortedBy { it.key }.map { (symbolId, pos) ->
            val mark = marks[symbolId]
            val upl = if (mark != null) PaperEngine.positionMtm(pos, mark) else 0L
            com.testlogon.android.feature.portfolio.PortfolioPosition(
                symbol = name(symbolId, names),
                qty = pos.qty,
                entryPrice = pos.avgEntry,
                liquidationPrice = 0L,
                unrealizedPnl = upl,
            )
        }

    private fun sameSign(a: Long, b: Long): Boolean = (a > 0 && b > 0) || (a < 0 && b < 0)

    private fun weightedEntry(heldQty: Long, heldEntry: Long, addQty: Long, addPrice: Long): Long {
        val held = Math.abs(heldQty)
        val total = held + addQty
        if (total == 0L) return 0L
        return (held * heldEntry + addQty * addPrice) / total
    }
}
