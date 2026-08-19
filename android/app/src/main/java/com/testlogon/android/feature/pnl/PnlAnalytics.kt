package com.testlogon.android.feature.pnl

import com.testlogon.android.data.exchange.FillFee
import com.testlogon.android.data.exchange.FillsFees
import com.testlogon.android.data.exchange.FundingPayment
import com.testlogon.android.data.exchange.FundingPayments
import com.testlogon.android.data.exchange.Liquidation
import com.testlogon.android.data.exchange.Liquidations
import com.testlogon.android.data.exchange.OrderSide

/**
 * PURE, unit-testable PnL & performance analytics. NO Android / coroutine / Compose deps: the ViewModel
 * fetches the four exchange reads (fills-fees, liquidations, funding payments, margin account) and hands
 * them here; every derived number below is computed in plain Kotlin so it can be tested in isolation.
 *
 * Realized PnL uses AVERAGE-COST accounting per symbol: fills are walked oldest -> newest keeping a
 * running (netQty, avgEntry). A same-side fill (extends the position) folds into a weighted average
 * entry; an opposite-side fill CLOSES up to the open quantity and realizes (price - avgEntry) * closed
 * * dir, where dir = +1 while the closed position was long and -1 while it was short. Closing beyond
 * the open quantity flips the position and re-seeds avgEntry at the fill price for the residual.
 *
 * Net realized rolls the trade realizations together with the other cash legs:
 *   net = sum(realized) - sum(fees) + sum(funding.payment signed) + sum(liq.realizedPnl) - sum(liq.fee)
 *
 * All amounts are raw integer engine units (Long); price scalers are 1 today (identity), so the caller
 * formats for display.
 */
object PnlAnalytics {

    /** Signed direction of a side: BUY = +1, SELL = -1, null (unknown) = 0 (ignored for realization). */
    private fun dirOf(side: OrderSide?): Int = when (side) {
        OrderSide.BUY -> 1
        OrderSide.SELL -> -1
        null -> 0
    }

    /**
     * Per-symbol realized-PnL + activity accumulator produced by [realizedBySymbol]. [realized] is the
     * average-cost trade realization for this symbol BEFORE the non-trade legs (fees/funding/liq).
     * [volume] is sum(|qty|*price) over the symbol's fills. [closingTrades]/[winningTrades] drive win rate.
     */
    data class SymbolPnl(
        val symbolId: Int,
        val realized: Long,
        val fees: Long,
        val volume: Long,
        val tradeCount: Int,
        val closingTrades: Int,
        val winningTrades: Int,
    )

    /**
     * The full PnL snapshot the screen renders. [netRealized] already folds every cash leg together;
     * [unrealized] comes from the margin account (position uPnL) and is passed through untouched. The
     * per-symbol rows are sorted by descending |realized| so the biggest movers surface first.
     */
    data class PnlReport(
        val netRealized: Long,
        val tradeRealized: Long,
        val unrealized: Long,
        val totalFees: Long,
        val fundingTotal: Long,
        val liquidationPnl: Long,
        val winRate: Float,
        val closingTradeCount: Int,
        val tradeCount: Int,
        val volume: Long,
        val bySymbol: List<SymbolPnl>,
        val equityCurve: List<EquityPoint>,
    ) {
        val isEmpty: Boolean
            get() = tradeCount == 0 && bySymbol.isEmpty() && equityCurve.isEmpty() &&
                fundingTotal == 0L && liquidationPnl == 0L
    }

    /** One cumulative point on the equity curve: a nanosecond timestamp + the running net total to date. */
    data class EquityPoint(val tsNs: Long, val cumulative: Long)

    /** A dated realized-cash event, used to build the time-ordered [EquityPoint] curve. */
    private data class CashEvent(val tsNs: Long, val amount: Long)

    /**
     * Walk each symbol's fills oldest -> newest keeping (netQty, avgEntry) and accumulate average-cost
     * realized PnL, fees, notional volume, and win stats. One [SymbolPnl] per symbol that had a fill.
     */
    fun realizedBySymbol(fills: List<FillFee>): List<SymbolPnl> {
        val bySymbol = fills.groupBy { it.symbolId }
        return bySymbol.map { (symbolId, symbolFills) ->
            var netQty = 0L
            var avgEntry = 0L
            var realized = 0L
            var fees = 0L
            var volume = 0L
            var closing = 0
            var winning = 0
            // Oldest -> newest so the running average-cost basis is chronologically correct.
            symbolFills.sortedBy { it.tsNs }.forEach { f ->
                val dir = dirOf(f.side)
                fees += f.fee
                volume += Math.abs(f.qty) * f.price
                if (dir == 0 || f.qty <= 0L) return@forEach
                val signedQty = dir * f.qty
                if (netQty == 0L || sameSign(netQty, signedQty)) {
                    // Opening or extending: weighted-average the entry price into the (growing) position.
                    val newQty = netQty + signedQty
                    avgEntry = weightedEntry(netQty, avgEntry, f.qty, f.price)
                    netQty = newQty
                } else {
                    // Opposite side: close against the open position (up to its size), realizing PnL.
                    val closable = Math.min(f.qty, Math.abs(netQty))
                    val posDir = if (netQty > 0) 1 else -1
                    val pnl = (f.price - avgEntry) * closable * posDir
                    realized += pnl
                    closing += 1
                    if (pnl > 0) winning += 1
                    val remaining = Math.abs(netQty) - closable
                    netQty = posDir.toLong() * remaining
                    if (netQty == 0L) {
                        avgEntry = 0L
                        // Any residual beyond the close flips the position, re-seeded at the fill price.
                        val flip = f.qty - closable
                        if (flip > 0L) {
                            netQty = dir.toLong() * flip
                            avgEntry = f.price
                        }
                    }
                }
            }
            SymbolPnl(
                symbolId = symbolId,
                realized = realized,
                fees = fees,
                volume = volume,
                tradeCount = symbolFills.size,
                closingTrades = closing,
                winningTrades = winning,
            )
        }.sortedByDescending { Math.abs(it.realized) }
    }

    private fun sameSign(a: Long, b: Long): Boolean = (a > 0 && b > 0) || (a < 0 && b < 0)

    /** Weighted-average entry price when adding [addQty] @ [addPrice] onto [heldQty] @ [heldEntry]. */
    private fun weightedEntry(heldQty: Long, heldEntry: Long, addQty: Long, addPrice: Long): Long {
        val held = Math.abs(heldQty)
        val total = held + addQty
        if (total == 0L) return 0L
        return (held * heldEntry + addQty * addPrice) / total
    }

    /**
     * Fold the four already-fetched reads into the full [PnlReport]. [unrealizedPnl] is the margin
     * account's position uPnL (0 when flat / unavailable). Every non-trade cash leg (fees, funding,
     * liquidation realized/fee) is rolled into [PnlReport.netRealized], and a time-ordered cumulative
     * equity curve is built from ALL dated cash events (per-fill realized net-of-fee + funding + liq).
     */
    fun analyze(
        fills: FillsFees,
        liquidations: Liquidations,
        funding: FundingPayments,
        unrealizedPnl: Long,
    ): PnlReport {
        val bySymbol = realizedBySymbol(fills.fills)
        val tradeRealized = bySymbol.sumOf { it.realized }
        val totalFees = bySymbol.sumOf { it.fees }
        val fundingTotal = funding.payments.sumOf { it.payment }
        val liquidationPnl = liquidations.events.sumOf { it.realizedPnl }
        val liquidationFees = liquidations.events.sumOf { it.fee }
        val netRealized = tradeRealized - totalFees + fundingTotal + liquidationPnl - liquidationFees

        val closingCount = bySymbol.sumOf { it.closingTrades }
        val winningCount = bySymbol.sumOf { it.winningTrades }
        val winRate = if (closingCount > 0) winningCount.toFloat() / closingCount.toFloat() else 0f
        val volume = bySymbol.sumOf { it.volume }
        val tradeCount = bySymbol.sumOf { it.tradeCount }

        return PnlReport(
            netRealized = netRealized,
            tradeRealized = tradeRealized,
            unrealized = unrealizedPnl,
            totalFees = totalFees,
            fundingTotal = fundingTotal,
            liquidationPnl = liquidationPnl,
            winRate = winRate,
            closingTradeCount = closingCount,
            tradeCount = tradeCount,
            volume = volume,
            bySymbol = bySymbol,
            equityCurve = equityCurve(fills.fills, liquidations.events, funding.payments),
        )
    }

    /**
     * Build the cumulative equity curve: every dated cash event (per-symbol per-fill realized net of
     * that fill's fee, funding payments, liquidation realized-minus-fee) is emitted, sorted by time, and
     * accumulated into a running total. Realized-per-fill mirrors the average-cost walk in
     * [realizedBySymbol] so the curve's final value reconciles with the roll-up (minus uPnL).
     */
    fun equityCurve(
        fills: List<FillFee>,
        liquidations: List<Liquidation>,
        funding: List<FundingPayment>,
    ): List<EquityPoint> {
        val events = mutableListOf<CashEvent>()

        // Per-symbol average-cost walk, emitting a signed cash event per fill (realized - fee).
        fills.groupBy { it.symbolId }.forEach { (_, symbolFills) ->
            var netQty = 0L
            var avgEntry = 0L
            symbolFills.sortedBy { it.tsNs }.forEach { f ->
                var realized = 0L
                val dir = dirOf(f.side)
                if (dir != 0 && f.qty > 0L) {
                    val signedQty = dir * f.qty
                    if (netQty == 0L || sameSign(netQty, signedQty)) {
                        avgEntry = weightedEntry(netQty, avgEntry, f.qty, f.price)
                        netQty += signedQty
                    } else {
                        val closable = Math.min(f.qty, Math.abs(netQty))
                        val posDir = if (netQty > 0) 1 else -1
                        realized = (f.price - avgEntry) * closable * posDir
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
                events += CashEvent(f.tsNs, realized - f.fee)
            }
        }

        funding.forEach { events += CashEvent(it.tsNs, it.payment) }
        liquidations.forEach { events += CashEvent(it.tsNs, it.realizedPnl - it.fee) }

        if (events.isEmpty()) return emptyList()
        var running = 0L
        return events.sortedBy { it.tsNs }.map { e ->
            running += e.amount
            EquityPoint(e.tsNs, running)
        }
    }
}
