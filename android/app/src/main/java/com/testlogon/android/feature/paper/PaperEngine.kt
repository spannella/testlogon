package com.testlogon.android.feature.paper

import com.testlogon.android.data.exchange.OrderSide

/**
 * PURE, framework-free paper-trading engine -- the client-side simulation core. NO Android / coroutine /
 * Compose / network dependencies: every function below is a plain, deterministic transformation over
 * immutable value types so it can be unit-tested in isolation and called freely from a ViewModel.
 *
 * This engine NEVER touches the real order/matching stack -- it exists only to let a user practise with
 * simulated funds. All money / price / quantity are raw int64 engine units (Long), matching the rest of
 * the trading stack (price scalers are 1 today, so notional = price * qty). Position [qty] is SIGNED:
 * positive = long, negative = short.
 *
 * Accounting is AVERAGE-COST: extending a position folds the fill into a weighted-average entry; reducing
 * or closing realizes (fillPrice - avgEntry) * closedQty * dir (dir = +1 while long, -1 while short); a
 * fill larger than the open position cleanly flips it, re-seeding avgEntry at the fill price for the
 * residual. Cash moves on every fill (buy: cash -= price*qty ; sell: cash += price*qty), so a short sale
 * credits cash and a buy-to-cover debits it, exactly like the real venue's cash leg.
 */
object PaperEngine {

    /** Order type for a paper order. */
    enum class PaperOrderType { MARKET, LIMIT }

    /** Lifecycle of a paper order. MARKET orders are FILLED immediately; LIMIT orders start WORKING. */
    enum class PaperOrderStatus { WORKING, FILLED, CANCELLED }

    /**
     * A simulated order. [limitPrice] is required for LIMIT and ignored for MARKET. [qty] is always a
     * positive magnitude; [side] carries the direction. [id] is a caller-supplied stable identifier.
     */
    data class PaperOrder(
        val id: String,
        val symbolId: Int,
        val side: OrderSide,
        val type: PaperOrderType,
        val qty: Long,
        val limitPrice: Long? = null,
        val status: PaperOrderStatus = PaperOrderStatus.WORKING,
        val createdTsMs: Long = 0L,
    )

    /** A simulated fill (audit trail + history UI). [qty] is a positive magnitude; [side] the direction. */
    data class PaperFill(
        val orderId: String,
        val symbolId: Int,
        val side: OrderSide,
        val price: Long,
        val qty: Long,
        val tsMs: Long = 0L,
    )

    /** A held position. [qty] is SIGNED (negative = short). [avgEntry] is the average-cost basis (>=0). */
    data class PaperPosition(
        val qty: Long,
        val avgEntry: Long,
    )

    /**
     * The whole simulated account. [cash] is free simulated cash (can go negative under leverage/shorts,
     * matching a real cash leg). [positions] is keyed by symbolId; a symbol with a flat position is
     * removed. [realizedPnl] accumulates closed-trade PnL. [startingCash] is retained for the account
     * panel + reset baseline.
     */
    data class PaperAccount(
        val cash: Long,
        val positions: Map<Int, PaperPosition>,
        val orders: List<PaperOrder>,
        val fills: List<PaperFill>,
        val realizedPnl: Long,
        val startingCash: Long,
    )

    /** A fresh account seeded with [startingCash] free cash and nothing open. */
    fun newAccount(startingCash: Long): PaperAccount = PaperAccount(
        cash = startingCash,
        positions = emptyMap(),
        orders = emptyList(),
        fills = emptyList(),
        realizedPnl = 0L,
        startingCash = startingCash,
    )

    private fun dirOf(side: OrderSide): Int = if (side == OrderSide.BUY) 1 else -1

    /**
     * Place [order] against the current [marketPrice]. A MARKET order (and a LIMIT order already
     * marketable at placement) fills IMMEDIATELY: MARKET at [marketPrice], a marketable LIMIT at its
     * limit price (never worse than the limit). A non-marketable LIMIT is appended as a WORKING order to
     * be filled later by [onTick]. Orders with a non-positive qty, or a LIMIT with no limit price, are
     * ignored (returned unchanged) rather than corrupting the book.
     */
    fun placeOrder(acct: PaperAccount, order: PaperOrder, marketPrice: Long): PaperAccount {
        if (order.qty <= 0L) return acct
        return when (order.type) {
            PaperOrderType.MARKET ->
                fillOrder(acct, order.copy(status = PaperOrderStatus.FILLED), marketPrice)
            PaperOrderType.LIMIT -> {
                val limit = order.limitPrice ?: return acct
                if (isMarketable(order.side, limit, marketPrice)) {
                    // Marketable on arrival -- fill at the limit (price improvement kept by the venue-sim).
                    fillOrder(acct, order.copy(status = PaperOrderStatus.FILLED), limit)
                } else {
                    acct.copy(orders = acct.orders + order.copy(status = PaperOrderStatus.WORKING))
                }
            }
        }
    }

    /** A LIMIT is marketable when a BUY limit >= market, or a SELL limit <= market. */
    private fun isMarketable(side: OrderSide, limit: Long, marketPrice: Long): Boolean =
        if (side == OrderSide.BUY) marketPrice <= limit else marketPrice >= limit

    /**
     * Feed a new [marketPrice] for [symbolId] to the account, filling any WORKING LIMIT order on that
     * symbol that the price has reached: a BUY limit fills when marketPrice <= limit; a SELL limit fills
     * when marketPrice >= limit. Each triggered order fills at ITS OWN limit price (the sim assumes the
     * resting order is filled at its posted price). Orders are processed oldest-first.
     */
    fun onTick(acct: PaperAccount, symbolId: Int, marketPrice: Long): PaperAccount {
        var current = acct
        // Snapshot the working orders to fill so we iterate a stable list while `current` mutates.
        val toFill = acct.orders.filter {
            it.status == PaperOrderStatus.WORKING &&
                it.symbolId == symbolId &&
                it.type == PaperOrderType.LIMIT &&
                it.limitPrice != null &&
                triggers(it.side, it.limitPrice, marketPrice)
        }
        for (order in toFill) {
            val limit = order.limitPrice ?: continue
            current = fillOrder(current, order.copy(status = PaperOrderStatus.FILLED), limit)
        }
        return current
    }

    /** A resting BUY limit triggers at marketPrice <= limit; a resting SELL limit at marketPrice >= limit. */
    private fun triggers(side: OrderSide, limit: Long, marketPrice: Long): Boolean =
        if (side == OrderSide.BUY) marketPrice <= limit else marketPrice >= limit

    /**
     * Cancel the WORKING order with [orderId] (no-op if it's absent or already terminal). The order is
     * marked CANCELLED in place so it stays in history rather than vanishing.
     */
    fun cancelOrder(acct: PaperAccount, orderId: String): PaperAccount {
        val idx = acct.orders.indexOfFirst { it.id == orderId && it.status == PaperOrderStatus.WORKING }
        if (idx < 0) return acct
        val updated = acct.orders.toMutableList()
        updated[idx] = updated[idx].copy(status = PaperOrderStatus.CANCELLED)
        return acct.copy(orders = updated)
    }

    /**
     * Apply a fill of [order] at [fillPrice] to [acct]: average-cost position update + realized PnL +
     * cash leg + fill-history append + the order marked FILLED (replacing its WORKING entry when present,
     * else appended). The single choke point every fill path routes through.
     */
    private fun fillOrder(acct: PaperAccount, order: PaperOrder, fillPrice: Long): PaperAccount {
        val dir = dirOf(order.side)
        val signedQty = dir * order.qty
        val existing = acct.positions[order.symbolId] ?: PaperPosition(0L, 0L)

        var netQty = existing.qty
        var avgEntry = existing.avgEntry
        var realized = 0L

        if (netQty == 0L || sameSign(netQty, signedQty)) {
            // Opening or extending: weighted-average the entry over the (growing) absolute size.
            avgEntry = weightedEntry(netQty, avgEntry, order.qty, fillPrice)
            netQty += signedQty
        } else {
            // Opposite side: close against the open position (up to its size), realizing PnL.
            val closable = minOf(order.qty, Math.abs(netQty))
            val posDir = if (netQty > 0) 1 else -1
            realized = (fillPrice - avgEntry) * closable * posDir
            val remaining = Math.abs(netQty) - closable
            netQty = posDir.toLong() * remaining
            if (netQty == 0L) {
                avgEntry = 0L
                // Any residual beyond the close flips the position, re-seeded at the fill price.
                val flip = order.qty - closable
                if (flip > 0L) {
                    netQty = dir.toLong() * flip
                    avgEntry = fillPrice
                }
            }
        }

        // Cash leg: buy debits price*qty, sell credits price*qty (short sale credits, cover debits).
        val cashDelta = -signedQty * fillPrice
        val newPositions = acct.positions.toMutableMap()
        if (netQty == 0L) {
            newPositions.remove(order.symbolId)
        } else {
            newPositions[order.symbolId] = PaperPosition(qty = netQty, avgEntry = avgEntry)
        }

        val fill = PaperFill(
            orderId = order.id,
            symbolId = order.symbolId,
            side = order.side,
            price = fillPrice,
            qty = order.qty,
            tsMs = order.createdTsMs,
        )

        // Replace the working order in place (limit fill) or append (market / marketable-on-arrival).
        val orders = if (acct.orders.any { it.id == order.id }) {
            acct.orders.map { if (it.id == order.id) order else it }
        } else {
            acct.orders + order
        }

        return acct.copy(
            cash = acct.cash + cashDelta,
            positions = newPositions,
            orders = orders,
            fills = acct.fills + fill,
            realizedPnl = acct.realizedPnl + realized,
        )
    }

    private fun sameSign(a: Long, b: Long): Boolean = (a > 0 && b > 0) || (a < 0 && b < 0)

    /** Weighted-average entry when adding [addQty] @ [addPrice] onto |[heldQty]| @ [heldEntry]. */
    private fun weightedEntry(heldQty: Long, heldEntry: Long, addQty: Long, addPrice: Long): Long {
        val held = Math.abs(heldQty)
        val total = held + addQty
        if (total == 0L) return 0L
        return (held * heldEntry + addQty * addPrice) / total
    }

    /**
     * Mark-to-market value of a single [position] at [markPrice]: signed unrealized PnL =
     * (mark - avgEntry) * qty (qty already carries the sign, so a short profits as the mark falls).
     */
    fun positionMtm(position: PaperPosition, markPrice: Long): Long =
        (markPrice - position.avgEntry) * position.qty

    /**
     * Total unrealized PnL across all open positions, given a [marks] map of symbolId -> mark price.
     * A position with no available mark contributes 0 (unknown, not fabricated).
     */
    fun unrealized(acct: PaperAccount, marks: Map<Int, Long>): Long =
        acct.positions.entries.sumOf { (symbolId, pos) ->
            val mark = marks[symbolId] ?: return@sumOf 0L
            positionMtm(pos, mark)
        }

    /**
     * Account equity = free cash + mark value of every open position (avg-entry basis + its unrealized).
     * Equivalently cash + sum(qty * mark) over positions with a known mark; a position with no mark
     * contributes its cost basis only (mark treated as avgEntry -> 0 unrealized) so equity never jumps on
     * missing data.
     */
    fun equity(acct: PaperAccount, marks: Map<Int, Long>): Long =
        acct.cash + acct.positions.entries.sumOf { (symbolId, pos) ->
            val mark = marks[symbolId] ?: pos.avgEntry
            pos.qty * mark
        }
}
