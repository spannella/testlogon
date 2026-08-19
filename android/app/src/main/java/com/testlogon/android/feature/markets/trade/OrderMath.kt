package com.testlogon.android.feature.markets.trade

import com.testlogon.android.data.exchange.OrderSide

/**
 * Pure order-entry math for the trade ticket. All prices/quantities are raw int64 ticks (scaler = 1),
 * matching the rest of the trading stack. Every function is side-effect free and null/zero-guarded so
 * it can be unit-tested and called freely from Compose recomposition.
 *
 * Margin impact + estimated liquidation price rely on per-symbol initial/maintenance margin bps that
 * the live feeds do NOT currently expose to the client (only the admin config form + the liquidation-fee
 * bps from the fee schedule are readable). When real bps aren't available the UI falls back to
 * [DEFAULT_INITIAL_MARGIN_BPS]/[DEFAULT_MAINTENANCE_MARGIN_BPS] and tags the numbers "(est.)" so a
 * fabricated precise figure is never shown as authoritative.
 */
object OrderMath {

    /** Assumed venue defaults used ONLY when the symbol's real margin bps are unreadable (tag as est.). */
    const val DEFAULT_INITIAL_MARGIN_BPS = 1000L      // 10%  (10x max leverage)
    const val DEFAULT_MAINTENANCE_MARGIN_BPS = 500L   // 5%

    /** Exact notional = price x qty. Null when either input is missing; never negative for sane inputs. */
    fun notional(price: Long?, qty: Long?): Long? {
        if (price == null || qty == null) return null
        return price * qty
    }

    /**
     * Max whole quantity affordable at [price] from [available] balance, with no leverage
     * (available / price, floored). Returns 0 when price/available are non-positive.
     */
    fun maxQtyForBalance(available: Long?, price: Long?): Long {
        if (available == null || price == null || price <= 0L || available <= 0L) return 0L
        return available / price
    }

    /**
     * A percentage [pct] (0..100) of the max affordable quantity at [price]. A positive pct floors to at
     * least 1 (so "25%" of a tiny balance still stages a tradeable qty); 0 stays 0.
     */
    fun qtyForPercent(available: Long?, price: Long?, pct: Int): Long {
        val max = maxQtyForBalance(available, price)
        if (max <= 0L) return 0L
        val q = max * pct.toLong() / 100L
        return if (pct > 0) q.coerceAtLeast(1L) else 0L
    }

    /**
     * Position size from a fixed risk budget: qty = floor(riskAmount / |entry - stop|). The stop distance
     * is the per-unit loss if the stop is hit, so risk / loss-per-unit = units to buy. Returns 0 when the
     * risk amount is non-positive or entry == stop (zero/undefined distance).
     */
    fun riskSizedQty(riskAmount: Long?, entry: Long?, stop: Long?): Long {
        if (riskAmount == null || entry == null || stop == null) return 0L
        if (riskAmount <= 0L) return 0L
        val dist = kotlin.math.abs(entry - stop)
        if (dist <= 0L) return 0L
        return riskAmount / dist
    }

    /**
     * Initial margin a position of [notional] locks at [initialMarginBps] bps (round to nearest tick).
     * 0 when inputs are non-positive.
     */
    fun marginRequired(notional: Long?, initialMarginBps: Long): Long {
        if (notional == null || notional <= 0L || initialMarginBps <= 0L) return 0L
        return Math.round(notional.toDouble() * initialMarginBps.toDouble() / 10_000.0)
    }

    /**
     * Estimated liquidation price for a fresh position opened at [entry] on [side], given the
     * [maintenanceMarginBps]. Long liquidates below entry, short above, by the maintenance fraction:
     *   long:  entry * (1 - mmr)
     *   short: entry * (1 + mmr)
     * where mmr = maintenanceMarginBps / 10000. Null when entry is non-positive. This is a first-order
     * estimate (ignores fees, funding, cross-margin from other positions) and must be surfaced as "(est.)".
     */
    fun estLiquidationPrice(entry: Long?, side: OrderSide, maintenanceMarginBps: Long): Long? {
        if (entry == null || entry <= 0L) return null
        if (maintenanceMarginBps <= 0L) return null
        val mmr = maintenanceMarginBps.toDouble() / 10_000.0
        val factor = if (side == OrderSide.BUY) (1.0 - mmr) else (1.0 + mmr)
        val liq = Math.round(entry.toDouble() * factor)
        return liq.coerceAtLeast(0L)
    }
}
