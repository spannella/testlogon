package com.testlogon.android.feature.markets.trade

import com.testlogon.android.data.exchange.OrderSide

/**
 * Extended pure order-entry math for the trade ticket depth features: position sizing, risk:reward,
 * bracket break-even, an estimated liquidation preview, and the client-side TWAP / Iceberg algo splits.
 *
 * Sits alongside [OrderMath] (which owns notional / buying-power / basic risk sizing + est. liquidation).
 * [OrderCalc] adds the bracket + algo-scheduling math. Everything is side-effect free and guards
 * degenerate inputs (nulls, non-positive prices/qty, zero distances, zero slices) so it can be called
 * freely from Compose recomposition and unit-tested on the JVM. All prices/quantities are raw int64
 * ticks (scaler = 1), matching the rest of the trading stack.
 */
object OrderCalc {

    /**
     * Position size from a risk budget expressed as a PERCENT of account equity: risk = equity * pct/100,
     * then qty = floor(risk / |entry - stop|). Mirrors [OrderMath.riskSizedQty] but takes the risk % +
     * equity rather than a pre-computed risk amount. Returns 0 for any degenerate input (null equity,
     * pct <= 0, entry == stop, missing prices).
     */
    fun positionSizeQty(equity: Long?, riskPct: Int, entry: Long?, stop: Long?): Long {
        if (equity == null || entry == null || stop == null) return 0L
        if (equity <= 0L || riskPct <= 0) return 0L
        val dist = kotlin.math.abs(entry - stop)
        if (dist <= 0L) return 0L
        val riskAmount = equity * riskPct.toLong() / 100L
        if (riskAmount <= 0L) return 0L
        return riskAmount / dist
    }

    /**
     * Risk:reward for a bracket. Risk = |entry - stop|, Reward = |takeProfit - entry|; the ratio is
     * reward/risk. Null when any leg is missing or the risk distance is zero (undefined ratio). The
     * ratio is returned as a Double for display (e.g. 2.5 == "2.5:1"); the raw distances are exposed so
     * the UI can show them without recomputing.
     */
    data class RiskReward(val risk: Long, val reward: Long, val ratio: Double)

    fun riskReward(entry: Long?, stop: Long?, takeProfit: Long?): RiskReward? {
        if (entry == null || stop == null || takeProfit == null) return null
        val risk = kotlin.math.abs(entry - stop)
        val reward = kotlin.math.abs(takeProfit - entry)
        if (risk <= 0L) return null
        return RiskReward(risk = risk, reward = reward, ratio = reward.toDouble() / risk.toDouble())
    }

    /**
     * Estimated liquidation price for a fresh position — a thin, [side]-aware wrapper over
     * [OrderMath.estLiquidationPrice] so the depth UI has a single call site. First-order estimate
     * (ignores fees / funding / cross-margin); surface as "(est.)". Null when entry/bps are non-positive.
     */
    fun liquidationPreview(entry: Long?, side: OrderSide, maintenanceMarginBps: Long): Long? =
        OrderMath.estLiquidationPrice(entry, side, maintenanceMarginBps)

    /**
     * Break-even price for a position after round-trip taker fees, in ticks. A BUY must exit high enough
     * to cover the entry + exit fee; a SELL low enough. feeBps applies to notional on each side, so the
     * combined drag is ~2 * feeBps; break-even = entry * (1 +/- 2*feeBps/10000). feeBps <= 0 -> break-even
     * is just the entry. Null when entry is non-positive.
     */
    fun breakevenPrice(entry: Long?, side: OrderSide, feeBps: Long): Long? {
        if (entry == null || entry <= 0L) return null
        if (feeBps <= 0L) return entry
        val drag = 2.0 * feeBps.toDouble() / 10_000.0
        val factor = if (side == OrderSide.BUY) (1.0 + drag) else (1.0 - drag)
        return Math.round(entry.toDouble() * factor).coerceAtLeast(0L)
    }

    /**
     * A single TWAP child slice: which slice (1-based), the qty for it, and the offset (ms from start)
     * at which it should fire.
     */
    data class TwapSlice(val index: Int, val qty: Long, val offsetMs: Long)

    /**
     * Even TWAP schedule for [totalQty] over [slices] evenly spaced across [durationMs]. The base per-slice
     * qty is floor(total/slices); the remainder is spread one-unit-each onto the EARLIEST slices so the sum
     * of the schedule always equals [totalQty] exactly. Slice i fires at offset i * durationMs/slices
     * (slice 1 at t=0). Returns an empty list for degenerate inputs (qty <= 0, slices <= 0, or slices >
     * totalQty which would create zero-qty children). Duration < 0 is clamped to 0 (all fire immediately).
     */
    fun twapSchedule(totalQty: Long, slices: Int, durationMs: Long): List<TwapSlice> {
        if (totalQty <= 0L || slices <= 0) return emptyList()
        if (slices.toLong() > totalQty) return emptyList()   // would create zero-qty children
        val dur = durationMs.coerceAtLeast(0L)
        val base = totalQty / slices
        var remainder = totalQty - base * slices              // 0 .. slices-1
        val step = dur / slices                               // even spacing; slice 1 at t=0
        val out = ArrayList<TwapSlice>(slices)
        for (i in 0 until slices) {
            val extra = if (remainder > 0L) 1L else 0L
            if (remainder > 0L) remainder--
            out.add(TwapSlice(index = i + 1, qty = base + extra, offsetMs = i.toLong() * step))
        }
        return out
    }

    /**
     * Split [totalQty] into visible-sized iceberg clips of [visibleQty] each, the last clip holding the
     * remainder. E.g. total 100, visible 30 -> [30, 30, 30, 10]. Returns an empty list for degenerate
     * inputs (total <= 0, visible <= 0). A visible >= total yields a single clip == total.
     */
    fun icebergClips(totalQty: Long, visibleQty: Long): List<Long> {
        if (totalQty <= 0L || visibleQty <= 0L) return emptyList()
        val out = ArrayList<Long>()
        var remaining = totalQty
        while (remaining > 0L) {
            val clip = kotlin.math.min(visibleQty, remaining)
            out.add(clip)
            remaining -= clip
        }
        return out
    }
}
