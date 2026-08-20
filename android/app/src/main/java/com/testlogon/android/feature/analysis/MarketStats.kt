package com.testlogon.android.feature.analysis

import kotlin.math.ln
import kotlin.math.sqrt

/**
 * Pure, framework-free market-statistics math for the Analysis workbench. No Android/Compose imports
 * so it can be unit-tested on the JVM (see MarketStatsTest). Every helper takes plain price/return
 * series (chronological, oldest-first) and returns render-ready primitives. Edge cases (empty / single
 * bar / zero baseline) return null or an identity value rather than throwing.
 */
object MarketStats {

    /** ~trading periods per year used to annualize a per-bar volatility (approx calendar days). */
    const val ANNUALIZATION_PERIODS = 365.0

    /** Simple period return (last-first)/first as a fraction. Null when <2 points or a zero baseline. */
    fun periodReturn(closes: List<Double>): Double? {
        if (closes.size < 2) return null
        val first = closes.first()
        if (first == 0.0) return null
        return (closes.last() - first) / first
    }

    /** Alias for [periodReturn] as a percent (x100). */
    fun cumulativeReturnPct(closes: List<Double>): Double? = periodReturn(closes)?.let { it * 100.0 }

    /**
     * Per-step log returns ln(p_i / p_prev), aligned to the gaps between consecutive closes (so a
     * series of N closes yields N-1 returns). Non-positive prices are skipped (log undefined).
     */
    fun logReturns(closes: List<Double>): List<Double> {
        if (closes.size < 2) return emptyList()
        val out = ArrayList<Double>(closes.size - 1)
        for (i in 1 until closes.size) {
            val prev = closes[i - 1]
            val cur = closes[i]
            if (prev > 0.0 && cur > 0.0) out.add(ln(cur / prev))
        }
        return out
    }

    /** Sample standard deviation of a series. Null when fewer than two samples. */
    fun stdev(values: List<Double>): Double? {
        if (values.size < 2) return null
        val mean = values.average()
        val variance = values.sumOf { (it - mean) * (it - mean) } / (values.size - 1)
        return sqrt(variance)
    }

    /**
     * Annualized volatility: sample stdev of log-returns scaled by sqrt([periodsPerYear]). Null when
     * there are not enough returns to form a stdev. Returned as a fraction (0.25 == 25% vol).
     */
    fun annualizedVolatility(
        closes: List<Double>,
        periodsPerYear: Double = ANNUALIZATION_PERIODS,
    ): Double? {
        val sd = stdev(logReturns(closes)) ?: return null
        return sd * sqrt(periodsPerYear)
    }

    /**
     * Maximum drawdown as a POSITIVE fraction: the largest peak-to-trough decline over the series.
     * 0.0 for a monotonically non-decreasing series; null for empty input. A 100 to 50 dip returns 0.5.
     */
    fun maxDrawdown(closes: List<Double>): Double? {
        if (closes.isEmpty()) return null
        var peak = closes.first()
        var maxDd = 0.0
        for (c in closes) {
            if (c > peak) peak = c
            if (peak > 0.0) {
                val dd = (peak - c) / peak
                if (dd > maxDd) maxDd = dd
            }
        }
        return maxDd
    }

    /** Highest close in the series, or null when empty. */
    fun high(closes: List<Double>): Double? = closes.maxOrNull()

    /** Lowest close in the series, or null when empty. */
    fun low(closes: List<Double>): Double? = closes.minOrNull()

    /** Average of a series, or null when empty. */
    fun average(values: List<Double>): Double? = if (values.isEmpty()) null else values.average()

    /** Sum of a series (0.0 when empty). */
    fun total(values: List<Double>): Double = values.sum()

    /**
     * Pearson correlation of two aligned series over their common leading length. Null when fewer
     * than two overlapping points or when either side has zero variance (undefined correlation).
     * Result is clamped to the range minus-one..one to absorb floating-point overshoot.
     */
    fun correlation(a: List<Double>, b: List<Double>): Double? {
        val n = minOf(a.size, b.size)
        if (n < 2) return null
        val xs = a.subList(0, n)
        val ys = b.subList(0, n)
        val mx = xs.average()
        val my = ys.average()
        var sxy = 0.0
        var sxx = 0.0
        var syy = 0.0
        for (i in 0 until n) {
            val dx = xs[i] - mx
            val dy = ys[i] - my
            sxy += dx * dy
            sxx += dx * dx
            syy += dy * dy
        }
        if (sxx == 0.0 || syy == 0.0) return null
        val r = sxy / sqrt(sxx * syy)
        return r.coerceIn(-1.0, 1.0)
    }

    /**
     * Normalize a close series to a base of 100 at its first point, for a multi-symbol overlay. Empty
     * or zero-baseline input returns an empty list (nothing meaningful to overlay).
     */
    fun normalizeToBase(closes: List<Double>, base: Double = 100.0): List<Double> {
        val first = closes.firstOrNull() ?: return emptyList()
        if (first == 0.0) return emptyList()
        return closes.map { it / first * base }
    }

    /**
     * A simple fast/slow SMA-cross backtest over [closes]. Position is LONG when fast SMA > slow SMA,
     * else FLAT; entries/exits act on the NEXT bar (no look-ahead). Returns a [BacktestResult] with
     * the equity curve (starts at 1.0), total return fraction, win rate, and trade count.
     */
    fun backtestMaCross(closes: List<Double>, fast: Int, slow: Int): BacktestResult {
        if (fast <= 0 || slow <= 0 || fast >= slow || closes.size < slow + 1) {
            return BacktestResult(equityCurve = listOf(1.0), totalReturn = 0.0, winRate = 0.0, trades = 0)
        }
        val fastSma = sma(closes, fast)
        val slowSma = sma(closes, slow)

        val equity = ArrayList<Double>(closes.size)
        var cash = 1.0
        equity.add(cash)

        var inPosition = false
        var entryPrice = 0.0
        var trades = 0
        var wins = 0

        // Signal at bar i (using SMAs up to i) is acted on the return from i to i+1.
        for (i in 0 until closes.size - 1) {
            val f = fastSma[i]
            val s = slowSma[i]
            val wantLong = f != null && s != null && f > s

            if (wantLong && !inPosition) {
                inPosition = true
                entryPrice = closes[i]
                trades++
            } else if (!wantLong && inPosition) {
                inPosition = false
                if (closes[i] > entryPrice) wins++
            }

            // Apply this bar-to-next return only while holding.
            if (inPosition && closes[i] != 0.0) {
                cash *= closes[i + 1] / closes[i]
            }
            equity.add(cash)
        }
        // Close any open position at the final bar for win/trade accounting.
        if (inPosition) {
            if (closes.last() > entryPrice) wins++
        }

        val total = cash - 1.0
        val winRate = if (trades == 0) 0.0 else wins.toDouble() / trades
        return BacktestResult(equityCurve = equity, totalReturn = total, winRate = winRate, trades = trades)
    }

    /** Simple moving average aligned 1:1 with [values]; null until [period] samples are available. */
    fun sma(values: List<Double>, period: Int): List<Double?> {
        if (period <= 0) return values.map { null }
        val out = ArrayList<Double?>(values.size)
        var sum = 0.0
        for (i in values.indices) {
            sum += values[i]
            if (i >= period) sum -= values[i - period]
            out.add(if (i >= period - 1) sum / period else null)
        }
        return out
    }
}

/** Result of [MarketStats.backtestMaCross]: the equity curve plus summary stats. */
data class BacktestResult(
    val equityCurve: List<Double>,
    val totalReturn: Double,
    val winRate: Double,
    val trades: Int,
)
