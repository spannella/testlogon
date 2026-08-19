package com.testlogon.android.feature.markets.chart

import kotlin.math.sqrt

/**
 * Pure, dependency-free technical-indicator math for [CandlestickChart]. Extracted here so it can be
 * unit-tested in isolation (see ChartIndicatorsTest). Every function returns a series aligned 1:1
 * with its input, using `null` for the leading positions where not enough samples exist yet.
 */
internal object ChartIndicators {

    /** Simple moving average aligned 1:1 with [closes]; null until [period] samples are available. */
    fun sma(closes: List<Double>, period: Int): List<Double?> {
        if (period <= 0) return closes.map { null }
        val out = ArrayList<Double?>(closes.size)
        var sum = 0.0
        for (i in closes.indices) {
            sum += closes[i]
            if (i >= period) sum -= closes[i - period]
            out.add(if (i >= period - 1) sum / period else null)
        }
        return out
    }

    /**
     * Exponential moving average aligned 1:1 with [closes]. The EMA is seeded at the first sample and
     * runs continuously, but values are only emitted once [period] samples have been seen (leading
     * positions are null) so the overlay doesn't draw an unstable warm-up head.
     */
    fun ema(closes: List<Double>, period: Int): List<Double?> {
        if (period <= 0 || closes.isEmpty()) return closes.map { null }
        val k = 2.0 / (period + 1)
        val out = ArrayList<Double?>(closes.size)
        var prev = closes[0]
        for (i in closes.indices) {
            prev = if (i == 0) closes[0] else closes[i] * k + prev * (1 - k)
            out.add(if (i >= period - 1) prev else null)
        }
        return out
    }

    /** Rolling population standard deviation over [period], aligned 1:1 with [closes]. */
    fun stdDev(closes: List<Double>, period: Int): List<Double?> {
        if (period <= 0) return closes.map { null }
        val out = ArrayList<Double?>(closes.size)
        for (i in closes.indices) {
            if (i < period - 1) { out.add(null); continue }
            val window = closes.subList(i - period + 1, i + 1)
            val mean = window.average()
            val variance = window.sumOf { (it - mean) * (it - mean) } / period
            out.add(sqrt(variance))
        }
        return out
    }

    /**
     * Session VWAP from cumulative typical-price*volume over volume. [typical] is (high+low+close)/3
     * per bar; [volume] is that bar's volume. Both lists must be the same length.
     */
    fun vwap(typical: List<Double>, volume: List<Double>): List<Double?> {
        var cumPv = 0.0
        var cumV = 0.0
        return typical.indices.map { i ->
            cumPv += typical[i] * volume[i]
            cumV += volume[i]
            if (cumV > 0.0) cumPv / cumV else null
        }
    }

    /** Wilder RSI over [period], aligned 1:1 with [closes]; null until enough samples. */
    fun rsi(closes: List<Double>, period: Int): List<Double?> {
        val out = arrayOfNulls<Double>(closes.size).toMutableList()
        if (closes.size <= period) return out
        var gain = 0.0
        var loss = 0.0
        for (i in 1..period) {
            val ch = closes[i] - closes[i - 1]
            if (ch >= 0) gain += ch else loss -= ch
        }
        var avgGain = gain / period
        var avgLoss = loss / period
        out[period] = if (avgLoss == 0.0) 100.0 else 100.0 - 100.0 / (1 + avgGain / avgLoss)
        for (i in period + 1 until closes.size) {
            val ch = closes[i] - closes[i - 1]
            val g = if (ch >= 0) ch else 0.0
            val l = if (ch < 0) -ch else 0.0
            avgGain = (avgGain * (period - 1) + g) / period
            avgLoss = (avgLoss * (period - 1) + l) / period
            out[i] = if (avgLoss == 0.0) 100.0 else 100.0 - 100.0 / (1 + avgGain / avgLoss)
        }
        return out
    }

    /** MACD(12,26,9): returns (macd line, signal, histogram) each aligned 1:1 with [closes]. */
    fun macd(closes: List<Double>): Triple<List<Double?>, List<Double?>, List<Double?>> {
        val fast = emaSeeded(closes, 12)
        val slow = emaSeeded(closes, 26)
        val macdLine = closes.indices.map { i -> if (i >= 25) fast[i] - slow[i] else null }
        val signal = emaNullable(macdLine, 9)
        val hist = closes.indices.map { i ->
            val m = macdLine[i]
            val s = signal[i]
            if (m != null && s != null) m - s else null
        }
        return Triple(macdLine, signal, hist)
    }

    /** Continuous EMA seeded at the first sample (no leading nulls). */
    fun emaSeeded(closes: List<Double>, period: Int): DoubleArray {
        val k = 2.0 / (period + 1)
        val out = DoubleArray(closes.size)
        for (i in closes.indices) out[i] = if (i == 0) closes[0] else closes[i] * k + out[i - 1] * (1 - k)
        return out
    }

    /** EMA over a series that may have leading nulls; starts once [period] real samples are seen. */
    fun emaNullable(src: List<Double?>, period: Int): List<Double?> {
        val k = 2.0 / (period + 1)
        val out = arrayOfNulls<Double>(src.size).toMutableList()
        var prev: Double? = null
        var count = 0
        for (i in src.indices) {
            val v = src[i] ?: continue
            prev = if (prev == null) v else v * k + prev!! * (1 - k)
            count++
            if (count >= period) out[i] = prev
        }
        return out
    }
}
