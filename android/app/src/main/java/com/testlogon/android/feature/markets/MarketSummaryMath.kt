package com.testlogon.android.feature.markets

/**
 * Pure, dependency-free helpers backing the Markets-list row summary — the sparkline series and the
 * percent-change pill. Extracted from [MarketsViewModel] so the math can be unit-tested in isolation
 * (see MarketSummaryMathTest) and shares one definition of "% change over the sparkline window".
 */
internal object MarketSummaryMath {

    /**
     * The trailing [points] closes used for a row sparkline, in chronological order. Returns an empty
     * list when [closes] is empty; otherwise the last [points] elements (or all of them if fewer).
     */
    fun spark(closes: List<Double>, points: Int): List<Float> {
        if (closes.isEmpty() || points <= 0) return emptyList()
        return closes.takeLast(points).map { it.toFloat() }
    }

    /**
     * Percent change across a window: (last - first) / first * 100. Returns null when the window has
     * fewer than two points or the first value is zero (undefined baseline), so the pill renders "--".
     */
    fun changePct(first: Double, last: Double, windowSize: Int): Double? {
        if (windowSize < 2 || first == 0.0) return null
        return (last - first) / first * 100.0
    }

    /**
     * Convenience over a raw close series: takes the last [points] closes, then computes the percent
     * change from the first to the last close of that window. Null when there is nothing to compare.
     */
    fun changePctOf(closes: List<Double>, points: Int): Double? {
        val window = if (points > 0) closes.takeLast(points) else closes
        if (window.size < 2) return null
        return changePct(window.first(), window.last(), window.size)
    }
}
