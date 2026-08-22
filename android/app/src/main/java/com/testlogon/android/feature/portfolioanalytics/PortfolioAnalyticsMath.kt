package com.testlogon.android.feature.portfolioanalytics

import kotlin.math.abs
import kotlin.math.max
import kotlin.math.sqrt

/**
 * Pure, framework-free portfolio analytics math for the "how am I positioned / what is my risk"
 * surface. No Android/Compose/coroutine imports so it is unit-testable on the JVM (see
 * PortfolioAnalyticsMathTest). Every function guards its edge cases (empty / single / zero-equity /
 * degenerate matrix) with a null or identity value rather than throwing.
 *
 * The ViewModel normalizes every holding (custody / spot / margin / creator tokens / strategy funds /
 * staking) into a [NormalizedPosition] with an indicative USD [valueCents], then these helpers compute
 * allocation, concentration, exposure, portfolio volatility, VaR and a diversification score. All
 * monetary inputs/outputs are integer CENTS; all weights are BASIS POINTS (10_000 bps == 100%).
 */

/** Which side of the book a position sits on (drives gross/net/long/short exposure). */
enum class PositionSide { LONG, SHORT }

/** How to bucket holdings for the allocation breakdown. */
enum class AllocationBy { ASSET, CLASS, PRODUCT }

/**
 * One normalized holding across every venue, reduced to the fields the analytics need.
 *
 * [key] is the stable dedupe/return-series key (usually an uppercase asset symbol, e.g. "BTC");
 * [label] is the human row label; [group] is the PRODUCT bucket (venue/product family, e.g. "Spot");
 * [assetClass] is the CLASS bucket (e.g. "Crypto", "Cash", "Fund"); [valueCents] is the indicative
 * USD gross value (magnitude used); [side] is LONG/SHORT; [qty] is informational.
 */
data class NormalizedPosition(
    val key: String,
    val label: String,
    val group: String,
    val assetClass: String,
    val valueCents: Long,
    val side: PositionSide = PositionSide.LONG,
    val qty: Double = 0.0,
)

/** One weighted breakdown slice: a bucket [key], its gross [valueCents], and its [weightBps]. */
data class AllocationSlice(
    val key: String,
    val valueCents: Long,
    val weightBps: Int,
)

/** Concentration read: Herfindahl-Hirschman Index over weights plus the topN cumulative weight. */
data class Concentration(
    val hhi: Int,
    val topWeightBps: Int,
    val topKey: String?,
    val topNCumulativeBps: Int,
    val n: Int,
) {
    /** Effective number of independent bets (1/normalized-HHI); 0 when there is nothing to hold. */
    val effectiveBets: Double get() = if (hhi <= 0) 0.0 else 10_000.0 / hhi
}

/** Gross/net/long/short exposure (all cents) plus leverage vs net equity (bps; 10_000 == 1.0x). */
data class Exposure(
    val grossCents: Long,
    val netCents: Long,
    val longCents: Long,
    val shortCents: Long,
    val leverageBps: Int,
)

object PortfolioAnalyticsMath {

    /** Total gross USD value across positions (sum of magnitudes), in cents. */
    fun totalValueCents(positions: List<NormalizedPosition>): Long =
        positions.sumOf { abs(it.valueCents) }

    /**
     * Weighted allocation breakdown bucketed [by] ASSET/CLASS/PRODUCT. Each slice carries its summed
     * gross value and its weight in bps of the total gross. Empty input -> empty list; a zero-total
     * (all positions worth 0) -> slices with 0 bps (no divide-by-zero). Sorted descending by value.
     */
    fun allocation(positions: List<NormalizedPosition>, by: AllocationBy): List<AllocationSlice> {
        if (positions.isEmpty()) return emptyList()
        val grouped = positions.groupBy {
            when (by) {
                AllocationBy.ASSET -> it.key
                AllocationBy.CLASS -> it.assetClass
                AllocationBy.PRODUCT -> it.group
            }
        }
        val total = totalValueCents(positions)
        return grouped.map { (k, ps) ->
            val v = ps.sumOf { abs(it.valueCents) }
            AllocationSlice(key = k, valueCents = v, weightBps = bpsOf(v, total))
        }.sortedByDescending { it.valueCents }
    }

    /** The weight-in-bps vector implied by a set of allocation slices (order preserved). */
    fun weightsBps(slices: List<AllocationSlice>): List<Int> = slices.map { it.weightBps }

    /**
     * Concentration over a set of allocation slices. HHI = sum(w_i^2) with w_i as a FRACTION, scaled
     * back to a 0..10_000 index (10_000 == a single 100% holding; ~0 == perfectly diffuse). [topN]
     * cumulative weight is the sum of the largest N weights. Empty -> a zeroed read.
     */
    fun concentration(slices: List<AllocationSlice>, topN: Int = 3): Concentration {
        if (slices.isEmpty()) return Concentration(hhi = 0, topWeightBps = 0, topKey = null, topNCumulativeBps = 0, n = 0)
        val sorted = slices.sortedByDescending { it.weightBps }
        // HHI: sum of squared fractional weights, rescaled to the conventional 0..10_000 index.
        val hhi = sorted.sumOf { s ->
            val frac = s.weightBps / 10_000.0
            frac * frac
        } * 10_000.0
        val top = sorted.first()
        val cum = sorted.take(topN.coerceAtLeast(1)).sumOf { it.weightBps }
        return Concentration(
            hhi = hhi.toInt().coerceIn(0, 10_000),
            topWeightBps = top.weightBps,
            topKey = top.key,
            topNCumulativeBps = cum.coerceAtMost(10_000),
            n = slices.size,
        )
    }

    /**
     * Gross/net/long/short exposure (cents) + leverage. Long value is positive, short value negative in
     * the NET sum; gross is the sum of magnitudes. Leverage = gross / |net| in bps (10_000 == 1.0x);
     * when net is 0 (perfectly hedged) leverage is 0 to avoid a divide-by-zero blow-up.
     */
    fun exposure(positions: List<NormalizedPosition>): Exposure {
        var longC = 0L
        var shortC = 0L
        for (p in positions) {
            val v = abs(p.valueCents)
            if (p.side == PositionSide.SHORT) shortC += v else longC += v
        }
        val gross = longC + shortC
        val net = longC - shortC
        val leverage = if (net == 0L) 0 else Math.round(gross.toDouble() / abs(net).toDouble() * 10_000.0).toInt()
        return Exposure(grossCents = gross, netCents = net, longCents = longC, shortCents = shortC, leverageBps = leverage)
    }

    /**
     * Portfolio volatility (bps) via the covariance combine sigma_p = sqrt(w^T C w), where C_ij =
     * rho_ij * sigma_i * sigma_j. [weightsBps] and [perAssetVolBps] are aligned index-for-index;
     * [correlationMatrix] is NxN (row-major) with 1.0 on the diagonal. A missing/short matrix falls
     * back to the ASSUME-INDEPENDENT diagonal (rho=0 off-diagonal). Empty/degenerate input -> null.
     * Weights are treated as fractions of the whole (bps/10_000); a single asset returns its own vol.
     */
    fun portfolioVolatilityBps(
        weightsBps: List<Int>,
        perAssetVolBps: List<Int>,
        correlationMatrix: List<List<Double>>? = null,
    ): Int? {
        val n = minOf(weightsBps.size, perAssetVolBps.size)
        if (n == 0) return null
        val w = DoubleArray(n) { weightsBps[it] / 10_000.0 }
        val s = DoubleArray(n) { perAssetVolBps[it] / 10_000.0 }
        var variance = 0.0
        for (i in 0 until n) {
            for (j in 0 until n) {
                val rho = when {
                    i == j -> 1.0
                    correlationMatrix != null && i < correlationMatrix.size && j < correlationMatrix[i].size ->
                        correlationMatrix[i][j].coerceIn(-1.0, 1.0)
                    else -> 0.0
                }
                variance += w[i] * w[j] * s[i] * s[j] * rho
            }
        }
        if (variance <= 0.0) return 0
        return (sqrt(variance) * 10_000.0).toInt().coerceAtLeast(0)
    }

    /**
     * Parametric (variance-covariance) Value-at-Risk in CENTS: VaR = value * volFraction * z, where
     * [volBps] is the horizon volatility in bps and [z] is the confidence z-score (1.645 == 95%,
     * 2.326 == 99%). A non-positive value or vol -> 0. Returned as a positive cents figure (a loss).
     */
    fun parametricVarCents(valueCents: Long, volBps: Int, z: Double): Long {
        if (valueCents <= 0L || volBps <= 0) return 0L
        val vol = volBps / 10_000.0
        return max(0.0, valueCents * vol * z).toLong()
    }

    /**
     * Historical VaR in CENTS from a series of periodic portfolio [returns] (fractions, e.g. -0.03) at
     * a [confidence] (0..1, e.g. 0.95). Takes the (1-confidence) worst-quantile loss and scales it by
     * the current [valueCents]. Fewer than two returns -> 0 (nothing to rank). The result is a positive
     * cents loss figure (0 when the quantile return is non-negative).
     */
    fun historicalVarCents(valueCents: Long, returns: List<Double>, confidence: Double): Long {
        if (valueCents <= 0L || returns.size < 2) return 0L
        val c = confidence.coerceIn(0.0, 0.999)
        val sorted = returns.sorted() // ascending: worst (most negative) first
        // Quantile index at the lower tail: floor((1 - c) * N), clamped into range.
        val idx = ((1.0 - c) * sorted.size).toInt().coerceIn(0, sorted.size - 1)
        val quantileReturn = sorted[idx]
        if (quantileReturn >= 0.0) return 0L
        return max(0.0, valueCents * -quantileReturn).toLong()
    }

    /**
     * A 0..100 diversification score. Combines HOW SPREAD the weights are (1 - normalized HHI) with HOW
     * UNCORRELATED the book is (1 - average absolute pairwise correlation, weight-weighted). A single
     * holding scores 0; many equal, uncorrelated holdings approach 100. Empty -> 0. When no correlation
     * matrix is supplied the correlation term is treated as fully diversifying (independent assumption).
     */
    fun diversificationScore(
        weightsBps: List<Int>,
        correlationMatrix: List<List<Double>>? = null,
    ): Int {
        val n = weightsBps.size
        if (n == 0) return 0
        if (n == 1) return 0
        val w = weightsBps.map { it / 10_000.0 }
        // Spread term: 1 - normalized HHI, where normalized HHI in [1/n, 1] maps to [0, 1].
        val hhi = w.sumOf { it * it }
        val minHhi = 1.0 / n
        val spread = if (1.0 - minHhi <= 0.0) 0.0 else ((1.0 - hhi) / (1.0 - minHhi)).coerceIn(0.0, 1.0)
        // Correlation term: 1 - weight-weighted average |rho| over distinct pairs.
        val corrTerm: Double = if (correlationMatrix == null) {
            1.0
        } else {
            var wsum = 0.0
            var acc = 0.0
            for (i in 0 until n) {
                for (j in i + 1 until n) {
                    val rho = if (i < correlationMatrix.size && j < correlationMatrix[i].size)
                        abs(correlationMatrix[i][j].coerceIn(-1.0, 1.0)) else 0.0
                    val pairW = w[i] * w[j]
                    acc += pairW * rho
                    wsum += pairW
                }
            }
            if (wsum <= 0.0) 1.0 else (1.0 - (acc / wsum)).coerceIn(0.0, 1.0)
        }
        val score = 100.0 * (0.5 * spread + 0.5 * corrTerm)
        return score.toInt().coerceIn(0, 100)
    }

    /** value/total as bps (0 when total <= 0), rounded to nearest, clamped to 0..10_000. */
    private fun bpsOf(value: Long, total: Long): Int {
        if (total <= 0L) return 0
        val bps = Math.round(value.toDouble() / total.toDouble() * 10_000.0)
        return bps.toInt().coerceIn(0, 10_000)
    }
}
