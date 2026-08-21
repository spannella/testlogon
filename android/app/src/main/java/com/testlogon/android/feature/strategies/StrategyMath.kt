package com.testlogon.android.feature.strategies

import com.testlogon.android.data.strategies.StrategyLeg

/**
 * Pure, side-effect-free math for the USER-CREATED STRATEGIES / BASKETS surface. Extracted so the
 * tricky bits (NAV unit issuance/redemption, dual-fee accrual with a high-water mark, weight
 * validation, min-size + capacity checks, and the client-side basket backtest) are unit-testable off
 * the Android runtime (see StrategyMathTest). All amounts are integer CENTS; `Bps` are basis points
 * (10_000 bps == 100%). NAV per unit is carried in cents.
 *
 * The fund is a POOLED fund with NAV units — an ASSUMPTION surfaced in the UI (see the pooled-NAV note
 * on the detail screen) so it can be flipped to copy/replication later without touching the rest of
 * the surface.
 */
object StrategyMath {

    /** Basis-points denominator: 10_000 bps == 100%. */
    const val BPS_DENOM: Int = 10_000

    /** The par NAV per unit at inception, in cents ($1.00 per unit). */
    const val PAR_NAV_CENTS: Long = 100L

    /** Approximate calendar days per year used to annualize the management-fee accrual. */
    const val DAYS_PER_YEAR: Double = 365.0

    // ---- Weight validation -------------------------------------------------

    /** Sum of every leg weight in bps (may exceed / fall short of 10_000). */
    fun totalWeightBps(legs: List<StrategyLeg>): Int = legs.sumOf { it.weightBps.coerceAtLeast(0) }

    /**
     * True when the basket is a valid target: at least one leg, no non-positive weight, and the
     * weights sum to EXACTLY 10_000 bps (100%).
     */
    fun weightsValid(legs: List<StrategyLeg>): Boolean =
        legs.isNotEmpty() &&
            legs.all { it.weightBps > 0 && it.symbolId > 0 } &&
            totalWeightBps(legs) == BPS_DENOM

    // ---- NAV unit math -----------------------------------------------------

    /**
     * Units issued for an [amountCents] subscription at [navPerUnitCents]. Units are carried at
     * 1e-6-unit granularity (micro-units) so small NAV moves don't round a subscription to zero:
     * `floor(amount * 1_000_000 / nav)`. A non-positive NAV or amount yields 0.
     */
    fun unitsForInvestment(amountCents: Long, navPerUnitCents: Long): Long {
        if (amountCents <= 0L || navPerUnitCents <= 0L) return 0L
        return (amountCents * UNIT_SCALE) / navPerUnitCents
    }

    /**
     * Cash proceeds (cents, floored) for redeeming [units] micro-units at [navPerUnitCents]:
     * `floor(units * nav / 1_000_000)`. Non-positive inputs yield 0.
     */
    fun proceedsForUnits(units: Long, navPerUnitCents: Long): Long {
        if (units <= 0L || navPerUnitCents <= 0L) return 0L
        return (units * navPerUnitCents) / UNIT_SCALE
    }

    /**
     * NAV per unit (cents) for a fund holding [aumCents] across [unitsOutstanding] micro-units:
     * `aum * 1_000_000 / units`. Falls back to [PAR_NAV_CENTS] when there are no units outstanding
     * (a fresh fund prices its first subscription at par).
     */
    fun navPerUnit(aumCents: Long, unitsOutstanding: Long): Long {
        if (unitsOutstanding <= 0L) return PAR_NAV_CENTS
        return (aumCents.coerceAtLeast(0L) * UNIT_SCALE) / unitsOutstanding
    }

    // ---- Fee accrual -------------------------------------------------------

    /**
     * Management fee accrued over [days] on an [aumCents] base at [mgmtFeeBps] ANNUAL:
     * `aum * mgmtFeeBps/10_000 * days/365`, rounded half-up to the nearest cent. Never negative.
     */
    fun mgmtFeeAccrual(aumCents: Long, mgmtFeeBps: Int, days: Double): Long {
        if (aumCents <= 0L || mgmtFeeBps <= 0 || days <= 0.0) return 0L
        val annual = aumCents.toDouble() * mgmtFeeBps / BPS_DENOM
        val accrued = annual * (days / DAYS_PER_YEAR)
        return Math.round(accrued).coerceAtLeast(0L)
    }

    /**
     * Performance fee on profit ABOVE a high-water mark. Charged only on the gain of the current NAV
     * ([navPerUnitCents]) over the prior [highWaterMarkCents], applied to [units] micro-units:
     * `perfFeeBps/10_000 * (nav - hwm) * units/1_000_000`. Zero when NAV is at/below the HWM (no fee
     * on a recovery back to the mark) or when there is no profit. Rounded half-up; never negative.
     */
    fun perfFee(
        navPerUnitCents: Long,
        highWaterMarkCents: Long,
        units: Long,
        perfFeeBps: Int,
    ): Long {
        if (perfFeeBps <= 0 || units <= 0L) return 0L
        val gainPerUnit = navPerUnitCents - highWaterMarkCents
        if (gainPerUnit <= 0L) return 0L
        val profitCents = gainPerUnit.toDouble() * units / UNIT_SCALE
        val fee = profitCents * perfFeeBps / BPS_DENOM
        return Math.round(fee).coerceAtLeast(0L)
    }

    /**
     * The new high-water mark after observing [navPerUnitCents]: the mark only ratchets UP (a
     * performance fee is never charged twice on the same peak). Equal to `max(prior, nav)`.
     */
    fun updatedHighWaterMark(priorHwmCents: Long, navPerUnitCents: Long): Long =
        maxOf(priorHwmCents, navPerUnitCents)

    // ---- Size + capacity checks -------------------------------------------

    /** True when [amountCents] meets the [minInvestmentCents] floor (a 0/absent floor always passes). */
    fun meetsMinInvestment(amountCents: Long, minInvestmentCents: Long): Boolean =
        amountCents > 0L && amountCents >= minInvestmentCents.coerceAtLeast(0L)

    /** Remaining capacity in cents = `max(0, maxAum - currentAum)`; a 0/absent max means uncapped (null). */
    fun capacityRemaining(maxAumCents: Long, currentAumCents: Long): Long? {
        if (maxAumCents <= 0L) return null
        return (maxAumCents - currentAumCents.coerceAtLeast(0L)).coerceAtLeast(0L)
    }

    /**
     * True when an [amountCents] subscription fits the remaining capacity. An uncapped fund
     * (max AUM <= 0) always fits; otherwise the subscription must not push AUM past the cap.
     */
    fun withinCapacity(amountCents: Long, maxAumCents: Long, currentAumCents: Long): Boolean {
        val remaining = capacityRemaining(maxAumCents, currentAumCents) ?: return true
        return amountCents in 1L..remaining
    }

    // ---- Basket backtest ---------------------------------------------------

    /**
     * Client-side basket backtest: given per-leg close series (chronological, oldest-first) each with
     * its target weight in bps, build the portfolio EQUITY CURVE (base 1.0) of a weight-target basket.
     *
     * Each leg is normalized to base 1.0 at its first observation; the portfolio value at each step is
     * the weight-weighted sum of the legs' normalized levels (a periodically-rebalanced-to-target
     * approximation). Series are truncated to their common leading length so a short leg never
     * fabricates data. Returns a single-point [1.0] curve when there is nothing to compute.
     *
     * Weights are normalized by their own sum, so an off-100% draft still produces a sensible preview.
     */
    fun basketEquityCurve(legs: List<BacktestLeg>): List<Double> {
        val usable = legs.filter { it.closes.size >= 2 && it.weightBps > 0 }
        if (usable.isEmpty()) return listOf(1.0)
        val n = usable.minOf { it.closes.size }
        if (n < 2) return listOf(1.0)
        val weightSum = usable.sumOf { it.weightBps.toDouble() }
        if (weightSum <= 0.0) return listOf(1.0)

        // Per-leg normalized level series (base 1.0 at its first common point).
        val normalized = usable.map { leg ->
            val base = leg.closes[0]
            val w = leg.weightBps / weightSum
            Pair(w, DoubleArray(n) { i -> if (base != 0.0) leg.closes[i] / base else 1.0 })
        }

        val curve = ArrayList<Double>(n)
        for (i in 0 until n) {
            var v = 0.0
            for ((w, series) in normalized) v += w * series[i]
            curve.add(v)
        }
        return curve
    }

    /** Total return fraction of an equity [curve] (last/first - 1). 0.0 for a degenerate curve. */
    fun totalReturn(curve: List<Double>): Double {
        if (curve.size < 2) return 0.0
        val first = curve.first()
        if (first == 0.0) return 0.0
        return curve.last() / first - 1.0
    }

    // ---- Formatting --------------------------------------------------------

    /** Human label for a basis-points value, e.g. 250 -> "2.50%", 10000 -> "100.00%". */
    fun formatBps(bps: Int): String = String.format("%.2f%%", bps / 100.0)

    /** Format integer cents as a dollar string, e.g. 10000 -> "$100.00", -50 -> "-$0.50". */
    fun formatCents(cents: Long): String {
        val sign = if (cents < 0) "-" else ""
        val abs = kotlin.math.abs(cents)
        return "$sign$" + String.format("%,d.%02d", abs / 100, abs % 100)
    }

    /** Format a NAV-per-unit (cents) at 4 decimals of a dollar, e.g. 100 -> "$1.0000". */
    fun formatNav(navCents: Long): String = String.format("$%,.4f", navCents / 100.0)

    /** Micro-unit scale: units are carried at 1e-6-unit granularity. */
    private const val UNIT_SCALE: Long = 1_000_000L

    /** One backtest leg: its target [weightBps] and its close series (oldest-first). */
    data class BacktestLeg(
        val weightBps: Int,
        val closes: List<Double>,
    )
}
