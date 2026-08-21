package com.testlogon.android.feature.bailout

import com.testlogon.android.data.bailout.HealthZone

/**
 * Pure, side-effect-free math for the MARGIN DISTRESS / PRE-EMPTIVE BAILOUT AUCTION surface. Extracted
 * so the tricky bits (health-zone classification, single-clearing-price bailout clearing) are
 * unit-testable off the Android runtime.
 *
 * All amounts are integer CENTS; `Bps` are basis points (10_000 bps == 100%). This math NEVER decides
 * distress on its own account values — the server is authoritative and passes buffer/danger/solvency in;
 * [healthZone] only classifies numbers the server already computed.
 */
object BailoutMath {

    /** Basis points denominator: 10_000 bps == 100%. */
    const val BPS_DENOM: Int = 10_000

    /**
     * Classify a position into a health zone from its volatility-scaled band read.
     *
     * - NOT [solvent] (equity <= maintenance) -> [HealthZone.LIQUIDATION] regardless of buffer: a
     *   pre-emptive bailout is impossible once maintenance is breached.
     * - solvent AND `bufferBps <= dangerBps` (inside the danger band) -> [HealthZone.DISTRESS]: a
     *   pre-emptive bailout auction is possible here (distressed but still solvent).
     * - solvent AND `bufferBps > dangerBps` -> [HealthZone.HEALTHY].
     *
     * [bufferBps] is `|mark - liqPrice| / mark` in bps (distance to liquidation); [dangerBps] is the
     * clamped volatility-scaled danger line. Negative inputs are treated as zero.
     */
    fun healthZone(bufferBps: Int, dangerBps: Int, solvent: Boolean): HealthZone {
        if (!solvent) return HealthZone.LIQUIDATION
        val buffer = bufferBps.coerceAtLeast(0)
        val danger = dangerBps.coerceAtLeast(0)
        return if (buffer <= danger) HealthZone.DISTRESS else HealthZone.HEALTHY
    }

    /**
     * The volatility-scaled danger line in bps: `clamp(k * volatilityBps, floor, ceil)`. Provided so the
     * client can render/verify the danger line the server computed. [kNumerator]/[kDenominator] express
     * the multiplier `k` as a fraction (default k = 1.5). Result is clamped to [floorBps]..[ceilBps].
     */
    fun dangerBps(
        volatilityBps: Int,
        kNumerator: Int = 3,
        kDenominator: Int = 2,
        floorBps: Int = 100,
        ceilBps: Int = 3_000,
    ): Int {
        if (volatilityBps <= 0 || kDenominator <= 0) return floorBps.coerceAtLeast(0)
        val scaled = (volatilityBps.toLong() * kNumerator / kDenominator).toInt()
        val lo = floorBps.coerceAtLeast(0)
        val hi = ceilBps.coerceAtLeast(lo)
        return scaled.coerceIn(lo, hi)
    }

    /** Distance-to-liquidation buffer in bps from a mark + liq price (`|mark - liq| / mark`). */
    fun bufferBps(markPrice: Long, liqPrice: Long): Int {
        if (markPrice <= 0L) return 0
        val dist = kotlin.math.abs(markPrice - liqPrice)
        return ((dist * BPS_DENOM + markPrice / 2) / markPrice).toInt().coerceIn(0, BPS_DENOM)
    }

    /**
     * Summary of a single-clearing-price bailout auction over sealed rescue [bids] to raise
     * [capitalNeededCents].
     *
     * Each bid offers [BailoutBid.capitalCents] of rescue capital in return for up to
     * [BailoutBid.shareBps] of the position-share. Cheaper (LESS share per dollar) capital is taken
     * FIRST — bids are ordered by their share-rate `shareBps / capitalCents` ascending (least dilutive).
     * The CLEARING SHARE-RATE is the marginal filled bid's rate, and EVERY filled dollar gives up share
     * at that one rate (single clearing price). The marginal bid is PRO-RATED so exactly the needed
     * capital is raised. [clearingShareBps] is the total position-share the owner gives up across all
     * fills at that clearing rate; null when nothing can be raised.
     *
     * If total offered capital is below [capitalNeededCents] the whole book fills (partial raise) and
     * the clearing rate is the worst (highest) accepted rate.
     */
    fun clearingSummary(
        bids: List<BailoutBid>,
        capitalNeededCents: Long,
    ): BailoutClearing {
        if (capitalNeededCents <= 0L) {
            return BailoutClearing(clearingShareBps = 0, raisedCents = 0L, filledRescuers = 0, fullyFunded = true)
        }
        // Rate = share-bps per cent; scaled by BPS_DENOM to keep integer ordering stable and precise.
        val eligible = bids
            .filter { it.capitalCents > 0L && it.shareBps > 0 }
            .sortedBy { rateScaled(it) }
        if (eligible.isEmpty()) {
            return BailoutClearing(clearingShareBps = null, raisedCents = 0L, filledRescuers = 0, fullyFunded = false)
        }

        var remaining = capitalNeededCents
        var raised = 0L
        var filled = 0
        var totalShareBps = 0L
        var worstRateScaled = 0L
        for (bid in eligible) {
            if (remaining <= 0L) break
            val take = bid.capitalCents.coerceAtMost(remaining)
            if (take <= 0L) break
            // Share given up for this slice at THIS bid's rate: shareBps * take / capitalCents (round half-up).
            val slice = (bid.shareBps.toLong() * take + bid.capitalCents / 2) / bid.capitalCents
            totalShareBps += slice
            raised += take
            remaining -= take
            filled += 1
            worstRateScaled = rateScaled(bid)
        }
        val clearing = totalShareBps.coerceIn(0L, BPS_DENOM.toLong()).toInt()
        return BailoutClearing(
            clearingShareBps = clearing,
            raisedCents = raised,
            filledRescuers = filled,
            fullyFunded = remaining <= 0L,
            worstRateScaled = worstRateScaled,
        )
    }

    /** Share-bps per cent, scaled by [BPS_DENOM] for stable integer ordering (lower == less dilutive). */
    private fun rateScaled(bid: BailoutBid): Long =
        if (bid.capitalCents <= 0L) Long.MAX_VALUE
        else (bid.shareBps.toLong() * BPS_DENOM) / bid.capitalCents

    /** The position-share (in bps) a rescuer receives for [capitalCents] at a clearing rate. */
    fun shareForCapital(capitalCents: Long, clearingShareBps: Int, raisedCents: Long): Int {
        if (capitalCents <= 0L || clearingShareBps <= 0 || raisedCents <= 0L) return 0
        return ((clearingShareBps.toLong() * capitalCents + raisedCents / 2) / raisedCents)
            .toInt().coerceIn(0, BPS_DENOM)
    }

    /** Human label for a basis-points value, e.g. 2500 -> "25.00%", 10000 -> "100.00%". */
    fun formatBps(bps: Int): String = String.format("%.2f%%", bps.coerceAtLeast(0) / 100.0)

    /** Format integer cents as a dollar string, e.g. 10000 -> "$100.00". */
    fun formatCents(cents: Long): String {
        val sign = if (cents < 0) "-" else ""
        val abs = kotlin.math.abs(cents)
        return "$sign$" + String.format("%,d.%02d", abs / 100, abs % 100)
    }

    /** One sealed rescue bid: [capitalCents] injected for up to [shareBps] of the position-share. */
    data class BailoutBid(
        val capitalCents: Long,
        val shareBps: Int,
    )

    /**
     * Result of [clearingSummary]: the single [clearingShareBps] the owner gives up in total across all
     * fills (null when nothing clears), the [raisedCents] raised, how many [filledRescuers] were (fully
     * or partially) filled, and whether the target was [fullyFunded].
     */
    data class BailoutClearing(
        val clearingShareBps: Int?,
        val raisedCents: Long,
        val filledRescuers: Int,
        val fullyFunded: Boolean,
        val worstRateScaled: Long = 0L,
    )
}
