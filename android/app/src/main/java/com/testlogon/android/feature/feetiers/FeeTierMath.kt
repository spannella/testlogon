package com.testlogon.android.feature.feetiers

import com.testlogon.android.data.exchange.FillFee

/**
 * Pure, dependency-free MAKER/TAKER FEE-TIER (VIP schedule) engine, computed CLIENT-SIDE from the
 * account's executed fills. NO framework, NO I/O, NO Android — every monetary value is an INTEGER in
 * USD cents and every rate is an integer basis-point (bps), so the arithmetic is exact and the module
 * is trivially unit-testable (see FeeTierMathTest).
 *
 * A trader's fee tier is a function of their 30-day rolling trading VOLUME (sum of executed-fill
 * NOTIONAL = price*qty). Higher volume -> lower maker & taker rates. [FEE_TIERS] is CANONICAL and is
 * an EXACT mirror of the web client's frontend/src/lib/feeTiers.ts — do NOT change the
 * thresholds/rates here without changing both.
 */
object FeeTierMath {

    /** One tier in the maker/taker VIP schedule. */
    data class FeeTier(
        /** Stable id shared with the authoritative backend read. */
        val id: String,
        /** Human label. */
        val name: String,
        /** Minimum 30-day volume (USD cents, inclusive) to qualify for this tier. */
        val minVolumeCents: Long,
        /** Maker fee, basis points. */
        val makerBps: Int,
        /** Taker fee, basis points. */
        val takerBps: Int,
    )

    /**
     * Canonical maker/taker VIP schedule (ascending by threshold). Identical to the web feeTiers.ts:
     * Standard $0 10/15 ; Bronze $50k 9/14 ; Silver $250k 8/12 ; Gold $1M 6/10 ; Platinum $5M 4/8 ;
     * Diamond (VIP) $25M 2/6.
     */
    val FEE_TIERS: List<FeeTier> = listOf(
        FeeTier("standard", "Standard", 0L, 10, 15),
        FeeTier("bronze", "Bronze", 50_000_00L, 9, 14),
        FeeTier("silver", "Silver", 250_000_00L, 8, 12),
        FeeTier("gold", "Gold", 1_000_000_00L, 6, 10),
        FeeTier("platinum", "Platinum", 5_000_000_00L, 4, 8),
        FeeTier("diamond", "Diamond (VIP)", 25_000_000_00L, 2, 6),
    )

    /** One normalized executed fill for the volume sum. [ts] is unix seconds OR milliseconds. */
    data class VolumeFill(
        /** Unix timestamp — seconds OR milliseconds (engine-native). */
        val ts: Long,
        /** Per-unit executed price, integer minor units (cents). */
        val priceCents: Long,
        /** Executed quantity (treated as a positive magnitude). */
        val qty: Long,
    )

    private const val DAY_MS = 24L * 60L * 60L * 1000L

    // A ts below this is assumed to be seconds; at/above, milliseconds. (~2001 in ms / ~33k AD in s —
    // the same heuristic the web engine uses.)
    private const val MS_THRESHOLD = 1_000_000_000_000L

    private fun toMs(ts: Long): Long = if (ts < MS_THRESHOLD) ts * 1000L else ts

    /**
     * Normalize the account's [FillFee] feed (nanosecond ts, raw integer price/qty — price scalers are
     * identity today, matching the Tax report) into [VolumeFill]s for the volume sum.
     */
    fun fromFills(fills: List<FillFee>): List<VolumeFill> =
        fills.map { VolumeFill(ts = it.tsNs / 1_000_000L, priceCents = it.price, qty = it.qty) }

    /**
     * Sum of executed-fill NOTIONAL (priceCents * qty) within the trailing [windowDays] window ending
     * at [nowMs]. Fills outside the window, or with non-positive price/qty, are ignored. Timestamps
     * accept seconds OR milliseconds. Never negative.
     */
    fun volume30dCents(
        fills: List<VolumeFill>,
        nowMs: Long,
        windowDays: Int = 30,
    ): Long {
        if (fills.isEmpty()) return 0L
        val window = maxOf(0, windowDays).toLong() * DAY_MS
        val cutoff = nowMs - window
        var total = 0L
        for (f in fills) {
            if (f.priceCents <= 0L || f.qty <= 0L) continue
            val ms = toMs(f.ts)
            if (ms < cutoff || ms > nowMs) continue
            total += f.priceCents * f.qty
        }
        return if (total < 0L) 0L else total
    }

    /**
     * The highest tier whose [FeeTier.minVolumeCents] is <= [volumeCents]. Negative / empty volume ->
     * Standard (the first tier). Always returns a tier.
     */
    fun tierForVolume(volumeCents: Long): FeeTier {
        val v = if (volumeCents > 0L) volumeCents else 0L
        var match = FEE_TIERS.first()
        for (t in FEE_TIERS) {
            if (v >= t.minVolumeCents) match = t else break
        }
        return match
    }

    /** Look up a tier by its stable id (e.g. from the authoritative backend read). */
    fun tierById(id: String): FeeTier? = FEE_TIERS.firstOrNull { it.id == id }

    /** The next-higher tier above [tier], or null when already at the top. */
    fun nextTier(tier: FeeTier): FeeTier? {
        val i = FEE_TIERS.indexOfFirst { it.id == tier.id }
        if (i < 0 || i >= FEE_TIERS.size - 1) return null
        return FEE_TIERS[i + 1]
    }

    /**
     * Progress (0..1) toward the NEXT tier's threshold, measured from the CURRENT tier's threshold.
     * Returns 1.0 when already at the top tier. Clamped to [0,1].
     */
    fun progressToNextFraction(volumeCents: Long): Double {
        val v = if (volumeCents > 0L) volumeCents else 0L
        val current = tierForVolume(v)
        val next = nextTier(current) ?: return 1.0
        val span = next.minVolumeCents - current.minVolumeCents
        if (span <= 0L) return 1.0
        val gained = v - current.minVolumeCents
        val frac = gained.toDouble() / span.toDouble()
        return when {
            frac <= 0.0 -> 0.0
            frac >= 1.0 -> 1.0
            else -> frac
        }
    }

    /** USD cents of additional volume needed to reach the next tier (0 at top). */
    fun volumeToNextTierCents(volumeCents: Long): Long {
        val v = if (volumeCents > 0L) volumeCents else 0L
        val next = nextTier(tierForVolume(v)) ?: return 0L
        val remaining = next.minVolumeCents - v
        return if (remaining > 0L) remaining else 0L
    }

    /**
     * Fee (integer cents, rounded half-up) charged on [notionalCents] at [bps] basis points.
     * bps of 15 = 0.15%. Guards non-positive inputs -> 0.
     */
    fun makerTakerFeeCents(notionalCents: Long, bps: Int): Long {
        if (notionalCents <= 0L || bps <= 0) return 0L
        // fee = notional * bps / 10_000, rounded half-up for a deterministic result.
        return (notionalCents * bps + 5_000L) / 10_000L
    }
}
