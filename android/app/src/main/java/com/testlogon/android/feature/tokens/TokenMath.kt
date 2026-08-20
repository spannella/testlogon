package com.testlogon.android.feature.tokens

import com.testlogon.android.data.tokens.TokenBid

/**
 * Pure, side-effect-free math for the CREATOR REVENUE-SHARE TOKEN surface. Extracted so the tricky
 * bits (pro-rata upkeep share, pct_bps <-> qty, single-clearing-price summary) are unit-testable off
 * the Android runtime. All amounts are integer CENTS; `Bps` are basis points (10_000 bps = 100%).
 *
 * The book-upkeep charge is modelled as a SHORTFALL top-up (see [upkeepAmountDue]): a flat $100/month
 * is offset by trading fees already generated that month. This shortfall-vs-flat choice is an
 * ASSUMPTION surfaced in the UI (see the Upkeep section label) so it can be flipped to a flat charge
 * later without touching the rest of the surface.
 */
object TokenMath {

    /** Basis points denominator: 10_000 bps == 100%. */
    const val BPS_DENOM: Int = 10_000

    /** The flat monthly book-upkeep threshold in cents ($100.00). */
    const val UPKEEP_THRESHOLD_CENTS: Long = 100_00L

    /** The one-time token creation fee in cents ($100.00). */
    const val CREATION_FEE_CENTS: Long = 100_00L

    /**
     * The shortfall the book still owes this month: `max(0, threshold - feesGenerated)`. Zero once the
     * month's trading fees already meet/exceed the threshold. Negative inputs are clamped to zero.
     */
    fun upkeepAmountDue(feesGeneratedCents: Long, thresholdCents: Long = UPKEEP_THRESHOLD_CENTS): Long {
        val fees = feesGeneratedCents.coerceAtLeast(0L)
        val threshold = thresholdCents.coerceAtLeast(0L)
        return (threshold - fees).coerceAtLeast(0L)
    }

    /**
     * A single holder's PRO-RATA share of an [amountDueCents] charge, by their holding fraction
     * `myQty / totalSupply`. Rounded to the nearest cent (half-up). Guards divide-by-zero (0 supply or
     * 0 qty -> 0) and never exceeds [amountDueCents]. Uses Long arithmetic (no Double drift on cents).
     */
    fun proRataShare(amountDueCents: Long, myQty: Long, totalSupply: Long): Long {
        if (amountDueCents <= 0L || myQty <= 0L || totalSupply <= 0L) return 0L
        val q = myQty.coerceAtMost(totalSupply)
        // round(amountDue * q / total) via integer half-up: (a*q + total/2) / total
        val share = (amountDueCents * q + totalSupply / 2) / totalSupply
        return share.coerceIn(0L, amountDueCents)
    }

    /** Ownership fraction (of total supply) expressed in basis points. 0 supply -> 0. */
    fun qtyToBps(qty: Long, totalSupply: Long): Int {
        if (qty <= 0L || totalSupply <= 0L) return 0
        val q = qty.coerceAtMost(totalSupply)
        return ((q * BPS_DENOM + totalSupply / 2) / totalSupply).toInt().coerceIn(0, BPS_DENOM)
    }

    /** The token quantity a [pctBps] slice of [totalSupply] represents (floor). Negatives clamp to 0. */
    fun bpsToQty(pctBps: Int, totalSupply: Long): Long {
        if (pctBps <= 0 || totalSupply <= 0L) return 0L
        val bps = pctBps.coerceAtMost(BPS_DENOM)
        return (totalSupply * bps) / BPS_DENOM
    }

    /** Human label for a basis-points value, e.g. 2500 -> "25.00%", 10000 -> "100.00%". */
    fun formatBps(bps: Int): String = String.format("%.2f%%", bps.coerceAtLeast(0) / 100.0)

    /** Format integer cents as a dollar string, e.g. 10000 -> "$100.00". */
    fun formatCents(cents: Long): String {
        val sign = if (cents < 0) "-" else ""
        val abs = kotlin.math.abs(cents)
        return "$sign$" + String.format("%,d.%02d", abs / 100, abs % 100)
    }

    /**
     * Summary of a single-clearing-price IPO auction over sealed [bids] for [offeredQty] tokens.
     *
     * Bids are filled highest-limit-first; the CLEARING PRICE is the lowest accepted bid's limit (the
     * price the marginal filled bid is willing to pay), and ALL fills execute at that one price. A bid
     * only clears if its limit >= [reservePrice]. If demand at/above reserve is below [offeredQty], the
     * whole eligible demand clears (partial book); [clearingPrice] is null when nothing clears.
     */
    fun clearingSummary(
        bids: List<TokenBid>,
        offeredQty: Long,
        reservePrice: Long,
    ): ClearingSummary {
        if (offeredQty <= 0L) return ClearingSummary(clearingPrice = null, filledQty = 0L, clearedBids = 0)
        val eligible = bids
            .filter { it.qty > 0L && it.limitPrice >= reservePrice }
            .sortedWith(compareByDescending<TokenBid> { it.limitPrice }.thenByDescending { it.qty })
        if (eligible.isEmpty()) return ClearingSummary(clearingPrice = null, filledQty = 0L, clearedBids = 0)

        var remaining = offeredQty
        var filled = 0L
        var clearedBids = 0
        var lastAcceptedPrice = 0L
        for (bid in eligible) {
            if (remaining <= 0L) break
            val take = bid.qty.coerceAtMost(remaining)
            if (take <= 0L) break
            filled += take
            remaining -= take
            clearedBids += 1
            lastAcceptedPrice = bid.limitPrice
        }
        return ClearingSummary(
            clearingPrice = lastAcceptedPrice,
            filledQty = filled,
            clearedBids = clearedBids,
        )
    }

    /** Total demand in cents for a set of [bids] at their own limit prices (for a "demand" read-out). */
    fun totalDemandCents(bids: List<TokenBid>): Long =
        bids.filter { it.qty > 0L && it.limitPrice > 0L }.sumOf { it.qty * it.limitPrice }

    /**
     * Result of [clearingSummary]: the single [clearingPrice] every fill executes at (null when nothing
     * clears), the total [filledQty], and how many [clearedBids] were (fully or partially) filled.
     */
    data class ClearingSummary(
        val clearingPrice: Long?,
        val filledQty: Long,
        val clearedBids: Int,
    )
}
