package com.testlogon.android.feature.adsbilling.ui

/**
 * FE-160 - pure, framework-free money math for the ad-account "Add funds" (deposit / top-up) surface,
 * including the "Fund with crypto balance" path. Every function is deterministic and side-effect free
 * (no clock, no I/O): amounts are integer USD cents (Long) so there is no binary-float drift. The FX /
 * rate-lock math for the crypto path lives in the shipped
 * [com.testlogon.android.feature.checkout.CheckoutCryptoMath] (reused as-is); this object only owns the
 * top-up amount presets + validation + balance projection for the ad account.
 *
 * Mirrors the deposit bounds already enforced by the ads-billing ViewModel/server (min $50, max $100k)
 * but with a lower validation floor for the "is this text even a sane top-up" check requested by FE-160
 * (min $1); the ViewModel keeps its own server-authoritative 5000..10000000 gate for the actual charge.
 */
object AdDepositMath {

    /** USD sign kept as a constant so string building never trips Kotlin's dollar interpolation. */
    private const val USD = "$"

    /** Quick top-up presets shown as chips, in integer USD cents ($25 / $50 / $100 / $250). */
    val PRESET_TOPUPS_CENTS: List<Long> = listOf(2_500L, 5_000L, 10_000L, 25_000L)

    /** The lowest a top-up may be (FE-160: min $1) in integer cents. */
    const val MIN_TOPUP_CENTS: Long = 100L

    /** A sane upper bound so a fat-fingered entry can't request an absurd charge ($100k) in cents. */
    const val MAX_TOPUP_CENTS: Long = 10_000_000L

    /**
     * True when [cents] is a valid top-up: a positive integer number of cents within
     * [MIN_TOPUP_CENTS]..[MAX_TOPUP_CENTS]. Cents are already integral (Long), so "integer" here means
     * simply in-range and non-fractional-by-construction.
     */
    fun isValidTopUpCents(cents: Long): Boolean = cents in MIN_TOPUP_CENTS..MAX_TOPUP_CENTS

    /** Human label for a top-up amount, e.g. 2500 -> "$25". Whole dollars drop the ".00". */
    fun topUpLabel(cents: Long): String = USD + formatCents(cents)

    /**
     * The account balance after crediting [addedCents] to [currentCents]. Negative operands are treated
     * as 0 (a balance never goes below zero from a top-up; a negative add is a no-op). Saturates at
     * [Long.MAX_VALUE] rather than overflowing.
     */
    fun newBalanceCents(currentCents: Long, addedCents: Long): Long {
        val cur = if (currentCents < 0L) 0L else currentCents
        val add = if (addedCents < 0L) 0L else addedCents
        val sum = cur + add
        // Overflow guard: if adding wrapped to negative, saturate.
        return if (sum < cur) Long.MAX_VALUE else sum
    }

    /** dollars (Double) -> integer cents, half-up, clamped to >= 0. */
    fun dollarsToCents(dollars: Double): Long {
        val safe = if (dollars.isNaN() || dollars.isInfinite() || dollars < 0.0) 0.0 else dollars
        return Math.round(safe * 100.0)
    }

    /** integer cents -> dollars (Double). */
    fun centsToDollars(cents: Long): Double = cents / 100.0

    /**
     * Formats integer [cents] as a plain dollar-and-cent string WITHOUT the currency symbol: whole
     * dollars render with no decimals ("25"), otherwise two decimals ("25.50"). No locale coupling.
     */
    fun formatCents(cents: Long): String {
        val abs = if (cents < 0L) -cents else cents
        val dollars = abs / 100L
        val rem = abs % 100L
        val sign = if (cents < 0L) "-" else ""
        return if (rem == 0L) {
            sign + dollars.toString()
        } else {
            sign + dollars.toString() + "." + rem.toString().padStart(2, '0')
        }
    }
}
