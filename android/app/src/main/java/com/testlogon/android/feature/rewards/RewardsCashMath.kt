package com.testlogon.android.feature.rewards

/**
 * Pure, Android-free math + validation for the DIRECT "convert reward points -> USD cash wallet"
 * redemption. Kept out of the ViewModel/Compose so the rate, minimum, conversion and validation are unit
 * testable. The canonical rate mirrors the web contract EXACTLY: 100 points = $1.00, i.e. 1 cent per
 * point ([CENTS_PER_POINT]). Points and cents are integers throughout — no float drift, no fractional
 * cents. The client only proposes/validates; crediting is entirely server-side (source of truth).
 */
object RewardsCashMath {

    /** Canonical rate: 100 points = $1.00 -> exactly 1 USD cent per point. Integer, no rounding. */
    const val CENTS_PER_POINT: Long = 1L

    /** Minimum redeemable points (500 points = $5.00). Below this the redeem is rejected client-side. */
    const val MIN_REDEEM_POINTS: Long = 500L

    /** USD cents credited for [points] points (points * [CENTS_PER_POINT]); floored at 0 for non-positive. */
    fun cashCentsForPoints(points: Long): Long =
        if (points <= 0L) 0L else points * CENTS_PER_POINT

    /**
     * Points required to redeem exactly [cashCents] USD cents at the canonical rate. Rounds UP so a preset
     * dollar target is always fully covered (never under-funds the target). Non-positive -> 0.
     */
    fun pointsForCashCents(cashCents: Long): Long {
        if (cashCents <= 0L) return 0L
        return (cashCents + CENTS_PER_POINT - 1L) / CENTS_PER_POINT
    }

    /** The minimum redemption expressed in USD cents (MIN_REDEEM_POINTS at the canonical rate). */
    fun minRedeemCents(): Long = cashCentsForPoints(MIN_REDEEM_POINTS)

    /** Points left after redeeming [points] from a [balancePoints] wallet, floored at 0 (never negative). */
    fun pointsAfterRedeem(balancePoints: Long, points: Long): Long =
        (balancePoints - points).coerceAtLeast(0L)

    /**
     * Result of validating a proposed points redemption against the wallet balance. Exactly one of the
     * flags is meaningful when [valid] is false; when [valid] is true the redemption is safe to confirm.
     */
    enum class Validation { VALID, NOT_POSITIVE, BELOW_MIN, INSUFFICIENT }

    /**
     * Validate a DIRECT points->cash redemption of [points] against [balancePoints]:
     * - [Validation.NOT_POSITIVE] when points <= 0 (nothing to redeem),
     * - [Validation.BELOW_MIN] when points < [MIN_REDEEM_POINTS],
     * - [Validation.INSUFFICIENT] when points > balance,
     * - [Validation.VALID] otherwise.
     * Order matters: a non-positive/too-small amount is reported before an insufficient-balance check.
     */
    fun validatePointsRedemption(points: Long, balancePoints: Long): Validation = when {
        points <= 0L -> Validation.NOT_POSITIVE
        points < MIN_REDEEM_POINTS -> Validation.BELOW_MIN
        points > balancePoints -> Validation.INSUFFICIENT
        else -> Validation.VALID
    }

    /** Convenience: true only when [validatePointsRedemption] returns [Validation.VALID]. */
    fun canRedeem(points: Long, balancePoints: Long): Boolean =
        validatePointsRedemption(points, balancePoints) == Validation.VALID

    /**
     * The largest number of points the [balancePoints] wallet can redeem to cash right now: the whole
     * balance when it is at least the minimum, otherwise 0 (the min is not yet met). Used by the "Max"
     * preset so it never proposes an invalid amount.
     */
    fun maxRedeemablePoints(balancePoints: Long): Long =
        if (balancePoints >= MIN_REDEEM_POINTS) balancePoints else 0L

    // ---- Formatting (delegates to RewardsMath for a single money/points format source of truth) ----

    /** Format integer cents as a USD currency amount with symbol (500 -> "$5.00"). */
    fun formatCentsUsd(cents: Long): String = RewardsMath.formatCentsUsd(cents)

    /** Format integer points with grouping ("1,250 pts"). */
    fun formatPoints(points: Long): String = RewardsMath.formatPoints(points)

    /** Human rate line, e.g. "100 points = $1.00". Pure, JVM-testable. */
    fun rateLabel(): String =
        "${formatPoints(100L / CENTS_PER_POINT)} = ${formatCentsUsd(100L)}"
}
