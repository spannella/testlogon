package com.testlogon.android.data.payouts

/**
 * AND-259 — the pure, unit-testable payout gate decision.
 *
 * Prefers the server's `eligible` boolean (from the requirements call); falls back to a rank compare
 * (`currentTier >= requiredTier`) when eligibility is unresolved. A null [TierStatus] (KYC unavailable)
 * fails CLOSED to [Unknown] so a payout can never be requested without a confirmed sufficient tier.
 */
sealed interface PayoutGate {
    data object Allowed : PayoutGate

    data class Blocked(
        val currentTier: KycTier,
        val requiredTier: KycTier,
        val missing: List<String>,
    ) : PayoutGate

    /** Tier state unavailable -> fail closed (form disabled, retry offered). */
    data object Unknown : PayoutGate
}

object PayoutGateEvaluator {
    fun evaluate(status: TierStatus?): PayoutGate = when {
        status == null -> PayoutGate.Unknown
        status.eligibleForPayoutTier == true ||
            (status.eligibleForPayoutTier == null &&
                status.currentTier.rank >= status.requiredTierForPayouts.rank) ->
            PayoutGate.Allowed
        else -> PayoutGate.Blocked(
            currentTier = status.currentTier,
            requiredTier = status.requiredTierForPayouts,
            missing = status.unmetRequirements,
        )
    }
}
