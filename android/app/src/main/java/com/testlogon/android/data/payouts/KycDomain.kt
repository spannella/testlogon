package com.testlogon.android.data.payouts

/**
 * AND-259 — framework-free KYC tier domain models + DTO -> domain mappers (the payout gate's source).
 *
 * Tiers are INTEGER ranks (0 = none, higher = more verified). The required tier for payouts is NOT a
 * backend field — it is a client/product constant [PAYOUT_REQUIRED_TIER] (STOP-AND-FLAG, see §16 OA1).
 * The gate prefers the server's `eligible` boolean from the requirements call and falls back to a rank
 * comparison.
 */

/** A KYC tier rank. 0 = none/unverified; higher = more verified. */
@JvmInline
value class KycTier(val rank: Int)

/**
 * Combined tier state used by the gate. [eligibleForPayoutTier] is null until a requirements call
 * resolves it; [unmetRequirements] are raw requirement CODE strings (e.g. "gov_id").
 */
data class TierStatus(
    val currentTier: KycTier,
    val tierName: String,
    val requiredTierForPayouts: KycTier,
    val eligibleForPayoutTier: Boolean?,
    val unmetRequirements: List<String>,
)

internal fun TierDetailsDto.toDomain(
    requiredTier: KycTier,
    eligible: Boolean? = null,
    unmet: List<String> = emptyList(),
): TierStatus = TierStatus(
    currentTier = KycTier(currentTier),
    tierName = tierName,
    requiredTierForPayouts = requiredTier,
    eligibleForPayoutTier = eligible,
    unmetRequirements = unmet,
)

/**
 * STOP-AND-FLAG (AND-259 §16 OA1): no backend field expresses the required payout tier. This is a
 * client/product constant and the exact rank MUST be confirmed with product/backend. Tier 1 is used as
 * a conservative placeholder (any verification above "none" gates payouts).
 */
const val PAYOUT_REQUIRED_TIER: Int = 1
