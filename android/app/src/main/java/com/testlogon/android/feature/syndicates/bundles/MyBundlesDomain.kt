package com.testlogon.android.feature.syndicates.bundles

/**
 * Framework-free domain models for the "My Bundles" surface (web parity: /syndicates/my-bundles).
 * Kept in the feature (NOT core-model) because core-model cannot depend on core-network. Times are EPOCH
 * SECONDS; money is *_cents (Int).
 */

/** One active syndicate bundle subscription. */
data class BundleSubscription(
    val subscriptionId: String,
    val syndicateId: String,
    val syndicateName: String,
    val status: String,
    val priceCents: Int,
    val interval: String,
    val currentPeriodStart: Long?,
    val currentPeriodEnd: Long?,
    val includedCreators: List<BundleCreator>,
) {
    val isActive: Boolean get() = status.equals("active", ignoreCase = true)
}

/** One creator included in a bundle. */
data class BundleCreator(
    val userId: String,
    val displayName: String,
)
