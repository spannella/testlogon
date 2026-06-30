package com.testlogon.android.feature.syndicates.bundles

import com.testlogon.android.core.network.syndicates.BundleCreatorOut
import com.testlogon.android.core.network.syndicates.BundleSubscriptionOut

/** DTO -> domain mappers for the My Bundles surface (in :app, since core-model has no core-network dep). */

fun BundleSubscriptionOut.toDomain(): BundleSubscription = BundleSubscription(
    subscriptionId = subscriptionId,
    syndicateId = syndicateId,
    syndicateName = syndicateName?.takeIf { it.isNotBlank() } ?: syndicateId,
    status = status?.takeIf { it.isNotBlank() } ?: "active",
    priceCents = priceCents,
    interval = interval?.takeIf { it.isNotBlank() } ?: "month",
    currentPeriodStart = currentPeriodStart?.takeIf { it > 0 },
    currentPeriodEnd = currentPeriodEnd?.takeIf { it > 0 },
    includedCreators = includedCreators.map { it.toDomain() },
)

fun BundleCreatorOut.toDomain(): BundleCreator = BundleCreator(
    userId = userId,
    displayName = displayName?.takeIf { it.isNotBlank() } ?: userId,
)
