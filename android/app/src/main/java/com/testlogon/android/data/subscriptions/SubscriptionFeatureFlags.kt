package com.testlogon.android.data.subscriptions

import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-235 — feature gate for the subscription checkout/purchase path.
 *
 * FLAGGED: the subscribe purchase routes through the BillingAuthorizer stub (NotConfigured -> never
 * charges) and the destination checkout route is not built this milestone, so [checkoutEnabled]
 * defaults to false. When the subscription checkout lands, swap the binding (or flip this flag) to
 * enable the NavigateToCheckout event; until then the Subscribe CTA emits a "payments unavailable"
 * effect and never reaches a charge.
 */
interface SubscriptionFeatureFlags {
    val checkoutEnabled: Boolean
}

@Singleton
class DefaultSubscriptionFeatureFlags @Inject constructor() : SubscriptionFeatureFlags {
    override val checkoutEnabled: Boolean = false
}
