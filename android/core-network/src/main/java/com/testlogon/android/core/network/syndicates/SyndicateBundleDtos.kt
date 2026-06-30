package com.testlogon.android.core.network.syndicates

import com.squareup.moshi.Json

/**
 * Transport DTOs for the "My Bundles" surface (web parity: /syndicates/my-bundles) - the caller's active
 * syndicate bundle subscriptions. Backend: app/routers/syndicates.py GET /ui/syndicates/my-bundles ->
 * List[BundleSubscriptionOut]; cancel POST /ui/syndicates/{sid}/subscriptions/{subId}/cancel.
 *
 * CODEGEN NOTE: same as the rest of core-network - reflective KotlinJsonAdapterFactory, so every wire key
 * is pinned with an explicit @Json(name = ...); @JsonClass(generateAdapter=true) is OMITTED.
 *
 * TIME: current_period_start / current_period_end / created_at / cancelled_at are EPOCH SECONDS (Long).
 * MONEY: price_cents is an Int.
 */

/** One active bundle subscription row (GET /ui/syndicates/my-bundles, a bare array). */
data class BundleSubscriptionOut(
    @Json(name = "subscription_id") val subscriptionId: String,
    @Json(name = "plan_id") val planId: String? = null,
    @Json(name = "syndicate_id") val syndicateId: String,
    @Json(name = "syndicate_name") val syndicateName: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "price_cents") val priceCents: Int = 0,
    @Json(name = "interval") val interval: String? = null,
    @Json(name = "current_period_start") val currentPeriodStart: Long? = null,
    @Json(name = "current_period_end") val currentPeriodEnd: Long? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "cancelled_at") val cancelledAt: Long? = null,
    @Json(name = "included_creators") val includedCreators: List<BundleCreatorOut> = emptyList(),
)

/** One creator included in a bundle (a SyndicateMemberOut shape on the wire). */
data class BundleCreatorOut(
    @Json(name = "user_id") val userId: String,
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "role") val role: String? = null,
    @Json(name = "joined_at") val joinedAt: Long? = null,
)

/** Response of the cancel endpoint: {subscription_id, status, current_period_end, cancelled_at}. */
data class CancelBundleSubscriptionOut(
    @Json(name = "subscription_id") val subscriptionId: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "current_period_end") val currentPeriodEnd: Long? = null,
    @Json(name = "cancelled_at") val cancelledAt: Long? = null,
)
