package com.testlogon.android.core.network.syndicates

import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.GET
import retrofit2.http.Path

/**
 * Retrofit interface for the "My Bundles" surface (web parity: /syndicates/my-bundles). Transport only;
 * the :app repository folds these RAW DTO returns into ApiResult. Paths are relative (no leading slash);
 * the shared authenticated client attaches the session cookie + X-CSRF-Token + Bearer globally.
 *
 * Kept separate from the main SyndicateApi (additive; does not touch the large existing interface).
 */
interface SyndicateBundleApi {

    /** GET the caller's active bundle subscriptions (bare array). Idempotent. */
    @GET("ui/syndicates/my-bundles")
    suspend fun listMyBundles(): List<BundleSubscriptionOut>

    /**
     * POST a cancel for a bundle subscription. Access continues until the end of the current period.
     * NON-idempotent in spirit; no body. Returns {subscription_id, status, current_period_end, cancelled_at}.
     */
    @Headers("Content-Type: application/json")
    @POST("ui/syndicates/{syndicateId}/subscriptions/{subscriptionId}/cancel")
    suspend fun cancelBundleSubscription(
        @Path("syndicateId") syndicateId: String,
        @Path("subscriptionId") subscriptionId: String,
    ): CancelBundleSubscriptionOut
}
