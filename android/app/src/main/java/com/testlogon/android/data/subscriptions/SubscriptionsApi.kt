package com.testlogon.android.data.subscriptions

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-234 — Retrofit interface + Moshi DTOs for the real subscriptions surface (creator "plans" +
 * the viewer's subscriptions). Distinct from the AND-223 `ui/billing/subscriptions` billing summary:
 * these are the `api/...` plan/subscription endpoints.
 *
 * VERIFIED against reference/openapi.index.txt + reference/src/api/endpoints/subscriptions.ts +
 * reference/src/api/types.ts (SubscriptionPlan L2696, SubscriptionOut L2713, SubscriptionSummary
 * L2739). Money is integer cents (`*_cents`); timestamps are epoch-seconds Longs.
 *
 * Endpoint citations (reference/openapi.index.txt):
 *  - GET  api/creators/{creator_id}/plans            op=list_plans_...           PUBLIC (no x-user-id)
 *  - GET  api/subscriptions                          op=list_subscriptions_...   requires x-user-id
 *  - GET  api/subscriptions/{subscription_id}/summary op=get_subscription_summary_...  x-user-id
 *  - POST api/plans/{plan_id}/subscribe              req=SubscribeIn  resp=SubscriptionOut  x-user-id
 *  - POST api/subscriptions/{subscription_id}/change-plan req=SubscriptionChangePlanIn       x-user-id
 *  - POST api/subscriptions/{subscription_id}/cancel req=SubscriptionCancelIn resp=SubscriptionOut x-user-id
 *
 * AUTH NOTE: session cookies + Authorization Bearer + X-CSRF-Token are attached by the shared
 * core-network interceptors. The subscription server ALSO requires X-User-Id on the authenticated
 * endpoints (reference subscriptions.ts: userIdHeader()); it is supplied per-method via @Header by
 * the repository (the public plan list omits it).
 */
interface SubscriptionsApi {

    /** Plans ("tiers") a creator offers. PUBLIC — no X-User-Id. Idempotent GET. Bare array. */
    @GET("api/creators/{creatorId}/plans")
    suspend fun plans(
        @Path("creatorId") creatorId: String,
        @Query("include_profile") includeProfile: Boolean? = null,
    ): List<SubscriptionPlanDto>

    /** The viewer's own subscriptions. Requires X-User-Id. Idempotent GET. Bare array. */
    @GET("api/subscriptions")
    suspend fun mySubscriptions(
        @Header("X-User-Id") userId: String,
        @Query("include_summary") includeSummary: Boolean? = null,
    ): List<SubscriptionOutDto>

    /** Single-subscription read (the /summary projection). Requires X-User-Id. Idempotent GET. */
    @GET("api/subscriptions/{subscriptionId}/summary")
    suspend fun subscriptionSummary(
        @Header("X-User-Id") userId: String,
        @Path("subscriptionId") subscriptionId: String,
    ): SubscriptionSummaryDto

    /** Subscribe to a plan (plan id is a PATH param). Returns the created SubscriptionOut. */
    @Headers("Content-Type: application/json")
    @POST("api/plans/{planId}/subscribe")
    suspend fun subscribe(
        @Header("X-User-Id") userId: String,
        @Path("planId") planId: String,
        @Body body: SubscribeReqDto,
    ): SubscriptionOutDto

    /** Move an existing subscription to a different plan. Returns the updated SubscriptionOut. */
    @Headers("Content-Type: application/json")
    @POST("api/subscriptions/{subscriptionId}/change-plan")
    suspend fun changePlan(
        @Header("X-User-Id") userId: String,
        @Path("subscriptionId") subscriptionId: String,
        @Body body: ChangePlanReqDto,
    ): SubscriptionOutDto

    /** Cancel a subscription (POST .../cancel -> updated SubscriptionOut; NOT DELETE, NOT OkResp). */
    @Headers("Content-Type: application/json")
    @POST("api/subscriptions/{subscriptionId}/cancel")
    suspend fun cancel(
        @Header("X-User-Id") userId: String,
        @Path("subscriptionId") subscriptionId: String,
        @Body body: CancelSubscriptionReqDto,
    ): SubscriptionOutDto
}

// ---- Response DTOs (AND-234) ----

/**
 * Creator-offered plan (the "tier"). Verified: types.ts SubscriptionPlan (L2696).
 * Price is FLAT (price_cents/currency/interval) — no nested price object. `interval`/`status` stay
 * String here (mapped to enums in the domain layer); timestamps are epoch numbers. `assets[].name`
 * supplies the feature/perk bullets (no dedicated `benefits`/`perks` field exists).
 */
@JsonClass(generateAdapter = true)
data class SubscriptionPlanDto(
    @Json(name = "plan_id") val planId: String,
    @Json(name = "creator_id") val creatorId: String,
    @Json(name = "name") val name: String,
    @Json(name = "description") val description: String? = null,
    @Json(name = "price_cents") val priceCents: Long,
    @Json(name = "currency") val currency: String,
    @Json(name = "interval") val interval: String,
    @Json(name = "annual_price_cents") val annualPriceCents: Long? = null,
    @Json(name = "status") val status: String,
    @Json(name = "assets") val assets: List<PlanAssetDto>? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,
)

/** Plan asset (verified: types.ts SubscriptionPlan.assets). Only `name` is consumed (perk label). */
@JsonClass(generateAdapter = true)
data class PlanAssetDto(
    @Json(name = "name") val name: String? = null,
    @Json(name = "path") val path: String? = null,
    @Json(name = "type") val type: String? = null,
    @Json(name = "content_type") val contentType: String? = null,
)

/** Viewer subscription. Verified: types.ts SubscriptionOut (L2713). */
@JsonClass(generateAdapter = true)
data class SubscriptionOutDto(
    @Json(name = "subscription_id") val subscriptionId: String,
    @Json(name = "plan_id") val planId: String,
    @Json(name = "creator_id") val creatorId: String,
    @Json(name = "subscriber_id") val subscriberId: String? = null,
    @Json(name = "interval") val interval: String? = null,
    @Json(name = "provider") val provider: String? = null,
    @Json(name = "provider_subscription_id") val providerSubscriptionId: String? = null,
    @Json(name = "status") val status: String,
    @Json(name = "start_at") val startAt: Long? = null,
    @Json(name = "current_period_end") val currentPeriodEnd: Long? = null,
    @Json(name = "cancel_at_period_end") val cancelAtPeriodEnd: Boolean = false,
    @Json(name = "price_cents") val priceCents: Long? = null,
    @Json(name = "currency") val currency: String? = null,
    @Json(name = "auto_renew") val autoRenew: Boolean = true,
    @Json(name = "trial_start") val trialStart: Long? = null,
    @Json(name = "trial_end") val trialEnd: Long? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,
    @Json(name = "plan") val plan: SubscriptionPlanDto? = null,
)

/** Single-subscription read projection. Verified: types.ts SubscriptionSummary (L2739). */
@JsonClass(generateAdapter = true)
data class SubscriptionSummaryDto(
    @Json(name = "subscription_id") val subscriptionId: String,
    @Json(name = "status") val status: String,
    @Json(name = "cancel_at_period_end") val cancelAtPeriodEnd: Boolean = false,
    @Json(name = "total_paid_cents") val totalPaidCents: Long = 0,
    @Json(name = "currency") val currency: String? = null,
    @Json(name = "next_amount_cents") val nextAmountCents: Long = 0,
    @Json(name = "next_renewal_at") val nextRenewalAt: Long? = null,
    @Json(name = "last_invoice_at") val lastInvoiceAt: Long? = null,
)

// ---- Request DTOs (AND-234) ----

/** Subscribe request. Verified: SubscribeIn — ALL fields optional; plan id is a PATH param. */
@JsonClass(generateAdapter = true)
data class SubscribeReqDto(
    @Json(name = "interval") val interval: String? = null,
    @Json(name = "discount_code") val discountCode: String? = null,
    @Json(name = "trial_days") val trialDays: Int? = null,
    @Json(name = "subscriber_id") val subscriberId: String? = null,
)

/** Change-plan request. Verified: SubscriptionChangePlanIn — `plan_id` required. */
@JsonClass(generateAdapter = true)
data class ChangePlanReqDto(
    @Json(name = "plan_id") val planId: String,
    @Json(name = "interval") val interval: String? = null,
    @Json(name = "effective") val effective: String? = null,
    @Json(name = "proration_policy") val prorationPolicy: String? = null,
    @Json(name = "reason") val reason: String? = null,
)

/** Cancel request. Verified: SubscriptionCancelIn — cancel_at_period_end defaults true. */
@JsonClass(generateAdapter = true)
data class CancelSubscriptionReqDto(
    @Json(name = "cancel_at_period_end") val cancelAtPeriodEnd: Boolean = true,
    @Json(name = "reason") val reason: String? = null,
)
