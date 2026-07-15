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
 *  - POST api/subscriptions/{subscription_id}/renewal req=SubscriptionRenewalIn resp=SubscriptionOut x-user-id (AND-237)
 *  - POST api/subscriptions/{subscription_id}/resume  req=SubscriptionResumeIn  resp=SubscriptionOut x-user-id (AND-237)
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

    /**
     * SUB-E2 PART 2 (SUB-23) — gift ONE cycle of a creator plan to another user. The GIFTER
     * (X-User-Id) is charged once; the recipient receives a no-renew (auto_renew=false) sub that
     * lapses at period end. Returns the created recipient SubscriptionOut.
     */
    @Headers("Content-Type: application/json")
    @POST("api/plans/{planId}/gift")
    suspend fun gift(
        @Header("X-User-Id") userId: String,
        @Path("planId") planId: String,
        @Body body: GiftSubscriptionReqDto,
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

    /**
     * AND-237 — clear a scheduled cancellation / toggle auto-renew (POST .../renewal -> updated
     * SubscriptionOut). Sending auto_renew=true un-cancels an active cancel-at-period-end sub.
     */
    @Headers("Content-Type: application/json")
    @POST("api/subscriptions/{subscriptionId}/renewal")
    suspend fun renewal(
        @Header("X-User-Id") userId: String,
        @Path("subscriptionId") subscriptionId: String,
        @Body body: RenewalReqDto,
    ): SubscriptionOutDto

    /**
     * AND-237 — reactivate a paused/canceled (no-new-payment) subscription (POST .../resume ->
     * updated SubscriptionOut).
     */
    @Headers("Content-Type: application/json")
    @POST("api/subscriptions/{subscriptionId}/resume")
    suspend fun resume(
        @Header("X-User-Id") userId: String,
        @Path("subscriptionId") subscriptionId: String,
        @Body body: ResumeSubscriptionReqDto,
    ): SubscriptionOutDto

    /**
     * SUBX-22 — retry a PAST_DUE (dunning) subscription's failed renewal charge. Optionally swaps the
     * PM first (the subscriber just added a card). On a real collected charge past_due clears to
     * active; a decline / missing PM returns HTTP 402. Returns the updated SubscriptionOut.
     */
    @Headers("Content-Type: application/json")
    @POST("api/subscriptions/{subscriptionId}/retry-payment")
    suspend fun retryPayment(
        @Header("X-User-Id") userId: String,
        @Path("subscriptionId") subscriptionId: String,
        @Body body: RetryPaymentReqDto,
    ): SubscriptionOutDto

    // ---- SUB-E4-3: creator subscriber management + MRR/analytics ----

    /** SUB-E4-1 - owner-scoped creator subscriber list (CREATOR#SUB# index). Requires X-User-Id. */
    @GET("api/creators/{creatorId}/subscribers")
    suspend fun creatorSubscribers(
        @Header("X-User-Id") userId: String,
        @Path("creatorId") creatorId: String,
        @Query("status") status: String? = null,
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): CreatorSubscriberListDto

    /** SUB-E4-2 - MRR/analytics computed from the creator sub records + ledger. Requires X-User-Id. */
    @GET("api/creators/{creatorId}/subscription-analytics")
    suspend fun subscriptionAnalytics(
        @Header("X-User-Id") userId: String,
        @Path("creatorId") creatorId: String,
        @Query("period_days") periodDays: Int? = null,
    ): SubscriptionAnalyticsDto

    /** SUB-E4-3 - creator removes a subscriber (cancel + refund). Returns updated SubscriptionOut. */
    @Headers("Content-Type: application/json")
    @POST("api/creators/{creatorId}/subscriptions/{subscriptionId}/remove")
    suspend fun removeSubscriber(
        @Header("X-User-Id") userId: String,
        @Path("creatorId") creatorId: String,
        @Path("subscriptionId") subscriptionId: String,
        @Body body: CreatorSubscriberActionReqDto,
    ): SubscriptionOutDto

    /** SUB-E4-3 - creator stops a subscriber renewal (cancel at period end). Returns SubscriptionOut. */
    @Headers("Content-Type: application/json")
    @POST("api/creators/{creatorId}/subscriptions/{subscriptionId}/stop-renewal")
    suspend fun stopSubscriberRenewal(
        @Header("X-User-Id") userId: String,
        @Path("creatorId") creatorId: String,
        @Path("subscriptionId") subscriptionId: String,
        @Body body: CreatorSubscriberActionReqDto,
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
    // SUB-E0: structured tier benefits/perks ({label, detail}) beyond the free-form assets.
    @Json(name = "benefits") val benefits: List<PlanBenefitDto>? = null,
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

/**
 * SUB-E0 - a structured tier benefit/perk descriptor (label + optional detail). First-class,
 * distinct from the free-form asset names; verified against backend PlanBenefit (subscription_server.py).
 */
@JsonClass(generateAdapter = true)
data class PlanBenefitDto(
    @Json(name = "label") val label: String,
    @Json(name = "detail") val detail: String? = null,
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
    // SUB-E0: authoritative next-charge timestamp + the PM/PI that were actually charged.
    @Json(name = "next_billing_date") val nextBillingDate: Long? = null,
    @Json(name = "payment_method_id") val paymentMethodId: String? = null,
    @Json(name = "payment_intent_id") val paymentIntentId: String? = null,
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
    // ADV-405: last-click CPA attribution handle carried from an ad CTA (backend ADV-402 SubscribeIn).
    @Json(name = "ad_click_id") val adClickId: String? = null,
    @Json(name = "discount_code") val discountCode: String? = null,
    @Json(name = "trial_days") val trialDays: Int? = null,
    @Json(name = "subscriber_id") val subscriberId: String? = null,
    // SUB-E0: the PM to charge (explicit -> subscriber default). A non-trial subscribe with no
    // resolvable PM is rejected server-side with HTTP 402 (no phantom subscription).
    @Json(name = "payment_method_id") val paymentMethodId: String? = null,
    // SUB-E0: client idempotency key - a retry with the same value never double-charges/subscribes.
    @Json(name = "client_request_id") val clientRequestId: String? = null,
)

/**
 * SUB-E2 PART 2 (SUB-23) — gift request. recipient_id is required; the gifter pays one cycle. Verified
 * against backend SubscriptionGiftIn (subscription_server.py:441).
 */
@JsonClass(generateAdapter = true)
data class GiftSubscriptionReqDto(
    @Json(name = "recipient_id") val recipientId: String,
    @Json(name = "interval") val interval: String? = null,
    @Json(name = "payment_method_id") val paymentMethodId: String? = null,
    @Json(name = "message") val message: String? = null,
    @Json(name = "client_request_id") val clientRequestId: String? = null,
)

/** Change-plan request. Verified: SubscriptionChangePlanIn — `plan_id` required. */
@JsonClass(generateAdapter = true)
data class ChangePlanReqDto(
    @Json(name = "plan_id") val planId: String,
    @Json(name = "interval") val interval: String? = null,
    @Json(name = "effective") val effective: String? = null,
    @Json(name = "proration_policy") val prorationPolicy: String? = null,
    // SUB-E2: the PM to charge an UPGRADE prorated delta against (blank -> subscriber default).
    @Json(name = "payment_method_id") val paymentMethodId: String? = null,
    @Json(name = "reason") val reason: String? = null,
)

/** Cancel request. Verified: SubscriptionCancelIn — cancel_at_period_end defaults true. */
@JsonClass(generateAdapter = true)
data class CancelSubscriptionReqDto(
    @Json(name = "cancel_at_period_end") val cancelAtPeriodEnd: Boolean = true,
    // SUB-E2 PART 2 (SUB-25): on an IMMEDIATE cancel (cancel_at_period_end=false) refund the unused
    // prorated portion by default; pass false to force immediate-cancel with no refund. Ignored when
    // cancelling at period end (that path never refunds).
    @Json(name = "refund") val refund: Boolean? = null,
    @Json(name = "reason") val reason: String? = null,
)

/**
 * AND-237 — renewal request. Verified: SubscriptionRenewalIn (subscriptions.ts updateRenewal —
 * `auto_renew` required; effective/renewal_policy/reason optional). Sending auto_renew=true clears a
 * scheduled cancel.
 */
@JsonClass(generateAdapter = true)
data class RenewalReqDto(
    @Json(name = "auto_renew") val autoRenew: Boolean = true,
    @Json(name = "effective") val effective: String? = null,
    @Json(name = "renewal_policy") val renewalPolicy: String? = null,
    @Json(name = "reason") val reason: String? = null,
)

/** AND-237 — resume request. Verified: SubscriptionResumeIn (subscriptions.ts resumeSubscription — reason only). */
@JsonClass(generateAdapter = true)
data class ResumeSubscriptionReqDto(
    @Json(name = "reason") val reason: String? = null,
)

/** SUBX-22 — retry-payment request. Optional PM swap for PAST_DUE dunning recovery. */
@JsonClass(generateAdapter = true)
data class RetryPaymentReqDto(
    @Json(name = "payment_method_id") val paymentMethodId: String? = null,
    @Json(name = "reason") val reason: String? = null,
)

// ---- SUB-E4-3 DTOs (creator subscriber management + analytics) ----

/** SUB-E4-1 - one row of the creator subscriber list (CREATOR#SUB# index). */
@JsonClass(generateAdapter = true)
data class CreatorSubscriberDto(
    @Json(name = "subscription_id") val subscriptionId: String,
    @Json(name = "subscriber_id") val subscriberId: String,
    @Json(name = "subscriber_name") val subscriberName: String? = null,
    @Json(name = "plan_id") val planId: String? = null,
    @Json(name = "plan_name") val planName: String? = null,
    @Json(name = "status") val status: String,
    @Json(name = "interval") val interval: String? = null,
    @Json(name = "price_cents") val priceCents: Long = 0,
    @Json(name = "currency") val currency: String? = null,
    @Json(name = "since") val since: Long = 0,
    @Json(name = "current_period_end") val currentPeriodEnd: Long? = null,
    @Json(name = "next_billing_date") val nextBillingDate: Long? = null,
    @Json(name = "cancel_at_period_end") val cancelAtPeriodEnd: Boolean = false,
    @Json(name = "auto_renew") val autoRenew: Boolean = true,
    @Json(name = "is_gift") val isGift: Boolean = false,
    @Json(name = "gifter_id") val gifterId: String? = null,
    @Json(name = "is_trial") val isTrial: Boolean = false,
)

/** SUB-E4-1 - paginated creator subscriber list envelope. */
@JsonClass(generateAdapter = true)
data class CreatorSubscriberListDto(
    @Json(name = "creator_id") val creatorId: String,
    @Json(name = "status_filter") val statusFilter: String? = null,
    @Json(name = "count") val count: Int = 0,
    @Json(name = "total") val total: Int = 0,
    @Json(name = "next_cursor") val nextCursor: String? = null,
    @Json(name = "subscribers") val subscribers: List<CreatorSubscriberDto> = emptyList(),
)

/** SUB-E4-2 - creator subscription MRR/analytics projection. */
@JsonClass(generateAdapter = true)
data class SubscriptionAnalyticsDto(
    @Json(name = "creator_id") val creatorId: String,
    @Json(name = "currency") val currency: String? = null,
    @Json(name = "generated_at") val generatedAt: Long = 0,
    @Json(name = "active_subscribers") val activeSubscribers: Int = 0,
    @Json(name = "trialing") val trialing: Int = 0,
    @Json(name = "past_due") val pastDue: Int = 0,
    @Json(name = "canceled_total") val canceledTotal: Int = 0,
    @Json(name = "total_subscribers") val totalSubscribers: Int = 0,
    @Json(name = "mrr_cents") val mrrCents: Long = 0,
    @Json(name = "arpu_cents") val arpuCents: Long = 0,
    @Json(name = "period_days") val periodDays: Int = 30,
    @Json(name = "new_subs_30d") val newSubs30d: Int = 0,
    @Json(name = "churned_30d") val churned30d: Int = 0,
    @Json(name = "churn_rate") val churnRate: Double = 0.0,
    @Json(name = "gross_revenue_to_date_cents") val grossRevenueToDateCents: Long = 0,
    @Json(name = "fee_to_date_cents") val feeToDateCents: Long = 0,
    @Json(name = "refunded_to_date_cents") val refundedToDateCents: Long = 0,
    @Json(name = "net_revenue_to_date_cents") val netRevenueToDateCents: Long = 0,
)

/** SUB-E4-3 - creator subscriber action (remove / stop-renewal) request; reason optional. */
@JsonClass(generateAdapter = true)
data class CreatorSubscriberActionReqDto(
    @Json(name = "reason") val reason: String? = null,
)
