package com.testlogon.android.data.subscriptions

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult

/**
 * AND-236 / AND-237 — a configurable [SubscriptionsRepository] test double shared by the subscribe and
 * manage-subscription ViewModel tests. Records call counts so tests can assert that the subscribe /
 * cancel / renew / resume endpoints are (or are NOT) hit, and lets each method's result be programmed.
 *
 * NOT named the same as any [SubscriptionsRepository] member (per the test-helper gotcha): the builder
 * for a sample subscription is [sampleSubscription].
 */
class TestSubscriptionsRepository : SubscriptionsRepository {

    var tiersResult: ApiResult<List<SubscriptionTier>> = ApiResult.Success(emptyList())
    var mySubsResult: ApiResult<List<CreatorSubscription>> = ApiResult.Success(emptyList())
    var summaryResult: ApiResult<CreatorSubscriptionSummary> =
        ApiResult.Failure(ApiError(status = 500, message = "not configured"))
    var subscribeResult: ApiResult<CreatorSubscription> =
        ApiResult.Failure(ApiError(status = 500, message = "not configured"))
    var cancelResult: ApiResult<CreatorSubscription> =
        ApiResult.Failure(ApiError(status = 500, message = "not configured"))
    var renewResult: ApiResult<CreatorSubscription> =
        ApiResult.Failure(ApiError(status = 500, message = "not configured"))
    var resumeResult: ApiResult<CreatorSubscription> =
        ApiResult.Failure(ApiError(status = 500, message = "not configured"))
    var changePlanResult: ApiResult<CreatorSubscription> =
        ApiResult.Failure(ApiError(status = 500, message = "not configured"))
    var giftResult: ApiResult<CreatorSubscription> =
        ApiResult.Failure(ApiError(status = 500, message = "not configured"))

    var subscribeCalls = 0
        private set
    var cancelCalls = 0
        private set
    var renewCalls = 0
        private set
    var resumeCalls = 0
        private set
    var changePlanCalls = 0
        private set
    var giftCalls = 0
        private set

    override suspend fun getCreatorTiers(creatorId: String) = tiersResult
    override suspend fun getMySubscriptions() = mySubsResult
    override suspend fun getSubscriptionSummary(subscriptionId: String) = summaryResult

    override suspend fun subscribe(planId: String, body: SubscribeReqDto): ApiResult<CreatorSubscription> {
        subscribeCalls++
        return subscribeResult
    }

    override suspend fun cancel(
        subscriptionId: String,
        body: CancelSubscriptionReqDto,
    ): ApiResult<CreatorSubscription> {
        cancelCalls++
        return cancelResult
    }

    override suspend fun renew(subscriptionId: String, body: RenewalReqDto): ApiResult<CreatorSubscription> {
        renewCalls++
        return renewResult
    }

    override suspend fun resume(
        subscriptionId: String,
        body: ResumeSubscriptionReqDto,
    ): ApiResult<CreatorSubscription> {
        resumeCalls++
        return resumeResult
    }

    override suspend fun changePlan(
        subscriptionId: String,
        body: ChangePlanReqDto,
    ): ApiResult<CreatorSubscription> {
        changePlanCalls++
        return changePlanResult
    }

    override suspend fun gift(
        planId: String,
        body: GiftSubscriptionReqDto,
    ): ApiResult<CreatorSubscription> {
        giftCalls++
        return giftResult
    }

    // ---- SUBX-40/43 + SUB-E4 additions (creator tier authoring, subscriber mgmt, analytics) ----
    // Programmable results; default to a "not configured" failure so a test opting into these
    // surfaces must set them explicitly (mirrors the pre-existing style above).
    var creatorTiersResult: ApiResult<List<SubscriptionTier>> = ApiResult.Success(emptyList())
    var myTiersResult: ApiResult<List<SubscriptionTier>> = ApiResult.Success(emptyList())
    var createTierResult: ApiResult<SubscriptionTier> =
        ApiResult.Failure(ApiError(status = 500, message = "not configured"))
    var updateTierResult: ApiResult<SubscriptionTier> =
        ApiResult.Failure(ApiError(status = 500, message = "not configured"))
    var archiveTierResult: ApiResult<SubscriptionTier> =
        ApiResult.Failure(ApiError(status = 500, message = "not configured"))
    var reorderTiersResult: ApiResult<List<SubscriptionTier>> = ApiResult.Success(emptyList())
    var refundSubscriberResult: ApiResult<SubscriptionRefundResult> =
        ApiResult.Failure(ApiError(status = 500, message = "not configured"))
    var retryPaymentResult: ApiResult<CreatorSubscription> =
        ApiResult.Failure(ApiError(status = 500, message = "not configured"))
    var mySubscribersResult: ApiResult<CreatorSubscriberPage> =
        ApiResult.Failure(ApiError(status = 500, message = "not configured"))
    var myAnalyticsResult: ApiResult<SubscriptionAnalytics> =
        ApiResult.Failure(ApiError(status = 500, message = "not configured"))
    var removeSubscriberResult: ApiResult<CreatorSubscription> =
        ApiResult.Failure(ApiError(status = 500, message = "not configured"))
    var stopSubscriberRenewalResult: ApiResult<CreatorSubscription> =
        ApiResult.Failure(ApiError(status = 500, message = "not configured"))

    override suspend fun getMyTiers() = myTiersResult
    override suspend fun createTier(body: PlanWriteReqDto) = createTierResult
    override suspend fun updateTier(planId: String, body: PlanWriteReqDto) = updateTierResult
    override suspend fun archiveTier(planId: String) = archiveTierResult
    override suspend fun reorderTiers(planIds: List<String>) = reorderTiersResult
    override suspend fun refundSubscriber(
        subscriptionId: String,
        fraction: Double?,
        reason: String?,
    ) = refundSubscriberResult

    override suspend fun retryPayment(
        subscriptionId: String,
        body: RetryPaymentReqDto,
    ) = retryPaymentResult

    override suspend fun getMySubscribers(
        status: String?,
        planId: String?,
        limit: Int?,
        cursor: String?,
    ) = mySubscribersResult

    override suspend fun getMyAnalytics(periodDays: Int?) = myAnalyticsResult
    override suspend fun removeSubscriber(subscriptionId: String, reason: String?) = removeSubscriberResult
    override suspend fun stopSubscriberRenewal(subscriptionId: String, reason: String?) = stopSubscriberRenewalResult
}

/** Sample [CreatorSubscription] builder (NOT named like an interface member). */
fun sampleSubscription(
    subscriptionId: String = "sub_1",
    planId: String = "plan_basic",
    creatorId: String = "usr_42",
    status: SubscriptionState = SubscriptionState.ACTIVE,
    cancelAtPeriodEnd: Boolean = false,
    currentPeriodEnd: Long? = 1_751_716_800L,
    priceCents: Long? = 499,
    currency: String? = "USD",
): CreatorSubscription = CreatorSubscription(
    subscriptionId = subscriptionId,
    planId = planId,
    creatorId = creatorId,
    subscriberId = "usr_me",
    interval = BillingInterval.MONTH,
    provider = "ccbill",
    status = status,
    startAtEpochSeconds = 1_749_124_800L,
    currentPeriodEndEpochSeconds = currentPeriodEnd,
    cancelAtPeriodEnd = cancelAtPeriodEnd,
    priceCents = priceCents,
    currency = currency,
    autoRenew = !cancelAtPeriodEnd,
)
