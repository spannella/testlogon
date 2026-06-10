package com.testlogon.android.data.fanclub

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.LogoutReason
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.data.subscriptions.CancelSubscriptionReqDto
import com.testlogon.android.data.subscriptions.CreatorSubscription
import com.testlogon.android.data.subscriptions.CreatorSubscriptionSummary
import com.testlogon.android.data.subscriptions.RenewalReqDto
import com.testlogon.android.data.subscriptions.ResumeSubscriptionReqDto
import com.testlogon.android.data.subscriptions.SubscribeReqDto
import com.testlogon.android.data.subscriptions.SubscriptionTier
import com.testlogon.android.data.subscriptions.SubscriptionsRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** Minimal [AuthStateStore] fake — only [userSub] is exercised by the fan-club layer. */
class FakeAuthStateStore(userSub: String? = null) : AuthStateStore {
    private val _userSub = MutableStateFlow(userSub)
    override val userSub: StateFlow<String?> = _userSub
    private val _isAuthenticated = MutableStateFlow(userSub != null)
    override val isAuthenticated: StateFlow<Boolean> = _isAuthenticated

    override suspend fun setAuthenticated(userSub: String) {
        _userSub.value = userSub
        _isAuthenticated.value = true
    }

    override suspend fun clear(reason: LogoutReason) {
        _userSub.value = null
        _isAuthenticated.value = false
    }

    override suspend fun lastLogoutReason(): LogoutReason? = null
    override suspend fun clearLogoutReason() = Unit
}

/** [SubscriptionsRepository] fake — only [getMySubscriptions] is exercised (for the active-tier join). */
class FakeSubscriptionsRepository(
    private val mySubscriptions: ApiResult<List<CreatorSubscription>> = ApiResult.Success(emptyList()),
) : SubscriptionsRepository {
    override suspend fun getCreatorTiers(creatorId: String): ApiResult<List<SubscriptionTier>> =
        ApiResult.Success(emptyList())

    override suspend fun getMySubscriptions(): ApiResult<List<CreatorSubscription>> = mySubscriptions

    override suspend fun getSubscriptionSummary(subscriptionId: String): ApiResult<CreatorSubscriptionSummary> =
        ApiResult.Success(
            CreatorSubscriptionSummary(
                subscriptionId = subscriptionId,
                status = com.testlogon.android.data.subscriptions.SubscriptionState.ACTIVE,
                cancelAtPeriodEnd = false,
                totalPaidCents = 0,
                currency = null,
                nextAmountCents = 0,
                nextRenewalAtEpochSeconds = null,
                lastInvoiceAtEpochSeconds = null,
            ),
        )

    override suspend fun subscribe(planId: String, body: SubscribeReqDto): ApiResult<CreatorSubscription> =
        error("not used")

    override suspend fun cancel(subscriptionId: String, body: CancelSubscriptionReqDto): ApiResult<CreatorSubscription> =
        error("not used")

    override suspend fun renew(subscriptionId: String, body: RenewalReqDto): ApiResult<CreatorSubscription> =
        error("not used")

    override suspend fun resume(subscriptionId: String, body: ResumeSubscriptionReqDto): ApiResult<CreatorSubscription> =
        error("not used")
}
