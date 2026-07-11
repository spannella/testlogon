package com.testlogon.android.data.subscriptions

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.auth.AuthStateStore
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-234 — subscriptions data layer over [SubscriptionsApi].
 *
 * Wraps every call in [ApiResult] (matching the billing/catalog repositories): CancellationException
 * is re-thrown, HTTP errors fold to Failure (via [ApiErrorParser]), transport failures to
 * NetworkError. DTOs are mapped to domain before returning (no raw DTOs leak out).
 *
 * The authenticated reads/mutations require the `X-User-Id` header (verified: reference
 * subscriptions.ts userIdHeader()); the current principal is read from [AuthStateStore.userSub].
 * The public plan list omits it. GET reads are idempotent; subscribe/cancel are non-idempotent and
 * never auto-retried (the subscribe action additionally routes through the BillingAuthorizer stub at
 * the feature layer, so this layer is only reached once payments are configured).
 */
interface SubscriptionsRepository {

    /** Public — a creator's offered plans ("tiers"). */
    suspend fun getCreatorTiers(creatorId: String): ApiResult<List<SubscriptionTier>>

    /** The viewer's own subscriptions (X-User-Id). */
    suspend fun getMySubscriptions(): ApiResult<List<CreatorSubscription>>

    /** Single-subscription summary read (X-User-Id). */
    suspend fun getSubscriptionSummary(subscriptionId: String): ApiResult<CreatorSubscriptionSummary>

    /** Subscribe to [planId] (X-User-Id). Non-idempotent. */
    suspend fun subscribe(planId: String, body: SubscribeReqDto = SubscribeReqDto()): ApiResult<CreatorSubscription>

    /**
     * SUB-E2 — upgrade/downgrade an existing subscription to another plan (X-User-Id). An UPGRADE
     * (higher price) charges the prorated delta immediately; a DOWNGRADE is scheduled at period end.
     */
    suspend fun changePlan(
        subscriptionId: String,
        body: ChangePlanReqDto,
    ): ApiResult<CreatorSubscription>

    /** SUB-E2 PART 2 — gift ONE cycle of [planId] to another user; the gifter (X-User-Id) pays once. */
    suspend fun gift(
        planId: String,
        body: GiftSubscriptionReqDto,
    ): ApiResult<CreatorSubscription>

    /** Cancel [subscriptionId] (X-User-Id). */
    suspend fun cancel(
        subscriptionId: String,
        body: CancelSubscriptionReqDto = CancelSubscriptionReqDto(),
    ): ApiResult<CreatorSubscription>

    /**
     * AND-237 — clear a scheduled cancellation / re-enable auto-renew on [subscriptionId] (X-User-Id).
     * No new payment is taken; the server returns the updated subscription.
     */
    suspend fun renew(
        subscriptionId: String,
        body: RenewalReqDto = RenewalReqDto(),
    ): ApiResult<CreatorSubscription>

    /** AND-237 — reactivate a paused/canceled (no-new-payment) [subscriptionId] (X-User-Id). */
    suspend fun resume(
        subscriptionId: String,
        body: ResumeSubscriptionReqDto = ResumeSubscriptionReqDto(),
    ): ApiResult<CreatorSubscription>

    /** SUB-E4-1 - the current creator own subscriber list (owner-scoped; X-User-Id = creator id). */
    suspend fun getMySubscribers(
        status: String? = null,
        limit: Int? = null,
        cursor: String? = null,
    ): ApiResult<CreatorSubscriberPage>

    /** SUB-E4-2 - the current creator own subscription MRR/analytics (owner-scoped). */
    suspend fun getMyAnalytics(periodDays: Int? = null): ApiResult<SubscriptionAnalytics>

    /** SUB-E4-3 - creator removes one of their subscribers (cancel + refund). */
    suspend fun removeSubscriber(subscriptionId: String, reason: String? = null): ApiResult<CreatorSubscription>

    /** SUB-E4-3 - creator stops a subscriber auto-renewal (cancel at period end). */
    suspend fun stopSubscriberRenewal(subscriptionId: String, reason: String? = null): ApiResult<CreatorSubscription>
}

@Singleton
class SubscriptionsRepositoryImpl @Inject constructor(
    private val api: SubscriptionsApi,
    private val errorParser: ApiErrorParser,
    private val authStateStore: AuthStateStore,
) : SubscriptionsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun getCreatorTiers(creatorId: String): ApiResult<List<SubscriptionTier>> =
        withContext(io) {
            call { api.plans(creatorId) }.map { dtos -> dtos.map { it.toDomain() } }
        }

    override suspend fun getMySubscriptions(): ApiResult<List<CreatorSubscription>> = withContext(io) {
        val userId = currentUserId() ?: return@withContext unauthenticated()
        call { api.mySubscriptions(userId) }.map { dtos -> dtos.map { it.toDomain() } }
    }

    override suspend fun getSubscriptionSummary(
        subscriptionId: String,
    ): ApiResult<CreatorSubscriptionSummary> = withContext(io) {
        val userId = currentUserId() ?: return@withContext unauthenticated()
        call { api.subscriptionSummary(userId, subscriptionId) }.map { it.toDomain() }
    }

    override suspend fun subscribe(
        planId: String,
        body: SubscribeReqDto,
    ): ApiResult<CreatorSubscription> = withContext(io) {
        val userId = currentUserId() ?: return@withContext unauthenticated()
        call { api.subscribe(userId, planId, body) }.map { it.toDomain() }
    }

    override suspend fun changePlan(
        subscriptionId: String,
        body: ChangePlanReqDto,
    ): ApiResult<CreatorSubscription> = withContext(io) {
        val userId = currentUserId() ?: return@withContext unauthenticated()
        call { api.changePlan(userId, subscriptionId, body) }.map { it.toDomain() }
    }

    override suspend fun gift(
        planId: String,
        body: GiftSubscriptionReqDto,
    ): ApiResult<CreatorSubscription> = withContext(io) {
        val userId = currentUserId() ?: return@withContext unauthenticated()
        call { api.gift(userId, planId, body) }.map { it.toDomain() }
    }

    override suspend fun cancel(
        subscriptionId: String,
        body: CancelSubscriptionReqDto,
    ): ApiResult<CreatorSubscription> = withContext(io) {
        val userId = currentUserId() ?: return@withContext unauthenticated()
        call { api.cancel(userId, subscriptionId, body) }.map { it.toDomain() }
    }

    override suspend fun renew(
        subscriptionId: String,
        body: RenewalReqDto,
    ): ApiResult<CreatorSubscription> = withContext(io) {
        val userId = currentUserId() ?: return@withContext unauthenticated()
        call { api.renewal(userId, subscriptionId, body) }.map { it.toDomain() }
    }

    override suspend fun resume(
        subscriptionId: String,
        body: ResumeSubscriptionReqDto,
    ): ApiResult<CreatorSubscription> = withContext(io) {
        val userId = currentUserId() ?: return@withContext unauthenticated()
        call { api.resume(userId, subscriptionId, body) }.map { it.toDomain() }
    }

    override suspend fun getMySubscribers(
        status: String?,
        limit: Int?,
        cursor: String?,
    ): ApiResult<CreatorSubscriberPage> = withContext(io) {
        val userId = currentUserId() ?: return@withContext unauthenticated()
        call { api.creatorSubscribers(userId, userId, status, limit, cursor) }.map { it.toDomain() }
    }

    override suspend fun getMyAnalytics(periodDays: Int?): ApiResult<SubscriptionAnalytics> = withContext(io) {
        val userId = currentUserId() ?: return@withContext unauthenticated()
        call { api.subscriptionAnalytics(userId, userId, periodDays) }.map { it.toDomain() }
    }

    override suspend fun removeSubscriber(
        subscriptionId: String,
        reason: String?,
    ): ApiResult<CreatorSubscription> = withContext(io) {
        val userId = currentUserId() ?: return@withContext unauthenticated()
        call { api.removeSubscriber(userId, userId, subscriptionId, CreatorSubscriberActionReqDto(reason)) }
            .map { it.toDomain() }
    }

    override suspend fun stopSubscriberRenewal(
        subscriptionId: String,
        reason: String?,
    ): ApiResult<CreatorSubscription> = withContext(io) {
        val userId = currentUserId() ?: return@withContext unauthenticated()
        call { api.stopSubscriberRenewal(userId, userId, subscriptionId, CreatorSubscriberActionReqDto(reason)) }
            .map { it.toDomain() }
    }

    private suspend fun currentUserId(): String? = authStateStore.userSub.first()?.takeIf { it.isNotBlank() }

    private fun <T> unauthenticated(): ApiResult<T> =
        ApiResult.Failure(errorParser.fromThrowable(IOException(UNAUTHENTICATED)))

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    private companion object {
        const val UNAUTHENTICATED = "Not signed in"
    }
}
