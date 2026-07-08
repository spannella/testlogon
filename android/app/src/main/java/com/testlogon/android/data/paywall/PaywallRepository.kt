package com.testlogon.android.data.paywall

import com.testlogon.android.core.data.paywall.EntitlementDao
import com.testlogon.android.core.data.paywall.EntitlementEntity
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.ads.AdClickAttributionStore
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-177 — outcome of an unlock attempt (domain projection consumed by the ViewModel).
 */
sealed interface UnlockOutcome {
    data class Success(val postId: String) : UnlockOutcome
    data object AlreadyEntitled : UnlockOutcome

    /**
     * STOP-AND-FLAG (payments, AND-031): no real billing provider is wired
     * ([com.testlogon.android.data.messaging.StubBillingAuthorizer] returns NotConfigured), so we did
     * NOT call /posts/unlock and did NOT fake a charge. The UI must surface a "payments unavailable"
     * state. Replacing the BillingAuthorizer binding enables the real flow with no ViewModel changes.
     */
    data object PaymentsUnavailable : UnlockOutcome
    data object SoldOut : UnlockOutcome
    data class Cancelled(val reason: String? = null) : UnlockOutcome
    data class Failure(val message: String, val retryable: Boolean) : UnlockOutcome
}

/**
 * AND-177 — paywall unlock + durable entitlement caching.
 *
 * REUSES the AND-139 [BillingAuthorizer] seam: fixed-price unlock requires a payment_method_id obtained
 * from the (out-of-scope) payment picker. The shipped [com.testlogon.android.data.messaging.StubBillingAuthorizer]
 * returns [BillingResult.NotConfigured], so this repo short-circuits to [UnlockOutcome.PaymentsUnavailable]
 * and never calls the unlock endpoint or fakes a charge (STOP-AND-FLAG). When a real authorizer is bound,
 * the full call path runs: authorize -> POST /posts/unlock -> cache entitlement -> reveal.
 *
 * Entitlements are cached in Room keyed by (userSub, postId) so a relaunch / fresh feed shows the post
 * already unlocked without re-charging (FR-4). A stable idempotency_key per (postId, session) makes a
 * user-initiated retry safe against double-charge (FR-5).
 */
interface PaywallRepository {

    /** Reactive entitlement for a post (true => reveal without a network call). */
    fun isEntitled(postId: String): Flow<Boolean>

    /** Reactive set of entitled post ids for the current user (drives the feed reveal overlay). */
    val entitledPostIds: Flow<Set<String>>

    suspend fun unlock(postId: String): UnlockOutcome

    /** Clears the current user's entitlement cache (logout / account switch). */
    suspend fun clearEntitlementsForCurrentUser()
}

@Singleton
class PaywallRepositoryImpl @Inject constructor(
    private val api: PaywallApi,
    private val billing: BillingAuthorizer,
    private val adAttribution: AdClickAttributionStore,
    private val dao: EntitlementDao,
    private val authState: AuthStateStore,
    private val errorParser: ApiErrorParser,
) : PaywallRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    // Stable per-(postId, process-session) idempotency keys for safe retries.
    private val idempotencyKeys = mutableMapOf<String, String>()

    override fun isEntitled(postId: String): Flow<Boolean> {
        val userSub = authState.userSub.value ?: return flowOf(false)
        return dao.isEntitled(userSub, postId)
    }

    override val entitledPostIds: Flow<Set<String>>
        get() {
            val userSub = authState.userSub.value ?: return flowOf(emptySet())
            return dao.observeEntitledPosts(userSub).map { it.toHashSet() }
        }

    override suspend fun unlock(postId: String): UnlockOutcome = withContext(io) {
        val userSub = authState.userSub.value
            ?: return@withContext UnlockOutcome.Failure(MSG_SIGN_IN, retryable = false)

        // 1. Short-circuit if already entitled (no HTTP, no charge).
        if (dao.exists(userSub, postId)) return@withContext UnlockOutcome.AlreadyEntitled

        // 2. Authorize payment via the billing seam (AND-139). Stub => NotConfigured (STOP-AND-FLAG).
        val billingResult = billing.authorize(amountMinorUnits = 0L, currency = CURRENCY_USD)
        val paymentMethodId: String = when (billingResult) {
            is BillingResult.Authorized -> billingResult.paymentMethodId
            BillingResult.NotConfigured -> return@withContext UnlockOutcome.PaymentsUnavailable
            BillingResult.Cancelled -> return@withContext UnlockOutcome.Cancelled()
            is BillingResult.Declined -> return@withContext UnlockOutcome.Failure(billingResult.reason, retryable = true)
            is BillingResult.Failed -> return@withContext UnlockOutcome.Failure(MSG_GENERIC, retryable = true)
        }

        // 3. Call /posts/unlock with the authorized payment method + a stable idempotency key.
        val idemKey = idempotencyKeys.getOrPut(postId) { "unlock:$postId:${randomNonce()}" }
        val result = try {
            val resp = api.unlock(
                UnlockPostRequestDto(
                    postId = postId,
                    paymentMethodId = paymentMethodId,
                    // ADV-405: attach the session last-click ad_click_id so an unlock converts the ad (ADV-404).
                    adClickId = adAttribution.peek(),
                    idempotencyKey = idemKey,
                ),
            )
            mapSuccess(userSub, postId, resp)
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            mapHttpError(userSub, postId, e)
        } catch (e: IOException) {
            UnlockOutcome.Failure(MSG_OFFLINE, retryable = true)
        }
        result
    }

    private suspend fun mapSuccess(userSub: String, postId: String, resp: UnlockPostResponseDto): UnlockOutcome {
        // payment_intent is opaque; a 200 with an intent is treated as confirmable (real provider would
        // action "requires_action"). On a confirmed/already-paid intent, write the entitlement + clear key.
        writeEntitlement(userSub, postId, source = "purchase")
        idempotencyKeys.remove(postId)
        return UnlockOutcome.Success(postId)
    }

    private suspend fun mapHttpError(userSub: String, postId: String, e: HttpException): UnlockOutcome {
        val error = errorParser.from(e)
        return when (error.status) {
            HTTP_CONFLICT -> {
                // Already unlocked / race -> treat as entitled, reveal, no error (FR-6 / AC-5).
                writeEntitlement(userSub, postId, source = "already_entitled")
                idempotencyKeys.remove(postId)
                UnlockOutcome.AlreadyEntitled
            }
            HTTP_PAYMENT_REQUIRED -> UnlockOutcome.Failure(error.message, retryable = true)
            else -> UnlockOutcome.Failure(error.message, retryable = error.status >= 500)
        }
    }

    private suspend fun writeEntitlement(userSub: String, postId: String, source: String) {
        dao.upsert(
            EntitlementEntity(
                userSub = userSub,
                postId = postId,
                unlockedAtEpochMs = System.currentTimeMillis(),
                source = source,
            ),
        )
    }

    override suspend fun clearEntitlementsForCurrentUser() {
        val userSub = authState.userSub.first() ?: return
        dao.clearForUser(userSub)
    }

    private fun randomNonce(): String =
        (0 until NONCE_LEN).map { NONCE_ALPHABET.random() }.joinToString("")

    private companion object {
        const val CURRENCY_USD = "USD"
        const val HTTP_CONFLICT = 409
        const val HTTP_PAYMENT_REQUIRED = 402
        const val NONCE_LEN = 8
        const val NONCE_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
        const val MSG_SIGN_IN = "Please sign in again."
        const val MSG_OFFLINE = "You're offline. Try again."
        const val MSG_GENERIC = "Couldn't unlock. Try again."
    }
}
