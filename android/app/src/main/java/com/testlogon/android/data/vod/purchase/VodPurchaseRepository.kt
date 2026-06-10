package com.testlogon.android.data.vod.purchase

import com.testlogon.android.core.data.paywall.EntitlementDao
import com.testlogon.android.core.data.paywall.EntitlementEntity
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-193 — outcome of a tier purchase (domain projection consumed by the ViewModel).
 *
 * Mirrors the AND-177 paywall outcome: a stubbed billing authorizer short-circuits to
 * [PaymentsUnavailable] and NEVER calls purchase or fakes a charge (STOP-AND-FLAG).
 */
sealed interface PurchaseOutcome {
    /** Purchased (or already-owned idempotent success): content is now unlocked. */
    data class Unlocked(val entitlement: Entitlement) : PurchaseOutcome

    /**
     * STOP-AND-FLAG (payments, AND-031): the shipped StubBillingAuthorizer returns NotConfigured, so
     * we did NOT call purchase and did NOT fake a charge. The sheet surfaces a "payments unavailable"
     * state. Binding a real BillingAuthorizer enables the full path with no VM change.
     */
    data object PaymentsUnavailable : PurchaseOutcome
    data class Cancelled(val reason: String? = null) : PurchaseOutcome
    data object RequireReauth : PurchaseOutcome
    data class Failure(val message: String, val retryable: Boolean) : PurchaseOutcome
}

/**
 * AND-193 — VOD tier-purchase data layer over [VodPurchaseApi].
 *
 * REUSES the AND-139 [BillingAuthorizer] seam and the AND-177 [EntitlementDao]/[EntitlementEntity] Room
 * cache (keyed by user_sub + content id) so a purchase survives navigation, process death, and relaunch
 * without re-charging. The access GET is idempotent; the purchase POST is never auto-retried, and the
 * `idempotency_key` body field makes a deliberate user retry safe. `already_owned == true` (a normal
 * 200) is treated as an idempotent success — there is no 409.
 */
interface VodPurchaseRepository {

    /** Reactive entitlement for a VOD (true => render unlocked without a network call). */
    fun isEntitled(videoId: String): Flow<Boolean>

    /** The purchase offer / access state (GET access). */
    suspend fun getOffer(videoId: String): ApiResult<VodOffer>

    /** Purchase [videoId] at [purchaseType]; authorizes payment via the billing seam first. */
    suspend fun purchase(videoId: String, purchaseType: String): PurchaseOutcome
}

@Singleton
class VodPurchaseRepositoryImpl @Inject constructor(
    private val api: VodPurchaseApi,
    private val billing: BillingAuthorizer,
    private val dao: EntitlementDao,
    private val authState: AuthStateStore,
    private val errorParser: ApiErrorParser,
) : VodPurchaseRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    // Stable per-(videoId, purchaseType, process-session) idempotency keys; rotates on selection change.
    private val idempotencyKeys = mutableMapOf<String, String>()

    override fun isEntitled(videoId: String): Flow<Boolean> {
        val userSub = authState.userSub.value ?: return flowOf(false)
        // Reuses the AND-177 entitlement table; the VOD id occupies the post_id column.
        return dao.isEntitled(userSub, videoId)
    }

    override suspend fun getOffer(videoId: String): ApiResult<VodOffer> = withContext(io) {
        call { api.getAccess(videoId) }.map { it.toOffer() }
    }

    override suspend fun purchase(videoId: String, purchaseType: String): PurchaseOutcome =
        withContext(io) {
            val userSub = authState.userSub.value
                ?: return@withContext PurchaseOutcome.RequireReauth

            // Already entitled locally => idempotent unlock, no HTTP, no charge.
            if (dao.exists(userSub, videoId)) {
                return@withContext PurchaseOutcome.Unlocked(localEntitlement(videoId, purchaseType))
            }

            // Authorize payment via the AND-139 billing seam. Stub => NotConfigured (STOP-AND-FLAG).
            val billingResult = billing.authorize(amountMinorUnits = 0L, currency = CURRENCY_USD)
            val paymentMethodId: String? = when (billingResult) {
                is BillingResult.Authorized -> billingResult.paymentMethodId
                BillingResult.NotConfigured -> return@withContext PurchaseOutcome.PaymentsUnavailable
                BillingResult.Cancelled -> return@withContext PurchaseOutcome.Cancelled()
                is BillingResult.Declined ->
                    return@withContext PurchaseOutcome.Failure(billingResult.reason, retryable = true)
                is BillingResult.Failed ->
                    return@withContext PurchaseOutcome.Failure(MSG_GENERIC, retryable = true)
            }

            val keyId = "$videoId:$purchaseType"
            val idemKey = idempotencyKeys.getOrPut(keyId) { "vodpur:$keyId:${randomNonce()}" }
            try {
                val entitlement = api.purchase(
                    videoId,
                    VodPurchaseInDto(
                        purchaseType = purchaseType,
                        idempotencyKey = idemKey,
                        paymentMethodId = paymentMethodId,
                    ),
                ).toEntitlement()
                // already_owned == true is a normal 200 success; both branches unlock.
                writeEntitlement(userSub, videoId, source = if (entitlement.alreadyOwned) "already_entitled" else "purchase")
                idempotencyKeys.remove(keyId)
                PurchaseOutcome.Unlocked(entitlement)
            } catch (e: CancellationException) {
                throw e
            } catch (e: HttpException) {
                val error = errorParser.from(e)
                when {
                    error.isAuth -> PurchaseOutcome.RequireReauth
                    error.status == HTTP_CONFLICT -> {
                        // Defensive (not declared): treat as already-owned success.
                        writeEntitlement(userSub, videoId, source = "already_entitled")
                        idempotencyKeys.remove(keyId)
                        PurchaseOutcome.Unlocked(localEntitlement(videoId, purchaseType))
                    }
                    else -> PurchaseOutcome.Failure(error.message, retryable = error.status >= 500)
                }
            } catch (e: IOException) {
                PurchaseOutcome.Failure(MSG_OFFLINE, retryable = true)
            }
        }

    private suspend fun writeEntitlement(userSub: String, videoId: String, source: String) {
        dao.upsert(
            EntitlementEntity(
                userSub = userSub,
                postId = videoId,
                unlockedAtEpochMs = System.currentTimeMillis(),
                source = source,
            ),
        )
    }

    private fun localEntitlement(videoId: String, purchaseType: String): Entitlement = Entitlement(
        videoId = videoId,
        purchaseType = PurchaseTypeOption.fromWire(purchaseType),
        alreadyOwned = true,
        grantType = "purchase",
        amountCents = 0L,
        purchaseId = "",
        viewsRemaining = -1,
        grantedAtSeconds = System.currentTimeMillis() / 1000L,
        expiresAtSeconds = null,
        downloadAllowed = false,
    )

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    private fun randomNonce(): String =
        (0 until NONCE_LEN).map { NONCE_ALPHABET.random() }.joinToString("")

    private companion object {
        const val CURRENCY_USD = "USD"
        const val HTTP_CONFLICT = 409
        const val NONCE_LEN = 8
        const val NONCE_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
        const val MSG_OFFLINE = "You're offline. Try again."
        const val MSG_GENERIC = "Couldn't complete your purchase. Please try again."
    }
}
