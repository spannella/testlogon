package com.testlogon.android.data.vod.rental

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-192 — outcome of a rent attempt (domain projection consumed by the ViewModel).
 *
 * Mirrors the AND-177 paywall [com.testlogon.android.data.paywall.UnlockOutcome] shape: a stubbed
 * billing authorizer short-circuits to [PaymentsUnavailable] and NEVER calls start or fakes a charge.
 */
sealed interface RentOutcome {
    /** Rented (or already-active idempotent success): carries the fresh access state. */
    data class Active(val receipt: RentalReceipt, val access: RentalAccess) : RentOutcome

    /**
     * STOP-AND-FLAG (payments, AND-031): the shipped [com.testlogon.android.data.messaging.StubBillingAuthorizer]
     * returns NotConfigured, so we did NOT call start and did NOT fake a charge. The UI surfaces a
     * "payments unavailable" state. Binding a real BillingAuthorizer enables the full path with no VM
     * change.
     */
    data object PaymentsUnavailable : RentOutcome
    data class Cancelled(val reason: String? = null) : RentOutcome
    data class Failure(val message: String, val retryable: Boolean) : RentOutcome
}

/**
 * AND-192 — VOD rental data layer over [VodRentalApi].
 *
 * REUSES the AND-139 [BillingAuthorizer] seam exactly like the paywall: `start` requires a
 * payment_method_id obtained from the (out-of-scope) payment picker. GETs (status/access/list) are
 * idempotent and wrapped in [ApiResult]; the start/playback/playback-complete POSTs are never
 * auto-retried (avoid double-charge — `already_active` is the server-side idempotency signal).
 */
interface VodRentalRepository {

    /** Current rental status (GET status), mapped to access state. */
    suspend fun status(videoId: String): ApiResult<RentalAccess>

    /** Lightweight access check (GET access). */
    suspend fun access(videoId: String): ApiResult<RentalAccess>

    /**
     * Rent [videoId] at [tier] ("rental"|"view_once"). Authorizes payment via the billing seam first;
     * a stubbed authorizer yields [RentOutcome.PaymentsUnavailable] without any network call.
     * [durationHours] is sent only for tier == "rental".
     */
    suspend fun rent(videoId: String, tier: String, durationHours: Int?): RentOutcome

    /** Short-lived playback grant (POST playback). The url/token are never persisted. */
    suspend fun beginPlayback(videoId: String): ApiResult<RentalPlayback>

    /** Reports playback finished so the server decrements the view budget (POST playback-complete). */
    suspend fun finishPlayback(videoId: String): ApiResult<RentalConsumeResult>

    /** The caller's rentals (GET list) for warm cache / "My rentals". */
    suspend fun list(): ApiResult<List<RentalAccess>>

    /** The caller's rentals (GET list) as rich rows for the "My Rentals" screen (web VodRentalsPage parity). */
    suspend fun listItems(): ApiResult<List<RentalListItem>>
}

/** Result of POST playback-complete. */
data class RentalConsumeResult(val ok: Boolean, val viewsRemaining: Int, val consumed: Boolean)

@Singleton
class VodRentalRepositoryImpl @Inject constructor(
    private val api: VodRentalApi,
    private val billing: BillingAuthorizer,
    private val errorParser: ApiErrorParser,
) : VodRentalRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun status(videoId: String): ApiResult<RentalAccess> = withContext(io) {
        call { api.status(videoId) }.map { it.toAccess() }
    }

    override suspend fun access(videoId: String): ApiResult<RentalAccess> = withContext(io) {
        call { api.access(videoId) }.map { it.toDomain() }
    }

    override suspend fun rent(videoId: String, tier: String, durationHours: Int?): RentOutcome =
        withContext(io) {
            // Authorize payment via the AND-139 billing seam. Stub => NotConfigured (STOP-AND-FLAG):
            // no start call, no faked charge.
            val billingResult = billing.authorize(amountMinorUnits = 0L, currency = CURRENCY_USD)
            val paymentMethodId: String? = when (billingResult) {
                is BillingResult.Authorized -> billingResult.paymentMethodId
                BillingResult.NotConfigured -> return@withContext RentOutcome.PaymentsUnavailable
                BillingResult.Cancelled -> return@withContext RentOutcome.Cancelled()
                is BillingResult.Declined ->
                    return@withContext RentOutcome.Failure(billingResult.reason, retryable = true)
                is BillingResult.Failed ->
                    return@withContext RentOutcome.Failure(MSG_GENERIC, retryable = true)
            }

            // rental_duration_hours is sent ONLY for tier == "rental" (view_once omits it).
            val body = VodRentalStartInDto(
                tier = tier,
                paymentMethodId = paymentMethodId,
                rentalDurationHours = if (tier == VodRentalApi.TIER_RENTAL) durationHours else null,
            )
            try {
                val receipt = api.start(videoId, body).toReceipt()
                // Re-anchor on the authoritative server state (handles already_active too).
                val access = when (val a = call { api.access(videoId) }) {
                    is ApiResult.Success -> a.data.toDomain()
                    else -> RentalAccess(
                        active = true,
                        tier = receipt.tier,
                        reason = null,
                        expiresAt = receipt.expiresAt,
                        remainingSeconds = 0L,
                        viewsRemaining = receipt.viewsRemaining,
                        rentalId = receipt.rentalId,
                        started = true,
                    )
                }
                RentOutcome.Active(receipt, access)
            } catch (e: CancellationException) {
                throw e
            } catch (e: HttpException) {
                val error = errorParser.from(e)
                when (error.status) {
                    // Defensive (NOT in OpenAPI for start, which declares 200/422): treat 409 as
                    // already-rented success by refreshing state; 402 as a retryable payment error.
                    HTTP_CONFLICT -> when (val a = call { api.access(videoId) }) {
                        is ApiResult.Success -> RentOutcome.Active(
                            RentalReceipt(
                                videoId = videoId,
                                rentalId = a.data.rentalId.orEmpty(),
                                tier = tier,
                                alreadyActive = true,
                                expiresAt = a.data.expiresAt,
                                viewsRemaining = a.data.viewsRemaining,
                                amountCents = 0,
                                durationHours = durationHours,
                            ),
                            a.data.toDomain(),
                        )
                        else -> RentOutcome.Failure(error.message, retryable = true)
                    }
                    else -> RentOutcome.Failure(error.message, retryable = error.status >= 500)
                }
            } catch (e: IOException) {
                RentOutcome.Failure(MSG_OFFLINE, retryable = true)
            }
        }

    override suspend fun beginPlayback(videoId: String): ApiResult<RentalPlayback> = withContext(io) {
        callNoRetry { api.playback(videoId) }.map { it.toDomain() }
    }

    override suspend fun finishPlayback(videoId: String): ApiResult<RentalConsumeResult> =
        withContext(io) {
            callNoRetry { api.playbackComplete(videoId) }
                .map { RentalConsumeResult(it.ok, it.viewsRemaining, it.consumed) }
        }

    override suspend fun list(): ApiResult<List<RentalAccess>> = withContext(io) {
        call { api.list() }.map { resp -> resp.items.map { it.toAccess() } }
    }

    override suspend fun listItems(): ApiResult<List<RentalListItem>> = withContext(io) {
        call { api.list() }.map { resp -> resp.items.map { it.toListItem() } }
    }

    // Idempotent-GET wrapper (NetworkError is retryable upstream by the caller / interceptor).
    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = mapCall(block)

    // POST wrapper (same mapping; semantics differ only in that callers never auto-retry).
    private suspend fun <T> callNoRetry(block: suspend () -> T): ApiResult<T> = mapCall(block)

    private suspend fun <T> mapCall(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    private companion object {
        const val CURRENCY_USD = "USD"
        const val HTTP_CONFLICT = 409
        const val MSG_OFFLINE = "You're offline. Try again."
        const val MSG_GENERIC = "Couldn't rent. Try again."
    }
}
