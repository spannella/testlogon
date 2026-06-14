package com.testlogon.android.data.payouts

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
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
 * AND-258 — payouts data layer over [PayoutsApi].
 *
 * Wraps every call in [ApiResult] (matching the earnings/invoices repositories): CancellationException
 * is re-thrown; HTTP errors fold to Failure (via [ApiErrorParser]); transport failures to NetworkError.
 * DTOs are mapped to domain before returning (no raw DTOs leak out).
 *
 * GET reads (balance/list) are idempotent (the core-network RetryInterceptor handles bounded retry).
 * The write paths are mutations, NEVER auto-retried, and — per the AND-258/259 policy — request-payout
 * is GATED THROUGH THE [com.testlogon.android.data.messaging.BillingAuthorizer] STUB so no real payout
 * is ever executed (see AND-259's PayoutSetupRepository which owns the gate; this layer exposes the raw
 * request call only for that gated caller).
 *
 * Per-payout currency: PayoutOut has none, so callers may pass the balance currency; it defaults to "USD".
 */
interface PayoutsRepository {

    /** The current user's payout balance/state. Idempotent GET. */
    suspend fun getBalance(): ApiResult<PayoutBalance>

    /** One page of payout history (cursor pagination; null cursor = first page). Idempotent GET. */
    suspend fun getPayouts(cursor: String? = null, limit: Int = PayoutsApi.DEFAULT_LIMIT): ApiResult<PayoutPage>

    /**
     * Request a payout. Mutation; NEVER auto-retried. AND-259 routes this ONLY after the
     * BillingAuthorizer stub authorizes (which it never does while NotConfigured), so a real payout is
     * never executed. [currency] stamps the create result's [PayoutMoney].
     */
    suspend fun requestPayout(
        amountCents: Long,
        method: String = DEFAULT_PAYOUT_METHOD,
        notes: String = "",
        currency: String = DEFAULT_PAYOUT_CURRENCY,
    ): ApiResult<PayoutCreateResult>

    /** Cancel a pending payout request. Mutation; NEVER auto-retried. */
    suspend fun cancelPayout(payoutId: String): ApiResult<PayoutActionResult>
}

@Singleton
class PayoutsRepositoryImpl @Inject constructor(
    private val api: PayoutsApi,
    private val errorParser: ApiErrorParser,
) : PayoutsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun getBalance(): ApiResult<PayoutBalance> = withContext(io) {
        call { api.getBalance() }.map { it.toDomain() }
    }

    override suspend fun getPayouts(cursor: String?, limit: Int): ApiResult<PayoutPage> = withContext(io) {
        call { api.listPayouts(limit = limit, cursor = cursor) }.map { it.toDomain() }
    }

    override suspend fun requestPayout(
        amountCents: Long,
        method: String,
        notes: String,
        currency: String,
    ): ApiResult<PayoutCreateResult> = withContext(io) {
        call { api.requestPayout(PayoutRequestDto(amountCents = amountCents, method = method, notes = notes)) }
            .map { it.toDomain(currency) }
    }

    override suspend fun cancelPayout(payoutId: String): ApiResult<PayoutActionResult> = withContext(io) {
        call { api.cancelPayout(payoutId) }.map { it.toDomain() }
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
