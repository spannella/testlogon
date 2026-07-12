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
 * GET reads (balance/wallet/detail/list) are idempotent (the core-network RetryInterceptor handles
 * bounded retry). The write paths are mutations, NEVER auto-retried. PAY-52: request-payout now hits
 * the REAL gate-enforced POST ui/payouts/request (the AND-259 BillingAuthorizer stub is gone); the
 * backend enforces the PAY-C KYC + W-9 gate (403), available balance (400) and target method (400).
 *
 * Per-payout currency: PayoutOut has none, so callers may pass the balance currency; it defaults to "USD".
 */
interface PayoutsRepository {

    /** The current user's payout balance/state. Idempotent GET. */
    suspend fun getBalance(): ApiResult<PayoutBalance>

    /** PAY-50 wallet home summary (available/held/pending/lifetime-paid). Idempotent GET. */
    suspend fun getWallet(): ApiResult<WalletSummary>

    /** PAY-50 payout statement/detail (lifecycle timeline + transfer ref + last-4 + reason). Idempotent GET. */
    suspend fun getPayoutDetail(payoutId: String): ApiResult<PayoutDetail>

    /** One page of payout history (cursor pagination; null cursor = first page). Idempotent GET. */
    suspend fun getPayouts(cursor: String? = null, limit: Int = PayoutsApi.DEFAULT_LIMIT): ApiResult<PayoutPage>

    /**
     * PAY-52: request a REAL payout. Mutation; NEVER auto-retried. The backend enforces the PAY-C gate
     * (403 {code,message,kyc_status} on kyc_required/tax_info_required), insufficient-balance (400) and
     * an invalid/unverified [methodId] (400); those surface as [ApiResult.Failure]. [methodId] targets
     * the verified PAY-B destination; [currency] stamps the create result's [PayoutMoney].
     */
    suspend fun requestPayout(
        amountCents: Long,
        method: String = DEFAULT_PAYOUT_METHOD,
        methodId: String? = null,
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

    override suspend fun getWallet(): ApiResult<WalletSummary> = withContext(io) {
        call { api.getWallet() }.map { it.toDomain() }
    }

    override suspend fun getPayoutDetail(payoutId: String): ApiResult<PayoutDetail> = withContext(io) {
        // The detail carries no per-payout currency; the wallet/balance currency is authoritative, so
        // callers may re-stamp. Default USD keeps the mapper total.
        call { api.getPayoutDetail(payoutId) }.map { it.toDomain() }
    }

    override suspend fun getPayouts(cursor: String?, limit: Int): ApiResult<PayoutPage> = withContext(io) {
        call { api.listPayouts(limit = limit, cursor = cursor) }.map { it.toDomain() }
    }

    override suspend fun requestPayout(
        amountCents: Long,
        method: String,
        methodId: String?,
        notes: String,
        currency: String,
    ): ApiResult<PayoutCreateResult> = withContext(io) {
        call {
            api.requestPayout(
                PayoutRequestDto(amountCents = amountCents, method = method, methodId = methodId, notes = notes),
            )
        }.map { it.toDomain(currency) }
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
