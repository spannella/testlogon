package com.testlogon.android.data.billing

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.flatMap
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
 * AND-223 / AND-224 — billing data layer over [BillingApi].
 *
 * Wraps every call in [ApiResult] (matching the cart/checkout repositories): CancellationException is
 * re-thrown, HTTP errors fold to Failure, transport failures to NetworkError. DTOs are mapped to
 * domain before returning (no raw DTOs leak out). GET list reads are idempotent (safe to retry on
 * NetworkError upstream); the set-default / delete mutations are non-idempotent and never auto-retried.
 *
 * Reconciliation model (AND-224): set-default and delete return only OkResp, so each mutation
 * reconciles by re-fetching GET ui/billing/payment-methods — exactly as the web client does. The
 * ordering (default-first, then priority asc) is applied here so the UI renders a single sorted list.
 */
interface BillingRepository {

    /** AND-224 — saved payment methods, ordered default-first then by ascending priority. */
    suspend fun getPaymentMethods(): ApiResult<List<PaymentMethod>>

    /** AND-224 — set [id] as default (POST .../default), then re-fetch the sorted list. */
    suspend fun setDefaultPaymentMethod(id: String): ApiResult<List<PaymentMethod>>

    /** AND-224 — remove [id] (DELETE), then re-fetch the sorted list. */
    suspend fun removePaymentMethod(id: String): ApiResult<List<PaymentMethod>>

    /** AND-223 — billing config (publishable key + currency). */
    suspend fun getConfig(): ApiResult<BillingConfig>

    /** AND-223 — billing settings (autopay, default method). */
    suspend fun getSettings(): ApiResult<BillingSettings>

    /** AND-223 — account balance (all amounts integer cents). */
    suspend fun getBalance(): ApiResult<BillingBalance>

    /** AND-223 — subscriptions list (limit-based). */
    suspend fun getSubscriptions(limit: Int = BillingApi.DEFAULT_LIMIT): ApiResult<List<Subscription>>

    /** AND-223 — ledger entries (financial history). Currency is threaded from the account balance. */
    suspend fun getLedger(limit: Int = BillingApi.DEFAULT_LIMIT): ApiResult<LedgerPage>

    /** AND-223 — payments entries. Currency is threaded from the account balance. */
    suspend fun getPayments(limit: Int = BillingApi.DEFAULT_LIMIT): ApiResult<LedgerPage>

    /** AND-223 — wallet balance. */
    suspend fun getWallet(): ApiResult<WalletBalance>
}

@Singleton
class BillingRepositoryImpl @Inject constructor(
    private val api: BillingApi,
    private val errorParser: ApiErrorParser,
) : BillingRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun getPaymentMethods(): ApiResult<List<PaymentMethod>> = withContext(io) {
        fetchSortedMethods()
    }

    override suspend fun setDefaultPaymentMethod(id: String): ApiResult<List<PaymentMethod>> =
        withContext(io) {
            // OkResp carries no method object -> reconcile by re-fetching the authoritative list.
            call { api.setDefaultPaymentMethod(SetDefaultReqDto(paymentMethodId = id)) }
                .flatMap { fetchSortedMethods() }
        }

    override suspend fun removePaymentMethod(id: String): ApiResult<List<PaymentMethod>> =
        withContext(io) {
            call { api.deletePaymentMethod(id) }.flatMap { fetchSortedMethods() }
        }

    override suspend fun getConfig(): ApiResult<BillingConfig> =
        withContext(io) { call { api.getConfig() }.map { it.toDomain() } }

    override suspend fun getSettings(): ApiResult<BillingSettings> =
        withContext(io) { call { api.getSettings() }.map { it.toDomain() } }

    override suspend fun getBalance(): ApiResult<BillingBalance> =
        withContext(io) { call { api.getBalance() }.map { it.toDomain() } }

    override suspend fun getSubscriptions(limit: Int): ApiResult<List<Subscription>> =
        withContext(io) { call { api.getSubscriptions(limit) }.map { dto -> dto.items.map { it.toDomain() } } }

    override suspend fun getLedger(limit: Int): ApiResult<LedgerPage> =
        withContext(io) { call { api.getLedger(limit) }.map { it.toDomain(accountCurrency()) } }

    override suspend fun getPayments(limit: Int): ApiResult<LedgerPage> =
        withContext(io) { call { api.getPayments(limit) }.map { it.toDomain(accountCurrency()) } }

    override suspend fun getWallet(): ApiResult<WalletBalance> =
        withContext(io) { call { api.getWallet() }.map { it.toDomain() } }

    /** Fetches + maps + sorts the payment methods (default-first, then priority ascending). */
    private suspend fun fetchSortedMethods(): ApiResult<List<PaymentMethod>> =
        call { api.getPaymentMethods() }.map { dtos ->
            dtos.map { it.toDomain() }
                .sortedWith(compareByDescending<PaymentMethod> { it.isDefault }.thenBy { it.priority })
        }

    /** Ledger entries carry no per-row currency; best-effort thread the balance currency, else USD. */
    private suspend fun accountCurrency(): String =
        (call { api.getBalance() } as? ApiResult.Success)?.data?.currency ?: DEFAULT_CURRENCY

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    companion object {
        private const val DEFAULT_CURRENCY = "USD"
    }
}
