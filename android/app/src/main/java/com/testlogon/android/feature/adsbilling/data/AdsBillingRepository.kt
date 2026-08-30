package com.testlogon.android.feature.adsbilling.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.ads.AdAccountSummary
import com.testlogon.android.core.model.ads.AdBillingEntry
import com.testlogon.android.core.model.ads.AdCampaign
import com.testlogon.android.core.model.ads.AdInvoice
import com.testlogon.android.core.model.ads.DepositResult
import com.testlogon.android.core.network.ads.AdCampaignUpdateIn
import com.testlogon.android.core.network.ads.AdDepositIn
import com.testlogon.android.core.network.ads.AdsAccountsApi
import com.testlogon.android.core.network.error.ApiErrorParser
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-367 - data layer for the ads-account BILLING + DEPOSIT surface. This is the FIRST :app repo over the
 * AND-363 [AdsAccountsApi] (AND-363 shipped transport only). Each call REUSES the raw-DTO api, wraps it in
 * [call], and maps the DTO to the core-model domain BEFORE the typed [ApiResult] (mirrors AND-364
 * BoostRepository).
 *
 * SUMMARY is read from the single-account GET (balance + lifetime-spend live ON the account; there is NO
 * separate billing summary object). The billing LEDGER is a bare array (limit-capped). The monthly INVOICE
 * is a separate endpoint. DEPOSIT is the first MUTATING ads operation: NON-idempotent, so neither this repo
 * nor the VM ever auto-retries it. NO vendor payment SDK (the optional payment_method_id is passed through;
 * the server charges the wallet / an existing saved method). NO Room / disk persistence.
 */
interface AdsBillingRepository {

    /**
     * AND-369 - GET the advertiser-accounts list (bare array), mapped to [AdAccountSummary] rows (the list
     * row reuses the AND-367 summary type). Idempotent GET. Backs the AdsAccountsViewModel.
     */
    suspend fun listAccounts(): ApiResult<List<AdAccountSummary>>

    /**
     * AND-369 - GET the read-only campaigns under [accountId] (bare array), mapped to [AdCampaign]. Idempotent
     * GET. Backs the AdsCampaignsViewModel.
     */
    suspend fun getCampaigns(accountId: String): ApiResult<List<AdCampaign>>

    /**
     * ADV3-4 (B2) - GET one campaign (for the management detail screen). Idempotent GET.
     */
    suspend fun getCampaign(accountId: String, campaignId: String): ApiResult<AdCampaign>

    /**
     * ADV3-4 (B2) - PATCH a campaign: pause/resume (via [status]), edit [budgetCents] / [bidCpmCents] /
     * [bidCpcCents] / [bidCpaCents], or archive. Only non-null args are sent. The server returns {"ok":true}
     * so this maps to Unit; the caller re-reads via [getCampaign]. NON-idempotent -> callers never auto-retry.
     */
    suspend fun updateCampaign(
        accountId: String,
        campaignId: String,
        status: String? = null,
        budgetCents: Long? = null,
        bidCpmCents: Int? = null,
        bidCpcCents: Int? = null,
        bidCpaCents: Int? = null,
    ): ApiResult<Unit>

    /** GET the account summary (balance + lifetime spend + company name + status), mapped. Idempotent GET. */
    suspend fun getAccount(accountId: String): ApiResult<AdAccountSummary>

    /** GET the billing-history ledger (bare array, [limit]-capped), mapped. Idempotent GET. */
    suspend fun getBillingHistory(accountId: String, limit: Int = 50): ApiResult<List<AdBillingEntry>>

    /** GET one monthly invoice (assumed "YYYY-MM"), mapped. Idempotent GET. */
    suspend fun getInvoice(accountId: String, month: String): ApiResult<AdInvoice>

    /**
     * POST a deposit (add funds). Body is {amount_cents, payment_method_id?}; the server charges the wallet
     * / an existing saved method and returns the updated balance. NON-idempotent -> callers NEVER auto-retry.
     */
    suspend fun deposit(
        accountId: String,
        amountCents: Long,
        paymentMethodId: String? = null,
        payWith: String? = null,
        quoteToken: String? = null,
    ): ApiResult<DepositResult>
}

@Singleton
class AdsBillingRepositoryImpl @Inject constructor(
    private val api: AdsAccountsApi,
    private val errorParser: ApiErrorParser,
) : AdsBillingRepository {

    override suspend fun listAccounts(): ApiResult<List<AdAccountSummary>> =
        withContext(Dispatchers.IO) {
            call { api.listAdsAccounts().map { it.toAccountSummary() } }
        }

    override suspend fun getCampaigns(accountId: String): ApiResult<List<AdCampaign>> =
        withContext(Dispatchers.IO) {
            call { api.listAdsAccountCampaigns(accountId).map { it.toDomain() } }
        }

    override suspend fun getCampaign(
        accountId: String,
        campaignId: String,
    ): ApiResult<AdCampaign> = withContext(Dispatchers.IO) {
        call { api.getCampaign(accountId, campaignId).toDomain() }
    }

    override suspend fun updateCampaign(
        accountId: String,
        campaignId: String,
        status: String?,
        budgetCents: Long?,
        bidCpmCents: Int?,
        bidCpcCents: Int?,
        bidCpaCents: Int?,
    ): ApiResult<Unit> = withContext(Dispatchers.IO) {
        call {
            api.updateCampaign(
                accountId,
                campaignId,
                AdCampaignUpdateIn(
                    status = status,
                    budgetCents = budgetCents,
                    bidCpmCents = bidCpmCents,
                    bidCpcCents = bidCpcCents,
                    bidCpaCents = bidCpaCents,
                ),
            )
            Unit
        }
    }

    override suspend fun getAccount(accountId: String): ApiResult<AdAccountSummary> =
        withContext(Dispatchers.IO) {
            call { api.getAdsAccount(accountId).toBillingSummary() }
        }

    override suspend fun getBillingHistory(
        accountId: String,
        limit: Int,
    ): ApiResult<List<AdBillingEntry>> = withContext(Dispatchers.IO) {
        call { api.getAdsAccountBilling(accountId, limit).map { it.toDomain() } }
    }

    override suspend fun getInvoice(accountId: String, month: String): ApiResult<AdInvoice> =
        withContext(Dispatchers.IO) {
            call { api.getInvoice(accountId, month).toDomain() }
        }

    override suspend fun deposit(
        accountId: String,
        amountCents: Long,
        paymentMethodId: String?,
        payWith: String?,
        quoteToken: String?,
    ): ApiResult<DepositResult> = withContext(Dispatchers.IO) {
        call {
            api.deposit(
                accountId,
                AdDepositIn(
                    amountCents = amountCents,
                    paymentMethodId = paymentMethodId,
                    payWith = payWith,
                    quoteToken = quoteToken,
                ),
            ).toDomain()
        }
    }

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser], preserving the status);
     * malformed JSON -> Failure(parse); transport failures -> NetworkError. The JsonEncodingException catch
     * precedes the IOException catch (it is an IOException subtype). Cancellation is re-thrown. Mirrors the
     * AND-364 BoostRepository.
     */
    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonEncodingException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}

/**
 * AND-367 - Hilt wiring for the ads-billing feature. Binds the repository seam to its default impl (which
 * consumes the AND-363 [AdsAccountsApi] + the shared [ApiErrorParser]). NO new endpoint module, migration,
 * or dependency is added here (the api is already provided by AND-363 AdsNetworkModule).
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class AdsBillingDataModule {

    @Binds
    @Singleton
    abstract fun bindAdsBillingRepository(impl: AdsBillingRepositoryImpl): AdsBillingRepository
}
