package com.testlogon.android.feature.ads.create.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.ads.AdAccountRef
import com.testlogon.android.core.model.ads.AdAccountSummary
import com.testlogon.android.core.model.ads.AdCampaign
import com.testlogon.android.core.model.ads.AdCreative
import com.testlogon.android.core.network.ads.AdAccountCreateIn
import com.testlogon.android.core.network.ads.AdCampaignCreateIn
import com.testlogon.android.core.network.ads.AdCreativeCreateIn
import com.testlogon.android.core.network.ads.AdsAccountsApi
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.feature.adsbilling.data.AdsBillingRepository
import com.testlogon.android.feature.adsbilling.data.toDomain
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MultipartBody
import okhttp3.RequestBody.Companion.toRequestBody
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * ADV-107/108/109 - data layer for the MUTATING advertiser CREATE flow (create ad account -> create campaign
 * -> create creative + asset upload -> submit-for-review), over the AND-363 [AdsAccountsApi]. All writes are
 * NON-idempotent, so neither this repo nor its VMs auto-retry them.
 *
 * The account / campaign PICKER reads delegate to the existing AND-367 [AdsBillingRepository] (listAccounts /
 * getCampaigns) so their DTO->domain mapping is reused, not duplicated. Each write REUSES the raw-DTO api,
 * wraps it in [call], and maps the DTO to core-model BEFORE the typed [ApiResult] (mirrors AdsBillingRepository).
 */
interface AdsCreateRepository {

    /** ADV-107 - create an advertiser account (returns the new id + pending_review status). */
    suspend fun createAccount(companyName: String, billingEmail: String): ApiResult<AdAccountRef>

    /** Picker read: the caller advertiser accounts (delegates to the billing repo mapped list). */
    suspend fun listAccounts(): ApiResult<List<AdAccountSummary>>

    /** Picker read: the campaigns under [accountId] (delegates to the billing repo mapped list). */
    suspend fun listCampaigns(accountId: String): ApiResult<List<AdCampaign>>

    /** ADV-108 - create a draft campaign under [accountId]. */
    suspend fun createCampaign(
        accountId: String,
        name: String,
        objective: String,
        budgetCents: Long,
        budgetType: String,
        bidCpmCents: Int,
        bidCpcCents: Int?,
        bidCpaCents: Int?,
        category: String?,
        startDate: Long?,
        endDate: Long?,
    ): ApiResult<AdCampaign>

    /** ADV-108 - submit a draft campaign for admin review. */
    suspend fun submitCampaign(accountId: String, campaignId: String): ApiResult<String>

    /** ADV-109 - create a draft creative under [campaignId]. */
    suspend fun createCreative(
        campaignId: String,
        format: String,
        title: String,
        headline: String?,
        bodyText: String?,
        ctaText: String?,
        ctaUrl: String?,
        rotationWeight: Int,
    ): ApiResult<AdCreative>

    /** ADV-109 - upload the creative image/video asset (multipart); returns the stored asset URL. */
    suspend fun uploadCreativeAsset(
        campaignId: String,
        creativeId: String,
        bytes: ByteArray,
        contentType: String,
        fileName: String,
        assetType: String,
    ): ApiResult<String>

    /** ADV-109 - submit a draft creative for admin review. */
    suspend fun submitCreative(campaignId: String, creativeId: String): ApiResult<String>
}

@Singleton
class AdsCreateRepositoryImpl @Inject constructor(
    private val api: AdsAccountsApi,
    private val billing: AdsBillingRepository,
    private val errorParser: ApiErrorParser,
) : AdsCreateRepository {

    override suspend fun createAccount(
        companyName: String,
        billingEmail: String,
    ): ApiResult<AdAccountRef> = withContext(Dispatchers.IO) {
        call { api.createAdsAccount(AdAccountCreateIn(companyName, billingEmail)).toDomain() }
    }

    override suspend fun listAccounts(): ApiResult<List<AdAccountSummary>> = billing.listAccounts()

    override suspend fun listCampaigns(accountId: String): ApiResult<List<AdCampaign>> =
        billing.getCampaigns(accountId)

    override suspend fun createCampaign(
        accountId: String,
        name: String,
        objective: String,
        budgetCents: Long,
        budgetType: String,
        bidCpmCents: Int,
        bidCpcCents: Int?,
        bidCpaCents: Int?,
        category: String?,
        startDate: Long?,
        endDate: Long?,
    ): ApiResult<AdCampaign> = withContext(Dispatchers.IO) {
        call {
            api.createCampaign(
                accountId,
                AdCampaignCreateIn(
                    name = name,
                    objective = objective,
                    budgetCents = budgetCents,
                    budgetType = budgetType,
                    bidCpmCents = bidCpmCents,
                    bidCpcCents = bidCpcCents,
                    bidCpaCents = bidCpaCents,
                    category = category,
                    startDate = startDate,
                    endDate = endDate,
                ),
            ).toDomain()
        }
    }

    override suspend fun submitCampaign(
        accountId: String,
        campaignId: String,
    ): ApiResult<String> = withContext(Dispatchers.IO) {
        call { api.submitCampaign(accountId, campaignId).let { it.status ?: SUBMITTED_STATUS } }
    }

    override suspend fun createCreative(
        campaignId: String,
        format: String,
        title: String,
        headline: String?,
        bodyText: String?,
        ctaText: String?,
        ctaUrl: String?,
        rotationWeight: Int,
    ): ApiResult<AdCreative> = withContext(Dispatchers.IO) {
        call {
            api.createCreative(
                campaignId,
                AdCreativeCreateIn(
                    format = format,
                    title = title,
                    headline = headline,
                    bodyText = bodyText,
                    ctaText = ctaText,
                    ctaUrl = ctaUrl,
                    rotationWeight = rotationWeight,
                ),
            ).toDomain()
        }
    }

    override suspend fun uploadCreativeAsset(
        campaignId: String,
        creativeId: String,
        bytes: ByteArray,
        contentType: String,
        fileName: String,
        assetType: String,
    ): ApiResult<String> = withContext(Dispatchers.IO) {
        val filePart = MultipartBody.Part.createFormData(
            "file", fileName, bytes.toRequestBody(contentType.toMediaType()),
        )
        val typePart = assetType.toRequestBody("text/plain".toMediaType())
        call { api.uploadCreativeAsset(campaignId, creativeId, filePart, typePart).url.orEmpty() }
    }

    override suspend fun submitCreative(
        campaignId: String,
        creativeId: String,
    ): ApiResult<String> = withContext(Dispatchers.IO) {
        call { api.submitCreative(campaignId, creativeId).let { it.status ?: SUBMITTED_STATUS } }
    }

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (preserving the status via [ApiErrorParser]);
     * malformed JSON -> Failure(parse); transport failures -> NetworkError. Cancellation is re-thrown.
     * Mirrors AdsBillingRepository.call.
     */
    private companion object { const val SUBMITTED_STATUS = "pending_review" }

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

/** ADV-107/108/109 - Hilt wiring: binds the create-repository seam to its default impl. */
@Module
@InstallIn(SingletonComponent::class)
abstract class AdsCreateDataModule {

    @Binds
    @Singleton
    abstract fun bindAdsCreateRepository(impl: AdsCreateRepositoryImpl): AdsCreateRepository
}
