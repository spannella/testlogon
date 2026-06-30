package com.testlogon.android.feature.syndicates.campaign

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.syndicates.SyndicateCampaignApi
import com.testlogon.android.core.network.syndicates.SyndicateCampaignBudgetAddIn
import com.testlogon.android.core.network.syndicates.SyndicateCampaignStatusUpdateIn
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
 * Data layer for the syndicate-advertising campaign DETAIL surface (web parity:
 * /syndicates/:syndicateId/campaigns/:campaignId), over [SyndicateCampaignApi]. Read = members; mutations
 * (status / add-budget) = admin-only (a 403 surfaces as Failure). Folds into [ApiResult] via [call].
 */
interface CampaignRepository {

    suspend fun getCampaign(syndicateId: String, campaignId: String): ApiResult<SyndicateCampaign>

    suspend fun getAnalytics(syndicateId: String, campaignId: String): ApiResult<CampaignAnalytics>

    suspend fun updateStatus(syndicateId: String, campaignId: String, status: String): ApiResult<SyndicateCampaign>

    suspend fun addBudget(syndicateId: String, campaignId: String, additionalCents: Int): ApiResult<SyndicateCampaign>
}

@Singleton
class DefaultCampaignRepository @Inject constructor(
    private val api: SyndicateCampaignApi,
    private val errorParser: ApiErrorParser,
) : CampaignRepository {

    override suspend fun getCampaign(syndicateId: String, campaignId: String): ApiResult<SyndicateCampaign> =
        withContext(Dispatchers.IO) {
            call { api.getCampaign(syndicateId, campaignId).toDomain(syndicateId) }
        }

    override suspend fun getAnalytics(syndicateId: String, campaignId: String): ApiResult<CampaignAnalytics> =
        withContext(Dispatchers.IO) {
            call { api.getAnalytics(syndicateId, campaignId).toDomain() }
        }

    override suspend fun updateStatus(
        syndicateId: String,
        campaignId: String,
        status: String,
    ): ApiResult<SyndicateCampaign> = withContext(Dispatchers.IO) {
        call {
            api.updateStatus(syndicateId, campaignId, SyndicateCampaignStatusUpdateIn(status))
                .toDomain(syndicateId)
        }
    }

    override suspend fun addBudget(
        syndicateId: String,
        campaignId: String,
        additionalCents: Int,
    ): ApiResult<SyndicateCampaign> = withContext(Dispatchers.IO) {
        call {
            api.addBudget(syndicateId, campaignId, SyndicateCampaignBudgetAddIn(additionalCents))
                .toDomain(syndicateId)
        }
    }

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

/** Hilt wiring for the syndicate campaign-detail feature. */
@Module
@InstallIn(SingletonComponent::class)
abstract class CampaignDataModule {

    @Binds
    @Singleton
    abstract fun bindCampaignRepository(impl: DefaultCampaignRepository): CampaignRepository
}
