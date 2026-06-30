package com.testlogon.android.feature.ads.optimization.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.ads.AdOptimizationApi
import com.testlogon.android.core.network.ads.AdRecommendationDto
import com.testlogon.android.core.network.ads.BudgetRecommendationDto
import com.testlogon.android.core.network.ads.OptimizationConfigResultDto
import com.testlogon.android.core.network.ads.OptimizationConfigUpdateIn
import com.testlogon.android.core.network.ads.SuggestedBidDto
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
 * Data layer for the ad OPTIMIZATION panel (web parity: /ads/optimization). Wraps the [AdOptimizationApi]
 * raw DTOs in the typed [ApiResult] via [call] (mirrors AdsBillingRepository). generate / apply / dismiss are
 * NON-idempotent POSTs (never auto-retried). NO Room / persistence.
 */
interface AdOptimizationRepository {

    /** POST a deterministic optimization pass; returns the freshly persisted recommendations. */
    suspend fun generate(campaignId: String): ApiResult<List<AdRecommendationDto>>

    /** GET recommendation history (newest first). */
    suspend fun listRecommendations(campaignId: String): ApiResult<List<AdRecommendationDto>>

    /** POST apply a recommendation. NON-idempotent. */
    suspend fun applyRecommendation(campaignId: String, recommendationId: String): ApiResult<String>

    /** POST dismiss a recommendation. NON-idempotent. */
    suspend fun dismissRecommendation(campaignId: String, recommendationId: String): ApiResult<String>

    /** GET the suggested bid range. */
    suspend fun getSuggestedBid(campaignId: String): ApiResult<SuggestedBidDto>

    /** GET the recommended daily budget for a desired reach. */
    suspend fun getBudgetRecommendation(campaignId: String, desiredDailyReach: Int): ApiResult<BudgetRecommendationDto>

    /** PATCH the auto-optimize toggle. */
    suspend fun setAutoOptimize(campaignId: String, enabled: Boolean): ApiResult<OptimizationConfigResultDto>
}

@Singleton
class AdOptimizationRepositoryImpl @Inject constructor(
    private val api: AdOptimizationApi,
    private val errorParser: ApiErrorParser,
) : AdOptimizationRepository {

    override suspend fun generate(campaignId: String): ApiResult<List<AdRecommendationDto>> =
        withContext(Dispatchers.IO) { call { api.generate(campaignId).recommendations } }

    override suspend fun listRecommendations(campaignId: String): ApiResult<List<AdRecommendationDto>> =
        withContext(Dispatchers.IO) { call { api.listRecommendations(campaignId).recommendations } }

    override suspend fun applyRecommendation(campaignId: String, recommendationId: String): ApiResult<String> =
        withContext(Dispatchers.IO) { call { api.applyRecommendation(campaignId, recommendationId).status } }

    override suspend fun dismissRecommendation(campaignId: String, recommendationId: String): ApiResult<String> =
        withContext(Dispatchers.IO) { call { api.dismissRecommendation(campaignId, recommendationId).status } }

    override suspend fun getSuggestedBid(campaignId: String): ApiResult<SuggestedBidDto> =
        withContext(Dispatchers.IO) { call { api.getSuggestedBid(campaignId) } }

    override suspend fun getBudgetRecommendation(
        campaignId: String,
        desiredDailyReach: Int,
    ): ApiResult<BudgetRecommendationDto> = withContext(Dispatchers.IO) {
        call { api.getBudgetRecommendation(campaignId, desiredDailyReach) }
    }

    override suspend fun setAutoOptimize(
        campaignId: String,
        enabled: Boolean,
    ): ApiResult<OptimizationConfigResultDto> = withContext(Dispatchers.IO) {
        call { api.updateConfig(campaignId, OptimizationConfigUpdateIn(autoOptimizeEnabled = enabled)) }
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

@Module
@InstallIn(SingletonComponent::class)
abstract class AdOptimizationDataModule {

    @Binds
    @Singleton
    abstract fun bindAdOptimizationRepository(impl: AdOptimizationRepositoryImpl): AdOptimizationRepository
}
