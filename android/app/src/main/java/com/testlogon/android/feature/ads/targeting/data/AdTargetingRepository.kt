package com.testlogon.android.feature.ads.targeting.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.ads.AdTargetingApi
import com.testlogon.android.core.network.ads.AdTargetingCreateIn
import com.testlogon.android.core.network.ads.AdTargetingDto
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
 * Data layer for the ad TARGETING editor (web parity: /ads/targeting). Wraps the AND-network [AdTargetingApi]
 * raw DTOs in the typed [ApiResult] via [call] (mirrors AdsBillingRepository). The targeting set DTO is
 * surfaced directly (the screen edits it as-is) - no separate domain type this surface. NO Room / persistence.
 */
interface AdTargetingRepository {

    /** GET all targeting sets for a campaign (bare array). */
    suspend fun listTargeting(campaignId: String): ApiResult<List<AdTargetingDto>>

    /** POST a new targeting set. NON-idempotent. */
    suspend fun createTargeting(campaignId: String, body: AdTargetingCreateIn): ApiResult<AdTargetingDto>

    /** PUT (replace) an existing targeting set. */
    suspend fun updateTargeting(
        campaignId: String,
        targetSetId: String,
        body: AdTargetingCreateIn,
    ): ApiResult<AdTargetingDto>

    /** POST an audience estimate for an unsaved spec (does not persist). */
    suspend fun estimateAudience(campaignId: String, body: AdTargetingCreateIn): ApiResult<Long>
}

@Singleton
class AdTargetingRepositoryImpl @Inject constructor(
    private val api: AdTargetingApi,
    private val errorParser: ApiErrorParser,
) : AdTargetingRepository {

    override suspend fun listTargeting(campaignId: String): ApiResult<List<AdTargetingDto>> =
        withContext(Dispatchers.IO) { call { api.listTargeting(campaignId) } }

    override suspend fun createTargeting(
        campaignId: String,
        body: AdTargetingCreateIn,
    ): ApiResult<AdTargetingDto> = withContext(Dispatchers.IO) {
        call { api.createTargeting(campaignId, body) }
    }

    override suspend fun updateTargeting(
        campaignId: String,
        targetSetId: String,
        body: AdTargetingCreateIn,
    ): ApiResult<AdTargetingDto> = withContext(Dispatchers.IO) {
        call { api.updateTargeting(campaignId, targetSetId, body) }
    }

    override suspend fun estimateAudience(
        campaignId: String,
        body: AdTargetingCreateIn,
    ): ApiResult<Long> = withContext(Dispatchers.IO) {
        call { api.estimateAudience(campaignId, body).estimatedReach }
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
abstract class AdTargetingDataModule {

    @Binds
    @Singleton
    abstract fun bindAdTargetingRepository(impl: AdTargetingRepositoryImpl): AdTargetingRepository
}
