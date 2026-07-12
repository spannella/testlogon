package com.testlogon.android.feature.ads.contentcontrols.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.ads.AdRevenueBreakdown
import com.testlogon.android.core.model.ads.AdvertiserTransparency
import com.testlogon.android.core.model.ads.ContentAdOverride
import com.testlogon.android.core.network.ads.ContentAdControlsApi
import com.testlogon.android.core.network.ads.ContentAdOverrideIn
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
 * Data layer for the CONTENT AD-CONTROLS surface (web parity: ContentAdControlsPage.tsx). Wraps the
 * core-network [ContentAdControlsApi] raw DTOs in the typed [ApiResult] via [call] (mirrors
 * AdTargetingRepository), mapping each DTO to its core-model domain BEFORE the result. NO Room / persistence.
 */
interface ContentAdControlsRepository {

    /** GET all per-content overrides for the caller. */
    suspend fun listOverrides(): ApiResult<List<ContentAdOverride>>

    /** PUT (upsert) one override; returns the saved override. */
    suspend fun upsertOverride(contentId: String, body: ContentAdOverrideIn): ApiResult<ContentAdOverride>

    /** DELETE one override. */
    suspend fun deleteOverride(contentId: String): ApiResult<Unit>

    /** GET the creator revenue share (basis points). */
    suspend fun getRevenueShare(): ApiResult<Int>

    /** PUT the creator revenue share (basis points); returns the saved value. */
    suspend fun setRevenueShare(revenueShareBps: Int): ApiResult<Int>

    /** GET the ad-revenue breakdown over a day window. */
    suspend fun getRevenueBreakdown(days: Int): ApiResult<AdRevenueBreakdown>

    /** GET the advertiser transparency list (optionally for a YYYY-MM month). */
    suspend fun getTransparency(month: String? = null): ApiResult<List<AdvertiserTransparency>>
}

@Singleton
class ContentAdControlsRepositoryImpl @Inject constructor(
    private val api: ContentAdControlsApi,
    private val errorParser: ApiErrorParser,
) : ContentAdControlsRepository {

    override suspend fun listOverrides(): ApiResult<List<ContentAdOverride>> =
        withContext(Dispatchers.IO) { call { api.listOverrides().map { it.toDomain() } } }

    override suspend fun upsertOverride(
        contentId: String,
        body: ContentAdOverrideIn,
    ): ApiResult<ContentAdOverride> =
        withContext(Dispatchers.IO) { call { api.upsertOverride(contentId, body).toDomain() } }

    override suspend fun deleteOverride(contentId: String): ApiResult<Unit> =
        withContext(Dispatchers.IO) {
            call {
                api.deleteOverride(contentId)
                Unit
            }
        }

    override suspend fun getRevenueShare(): ApiResult<Int> =
        withContext(Dispatchers.IO) { call { api.getRevenueShare().revenueShareBps } }

    override suspend fun setRevenueShare(revenueShareBps: Int): ApiResult<Int> =
        withContext(Dispatchers.IO) {
            call { api.setRevenueShare(com.testlogon.android.core.network.ads.RevenueShareIn(revenueShareBps)).revenueShareBps }
        }

    override suspend fun getRevenueBreakdown(days: Int): ApiResult<AdRevenueBreakdown> =
        withContext(Dispatchers.IO) { call { api.getRevenueBreakdown(days).toDomain() } }

    override suspend fun getTransparency(month: String?): ApiResult<List<AdvertiserTransparency>> =
        withContext(Dispatchers.IO) { call { api.getTransparency(month).map { it.toDomain() } } }

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
abstract class ContentAdControlsDataModule {

    @Binds
    @Singleton
    abstract fun bindContentAdControlsRepository(
        impl: ContentAdControlsRepositoryImpl,
    ): ContentAdControlsRepository
}
