package com.testlogon.android.feature.ads.analytics.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.ads.AdAnalyticsSummary
import com.testlogon.android.core.model.ads.AdBreakdownEntry
import com.testlogon.android.core.model.ads.AdTimeSeriesPoint
import com.testlogon.android.core.model.ads.BreakdownDimension
import com.testlogon.android.core.model.ads.DateRange
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
 * AND-368 - data layer for the READ-ONLY ad-analytics dashboard. EXTENDS the AND-363 [AdsAccountsApi] (no
 * fork): the summary / timeseries / breakdown reads + the campaign list (for the breakdown name join) all go
 * through the one ads service. Each call REUSES the raw-DTO api, wraps it in [call], and maps the DTO to the
 * core-model domain BEFORE the typed [ApiResult] (mirrors AND-367 AdsBillingRepository).
 *
 * The summary is a single DTO; the timeseries + breakdown are BARE ARRAYS (no paging - the breakdown is
 * bounded client-side via [BREAKDOWN_CAP]). READ-ONLY: there are no mutating operations here. NO Room / disk
 * persistence (the in-memory stale fallback lives in the VM).
 */
interface AdAnalyticsRepository {

    /** GET the KPI summary for [accountId] over [range], mapped. Idempotent GET. */
    suspend fun getSummary(accountId: String, range: DateRange): ApiResult<AdAnalyticsSummary>

    /** GET the daily time series (bare array) for [accountId] over [range], mapped. Idempotent GET. */
    suspend fun getTimeseries(accountId: String, range: DateRange): ApiResult<List<AdTimeSeriesPoint>>

    /**
     * GET the [dimension] breakdown (bare array, capped at [BREAKDOWN_CAP]) for [accountId] over [range], with
     * each row's campaign name joined from the AND-363 campaign list (best-effort - a campaign-list failure
     * leaves names null but does NOT fail the breakdown). Idempotent GET.
     */
    suspend fun getBreakdown(
        accountId: String,
        dimension: BreakdownDimension,
        range: DateRange,
    ): ApiResult<List<AdBreakdownEntry>>

    companion object {
        /** Client-side cap on breakdown rows (single bounded fetch, no paging). */
        const val BREAKDOWN_CAP = 50
    }
}

@Singleton
class AdAnalyticsRepositoryImpl @Inject constructor(
    private val api: AdsAccountsApi,
    private val errorParser: ApiErrorParser,
) : AdAnalyticsRepository {

    override suspend fun getSummary(
        accountId: String,
        range: DateRange,
    ): ApiResult<AdAnalyticsSummary> = withContext(Dispatchers.IO) {
        call { api.getAnalyticsSummary(accountId, range.from, range.to).toDomain() }
    }

    override suspend fun getTimeseries(
        accountId: String,
        range: DateRange,
    ): ApiResult<List<AdTimeSeriesPoint>> = withContext(Dispatchers.IO) {
        call { api.getAnalyticsTimeseries(accountId, range.from, range.to).map { it.toDomain() } }
    }

    override suspend fun getBreakdown(
        accountId: String,
        dimension: BreakdownDimension,
        range: DateRange,
    ): ApiResult<List<AdBreakdownEntry>> = withContext(Dispatchers.IO) {
        call {
            val rows = api.getAnalyticsBreakdown(accountId, dimension.wire, range.from, range.to)
                .take(AdAnalyticsRepository.BREAKDOWN_CAP)
                .map { it.toDomain() }
            // Best-effort campaign-name join: the breakdown row carries no name, so join from the campaign
            // list keyed by campaign id. A campaign-list failure must NOT fail the breakdown, so it is read
            // defensively (names simply stay null).
            val names = campaignNames(accountId)
            rows.map { row ->
                val name = row.key?.let { names[it] }
                if (name == null) row else row.copy(campaignName = name)
            }
        }
    }

    /** Reads the campaign list and builds a campaignId -> name map; an error yields an empty map. */
    private suspend fun campaignNames(accountId: String): Map<String, String> = try {
        api.listAdsAccountCampaigns(accountId)
            .mapNotNull { dto -> dto.name?.let { dto.campaignId to it } }
            .toMap()
    } catch (e: CancellationException) {
        throw e
    } catch (_: Throwable) {
        emptyMap()
    }

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser], preserving the status);
     * malformed JSON -> Failure(parse); transport failures -> NetworkError. The JsonEncodingException catch
     * precedes the IOException catch (it is an IOException subtype). Cancellation is re-thrown. Mirrors the
     * AND-367 AdsBillingRepository.
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
 * AND-368 - Hilt wiring for the ad-analytics feature. Binds the repository seam to its default impl (which
 * consumes the AND-363 [AdsAccountsApi] + the shared [ApiErrorParser]). NO new endpoint module, migration, or
 * dependency (the api is already provided by the AND-363 AdsNetworkModule).
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class AdAnalyticsDataModule {

    @Binds
    @Singleton
    abstract fun bindAdAnalyticsRepository(impl: AdAnalyticsRepositoryImpl): AdAnalyticsRepository
}
