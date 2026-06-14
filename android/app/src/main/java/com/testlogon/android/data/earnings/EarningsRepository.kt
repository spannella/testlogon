package com.testlogon.android.data.earnings

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-252 — earnings dashboard data layer over [EarningsApi].
 *
 * Thin orchestration: a dashboard load issues TWO concurrent idempotent GETs —
 * `getQuickStats()` (lifetime/pending/period headline figures) and
 * `getSummary(fromDate, toDate, granularity)` where the dates are derived client-side from the
 * selected [EarningsRange] (ALL omits both) — and combines them into an [EarningsDashboard].
 * Every call is wrapped in [ApiResult] (CancellationException re-thrown, HTTP -> Failure, transport ->
 * NetworkError). DTOs map to domain before returning (no raw DTOs leak out).
 *
 * Caching: a last-known-good [EarningsDashboard] is held in memory per range (matching the dashboard
 * surface's `cachedDashboard()` pattern) so a failed refresh can fall back to a stale snapshot for the
 * offline/stale UI. No earnings JSON is persisted to disk (financial PII; §8). [clear] empties the
 * cache and MUST be invoked by the logout cleanup.
 */
interface EarningsRepository {

    /** Load (or refresh) the dashboard for [range] with the given chart [granularity]. */
    suspend fun loadDashboard(
        range: EarningsRange,
        granularity: String = EarningsApi.DEFAULT_GRANULARITY,
    ): ApiResult<EarningsDashboard>

    /** Last successful snapshot for [range], or null if none cached. */
    fun cached(range: EarningsRange): EarningsDashboard?

    /** Drop all cached snapshots (logout cleanup, AND-032). */
    fun clear()
}

@Singleton
class EarningsRepositoryImpl @Inject constructor(
    private val api: EarningsApi,
    private val errorParser: ApiErrorParser,
    private val clock: EarningsClock,
) : EarningsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO
    private val cache = ConcurrentHashMap<EarningsRange, EarningsDashboard>()

    override suspend fun loadDashboard(
        range: EarningsRange,
        granularity: String,
    ): ApiResult<EarningsDashboard> = withContext(io) {
        val window = range.toDateWindow(clock.todayEpochDay())
        call {
            coroutineScope {
                val quickStatsDeferred = async { api.getQuickStats() }
                val summaryDeferred = async {
                    api.getSummary(
                        fromDate = window.fromDate,
                        toDate = window.toDate,
                        granularity = granularity,
                    )
                }
                val quickStats = quickStatsDeferred.await().toDomain()
                val summary = summaryDeferred.await().toDomain()
                EarningsDashboard(
                    range = range,
                    quickStats = quickStats,
                    summary = summary,
                    currency = summary.total.currency,
                    fetchedAtEpochMs = clock.nowEpochMs(),
                    isStale = false,
                )
            }
        }.also { result ->
            if (result is ApiResult.Success) cache[range] = result.data
        }
    }

    override fun cached(range: EarningsRange): EarningsDashboard? = cache[range]

    override fun clear() = cache.clear()

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
