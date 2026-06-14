package com.testlogon.android.data.analytics

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.earnings.EarningsClock
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
 * AND-399 - the analytics-dashboard data layer over [AnalyticsDashboardApi].
 *
 * A load fans out the per-metric idempotent GETs (overview / views / subscribers / top-content /
 * audience) in PARALLEL (coroutineScope { async {...} }), maps each DTO -> domain, and assembles one
 * [AnalyticsDashboard]. Partial success is expected behaviour (spec section 7): the OVERVIEW call is
 * authoritative (its failure fails the load), while the four secondary sections are best-effort - a
 * failed secondary call degrades to an empty section (audience/top-content flag the failure so the UI
 * can show an inline retry) rather than failing the whole page.
 *
 * Every call is wrapped in [ApiResult] via the established call{} pattern (CancellationException
 * re-thrown, HttpException -> Failure, transport -> NetworkError). DTOs never leak past this layer.
 *
 * Caching: an in-memory snapshot per range (mirroring AND-252 EarningsRepository) backs the
 * stale-on-failure UI - the ViewModel serves the last good snapshot with isStale=true when a refresh
 * fails. No Room (and so no migration); the cache is app-private and process-scoped.
 *
 * [refresh] issues POST /ui/analytics/refresh (the recompute trigger) then re-loads bypassing the
 * cache. It is the only non-GET call and is idempotent (a recompute, not an analytics write).
 */
interface AnalyticsDashboardRepository {

    /** Load + assemble the dashboard for [range]. Overview failure = load failure; others degrade. */
    suspend fun loadDashboard(range: AnalyticsDashboardRange): ApiResult<AnalyticsDashboard>

    /** Recompute (POST /refresh) then reload [range] fresh. A refresh failure is non-fatal upstream. */
    suspend fun refresh(range: AnalyticsDashboardRange): ApiResult<AnalyticsDashboard>

    /** The last good snapshot for [range], or null if none cached (drives the stale-cache UI). */
    fun cached(range: AnalyticsDashboardRange): AnalyticsDashboard?

    /** Drop all cached snapshots (logout / account-switch cleanup). */
    fun clear()
}

@Singleton
class AnalyticsDashboardRepositoryImpl @Inject constructor(
    private val api: AnalyticsDashboardApi,
    private val errorParser: ApiErrorParser,
    private val clock: EarningsClock,
) : AnalyticsDashboardRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO
    private val cache = ConcurrentHashMap<AnalyticsDashboardRange, AnalyticsDashboard>()

    override suspend fun loadDashboard(range: AnalyticsDashboardRange): ApiResult<AnalyticsDashboard> =
        withContext(io) { fetch(range) }

    override suspend fun refresh(range: AnalyticsDashboardRange): ApiResult<AnalyticsDashboard> =
        withContext(io) {
            // Best-effort recompute; a failed /refresh must NOT block the subsequent re-fetch.
            runCatching { api.refresh() }
            fetch(range)
        }

    private suspend fun fetch(range: AnalyticsDashboardRange): ApiResult<AnalyticsDashboard> {
        val window = range.toDateWindow(clock.todayEpochDay())
        return call {
            coroutineScope {
                // Overview is authoritative: a thrown failure here propagates to the call{} wrapper.
                val overviewDeferred = async {
                    api.getOverview(fromDate = window.fromDate, toDate = window.toDate)
                }
                // Secondary sections are best-effort: capture the result, never throw out of the async.
                val viewsDeferred = async {
                    runCatching { api.getViews(fromDate = window.fromDate, toDate = window.toDate) }
                }
                val subscribersDeferred = async {
                    runCatching { api.getSubscribers(fromDate = window.fromDate, toDate = window.toDate) }
                }
                val topContentDeferred = async {
                    runCatching { api.getTopContent(fromDate = window.fromDate, toDate = window.toDate) }
                }
                val audienceDeferred = async {
                    runCatching { api.getAudience(fromDate = window.fromDate, toDate = window.toDate) }
                }

                val overview = overviewDeferred.await()
                val viewsResult = viewsDeferred.await()
                val subscribersResult = subscribersDeferred.await()
                val topContentResult = topContentDeferred.await()
                val audienceResult = audienceDeferred.await()

                val audience = audienceResult.getOrNull()
                val topContentDto = topContentResult.getOrNull()
                // Top content is embedded in the overview AND available standalone; prefer the dedicated
                // endpoint when it succeeded, else fall back to the overview's embedded list.
                val topContentRows = topContentDto?.toDomain()
                    ?: overview.topContent.map { it.toDomain() }

                AnalyticsDashboard(
                    overview = overview.toDomain(),
                    views = viewsResult.getOrNull()?.toDomain().orEmpty(),
                    subscribers = subscribersResult.getOrNull()?.toDomain().orEmpty(),
                    topContent = topContentRows,
                    audienceCountries = audience?.countries?.map { it.toAudienceRow() }.orEmpty(),
                    audienceDevices = audience?.devices?.map { it.toAudienceRow() }.orEmpty(),
                    audienceFailed = audienceResult.isFailure,
                    topContentFailed = topContentResult.isFailure,
                )
            }
        }.also { result ->
            if (result is ApiResult.Success && !result.data.isEmpty) cache[range] = result.data
        }
    }

    override fun cached(range: AnalyticsDashboardRange): AnalyticsDashboard? = cache[range]

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
