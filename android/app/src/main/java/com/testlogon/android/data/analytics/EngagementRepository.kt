package com.testlogon.android.data.analytics

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
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-254 — engagement data layer over [EngagementApi].
 *
 * A load issues TWO concurrent idempotent GETs — getEngagement(periodDays) (server-computed rate +
 * counts + trend) and getEngagementHistory() (the rate time-series for the trend chart) — and combines
 * them into one [Engagement]. Every call is wrapped in [ApiResult] (CancellationException re-thrown,
 * HTTP -> Failure, transport -> NetworkError). DTOs map to domain before returning (no raw DTOs leak).
 *
 * The history call is best-effort: a failed history (but successful rate) still yields a [Success] with
 * an empty trend, so a chart-source outage never blocks the headline metrics. A failed RATE call is the
 * load failure.
 */
interface EngagementRepository {

    /** Load engagement metrics (+ trend) for the given [periodDays] window. */
    suspend fun load(periodDays: Int = EngagementApi.DEFAULT_PERIOD_DAYS): ApiResult<Engagement>
}

@Singleton
class EngagementRepositoryImpl @Inject constructor(
    private val api: EngagementApi,
    private val errorParser: ApiErrorParser,
) : EngagementRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun load(periodDays: Int): ApiResult<Engagement> = withContext(io) {
        call {
            coroutineScope {
                val rateDeferred = async { api.getEngagement(periodDays) }
                // History is best-effort; a transport/HTTP failure degrades to an empty trend rather
                // than failing the whole load (the headline rate is the authoritative metric).
                val historyDeferred = async {
                    runCatching { api.getEngagementHistory() }.getOrNull()
                }
                val metrics = rateDeferred.await().toMetrics()
                val trend = historyDeferred.await()?.toDomain().orEmpty()
                Engagement(metrics = metrics, trend = trend)
            }
        }
    }

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
