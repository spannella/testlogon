package com.testlogon.android.data.costs

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
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Cost-tracking data layer over [CostsApi].
 *
 * loadOverview() fans out daily-summary + 30-day trends + unacked alerts + optimizations in parallel and
 * folds the web CostOverviewPage's derived week/month totals. The breakdown / budgets / alerts screens
 * call the narrower loaders. Every call is wrapped in [ApiResult] (CancellationException re-thrown,
 * HTTP -> Failure, transport -> NetworkError). A last-known-good overview is cached in-memory for stale
 * fallback; [clear] empties it (logout cleanup).
 */
interface CostsRepository {
    suspend fun loadOverview(): ApiResult<CostOverview>
    suspend fun loadDailySummary(date: String): ApiResult<CostSummary>
    suspend fun loadTicketCosts(): ApiResult<List<TicketCost>>
    suspend fun loadBudgets(): ApiResult<List<Budget>>
    suspend fun createBudget(body: CostBudgetInDto): ApiResult<Unit>
    suspend fun updateBudget(budgetId: String, body: CostBudgetUpdateInDto): ApiResult<Unit>
    suspend fun deleteBudget(budgetId: String): ApiResult<Unit>
    suspend fun loadAlerts(unacknowledgedOnly: Boolean): ApiResult<List<CostAlert>>
    suspend fun acknowledgeAlert(alertId: String): ApiResult<Unit>
    fun cachedOverview(): CostOverview?
    fun today(): String
    fun clear()
}

@Singleton
class CostsRepositoryImpl @Inject constructor(
    private val api: CostsApi,
    private val errorParser: ApiErrorParser,
) : CostsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    @Volatile
    private var overviewSnapshot: CostOverview? = null

    override fun today(): String {
        val fmt = SimpleDateFormat("yyyy-MM-dd", Locale.US)
        fmt.timeZone = TimeZone.getTimeZone("UTC")
        return fmt.format(Date())
    }

    override suspend fun loadOverview(): ApiResult<CostOverview> = withContext(io) {
        call {
            coroutineScope {
                val dailyD = async { api.getDailySummary(today()) }
                val trendsD = async { api.getTrends(30) }
                val alertsD = async { api.listAlerts(acknowledged = false) }
                // Optimizations are best-effort; a failure there shouldn't blank the overview.
                val optsD = async {
                    try {
                        api.getOptimizations()
                    } catch (e: CancellationException) {
                        throw e
                    } catch (_: Exception) {
                        emptyList()
                    }
                }
                val daily = dailyD.await().toDomain()
                val weeks = trendsD.await().weeks.map { it.toDomain() }
                CostOverview(
                    today = daily,
                    weekCents = weeks.lastOrNull()?.totalCents ?: 0L,
                    monthCents = weeks.sumOf { it.totalCents },
                    weeks = weeks,
                    unacknowledgedAlerts = alertsD.await().alerts.size,
                    optimizations = optsD.await().map { it.toDomain() },
                )
            }
        }.also { if (it is ApiResult.Success) overviewSnapshot = it.data }
    }

    override suspend fun loadDailySummary(date: String): ApiResult<CostSummary> = withContext(io) {
        call { api.getDailySummary(date).toDomain() }
    }

    override suspend fun loadTicketCosts(): ApiResult<List<TicketCost>> = withContext(io) {
        call { api.listTicketCosts(limit = 50).ticketCosts.map { it.toDomain() } }
    }

    override suspend fun loadBudgets(): ApiResult<List<Budget>> = withContext(io) {
        call { api.listBudgets().map { it.toDomain() } }
    }

    override suspend fun createBudget(body: CostBudgetInDto): ApiResult<Unit> = mutate { api.createBudget(body) }

    override suspend fun updateBudget(budgetId: String, body: CostBudgetUpdateInDto): ApiResult<Unit> =
        mutate { api.updateBudget(budgetId, body) }

    override suspend fun deleteBudget(budgetId: String): ApiResult<Unit> = mutate { api.deleteBudget(budgetId) }

    override suspend fun loadAlerts(unacknowledgedOnly: Boolean): ApiResult<List<CostAlert>> = withContext(io) {
        call {
            api.listAlerts(acknowledged = if (unacknowledgedOnly) false else null)
                .alerts.map { it.toDomain() }
        }
    }

    override suspend fun acknowledgeAlert(alertId: String): ApiResult<Unit> = mutate { api.acknowledgeAlert(alertId) }

    override fun cachedOverview(): CostOverview? = overviewSnapshot

    override fun clear() {
        overviewSnapshot = null
    }

    private suspend fun mutate(block: suspend () -> Any?): ApiResult<Unit> = withContext(io) {
        call {
            block()
            Unit
        }
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: com.squareup.moshi.JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
