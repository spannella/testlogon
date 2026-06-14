package com.testlogon.android.data.dashboard

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.Dashboard
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-065 — dashboard data layer over [DashboardApi].
 *
 * Fetches `GET ui/dashboard/summary`, maps it to the [Dashboard] domain type, and returns it wrapped
 * in [ApiResult]. `forceRefresh = true` first fires the rate-limited `POST ui/dashboard/refresh`
 * (best-effort; its failure does not abort the read) then re-fetches the summary — mirroring the web
 * client. A last-known-good snapshot is retained in memory so the ViewModel can serve stale content
 * on a failed refresh (AND-068 offline state); no Room/DataStore cache is in scope.
 */
interface DashboardRepository {
    suspend fun getDashboard(forceRefresh: Boolean = false): ApiResult<Dashboard>
    fun dashboard(): Flow<ApiResult<Dashboard>>

    /** Last-known-good dashboard snapshot for offline/stale rendering, or null. */
    fun cachedDashboard(): Dashboard?
}

@Singleton
class DashboardRepositoryImpl @Inject constructor(
    private val api: DashboardApi,
    private val errorParser: ApiErrorParser,
) : DashboardRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    @Volatile
    private var cache: Dashboard? = null

    override suspend fun getDashboard(forceRefresh: Boolean): ApiResult<Dashboard> =
        withContext(io) {
            if (forceRefresh) {
                // Best-effort server-side refresh trigger; a failure here (incl. 429 rate-limit)
                // must not abort the subsequent summary read.
                runCatching { api.refreshDashboard() }
            }
            apiCall { api.getDashboard().toDomain() }.also { result ->
                if (result is ApiResult.Success) cache = result.data
            }
        }

    override fun dashboard(): Flow<ApiResult<Dashboard>> = flow {
        emit(getDashboard())
    }.flowOn(io)

    override fun cachedDashboard(): Dashboard? = cache

    private suspend fun <T> apiCall(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
