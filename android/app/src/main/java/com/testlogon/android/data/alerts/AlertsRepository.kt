package com.testlogon.android.data.alerts

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Alerts-inbox data layer over [AlertsApi].
 *
 * loadAlerts() issues the idempotent GET ui/alerts (first page, optionally unread-only) and maps to
 * [AlertsPage]; markRead()/markAllRead() POST the mutations (not auto-retried). Every call is wrapped
 * in [ApiResult] (CancellationException re-thrown, HTTP -> Failure, transport -> NetworkError). A
 * last-known-good page is held in memory so a failed refresh can fall back to a stale snapshot;
 * [clear] empties it (logout cleanup).
 */
interface AlertsRepository {

    suspend fun loadAlerts(unreadOnly: Boolean): ApiResult<AlertsPage>

    suspend fun markRead(alertIds: List<String>): ApiResult<Unit>

    suspend fun markAllRead(): ApiResult<Unit>

    fun cached(): AlertsPage?

    fun clear()
}

@Singleton
class AlertsRepositoryImpl @Inject constructor(
    private val api: AlertsApi,
    private val errorParser: ApiErrorParser,
) : AlertsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    @Volatile
    private var snapshot: AlertsPage? = null

    override suspend fun loadAlerts(unreadOnly: Boolean): ApiResult<AlertsPage> = withContext(io) {
        call { api.getAlerts(limit = PAGE_SIZE, unreadOnly = if (unreadOnly) true else null).toDomain() }
            .also { if (it is ApiResult.Success) snapshot = it.data }
    }

    override suspend fun markRead(alertIds: List<String>): ApiResult<Unit> = withContext(io) {
        if (alertIds.isEmpty()) return@withContext ApiResult.Success(Unit)
        call { api.markRead(MarkReadReqDto(alertIds)); Unit }
    }

    override suspend fun markAllRead(): ApiResult<Unit> = withContext(io) {
        call { api.markAllRead(); Unit }
    }

    override fun cached(): AlertsPage? = snapshot

    override fun clear() {
        snapshot = null
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

    private companion object {
        private const val PAGE_SIZE = 50
    }
}
