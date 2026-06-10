package com.testlogon.android.data.tracking

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
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
 * AND-215 — carrier-tracking data layer over [TrackingApi].
 *
 * `tracking(txnId)` GETs the flat CarrierTrackingView and maps it to a [CarrierTracking] (shipment null
 * when not shipped). Wraps every call in [ApiResult]; CancellationException is re-thrown; HTTP errors
 * fold to Failure and transport failures to NetworkError. The GET is idempotent; a single bounded
 * backoff retry is applied for transport failures only (4xx/Failure is never retried).
 */
interface TrackingRepository {
    suspend fun tracking(txnId: String): ApiResult<CarrierTracking>
}

@Singleton
class TrackingRepositoryImpl @Inject constructor(
    private val api: TrackingApi,
    private val errorParser: ApiErrorParser,
) : TrackingRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun tracking(txnId: String): ApiResult<CarrierTracking> = withContext(io) {
        var last: ApiResult<CarrierTracking> = call { api.getTracking(txnId) }.map { it.toDomain() }
        var attempt = 0
        // Retry transport failures (idempotent GET) up to MAX_RETRIES; never retry server Failures.
        while (last is ApiResult.NetworkError && attempt < MAX_RETRIES) {
            attempt++
            last = call { api.getTracking(txnId) }.map { it.toDomain() }
        }
        last
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

    companion object {
        /** Idempotent GET: one bounded retry on transport failure. */
        const val MAX_RETRIES = 1
    }
}
