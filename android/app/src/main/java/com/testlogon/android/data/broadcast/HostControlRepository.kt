package com.testlogon.android.data.broadcast

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
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
 * AND-309 — data layer over [HostControlApi] for the host LIVE lifecycle control plane.
 *
 * Kept DELIBERATELY SEPARATE from [BroadcastRepository] so the shared repository's fakes (ViewerViewModel /
 * BroadcastBrowseViewModel / CreateBroadcastViewModel / IngestViewModel tests) are NOT touched. Each call is
 * wrapped in [ApiResult] (Failure for HTTP errors via [ApiErrorParser], NetworkError for transport
 * failures, Failure(parse) for malformed JSON) and the wire DTO is mapped to the domain BEFORE the typed
 * result. Never throws (CancellationException is re-thrown).
 *
 * start / stop / resume / reschedule all return the full [BroadcastSession] (reusing the existing
 * BroadcastSessionDto -> domain mapper); [health] returns a [HostHealthReport].
 */
interface HostControlRepository {

    /** Start (go-live) [sessionId]. */
    suspend fun start(sessionId: String): ApiResult<BroadcastSession>

    /** Stop [sessionId] (terminal "stopped"). */
    suspend fun stop(sessionId: String): ApiResult<BroadcastSession>

    /** Resume [sessionId] (bodiless). */
    suspend fun resume(sessionId: String): ApiResult<BroadcastSession>

    /** Reschedule [sessionId] to [scheduledAtEpochSeconds] (Unix epoch SECONDS). */
    suspend fun reschedule(
        sessionId: String,
        scheduledAtEpochSeconds: Long,
    ): ApiResult<BroadcastSession>

    /** Poll [sessionId] ingest/output health. */
    suspend fun health(sessionId: String): ApiResult<HostHealthReport>

    /** Read [sessionId]'s current full session (load + re-sync after a failed action). */
    suspend fun session(sessionId: String): ApiResult<BroadcastSession>
}

@Singleton
class HostControlRepositoryImpl @Inject constructor(
    private val api: HostControlApi,
    private val errorParser: ApiErrorParser,
) : HostControlRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun start(sessionId: String): ApiResult<BroadcastSession> =
        withContext(io) {
            call { api.start(sessionId, SessionActionDto()) }.map { it.toDomain() }
        }

    override suspend fun stop(sessionId: String): ApiResult<BroadcastSession> =
        withContext(io) {
            call { api.stop(sessionId, SessionActionDto()) }.map { it.toDomain() }
        }

    override suspend fun resume(sessionId: String): ApiResult<BroadcastSession> =
        withContext(io) {
            call { api.resume(sessionId) }.map { it.toDomain() }
        }

    override suspend fun reschedule(
        sessionId: String,
        scheduledAtEpochSeconds: Long,
    ): ApiResult<BroadcastSession> = withContext(io) {
        call { api.reschedule(sessionId, RescheduleRequest(scheduledAt = scheduledAtEpochSeconds)) }
            .map { it.toDomain() }
    }

    override suspend fun health(sessionId: String): ApiResult<HostHealthReport> =
        withContext(io) {
            call { api.health(sessionId) }.map { it.toDomain() }
        }

    override suspend fun session(sessionId: String): ApiResult<BroadcastSession> =
        withContext(io) {
            call { api.session(sessionId) }.map { it.toDomain() }
        }

    /**
     * Folds a single call into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser]); transport
     * failures -> NetworkError; malformed JSON -> Failure(parse). The JsonEncodingException catch precedes
     * the IOException catch (it is an IOException subtype). Cancellation is re-thrown.
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
