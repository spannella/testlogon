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
 * AND-278 — data layer over [BroadcastApi].
 *
 * Wraps each call in [ApiResult] (Failure for HTTP errors via [ApiErrorParser], NetworkError for
 * transport failures, Failure(parse) for malformed JSON), mapping wire DTOs to the redaction-safe
 * domain. Never throws (CancellationException is re-thrown). No Room cache in this slice (SWR caching is
 * AND-116 / AND-279's concern). Data-only wave: no ViewModel/UI here (the viewer screen is AND-280/286).
 */
interface BroadcastRepository {

    /** List sessions, optionally filtered by lifecycle [status] (live/scheduled/stopped/...). */
    suspend fun sessions(status: String? = null, limit: Int? = null): ApiResult<BroadcastSessionPage>

    /** Dedicated scheduled-sessions route ({ items, count }). */
    suspend fun scheduledSessions(limit: Int? = null): ApiResult<BroadcastScheduledPage>

    /** Dedicated upcoming-sessions route ({ items, count }). */
    suspend fun upcomingSessions(limit: Int? = null): ApiResult<BroadcastScheduledPage>

    /** A single session's full detail (same shape as a list element). */
    suspend fun session(sessionId: String): ApiResult<BroadcastSession>

    /** Mints a fresh short-lived signed playback URL for [sessionId]. */
    suspend fun mintPlaybackUrl(sessionId: String): ApiResult<BroadcastPlaybackUrl>
}

@Singleton
class BroadcastRepositoryImpl @Inject constructor(
    private val api: BroadcastApi,
    private val errorParser: ApiErrorParser,
) : BroadcastRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun sessions(status: String?, limit: Int?): ApiResult<BroadcastSessionPage> =
        withContext(io) {
            call { api.listSessions(status, limit) }.map { it.toDomain() }
        }

    override suspend fun scheduledSessions(limit: Int?): ApiResult<BroadcastScheduledPage> =
        withContext(io) {
            call { api.listScheduledSessions(limit) }.map { it.toDomain() }
        }

    override suspend fun upcomingSessions(limit: Int?): ApiResult<BroadcastScheduledPage> =
        withContext(io) {
            call { api.listUpcomingSessions(limit) }.map { it.toDomain() }
        }

    override suspend fun session(sessionId: String): ApiResult<BroadcastSession> =
        withContext(io) {
            call { api.getSession(sessionId) }.map { it.toDomain() }
        }

    override suspend fun mintPlaybackUrl(sessionId: String): ApiResult<BroadcastPlaybackUrl> =
        withContext(io) {
            call { api.mintPlaybackUrl(sessionId) }.map { it.toDomain() }
        }

    /**
     * Folds a single call into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser]); transport
     * failures -> NetworkError; malformed JSON -> Failure(parse). The JsonEncodingException catch
     * precedes the IOException catch (it is an IOException subtype). Cancellation is re-thrown.
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
