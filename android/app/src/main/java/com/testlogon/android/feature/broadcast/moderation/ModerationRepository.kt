package com.testlogon.android.feature.broadcast.moderation

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Response
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-313 - data layer over [ModerationApi] for broadcast chat moderation.
 *
 * Kept DELIBERATELY SEPARATE from BroadcastRepository / HostControlRepository / GuestRepository so the shared
 * repository fakes are NOT touched. Each call is wrapped in [ApiResult] (Failure for HTTP errors via
 * [ApiErrorParser], NetworkError for transport failures, Failure(parse) for malformed JSON) and the wire DTO
 * is mapped to the domain BEFORE the typed result. Never throws (CancellationException is re-thrown). POSTs /
 * DELETEs are NOT retried; the log GET is idempotent.
 *
 * ROUTING (the two endpoint families):
 *  - ban / unban / pin / unpin / moderationLog -> ALWAYS the DELEGATE path (require a non-blank creatorId;
 *    a blank creatorId is a fast Failure with no network call).
 *  - mute / deleteMessage -> the HOST path by default; the DELEGATE path when a non-blank [creatorId]
 *    OVERRIDE is supplied. (AND-359 delegate routing is NOT implemented yet; AuthStateStore does not expose a
 *    managingCreator flow, so the override is the explicit signal - see the AND-313 report.)
 */
interface ModerationRepository {

    /**
     * Mute [userId] for [spec]. HOST path by default; DELEGATE path when [creatorId] is non-blank. Returns
     * the muted-until [java.time.Instant] mapped from the 200 body.
     */
    suspend fun mute(
        sessionId: String,
        creatorId: String?,
        userId: String,
        spec: MuteSpec,
    ): ApiResult<java.time.Instant>

    /** Ban [userId] (optional [reason]). DELEGATE path only (requires [creatorId]). */
    suspend fun ban(
        sessionId: String,
        creatorId: String,
        userId: String,
        reason: String?,
    ): ApiResult<Unit>

    /** Unban [userId]. DELEGATE path only (requires [creatorId]). */
    suspend fun unban(
        sessionId: String,
        creatorId: String,
        userId: String,
    ): ApiResult<Unit>

    /** Delete [messageId]. HOST path by default; DELEGATE path when [creatorId] is non-blank. */
    suspend fun deleteMessage(
        sessionId: String,
        creatorId: String?,
        messageId: String,
    ): ApiResult<Unit>

    /** Pin [messageId]. DELEGATE path only (requires [creatorId]). Returns the pinned flag from the 200 body. */
    suspend fun pin(
        sessionId: String,
        creatorId: String,
        messageId: String,
    ): ApiResult<Boolean>

    /** Unpin [messageId]. DELEGATE path only (requires [creatorId]). */
    suspend fun unpin(
        sessionId: String,
        creatorId: String,
        messageId: String,
    ): ApiResult<Unit>

    /** List current bans. DELEGATE path only (requires [creatorId]). Plain array -> domain list. */
    suspend fun listBans(
        sessionId: String,
        creatorId: String,
    ): ApiResult<List<ModerationBan>>

    /**
     * Fetch the moderation log (newest-first, [limit] entries). DELEGATE path only (requires [creatorId]).
     * Plain array (NO cursor / paging) -> domain list.
     */
    suspend fun moderationLog(
        sessionId: String,
        creatorId: String,
        limit: Int = 100,
    ): ApiResult<List<ModerationLogEntry>>
}

@Singleton
class ModerationRepositoryImpl @Inject constructor(
    private val api: ModerationApi,
    private val errorParser: ApiErrorParser,
) : ModerationRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun mute(
        sessionId: String,
        creatorId: String?,
        userId: String,
        spec: MuteSpec,
    ): ApiResult<java.time.Instant> = withContext(io) {
        val cid = creatorId?.takeIf { it.isNotBlank() }
        val result = if (cid != null) {
            // DELEGATE path (managingCreator / override): { user_id, duration_seconds }.
            callBody { api.mute(cid, sessionId, MuteRequestDto(userId, spec.durationSeconds)) }
        } else {
            // HOST path: { target_user_id, duration_seconds }.
            callBody { api.muteHost(sessionId, ChatMuteRequestDto(userId, spec.durationSeconds)) }
        }
        result.map { java.time.Instant.ofEpochSecond(it.mutedUntil) }
    }

    override suspend fun ban(
        sessionId: String,
        creatorId: String,
        userId: String,
        reason: String?,
    ): ApiResult<Unit> = withContext(io) {
        requireDelegate(creatorId) ?: callUnit {
            api.ban(creatorId, sessionId, BanRequestDto(userId, reason.orEmpty()))
        }
    }

    override suspend fun unban(
        sessionId: String,
        creatorId: String,
        userId: String,
    ): ApiResult<Unit> = withContext(io) {
        requireDelegate(creatorId) ?: callUnit { api.unban(creatorId, sessionId, userId) }
    }

    override suspend fun deleteMessage(
        sessionId: String,
        creatorId: String?,
        messageId: String,
    ): ApiResult<Unit> = withContext(io) {
        val cid = creatorId?.takeIf { it.isNotBlank() }
        if (cid != null) {
            callUnit { api.deleteMessage(cid, sessionId, messageId) }
        } else {
            callUnit { api.deleteMessageHost(sessionId, messageId) }
        }
    }

    override suspend fun pin(
        sessionId: String,
        creatorId: String,
        messageId: String,
    ): ApiResult<Boolean> = withContext(io) {
        val guard = requireDelegateOf<Boolean>(creatorId)
        guard ?: callBody { api.pin(creatorId, sessionId, messageId) }.map { it.pinned }
    }

    override suspend fun unpin(
        sessionId: String,
        creatorId: String,
        messageId: String,
    ): ApiResult<Unit> = withContext(io) {
        requireDelegate(creatorId) ?: callUnit { api.unpin(creatorId, sessionId, messageId) }
    }

    override suspend fun listBans(
        sessionId: String,
        creatorId: String,
    ): ApiResult<List<ModerationBan>> = withContext(io) {
        val guard = requireDelegateOf<List<ModerationBan>>(creatorId)
        guard ?: call { api.listBans(creatorId, sessionId) }.map { list -> list.map { it.toDomain() } }
    }

    override suspend fun moderationLog(
        sessionId: String,
        creatorId: String,
        limit: Int,
    ): ApiResult<List<ModerationLogEntry>> = withContext(io) {
        val guard = requireDelegateOf<List<ModerationLogEntry>>(creatorId)
        guard ?: call { api.log(creatorId, sessionId, limit) }.map { list -> list.map { it.toDomain() } }
    }

    /** Guard for Unit-returning delegate calls: a blank creatorId is a fast Failure (no network). */
    private fun requireDelegate(creatorId: String): ApiResult<Unit>? =
        if (creatorId.isBlank()) ApiResult.Failure(MISSING_CREATOR_ERROR) else null

    /** Typed variant of [requireDelegate] for non-Unit delegate calls. */
    private fun <T> requireDelegateOf(creatorId: String): ApiResult<T>? =
        if (creatorId.isBlank()) ApiResult.Failure(MISSING_CREATOR_ERROR) else null

    /**
     * Folds a single call into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser]); transport failures
     * -> NetworkError; malformed JSON -> Failure(parse). The JsonEncodingException catch precedes the
     * IOException catch (it is an IOException subtype). Cancellation is re-thrown.
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

    /**
     * Folds a [Response] returning call (an { ok } / empty 200 mutation) into [ApiResult] of Unit. A non-2xx
     * Response is mapped through [ApiErrorParser] from the synthesized [HttpException]; an empty 200 body is
     * success (Retrofit consumes the body without JSON parsing - tolerates EOF on empty).
     */
    private suspend fun callUnit(block: suspend () -> Response<Unit>): ApiResult<Unit> =
        when (val result = call { block() }) {
            is ApiResult.Success -> {
                val response = result.data
                if (response.isSuccessful) {
                    ApiResult.Success(Unit)
                } else {
                    ApiResult.Failure(errorParser.from(HttpException(response)))
                }
            }
            is ApiResult.Failure -> result
            is ApiResult.NetworkError -> result
        }

    /**
     * Folds a [Response] returning call WITH a typed JSON body (mute / pin results) into [ApiResult] of the
     * body. A non-2xx Response -> Failure; a 2xx with an absent body -> a default-constructed body so the
     * caller still maps a successful outcome.
     */
    private suspend fun <T> callBody(block: suspend () -> Response<T>): ApiResult<T> =
        when (val result = call { block() }) {
            is ApiResult.Success -> {
                val response = result.data
                if (response.isSuccessful) {
                    val body = response.body()
                    if (body != null) {
                        ApiResult.Success(body)
                    } else {
                        ApiResult.Failure(
                            ApiError(status = ApiError.STATUS_PARSE, message = "Empty response body."),
                        )
                    }
                } else {
                    ApiResult.Failure(errorParser.from(HttpException(response)))
                }
            }
            is ApiResult.Failure -> result
            is ApiResult.NetworkError -> result
        }

    private companion object {
        /** A blank creatorId on a delegate-only call -> a non-retryable client error (no network). */
        val MISSING_CREATOR_ERROR = ApiError(
            status = 400,
            message = "This action requires a broadcast creator.",
            code = "missing_creator",
        )
    }
}
