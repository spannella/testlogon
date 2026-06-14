package com.testlogon.android.data.call.group

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
 * AND-299 — data layer over [GroupCallApi] for the GROUP-call CONTROL PLANE.
 *
 * Plain authenticated network reads/writes with REAL backend endpoints, so this is fully implemented +
 * testable independent of the FLAGGED native-WebRTC mesh ([com.testlogon.android.data.webrtc.MeshConnectionManager]).
 * Each op is wrapped in [ApiResult] (Failure for HTTP errors via [ApiErrorParser], NetworkError for
 * transport failures, Failure(parse) for malformed JSON), mapping wire DTOs -> domain before returning.
 * Never throws (CancellationException re-thrown). The JsonEncodingException catch precedes IOException (it
 * is an IOException subtype) — matching [com.testlogon.android.data.call.CallRepository].
 *
 * [selfUserId] is optional: when null, isSelf is simply never true (the control plane still functions).
 */
interface GroupCallRepository {

    /** POST .../create — start a group call. */
    suspend fun create(
        conversationId: String,
        mode: String = "video",
        maxParticipants: Int = 8,
        selfUserId: String? = null,
    ): ApiResult<GroupCall>

    /** GET .../{callId}. */
    suspend fun get(callId: String, selfUserId: String? = null): ApiResult<GroupCall>

    /** GET .../{callId}/participants. */
    suspend fun participants(
        callId: String,
        creatorUserId: String,
        selfUserId: String? = null,
    ): ApiResult<List<GroupParticipant>>

    /** GET .../active/{conversationId}. */
    suspend fun active(conversationId: String): ApiResult<GroupCallActive>

    /** POST .../{callId}/join. [creatorUserId] supplies the host id the join body lacks. */
    suspend fun join(
        callId: String,
        conversationId: String,
        creatorUserId: String,
        selfUserId: String? = null,
    ): ApiResult<GroupCall>

    /** POST .../{callId}/leave. */
    suspend fun leave(callId: String): ApiResult<GroupCallLeave>

    /** POST .../{callId}/end. */
    suspend fun end(callId: String): ApiResult<GroupCallEnd>

    /** PATCH .../{callId}/media (only the non-null toggles are sent). */
    suspend fun media(
        callId: String,
        audio: Boolean? = null,
        video: Boolean? = null,
        screen: Boolean? = null,
    ): ApiResult<GroupCallMedia>

    /** POST .../{callId}/signal — relay an opaque payload to a peer. */
    suspend fun signal(
        callId: String,
        type: String,
        targetUserId: String,
        payload: Map<String, Any?>? = null,
    ): ApiResult<GroupCallSignal>
}

/** Result of the active-call probe (GET .../active/{conversationId}). */
data class GroupCallActive(
    val active: Boolean,
    val callId: String?,
    val state: String?,
    val mode: String?,
    val currentParticipantCount: Int?,
)

/** Result of leaving a group call (POST .../leave). */
data class GroupCallLeave(
    val ok: Boolean,
    val callEnded: Boolean,
    val remainingParticipants: Int,
)

/** Result of ending a group call (POST .../end). */
data class GroupCallEnd(
    val ok: Boolean,
    val callId: String?,
    val durationSeconds: Long,
    val totalParticipants: Int,
)

/** Result of a media toggle (PATCH .../media). */
data class GroupCallMedia(
    val ok: Boolean,
    val audio: Boolean,
    val video: Boolean,
    val screen: Boolean,
)

/** Result of a signal relay (POST .../signal). */
data class GroupCallSignal(
    val ok: Boolean,
    val relayedTo: String?,
)

@Singleton
class GroupCallRepositoryImpl @Inject constructor(
    private val api: GroupCallApi,
    private val errorParser: ApiErrorParser,
) : GroupCallRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun create(
        conversationId: String,
        mode: String,
        maxParticipants: Int,
        selfUserId: String?,
    ): ApiResult<GroupCall> = withContext(io) {
        call {
            api.create(
                GroupCallCreateInDto(
                    conversationId = conversationId,
                    mode = mode,
                    maxParticipants = maxParticipants,
                ),
            )
        }.map { it.toDomain(selfUserId) }
    }

    override suspend fun get(callId: String, selfUserId: String?): ApiResult<GroupCall> =
        withContext(io) {
            call { api.get(callId) }.map { it.toDomain(selfUserId) }
        }

    override suspend fun participants(
        callId: String,
        creatorUserId: String,
        selfUserId: String?,
    ): ApiResult<List<GroupParticipant>> = withContext(io) {
        call { api.participants(callId) }.map { it.toDomain(selfUserId, creatorUserId) }
    }

    override suspend fun active(conversationId: String): ApiResult<GroupCallActive> = withContext(io) {
        call { api.active(conversationId) }.map {
            GroupCallActive(
                active = it.active,
                callId = it.callId,
                state = it.state,
                mode = it.mode,
                currentParticipantCount = it.currentParticipantCount,
            )
        }
    }

    override suspend fun join(
        callId: String,
        conversationId: String,
        creatorUserId: String,
        selfUserId: String?,
    ): ApiResult<GroupCall> = withContext(io) {
        call { api.join(callId) }.map {
            it.toDomain(selfUserId = selfUserId, conversationId = conversationId, creatorUserId = creatorUserId)
        }
    }

    override suspend fun leave(callId: String): ApiResult<GroupCallLeave> = withContext(io) {
        call { api.leave(callId) }.map {
            GroupCallLeave(ok = it.ok, callEnded = it.callEnded, remainingParticipants = it.remainingParticipants)
        }
    }

    override suspend fun end(callId: String): ApiResult<GroupCallEnd> = withContext(io) {
        call { api.end(callId) }.map {
            GroupCallEnd(
                ok = it.ok,
                callId = it.callId,
                durationSeconds = it.durationSeconds,
                totalParticipants = it.totalParticipants,
            )
        }
    }

    override suspend fun media(
        callId: String,
        audio: Boolean?,
        video: Boolean?,
        screen: Boolean?,
    ): ApiResult<GroupCallMedia> = withContext(io) {
        call {
            api.media(callId, GroupCallMediaUpdateInDto(audio = audio, video = video, screen = screen))
        }.map {
            GroupCallMedia(
                ok = it.ok,
                audio = it.mediaStatus.audio,
                video = it.mediaStatus.video,
                screen = it.mediaStatus.screen,
            )
        }
    }

    override suspend fun signal(
        callId: String,
        type: String,
        targetUserId: String,
        payload: Map<String, Any?>?,
    ): ApiResult<GroupCallSignal> = withContext(io) {
        call {
            api.signal(
                callId,
                GroupCallSignalInDto(type = type, targetUserId = targetUserId, payload = payload),
            )
        }.map { GroupCallSignal(ok = it.ok, relayedTo = it.relayedTo) }
    }

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
