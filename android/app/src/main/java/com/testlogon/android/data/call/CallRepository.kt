package com.testlogon.android.data.call

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
 * AND-295 — data layer over [CallApi] for the 1:1 call CONTROL PLANE.
 *
 * Plain authenticated network reads/writes with REAL backend endpoints, so this is fully implemented +
 * testable independent of the FLAGGED native-WebRTC engine. Each op is wrapped in [ApiResult] (Failure for
 * HTTP errors via [ApiErrorParser], NetworkError for transport failures, Failure(parse) for malformed
 * JSON), mapping wire DTOs -> domain before returning. Never throws (CancellationException re-thrown). The
 * JsonEncodingException catch precedes IOException (it is an IOException subtype) — matching
 * SignalingRepository.
 *
 * TURN-credential fetch + signaling send are NOT here: they are reused from AND-291
 * [com.testlogon.android.data.webrtc.IceServersRepository] / AND-290
 * [com.testlogon.android.data.webrtc.SignalingRepository].
 */
interface CallRepository {

    /** POST .../invite — place a 1:1 call. */
    suspend fun invite(
        callId: String,
        conversationId: String,
        calleeUserId: String,
        mode: CallMode = CallMode.AUDIO,
        idempotencyKey: String? = null,
        paid: Boolean = false,
        rateCentsPerMin: Int? = null,
    ): ApiResult<CallInvited>

    /** POST .../{callId}/accept. */
    suspend fun accept(callId: String, idempotencyKey: String? = null): ApiResult<CallAction>

    /** POST .../{callId}/decline (reason default "declined"; "busy" for the single-call invariant). */
    suspend fun decline(callId: String, reason: String = "declined"): ApiResult<CallAction>

    /** POST .../{callId}/end. */
    suspend fun end(
        callId: String,
        reason: String = "ended",
        idempotencyKey: String? = null,
    ): ApiResult<CallAction>

    /** POST .../{callId}/timeout (reason default "no_answer"). */
    suspend fun timeout(
        callId: String,
        reason: String = "no_answer",
        idempotencyKey: String? = null,
    ): ApiResult<CallAction>

    /** PATCH .../{callId}/heartbeat (billing keepalive). */
    suspend fun heartbeat(callId: String, clientTsEpochSeconds: Long? = null): ApiResult<CallHeartbeat>

    /** GET .../{callId}/billing. */
    suspend fun billing(callId: String): ApiResult<CallBillingStatus>

    /** GET /ui/calls/history (paged). */
    suspend fun history(cursor: String? = null, limit: Int? = null): ApiResult<CallHistoryPage>
}

@Singleton
class CallRepositoryImpl @Inject constructor(
    private val api: CallApi,
    private val errorParser: ApiErrorParser,
) : CallRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun invite(
        callId: String,
        conversationId: String,
        calleeUserId: String,
        mode: CallMode,
        idempotencyKey: String?,
        paid: Boolean,
        rateCentsPerMin: Int?,
    ): ApiResult<CallInvited> = withContext(io) {
        call {
            api.invite(
                CallInviteInDto(
                    callId = callId,
                    conversationId = conversationId,
                    calleeUserId = calleeUserId,
                    initialMode = mode.wire,
                    idempotencyKey = idempotencyKey,
                    paid = paid,
                    rateCentsPerMin = rateCentsPerMin,
                ),
            )
        }.map { it.toDomain() }
    }

    override suspend fun accept(callId: String, idempotencyKey: String?): ApiResult<CallAction> =
        withContext(io) {
            call { api.accept(callId, CallAcceptInDto(idempotencyKey = idempotencyKey)) }.map { it.toDomain() }
        }

    override suspend fun decline(callId: String, reason: String): ApiResult<CallAction> =
        withContext(io) {
            call { api.decline(callId, CallDeclineInDto(reason = reason)) }.map { it.toDomain() }
        }

    override suspend fun end(
        callId: String,
        reason: String,
        idempotencyKey: String?,
    ): ApiResult<CallAction> = withContext(io) {
        call {
            api.end(callId, CallEndInDto(reason = reason, idempotencyKey = idempotencyKey))
        }.map { it.toDomain() }
    }

    override suspend fun timeout(
        callId: String,
        reason: String,
        idempotencyKey: String?,
    ): ApiResult<CallAction> = withContext(io) {
        call {
            api.timeout(callId, CallTimeoutInDto(reason = reason, idempotencyKey = idempotencyKey))
        }.map { it.toDomain() }
    }

    override suspend fun heartbeat(callId: String, clientTsEpochSeconds: Long?): ApiResult<CallHeartbeat> =
        withContext(io) {
            call {
                api.heartbeat(callId, HeartbeatInDto(clientTsEpochSeconds = clientTsEpochSeconds))
            }.map { it.toDomain() }
        }

    override suspend fun billing(callId: String): ApiResult<CallBillingStatus> = withContext(io) {
        call { api.billing(callId) }.map { it.toDomain() }
    }

    override suspend fun history(cursor: String?, limit: Int?): ApiResult<CallHistoryPage> =
        withContext(io) {
            call { api.history(cursor = cursor, limit = limit) }.map { it.toDomain() }
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
