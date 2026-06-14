package com.testlogon.android.data.webrtc

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
 * AND-290 — data layer over [SignalingApi] for the REAL signaling send paths.
 *
 * These are plain authenticated network reads/writes that have real backend endpoints, so they are fully
 * implemented + testable (independent of the FLAGGED native-WebRTC engine). The host go-live publish SDP
 * exchange ([exchangeBroadcastOffer]) is the path the broadcast publisher would drive once a real
 * PeerConnection produced an SDP offer; until the SDK is wired, [BroadcastPublisher] never produces one,
 * so this repo is exercised by tests/fakes only.
 *
 * Wraps each call in [ApiResult] (Failure for HTTP errors via [ApiErrorParser], NetworkError for
 * transport failures, Failure(parse) for malformed JSON), mapping wire DTOs to the redaction-safe domain.
 * Never throws (CancellationException is re-thrown). The JsonEncodingException catch precedes IOException
 * (it is an IOException subtype).
 */
interface SignalingRepository {

    /**
     * HOST publish SDP exchange: POST the local [sdpOffer] for [inputId] of [sessionId], returning the
     * SFU's SDP answer mapped to [PublishAnswer].
     */
    suspend fun exchangeBroadcastOffer(
        sessionId: String,
        inputId: String,
        sdpOffer: String,
    ): ApiResult<PublishAnswer>

    /** 1:1 / group call signaling send (offer / answer / ICE). Returns the [SignalingAck]. */
    suspend fun sendCallSignal(
        callId: String,
        conversationId: String,
        recipientUserId: String,
        eventId: String,
        nonce: String,
        sentAtEpochSeconds: Long,
        message: SignalingMessage,
    ): ApiResult<SignalingAck>
}

@Singleton
class SignalingRepositoryImpl @Inject constructor(
    private val api: SignalingApi,
    private val errorParser: ApiErrorParser,
) : SignalingRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun exchangeBroadcastOffer(
        sessionId: String,
        inputId: String,
        sdpOffer: String,
    ): ApiResult<PublishAnswer> = withContext(io) {
        call {
            api.sendBroadcastOffer(sessionId, inputId, BroadcastWebRtcOfferRequestDto(sdpOffer = sdpOffer))
        }.map { it.toDomain() }
    }

    override suspend fun sendCallSignal(
        callId: String,
        conversationId: String,
        recipientUserId: String,
        eventId: String,
        nonce: String,
        sentAtEpochSeconds: Long,
        message: SignalingMessage,
    ): ApiResult<SignalingAck> = withContext(io) {
        val dto = CallSignalingInDto(
            type = message.callWireType(),
            eventId = eventId,
            conversationId = conversationId,
            recipientUserId = recipientUserId,
            nonce = nonce,
            sentAt = sentAtEpochSeconds,
            payload = message.callPayload(),
        )
        call { api.sendCallSignal(callId, dto) }.map { it.toDomain() }
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

// ─── DTO -> domain mappers ───────────────────────────────────────────────────────────────────────

internal fun BroadcastWebRtcAnswerDto.toDomain(): PublishAnswer = PublishAnswer(
    sessionId = sessionId,
    inputId = inputId,
    answer = SdpDescription(type = SdpType.ANSWER, sdp = sdpAnswer),
)

internal fun CallSignalingOutDto.toDomain(): SignalingAck = SignalingAck(
    eventId = eventId,
    callId = callId,
    deliveredTo = deliveredTo,
    status = status.toSignalingStatus(),
)
