package com.testlogon.android.feature.broadcast.audioroom

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.analytics.PlaybackAnalyticsApi
import com.testlogon.android.data.analytics.ViewerJoinDto
import com.testlogon.android.data.broadcast.BroadcastApi
import com.testlogon.android.data.broadcast.BroadcastSessionCreateInDto
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/** #104 — a decoded stage.* realtime signal (delivered over messaging/events/poll to the caller). */
sealed interface StageEvent {
    /** This user was promoted to speaker (for SELF: re-fetch token + enable mic). */
    data class Promote(val userId: String) : StageEvent
    /** This user was demoted to listener (for SELF: stop publishing). */
    data class Demote(val userId: String) : StageEvent
    /** A speaker was force-muted by the host (reflect in the UI). */
    data class Mute(val userId: String) : StageEvent
    /** A speaker was unmuted by the host. */
    data class Unmute(val userId: String) : StageEvent
    /** A listener raised/lowered a hand (host refreshes the hand list). */
    data class Hand(val userId: String, val raised: Boolean) : StageEvent
}

/**
 * #104 AUDIO ROOM — repository over the backend #102 stage control plane + viewer presence + create/start.
 * All one-shot calls fold into [ApiResult] exactly like the other broadcast repos; the stage.* realtime
 * feed is a cold [Flow] polled off GET messaging/events/poll (the same reliable poll the call/webrtc
 * signaling uses). LiveKit transport itself is owned by [LiveKitRoomController] — this repo only touches
 * the REST stage store (the server-authoritative source of truth for roles + force-mute).
 */
@Singleton
class AudioRoomRepository @Inject constructor(
    private val stageApi: AudioRoomStageApi,
    private val broadcastApi: BroadcastApi,
    private val analyticsApi: PlaybackAnalyticsApi,
    private val errorParser: ApiErrorParser,
) {

    /** Create a mode=audio_room session and best-effort flip it live for discovery; returns the session id. */
    suspend fun createAudioRoom(profileId: String, maxSlots: Int = 20): ApiResult<String> = call {
        val session = broadcastApi.createSession(
            BroadcastSessionCreateInDto(profileId = profileId, mode = "audio_room", stageMaxSlots = maxSlots),
        )
        // Best-effort go-live so the room shows up in GET broadcast/live?mode=audio_room. A failure here
        // (provider quirk / already-live) must NOT fail room creation — the host can still host + others
        // who have the id can still join via LiveKit regardless of session status.
        runCatching { stageApi.startSession(session.id, StageActionBodyDto(reason = "audio_room_go_live")) }
        session.id
    }

    suspend fun token(sessionId: String): ApiResult<LivekitTokenDto> =
        call { stageApi.livekitToken(sessionId) }

    suspend fun roster(sessionId: String): ApiResult<StageRosterDto> =
        call { stageApi.stageRoster(sessionId) }

    suspend fun raiseHand(sessionId: String): ApiResult<Unit> =
        call { stageApi.raiseHand(sessionId); Unit }

    suspend fun promote(sessionId: String, userId: String): ApiResult<StageRosterDto?> =
        call { stageApi.promote(sessionId, StageUserInDto(userId)).roster }

    suspend fun demote(sessionId: String, userId: String): ApiResult<StageRosterDto?> =
        call { stageApi.demote(sessionId, StageUserInDto(userId)).roster }

    suspend fun mute(sessionId: String, userId: String): ApiResult<Unit> =
        call { stageApi.mute(sessionId, StageUserInDto(userId)); Unit }

    suspend fun unmute(sessionId: String, userId: String): ApiResult<Unit> =
        call { stageApi.unmute(sessionId, StageUserInDto(userId)); Unit }

    suspend fun leaveStage(sessionId: String): ApiResult<Unit> =
        call { stageApi.leaveStage(sessionId); Unit }

    // ---- Listener presence (reused viewers/{join,heartbeat,leave}); returns the server viewer_count. ----

    suspend fun viewerJoin(sessionId: String): ApiResult<ViewerJoinDto?> =
        call { analyticsApi.viewerJoin(sessionId).body() }

    suspend fun viewerHeartbeat(sessionId: String, viewerId: String): ApiResult<Int?> =
        call { analyticsApi.viewerHeartbeat(sessionId, viewerId).body()?.viewerCount }

    suspend fun viewerLeave(sessionId: String, viewerId: String): ApiResult<Unit> =
        call { analyticsApi.viewerLeave(sessionId, viewerId); Unit }

    /**
     * Cold flow of stage.* events addressed to the caller, polled from messaging/events/poll every
     * [intervalMs]. Filters to this session's `broadcast:<id>` conversation + dedups by event_id so a
     * repeated poll window never double-applies. Collecting starts the poll; cancelling stops it.
     */
    fun stageEvents(sessionId: String, intervalMs: Long = 1500L): Flow<StageEvent> = flow {
        val convId = "broadcast:$sessionId"
        val seen = LinkedHashSet<String>()
        while (true) {
            val events = try {
                stageApi.pollEvents(limit = 100).events
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                emptyList()
            }
            // Oldest-first so ordering of promote/demote is preserved when several arrive in one window.
            for (ev in events.asReversed()) {
                val type = ev.type ?: continue
                if (!type.startsWith("stage.")) continue
                val p = ev.payload
                if (ev.conversationId != null && ev.conversationId != convId) continue
                if (p?.sessionId != null && p.sessionId != sessionId) continue
                val id = ev.eventId ?: (type + ":" + (p?.userId ?: "") + ":" + (p?.handRaised ?: p?.micMuted ?: ""))
                if (!seen.add(id)) continue
                if (seen.size > 512) repeat(128) { seen.remove(seen.first()) }
                val uid = p?.userId ?: continue
                val decoded = when (type) {
                    "stage.promote" -> StageEvent.Promote(uid)
                    "stage.demote" -> StageEvent.Demote(uid)
                    "stage.mute" -> StageEvent.Mute(uid)
                    "stage.unmute" -> StageEvent.Unmute(uid)
                    "stage.hand" -> StageEvent.Hand(uid, p.handRaised ?: true)
                    else -> null
                }
                if (decoded != null) emit(decoded)
            }
            delay(intervalMs)
        }
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    } catch (e: Exception) {
        ApiResult.Failure(ApiError(status = ApiError.STATUS_PARSE, message = e.message ?: "audio_room_error"))
    }
}
