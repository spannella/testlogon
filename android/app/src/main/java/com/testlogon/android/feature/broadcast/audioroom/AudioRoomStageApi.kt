package com.testlogon.android.feature.broadcast.audioroom

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query
import javax.inject.Singleton

/**
 * #104 AUDIO ROOM (LiveKit) — Retrofit interface for the backend #102 broadcast STAGE control plane
 * (mode="audio_room"). The stage store is the source of truth for the roster; LiveKit RoomService (server
 * side) enforces the roles. Paths are relative so they resolve against the shared Retrofit base URL; the
 * cookie / X-CSRF-Token auth is attached by the core-network interceptor chain (same as every other
 * authenticated read/write), so this interface stays header-agnostic.
 *
 * Verified live against prod openapi + the prod broadcast.py source:
 *  - GET  sessions/{id}/livekit-token  -> { token, url, room, identity, role, can_publish } (ALREADY
 *    returns url+room — no backend tweak was needed for the app to avoid hardcoding the ws host).
 *  - GET  sessions/{id}/stage          -> { speakers[], hands[], speaker_count, listener_count, stage_max_slots }
 *  - POST sessions/{id}/stage/request  (listener raises a hand; no body)
 *  - POST sessions/{id}/stage/promote|demote|mute|unmute  (host-gated, StageUserIn { user_id } body)
 *  - POST sessions/{id}/stage/leave    (self step-down; no body)
 *  Stage.* events fan to the target user's GET messaging/events/poll queue (conversation_id="broadcast:<id>").
 */
interface AudioRoomStageApi {

    @GET("broadcast/sessions/{sessionId}/livekit-token")
    suspend fun livekitToken(@Path("sessionId") sessionId: String): LivekitTokenDto

    @GET("broadcast/sessions/{sessionId}/stage")
    suspend fun stageRoster(@Path("sessionId") sessionId: String): StageRosterDto

    @POST("broadcast/sessions/{sessionId}/stage/request")
    suspend fun raiseHand(@Path("sessionId") sessionId: String): StageOkDto

    @POST("broadcast/sessions/{sessionId}/stage/promote")
    suspend fun promote(
        @Path("sessionId") sessionId: String,
        @Body body: StageUserInDto,
    ): StageOpResultDto

    @POST("broadcast/sessions/{sessionId}/stage/demote")
    suspend fun demote(
        @Path("sessionId") sessionId: String,
        @Body body: StageUserInDto,
    ): StageOpResultDto

    @POST("broadcast/sessions/{sessionId}/stage/mute")
    suspend fun mute(
        @Path("sessionId") sessionId: String,
        @Body body: StageUserInDto,
    ): StageOkDto

    @POST("broadcast/sessions/{sessionId}/stage/unmute")
    suspend fun unmute(
        @Path("sessionId") sessionId: String,
        @Body body: StageUserInDto,
    ): StageOkDto

    @POST("broadcast/sessions/{sessionId}/stage/leave")
    suspend fun leaveStage(@Path("sessionId") sessionId: String): StageOkDto

    /**
     * Best-effort flip an audio_room session to status="live" so it appears in the public
     * GET broadcast/live discovery feed (owner-gated). The LiveKit room itself works regardless of
     * session status (the token route only requires mode=audio_room), so a start failure never blocks
     * the host — it only affects discoverability.
     */
    @POST("broadcast/sessions/{sessionId}/start")
    suspend fun startSession(
        @Path("sessionId") sessionId: String,
        @Body body: StageActionBodyDto,
    ): StageOkDto

    /** Reliable JSON poll of the per-user event queue; we filter for the stage.* events (see repository). */
    @GET("messaging/events/poll")
    suspend fun pollEvents(@Query("limit") limit: Int = 100): StagePollResponseDto
}

/** GET livekit-token — the server already returns url + room so the app never hardcodes the ws host. */
@JsonClass(generateAdapter = true)
data class LivekitTokenDto(
    @Json(name = "token") val token: String = "",
    @Json(name = "url") val url: String = "",
    @Json(name = "room") val room: String = "",
    @Json(name = "identity") val identity: String = "",
    @Json(name = "role") val role: String = "listener",
    @Json(name = "can_publish") val canPublish: Boolean = false,
)

/** One roster member (host / speaker / listener-with-raised-hand). joined_at is ignored (Moshi skips it). */
@JsonClass(generateAdapter = true)
data class StageMemberDto(
    @Json(name = "user_id") val userId: String = "",
    @Json(name = "role") val role: String = "listener",
    @Json(name = "mic_muted") val micMuted: Boolean = false,
    @Json(name = "hand_raised") val handRaised: Boolean = false,
)

/** GET stage roster — the audio-room stage snapshot. */
@JsonClass(generateAdapter = true)
data class StageRosterDto(
    @Json(name = "speakers") val speakers: List<StageMemberDto> = emptyList(),
    @Json(name = "hands") val hands: List<StageMemberDto> = emptyList(),
    @Json(name = "speaker_count") val speakerCount: Int = 0,
    @Json(name = "listener_count") val listenerCount: Int = 0,
    @Json(name = "stage_max_slots") val stageMaxSlots: Int = 20,
)

/** StageUserIn — the { user_id } body for host-gated promote/demote/mute/unmute. */
@JsonClass(generateAdapter = true)
data class StageUserInDto(
    @Json(name = "user_id") val userId: String,
)

/** BroadcastSessionActionIn — { reason } body for start. */
@JsonClass(generateAdapter = true)
data class StageActionBodyDto(
    @Json(name = "reason") val reason: String? = null,
)

/** Generic { ok, ... } response (roster/livekit fields are ignored — we re-fetch the roster). */
@JsonClass(generateAdapter = true)
data class StageOkDto(
    @Json(name = "ok") val ok: Boolean = true,
)

/** promote/demote return { ok, record, livekit, roster } — we consume the embedded roster directly. */
@JsonClass(generateAdapter = true)
data class StageOpResultDto(
    @Json(name = "ok") val ok: Boolean = true,
    @Json(name = "roster") val roster: StageRosterDto? = null,
)

/** One event from GET messaging/events/poll (only the stage.* subset is meaningful here). */
@JsonClass(generateAdapter = true)
data class StagePollEventDto(
    @Json(name = "event_id") val eventId: String? = null,
    @Json(name = "type") val type: String? = null,
    @Json(name = "conversation_id") val conversationId: String? = null,
    @Json(name = "payload") val payload: StageEventPayloadDto? = null,
)

/** stage.* payload: { session_id, user_id, role?|mic_muted?|hand_raised? }. */
@JsonClass(generateAdapter = true)
data class StageEventPayloadDto(
    @Json(name = "session_id") val sessionId: String? = null,
    @Json(name = "user_id") val userId: String? = null,
    @Json(name = "role") val role: String? = null,
    @Json(name = "mic_muted") val micMuted: Boolean? = null,
    @Json(name = "hand_raised") val handRaised: Boolean? = null,
)

@JsonClass(generateAdapter = true)
data class StagePollResponseDto(
    @Json(name = "events") val events: List<StagePollEventDto> = emptyList(),
)

@Module
@InstallIn(SingletonComponent::class)
object AudioRoomStageApiModule {
    @Provides
    @Singleton
    fun provideAudioRoomStageApi(retrofit: Retrofit): AudioRoomStageApi =
        retrofit.create(AudioRoomStageApi::class.java)
}
