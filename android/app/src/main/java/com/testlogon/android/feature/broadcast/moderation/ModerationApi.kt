package com.testlogon.android.feature.broadcast.moderation

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-313 - Retrofit interface for broadcast chat MODERATION (mute / ban / unban / delete / pin / unpin
 * plus the moderation log) for a live broadcast. Built on the AND-281 live chat.
 *
 * Kept SEPARATE from BroadcastChatApi / BroadcastApi / HostControlApi / GuestApi so the shared broadcast
 * repository fakes are NOT touched. Provided on the SHARED Retrofit by BroadcastApiModule (no new OkHttp /
 * Retrofit, no new dependency). Paths are relative (no leading slash) so they resolve against the shared
 * base URL; cookies / Authorization: Bearer / X-CSRF-Token are attached project-wide by the core-network
 * interceptor chain - this interface stays header-agnostic.
 *
 * TWO endpoint families (VERIFIED; do not drift):
 *  - HOST-scoped: mute + delete ONLY, under broadcast/sessions/{id}/chat/...
 *  - DELEGATE-scoped: mute / ban / unban / list-bans / delete / pin / unpin / moderation-log, under
 *    ui/broadcast/delegate/{creatorId}/sessions/{sessionId}/... (NOTE: delegate/, NOT creators/).
 * BAN / UNBAN / PIN / UNPIN / LOG exist ONLY under the delegate prefix, so they ALWAYS require a creatorId.
 *
 * EMPTY / { ok } 200 responses use Response of Unit so an EMPTY 200 body is success - Retrofit consumes the
 * body without JSON parsing (an { ok } body is also tolerated). Moshi would throw EOF on an empty body if a
 * concrete DTO were used (this bit us on AND-312). The moderation-log + list-bans return PLAIN ARRAYS (no
 * envelope), decoded directly to a List.
 */
interface ModerationApi {

    // ---- HOST-scoped (mute + delete only) ----

    /**
     * Host mute: POST broadcast/sessions/{id}/chat/mute, body { target_user_id, duration_seconds }.
     * 200 -> { target_user_id, muted_until, session_id }. There is NO reason field for a mute.
     */
    @POST("broadcast/sessions/{id}/chat/mute")
    suspend fun muteHost(
        @Path("id") sessionId: String,
        @Body body: ChatMuteRequestDto,
    ): Response<MuteResultDto>

    /** Host delete: DELETE broadcast/sessions/{id}/chat/{messageId}, NO body -> 200 { ok, message_id }. */
    @DELETE("broadcast/sessions/{id}/chat/{messageId}")
    suspend fun deleteMessageHost(
        @Path("id") sessionId: String,
        @Path("messageId") messageId: String,
    ): Response<Unit>

    // ---- DELEGATE-scoped (ui/broadcast/delegate/{creatorId}/sessions/{sessionId}/...) ----

    /** Delegate mute: POST .../mute, body { user_id, duration_seconds } -> 200. */
    @POST("ui/broadcast/delegate/{cid}/sessions/{id}/mute")
    suspend fun mute(
        @Path("cid") creatorId: String,
        @Path("id") sessionId: String,
        @Body body: MuteRequestDto,
    ): Response<MuteResultDto>

    /** Delegate ban: POST .../ban, body { user_id, reason (optional, default "", maxLength 500) } -> 200. */
    @POST("ui/broadcast/delegate/{cid}/sessions/{id}/ban")
    suspend fun ban(
        @Path("cid") creatorId: String,
        @Path("id") sessionId: String,
        @Body body: BanRequestDto,
    ): Response<Unit>

    /** Delegate unban: DELETE .../ban/{userId} -> 200. */
    @DELETE("ui/broadcast/delegate/{cid}/sessions/{id}/ban/{userId}")
    suspend fun unban(
        @Path("cid") creatorId: String,
        @Path("id") sessionId: String,
        @Path("userId") userId: String,
    ): Response<Unit>

    /** Delegate list-bans: GET .../bans -> PLAIN ARRAY [BanOut]. */
    @GET("ui/broadcast/delegate/{cid}/sessions/{id}/bans")
    suspend fun listBans(
        @Path("cid") creatorId: String,
        @Path("id") sessionId: String,
    ): List<BanDto>

    /** Delegate delete: DELETE .../chat/{messageId}, NO body -> 200. */
    @DELETE("ui/broadcast/delegate/{cid}/sessions/{id}/chat/{messageId}")
    suspend fun deleteMessage(
        @Path("cid") creatorId: String,
        @Path("id") sessionId: String,
        @Path("messageId") messageId: String,
    ): Response<Unit>

    /** Delegate pin: POST .../chat/{messageId}/pin, NO body -> 200 { ok, message_id, pinned }. */
    @POST("ui/broadcast/delegate/{cid}/sessions/{id}/chat/{messageId}/pin")
    suspend fun pin(
        @Path("cid") creatorId: String,
        @Path("id") sessionId: String,
        @Path("messageId") messageId: String,
    ): Response<PinResultDto>

    /** Delegate unpin: DELETE .../chat/{messageId}/pin -> 200. */
    @DELETE("ui/broadcast/delegate/{cid}/sessions/{id}/chat/{messageId}/pin")
    suspend fun unpin(
        @Path("cid") creatorId: String,
        @Path("id") sessionId: String,
        @Path("messageId") messageId: String,
    ): Response<Unit>

    /**
     * Delegate moderation log: GET .../moderation-log?limit=100 -> PLAIN ARRAY [BroadcastModerationLogEntry].
     * There is NO cursor / paging. This GET is idempotent (a bounded retry is acceptable).
     */
    @GET("ui/broadcast/delegate/{cid}/sessions/{id}/moderation-log")
    suspend fun log(
        @Path("cid") creatorId: String,
        @Path("id") sessionId: String,
        @Query("limit") limit: Int = 100,
    ): List<ModerationLogEntryDto>
}

// --- wire DTOs (exact snake_case via @Json; absent optionals fall back to Kotlin defaults) ------------

/** AND-313 - host mute request body: { target_user_id, duration_seconds }. NO reason field. */
@JsonClass(generateAdapter = true)
data class ChatMuteRequestDto(
    @Json(name = "target_user_id") val targetUserId: String,
    @Json(name = "duration_seconds") val durationSeconds: Long,
)

/** AND-313 - delegate mute request body: { user_id, duration_seconds }. NO reason field. */
@JsonClass(generateAdapter = true)
data class MuteRequestDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "duration_seconds") val durationSeconds: Long,
)

/** AND-313 - delegate ban request body: { user_id, reason (optional, default "", maxLength 500) }. */
@JsonClass(generateAdapter = true)
data class BanRequestDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "reason") val reason: String = "",
)

/** AND-313 - mute 200 result: { target_user_id, muted_until (epoch seconds), session_id }. */
@JsonClass(generateAdapter = true)
data class MuteResultDto(
    @Json(name = "target_user_id") val targetUserId: String = "",
    @Json(name = "muted_until") val mutedUntil: Long = 0L,
    @Json(name = "session_id") val sessionId: String = "",
)

/** AND-313 - pin 200 result: { ok, message_id, pinned }. */
@JsonClass(generateAdapter = true)
data class PinResultDto(
    @Json(name = "ok") val ok: Boolean = true,
    @Json(name = "message_id") val messageId: String = "",
    @Json(name = "pinned") val pinned: Boolean = true,
)

/** AND-313 - BanOut row (from the list-bans plain array). `ts` is epoch SECONDS. */
@JsonClass(generateAdapter = true)
data class BanDto(
    @Json(name = "user_id") val userId: String = "",
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "reason") val reason: String? = null,
    @Json(name = "moderator_id") val moderatorId: String? = null,
    @Json(name = "ts") val ts: Long = 0L,
)

/**
 * AND-313 - BroadcastModerationLogEntry row (from the moderation-log plain array).
 *
 * `moderation_type` is one of "mute" | "ban" | "unban" | "delete" | "pin" | "unpin" (an UNKNOWN value maps
 * to a safe default in the mapper, never throws). `target_user_id` / `target_message_id` are optional.
 * `details` is a free-form object (kept loosely-typed). `ts` is epoch SECONDS.
 */
@JsonClass(generateAdapter = true)
data class ModerationLogEntryDto(
    @Json(name = "event_id") val eventId: String = "",
    @Json(name = "moderator_id") val moderatorId: String = "",
    @Json(name = "moderator_display_name") val moderatorDisplayName: String? = null,
    @Json(name = "moderation_type") val moderationType: String = "",
    @Json(name = "target_user_id") val targetUserId: String? = null,
    @Json(name = "target_message_id") val targetMessageId: String? = null,
    @Json(name = "details") val details: Map<String, Any?>? = null,
    @Json(name = "ts") val ts: Long = 0L,
)
