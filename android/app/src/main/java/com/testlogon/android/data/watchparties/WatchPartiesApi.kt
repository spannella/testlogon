package com.testlogon.android.data.watchparties

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * Retrofit interface + Moshi DTOs for the watch-parties feature (web ENGAGE-004).
 *
 * Endpoints + shapes verified against frontend/src/api/endpoints/watchParties.ts and the
 * WatchParty / WatchPartyParticipant / CreatePartyReq / InviteResolveResp interfaces in
 * frontend/src/api/types.ts (the OpenAPI bodies are untyped, so the frontend TS types are
 * authoritative). v1 covers: list (GET ui/watch-parties/), create (POST ui/watch-parties/),
 * detail (GET ui/watch-parties/{id}), participants (GET ui/watch-parties/{id}/participants),
 * join / leave (POST .../join, .../leave) and invite-resolve (GET ui/watch-parties/join/{code}).
 * Realtime playback control (.../control, heartbeat, playback-url) is intentionally NOT surfaced
 * here - live sync is out of scope for v1. Session cookies / Bearer / X-CSRF are interceptor-added.
 */
interface WatchPartiesApi {

    /** The caller's / discoverable watch parties. */
    @GET("ui/watch-parties/")
    suspend fun listParties(): List<WatchPartyDto>

    /** Creates a watch party around a video. */
    @POST("ui/watch-parties/")
    suspend fun createParty(@Body body: CreatePartyReqDto): WatchPartyDto

    /** A single party's current (static) state. */
    @GET("ui/watch-parties/{partyId}")
    suspend fun getParty(@Path("partyId") partyId: String): WatchPartyDto

    /** Active + historical participants for a party. */
    @GET("ui/watch-parties/{partyId}/participants")
    suspend fun listParticipants(@Path("partyId") partyId: String): List<WatchPartyParticipantDto>

    /** Joins the party; returns the caller's participant row. */
    @POST("ui/watch-parties/{partyId}/join")
    suspend fun joinParty(@Path("partyId") partyId: String): WatchPartyParticipantDto

    /** Leaves the party. */
    @POST("ui/watch-parties/{partyId}/leave")
    suspend fun leaveParty(@Path("partyId") partyId: String)

    /** Resolves an invite code to a lightweight party summary (web /party/{code}). */
    @GET("ui/watch-parties/join/{inviteCode}")
    suspend fun resolveInvite(@Path("inviteCode") inviteCode: String): InviteResolveRespDto
}

// ---- DTOs ----

@JsonClass(generateAdapter = true)
data class WatchPartyDto(
    @Json(name = "party_id") val partyId: String,
    @Json(name = "host_user_sub") val hostUserSub: String = "",
    @Json(name = "video_id") val videoId: String = "",
    @Json(name = "video_title") val videoTitle: String = "",
    @Json(name = "video_duration_seconds") val videoDurationSeconds: Long = 0,
    val title: String = "",
    @Json(name = "invite_code") val inviteCode: String = "",
    val status: String = "",
    @Json(name = "max_participants") val maxParticipants: Int = 0,
    @Json(name = "participant_count") val participantCount: Int = 0,
    val position: Double = 0.0,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
    @Json(name = "ended_at") val endedAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class WatchPartyParticipantDto(
    @Json(name = "party_id") val partyId: String = "",
    @Json(name = "user_sub") val userSub: String,
    val role: String = "",
    val status: String = "",
    @Json(name = "joined_at") val joinedAt: Long = 0,
    @Json(name = "last_seen") val lastSeen: Long? = null,
)

@JsonClass(generateAdapter = true)
data class CreatePartyReqDto(
    @Json(name = "video_id") val videoId: String,
    val title: String? = null,
    @Json(name = "max_participants") val maxParticipants: Int? = null,
)

@JsonClass(generateAdapter = true)
data class InviteResolveRespDto(
    @Json(name = "party_id") val partyId: String,
    val title: String = "",
    @Json(name = "host_user_sub") val hostUserSub: String = "",
    @Json(name = "video_title") val videoTitle: String = "",
    val status: String = "",
    @Json(name = "participant_count") val participantCount: Int = 0,
    @Json(name = "max_participants") val maxParticipants: Int = 0,
)
