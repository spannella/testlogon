package com.testlogon.android.feature.guest

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-312 — Retrofit interface for the broadcast GUEST invite / management surface (host-side invite,
 * accept, revoke, promote, mute, remove of co-broadcast guests).
 *
 * Kept SEPARATE from [com.testlogon.android.data.broadcast.BroadcastApi] / InputsApi / HostControlApi so the
 * shared broadcast repository fakes are NOT touched. Provided on the SHARED Retrofit by
 * BroadcastApiModule (no new OkHttp / Retrofit). Paths are relative (no leading slash) so they resolve
 * against the shared base URL; cookies / Authorization: Bearer / X-CSRF-Token are attached project-wide by
 * the core-network interceptor chain - this interface stays header-agnostic.
 *
 * Base path: broadcast/sessions/{sessionId}/...
 *
 * KEY WIRE FACTS (verified; do not drift):
 *  - GET guest-invites returns a LIST envelope { session_id, count, invites:[GuestInviteOut] }.
 *  - POST guest-invites returns 201 GuestInviteOut (the freshly created invite, with invite_url etc.).
 *  - accept returns 200 BroadcastGuestAcceptOut; revoke / promote / mute / remove return 200 { ok } (or an
 *    empty 200), so those use [Response] of [OkDto] to tolerate an empty body.
 *  - ALL mutating calls are POST (not DELETE). Identity is (session_id, invite_id) - there is NO token.
 *  - stream_key on GuestInviteOut is a SECRET and is NEVER logged.
 */
interface GuestApi {

    /** List all guest invites for [sessionId] (LIST envelope with count + invites). */
    @GET("broadcast/sessions/{sessionId}/guest-invites")
    suspend fun listInvites(@Path("sessionId") sessionId: String): GuestInviteListDto

    /** Create a guest invite (201 GuestInviteOut). [body] carries join_mode / label / expiry_minutes. */
    @POST("broadcast/sessions/{sessionId}/guest-invites")
    suspend fun createInvite(
        @Path("sessionId") sessionId: String,
        @Body body: CreateInviteRequest,
    ): GuestInviteDto

    /** Accept invite [inviteId] with a required display_name (200 BroadcastGuestAcceptOut). */
    @POST("broadcast/sessions/{sessionId}/guest-invites/{inviteId}/accept")
    suspend fun acceptInvite(
        @Path("sessionId") sessionId: String,
        @Path("inviteId") inviteId: String,
        @Body body: AcceptInviteRequest,
    ): GuestAcceptDto

    /**
     * Revoke invite [inviteId] (no body; 200 { ok } or empty). Uses [Response] of [Unit] so an EMPTY 200
     * body is success — Retrofit consumes the body without JSON parsing (an { ok } body is also tolerated).
     */
    @POST("broadcast/sessions/{sessionId}/guest-invites/{inviteId}/revoke")
    suspend fun revokeInvite(
        @Path("sessionId") sessionId: String,
        @Path("inviteId") inviteId: String,
    ): Response<Unit>

    /** Promote guest input [inputId] to the live program (no body; 200 { ok } or empty -> [Response] of [Unit]). */
    @POST("broadcast/sessions/{sessionId}/guests/{inputId}/promote")
    suspend fun promote(
        @Path("sessionId") sessionId: String,
        @Path("inputId") inputId: String,
    ): Response<Unit>

    /** Mute / unmute guest input [inputId] (body { muted }; 200 { ok } or empty -> [Response] of [Unit]). */
    @POST("broadcast/sessions/{sessionId}/guests/{inputId}/mute")
    suspend fun setMuted(
        @Path("sessionId") sessionId: String,
        @Path("inputId") inputId: String,
        @Body body: MuteRequest,
    ): Response<Unit>

    /** Remove guest input [inputId] from the broadcast (no body; 200 { ok } or empty -> [Response] of [Unit]). */
    @POST("broadcast/sessions/{sessionId}/guests/{inputId}/remove")
    suspend fun remove(
        @Path("sessionId") sessionId: String,
        @Path("inputId") inputId: String,
    ): Response<Unit>
}

// --- wire DTOs (exact snake_case via @Json; absent optionals fall back to Kotlin defaults) -----------

/** AND-312 - BroadcastGuestInviteListOut: the guest-invites LIST envelope. */
@JsonClass(generateAdapter = true)
data class GuestInviteListDto(
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "count") val count: Int = 0,
    @Json(name = "invites") val invites: List<GuestInviteDto> = emptyList(),
)

/**
 * AND-312 - GuestInviteOut: a single guest invite row.
 *
 * `status` is "pending" | "accepted" | "expired" | "revoked" (unknown -> a safe default, never throws).
 * `join_mode` is "rtmp" | "browser". `expires_at` / `accepted_at` are epoch SECONDS integers; `created_at`
 * is an ISO string. `stream_key` is a SECRET and is never logged. There is NO `token` field - identity is
 * (session_id, invite_id).
 */
@JsonClass(generateAdapter = true)
data class GuestInviteDto(
    @Json(name = "invite_id") val inviteId: String,
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "input_id") val inputId: String? = null,
    @Json(name = "join_mode") val joinMode: String = GuestJoinMode.BROWSER,
    @Json(name = "status") val status: String = "pending",
    @Json(name = "expires_at") val expiresAt: Long? = null,
    @Json(name = "created_at") val createdAt: String? = null,
    @Json(name = "accepted_at") val acceptedAt: Long? = null,
    @Json(name = "invite_url") val inviteUrl: String? = null,
    @Json(name = "ingest_url") val ingestUrl: String? = null,
    @Json(name = "stream_key") val streamKey: String? = null,
    @Json(name = "guest_user_id") val guestUserId: String? = null,
    @Json(name = "guest_display_name") val guestDisplayName: String? = null,
)

/** AND-312 - BroadcastGuestAcceptOut: the result of accepting an invite. */
@JsonClass(generateAdapter = true)
data class GuestAcceptDto(
    @Json(name = "invite_id") val inviteId: String = "",
    @Json(name = "input_id") val inputId: String = "",
    @Json(name = "join_mode") val joinMode: String = GuestJoinMode.BROWSER,
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "ingest_url") val ingestUrl: String? = null,
)

/**
 * AND-312 - BroadcastGuestInviteCreateIn. Defaults match the verified wire defaults (join_mode "browser",
 * label "Guest", expiry_minutes 60, valid 5..1440). Nulls are omitted by Moshi.
 */
@JsonClass(generateAdapter = true)
data class CreateInviteRequest(
    @Json(name = "join_mode") val joinMode: String = GuestJoinMode.BROWSER,
    @Json(name = "label") val label: String = "Guest",
    @Json(name = "expiry_minutes") val expiryMinutes: Int = 60,
)

/** AND-312 - BroadcastGuestAcceptIn. `display_name` is REQUIRED (1..100). */
@JsonClass(generateAdapter = true)
data class AcceptInviteRequest(
    @Json(name = "display_name") val displayName: String,
)

/** AND-312 - BroadcastGuestMuteIn. `muted` defaults to true. */
@JsonClass(generateAdapter = true)
data class MuteRequest(
    @Json(name = "muted") val muted: Boolean = true,
)

/** AND-312 - verified guest join modes. `joinMode` stays a String on the domain; these are wire values. */
object GuestJoinMode {
    const val RTMP = "rtmp"
    const val BROWSER = "browser"
}
