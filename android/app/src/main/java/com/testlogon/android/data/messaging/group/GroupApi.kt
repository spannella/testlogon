package com.testlogon.android.data.messaging.group

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.data.messaging.ConversationDto
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-157 / AND-158 / AND-159 — Retrofit interface for group conversation create, participant
 * management, and per-member settings.
 *
 * Kept SEPARATE from [com.testlogon.android.data.messaging.MessagingApi] on purpose: the group
 * endpoints are a cohesive sub-surface, and a dedicated interface keeps the (large) MessagingApi +
 * its hand-written test FakeApi untouched. Paths are relative (no leading slash) so they resolve
 * against the shared Retrofit base URL; cookies, Authorization and `X-CSRF-Token` are attached by
 * the core-network interceptor chain. All methods are `suspend`; non-2xx surfaces as HttpException.
 *
 * Endpoints verified against reference/openapi.index.txt + reference/openapi.pretty.json:
 *  - createGroup       POST   messaging/conversations/group                                  (line 315, req=StartGroupConversationIn, 200:ConversationOut)
 *  - getConversation   GET    messaging/conversations/{id}                                   (line 317, 200:ConversationOut)
 *  - listParticipants  GET    messaging/conversations/{id}/participants                      (line 368, 200 untyped)
 *  - addParticipants   POST   messaging/conversations/{id}/participants                      (line 369, req=AddParticipantsIn)
 *  - removeParticipant DELETE messaging/conversations/{id}/participants/{participantId}      (line 370, 200 body ignored)
 *  - changeRole        PATCH  messaging/conversations/{id}/participants/{participantId}      (line 371, req=UpdateParticipantRoleIn)
 *  - mute              POST   messaging/conversations/{id}/mute                              (line 367, req=MuteIn, empty 200)
 *  - leave             POST   messaging/conversations/{id}/leave                             (line 328, empty 200)
 *  - accept            POST   messaging/conversations/{id}/accept                            (line 319, empty 200)
 */
interface GroupApi {

    /**
     * AND-157 — create a group conversation. Body = StartGroupConversationIn (only `participant_ids`
     * required, minItems 2). Returns ConversationOut (HTTP 200, NOT 201). The current user is implicit.
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/group")
    suspend fun createGroup(@Body body: CreateGroupRequest): ConversationDto

    /** AND-158/AND-159 — single conversation by id (used to refresh roster + settings). Idempotent GET. */
    @GET("messaging/conversations/{id}")
    suspend fun getConversation(@Path("id") id: String): ConversationDto

    /**
     * AND-158 — roster GET. The OpenAPI response is untyped (`schema: {}`) and the server returns a
     * BARE JSON ARRAY of ParticipantOut (verified on-device). Typing it as List<ParticipantDto> uses
     * Moshi's built-in collection adapter (the old RosterResponse object envelope crashed with
     * "Expected BEGIN_OBJECT but was BEGIN_ARRAY" — bug #14 P0). The repo still falls back to the
     * conversation GET when this list is empty.
     */
    @GET("messaging/conversations/{id}/participants")
    suspend fun listParticipants(@Path("id") id: String): List<com.testlogon.android.data.messaging.ParticipantDto>

    /**
     * AND-158 — add members. Body = AddParticipantsIn {participant_ids}. Response = {ok, added_count}
     * (does NOT echo rows — the repo follows with a roster refresh). Non-idempotent POST.
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/participants")
    suspend fun addParticipants(
        @Path("id") id: String,
        @Body body: AddParticipantsRequest,
    ): AddParticipantsResponse

    /**
     * AND-158 — change a member's role. Body = UpdateParticipantRoleIn {role: admin|member}.
     * Response = {ok, role}. State-changing PATCH (not auto-retried).
     */
    @Headers("Content-Type: application/json")
    @PATCH("messaging/conversations/{id}/participants/{participantId}")
    suspend fun changeRole(
        @Path("id") id: String,
        @Path("participantId") participantId: String,
        @Body body: ChangeRoleRequest,
    ): ChangeRoleResponse

    /** AND-158 — remove a member. HTTP 200 with a body that is intentionally ignored. Non-idempotent. */
    @DELETE("messaging/conversations/{id}/participants/{participantId}")
    suspend fun removeParticipant(
        @Path("id") id: String,
        @Path("participantId") participantId: String,
    )

    /**
     * AND-159 — mute/unmute. Body = MuteIn {muted?, muted_until?} (muted_until is an INTEGER epoch).
     * Empty 200 body — re-GET the conversation to refresh. Non-idempotent POST.
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/mute")
    suspend fun mute(
        @Path("id") id: String,
        @Body body: MuteRequest,
    )

    /** AND-159 — leave the group (no body). Empty 200. Non-idempotent POST (no auto-retry). */
    @POST("messaging/conversations/{id}/leave")
    suspend fun leave(@Path("id") id: String)

    /** AND-159 — accept a pending invite (no body). Empty 200. Non-idempotent POST. */
    @POST("messaging/conversations/{id}/accept")
    suspend fun accept(@Path("id") id: String)

    /**
     * AND-160 — delete the whole conversation (the final conversation-lifecycle route). No body;
     * HTTP 200 with a body that is intentionally ignored (mirrors [removeParticipant]). A 404 means
     * it is already gone — the repository degrades that to success. Non-idempotent DELETE.
     */
    @DELETE("messaging/conversations/{id}")
    suspend fun deleteConversation(@Path("id") id: String)
}

/**
 * AND-157 — POST body = StartGroupConversationIn. Group name maps to `title` (optional server-side,
 * product-required here); avatar ref maps to `icon` (optional). There is NO `name`/`avatar_url`.
 * Only `participant_ids` is required (minItems 2). The current user is NOT included.
 */
@JsonClass(generateAdapter = true)
data class CreateGroupRequest(
    @Json(name = "title") val title: String?,
    @Json(name = "participant_ids") val participantIds: List<String>,
    @Json(name = "icon") val icon: String? = null,
)

/** AND-158 — POST add body = AddParticipantsIn. Field is `participant_ids` (NOT `user_ids`). */
@JsonClass(generateAdapter = true)
data class AddParticipantsRequest(
    @Json(name = "participant_ids") val participantIds: List<String>,
)

/** AND-158 — add response = {ok, added_count}. Does not echo member rows. */
@JsonClass(generateAdapter = true)
data class AddParticipantsResponse(
    val ok: Boolean = true,
    @Json(name = "added_count") val addedCount: Int = 0,
)

/** AND-158 — PATCH role body = UpdateParticipantRoleIn. `role` ∈ {"admin","member"}. */
@JsonClass(generateAdapter = true)
data class ChangeRoleRequest(
    @Json(name = "role") val role: String,
)

/** AND-158 — change-role response = {ok, role}. */
@JsonClass(generateAdapter = true)
data class ChangeRoleResponse(
    val ok: Boolean = true,
    val role: String = "member",
)

/**
 * AND-159 — POST mute body = MuteIn. `muted_until` is an INTEGER epoch (Long), nullable. "Forever"
 * sends `muted: true` with `muted_until` null; unmute sends `muted: false`.
 */
@JsonClass(generateAdapter = true)
data class MuteRequest(
    @Json(name = "muted") val muted: Boolean?,
    @Json(name = "muted_until") val mutedUntil: Long?,
)

/**
 * AND-158 — roster GET envelope. The endpoint is untyped server-side; the web app derives the roster
 * from ConversationOut.participants. We accept an optional `{participants:[...]}` envelope; the repo
 * additionally falls back to the conversation GET when this is empty/absent.
 */
@JsonClass(generateAdapter = true)
data class RosterResponse(
    val participants: List<com.testlogon.android.data.messaging.ParticipantDto>? = null,
)
