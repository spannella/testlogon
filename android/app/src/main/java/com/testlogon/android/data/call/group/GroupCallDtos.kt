package com.testlogon.android.data.call.group

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.data.webrtc.TurnIceServerDto

/**
 * AND-299 — wire DTOs for the GROUP-call CONTROL PLANE under `ui/calls/group/`.
 *
 * Shapes VERIFIED against the AND-299 spec §5. snake_case field names via [Json]; absent optionals fall
 * back to Kotlin defaults / nullable (lenient decode). Epoch timestamps are Long SECONDS (no java.time).
 * Participants are keyed by `user_id` (there is NO participant_id); `state` and `connection_quality` are
 * FREE-FORM wire strings mapped defensively in [GroupCallDomain]. There is NO top-level ice_servers — the
 * ICE server list is nested under `signaling.ice_servers`.
 *
 * The ICE-server entry reuses AND-291's [TurnIceServerDto] ({urls, username, credential}) rather than
 * redefining an identical DTO.
 *
 * Cookies / Authorization / X-CSRF-Token are attached by the core-network interceptor chain — these DTOs
 * (and [GroupCallApi]) stay header-agnostic.
 */

// ─── Signaling block (nested in create/get/join responses) ──────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class SignalingInfoDto(
    @Json(name = "mode") val mode: String? = null,
    @Json(name = "ice_servers") val iceServers: List<TurnIceServerDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class MediaStatusDto(
    @Json(name = "audio") val audio: Boolean = true,
    @Json(name = "video") val video: Boolean = true,
    @Json(name = "screen") val screen: Boolean = false,
)

// ─── Participant ────────────────────────────────────────────────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class GroupCallParticipantDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "joined_at") val joinedAtEpochSeconds: Long = 0,
    @Json(name = "left_at") val leftAtEpochSeconds: Long? = null,
    @Json(name = "media_status") val mediaStatus: MediaStatusDto = MediaStatusDto(),
    @Json(name = "connection_quality") val connectionQuality: String? = null,
    @Json(name = "state") val state: String? = null,
)

// ─── Create / get ─────────────────────────────────────────────────────────────────────────────────

/** POST ui/calls/group/create body. mode default "video"; max_participants 2..8, default 8. */
@JsonClass(generateAdapter = true)
data class GroupCallCreateInDto(
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "mode") val mode: String = "video",
    @Json(name = "max_participants") val maxParticipants: Int = 8,
)

/** GroupCallOut — the canonical group-call resource (create 201 / GET). */
@JsonClass(generateAdapter = true)
data class GroupCallOutDto(
    @Json(name = "call_id") val callId: String,
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "creator_user_id") val creatorUserId: String,
    @Json(name = "state") val state: String? = null,
    @Json(name = "mode") val mode: String? = null,
    @Json(name = "max_participants") val maxParticipants: Int = 8,
    @Json(name = "current_participant_count") val currentParticipantCount: Int = 0,
    @Json(name = "participants") val participants: List<GroupCallParticipantDto> = emptyList(),
    @Json(name = "created_at") val createdAtEpochSeconds: Long = 0,
    @Json(name = "started_at") val startedAtEpochSeconds: Long? = null,
    @Json(name = "end_ts") val endTsEpochSeconds: Long? = null,
    @Json(name = "end_reason") val endReason: String? = null,
    @Json(name = "duration_seconds") val durationSeconds: Long = 0,
    @Json(name = "signaling") val signaling: SignalingInfoDto? = null,
)

// ─── Participants list ──────────────────────────────────────────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class GroupCallParticipantsOutDto(
    @Json(name = "participants") val participants: List<GroupCallParticipantDto> = emptyList(),
    @Json(name = "total_active") val totalActive: Int = 0,
    @Json(name = "total_joined") val totalJoined: Int = 0,
)

// ─── Active probe ───────────────────────────────────────────────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class GroupCallActiveOutDto(
    @Json(name = "active") val active: Boolean = false,
    @Json(name = "call_id") val callId: String? = null,
    @Json(name = "state") val state: String? = null,
    @Json(name = "mode") val mode: String? = null,
    @Json(name = "current_participant_count") val currentParticipantCount: Int? = null,
    @Json(name = "participants") val participants: List<GroupCallParticipantDto> = emptyList(),
)

// ─── Join ──────────────────────────────────────────────────────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class GroupCallJoinOutDto(
    @Json(name = "call_id") val callId: String,
    @Json(name = "state") val state: String? = null,
    @Json(name = "mode") val mode: String? = null,
    @Json(name = "current_participant_count") val currentParticipantCount: Int = 0,
    @Json(name = "participants") val participants: List<GroupCallParticipantDto> = emptyList(),
    @Json(name = "signaling") val signaling: SignalingInfoDto? = null,
)

// ─── Leave ─────────────────────────────────────────────────────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class GroupCallLeaveOutDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "call_ended") val callEnded: Boolean = false,
    @Json(name = "remaining_participants") val remainingParticipants: Int = 0,
)

// ─── End ───────────────────────────────────────────────────────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class GroupCallEndOutDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "call_id") val callId: String? = null,
    @Json(name = "duration_seconds") val durationSeconds: Long = 0,
    @Json(name = "total_participants") val totalParticipants: Int = 0,
)

// ─── Media update ──────────────────────────────────────────────────────────────────────────────────

/** PATCH ui/calls/group/{id}/media body — every field optional (only sent toggles are present). */
@JsonClass(generateAdapter = true)
data class GroupCallMediaUpdateInDto(
    @Json(name = "audio") val audio: Boolean? = null,
    @Json(name = "video") val video: Boolean? = null,
    @Json(name = "screen") val screen: Boolean? = null,
)

@JsonClass(generateAdapter = true)
data class GroupCallMediaUpdateOutDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "media_status") val mediaStatus: MediaStatusDto = MediaStatusDto(),
)

// ─── Signal relay ──────────────────────────────────────────────────────────────────────────────────

/** POST ui/calls/group/{id}/signal body — opaque [payload] forwarded to a target peer. */
@JsonClass(generateAdapter = true)
data class GroupCallSignalInDto(
    @Json(name = "type") val type: String,
    @Json(name = "target_user_id") val targetUserId: String,
    @Json(name = "payload") val payload: Map<String, Any?>? = null,
)

@JsonClass(generateAdapter = true)
data class GroupCallSignalOutDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "relayed_to") val relayedTo: String? = null,
)
