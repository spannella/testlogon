package com.testlogon.android.data.call.group

/**
 * AND-299 — pure (DTO-free, android-free) domain models for the GROUP-call control plane.
 *
 * The repository maps wire DTOs -> these before returning a typed ApiResult (never leaks raw DTOs). No
 * android.* types (JVM-unit-testable on minSdk 24); epoch timestamps are Long SECONDS.
 *
 * `state` / `connection_quality` are FREE-FORM wire strings — [ParticipantState.fromWire] /
 * [ConnQuality.fromWire] map unknown values defensively (-> Connecting / Unknown) rather than throwing.
 * The wire has NO is_host / mic_muted / camera_off flags: isHost is derived (user_id == creator_user_id),
 * micMuted = !media_status.audio, cameraOff = !media_status.video. Participants are keyed by user_id.
 */

/** Lifecycle of a single participant. [fromWire] maps the free-form server token defensively. */
enum class ParticipantState {
    Ringing,
    Connecting,
    Connected,
    Reconnecting,
    Left,
    Failed,
    ;

    companion object {
        fun fromWire(s: String?): ParticipantState = when (s?.trim()?.lowercase()) {
            "ringing" -> Ringing
            "connecting" -> Connecting
            "connected", "active", "joined" -> Connected
            "reconnecting" -> Reconnecting
            "left", "disconnected" -> Left
            "failed", "error" -> Failed
            else -> Connecting
        }
    }
}

/** Derived connection quality. [fromWire] maps the free-form server token defensively. */
enum class ConnQuality {
    Good,
    Fair,
    Poor,
    Unknown,
    ;

    companion object {
        fun fromWire(s: String?): ConnQuality = when (s?.trim()?.lowercase()) {
            "good", "excellent" -> Good
            "fair", "ok", "medium" -> Fair
            "poor", "bad", "weak" -> Poor
            else -> Unknown
        }
    }
}

/** A STUN/TURN ICE server entry surfaced to the (FLAGGED) mesh; mirrors the AND-291 wire shape. */
data class IceServerInfo(
    val urls: List<String>,
    val username: String? = null,
    val credential: String? = null,
)

/** A single participant in a group call. avatarUrl is not in the wire data — left null. */
data class GroupParticipant(
    val userId: String,
    val displayName: String?,
    val isSelf: Boolean,
    val isHost: Boolean,
    val state: ParticipantState,
    val micMuted: Boolean,
    val cameraOff: Boolean,
    val speaking: Boolean = false,
    val quality: ConnQuality,
    val joinedAt: Long,
    val avatarUrl: String? = null,
)

/** A group call's identity + roster + (FLAGGED) signaling config. */
data class GroupCall(
    val callId: String,
    val conversationId: String,
    val creatorUserId: String,
    val mode: String?,
    val maxParticipants: Int,
    val state: String,
    val participants: List<GroupParticipant>,
    val iceServers: List<IceServerInfo>,
)

// ─── DTO -> domain mappers ───────────────────────────────────────────────────────────────────────

internal fun GroupCallParticipantDto.toDomain(
    selfUserId: String?,
    creatorUserId: String,
): GroupParticipant = GroupParticipant(
    userId = userId,
    displayName = displayName,
    isSelf = selfUserId != null && userId == selfUserId,
    isHost = userId == creatorUserId,
    state = ParticipantState.fromWire(state),
    micMuted = !mediaStatus.audio,
    cameraOff = !mediaStatus.video,
    quality = ConnQuality.fromWire(connectionQuality),
    joinedAt = joinedAtEpochSeconds,
)

internal fun SignalingInfoDto?.toIceServers(): List<IceServerInfo> =
    this?.iceServers?.map { IceServerInfo(urls = it.urls, username = it.username, credential = it.credential) }
        ?: emptyList()

internal fun GroupCallOutDto.toDomain(selfUserId: String?): GroupCall = GroupCall(
    callId = callId,
    conversationId = conversationId,
    creatorUserId = creatorUserId,
    mode = mode,
    maxParticipants = maxParticipants,
    state = state.orEmpty(),
    participants = participants.map { it.toDomain(selfUserId, creatorUserId) },
    iceServers = signaling.toIceServers(),
)

/**
 * The join response carries no creator_user_id of its own; the caller supplies [creatorUserId] (from the
 * create/get result, or self when creating) so isHost can still be derived.
 */
internal fun GroupCallJoinOutDto.toDomain(
    selfUserId: String?,
    conversationId: String,
    creatorUserId: String,
): GroupCall = GroupCall(
    callId = callId,
    conversationId = conversationId,
    creatorUserId = creatorUserId,
    mode = mode,
    maxParticipants = participants.size.coerceAtLeast(currentParticipantCount),
    state = state.orEmpty(),
    participants = participants.map { it.toDomain(selfUserId, creatorUserId) },
    iceServers = signaling.toIceServers(),
)

/** Roster-only domain mapping (participants endpoint has no creator field; pass it through). */
internal fun GroupCallParticipantsOutDto.toDomain(
    selfUserId: String?,
    creatorUserId: String,
): List<GroupParticipant> = participants.map { it.toDomain(selfUserId, creatorUserId) }
