package com.testlogon.android.data.watchparties

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Framework-free watch-parties domain models + total DTO -> domain mappers.
 *
 * [WatchPartyStatus] mirrors the web "waiting|playing|paused|ended" enum (unknown -> WAITING).
 * Timestamps are epoch-seconds; formatting uses SimpleDateFormat/Date (no java.time - core-library
 * desugaring is off) and stays JVM-unit-testable. Mapping is total: absent optionals default per the
 * schema.
 */
enum class WatchPartyStatus { WAITING, PLAYING, PAUSED, ENDED, UNKNOWN }

enum class ParticipantRole { HOST, CO_HOST, MEMBER }

enum class ParticipantStatus { ACTIVE, LEFT, KICKED, UNKNOWN }

data class WatchParty(
    val id: String,
    val hostUserSub: String,
    val videoId: String,
    val videoTitle: String,
    val videoDurationSeconds: Long,
    val title: String,
    val inviteCode: String,
    val status: WatchPartyStatus,
    val maxParticipants: Int,
    val participantCount: Int,
    val positionSeconds: Long,
    val createdAtSeconds: Long,
    val endedAtSeconds: Long?,
) {
    val isEnded: Boolean get() = status == WatchPartyStatus.ENDED

    val displayTitle: String get() = title.ifBlank { videoTitle.ifBlank { id } }

    /** Human-readable created date, e.g. "Jun 17, 2026". */
    fun formattedCreated(): String =
        if (createdAtSeconds <= 0L) "" else DATE_FORMAT.format(Date(createdAtSeconds * 1000L))

    private companion object {
        private val DATE_FORMAT = SimpleDateFormat("MMM d, yyyy", Locale.getDefault())
    }
}

data class WatchPartyParticipant(
    val userSub: String,
    val role: ParticipantRole,
    val status: ParticipantStatus,
    val joinedAtSeconds: Long,
) {
    val isActive: Boolean get() = status == ParticipantStatus.ACTIVE
}

/** Lightweight summary returned when resolving an invite code (web /party/{code}). */
data class InviteResolution(
    val partyId: String,
    val title: String,
    val videoTitle: String,
    val status: WatchPartyStatus,
    val participantCount: Int,
    val maxParticipants: Int,
)

// ---- Mappers (DTO -> domain) ----

internal fun statusOf(raw: String): WatchPartyStatus = when (raw.lowercase(Locale.US)) {
    "waiting" -> WatchPartyStatus.WAITING
    "playing" -> WatchPartyStatus.PLAYING
    "paused" -> WatchPartyStatus.PAUSED
    "ended" -> WatchPartyStatus.ENDED
    else -> WatchPartyStatus.UNKNOWN
}

internal fun WatchPartyDto.toDomain(): WatchParty = WatchParty(
    id = partyId,
    hostUserSub = hostUserSub,
    videoId = videoId,
    videoTitle = videoTitle,
    videoDurationSeconds = videoDurationSeconds,
    title = title,
    inviteCode = inviteCode,
    status = statusOf(status),
    maxParticipants = maxParticipants,
    participantCount = participantCount,
    positionSeconds = position.toLong(),
    createdAtSeconds = createdAt,
    endedAtSeconds = endedAt,
)

internal fun WatchPartyParticipantDto.toDomain(): WatchPartyParticipant = WatchPartyParticipant(
    userSub = userSub,
    role = when (role.lowercase(Locale.US)) {
        "host" -> ParticipantRole.HOST
        "co-host", "cohost" -> ParticipantRole.CO_HOST
        else -> ParticipantRole.MEMBER
    },
    status = when (status.lowercase(Locale.US)) {
        "active" -> ParticipantStatus.ACTIVE
        "left" -> ParticipantStatus.LEFT
        "kicked" -> ParticipantStatus.KICKED
        else -> ParticipantStatus.UNKNOWN
    },
    joinedAtSeconds = joinedAt,
)

internal fun InviteResolveRespDto.toDomain(): InviteResolution = InviteResolution(
    partyId = partyId,
    title = title,
    videoTitle = videoTitle,
    status = statusOf(status),
    participantCount = participantCount,
    maxParticipants = maxParticipants,
)
