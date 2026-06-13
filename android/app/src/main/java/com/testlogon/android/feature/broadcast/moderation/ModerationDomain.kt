package com.testlogon.android.feature.broadcast.moderation

import java.time.Instant

/**
 * AND-313 - broadcast chat moderation domain models (DTO-free) + DTO -> domain mappers.
 *
 * Reuses the AND-281 chat models (ChatMessage / ChatAuthor-equivalent senderId+senderDisplayName) at the
 * presentation layer; these domain types describe the moderation actions + the moderation log only.
 *
 * NOTE on "unmute": there is NO unmute endpoint on the wire, so [ModerationActionType.UNMUTE] is only ever a
 * value that may appear in a decoded moderation-log entry - the UI never OFFERS an unmute action (see the
 * UserModerationSheet). A ban can be lifted via unban; a mute simply expires.
 */
enum class ModerationActionType {
    MUTE, UNMUTE, BAN, UNBAN, DELETE, PIN, UNPIN, UNKNOWN
}

/** The subject of a moderation action: a user (mute / ban / unban) and/or a message (delete / pin / unpin). */
data class ModerationTarget(
    val userId: String? = null,
    val messageId: String? = null,
)

/** Parameters of a mute. There is NO reason field - a mute carries only a duration. */
data class MuteSpec(
    val durationSeconds: Long,
) {
    companion object {
        /** Wire bounds: min 30s, max 86400s (24h), default 300s (5m). */
        const val MIN_DURATION_SECONDS = 30L
        const val MAX_DURATION_SECONDS = 86_400L
        const val DEFAULT_DURATION_SECONDS = 300L

        val FIVE_MINUTES = MuteSpec(300L)
        val ONE_HOUR = MuteSpec(3_600L)
        val ONE_DAY = MuteSpec(86_400L)
    }
}

/** A single moderation-log entry, mapped from [ModerationLogEntryDto]. */
data class ModerationLogEntry(
    val id: String,
    val action: ModerationActionType,
    val moderatorId: String,
    val moderatorName: String,
    val target: ModerationTarget,
    /** A short human label for the target (display name, or a truncated user/message id). */
    val targetLabel: String,
    val reason: String?,
    val createdAt: Instant,
)

/** A current ban, mapped from [BanDto]. */
data class ModerationBan(
    val userId: String,
    val displayName: String?,
    val reason: String?,
    val moderatorId: String?,
    val createdAt: Instant,
)

// --- DTO -> domain mappers (epoch SECONDS -> Instant; unknown enum -> safe default, never throws) ------

/** Maps a wire moderation_type string to [ModerationActionType]; an unknown value -> [UNKNOWN]. */
fun moderationActionTypeOf(wire: String?): ModerationActionType = when (wire?.lowercase()) {
    "mute" -> ModerationActionType.MUTE
    "unmute" -> ModerationActionType.UNMUTE
    "ban" -> ModerationActionType.BAN
    "unban" -> ModerationActionType.UNBAN
    "delete" -> ModerationActionType.DELETE
    "pin" -> ModerationActionType.PIN
    "unpin" -> ModerationActionType.UNPIN
    else -> ModerationActionType.UNKNOWN
}

/** Maps a [ModerationLogEntryDto] to the domain [ModerationLogEntry] (never throws). */
fun ModerationLogEntryDto.toDomain(): ModerationLogEntry {
    val target = ModerationTarget(userId = targetUserId, messageId = targetMessageId)
    val reason = (details?.get("reason") as? String)?.takeIf { it.isNotBlank() }
    return ModerationLogEntry(
        id = eventId,
        action = moderationActionTypeOf(moderationType),
        moderatorId = moderatorId,
        moderatorName = moderatorDisplayName?.takeIf { it.isNotBlank() } ?: moderatorId,
        target = target,
        targetLabel = targetMessageId ?: targetUserId ?: "",
        reason = reason,
        createdAt = Instant.ofEpochSecond(ts),
    )
}

/** Maps a [BanDto] to the domain [ModerationBan] (never throws). */
fun BanDto.toDomain(): ModerationBan = ModerationBan(
    userId = userId,
    displayName = displayName?.takeIf { it.isNotBlank() },
    reason = reason?.takeIf { it.isNotBlank() },
    moderatorId = moderatorId?.takeIf { it.isNotBlank() },
    createdAt = Instant.ofEpochSecond(ts),
)
