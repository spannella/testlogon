package com.testlogon.android.data.activity

/**
 * AND-091 — domain model + mapping for activity events (framework-free, JVM-unit-test safe).
 *
 * Timestamps are kept as epoch SECONDS Long (no java.time at this layer) so the mapper is
 * minSdk24-safe and unit-testable without desugaring; relative-time formatting is a UI concern.
 * "activity_type" is a free-form server string normalized to [ActivityEventType] with an
 * [ActivityEventType.UNKNOWN] fallback so additive backend kinds can never crash the feed.
 *
 * There is no server "detail"/"ip"/"user_agent"; the optional [detail] subtitle is DERIVED at map
 * time from target_* / selected metadata keys.
 */
enum class ActivityEventType {
    LOGIN_SUCCESS,
    LOGIN_FAILED,
    MFA_CHALLENGE,
    SESSION_REVOKED,
    PASSWORD_CHANGED,
    PROFILE_UPDATED,
    SECURITY_ALERT,
    // Social activity kinds (BK5: /ui/activity/feed records follow/like/comment/tip/mention).
    FOLLOW,
    LIKE,
    COMMENT,
    MENTION,
    TIP,
    SUBSCRIBE,
    UNKNOWN,
    ;

    companion object {
        fun fromToken(token: String?): ActivityEventType {
            if (token.isNullOrBlank()) return UNKNOWN
            entries.firstOrNull { it != UNKNOWN && it.name.equals(token, ignoreCase = true) }?.let { return it }
            val t = token.lowercase()
            return when {
                "follow" in t -> FOLLOW
                "subscrib" in t -> SUBSCRIBE
                "tip" in t || "donat" in t -> TIP
                "like" in t || "react" in t -> LIKE
                "comment" in t || "reply" in t -> COMMENT
                "mention" in t -> MENTION
                "login_success" in t -> LOGIN_SUCCESS
                "login_fail" in t -> LOGIN_FAILED
                "mfa" in t -> MFA_CHALLENGE
                "session" in t && "revok" in t -> SESSION_REVOKED
                "password" in t -> PASSWORD_CHANGED
                "profile" in t -> PROFILE_UPDATED
                "security" in t || "alert" in t -> SECURITY_ALERT
                else -> UNKNOWN
            }
        }
    }
}

/** A single activity event as consumed by the feature layer. */
data class ActivityEvent(
    val id: String,
    val type: ActivityEventType,
    /** Preserved raw server token so unknown kinds still carry their label. */
    val rawType: String,
    val actorId: String,
    /** Epoch SECONDS (server contract). 0 maps to the Unix epoch. */
    val createdAtEpochSeconds: Long,
    val targetType: String?,
    val targetId: String?,
    val read: Boolean,
    /** DERIVED subtitle (target / metadata hint), or null when nothing useful is present. */
    val detail: String?,
)

/** One page of activity events + the opaque cursor for the next page (null = terminal). */
data class ActivityPage(
    val items: List<ActivityEvent>,
    val nextCursor: String?,
    val totalUnread: Int,
)

internal fun ActivityEventDto.toDomain(): ActivityEvent = ActivityEvent(
    id = activityId,
    type = ActivityEventType.fromToken(activityType),
    rawType = activityType,
    actorId = actorId,
    createdAtEpochSeconds = createdAt,
    targetType = targetType.ifBlank { null },
    targetId = targetId.ifBlank { null },
    read = read,
    detail = deriveDetail(),
)

/**
 * Best-effort human-readable subtitle. Prefers a known location/device hint from the free-form
 * metadata, falling back to a "type id" target descriptor. Never throws on odd metadata shapes.
 */
private fun ActivityEventDto.deriveDetail(): String? {
    val metaHint = sequenceOf("ip", "location", "device", "factor", "user_agent")
        .mapNotNull { key -> (metadata[key] as? String)?.takeIf { it.isNotBlank() } }
        .firstOrNull()
    if (metaHint != null) return metaHint
    val tType = targetType.ifBlank { null } ?: return null
    val tId = targetId.ifBlank { null }
    return if (tId != null) "$tType $tId" else tType
}
