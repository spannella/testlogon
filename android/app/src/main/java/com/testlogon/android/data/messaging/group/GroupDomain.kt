package com.testlogon.android.data.messaging.group

import com.testlogon.android.core.data.messaging.ParticipantEntity
import com.testlogon.android.data.messaging.ParticipantDto

/**
 * AND-158 — participant role. The messaging participant contract is exactly {admin, member}
 * (UpdateParticipantRoleIn.role enum = ["admin","member"]; ParticipantOut.role observed admin/member).
 * There is NO `owner` role here. [UNKNOWN] is a defensive client-only fallback bucket for an
 * unrecognised wire value; it is NEVER sent to the server.
 */
enum class GroupRole { ADMIN, MEMBER, UNKNOWN;

    /** Wire value for the PATCH role endpoint (UNKNOWN coerces to member, never sent as "unknown"). */
    fun wire(): String = when (this) {
        ADMIN -> "admin"
        else -> "member"
    }

    companion object {
        fun fromWire(value: String?): GroupRole = when (value?.lowercase()) {
            "admin" -> ADMIN
            "member" -> MEMBER
            null -> MEMBER
            else -> UNKNOWN
        }
    }
}

/**
 * AND-159 — the current user's membership status in a group, derived from the matching
 * participants[] entry (status ∈ active|invited|pending_approval) and `left_at` (>0 ⇒ left). There is
 * no top-level membership field on the wire.
 */
enum class MembershipStatus { ACTIVE, INVITED, LEFT, UNKNOWN }

/**
 * AND-158 — one group participant for the roster UI. Maps from [ParticipantDto]: image field is
 * `profile_photo_url` (NOT `avatar_url`); `joined_at` is a numeric epoch (seconds). `display_name`
 * may be null.
 */
data class GroupParticipant(
    val userId: String,
    val displayName: String?,
    val avatarUrl: String?,
    val role: GroupRole,
    val joinedAtEpochSeconds: Long,
)

/**
 * AND-158 — a group's roster plus the current user's derived role. `currentUserRole` is computed
 * client-side (the server returns no `current_user_role` field) by matching the logged-in user id
 * against [participants]; absent ⇒ [GroupRole.MEMBER] (read-only, server is the real gate).
 */
data class GroupRoster(
    val conversationId: String,
    val participants: List<GroupParticipant>,
    val currentUserRole: GroupRole,
    val currentUserId: String?,
) {
    /** AND-158 — admins may add/remove/change-role; members see a read-only roster (UX gate only). */
    val canManage: Boolean get() = currentUserRole == GroupRole.ADMIN

    /** AND-158 — the number of ADMINs, used for the last-admin self-protection guard. */
    val adminCount: Int get() = participants.count { it.role == GroupRole.ADMIN }
}

/**
 * AND-159 — per-member group settings derived from ConversationOut: the group identity (title/icon),
 * the current user's membership status, and the mute state (muted_until epoch seconds, 0 = not muted).
 */
data class GroupSettings(
    val conversationId: String,
    val title: String,
    val iconUrl: String?,
    val membership: MembershipStatus,
    val mutedUntilEpochSeconds: Long,
) {
    /** Muted when `muted_until` is in the future relative to [nowSeconds] (a sentinel far-future = forever). */
    fun isMuted(nowSeconds: Long): Boolean = mutedUntilEpochSeconds > nowSeconds
}

// ---- Mappers (pure / JVM-testable) ----

/** AND-158 — wire participant -> domain. */
internal fun ParticipantDto.toGroupParticipant(): GroupParticipant =
    GroupParticipant(
        userId = userId,
        displayName = displayName?.takeIf { it.isNotBlank() },
        avatarUrl = profilePhotoUrl,
        role = GroupRole.fromWire(role),
        joinedAtEpochSeconds = joinedAt,
    )

/** AND-158 — Room row -> domain. */
internal fun ParticipantEntity.toDomain(): GroupParticipant = GroupParticipant(
    userId = userId,
    displayName = displayName,
    avatarUrl = avatarUrl,
    role = GroupRole.fromWire(role),
    joinedAtEpochSeconds = joinedAtEpochSeconds,
)

/** AND-158 — domain -> Room row. */
internal fun GroupParticipant.toEntity(conversationId: String): ParticipantEntity = ParticipantEntity(
    conversationId = conversationId,
    userId = userId,
    displayName = displayName,
    avatarUrl = avatarUrl,
    role = role.wire().uppercase(),
    joinedAtEpochSeconds = joinedAtEpochSeconds,
)
