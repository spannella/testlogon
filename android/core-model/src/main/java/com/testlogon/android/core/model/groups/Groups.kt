package com.testlogon.android.core.model.groups

/**
 * AND-355 - domain model + role enum for the SOCIAL GROUPS surface (distinct from messaging group chats).
 *
 * core-model has NO Moshi dependency: these are plain domain types. The wire DTOs (core-network
 * GroupDtos) carry my_role / role as raw Strings; [GroupRole.from] parses that token into the typed enum
 * with a [GroupRole.UNKNOWN] fallback so an unrecognized role NEVER crashes the UI. Member `status` is
 * kept as a raw String here (do NOT hardcode an enum); a member with status=="invited" is a PENDING entry.
 *
 * ROLE NOTE: there is NO owner role - the owner is identified by [Group.adminUserId]. [GroupRole.canManage]
 * is true ONLY for [GroupRole.ADMIN].
 */

/** A caller's / member's role within a social group (there is NO owner role). */
enum class GroupRole {
    ADMIN,
    MODERATOR,
    MEMBER,
    UNKNOWN,
    ;

    /** True for the role that may manage membership (invite / change-role / remove / etc). */
    val canManage: Boolean get() = this == ADMIN

    /** The wire token for this role (UNKNOWN has no canonical wire token). */
    val wire: String?
        get() = when (this) {
            ADMIN -> "admin"
            MODERATOR -> "moderator"
            MEMBER -> "member"
            UNKNOWN -> null
        }

    companion object {
        /** Parses a wire token into a [GroupRole]; null / unknown -> [UNKNOWN] (never throws). */
        fun from(wire: String?): GroupRole = when (wire?.trim()?.lowercase()) {
            "admin" -> ADMIN
            "moderator" -> MODERATOR
            "member" -> MEMBER
            else -> UNKNOWN
        }

        /**
         * The roles assignable via the change-role UI (admin is NOT one of them - you cannot PATCH to
         * admin; admin is the owner, identified by admin_user_id).
         */
        val ASSIGNABLE: List<GroupRole> = listOf(MODERATOR, MEMBER)
    }
}

/** One social group the caller belongs to. [myRole] gates membership-management affordances. */
data class Group(
    val id: String,
    val name: String,
    val description: String? = null,
    val memberCount: Int? = null,
    val myRole: GroupRole = GroupRole.UNKNOWN,
    val adminUserId: String? = null,
    val coverImageUrl: String? = null,
) {
    /** True when the caller may manage membership (admin only). */
    val canManage: Boolean get() = myRole.canManage
}

/**
 * One member of a group. Identity is [userId] ([displayName] is shown when present). [status] is kept raw;
 * a member with status=="invited" is a PENDING entry (an outstanding invite, not an active member).
 */
data class GroupMember(
    val userId: String,
    val role: GroupRole = GroupRole.UNKNOWN,
    val status: String,
    val displayName: String? = null,
    val joinedAt: String? = null,
    val promotedAt: String? = null,
) {
    /** True when this member row represents a pending (not-yet-accepted) invite. */
    val isPending: Boolean get() = status.equals(STATUS_INVITED, ignoreCase = true)

    companion object {
        /** The raw status value marking a pending invite entry. */
        const val STATUS_INVITED = "invited"
    }
}
