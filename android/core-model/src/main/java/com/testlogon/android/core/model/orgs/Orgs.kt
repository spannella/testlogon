package com.testlogon.android.core.model.orgs

/**
 * AND-353 - domain model + role enum for the organizations members/roles surface.
 *
 * core-model has NO Moshi dependency: these are plain domain types. The wire DTOs (core-network
 * OrgDtos) carry org_role as a raw String; [OrgRole.from] parses that token into the typed enum with an
 * [OrgRole.UNKNOWN] fallback so an unrecognized role NEVER crashes the UI. Member `status` is kept as a
 * raw String here (the contract does not pin a confirmed enum of status values - do NOT hardcode one).
 */

/** A caller's / member's role within an organization. */
enum class OrgRole {
    OWNER,
    ADMIN,
    MEMBER,
    VIEWER,
    UNKNOWN,
    ;

    /** True for roles that may manage members (invite / change-role / remove). */
    val isManager: Boolean get() = this == OWNER || this == ADMIN

    /** The wire token for this role (UNKNOWN has no canonical wire token). */
    val wire: String?
        get() = when (this) {
            OWNER -> "owner"
            ADMIN -> "admin"
            MEMBER -> "member"
            VIEWER -> "viewer"
            UNKNOWN -> null
        }

    companion object {
        /** Parses a wire token into an [OrgRole]; null / unknown -> [UNKNOWN] (never throws). */
        fun from(wire: String?): OrgRole = when (wire?.trim()?.lowercase()) {
            "owner" -> OWNER
            "admin" -> ADMIN
            "member" -> MEMBER
            "viewer" -> VIEWER
            else -> UNKNOWN
        }

        /** The roles assignable via the invite / role-change UI (owner is NOT one of them). */
        val ASSIGNABLE: List<OrgRole> = listOf(ADMIN, MEMBER, VIEWER)
    }
}

/** One organization the caller belongs to. [callerRole] gates member-management affordances. */
data class Org(
    val orgId: String,
    val name: String? = null,
    val callerRole: OrgRole = OrgRole.UNKNOWN,
)

/** One member of an org. Identity is [userSub] (there is NO display_name on the wire). */
data class OrgMember(
    val userSub: String,
    val role: OrgRole = OrgRole.UNKNOWN,
    val status: String? = null,
    val joinedAt: String? = null,
    val storageUsedBytes: Long? = null,
    val lastActiveAt: String? = null,
)

/** One pending invite (a separate resource from members). */
data class OrgInvite(
    val inviteId: String,
    val email: String,
    val role: OrgRole = OrgRole.UNKNOWN,
    val orgId: String? = null,
    val orgName: String? = null,
    val status: String? = null,
    val invitedBy: String? = null,
    val createdAt: String? = null,
    val expiresAt: String? = null,
)
