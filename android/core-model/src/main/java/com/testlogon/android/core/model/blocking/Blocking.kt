package com.testlogon.android.core.model.blocking

/**
 * AND-382 - domain models for user-level block / unblock.
 *
 * The block relationship is server-authoritative (DynamoDB); these are the decoded, framework-free
 * shapes the feature layer renders. The two boolean directions come from the verified
 * BlockStatusResponse { is_blocked_by_me, is_blocking_me } (and the optional same-named flags on the
 * follow-status payload). See spec sec.3 FR-7 and the citation audit sec.16 (#10).
 */

/**
 * The block relationship between the signed-in user and a viewed user, collapsed into the three
 * states the UI cares about. Derived from is_blocked_by_me / is_blocking_me:
 *  - [BlockedByMe]  == is_blocked_by_me (the signed-in user blocked the other)
 *  - [BlockedMe]    == is_blocking_me   (the other user blocked the signed-in user)
 *  - [Normal]       == neither
 *
 * When both directions are true, [BlockedByMe] wins for affordance purposes: the blocker should see
 * their own unblock affordance rather than the passive "you can't contact" banner.
 */
enum class BlockRelationship {
    Normal,
    BlockedByMe,
    BlockedMe,
    ;

    /** Either direction blocks contact (composer must be disabled). */
    val contactBlocked: Boolean
        get() = this != Normal

    companion object {
        /** Collapse the two verified wire flags into a [BlockRelationship]. */
        fun from(isBlockedByMe: Boolean, isBlockingMe: Boolean): BlockRelationship = when {
            isBlockedByMe -> BlockedByMe
            isBlockingMe -> BlockedMe
            else -> Normal
        }
    }
}

/**
 * A single entry in the signed-in user's blocked list (the blocked-by-me direction only).
 *
 * Mirrors the verified BlockedUserItem { user_id, display_name?, profile_photo_url?, blocked_at }.
 * There is deliberately NO handle and NO created_at field (citation audit sec.16 #9). [blockedAt] is
 * an ISO-8601 timestamp string as the server emits it.
 */
data class BlockedUser(
    val userId: String,
    val displayName: String?,
    val profilePhotoUrl: String?,
    val blockedAt: String,
)
