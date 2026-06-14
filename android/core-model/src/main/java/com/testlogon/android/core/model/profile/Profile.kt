package com.testlogon.android.core.model.profile

/**
 * AND-070 — immutable profile domain models.
 *
 * These are UI- and storage-agnostic; DTOs and Moshi/Retrofit annotations stay in the data layer.
 * Field set mirrors the verified web contract (reference: src/api/types.ts: Profile,
 * CrossUserProfileResp, PublicProfileData). There is no username/bio/avatar_url/stats/links/is_self
 * on the backend Profile: bio is `description`, avatar is `profilePhotoUrl`, ownership is `audience`.
 */
data class Profile(
    val displayName: String?,
    val firstName: String?,
    val middleName: String?,
    val lastName: String?,
    val title: String?,
    val description: String?,
    val birthday: String?,
    val gender: String?,
    val location: String?,
    val displayedEmail: String?,
    val displayedTelephoneNumber: String?,
    val profilePhotoUrl: String?,
    val coverPhotoUrl: String?,
    val languages: List<ProfileLanguage>,
) {
    /** A best-effort label for the header: display name, then a name part, else null. */
    val bestName: String?
        get() = displayName
            ?: listOfNotNull(firstName, lastName).joinToString(" ").takeIf { it.isNotBlank() }

    companion object {
        /** An all-empty profile (every optional null, no languages); used as a safe default. */
        val EMPTY = Profile(
            displayName = null,
            firstName = null,
            middleName = null,
            lastName = null,
            title = null,
            description = null,
            birthday = null,
            gender = null,
            location = null,
            displayedEmail = null,
            displayedTelephoneNumber = null,
            profilePhotoUrl = null,
            coverPhotoUrl = null,
            languages = emptyList(),
        )
    }
}

/** A spoken language entry (reference: src/api/types.ts: Language). */
data class ProfileLanguage(
    val name: String,
    val level: String,
)

/** Server-inferred viewer audience for a cross-user read (reference: ProfileViewAudience). */
enum class ProfileAudience { OWNER, MEMBER, PUBLIC, UNKNOWN }

/**
 * Cross-user profile (reference: GET /ui/profiles/{identifier} -> CrossUserProfileResp).
 * `audience` is decided server-side; the client never fabricates or widens it.
 */
data class CrossUserProfile(
    val identifier: String,
    val canonicalIdentifier: String?,
    val userSub: String,
    val audience: ProfileAudience,
    val profile: Profile,
) {
    val viewerIsOwner: Boolean get() = audience == ProfileAudience.OWNER
}

/**
 * Storefront public profile (reference: GET /ui/profile/public/{identifier} -> PublicProfileData).
 * `createdAtEpochSeconds` is a unix-epoch SECONDS integer on the wire (NOT ISO-8601); kept as a
 * Long here so JVM unit tests need no java.time (minSdk-24 safe).
 */
data class PublicProfile(
    val userId: String,
    val identifier: String,
    val canonicalIdentifier: String?,
    val displayName: String,
    val title: String?,
    val description: String?,
    val location: String?,
    val profilePhotoUrl: String?,
    val coverPhotoUrl: String?,
    val followerCount: Int,
    val followingCount: Int,
    val postCount: Int,
    val isFollowing: Boolean,
    val isFollowedBy: Boolean,
    val isMutual: Boolean,
    val hasSubscriptionPlans: Boolean,
    val createdAtEpochSeconds: Long?,
    val discoverability: String?,
)

/**
 * Partial profile update payload (reference: PATCH /ui/profile, schema ProfilePatchReq). Only the
 * fields edited by AND-072 are modeled; all are nullable so a true partial update is sent. There is
 * no `bio` (use `description`) and no `links` field in the contract.
 */
data class ProfilePatch(
    val displayName: String? = null,
    val description: String? = null,
    val location: String? = null,
    val title: String? = null,
    val firstName: String? = null,
    val middleName: String? = null,
    val lastName: String? = null,
) {
    /** True when no field is set (nothing to send). */
    val isEmpty: Boolean
        get() = displayName == null && description == null && location == null && title == null &&
            firstName == null && middleName == null && lastName == null
}
