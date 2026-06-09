package com.testlogon.android.data.profile

import com.testlogon.android.core.model.profile.CrossUserProfile
import com.testlogon.android.core.model.profile.Profile
import com.testlogon.android.core.model.profile.ProfileAudience
import com.testlogon.android.core.model.profile.ProfileLanguage
import com.testlogon.android.core.model.profile.ProfilePatch
import com.testlogon.android.core.model.profile.PublicProfile

/**
 * AND-070 — total DTO -> domain mappers. They never throw: blank strings normalize to null, nullable
 * collections become empty lists, and an unknown `audience` maps to [ProfileAudience.UNKNOWN].
 */

fun ProfileDto.toDomain(): Profile = Profile(
    displayName = displayName.normalizeOrNull(),
    firstName = firstName.normalizeOrNull(),
    middleName = middleName.normalizeOrNull(),
    lastName = lastName.normalizeOrNull(),
    title = title.normalizeOrNull(),
    description = description?.trim()?.takeIf { it.isNotBlank() },
    birthday = birthday.normalizeOrNull(),
    gender = gender.normalizeOrNull(),
    location = location.normalizeOrNull(),
    displayedEmail = displayedEmail.normalizeOrNull(),
    displayedTelephoneNumber = displayedTelephoneNumber.normalizeOrNull(),
    profilePhotoUrl = profilePhotoUrl.normalizeOrNull(),
    coverPhotoUrl = coverPhotoUrl.normalizeOrNull(),
    languages = languages.orEmpty().mapNotNull { it.toDomainOrNull() },
)

fun LanguageDto.toDomainOrNull(): ProfileLanguage? {
    val n = name.normalizeOrNull() ?: return null
    return ProfileLanguage(name = n, level = level.normalizeOrNull().orEmpty())
}

fun CrossUserProfileDto.toDomain(): CrossUserProfile = CrossUserProfile(
    identifier = identifier,
    canonicalIdentifier = canonicalIdentifier.normalizeOrNull(),
    userSub = userSub,
    audience = audience.toAudience(),
    profile = profile.toDomain(),
)

fun PublicProfileDataDto.toDomain(): PublicProfile = PublicProfile(
    userId = userId,
    identifier = identifier,
    canonicalIdentifier = canonicalIdentifier.normalizeOrNull(),
    displayName = displayName,
    title = title.normalizeOrNull(),
    description = description?.trim()?.takeIf { it.isNotBlank() },
    location = location.normalizeOrNull(),
    profilePhotoUrl = profilePhotoUrl.normalizeOrNull(),
    coverPhotoUrl = coverPhotoUrl.normalizeOrNull(),
    followerCount = followerCount,
    followingCount = followingCount,
    postCount = postCount,
    isFollowing = isFollowing,
    isFollowedBy = isFollowedBy,
    isMutual = isMutual,
    hasSubscriptionPlans = hasSubscriptionPlans,
    createdAtEpochSeconds = createdAt?.takeIf { it > 0 },
    discoverability = discoverability.normalizeOrNull(),
)

/** Domain patch -> wire request. Pure. */
fun ProfilePatch.toReqDto(): ProfilePatchReqDto = ProfilePatchReqDto(
    displayName = displayName,
    description = description,
    location = location,
    title = title,
    firstName = firstName,
    middleName = middleName,
    lastName = lastName,
)

private fun String?.toAudience(): ProfileAudience = when (this?.lowercase()) {
    "owner" -> ProfileAudience.OWNER
    "member" -> ProfileAudience.MEMBER
    "public" -> ProfileAudience.PUBLIC
    else -> ProfileAudience.UNKNOWN
}

private fun String?.normalizeOrNull(): String? = this?.trim()?.takeIf { it.isNotBlank() }
