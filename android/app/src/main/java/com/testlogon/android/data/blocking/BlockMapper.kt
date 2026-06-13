package com.testlogon.android.data.blocking

import com.testlogon.android.core.model.blocking.BlockRelationship
import com.testlogon.android.core.model.blocking.BlockedUser

/**
 * AND-382 - DTO -> domain mappers. Per the established architecture, DTO->domain mapping lives in
 * :app (core-model has no Moshi dependency). Total and side-effect-free.
 */

fun BlockedUserDto.toDomain(): BlockedUser = BlockedUser(
    userId = userId,
    displayName = displayName,
    profilePhotoUrl = profilePhotoUrl,
    blockedAt = blockedAt,
)

fun BlockStatusDto.toRelationship(): BlockRelationship =
    BlockRelationship.from(isBlockedByMe = isBlockedByMe, isBlockingMe = isBlockingMe)
