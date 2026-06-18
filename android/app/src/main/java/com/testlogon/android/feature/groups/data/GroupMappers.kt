package com.testlogon.android.feature.groups.data

import com.testlogon.android.core.model.groups.Group
import com.testlogon.android.core.model.groups.GroupMember
import com.testlogon.android.core.model.groups.GroupRole
import com.testlogon.android.core.network.groups.GroupMemberDto
import com.testlogon.android.core.network.groups.UserGroupDto

/**
 * AND-355 - DTO -> domain mappers for the social-groups surface.
 *
 * PLACEMENT: core-model has no dependency on core-network's DTOs (and core-network has no domain dep), so
 * the bridging mappers live here in the feature, which depends on BOTH. my_role / role are parsed via
 * [GroupRole.from] (UNKNOWN fallback); member `status` is passed through as a raw String (a status of
 * "invited" marks a PENDING entry). There is NO owner role - the owner is admin_user_id.
 */

/** Maps a [UserGroupDto] to the domain [Group]; my_role becomes the caller's role. */
fun UserGroupDto.toDomain(): Group = Group(
    id = groupId,
    name = name,
    description = description,
    memberCount = memberCount,
    myRole = GroupRole.from(myRole),
    adminUserId = adminUserId,
    coverImageUrl = coverImageUrl,
    topic = topic,
    visibility = visibility,
    status = status,
)

/**
 * Maps a [GroupMemberDto] to the domain [GroupMember]. status is kept raw (defaulting to an empty string
 * only when the wire omits it); a status of "invited" marks a pending invite.
 */
fun GroupMemberDto.toDomain(): GroupMember = GroupMember(
    userId = userId,
    role = GroupRole.from(role),
    status = status.orEmpty(),
    displayName = displayName,
    joinedAt = joinedAt,
    promotedAt = promotedAt,
)
