package com.testlogon.android.feature.groups.data

import com.testlogon.android.core.model.groups.Group
import com.testlogon.android.core.model.groups.GroupComment
import com.testlogon.android.core.model.groups.GroupFeedPost
import com.testlogon.android.core.model.groups.GroupMember
import com.testlogon.android.core.model.groups.GroupRole
import com.testlogon.android.core.network.groups.GroupCommentDto
import com.testlogon.android.core.network.groups.GroupFeedPostDto
import com.testlogon.android.core.network.groups.GroupMemberDto
import com.testlogon.android.core.network.groups.UserGroupDto
import com.testlogon.android.data.poll.toDomain

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
    // Batch-8 (#10): the owner/admin row arrives with an EMPTY display_name from the backend; coerce a
    // blank value to null so the UI falls back to the user_id instead of rendering an empty, "missing" row.
    displayName = displayName?.takeIf { it.isNotBlank() },
    joinedAt = joinedAt,
    promotedAt = promotedAt,
)

/**
 * Batch-8 (#11) - maps a [GroupFeedPostDto] to the domain [GroupFeedPost]. A post is "locked" when it has a
 * positive unlock price AND the wire says the viewer has not unlocked it (text comes back null in that case).
 */
fun GroupFeedPostDto.toDomain(): GroupFeedPost {
    val price = unlockPriceCents
    val isUnlocked = unlocked ?: true
    return GroupFeedPost(
        postId = postId,
        authorId = userId,
        authorName = userDisplayName?.takeIf { it.isNotBlank() } ?: userId,
        authorAvatarUrl = userAvatarUrl,
        text = text,
        imageUrl = imageUrl,
        imageUrls = imageUrls ?: (imageUrl?.let { listOf(it) } ?: emptyList()),
        videoId = videoId,
        pinned = pinned ?: false,
        locked = price != null && price > 0 && !isUnlocked,
        unlockPriceCents = price,
        tipTotalCents = tipTotalCents ?: 0,
        commentCount = commentCount ?: 0,
        createdAt = createdAt ?: 0,
        poll = poll?.toDomain(),
    )
}

/**
 * Batch-9 (#11) - maps a [GroupCommentDto] to the domain [GroupComment]. A blank display name falls back to
 * the user id (the backend currently echoes the user_id as the display name).
 */
fun GroupCommentDto.toDomain(): GroupComment = GroupComment(
    commentId = commentId,
    postId = postId.orEmpty(),
    authorId = userId,
    authorName = userDisplayName?.takeIf { it.isNotBlank() } ?: userId,
    text = text,
    imageUrl = imageUrl,
    parentCommentId = parentCommentId,
    createdAt = createdAt ?: 0,
)
