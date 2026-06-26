package com.testlogon.android.core.network.groups

import com.squareup.moshi.Json

/**
 * Batch-9 (#11) - transport DTOs for GROUP POST COMMENTS (B-GRPFULL #11 backend).
 *
 * CODEGEN NOTE: core-network does NOT apply Moshi KSP codegen, so these decode via the reflective
 * KotlinJsonAdapterFactory on the shared Moshi - every snake_case wire key is pinned with @Json.
 *
 * CONTRACT (verified live on prod, group_feed router):
 *   POST   ui/groups/{groupId}/posts/{postId}/comments {text?, image_url?, parent_comment_id?} -> 201 GroupCommentDto
 *   GET    ui/groups/{groupId}/posts/{postId}/comments?cursor=&limit= -> {comments[], next_cursor}
 *   DELETE ui/groups/{groupId}/posts/{postId}/comments/{commentId} -> {ok, comment_id}
 */

/** Request body for POST a group post comment. At least one of text/image_url must be present (server-validated). */
data class GroupCommentCreateIn(
    @Json(name = "text") val text: String? = null,
    @Json(name = "image_url") val imageUrl: String? = null,
    @Json(name = "parent_comment_id") val parentCommentId: String? = null,
)

/** One group post comment (the _comment_out shape). `created_at` is INTEGER epoch seconds. */
data class GroupCommentDto(
    @Json(name = "comment_id") val commentId: String,
    @Json(name = "post_id") val postId: String? = null,
    @Json(name = "group_id") val groupId: String? = null,
    @Json(name = "user_id") val userId: String,
    @Json(name = "user_display_name") val userDisplayName: String? = null,
    @Json(name = "text") val text: String? = null,
    @Json(name = "image_url") val imageUrl: String? = null,
    @Json(name = "parent_comment_id") val parentCommentId: String? = null,
    @Json(name = "created_at") val createdAt: Long? = 0,
)

/** The comment list page envelope { comments, next_cursor }. A null/blank next_cursor terminates pagination. */
data class GroupCommentListResponse(
    @Json(name = "comments") val comments: List<GroupCommentDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)
