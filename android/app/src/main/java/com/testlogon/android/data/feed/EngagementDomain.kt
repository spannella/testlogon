package com.testlogon.android.data.feed

/**
 * AND-173 / AND-174 / AND-175 — domain models + mapping for feed content-engagement (framework-free,
 * JVM-unit-test safe). No android.* / java.time(API26) here; timestamps are epoch SECONDS (Long) and
 * relative-time formatting is a UI concern (reuses RelativeTime + parseIsoToEpochSeconds from AND-097).
 */

// ---- Likes (AND-173) ----

/** Confirmed like state for a post: liked flag + count. */
data class LikeState(
    val liked: Boolean,
    val likeCount: Int,
)

// ---- Comments (AND-174) ----

/** A single post comment as consumed by the feature layer. */
data class Comment(
    /** Maps from DTO comment_id; for an optimistic comment this is a generated local id. */
    val id: String,
    val postId: String,
    /** parent_comment_id; null => top-level. */
    val parentId: String?,
    /** Flat author_id (no nested author DTO exists). */
    val authorId: String,
    /** body_plain ?? body; "" when blank/null on the wire. */
    val body: String,
    /** Epoch SECONDS (0 = unknown). */
    val createdAtEpochSeconds: Long,
    /** Non-null => the comment was edited. */
    val updatedAtEpochSeconds: Long?,
    /** deleted => render a "Comment deleted" tombstone. */
    val deleted: Boolean = false,
    val tipTotalCents: Int = 0,
    // ---- rich-comment payloads (null on plain text comments) ----
    /** Remote GIF url when this is a GIF comment (kind == "gif"). */
    val gifUrl: String? = null,
    /** Remote sticker image url when this is a sticker comment (kind == "sticker"). */
    val stickerUrl: String? = null,
    // ---- client-only optimistic flags ----
    /** DERIVED: authorId == current user id (no server field). */
    val canDelete: Boolean = false,
    /** DERIVED: own, non-deleted comment can be edited. */
    val canEdit: Boolean = false,
    /** Optimistic, not yet reconciled. */
    val pending: Boolean = false,
    /** Post failed; show Retry / Discard. */
    val failed: Boolean = false,
    /** Stable diff key; equals [id] for server comments, a UUID for optimistic ones. */
    val localKey: String = id,
)

/** One page of comments + the opaque cursor for the next page (null = terminal). */
data class CommentPage(
    val items: List<Comment>,
    val nextCursor: String?,
)

// ---- Hide / not-interested (AND-175): PostSuppressionKind lives in core-data (Room-adjacent). ----

// ---- Mapping (pure, side-effect free) ----

internal fun CommentPageDto.toDomain(currentUserId: String?): CommentPage = CommentPage(
    items = items.map { it.toDomain(currentUserId) },
    nextCursor = nextCursor,
)

internal fun CommentDto.toDomain(currentUserId: String?): Comment = Comment(
    id = commentId,
    postId = postId,
    parentId = parentCommentId,
    authorId = authorId,
    body = (bodyPlain ?: body).orEmpty(),
    createdAtEpochSeconds = parseIsoToEpochSeconds(createdAt),
    updatedAtEpochSeconds = updatedAt?.let { parseIsoToEpochSeconds(it) }?.takeIf { it > 0L },
    deleted = deleted,
    tipTotalCents = tipTotalCents,
    gifUrl = gifUrl,
    stickerUrl = stickerUrl,
    canDelete = !deleted && authorId.isNotBlank() && authorId == currentUserId,
    canEdit = !deleted && authorId.isNotBlank() && authorId == currentUserId,
    localKey = commentId,
)
