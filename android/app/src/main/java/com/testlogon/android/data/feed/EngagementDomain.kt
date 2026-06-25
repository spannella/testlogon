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

// ---- Reactions (#20 / #23) — full emoji reactions on posts AND comments. ----

/** Curated reaction emoji bar; MUST match the backend allowlist (newsfeed ALLOWED_REACTION_EMOJIS). */
val REACTION_EMOJIS: List<String> = listOf("👍", "❤️", "😂", "🔥", "😮")

/** One emoji's reaction tally + whether the viewer picked it. */
data class ReactionTally(
    val emoji: String,
    val count: Int,
    val reactedByMe: Boolean,
)

/**
 * Builds the display chip list (only non-zero counts, ordered by [REACTION_EMOJIS]) from the wire
 * `reactions_counts` + `my_reactions`.
 */
internal fun reactionTallies(
    counts: Map<String, Int>?,
    mine: List<String>?,
): List<ReactionTally> {
    if (counts.isNullOrEmpty()) return emptyList()
    val mineSet = mine.orEmpty().toSet()
    return REACTION_EMOJIS.mapNotNull { e ->
        val c = counts[e] ?: 0
        if (c > 0) ReactionTally(emoji = e, count = c, reactedByMe = e in mineSet) else null
    }
}

/** Apply an optimistic toggle of [emoji] to a tally list (used before the server confirms). */
fun List<ReactionTally>.toggledReaction(emoji: String): List<ReactionTally> {
    val existing = firstOrNull { it.emoji == emoji }
    val out = toMutableList()
    if (existing != null && existing.reactedByMe) {
        // Remove my reaction.
        val newCount = (existing.count - 1).coerceAtLeast(0)
        if (newCount == 0) out.removeAll { it.emoji == emoji }
        else out[out.indexOfFirst { it.emoji == emoji }] = existing.copy(count = newCount, reactedByMe = false)
    } else if (existing != null) {
        out[out.indexOfFirst { it.emoji == emoji }] = existing.copy(count = existing.count + 1, reactedByMe = true)
    } else {
        out.add(ReactionTally(emoji = emoji, count = 1, reactedByMe = true))
    }
    // Keep canonical order.
    return REACTION_EMOJIS.mapNotNull { e -> out.firstOrNull { it.emoji == e } }
}

/** Whether the viewer currently reacts with [emoji] in this tally list. */
fun List<ReactionTally>.reactedByMe(emoji: String): Boolean =
    firstOrNull { it.emoji == emoji }?.reactedByMe == true

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
    /** Uploaded image url when this is an image comment (kind == "image"). #24 */
    val imageUrl: String? = null,
    /** #23 — emoji reaction tallies for this comment (empty when none). */
    val reactions: List<ReactionTally> = emptyList(),
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
    imageUrl = imageUrl,
    reactions = reactionTallies(reactionsCounts, myReactions),
    canDelete = !deleted && authorId.isNotBlank() && authorId == currentUserId,
    canEdit = !deleted && authorId.isNotBlank() && authorId == currentUserId,
    localKey = commentId,
)
