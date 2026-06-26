package com.testlogon.android.core.model.groups

/**
 * Batch-9 (#11) - domain model for a GROUP POST COMMENT (B-GRPFULL #11).
 *
 * core-model has no Moshi dependency; the DTO -> domain bridge lives in the :app feature (GroupMappers).
 * [text] and/or [imageUrl] is present. [parentCommentId] is non-null for a one-level threaded reply.
 * [createdAt] is the raw epoch seconds; the UI relative-formats it.
 */
data class GroupComment(
    val commentId: String,
    val postId: String,
    val authorId: String,
    val authorName: String,
    val text: String? = null,
    val imageUrl: String? = null,
    val parentCommentId: String? = null,
    val createdAt: Long = 0,
)
