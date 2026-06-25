package com.testlogon.android.core.model.groups

/**
 * Batch-8 (#11) - domain model for a GROUP FEED post (GROUP-002).
 *
 * core-model has no Moshi dependency; the DTO -> domain bridge lives in the :app feature (GroupFeedMappers).
 * [text] is null when a locked post has not been unlocked by the viewer. [createdAt] is the raw epoch
 * seconds; the UI relative-formats it. [locked] = there is an unlock price AND the viewer has not unlocked.
 */
data class GroupFeedPost(
    val postId: String,
    val authorId: String,
    val authorName: String,
    val authorAvatarUrl: String? = null,
    val text: String? = null,
    val imageUrl: String? = null,
    val pinned: Boolean = false,
    val locked: Boolean = false,
    val unlockPriceCents: Int? = null,
    val tipTotalCents: Int = 0,
    val commentCount: Int = 0,
    val createdAt: Long = 0,
)
