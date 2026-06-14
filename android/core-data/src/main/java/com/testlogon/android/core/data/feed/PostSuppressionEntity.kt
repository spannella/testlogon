package com.testlogon.android.core.data.feed

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * AND-175 — durable record of a post the viewer has hidden or marked "not interested".
 *
 * Stores only the post id, the suppression kind, a creation timestamp, and a pending flag (true until
 * the backend acks the write). No post content / PII is stored. Backed by the shared [TestLogonDatabase]
 * (DB v3); the durable set survives process death so the feed never re-renders a post the user already
 * suppressed before the backend reflects it. See AND-175 §6.
 */
@Entity(tableName = "post_suppression")
data class PostSuppressionEntity(
    @PrimaryKey @ColumnInfo(name = "post_id") val postId: String,
    /** [com.testlogon.android.core.data.feed] consumers map this to PostSuppressionKind.name. */
    @ColumnInfo(name = "kind") val kind: String,
    @ColumnInfo(name = "created_at_epoch_ms") val createdAtEpochMs: Long,
    @ColumnInfo(name = "pending") val pending: Boolean,
)
