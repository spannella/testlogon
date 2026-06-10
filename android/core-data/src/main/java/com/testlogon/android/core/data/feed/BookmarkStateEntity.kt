package com.testlogon.android.core.data.feed

import androidx.room.ColumnInfo
import androidx.room.Entity

/**
 * AND-176 — durable per-content bookmark state used by the FEED bookmark toggle.
 *
 * Keyed by the composite (content_type, content_id) — the same key the real /ui/bookmarks endpoints use
 * (AND-092). This is the single source of truth for the feed's optimistic bookmark icon: a toggle
 * upserts a row with [pending] = true before the network call and clears it on ack, or deletes it on a
 * hard failure (rollback). It also lets a post already saved elsewhere render as saved in the feed and
 * survives process death (AND-176 FR-4/FR-8). No post content / PII is stored.
 *
 * Backed by the shared [TestLogonDatabase] (DB v4).
 */
@Entity(tableName = "bookmark_state", primaryKeys = ["content_type", "content_id"])
data class BookmarkStateEntity(
    @ColumnInfo(name = "content_type") val contentType: String,
    @ColumnInfo(name = "content_id") val contentId: String,
    @ColumnInfo(name = "collection_id") val collectionId: String?,
    @ColumnInfo(name = "created_at_epoch_ms") val createdAtEpochMs: Long,
    /** True while an add/remove is in flight (not yet acked by the backend). */
    @ColumnInfo(name = "pending") val pending: Boolean,
)
