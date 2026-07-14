package com.testlogon.android.core.data.feed

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Upsert
import kotlinx.coroutines.flow.Flow

/**
 * AND-176 — read/write surface for the [BookmarkStateEntity] cache (feed / player bookmark toggle).
 *
 * [observeIds] is the single source of truth for the per-post saved icon (derived into a Set<String> of
 * saved content ids by the repository). [observeIdsForType] scopes that to one content_type so the feed
 * ("post") and the clips player ("video") never leak ids into each other (P0-consumer/bookmarks).
 * Optimistic toggles upsert/delete rows; the durable set survives scroll/recycle and process death
 * (AND-176 FR-4/FR-8).
 */
@Dao
interface BookmarkStateDao {

    /** All saved content ids (any type). Retained for callers that don't care about the type. */
    @Query("SELECT content_id FROM bookmark_state")
    fun observeIds(): Flow<List<String>>

    /** Saved content ids of a single [type] (e.g. "post" or "video"). */
    @Query("SELECT content_id FROM bookmark_state WHERE content_type = :type")
    fun observeIdsForType(type: String): Flow<List<String>>

    @Query("SELECT EXISTS(SELECT 1 FROM bookmark_state WHERE content_type = :type AND content_id = :id)")
    fun isBookmarked(type: String, id: String): Flow<Boolean>

    @Query("SELECT * FROM bookmark_state WHERE content_type = :type AND content_id = :id")
    suspend fun find(type: String, id: String): BookmarkStateEntity?

    @Upsert
    suspend fun upsert(entity: BookmarkStateEntity)

    @Query("UPDATE bookmark_state SET pending = :pending WHERE content_type = :type AND content_id = :id")
    suspend fun setPending(type: String, id: String, pending: Boolean)

    @Query("DELETE FROM bookmark_state WHERE content_type = :type AND content_id = :id")
    suspend fun delete(type: String, id: String)
}
