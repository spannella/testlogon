package com.testlogon.android.core.data.feed

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Upsert
import kotlinx.coroutines.flow.Flow

/**
 * AND-175 — read/write surface for the [PostSuppressionEntity] cache.
 *
 * [observeAll] is the single source of truth for client-side feed filtering (derived into a
 * Set<String> of suppressed ids by the repository). [purgeOlderThan] keeps the table bounded since
 * the backend is the long-term authority and reflects suppression in feed responses.
 */
@Dao
interface PostSuppressionDao {

    @Query("SELECT * FROM post_suppression")
    fun observeAll(): Flow<List<PostSuppressionEntity>>

    @Query("SELECT * FROM post_suppression")
    suspend fun getAll(): List<PostSuppressionEntity>

    @Upsert
    suspend fun upsert(entity: PostSuppressionEntity)

    @Query("UPDATE post_suppression SET pending = :pending WHERE post_id = :postId")
    suspend fun setPending(postId: String, pending: Boolean)

    @Query("DELETE FROM post_suppression WHERE post_id = :postId")
    suspend fun delete(postId: String)

    @Query("DELETE FROM post_suppression WHERE created_at_epoch_ms < :cutoffEpochMs")
    suspend fun purgeOlderThan(cutoffEpochMs: Long)
}
