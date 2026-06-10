package com.testlogon.android.core.data.download

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Upsert
import kotlinx.coroutines.flow.Flow

/**
 * AND-195 — read/write surface for the [DownloadEntity] cache (watermarked VOD downloads).
 *
 * [observe] drives the per-VOD detail download affordance; [completed] backs the "Downloads" list.
 */
@Dao
interface DownloadDao {

    @Query("SELECT * FROM vod_download WHERE video_id = :videoId")
    fun observe(videoId: String): Flow<DownloadEntity?>

    @Query("SELECT * FROM vod_download WHERE video_id = :videoId")
    suspend fun get(videoId: String): DownloadEntity?

    @Query("SELECT * FROM vod_download WHERE status = 'COMPLETED' ORDER BY completed_at_epoch_ms DESC")
    fun completed(): Flow<List<DownloadEntity>>

    @Upsert
    suspend fun upsert(entity: DownloadEntity)

    @Query("DELETE FROM vod_download WHERE video_id = :videoId")
    suspend fun delete(videoId: String)
}
