package com.testlogon.android.core.data.call

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Upsert
import kotlinx.coroutines.flow.Flow

/**
 * AND-302 — read/write surface for the [PendingRecordingEntity] durable upload queue.
 *
 * [observe] backs the in-call upload-status affordance; [getAll] is read on resume to re-drive any uploads
 * that were in flight when the process died. Rows are deleted on Uploaded/Cancelled.
 */
@Dao
interface PendingRecordingDao {

    @Upsert
    suspend fun upsert(entity: PendingRecordingEntity)

    @Query("SELECT * FROM pending_recording ORDER BY created_at ASC")
    suspend fun getAll(): List<PendingRecordingEntity>

    @Query("SELECT * FROM pending_recording ORDER BY created_at ASC")
    fun observe(): Flow<List<PendingRecordingEntity>>

    @Query("SELECT * FROM pending_recording WHERE recording_id = :recordingId")
    suspend fun get(recordingId: String): PendingRecordingEntity?

    @Query("DELETE FROM pending_recording WHERE recording_id = :recordingId")
    suspend fun delete(recordingId: String)
}
