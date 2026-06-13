package com.testlogon.android.core.data.privacy

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Upsert
import kotlinx.coroutines.flow.Flow

/**
 * AND-385 - read/write surface for the [ExportRequestEntity] cache.
 *
 * [observeAll] is the single source of truth the repository exposes (newest-first); a network refresh upserts
 * rows so the UI updates reactively. [replaceAll] is a transactional sync of the full list fetched from
 * GET /ui/privacy/requests (rows the server no longer returns are pruned). [clearAll] wipes the cache on
 * sign-out (PII hygiene - the export reference may be a signed URL).
 */
@Dao
interface ExportRequestDao {

    @Query("SELECT * FROM export_requests ORDER BY requested_at DESC")
    fun observeAll(): Flow<List<ExportRequestEntity>>

    @Query("SELECT * FROM export_requests ORDER BY requested_at DESC")
    suspend fun getAll(): List<ExportRequestEntity>

    @Upsert
    suspend fun upsert(entity: ExportRequestEntity)

    @Upsert
    suspend fun upsertAll(entities: List<ExportRequestEntity>)

    @Query("DELETE FROM export_requests")
    suspend fun clearAll()

    @androidx.room.Transaction
    suspend fun replaceAll(entities: List<ExportRequestEntity>) {
        clearAll()
        upsertAll(entities)
    }
}
