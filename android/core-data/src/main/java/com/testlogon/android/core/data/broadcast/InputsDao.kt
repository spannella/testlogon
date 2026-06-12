package com.testlogon.android.core.data.broadcast

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.Upsert
import kotlinx.coroutines.flow.Flow

/**
 * AND-310 — read/write surface for the broadcast inputs + layout cache on the shared
 * [com.testlogon.android.core.data.db.TestLogonDatabase].
 *
 * [observeBySession] / [observeLayout] back the inputs screen (offline-friendly last-known data).
 * [replaceForSession] atomically swaps the cached set after a fresh GET (delete-then-insert in one
 * [Transaction]) so removed inputs disappear; [upsertAll] / [upsertLayout] write the authoritative
 * refetch results. Rows are keyed by (session_id, input_id) / session_id.
 */
@Dao
interface InputsDao {

    // ── inputs ──────────────────────────────────────────────────────────────────────────────────────

    @Query("SELECT * FROM broadcast_input WHERE session_id = :sessionId ORDER BY position ASC, input_id ASC")
    fun observeBySession(sessionId: String): Flow<List<BroadcastInputEntity>>

    @Query("SELECT * FROM broadcast_input WHERE session_id = :sessionId ORDER BY position ASC, input_id ASC")
    suspend fun getBySession(sessionId: String): List<BroadcastInputEntity>

    @Upsert
    suspend fun upsertAll(rows: List<BroadcastInputEntity>)

    @Query("DELETE FROM broadcast_input WHERE session_id = :sessionId")
    suspend fun deleteForSession(sessionId: String)

    /** Atomically replace the cached input set for [sessionId] (delete then insert in one transaction). */
    @Transaction
    suspend fun replaceForSession(sessionId: String, rows: List<BroadcastInputEntity>) {
        deleteForSession(sessionId)
        upsertAll(rows)
    }

    // ── layout ──────────────────────────────────────────────────────────────────────────────────────

    @Query("SELECT * FROM broadcast_layout WHERE session_id = :sessionId")
    fun observeLayout(sessionId: String): Flow<BroadcastLayoutEntity?>

    @Query("SELECT * FROM broadcast_layout WHERE session_id = :sessionId")
    suspend fun getLayout(sessionId: String): BroadcastLayoutEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertLayout(layout: BroadcastLayoutEntity)
}
