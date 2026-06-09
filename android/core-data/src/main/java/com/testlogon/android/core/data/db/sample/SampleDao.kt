package com.testlogon.android.core.data.db.sample

import androidx.room.Dao
import androidx.room.Query
import com.testlogon.android.core.data.db.BaseDao
import kotlinx.coroutines.flow.Flow

/**
 * AND-115 — canonical DAO shape feature DAOs copy: inherits the generic [BaseDao] CRUD surface and
 * adds per-table `getById`/`observeAll`/`clear` (Room cannot generate these generically).
 *
 * Reads return `Flow` so repositories/ViewModels re-render on any table change; `clear()` is the
 * teardown primitive AND-118 relies on for per-user cache wipe.
 */
@Dao
interface SampleDao : BaseDao<CachedSampleEntity> {
    @Query("SELECT * FROM cached_sample WHERE id = :id LIMIT 1")
    fun getById(id: String): Flow<CachedSampleEntity?>

    @Query("SELECT * FROM cached_sample WHERE id = :id LIMIT 1")
    suspend fun getByIdOnce(id: String): CachedSampleEntity?

    @Query("SELECT * FROM cached_sample")
    fun observeAll(): Flow<List<CachedSampleEntity>>

    @Query("DELETE FROM cached_sample")
    suspend fun clear()
}
