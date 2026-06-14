package com.testlogon.android.core.data.db

import androidx.room.Delete
import androidx.room.Upsert

/**
 * AND-115 — generic CRUD surface inherited by every feature DAO.
 *
 * [T] must be a Room `@Entity` implementing [CacheEntity]. `@Upsert` (Room 2.6) gives
 * insert-or-update without a per-DAO conflict strategy. `getById`/`clear` are declared per-DAO
 * (Room cannot generate a generic `@Query` against an unknown table name); see [com.testlogon.android.core.data.db.sample.SampleDao]
 * for the canonical shape feature DAOs copy.
 *
 * All write methods are `suspend` and run off the main thread on Room's executor.
 */
interface BaseDao<T> {
    @Upsert
    suspend fun upsert(item: T)

    @Upsert
    suspend fun upsertAll(items: List<T>)

    @Delete
    suspend fun delete(item: T)
}
