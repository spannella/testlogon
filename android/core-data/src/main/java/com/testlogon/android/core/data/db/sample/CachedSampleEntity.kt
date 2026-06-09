package com.testlogon.android.core.data.db.sample

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.PrimaryKey
import com.testlogon.android.core.data.db.CacheEntity

/**
 * AND-115 — sample/reference cache entity that demonstrates and verifies the [CacheEntity] pattern.
 *
 * This is internal reference scaffolding (and an AND-118 canary for the maintenance DAO + TTL
 * columns), not a shipping feature surface. Real feature entities copy this shape.
 */
@Entity(tableName = "cached_sample")
data class CachedSampleEntity(
    @PrimaryKey override val id: String,
    @ColumnInfo(name = "payload") val payload: String,
    @ColumnInfo(name = "updated_at") override val updatedAt: Long,
    // AND-118 metadata columns (added in DB v2). Defaults make pre-AND-118 callers compile;
    // the AND-118 migration backfills existing rows so they classify as EXPIRED on next read.
    @ColumnInfo(name = "fetched_at", defaultValue = "0") val fetchedAt: Long = 0L,
    @ColumnInfo(name = "last_accessed_at", defaultValue = "0") val lastAccessedAt: Long = 0L,
    @ColumnInfo(name = "user_scope") val userScope: String? = null,
    @ColumnInfo(name = "approx_bytes", defaultValue = "0") val approxBytes: Int = 0,
) : CacheEntity
