package com.testlogon.android.core.data.cache

import androidx.room.ColumnInfo

/**
 * AND-118 — Room-embeddable cache-lifecycle metadata block.
 *
 * Entities embed it via `@Embedded val meta: CacheMeta` (composition, not inheritance — Room
 * cannot cleanly extend a base entity with columns). The column names match the AND-118 migration
 * so embedding entities and the raw maintenance SQL agree on the schema.
 *
 * @param cacheKey       logical key for the row.
 * @param userScope      owning user id (`user_sub` from /ui/me), or null for global/anonymous data.
 * @param fetchedAt      epoch millis of the last successful network write; basis for TTL.
 * @param lastAccessedAt epoch millis of the last read hit; basis for LRU eviction.
 * @param approxBytes    estimated serialized size, used by the soft byte budget.
 */
data class CacheMeta(
    @ColumnInfo(name = "cache_key") val cacheKey: String,
    @ColumnInfo(name = "user_scope") val userScope: String?,
    @ColumnInfo(name = "fetched_at") val fetchedAt: Long,
    @ColumnInfo(name = "last_accessed_at") val lastAccessedAt: Long,
    @ColumnInfo(name = "approx_bytes") val approxBytes: Int = 0,
)

/** AND-118 — marker exposing [CacheMeta] for generic maintenance. */
interface Cacheable {
    val meta: CacheMeta
}
