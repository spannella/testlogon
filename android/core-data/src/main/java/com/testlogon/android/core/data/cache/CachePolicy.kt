package com.testlogon.android.core.data.cache

import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes

/** AND-118 — classification of a cached entry's age against its [CachePolicy]. */
enum class Freshness { FRESH, STALE, EXPIRED }

/**
 * AND-118 — per-table cache lifecycle policy.
 *
 * @param ttl          fresh+stale window; an entry older than this is [Freshness.EXPIRED].
 * @param staleAfter   optional separate stale threshold; defaults to [ttl] (empty STALE band).
 *                     When `staleAfter < ttl`, entries transition FRESH -> STALE -> EXPIRED.
 * @param maxEntries   hard cap on row count per table (LRU eviction trims to this).
 * @param maxApproxBytes soft cap on approximate stored bytes per table.
 *
 * This is pure logic (no Room, no Android), so [freshness] is directly JVM-unit-testable.
 */
data class CachePolicy(
    val ttl: Duration,
    val staleAfter: Duration = ttl,
    val maxEntries: Int = 500,
    val maxApproxBytes: Long = 4L * 1024 * 1024, // 4 MiB
) {
    /**
     * Classifies [fetchedAt] (epoch millis) against [now] (epoch millis).
     *
     * Clock-skew fail-safe: a negative age (device clock moved backward; `now < fetchedAt`) is
     * treated as [Freshness.FRESH] — never crashes, never reports something as more expired than
     * reality.
     */
    fun freshness(fetchedAt: Long, now: Long): Freshness {
        val age = (now - fetchedAt).milliseconds
        return when {
            age < staleAfter -> Freshness.FRESH
            age < ttl -> Freshness.STALE
            else -> Freshness.EXPIRED
        }
    }
}

/**
 * AND-118 — per-table policy registry. Table names are the compile-time [CacheTables] allowlist;
 * unknown tables fall back to [DEFAULT].
 */
object CachePolicies {
    val DEFAULT = CachePolicy(ttl = 15.minutes)
    val LISTS = CachePolicy(ttl = 5.minutes, staleAfter = 1.minutes, maxEntries = 1000)
    val DETAIL = CachePolicy(ttl = 30.minutes, staleAfter = 5.minutes, maxEntries = 300)

    private val registry: Map<String, CachePolicy> = mapOf(
        CacheTables.SAMPLE to DEFAULT,
    )

    fun forTable(table: String): CachePolicy = registry[table] ?: DEFAULT
}
