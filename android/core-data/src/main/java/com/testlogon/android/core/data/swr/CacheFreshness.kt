package com.testlogon.android.core.data.swr

/**
 * AND-116 — SWR freshness window defaults. Pure logic, JVM-unit-testable.
 *
 * 60s default is a heuristic for the flaky dev host; per-repository TTLs override it (and AND-118's
 * [com.testlogon.android.core.data.cache.CachePolicy] owns the richer per-table FRESH/STALE/EXPIRED
 * model). This helper is the simple binary "is the cache fresh enough to skip the network?" gate
 * used by [SwrRepository.isFresh].
 */
object CachePolicyDefaults {
    const val DEFAULT_TTL_MS: Long = 60_000L
}

/**
 * Returns true when [fetchedAt] (epoch millis) is within [ttlMs] of [now] (epoch millis).
 * A null [fetchedAt] is never fresh. Boundary is exclusive: `age == ttlMs` is NOT fresh.
 */
fun isFresh(fetchedAt: Long?, now: Long, ttlMs: Long = CachePolicyDefaults.DEFAULT_TTL_MS): Boolean =
    fetchedAt != null && (now - fetchedAt) < ttlMs
