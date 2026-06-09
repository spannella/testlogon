package com.testlogon.android.core.data.cache

/**
 * AND-118 — local, in-memory cache diagnostics counters (no analytics SDK).
 * Exposed for tests and debug logging only.
 */
data class CacheStats(
    val hits: Long = 0,
    val misses: Long = 0,
    val staleServes: Long = 0,
    val evicted: Long = 0,
    val expiredPurged: Long = 0,
)
