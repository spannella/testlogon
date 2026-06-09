package com.testlogon.android.core.data.cache

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicLong
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-118 — cache lifecycle operations: TTL sweep, size/LRU eviction, and per-user purge.
 *
 * All ops are `suspend`, run on the IO dispatcher, and are safe to call concurrently (Room's single
 * writer serializes them). Maintenance failures are caught and counted, never propagated to the UI
 * (a failed sweep/evict is retried on the next write).
 *
 * TTL semantics: an entry is FRESH/STALE/EXPIRED per [CachePolicy.freshness] using [clock].now().
 * User-scope isolation: [clearUserCache]/[clearAllUserScopedCache] guarantee account B never sees
 * account A's cached content (the primary AND-118 security goal); hooked into the AND-032 logout
 * flow.
 */
@Singleton
class CacheManager @Inject constructor(
    private val maintenanceDao: CacheMaintenanceDao,
    private val clock: Clock,
) : UserScopedCacheCleaner {

    // IO dispatcher kept as a property (project convention) so the Hilt @Inject constructor needs
    // no CoroutineDispatcher binding. Overridable for tests via the internal secondary constructor.
    private var io: CoroutineDispatcher = Dispatchers.IO

    internal constructor(
        maintenanceDao: CacheMaintenanceDao,
        clock: Clock,
        io: CoroutineDispatcher,
    ) : this(maintenanceDao, clock) {
        this.io = io
    }
    private val hits = AtomicLong(0)
    private val misses = AtomicLong(0)
    private val staleServes = AtomicLong(0)
    private val evicted = AtomicLong(0)
    private val expiredPurged = AtomicLong(0)

    /** Records a cache read hit and bumps the row's `last_accessed_at` (LRU). */
    suspend fun touch(table: String, cacheKey: String): Unit = withContext(io) {
        hits.incrementAndGet()
        runCatching { maintenanceDao.touch(CacheTables.require(table), cacheKey, clock.now()) }
    }

    fun recordMiss() {
        misses.incrementAndGet()
    }

    fun recordStaleServe() {
        staleServes.incrementAndGet()
    }

    /** Deletes EXPIRED rows from [table] (age beyond [policy].ttl). Returns rows purged. */
    suspend fun sweepExpired(table: String, policy: CachePolicy): Int = withContext(io) {
        CacheTables.require(table)
        val cutoff = clock.now() - policy.ttl.inWholeMilliseconds
        val n = runCatching { maintenanceDao.deleteExpired(table, cutoff) }.getOrDefault(0)
        expiredPurged.addAndGet(n.toLong())
        n
    }

    /** Trims [table] to [policy].maxEntries, evicting least-recently-accessed rows first. */
    suspend fun enforceLimits(table: String, policy: CachePolicy): Int = withContext(io) {
        CacheTables.require(table)
        val total = runCatching { maintenanceDao.count(table) }.getOrDefault(0L)
        if (total <= policy.maxEntries) return@withContext 0
        val n = runCatching { maintenanceDao.evictOverLimit(table, policy.maxEntries) }.getOrDefault(0)
        evicted.addAndGet(n.toLong())
        n
    }

    /** App-start TTL purge across every allowlisted cache table. */
    suspend fun sweepAll(): Unit = withContext(io) {
        CacheTables.ALL.forEach { sweepExpired(it, CachePolicies.forTable(it)) }
    }

    /** Deletes all rows owned by [userId] across every cache table (user switch). */
    suspend fun clearUserCache(userId: String): Unit = withContext(io) {
        CacheTables.ALL.forEach { table ->
            runCatching { maintenanceDao.deleteUserScoped(table, userId) }
        }
    }

    /**
     * Deletes every user-scoped row across every cache table; global (`user_scope IS NULL`) rows
     * survive. Called by the AND-032 logout flow.
     */
    override suspend fun clearAllUserScopedCache(): Unit = withContext(io) {
        CacheTables.ALL.forEach { table ->
            runCatching { maintenanceDao.deleteAllUserScoped(table) }
        }
    }

    fun snapshotStats(): CacheStats = CacheStats(
        hits = hits.get(),
        misses = misses.get(),
        staleServes = staleServes.get(),
        evicted = evicted.get(),
        expiredPurged = expiredPurged.get(),
    )
}
