package com.testlogon.android.core.data.cache

import androidx.sqlite.db.SupportSQLiteQuery
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/**
 * AND-118 / AND-119 — JVM unit tests for [CacheManager] decision logic with a fake maintenance DAO
 * and an injected [Clock]. Asserts the SQL the manager issues (cutoff, eviction gating, per-user
 * delegation) and the stats counters — without a real database.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class CacheManagerTest {

    /** Records the raw SQL the manager asks Room to run, and returns canned counts. */
    private class RecordingDao(
        private val countResult: Long = 0,
        private val deleteResult: Int = 0,
    ) : CacheMaintenanceDao() {
        val deletes = mutableListOf<String>()
        val counts = mutableListOf<String>()
        override suspend fun execDelete(query: SupportSQLiteQuery): Int {
            deletes.add(query.sql)
            return deleteResult
        }
        override suspend fun execCount(query: SupportSQLiteQuery): Long {
            counts.add(query.sql)
            return countResult
        }
    }

    private fun fixedClock(now: Long) = Clock { now }

    @Test
    fun `sweepExpired uses now minus ttl as cutoff and counts purged`() = runTest {
        val dao = RecordingDao(deleteResult = 3)
        val mgr = CacheManager(dao, fixedClock(10_000), StandardTestDispatcher(testScheduler))
        val purged = mgr.sweepExpired(CacheTables.SAMPLE, CachePolicy(ttl = 1.seconds))
        assertEquals(3, purged)
        assertEquals(3L, mgr.snapshotStats().expiredPurged)
        assertTrue(dao.deletes.single().contains("DELETE FROM cached_sample WHERE fetched_at < ?"))
    }

    @Test
    fun `enforceLimits does nothing when under cap`() = runTest {
        val dao = RecordingDao(countResult = 5)
        val mgr = CacheManager(dao, fixedClock(0), StandardTestDispatcher(testScheduler))
        val evicted = mgr.enforceLimits(CacheTables.SAMPLE, CachePolicy(ttl = 10.minutes, maxEntries = 10))
        assertEquals(0, evicted)
        assertTrue(dao.deletes.isEmpty()) // count checked, no delete issued
    }

    @Test
    fun `enforceLimits evicts when over cap`() = runTest {
        val dao = RecordingDao(countResult = 12, deleteResult = 2)
        val mgr = CacheManager(dao, fixedClock(0), StandardTestDispatcher(testScheduler))
        val evicted = mgr.enforceLimits(CacheTables.SAMPLE, CachePolicy(ttl = 10.minutes, maxEntries = 10))
        assertEquals(2, evicted)
        assertEquals(2L, mgr.snapshotStats().evicted)
        assertTrue(dao.deletes.single().contains("ORDER BY last_accessed_at DESC LIMIT ?"))
    }

    @Test
    fun `clearAllUserScopedCache deletes user-scoped rows on every table`() = runTest {
        val dao = RecordingDao(deleteResult = 4)
        val mgr = CacheManager(dao, fixedClock(0), StandardTestDispatcher(testScheduler))
        mgr.clearAllUserScopedCache()
        assertEquals(CacheTables.ALL.size, dao.deletes.size)
        assertTrue(dao.deletes.all { it.contains("WHERE user_scope IS NOT NULL") })
    }

    @Test
    fun `clearUserCache scopes by user id`() = runTest {
        val dao = RecordingDao(deleteResult = 1)
        val mgr = CacheManager(dao, fixedClock(0), StandardTestDispatcher(testScheduler))
        mgr.clearUserCache("A")
        assertTrue(dao.deletes.all { it.contains("WHERE user_scope = ?") })
    }

    @Test
    fun `touch records a hit and bumps last_accessed_at`() = runTest {
        val dao = RecordingDao(deleteResult = 1)
        val mgr = CacheManager(dao, fixedClock(42), StandardTestDispatcher(testScheduler))
        mgr.touch(CacheTables.SAMPLE, "k1")
        assertEquals(1L, mgr.snapshotStats().hits)
        assertTrue(dao.deletes.single().contains("UPDATE cached_sample SET last_accessed_at = ?"))
    }
}
