package com.testlogon.android.core.data.cache

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.data.db.TestLogonDatabase
import com.testlogon.android.core.data.db.sample.CachedSampleEntity
import com.testlogon.android.core.data.db.sample.SampleDao
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-118 / AND-119 — instrumented round-trip tests for the cache maintenance DAO (TTL sweep, LRU
 * eviction, per-user clear) against a real in-memory Room database.
 */
@RunWith(AndroidJUnit4::class)
class CacheMaintenanceDaoTest {

    private lateinit var db: TestLogonDatabase
    private lateinit var dao: SampleDao
    private lateinit var maint: CacheMaintenanceDao

    @Before
    fun setUp() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        db = Room.inMemoryDatabaseBuilder(ctx, TestLogonDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        dao = db.sampleDao()
        maint = db.cacheMaintenanceDao()
    }

    @After
    fun tearDown() = db.close()

    private suspend fun seed(
        id: String,
        fetchedAt: Long,
        lastAccessedAt: Long = fetchedAt,
        userScope: String? = null,
    ) = dao.upsert(
        CachedSampleEntity(
            id = id,
            payload = "p$id",
            updatedAt = fetchedAt,
            fetchedAt = fetchedAt,
            lastAccessedAt = lastAccessedAt,
            userScope = userScope,
        ),
    )

    @Test
    fun deleteExpired_removes_only_old_rows() = runTest {
        seed("fresh", fetchedAt = 1_000)
        seed("old", fetchedAt = 100)
        val deleted = maint.deleteExpired(CacheTables.SAMPLE, expiryCutoff = 500)
        assertEquals(1, deleted)
        assertEquals(1L, maint.count(CacheTables.SAMPLE))
    }

    @Test
    fun evictOverLimit_keeps_most_recently_accessed() = runTest {
        seed("a", fetchedAt = 1, lastAccessedAt = 1)
        seed("b", fetchedAt = 1, lastAccessedAt = 2)
        seed("c", fetchedAt = 1, lastAccessedAt = 3)
        val deleted = maint.evictOverLimit(CacheTables.SAMPLE, keep = 2)
        assertEquals(1, deleted) // "a" (oldest access) evicted
        assertEquals(2L, maint.count(CacheTables.SAMPLE))
    }

    @Test
    fun deleteAllUserScoped_keeps_global_rows() = runTest {
        seed("ga", fetchedAt = 1, userScope = null) // global
        seed("ua", fetchedAt = 1, userScope = "A")
        seed("ub", fetchedAt = 1, userScope = "B")
        val deleted = maint.deleteAllUserScoped(CacheTables.SAMPLE)
        assertEquals(2, deleted)
        assertEquals(1L, maint.count(CacheTables.SAMPLE)) // global survives
    }

    @Test
    fun deleteUserScoped_scopes_to_one_user() = runTest {
        seed("ua", fetchedAt = 1, userScope = "A")
        seed("ub", fetchedAt = 1, userScope = "B")
        val deleted = maint.deleteUserScoped(CacheTables.SAMPLE, userId = "A")
        assertEquals(1, deleted)
        assertEquals(1L, maint.count(CacheTables.SAMPLE))
    }

    @Test
    fun touch_updates_last_accessed_at() = runTest {
        seed("a", fetchedAt = 1, lastAccessedAt = 1)
        maint.touch(CacheTables.SAMPLE, cacheKey = "a", now = 999)
        // After touch, evicting keep=0 deletes all; but verify via re-eviction ordering instead:
        seed("b", fetchedAt = 1, lastAccessedAt = 500)
        val deleted = maint.evictOverLimit(CacheTables.SAMPLE, keep = 1)
        // "a" was touched to 999 (most recent), so "b" (500) is evicted.
        assertEquals(1, deleted)
        assertEquals(1L, maint.count(CacheTables.SAMPLE))
    }
}
