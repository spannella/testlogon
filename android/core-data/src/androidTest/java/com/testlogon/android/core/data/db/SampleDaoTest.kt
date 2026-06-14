package com.testlogon.android.core.data.db

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.data.db.sample.CachedSampleEntity
import com.testlogon.android.core.data.db.sample.SampleDao
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-115 / AND-119 — instrumented Room DAO round-trip tests. In-memory Room needs an Android
 * runtime, so these run on an emulator/device (NOT in testDebugUnitTest, keeping the JVM suite green
 * without a device).
 */
@RunWith(AndroidJUnit4::class)
class SampleDaoTest {

    private lateinit var db: TestLogonDatabase
    private lateinit var dao: SampleDao

    @Before
    fun setUp() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        db = Room.inMemoryDatabaseBuilder(ctx, TestLogonDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        dao = db.sampleDao()
    }

    @After
    fun tearDown() = db.close()

    @Test
    fun upsert_then_read_round_trips() = runTest {
        val row = CachedSampleEntity(id = "k1", payload = "hello", updatedAt = 42L)
        dao.upsert(row)
        assertEquals(row, dao.getById("k1").first())
    }

    @Test
    fun upsert_updates_existing_row() = runTest {
        dao.upsert(CachedSampleEntity("k1", "v1", 1L))
        dao.upsert(CachedSampleEntity("k1", "v2", 2L))
        val r = dao.getById("k1").first()!!
        assertEquals("v2", r.payload)
        assertEquals(2L, r.updatedAt)
        assertEquals(1, dao.observeAll().first().size)
    }

    @Test
    fun clear_empties_table() = runTest {
        dao.upsert(CachedSampleEntity("k1", "v", 1L))
        dao.clear()
        assertTrue(dao.observeAll().first().isEmpty())
    }
}
