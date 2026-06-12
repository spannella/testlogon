package com.testlogon.android.core.data.call

import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.data.db.TestLogonDatabase
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-302 — [PendingRecordingDao] round-trips on the real [TestLogonDatabase] (in-memory). Instrumented
 * (Room needs an Android runtime). Verifies upsert/getAll/get/observe/delete for the durable upload queue.
 */
@RunWith(AndroidJUnit4::class)
class PendingRecordingDaoTest {

    private lateinit var db: TestLogonDatabase
    private lateinit var dao: PendingRecordingDao

    @Before
    fun setUp() {
        db = Room.inMemoryDatabaseBuilder(
            ApplicationProvider.getApplicationContext(),
            TestLogonDatabase::class.java,
        ).allowMainThreadQueries().build()
        dao = db.pendingRecordingDao()
    }

    @After
    fun tearDown() = db.close()

    private fun row(id: String, createdAt: Long = 1L) = PendingRecordingEntity(
        recordingId = id,
        callId = "c1",
        filePath = "/tmp/$id.mp4",
        sizeBytes = 2048,
        durationMs = 12_500,
        phase = "PendingUpload",
        attempts = 0,
        createdAtEpochMs = createdAt,
    )

    @Test
    fun upsert_get_delete() = runTest {
        dao.upsert(row("rec_1"))
        assertEquals("/tmp/rec_1.mp4", dao.get("rec_1")?.filePath)
        assertEquals("/tmp/rec_1.mp4", dao.observe().first().single().filePath)
        dao.delete("rec_1")
        assertNull(dao.get("rec_1"))
    }

    @Test
    fun upsert_replacesByPrimaryKey() = runTest {
        dao.upsert(row("rec_1"))
        dao.upsert(row("rec_1").copy(phase = "Uploading", attempts = 2))
        assertEquals("Uploading", dao.get("rec_1")?.phase)
        assertEquals(2, dao.get("rec_1")?.attempts)
        assertEquals(1, dao.getAll().size)
    }

    @Test
    fun getAll_ordersByCreatedAtAsc() = runTest {
        dao.upsert(row("rec_b", createdAt = 20))
        dao.upsert(row("rec_a", createdAt = 10))
        assertEquals(listOf("rec_a", "rec_b"), dao.getAll().map { it.recordingId })
    }
}
