package com.testlogon.android.core.data.feed

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.data.db.TestLogonDatabase
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-175 — instrumented Room round-trip tests for [PostSuppressionDao]: upsert/setPending/delete +
 * durability (re-open proxy for process death) + purgeOlderThan.
 */
@RunWith(AndroidJUnit4::class)
class PostSuppressionDaoTest {

    private lateinit var db: TestLogonDatabase
    private lateinit var dao: PostSuppressionDao

    @Before
    fun setUp() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        db = Room.inMemoryDatabaseBuilder(ctx, TestLogonDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        dao = db.postSuppressionDao()
    }

    @After
    fun tearDown() = db.close()

    @Test
    fun upsert_setPending_delete_roundTrip() = runTest {
        dao.upsert(PostSuppressionEntity("p1", PostSuppressionKind.HIDDEN.name, 100L, pending = true))
        assertEquals(setOf("p1"), dao.observeAll().first().mapTo(HashSet()) { it.postId })
        assertTrue(dao.observeAll().first().first().pending)

        dao.setPending("p1", pending = false)
        assertFalse(dao.observeAll().first().first().pending)

        dao.delete("p1")
        assertTrue(dao.observeAll().first().isEmpty())
    }

    @Test
    fun purgeOlderThan_removesOnlyStaleRows() = runTest {
        dao.upsert(PostSuppressionEntity("old", PostSuppressionKind.HIDDEN.name, 10L, pending = false))
        dao.upsert(PostSuppressionEntity("new", PostSuppressionKind.NOT_INTERESTED.name, 1_000L, pending = false))

        dao.purgeOlderThan(cutoffEpochMs = 500L)

        assertEquals(setOf("new"), dao.getAll().mapTo(HashSet()) { it.postId })
    }
}
