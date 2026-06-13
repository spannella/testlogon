package com.testlogon.android.core.data.respond

import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.data.db.TestLogonDatabase
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-348 — [SessionDraftDao] round-trips on the real [TestLogonDatabase] (in-memory). Instrumented
 * (Room needs an Android runtime). Verifies upsert/getBySlug/observe/setDirty/delete for the durable
 * respondent-session draft (single active session per slug, FR-7).
 */
@RunWith(AndroidJUnit4::class)
class SessionDraftDaoTest {

    private lateinit var db: TestLogonDatabase
    private lateinit var dao: SessionDraftDao

    @Before
    fun setUp() {
        db = Room.inMemoryDatabaseBuilder(
            ApplicationProvider.getApplicationContext(),
            TestLogonDatabase::class.java,
        ).allowMainThreadQueries().build()
        dao = db.sessionDraftDao()
    }

    @After
    fun tearDown() = db.close()

    private fun draftRow(slug: String, dirty: Boolean = true, updatedAt: Long = 1L) = SessionDraftEntity(
        slug = slug,
        sessionId = "rs_$slug",
        questionnaireId = "q1",
        versionId = "v1",
        answersJson = """{"q1":"hi"}""",
        currentSectionIndex = 0,
        currentQuestionId = "q1",
        dirty = dirty,
        updatedAt = updatedAt,
    )

    @Test
    fun upsert_getBySlug_delete() = runTest {
        dao.upsert(draftRow("slug-a"))
        assertEquals("rs_slug-a", dao.getBySlug("slug-a")?.sessionId)
        assertEquals("rs_slug-a", dao.observe("slug-a").first()?.sessionId)
        dao.deleteBySlug("slug-a")
        assertNull(dao.getBySlug("slug-a"))
    }

    @Test
    fun upsert_replacesBySlug_singleActiveSession() = runTest {
        dao.upsert(draftRow("slug-a"))
        dao.upsert(draftRow("slug-a").copy(sessionId = "rs_new", answersJson = """{"q1":"bye"}"""))
        assertEquals("rs_new", dao.getBySlug("slug-a")?.sessionId)
        assertEquals("""{"q1":"bye"}""", dao.getBySlug("slug-a")?.answersJson)
    }

    @Test
    fun setDirty_flipsFlagWithoutTouchingAnswers() = runTest {
        dao.upsert(draftRow("slug-a", dirty = true))
        dao.setDirty("slug-a", dirty = false, updatedAt = 99L)
        val row = dao.getBySlug("slug-a")!!
        assertFalse(row.dirty)
        assertEquals(99L, row.updatedAt)
        // Answers were not rewritten by the dirty flip.
        assertEquals("""{"q1":"hi"}""", row.answersJson)
    }

    @Test
    fun nullableCursor_roundTrips() = runTest {
        dao.upsert(draftRow("slug-a").copy(currentSectionIndex = null, currentQuestionId = null))
        val row = dao.getBySlug("slug-a")!!
        assertNull(row.currentSectionIndex)
        assertNull(row.currentQuestionId)
        assertTrue(row.dirty)
    }
}
