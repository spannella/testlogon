package com.testlogon.android.core.data.broadcast

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
 * AND-310 — [InputsDao] round-trips on the real [TestLogonDatabase] (in-memory). Instrumented (Room needs
 * an Android runtime). Verifies (session_id, input_id) keying, atomic replaceForSession, observe emission
 * on change, and layout upsert/observe (incl. the input_ids TypeConverter round-trip).
 */
@RunWith(AndroidJUnit4::class)
class InputsDaoTest {

    private lateinit var db: TestLogonDatabase
    private lateinit var dao: InputsDao

    @Before
    fun setUp() {
        db = Room.inMemoryDatabaseBuilder(
            ApplicationProvider.getApplicationContext(),
            TestLogonDatabase::class.java,
        ).allowMainThreadQueries().build()
        dao = db.inputsDao()
    }

    @After
    fun tearDown() = db.close()

    private fun input(session: String, id: String, position: Int = 0, isLive: Boolean = false) =
        BroadcastInputEntity(
            sessionId = session,
            inputId = id,
            inputType = "guest",
            label = "Input $id",
            isLive = isLive,
            position = position,
            createdBy = "host",
        )

    @Test
    fun upsert_keyedBySessionAndInput() = runTest {
        dao.upsertAll(listOf(input("s1", "a"), input("s1", "b")))
        // Same input_id under a DIFFERENT session is a distinct row (composite key).
        dao.upsertAll(listOf(input("s2", "a")))
        assertEquals(2, dao.getBySession("s1").size)
        assertEquals(1, dao.getBySession("s2").size)

        // Upsert replaces by composite key.
        dao.upsertAll(listOf(input("s1", "a", isLive = true)))
        assertEquals(true, dao.getBySession("s1").first { it.inputId == "a" }.isLive)
        assertEquals(2, dao.getBySession("s1").size)
    }

    @Test
    fun replaceForSession_atomicallySwapsSet() = runTest {
        dao.upsertAll(listOf(input("s1", "a"), input("s1", "b")))
        dao.replaceForSession("s1", listOf(input("s1", "c")))
        assertEquals(listOf("c"), dao.getBySession("s1").map { it.inputId })
    }

    @Test
    fun observe_emitsOnChange() = runTest {
        dao.upsertAll(listOf(input("s1", "a")))
        assertEquals(listOf("a"), dao.observeBySession("s1").first().map { it.inputId })
        dao.upsertAll(listOf(input("s1", "b", position = 1)))
        assertEquals(listOf("a", "b"), dao.observeBySession("s1").first().map { it.inputId })
    }

    @Test
    fun layout_upsertAndObserve_roundTripsInputIds() = runTest {
        assertNull(dao.observeLayout("s1").first())
        dao.upsertLayout(
            BroadcastLayoutEntity(
                sessionId = "s1",
                mode = "single",
                primaryInputId = "a",
                inputIds = listOf("a", "b", "c"),
            ),
        )
        val cached = dao.observeLayout("s1").first()
        assertEquals("single", cached?.mode)
        assertEquals("a", cached?.primaryInputId)
        assertEquals(listOf("a", "b", "c"), cached?.inputIds)

        // Upsert (REPLACE) overwrites the same session row.
        dao.upsertLayout(
            BroadcastLayoutEntity(sessionId = "s1", mode = "grid", primaryInputId = null, inputIds = emptyList()),
        )
        val updated = dao.getLayout("s1")
        assertEquals("grid", updated?.mode)
        assertNull(updated?.primaryInputId)
        assertEquals(emptyList<String>(), updated?.inputIds)
    }
}
