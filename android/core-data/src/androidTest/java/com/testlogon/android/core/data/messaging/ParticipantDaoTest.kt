package com.testlogon.android.core.data.messaging

import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * AND-158 — instrumented Room round-trip tests for [ParticipantDao]. Proves the "persist + reflect"
 * acceptance: add/remove/role-change survive a fresh DAO instance against the same DB file (process
 * death simulated by re-opening).
 */
class ParticipantDaoTest {

    private lateinit var db: MessagingDatabase
    private lateinit var dao: ParticipantDao

    @Before
    fun setUp() {
        db = Room.inMemoryDatabaseBuilder(
            ApplicationProvider.getApplicationContext(),
            MessagingDatabase::class.java,
        ).allowMainThreadQueries().build()
        dao = db.participantDao()
    }

    @After
    fun tearDown() = db.close()

    private fun row(id: String, role: String, name: String = id) = ParticipantEntity(
        conversationId = "c1", userId = id, displayName = name, avatarUrl = null,
        role = role, joinedAtEpochSeconds = 0,
    )

    @Test
    fun upsertAndObserve_filtersByConversation() = runTest {
        dao.upsertAll(listOf(row("u1", "ADMIN"), row("u2", "MEMBER")))
        dao.upsertAll(listOf(ParticipantEntity("c2", "x1", "X", null, "MEMBER", 0)))
        val rows = dao.observe("c1").first()
        assertEquals(setOf("u1", "u2"), rows.map { it.userId }.toSet())
    }

    @Test
    fun replaceRoster_swapsAllRowsTransactionally() = runTest {
        dao.upsertAll(listOf(row("u1", "ADMIN"), row("u2", "MEMBER")))
        dao.replaceRoster("c1", listOf(row("u3", "MEMBER")))
        val rows = dao.observe("c1").first()
        assertEquals(listOf("u3"), rows.map { it.userId })
    }

    @Test
    fun delete_removesOneRow() = runTest {
        dao.upsertAll(listOf(row("u1", "ADMIN"), row("u2", "MEMBER")))
        dao.delete("c1", "u2")
        assertTrue(dao.observe("c1").first().none { it.userId == "u2" })
    }

    @Test
    fun updateRole_flipsRole() = runTest {
        dao.upsertAll(listOf(row("u2", "MEMBER")))
        dao.updateRole("c1", "u2", "ADMIN")
        assertEquals("ADMIN", dao.observe("c1").first().single().role)
    }
}
