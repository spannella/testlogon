package com.testlogon.android.core.data.messaging

import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * AND-141 — DraftDao round-trips, and AND-140 — the hide flag survives an unrelated message upsert
 * (the merge rule from §6/R5). Instrumented (Room needs an Android runtime).
 */
class DraftAndActionsDaoTest {

    private lateinit var db: MessagingDatabase
    private lateinit var draftDao: DraftDao
    private lateinit var messageDao: MessageDao

    @Before
    fun setUp() {
        db = Room.inMemoryDatabaseBuilder(
            ApplicationProvider.getApplicationContext(),
            MessagingDatabase::class.java,
        ).allowMainThreadQueries().build()
        draftDao = db.draftDao()
        messageDao = db.messageDao()
    }

    @After
    fun tearDown() = db.close()

    @Test
    fun draft_upsertGetObserveDelete() = runTest {
        val entity = DraftEntity("c1", "see you at 6", updatedAtEpochMs = 100, version = 1, remoteId = "drf_1", pendingSync = false)
        draftDao.upsert(entity)
        assertEquals("see you at 6", draftDao.get("c1")?.text)
        assertEquals("see you at 6", draftDao.observe("c1").first()?.text)
        draftDao.delete("c1")
        assertNull(draftDao.get("c1"))
        assertNull(draftDao.observe("c1").first())
    }

    @Test
    fun draft_pending_filtersPendingSync() = runTest {
        draftDao.upsert(DraftEntity("c1", "a", 1, 1, null, pendingSync = true))
        draftDao.upsert(DraftEntity("c2", "b", 1, 1, "drf_2", pendingSync = false))
        assertEquals(listOf("c1"), draftDao.pending().map { it.conversationId })
    }

    @Test
    fun setHidden_persists_andSurvivesUnrelatedUpsert() = runTest {
        messageDao.upsert(
            MessageEntity(
                messageId = "m1", conversationId = "c1", senderId = "u1", text = "hi",
                createdAtEpochSeconds = 100, clientId = null,
            ),
        )
        messageDao.setHidden("m1", true)
        assertTrue(messageDao.findById("m1")!!.isHidden)

        // An unrelated upsert that preserves the captured local flag must not clobber it.
        val prior = messageDao.findById("m1")!!
        messageDao.upsert(prior.copy(text = "edited", isHidden = prior.isHidden))
        assertEquals("edited", messageDao.findById("m1")!!.text)
        assertTrue(messageDao.findById("m1")!!.isHidden)
    }

    @Test
    fun setPinned_persists() = runTest {
        messageDao.upsert(
            MessageEntity(
                messageId = "m1", conversationId = "c1", senderId = "u1", text = "hi",
                createdAtEpochSeconds = 100, clientId = null,
            ),
        )
        messageDao.setPinned("m1", true)
        assertTrue(messageDao.findById("m1")!!.isPinned)
        assertEquals(listOf("m1"), messageDao.pinnedForConversation("c1").map { it.messageId })
        messageDao.setPinned("m1", false)
        assertFalse(messageDao.findById("m1")!!.isPinned)
    }
}
