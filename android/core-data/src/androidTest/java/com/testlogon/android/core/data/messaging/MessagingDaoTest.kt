package com.testlogon.android.core.data.messaging

import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

/** AND-115 — instrumented Room round-trip tests for the messaging cache + outbox DAOs. */
class MessagingDaoTest {

    private lateinit var db: MessagingDatabase
    private lateinit var conversationDao: ConversationDao
    private lateinit var messageDao: MessageDao
    private lateinit var outboxDao: OutboxDao

    @Before
    fun setUp() {
        db = Room.inMemoryDatabaseBuilder(
            ApplicationProvider.getApplicationContext(),
            MessagingDatabase::class.java,
        ).allowMainThreadQueries().build()
        conversationDao = db.conversationDao()
        messageDao = db.messageDao()
        outboxDao = db.outboxDao()
    }

    @After
    fun tearDown() = db.close()

    @Test
    fun conversations_upsertAndObserve_sortedNewestFirst() = runTest {
        conversationDao.upsertAll(
            listOf(
                conversation("c-old", activity = 100),
                conversation("c-new", activity = 300),
            ),
        )
        val rows = conversationDao.observeAll().first()
        assertEquals(listOf("c-new", "c-old"), rows.map { it.conversationId })
    }

    @Test
    fun messages_observeForConversation_oldestFirst() = runTest {
        messageDao.upsertAll(
            listOf(
                message("m2", "c1", createdAt = 200),
                message("m1", "c1", createdAt = 100),
                message("x1", "c2", createdAt = 150),
            ),
        )
        val rows = messageDao.observeForConversation("c1").first()
        assertEquals(listOf("m1", "m2"), rows.map { it.messageId })
    }

    @Test
    fun outbox_upsertObserveDelete() = runTest {
        outboxDao.upsert(outbox("cid-1", status = "SENDING"))
        assertEquals(1, outboxDao.observe("c1").first().size)

        outboxDao.upsert(outbox("cid-1", status = "FAILED", attempt = 1))
        val failed = outboxDao.findById("cid-1")
        assertEquals("FAILED", failed?.status)
        assertEquals(1, failed?.attemptCount)

        outboxDao.delete("cid-1")
        assertNull(outboxDao.findById("cid-1"))
        assertEquals(0, outboxDao.observe("c1").first().size)
    }

    private fun conversation(id: String, activity: Long) = ConversationEntity(
        conversationId = id, title = id, iconUrl = null, lastMessagePreview = null,
        lastActivityEpochSeconds = activity, unreadCount = 0,
    )

    private fun message(id: String, conversationId: String, createdAt: Long) = MessageEntity(
        messageId = id, conversationId = conversationId, senderId = "u1", text = "x",
        createdAtEpochSeconds = createdAt, clientId = null,
    )

    private fun outbox(clientId: String, status: String, attempt: Int = 0) = OutboxMessageEntity(
        clientId = clientId, conversationId = "c1", text = "hi",
        createdAtEpochSeconds = 1, status = status, attemptCount = attempt,
    )
}
