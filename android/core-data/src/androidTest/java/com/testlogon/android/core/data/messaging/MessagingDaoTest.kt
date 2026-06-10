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

    @Test
    fun conversations_clearUnread_andAggregateUnreadCount() = runTest {
        conversationDao.upsertAll(
            listOf(
                conversation("c1", activity = 100, unread = 3),
                conversation("c2", activity = 200, unread = 1),
                conversation("c3", activity = 300, unread = 0),
            ),
        )
        assertEquals(2, conversationDao.observeUnreadConversationCount().first())

        conversationDao.clearUnread("c1")
        assertEquals(0, conversationDao.findById("c1")?.unreadCount)
        // AND-125: aggregate recomputes reactively (2 unread -> 1 after clearing c1).
        assertEquals(1, conversationDao.observeUnreadConversationCount().first())
    }

    @Test
    fun messages_monetizationAndCountdownColumns_roundTrip() = runTest {
        // AND-137/138/139 (DB v5) — new countdown/calendar/monetization columns persist.
        messageDao.upsert(
            MessageEntity(
                messageId = "cd1", conversationId = "c1", senderId = "u1", text = "",
                createdAtEpochSeconds = 1, clientId = null, kind = "countdown",
                countdownTitle = "Launch", countdownTargetEpochSeconds = 1780000000,
                countdownEventType = "custom",
            ),
        )
        messageDao.upsert(
            MessageEntity(
                messageId = "paid1", conversationId = "c1", senderId = "u2", text = "",
                createdAtEpochSeconds = 2, clientId = null, kind = "text",
                monetizationType = "FIXED", monetizationUnlocked = false,
                lockPriceCents = 500, lockCurrency = "USD", lockTeaser = "preview",
            ),
        )
        val cd = messageDao.findById("cd1")
        assertEquals(1780000000L, cd?.countdownTargetEpochSeconds)
        assertEquals("Launch", cd?.countdownTitle)
        val paid = messageDao.findById("paid1")
        assertEquals("FIXED", paid?.monetizationType)
        assertEquals(500L, paid?.lockPriceCents)
        assertEquals("preview", paid?.lockTeaser)
        assertEquals(false, paid?.monetizationUnlocked)
    }

    private fun conversation(id: String, activity: Long, unread: Int = 0) = ConversationEntity(
        conversationId = id, title = id, iconUrl = null, lastMessagePreview = null,
        lastActivityEpochSeconds = activity, unreadCount = unread,
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
