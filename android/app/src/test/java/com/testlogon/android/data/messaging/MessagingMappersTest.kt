package com.testlogon.android.data.messaging

import com.testlogon.android.core.data.messaging.OutboxMessageEntity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-120..124 — pure mapper / merge / sort tests (no Android, no Room runtime). */
class MessagingMappersTest {

    @Test
    fun conversationDto_toDomain_mapsFieldsAndPreviewFallback() {
        val dto = ConversationDto(
            conversationId = "c1",
            title = "Ada",
            icon = "https://x/ada.png",
            createdAt = 100,
            lastMessageAt = 200,
            lastMessagePreview = null,
            unreadCount = 3,
            lastMessage = MessageDto(
                messageId = "m1",
                conversationId = "c1",
                senderId = "u2",
                createdAt = 200,
                kind = "text",
                preview = "hey there",
            ),
        )
        val domain = dto.toDomain()
        assertEquals("c1", domain.id)
        assertEquals("Ada", domain.title)
        assertEquals("https://x/ada.png", domain.iconUrl)
        assertEquals("hey there", domain.lastMessagePreview) // falls back to last_message.preview
        assertEquals(200L, domain.lastActivityEpochSeconds)
        assertEquals(3, domain.unreadCount)
        assertTrue(domain.isUnread)
    }

    @Test
    fun conversationDto_toDomain_fallsBackToCreatedAt_andParticipantName() {
        val dto = ConversationDto(
            conversationId = "c2",
            title = null,
            createdAt = 50,
            lastMessageAt = null,
            participants = listOf(ParticipantDto(userId = "u9", displayName = "Bob")),
        )
        val domain = dto.toDomain()
        assertEquals("Bob", domain.title) // derived from participant when title null
        assertEquals(50L, domain.lastActivityEpochSeconds)
        assertFalse(domain.isUnread)
    }

    @Test
    fun messageDto_toDomain_prefersTextThenPreview() {
        val withText = MessageDto(messageId = "m1", text = "hi", preview = "p").toDomain()
        assertEquals("hi", withText.text)
        assertEquals(SendStatus.SENT, withText.sendStatus)

        val previewOnly = MessageDto(messageId = "m2", text = null, preview = "p").toDomain()
        assertEquals("p", previewOnly.text)
    }

    @Test
    fun sortedNewestFirst_descByActivity_stableIdTieBreak() {
        val rows = listOf(
            conv("b", 200),
            conv("a", 200),
            conv("c", 300),
        )
        val sorted = rows.sortedNewestFirst()
        assertEquals(listOf("c", "a", "b"), sorted.map { it.id })
    }

    @Test
    fun mergeThread_dropsOutboxAlreadyConfirmedByClientId() {
        val history = listOf(
            Message(id = "m1", clientId = "cid-1", conversationId = "c", senderId = "u1", text = "hi", createdAtEpochSeconds = 10),
        )
        val outbox = listOf(
            Message(id = null, clientId = "cid-1", conversationId = "c", senderId = "", text = "hi", createdAtEpochSeconds = 10, sendStatus = SendStatus.SENDING),
            Message(id = null, clientId = "cid-2", conversationId = "c", senderId = "", text = "later", createdAtEpochSeconds = 20, sendStatus = SendStatus.SENDING),
        )
        val merged = mergeThread(history, outbox)
        // The reconciled cid-1 outbox row is dropped; the still-pending cid-2 remains.
        assertEquals(2, merged.size)
        assertEquals(listOf("m1", null), merged.map { it.id })
        assertEquals("later", merged[1].text)
    }

    @Test
    fun outboxEntity_toDomain_parsesStatus() {
        val failed = OutboxMessageEntity(
            clientId = "cid",
            conversationId = "c",
            text = "x",
            createdAtEpochSeconds = 1,
            status = "FAILED",
        ).toDomain()
        assertEquals(SendStatus.FAILED, failed.sendStatus)
        assertEquals("", failed.senderId)
    }

    private fun conv(id: String, activity: Long) = Conversation(
        id = id, title = id, iconUrl = null, lastMessagePreview = null,
        lastActivityEpochSeconds = activity, unreadCount = 0,
    )
}
