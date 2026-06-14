package com.testlogon.android.data.messaging.realtime

import com.squareup.moshi.Moshi
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-123 (realtime) — SSE envelope parsing for the REAL stream protocol (typed SSE frames). */
class SseEnvelopeParserTest {

    private val parser = SseEnvelopeParser(Moshi.Builder().build())

    @Test
    fun parsesMessageNew_fromTypedEvent() {
        val event = parser.parse(
            eventType = "message:new",
            dataJson = """{"conversation_id":"c1","message_id":"m1","sender_id":"u2",
                           "kind":"text","text":"hi","created_at":1749126660}""",
        )
        assertTrue(event is MessagingEvent.NewMessage)
        event as MessagingEvent.NewMessage
        assertEquals("c1", event.conversationId)
        assertEquals("m1", event.messageId)
        assertEquals("u2", event.senderId)
        assertEquals("hi", event.text)
        assertEquals(1749126660L, event.createdAtEpochSeconds)
    }

    @Test
    fun fallsBackToTypeInsideData_whenEventFieldBlank() {
        val event = parser.parse(
            eventType = "",
            dataJson = """{"type":"message:new","conversation_id":"c1","message_id":"m2"}""",
        )
        assertTrue(event is MessagingEvent.NewMessage)
        assertEquals("m2", (event as MessagingEvent.NewMessage).messageId)
    }

    @Test
    fun ignoresUntypedMessageEvent() {
        // An untyped "message"-typed frame with no inner type is not actionable.
        assertNull(parser.parse(eventType = "message", dataJson = """{"foo":"bar"}"""))
    }

    @Test
    fun conversationUpdated_isParsed() {
        val event = parser.parse("conversation_updated", """{"conversation_id":"c1"}""")
        assertEquals(MessagingEvent.ConversationUpdated("c1"), event)
    }

    @Test
    fun otherEventTypeCollapsesToOther() {
        // A genuinely-unhandled event type collapses to Other (used to refresh lists).
        val event = parser.parse("poll:vote", """{"conversation_id":"c1","poll_id":"p3"}""")
        assertTrue(event is MessagingEvent.Other)
        assertEquals("poll:vote", (event as MessagingEvent.Other).type)
    }

    // ---- AND-145: presence:update ----

    @Test
    fun parsesPresenceUpdate() {
        val event = parser.parse(
            eventType = "presence:update",
            dataJson = """{"user_id":"u9","online":true,"last_seen_at":1749126670}""",
        )
        assertTrue(event is MessagingEvent.PresenceUpdate)
        event as MessagingEvent.PresenceUpdate
        assertEquals("u9", event.userId)
        assertTrue(event.online)
        assertEquals(1749126670L, event.lastSeenAtEpochSeconds)
    }

    @Test
    fun presenceUpdate_defaultsOfflineAndNullLastSeen_whenAbsent() {
        val event = parser.parse("presence:update", """{"user_id":"u9"}""")
        event as MessagingEvent.PresenceUpdate
        assertEquals(false, event.online)
        assertNull(event.lastSeenAtEpochSeconds)
    }

    @Test
    fun presenceUpdate_missingUserId_returnsNull() {
        assertNull(parser.parse("presence:update", """{"online":true}"""))
    }

    // ---- AND-146: typing:update ----

    @Test
    fun parsesTypingUpdate() {
        val event = parser.parse(
            eventType = "typing:update",
            dataJson = """{"conversation_id":"c1","user_id":"u3","is_typing":true,"updated_at":1717632000}""",
        )
        assertTrue(event is MessagingEvent.Typing)
        event as MessagingEvent.Typing
        assertEquals("c1", event.conversationId)
        assertEquals("u3", event.userId)
        assertTrue(event.isTyping)
        assertEquals(1717632000L, event.updatedAtEpochSeconds)
    }

    @Test
    fun typingUpdate_failsOpenToTrue_whenIsTypingAbsent() {
        val event = parser.parse("typing:update", """{"conversation_id":"c1","user_id":"u3"}""")
        event as MessagingEvent.Typing
        assertTrue(event.isTyping)
        assertEquals(0L, event.updatedAtEpochSeconds)
    }

    @Test
    fun typingUpdate_stopParsesIsTypingFalse() {
        val event = parser.parse(
            "typing:update",
            """{"conversation_id":"c1","user_id":"u3","is_typing":false,"updated_at":5}""",
        )
        event as MessagingEvent.Typing
        assertFalse(event.isTyping)
    }

    // ---- AND-147: message:viewed (read receipt) ----

    @Test
    fun parsesMessageViewed() {
        val event = parser.parse(
            eventType = "message:viewed",
            dataJson = """{"conversation_id":"c1","message_id":"m7","viewer_id":"u9","viewed_at":1749126680}""",
        )
        assertTrue(event is MessagingEvent.MessageViewed)
        event as MessagingEvent.MessageViewed
        assertEquals("c1", event.conversationId)
        assertEquals("m7", event.messageId)
        assertEquals("u9", event.viewerId)
        assertEquals(1749126680L, event.viewedAtEpochSeconds)
    }

    @Test
    fun messageViewed_missingViewerId_returnsNull() {
        assertNull(parser.parse("message:viewed", """{"conversation_id":"c1","message_id":"m7"}"""))
    }

    @Test
    fun messageViewed_defaultsViewedAtToZero_whenAbsent() {
        val event = parser.parse(
            "message:viewed",
            """{"conversation_id":"c1","message_id":"m7","viewer_id":"u9"}""",
        )
        event as MessagingEvent.MessageViewed
        assertEquals(0L, event.viewedAtEpochSeconds)
    }

    @Test
    fun malformedJson_returnsNull() {
        assertNull(parser.parse("message:new", "{not json"))
    }

    @Test
    fun messageNewMissingRequiredFields_returnsNull() {
        // No message_id -> not a usable NewMessage.
        assertNull(parser.parse("message:new", """{"conversation_id":"c1"}"""))
    }
}
