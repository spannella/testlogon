package com.testlogon.android.data.messaging.realtime

import com.squareup.moshi.Moshi
import org.junit.Assert.assertEquals
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
        val event = parser.parse("typing:update", """{"conversation_id":"c1","user_id":"u3"}""")
        assertTrue(event is MessagingEvent.Other)
        assertEquals("typing:update", (event as MessagingEvent.Other).type)
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
