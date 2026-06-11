package com.testlogon.android.data.broadcast.chat

import com.squareup.moshi.Moshi
import com.testlogon.android.data.messaging.realtime.SseFrame
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-281 — colon-delimited event-name parsing; bad/unknown frames map to Unknown (never throw). */
class ChatEventParserTest {

    private val parser = ChatEventParser(Moshi.Builder().build())

    private fun frame(event: String, data: String) = SseFrame(id = null, event = event, data = data)

    @Test
    fun chatMessage_parsesToMessageReceived() {
        val data = """
            {"message_id":"cm1","session_id":"s1","sender_id":"u9","sender_display_name":"Mira",
             "text":"hello!","kind":"text","created_at":1749164470,"deleted":false,
             "reactions_counts":{"🔥":3},"my_reactions":[]}
        """.trimIndent()
        val result = parser.parse(frame("chat:message", data), selfId = "u9")
        assertTrue(result is ChatStreamEvent.MessageReceived)
        val msg = (result as ChatStreamEvent.MessageReceived).message
        assertEquals("cm1", msg.id)
        assertEquals("Mira", msg.senderDisplayName)
        assertEquals(1749164470L, msg.createdAtEpochSeconds)
        assertTrue(msg.isSelf) // sender == selfId
        assertEquals(1, msg.reactions.size)
        assertEquals(3, msg.reactions.single().count)
    }

    @Test
    fun chatReaction_parsesCounts() {
        val result = parser.parse(
            frame("chat:reaction", """{"message_id":"cm1","counts":{"🔥":12,"❤️":4}}"""),
            selfId = null,
        )
        assertTrue(result is ChatStreamEvent.ReactionUpdated)
        val r = result as ChatStreamEvent.ReactionUpdated
        assertEquals("cm1", r.messageId)
        assertEquals(12, r.counts["🔥"])
    }

    @Test
    fun chatDelete_parsesMessageId() {
        val result = parser.parse(frame("chat:delete", """{"message_id":"cm1"}"""), selfId = null)
        assertEquals("cm1", (result as ChatStreamEvent.MessageDeleted).messageId)
    }

    @Test
    fun chatUnlock_parsesText() {
        val result = parser.parse(
            frame("chat:unlock", """{"message_id":"cm1","text":"revealed"}"""),
            selfId = null,
        )
        val u = result as ChatStreamEvent.MessageUnlocked
        assertEquals("cm1", u.messageId)
        assertEquals("revealed", u.text)
    }

    @Test
    fun unknownEvent_mapsToUnknown() {
        assertEquals(ChatStreamEvent.Unknown, parser.parse(frame("chat:typing", "{}"), null))
    }

    @Test
    fun malformedData_mapsToUnknown_noThrow() {
        assertEquals(ChatStreamEvent.Unknown, parser.parse(frame("chat:message", "{not json"), null))
    }
}
