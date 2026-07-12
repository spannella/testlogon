package com.testlogon.android.core.network.support

import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.network.json.BigDecimalAdapter
import com.testlogon.android.core.network.json.LenientNumberAdapters
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Helpdesk FAIL #3 / #4 (B-HELP-SHAPE) regression coverage for the support-ticket transport.
 *
 * The bug: when a media item's numeric fields (size_bytes / width / height) came across the wire as JSON
 * STRINGS (a FastAPI Decimal-in-untyped-dict artifact), the generated Moshi adapter for the plainly-typed
 * Long? / Int? fields threw JsonDataException, which empties the WHOLE ticket list (GET /tickets) and breaks
 * the close-ticket {ticket} envelope (POST /tickets/{id}/close) -> "We received an unexpected response".
 *
 * These tests pin the fix: the LenientLong / LenientInt qualifiers + LenientNumberAdapters make those fields
 * tolerate a number, a numeric string, an empty string (-> null) or null, so a media-bearing ticket / close
 * envelope ALWAYS parses. Moshi is built like NetworkModule.provideMoshi (the lenient adapters are registered
 * before the reflective factory). KDoc avoids the comment-terminator pair.
 */
class SupportDtoJsonTest {

    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(LenientNumberAdapters)
        .add(KotlinJsonAdapterFactory())
        .build()

    @Test
    fun mediaItem_withStringifiedNumbers_parsesToNumbers() {
        val adapter = moshi.adapter(SupportTicketMediaDto::class.java)
        val json = """{"kind":"image","url":"https://x/y.jpg",
            "size_bytes":"10","width":"100","height":"50"}"""
        val m = requireNotNull(adapter.fromJson(json))
        assertEquals(10L, m.sizeBytes)
        assertEquals(100, m.width)
        assertEquals(50, m.height)
    }

    @Test
    fun mediaItem_withRealNumbers_stillParses() {
        val adapter = moshi.adapter(SupportTicketMediaDto::class.java)
        val json = """{"kind":"image","size_bytes":2048,"width":640,"height":480}"""
        val m = requireNotNull(adapter.fromJson(json))
        assertEquals(2048L, m.sizeBytes)
        assertEquals(640, m.width)
        assertEquals(480, m.height)
    }

    @Test
    fun mediaItem_withEmptyOrNullNumbers_parsesToNull() {
        val adapter = moshi.adapter(SupportTicketMediaDto::class.java)
        val json = """{"kind":"file","size_bytes":"","width":null}"""
        val m = requireNotNull(adapter.fromJson(json))
        assertNull(m.sizeBytes)
        assertNull(m.width)
        assertNull(m.height)
    }

    @Test
    fun ticketEnvelope_withMediaBearingMessage_stringifiedNumbers_parses() {
        val adapter = moshi.adapter(SupportTicketEnvelope::class.java)
        val json = """{"ticket":{"ticket_id":"t_1","subject":"Help","owner_sub":"u_1",
            "status":"done","created_at":1782828610,"updated_at":1782828700,
            "messages":[{"message_id":"m_1","sender_sub":"u_1","sender_role":"user",
            "body":"see attached","created_at":1782828610,
            "media":[{"kind":"image","url":"https://x/a.png",
            "size_bytes":"10","width":"100","height":"50"}]}]}}"""
        val env = requireNotNull(adapter.fromJson(json))
        assertEquals("t_1", env.ticket.ticketId)
        assertEquals("done", env.ticket.status)
        val media = env.ticket.messages.first().media!!.first()
        assertEquals(10L, media.sizeBytes)
        assertEquals(100, media.width)
    }

    @Test
    fun listEnvelope_withMediaBearingTicket_stringifiedNumbers_parsesAllRows() {
        val adapter = moshi.adapter(SupportTicketListEnvelope::class.java)
        val json = """{"items":[
            {"ticket_id":"t_1","subject":"Plain","owner_sub":"u_1","status":"open",
             "created_at":1,"updated_at":2,"messages":[]},
            {"ticket_id":"t_2","subject":"WithMedia","owner_sub":"u_1","status":"in_progress",
             "created_at":3,"updated_at":4,
             "messages":[{"message_id":"m_2","sender_sub":"u_1","sender_role":"user",
             "body":"x","created_at":3,
             "media":[{"kind":"file","name":"doc.pdf","size_bytes":"123","width":"0","height":"0"}]}]}
            ],"next_cursor":null}"""
        val env = requireNotNull(adapter.fromJson(json))
        assertEquals(2, env.items.size)
        assertEquals(123L, env.items[1].messages.first().media!!.first().sizeBytes)
    }
}
