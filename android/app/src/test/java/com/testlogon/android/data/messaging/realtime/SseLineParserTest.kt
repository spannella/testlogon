package com.testlogon.android.data.messaging.realtime

import okio.Buffer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * AND-143 — pure SSE line/frame parser tests: frame accumulation, comment/heartbeat handling, and
 * id/retry retention for resume. Fed from an in-memory okio [Buffer] (no socket).
 */
class SseLineParserTest {

    private fun source(text: String) = Buffer().writeUtf8(text)

    private fun framesOf(text: String): List<SseFrame> {
        val parser = SseLineParser()
        val out = mutableListOf<SseFrame>()
        parser.readFrames(source(text)) { out += it; true }
        return out
    }

    @Test
    fun parsesTwoTypedFrames() {
        val frames = framesOf(
            "id:1\nevent:notification\ndata:{\"x\":1}\n\n" +
                "id:2\nevent:notification\ndata:{\"x\":2}\n\n",
        )
        assertEquals(2, frames.size)
        assertEquals(SseFrame("1", "notification", "{\"x\":1}"), frames[0])
        assertEquals(SseFrame("2", "notification", "{\"x\":2}"), frames[1])
    }

    @Test
    fun unnamedFrameDefaultsToMessageEvent() {
        val frames = framesOf("data:hello\n\n")
        assertEquals(1, frames.size)
        assertEquals("message", frames[0].event)
        assertEquals("hello", frames[0].data)
    }

    @Test
    fun commentAndHeartbeatLinesAreNotFrames() {
        // A pure-comment group produces no frame; the socket stays alive.
        val frames = framesOf(": heartbeat\n\n:keep-alive\n\ndata:real\n\n")
        assertEquals(1, frames.size)
        assertEquals("real", frames[0].data)
    }

    @Test
    fun multilineDataIsJoinedWithNewline() {
        val frames = framesOf("data:line1\ndata:line2\n\n")
        assertEquals("line1\nline2", frames[0].data)
    }

    @Test
    fun leadingSpaceInValueIsStripped() {
        val frames = framesOf("event: typed\ndata: value\n\n")
        assertEquals("typed", frames[0].event)
        assertEquals("value", frames[0].data)
    }

    @Test
    fun retainsLastEventIdAcrossFrames() {
        val parser = SseLineParser()
        parser.readFrames(source("id:42\ndata:a\n\ndata:b\n\n")) { true }
        // The id persists past a frame that omits it (per the SSE last-event-id rule).
        assertEquals("42", parser.lastEventId)
    }

    @Test
    fun parsesRetryHintAsMillis() {
        val parser = SseLineParser()
        parser.readFrames(source("retry:3000\ndata:a\n\n")) { true }
        assertEquals(3000L, parser.retryMillis)
    }

    @Test
    fun seedLastEventIdSetsResumeId() {
        val parser = SseLineParser()
        parser.seedLastEventId("prev-7")
        assertEquals("prev-7", parser.lastEventId)
    }

    @Test
    fun emptyIdLineDoesNotClearRetainedId() {
        val parser = SseLineParser()
        parser.readFrames(source("id:9\ndata:a\n\nid:\ndata:b\n\n")) { true }
        assertEquals("9", parser.lastEventId)
    }

    @Test
    fun stopsWhenCallbackReturnsFalse() {
        val parser = SseLineParser()
        var count = 0
        parser.readFrames(source("data:a\n\ndata:b\n\ndata:c\n\n")) { count++; false }
        assertEquals(1, count)
    }

    @Test
    fun noTrailingBlankLineProducesNoFinalFrame() {
        // A frame is only emitted on a blank line; a dangling frame at EOF is not delivered.
        val frames = framesOf("data:partial")
        assertNull(frames.firstOrNull())
    }
}
