package com.testlogon.android.data.exchange

import com.testlogon.android.core.network.SettingsStore
import com.testlogon.android.testutil.testMoshi
import okhttp3.OkHttpClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.mockito.Mockito.mock

/**
 * Unit tests for the SSE `data:` frame decoder [ExchangeStream.parseFrame] (the raw-JSON -> [MdFrame]
 * mapping — the [SseLineParser] line/frame state machine is tested separately). Verifies a well-formed
 * `event: md` payload decodes to a Frame with book + latest candle, and that comment/ping/malformed
 * data never throws (yields null so the stream keeps running).
 */
class ExchangeStreamParseTest {

    private val stream = ExchangeStream(
        baseClient = OkHttpClient(),
        settingsStore = mock(SettingsStore::class.java),
        moshi = testMoshi(),
    )

    @Test
    fun wellFormedFrame_parsesBookAndLatestCandle() {
        val data = """
            {"symbol":3,
             "book":{"symbol":3,"bid_px":100,"ask_px":101,"bids":[[100,5]],"asks":[[101,7]]},
             "bars":{"symbol":3,"bars":[
               {"open":1,"high":2,"low":1,"close":2,"volume":10,"trades":3,"ts_start_ns":1700000000000000000},
               {"open":2,"high":4,"low":2,"close":3,"volume":20,"trades":4,"ts_start_ns":1700000000060000000}
             ]}}
        """.trimIndent()
        val frame = stream.parseFrame(data)
        assertNotNull(frame)
        frame!!
        assertEquals(3, frame.orderBook.symbolId)
        assertEquals(100L, frame.orderBook.bestBid)
        assertEquals(101L, frame.orderBook.bestAsk)
        assertEquals(1, frame.orderBook.bids.size)
        // The LATEST bar becomes the live candle.
        assertNotNull(frame.candle)
        assertEquals(3L, frame.candle!!.close)
    }

    @Test
    fun frameWithBookButNoBars_hasNullCandle() {
        val data = """{"symbol":1,"book":{"symbol":1,"bid_px":10,"ask_px":11,"bids":[],"asks":[]}}"""
        val frame = stream.parseFrame(data)
        assertNotNull(frame)
        assertNull(frame!!.candle)
    }

    @Test
    fun frameWithNoOrderBook_yieldsNull() {
        // No `book` -> there is nothing to render; suppress the frame (never crash).
        assertNull(stream.parseFrame("""{"symbol":1,"bars":{"symbol":1,"bars":[]}}"""))
    }

    @Test
    fun malformedJson_doesNotCrashAndYieldsNull() {
        assertNull(stream.parseFrame("not json at all"))
        assertNull(stream.parseFrame(""))
        assertNull(stream.parseFrame("{"))
    }

    @Test
    fun commentOrPingPayload_yieldsNull() {
        // A `:` comment/heartbeat line's residual (or any non-object) must not decode to a frame.
        assertNull(stream.parseFrame(": keep-alive"))
    }
}
