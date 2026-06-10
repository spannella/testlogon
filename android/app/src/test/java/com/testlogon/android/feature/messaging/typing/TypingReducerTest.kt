package com.testlogon.android.feature.messaging.typing

import com.testlogon.android.data.messaging.realtime.MessagingEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-146 — pure typing reducer + label-selection logic. */
class TypingReducerTest {

    private fun typing(conv: String, user: String, isTyping: Boolean) =
        MessagingEvent.Typing(conv, user, isTyping, updatedAtEpochSeconds = 0L)

    @Test
    fun applyTrue_addsWithExpiry_andResolvesName() {
        val out = TypingReducer.apply(
            current = emptyMap(),
            event = typing("c1", "u1", true),
            nowMillis = 1_000,
            ttlMs = 6_000,
            fallbackName = "Someone",
            resolveName = { "Alice" },
        )
        assertEquals(1, out.size)
        assertEquals("Alice", out["u1"]?.displayName)
        assertEquals(7_000L, out["u1"]?.expiresAtMillis)
    }

    @Test
    fun applyTrue_usesFallbackWhenNameUnknown() {
        val out = TypingReducer.apply(emptyMap(), typing("c1", "u1", true), 0, 6_000, "Someone") { null }
        assertEquals("Someone", out["u1"]?.displayName)
    }

    @Test
    fun applyFalse_removesImmediately() {
        val start = TypingReducer.apply(emptyMap(), typing("c1", "u1", true), 0, 6_000, "Someone") { "Alice" }
        val stop = TypingReducer.apply(start, typing("c1", "u1", false), 0, 6_000, "Someone") { "Alice" }
        assertTrue(stop.isEmpty())
    }

    @Test
    fun sweepRemovesExpiredEntries() {
        val m = mapOf(
            "u1" to TypingUiUser("u1", "Alice", expiresAtMillis = 5_000),
            "u2" to TypingUiUser("u2", "Bob", expiresAtMillis = 10_000),
        )
        val swept = TypingReducer.sweepExpired(m, nowMillis = 6_000)
        assertEquals(setOf("u2"), swept.keys)
    }

    @Test
    fun orderedSortsByDisplayName() {
        val m = mapOf(
            "u2" to TypingUiUser("u2", "Bob", 0),
            "u1" to TypingUiUser("u1", "Alice", 0),
        )
        assertEquals(listOf("Alice", "Bob"), TypingReducer.ordered(m).map { it.displayName })
    }

    @Test
    fun labelBranches() {
        assertEquals(TypingLabel.Hidden, TypingLabel.of(emptyList()))
        assertEquals(TypingLabel.One("A"), TypingLabel.of(listOf(TypingUiUser("a", "A", 0))))
        assertEquals(
            TypingLabel.Two("A", "B"),
            TypingLabel.of(listOf(TypingUiUser("a", "A", 0), TypingUiUser("b", "B", 0))),
        )
        assertEquals(
            TypingLabel.Several,
            TypingLabel.of(
                listOf(
                    TypingUiUser("a", "A", 0),
                    TypingUiUser("b", "B", 0),
                    TypingUiUser("c", "C", 0),
                ),
            ),
        )
    }
}
