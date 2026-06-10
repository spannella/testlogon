package com.testlogon.android.data.messaging

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-151 / AND-152 — pure JVM tests for search flatten + DTO->domain mappers. */
class MessageSearchTest {

    private fun msg(id: String, text: String?, createdAt: Long, kind: String = "text") = MessageDto(
        messageId = id,
        conversationId = "conv_1",
        senderId = "usr_1",
        createdAt = createdAt,
        kind = kind,
        text = text,
    )

    @Test
    fun flatten_expandsMultipleOccurrencesPerMessage() {
        val dtos = listOf(msg("m1", "deploy then deploy again", createdAt = 100))
        val matches = dtos.toSearchMatches("deploy")
        assertEquals(2, matches.size)
        assertEquals(0, matches[0].occurrenceIndex)
        assertEquals(1, matches[1].occurrenceIndex)
        assertEquals("m1", matches[0].messageId)
    }

    @Test
    fun flatten_sortsByCreatedAtThenIdThenOccurrence() {
        val dtos = listOf(
            msg("m2", "deploy", createdAt = 200),
            msg("m1", "deploy and deploy", createdAt = 100),
        )
        val matches = dtos.toSearchMatches("deploy")
        // m1 (older) first, both occurrences, then m2.
        assertEquals(listOf("m1", "m1", "m2"), matches.map { it.messageId })
        assertEquals(listOf(0, 1, 0), matches.map { it.occurrenceIndex })
    }

    @Test
    fun flatten_dropsNullAndBlankAndNonMatchingText() {
        val dtos = listOf(
            msg("m1", null, createdAt = 100, kind = "image"),
            msg("m2", "", createdAt = 110),
            msg("m3", "nothing relevant here", createdAt = 120),
            msg("m4", "deploy", createdAt = 130),
        )
        val matches = dtos.toSearchMatches("deploy")
        assertEquals(1, matches.size)
        assertEquals("m4", matches[0].messageId)
    }

    @Test
    fun flatten_offsetsIndexIntoOriginalText() {
        val dtos = listOf(msg("m1", "we deploy now", createdAt = 100))
        val matches = dtos.toSearchMatches("deploy")
        assertEquals(1, matches.size)
        assertEquals(3, matches[0].start)
        assertEquals(9, matches[0].end)
        assertEquals("we deploy now", matches[0].text)
    }

    @Test
    fun resultItem_mapperToleratesNullTextAndCarriesFields() {
        val item = msg("m1", null, createdAt = 1746210060, kind = "image").toSearchResultItem()
        assertEquals("m1", item.messageId)
        assertEquals("conv_1", item.conversationId)
        assertEquals("usr_1", item.senderId)
        assertEquals("image", item.kind)
        assertTrue(item.text == null)
        assertEquals(1746210060L, item.createdAtEpochSeconds)
    }
}
