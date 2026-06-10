package com.testlogon.android.data.messaging.realtime

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * AND-147 / AND-150 — pure read-receipt reducer tests: delivered/seen derivation from the payload
 * counts, live message:viewed folding, idempotent duplicate viewers, and self-exclusion (FR-6).
 */
class ReceiptReducerTest {

    private fun viewed(messageId: String, viewerId: String, at: Long) =
        MessagingEvent.MessageViewed(
            conversationId = "c1",
            messageId = messageId,
            viewerId = viewerId,
            viewedAtEpochSeconds = at,
        )

    @Test
    fun sentMessage_withNoReceipts_staysSent() {
        val r = ReceiptReducer.derive(
            sendStatus = ReceiptStatus.SENT,
            deliveredToCount = 0, deliveredToUserIds = null,
            readByCount = 0, readByUserIds = null,
        )
        assertEquals(ReceiptStatus.SENT, r.status)
        assertEquals(0, r.seenCount)
    }

    @Test
    fun deliveredDerivedFromPayloadCount() {
        // TC-AND-147-07 — delivered from delivered_to_count, no SSE delivered event needed.
        val r = ReceiptReducer.derive(
            sendStatus = ReceiptStatus.SENT,
            deliveredToCount = 2, deliveredToUserIds = null,
            readByCount = 0, readByUserIds = null,
        )
        assertEquals(ReceiptStatus.DELIVERED, r.status)
        assertEquals(2, r.deliveredCount)
    }

    @Test
    fun seenWinsOverDelivered_whenReadByCountPositive() {
        val r = ReceiptReducer.derive(
            sendStatus = ReceiptStatus.SENT,
            deliveredToCount = 2, deliveredToUserIds = null,
            readByCount = 1, readByUserIds = listOf("u9"),
        )
        assertEquals(ReceiptStatus.SEEN, r.status)
        assertEquals(1, r.seenCount)
    }

    @Test
    fun sendingAndFailed_areNeverDowngradedToSentBySent() {
        val sending = ReceiptReducer.derive(
            ReceiptStatus.SENDING, deliveredToCount = 5, deliveredToUserIds = null,
            readByCount = 0, readByUserIds = null,
        )
        assertEquals(ReceiptStatus.SENDING, sending.status)
        val failed = ReceiptReducer.derive(
            ReceiptStatus.FAILED, deliveredToCount = 5, deliveredToUserIds = null,
            readByCount = 3, readByUserIds = null,
        )
        assertEquals(ReceiptStatus.FAILED, failed.status)
    }

    @Test
    fun applyViewed_addsDistinctViewer_andSetsSeen() {
        // TC-AND-147-03 — live SEEN via a single viewed event.
        val viewers = ReceiptReducer.applyViewed(emptyList(), viewed("m1", "u9", 100), selfUserId = "me")
        assertEquals(1, viewers.size)
        assertEquals("u9", viewers[0].userId)
    }

    @Test
    fun applyViewed_duplicateViewer_isIdempotent_noDoubleCount() {
        // TC-AND-147-04 — a replayed identical event does not add a second roster row.
        var viewers = ReceiptReducer.applyViewed(emptyList(), viewed("m1", "u9", 100), "me")
        viewers = ReceiptReducer.applyViewed(viewers, viewed("m1", "u9", 100), "me")
        assertEquals(1, viewers.size)
        // A distinct second viewer increments to 2.
        viewers = ReceiptReducer.applyViewed(viewers, viewed("m1", "u5", 200), "me")
        assertEquals(2, viewers.size)
    }

    @Test
    fun applyViewed_ignoresSelfEcho() {
        // FR-6 / AC-5 — the local user never appears in their own roster.
        val viewers = ReceiptReducer.applyViewed(emptyList(), viewed("m1", "me", 100), selfUserId = "me")
        assertEquals(0, viewers.size)
    }

    @Test
    fun derive_excludesSelfFromSeen() {
        val r = ReceiptReducer.derive(
            ReceiptStatus.SENT, deliveredToCount = 0, deliveredToUserIds = null,
            readByCount = 0, readByUserIds = listOf("me"),
            viewers = listOf(MessageViewer("me", 1, 1)),
            selfUserId = "me",
        )
        assertEquals(ReceiptStatus.SENT, r.status)
        assertEquals(0, r.seenCount)
        assertEquals(0, r.viewers.size)
    }

    @Test
    fun viewersSortedMostRecentFirst_andFirstSeenIsEarliest() {
        val r = ReceiptReducer.derive(
            ReceiptStatus.SENT, deliveredToCount = 0, deliveredToUserIds = null,
            readByCount = 0, readByUserIds = null,
            viewers = listOf(MessageViewer("a", 100, 1), MessageViewer("b", 300, 1), MessageViewer("c", 200, 1)),
            selfUserId = "me",
        )
        assertEquals(listOf("b", "c", "a"), r.viewers.map { it.userId })
        assertEquals(100L, r.firstSeenAtEpochSeconds)
    }

    @Test
    fun fromRoster_excludesSelf_andSortsNewestFirst() {
        val rows = listOf(MessageViewer("me", 50, 1), MessageViewer("u1", 10, 2), MessageViewer("u2", 90, 1))
        val out = ReceiptReducer.fromRoster(rows, selfUserId = "me")
        assertEquals(listOf("u2", "u1"), out.map { it.userId })
    }

    @Test
    fun noViewers_firstSeenIsNull() {
        val r = ReceiptReducer.derive(
            ReceiptStatus.SENT, deliveredToCount = 1, deliveredToUserIds = null,
            readByCount = 0, readByUserIds = null,
        )
        assertNull(r.firstSeenAtEpochSeconds)
    }
}
