package com.testlogon.android.data.messaging.realtime

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-148 / AND-150 — pure reconcile core tests: de-dup, ordering, live insert, idempotent replay,
 * resume-cursor derivation, and reconnect gap detection. Embodies the ticket's hard guarantee — no
 * duplicate rows and no gaps across a reconnect (AC-1/AC-2/AC-3).
 */
class MessageReconcilerTest {

    private fun row(id: String, t: Long) = MessageReconciler.Row(id, t)

    @Test
    fun merge_dedupesById_lastWriterWins() {
        // TC-AND-150-01 / FR-2 — same id N times -> one row, contents from the last write.
        val existing = listOf(row("m1", 10), row("m2", 20))
        val incoming = listOf(row("m1", 99), row("m1", 11)) // updated created_at
        val out = MessageReconciler.merge(existing, incoming)
        assertEquals(2, out.size)
        assertEquals(1, out.count { it.id == "m1" })
    }

    @Test
    fun merge_ordersByCreatedAtThenId() {
        // TC-AND-150-04 / FR-3 — strict (createdAt, id) ascending under shuffled arrival.
        val out = MessageReconciler.merge(
            emptyList(),
            listOf(row("c", 3), row("a", 1), row("b", 2), row("a2", 1)),
        )
        assertEquals(listOf("a", "a2", "b", "c"), out.map { it.id })
    }

    @Test
    fun merge_isIdempotent_replayYieldsSameList() {
        // TC-AND-150-02 / FR-7/FR-8 — replaying overlap leaves the cache identical.
        val base = MessageReconciler.merge(emptyList(), listOf(row("m1", 1), row("m2", 2)))
        val once = MessageReconciler.merge(base, listOf(row("m3", 3)))
        val twice = MessageReconciler.merge(once, listOf(row("m1", 1), row("m2", 2), row("m3", 3)))
        assertEquals(once, twice)
        assertEquals(listOf("m1", "m2", "m3"), twice.map { it.id })
    }

    @Test
    fun merge_liveInsertAtHead_withoutReload() {
        // FR-4 — a newer live event surfaces at the tail (newest) without losing the snapshot.
        val snapshot = MessageReconciler.merge(emptyList(), (1..5).map { row("m$it", it.toLong()) })
        val merged = MessageReconciler.merge(snapshot, listOf(row("m6", 6)))
        assertEquals("m6", merged.last().id)
        assertEquals(6, merged.size)
    }

    @Test
    fun merge_lateEvent_landsInSortedPosition_notAtTop() {
        // FR-5 — an older late event sorts into place rather than jumping to the head.
        val snapshot = MessageReconciler.merge(emptyList(), listOf(row("m1", 1), row("m3", 3)))
        val merged = MessageReconciler.merge(snapshot, listOf(row("m2", 2)))
        assertEquals(listOf("m1", "m2", "m3"), merged.map { it.id })
    }

    @Test
    fun resumeCursor_isNewestKnownId() {
        val rows = listOf(row("m1", 1), row("m3", 3), row("m2", 2))
        assertEquals("m3", MessageReconciler.resumeCursor(rows))
        assertNull(MessageReconciler.resumeCursor(emptyList()))
    }

    @Test
    fun needsBackfill_falseOnColdStart() {
        assertFalse(MessageReconciler.needsBackfill(emptySet(), listOf("m1")))
    }

    @Test
    fun needsBackfill_falseWhenReconnectOverlapsKnown() {
        // Lossless: a resumed id we already hold proves the tail is contiguous.
        assertFalse(MessageReconciler.needsBackfill(setOf("m1", "m2"), listOf("m2", "m3")))
    }

    @Test
    fun needsBackfill_trueWhenNoOverlap() {
        // Lossy: nothing resumed was known -> a gap may exist -> backfill (TC-AND-150-03 / FR-2/FR-6).
        assertTrue(MessageReconciler.needsBackfill(setOf("m1", "m2"), listOf("m5", "m6")))
    }

    @Test
    fun needsBackfill_falseWhenNothingResumed() {
        assertFalse(MessageReconciler.needsBackfill(setOf("m1"), emptyList()))
    }

    @Test
    fun acceptance_reconnect_noDupNoGap() {
        // TC-AND-148-13 (scaled) — snapshot 1..100, live to 150, lossy reconnect, backfill 151..200.
        val snapshot = (1..100).map { row("m$it", it.toLong()) }
        var cache = MessageReconciler.merge(emptyList(), snapshot)
        val live = (101..150).map { row("m$it", it.toLong()) }
        cache = MessageReconciler.merge(cache, live)
        // Lossy reconnect resumes at 200 with no overlap -> backfill the missing window.
        val resumed = listOf(row("m200", 200))
        assertTrue(MessageReconciler.needsBackfill(cache.map { it.id }.toSet(), resumed.map { it.id }))
        val backfill = (151..200).map { row("m$it", it.toLong()) }
        cache = MessageReconciler.merge(cache, backfill + resumed)
        // Exactly 1..200, each id once, strictly ordered.
        assertEquals(200, cache.size)
        assertEquals(200, cache.map { it.id }.toSet().size)
        assertEquals((1..200).map { "m$it" }, cache.map { it.id })
    }
}
