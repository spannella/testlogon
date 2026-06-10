package com.testlogon.android.data.messaging

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-136 — pure poll logic: vote cycling, votes-map building, optimistic tally, animation infer. */
class MeetingPollLogicTest {

    private fun poll(myVote: SlotVote? = null): MeetingPoll = MeetingPoll(
        pollId = "p1", title = "t", durationMinutes = 30, creatorId = "u1",
        status = MeetingPollStatus.OPEN, confirmedSlotId = null,
        slots = listOf(
            MeetingPollSlot("slot_1", "2026-06-08T15:00:00Z", "2026-06-08T15:30:00Z", 1, 0, 0, myVote),
            MeetingPollSlot("slot_2", "2026-06-09T21:00:00Z", "2026-06-09T21:30:00Z", 2, 1, 0, SlotVote.MAYBE),
        ),
    )

    @Test
    fun cycle_cyclesYesMaybeNoClear() {
        assertEquals(SlotVote.YES, (null as SlotVote?).cycle())
        assertEquals(SlotVote.MAYBE, SlotVote.YES.cycle())
        assertEquals(SlotVote.NO, SlotVote.MAYBE.cycle())
        assertNull(SlotVote.NO.cycle())
    }

    @Test
    fun buildVotesMap_includesExistingResponses_andUpdatesTargetSlot() {
        val map = buildVotesMap(poll(myVote = SlotVote.YES), slotId = "slot_1", newVote = SlotVote.NO)
        // slot_1 updated to no; slot_2 retains its maybe.
        assertEquals("no", map["slot_1"])
        assertEquals("maybe", map["slot_2"])
    }

    @Test
    fun buildVotesMap_clearOmitsTheSlot() {
        val map = buildVotesMap(poll(myVote = SlotVote.YES), slotId = "slot_1", newVote = null)
        assertFalse(map.containsKey("slot_1"))
        assertEquals("maybe", map["slot_2"]) // other responses preserved
    }

    @Test
    fun applyOptimisticVote_movesCountFromPriorToNew() {
        val before = poll(myVote = SlotVote.YES) // slot_1: yes=1, my=yes
        val after = before.applyOptimisticVote("slot_1", SlotVote.NO)
        val slot = after.slots.first { it.slotId == "slot_1" }
        assertEquals(0, slot.yesCount) // undid the prior yes
        assertEquals(1, slot.noCount) // applied the new no
        assertEquals(SlotVote.NO, slot.myVote)
    }

    @Test
    fun applyOptimisticVote_clearDecrementsPrior() {
        val before = poll(myVote = SlotVote.YES)
        val after = before.applyOptimisticVote("slot_1", null)
        val slot = after.slots.first { it.slotId == "slot_1" }
        assertEquals(0, slot.yesCount)
        assertNull(slot.myVote)
    }

    @Test
    fun applyOptimisticVote_neverGoesNegative() {
        val zeroed = poll().copy(
            slots = listOf(MeetingPollSlot("slot_1", "", "", 0, 0, 0, SlotVote.YES)),
        )
        val after = zeroed.applyOptimisticVote("slot_1", null)
        assertEquals(0, after.slots[0].yesCount)
    }

    @Test
    fun animationInferredFromContentType() {
        assertTrue(isAnimatedContentType("image/gif"))
        assertTrue(isAnimatedContentType("image/webp"))
        assertFalse(isAnimatedContentType("image/png"))
        assertFalse(isAnimatedContentType(null))
    }

    @Test
    fun statusMapping() {
        assertEquals(MeetingPollStatus.CONFIRMED, "confirmed".toPollStatus())
        assertEquals(MeetingPollStatus.CANCELLED, "cancelled".toPollStatus())
        assertEquals(MeetingPollStatus.OPEN, "open".toPollStatus())
        assertEquals(MeetingPollStatus.OPEN, null.toPollStatus())
    }
}
