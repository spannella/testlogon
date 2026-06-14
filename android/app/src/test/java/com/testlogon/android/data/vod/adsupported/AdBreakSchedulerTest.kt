package com.testlogon.android.data.vod.adsupported

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-194 — pure ad-break scheduling + forward-seek gating (TC-AND-194-04/05). JVM, no Android. */
class AdBreakSchedulerTest {

    private fun br(
        id: String,
        slot: String,
        posSec: Int,
        durSec: Int = 30,
        skipSec: Int = 5,
        completed: Boolean = false,
    ) = AdBreak(
        breakId = id, slotType = slot, positionMs = posSec * 1000L, durationMs = durSec * 1000L,
        creativeId = "c_$id", creativeUrl = "u", creativeType = "video", skipAfterMs = skipSec * 1000L,
        slotIndex = 0, completed = completed,
    )

    private fun scheduler() = AdBreakScheduler(
        listOf(
            br("pre", VodAdSupportedApi.SLOT_PRE_ROLL, 0),
            br("mid1", VodAdSupportedApi.SLOT_MID_ROLL, 900),
            br("mid2", VodAdSupportedApi.SLOT_MID_ROLL, 1800),
            br("ovl", VodAdSupportedApi.SLOT_OVERLAY, 600),
        ),
    )

    @Test
    fun preRoll_returnsPreRollBreak() {
        assertEquals("pre", scheduler().preRoll()?.breakId)
    }

    @Test
    fun breakCrossedBy_returnsCrossedMidRoll() {
        assertEquals("mid1", scheduler().breakCrossedBy(901_000L)?.breakId)
    }

    @Test
    fun forwardSeek_acrossUnwatchedMid_isDisallowed_andBreakDue() {
        val s = scheduler()
        assertFalse(s.isForwardSeekAllowed(0L, 1_000_000L))
        assertEquals("mid1", s.breakDueForSeek(0L, 1_000_000L)?.breakId)
    }

    @Test
    fun watchedMid_doesNotGateForwardSeek() {
        // TC-AND-194-05: a completed break does not gate; backward seek returns null.
        val s = AdBreakScheduler(
            listOf(br("mid1", VodAdSupportedApi.SLOT_MID_ROLL, 900, completed = true)),
        )
        assertTrue(s.isForwardSeekAllowed(0L, 1_000_000L))
        assertNull(s.breakDueForSeek(1_200_000L, 300_000L))
    }

    @Test
    fun markWatched_removesGate() {
        val s = scheduler()
        assertFalse(s.isForwardSeekAllowed(0L, 1_000_000L))
        s.markWatched("mid1")
        // mid2 is at 1800s, beyond the 1000s target -> now allowed.
        assertTrue(s.isForwardSeekAllowed(0L, 1_000_000L))
    }

    @Test
    fun backwardSeek_isAlwaysAllowed_andReturnsNoBreak() {
        val s = scheduler()
        assertTrue(s.isForwardSeekAllowed(2_000_000L, 100_000L))
        assertNull(s.breakDueForSeek(2_000_000L, 100_000L))
    }

    @Test
    fun overlay_doesNotGate() {
        // overlay at 600s never blocks a forward seek across it.
        val s = AdBreakScheduler(listOf(br("ovl", VodAdSupportedApi.SLOT_OVERLAY, 600)))
        assertTrue(s.isForwardSeekAllowed(0L, 700_000L))
    }

    @Test
    fun adBreak_skippability_fromSkipOffset() {
        assertTrue(br("a", VodAdSupportedApi.SLOT_MID_ROLL, 0, durSec = 30, skipSec = 5).isSkippable)
        assertFalse(br("a", VodAdSupportedApi.SLOT_MID_ROLL, 0, durSec = 15, skipSec = 15).isSkippable)
    }
}
