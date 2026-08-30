package com.testlogon.android.feature.messaging

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * FE-120 (EPIC C) — pure JVM tests for the reveal-at math + TLRVL1 sentinel codec. No Android types;
 * `nowSec` is always supplied so the logic is deterministic.
 */
class RevealAtMathTest {

    private val now = 1_000_000L

    // ---- isRevealLocked ----

    @Test
    fun sender_is_never_locked() {
        assertFalse(RevealAtMath.isRevealLocked(now + 3600, isSender = true, nowSec = now))
    }

    @Test
    fun recipient_locked_before_reveal() {
        assertTrue(RevealAtMath.isRevealLocked(now + 3600, isSender = false, nowSec = now))
    }

    @Test
    fun recipient_unlocked_at_reveal_instant() {
        assertFalse(RevealAtMath.isRevealLocked(now, isSender = false, nowSec = now))
    }

    @Test
    fun recipient_unlocked_after_reveal() {
        assertFalse(RevealAtMath.isRevealLocked(now - 1, isSender = false, nowSec = now))
    }

    @Test
    fun absent_or_zero_reveal_is_never_locked() {
        assertFalse(RevealAtMath.isRevealLocked(null, isSender = false, nowSec = now))
        assertFalse(RevealAtMath.isRevealLocked(0L, isSender = false, nowSec = now))
        assertFalse(RevealAtMath.isRevealLocked(-5L, isSender = false, nowSec = now))
    }

    // ---- secondsUntilReveal ----

    @Test
    fun seconds_until_reveal_counts_down() {
        assertEquals(3600L, RevealAtMath.secondsUntilReveal(now + 3600, now))
    }

    @Test
    fun seconds_until_reveal_clamps_to_zero() {
        assertEquals(0L, RevealAtMath.secondsUntilReveal(now - 100, now))
        assertEquals(0L, RevealAtMath.secondsUntilReveal(null, now))
        assertEquals(0L, RevealAtMath.secondsUntilReveal(0L, now))
    }

    // ---- isRevealable / meetsMinLead ----

    @Test
    fun revealable_only_when_future_and_positive() {
        assertTrue(RevealAtMath.isRevealable(now + 1, now))
        assertFalse(RevealAtMath.isRevealable(now, now))
        assertFalse(RevealAtMath.isRevealable(now - 1, now))
        assertFalse(RevealAtMath.isRevealable(null, now))
        assertFalse(RevealAtMath.isRevealable(0L, now))
    }

    @Test
    fun meets_min_lead_respects_threshold() {
        assertTrue(RevealAtMath.meetsMinLead(now + RevealAtMath.MIN_REVEAL_LEAD_SEC, now))
        assertFalse(RevealAtMath.meetsMinLead(now + RevealAtMath.MIN_REVEAL_LEAD_SEC - 1, now))
        assertFalse(RevealAtMath.meetsMinLead(null, now))
    }

    // ---- revealCountdownLabel ----

    @Test
    fun countdown_label_hms_without_days() {
        // 4h 12m 9s
        val t = now + (4 * 3600 + 12 * 60 + 9)
        assertEquals("04:12:09", RevealAtMath.revealCountdownLabel(t, now))
    }

    @Test
    fun countdown_label_with_days() {
        val t = now + (2 * 86_400 + 4 * 3600 + 12 * 60 + 9)
        assertEquals("2d 04:12:09", RevealAtMath.revealCountdownLabel(t, now))
    }

    @Test
    fun countdown_label_zero_when_reached() {
        assertEquals("00:00:00", RevealAtMath.revealCountdownLabel(now, now))
        assertEquals("00:00:00", RevealAtMath.revealCountdownLabel(now - 500, now))
    }

    // ---- encode / parse round-trip ----

    @Test
    fun encode_wraps_with_sentinel() {
        val out = RevealAtMath.encode(now + 60, "hello world")
        assertTrue(out.startsWith(RevealAtMath.SENTINEL))
        assertTrue(RevealAtMath.isWrapped(out))
    }

    @Test
    fun round_trip_plain_text() {
        val out = RevealAtMath.encode(now + 60, "the secret drop")
        val w = RevealAtMath.parse(out)
        assertEquals(now + 60, w!!.revealAtSec)
        assertEquals("the secret drop", w.innerBody)
    }

    @Test
    fun round_trip_preserves_inner_card_sentinel_and_delimiters() {
        // The inner body is itself another card sentinel full of ';' and '=' — must survive verbatim.
        val inner = "TLSHOP1:product_card;item=it1;title=Cool%3B%20Thing;price=1999"
        val out = RevealAtMath.encode(now + 3600, inner)
        val w = RevealAtMath.parse(out)
        assertEquals(inner, w!!.innerBody)
        assertEquals(now + 3600, w.revealAtSec)
    }

    @Test
    fun encode_no_op_when_no_reveal_or_blank_body() {
        assertEquals("body", RevealAtMath.encode(0L, "body"))
        assertEquals("body", RevealAtMath.encode(-1L, "body"))
        assertEquals("   ", RevealAtMath.encode(now + 60, "   "))
    }

    @Test
    fun parse_returns_null_for_non_wrapped() {
        assertNull(RevealAtMath.parse(null))
        assertNull(RevealAtMath.parse("just text"))
        assertNull(RevealAtMath.parse("TLSHOP1:product_card;item=x"))
    }

    @Test
    fun parse_returns_null_for_malformed_wrapper() {
        assertNull(RevealAtMath.parse("TLRVL1:notanumber;body"))
        assertNull(RevealAtMath.parse("TLRVL1:0;body"))     // non-positive time
        assertNull(RevealAtMath.parse("TLRVL1:12345"))       // no separator
        assertNull(RevealAtMath.parse("TLRVL1:12345;"))      // empty inner body
    }

    // ---- previewForBody ----

    @Test
    fun preview_masks_wrapped_body_and_never_leaks_inner() {
        val out = RevealAtMath.encode(now + 60, "TOP SECRET reveal text")
        val preview = RevealAtMath.previewForBody(out)
        assertEquals(RevealAtMath.LOCKED_PREVIEW, preview)
        assertFalse(preview!!.contains("SECRET"))
    }

    @Test
    fun preview_null_for_non_wrapped() {
        assertNull(RevealAtMath.previewForBody("plain text"))
        assertNull(RevealAtMath.previewForBody(null))
    }
}
