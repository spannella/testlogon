package com.testlogon.android.feature.messaging

import com.testlogon.android.feature.messaging.LiveLocationModel.LiveShare
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** EPIC D (FE-131) - pure active/expiry math, remaining-label, and TLLIVE1 encode/parse round-trip. */
class LiveLocationModelTest {

    private fun share(
        exp: Long,
        start: Long = 1_000L,
        stop: Long? = null,
        lat: Double = 37.7749,
        lng: Double = -122.4194,
        label: String? = null,
    ) = LiveShare("sh_1", lat, lng, start, exp, stop, label)

    @Test
    fun duration_options_are_15m_1h_8h() {
        assertEquals(3, LiveLocationModel.LIVE_DURATION_OPTIONS.size)
        assertEquals(900L, LiveLocationModel.LIVE_DURATION_OPTIONS[0].seconds)
        assertEquals(3600L, LiveLocationModel.LIVE_DURATION_OPTIONS[1].seconds)
        assertEquals(28800L, LiveLocationModel.LIVE_DURATION_OPTIONS[2].seconds)
    }

    @Test
    fun compute_expires_at_adds_duration_and_clamps() {
        assertEquals(1900L, LiveLocationModel.computeExpiresAt(1000L, 900L))
        assertEquals(1000L, LiveLocationModel.computeExpiresAt(1000L, 0L))
        assertEquals(1000L, LiveLocationModel.computeExpiresAt(1000L, -50L))
    }

    @Test
    fun is_live_active_true_before_expiry() {
        assertTrue(LiveLocationModel.isLiveActive(2000L, null, 1999L))
    }

    @Test
    fun is_live_active_false_at_and_after_expiry() {
        assertFalse(LiveLocationModel.isLiveActive(2000L, null, 2000L))
        assertFalse(LiveLocationModel.isLiveActive(2000L, null, 2001L))
    }

    @Test
    fun is_live_active_false_when_stopped_before_now() {
        assertFalse(LiveLocationModel.isLiveActive(9999L, 1500L, 1600L))
    }

    @Test
    fun is_live_active_ignores_future_stop_time() {
        // stop in the future (clock skew) does not prematurely end an otherwise-active share.
        assertTrue(LiveLocationModel.isLiveActive(9999L, 5000L, 1600L))
    }

    @Test
    fun seconds_remaining_clamps_to_zero() {
        assertEquals(400L, LiveLocationModel.liveSecondsRemaining(2000L, 1600L))
        assertEquals(0L, LiveLocationModel.liveSecondsRemaining(2000L, 2000L))
        assertEquals(0L, LiveLocationModel.liveSecondsRemaining(2000L, 5000L))
    }

    @Test
    fun should_auto_stop_is_inverse_of_active() {
        assertFalse(LiveLocationModel.shouldAutoStop(2000L, null, 1999L))
        assertTrue(LiveLocationModel.shouldAutoStop(2000L, null, 2000L))
        assertTrue(LiveLocationModel.shouldAutoStop(9999L, 1500L, 1600L))
    }

    @Test
    fun remaining_label_formats_by_magnitude() {
        val start = 0L
        assertEquals("8h 0m left", LiveLocationModel.liveRemainingLabel(28800L, null, start))
        assertEquals("14m left", LiveLocationModel.liveRemainingLabel(900L, null, 60L))
        assertEquals("45s left", LiveLocationModel.liveRemainingLabel(45L, null, 0L))
        assertEquals("Ended", LiveLocationModel.liveRemainingLabel(45L, null, 100L))
        assertEquals("Ended", LiveLocationModel.liveRemainingLabel(9999L, 50L, 100L))
    }

    @Test
    fun encode_parse_round_trip_all_fields() {
        val s = share(exp = 2000L, start = 1000L, stop = 1500L, label = "On my way")
        val body = LiveLocationModel.encode(s)
        assertTrue(body.startsWith(LiveLocationModel.SENTINEL))
        val back = LiveLocationModel.parse(body)!!
        assertEquals(s.shareId, back.shareId)
        assertEquals(s.lat, back.lat, 0.0)
        assertEquals(s.lng, back.lng, 0.0)
        assertEquals(s.startedAtSec, back.startedAtSec)
        assertEquals(s.expiresAtSec, back.expiresAtSec)
        assertEquals(s.stoppedAtSec, back.stoppedAtSec)
        assertEquals(s.label, back.label)
    }

    @Test
    fun encode_parse_round_trip_minimal() {
        val s = share(exp = 2000L)
        val back = LiveLocationModel.parse(LiveLocationModel.encode(s))!!
        assertEquals("sh_1", back.shareId)
        assertNull(back.stoppedAtSec)
        assertNull(back.label)
    }

    @Test
    fun label_with_delimiters_round_trips() {
        val s = share(exp = 2000L, label = "a;b=c%d")
        val back = LiveLocationModel.parse(LiveLocationModel.encode(s))!!
        assertEquals("a;b=c%d", back.label)
    }

    @Test
    fun parse_rejects_non_card_and_malformed() {
        assertNull(LiveLocationModel.parse(null))
        assertNull(LiveLocationModel.parse("hello"))
        assertNull(LiveLocationModel.parse(LiveLocationModel.SENTINEL + "lat=1;lng=2")) // missing id/start/exp
        assertNull(LiveLocationModel.parse(LiveLocationModel.SENTINEL + "id=x;lat=999;lng=2;start=1;exp=2")) // bad coord
        assertNull(LiveLocationModel.parse(LiveLocationModel.SENTINEL + "id=x;lat=1;lng=2;start=xx;exp=2")) // bad start
    }

    @Test
    fun is_card_and_preview_mask_the_sentinel() {
        val body = LiveLocationModel.encode(share(exp = 2000L))
        assertTrue(LiveLocationModel.isCard(body))
        assertFalse(LiveLocationModel.isCard("plain"))
        assertEquals("${LiveLocationModel.PIN} Live location", LiveLocationModel.previewForBody(body))
        assertNull(LiveLocationModel.previewForBody("plain"))
    }
}
