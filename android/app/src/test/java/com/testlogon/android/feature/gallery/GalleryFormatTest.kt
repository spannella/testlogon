package com.testlogon.android.feature.gallery

import org.junit.Assert.assertEquals
import org.junit.Test

/** AND-201 — pure formatter tests (duration mm:ss / h:mm:ss; count K/M). */
class GalleryFormatTest {

    @Test
    fun duration_under_an_hour_is_mm_ss() {
        assertEquals("2:34", formatDuration(154))
        assertEquals("0:05", formatDuration(5))
        assertEquals("0:00", formatDuration(0))
    }

    @Test
    fun duration_over_an_hour_is_h_mm_ss() {
        assertEquals("1:00:00", formatDuration(3600))
        assertEquals("1:02:03", formatDuration(3723))
    }

    @Test
    fun count_under_thousand_is_raw() {
        assertEquals("0", formatCount(0))
        assertEquals("999", formatCount(999))
    }

    @Test
    fun count_thousands_is_k() {
        assertEquals("1K", formatCount(1_000))
        assertEquals("1.2K", formatCount(1_203))
        assertEquals("12.3K", formatCount(12_345))
    }

    @Test
    fun count_millions_is_m() {
        assertEquals("1M", formatCount(1_000_000))
        assertEquals("3.4M", formatCount(3_456_789))
    }
}
