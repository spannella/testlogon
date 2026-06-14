package com.testlogon.android.feature.feed

import org.junit.Assert.assertEquals
import org.junit.Test

/** AND-173 — compact like/comment count formatting. */
class CompactCountTest {

    @Test
    fun belowThousand_isPlain() {
        assertEquals("0", compactCount(0))
        assertEquals("42", compactCount(42))
        assertEquals("999", compactCount(999))
    }

    @Test
    fun thousands_useK() {
        assertEquals("1K", compactCount(1_000))
        assertEquals("1.2K", compactCount(1_234))
        assertEquals("12.3K", compactCount(12_345))
    }

    @Test
    fun millions_useM() {
        assertEquals("1M", compactCount(1_000_000))
        assertEquals("1.5M", compactCount(1_500_000))
    }
}
