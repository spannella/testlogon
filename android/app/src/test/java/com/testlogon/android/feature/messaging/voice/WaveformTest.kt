package com.testlogon.android.feature.messaging.voice

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-133 — pure waveform normalize/resample edge cases (JVM). */
class WaveformTest {

    @Test
    fun normalize_emptyInput_returnsFlatBuckets() {
        val out = Waveform.normalize(emptyList(), 64)
        assertEquals(64, out.size)
        assertTrue(out.all { it == 0f })
    }

    @Test
    fun normalize_clampsBucketCountToRange() {
        assertEquals(Waveform.MIN_BUCKETS, Waveform.normalize(listOf(1, 2, 3), 1).size)
        assertEquals(Waveform.MAX_BUCKETS, Waveform.normalize(List(1000) { it }, 500).size)
    }

    @Test
    fun normalize_valuesInUnitRange() {
        val out = Waveform.normalize(List(300) { (it * 97) % 32768 }, 64)
        assertEquals(64, out.size)
        assertTrue(out.all { it in 0f..1f })
        // The loudest sample maps to ~1.0 (relative normalization against the peak).
        assertEquals(1f, out.max(), 0.01f)
    }

    @Test
    fun normalize_constantAmplitude_givesEqualBuckets() {
        val out = Waveform.normalize(List(128) { 8000 }, 32)
        assertTrue(out.all { kotlin.math.abs(it - out.first()) < 0.001f })
    }

    @Test
    fun normalize_shorterThanBuckets_noException() {
        val out = Waveform.normalize(listOf(10000, 20000), 64)
        assertEquals(64, out.size)
        assertTrue(out.all { it in 0f..1f })
    }

    @Test
    fun resample_toFixedBars() {
        val out = Waveform.resample(List(200) { 0.5f }, 64)
        assertEquals(64, out.size)
        assertTrue(out.all { kotlin.math.abs(it - 0.5f) < 0.001f })
    }
}
