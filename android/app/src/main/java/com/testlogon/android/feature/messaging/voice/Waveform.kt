package com.testlogon.android.feature.messaging.voice

/**
 * AND-133 — pure, JVM-testable waveform downsampling.
 *
 * Collapses raw max-amplitude samples (0..32767 from MediaRecorder.getMaxAmplitude) into [buckets]
 * normalized peaks. The wire format is a JSON array of floats 0.0..1.0 (CreateVoiceMessageRequest
 * .waveform_data: number[], 10..200 items) — NOT base64 and NOT a fixed 64-byte field.
 */
object Waveform {

    const val MIN_BUCKETS = 10
    const val MAX_BUCKETS = 200
    const val DEFAULT_BUCKETS = 64
    private const val MAX_AMPLITUDE = 32767f

    /**
     * Returns exactly [buckets] (clamped to [MIN_BUCKETS]..[MAX_BUCKETS]) values in 0f..1f. Each
     * bucket is the average of its slice of [raw], normalized against the loudest sample so the
     * waveform uses the full visual range. Empty/short input is handled without throwing.
     */
    fun normalize(raw: List<Int>, buckets: Int = DEFAULT_BUCKETS): List<Float> {
        val n = buckets.coerceIn(MIN_BUCKETS, MAX_BUCKETS)
        if (raw.isEmpty()) return List(n) { 0f }

        // Peak for relative normalization (fall back to the absolute max to avoid divide-by-zero).
        val peak = (raw.maxOrNull() ?: 0).coerceAtLeast(1).toFloat()

        return List(n) { i ->
            val start = (i.toLong() * raw.size / n).toInt()
            val end = ((i + 1).toLong() * raw.size / n).toInt().coerceAtLeast(start + 1).coerceAtMost(raw.size)
            if (start >= raw.size) {
                0f
            } else {
                val slice = raw.subList(start, end)
                val avg = slice.sumOf { it.coerceAtLeast(0).toLong() }.toFloat() / slice.size
                (avg / peak).coerceIn(0f, 1f)
            }
        }
    }

    /**
     * Resamples a static (already-normalized 0..1) waveform to [buckets] bars for rendering, so a
     * received waveform of arbitrary length draws at a fixed bar count. Empty input -> flat bars.
     */
    fun resample(values: List<Float>, buckets: Int = DEFAULT_BUCKETS): List<Float> {
        val n = buckets.coerceIn(MIN_BUCKETS, MAX_BUCKETS)
        if (values.isEmpty()) return List(n) { 0f }
        return List(n) { i ->
            val start = (i.toLong() * values.size / n).toInt()
            val end = ((i + 1).toLong() * values.size / n).toInt().coerceAtLeast(start + 1).coerceAtMost(values.size)
            if (start >= values.size) 0f else values.subList(start, end).average().toFloat().coerceIn(0f, 1f)
        }
    }
}
