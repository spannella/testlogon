package com.testlogon.android.data.messaging.realtime

import kotlin.random.Random

/**
 * AND-143 (SSE client core) — pure, JVM-testable reconnect backoff policy.
 *
 * Full-jitter exponential backoff with a base/cap, plus a lower bound from any server-provided
 * `retry:` hint (AND-143 FR-5/FR-6). Hardens the previously-inline `min(BASE shl attempt, MAX)`
 * computation in [SseMessagingEventStream] into a tested unit, and adds jitter (an intentional
 * enhancement over the web reference's jitter-free backoff for the flaky dev host).
 *
 * [maxConsecutiveFailures] bounds reconnect attempts so a permanently-down stream can surface a
 * stale/offline state rather than reconnecting forever.
 */
data class SseBackoffPolicy(
    val baseMillis: Long = BASE_BACKOFF_MS,
    val maxMillis: Long = MAX_BACKOFF_MS,
    val maxConsecutiveFailures: Int = MAX_CONSECUTIVE_FAILURES,
) {
    /**
     * Delay before reconnect [attempt] (1-based). Full-jitter in `[base, exp]` where
     * `exp = min(base * 2^(attempt-1), cap)`, then floored by [serverRetryMillis] when present.
     * [rng] is injectable for deterministic tests.
     */
    fun nextDelayMillis(
        attempt: Int,
        serverRetryMillis: Long? = null,
        rng: Random = Random.Default,
    ): Long {
        val safeAttempt = attempt.coerceAtLeast(1)
        val shift = (safeAttempt - 1).coerceAtMost(MAX_SHIFT)
        val exp = (baseMillis shl shift).coerceAtMost(maxMillis)
        val upper = exp.coerceAtLeast(baseMillis)
        val jittered = rng.nextLong(baseMillis, upper + 1)
        return maxOf(jittered, serverRetryMillis ?: 0L)
    }

    companion object {
        const val BASE_BACKOFF_MS = 1_000L
        const val MAX_BACKOFF_MS = 30_000L
        const val MAX_CONSECUTIVE_FAILURES = 8

        /** Cap on the left-shift so `base shl shift` never overflows toward the 30s cap. */
        const val MAX_SHIFT = 5
    }
}
