package com.testlogon.android.data.messaging.realtime

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.random.Random

/** AND-143 — pure backoff policy: jitter bounds, growth toward the cap, and server-retry floor. */
class SseBackoffPolicyTest {

    private val policy = SseBackoffPolicy()

    @Test
    fun firstAttemptIsWithinBaseWindow() {
        repeat(50) {
            val d = policy.nextDelayMillis(attempt = 1)
            assertTrue("delay $d", d in policy.baseMillis..policy.baseMillis) // exp == base on attempt 1
        }
    }

    @Test
    fun jitterStaysWithinBaseAndExpWindow() {
        // attempt 3 -> exp = base * 2^2 = 4000; jitter in [1000, 4000].
        repeat(200) {
            val d = policy.nextDelayMillis(attempt = 3)
            assertTrue("delay $d", d in 1_000L..4_000L)
        }
    }

    @Test
    fun delayIsCappedAtMax() {
        repeat(200) {
            val d = policy.nextDelayMillis(attempt = 20)
            assertTrue("delay $d", d in 1_000L..30_000L)
        }
    }

    @Test
    fun serverRetryHintFloorsTheDelay() {
        // Even with the smallest possible jitter, the 5s server hint wins.
        val rng = Random(1)
        val d = policy.nextDelayMillis(attempt = 1, serverRetryMillis = 5_000L, rng = rng)
        assertTrue("delay $d", d >= 5_000L)
    }

    @Test
    fun deterministicWithSeededRng() {
        val a = policy.nextDelayMillis(attempt = 4, rng = Random(42))
        val b = policy.nextDelayMillis(attempt = 4, rng = Random(42))
        assertEquals(a, b)
    }

    @Test
    fun attemptZeroIsTreatedAsOne() {
        val d = policy.nextDelayMillis(attempt = 0)
        assertEquals(1_000L, d)
    }
}
