package com.testlogon.android.feature.call.domain

/**
 * AND-296 — tunable timing for the call state machine, injected so tests can shorten the ring/heartbeat
 * windows and the production values can be retuned for the unreliable dev backend.
 *
 * All values are millis. The ring timeout (45s) and the heartbeat interval (15s) match the spec; both
 * timers are bounded coroutine jobs (NO unbounded while+delay) so advanceUntilIdle never hangs.
 */
data class CallTiming(
    val ringTimeoutMs: Long = 45_000,
    val heartbeatIntervalMs: Long = 15_000,
    val signalRetryDelayMs: Long = 2_000,
    val maxConsecutiveHeartbeatFailures: Int = 3,
)
